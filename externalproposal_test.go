package mls

import (
	"bytes"
	"errors"
	"testing"
)

// TestExternalProposal runs the two ways RFC 9420, Section 12.1.8
// lets a party outside a group send it a proposal: an external sender
// the group provisioned, and a client proposing its own addition.
func TestExternalProposal(t *testing.T) {
	cs := testSuite()
	alice := newTestClient(t, cs, "alice")
	bob := newTestClient(t, cs, "bob")
	carol := newTestClient(t, cs, "carol")
	accept := func(*AuthenticatedContent) error { return nil }
	alice.ExternalProposal = accept
	bob.ExternalProposal = accept

	// The group provisions a signature key for a service that may
	// propose on its behalf.
	priv, pub, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	senders := ExternalSenders{{
		SignatureKey: pub,
		Credential:   Credential{Type: CredentialTypeBasic, Identity: []byte("directory")},
	}}
	var ext Extensions
	if err := ext.Set(ExtensionTypeExternalSenders, &senders); err != nil {
		t.Fatal(err)
	}
	g, err := alice.NewGroup([]byte("group"), ext)
	if err != nil {
		t.Fatal(err)
	}

	// The service proposes adding Bob, and Alice commits it.
	// The service learns the group and epoch to name from a
	// message it sees pass by; see ParseHeader.
	seen, err := g.Protect(nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(seen)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	dir := &ExternalClient{CipherSuite: cs, SignaturePriv: priv}
	add := &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}}
	msg, err := dir.Propose(h.GroupID, h.Epoch, add)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Handle(send(t, msg)); err != nil {
		t.Fatal(err)
	}
	g2, commit, welcome, err := g.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = commit
	if welcome == nil {
		t.Fatal("no welcome for the added member")
	}
	if got := members(g2.Tree); got != 2 {
		t.Fatalf("members = %d, want 2", got)
	}

	// Carol asks to join, and Bob, who has joined by welcome,
	// commits her proposal.
	gb, err := bob.Join(welcome.Welcome, g2.Tree)
	if err != nil {
		t.Fatal(err)
	}
	ask, err := carol.ProposeAdd(gb.Context.GroupID, gb.Context.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := gb.Handle(send(t, ask)); err != nil {
		t.Fatal(err)
	}
	gb2, _, welcome, err := gb.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := members(gb2.Tree); got != 3 {
		t.Fatalf("members = %d, want 3", got)
	}
	gc, err := carol.Join(welcome.Welcome, gb2.Tree)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gc.EpochAuthenticator(), gb2.EpochAuthenticator()) {
		t.Error("carol did not reach the same epoch")
	}
}

// TestExternalProposalRules checks what an external sender may not do.
func TestExternalProposalRules(t *testing.T) {
	cs := testSuite()
	alice := newTestClient(t, cs, "alice")
	priv, pub, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	senders := ExternalSenders{{SignatureKey: pub, Credential: Credential{Type: CredentialTypeBasic, Identity: []byte("d")}}}
	var ext Extensions
	if err := ext.Set(ExtensionTypeExternalSenders, &senders); err != nil {
		t.Fatal(err)
	}
	g, err := alice.NewGroup([]byte("group"), ext)
	if err != nil {
		t.Fatal(err)
	}

	dir := &ExternalClient{CipherSuite: cs, SignaturePriv: priv}

	// Update is not among the types Section 12.1.8 allows.
	up := &Proposal{Type: ProposalTypeUpdate, Update: &Update{LeafNode: alice.KeyPackage.LeafNode}}
	if _, err := dir.Propose(g.Context.GroupID, g.Context.Epoch, up); !errors.Is(err, ErrBadExternalSender) {
		t.Errorf("Propose(update) = %v, want %v", err, ErrBadExternalSender)
	}

	// A sender the extension does not list is rejected.
	stranger := &ExternalClient{CipherSuite: cs, Index: 1, SignaturePriv: priv}
	rm := &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 0}}
	msg, err := stranger.Propose(g.Context.GroupID, g.Context.Epoch, rm)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Handle(send(t, msg)); !errors.Is(err, ErrBadExternalSender) {
		t.Errorf("Handle = %v, want %v", err, ErrBadExternalSender)
	}

	// A group with no external_senders extension admits none.
	plain, err := alice.NewGroup([]byte("plain"), nil)
	if err != nil {
		t.Fatal(err)
	}
	msg, err = dir.Propose(plain.Context.GroupID, plain.Context.Epoch, rm)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := plain.Handle(send(t, msg)); !errors.Is(err, ErrBadExternalSender) {
		t.Errorf("Handle = %v, want %v", err, ErrBadExternalSender)
	}
}

// A proposal from outside the group is staged only if the client's
// policy accepts it; without one, a stranger asking to join would be
// added by the next commit of any member.
func TestExternalProposalPolicy(t *testing.T) {
	cs := testSuite()
	eve := newTestClient(t, cs, "eve")
	errNo := errors.New("not eve")
	tests := []struct {
		name   string
		policy func(*AuthenticatedContent) error
		want   error
	}{
		{"no policy", nil, ErrExternalProposal},
		{"policy refuses", func(*AuthenticatedContent) error { return errNo }, errNo},
		{"policy accepts", func(*AuthenticatedContent) error { return nil }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _, _ := threeMember(t)
			a.client.ExternalProposal = tt.policy
			ask, err := eve.ProposeAdd(a.Context.GroupID, a.Context.Epoch)
			if err != nil {
				t.Fatal(err)
			}
			g, _, err := a.Handle(send(t, ask))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Handle = %v, want %v", err, tt.want)
			}
			if err != nil && g != nil {
				t.Error("Handle returned a group along with an error")
			}
			a2, _, _, err := a.Commit(nil)
			if err != nil {
				t.Fatal(err)
			}
			want := 3
			if tt.want == nil {
				want = 4
			}
			if got := members(a2.Tree); got != want {
				t.Errorf("members = %d, want %d", got, want)
			}
		})
	}
}

// With no policy, a member accepts proposals from the senders the
// group provisioned: listing a sender in external_senders is the
// group's authorization of it (RFC 9420, Section 12.1.8.1).
func TestExternalProposalDefault(t *testing.T) {
	cs := testSuite()
	alice := newTestClient(t, cs, "alice")
	bob := newTestClient(t, cs, "bob")
	priv, pub, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	senders := ExternalSenders{{SignatureKey: pub, Credential: Credential{Type: CredentialTypeBasic, Identity: []byte("d")}}}
	var ext Extensions
	if err := ext.Set(ExtensionTypeExternalSenders, &senders); err != nil {
		t.Fatal(err)
	}
	g, err := alice.NewGroup([]byte("group"), ext)
	if err != nil {
		t.Fatal(err)
	}
	dir := &ExternalClient{CipherSuite: cs, SignaturePriv: priv}
	add := &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}}
	msg, err := dir.Propose(g.Context.GroupID, g.Context.Epoch, add)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Handle(send(t, msg)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	g2, _, _, err := g.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := members(g2.Tree); got != 2 {
		t.Errorf("members = %d, want 2", got)
	}
}

// A group remembers a bounded number of proposals from one sender in
// one epoch, and others may still propose once one sender reaches it.
func TestTooManyProposals(t *testing.T) {
	a, b, _ := threeMember(t)
	for i := 1; i <= maxSenderProposals+1; i++ {
		_, err := a.Propose(numberedPSK(i))
		if i <= maxSenderProposals && err != nil {
			t.Fatalf("proposal %d: %v", i, err)
		}
		if i > maxSenderProposals && !errors.Is(err, ErrTooManyProposals) {
			t.Fatalf("proposal %d: %v, want %v", i, err, ErrTooManyProposals)
		}
	}
	stageUpdate(t, a, b)
	if n := len(a.proposals); n != maxSenderProposals+1 {
		t.Errorf("%d proposals staged, want %d", n, maxSenderProposals+1)
	}
}

// A group remembers a bounded number of proposals in all, however
// many senders they come from.
func TestTooManySenders(t *testing.T) {
	cs := testSuite()
	alice := newTestClient(t, cs, "alice")
	priv, pub, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var senders ExternalSenders
	for range maxProposals / maxSenderProposals {
		senders = append(senders, ExternalSender{SignatureKey: pub, Credential: Credential{Type: CredentialTypeBasic, Identity: []byte("d")}})
	}
	var ext Extensions
	if err := ext.Set(ExtensionTypeExternalSenders, &senders); err != nil {
		t.Fatal(err)
	}
	g, err := alice.NewGroup([]byte("group"), ext)
	if err != nil {
		t.Fatal(err)
	}
	for i := range senders {
		dir := &ExternalClient{CipherSuite: cs, Index: uint32(i), SignaturePriv: priv}
		for j := range maxSenderProposals {
			m, err := dir.Propose(g.Context.GroupID, g.Context.Epoch, numberedPSK(j))
			if err != nil {
				t.Fatal(err)
			}
			handle(t, g, m)
		}
	}
	if _, err := g.Propose(numberedPSK(0)); !errors.Is(err, ErrTooManyProposals) {
		t.Errorf("Propose = %v, want %v", err, ErrTooManyProposals)
	}
}

// numberedPSK returns an external PSK proposal distinct for each i.
func numberedPSK(i int) *Proposal {
	p := externalPSK("k")
	p.PreSharedKey.PSK.PSKNonce[0] = byte(i)
	p.PreSharedKey.PSK.PSKNonce[1] = byte(i >> 8)
	return p
}
