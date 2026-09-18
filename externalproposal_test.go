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
	cs := X25519AES128GCMSHA256Ed25519
	alice := newTestClient(t, cs, "alice")
	bob := newTestClient(t, cs, "bob")
	carol := newTestClient(t, cs, "carol")

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
	if _, err := g.Handle(send(t, msg)); err != nil {
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
	if _, err := gb.Handle(send(t, ask)); err != nil {
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
	cs := X25519AES128GCMSHA256Ed25519
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
	if _, err := g.Handle(send(t, msg)); !errors.Is(err, ErrBadExternalSender) {
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
	if _, err := plain.Handle(send(t, msg)); !errors.Is(err, ErrBadExternalSender) {
		t.Errorf("Handle = %v, want %v", err, ErrBadExternalSender)
	}
}
