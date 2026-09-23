package mls

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func newTestClient(t testing.TB, cs CipherSuite, name string) *Client {
	t.Helper()
	c, err := NewClient(cs, Credential{Type: CredentialTypeBasic, Identity: []byte(name)}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.KeyPackage.Verify(); err != nil {
		t.Fatalf("%s: key package does not verify: %v", name, err)
	}
	return c
}

// send round-trips a message through its encoding, as the delivery
// service would.
func send(t testing.TB, m *Message) *Message {
	t.Helper()
	b, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var got Message
	if err := Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	return &got
}

func TestGroup(t *testing.T) {
	for _, cs := range []CipherSuite{
		X25519AES128GCMSHA256Ed25519,
		P256AES128GCMSHA256P256,
		X25519ChaCha20Poly1305SHA256Ed25519,
		P521AES256GCMSHA512P521,
		P384AES256GCMSHA384P384,
	} {
		t.Run(cs.String(), func(t *testing.T) { testGroup(t, cs) })
	}
}

func testGroup(t *testing.T, cs CipherSuite) {
	alice := newTestClient(t, cs, "alice")
	bob := newTestClient(t, cs, "bob")
	carol := newTestClient(t, cs, "carol")

	a0, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Alice adds Bob.
	add := &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}}
	a1, _, welcome, err := a0.Commit([]*Proposal{add})
	if err != nil {
		t.Fatal(err)
	}
	if welcome == nil {
		t.Fatal("no welcome for the added member")
	}
	b1, err := bob.Join(send(t, welcome).Welcome, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a1.EpochAuthenticator(), b1.EpochAuthenticator()) {
		t.Fatal("alice and bob disagree after the add")
	}
	if b1.Epoch() != 1 {
		t.Fatalf("bob joined at epoch %d, want 1", b1.Epoch())
	}

	// Application messages flow both ways.
	for _, tc := range []struct{ from, to *Group }{{a1, b1}, {b1, a1}} {
		msg, err := tc.from.Protect([]byte("aad"), []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := tc.to.Unprotect(send(t, msg))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Content.ApplicationData, []byte("hello")) {
			t.Errorf("got %q, want %q", got.Content.ApplicationData, "hello")
		}
	}

	// Bob proposes to add Carol; Alice commits the proposal by
	// reference, and both of them plus Carol end up in step.
	prop, err := b1.Propose(&Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *carol.KeyPackage}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a1.Handle(send(t, prop)); err != nil {
		t.Fatal(err)
	}
	a2, commit, welcome, err := a1.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := b1.Handle(send(t, commit))
	if err != nil {
		t.Fatal(err)
	}
	c2, err := carol.Join(send(t, welcome).Welcome, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []*Group{b2, c2} {
		if !bytes.Equal(a2.EpochAuthenticator(), g.EpochAuthenticator()) {
			t.Fatal("members disagree after the second add")
		}
	}

	// Carol commits an update of her own leaf, which exercises a
	// commit from a member that is not the group's creator.
	c3, commit, _, err := c2.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	commit = send(t, commit)
	a3, err := a2.Handle(commit)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := b2.Handle(commit)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []*Group{a3, b3} {
		if !bytes.Equal(c3.EpochAuthenticator(), g.EpochAuthenticator()) {
			t.Fatal("members disagree after carol's commit")
		}
	}
	msg, err := c3.Protect(nil, []byte("from carol"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a3.Unprotect(send(t, msg)); err != nil {
		t.Fatal(err)
	}

	// Alice removes Bob. Bob can no longer follow the group.
	remove := &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: uint32(b3.Index)}}
	a4, commit, _, err := a3.Commit([]*Proposal{remove})
	if err != nil {
		t.Fatal(err)
	}
	commit = send(t, commit)
	c4, err := c3.Handle(commit)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a4.EpochAuthenticator(), c4.EpochAuthenticator()) {
		t.Fatal("alice and carol disagree after the remove")
	}
	if _, err := b3.Handle(commit); err != ErrRemoved {
		t.Errorf("bob handling his own removal: %v, want %v", err, ErrRemoved)
	}
}

// A joiner takes the leaf holding its key package's leaf node, not
// just any leaf with its encryption key. See RFC 9420, Section
// 12.4.3.1. Here a committer seats Mallory's signature key beside
// Bob's encryption key and addresses the welcome to Bob.
func TestJoinOwnLeaf(t *testing.T) {
	cs := X25519AES128GCMSHA256Ed25519
	alice := newTestClient(t, cs, "alice")
	bob := newTestClient(t, cs, "bob")
	mallory := newTestClient(t, cs, "mallory")

	kp := *mallory.KeyPackage
	kp.LeafNode.EncryptionKey = bob.KeyPackage.LeafNode.EncryptionKey
	if err := kp.LeafNode.Sign(cs, mallory.SignaturePriv, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := kp.Sign(mallory.SignaturePriv); err != nil {
		t.Fatal(err)
	}
	g0, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	g1, _, _, err := g0.Commit([]*Proposal{{Type: ProposalTypeAdd, Add: &Add{KeyPackage: kp}}})
	if err != nil {
		t.Fatal(err)
	}
	tag, err := cs.ConfirmationTag(g1.schedule.ConfirmationKey, g1.Context.ConfirmedTranscriptHash)
	if err != nil {
		t.Fatal(err)
	}
	add := &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}}
	w, err := g1.welcome(tag, []proposal{{Proposal: add}}, []LeafIndex{1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Join(send(t, w).Welcome, nil); !errors.Is(err, ErrNotMember) {
		t.Errorf("Join = %v, want %v", err, ErrNotMember)
	}
}

// A joiner checks that the group it joins runs the version and cipher
// suite it expects: the welcome's cipher suite covers only the
// welcome itself.
func TestJoinGroupContext(t *testing.T) {
	cs := X25519AES128GCMSHA256Ed25519
	tests := []struct {
		name   string
		mutate func(*GroupContext)
		want   error
	}{
		{"cipher suite", func(c *GroupContext) { c.CipherSuite = P256AES128GCMSHA256P256 }, ErrUnsupportedCipherSuite},
		{"version", func(c *GroupContext) { c.Version = Version10 + 1 }, ErrUnsupportedVersion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alice := newTestClient(t, cs, "alice")
			bob := newTestClient(t, cs, "bob")
			g0, err := alice.NewGroup([]byte("group"), nil)
			if err != nil {
				t.Fatal(err)
			}
			add := &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}}
			g1, _, _, err := g0.Commit([]*Proposal{add})
			if err != nil {
				t.Fatal(err)
			}
			// Rebuild the epoch around the altered context, so
			// that nothing but the check can catch it.
			h := *g1
			tt.mutate(&h.Context)
			if h.schedule, err = newKeySchedule(cs, g1.schedule.JoinerSecret, nil, &h.Context); err != nil {
				t.Fatal(err)
			}
			tag, err := cs.ConfirmationTag(h.schedule.ConfirmationKey, h.Context.ConfirmedTranscriptHash)
			if err != nil {
				t.Fatal(err)
			}
			w, err := h.welcome(tag, []proposal{{Proposal: add}}, []LeafIndex{1}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := bob.Join(send(t, w).Welcome, nil); !errors.Is(err, tt.want) {
				t.Errorf("Join = %v, want %v", err, tt.want)
			}
		})
	}
}
