package mls

import (
	"bytes"
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
