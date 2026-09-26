package mls

import (
	"bytes"
	"errors"
	"testing"
)

// rotate builds the leaf node of an update for g's own member,
// rotating both the encryption key and the signature key, and returns
// it with the two new private keys.
func rotate(t *testing.T, g *Group) (*LeafNode, []byte, []byte) {
	t.Helper()
	cs := g.CipherSuite
	encPriv, encPub, err := cs.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sigPriv, sigPub, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	leaf := *g.Tree.Leaf(g.Index)
	leaf.EncryptionKey = encPub
	leaf.SignatureKey = sigPub
	leaf.Source = LeafNodeSourceUpdate
	leaf.Lifetime = Lifetime{}
	if err := leaf.Sign(cs, sigPriv, g.Context.GroupID, g.Index); err != nil {
		t.Fatal(err)
	}
	return &leaf, encPriv, sigPriv
}

// TestProposeUpdate checks that a member can follow the commit that
// applies its own update. The committer encrypts the path secrets to
// the leaf key the update installs, so only the proposer can decrypt
// them, and only if it kept the private half.
func TestProposeUpdate(t *testing.T) {
	cs := testSuite()
	alice, bob := newTestClient(t, cs, "alice"), newTestClient(t, cs, "bob")
	ga, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ga, _, welcome, err := ga.Commit([]*Proposal{{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}}})
	if err != nil {
		t.Fatal(err)
	}
	gb, err := bob.Join(send(t, welcome).Welcome, ga.Tree)
	if err != nil {
		t.Fatal(err)
	}

	leaf, encPriv, sigPriv := rotate(t, gb)
	prop, err := gb.ProposeUpdate(leaf, encPriv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ga.Unprotect(send(t, prop))
	if err != nil {
		t.Fatal(err)
	}
	if err := ga.AddProposal(c); err != nil {
		t.Fatal(err)
	}
	ga2, commit, _, err := ga.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	gb2, _, err := gb.Handle(send(t, commit))
	if err != nil {
		t.Fatalf("following one's own update: %v", err)
	}
	if !bytes.Equal(ga2.EpochAuthenticator(), gb2.EpochAuthenticator()) {
		t.Fatal("epoch authenticators disagree after an update")
	}
	if got := gb2.Tree.Leaf(gb2.Index).SignatureKey; !bytes.Equal(got, leaf.SignatureKey) {
		t.Error("the update did not install the new signature key")
	}

	// The rotated keys must be the ones that work from here on.
	bob.SignaturePriv = sigPriv
	msg, err := gb2.Protect(nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ga2.Unprotect(send(t, msg))
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Content.ApplicationData) != "hello" {
		t.Errorf("got %q, want %q", got.Content.ApplicationData, "hello")
	}
}

// TestProposeUpdateErrors covers the ways an update goes wrong.
func TestProposeUpdateErrors(t *testing.T) {
	cs := testSuite()
	alice, bob := newTestClient(t, cs, "alice"), newTestClient(t, cs, "bob")
	ga, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ga, _, welcome, err := ga.Commit([]*Proposal{{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}}})
	if err != nil {
		t.Fatal(err)
	}
	gb, err := bob.Join(send(t, welcome).Welcome, ga.Tree)
	if err != nil {
		t.Fatal(err)
	}
	leaf, encPriv, _ := rotate(t, gb)

	t.Run("source", func(t *testing.T) {
		bad := *leaf
		bad.Source = LeafNodeSourceCommit
		if _, err := gb.ProposeUpdate(&bad, encPriv); !errors.Is(err, ErrBadLeafNodeSource) {
			t.Errorf("got %v, want %v", err, ErrBadLeafNodeSource)
		}
	})
	t.Run("mismatched key", func(t *testing.T) {
		other, _, err := cs.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gb.ProposeUpdate(leaf, other); !errors.Is(err, ErrBadTreeKEM) {
			t.Errorf("got %v, want %v", err, ErrBadTreeKEM)
		}
	})

	// An update proposed without keeping the private key cannot be
	// followed, and says so rather than failing to decrypt.
	t.Run("key not kept", func(t *testing.T) {
		prop, err := gb.Propose(&Proposal{Type: ProposalTypeUpdate, Update: &Update{LeafNode: *leaf}})
		if err != nil {
			t.Fatal(err)
		}
		c, err := ga.Unprotect(send(t, prop))
		if err != nil {
			t.Fatal(err)
		}
		if err := ga.AddProposal(c); err != nil {
			t.Fatal(err)
		}
		_, commit, _, err := ga.Commit(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := gb.Handle(send(t, commit)); !errors.Is(err, ErrBadTreeKEM) {
			t.Errorf("got %v, want %v", err, ErrBadTreeKEM)
		}
	})
}

// TestCommitDropsOwnUpdate checks that a member with an update
// outstanding can still commit. RFC 9420, Section 12.2 forbids a
// commit from carrying its own sender's update, so the commit leaves
// it behind; the update path replaces the sender's leaf anyway.
func TestCommitDropsOwnUpdate(t *testing.T) {
	cs := testSuite()
	alice, bob := newTestClient(t, cs, "alice"), newTestClient(t, cs, "bob")
	ga, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ga, _, welcome, err := ga.Commit([]*Proposal{{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}}})
	if err != nil {
		t.Fatal(err)
	}
	gb, err := bob.Join(send(t, welcome).Welcome, ga.Tree)
	if err != nil {
		t.Fatal(err)
	}
	leaf, encPriv, _ := rotate(t, gb)
	if _, err := gb.ProposeUpdate(leaf, encPriv); err != nil {
		t.Fatal(err)
	}
	gb2, commit, _, err := gb.Commit(nil)
	if err != nil {
		t.Fatalf("committing with one's own update outstanding: %v", err)
	}
	ga2, _, err := ga.Handle(send(t, commit))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ga2.EpochAuthenticator(), gb2.EpochAuthenticator()) {
		t.Fatal("epoch authenticators disagree")
	}
}

// An update may take up a key held by a member the same commit
// removes, which is no longer a member when the update applies.
func TestUpdateKeyOfRemoved(t *testing.T) {
	a, b, c := threeMember(t)
	cs := b.CipherSuite
	leaf := *b.Tree.Leaf(b.Index)
	leaf.EncryptionKey = c.Tree.Leaf(c.Index).EncryptionKey
	leaf.Source = LeafNodeSourceUpdate
	leaf.Lifetime = Lifetime{}
	if err := leaf.Sign(cs, b.client.SignaturePriv, b.Context.GroupID, b.Index); err != nil {
		t.Fatal(err)
	}
	m, err := b.ProposeUpdate(&leaf, c.client.EncryptionPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Handle(send(t, m)); err != nil {
		t.Fatal(err)
	}
	a2, commit, _, err := a.Commit([]*Proposal{{Type: ProposalTypeRemove, Remove: &Remove{Removed: uint32(c.Index)}}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a2.Tree.Leaf(b.Index).EncryptionKey, leaf.EncryptionKey) {
		t.Error("the commit left the update out")
	}
	if _, _, err := b.Handle(send(t, commit)); err != nil {
		t.Errorf("the proposer rejects the commit: %v", err)
	}
}
