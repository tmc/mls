package mls

import (
	"bytes"
	"errors"
	"testing"
)

// setup builds a three-member group and returns it as each member
// sees it.
func setup(t *testing.T, cs CipherSuite) (*Client, *Client, *Client, *Group, *Group, *Group) {
	t.Helper()
	alice := newTestClient(t, cs, "alice")
	bob := newTestClient(t, cs, "bob")
	carol := newTestClient(t, cs, "carol")
	ga, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ga, _, welcome, err := ga.Commit([]*Proposal{
		{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}},
		{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *carol.KeyPackage}},
	})
	if err != nil {
		t.Fatal(err)
	}
	gb, err := bob.Join(send(t, welcome).Welcome, ga.Tree)
	if err != nil {
		t.Fatal(err)
	}
	gc, err := carol.Join(send(t, welcome).Welcome, ga.Tree)
	if err != nil {
		t.Fatal(err)
	}
	return alice, bob, carol, ga, gb, gc
}

// TestReinit runs the three steps of RFC 9420, Section 11.2: a Reinit
// proposal, a commit covering it, and the new group that carries the
// membership over.
func TestReinit(t *testing.T) {
	cs := X25519AES128GCMSHA256Ed25519
	alice, bob, carol, ga, gb, gc := setup(t, cs)

	ri := &Reinit{GroupID: []byte("successor"), Version: Version10, CipherSuite: cs}
	msg, err := gb.Propose(&Proposal{Type: ProposalTypeReinit, Reinit: ri})
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []*Group{ga, gc} {
		if _, err := g.Handle(send(t, msg)); err != nil {
			t.Fatal(err)
		}
	}
	ga2, commit, _, err := ga.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	gb2, err := gb.Handle(send(t, commit))
	if err != nil {
		t.Fatal(err)
	}
	gc2, err := gc.Handle(send(t, commit))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []*Group{ga2, gb2, gc2} {
		if got := g.Reinit(); got == nil || !bytes.Equal(got.GroupID, ri.GroupID) {
			t.Fatalf("Reinit = %v, want %v", got, ri)
		}
		// The old group is finished.
		if _, _, _, err := g.Commit(nil); !errors.Is(err, ErrReinitialized) {
			t.Errorf("Commit = %v, want %v", err, ErrReinitialized)
		}
		if _, err := g.Propose(&Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 1}}); !errors.Is(err, ErrReinitialized) {
			t.Errorf("Propose = %v, want %v", err, ErrReinitialized)
		}
	}

	// Any member may create the successor; here it is Carol, who
	// did not commit the Reinit. The others fetch new key
	// packages, since the successor may use a new cipher suite.
	bob2 := newTestClient(t, cs, "bob")
	alice2 := newTestClient(t, cs, "alice")
	next, welcome, err := gc2.Reinitialize([]*KeyPackage{alice2.KeyPackage, bob2.KeyPackage})
	if err != nil {
		t.Fatal(err)
	}
	if next.Epoch() != 1 {
		t.Errorf("epoch = %d, want 1", next.Epoch())
	}
	if !bytes.Equal(next.Context.GroupID, ri.GroupID) {
		t.Errorf("group id = %q, want %q", next.Context.GroupID, ri.GroupID)
	}
	for _, c := range []*Client{alice2, bob2} {
		g, err := c.Resume(send(t, welcome).Welcome, next.Tree, gc2)
		if err != nil {
			t.Fatalf("%s: %v", c.KeyPackage.LeafNode.Credential.Identity, err)
		}
		if !bytes.Equal(g.EpochAuthenticator(), next.EpochAuthenticator()) {
			t.Error("joiner did not reach the same epoch")
		}
	}

	// Join does not accept it: the resumption key is not one the
	// joining client can resolve on its own.
	if _, err := bob2.Join(send(t, welcome).Welcome, next.Tree); err == nil {
		t.Error("Join accepted a welcome that needs a resumption key")
	}
	// Nor does it resume from an epoch that never committed the
	// Reinit, whose resumption key the welcome does not name.
	if _, err := bob2.Resume(send(t, welcome).Welcome, next.Tree, ga); !errors.Is(err, ErrUnknownPSK) {
		t.Errorf("Resume = %v, want %v", err, ErrUnknownPSK)
	}
	_ = alice
	_ = bob
	_ = carol
}

// TestBranch covers RFC 9420, Section 11.3: a member forms a subgroup
// of the original group's members.
func TestBranch(t *testing.T) {
	cs := X25519AES128GCMSHA256Ed25519
	_, bob, _, ga, _, _ := setup(t, cs)

	bob2 := newTestClient(t, cs, "bob")
	sub, welcome, err := ga.Branch([]*KeyPackage{bob2.KeyPackage})
	if err != nil {
		t.Fatal(err)
	}
	if next := sub.Epoch(); next != 1 {
		t.Errorf("epoch = %d, want 1", next)
	}
	if got := members(sub.Tree); got != 2 {
		t.Errorf("members = %d, want 2", got)
	}
	g, err := bob2.Resume(send(t, welcome).Welcome, sub.Tree, ga)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(g.EpochAuthenticator(), sub.EpochAuthenticator()) {
		t.Error("joiner did not reach the same epoch")
	}

	// A client that was not in the original group cannot be
	// branched into the subgroup.
	dave := newTestClient(t, cs, "dave")
	sub, welcome, err = ga.Branch([]*KeyPackage{dave.KeyPackage})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dave.Resume(send(t, welcome).Welcome, sub.Tree, ga); !errors.Is(err, ErrNotResumed) {
		t.Errorf("Resume = %v, want %v", err, ErrNotResumed)
	}
	_ = bob
}
