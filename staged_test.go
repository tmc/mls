package mls

import (
	"bytes"
	"testing"
)

// stageUpdate has b propose a key rotation and a remember it, the way
// a committer stages the proposals it saw in the epoch. It returns
// the leaf the rotation installs.
func stageUpdate(t *testing.T, a, b *Group) *LeafNode {
	t.Helper()
	leaf, encPriv, _ := rotate(t, b, nil)
	m, err := b.ProposeUpdate(leaf, encPriv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.Unprotect(send(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddProposal(c); err != nil {
		t.Fatal(err)
	}
	return leaf
}

// A member that rotates twice in one epoch supersedes its own first
// update. Carrying both would cover one leaf twice, which Section
// 12.2 forbids, and nothing outside the package can drop either one.
func TestStagedUpdateSupersedes(t *testing.T) {
	a, b, _ := threeMember(t)
	stageUpdate(t, a, b)
	second := stageUpdate(t, a, b)
	if n := len(a.proposals); n != 1 {
		t.Errorf("after two updates from one leaf, %d staged, want 1", n)
	}
	a2, msg, _, err := a.Commit(nil)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got := a2.Tree.Leaf(b.Index).EncryptionKey; !bytes.Equal(got, second.EncryptionKey) {
		t.Error("the commit applied the superseded update, not the later one")
	}
	// The proposer must still be able to follow it.
	if _, err := b.Handle(send(t, msg)); err != nil {
		t.Errorf("the proposer cannot follow its own update: %v", err)
	}
}

// A staged update must not keep the committer from removing the
// member that sent it. One update was enough to make a member
// unremovable for the rest of the epoch.
func TestStagedUpdateDoesNotBlockRemove(t *testing.T) {
	a, b, _ := threeMember(t)
	stageUpdate(t, a, b)
	a2, _, _, err := a.Commit([]*Proposal{{Type: ProposalTypeRemove, Remove: &Remove{Removed: uint32(b.Index)}}})
	if err != nil {
		t.Fatalf("commit removing the proposer: %v", err)
	}
	if a2.Tree.Leaf(b.Index) != nil {
		t.Error("the member is still in the tree")
	}
}

// A removal staged before an update of the same leaf is not undone by
// it: the leaf is removed and the update is left behind.
func TestStagedRemoveBeatsUpdate(t *testing.T) {
	a, b, c := threeMember(t)
	m, err := c.Propose(&Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: uint32(b.Index)}})
	if err != nil {
		t.Fatal(err)
	}
	ac, err := a.Unprotect(send(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddProposal(ac); err != nil {
		t.Fatal(err)
	}
	stageUpdate(t, a, b)
	a2, _, _, err := a.Commit(nil)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if a2.Tree.Leaf(b.Index) != nil {
		t.Error("an update saved the leaf a staged removal covered")
	}
}

// A commit still carries the proposals it should: two members rotate,
// both updates are applied, and an unrelated staged proposal is not
// dropped by the conflict rules.
func TestStagedNoConflict(t *testing.T) {
	a, b, c := threeMember(t)
	bl := stageUpdate(t, a, b)
	cl := stageUpdate(t, a, c)
	a2, _, _, err := a.Commit(nil)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !bytes.Equal(a2.Tree.Leaf(b.Index).EncryptionKey, bl.EncryptionKey) ||
		!bytes.Equal(a2.Tree.Leaf(c.Index).EncryptionKey, cl.EncryptionKey) {
		t.Error("a commit dropped an update that conflicted with nothing")
	}
}
