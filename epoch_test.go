package mls

import (
	"bytes"
	"testing"
)

// TestEpochIsolation checks that moving to a new epoch leaves the old
// group untouched, as the documentation of Group promises. The tree
// is the part that is easy to get wrong: its nodes are pointers, so a
// copy of the array alone still shares them, and RatchetTree.Add
// writes to the nodes above the leaf it fills.
func TestEpochIsolation(t *testing.T) {
	cs := testSuite()
	add := func(c *Client) *Proposal {
		return &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *c.KeyPackage}}
	}
	hash := func(t *testing.T, g *Group) []byte {
		t.Helper()
		h, err := g.Tree.RootHash(cs)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}

	// A group of four that then removes leaf 1, so that the next
	// Add refills a blank leaf whose direct path already exists.
	// Filling a leaf past the end of the array instead would grow
	// the array and touch no shared node.
	alice := newTestClient(t, cs, "alice")
	g, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	g, _, _, err = g.Commit([]*Proposal{
		add(newTestClient(t, cs, "bob")),
		add(newTestClient(t, cs, "carol")),
		add(newTestClient(t, cs, "dave")),
	})
	if err != nil {
		t.Fatal(err)
	}
	g, _, _, err = g.Commit([]*Proposal{{Type: ProposalTypeRemove, Remove: &Remove{Removed: 1}}})
	if err != nil {
		t.Fatal(err)
	}

	erin := newTestClient(t, cs, "erin")
	want := hash(t, g)
	next, _, welcome, err := g.Commit([]*Proposal{add(erin)})
	if err != nil {
		t.Fatal(err)
	}
	if got := hash(t, g); !bytes.Equal(got, want) {
		t.Errorf("Commit changed the committer's old tree:\n got %x\nwant %x", got, want)
	}

	// Erin joins against next.Tree, which the caller still holds;
	// her group must not share it.
	eg, err := erin.Join(send(t, welcome).Welcome, next.Tree)
	if err != nil {
		t.Fatal(err)
	}
	want = hash(t, next)
	if _, _, _, err := eg.Commit(nil); err != nil {
		t.Fatal(err)
	}
	if got := hash(t, next); !bytes.Equal(got, want) {
		t.Errorf("a joiner's commit changed the tree it joined against:\n got %x\nwant %x", got, want)
	}

	// Handling a commit must leave the epoch it was handled in
	// alone, for a member that keeps the old epoch to process
	// messages still in flight.
	frank := newTestClient(t, cs, "frank")
	_, commit, _, err := next.Commit([]*Proposal{add(frank)})
	if err != nil {
		t.Fatal(err)
	}
	want = hash(t, eg)
	if _, _, err := eg.Handle(send(t, commit)); err != nil {
		t.Fatal(err)
	}
	if got := hash(t, eg); !bytes.Equal(got, want) {
		t.Errorf("Handle changed the epoch it was handled in:\n got %x\nwant %x", got, want)
	}
}
