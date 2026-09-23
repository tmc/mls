package mls

//go:generate curl -sSfo testdata/tree-validation.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/tree-validation.json
//go:generate curl -sSfo testdata/tree-operations.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/tree-operations.json

import (
	"bytes"
	"fmt"
	"slices"
	"testing"
)

func TestTreeValidationVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite CipherSuite `json:"cipher_suite"`
		Tree        hexBytes    `json:"tree"`
		GroupID     hexBytes    `json:"group_id"`
		Resolutions [][]uint32  `json:"resolutions"`
		TreeHashes  []hexBytes  `json:"tree_hashes"`
	}
	loadVectors(t, "tree-validation", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}
	for i, vec := range vectors {
		cs := vec.CipherSuite
		if !cs.Supported() {
			continue
		}
		var tree RatchetTree
		if err := Unmarshal(vec.Tree, &tree); err != nil {
			t.Errorf("vector %d: Unmarshal tree: %v", i, err)
			continue
		}
		for x, want := range vec.Resolutions {
			got := tree.Resolution(NodeIndex(x))
			if len(got) != len(want) {
				t.Errorf("vector %d: resolution(%d) = %v, want %v", i, x, got, want)
				continue
			}
			for j := range got {
				if uint32(got[j]) != want[j] {
					t.Errorf("vector %d: resolution(%d) = %v, want %v", i, x, got, want)
					break
				}
			}
		}
		for x, want := range vec.TreeHashes {
			got, err := tree.TreeHash(cs, NodeIndex(x))
			if err != nil {
				t.Errorf("vector %d: TreeHash(%d): %v", i, x, err)
				continue
			}
			if !bytes.Equal(got, want) {
				t.Errorf("vector %d: TreeHash(%d) = %x, want %x", i, x, got, want)
			}
		}
		if err := tree.VerifyParentHashes(cs); err != nil {
			t.Errorf("vector %d: VerifyParentHashes: %v", i, err)
		}
		if err := tree.VerifyLeafSignatures(cs, vec.GroupID); err != nil {
			t.Errorf("vector %d: VerifyLeafSignatures: %v", i, err)
		}
	}
}

func TestTreeOperationVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite    CipherSuite `json:"cipher_suite"`
		TreeBefore     hexBytes    `json:"tree_before"`
		Proposal       hexBytes    `json:"proposal"`
		ProposalSender uint32      `json:"proposal_sender"`
		TreeHashBefore hexBytes    `json:"tree_hash_before"`
		TreeAfter      hexBytes    `json:"tree_after"`
		TreeHashAfter  hexBytes    `json:"tree_hash_after"`
	}
	loadVectors(t, "tree-operations", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}
	for i, vec := range vectors {
		cs := vec.CipherSuite
		if !cs.Supported() {
			continue
		}
		var tree RatchetTree
		if err := Unmarshal(vec.TreeBefore, &tree); err != nil {
			t.Errorf("vector %d: Unmarshal tree: %v", i, err)
			continue
		}
		if got, err := tree.RootHash(cs); err != nil {
			t.Errorf("vector %d: RootHash: %v", i, err)
		} else if !bytes.Equal(got, vec.TreeHashBefore) {
			t.Errorf("vector %d: tree hash before = %x, want %x", i, got, vec.TreeHashBefore)
		}

		var p Proposal
		if err := Unmarshal(vec.Proposal, &p); err != nil {
			t.Errorf("vector %d: Unmarshal proposal: %v", i, err)
			continue
		}
		switch p.Type {
		case ProposalTypeAdd:
			tree.Add(&p.Add.KeyPackage.LeafNode)
		case ProposalTypeUpdate:
			tree.Update(LeafIndex(vec.ProposalSender), &p.Update.LeafNode)
		case ProposalTypeRemove:
			tree.Remove(LeafIndex(p.Remove.Removed))
		default:
			t.Errorf("vector %d: unexpected proposal type %s", i, p.Type)
			continue
		}

		if got, err := Marshal(&tree); err != nil {
			t.Errorf("vector %d: Marshal tree: %v", i, err)
		} else if !bytes.Equal(got, vec.TreeAfter) {
			t.Errorf("vector %d: %s: tree after = %x, want %x", i, p.Type, got, vec.TreeAfter)
		}
		if got, err := tree.RootHash(cs); err != nil {
			t.Errorf("vector %d: RootHash: %v", i, err)
		} else if !bytes.Equal(got, vec.TreeHashAfter) {
			t.Errorf("vector %d: tree hash after = %x, want %x", i, got, vec.TreeHashAfter)
		}
	}
}

// groupOf returns the committer's view of a group of n members.
func groupOf(t *testing.T, n int) *Group {
	t.Helper()
	cs := X25519AES128GCMSHA256Ed25519
	alice := newTestClient(t, cs, "alice")
	g, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var ps []*Proposal
	for i := 1; i < n; i++ {
		c := newTestClient(t, cs, fmt.Sprintf("member%d", i))
		ps = append(ps, &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *c.KeyPackage}})
	}
	if g, _, _, err = g.Commit(ps); err != nil {
		t.Fatal(err)
	}
	return g
}

// parents returns the indices of the tree's non-blank parent nodes.
func parents(t RatchetTree) []NodeIndex {
	var xs []NodeIndex
	for x := NodeIndex(1); int(x) < len(t); x += 2 {
		if n := t.Node(x); n != nil && n.Parent != nil {
			xs = append(xs, x)
		}
	}
	return xs
}

// One encryption key must not appear at two nodes: its holder reads
// both. See RFC 9420, Section 12.4.
func TestVerifyNodeKeys(t *testing.T) {
	g := groupOf(t, 4)
	if err := g.Tree.verifyNodeKeys(); err != nil {
		t.Fatalf("a legitimate tree was rejected: %v", err)
	}
	xs := parents(g.Tree)
	if len(xs) < 2 {
		t.Fatalf("tree has %d populated parents, want at least 2", len(xs))
	}
	for _, tt := range []struct {
		name string
		bad  func(RatchetTree)
	}{
		{"parent at a parent", func(tr RatchetTree) {
			tr.Node(xs[1]).Parent.EncryptionKey = tr.Node(xs[0]).Parent.EncryptionKey
		}},
		{"parent at a leaf", func(tr RatchetTree) {
			tr.Leaf(1).EncryptionKey = tr.Node(xs[0]).Parent.EncryptionKey
		}},
		{"leaf at a leaf", func(tr RatchetTree) {
			tr.Leaf(1).EncryptionKey = tr.Leaf(0).EncryptionKey
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tr := g.Tree.Clone()
			tt.bad(tr)
			if err := tr.verifyNodeKeys(); err != ErrDuplicateNodeKey {
				t.Errorf("verifyNodeKeys = %v, want %v", err, ErrDuplicateNodeKey)
			}
		})
	}
}

// unmergedGroup returns a group whose tree has a leaf that is
// unmerged in a parent above it. That takes a tree wide enough to
// survive a removal: eight members, remove leaf 5, a commit from leaf
// 4 to repopulate the node two levels above the hole, then an Add
// that refills leaf 5 under it. An added leaf is unmerged in every
// parent above it that the committer's own path does not replace.
// The parent directly above a blank leaf cannot be populated while
// the leaf is blank, because the filtered direct path skips a parent
// whose copath child resolves to nothing, so the entry appears one
// level higher.
func unmergedGroup(t *testing.T) *Group {
	t.Helper()
	cs := X25519AES128GCMSHA256Ed25519
	alice := newTestClient(t, cs, "alice")
	erin := newTestClient(t, cs, "erin")
	g, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	add := func(c *Client) *Proposal {
		return &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *c.KeyPackage}}
	}
	ps := []*Proposal{
		add(newTestClient(t, cs, "bob")),
		add(newTestClient(t, cs, "carol")),
		add(newTestClient(t, cs, "dave")),
		add(erin),
		add(newTestClient(t, cs, "frank")),
		add(newTestClient(t, cs, "grace")),
		add(newTestClient(t, cs, "heidi")),
	}
	g, _, w, err := g.Commit(ps)
	if err != nil {
		t.Fatal(err)
	}
	eg, err := erin.Join(send(t, w).Welcome, nil)
	if err != nil {
		t.Fatal(err)
	}
	g, msg, _, err := g.Commit([]*Proposal{{Type: ProposalTypeRemove, Remove: &Remove{Removed: 5}}})
	if err != nil {
		t.Fatal(err)
	}
	if eg, err = eg.Handle(send(t, msg)); err != nil {
		t.Fatal(err)
	}
	eg, msg, _, err = eg.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	if g, err = g.Handle(send(t, msg)); err != nil {
		t.Fatal(err)
	}
	if g, _, _, err = g.Commit([]*Proposal{add(newTestClient(t, cs, "ivan"))}); err != nil {
		t.Fatal(err)
	}
	return g
}

// A parent's unmerged_leaves must name leaves below it, in order,
// that are not blank and that the nodes in between agree on. The list
// steers node resolution, and so who a commit encrypts path secrets
// to. See RFC 9420, Section 12.4.3.1.
func TestVerifyUnmergedLeaves(t *testing.T) {
	g := unmergedGroup(t)
	if err := g.Tree.verifyUnmergedLeaves(); err != nil {
		t.Fatalf("a legitimate tree was rejected: %v", err)
	}
	// Node 11 covers leaves 4 through 7 and lists leaf 5, which
	// the fixture exists to produce. Without it the cases below
	// would prove nothing.
	if n := g.Tree.Node(11); n == nil || n.Parent == nil || !slices.Contains(n.Parent.UnmergedLeaves, 5) {
		t.Fatalf("fixture does not have leaf 5 unmerged at node 11")
	}
	for _, tt := range []struct {
		name string
		bad  func(RatchetTree)
	}{
		{"not below the node", func(tr RatchetTree) {
			tr.Node(11).Parent.UnmergedLeaves = []uint32{0}
		}},
		{"out of range", func(tr RatchetTree) {
			tr.Node(11).Parent.UnmergedLeaves = []uint32{99}
		}},
		{"out of order", func(tr RatchetTree) {
			tr.Node(11).Parent.UnmergedLeaves = []uint32{6, 5}
		}},
		{"repeated", func(tr RatchetTree) {
			tr.Node(11).Parent.UnmergedLeaves = []uint32{5, 5}
		}},
		{"blank leaf", func(tr RatchetTree) {
			tr.Node(11).Parent.UnmergedLeaves = []uint32{4}
			tr[LeafIndex(4).NodeIndex()] = nil
		}},
		{"intermediate node disagrees", func(tr RatchetTree) {
			// Node 9 sits between leaf 5 and node 11. A
			// group never populates it while leaf 5 is
			// blank, but a tree that arrives in a Welcome
			// can say anything.
			tr[9] = &Node{Type: NodeTypeParent, Parent: &ParentNode{
				EncryptionKey: []byte("not a key any member holds"),
			}}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tr := g.Tree.Clone()
			tt.bad(tr)
			if err := tr.verifyUnmergedLeaves(); err != ErrBadUnmergedLeaves {
				t.Errorf("verifyUnmergedLeaves = %v, want %v", err, ErrBadUnmergedLeaves)
			}
		})
	}
}

// A leaf index at or past the size of the tree names no leaf,
// however large. LeafIndex.NodeIndex wraps at 1<<31, which once made
// Leaf(1<<31+1) return leaf 1.
func TestLeafRange(t *testing.T) {
	tr := groupOf(t, 2).Tree
	for _, i := range []LeafIndex{2, 3, 1 << 31, 1<<31 + 1, 1<<32 - 1} {
		if tr.Leaf(i) != nil {
			t.Errorf("Leaf(%d) = non-nil, want nil", i)
		}
	}
}

// The tree operations must be total in the leaf index: an index past
// the tree once made directPath loop forever, and one past 1<<31
// wrapped around to another member's leaf.
func TestTreeOutOfRange(t *testing.T) {
	g := groupOf(t, 2)
	cs := g.CipherSuite
	want, err := Marshal(&g.Tree)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []LeafIndex{2, 3, 1 << 31, 1<<31 + 1} {
		tr := g.Tree.Clone()
		tr.Remove(i)
		tr.Update(i, g.Tree.Leaf(0))
		if got, err := Marshal(&tr); err != nil || !bytes.Equal(got, want) {
			t.Errorf("Remove and Update of leaf %d changed the tree", i)
		}
		if got := tr.FilteredDirectPath(i); got != nil {
			t.Errorf("FilteredDirectPath(%d) = %v, want nil", i, got)
		}
		if err := tr.MergeUpdatePath(cs, i, &UpdatePath{}); err != ErrLeafRange {
			t.Errorf("MergeUpdatePath(%d) = %v, want %v", i, err, ErrLeafRange)
		}
		if _, err := tr.DecryptPathSecrets(cs, i, &UpdatePath{}, &g.Context, g.Secrets, nil); err != ErrLeafRange {
			t.Errorf("DecryptPathSecrets(%d) = %v, want %v", i, err, ErrLeafRange)
		}
		s := NewTreeSecrets(i, nil)
		if err := s.SetPath(cs, tr, 1, nil); err != ErrLeafRange {
			t.Errorf("SetPath(%d) = %v, want %v", i, err, ErrLeafRange)
		}
	}
}
