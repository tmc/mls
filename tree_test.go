package mls

//go:generate curl -sSfo testdata/tree-validation.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/tree-validation.json
//go:generate curl -sSfo testdata/tree-operations.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/tree-operations.json

import (
	"bytes"
	"fmt"
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
