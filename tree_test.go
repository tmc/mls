package mls

//go:generate curl -sSfo testdata/tree-validation.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/tree-validation.json
//go:generate curl -sSfo testdata/tree-operations.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/tree-operations.json

import (
	"bytes"
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
