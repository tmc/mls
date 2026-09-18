package mls

//go:generate curl -sSfo testdata/treekem.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/treekem.json

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/tmc/mls/tlssyntax"
)

type treeKEMVector struct {
	CipherSuite             CipherSuite `json:"cipher_suite"`
	GroupID                 hexBytes    `json:"group_id"`
	Epoch                   uint64      `json:"epoch"`
	ConfirmedTranscriptHash hexBytes    `json:"confirmed_transcript_hash"`
	RatchetTree             hexBytes    `json:"ratchet_tree"`

	LeavesPrivate []struct {
		Index          LeafIndex `json:"index"`
		EncryptionPriv hexBytes  `json:"encryption_priv"`
		SignaturePriv  hexBytes  `json:"signature_priv"`
		PathSecrets    []struct {
			Node       NodeIndex `json:"node"`
			PathSecret hexBytes  `json:"path_secret"`
		} `json:"path_secrets"`
	} `json:"leaves_private"`

	UpdatePaths []struct {
		Sender        LeafIndex  `json:"sender"`
		UpdatePath    hexBytes   `json:"update_path"`
		PathSecrets   []hexBytes `json:"path_secrets"`
		CommitSecret  hexBytes   `json:"commit_secret"`
		TreeHashAfter hexBytes   `json:"tree_hash_after"`
	} `json:"update_paths"`
}

// overlap returns the node of the sender's filtered direct path whose
// path secret the member at leaf j decrypts directly.
func overlap(t RatchetTree, sender, j LeafIndex) NodeIndex {
	for _, x := range t.FilteredDirectPath(sender) {
		if contains(copathChild(x, sender), j) {
			return x
		}
	}
	return 0
}

func TestTreeKEMVectors(t *testing.T) {
	var vectors []treeKEMVector
	loadVectors(t, "treekem", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}
	for i, vec := range vectors {
		t.Run(fmt.Sprintf("%d/%s", i, vec.CipherSuite), func(t *testing.T) {
			if !vec.CipherSuite.Supported() {
				t.Skipf("%s is not implementable with the Go standard library", vec.CipherSuite)
			}
			testTreeKEM(t, &vec)
		})
	}
}

func testTreeKEM(t *testing.T, vec *treeKEMVector) {
	cs := vec.CipherSuite
	var tree RatchetTree
	if err := tlssyntax.Unmarshal(vec.RatchetTree, &tree); err != nil {
		t.Fatalf("ratchet_tree: %v", err)
	}

	// Each member's private state must match the public tree.
	secrets := make(map[LeafIndex]*TreeSecrets)
	sigPriv := make(map[LeafIndex][]byte)
	for _, lp := range vec.LeavesPrivate {
		s := NewTreeSecrets(lp.Index, lp.EncryptionPriv)
		for _, ps := range lp.PathSecrets {
			s.Secrets[ps.Node] = ps.PathSecret
		}
		if tree.Leaf(lp.Index) == nil {
			t.Fatalf("leaf %d is blank", lp.Index)
		}
		if err := s.Consistent(cs, tree); err != nil {
			t.Errorf("leaf %d: private state: %v", lp.Index, err)
		}
		secrets[lp.Index] = s
		sigPriv[lp.Index] = lp.SignaturePriv
	}

	ctx := &GroupContext{
		Version:                 Version10,
		CipherSuite:             cs,
		GroupID:                 vec.GroupID,
		Epoch:                   vec.Epoch,
		ConfirmedTranscriptHash: vec.ConfirmedTranscriptHash,
	}

	members := func(except LeafIndex) []LeafIndex {
		var out []LeafIndex
		for j := LeafIndex(0); j < tree.Size(); j++ {
			if j != except && tree.Leaf(j) != nil && secrets[j] != nil {
				out = append(out, j)
			}
		}
		return out
	}
	clone := func() RatchetTree { return slices.Clone(tree) }
	private := func(j LeafIndex) *TreeSecrets {
		s := secrets[j]
		c := NewTreeSecrets(s.Index, s.Leaf)
		for x, v := range s.Secrets {
			c.Secrets[x] = v
		}
		return c
	}

	for _, up := range vec.UpdatePaths {
		var path UpdatePath
		if err := tlssyntax.Unmarshal(up.UpdatePath, &path); err != nil {
			t.Fatalf("update_path from %d: %v", up.Sender, err)
		}

		after := clone()
		if err := after.MergeUpdatePath(cs, up.Sender, &path); err != nil {
			t.Fatalf("merge update path from %d: %v", up.Sender, err)
		}
		if got, err := after.RootHash(cs); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(got, up.TreeHashAfter) {
			t.Errorf("tree hash after update from %d = %x, want %x", up.Sender, got, up.TreeHashAfter)
		}
		if err := after.VerifyParentHashes(cs); err != nil {
			t.Errorf("parent hashes after update from %d: %v", up.Sender, err)
		}

		for _, j := range members(up.Sender) {
			s := private(j)
			commit, err := after.DecryptPathSecrets(cs, up.Sender, &path, ctx, s)
			if err != nil {
				t.Errorf("leaf %d: decrypt path from %d: %v", j, up.Sender, err)
				continue
			}
			if want := up.PathSecrets[j]; !bytes.Equal(s.Secrets[overlap(tree, up.Sender, j)], want) {
				t.Errorf("leaf %d: path secret = %x, want %x", j, s.Secrets[overlap(tree, up.Sender, j)], want)
			}
			if !bytes.Equal(commit, up.CommitSecret) {
				t.Errorf("leaf %d: commit secret = %x, want %x", j, commit, up.CommitSecret)
			}
		}

		// Create a fresh update path from the same sender and check
		// that every other member arrives at the same commit secret.
		if sigPriv[up.Sender] == nil {
			continue
		}
		mine := clone()
		leafSecret := bytes.Repeat([]byte{byte(up.Sender) + 1}, cs.HashSize())
		fresh, _, commitSecret, err := mine.CreateUpdatePath(cs, up.Sender, leafSecret, sigPriv[up.Sender], ctx, nil)
		if err != nil {
			t.Fatalf("create update path from %d: %v", up.Sender, err)
		}
		if err := mine.VerifyParentHashes(cs); err != nil {
			t.Errorf("new path from %d: parent hashes: %v", up.Sender, err)
		}
		if err := fresh.LeafNode.Verify(cs, vec.GroupID, up.Sender); err != nil {
			t.Errorf("new path from %d: leaf signature: %v", up.Sender, err)
		}
		theirs := clone()
		if err := theirs.MergeUpdatePath(cs, up.Sender, fresh); err != nil {
			t.Fatalf("merge new path from %d: %v", up.Sender, err)
		}
		for _, j := range members(up.Sender) {
			commit, err := theirs.DecryptPathSecrets(cs, up.Sender, fresh, ctx, private(j))
			if err != nil {
				t.Errorf("leaf %d: decrypt new path from %d: %v", j, up.Sender, err)
				continue
			}
			if !bytes.Equal(commit, commitSecret) {
				t.Errorf("leaf %d: new commit secret = %x, want %x", j, commit, commitSecret)
			}
		}
	}
}
