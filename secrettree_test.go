package mls

//go:generate curl -sSfo testdata/secret-tree.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/secret-tree.json

import (
	"bytes"
	"strconv"
	"testing"
)

type secretTreeVector struct {
	CipherSuite      CipherSuite `json:"cipher_suite"`
	EncryptionSecret hexBytes    `json:"encryption_secret"`
	SenderData       struct {
		SenderDataSecret hexBytes `json:"sender_data_secret"`
		Ciphertext       hexBytes `json:"ciphertext"`
		Key              hexBytes `json:"key"`
		Nonce            hexBytes `json:"nonce"`
	} `json:"sender_data"`
	Leaves [][]struct {
		Generation       uint32   `json:"generation"`
		ApplicationKey   hexBytes `json:"application_key"`
		ApplicationNonce hexBytes `json:"application_nonce"`
		HandshakeKey     hexBytes `json:"handshake_key"`
		HandshakeNonce   hexBytes `json:"handshake_nonce"`
	} `json:"leaves"`
}

func TestSecretTreeVectors(t *testing.T) {
	var vectors []secretTreeVector
	loadVectors(t, "secret-tree", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}
	for _, vec := range vectors {
		cs := vec.CipherSuite
		t.Run(cs.String(), func(t *testing.T) {
			if !cs.Supported() {
				t.Skipf("%s is not implementable with the Go standard library", cs)
			}
			d := vec.SenderData
			key, nonce, err := cs.SenderDataKey(d.SenderDataSecret, d.Ciphertext)
			if err != nil {
				t.Fatalf("SenderDataKey: %v", err)
			}
			if !bytes.Equal(key, d.Key) || !bytes.Equal(nonce, d.Nonce) {
				t.Errorf("SenderDataKey = %x/%x, want %x/%x", key, nonce, d.Key, d.Nonce)
			}

			n := LeafIndex(len(vec.Leaves))
			// Each ratchet may be taken only once, so build a
			// fresh tree for each content type.
			for _, ct := range []ContentType{ContentTypeApplication, ContentTypeProposal} {
				tree := NewSecretTree(cs, n, vec.EncryptionSecret)
				for i, steps := range vec.Leaves {
					leaf := LeafIndex(i)
					r, err := tree.Ratchet(leaf, ct)
					if err != nil {
						t.Fatalf("leaf %d: Ratchet: %v", i, err)
					}
					for _, step := range steps {
						key, nonce, err := r.Key(step.Generation)
						if err != nil {
							t.Fatalf("leaf %d: Key(%d): %v", i, step.Generation, err)
						}
						wantKey, wantNonce := step.ApplicationKey, step.ApplicationNonce
						if ct != ContentTypeApplication {
							wantKey, wantNonce = step.HandshakeKey, step.HandshakeNonce
						}
						name := "leaf " + strconv.Itoa(i) + " generation " + strconv.FormatUint(uint64(step.Generation), 10)
						if !bytes.Equal(key, wantKey) {
							t.Errorf("%s: key = %x, want %x", name, key, wantKey)
						}
						if !bytes.Equal(nonce, wantNonce) {
							t.Errorf("%s: nonce = %x, want %x", name, nonce, wantNonce)
						}
					}
				}
			}
		})
	}
}
