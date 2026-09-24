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

			// One tree serves both content types: taking a
			// leaf's application ratchet must not consume its
			// handshake ratchet.
			tree := newSecretTree(cs, LeafIndex(len(vec.Leaves)), vec.EncryptionSecret)
			for _, ct := range []ContentType{ContentTypeApplication, ContentTypeProposal} {
				for i, steps := range vec.Leaves {
					leaf := LeafIndex(i)
					r, err := tree.ratchet(leaf, ct)
					if err != nil {
						t.Fatalf("leaf %d: ratchet: %v", i, err)
					}
					for _, step := range steps {
						key, nonce, advance, err := r.Key(step.Generation)
						if err != nil {
							t.Fatalf("leaf %d: Key(%d): %v", i, step.Generation, err)
						}
						advance()
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

// A ratchet is spent only when the caller says so, and refuses a jump
// it cannot afford.
func TestRatchetKeyBounds(t *testing.T) {
	cs := testSuite()
	tr := newSecretTree(cs, 2, make([]byte, cs.HashSize()))
	r, err := tr.ratchet(0, ContentTypeApplication)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := r.Key(maxGenerationJump + 1); err != ErrGenerationJump {
		t.Errorf("Key(maxGenerationJump+1) = %v, want %v", err, ErrGenerationJump)
	}
	if r.Generation() != 0 {
		t.Errorf("a refused jump advanced the ratchet to %d", r.Generation())
	}
	_, _, advance, err := r.Key(3)
	if err != nil {
		t.Fatalf("Key(3): %v", err)
	}
	if r.Generation() != 0 {
		t.Errorf("generation = %d before advance, want 0", r.Generation())
	}
	advance()
	if r.Generation() != 4 {
		t.Errorf("generation = %d after advance, want 4", r.Generation())
	}
	if _, _, _, err := r.Key(3); err != ErrConsumed {
		t.Errorf("Key(3) replayed = %v, want %v", err, ErrConsumed)
	}
}

// A ratchet keeps the keys it skips, for messages that arrive late,
// until they are used or fall too far behind.
func TestRatchetSkippedKeys(t *testing.T) {
	cs := testSuite()
	newRatchet := func() *ratchet {
		tr := newSecretTree(cs, 2, make([]byte, cs.HashSize()))
		r, err := tr.ratchet(0, ContentTypeApplication)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	var want []keyNonce
	for fresh := newRatchet(); len(want) < 4; {
		key, nonce, err := fresh.Next()
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, keyNonce{key, nonce})
	}

	r := newRatchet()
	for _, gen := range []uint32{3, 1, 0, 2} {
		key, nonce, consume, err := r.Key(gen)
		if err != nil {
			t.Fatalf("Key(%d): %v", gen, err)
		}
		if !bytes.Equal(key, want[gen].key) || !bytes.Equal(nonce, want[gen].nonce) {
			t.Errorf("Key(%d) = %x/%x, want %x/%x", gen, key, nonce, want[gen].key, want[gen].nonce)
		}
		consume()
		if _, _, _, err := r.Key(gen); err != ErrConsumed {
			t.Errorf("Key(%d) after use = %v, want %v", gen, err, ErrConsumed)
		}
	}
	if len(r.skipped) != 0 {
		t.Errorf("%d skipped keys left after all were used", len(r.skipped))
	}

	// A key left unused is dropped once the ratchet is
	// maxGenerationJump past it.
	_, _, consume, err := r.Key(5)
	if err != nil {
		t.Fatal(err)
	}
	consume()
	if _, _, consume, err = r.Key(5 + maxGenerationJump); err != nil {
		t.Fatal(err)
	}
	consume()
	if _, _, _, err := r.Key(4); err != ErrConsumed {
		t.Errorf("Key(4) far behind = %v, want %v", err, ErrConsumed)
	}
	if len(r.skipped) > maxGenerationJump {
		t.Errorf("ratchet keeps %d skipped keys, want at most %d", len(r.skipped), maxGenerationJump)
	}
}
