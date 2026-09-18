package mls

//go:generate curl -sSfo testdata/crypto-basics.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/crypto-basics.json

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// hexBytes decodes a hex string from a JSON test vector.
type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*h = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = b
	return nil
}

type cryptoVector struct {
	CipherSuite CipherSuite `json:"cipher_suite"`

	RefHash struct {
		Label string   `json:"label"`
		Value hexBytes `json:"value"`
		Out   hexBytes `json:"out"`
	} `json:"ref_hash"`

	ExpandWithLabel struct {
		Secret  hexBytes `json:"secret"`
		Label   string   `json:"label"`
		Context hexBytes `json:"context"`
		Length  uint16   `json:"length"`
		Out     hexBytes `json:"out"`
	} `json:"expand_with_label"`

	DeriveSecret struct {
		Secret hexBytes `json:"secret"`
		Label  string   `json:"label"`
		Out    hexBytes `json:"out"`
	} `json:"derive_secret"`

	DeriveTreeSecret struct {
		Secret     hexBytes `json:"secret"`
		Label      string   `json:"label"`
		Generation uint32   `json:"generation"`
		Length     uint16   `json:"length"`
		Out        hexBytes `json:"out"`
	} `json:"derive_tree_secret"`

	SignWithLabel struct {
		Priv      hexBytes `json:"priv"`
		Pub       hexBytes `json:"pub"`
		Content   hexBytes `json:"content"`
		Label     string   `json:"label"`
		Signature hexBytes `json:"signature"`
	} `json:"sign_with_label"`

	EncryptWithLabel struct {
		Priv       hexBytes `json:"priv"`
		Pub        hexBytes `json:"pub"`
		Label      string   `json:"label"`
		Context    hexBytes `json:"context"`
		Plaintext  hexBytes `json:"plaintext"`
		KEMOutput  hexBytes `json:"kem_output"`
		Ciphertext hexBytes `json:"ciphertext"`
	} `json:"encrypt_with_label"`
}

func loadVectors(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

func TestCryptoBasicsVectors(t *testing.T) {
	var vectors []cryptoVector
	loadVectors(t, "crypto-basics", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}
	for _, vec := range vectors {
		cs := vec.CipherSuite
		t.Run(cs.String(), func(t *testing.T) {
			if !cs.Supported() {
				t.Skipf("%s is not implementable with the Go standard library", cs)
			}

			r := vec.RefHash
			if got, err := cs.RefHash(r.Label, r.Value); err != nil {
				t.Errorf("RefHash: %v", err)
			} else if !bytes.Equal(got, r.Out) {
				t.Errorf("RefHash = %x, want %x", got, r.Out)
			}

			e := vec.ExpandWithLabel
			if got, err := cs.ExpandWithLabel(e.Secret, e.Label, e.Context, e.Length); err != nil {
				t.Errorf("ExpandWithLabel: %v", err)
			} else if !bytes.Equal(got, e.Out) {
				t.Errorf("ExpandWithLabel = %x, want %x", got, e.Out)
			}

			d := vec.DeriveSecret
			if got, err := cs.DeriveSecret(d.Secret, d.Label); err != nil {
				t.Errorf("DeriveSecret: %v", err)
			} else if !bytes.Equal(got, d.Out) {
				t.Errorf("DeriveSecret = %x, want %x", got, d.Out)
			}

			dt := vec.DeriveTreeSecret
			if got, err := cs.DeriveTreeSecret(dt.Secret, dt.Label, dt.Generation, dt.Length); err != nil {
				t.Errorf("DeriveTreeSecret: %v", err)
			} else if !bytes.Equal(got, dt.Out) {
				t.Errorf("DeriveTreeSecret = %x, want %x", got, dt.Out)
			}

			// Signatures are randomized for ECDSA, so check the
			// vector's signature rather than reproducing it, then
			// check that our own signatures verify.
			s := vec.SignWithLabel
			if err := cs.VerifyWithLabel(SignaturePublicKey(s.Pub), s.Label, s.Content, s.Signature); err != nil {
				t.Errorf("VerifyWithLabel: %v", err)
			}
			if sig, err := cs.SignWithLabel(s.Priv, s.Label, s.Content); err != nil {
				t.Errorf("SignWithLabel: %v", err)
			} else if err := cs.VerifyWithLabel(SignaturePublicKey(s.Pub), s.Label, s.Content, sig); err != nil {
				t.Errorf("VerifyWithLabel of our own signature: %v", err)
			}

			// HPKE encryption is randomized too: decrypt the
			// vector, then round-trip our own ciphertext.
			c := vec.EncryptWithLabel
			ct := &HPKECiphertext{KEMOutput: c.KEMOutput, Ciphertext: c.Ciphertext}
			if got, err := cs.DecryptWithLabel(c.Priv, c.Label, c.Context, ct); err != nil {
				t.Errorf("DecryptWithLabel: %v", err)
			} else if !bytes.Equal(got, c.Plaintext) {
				t.Errorf("DecryptWithLabel = %x, want %x", got, c.Plaintext)
			}
			mine, err := cs.EncryptWithLabel(HPKEPublicKey(c.Pub), c.Label, c.Context, c.Plaintext)
			if err != nil {
				t.Fatalf("EncryptWithLabel: %v", err)
			}
			if got, err := cs.DecryptWithLabel(c.Priv, c.Label, c.Context, mine); err != nil {
				t.Errorf("DecryptWithLabel of our own ciphertext: %v", err)
			} else if !bytes.Equal(got, c.Plaintext) {
				t.Errorf("round trip = %x, want %x", got, c.Plaintext)
			}
		})
	}
}
