package hpkex448

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/tmc/mls/internal/x448"
)

// hexBytes is a byte string encoded in JSON as hex.
type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	var err error
	*h, err = hex.DecodeString(s)
	return err
}

// TestVectors runs the DHKEM(X448, HKDF-SHA512), HKDF-SHA512 base-mode
// vectors of the CFRG HPKE draft repository, which RFC 9180,
// Appendix A, abridges. testdata/rfc9180-x448.json keeps, of each
// vector, the encryptions at sequence numbers 0, 1, 255 and 256.
func TestVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/rfc9180-x448.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		AEAD           AEAD     `json:"aead_id"`
		Info           hexBytes `json:"info"`
		IKME           hexBytes `json:"ikmE"`
		IKMR           hexBytes `json:"ikmR"`
		SKRm           hexBytes `json:"skRm"`
		PKRm           hexBytes `json:"pkRm"`
		SKEm           hexBytes `json:"skEm"`
		PKEm           hexBytes `json:"pkEm"`
		Enc            hexBytes `json:"enc"`
		SharedSecret   hexBytes `json:"shared_secret"`
		BaseNonce      hexBytes `json:"base_nonce"`
		ExporterSecret hexBytes `json:"exporter_secret"`
		Encryptions    []struct {
			Seq   uint64   `json:"seq"`
			AAD   hexBytes `json:"aad"`
			CT    hexBytes `json:"ct"`
			Nonce hexBytes `json:"nonce"`
			PT    hexBytes `json:"pt"`
		} `json:"encryptions"`
		Exports []struct {
			Context hexBytes `json:"exporter_context"`
			L       int      `json:"L"`
			Value   hexBytes `json:"exported_value"`
		} `json:"exports"`
	}
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 3 {
		t.Fatalf("got %d vectors, want 3", len(vectors))
	}
	for _, v := range vectors {
		t.Run(hex.EncodeToString([]byte{byte(v.AEAD)}), func(t *testing.T) {
			for _, kp := range []struct {
				name        string
				ikm, sk, pk []byte
			}{
				{"recipient", v.IKMR, v.SKRm, v.PKRm},
				{"ephemeral", v.IKME, v.SKEm, v.PKEm},
			} {
				sk, pk, err := DeriveKeyPair(kp.ikm)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(sk, kp.sk) || !bytes.Equal(pk, kp.pk) {
					t.Fatalf("DeriveKeyPair(%s) = %x, %x, want %x, %x", kp.name, sk, pk, kp.sk, kp.pk)
				}
			}

			enc, sender, err := newSender(v.PKRm, v.SKEm, v.AEAD, v.Info)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(enc, v.Enc) {
				t.Fatalf("enc = %x, want %x", enc, v.Enc)
			}
			recipient, err := NewRecipient(enc, v.SKRm, v.AEAD, v.Info)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []*Context{sender, recipient} {
				if !bytes.Equal(c.baseNonce, v.BaseNonce) {
					t.Errorf("base nonce = %x, want %x", c.baseNonce, v.BaseNonce)
				}
				if !bytes.Equal(c.exporter, v.ExporterSecret) {
					t.Errorf("exporter secret = %x, want %x", c.exporter, v.ExporterSecret)
				}
			}
			dh, err := x448.X448(v.SKEm, v.PKRm)
			if err != nil {
				t.Fatal(err)
			}
			shared, err := extractAndExpand(dh, enc, v.PKRm)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(shared, v.SharedSecret) {
				t.Errorf("shared secret = %x, want %x", shared, v.SharedSecret)
			}

			for _, e := range v.Encryptions {
				sender.seq, recipient.seq = e.Seq, e.Seq
				nonce, err := sender.nonce()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(nonce, e.Nonce) {
					t.Errorf("seq %d: nonce = %x, want %x", e.Seq, nonce, e.Nonce)
				}
				ct, err := sender.Seal(e.AAD, e.PT)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(ct, e.CT) {
					t.Errorf("seq %d: Seal = %x, want %x", e.Seq, ct, e.CT)
				}
				pt, err := recipient.Open(e.AAD, e.CT)
				if err != nil {
					t.Fatalf("seq %d: Open: %v", e.Seq, err)
				}
				if !bytes.Equal(pt, e.PT) {
					t.Errorf("seq %d: Open = %x, want %x", e.Seq, pt, e.PT)
				}
			}

			for _, x := range v.Exports {
				for _, c := range []*Context{sender, recipient} {
					got, err := c.Export(x.Context, x.L)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, x.Value) {
						t.Errorf("Export(%x, %d) = %x, want %x", x.Context, x.L, got, x.Value)
					}
				}
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, aead := range []AEAD{AES128GCM, AES256GCM, ChaCha20Poly1305} {
		enc, s, err := NewSender(pub, aead, []byte("info"))
		if err != nil {
			t.Fatal(err)
		}
		ct, err := s.Seal([]byte("aad"), []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		r, err := NewRecipient(enc, priv, aead, []byte("info"))
		if err != nil {
			t.Fatal(err)
		}
		// A failed Open leaves the sequence number where it was.
		if _, err := r.Open([]byte("bad"), ct); err == nil {
			t.Fatal("Open with the wrong aad succeeded")
		}
		pt, err := r.Open([]byte("aad"), ct)
		if err != nil {
			t.Fatal(err)
		}
		if string(pt) != "hello" {
			t.Errorf("Open = %q", pt)
		}
	}
	if _, _, err := NewSender(pub, 0xffff, nil); err == nil {
		t.Error("NewSender with an export-only AEAD succeeded")
	}
	if _, _, err := NewSender(make([]byte, keyLen), AES256GCM, nil); err == nil {
		t.Error("NewSender to a low-order public key succeeded")
	}
	if _, err := NewRecipient(make([]byte, keyLen), priv, AES256GCM, nil); err == nil {
		t.Error("NewRecipient of a low-order enc succeeded")
	}
}
