package mls

import (
	"bytes"
	"testing"
)

// TestSuite448Keys checks the key forms of suites 4 and 6: a 57-byte
// Ed448 seed and a 56-byte X448 scalar, and nothing else.
func TestSuite448Keys(t *testing.T) {
	for _, cs := range []CipherSuite{X448AES256GCMSHA512Ed448, X448ChaCha20Poly1305SHA512Ed448} {
		t.Run(cs.String(), func(t *testing.T) {
			skipUnapproved(t, cs)
			sigPriv, sigPub, err := cs.GenerateSignatureKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			if len(sigPriv) != 57 || len(sigPub) != 57 {
				t.Fatalf("signature key sizes = %d, %d, want 57, 57", len(sigPriv), len(sigPub))
			}
			sig, err := cs.SignWithLabel(sigPriv, "label", []byte("content"))
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.VerifyWithLabel(sigPub, "label", []byte("content"), sig); err != nil {
				t.Fatal(err)
			}
			if err := cs.VerifyWithLabel(sigPub, "other", []byte("content"), sig); err == nil {
				t.Error("VerifyWithLabel under another label succeeded")
			}
			// The 114-byte seed||public form is not a private key here.
			if _, err := cs.SignWithLabel(append(sigPriv, sigPub...), "label", nil); err == nil {
				t.Error("SignWithLabel with a 114-byte key succeeded")
			}
			if err := cs.VerifyWithLabel(sigPub[:56], "label", []byte("content"), sig); err == nil {
				t.Error("VerifyWithLabel with a 56-byte key succeeded")
			}

			priv, pub, err := cs.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			if len(priv) != 56 || len(pub) != 56 {
				t.Fatalf("HPKE key sizes = %d, %d, want 56, 56", len(priv), len(pub))
			}
			if got, err := cs.PublicKey(priv); err != nil || !bytes.Equal(got, pub) {
				t.Errorf("PublicKey = %x, %v, want %x", got, err, pub)
			}
			if _, err := cs.PublicKey(priv[:55]); err == nil {
				t.Error("PublicKey of a 55-byte key succeeded")
			}
			if _, err := cs.EncryptWithLabel(make(HPKEPublicKey, 56), "label", nil, nil); err == nil {
				t.Error("EncryptWithLabel to the zero point succeeded")
			}
		})
	}
}
