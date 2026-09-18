package multicred_test

import (
	"bytes"
	"testing"

	"github.com/tmc/mls"
	"github.com/tmc/mls/multicred"
)

// newBinding returns a binding of a basic credential with the given
// identity, signed under suite cs and bound to signatureKey.
func newBinding(t *testing.T, cs mls.CipherSuite, identity string, signatureKey mls.SignaturePublicKey) multicred.Binding {
	t.Helper()
	priv, pub, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	b := multicred.Binding{
		CipherSuite:   cs,
		Credential:    mls.Credential{Type: mls.CredentialTypeBasic, Identity: []byte(identity)},
		CredentialKey: pub,
	}
	if err := b.Sign(priv, signatureKey); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCredential(t *testing.T) {
	suites := []mls.CipherSuite{
		mls.X25519AES128GCMSHA256Ed25519,
		mls.P256AES128GCMSHA256P256,
		mls.P521AES256GCMSHA512P521,
	}
	for _, cs := range suites {
		t.Run(cs.String(), func(t *testing.T) {
			_, signatureKey, err := cs.GenerateSignatureKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			// Bindings may use suites other than the group's.
			body := &multicred.Credential{Bindings: []multicred.Binding{
				newBinding(t, cs, "alice@example.com", signatureKey),
				newBinding(t, mls.X25519AES128GCMSHA256Ed25519, "alice@example.org", signatureKey),
			}}
			if err := body.Verify(signatureKey, nil); err != nil {
				t.Fatalf("Verify: %v", err)
			}

			// The credential must survive a round trip through a
			// leaf node, where its type is all that identifies it.
			leaf := &mls.LeafNode{
				SignatureKey: signatureKey,
				Credential:   mls.Credential{Type: multicred.TypeMulti, Body: body},
				Source:       mls.LeafNodeSourceUpdate,
			}
			b, err := mls.Marshal(leaf)
			if err != nil {
				t.Fatal(err)
			}
			got := new(mls.LeafNode)
			if err := mls.Unmarshal(b, got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if got.Credential.Type != multicred.TypeMulti {
				t.Fatalf("credential type = %v, want %v", got.Credential.Type, multicred.TypeMulti)
			}
			back, ok := got.Credential.Body.(*multicred.Credential)
			if !ok {
				t.Fatalf("credential body has type %T", got.Credential.Body)
			}
			if len(back.Bindings) != len(body.Bindings) {
				t.Fatalf("got %d bindings, want %d", len(back.Bindings), len(body.Bindings))
			}
			if err := back.Verify(got.SignatureKey, nil); err != nil {
				t.Errorf("Verify after round trip: %v", err)
			}
			if !bytes.Equal(back.Bindings[0].Credential.Identity, []byte("alice@example.com")) {
				t.Errorf("identity = %q", back.Bindings[0].Credential.Identity)
			}

			// A binding must not verify against another leaf node.
			_, other, err := cs.GenerateSignatureKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			if err := back.Verify(other, nil); err == nil {
				t.Error("Verify accepted a credential bound to another leaf node")
			}

			// A weak multi-credential verifies only the bindings
			// the client supports.
			back.Bindings[0].Signature[0] ^= 1
			if err := back.Verify(signatureKey, nil); err == nil {
				t.Error("Verify accepted a corrupted signature")
			}
			supported := func(b *multicred.Binding) bool {
				return !bytes.Equal(b.Credential.Identity, []byte("alice@example.com"))
			}
			if err := back.Verify(signatureKey, supported); err != nil {
				t.Errorf("Verify of supported bindings only: %v", err)
			}
		})
	}
}

func TestRegisterCredentialPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("registering a second time did not panic")
		}
	}()
	mls.RegisterCredential(multicred.TypeMulti, func() mls.CredentialCodec {
		return new(multicred.Credential)
	})
}
