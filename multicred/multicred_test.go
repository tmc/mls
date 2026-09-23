package multicred_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/tmc/mls"
	"github.com/tmc/mls/multicred"
	"github.com/tmc/mls/tlssyntax"
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

			// Supporting no binding at all verifies nothing, which
			// must not pass for success.
			none := func(*multicred.Binding) bool { return false }
			if err := back.Verify(signatureKey, none); !errors.Is(err, multicred.ErrNoneVerified) {
				t.Errorf("Verify with no supported bindings: %v, want %v", err, multicred.ErrNoneVerified)
			}
		})
	}
}

// nested returns the encoding of a credential that is a
// multi-credential depth levels deep: at each level, one binding
// whose credential is the next level down, and at the bottom a basic
// credential. It builds the encoding directly, so that it can reach
// depths the encoder refuses.
func nested(depth int) []byte {
	inner := []byte{0, 1, 1, 'a'} // basic credential, identity "a"
	// Each level is a prefix (type, bindings length, cipher suite)
	// before the level below and a suffix (empty credential key and
	// signature) after it.
	lens := make([]int, depth+1)
	lens[0] = len(inner)
	for k := 1; k <= depth; k++ {
		binding := 2 + lens[k-1] + 2
		lens[k] = 2 + len(appendVarint(nil, binding)) + binding
	}
	var b []byte
	for k := depth; k >= 1; k-- {
		b = binary.BigEndian.AppendUint16(b, uint16(multicred.TypeMulti))
		b = appendVarint(b, 2+lens[k-1]+2)
		b = binary.BigEndian.AppendUint16(b, uint16(mls.X25519AES128GCMSHA256Ed25519))
	}
	b = append(b, inner...)
	for range depth {
		b = append(b, 0, 0)
	}
	return b
}

// appendVarint appends the variable-length encoding of v.
// See RFC 9420, Section 2.1.2.
func appendVarint(b []byte, v int) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, 0x4000|uint16(v))
	default:
		return binary.BigEndian.AppendUint32(b, 0x80000000|uint32(v))
	}
}

func TestNested(t *testing.T) {
	var c mls.Credential
	if err := mls.Unmarshal(nested(1), &c); err != nil {
		t.Fatalf("Unmarshal of a multi-credential: %v", err)
	}
	for _, depth := range []int{2, 3, 100_000} {
		err := mls.Unmarshal(nested(depth), &c)
		if !errors.Is(err, multicred.ErrNested) || !errors.Is(err, tlssyntax.ErrMalformed) {
			t.Errorf("Unmarshal of depth %d: %v, want %v and %v", depth, err, multicred.ErrNested, tlssyntax.ErrMalformed)
		}
	}

	_, signatureKey, err := mls.X25519AES128GCMSHA256Ed25519.GenerateSignatureKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	inner := &multicred.Credential{Bindings: []multicred.Binding{
		newBinding(t, mls.X25519AES128GCMSHA256Ed25519, "alice@example.com", signatureKey),
	}}
	for _, typ := range []mls.CredentialType{multicred.TypeMulti, multicred.TypeWeakMulti} {
		outer := &multicred.Credential{Bindings: []multicred.Binding{{
			CipherSuite: mls.X25519AES128GCMSHA256Ed25519,
			Credential:  mls.Credential{Type: typ, Body: inner},
		}}}
		if _, err := mls.Marshal(outer); !errors.Is(err, multicred.ErrNested) {
			t.Errorf("Marshal of %v in a binding: %v, want %v", typ, err, multicred.ErrNested)
		}
		if err := outer.Verify(signatureKey, nil); !errors.Is(err, multicred.ErrNested) {
			t.Errorf("Verify of %v in a binding: %v, want %v", typ, err, multicred.ErrNested)
		}
	}
}

func TestMaxBindings(t *testing.T) {
	cs := mls.X25519AES128GCMSHA256Ed25519
	_, signatureKey, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var bindings []multicred.Binding
	for range multicred.MaxBindings + 1 {
		bindings = append(bindings, newBinding(t, cs, "alice@example.com", signatureKey))
	}
	tests := []struct {
		n       int
		wantErr bool
	}{
		{multicred.MaxBindings, false},
		{multicred.MaxBindings + 1, true},
	}
	for _, tt := range tests {
		c := &multicred.Credential{Bindings: bindings[:tt.n]}
		// Encode the bindings directly, since Marshal refuses too many.
		var w tlssyntax.Writer
		w.WriteVector(func(w *tlssyntax.Writer) {
			for i := range c.Bindings {
				c.Bindings[i].MarshalTLS(w)
			}
		})
		enc, err := w.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		var got multicred.Credential
		errs := map[string]error{
			"Unmarshal": mls.Unmarshal(enc, &got),
			"Verify":    c.Verify(signatureKey, nil),
		}
		_, errs["Marshal"] = mls.Marshal(c)
		for name, err := range errs {
			if tt.wantErr && !errors.Is(err, multicred.ErrTooManyBindings) {
				t.Errorf("%s of %d bindings: %v, want %v", name, tt.n, err, multicred.ErrTooManyBindings)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("%s of %d bindings: %v", name, tt.n, err)
			}
		}
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
