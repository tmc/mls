package multicred_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/tmc/mls"
	"github.com/tmc/mls/multicred"
	"github.com/tmc/mls/tlssyntax"
)

// FuzzCredential decodes arbitrary bytes as the body of a
// multi-credential, as an mls.Credential of either multi-credential
// type, and as a leaf node carrying one, and verifies whatever
// decodes, both in full and with a filter that supports only some
// bindings.
//
// Beyond not panicking or exhausting the stack, a value that decodes
// must re-encode to the bytes it came from, since a signature over a
// leaf node covers the encoding of its credential.
func FuzzCredential(f *testing.F) {
	cs := testSuite()
	_, signatureKey, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		f.Fatal(err)
	}
	var bindings []multicred.Binding
	for _, s := range []mls.CipherSuite{cs, mls.P256AES128GCMSHA256P256} {
		priv, pub, err := s.GenerateSignatureKeyPair()
		if err != nil {
			f.Fatal(err)
		}
		b := multicred.Binding{
			CipherSuite:   s,
			Credential:    mls.Credential{Type: mls.CredentialTypeBasic, Identity: []byte("alice@example.com")},
			CredentialKey: pub,
		}
		if err := b.Sign(priv, signatureKey); err != nil {
			f.Fatal(err)
		}
		bindings = append(bindings, b)
	}
	body := &multicred.Credential{Bindings: bindings}
	for _, v := range []tlssyntax.Marshaler{
		body,
		&multicred.Credential{Bindings: bindings[:1]},
		&mls.Credential{Type: multicred.TypeMulti, Body: body},
		&mls.Credential{Type: multicred.TypeWeakMulti, Body: body},
	} {
		b, err := mls.Marshal(v)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}

	// Only the bindings of the group's own suite are supported.
	sameSuite := func(b *multicred.Binding) bool { return b.CipherSuite == cs }
	verify := func(c *multicred.Credential) {
		_ = c.Verify(signatureKey, nil)
		_ = c.Verify(signatureKey, sameSuite)
		_ = c.Verify(nil, nil)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var c multicred.Credential
		if err := mls.Unmarshal(data, &c); err == nil {
			verify(&c)
			roundTrip(t, data, &c, new(multicred.Credential))
		}

		var mc mls.Credential
		if err := mls.Unmarshal(data, &mc); err == nil {
			if body, ok := mc.Body.(*multicred.Credential); ok {
				verify(body)
			}
			roundTrip(t, data, &mc, new(mls.Credential))
		}

		var leaf mls.LeafNode
		if err := mls.Unmarshal(data, &leaf); err == nil {
			if body, ok := leaf.Credential.Body.(*multicred.Credential); ok {
				verify(body)
			}
			roundTrip(t, data, &leaf, new(mls.LeafNode))
		}
	})
}

// roundTrip checks that v, decoded from data, re-encodes to data, and
// that the re-encoding decodes into fresh to the same value.
func roundTrip[T interface {
	tlssyntax.Marshaler
	tlssyntax.Unmarshaler
}](t *testing.T, data []byte, v, fresh T) {
	t.Helper()
	out, err := mls.Marshal(v)
	if err != nil {
		t.Fatalf("%T decoded but would not re-encode: %v", v, err)
	}
	if !bytes.Equal(out, data) {
		t.Fatalf("%T round trip changed the encoding:\n in %x\nout %x", v, data, out)
	}
	if err := mls.Unmarshal(out, fresh); err != nil {
		t.Fatalf("%T re-encoding does not decode: %v", v, err)
	}
	if !reflect.DeepEqual(v, fresh) {
		t.Fatalf("%T decodes differently the second time:\n%+v\n%+v", v, v, fresh)
	}
}
