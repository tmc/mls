package multicred_test

import (
	"errors"
	"fmt"
	"log"

	"github.com/tmc/mls"
	"github.com/tmc/mls/multicred"
)

// bind returns a binding of a basic credential for identity, signed
// under suite cs by a fresh credential key and bound to signatureKey.
func bind(cs mls.CipherSuite, identity string, signatureKey mls.SignaturePublicKey) multicred.Binding {
	priv, pub, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	b := multicred.Binding{
		CipherSuite:   cs,
		Credential:    mls.Credential{Type: mls.CredentialTypeBasic, Identity: []byte(identity)},
		CredentialKey: pub,
	}
	if err := b.Sign(priv, signatureKey); err != nil {
		log.Fatal(err)
	}
	return b
}

// A member presents two identities, each bound by its own credential
// key to the signature key of the member's leaf node. The bindings may
// use different cipher suites.
func Example() {
	cs := mls.P256AES128GCMSHA256P256
	_, leafKey, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	cred := mls.Credential{Type: multicred.TypeMulti, Body: &multicred.Credential{Bindings: []multicred.Binding{
		bind(cs, "alice@example.com", leafKey),
		bind(mls.P384AES256GCMSHA384P384, "alice@example.org", leafKey),
	}}}

	// The credential goes in a leaf node; a member checks it against
	// that leaf's signature key.
	body := cred.Body.(*multicred.Credential)
	fmt.Println(body.Verify(leafKey, nil))

	// Bound to a different leaf, the bindings do not verify.
	_, otherKey, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(body.Verify(otherKey, nil) != nil)
	// Output:
	// <nil>
	// true
}

// For a weak multi-credential, a member verifies only the bindings
// whose cipher suites it supports.
func ExampleCredential_Verify_weak() {
	cs := mls.P256AES128GCMSHA256P256
	_, leafKey, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	body := &multicred.Credential{Bindings: []multicred.Binding{
		bind(cs, "alice@example.com", leafKey),
		bind(mls.P521AES256GCMSHA512P521, "alice@example.org", leafKey),
	}}

	onlyP256 := func(b *multicred.Binding) bool { return b.CipherSuite == cs }
	fmt.Println(body.Verify(leafKey, onlyP256))

	none := func(*multicred.Binding) bool { return false }
	fmt.Println(errors.Is(body.Verify(leafKey, none), multicred.ErrNoneVerified))
	// Output:
	// <nil>
	// true
}
