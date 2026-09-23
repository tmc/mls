// Package multicred implements the multi-credentials of
// draft-ietf-mls-extensions, which let one member present several
// credentials at once.
//
// A multi-credential is a list of bindings. Each binding is a
// statement, signed by the holder of one credential, that the
// signature key in the member's leaf node belongs to that holder. A
// member of a group whose credential is a multi-credential therefore
// proves at once that it controls every identity in the list.
//
// Importing this package registers the credential types with
// [github.com/tmc/mls], so that a leaf node carrying one decodes into
// a [Credential] in the Body field of [mls.Credential].
//
// The credential type values are those suggested by the draft, which
// IANA has not yet assigned.
package multicred

import (
	"fmt"

	"github.com/tmc/mls"
	"github.com/tmc/mls/tlssyntax"
)

// The credential types this package registers.
// See draft-ietf-mls-extensions, Section 7.3.
const (
	// TypeMulti requires every member of the group to support, and
	// every member to verify, every binding.
	TypeMulti mls.CredentialType = 3

	// TypeWeakMulti requires only that each member support one
	// binding, and each verifies the bindings it supports. Its
	// security is that of the weakest binding in the list.
	TypeWeakMulti mls.CredentialType = 4
)

func init() {
	mls.RegisterCredential(TypeMulti, func() mls.CredentialCodec { return new(Credential) })
	mls.RegisterCredential(TypeWeakMulti, func() mls.CredentialCodec { return new(Credential) })
}

// A Binding is one credential of a multi-credential, together with
// the signature that binds it to a leaf node's signature key. The
// cipher suite is the binding's own and need not be the group's.
// See draft-ietf-mls-extensions, Section 6.5.
//
// The credential of a binding may not itself be a multi-credential.
// The draft does not forbid one, but it describes no use for it, and
// each level of nesting is another level of recursion in the decoder,
// so that a key package of a few megabytes could exhaust the stack.
// Encoding, decoding and verifying all reject it with [ErrNested].
type Binding struct {
	CipherSuite   mls.CipherSuite
	Credential    mls.Credential
	CredentialKey mls.SignaturePublicKey
	Signature     []byte
}

func (b *Binding) MarshalTLS(w *tlssyntax.Writer) {
	if isMulti(b.Credential.Type) {
		w.SetError(ErrNested)
		return
	}
	b.marshalTBS(w, nil)
	w.WriteOpaque(b.Signature)
}

// marshalTBS writes the CredentialBindingTBS that the signature
// covers: the binding without its signature, followed by the
// signature key of the leaf node the credential is bound to.
func (b *Binding) marshalTBS(w *tlssyntax.Writer, signatureKey mls.SignaturePublicKey) {
	w.WriteUint16(uint16(b.CipherSuite))
	b.Credential.MarshalTLS(w)
	w.WriteOpaque(b.CredentialKey)
	if signatureKey != nil {
		w.WriteOpaque(signatureKey)
	}
}

func (b *Binding) UnmarshalTLS(r *tlssyntax.Reader) {
	*b = Binding{}
	b.CipherSuite = mls.CipherSuite(r.ReadUint16())
	// Look at the credential type before decoding the credential,
	// so that nesting is refused before it can recurse.
	peek := *r
	if isMulti(mls.CredentialType(peek.ReadUint16())) {
		r.SetError(fmt.Errorf("%w: %w", tlssyntax.ErrMalformed, ErrNested))
		return
	}
	b.Credential.UnmarshalTLS(r)
	b.CredentialKey = r.ReadOpaque()
	b.Signature = r.ReadOpaque()
}

// isMulti reports whether t is one of the multi-credential types.
func isMulti(t mls.CredentialType) bool {
	return t == TypeMulti || t == TypeWeakMulti
}

// SignedContent returns the CredentialBindingTBS bytes that
// b.Signature covers, for the leaf node whose signature key is
// signatureKey.
func (b *Binding) SignedContent(signatureKey mls.SignaturePublicKey) ([]byte, error) {
	if signatureKey == nil {
		return nil, ErrNoSignatureKey
	}
	return mls.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		b.marshalTBS(w, signatureKey)
	}))
}

// Sign signs b with priv, the private half of b.CredentialKey,
// binding it to the leaf node whose signature key is signatureKey.
func (b *Binding) Sign(priv []byte, signatureKey mls.SignaturePublicKey) error {
	content, err := b.SignedContent(signatureKey)
	if err != nil {
		return err
	}
	b.Signature, err = b.CipherSuite.SignWithLabel(priv, "CredentialBindingTBS", content)
	return err
}

// Verify checks b.Signature against b.CredentialKey. The signature is
// made by the holder of the credential, so it is that key, not the
// leaf node's, that verifies it; signatureKey is the value signed
// over. See draft-ietf-mls-extensions, Section 6.5.2.
func (b *Binding) Verify(signatureKey mls.SignaturePublicKey) error {
	content, err := b.SignedContent(signatureKey)
	if err != nil {
		return err
	}
	return b.CipherSuite.VerifyWithLabel(b.CredentialKey, "CredentialBindingTBS", content, b.Signature)
}

// A Credential is the body of a multi-credential: the list of
// bindings that the member presents.
type Credential struct {
	Bindings []Binding
}

func (c *Credential) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteVector(func(w *tlssyntax.Writer) {
		for i := range c.Bindings {
			c.Bindings[i].MarshalTLS(w)
		}
	})
}

func (c *Credential) UnmarshalTLS(r *tlssyntax.Reader) {
	*c = Credential{}
	r.ReadAll(func(r *tlssyntax.Reader) {
		var b Binding
		b.UnmarshalTLS(r)
		c.Bindings = append(c.Bindings, b)
	})
}

// Verify checks the bindings of c against signatureKey, the
// signature key of the leaf node that carries the credential.
//
// A multi-credential is valid only if every binding verifies, which
// is what a nil supported requires. For a weak multi-credential the
// client verifies the bindings it supports, and supported reports
// which those are; the others are left to members that do support
// them. See draft-ietf-mls-extensions, Section 6.5.2.
//
// Verify can therefore succeed without checking anything: a weak
// multi-credential none of whose bindings are supported returns nil.
// A caller that needs at least one binding checked, or that requires
// a particular shape - one binding, a basic inner credential, an
// identity equal to the credential key - must require it itself,
// before or after calling Verify. Nothing here can know those rules.
func (c *Credential) Verify(signatureKey mls.SignaturePublicKey, supported func(*Binding) bool) error {
	if len(c.Bindings) == 0 {
		return ErrNoBindings
	}
	for i := range c.Bindings {
		b := &c.Bindings[i]
		if isMulti(b.Credential.Type) {
			return ErrNested
		}
		if supported != nil && !supported(b) {
			continue
		}
		if !b.CipherSuite.Supported() {
			return mls.ErrUnsupportedCipherSuite
		}
		if err := b.Verify(signatureKey); err != nil {
			return err
		}
	}
	return nil
}
