package mls

import (
	"sync"

	"github.com/tmc/mls/tlssyntax"
)

// A CredentialType identifies the form of a [Credential].
type CredentialType uint16

// Credential types. See RFC 9420, Section 17.5.
const (
	CredentialTypeBasic CredentialType = 1
	CredentialTypeX509  CredentialType = 2
)

// A CredentialCodec is the body of a credential whose type this
// package does not define itself, such as one from a draft
// extension. See [RegisterCredential].
type CredentialCodec interface {
	tlssyntax.Marshaler
	tlssyntax.Unmarshaler
}

var (
	credentialsMu sync.RWMutex
	credentials   = map[CredentialType]func() CredentialCodec{}
)

// RegisterCredential records how to encode and decode the body of a
// credential of type t; body returns a fresh value to decode into.
// It panics if t is already registered or is a type this package
// defines itself.
//
// Registration is meant to happen from an init function, as
// [github.com/tmc/mls/multicred] does, but it is safe to call at any
// time: the registry is guarded, so a registration cannot race a
// credential being encoded or decoded.
func RegisterCredential(t CredentialType, body func() CredentialCodec) {
	switch t {
	case CredentialTypeBasic, CredentialTypeX509:
		panic("mls: cannot register " + t.String())
	}
	credentialsMu.Lock()
	defer credentialsMu.Unlock()
	if _, ok := credentials[t]; ok {
		panic("mls: credential type " + t.String() + " is already registered")
	}
	credentials[t] = body
}

// String returns the name of the credential type, or its number
// if it is not one this package knows.
func (t CredentialType) String() string {
	return enumString("CredentialType", uint64(t), []string{"reserved", "basic", "x509"})
}

// A Credential presents the identity of a group member. Which field
// holds that identity depends on Type: a basic credential carries an
// uninterpreted Identity, an x509 credential carries a chain of
// DER-encoded certificates, leaf first, and a credential of a
// registered type carries its own Body.
// See RFC 9420, Section 5.3.
type Credential struct {
	Type CredentialType

	Identity     []byte   // Type == CredentialTypeBasic
	Certificates [][]byte // Type == CredentialTypeX509

	// Body holds the credential of any other Type that has been
	// given to [RegisterCredential].
	Body CredentialCodec
}

func (c *Credential) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint16(uint16(c.Type))
	switch c.Type {
	case CredentialTypeBasic:
		w.WriteOpaque(c.Identity)
	case CredentialTypeX509:
		w.WriteVector(func(w *tlssyntax.Writer) {
			for _, cert := range c.Certificates {
				w.WriteOpaque(cert)
			}
		})
	default:
		if c.Body == nil {
			w.SetError(errUnknown("credential type", uint64(c.Type)))
			return
		}
		c.Body.MarshalTLS(w)
	}
}

func (c *Credential) UnmarshalTLS(r *tlssyntax.Reader) {
	*c = Credential{Type: CredentialType(r.ReadUint16())}
	switch c.Type {
	case CredentialTypeBasic:
		c.Identity = r.ReadOpaque()
	case CredentialTypeX509:
		r.ReadAll(func(r *tlssyntax.Reader) {
			c.Certificates = append(c.Certificates, r.ReadOpaque())
		})
	default:
		credentialsMu.RLock()
		body, ok := credentials[c.Type]
		credentialsMu.RUnlock()
		if !ok {
			if r.Err() == nil {
				r.SetError(errUnknown("credential type", uint64(c.Type)))
			}
			return
		}
		c.Body = body()
		c.Body.UnmarshalTLS(r)
	}
}
