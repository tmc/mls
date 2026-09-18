package mls

import "github.com/tmc/mls/tlssyntax"

// A CredentialType identifies the form of a [Credential].
type CredentialType uint16

// Credential types. See RFC 9420, Section 17.5.
const (
	CredentialTypeBasic CredentialType = 1
	CredentialTypeX509  CredentialType = 2
)

func (t CredentialType) String() string {
	return enumString("CredentialType", uint64(t), []string{"reserved", "basic", "x509"})
}

// A Credential presents the identity of a group member. Which field
// holds that identity depends on Type: a basic credential carries an
// uninterpreted Identity, an x509 credential carries a chain of
// DER-encoded certificates, leaf first.
// See RFC 9420, Section 5.3.
type Credential struct {
	Type CredentialType

	Identity     []byte   // Type == CredentialTypeBasic
	Certificates [][]byte // Type == CredentialTypeX509
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
		w.SetError(errUnknown("credential type", uint64(c.Type)))
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
		if r.Err() == nil {
			r.SetError(errUnknown("credential type", uint64(c.Type)))
		}
	}
}
