package mls

import (
	"fmt"
	"slices"

	"github.com/tmc/mls/tlssyntax"
)

// An ExtensionType identifies the contents of an [Extension].
type ExtensionType uint16

// Extension types. See RFC 9420, Section 17.3.
const (
	ExtensionTypeApplicationID        ExtensionType = 1
	ExtensionTypeRatchetTree          ExtensionType = 2
	ExtensionTypeRequiredCapabilities ExtensionType = 3
	ExtensionTypeExternalPub          ExtensionType = 4
	ExtensionTypeExternalSenders      ExtensionType = 5
)

// GREASE reports whether t is one of the reserved values that a
// client may insert at random to check that its peers ignore
// extensions they do not recognize. A GREASE extension carries no
// meaning, and its contents are arbitrary.
// See RFC 9420, Section 13.5.
func (t ExtensionType) GREASE() bool { return t&0x0f0f == 0x0a0a }

// String returns the name of the extension type, or its number if
// it is not one this package knows.
func (t ExtensionType) String() string {
	return enumString("ExtensionType", uint64(t), []string{
		"reserved", "application_id", "ratchet_tree", "required_capabilities",
		"external_pub", "external_senders",
	})
}

// An Extension carries data outside the base protocol. Its contents
// are opaque here; interpreting them is the business of whatever
// defines the extension type. See RFC 9420, Section 7.2.
type Extension struct {
	Type ExtensionType
	Data []byte
}

func (e *Extension) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint16(uint16(e.Type))
	w.WriteOpaque(e.Data)
}

func (e *Extension) UnmarshalTLS(r *tlssyntax.Reader) {
	e.Type = ExtensionType(r.ReadUint16())
	e.Data = r.ReadOpaque()
}

// Extensions is a vector of extensions, written "Extension
// extensions<V>" in the specification.
type Extensions []Extension

func (es *Extensions) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteVector(func(w *tlssyntax.Writer) {
		for i := range *es {
			(*es)[i].MarshalTLS(w)
		}
	})
}

func (es *Extensions) UnmarshalTLS(r *tlssyntax.Reader) {
	*es = nil
	r.ReadAll(func(r *tlssyntax.Reader) {
		var e Extension
		e.UnmarshalTLS(r)
		// RFC 9420, Section 13.4: a list of extensions must not
		// hold more than one extension of any given type. The
		// order of the list is not constrained.
		if es.Find(e.Type) != nil {
			r.SetError(fmt.Errorf("%w: %v", ErrDuplicateExtension, e.Type))
			return
		}
		*es = append(*es, e)
	})
}

// Find returns the first extension of the given type, or nil.
func (es Extensions) Find(t ExtensionType) *Extension {
	for i := range es {
		if es[i].Type == t {
			return &es[i]
		}
	}
	return nil
}

// Decode decodes the extension of type t into body. It reports whether
// the extension was present; a missing extension is not an error, so
// that a caller can distinguish absence from a malformed value.
//
// Extensions whose type this package does not define keep their
// contents in [Extension.Data], since RFC 9420, Section 13.4 requires
// that unrecognized extensions be ignored rather than rejected.
func (es Extensions) Decode(t ExtensionType, body tlssyntax.Unmarshaler) (bool, error) {
	e := es.Find(t)
	if e == nil {
		return false, nil
	}
	if err := Unmarshal(e.Data, body); err != nil {
		return true, fmt.Errorf("mls: %v extension: %w", t, err)
	}
	return true, nil
}

// Set encodes body as the extension of type t, replacing any
// extension of that type already present.
func (es *Extensions) Set(t ExtensionType, body tlssyntax.Marshaler) error {
	data, err := Marshal(body)
	if err != nil {
		return fmt.Errorf("mls: %v extension: %w", t, err)
	}
	if e := es.Find(t); e != nil {
		e.Data = data
		return nil
	}
	*es = append(*es, Extension{Type: t, Data: data})
	return nil
}

// An ApplicationID carries an application-chosen identifier for the
// member at a leaf, for applications that need one that outlives the
// member's keys. It says nothing about the member's identity, which
// is the credential's business.
// See RFC 9420, Section 7.2.
type ApplicationID struct {
	ID []byte
}

func (a *ApplicationID) MarshalTLS(w *tlssyntax.Writer)   { w.WriteOpaque(a.ID) }
func (a *ApplicationID) UnmarshalTLS(r *tlssyntax.Reader) { a.ID = r.ReadOpaque() }

// RequiredCapabilities lists what every member of a group must
// support. It appears in the group context, so that the requirement
// is one the whole group agrees on.
// See RFC 9420, Section 11.1.
type RequiredCapabilities struct {
	ExtensionTypes  []ExtensionType
	ProposalTypes   []ProposalType
	CredentialTypes []CredentialType
}

func (c *RequiredCapabilities) MarshalTLS(w *tlssyntax.Writer) {
	writeUint16s(w, c.ExtensionTypes)
	writeUint16s(w, c.ProposalTypes)
	writeUint16s(w, c.CredentialTypes)
}

func (c *RequiredCapabilities) UnmarshalTLS(r *tlssyntax.Reader) {
	*c = RequiredCapabilities{}
	readUint16s(r, &c.ExtensionTypes)
	readUint16s(r, &c.ProposalTypes)
	readUint16s(r, &c.CredentialTypes)
}

// Supported reports whether c lists nothing that caps does not
// advertise. A member may only be added to a group if its
// capabilities support the group's required capabilities.
// See RFC 9420, Section 7.2.
func (c *RequiredCapabilities) Supported(caps *Capabilities) bool {
	return subset(c.ExtensionTypes, caps.Extensions) &&
		subset(c.ProposalTypes, caps.Proposals) &&
		subset(c.CredentialTypes, caps.Credentials)
}

func subset[T comparable](want, have []T) bool {
	for _, v := range want {
		if !slices.Contains(have, v) {
			return false
		}
	}
	return true
}

// An ExternalPub publishes the public half of a group's external init
// key, which lets a non-member join by external commit. It appears in
// a GroupInfo. See RFC 9420, Section 12.4.3.2.
type ExternalPub struct {
	ExternalPub HPKEPublicKey
}

func (e *ExternalPub) MarshalTLS(w *tlssyntax.Writer)   { w.WriteOpaque(e.ExternalPub) }
func (e *ExternalPub) UnmarshalTLS(r *tlssyntax.Reader) { e.ExternalPub = r.ReadOpaque() }

// An ExternalSender is a party that may send proposals to a group
// without being a member of it.
// See RFC 9420, Section 12.1.8.1.
type ExternalSender struct {
	SignatureKey SignaturePublicKey
	Credential   Credential
}

func (s *ExternalSender) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteOpaque(s.SignatureKey)
	s.Credential.MarshalTLS(w)
}

func (s *ExternalSender) UnmarshalTLS(r *tlssyntax.Reader) {
	*s = ExternalSender{}
	s.SignatureKey = r.ReadOpaque()
	s.Credential.UnmarshalTLS(r)
}

// ExternalSenders is the group context extension that lists the
// parties allowed to send proposals from outside the group. The index
// in a [Sender] of type external is an index into this list.
// See RFC 9420, Section 12.1.8.1.
type ExternalSenders []ExternalSender

func (ss *ExternalSenders) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteVector(func(w *tlssyntax.Writer) {
		for i := range *ss {
			(*ss)[i].MarshalTLS(w)
		}
	})
}

func (ss *ExternalSenders) UnmarshalTLS(r *tlssyntax.Reader) {
	*ss = nil
	r.ReadAll(func(r *tlssyntax.Reader) {
		var s ExternalSender
		s.UnmarshalTLS(r)
		*ss = append(*ss, s)
	})
}
