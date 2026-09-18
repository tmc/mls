package mls

import "github.com/tmc/mls/tlssyntax"

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
