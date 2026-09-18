// Package tlssyntax encodes and decodes the TLS presentation language
// as extended by the Messaging Layer Security protocol, RFC 9420.
//
// Beyond the base syntax of RFC 8446, MLS adds optional values and
// vectors with variable-size length headers. An optional value is a
// presence octet, 0 or 1, followed by the value if present. A vector
// written "<V>" in the specification is a variable-length integer
// length header, in the manner of RFC 9000, followed by that many
// bytes of encoded elements. The header is 1, 2, or 4 bytes long and
// must be the shortest encoding of the length; longer encodings are
// rejected as malformed.
//
// Values encode themselves by implementing [Marshaler] and decode
// themselves by implementing [Unmarshaler]:
//
//	type Extension struct {
//		Type uint16
//		Data []byte
//	}
//
//	func (e *Extension) MarshalTLS(w *tlssyntax.Writer) {
//		w.WriteUint16(e.Type)
//		w.WriteOpaque(e.Data)
//	}
//
//	func (e *Extension) UnmarshalTLS(r *tlssyntax.Reader) {
//		e.Type = r.ReadUint16()
//		e.Data = r.ReadOpaque()
//	}
//
// Both [Writer] and [Reader] hold the first error they encounter and
// ignore subsequent operations, so encoders and decoders need not
// check for errors at every step. [Marshal] and [Unmarshal] report
// that error to the caller.
package tlssyntax
