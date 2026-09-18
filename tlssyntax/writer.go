package tlssyntax

import (
	"errors"
	"fmt"
)

// A Marshaler encodes itself in the TLS presentation language.
// MarshalTLS reports failure by calling [Writer.SetError]; it does not
// return an error of its own.
type Marshaler interface {
	MarshalTLS(w *Writer)
}

// A Writer accumulates an encoding. The zero Writer is ready to use.
//
// A Writer holds the first error it encounters and thereafter ignores
// writes, so an encoder may write a whole structure and let [Writer.Bytes]
// report the failure once.
type Writer struct {
	buf []byte
	err error
}

// Marshal returns the encoding of v.
func Marshal(v Marshaler) ([]byte, error) {
	var w Writer
	v.MarshalTLS(&w)
	return w.Bytes()
}

// Bytes returns the accumulated encoding, or the first error recorded
// during writing.
func (w *Writer) Bytes() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	return w.buf, nil
}

// Err returns the first error recorded during writing.
func (w *Writer) Err() error { return w.err }

// SetError records err as the writer's error if no error is set yet.
// Encoders use it to reject values they cannot represent, such as an
// unknown variant tag.
func (w *Writer) SetError(err error) {
	if w.err == nil {
		w.err = err
	}
}

func (w *Writer) failf(format string, args ...any) {
	w.SetError(fmt.Errorf(format, args...))
}

// WriteUint8 writes v.
func (w *Writer) WriteUint8(v uint8) {
	if w.err == nil {
		w.buf = append(w.buf, v)
	}
}

// WriteUint16 writes v in network byte order.
func (w *Writer) WriteUint16(v uint16) {
	if w.err == nil {
		w.buf = append(w.buf, byte(v>>8), byte(v))
	}
}

// WriteUint32 writes v in network byte order.
func (w *Writer) WriteUint32(v uint32) {
	if w.err == nil {
		w.buf = append(w.buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// WriteUint64 writes v in network byte order.
func (w *Writer) WriteUint64(v uint64) {
	if w.err == nil {
		w.buf = append(w.buf,
			byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// WriteRaw writes b with no length header. It is for fixed-size fields;
// variable-size fields use [Writer.WriteOpaque].
func (w *Writer) WriteRaw(b []byte) {
	if w.err == nil {
		w.buf = append(w.buf, b...)
	}
}

// WriteOpaque writes b as an opaque<V> vector.
func (w *Writer) WriteOpaque(b []byte) {
	w.WriteVector(func(w *Writer) { w.WriteRaw(b) })
}

// WriteVector writes the encoding produced by f as a <V> vector,
// prefixing it with its length.
func (w *Writer) WriteVector(f func(w *Writer)) {
	if w.err != nil {
		return
	}
	mark := len(w.buf)
	f(w)
	if w.err != nil {
		return
	}
	n := len(w.buf) - mark
	if n > MaxVectorLen {
		w.failf("tlssyntax: vector of %d bytes exceeds maximum %d", n, MaxVectorLen)
		return
	}
	var hdr [4]byte
	h := appendVarint(hdr[:0], uint64(n))
	w.buf = append(w.buf, h...)
	copy(w.buf[mark+len(h):], w.buf[mark:mark+n])
	copy(w.buf[mark:], h)
}

// WriteOptional writes an optional value. If f is nil the value is
// absent; otherwise f writes the value after the presence octet.
func (w *Writer) WriteOptional(f func(w *Writer)) {
	if f == nil {
		w.WriteUint8(0)
		return
	}
	w.WriteUint8(1)
	f(w)
}

// ErrUnknownVariant is the error recorded when a value carries a
// variant tag the encoder does not know how to encode.
var ErrUnknownVariant = errors.New("tlssyntax: unknown variant")

// A MarshalerFunc adapts an ordinary function to the Marshaler
// interface, for one-off structures that need no named type.
type MarshalerFunc func(w *Writer)

func (f MarshalerFunc) MarshalTLS(w *Writer) { f(w) }
