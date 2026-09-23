package tlssyntax

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// An Unmarshaler decodes itself from the TLS presentation language.
// UnmarshalTLS reports failure by calling [Reader.SetError]; it does
// not return an error of its own.
type Unmarshaler interface {
	UnmarshalTLS(r *Reader)
}

// A Reader decodes an encoding. The zero Reader is an empty input.
//
// A Reader holds the first error it encounters and thereafter reports
// no more data, so a decoder may read a whole structure and let
// [Reader.Err] report the failure once. Sub-readers returned by
// [Reader.ReadVector] share the error with the reader they came from,
// so a failure deep in a structure is visible at the top.
type Reader struct {
	s   []byte
	err *error
}

// NewReader returns a Reader that decodes data.
// The reader does not copy data, and slices returned by
// [Reader.ReadRaw] alias it.
func NewReader(data []byte) *Reader {
	return &Reader{s: data, err: new(error)}
}

// Unmarshal decodes data into v. It reports an error if decoding fails
// or if any bytes remain after v is decoded.
func Unmarshal(data []byte, v Unmarshaler) error {
	r := NewReader(data)
	v.UnmarshalTLS(r)
	if err := r.Err(); err != nil {
		return err
	}
	if len(r.s) != 0 {
		return fmt.Errorf("tlssyntax: %d bytes of trailing data", len(r.s))
	}
	return nil
}

// Err returns the first error recorded during reading.
func (r *Reader) Err() error {
	if r.err == nil {
		return nil
	}
	return *r.err
}

// SetError records err as the reader's error if no error is set yet
// and discards the remaining input. Decoders use it to reject values
// the syntax admits but the protocol does not, such as an unknown
// variant tag.
func (r *Reader) SetError(err error) {
	if r.err == nil {
		r.err = new(error)
	}
	if *r.err == nil {
		*r.err = err
	}
	r.s = nil
}

func (r *Reader) failf(format string, args ...any) {
	r.SetError(fmt.Errorf(format, args...))
}

// Empty reports whether the reader has no more data, either because
// the input is exhausted or because an error was recorded.
func (r *Reader) Empty() bool { return len(r.s) == 0 || r.Err() != nil }

func (r *Reader) next(n int) []byte {
	if r.Err() != nil {
		return nil
	}
	if len(r.s) < n {
		r.failf("tlssyntax: want %d bytes, have %d", n, len(r.s))
		return nil
	}
	b := r.s[:n]
	r.s = r.s[n:]
	return b
}

// ReadUint8 reads one byte.
func (r *Reader) ReadUint8() uint8 {
	b := r.next(1)
	if b == nil {
		return 0
	}
	return b[0]
}

// ReadUint16 reads two bytes in network byte order.
func (r *Reader) ReadUint16() uint16 {
	b := r.next(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

// ReadUint32 reads four bytes in network byte order.
func (r *Reader) ReadUint32() uint32 {
	b := r.next(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// ReadUint64 reads eight bytes in network byte order.
func (r *Reader) ReadUint64() uint64 {
	b := r.next(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

// ReadRaw reads n bytes with no length header. The returned slice
// aliases the reader's input; see [Reader.ReadOpaque] for a copy.
func (r *Reader) ReadRaw(n int) []byte { return r.next(n) }

// ReadVarint reads a variable-length integer. It rejects the reserved
// four-byte prefix and any encoding longer than the value requires.
func (r *Reader) ReadVarint() uint64 {
	b := r.next(1)
	if b == nil {
		return 0
	}
	prefix := b[0] >> 6
	if prefix == 3 {
		r.failf("tlssyntax: reserved variable-length integer prefix")
		return 0
	}
	v := uint64(b[0] & 0x3f)
	for _, c := range r.next(1<<prefix - 1) {
		v = v<<8 | uint64(c)
	}
	if r.Err() != nil {
		return 0
	}
	if v < varintMin[prefix] {
		r.failf("tlssyntax: variable-length integer %d is not minimally encoded", v)
		return 0
	}
	return v
}

// ReadVector reads a <V> vector header and returns a Reader over the
// vector's contents. The returned Reader shares this reader's error.
func (r *Reader) ReadVector() *Reader {
	n := r.ReadVarint()
	if r.Err() != nil {
		return &Reader{err: r.err}
	}
	if uint64(len(r.s)) < n {
		r.failf("tlssyntax: vector of %d bytes exceeds %d remaining", n, len(r.s))
		return &Reader{err: r.err}
	}
	b := r.s[:n]
	r.s = r.s[n:]
	return &Reader{s: b, err: r.err}
}

// ReadOpaque reads an opaque<V> vector. The returned slice is a copy
// and does not alias the reader's input. A zero-length vector reads as
// an empty, non-nil slice.
func (r *Reader) ReadOpaque() []byte {
	v := r.ReadVector()
	if r.Err() != nil {
		return nil
	}
	b := make([]byte, len(v.s))
	copy(b, v.s)
	return b
}

// ReadOptional reads a presence octet and reports whether a value
// follows. A presence octet other than 0 or 1 is malformed.
func (r *Reader) ReadOptional() bool {
	switch r.ReadUint8() {
	case 0:
		return false
	case 1:
		return true
	}
	if r.Err() == nil {
		r.failf("tlssyntax: malformed optional presence octet")
	}
	return false
}

// ReadAll reads elements from a <V> vector until it is exhausted,
// calling read once per element. A call to read that consumes no
// bytes and records no error is an error, since it would never
// exhaust the vector.
func (r *Reader) ReadAll(read func(r *Reader)) {
	v := r.ReadVector()
	for !v.Empty() {
		n := v.Len()
		read(v)
		if v.Len() == n && v.Err() == nil {
			v.failf("tlssyntax: vector element consumed no input")
		}
	}
}

// ErrMalformed is the error decoders record for input that is
// syntactically valid but not a legal protocol value.
var ErrMalformed = errors.New("tlssyntax: malformed value")

// An UnmarshalerFunc adapts an ordinary function to the Unmarshaler
// interface, for one-off structures that need no named type.
type UnmarshalerFunc func(r *Reader)

func (f UnmarshalerFunc) UnmarshalTLS(r *Reader) { f(r) }

// Len returns the number of bytes left to read.
func (r *Reader) Len() int { return len(r.s) }
