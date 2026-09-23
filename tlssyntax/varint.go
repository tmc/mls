package tlssyntax

import "encoding/binary"

// MaxVectorLen is the largest length a variable-size vector header can
// encode. See RFC 9420, Section 2.1.2.
const MaxVectorLen = 1<<30 - 1

// varintMin[p] is the smallest value that a varint with prefix p may
// encode. A smaller value must use a shorter encoding.
var varintMin = [3]uint64{0, 1 << 6, 1 << 14}

// appendVarint appends the minimal variable-length encoding of v.
// It assumes v <= MaxVectorLen.
func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, 0x4000|uint16(v))
	default:
		return binary.BigEndian.AppendUint32(b, 0x80000000|uint32(v))
	}
}
