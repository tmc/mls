package tlssyntax

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// varintTests includes the three examples given in RFC 9420, Section 2.1.2.
var varintTests = []struct {
	enc  string
	want uint64
}{
	{"00", 0},
	{"25", 37},
	{"3f", 63},
	{"4040", 64},
	{"7bbd", 15293},
	{"7fff", 16383},
	{"80004000", 16384},
	{"9d7f3e7d", 494878333},
	{"bfffffff", MaxVectorLen},
}

func TestVarint(t *testing.T) {
	for _, tt := range varintTests {
		enc := decodeHex(t, tt.enc)
		r := NewReader(enc)
		if got := r.ReadVarint(); got != tt.want || r.Err() != nil {
			t.Errorf("ReadVarint(%s) = %d, %v, want %d, nil", tt.enc, got, r.Err(), tt.want)
		}
		if got := appendVarint(nil, tt.want); !bytes.Equal(got, enc) {
			t.Errorf("appendVarint(%d) = %x, want %s", tt.want, got, tt.enc)
		}
	}
}

func TestVarintMalformed(t *testing.T) {
	tests := []struct {
		name string
		enc  string
	}{
		{"reserved prefix", "c000000000000000"},
		{"non-minimal two-byte", "4025"},
		{"non-minimal four-byte", "80003bbd"},
		{"truncated two-byte", "40"},
		{"truncated four-byte", "800040"},
		{"empty", ""},
	}
	for _, tt := range tests {
		r := NewReader(decodeHex(t, tt.enc))
		r.ReadVarint()
		if r.Err() == nil {
			t.Errorf("%s: ReadVarint(%s) succeeded, want error", tt.name, tt.enc)
		}
	}
}

func TestIntegers(t *testing.T) {
	var w Writer
	w.WriteUint8(0x01)
	w.WriteUint16(0x0203)
	w.WriteUint32(0x04050607)
	w.WriteUint64(0x08090a0b0c0d0e0f)
	got, err := w.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := decodeHex(t, "0102030405060708090a0b0c0d0e0f")
	if !bytes.Equal(got, want) {
		t.Fatalf("encoding = %x, want %x", got, want)
	}

	r := NewReader(got)
	if v := r.ReadUint8(); v != 0x01 {
		t.Errorf("ReadUint8 = %#x", v)
	}
	if v := r.ReadUint16(); v != 0x0203 {
		t.Errorf("ReadUint16 = %#x", v)
	}
	if v := r.ReadUint32(); v != 0x04050607 {
		t.Errorf("ReadUint32 = %#x", v)
	}
	if v := r.ReadUint64(); v != 0x08090a0b0c0d0e0f {
		t.Errorf("ReadUint64 = %#x", v)
	}
	if !r.Empty() || r.Err() != nil {
		t.Errorf("after reads: empty = %v, err = %v", r.Empty(), r.Err())
	}
}

func TestOpaque(t *testing.T) {
	tests := []struct {
		name string
		val  string // hex
		enc  string // hex
	}{
		{"empty", "", "00"},
		{"short", "abcd", "02abcd"},
		{"63 bytes", strings.Repeat("ff", 63), "3f" + strings.Repeat("ff", 63)},
		{"64 bytes", strings.Repeat("ff", 64), "4040" + strings.Repeat("ff", 64)},
	}
	for _, tt := range tests {
		val, enc := decodeHex(t, tt.val), decodeHex(t, tt.enc)
		var w Writer
		w.WriteOpaque(val)
		got, err := w.Bytes()
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if !bytes.Equal(got, enc) {
			t.Errorf("%s: WriteOpaque = %x, want %x", tt.name, got, enc)
		}
		r := NewReader(enc)
		if back := r.ReadOpaque(); !bytes.Equal(back, val) || r.Err() != nil {
			t.Errorf("%s: ReadOpaque = %x, %v, want %x, nil", tt.name, back, r.Err(), val)
		}
	}
}

func TestOpaqueDoesNotAlias(t *testing.T) {
	enc := decodeHex(t, "02abcd")
	b := NewReader(enc).ReadOpaque()
	b[0] = 0
	if enc[1] != 0xab {
		t.Error("ReadOpaque aliases the reader's input")
	}
}

// uint16s is a vector of uint16, standing in for the enum vectors of
// RFC 9420 such as Capabilities.versions.
type uint16s []uint16

func (v *uint16s) MarshalTLS(w *Writer) {
	w.WriteVector(func(w *Writer) {
		for _, x := range *v {
			w.WriteUint16(x)
		}
	})
}

func (v *uint16s) UnmarshalTLS(r *Reader) {
	*v = nil
	r.ReadAll(func(r *Reader) { *v = append(*v, r.ReadUint16()) })
}

func TestVector(t *testing.T) {
	tests := []struct {
		name string
		val  uint16s
		enc  string
	}{
		{"empty", nil, "00"},
		{"one", uint16s{1}, "020001"},
		{"three", uint16s{1, 2, 3}, "06000100020003"},
	}
	for _, tt := range tests {
		enc := decodeHex(t, tt.enc)
		got, err := Marshal(&tt.val)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if !bytes.Equal(got, enc) {
			t.Errorf("%s: Marshal = %x, want %x", tt.name, got, enc)
		}
		var back uint16s
		if err := Unmarshal(enc, &back); err != nil {
			t.Errorf("%s: Unmarshal: %v", tt.name, err)
		} else if len(back) != len(tt.val) {
			t.Errorf("%s: Unmarshal = %v, want %v", tt.name, back, tt.val)
		}
	}
}

func TestVectorTruncated(t *testing.T) {
	r := NewReader(decodeHex(t, "060001"))
	r.ReadVector()
	if r.Err() == nil {
		t.Error("ReadVector of truncated vector succeeded, want error")
	}
}

func TestOptional(t *testing.T) {
	var w Writer
	w.WriteOptional(nil)
	w.WriteOptional(func(w *Writer) { w.WriteUint16(0x0102) })
	got, err := w.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := decodeHex(t, "00010102")
	if !bytes.Equal(got, want) {
		t.Fatalf("encoding = %x, want %x", got, want)
	}

	r := NewReader(got)
	if r.ReadOptional() {
		t.Error("first optional is present, want absent")
	}
	if !r.ReadOptional() {
		t.Fatal("second optional is absent, want present")
	}
	if v := r.ReadUint16(); v != 0x0102 {
		t.Errorf("value = %#x", v)
	}
}

func TestOptionalMalformed(t *testing.T) {
	r := NewReader([]byte{2})
	r.ReadOptional()
	if r.Err() == nil {
		t.Error("presence octet 2 accepted, want error")
	}
}

// TestErrorIsSticky checks that a failure deep inside a vector is
// visible to the reader that created it, and that reads after a
// failure neither panic nor loop.
func TestErrorIsSticky(t *testing.T) {
	r := NewReader(decodeHex(t, "0400010002"))
	v := r.ReadVector()
	v.ReadUint64() // only four bytes available
	if r.Err() == nil {
		t.Fatal("error in sub-reader not visible in parent")
	}
	if !v.Empty() || !r.Empty() {
		t.Error("readers not empty after error")
	}
	for range 3 {
		r.ReadUint32()
		r.ReadOpaque()
		r.ReadVarint()
	}
}

func TestUnmarshalTrailingData(t *testing.T) {
	var v uint16s
	if err := Unmarshal(decodeHex(t, "020001ff"), &v); err == nil {
		t.Error("Unmarshal with trailing data succeeded, want error")
	}
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
