package tlssyntax

//go:generate curl -sSfo testdata/deserialization.json https://raw.githubusercontent.com/mlswg/mls-implementations/cfd450286d1bfd9cd2519b95c80f9771f94a5b1a/test-vectors/deserialization.json

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// maxBodyVector is the longest body TestDeserializationVectors builds.
// The vectors go up to MaxVectorLen, and a 1 GiB body, copied while
// decoding and encoding, costs several gigabytes, more than a CI
// runner has under the race detector.
const maxBodyVector = 1 << 16

// TestDeserializationVectors checks the variable-length header of
// RFC 9420, Section 2.1.2 against the working group's vectors, at
// https://github.com/mlswg/mls-implementations. Each vector is a
// header and the length it encodes.
func TestDeserializationVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/deserialization.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Header string `json:"vlbytes_header"`
		Length int    `json:"length"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}
	for _, vec := range vectors {
		header, err := hex.DecodeString(vec.Header)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", vec.Header, err)
		}

		// The header alone must decode to the length, using all of
		// its bytes, and the length must encode to the header.
		var n uint64
		if err := Unmarshal(header, UnmarshalerFunc(func(r *Reader) {
			n = r.ReadVarint()
		})); err != nil {
			t.Errorf("%s: Unmarshal: %v", vec.Header, err)
			continue
		}
		if n != uint64(vec.Length) {
			t.Errorf("%s: decoded length %d, want %d", vec.Header, n, vec.Length)
		}
		if got := appendVarint(nil, uint64(vec.Length)); !bytes.Equal(got, header) {
			t.Errorf("length %d encoded as %x, want %s", vec.Length, got, vec.Header)
		}
		if vec.Length > maxBodyVector {
			continue
		}

		// Decoding the header and the body it announces must
		// consume exactly the vector's length of bytes.
		body := bytes.Repeat([]byte{'x'}, vec.Length)
		var got []byte
		if err := Unmarshal(append(header, body...), UnmarshalerFunc(func(r *Reader) {
			got = r.ReadOpaque()
		})); err != nil {
			t.Errorf("%s: Unmarshal: %v", vec.Header, err)
			continue
		}
		if len(got) != vec.Length {
			t.Errorf("%s: decoded %d bytes, want %d", vec.Header, len(got), vec.Length)
		}

		// Encoding a body of that length must reproduce the header.
		enc, err := Marshal(MarshalerFunc(func(w *Writer) {
			w.WriteOpaque(body)
		}))
		if err != nil {
			t.Errorf("%s: Marshal: %v", vec.Header, err)
			continue
		}
		if !bytes.Equal(enc[:len(enc)-vec.Length], header) {
			t.Errorf("length %d encoded as %x, want %s", vec.Length, enc[:len(enc)-vec.Length], vec.Header)
		}
	}
}
