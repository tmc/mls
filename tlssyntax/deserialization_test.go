package tlssyntax_test

//go:generate curl -sSfo testdata/deserialization.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/deserialization.json

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/tmc/mls/tlssyntax"
)

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

		// Decoding the header and the body it announces must
		// consume exactly the vector's length of bytes.
		body := bytes.Repeat([]byte{'x'}, vec.Length)
		var got []byte
		if err := tlssyntax.Unmarshal(append(header, body...), tlssyntax.UnmarshalerFunc(func(r *tlssyntax.Reader) {
			got = r.ReadOpaque()
		})); err != nil {
			t.Errorf("%s: Unmarshal: %v", vec.Header, err)
			continue
		}
		if len(got) != vec.Length {
			t.Errorf("%s: decoded %d bytes, want %d", vec.Header, len(got), vec.Length)
		}

		// Encoding a body of that length must reproduce the header.
		enc, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
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
