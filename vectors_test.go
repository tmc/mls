package mls

//go:generate curl -sSfo testdata/messages.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/messages.json

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/tmc/mls/tlssyntax"
)

// A message is a protocol structure that encodes and decodes itself.
type message interface {
	tlssyntax.Marshaler
	tlssyntax.Unmarshaler
}

// messageFields maps each field of the "messages" test vector to the
// structure it holds. The vectors are at
// https://github.com/mlswg/mls-implementations, described in
// test-vectors.md: each field is the encoding of a structure filled
// with random values, and an implementation passes by decoding it and
// re-encoding it to the same bytes.
var messageFields = map[string]func() message{
	"mls_welcome":                       func() message { return new(Message) },
	"mls_group_info":                    func() message { return new(Message) },
	"mls_key_package":                   func() message { return new(Message) },
	"ratchet_tree":                      func() message { return new(RatchetTree) },
	"add_proposal":                      func() message { return new(Add) },
	"update_proposal":                   func() message { return new(Update) },
	"remove_proposal":                   func() message { return new(Remove) },
	"group_context_extensions_proposal": func() message { return new(GroupContextExtensions) },
	"pre_shared_key_proposal":           func() message { return new(PreSharedKey) },
	"re_init_proposal":                  func() message { return new(ReInit) },
	"external_init_proposal":            func() message { return new(ExternalInit) },
	"group_secrets":                     func() message { return new(GroupSecrets) },
	"commit":                            func() message { return new(Commit) },
	"public_message_application":        func() message { return new(Message) },
	"public_message_proposal":           func() message { return new(Message) },
	"public_message_commit":             func() message { return new(Message) },
	"private_message":                   func() message { return new(Message) },
}

// unsupportedFields are the fields of the "messages" test vector whose
// structures this package does not implement yet. Listing them keeps
// TestMessageVectors from quietly ignoring a field it ought to cover.
var unsupportedFields = map[string]string{}

func TestMessageVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []map[string]string
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}

	covered := 0
	for i, vec := range vectors {
		for field, enc := range vec {
			newMessage, ok := messageFields[field]
			if !ok {
				if _, known := unsupportedFields[field]; !known {
					t.Errorf("vector %d: field %q is neither implemented nor listed as unsupported", i, field)
				}
				continue
			}
			want, err := hex.DecodeString(enc)
			if err != nil {
				t.Fatalf("vector %d: field %q: bad hex: %v", i, field, err)
			}
			m := newMessage()
			if err := Unmarshal(want, m); err != nil {
				t.Errorf("vector %d: Unmarshal %s: %v", i, field, err)
				continue
			}
			got, err := Marshal(m)
			if err != nil {
				t.Errorf("vector %d: Marshal %s: %v", i, field, err)
				continue
			}
			if !bytes.Equal(got, want) {
				t.Errorf("vector %d: %s re-encoded differently\n got %x\nwant %x", i, field, got, want)
				continue
			}
			covered++
		}
	}
	t.Logf("round-tripped %d structures across %d vectors", covered, len(vectors))
}
