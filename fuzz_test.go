package mls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/tmc/mls/tlssyntax"
)

// seed adds every value of the named fields of the messages test
// vector to f's corpus, so that fuzzing starts from encodings the
// working group produced rather than from random bytes.
func seed(f *testing.F, fields ...string) {
	f.Helper()
	data, err := os.ReadFile("testdata/messages.json")
	if err != nil {
		f.Fatal(err)
	}
	var vectors []map[string]string
	if err := json.Unmarshal(data, &vectors); err != nil {
		f.Fatal(err)
	}
	for _, v := range vectors {
		for _, name := range fields {
			b, err := hex.DecodeString(v[name])
			if err != nil || len(b) == 0 {
				continue
			}
			f.Add(b)
		}
	}
}

// roundTrip checks that a value decoded from data re-encodes to data.
// A decoder that accepts two encodings of one value lets an attacker
// change the bytes a signature or a hash covers without changing the
// value they are checked against.
func roundTrip(t *testing.T, data []byte, v interface {
	tlssyntax.Marshaler
	tlssyntax.Unmarshaler
}) {
	t.Helper()
	if err := Unmarshal(data, v); err != nil {
		return
	}
	out, err := Marshal(v)
	if err != nil {
		t.Fatalf("decoded but would not re-encode: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Fatalf("round trip changed the encoding:\n in %x\nout %x", data, out)
	}
}

func FuzzMessage(f *testing.F) {
	seed(f, "mls_welcome", "mls_group_info", "mls_key_package",
		"public_message_application", "public_message_proposal",
		"public_message_commit", "private_message")
	f.Fuzz(func(t *testing.T, data []byte) {
		roundTrip(t, data, new(Message))
	})
}

func FuzzKeyPackage(f *testing.F) {
	seed(f, "mls_key_package")
	f.Fuzz(func(t *testing.T, data []byte) {
		kp := new(KeyPackage)
		if err := Unmarshal(data, kp); err != nil {
			return
		}
		// Validation runs on attacker bytes before anything
		// trusts them, so it must not panic either.
		_ = kp.Validate(time.Time{})
		roundTrip(t, data, new(KeyPackage))
	})
}

func FuzzRatchetTree(f *testing.F) {
	seed(f, "ratchet_tree")
	f.Fuzz(func(t *testing.T, data []byte) {
		var tree RatchetTree
		if err := Unmarshal(data, &tree); err != nil {
			return
		}
		cs := X25519AES128GCMSHA256Ed25519
		_, _ = tree.RootHash(cs)
		_ = tree.VerifyParentHashes(cs)
		for i := range min(tree.Size(), 64) {
			_ = tree.Leaf(i)
			_ = tree.Resolution(i.NodeIndex())
		}
		roundTrip(t, data, new(RatchetTree))
	})
}

func FuzzWelcome(f *testing.F) {
	seed(f, "mls_welcome")
	f.Fuzz(func(t *testing.T, data []byte) {
		roundTrip(t, data, new(Welcome))
	})
}

func FuzzGroupInfo(f *testing.F) {
	seed(f, "mls_group_info")
	f.Fuzz(func(t *testing.T, data []byte) {
		roundTrip(t, data, new(GroupInfo))
	})
}

func FuzzProposal(f *testing.F) {
	seed(f, "add_proposal", "update_proposal", "remove_proposal",
		"pre_shared_key_proposal", "re_init_proposal",
		"external_init_proposal", "group_context_extensions_proposal")
	f.Fuzz(func(t *testing.T, data []byte) {
		roundTrip(t, data, new(Proposal))
	})
}
