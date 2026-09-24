package mls

import (
	"bytes"
	"testing"
)

func TestParseHeader(t *testing.T) {
	cs := testSuite()
	alice := newTestClient(t, cs, "alice")
	bob := newTestClient(t, cs, "bob")
	g, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	add := &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}}
	next, commit, welcome, err := g.Commit([]*Proposal{add})
	if err != nil {
		t.Fatal(err)
	}
	app, err := next.Protect(nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	keyPackage := &Message{Version: Version10, WireFormat: WireFormatKeyPackage, KeyPackage: bob.KeyPackage}

	for _, tc := range []struct {
		name  string
		msg   *Message
		epoch uint64
		group []byte
	}{
		{"public", commit, 0, []byte("group")},
		{"private", app, 1, []byte("group")},
		{"welcome", welcome, 0, nil},
		{"key package", keyPackage, 0, nil},
	} {
		b, err := Marshal(tc.msg)
		if err != nil {
			t.Fatal(err)
		}
		h, err := ParseHeader(b)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if h.Version != Version10 || h.WireFormat != tc.msg.WireFormat {
			t.Errorf("%s: got %v %v, want %v %v", tc.name, h.Version, h.WireFormat, Version10, tc.msg.WireFormat)
		}
		if !bytes.Equal(h.GroupID, tc.group) || (h.GroupID == nil) != (tc.group == nil) {
			t.Errorf("%s: group = %q, want %q", tc.name, h.GroupID, tc.group)
		}
		if h.Epoch != tc.epoch {
			t.Errorf("%s: epoch = %d, want %d", tc.name, h.Epoch, tc.epoch)
		}
	}

	// A wire format this package cannot decode still routes: the
	// header is all a relay needs, and the rest must reach the
	// recipient unchanged.
	unknown := []byte{0, 1, 0, 99, 1, 2, 3}
	h, err := ParseHeader(unknown)
	if err != nil {
		t.Fatalf("unknown wire format: %v", err)
	}
	if h.WireFormat != 99 || h.GroupID != nil {
		t.Errorf("unknown wire format: got %v, %q", h.WireFormat, h.GroupID)
	}
	if err := Unmarshal(unknown, new(Message)); err == nil {
		t.Error("Unmarshal accepted an unknown wire format")
	}

	for _, tc := range []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"short header", []byte{0, 1, 0}},
		{"truncated group", []byte{0, 1, 0, 1, 5, 'a'}},
		{"truncated epoch", []byte{0, 1, 0, 2, 1, 'a', 0, 0}},
	} {
		if _, err := ParseHeader(tc.b); err == nil {
			t.Errorf("%s: ParseHeader succeeded", tc.name)
		}
	}
}
