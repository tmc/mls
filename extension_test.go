package mls

import (
	"bytes"
	"slices"
	"testing"
)

func TestExtensionRoundTrip(t *testing.T) {
	var es Extensions
	want := &RequiredCapabilities{
		ExtensionTypes:  []ExtensionType{ExtensionTypeApplicationID},
		ProposalTypes:   []ProposalType{ProposalTypeAdd, ProposalTypeRemove},
		CredentialTypes: []CredentialType{CredentialTypeBasic},
	}
	if err := es.Set(ExtensionTypeRequiredCapabilities, want); err != nil {
		t.Fatal(err)
	}
	if err := es.Set(ExtensionTypeApplicationID, &ApplicationID{ID: []byte("id")}); err != nil {
		t.Fatal(err)
	}
	// Setting again replaces rather than duplicating.
	if err := es.Set(ExtensionTypeApplicationID, &ApplicationID{ID: []byte("other")}); err != nil {
		t.Fatal(err)
	}
	if len(es) != 2 {
		t.Fatalf("got %d extensions, want 2", len(es))
	}

	b, err := Marshal(&es)
	if err != nil {
		t.Fatal(err)
	}
	var got Extensions
	if err := Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}

	var caps RequiredCapabilities
	if ok, err := got.Decode(ExtensionTypeRequiredCapabilities, &caps); err != nil || !ok {
		t.Fatalf("Get required_capabilities = %v, %v", ok, err)
	}
	if !slices.Equal(caps.ProposalTypes, want.ProposalTypes) {
		t.Errorf("proposal types = %v, want %v", caps.ProposalTypes, want.ProposalTypes)
	}
	var id ApplicationID
	if _, err := got.Decode(ExtensionTypeApplicationID, &id); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id.ID, []byte("other")) {
		t.Errorf("application id = %q, want %q", id.ID, "other")
	}

	// A missing extension is not an error.
	var pub ExternalPub
	if ok, err := got.Decode(ExtensionTypeExternalPub, &pub); ok || err != nil {
		t.Errorf("Get external_pub = %v, %v, want false, nil", ok, err)
	}
}

func TestDuplicateExtension(t *testing.T) {
	es := Extensions{
		{Type: ExtensionTypeApplicationID, Data: []byte("a")},
		{Type: ExtensionTypeApplicationID, Data: []byte("b")},
	}
	b, err := Marshal(&es)
	if err != nil {
		t.Fatal(err)
	}
	var got Extensions
	if err := Unmarshal(b, &got); err == nil {
		t.Error("Unmarshal accepted two extensions of the same type")
	}
}

func TestRequiredCapabilitiesSupported(t *testing.T) {
	caps := &Capabilities{
		Extensions:  []ExtensionType{ExtensionTypeApplicationID},
		Proposals:   []ProposalType{ProposalTypeAdd},
		Credentials: []CredentialType{CredentialTypeBasic},
	}
	for _, tc := range []struct {
		name string
		req  RequiredCapabilities
		want bool
	}{
		{"empty", RequiredCapabilities{}, true},
		{"met", RequiredCapabilities{ExtensionTypes: []ExtensionType{ExtensionTypeApplicationID}}, true},
		{"unmet extension", RequiredCapabilities{ExtensionTypes: []ExtensionType{ExtensionTypeExternalPub}}, false},
		{"unmet proposal", RequiredCapabilities{ProposalTypes: []ProposalType{ProposalTypeReInit}}, false},
		{"unmet credential", RequiredCapabilities{CredentialTypes: []CredentialType{CredentialTypeX509}}, false},
	} {
		if got := tc.req.Supported(caps); got != tc.want {
			t.Errorf("%s: Supported = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestGREASE(t *testing.T) {
	for _, t16 := range []ExtensionType{0x0a0a, 0x1a1a, 0x5a5a, 0xaaaa, 0xbaba, 0xeaea} {
		if !t16.GREASE() {
			t.Errorf("%#04x: GREASE = false, want true", uint16(t16))
		}
	}
	for _, t16 := range []ExtensionType{0, 1, 2, 3, 4, 5, 0x0a0b, 0xf000} {
		if t16.GREASE() {
			t.Errorf("%#04x: GREASE = true, want false", uint16(t16))
		}
	}
}
