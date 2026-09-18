package mls

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestVariants checks that each variant record encodes only the fields
// its selector admits.
func TestVariants(t *testing.T) {
	tests := []struct {
		name string
		val  message
		enc  string
	}{
		{
			"basic credential",
			&Credential{Type: CredentialTypeBasic, Identity: []byte("bob")},
			"0001" + "03" + "626f62",
		},
		{
			"x509 credential",
			&Credential{Type: CredentialTypeX509, Certificates: [][]byte{{0xaa}, {0xbb}}},
			"0002" + "04" + "01aa" + "01bb",
		},
		{
			"leaf node from update carries neither lifetime nor parent hash",
			&Update{LeafNode: LeafNode{
				EncryptionKey: []byte{0x01},
				SignatureKey:  []byte{0x02},
				Credential:    Credential{Type: CredentialTypeBasic, Identity: []byte{0x03}},
				Source:        LeafNodeSourceUpdate,
				Signature:     []byte{0x04},
			}},
			"0101" + "0102" + "0001" + "0103" + "0000000000" + "02" + "00" + "0104",
		},
		{
			"leaf node from commit carries a parent hash",
			&Update{LeafNode: LeafNode{
				EncryptionKey: []byte{0x01},
				SignatureKey:  []byte{0x02},
				Credential:    Credential{Type: CredentialTypeBasic, Identity: []byte{0x03}},
				Source:        LeafNodeSourceCommit,
				ParentHash:    []byte{0x05},
				Signature:     []byte{0x04},
			}},
			"0101" + "0102" + "0001" + "0103" + "0000000000" + "03" + "0105" + "00" + "0104",
		},
		{
			"blank ratchet tree nodes are absent optionals",
			&RatchetTree{nil, nil},
			"02" + "00" + "00",
		},
	}
	for _, tt := range tests {
		want, err := hex.DecodeString(tt.enc)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", tt.name, err)
		}
		got, err := Marshal(tt.val)
		if err != nil {
			t.Errorf("%s: Marshal: %v", tt.name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: Marshal = %x, want %x", tt.name, got, want)
		}
	}
}

func TestUnknownVariant(t *testing.T) {
	tests := []struct {
		name string
		enc  string
		val  message
	}{
		{"credential type", "0009" + "00", new(Credential)},
		{"node type", "09", new(Node)},
		{"wire format", "0001" + "0009", new(MLSMessage)},
	}
	for _, tt := range tests {
		if err := Unmarshal(mustHex(t, tt.enc), tt.val); err == nil {
			t.Errorf("%s: Unmarshal of unknown variant succeeded, want error", tt.name)
		}
	}
}

func TestTruncated(t *testing.T) {
	// A key package encoding, cut short at every length.
	full, err := Marshal(&KeyPackage{
		Version:     Version10,
		CipherSuite: X25519AES128GCMSHA256Ed25519,
		InitKey:     []byte("init"),
		LeafNode: LeafNode{
			Credential: Credential{Type: CredentialTypeBasic, Identity: []byte("carol")},
			Source:     LeafNodeSourceKeyPackage,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(full); n++ {
		if err := Unmarshal(full[:n], new(KeyPackage)); err == nil {
			t.Errorf("Unmarshal of %d-byte prefix succeeded, want error", n)
		}
	}
	if err := Unmarshal(full, new(KeyPackage)); err != nil {
		t.Errorf("Unmarshal of whole encoding: %v", err)
	}
}

func TestEnumStrings(t *testing.T) {
	tests := []struct {
		got  string
		want string
	}{
		{Version10.String(), "mls10"},
		{ProtocolVersion(7).String(), "ProtocolVersion(7)"},
		{WireFormatKeyPackage.String(), "mls_key_package"},
		{CredentialTypeX509.String(), "x509"},
		{LeafNodeSourceCommit.String(), "commit"},
		{NodeTypeParent.String(), "parent"},
		{ProposalTypeGroupContextExtensions.String(), "group_context_extensions"},
		{ContentTypeCommit.String(), "commit"},
		{SenderTypeNewMemberCommit.String(), "new_member_commit"},
		{ExtensionTypeRatchetTree.String(), "ratchet_tree"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("String() = %q, want %q", tt.got, tt.want)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
