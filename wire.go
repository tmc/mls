package mls

import "fmt"

// A ProtocolVersion identifies a version of the protocol.
type ProtocolVersion uint16

// Protocol versions. See RFC 9420, Section 6.
const (
	Version10 ProtocolVersion = 1
)

// String returns the name of the protocol version.
func (v ProtocolVersion) String() string {
	return enumString("ProtocolVersion", uint64(v), []string{"reserved", "mls10"})
}

// A CipherSuite identifies the set of cryptographic algorithms a group
// uses. See RFC 9420, Section 17.1.
type CipherSuite uint16

// Cipher suites.
const (
	X25519AES128GCMSHA256Ed25519        CipherSuite = 1
	P256AES128GCMSHA256P256             CipherSuite = 2
	X25519ChaCha20Poly1305SHA256Ed25519 CipherSuite = 3
	X448AES256GCMSHA512Ed448            CipherSuite = 4
	P521AES256GCMSHA512P521             CipherSuite = 5
	X448ChaCha20Poly1305SHA512Ed448     CipherSuite = 6
	P384AES256GCMSHA384P384             CipherSuite = 7
)

// String returns the name RFC 9420 gives the cipher suite, or its
// number if it is not one this package knows.
func (c CipherSuite) String() string {
	return enumString("CipherSuite", uint64(c), []string{
		"reserved",
		"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
		"MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
		"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519",
		"MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448",
		"MLS_256_DHKEMP521_AES256GCM_SHA512_P521",
		"MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448",
		"MLS_256_DHKEMP384_AES256GCM_SHA384_P384",
	})
}

// A WireFormat identifies which message an [MLSMessage] carries.
type WireFormat uint16

// Wire formats. See RFC 9420, Section 17.5.
const (
	WireFormatPublicMessage  WireFormat = 1
	WireFormatPrivateMessage WireFormat = 2
	WireFormatWelcome        WireFormat = 3
	WireFormatGroupInfo      WireFormat = 4
	WireFormatKeyPackage     WireFormat = 5
)

// String returns the name of the wire format.
func (f WireFormat) String() string {
	return enumString("WireFormat", uint64(f), []string{
		"reserved", "mls_public_message", "mls_private_message",
		"mls_welcome", "mls_group_info", "mls_key_package",
	})
}

// A ContentType identifies what a FramedContent carries.
type ContentType uint8

// Content types. See RFC 9420, Section 6.
const (
	ContentTypeApplication ContentType = 1
	ContentTypeProposal    ContentType = 2
	ContentTypeCommit      ContentType = 3
)

// String returns the name of the content type.
func (t ContentType) String() string {
	return enumString("ContentType", uint64(t), []string{"reserved", "application", "proposal", "commit"})
}

// A SenderType identifies the kind of sender of a FramedContent.
type SenderType uint8

// Sender types. See RFC 9420, Section 6.
const (
	SenderTypeMember            SenderType = 1
	SenderTypeExternal          SenderType = 2
	SenderTypeNewMemberProposal SenderType = 3
	SenderTypeNewMemberCommit   SenderType = 4
)

// String returns the name of the sender type.
func (t SenderType) String() string {
	return enumString("SenderType", uint64(t), []string{
		"reserved", "member", "external", "new_member_proposal", "new_member_commit",
	})
}

// A ProposalType identifies the kind of change a Proposal requests.
type ProposalType uint16

// Proposal types. See RFC 9420, Section 17.4.
const (
	ProposalTypeAdd                    ProposalType = 1
	ProposalTypeUpdate                 ProposalType = 2
	ProposalTypeRemove                 ProposalType = 3
	ProposalTypePreSharedKey           ProposalType = 4
	ProposalTypeReInit                 ProposalType = 5
	ProposalTypeExternalInit           ProposalType = 6
	ProposalTypeGroupContextExtensions ProposalType = 7
)

// String returns the name of the proposal type, or its number if it
// is not one this package knows.
func (t ProposalType) String() string {
	return enumString("ProposalType", uint64(t), []string{
		"reserved", "add", "update", "remove", "psk", "reinit",
		"external_init", "group_context_extensions",
	})
}

// A NodeType identifies which node a ratchet tree entry holds.
type NodeType uint8

// Node types. See RFC 9420, Section 12.4.3.1.
const (
	NodeTypeLeaf   NodeType = 1
	NodeTypeParent NodeType = 2
)

// String returns the name of the node type.
func (t NodeType) String() string {
	return enumString("NodeType", uint64(t), []string{"reserved", "leaf", "parent"})
}

// A LeafNodeSource records why a [LeafNode] was created, and decides
// which of its variant fields is present.
type LeafNodeSource uint8

// Leaf node sources. See RFC 9420, Section 7.2.
const (
	LeafNodeSourceKeyPackage LeafNodeSource = 1
	LeafNodeSourceUpdate     LeafNodeSource = 2
	LeafNodeSourceCommit     LeafNodeSource = 3
)

// String returns the name of the leaf node source.
func (s LeafNodeSource) String() string {
	return enumString("LeafNodeSource", uint64(s), []string{"reserved", "key_package", "update", "commit"})
}

// An HPKEPublicKey is a public key for HPKE encryption, in the format
// the group's cipher suite defines.
type HPKEPublicKey []byte

// A SignaturePublicKey is a public key for signature verification, in
// the format the group's cipher suite defines.
type SignaturePublicKey []byte

// A HashReference names another object by hash. A KeyPackageRef names
// a [KeyPackage]; a ProposalRef names a proposal.
// See RFC 9420, Section 5.2.
type HashReference []byte

// enumString returns the specification's name for value v, or a
// numeric form for values outside the registry.
func enumString(kind string, v uint64, names []string) string {
	if v < uint64(len(names)) {
		return names[v]
	}
	return fmt.Sprintf("%s(%d)", kind, v)
}
