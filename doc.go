// Package mls implements the Messaging Layer Security protocol,
// RFC 9420.
//
// This package defines the protocol's structures and their encodings.
// Each structure implements [github.com/tmc/mls/tlssyntax.Marshaler]
// and [github.com/tmc/mls/tlssyntax.Unmarshaler], so [Marshal] and
// [Unmarshal] convert between a structure and its encoding:
//
//	var kp mls.KeyPackage
//	if err := mls.Unmarshal(data, &kp); err != nil {
//		return err
//	}
//
// The structures follow the specification field for field, including
// its variant records: a structure that the specification writes as a
// select carries the selector as an ordinary field, and only the
// fields that selector admits are encoded. [LeafNode.Source], for
// example, decides whether a LeafNode carries a lifetime, a parent
// hash, or neither.
//
// Above the wire format, the package provides the cryptographic layer
// the protocol is built from: [CipherSuite] holds the labeled
// derivation, signature and HPKE operations of Section 5 and
// Section 8, [KeySchedule] derives an epoch's secrets, [SecretTree]
// derives the keys that protect its messages, and [RatchetTree]
// implements the tree hashes, parent hashes, membership changes and
// TreeKEM update paths. [AuthenticatedContent] frames and encrypts
// messages.
//
// [Client] and [Group] tie these together into the group state
// machine. A client generates its keys with [NewClient] and either
// starts a group with [Client.NewGroup] or joins one from a welcome
// message with [Client.Join]. A [Group] is one epoch's state, and
// processing a commit does not change it: [Group.Commit] and
// [Group.Handle] return the group's state in the epoch that the
// commit begins, so a caller that has not yet confirmed a commit can
// keep using the epoch it has.
//
//	alice, err := mls.NewClient(cs, cred, 24*time.Hour)
//	g, err := alice.NewGroup(groupID, nil)
//	next, commit, welcome, err := g.Commit([]*mls.Proposal{add})
//
// Two of the seven cipher suites need X448 and Ed448, which the Go
// standard library does not provide; they report
// [ErrUnsupportedCipherSuite]. Decoding never authenticates: a
// decoded structure is well formed, and the caller must still verify
// its signatures.
//
// Credential types outside RFC 9420 are registered by subpackages:
// see [RegisterCredential] and [github.com/tmc/mls/multicred].
package mls

import "github.com/tmc/mls/tlssyntax"

// Marshal returns the encoding of v.
func Marshal(v tlssyntax.Marshaler) ([]byte, error) { return tlssyntax.Marshal(v) }

// Unmarshal decodes data into v. It reports an error if decoding fails
// or if any bytes remain after v is decoded.
func Unmarshal(data []byte, v tlssyntax.Unmarshaler) error { return tlssyntax.Unmarshal(data, v) }
