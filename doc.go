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
// implements the tree hashes, parent hashes and membership changes.
// [AuthenticatedContent] frames and encrypts messages.
//
// Two of the seven cipher suites need X448 and Ed448, which the Go
// standard library does not provide; they report
// [ErrUnsupportedCipherSuite]. Decoding never authenticates: a
// decoded structure is well formed, and the caller must still verify
// its signatures.
//
// This package does not implement the group state machine. It has the
// pieces a client needs, but the client drives them.
package mls

import "github.com/tmc/mls/tlssyntax"

// Marshal returns the encoding of v.
func Marshal(v tlssyntax.Marshaler) ([]byte, error) { return tlssyntax.Marshal(v) }

// Unmarshal decodes data into v. It reports an error if decoding fails
// or if any bytes remain after v is decoded.
func Unmarshal(data []byte, v tlssyntax.Unmarshaler) error { return tlssyntax.Unmarshal(data, v) }
