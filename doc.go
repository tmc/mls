// Package mls implements the wire format of the Messaging Layer
// Security protocol, RFC 9420.
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
// This package does not implement the protocol itself. It has no key
// schedule, no ratchet tree operations, and it neither produces nor
// verifies signatures; a decoded structure is well formed but not
// authenticated.
package mls

import "github.com/tmc/mls/tlssyntax"

// Marshal returns the encoding of v.
func Marshal(v tlssyntax.Marshaler) ([]byte, error) { return tlssyntax.Marshal(v) }

// Unmarshal decodes data into v. It reports an error if decoding fails
// or if any bytes remain after v is decoded.
func Unmarshal(data []byte, v tlssyntax.Unmarshaler) error { return tlssyntax.Unmarshal(data, v) }
