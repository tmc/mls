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
// Section 8, and [RatchetTree] implements the tree hashes, parent
// hashes, membership changes and TreeKEM update paths. The key
// schedule of Section 8 and the secret tree of Section 9 are internal
// to the package; a [Group] reaches them for you, and [Group.Export]
// is the supported way to derive an application secret from an epoch.
//
// [Client] and [Group] tie these together into the group state
// machine. RFC 9420, Section 14 requires that generating a commit not
// modify the client's state, since the delivery service may accept a
// different commit for the same epoch; this package enforces that by
// construction, because a [Group] is one epoch's state and a commit
// never modifies it. A client generates its keys with [NewClient] and either
// starts a group with [Client.NewGroup] or joins one from a welcome
// message with [Client.Join], or from a GroupInfo alone with
// [Client.JoinExternal], which is the external commit of Section 8.3.
// A party outside a group may propose to it as well, either as a
// sender the group provisioned ([ExternalClient.Propose]) or by
// asking to be added ([Client.ProposeAdd]); a member keeps such a
// proposal, and so commits it, only if its [Client.ExternalProposal]
// policy accepts it, and by default accepts none. A member replaces
// its own keys with [Group.ProposeUpdate], which keeps the new
// encryption key so that the member can follow the commit that
// applies it. A group ends either by losing its members or by being
// reinitialized: see [Group.Reinit], [Group.Reinitialize],
// [Group.Branch] and [Client.Resume].
//
// Processing a commit does not change the group it applies to:
// [Group.Commit] and [Group.Handle] return the group's state in the
// epoch that the commit begins, so a caller that has not yet
// confirmed a commit can keep using the epoch it has. Within an
// epoch, though, a Group is not immutable: protecting and
// unprotecting messages advance its ratchets and proposals are
// recorded in it, so a Group is not safe for concurrent use.
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
//
// # Post-quantum cipher suites
//
// The package also implements the eleven cipher suites of
// draft-ietf-mls-pq-ciphersuites-06, from
// [MLKEM768X25519AES128GCMSHA256Ed25519] to
// [MLKEM1024AES256GCMSHA384MLDSA87]. Their KEMs are the ML-KEM and
// hybrid KEMs of [crypto/hpke] (draft-ietf-hpke-pq), and three of them
// sign with ML-DSA from [crypto/mldsa]: pure ML-DSA with an empty
// context string, as draft-ietf-tls-mldsa specifies for TLS, over the
// same SignContent as every other suite (RFC 9420, Section 5.1.2).
// ECDSA signs with the hash its TLS signature scheme names, so a
// P-256 suite signs with SHA-256 even where the suite's hash is
// SHA-384.
//
// The draft leaves the code points to IANA, which has not assigned
// them. This package uses the provisional code points of OpenMLS,
// which carries these suites behind its draft-ietf-mls-pq-ciphersuites
// feature, so that the two can interoperate; OpenMLS has none for the
// MLKEM768-P256 and MLKEM1024-P384 suites, which use 0xF003 to 0xF005
// from the private-use range. Every one of these code points will
// change when IANA assigns the real ones, and the suites themselves
// may change with the draft.
//
// Key packages and commits in these suites are large: an ML-KEM-1024
// public key is 1568 bytes and an ML-DSA-87 signature 4627 bytes.
//
// # Security
//
// This package has not been audited. Passing the working group's
// vectors is evidence about correctness, not about resistance to
// attack.
//
// Every operation that touches a private key runs under
// [crypto/subtle.WithDataIndependentTiming], which on an arm64 CPU
// with FEAT_DIT removes the operand dependence of instructions whose
// latency would otherwise vary. That is a floor, not a guarantee. It
// does not make variable-time code constant time, and in particular
// it does not hide a cache-timing signal, because the mode says
// nothing about which memory a program touches. The case that
// matters here is AES: on a CPU without AES instructions the standard
// library falls back to a table-driven implementation whose lookups
// are indexed by key material, which is the input a flush-and-reload
// attacker measures. On such a CPU prefer a ChaCha20-Poly1305 cipher
// suite, whose implementation is table-free.
//
// One property the package does not claim: secrets live in ordinary
// Go byte slices and are not zeroed when consumed, so the deletion
// requirement of RFC 9420, Section 9.2 is met logically but not in
// memory; Go offers no way to guarantee a wipe survives the
// optimizer.
//
// Against traffic analysis the package offers what RFC 9420, Section
// 15.1 offers, which is padding: set [Client.Padding] and
// [Group.Protect] pads each message to a multiple of it. The default
// of zero pads nothing and puts the exact length of every message on
// the wire.
//
// # FIPS 140-3
//
// In FIPS 140-3 mode (see [crypto/fips140]), set by GODEBUG=fips140=on
// or by building with GOFIPS140, including the certified module
// version GOFIPS140=v1.0.0, only [P256AES128GCMSHA256P256],
// [P384AES256GCMSHA384P384], [P521AES256GCMSHA512P521] and the
// post-quantum suites that use neither X25519 nor ChaCha20-Poly1305
// are supported. The suites that use X25519 report
// [ErrUnsupportedCipherSuite], whether a client uses one or a received
// message names one: X25519 is not an approved algorithm, and
// ChaCha20-Poly1305 comes from golang.org/x/crypto, outside the
// module. That includes the MLKEM768-X25519 suites, although the
// module runs that hybrid as an approved ML-KEM service, since a
// deployment that needs approved algorithms has the MLKEM768-P256 and
// pure ML-KEM suites. The module v1.0.0 has no ML-DSA, so built with
// GOFIPS140=v1.0.0 the ML-DSA suites report
// [ErrUnsupportedCipherSuite] as well.
//
// GODEBUG=fips140=only is not supported. MLS derives each AES-GCM
// nonce itself, from the secret tree and the reuse guard (RFC 9420,
// Sections 6.3.1 and 9.1), and the module approves GCM encryption
// only with nonces it generates itself or builds for specific
// protocols such as TLS, SSH and HPKE. In fips140=on mode such
// encryption runs but is recorded as a non-approved service;
// decryption with a supplied nonce is approved. With
// GOFIPS140=v1.0.0 the same holds for the AES-GCM inside
// [crypto/hpke], which encrypts group secrets and path secrets. In
// fips140=only mode [crypto/cipher.NewGCM] refuses the construction,
// and [CipherSuite.AEAD] reports [ErrUnsupportedCipherSuite], so a
// group can neither protect nor unprotect messages.
package mls

import "github.com/tmc/mls/tlssyntax"

// Marshal returns the encoding of v.
func Marshal(v tlssyntax.Marshaler) ([]byte, error) { return tlssyntax.Marshal(v) }

// Unmarshal decodes data into v. It reports an error if decoding fails
// or if any bytes remain after v is decoded.
func Unmarshal(data []byte, v tlssyntax.Unmarshaler) error { return tlssyntax.Unmarshal(data, v) }
