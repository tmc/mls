# mls

Package mls implements the Messaging Layer Security protocol,
[RFC 9420], with no dependencies beyond the Go standard library and
`golang.org/x/crypto`.

    go get github.com/tmc/mls

`tlssyntax` implements the TLS presentation language as MLS extends it:
optional values, and vectors with variable-size length headers. The
`mls` package defines the protocol's structures on top of it, along
with the cryptography that protects them.

```go
var msg mls.Message
if err := mls.Unmarshal(data, &msg); err != nil {
	return err
}
if msg.WireFormat == mls.WireFormatKeyPackage {
	fmt.Println(msg.KeyPackage.LeafNode.Credential.Identity)
}
```

## License

MIT. See [LICENSE](LICENSE). The test vectors in `testdata` come from
the MLS working group and carry their own license.

## State

Complete for the five cipher suites the Go standard library can
provide. The wire format covers every structure in RFC 9420, and above
it the package implements the cipher suites (over the Go 1.27
`crypto/hpke` package), the key schedule, the secret tree and its
ratchets, transcript hashes, signatures and hash references, message
framing and protection, the ratchet tree with its hashes and parent
hashes, TreeKEM update paths, the group state machine, external joins,
external proposals, reinitialization and branching.

```go
alice, err := mls.NewClient(cs, cred, 24*time.Hour)
g, err := alice.NewGroup(groupID, nil)
next, commit, welcome, err := g.Commit([]*mls.Proposal{
	{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *bobKeyPackage}},
})
```

Suites 4 and 6 need X448 and Ed448, which neither the standard library
nor `x/crypto` provides, and report `ErrUnsupportedCipherSuite`. Suite
3 uses ChaCha20-Poly1305 for message protection, which the standard
library exposes only through HPKE, so that one algorithm comes from
`golang.org/x/crypto/chacha20poly1305`; everything else is stdlib.

In FIPS 140-3 mode (`GODEBUG=fips140=on`, or a `GOFIPS140` build such
as the certified `v1.0.0` module), only suites 2, 5 and 7 (P-256,
P-521, P-384) are supported; the X25519 suites 1 and 3 report
`ErrUnsupportedCipherSuite`. `GODEBUG=fips140=only` is not supported:
MLS derives its own AES-GCM nonces, which the Go module does not approve
for encryption. See the package documentation.

Everything RFC 9420 defines is implemented for those suites.

The `multicred` subpackage implements the multi-credential and
weak multi-credential types of draft-ietf-mls-extensions, registered
through `mls.RegisterCredential`.

## Tests

The tests run the working group's [test vectors]. All sixteen suites
pass: `messages`, `deserialization`, `tree-math`, `crypto-basics`,
`key-schedule`, `psk_secret`, `transcript-hashes`, `secret-tree`,
`message-protection`, `tree-operations`, `tree-validation`, `welcome`,
`treekem`, `passive-client-welcome`, `passive-client-random`, and
`passive-client-handling-commit`. Cases on suites 4 and 6 are skipped.
The vector files are vendored in `testdata`; `go generate ./...`
refreshes them.

The wire format is fuzzed. `FuzzMessage`, `FuzzKeyPackage`,
`FuzzRatchetTree`, `FuzzWelcome`, `FuzzGroupInfo` and `FuzzProposal`
seed their corpora from the working group's own encodings and check
two properties: decoding must not panic, and anything that decodes
must re-encode to the bytes it came from. The second is the one that
matters for security, because a structure with two encodings lets an
attacker change the bytes a signature covers without changing the
value it is checked against.

    go test -fuzz FuzzMessage

## Security

This package has not been audited. It implements RFC 9420 and passes
the working group's vectors, which is evidence about correctness, not
about resistance to attack.

One property it does not claim: secrets live in ordinary Go byte
slices and are not zeroed when consumed, so RFC 9420 Section 9.2's
deletion requirement is met logically but not in memory.

Against traffic analysis the package offers only what RFC 9420 Section
15.1 offers, which is padding: set Client.Padding and Group.Protect
pads each message to a multiple of it. The default of zero pads
nothing and puts the exact length of every message on the wire.

Every operation that touches a private key runs under
crypto/subtle.WithDataIndependentTiming, which on an arm64 CPU with
FEAT_DIT removes the operand dependence of instructions whose latency
would otherwise vary. That is a floor, not a guarantee: it does not
make variable-time code constant time, and it does not hide the
cache-timing signal of the table-driven AES the standard library
falls back to on a CPU without AES instructions. On such a CPU prefer
a ChaCha20-Poly1305 cipher suite.

Report a vulnerability by opening an issue.

[RFC 9420]: https://www.rfc-editor.org/rfc/rfc9420.html
[test vectors]: https://github.com/mlswg/mls-implementations
