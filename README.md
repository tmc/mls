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
var msg mls.MLSMessage
if err := mls.Unmarshal(data, &msg); err != nil {
	return err
}
if msg.WireFormat == mls.WireFormatKeyPackage {
	fmt.Println(msg.KeyPackage.LeafNode.Credential.Identity)
}
```

## State

Complete for the five cipher suites the Go standard library can
provide. The wire format covers every structure in RFC 9420, and above
it the package implements the cipher suites (over the Go 1.27
`crypto/hpke` package), the key schedule, the secret tree and its
ratchets, transcript hashes, signatures and hash references, message
framing and protection, the ratchet tree with its hashes and parent
hashes, TreeKEM update paths, and the group state machine.

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

Not implemented: external commits, external joins, and reinitialization.

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

[RFC 9420]: https://www.rfc-editor.org/rfc/rfc9420.html
[test vectors]: https://github.com/mlswg/mls-implementations
