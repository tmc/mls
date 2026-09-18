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

The wire format is complete: every structure in RFC 9420 encodes and
decodes.

Above it, the package implements the cipher suites (over the Go 1.27
`crypto/hpke` package), the key schedule, the secret tree and its
ratchets, transcript hashes, signatures and hash references, message
framing and protection, and the ratchet tree's hashes, parent hashes
and membership changes.

Not yet implemented: TreeKEM update paths, and the group state
machine that ties these together.

Five of the seven cipher suites are implemented. Suites 4 and 6 need
X448 and Ed448, which neither the standard library nor `x/crypto`
provides. Suite 3 uses ChaCha20-Poly1305 for message protection, which
the standard library exposes only through HPKE, so that one algorithm
comes from `golang.org/x/crypto/chacha20poly1305`.

## Tests

The tests run the working group's [test vectors]. Of the sixteen
suites, twelve pass: `messages`, `deserialization`, `tree-math`,
`crypto-basics`, `key-schedule`, `psk_secret`, `transcript-hashes`,
`secret-tree`, `message-protection`, `tree-operations`,
`tree-validation`, and `welcome`. The vector files are vendored in
`testdata`; `go generate ./...` refreshes them.

[RFC 9420]: https://www.rfc-editor.org/rfc/rfc9420.html
[test vectors]: https://github.com/mlswg/mls-implementations
