# mls

Package mls implements the wire format of the Messaging Layer Security
protocol, [RFC 9420].

    go get github.com/tmc/mls

`tlssyntax` implements the TLS presentation language as MLS extends it:
optional values, and vectors with variable-size length headers. The
`mls` package defines the protocol's structures on top of it.

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

The codec is complete. Of the protocol's structures, these are
implemented and tested: `Extension`, `Credential`, `Capabilities`,
`Lifetime`, `LeafNode`, `ParentNode`, `Node`, `RatchetTree`,
`KeyPackage`, `GroupContext`, `Welcome`, `GroupInfo`, `MLSMessage`, and
the `Add`, `Update`, `Remove`, and `GroupContextExtensions` proposals.

Not yet implemented: `FramedContent` and the `PublicMessage` and
`PrivateMessage` framing; `Commit` and `UpdatePath`; the `PreSharedKey`,
`ReInit`, and `ExternalInit` proposals; and `GroupSecrets`.

Nothing above the wire format is implemented: no key schedule, no
ratchet tree operations, no signatures. A decoded structure is well
formed but not authenticated.

## Tests

`TestMessageVectors` decodes and re-encodes every structure this package
implements in the working group's `messages` test vector, checking that
the bytes come back identical. The vector file is vendored in
`testdata`; `go generate` refreshes it from
[mlswg/mls-implementations].

[RFC 9420]: https://www.rfc-editor.org/rfc/rfc9420.html
[mlswg/mls-implementations]: https://github.com/mlswg/mls-implementations
