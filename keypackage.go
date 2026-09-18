package mls

import "github.com/tmc/mls/tlssyntax"

// A KeyPackage offers a client for addition to a group: it publishes
// the client's leaf node along with an init key that an adder uses to
// encrypt the group's secrets to it. A key package is meant to be used
// once. It is signed by the client over a KeyPackageTBS, which this
// package does not yet construct.
// See RFC 9420, Section 10.
type KeyPackage struct {
	Version     ProtocolVersion
	CipherSuite CipherSuite
	InitKey     HPKEPublicKey
	LeafNode    LeafNode
	Extensions  Extensions
	Signature   []byte
}

func (p *KeyPackage) MarshalTLS(w *tlssyntax.Writer) {
	p.marshalTBS(w)
	w.WriteOpaque(p.Signature)
}

// marshalTBS writes every field but the signature, which is the
// content the signature covers.
func (p *KeyPackage) marshalTBS(w *tlssyntax.Writer) {
	w.WriteUint16(uint16(p.Version))
	w.WriteUint16(uint16(p.CipherSuite))
	w.WriteOpaque(p.InitKey)
	p.LeafNode.MarshalTLS(w)
	p.Extensions.MarshalTLS(w)
}

func (p *KeyPackage) UnmarshalTLS(r *tlssyntax.Reader) {
	*p = KeyPackage{}
	p.Version = ProtocolVersion(r.ReadUint16())
	p.CipherSuite = CipherSuite(r.ReadUint16())
	p.InitKey = r.ReadOpaque()
	p.LeafNode.UnmarshalTLS(r)
	p.Extensions.UnmarshalTLS(r)
	p.Signature = r.ReadOpaque()
}
