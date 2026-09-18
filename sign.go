package mls

import "github.com/tmc/mls/tlssyntax"

// SignedContent returns the KeyPackageTBS bytes that p.Signature
// covers: every field of the key package but the signature itself.
// See RFC 9420, Section 10.
func (p *KeyPackage) SignedContent() ([]byte, error) {
	return tlssyntax.Marshal(tlssyntax.MarshalerFunc(p.marshalTBS))
}

// Sign signs p with priv, which must be the private half of
// p.LeafNode.SignatureKey, and records the signature in p.Signature.
func (p *KeyPackage) Sign(priv []byte) error {
	tbs, err := p.SignedContent()
	if err != nil {
		return err
	}
	sig, err := p.CipherSuite.SignWithLabel(priv, "KeyPackageTBS", tbs)
	if err != nil {
		return err
	}
	p.Signature = sig
	return nil
}

// Verify checks p.Signature against the signature key in p's leaf
// node. It does not validate the leaf node itself; see
// [LeafNode.Verify].
func (p *KeyPackage) Verify() error {
	tbs, err := p.SignedContent()
	if err != nil {
		return err
	}
	return p.CipherSuite.VerifyWithLabel(p.LeafNode.SignatureKey, "KeyPackageTBS", tbs, p.Signature)
}

// Ref returns the key package reference by which proposals and
// welcome messages name p. See RFC 9420, Section 5.2.
func (p *KeyPackage) Ref() (HashReference, error) {
	b, err := Marshal(p)
	if err != nil {
		return nil, err
	}
	return p.CipherSuite.RefHash("MLS 1.0 KeyPackage Reference", b)
}

// SignedContent returns the LeafNodeTBS bytes that n.Signature
// covers. A leaf node from an update or a commit is bound to its
// position, so groupID and leafIndex must identify it; a leaf node
// from a key package is not, and they are ignored.
// See RFC 9420, Section 7.2.
func (n *LeafNode) SignedContent(groupID []byte, leafIndex LeafIndex) ([]byte, error) {
	return tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		n.marshalTBS(w)
		switch n.Source {
		case LeafNodeSourceUpdate, LeafNodeSourceCommit:
			w.WriteOpaque(groupID)
			w.WriteUint32(uint32(leafIndex))
		}
	}))
}

// Sign signs n with priv, which must be the private half of
// n.SignatureKey, and records the signature in n.Signature.
func (n *LeafNode) Sign(cs CipherSuite, priv []byte, groupID []byte, leafIndex LeafIndex) error {
	tbs, err := n.SignedContent(groupID, leafIndex)
	if err != nil {
		return err
	}
	sig, err := cs.SignWithLabel(priv, "LeafNodeTBS", tbs)
	if err != nil {
		return err
	}
	n.Signature = sig
	return nil
}

// Verify checks n.Signature against n.SignatureKey.
func (n *LeafNode) Verify(cs CipherSuite, groupID []byte, leafIndex LeafIndex) error {
	tbs, err := n.SignedContent(groupID, leafIndex)
	if err != nil {
		return err
	}
	return cs.VerifyWithLabel(n.SignatureKey, "LeafNodeTBS", tbs, n.Signature)
}
