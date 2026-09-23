package mls

import "github.com/tmc/mls/tlssyntax"

// Capabilities lists what a client supports. A client must be able to
// handle every value it lists here, and other members rely on that
// when choosing extensions and proposals.
// See RFC 9420, Section 7.2.
type Capabilities struct {
	Versions     []ProtocolVersion
	CipherSuites []CipherSuite
	Extensions   []ExtensionType
	Proposals    []ProposalType
	Credentials  []CredentialType
}

func (c *Capabilities) MarshalTLS(w *tlssyntax.Writer) {
	writeUint16s(w, c.Versions)
	writeUint16s(w, c.CipherSuites)
	writeUint16s(w, c.Extensions)
	writeUint16s(w, c.Proposals)
	writeUint16s(w, c.Credentials)
}

func (c *Capabilities) UnmarshalTLS(r *tlssyntax.Reader) {
	*c = Capabilities{}
	readUint16s(r, &c.Versions)
	readUint16s(r, &c.CipherSuites)
	readUint16s(r, &c.Extensions)
	readUint16s(r, &c.Proposals)
	readUint16s(r, &c.Credentials)
}

// writeUint16s writes a vector of values whose underlying type is
// uint16, such as the enum vectors in Capabilities.
func writeUint16s[T ~uint16](w *tlssyntax.Writer, vs []T) {
	w.WriteVector(func(w *tlssyntax.Writer) {
		for _, v := range vs {
			w.WriteUint16(uint16(v))
		}
	})
}

func readUint16s[T ~uint16](r *tlssyntax.Reader, vs *[]T) {
	*vs = nil
	r.ReadAll(func(r *tlssyntax.Reader) { *vs = append(*vs, T(r.ReadUint16())) })
}

// A Lifetime bounds the time over which a [KeyPackage] may be used, as
// absolute seconds since the UNIX epoch. Clients are expected to
// reject key packages outside this window, subject to their own clock
// skew allowance. See RFC 9420, Section 7.2.
type Lifetime struct {
	NotBefore uint64
	NotAfter  uint64
}

func (l *Lifetime) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint64(l.NotBefore)
	w.WriteUint64(l.NotAfter)
}

func (l *Lifetime) UnmarshalTLS(r *tlssyntax.Reader) {
	l.NotBefore = r.ReadUint64()
	l.NotAfter = r.ReadUint64()
}

// A LeafNode describes one member's appearance in the ratchet tree. It
// is signed by that member over a LeafNodeTBS; see [LeafNode.Sign] and
// [LeafNode.Verify].
//
// Source decides which of Lifetime and ParentHash is present: a leaf
// from a [KeyPackage] carries a Lifetime, a leaf installed by a commit
// carries a ParentHash, and a leaf from an Update proposal carries
// neither. See RFC 9420, Section 7.2.
type LeafNode struct {
	EncryptionKey HPKEPublicKey
	SignatureKey  SignaturePublicKey
	Credential    Credential
	Capabilities  Capabilities

	Source     LeafNodeSource
	Lifetime   Lifetime // Source == LeafNodeSourceKeyPackage
	ParentHash []byte   // Source == LeafNodeSourceCommit

	Extensions Extensions
	Signature  []byte
}

func (n *LeafNode) MarshalTLS(w *tlssyntax.Writer) {
	n.marshalTBS(w)
	w.WriteOpaque(n.Signature)
}

// marshalTBS writes every field but the signature, which is the
// content the signature covers.
func (n *LeafNode) marshalTBS(w *tlssyntax.Writer) {
	w.WriteOpaque(n.EncryptionKey)
	w.WriteOpaque(n.SignatureKey)
	n.Credential.MarshalTLS(w)
	n.Capabilities.MarshalTLS(w)
	w.WriteUint8(uint8(n.Source))
	switch n.Source {
	case LeafNodeSourceKeyPackage:
		n.Lifetime.MarshalTLS(w)
	case LeafNodeSourceUpdate:
		// no fields
	case LeafNodeSourceCommit:
		w.WriteOpaque(n.ParentHash)
	default:
		w.SetError(errUnknown("leaf node source", uint64(n.Source)))
		return
	}
	n.Extensions.MarshalTLS(w)
}

func (n *LeafNode) UnmarshalTLS(r *tlssyntax.Reader) {
	*n = LeafNode{}
	n.EncryptionKey = r.ReadOpaque()
	n.SignatureKey = r.ReadOpaque()
	n.Credential.UnmarshalTLS(r)
	n.Capabilities.UnmarshalTLS(r)
	n.Source = LeafNodeSource(r.ReadUint8())
	switch n.Source {
	case LeafNodeSourceKeyPackage:
		n.Lifetime.UnmarshalTLS(r)
	case LeafNodeSourceUpdate:
		// no fields
	case LeafNodeSourceCommit:
		n.ParentHash = r.ReadOpaque()
	default:
		r.SetError(errUnknown("leaf node source", uint64(n.Source)))
		return
	}
	n.Extensions.UnmarshalTLS(r)
	n.Signature = r.ReadOpaque()
}

// A ParentNode describes an interior node of the ratchet tree. Its
// encryption key is known only to the members at the leaves below it.
// UnmergedLeaves lists, in increasing order, the leaves below the node
// whose members do not hold that key.
// See RFC 9420, Section 7.1.
type ParentNode struct {
	EncryptionKey  HPKEPublicKey
	ParentHash     []byte
	UnmergedLeaves []uint32
}

func (n *ParentNode) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteOpaque(n.EncryptionKey)
	w.WriteOpaque(n.ParentHash)
	w.WriteVector(func(w *tlssyntax.Writer) {
		for _, leaf := range n.UnmergedLeaves {
			w.WriteUint32(leaf)
		}
	})
}

func (n *ParentNode) UnmarshalTLS(r *tlssyntax.Reader) {
	*n = ParentNode{}
	n.EncryptionKey = r.ReadOpaque()
	n.ParentHash = r.ReadOpaque()
	r.ReadAll(func(r *tlssyntax.Reader) {
		n.UnmergedLeaves = append(n.UnmergedLeaves, r.ReadUint32())
	})
}

// A Node is one occupied node of the ratchet tree: either a leaf or a
// parent, according to Type. See RFC 9420, Section 12.4.3.1.
type Node struct {
	Type   NodeType
	Leaf   *LeafNode   // Type == NodeTypeLeaf
	Parent *ParentNode // Type == NodeTypeParent
}

func (n *Node) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint8(uint8(n.Type))
	switch {
	case n.Type == NodeTypeLeaf && n.Leaf != nil:
		n.Leaf.MarshalTLS(w)
	case n.Type == NodeTypeParent && n.Parent != nil:
		n.Parent.MarshalTLS(w)
	default:
		w.SetError(errUnknown("node type", uint64(n.Type)))
	}
}

func (n *Node) UnmarshalTLS(r *tlssyntax.Reader) {
	*n = Node{Type: NodeType(r.ReadUint8())}
	switch n.Type {
	case NodeTypeLeaf:
		n.Leaf = new(LeafNode)
		n.Leaf.UnmarshalTLS(r)
	case NodeTypeParent:
		n.Parent = new(ParentNode)
		n.Parent.UnmarshalTLS(r)
	default:
		r.SetError(errUnknown("node type", uint64(n.Type)))
	}
}

// A RatchetTree is the array representation of a group's ratchet tree,
// as carried in a ratchet_tree extension. A nil entry is a blank node.
// See RFC 9420, Section 12.4.3.1.
type RatchetTree []*Node

func (t *RatchetTree) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteVector(func(w *tlssyntax.Writer) {
		for _, n := range *t {
			if n == nil {
				w.WriteOptional(nil)
				continue
			}
			w.WriteOptional(n.MarshalTLS)
		}
	})
}

func (t *RatchetTree) UnmarshalTLS(r *tlssyntax.Reader) {
	*t = nil
	r.ReadAll(func(r *tlssyntax.Reader) {
		if !r.ReadOptional() {
			*t = append(*t, nil)
			return
		}
		n := new(Node)
		n.UnmarshalTLS(r)
		*t = append(*t, n)
	})
}
