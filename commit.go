package mls

import "github.com/tmc/mls/tlssyntax"

// An UpdatePathNode is one node on the direct path of a committer's
// leaf: a fresh public key, and the path secret above it encrypted to
// each node in that node's resolution. See RFC 9420, Section 6.1.
type UpdatePathNode struct {
	EncryptionKey       HPKEPublicKey
	EncryptedPathSecret []HPKECiphertext
}

func (n *UpdatePathNode) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteOpaque(n.EncryptionKey)
	w.WriteVector(func(w *tlssyntax.Writer) {
		for i := range n.EncryptedPathSecret {
			n.EncryptedPathSecret[i].MarshalTLS(w)
		}
	})
}

func (n *UpdatePathNode) UnmarshalTLS(r *tlssyntax.Reader) {
	*n = UpdatePathNode{}
	n.EncryptionKey = r.ReadOpaque()
	r.ReadAll(func(r *tlssyntax.Reader) {
		var c HPKECiphertext
		c.UnmarshalTLS(r)
		n.EncryptedPathSecret = append(n.EncryptedPathSecret, c)
	})
}

// An UpdatePath carries the committer's new leaf node and the new
// keys along its direct path to the root. See RFC 9420, Section 6.1.
type UpdatePath struct {
	LeafNode LeafNode
	Nodes    []UpdatePathNode
}

func (p *UpdatePath) MarshalTLS(w *tlssyntax.Writer) {
	p.LeafNode.MarshalTLS(w)
	w.WriteVector(func(w *tlssyntax.Writer) {
		for i := range p.Nodes {
			p.Nodes[i].MarshalTLS(w)
		}
	})
}

func (p *UpdatePath) UnmarshalTLS(r *tlssyntax.Reader) {
	*p = UpdatePath{}
	p.LeafNode.UnmarshalTLS(r)
	r.ReadAll(func(r *tlssyntax.Reader) {
		var n UpdatePathNode
		n.UnmarshalTLS(r)
		p.Nodes = append(p.Nodes, n)
	})
}

// A Commit ends an epoch: it applies a list of proposals and, unless
// every one of them is an Add, updates the committer's direct path.
// See RFC 9420, Section 12.4.
type Commit struct {
	Proposals []ProposalOrRef
	Path      *UpdatePath
}

func (c *Commit) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteVector(func(w *tlssyntax.Writer) {
		for i := range c.Proposals {
			c.Proposals[i].MarshalTLS(w)
		}
	})
	if c.Path == nil {
		w.WriteOptional(nil)
		return
	}
	w.WriteOptional(c.Path.MarshalTLS)
}

func (c *Commit) UnmarshalTLS(r *tlssyntax.Reader) {
	*c = Commit{}
	r.ReadAll(func(r *tlssyntax.Reader) {
		var p ProposalOrRef
		p.UnmarshalTLS(r)
		c.Proposals = append(c.Proposals, p)
	})
	if r.ReadOptional() {
		c.Path = new(UpdatePath)
		c.Path.UnmarshalTLS(r)
	}
}

// A PathSecret is the secret for one node on a new member's direct
// path. See RFC 9420, Section 12.4.3.1.
type PathSecret struct {
	PathSecret []byte
}

func (p *PathSecret) MarshalTLS(w *tlssyntax.Writer)   { w.WriteOpaque(p.PathSecret) }
func (p *PathSecret) UnmarshalTLS(r *tlssyntax.Reader) { p.PathSecret = r.ReadOpaque() }

// GroupSecrets is the plaintext a joiner recovers from a [Welcome]:
// enough key material to derive the epoch secrets, plus the path
// secret for the lowest common ancestor with the committer, if the
// commit had a path. See RFC 9420, Section 12.4.3.1.
type GroupSecrets struct {
	JoinerSecret []byte
	PathSecret   *PathSecret
	PSKs         []PreSharedKeyID
}

func (g *GroupSecrets) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteOpaque(g.JoinerSecret)
	if g.PathSecret == nil {
		w.WriteOptional(nil)
	} else {
		w.WriteOptional(g.PathSecret.MarshalTLS)
	}
	w.WriteVector(func(w *tlssyntax.Writer) {
		for i := range g.PSKs {
			g.PSKs[i].MarshalTLS(w)
		}
	})
}

func (g *GroupSecrets) UnmarshalTLS(r *tlssyntax.Reader) {
	*g = GroupSecrets{}
	g.JoinerSecret = r.ReadOpaque()
	if r.ReadOptional() {
		g.PathSecret = new(PathSecret)
		g.PathSecret.UnmarshalTLS(r)
	}
	r.ReadAll(func(r *tlssyntax.Reader) {
		var p PreSharedKeyID
		p.UnmarshalTLS(r)
		g.PSKs = append(g.PSKs, p)
	})
}

// pathRequired reports whether a commit covering these proposals must
// carry an update path. A commit that covers nothing must update the
// committer's own keys, and Update, Remove, ExternalInit and
// GroupContextExtensions each change the membership in a way that the
// forward secrecy of a new path is what makes real: an update path is
// what evicts the removed member, or the old appearance of the
// updated one. See RFC 9420, Section 12.4.
func pathRequired(ps []proposal) bool {
	if len(ps) == 0 {
		return true
	}
	for _, p := range ps {
		switch p.Type {
		case ProposalTypeUpdate, ProposalTypeRemove,
			ProposalTypeExternalInit, ProposalTypeGroupContextExtensions:
			return true
		}
	}
	return false
}
