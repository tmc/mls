package mls

import (
	"bytes"
	"maps"
	"math/bits"
	"slices"

	"github.com/tmc/mls/tlssyntax"
)

// TreeSecrets is a member's private view of a ratchet tree: the HPKE
// private key of its own leaf, and the path secret of each node on
// its direct path whose key it knows. Every other private key the
// member holds is derived from one of those path secrets.
// See RFC 9420, Section 7.5.
type TreeSecrets struct {
	Index   LeafIndex            // the member's own leaf
	Leaf    []byte               // HPKE private key of that leaf
	Secrets map[NodeIndex][]byte // path secrets, by node
}

// NewTreeSecrets returns the private state of the member at leaf i
// whose leaf node holds the HPKE private key leafPriv.
func NewTreeSecrets(i LeafIndex, leafPriv []byte) *TreeSecrets {
	return &TreeSecrets{Index: i, Leaf: leafPriv, Secrets: make(map[NodeIndex][]byte)}
}

// PrivateKey returns the HPKE private key s holds for node x, or nil
// if it holds none.
func (s *TreeSecrets) PrivateKey(cs CipherSuite, x NodeIndex) ([]byte, error) {
	if x == s.Index.NodeIndex() {
		return s.Leaf, nil
	}
	secret, ok := s.Secrets[x]
	if !ok {
		return nil, nil
	}
	priv, _, err := cs.nodeKeyPair(secret)
	return priv, err
}

// Consistent reports whether every private key in s matches the
// corresponding public key in t. A member checks this after joining.
func (s *TreeSecrets) Consistent(cs CipherSuite, t RatchetTree) error {
	leaf := t.Leaf(s.Index)
	if leaf == nil {
		return ErrLeafRange
	}
	if pub, err := cs.PublicKey(s.Leaf); err != nil {
		return err
	} else if !bytes.Equal(pub, leaf.EncryptionKey) {
		return ErrBadTreeKEM
	}
	for _, x := range slices.Sorted(maps.Keys(s.Secrets)) {
		n := t.Node(x)
		if n == nil || n.Parent == nil {
			return ErrBlankParent
		}
		_, pub, err := cs.nodeKeyPair(s.Secrets[x])
		if err != nil {
			return err
		}
		if !bytes.Equal(pub, n.Parent.EncryptionKey) {
			return ErrBadTreeKEM
		}
	}
	return nil
}

// nodeKeyPair derives the HPKE key pair of the node whose path secret
// is secret. See RFC 9420, Section 7.4.
func (cs CipherSuite) nodeKeyPair(secret []byte) (priv []byte, pub HPKEPublicKey, err error) {
	node, err := cs.DeriveSecret(secret, "node")
	if err != nil {
		return nil, nil, err
	}
	return cs.DeriveKeyPair(node)
}

// contains reports whether the subtree headed by x holds leaf i.
func contains(x NodeIndex, i LeafIndex) bool {
	first, last := leavesUnder(x)
	return first <= i && i <= last
}

// copathChild returns the child of the parent node x that does not
// hold leaf i, that is, the child on i's copath.
func copathChild(x NodeIndex, i LeafIndex) NodeIndex {
	if contains(x.left(), i) {
		return x.right()
	}
	return x.left()
}

// FilteredDirectPath returns the nodes of leaf i's direct path whose
// copath child has a non-empty resolution. Only those nodes need key
// pairs of their own: encrypting to any other node on the path would
// be the same as encrypting to its child.
// See RFC 9420, Section 4.2.
func (t RatchetTree) FilteredDirectPath(i LeafIndex) []NodeIndex {
	if i >= t.Size() {
		return nil
	}
	var path []NodeIndex
	for _, x := range directPath(i.NodeIndex(), t.Size()) {
		if len(t.Resolution(copathChild(x, i))) > 0 {
			path = append(path, x)
		}
	}
	return path
}

// CreateUpdatePath refreshes the key pairs along leaf i's direct path
// and returns the UpdatePath that tells the rest of the group about
// it, the sender's new private state, and the commit secret that the
// new epoch's key schedule takes as input.
//
// The tree is updated in place. All of the new key material derives
// from leafSecret, which must be freshly sampled and as long as the
// cipher suite's hash. The new leaf node is signed with sigPriv, and
// the path secrets are encrypted under ctx, whose TreeHash this
// function recomputes from the updated tree. Leaves added by the same
// commit are named in exclude, and receive no path secret.
// See RFC 9420, Section 7.5.
func (t *RatchetTree) CreateUpdatePath(cs CipherSuite, i LeafIndex, leafSecret, sigPriv []byte, ctx *GroupContext, exclude []LeafIndex) (*UpdatePath, *TreeSecrets, []byte, error) {
	old := t.Leaf(i)
	if old == nil {
		return nil, nil, nil, ErrLeafRange
	}
	leaf := *old
	leafPriv, leafPub, err := cs.nodeKeyPair(leafSecret)
	if err != nil {
		return nil, nil, nil, err
	}
	leaf.EncryptionKey = leafPub
	leaf.Source = LeafNodeSourceCommit
	leaf.Lifetime = Lifetime{}

	t.blankPath(i)
	t.set(i.NodeIndex(), &Node{Type: NodeTypeLeaf, Leaf: &leaf})

	// Derive one path secret per node on the filtered direct path,
	// and the commit secret from the one above the root.
	path := t.FilteredDirectPath(i)
	secrets := make([][]byte, len(path))
	commitSecret, err := cs.DeriveSecret(leafSecret, "path")
	if err != nil {
		return nil, nil, nil, err
	}
	for k, x := range path {
		secrets[k] = commitSecret
		_, pub, err := cs.nodeKeyPair(secrets[k])
		if err != nil {
			return nil, nil, nil, err
		}
		t.set(x, &Node{Type: NodeTypeParent, Parent: &ParentNode{EncryptionKey: pub}})
		if commitSecret, err = cs.DeriveSecret(secrets[k], "path"); err != nil {
			return nil, nil, nil, err
		}
	}

	// Parent hashes run from the root down: each node records the
	// parent hash of the node above it on the filtered direct path,
	// and the topmost node records none.
	var hash []byte
	for _, x := range slices.Backward(path) {
		t.Node(x).Parent.ParentHash = hash
		if hash, err = t.ParentHash(cs, x, copathChild(x, i)); err != nil {
			return nil, nil, nil, err
		}
	}
	leaf.ParentHash = hash
	if err := leaf.Sign(cs, sigPriv, ctx.GroupID, i); err != nil {
		return nil, nil, nil, err
	}

	ctxBytes, err := t.provisionalContext(cs, ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	up := &UpdatePath{LeafNode: leaf, Nodes: make([]UpdatePathNode, len(path))}
	secret := NewTreeSecrets(i, leafPriv)
	for k, x := range path {
		up.Nodes[k].EncryptionKey = t.Node(x).Parent.EncryptionKey
		secret.Secrets[x] = secrets[k]
		for _, y := range t.resolutionExcluding(copathChild(x, i), exclude) {
			ct, err := cs.EncryptWithLabel(t.encryptionKey(y), "UpdatePathNode", ctxBytes, secrets[k])
			if err != nil {
				return nil, nil, nil, err
			}
			up.Nodes[k].EncryptedPathSecret = append(up.Nodes[k].EncryptedPathSecret, *ct)
		}
	}
	return up, secret, commitSecret, nil
}

// provisionalContext encodes ctx with the tree hash of the tree as
// the update path leaves it, which is the context that the path
// secrets are encrypted under. See RFC 9420, Section 12.4.3.2.
func (t RatchetTree) provisionalContext(cs CipherSuite, ctx *GroupContext) ([]byte, error) {
	c := *ctx
	var err error
	if c.TreeHash, err = t.RootHash(cs); err != nil {
		return nil, err
	}
	return tlssyntax.Marshal(&c)
}

// encryptionKey returns the HPKE public key of the non-blank node x.
func (t RatchetTree) encryptionKey(x NodeIndex) HPKEPublicKey {
	switch n := t.Node(x); {
	case n == nil:
		return nil
	case n.Leaf != nil:
		return n.Leaf.EncryptionKey
	default:
		return n.Parent.EncryptionKey
	}
}

// resolutionExcluding is the resolution of x without the leaves that
// a commit is adding, which have no path secret of their own.
// See RFC 9420, Section 7.6.
func (t RatchetTree) resolutionExcluding(x NodeIndex, exclude []LeafIndex) []NodeIndex {
	res := t.Resolution(x)
	if len(exclude) == 0 {
		return res
	}
	return slices.DeleteFunc(res, func(y NodeIndex) bool {
		return y.IsLeaf() && slices.Contains(exclude, y.LeafIndex())
	})
}

// MergeUpdatePath applies the public keys of an update path sent by
// the member at leaf i, updating the tree in place, and checks that
// the new leaf node's parent hash chains to the root.
// See RFC 9420, Section 7.5.
func (t *RatchetTree) MergeUpdatePath(cs CipherSuite, i LeafIndex, up *UpdatePath) error {
	if i >= t.Size() {
		return ErrLeafRange
	}
	// Every key the path introduces must be new, which the merge
	// is about to hide: the committer's current leaf key and the
	// keys on its old path are overwritten, and checking the merged
	// tree alone would miss a path that reuses one of them.
	// See RFC 9420, Section 12.4.2.
	old := make(map[string]bool, len(*t))
	for x := range NodeIndex(len(*t)) {
		if key := t.encryptionKey(x); key != nil {
			old[string(key)] = true
		}
	}
	if old[string(up.LeafNode.EncryptionKey)] {
		return ErrDuplicateLeafKey
	}
	for _, n := range up.Nodes {
		if old[string(n.EncryptionKey)] {
			return ErrDuplicateNodeKey
		}
	}
	t.blankPath(i)
	leaf := new(up.LeafNode)
	t.set(i.NodeIndex(), &Node{Type: NodeTypeLeaf, Leaf: leaf})
	path := t.FilteredDirectPath(i)
	if len(path) != len(up.Nodes) {
		return ErrBadTreeKEM
	}
	for k, x := range path {
		t.set(x, &Node{Type: NodeTypeParent, Parent: &ParentNode{EncryptionKey: up.Nodes[k].EncryptionKey}})
	}
	var hash []byte
	for _, x := range slices.Backward(path) {
		t.Node(x).Parent.ParentHash = hash
		var err error
		if hash, err = t.ParentHash(cs, x, copathChild(x, i)); err != nil {
			return err
		}
	}
	if !bytes.Equal(hash, leaf.ParentHash) {
		return ErrBadParentHash
	}
	// None of the keys the path introduces may already be in the
	// tree. See RFC 9420, Section 12.4.
	return t.verifyNodeKeys()
}

// DecryptPathSecrets recovers from an update path sent by the member
// at leaf i every path secret that s is entitled to, records them in
// s, and returns the epoch's commit secret. The tree must already
// have been merged, and ctx must be the group context of the new
// epoch; its TreeHash is recomputed from the merged tree. Leaves that
// the same commit added are named in exclude. See RFC 9420, Section 7.5.
func (t RatchetTree) DecryptPathSecrets(cs CipherSuite, i LeafIndex, up *UpdatePath, ctx *GroupContext, s *TreeSecrets, exclude []LeafIndex) ([]byte, error) {
	if i >= t.Size() {
		return nil, ErrLeafRange
	}
	path := t.FilteredDirectPath(i)
	if len(path) != len(up.Nodes) {
		return nil, ErrBadTreeKEM
	}
	// Every node carries one ciphertext for each node in the
	// resolution of its copath child, not only the node s reads.
	// See RFC 9420, Sections 7.6 and 12.4.2.
	for k, x := range path {
		if len(t.resolutionExcluding(copathChild(x, i), exclude)) != len(up.Nodes[k].EncryptedPathSecret) {
			return nil, ErrBadTreeKEM
		}
	}
	ctxBytes, err := t.provisionalContext(cs, ctx)
	if err != nil {
		return nil, err
	}
	// Exactly one node on the sender's filtered direct path has s
	// below its copath child; that is where the chain starts.
	for k, x := range path {
		c := copathChild(x, i)
		if !contains(c, s.Index) {
			continue
		}
		for n, y := range t.resolutionExcluding(c, exclude) {
			priv, err := s.PrivateKey(cs, y)
			if err != nil {
				return nil, err
			}
			if priv == nil {
				continue
			}
			secret, err := cs.DecryptWithLabel(priv, "UpdatePathNode", ctxBytes, &up.Nodes[k].EncryptedPathSecret[n])
			if err != nil {
				return nil, err
			}
			keys := make([]HPKEPublicKey, len(up.Nodes)-k)
			for n := range keys {
				keys[n] = up.Nodes[k+n].EncryptionKey
			}
			return s.chain(cs, secret, path[k:], keys)
		}
		break
	}
	return nil, ErrNotInPath
}

// chain records secret as the path secret of path[0] and derives the
// path secrets of the nodes above it, checking each against the
// public key keys[k] the sender advertised, and returns the secret
// one step past the end, which is the commit secret.
func (s *TreeSecrets) chain(cs CipherSuite, secret []byte, path []NodeIndex, keys []HPKEPublicKey) ([]byte, error) {
	for k, x := range path {
		_, pub, err := cs.nodeKeyPair(secret)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pub, keys[k]) {
			return nil, ErrBadTreeKEM
		}
		s.Secrets[x] = secret
		if secret, err = cs.DeriveSecret(secret, "path"); err != nil {
			return nil, err
		}
	}
	return secret, nil
}

// SetPath records secret as the path secret of node x and derives the
// path secrets of every node above x on the member's filtered direct
// path, checking each against the public key in t. A new member does
// this with the path secret a welcome message carries.
// See RFC 9420, Section 12.4.3.1.
func (s *TreeSecrets) SetPath(cs CipherSuite, t RatchetTree, x NodeIndex, secret []byte) error {
	if s.Index >= t.Size() {
		return ErrLeafRange
	}
	path := t.FilteredDirectPath(s.Index)
	k := slices.Index(path, x)
	if k < 0 {
		return ErrNotInPath
	}
	keys := make([]HPKEPublicKey, len(path)-k)
	for n, y := range path[k:] {
		keys[n] = t.encryptionKey(y)
	}
	_, err := s.chain(cs, secret, path[k:], keys)
	return err
}

// commonAncestor returns the lowest node whose subtree holds both
// leaf a and leaf b.
func commonAncestor(a, b LeafIndex) NodeIndex {
	k := bits.Len32(uint32(a ^ b))
	return NodeIndex(a>>k<<k)*2 + NodeIndex(1)<<k - 1
}

// prune drops every path secret whose node no longer holds the
// matching public key, which happens when a commit blanks or replaces
// the node.
func (s *TreeSecrets) prune(cs CipherSuite, t RatchetTree) {
	for x, secret := range s.Secrets {
		_, pub, err := cs.nodeKeyPair(secret)
		if err != nil || !bytes.Equal(pub, t.encryptionKey(x)) {
			delete(s.Secrets, x)
		}
	}
}
