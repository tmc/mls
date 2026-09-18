package mls

import (
	"math/bits"
	"slices"

	"github.com/tmc/mls/tlssyntax"
)

// Size is the number of leaves in the tree. Every tree in MLS is
// perfect, so the number of leaves is a power of two, and a tree
// whose trailing blank nodes have been trimmed still has the size of
// the whole. See RFC 9420, Section 4.1.
func (t RatchetTree) Size() LeafIndex {
	n := (len(t) + 1) / 2
	if n == 0 {
		return 0
	}
	return LeafIndex(1) << bits.Len32(uint32(n-1))
}

// Node returns the node at x, or nil if it is blank or beyond the
// trimmed end of the array.
func (t RatchetTree) Node(x NodeIndex) *Node {
	if int(x) < len(t) {
		return t[x]
	}
	return nil
}

// Leaf returns the leaf node of the member at i, or nil if that leaf
// is blank.
func (t RatchetTree) Leaf(i LeafIndex) *LeafNode {
	if n := t.Node(i.NodeIndex()); n != nil {
		return n.Leaf
	}
	return nil
}

// Clone returns a copy of t that shares no state with it. The array
// copy alone is not enough: [RatchetTree.Add] records the new leaf in
// the unmerged_leaves of the nodes above it, which would otherwise be
// a write through to the tree it was copied from. A group holds the
// tree of one epoch and must not be changed by the next.
func (t RatchetTree) Clone() RatchetTree {
	c := make(RatchetTree, len(t))
	for i, n := range t {
		if n == nil {
			continue
		}
		m := *n
		if n.Leaf != nil {
			leaf := *n.Leaf
			m.Leaf = &leaf
		}
		if n.Parent != nil {
			parent := *n.Parent
			parent.UnmergedLeaves = slices.Clone(n.Parent.UnmergedLeaves)
			m.Parent = &parent
		}
		c[i] = &m
	}
	return c
}

// grow extends t so that x is a valid index.
func (t *RatchetTree) grow(x NodeIndex) {
	for NodeIndex(len(*t)) <= x {
		*t = append(*t, nil)
	}
}

// set puts n at x, growing the tree if need be.
func (t *RatchetTree) set(x NodeIndex, n *Node) {
	t.grow(x)
	(*t)[x] = n
}

// Resolution is the ordered list of non-blank nodes that covers the
// subtree under x: x itself and its unmerged leaves if x is not
// blank, and otherwise the resolutions of its children in order.
// See RFC 9420, Section 4.2.
func (t RatchetTree) Resolution(x NodeIndex) []NodeIndex {
	n := t.Node(x)
	if n == nil {
		if x.IsLeaf() {
			return nil
		}
		return append(t.Resolution(x.left()), t.Resolution(x.right())...)
	}
	res := []NodeIndex{x}
	if n.Parent != nil {
		for _, leaf := range n.Parent.UnmergedLeaves {
			res = append(res, LeafIndex(leaf).NodeIndex())
		}
	}
	return res
}

// TreeHash returns the tree hash of the subtree headed by x, which
// summarizes everything below it. See RFC 9420, Section 7.8.
func (t RatchetTree) TreeHash(cs CipherSuite, x NodeIndex) ([]byte, error) {
	if x.IsLeaf() {
		leaf := t.Leaf(x.LeafIndex())
		b, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
			w.WriteUint8(uint8(NodeTypeLeaf))
			w.WriteUint32(uint32(x.LeafIndex()))
			if leaf == nil {
				w.WriteOptional(nil)
			} else {
				w.WriteOptional(leaf.MarshalTLS)
			}
		}))
		if err != nil {
			return nil, err
		}
		return cs.Hash(b)
	}
	left, err := t.TreeHash(cs, x.left())
	if err != nil {
		return nil, err
	}
	right, err := t.TreeHash(cs, x.right())
	if err != nil {
		return nil, err
	}
	var parent *ParentNode
	if n := t.Node(x); n != nil {
		parent = n.Parent
	}
	b, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteUint8(uint8(NodeTypeParent))
		if parent == nil {
			w.WriteOptional(nil)
		} else {
			w.WriteOptional(parent.MarshalTLS)
		}
		w.WriteOpaque(left)
		w.WriteOpaque(right)
	}))
	if err != nil {
		return nil, err
	}
	return cs.Hash(b)
}

// RootHash is the tree hash of the whole tree, which the group
// context carries so that members can confirm they agree on it.
func (t RatchetTree) RootHash(cs CipherSuite) ([]byte, error) {
	if t.Size() == 0 {
		return nil, ErrEmptyTree
	}
	return t.TreeHash(cs, root(t.Size()))
}

// withoutLeaves returns a copy of t with each of the given leaves
// blanked and removed from every unmerged leaf list. This is the
// "original" tree in which a parent hash's sibling tree hash is
// computed. See RFC 9420, Section 7.9.
func (t RatchetTree) withoutLeaves(leaves []uint32) RatchetTree {
	out := make(RatchetTree, len(t))
	for i, n := range t {
		x := NodeIndex(i)
		switch {
		case n == nil:
			// already blank
		case n.Leaf != nil:
			if !slices.Contains(leaves, uint32(x.LeafIndex())) {
				out[i] = n
			}
		case n.Parent != nil:
			p := *n.Parent
			p.UnmergedLeaves = slices.DeleteFunc(slices.Clone(p.UnmergedLeaves), func(l uint32) bool {
				return slices.Contains(leaves, l)
			})
			out[i] = &Node{Type: NodeTypeParent, Parent: &p}
		}
	}
	return out
}

// ParentHash returns the parent hash of the non-blank parent node p
// with copath child s, the summary that a node below p records to
// attest that p was set by a member of the group.
// See RFC 9420, Section 7.9.
func (t RatchetTree) ParentHash(cs CipherSuite, p, s NodeIndex) ([]byte, error) {
	node := t.Node(p)
	if node == nil || node.Parent == nil {
		return nil, ErrBlankParent
	}
	sibHash, err := t.withoutLeaves(node.Parent.UnmergedLeaves).TreeHash(cs, s)
	if err != nil {
		return nil, err
	}
	b, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteOpaque(node.Parent.EncryptionKey)
		w.WriteOpaque(node.Parent.ParentHash)
		w.WriteOpaque(sibHash)
	}))
	if err != nil {
		return nil, err
	}
	return cs.Hash(b)
}

// parentHashOf returns the parent_hash field a node records, which
// only parent nodes and leaves set by a commit have.
func (t RatchetTree) parentHashOf(x NodeIndex) []byte {
	n := t.Node(x)
	switch {
	case n == nil:
		return nil
	case n.Parent != nil:
		return n.Parent.ParentHash
	case n.Leaf != nil && n.Leaf.Source == LeafNodeSourceCommit:
		return n.Leaf.ParentHash
	}
	return nil
}

// leavesUnder returns the leaves of the subtree headed by x.
func leavesUnder(x NodeIndex) (first, last LeafIndex) {
	mask := NodeIndex(1<<(x.level()+1) - 1)
	return (x &^ mask).LeafIndex(), ((x | mask) - 1).LeafIndex()
}

// VerifyParentHashes checks that every non-blank parent node in the
// tree was introduced by a member: each must be chained to a leaf by
// a parent hash. A new member does this when it joins.
// See RFC 9420, Section 7.9.2.
func (t RatchetTree) VerifyParentHashes(cs CipherSuite) error {
	n := t.Size()
	for x := NodeIndex(1); x < nodeWidth(n); x += 2 {
		node := t.Node(x)
		if node == nil || node.Parent == nil {
			continue
		}
		ok, err := t.parentHashValid(cs, x)
		if err != nil {
			return err
		}
		if !ok {
			return ErrBadParentHash
		}
	}
	return nil
}

// parentHashValid reports whether some descendant of p records p's
// parent hash, under exactly the conditions of RFC 9420,
// Section 7.9.2.
func (t RatchetTree) parentHashValid(cs CipherSuite, p NodeIndex) (bool, error) {
	unmerged := t.Node(p).Parent.UnmergedLeaves
	for _, c := range [2]NodeIndex{p.left(), p.right()} {
		s := p.left()
		if c == s {
			s = p.right()
		}
		want, err := t.ParentHash(cs, p, s)
		if err != nil {
			return false, err
		}
		res := t.Resolution(c)
		for i, d := range res {
			if !slices.Equal(t.parentHashOf(d), want) {
				continue
			}
			// The rest of the resolution must be exactly p's
			// unmerged leaves that lie under c.
			rest := slices.Concat(res[:i:i], res[i+1:])
			first, last := leavesUnder(c)
			var wantRest []NodeIndex
			for _, l := range unmerged {
				if LeafIndex(l) >= first && LeafIndex(l) <= last {
					wantRest = append(wantRest, LeafIndex(l).NodeIndex())
				}
			}
			if slices.Equal(rest, wantRest) {
				return true, nil
			}
		}
	}
	return false, nil
}

// VerifyLeafSignatures checks the signature on every non-blank leaf,
// binding each to its position in the group.
func (t RatchetTree) VerifyLeafSignatures(cs CipherSuite, groupID []byte) error {
	for i := LeafIndex(0); i < t.Size(); i++ {
		leaf := t.Leaf(i)
		if leaf == nil {
			continue
		}
		if err := leaf.Verify(cs, groupID, i); err != nil {
			return err
		}
	}
	return nil
}

// Add places leaf at the leftmost blank leaf, extending the tree if
// every leaf is occupied, and records it as unmerged in each node
// above it. See RFC 9420, Section 13.4.3.
func (t *RatchetTree) Add(leaf *LeafNode) LeafIndex {
	i := LeafIndex(0)
	for ; i < t.Size(); i++ {
		if t.Leaf(i) == nil {
			break
		}
	}
	// Setting a leaf past the end extends the tree, which doubles
	// its size: every tree is perfect.
	t.set(i.NodeIndex(), &Node{Type: NodeTypeLeaf, Leaf: leaf})
	for _, x := range directPath(i.NodeIndex(), t.Size()) {
		n := t.Node(x)
		if n == nil || n.Parent == nil {
			continue
		}
		n.Parent.UnmergedLeaves = append(n.Parent.UnmergedLeaves, uint32(i))
		slices.Sort(n.Parent.UnmergedLeaves)
	}
	return i
}

// Update replaces the leaf node at i and blanks the nodes above it,
// whose keys the old member knew. See RFC 9420, Section 13.4.3.
func (t *RatchetTree) Update(i LeafIndex, leaf *LeafNode) {
	t.set(i.NodeIndex(), &Node{Type: NodeTypeLeaf, Leaf: leaf})
	t.blankPath(i)
}

// Remove blanks the leaf at i along with the nodes above it, then
// trims the tree if its right half has emptied.
// See RFC 9420, Section 13.4.3.
func (t *RatchetTree) Remove(i LeafIndex) {
	if int(i.NodeIndex()) < len(*t) {
		(*t)[i.NodeIndex()] = nil
	}
	t.blankPath(i)
	t.truncate()
}

// blankPath blanks every node between leaf i and the root.
func (t *RatchetTree) blankPath(i LeafIndex) {
	for _, x := range directPath(i.NodeIndex(), t.Size()) {
		if int(x) < len(*t) {
			(*t)[x] = nil
		}
	}
}

// truncate drops trailing blank nodes, halving the tree as long as
// its right half holds no members.
func (t *RatchetTree) truncate() {
	for n := t.Size(); n > 1; n /= 2 {
		occupied := false
		for i := n / 2; i < n; i++ {
			if t.Leaf(i) != nil {
				occupied = true
				break
			}
		}
		if occupied {
			break
		}
		*t = (*t)[:min(len(*t), int(nodeWidth(n/2)))]
	}
	for len(*t) > 0 && (*t)[len(*t)-1] == nil {
		*t = (*t)[:len(*t)-1]
	}
}
