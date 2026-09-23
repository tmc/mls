package mls

import "math/bits"

// The ratchet tree is a left-balanced binary tree held in an array.
// A tree with n leaves has 2*(n-1)+1 nodes; even indices are leaves
// and odd indices are parents. The functions below navigate that
// array. See RFC 9420, Appendix C.

// A NodeIndex identifies a node in the array representation of a
// ratchet tree, counting both leaf and parent nodes.
type NodeIndex uint32

// A LeafIndex identifies a member's leaf, counting only leaves.
// LeafIndex i is NodeIndex 2*i.
type LeafIndex uint32

// NodeIndex returns the array index of leaf i.
func (i LeafIndex) NodeIndex() NodeIndex { return NodeIndex(2 * i) }

// LeafIndex returns the leaf index of node x, which must be a leaf.
func (x NodeIndex) LeafIndex() LeafIndex { return LeafIndex(x / 2) }

// IsLeaf reports whether x is a leaf node.
func (x NodeIndex) IsLeaf() bool { return x%2 == 0 }

// level is the height of x above the leaves: 0 for a leaf, and one
// more than the level of its children otherwise.
func (x NodeIndex) level() int { return bits.TrailingZeros32(^uint32(x)) }

// nodeWidth is the number of nodes in the array representation of a
// tree with n leaves.
func nodeWidth(n LeafIndex) NodeIndex {
	if n == 0 {
		return 0
	}
	return NodeIndex(2*(n-1) + 1)
}

// root is the index of the root of a tree with n leaves, and 0 for
// a tree with none.
func root(n LeafIndex) NodeIndex {
	if n == 0 {
		return 0
	}
	w := uint32(nodeWidth(n))
	return NodeIndex(1<<(32-bits.LeadingZeros32(w)-1) - 1)
}

// left is the left child of x, which must not be a leaf.
func (x NodeIndex) left() NodeIndex {
	k := x.level()
	return x ^ NodeIndex(1<<(k-1))
}

// right is the right child of x, which must not be a leaf.
func (x NodeIndex) right() NodeIndex {
	k := x.level()
	return x ^ NodeIndex(3<<(k-1))
}

// parent is the parent of x, which must not be the root.
func (x NodeIndex) parent() NodeIndex {
	k := x.level()
	b := (x >> (k + 1)) & 1
	return (x | NodeIndex(1<<k)) ^ (b << (k + 1))
}

// sibling is the other child of x's parent.
func (x NodeIndex) sibling() NodeIndex {
	p := x.parent()
	if x < p {
		return p.right()
	}
	return p.left()
}

// directPath is the list of nodes from x's parent to the root of a
// tree with n leaves, in that order. It is nil for the root and for a
// node outside the tree, whose parents never reach the root.
func directPath(x NodeIndex, n LeafIndex) []NodeIndex {
	r := root(n)
	if x == r || x >= nodeWidth(n) {
		return nil
	}
	var path []NodeIndex
	for x != r {
		x = x.parent()
		path = append(path, x)
	}
	return path
}

// copath is the sibling of each node on the path from x to the root:
// the nodes whose subtrees the path excludes. It is nil for the root
// and for a node outside the tree.
func copath(x NodeIndex, n LeafIndex) []NodeIndex {
	if x == root(n) || x >= nodeWidth(n) {
		return nil
	}
	path := append([]NodeIndex{x}, directPath(x, n)...)
	path = path[:len(path)-1] // the root has no sibling
	co := make([]NodeIndex, len(path))
	for i, y := range path {
		co[i] = y.sibling()
	}
	return co
}
