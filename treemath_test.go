package mls

//go:generate curl -sSfo testdata/tree-math.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/tree-math.json

import "testing"

type treeMathVector struct {
	NLeaves LeafIndex    `json:"n_leaves"`
	NNodes  NodeIndex    `json:"n_nodes"`
	Root    NodeIndex    `json:"root"`
	Left    []*NodeIndex `json:"left"`
	Right   []*NodeIndex `json:"right"`
	Parent  []*NodeIndex `json:"parent"`
	Sibling []*NodeIndex `json:"sibling"`
}

func TestTreeMathVectors(t *testing.T) {
	var vectors []treeMathVector
	loadVectors(t, "tree-math", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}
	for _, vec := range vectors {
		n := vec.NLeaves
		if got := nodeWidth(n); got != vec.NNodes {
			t.Errorf("nodeWidth(%d) = %d, want %d", n, got, vec.NNodes)
		}
		if got := root(n); got != vec.Root {
			t.Errorf("root(%d) = %d, want %d", n, got, vec.Root)
		}
		for _, tt := range []struct {
			name string
			want []*NodeIndex
			f    func(NodeIndex) NodeIndex
			// defined reports whether f is defined at x.
			defined func(NodeIndex) bool
		}{
			{"left", vec.Left, NodeIndex.left, func(x NodeIndex) bool { return !x.IsLeaf() }},
			{"right", vec.Right, NodeIndex.right, func(x NodeIndex) bool { return !x.IsLeaf() }},
			{"parent", vec.Parent, NodeIndex.parent, func(x NodeIndex) bool { return x != root(n) }},
			{"sibling", vec.Sibling, NodeIndex.sibling, func(x NodeIndex) bool { return x != root(n) }},
		} {
			if len(tt.want) != int(vec.NNodes) {
				t.Fatalf("%s: %d entries, want %d", tt.name, len(tt.want), vec.NNodes)
			}
			for i, want := range tt.want {
				x := NodeIndex(i)
				if tt.defined(x) != (want != nil) {
					t.Errorf("n_leaves=%d: %s(%d) definedness disagrees with vector", n, tt.name, x)
					continue
				}
				if want == nil {
					continue
				}
				if got := tt.f(x); got != *want {
					t.Errorf("n_leaves=%d: %s(%d) = %d, want %d", n, tt.name, x, got, *want)
				}
			}
		}
	}
}

func TestDirectPath(t *testing.T) {
	// A tree with four leaves:
	//
	//            3
	//        ┌───┴───┐
	//        1       5
	//      ┌─┴─┐   ┌─┴─┐
	//      0   2   4   6
	const n = LeafIndex(4)
	tests := []struct {
		x      NodeIndex
		direct []NodeIndex
		co     []NodeIndex
	}{
		{0, []NodeIndex{1, 3}, []NodeIndex{2, 5}},
		{2, []NodeIndex{1, 3}, []NodeIndex{0, 5}},
		{4, []NodeIndex{5, 3}, []NodeIndex{6, 1}},
		{3, nil, nil},
	}
	for _, tt := range tests {
		if got := directPath(tt.x, n); !equalNodes(got, tt.direct) {
			t.Errorf("directPath(%d) = %v, want %v", tt.x, got, tt.direct)
		}
		if got := copath(tt.x, n); !equalNodes(got, tt.co) {
			t.Errorf("copath(%d) = %v, want %v", tt.x, got, tt.co)
		}
	}
}

func equalNodes(a, b []NodeIndex) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
