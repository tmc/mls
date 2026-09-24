package mls

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

func TestJoinExternal(t *testing.T) {
	for _, cs := range []CipherSuite{
		X25519AES128GCMSHA256Ed25519,
		P256AES128GCMSHA256P256,
		X25519ChaCha20Poly1305SHA256Ed25519,
		P521AES256GCMSHA512P521,
		P384AES256GCMSHA384P384,
	} {
		t.Run(cs.String(), func(t *testing.T) { testJoinExternal(t, cs) })
	}
}

func testJoinExternal(t *testing.T, cs CipherSuite) {
	alice := newTestClient(t, cs, "alice")
	bob := newTestClient(t, cs, "bob")
	carol := newTestClient(t, cs, "carol")

	a0, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	add := &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}}
	a1, _, welcome, err := a0.Commit([]*Proposal{add})
	if err != nil {
		t.Fatal(err)
	}
	b1, err := bob.Join(send(t, welcome).Welcome, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Carol joins the two-member group with no help from either
	// member beyond the published group info.
	info, err := a1.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	c2, commit, err := carol.JoinExternal(send(t, info).GroupInfo, nil)
	if err != nil {
		t.Fatal(err)
	}
	commit = send(t, commit)
	a2, err := a1.Handle(commit)
	if err != nil {
		t.Fatalf("alice handling the external commit: %v", err)
	}
	b2, err := b1.Handle(commit)
	if err != nil {
		t.Fatalf("bob handling the external commit: %v", err)
	}
	for _, g := range []*Group{a2, b2} {
		if !bytes.Equal(c2.EpochAuthenticator(), g.EpochAuthenticator()) {
			t.Fatal("members disagree with the external joiner")
		}
	}
	if c2.Epoch() != 2 {
		t.Errorf("joined at epoch %d, want 2", c2.Epoch())
	}
	if n := members(c2.Tree); n != 3 {
		t.Errorf("group has %d members, want 3", n)
	}

	// The joiner is a member like any other in the new epoch.
	msg, err := c2.Protect(nil, []byte("hello from outside"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := a2.Unprotect(send(t, msg))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Content.ApplicationData, []byte("hello from outside")) {
		t.Errorf("got %q", got.Content.ApplicationData)
	}
	msg, err = a2.Protect(nil, []byte("welcome"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Unprotect(send(t, msg)); err != nil {
		t.Fatal(err)
	}

	// The group info is good for one join: a joiner can still build
	// a commit from it, but it is a commit for an epoch that has
	// ended, and the group rejects it.
	_, stale, err := carol.JoinExternal(send(t, info).GroupInfo, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a2.Handle(send(t, stale)); !errors.Is(err, ErrNotForGroup) {
		t.Errorf("reusing a group info: %v, want %v", err, ErrNotForGroup)
	}

	// A resync: bob rejoins externally, replacing his own leaf.
	info, err = a2.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	b3, commit, err := bob.JoinExternal(send(t, info).GroupInfo, nil)
	if err != nil {
		t.Fatal(err)
	}
	commit = send(t, commit)
	a3, err := a2.Handle(commit)
	if err != nil {
		t.Fatalf("alice handling the resync: %v", err)
	}
	c3, err := c2.Handle(commit)
	if err != nil {
		t.Fatalf("carol handling the resync: %v", err)
	}
	if !bytes.Equal(b3.EpochAuthenticator(), a3.EpochAuthenticator()) || !bytes.Equal(b3.EpochAuthenticator(), c3.EpochAuthenticator()) {
		t.Fatal("members disagree after the resync")
	}
	if n := members(b3.Tree); n != 3 {
		t.Errorf("after the resync the group has %d members, want 3", n)
	}
}

// TestJoinExternalResyncLeftmost checks a resync whose Remove frees a
// leaf to the left of the tree's free leaves. The joiner must build
// its path in the tree the members get by applying the Remove and
// then placing it in the leftmost free leaf (RFC 9420, Section
// 12.4.3.2), leaving the rest of the tree as it was. The IETF interop
// harness's deep_random script found this.
func TestJoinExternalResyncLeftmost(t *testing.T) {
	cs := testSuite()
	names := []string{"alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi"}
	clients := make([]*Client, len(names))
	var adds []*Proposal
	for i, name := range names {
		clients[i] = newTestClient(t, cs, name)
		if i > 0 {
			adds = append(adds, &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *clients[i].KeyPackage}})
		}
	}
	a0, err := clients[0].NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	a1, _, welcome, err := a0.Commit(adds)
	if err != nil {
		t.Fatal(err)
	}
	groups := []*Group{a1}
	for _, c := range clients[1:] {
		g, err := c.Join(send(t, welcome).Welcome, nil)
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, g)
	}

	// Eve, at leaf 4, removes frank from leaf 5 and sets the node
	// above leaves 4 to 7, which is on leaf 5's direct path but not
	// on leaf 1's.
	remove := &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 5}}
	next, commit, _, err := groups[4].Commit([]*Proposal{remove})
	if err != nil {
		t.Fatal(err)
	}
	for i, g := range groups {
		switch i {
		case 4:
			groups[i] = next
		case 5:
			groups[i] = nil
		default:
			if groups[i], err = g.Handle(send(t, commit)); err != nil {
				t.Fatalf("%s handling eve's commit: %v", names[i], err)
			}
		}
	}

	// Bob, at leaf 1, rejoins; he must land back in leaf 1.
	info, err := groups[0].GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	b, commit, err := clients[1].JoinExternal(send(t, info).GroupInfo, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b.Index != 1 {
		t.Errorf("bob rejoined at leaf %d, want 1", b.Index)
	}
	for i, g := range groups {
		if g == nil || i == 1 {
			continue
		}
		next, err := g.Handle(send(t, commit))
		if err != nil {
			t.Fatalf("%s handling the resync: %v", names[i], err)
		}
		if !bytes.Equal(next.EpochAuthenticator(), b.EpochAuthenticator()) {
			t.Fatalf("%s disagrees with bob after the resync", names[i])
		}
	}
}

// members counts the non-blank leaves of a tree.
func members(t RatchetTree) int {
	n := 0
	for i := range t.Size() {
		if t.Leaf(i) != nil {
			n++
		}
	}
	return n
}

// TestExternalCommitRules checks the rules of RFC 9420, Section
// 12.4.3.2 on the proposals of an external commit.
func TestExternalCommitRules(t *testing.T) {
	a, b, c := threeMember(t)
	bob := &UpdatePath{LeafNode: *b.Tree.Leaf(b.Index)}
	inline := func(p *Proposal) ProposalOrRef {
		return ProposalOrRef{Type: ProposalOrRefTypeProposal, Proposal: p}
	}
	ei := inline(&Proposal{Type: ProposalTypeExternalInit, ExternalInit: &ExternalInit{}})
	remove := func(i LeafIndex) ProposalOrRef {
		return inline(&Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: uint32(i)}})
	}
	psk := inline(externalPSK("k"))
	for _, tc := range []struct {
		name   string
		commit Commit
		want   error
	}{
		{"no path", Commit{Proposals: []ProposalOrRef{ei}}, ErrBadExternalCommit},
		{"no external init", Commit{Path: bob}, ErrBadExternalCommit},
		{"two external inits", Commit{Path: bob, Proposals: []ProposalOrRef{ei, ei}}, ErrBadExternalCommit},
		{"by reference", Commit{Path: bob, Proposals: []ProposalOrRef{
			ei, {Type: ProposalOrRefTypeReference, Reference: []byte("ref")},
		}}, ErrBadExternalCommit},
		{"add", Commit{Path: bob, Proposals: []ProposalOrRef{
			ei, inline(&Proposal{Type: ProposalTypeAdd, Add: &Add{}}),
		}}, ErrBadExternalCommit},
		{"two removes", Commit{Path: bob, Proposals: []ProposalOrRef{ei, remove(b.Index), remove(c.Index)}}, ErrBadExternalCommit},
		{"remove of another member", Commit{Path: bob, Proposals: []ProposalOrRef{ei, remove(c.Index)}}, ErrBadExternalCommit},
		{"remove of a blank leaf", Commit{Path: bob, Proposals: []ProposalOrRef{ei, remove(3)}}, ErrLeafRange},
		{"same pre-shared key twice", Commit{Path: bob, Proposals: []ProposalOrRef{ei, psk, psk}}, ErrProposalList},
		{"resync", Commit{Path: bob, Proposals: []ProposalOrRef{ei, remove(b.Index), psk}}, nil},
	} {
		if err := a.Tree.externalCommitOK(&tc.commit, &a.Context); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

// JoinExternal checks the group info's signature before the tree,
// whose checks cost far more, so that an unsigned group info costs
// the joiner one signature verification.
func TestJoinExternalChecksSignatureFirst(t *testing.T) {
	cs := testSuite()
	a1, _, _ := threeMember(t)
	msg, err := a1.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	info := send(t, msg).GroupInfo
	info.Signature[0] ^= 1
	tree := append(a1.Tree.Clone(), nil, nil) // blank last node
	info.Extensions = slices.DeleteFunc(info.Extensions, func(e Extension) bool {
		return e.Type == ExtensionTypeRatchetTree
	})
	dave := newTestClient(t, cs, "dave")
	if _, _, err := dave.JoinExternal(info, tree); !errors.Is(err, ErrBadSignature) {
		t.Errorf("JoinExternal = %v, want %v", err, ErrBadSignature)
	}
}
