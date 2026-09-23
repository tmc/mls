package mls

import (
	"bytes"
	"errors"
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

// members counts the non-blank leaves of a tree.
func members(t RatchetTree) int {
	n := 0
	for i := LeafIndex(0); i < t.Size(); i++ {
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
