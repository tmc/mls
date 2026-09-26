package mls

import (
	"bytes"
	"errors"
	"testing"

	"github.com/tmc/mls/tlssyntax"
)

// setup builds a three-member group and returns it as each member
// sees it.
func setup(t *testing.T, cs CipherSuite) (*Client, *Client, *Client, *Group, *Group, *Group) {
	t.Helper()
	alice := newTestClient(t, cs, "alice")
	bob := newTestClient(t, cs, "bob")
	carol := newTestClient(t, cs, "carol")
	ga, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ga, _, welcome, err := ga.Commit([]*Proposal{
		{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}},
		{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *carol.KeyPackage}},
	})
	if err != nil {
		t.Fatal(err)
	}
	gb, err := bob.Join(send(t, welcome).Welcome, ga.Tree)
	if err != nil {
		t.Fatal(err)
	}
	gc, err := carol.Join(send(t, welcome).Welcome, ga.Tree)
	if err != nil {
		t.Fatal(err)
	}
	return alice, bob, carol, ga, gb, gc
}

// TestReinit runs the three steps of RFC 9420, Section 11.2: a Reinit
// proposal, a commit covering it, and the new group that carries the
// membership over.
func TestReinit(t *testing.T) {
	cs := testSuite()
	alice, bob, carol, ga, gb, gc := setup(t, cs)

	ri := &Reinit{GroupID: []byte("successor"), Version: Version10, CipherSuite: cs}
	msg, err := gb.Propose(&Proposal{Type: ProposalTypeReinit, Reinit: ri})
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []*Group{ga, gc} {
		if _, _, err := g.Handle(send(t, msg)); err != nil {
			t.Fatal(err)
		}
	}
	ga2, commit, _, err := ga.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	gb2, _, err := gb.Handle(send(t, commit))
	if err != nil {
		t.Fatal(err)
	}
	gc2, _, err := gc.Handle(send(t, commit))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []*Group{ga2, gb2, gc2} {
		if got := g.Reinit(); got == nil || !bytes.Equal(got.GroupID, ri.GroupID) {
			t.Fatalf("Reinit = %v, want %v", got, ri)
		}
		// The old group is finished.
		if _, _, _, err := g.Commit(nil); !errors.Is(err, ErrReinitialized) {
			t.Errorf("Commit = %v, want %v", err, ErrReinitialized)
		}
		if _, err := g.Propose(&Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 1}}); !errors.Is(err, ErrReinitialized) {
			t.Errorf("Propose = %v, want %v", err, ErrReinitialized)
		}
	}

	// Any member may create the successor; here it is Carol, who
	// did not commit the Reinit. The others fetch new key
	// packages, since the successor may use a new cipher suite.
	bob2 := newTestClient(t, cs, "bob")
	alice2 := newTestClient(t, cs, "alice")
	carol2 := newTestClient(t, cs, "carol")
	next, welcome, err := gc2.Reinitialize(carol2, []*KeyPackage{alice2.KeyPackage, bob2.KeyPackage})
	if err != nil {
		t.Fatal(err)
	}
	if next.Epoch() != 1 {
		t.Errorf("epoch = %d, want 1", next.Epoch())
	}
	if !bytes.Equal(next.Context.GroupID, ri.GroupID) {
		t.Errorf("group id = %q, want %q", next.Context.GroupID, ri.GroupID)
	}
	for _, c := range []*Client{alice2, bob2} {
		g, err := c.Resume(send(t, welcome).Welcome, next.Tree, gc2)
		if err != nil {
			t.Fatalf("%s: %v", c.KeyPackage.LeafNode.Credential.Identity, err)
		}
		if !bytes.Equal(g.EpochAuthenticator(), next.EpochAuthenticator()) {
			t.Error("joiner did not reach the same epoch")
		}
	}

	// Join does not accept it: the resumption key is not one the
	// joining client can resolve on its own.
	if _, err := bob2.Join(send(t, welcome).Welcome, next.Tree); err == nil {
		t.Error("Join accepted a welcome that needs a resumption key")
	}
	// Nor does it resume from an epoch that never committed the
	// Reinit, whose resumption key the welcome does not name.
	if _, err := bob2.Resume(send(t, welcome).Welcome, next.Tree, ga); !errors.Is(err, ErrUnknownPSK) {
		t.Errorf("Resume = %v, want %v", err, ErrUnknownPSK)
	}
	_ = alice
	_ = bob
	_ = carol
}

// TestBranch covers RFC 9420, Section 11.3: a member forms a subgroup
// of the original group's members.
func TestBranch(t *testing.T) {
	cs := testSuite()
	_, bob, _, ga, _, _ := setup(t, cs)

	bob2 := newTestClient(t, cs, "bob")
	sub, welcome, err := ga.Branch([]byte("subgroup"), ga.Context.Extensions, []*KeyPackage{bob2.KeyPackage})
	if err != nil {
		t.Fatal(err)
	}
	if next := sub.Epoch(); next != 1 {
		t.Errorf("epoch = %d, want 1", next)
	}
	if got := members(sub.Tree); got != 2 {
		t.Errorf("members = %d, want 2", got)
	}
	g, err := bob2.Resume(send(t, welcome).Welcome, sub.Tree, ga)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(g.EpochAuthenticator(), sub.EpochAuthenticator()) {
		t.Error("joiner did not reach the same epoch")
	}

	// A client that was not in the original group cannot be
	// branched into the subgroup.
	dave := newTestClient(t, cs, "dave")
	sub, welcome, err = ga.Branch([]byte("subgroup"), ga.Context.Extensions, []*KeyPackage{dave.KeyPackage})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dave.Resume(send(t, welcome).Welcome, sub.Tree, ga); !errors.Is(err, ErrNotResumed) {
		t.Errorf("Resume = %v, want %v", err, ErrNotResumed)
	}
	_ = bob
}

// A branch may carry extensions other than its parent's (RFC 9420,
// Section 11.3), and its members must support what they require.
func TestBranchExtensions(t *testing.T) {
	cs := testSuite()
	ext := func(typ ExtensionType, body tlssyntax.Marshaler) Extensions {
		var es Extensions
		if err := es.Set(typ, body); err != nil {
			t.Fatal(err)
		}
		return es
	}
	// The extensions of the interop harness's branch/with_extensions.
	harness := append(ext(ExtensionTypeRequiredCapabilities, &RequiredCapabilities{}),
		ext(ExtensionTypeExternalSenders, &ExternalSenders{})...)
	for _, tc := range []struct {
		name       string
		extensions Extensions
		want       error
	}{
		{"none", nil, nil},
		{"new", harness, nil},
		{"unsupported", ext(ExtensionTypeRequiredCapabilities, &RequiredCapabilities{ExtensionTypes: []ExtensionType{0xff00}}), ErrUnsupportedCapability},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, ga, _, _ := setup(t, cs)
			bob2 := newTestClient(t, cs, "bob")
			sub, welcome, err := ga.Branch([]byte("subgroup"), tc.extensions, []*KeyPackage{bob2.KeyPackage})
			if !errors.Is(err, tc.want) {
				t.Fatalf("Branch = %v, want %v", err, tc.want)
			}
			if err != nil {
				return
			}
			if !sameExtensions(sub.Context.Extensions, tc.extensions) {
				t.Errorf("branch extensions = %v, want %v", sub.Context.Extensions, tc.extensions)
			}
			g, err := bob2.Resume(send(t, welcome).Welcome, sub.Tree, ga)
			if err != nil {
				t.Fatal(err)
			}
			if !sameExtensions(g.Context.Extensions, tc.extensions) {
				t.Errorf("joiner's extensions = %v, want %v", g.Context.Extensions, tc.extensions)
			}
			if !bytes.Equal(g.EpochAuthenticator(), sub.EpochAuthenticator()) {
				t.Error("joiner did not reach the same epoch")
			}
		})
	}
}

// A branch is a new group and needs a new group ID. See RFC 9420,
// Section 11.3.
func TestBranchGroupID(t *testing.T) {
	cs := testSuite()
	_, _, _, ga, _, _ := setup(t, cs)
	bob2 := newTestClient(t, cs, "bob")
	if _, _, err := ga.Branch(ga.Context.GroupID, nil, []*KeyPackage{bob2.KeyPackage}); !errors.Is(err, ErrSameGroupID) {
		t.Errorf("Branch = %v, want %v", err, ErrSameGroupID)
	}
}

// A group can be reinitialized with a new cipher suite, which is one
// of the reasons RFC 9420, Section 11.2 gives for reinitializing.
// Whoever creates the new group does so with a client of the new
// suite, and one of the old suite is refused.
func TestReinitCipherSuite(t *testing.T) {
	cs, next := testSuite(), P384AES256GCMSHA384P384
	_, _, _, ga, gb, _ := setup(t, cs)
	ri := &Reinit{GroupID: []byte("successor"), Version: Version10, CipherSuite: next}
	ga2, commit, _, err := ga.Commit([]*Proposal{{Type: ProposalTypeReinit, Reinit: ri}})
	if err != nil {
		t.Fatal(err)
	}
	gb2, _, err := gb.Handle(send(t, commit))
	if err != nil {
		t.Fatal(err)
	}
	alice2 := newTestClient(t, next, "alice")
	bob2 := newTestClient(t, next, "bob")
	if _, _, err := ga2.Reinitialize(newTestClient(t, cs, "alice"), []*KeyPackage{bob2.KeyPackage}); !errors.Is(err, ErrUnsupportedCipherSuite) {
		t.Errorf("Reinitialize with a client of the old suite = %v, want %v", err, ErrUnsupportedCipherSuite)
	}
	na, welcome, err := ga2.Reinitialize(alice2, []*KeyPackage{bob2.KeyPackage})
	if err != nil {
		t.Fatalf("Reinitialize: %v", err)
	}
	if na.CipherSuite != next {
		t.Errorf("new group's suite = %v, want %v", na.CipherSuite, next)
	}
	nb, err := bob2.Resume(send(t, welcome).Welcome, nil, gb2)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if !bytes.Equal(na.EpochAuthenticator(), nb.EpochAuthenticator()) {
		t.Error("members of the new group disagree on its epoch")
	}
}

// A reinitialized group is resumed from the epoch that committed the
// Reinit, not from an earlier one whose resumption key a member also
// holds.
func TestResumeReinitEpoch(t *testing.T) {
	cs := testSuite()
	_, _, _, ga, gb, _ := setup(t, cs)
	ri := &Reinit{GroupID: []byte("successor"), Version: Version10, CipherSuite: cs}
	ga2, commit, _, err := ga.Commit([]*Proposal{{Type: ProposalTypeReinit, Reinit: ri}})
	if err != nil {
		t.Fatal(err)
	}
	gb2, _, err := gb.Handle(send(t, commit))
	if err != nil {
		t.Fatal(err)
	}
	// Alice builds the new group from the epoch before, whose
	// resumption key gb2 still holds.
	early := *ga2
	early.Context.Epoch--
	bob2 := newTestClient(t, cs, "bob")
	next, welcome, err := early.Reinitialize(newTestClient(t, cs, "alice"), []*KeyPackage{bob2.KeyPackage})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob2.Resume(send(t, welcome).Welcome, next.Tree, gb2); !errors.Is(err, ErrNotResumed) {
		t.Errorf("Resume = %v, want %v", err, ErrNotResumed)
	}
}

// A welcome links the new group to at most one old one. See RFC 9420,
// Section 12.4.3.1.
func TestResumeTwoPSKs(t *testing.T) {
	cs := testSuite()
	alice, _, _, ga, _, _ := setup(t, cs)
	branch := func(nonce byte) *Proposal {
		id := PreSharedKeyID{
			Type:       PSKTypeResumption,
			Usage:      ResumptionPSKUsageBranch,
			PSKGroupID: ga.Context.GroupID,
			PSKEpoch:   ga.Context.Epoch,
			PSKNonce:   make([]byte, cs.HashSize()),
		}
		id.PSKNonce[0] = nonce
		return &Proposal{Type: ProposalTypePreSharedKey, PreSharedKey: &PreSharedKey{PSK: id}}
	}
	sub, err := alice.NewGroup([]byte("subgroup"), nil)
	if err != nil {
		t.Fatal(err)
	}
	sub.prior = ga
	bob2 := newTestClient(t, cs, "bob")
	add := &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob2.KeyPackage}}
	next, _, welcome, err := sub.Commit([]*Proposal{branch(1), branch(2), add})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob2.Resume(send(t, welcome).Welcome, next.Tree, ga); !errors.Is(err, ErrNotResumed) {
		t.Errorf("Resume = %v, want %v", err, ErrNotResumed)
	}
}
