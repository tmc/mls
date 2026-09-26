package mls

import (
	"bytes"
	"errors"
	"strings"
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

// A reinitialized group is "a new group with the same membership"
// (RFC 9420, Section 11.2): Reinitialize refuses to build any other,
// and Resume refuses a welcome into one.
func TestReinitMembership(t *testing.T) {
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
	kp := func(name string) *KeyPackage { return newTestClient(t, cs, name).KeyPackage }
	tests := []struct {
		name    string
		self    string
		members []*KeyPackage
	}{
		{"missing member", "alice", []*KeyPackage{kp("bob")}},
		{"stranger", "alice", []*KeyPackage{kp("bob"), kp("carol"), kp("dave")}},
		{"stranger instead", "alice", []*KeyPackage{kp("bob"), kp("dave")}},
		{"not self", "dave", []*KeyPackage{kp("bob"), kp("carol")}},
		{"identity twice", "alice", []*KeyPackage{kp("bob"), kp("carol"), kp("carol")}},
		{"identity twice for a missing one", "alice", []*KeyPackage{kp("bob"), kp("bob")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ga2.Reinitialize(newTestClient(t, cs, tt.self), tt.members)
			if !errors.Is(err, ErrMembership) {
				t.Errorf("Reinitialize = %v, want %v", err, ErrMembership)
			}
		})
		// The same holds with an application's SameIdentity, which
		// is matched by a different path.
		t.Run(tt.name+"/SameIdentity", func(t *testing.T) {
			c := newTestClient(t, cs, tt.self)
			c.SameIdentity = func(a, b *Credential) bool { return bytes.Equal(a.Identity, b.Identity) }
			_, _, err := ga2.Reinitialize(c, tt.members)
			if !errors.Is(err, ErrMembership) {
				t.Errorf("Reinitialize = %v, want %v", err, ErrMembership)
			}
		})
	}

	// A welcome that brings a stranger along is refused.
	bob2 := newTestClient(t, cs, "bob")
	next, welcome, err := ga2.resume(newTestClient(t, cs, "alice"), ri.GroupID, nil, ResumptionPSKUsageReinit,
		[]*KeyPackage{bob2.KeyPackage, kp("carol"), kp("dave")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob2.Resume(send(t, welcome).Welcome, next.Tree, gb2); !errors.Is(err, ErrNotResumed) {
		t.Errorf("Resume = %v, want %v", err, ErrNotResumed)
	}

	// So is one that brings a member's identity in twice.
	bob3 := newTestClient(t, cs, "bob")
	next, welcome, err = ga2.resume(newTestClient(t, cs, "alice"), ri.GroupID, nil, ResumptionPSKUsageReinit,
		[]*KeyPackage{bob3.KeyPackage, kp("carol"), kp("carol")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob3.Resume(send(t, welcome).Welcome, next.Tree, gb2); !errors.Is(err, ErrNotResumed) {
		t.Errorf("Resume with an identity twice = %v, want %v", err, ErrNotResumed)
	}
}

// A member may hold several leaves of one identity, one per device,
// and a reinitialization carries each of them.
func TestReinitTwoDevices(t *testing.T) {
	cs := testSuite()
	alice := newTestClient(t, cs, "alice")
	g, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	laptop := newTestClient(t, cs, "alice")
	bob := newTestClient(t, cs, "bob")
	ri := &Reinit{GroupID: []byte("successor"), Version: Version10, CipherSuite: cs}
	g, _, _, err = g.Commit([]*Proposal{
		{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *laptop.KeyPackage}},
		{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}},
	})
	if err != nil {
		t.Fatal(err)
	}
	g2, _, _, err := g.Commit([]*Proposal{{Type: ProposalTypeReinit, Reinit: ri}})
	if err != nil {
		t.Fatal(err)
	}
	kp := func(name string) *KeyPackage { return newTestClient(t, cs, name).KeyPackage }
	if _, _, err := g2.Reinitialize(newTestClient(t, cs, "alice"), []*KeyPackage{kp("alice"), kp("bob")}); err != nil {
		t.Errorf("Reinitialize with both devices: %v", err)
	}
	if _, _, err := g2.Reinitialize(newTestClient(t, cs, "alice"), []*KeyPackage{kp("bob")}); !errors.Is(err, ErrMembership) {
		t.Errorf("Reinitialize without the second device = %v, want %v", err, ErrMembership)
	}
}

// A branch brings each old member in at most once.
func TestBranchIdentityTwice(t *testing.T) {
	cs := testSuite()
	_, _, _, ga, _, _ := setup(t, cs)
	b1 := newTestClient(t, cs, "bob")
	b2 := newTestClient(t, cs, "bob")
	if _, _, err := ga.Branch([]byte("subgroup"), nil, []*KeyPackage{b1.KeyPackage, b2.KeyPackage}); !errors.Is(err, ErrMembership) {
		t.Errorf("Branch = %v, want %v", err, ErrMembership)
	}
}

// A client's SameIdentity decides which credentials name the same
// member, as when a member's certificate changes with its keys.
func TestBranchSameIdentity(t *testing.T) {
	cs := testSuite()
	_, _, _, ga, _, _ := setup(t, cs)
	bob2 := newTestClient(t, cs, "bob@laptop")
	if _, _, err := ga.Branch([]byte("subgroup"), nil, []*KeyPackage{bob2.KeyPackage}); !errors.Is(err, ErrMembership) {
		t.Fatalf("Branch = %v, want %v", err, ErrMembership)
	}
	user := func(c *Credential) string { name, _, _ := strings.Cut(string(c.Identity), "@"); return name }
	same := func(a, b *Credential) bool { return user(a) == user(b) }
	ga.client.SameIdentity = same
	bob2.SameIdentity = same
	sub, welcome, err := ga.Branch([]byte("subgroup"), nil, []*KeyPackage{bob2.KeyPackage})
	if err != nil {
		t.Fatalf("Branch: %v", err)
	}
	if _, err := bob2.Resume(send(t, welcome).Welcome, sub.Tree, ga); err != nil {
		t.Errorf("Resume: %v", err)
	}
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
	// branched into the subgroup, and a welcome that tries to is
	// refused.
	dave := newTestClient(t, cs, "dave")
	if _, _, err := ga.Branch([]byte("subgroup"), ga.Context.Extensions, []*KeyPackage{dave.KeyPackage}); !errors.Is(err, ErrMembership) {
		t.Errorf("Branch = %v, want %v", err, ErrMembership)
	}
	sub, welcome, err = ga.resume(ga.client, []byte("subgroup"), ga.Context.Extensions, ResumptionPSKUsageBranch, []*KeyPackage{dave.KeyPackage})
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
	carol2 := newTestClient(t, next, "carol")
	joiners := []*KeyPackage{bob2.KeyPackage, carol2.KeyPackage}
	if _, _, err := ga2.Reinitialize(newTestClient(t, cs, "alice"), joiners); !errors.Is(err, ErrUnsupportedCipherSuite) {
		t.Errorf("Reinitialize with a client of the old suite = %v, want %v", err, ErrUnsupportedCipherSuite)
	}
	na, welcome, err := ga2.Reinitialize(alice2, joiners)
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
	carol2 := newTestClient(t, cs, "carol")
	next, welcome, err := early.Reinitialize(newTestClient(t, cs, "alice"), []*KeyPackage{bob2.KeyPackage, carol2.KeyPackage})
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

// A pre-shared key's nonce is as long as the suite's hash output
// (RFC 9420, Section 8.4), in a welcome message as in a commit.
func TestResumeShortNonce(t *testing.T) {
	cs := testSuite()
	_, _, _, ga, _, _ := setup(t, cs)
	bob2 := newTestClient(t, cs, "bob")
	_, msg, err := ga.Branch([]byte("subgroup"), nil, []*KeyPackage{bob2.KeyPackage})
	if err != nil {
		t.Fatal(err)
	}
	w := send(t, msg).Welcome
	ref := w.Secrets[0].NewMember
	secrets, err := w.GroupSecrets(ref, bob2.InitPriv)
	if err != nil {
		t.Fatal(err)
	}
	secrets.PSKs[0].PSKNonce = secrets.PSKs[0].PSKNonce[:8]
	w.Secrets = nil
	if err := w.AddMember(ref, bob2.KeyPackage.InitKey, secrets); err != nil {
		t.Fatal(err)
	}
	if _, err := bob2.Resume(w, nil, ga); !errors.Is(err, ErrBadPSKNonce) {
		t.Errorf("Resume = %v, want %v", err, ErrBadPSKNonce)
	}
}
