package mls

import (
	"maps"
	"testing"
)

func TestPathRequired(t *testing.T) {
	for _, tt := range []struct {
		name string
		ps   []proposal
		want bool
	}{
		{"empty commit", nil, true},
		{"add", []proposal{{Proposal: &Proposal{Type: ProposalTypeAdd}}}, false},
		{"psk", []proposal{{Proposal: &Proposal{Type: ProposalTypePreSharedKey}}}, false},
		{"reinit", []proposal{{Proposal: &Proposal{Type: ProposalTypeReinit}}}, false},
		{"update", []proposal{{Proposal: &Proposal{Type: ProposalTypeUpdate}}}, true},
		{"remove", []proposal{{Proposal: &Proposal{Type: ProposalTypeRemove}}}, true},
		{"external init", []proposal{{Proposal: &Proposal{Type: ProposalTypeExternalInit}}}, true},
		{"extensions", []proposal{{Proposal: &Proposal{Type: ProposalTypeGroupContextExtensions}}}, true},
		{"add and remove", []proposal{
			{Proposal: &Proposal{Type: ProposalTypeAdd}},
			{Proposal: &Proposal{Type: ProposalTypeRemove}},
		}, true},
	} {
		if got := pathRequired(tt.ps); got != tt.want {
			t.Errorf("pathRequired(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// threeMember returns alice, bob and carol's views of one epoch.
func threeMember(t *testing.T) (a, b, c *Group) {
	t.Helper()
	cs := testSuite()
	alice := newTestClient(t, cs, "alice")
	bob := newTestClient(t, cs, "bob")
	carol := newTestClient(t, cs, "carol")

	a0, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	a1, _, w, err := a0.Commit([]*Proposal{
		{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}},
		{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *carol.KeyPackage}},
	})
	if err != nil {
		t.Fatal(err)
	}
	wm := send(t, w)
	b1, err := bob.Join(wm.Welcome, nil)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := carol.Join(wm.Welcome, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a1, b1, c1
}

// pathlessCommit builds the commit a peer that ignores RFC 9420,
// Section 12.4 would send: one that carries no update path, and so a
// commit secret of all zeros. Group.Commit never builds one, so it
// has to be assembled here.
func pathlessCommit(t *testing.T, g *Group, ps []*Proposal) *Message {
	t.Helper()
	cs := g.CipherSuite
	commit := &Commit{}
	from := Sender{Type: SenderTypeMember, LeafIndex: uint32(g.Index)}
	var proposals []proposal
	for _, p := range ps {
		commit.Proposals = append(commit.Proposals, ProposalOrRef{Type: ProposalOrRefTypeProposal, Proposal: p})
		proposals = append(proposals, proposal{p, from})
	}
	next := &Group{
		CipherSuite: cs,
		Context:     g.Context,
		Tree:        g.Tree.Clone(),
		Index:       g.Index,
		client:      g.client,
		proposals:   make(map[string]*AuthenticatedContent),
		updates:     make(map[string][]byte),
		resumption:  maps.Clone(g.resumption),
	}
	if _, err := next.apply(proposals); err != nil {
		t.Fatal(err)
	}
	next.Context.Epoch = g.Context.Epoch + 1
	var err error
	if next.Context.TreeHash, err = next.Tree.RootHash(cs); err != nil {
		t.Fatal(err)
	}
	c := &AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content: FramedContent{
			GroupID:     g.Context.GroupID,
			Epoch:       g.Context.Epoch,
			Sender:      from,
			ContentType: ContentTypeCommit,
			Commit:      commit,
		},
		Auth: FramedContentAuthData{ContentType: ContentTypeCommit},
	}
	if err := c.Sign(cs, g.client.SignaturePriv, g.Context.Version, &g.Context); err != nil {
		t.Fatal(err)
	}
	if next.Context.ConfirmedTranscriptHash, err = cs.ConfirmedTranscriptHash(g.interim, c); err != nil {
		t.Fatal(err)
	}
	commitSecret := make([]byte, cs.HashSize()) // no path, so all zero
	joiner, err := cs.JoinerSecret(g.schedule.InitSecret, commitSecret, &next.Context)
	if err != nil {
		t.Fatal(err)
	}
	sched, err := newKeySchedule(cs, joiner, nil, &next.Context)
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth.ConfirmationTag, err = cs.ConfirmationTag(sched.ConfirmationKey, next.Context.ConfirmedTranscriptHash); err != nil {
		t.Fatal(err)
	}
	pm, err := c.PublicMessage(cs, g.schedule.MembershipKey, &g.Context)
	if err != nil {
		t.Fatal(err)
	}
	return &Message{Version: g.Context.Version, WireFormat: WireFormatPublicMessage, PublicMessage: pm}
}

// A commit with no update path must be rejected where the RFC
// requires one. Accepting a pathless removal leaves the new epoch
// derivable from the init secret the removed member still holds, so
// the removal removes nobody.
func TestCommitWithoutPath(t *testing.T) {
	for _, tt := range []struct {
		name string
		ps   []*Proposal
	}{
		{"remove", []*Proposal{{Type: ProposalTypeRemove, Remove: &Remove{Removed: 2}}}},
		{"empty", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a1, b1, _ := threeMember(t)
			if _, err := b1.Handle(send(t, pathlessCommit(t, a1, tt.ps))); err != ErrPathRequired {
				t.Errorf("Handle = %v, want %v", err, ErrPathRequired)
			}
		})
	}
}

// An Add alone does not require a path, so a commit that carries none
// must still be accepted.
func TestCommitWithoutPathAllowed(t *testing.T) {
	a1, b1, _ := threeMember(t)
	dave := newTestClient(t, a1.CipherSuite, "dave")
	add := []*Proposal{{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *dave.KeyPackage}}}
	b2, err := b1.Handle(send(t, pathlessCommit(t, a1, add)))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if b2.Epoch() != 2 {
		t.Errorf("epoch = %d, want 2", b2.Epoch())
	}
}

// A Remove must name a leaf of the tree. An index that wraps around
// to a member's leaf would remove that member under another name,
// past the rule that a committer cannot remove itself.
func TestCommitRemoveOutOfRange(t *testing.T) {
	for _, removed := range []uint32{3, 1 << 31, 1<<31 + 1} {
		a1, _, _ := threeMember(t)
		ps := []*Proposal{{Type: ProposalTypeRemove, Remove: &Remove{Removed: removed}}}
		if _, _, _, err := a1.Commit(ps); err != ErrLeafRange {
			t.Errorf("Commit(remove %d) = %v, want %v", removed, err, ErrLeafRange)
		}
	}
}
