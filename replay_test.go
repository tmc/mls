package mls

import (
	"errors"
	"testing"
)

// replayFixture holds proposals from outside a group, captured in
// one epoch, and the groups they might be replayed to.
type replayFixture struct {
	g1     *Group // alice's group "group", epoch 1, where the proposals were sent
	g2     *Group // the same group one epoch later
	twin   *Group // another group named "group" with the same external senders, epoch 1
	rekey  *Group // another group named "group" with a different external sender, epoch 1
	other  *Group // a group named "other" with the same external senders, epoch 1
	remove *Message
	add    *Message
}

func newReplayFixture(t *testing.T) *replayFixture {
	t.Helper()
	cs := testSuite()
	accept := func(*AuthenticatedContent) error { return nil }
	senders := func() (priv []byte, ext Extensions) {
		priv, pub, err := cs.GenerateSignatureKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		s := ExternalSenders{{SignatureKey: pub, Credential: Credential{Type: CredentialTypeBasic, Identity: []byte("directory")}}}
		if err := ext.Set(ExtensionTypeExternalSenders, &s); err != nil {
			t.Fatal(err)
		}
		return priv, ext
	}
	// group returns a two-member group at epoch 1.
	group := func(creator string, id []byte, ext Extensions) *Group {
		c := newTestClient(t, cs, creator)
		c.ExternalProposal = accept
		g0, err := c.NewGroup(id, ext)
		if err != nil {
			t.Fatal(err)
		}
		joiner := newTestClient(t, cs, creator+"'s friend")
		g1, _, _, err := g0.Commit([]*Proposal{{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *joiner.KeyPackage}}})
		if err != nil {
			t.Fatal(err)
		}
		return g1
	}

	priv, ext := senders()
	_, ext2 := senders()
	f := &replayFixture{
		g1:    group("alice", []byte("group"), ext),
		twin:  group("mallory", []byte("group"), ext),
		rekey: group("trent", []byte("group"), ext2),
		other: group("oscar", []byte("other"), ext),
	}
	var err error
	if f.g2, _, _, err = f.g1.Commit(nil); err != nil {
		t.Fatal(err)
	}
	dir := &ExternalClient{CipherSuite: cs, SignaturePriv: priv}
	rm := &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 1}}
	if f.remove, err = dir.Propose(f.g1.Context.GroupID, f.g1.Context.Epoch, rm); err != nil {
		t.Fatal(err)
	}
	dave := newTestClient(t, cs, "dave")
	if f.add, err = dave.ProposeAdd(f.g1.Context.GroupID, f.g1.Context.Epoch); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestExternalProposalReplay replays proposals from outside a group,
// by an external sender and by a client asking to be added, captured
// in epoch 1 of the group named "group".
//
// Neither kind of proposal carries a membership tag, and neither
// signature covers the group context: RFC 9420, Section 6.1 includes
// the context in FramedContentTBS only for member and new_member_commit
// senders, since a party outside the group does not know it. What
// binds such a proposal to a group is the group_id and epoch in its
// signed FramedContent. [Group.Unprotect] rejects a proposal naming
// another group or epoch with ErrNotForGroup, and rewriting either
// field breaks the signature.
//
// So a proposal is accepted by any group that has the same group ID
// and epoch and, for an external sender, lists the same signature key
// at the same index. That is a limitation of the protocol, not of this
// package: RFC 9420, Section 11 asks that group IDs be chosen so that
// honest creators almost never pick the same one, for example as a
// fresh random value of KDF.Nh bytes. The "twin" cases pin down that
// an application that reuses group IDs loses this protection.
func TestExternalProposalReplay(t *testing.T) {
	tests := []struct {
		name    string
		msg     func(f *replayFixture) *Message
		target  func(t *testing.T, f *replayFixture) *Group
		want    error
		members int // after the target commits, if the replay is accepted
	}{
		{
			name:   "add in a later epoch",
			msg:    func(f *replayFixture) *Message { return f.add },
			target: func(t *testing.T, f *replayFixture) *Group { return f.g2 },
			want:   ErrNotForGroup,
		},
		{
			name:   "remove in a later epoch",
			msg:    func(f *replayFixture) *Message { return f.remove },
			target: func(t *testing.T, f *replayFixture) *Group { return f.g2 },
			want:   ErrNotForGroup,
		},
		{
			// A duplicate has the same proposal reference as
			// the original and is remembered once, so the commit
			// adds dave once.
			name: "add twice in the same epoch",
			msg:  func(f *replayFixture) *Message { return f.add },
			target: func(t *testing.T, f *replayFixture) *Group {
				handle(t, f.g1, f.add)
				return f.g1
			},
			members: 3,
		},
		{
			name: "remove twice in the same epoch",
			msg:  func(f *replayFixture) *Message { return f.remove },
			target: func(t *testing.T, f *replayFixture) *Group {
				handle(t, f.g1, f.remove)
				return f.g1
			},
			members: 1,
		},
		{
			// Committing the proposal ends its epoch.
			name: "add after it was committed",
			msg:  func(f *replayFixture) *Message { return f.add },
			target: func(t *testing.T, f *replayFixture) *Group {
				handle(t, f.g1, f.add)
				g, _, _, err := f.g1.Commit(nil)
				if err != nil {
					t.Fatal(err)
				}
				return g
			},
			want: ErrNotForGroup,
		},
		{
			name: "remove after it was committed",
			msg:  func(f *replayFixture) *Message { return f.remove },
			target: func(t *testing.T, f *replayFixture) *Group {
				handle(t, f.g1, f.remove)
				g, _, _, err := f.g1.Commit(nil)
				if err != nil {
					t.Fatal(err)
				}
				return g
			},
			want: ErrNotForGroup,
		},
		{
			name:    "add to a twin with the same group ID",
			msg:     func(f *replayFixture) *Message { return f.add },
			target:  func(t *testing.T, f *replayFixture) *Group { return f.twin },
			members: 3,
		},
		{
			name:    "remove from a twin with the same group ID and external senders",
			msg:     func(f *replayFixture) *Message { return f.remove },
			target:  func(t *testing.T, f *replayFixture) *Group { return f.twin },
			members: 1,
		},
		{
			name:   "remove from a twin with other external senders",
			msg:    func(f *replayFixture) *Message { return f.remove },
			target: func(t *testing.T, f *replayFixture) *Group { return f.rekey },
			want:   ErrBadSignature,
		},
		{
			name:   "add to another group ID",
			msg:    func(f *replayFixture) *Message { return f.add },
			target: func(t *testing.T, f *replayFixture) *Group { return f.other },
			want:   ErrNotForGroup,
		},
		{
			name:   "remove from another group ID",
			msg:    func(f *replayFixture) *Message { return f.remove },
			target: func(t *testing.T, f *replayFixture) *Group { return f.other },
			want:   ErrNotForGroup,
		},
		{
			name:   "add readdressed to a later epoch",
			msg:    func(f *replayFixture) *Message { return readdress(t, f.add, f.g2) },
			target: func(t *testing.T, f *replayFixture) *Group { return f.g2 },
			want:   ErrBadSignature,
		},
		{
			name:   "remove readdressed to a later epoch",
			msg:    func(f *replayFixture) *Message { return readdress(t, f.remove, f.g2) },
			target: func(t *testing.T, f *replayFixture) *Group { return f.g2 },
			want:   ErrBadSignature,
		},
		{
			name:   "add readdressed to another group ID",
			msg:    func(f *replayFixture) *Message { return readdress(t, f.add, f.other) },
			target: func(t *testing.T, f *replayFixture) *Group { return f.other },
			want:   ErrBadSignature,
		},
		{
			name:   "remove readdressed to another group ID",
			msg:    func(f *replayFixture) *Message { return readdress(t, f.remove, f.other) },
			target: func(t *testing.T, f *replayFixture) *Group { return f.other },
			want:   ErrBadSignature,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newReplayFixture(t)
			g := tt.target(t, f)
			staged := len(g.proposals)
			got, err := g.Handle(send(t, tt.msg(f)))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Handle = %v, want %v", err, tt.want)
			}
			if err != nil {
				if got != nil {
					t.Error("Handle returned a group along with an error")
				}
				if len(g.proposals) != staged {
					t.Errorf("%d proposals staged after a rejected replay, want %d", len(g.proposals), staged)
				}
				return
			}
			if len(g.proposals) != 1 {
				t.Errorf("%d proposals staged, want 1", len(g.proposals))
			}
			next, _, _, err := g.Commit(nil)
			if err != nil {
				t.Fatalf("Commit: %v", err)
			}
			if n := members(next.Tree); n != tt.members {
				t.Errorf("members = %d, want %d", n, tt.members)
			}
		})
	}
}

// handle delivers m to g, which must accept it.
func handle(t *testing.T, g *Group, m *Message) {
	t.Helper()
	if _, err := g.Handle(send(t, m)); err != nil {
		t.Fatal(err)
	}
}

// readdress returns a copy of the public message m naming g's group ID
// and epoch in place of its own, as an attacker without the sender's
// signing key would forge it.
func readdress(t *testing.T, m *Message, g *Group) *Message {
	t.Helper()
	c := send(t, m)
	c.PublicMessage.Content.GroupID = g.Context.GroupID
	c.PublicMessage.Content.Epoch = g.Context.Epoch
	return c
}
