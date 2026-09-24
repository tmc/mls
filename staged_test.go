package mls

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// stageUpdate has b propose a key rotation and a remember it, the way
// a committer stages the proposals it saw in the epoch. It returns
// the leaf the rotation installs.
func stageUpdate(t *testing.T, a, b *Group) *LeafNode {
	t.Helper()
	leaf, encPriv, _ := rotate(t, b, nil)
	m, err := b.ProposeUpdate(leaf, encPriv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.Unprotect(send(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddProposal(c); err != nil {
		t.Fatal(err)
	}
	return leaf
}

// A member that rotates twice in one epoch supersedes its own first
// update. Carrying both would cover one leaf twice, which Section
// 12.2 forbids, and nothing outside the package can drop either one.
func TestStagedUpdateSupersedes(t *testing.T) {
	a, b, _ := threeMember(t)
	stageUpdate(t, a, b)
	second := stageUpdate(t, a, b)
	if n := len(a.proposals); n != 1 {
		t.Errorf("after two updates from one leaf, %d staged, want 1", n)
	}
	a2, msg, _, err := a.Commit(nil)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got := a2.Tree.Leaf(b.Index).EncryptionKey; !bytes.Equal(got, second.EncryptionKey) {
		t.Error("the commit applied the superseded update, not the later one")
	}
	// The proposer must still be able to follow it.
	if _, err := b.Handle(send(t, msg)); err != nil {
		t.Errorf("the proposer cannot follow its own update: %v", err)
	}
}

// A staged update must not keep the committer from removing the
// member that sent it. One update was enough to make a member
// unremovable for the rest of the epoch.
func TestStagedUpdateDoesNotBlockRemove(t *testing.T) {
	a, b, _ := threeMember(t)
	stageUpdate(t, a, b)
	a2, _, _, err := a.Commit([]*Proposal{{Type: ProposalTypeRemove, Remove: &Remove{Removed: uint32(b.Index)}}})
	if err != nil {
		t.Fatalf("commit removing the proposer: %v", err)
	}
	if a2.Tree.Leaf(b.Index) != nil {
		t.Error("the member is still in the tree")
	}
}

// A removal staged before an update of the same leaf is not undone by
// it: the leaf is removed and the update is left behind.
func TestStagedRemoveBeatsUpdate(t *testing.T) {
	a, b, c := threeMember(t)
	m, err := c.Propose(&Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: uint32(b.Index)}})
	if err != nil {
		t.Fatal(err)
	}
	ac, err := a.Unprotect(send(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddProposal(ac); err != nil {
		t.Fatal(err)
	}
	stageUpdate(t, a, b)
	a2, _, _, err := a.Commit(nil)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if a2.Tree.Leaf(b.Index) != nil {
		t.Error("an update saved the leaf a staged removal covered")
	}
}

// A commit still carries the proposals it should: two members rotate,
// both updates are applied, and an unrelated staged proposal is not
// dropped by the conflict rules.
func TestStagedNoConflict(t *testing.T) {
	a, b, c := threeMember(t)
	bl := stageUpdate(t, a, b)
	cl := stageUpdate(t, a, c)
	a2, _, _, err := a.Commit(nil)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !bytes.Equal(a2.Tree.Leaf(b.Index).EncryptionKey, bl.EncryptionKey) ||
		!bytes.Equal(a2.Tree.Leaf(c.Index).EncryptionKey, cl.EncryptionKey) {
		t.Error("a commit dropped an update that conflicted with nothing")
	}
}

// stageRaw has b send p and puts it among a's staged proposals
// without the checks AddProposal makes, as a peer running other code
// might have accepted it.
func stageRaw(t *testing.T, a, b *Group, p *Proposal) {
	t.Helper()
	c := &AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content: FramedContent{
			GroupID:     b.Context.GroupID,
			Epoch:       b.Context.Epoch,
			Sender:      Sender{Type: SenderTypeMember, LeafIndex: uint32(b.Index)},
			ContentType: ContentTypeProposal,
			Proposal:    p,
		},
		Auth: FramedContentAuthData{ContentType: ContentTypeProposal},
	}
	if err := c.Sign(b.CipherSuite, b.client.SignaturePriv, b.Context.Version, &b.Context); err != nil {
		t.Fatal(err)
	}
	ref, err := c.Ref(a.CipherSuite)
	if err != nil {
		t.Fatal(err)
	}
	a.proposals[hex.EncodeToString(ref)] = c
}

// stage has from propose p and each of to remember it.
func stage(t *testing.T, from *Group, p *Proposal, to ...*Group) {
	t.Helper()
	m, err := from.Propose(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range to {
		if _, err := g.Handle(send(t, m)); err != nil {
			t.Fatal(err)
		}
	}
}

// externalPSK is a proposal to inject the external pre-shared key id.
func externalPSK(id string) *Proposal {
	return &Proposal{Type: ProposalTypePreSharedKey, PreSharedKey: &PreSharedKey{
		PSK: PreSharedKeyID{Type: PSKTypeExternal, PSKID: []byte(id), PSKNonce: make([]byte, 32)},
	}}
}

// A staged proposal that cannot be committed must not keep the
// committer from committing: RFC 9420, Section 12.2 has it choose a
// valid set from what it was sent. Each case stages a bad proposal
// alongside a good one and checks that the commit carries only the
// good one.
func TestStagedInvalidLeftOut(t *testing.T) {
	cs := testSuite()
	psk := func(id PreSharedKeyID) ([]byte, error) {
		if string(id.PSKID) == "known" {
			return make([]byte, 32), nil
		}
		return nil, ErrUnknownPSK
	}
	add := func(c *Client) *Proposal {
		return &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *c.KeyPackage}}
	}
	dave := newTestClient(t, cs, "dave")
	erin := newTestClient(t, cs, "erin")
	corrupt := *erin.KeyPackage
	corrupt.Signature = bytes.Clone(corrupt.Signature)
	corrupt.Signature[0] ^= 1

	tests := []struct {
		name  string
		stage func(t *testing.T, a, b, c *Group)
		want  int // members after the commit
	}{
		{"two adds of one client", func(t *testing.T, a, b, c *Group) {
			stage(t, b, add(dave), a, c)
			stage(t, c, add(dave), a, b)
		}, 4},
		{"key package with a bad signature", func(t *testing.T, a, b, c *Group) {
			stageRaw(t, a, b, &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: corrupt}})
			stage(t, c, add(dave), a, b)
		}, 4},
		{"reinit alongside another proposal", func(t *testing.T, a, b, c *Group) {
			stage(t, b, &Proposal{Type: ProposalTypeReinit, Reinit: &Reinit{GroupID: []byte("new"), Version: Version10, CipherSuite: cs}}, a, c)
			stage(t, c, externalPSK("known"), a, b)
		}, 3},
		{"pre-shared key the committer does not have", func(t *testing.T, a, b, c *Group) {
			stage(t, b, externalPSK("unknown"), a, c)
			stage(t, c, add(dave), a, b)
		}, 4},
		{"psk nonce shorter than the hash", func(t *testing.T, a, b, c *Group) {
			p := externalPSK("known")
			p.PreSharedKey.PSK.PSKNonce = p.PreSharedKey.PSK.PSKNonce[:16]
			stage(t, b, p, a, c)
			stage(t, c, add(dave), a, b)
		}, 4},
		{"remove of a blank leaf", func(t *testing.T, a, b, c *Group) {
			stage(t, b, &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 3}}, a, c)
			stage(t, c, add(dave), a, b)
		}, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b, c := threeMember(t)
			for _, g := range []*Group{a, b, c} {
				g.client.PSK = psk
			}
			tt.stage(t, a, b, c)
			a2, msg, _, err := a.Commit(nil)
			if err != nil {
				t.Fatalf("Commit: %v", err)
			}
			if a2.Reinit() != nil {
				t.Error("the commit carried the reinit")
			}
			if got := members(a2.Tree); got != tt.want {
				t.Errorf("members = %d, want %d", got, tt.want)
			}
			if _, err := b.Handle(send(t, msg)); err != nil {
				t.Errorf("a member rejects the commit: %v", err)
			}
		})
	}
}

// A key package that could never be committed is not staged.
func TestAddProposalBadKeyPackage(t *testing.T) {
	a, b, _ := threeMember(t)
	kp := *newTestClient(t, a.CipherSuite, "dave").KeyPackage
	kp.Signature = bytes.Clone(kp.Signature)
	kp.Signature[0] ^= 1
	stageRaw(t, b, b, &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: kp}})
	for _, c := range b.proposals {
		if err := a.AddProposal(c); err == nil {
			t.Error("AddProposal accepted a key package with a bad signature")
		}
	}
	if n := len(a.proposals); n != 0 {
		t.Errorf("%d proposals staged, want 0", n)
	}
}
