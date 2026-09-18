package mls

import (
	"bytes"
	"slices"
)

// JoinExternal joins a group from a GroupInfo, without being added by
// a member. It returns the member's view of the group in the epoch
// the join begins, and the external commit that carries the join to
// the group: the caller must publish that commit, and must discard
// the group if the group does not accept it.
//
// The ratchet tree comes from the group info if it carries a
// ratchet_tree extension, and otherwise must be supplied in tree. The
// group info must carry an external_pub extension; its signature is
// verified here against the leaf of the member that signed it.
//
// A GroupInfo is specific to an epoch, and the join ends that epoch,
// so each GroupInfo is good for one external join.
// See RFC 9420, Section 12.4.3.2.
func (c *Client) JoinExternal(info *GroupInfo, tree RatchetTree) (*Group, *MLSMessage, error) {
	cs := c.CipherSuite
	if info.GroupContext.CipherSuite != cs {
		return nil, nil, ErrUnsupportedCipherSuite
	}
	var carried RatchetTree
	if ok, err := info.Extensions.Get(ExtensionTypeRatchetTree, &carried); err != nil {
		return nil, nil, err
	} else if ok {
		tree = carried
	}
	if tree == nil {
		return nil, nil, ErrNoRatchetTree
	}
	if err := tree.verify(cs, &info.GroupContext); err != nil {
		return nil, nil, err
	}
	signer := tree.Leaf(LeafIndex(info.Signer))
	if signer == nil {
		return nil, nil, ErrLeafRange
	}
	if err := info.Verify(signer.SignatureKey); err != nil {
		return nil, nil, err
	}
	var pub ExternalPub
	if ok, err := info.Extensions.Get(ExtensionTypeExternalPub, &pub); err != nil {
		return nil, nil, err
	} else if !ok {
		return nil, nil, ErrNoExternalPub
	}
	kemOutput, initSecret, err := cs.ExternalInit(pub.ExternalPub)
	if err != nil {
		return nil, nil, err
	}
	interim, err := cs.InterimTranscriptHash(info.GroupContext.ConfirmedTranscriptHash, info.ConfirmationTag)
	if err != nil {
		return nil, nil, err
	}

	// The joiner's view of the epoch it is joining. It holds no
	// secrets of that epoch and can decrypt nothing in it; it
	// exists to be committed into. The init secret is the one the
	// joiner just sent, which stands in for the one the group
	// derived. See RFC 9420, Section 8.3.
	g := &Group{
		CipherSuite: cs,
		Context:     info.GroupContext,
		Tree:        slices.Clone(tree),
		Schedule:    &KeySchedule{CipherSuite: cs, InitSecret: initSecret},
		client:      c,
		interim:     interim,
		proposals:   make(map[string]*AuthenticatedContent),
		resumption:  make(map[uint64][]byte),
	}

	// The joiner takes the leftmost free leaf, as an Add would give
	// it, and commits a path from there.
	leaf := c.KeyPackage.LeafNode
	g.Index = g.Tree.Add(&leaf)
	g.Secrets = NewTreeSecrets(g.Index, c.EncryptionPriv)

	proposals := []*Proposal{{Type: ProposalTypeExternalInit, ExternalInit: &ExternalInit{KEMOutput: kemOutput}}}
	// A member rejoining after losing its state removes its own
	// prior leaf in the same commit, which RFC 9420, Section
	// 12.4.3.2 calls a resync. The prior leaf is the one holding
	// the same signature key.
	for i := LeafIndex(0); i < tree.Size(); i++ {
		if l := tree.Leaf(i); l != nil && bytes.Equal(l.SignatureKey, leaf.SignatureKey) {
			proposals = append(proposals, &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: uint32(i)}})
		}
	}
	next, commit, _, err := g.commit(proposals, SenderTypeNewMemberCommit)
	if err != nil {
		return nil, nil, err
	}
	return next, commit, nil
}

// externalCommitOK checks the rules a commit from a new member must
// meet: it carries an update path, and the rules on its proposals
// below. See RFC 9420, Section 12.4.3.2.
func externalCommitOK(commit *Commit) error {
	if commit.Path == nil {
		return ErrBadExternalCommit
	}
	return externalProposalsOK(commit)
}

// externalProposalsOK checks the proposals of a commit from a new
// member: exactly one ExternalInit, nothing by reference, and nothing
// but Remove and PreSharedKey besides.
// externalProposalType reports whether a party outside the group may
// send a proposal of this type. See RFC 9420, Section 12.1.8.
func externalProposalType(t ProposalType) bool {
	switch t {
	case ProposalTypeAdd, ProposalTypeRemove, ProposalTypePreSharedKey,
		ProposalTypeReInit, ProposalTypeGroupContextExtensions:
		return true
	}
	return false
}

func externalProposalsOK(commit *Commit) error {
	n := 0
	for _, p := range commit.Proposals {
		// A new member cannot judge the proposals a group has
		// sent, so it may not commit any of them by reference.
		if p.Type != ProposalOrRefTypeProposal {
			return ErrBadExternalCommit
		}
		switch p.Proposal.Type {
		case ProposalTypeExternalInit:
			n++
		case ProposalTypeRemove, ProposalTypePreSharedKey:
		default:
			return ErrBadExternalCommit
		}
	}
	if n != 1 {
		return ErrBadExternalCommit
	}
	return nil
}

// GroupInfo returns a signed description of the group's current
// epoch, carrying the ratchet tree and the external_pub extension so
// that a client can join by external commit with [Client.JoinExternal].
//
// A GroupInfo is not public information: it names every member of the
// group. An application publishes it only to clients it is willing to
// let join. Each one is good for a single external join, since the
// join ends the epoch it describes.
// See RFC 9420, Section 12.4.3.2.
func (g *Group) GroupInfo() (*MLSMessage, error) {
	cs := g.CipherSuite
	tag, err := cs.ConfirmationTag(g.Schedule.ConfirmationKey, g.Context.ConfirmedTranscriptHash)
	if err != nil {
		return nil, err
	}
	pub, err := g.Schedule.ExternalPub()
	if err != nil {
		return nil, err
	}
	info := &GroupInfo{
		GroupContext:    g.Context,
		ConfirmationTag: tag,
		Signer:          uint32(g.Index),
	}
	if err := info.Extensions.Set(ExtensionTypeRatchetTree, &g.Tree); err != nil {
		return nil, err
	}
	if err := info.Extensions.Set(ExtensionTypeExternalPub, &ExternalPub{ExternalPub: pub}); err != nil {
		return nil, err
	}
	if err := info.Sign(g.client.SignaturePriv); err != nil {
		return nil, err
	}
	return &MLSMessage{Version: g.Context.Version, WireFormat: WireFormatGroupInfo, GroupInfo: info}, nil
}
