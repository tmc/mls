package mls

import (
	"bytes"
	"fmt"
	"slices"
	"time"
)

// Contains reports whether the lifetime covers t.
//
// A sender MUST check the lifetime of a leaf node it puts in a
// message; a receiver is only advised to, since a leaf node can
// expire between being sent and being received. See RFC 9420,
// Section 7.3.
func (l Lifetime) Contains(t time.Time) bool {
	s := uint64(t.Unix())
	return l.NotBefore <= s && s <= l.NotAfter
}

// Validate checks a key package before it is used to add a client to
// a group: its own signature, the leaf node rules of RFC 9420,
// Section 7.3 that do not depend on the group, and that now falls
// within the leaf node's lifetime. A zero now skips the lifetime
// check.
func (p *KeyPackage) Validate(now time.Time) error {
	if p.Version != Version10 {
		return ErrUnsupportedVersion
	}
	if p.LeafNode.Source != LeafNodeSourceKeyPackage {
		return ErrBadLeafNodeSource
	}
	if !now.IsZero() && !p.LeafNode.Lifetime.Contains(now) {
		return ErrExpired
	}
	if bytes.Equal(p.InitKey, p.LeafNode.EncryptionKey) {
		return ErrDuplicateLeafKey
	}
	if err := p.Verify(); err != nil {
		return err
	}
	return validateLeaf(p.CipherSuite, &p.LeafNode, nil, 0)
}

// validateLeaf checks the rules of RFC 9420, Section 7.3 that a leaf
// node satisfies on its own: its signature, and that its capabilities
// cover the credential type and the non-default extensions it uses. The group ID
// is empty for a leaf from a key package, whose signature does not
// cover its position.
func validateLeaf(cs CipherSuite, n *LeafNode, groupID []byte, i LeafIndex) error {
	if err := n.Verify(cs, groupID, i); err != nil {
		return err
	}
	if !slices.Contains(n.Capabilities.Credentials, n.Credential.Type) {
		return ErrUnsupportedCapability
	}
	for _, e := range n.Extensions {
		if !n.Capabilities.supportsExtension(e.Type) {
			return ErrUnsupportedCapability
		}
	}
	return nil
}

// validateLeafInGroup checks a leaf node that is entering the tree at
// leaf i, against the group it is entering: the group's required
// capabilities, the credential types the other members use and
// support, and the uniqueness of its keys. See RFC 9420, Section 7.3.
func (t RatchetTree) validateLeafInGroup(cs CipherSuite, n *LeafNode, i LeafIndex, ctx *GroupContext, source LeafNodeSource) error {
	if n.Source != source {
		return ErrBadLeafNodeSource
	}
	groupID := ctx.GroupID
	if source == LeafNodeSourceKeyPackage {
		groupID = nil
	}
	if err := validateLeaf(cs, n, groupID, i); err != nil {
		return err
	}
	var required RequiredCapabilities
	if ok, err := ctx.Extensions.Decode(ExtensionTypeRequiredCapabilities, &required); err != nil {
		return err
	} else if ok && !required.Supported(&n.Capabilities) {
		return ErrUnsupportedCapability
	}
	for j := LeafIndex(0); j < t.Size(); j++ {
		other := t.Leaf(j)
		if other == nil || j == i {
			continue
		}
		if bytes.Equal(other.EncryptionKey, n.EncryptionKey) || bytes.Equal(other.SignatureKey, n.SignatureKey) {
			return ErrDuplicateLeafKey
		}
		// Each member must support the credential types the
		// others use, in both directions.
		if !slices.Contains(n.Capabilities.Credentials, other.Credential.Type) {
			return ErrUnsupportedCapability
		}
		if !slices.Contains(other.Capabilities.Credentials, n.Credential.Type) {
			return ErrUnsupportedCapability
		}
	}
	return nil
}

// validateLeaves checks the leaves of a whole tree, as a client does
// when it joins a group. See RFC 9420, Section 7.3.
func (t RatchetTree) validateLeaves(cs CipherSuite, ctx *GroupContext) error {
	for i, n := range t.Members() {
		if err := t.validateLeafInGroup(cs, n, i, ctx, n.Source); err != nil {
			return err
		}
	}
	return nil
}

// validateProposals checks the list of proposals a regular commit
// covers against the rules of RFC 9420, Section 12.2. committer is
// the leaf of the member that sent the commit. The rules for an
// external commit are different and are checked by
// externalProposalsOK instead.
func (t RatchetTree) validateProposals(ps []proposal, committer LeafIndex, ctx *GroupContext) error {
	l := t.newProposalList(committer, ctx)
	for _, p := range ps {
		if p.Type == ProposalTypeRemove {
			l.removed[LeafIndex(p.Remove.Removed)] = true
		}
	}
	for _, p := range ps {
		if err := l.add(p); err != nil {
			return err
		}
	}
	return nil
}

// A proposalList is the list of proposals one commit covers, built up
// one proposal at a time. Each proposal is checked against the ones
// already in the list before it joins them, which lets a receiver
// check a whole commit and a committer choose, from the proposals it
// was sent, a set it may commit together.
type proposalList struct {
	tree      RatchetTree
	committer LeafIndex
	ctx       *GroupContext
	removed   map[LeafIndex]bool // leaves the commit removes
	touched   map[LeafIndex]bool // leaves an Update or Remove applies to
	keys      map[string]bool    // keys the Adds and Updates bring in
	psks      map[string]bool    // encoded PreSharedKeyIDs
	exts      bool               // the list has a group_context_extensions proposal
	reinit    bool               // the list has a reinit proposal
	n         int
}

func (t RatchetTree) newProposalList(committer LeafIndex, ctx *GroupContext) *proposalList {
	return &proposalList{
		tree:      t,
		committer: committer,
		ctx:       ctx,
		removed:   make(map[LeafIndex]bool),
		touched:   make(map[LeafIndex]bool),
		keys:      make(map[string]bool),
		psks:      make(map[string]bool),
	}
}

// add adds p to the list if the list may cover it alongside the
// proposals already in it. Otherwise it reports why not and leaves the
// list as it was.
func (l *proposalList) add(p proposal) error {
	if err := l.check(p); err != nil {
		return err
	}
	switch p.Type {
	case ProposalTypeUpdate:
		l.touched[p.leaf()] = true
		l.keys[string(p.Update.LeafNode.EncryptionKey)] = true
		l.keys[string(p.Update.LeafNode.SignatureKey)] = true
	case ProposalTypeRemove:
		l.touched[LeafIndex(p.Remove.Removed)] = true
		l.removed[LeafIndex(p.Remove.Removed)] = true
	case ProposalTypeAdd:
		l.keys[string(p.Add.KeyPackage.LeafNode.EncryptionKey)] = true
		l.keys[string(p.Add.KeyPackage.LeafNode.SignatureKey)] = true
	case ProposalTypePreSharedKey:
		b, err := Marshal(&p.PreSharedKey.PSK)
		if err != nil {
			return err
		}
		l.psks[string(b)] = true
	case ProposalTypeGroupContextExtensions:
		l.exts = true
	case ProposalTypeReinit:
		l.reinit = true
	}
	l.n++
	return nil
}

// check reports why the list may not cover p alongside the proposals
// already in it, if it may not.
func (l *proposalList) check(p proposal) error {
	if p.from.Type == SenderTypeExternal && !externalProposalType(p.Type) {
		return fmt.Errorf("%w: %v proposal from an external sender", ErrProposalList, p.Type)
	}
	if l.reinit || (p.Type == ProposalTypeReinit && l.n > 0) {
		return fmt.Errorf("%w: reinit proposal alongside others", ErrProposalList)
	}
	switch p.Type {
	case ProposalTypeUpdate:
		if p.from.Type != SenderTypeMember {
			return fmt.Errorf("%w: update proposal from outside the group", ErrProposalList)
		}
		if p.leaf() == l.committer {
			return fmt.Errorf("%w: update proposal from the committer", ErrProposalList)
		}
		if l.touched[p.leaf()] {
			return fmt.Errorf("%w: two proposals for leaf %d", ErrProposalList, p.leaf())
		}
		// The leaves a commit brings in must not share keys with
		// one another. Each is checked against the rest of the
		// tree when it is applied.
		n := &p.Update.LeafNode
		if l.keys[string(n.EncryptionKey)] || l.keys[string(n.SignatureKey)] {
			return fmt.Errorf("%w: two proposals bring in the same key", ErrProposalList)
		}

	case ProposalTypeRemove:
		i := LeafIndex(p.Remove.Removed)
		if i == l.committer {
			return fmt.Errorf("%w: remove proposal for the committer", ErrProposalList)
		}
		if l.touched[i] {
			return fmt.Errorf("%w: two proposals for leaf %d", ErrProposalList, i)
		}

	case ProposalTypeAdd:
		// Two clients are the same if they present the same
		// signature key, which is the comparison Section 12.2
		// leaves to the application.
		n := &p.Add.KeyPackage.LeafNode
		if l.keys[string(n.EncryptionKey)] || l.keys[string(n.SignatureKey)] {
			return fmt.Errorf("%w: two proposals bring in the same key", ErrProposalList)
		}
		for i, m := range l.tree.Members() {
			if bytes.Equal(m.SignatureKey, n.SignatureKey) && !l.removed[i] {
				return fmt.Errorf("%w: add proposal for a member of the group", ErrProposalList)
			}
		}

	case ProposalTypePreSharedKey:
		id := &p.PreSharedKey.PSK
		if err := checkPSK(id, l.ctx); err != nil {
			return err
		}
		b, err := Marshal(id)
		if err != nil {
			return err
		}
		if l.psks[string(b)] {
			return fmt.Errorf("%w: two proposals for the same pre-shared key", ErrProposalList)
		}

	case ProposalTypeGroupContextExtensions:
		if l.exts {
			return fmt.Errorf("%w: two group_context_extensions proposals", ErrProposalList)
		}
		// Section 11.1: the members already in the group must
		// meet whatever the proposal requires of them, since
		// nothing else will check them again. A member the
		// commit removes is no longer among them (Section
		// 12.1.7).
		var req RequiredCapabilities
		ok, err := p.GroupContextExtensions.Extensions.Decode(ExtensionTypeRequiredCapabilities, &req)
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		for i, n := range l.tree.Members() {
			if !l.removed[i] && !req.Supported(&n.Capabilities) {
				return fmt.Errorf("%w: leaf %d does not meet the required capabilities", ErrProposalList, i)
			}
		}

	case ProposalTypeExternalInit:
		return fmt.Errorf("%w: external_init proposal outside an external commit", ErrProposalList)

	case ProposalTypeReinit:
		if p.Reinit.Version < l.ctx.Version {
			// Section 12.1.5: a reinitialization must not
			// move the group backwards.
			return fmt.Errorf("%w: reinit proposal to an older version", ErrProposalList)
		}
	}
	return nil
}

// checkPSK checks a pre-shared key proposal on its own. The nonce
// must be as long as the output of the group's hash (Section
// 12.1.4), and a resumption key for a reinitialization or a branch
// belongs in the initial commit of the new group and nowhere else
// (Sections 11.2 and 11.3).
func checkPSK(id *PreSharedKeyID, ctx *GroupContext) error {
	if len(id.PSKNonce) != ctx.CipherSuite.HashSize() {
		return fmt.Errorf("%w: psk_nonce of %d bytes", ErrProposalList, len(id.PSKNonce))
	}
	if id.Type == PSKTypeResumption && ctx.Epoch != 0 {
		switch id.Usage {
		case ResumptionPSKUsageReinit, ResumptionPSKUsageBranch:
			return fmt.Errorf("%w: resumption psk with usage %v", ErrProposalList, id.Usage)
		}
	}
	return nil
}
