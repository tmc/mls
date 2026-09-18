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
// cover the extensions and the credential type it uses. The group ID
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
		if !slices.Contains(n.Capabilities.Extensions, e.Type) {
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
	if ok, err := ctx.Extensions.Get(ExtensionTypeRequiredCapabilities, &required); err != nil {
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
	for i := LeafIndex(0); i < t.Size(); i++ {
		n := t.Leaf(i)
		if n == nil {
			continue
		}
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
	var (
		touched = make(map[LeafIndex]bool) // leaves an Update or Remove applies to
		added   = make(map[string]bool)    // signature keys the Adds introduce
		removed = make(map[LeafIndex]bool)
		psks    = make(map[string]bool)
		exts    int
	)
	for _, p := range ps {
		if p.Type == ProposalTypeRemove {
			removed[LeafIndex(p.Remove.Removed)] = true
		}
	}
	for _, p := range ps {
		switch p.Type {
		case ProposalTypeUpdate:
			if p.from.Type != SenderTypeMember {
				return fmt.Errorf("%w: update proposal from outside the group", ErrProposalList)
			}
			if p.leaf() == committer {
				return fmt.Errorf("%w: update proposal from the committer", ErrProposalList)
			}
			if touched[p.leaf()] {
				return fmt.Errorf("%w: two proposals for leaf %d", ErrProposalList, p.leaf())
			}
			touched[p.leaf()] = true

		case ProposalTypeRemove:
			i := LeafIndex(p.Remove.Removed)
			if i == committer {
				return fmt.Errorf("%w: remove proposal for the committer", ErrProposalList)
			}
			if touched[i] {
				return fmt.Errorf("%w: two proposals for leaf %d", ErrProposalList, i)
			}
			touched[i] = true

		case ProposalTypeAdd:
			// Two clients are the same if they present the
			// same signature key, which is the comparison
			// Section 12.2 leaves to the application.
			key := string(p.Add.KeyPackage.LeafNode.SignatureKey)
			if added[key] {
				return fmt.Errorf("%w: two add proposals for the same client", ErrProposalList)
			}
			added[key] = true
			for i := LeafIndex(0); i < t.Size(); i++ {
				n := t.Leaf(i)
				if n != nil && string(n.SignatureKey) == key && !removed[i] {
					return fmt.Errorf("%w: add proposal for a member of the group", ErrProposalList)
				}
			}

		case ProposalTypePreSharedKey:
			id := p.PreSharedKey.PSK
			if id.Type == PSKTypeResumption {
				switch id.Usage {
				case ResumptionPSKUsageReInit, ResumptionPSKUsageBranch:
					// Sections 11.2 and 11.3: these
					// belong in the initial commit of
					// the new group and nowhere else.
					return fmt.Errorf("%w: resumption psk with usage %v", ErrProposalList, id.Usage)
				}
			}
			b, err := Marshal(&id)
			if err != nil {
				return err
			}
			if psks[string(b)] {
				return fmt.Errorf("%w: two proposals for the same pre-shared key", ErrProposalList)
			}
			psks[string(b)] = true

		case ProposalTypeGroupContextExtensions:
			exts++
			if exts > 1 {
				return fmt.Errorf("%w: two group_context_extensions proposals", ErrProposalList)
			}
			// Section 11.1: the members already in the group
			// must meet whatever the proposal requires of
			// them, since nothing else will check them again.
			var req RequiredCapabilities
			ok, err := p.GroupContextExtensions.Extensions.Get(ExtensionTypeRequiredCapabilities, &req)
			if err != nil {
				return err
			}
			if !ok {
				break
			}
			for i := LeafIndex(0); i < t.Size(); i++ {
				n := t.Leaf(i)
				if n == nil {
					continue
				}
				if !req.Supported(&n.Capabilities) {
					return fmt.Errorf("%w: leaf %d does not meet the required capabilities", ErrProposalList, i)
				}
			}

		case ProposalTypeExternalInit:
			return fmt.Errorf("%w: external_init proposal outside an external commit", ErrProposalList)

		case ProposalTypeReInit:
			if len(ps) > 1 {
				return fmt.Errorf("%w: reinit proposal alongside others", ErrProposalList)
			}
			if p.ReInit.Version < ctx.Version {
				// Section 12.1.5: a reinitialization
				// must not move the group backwards.
				return fmt.Errorf("%w: reinit proposal to an older version", ErrProposalList)
			}
		}
		if p.from.Type == SenderTypeExternal && !externalProposalType(p.Type) {
			return fmt.Errorf("%w: %v proposal from an external sender", ErrProposalList, p.Type)
		}
	}
	return nil
}
