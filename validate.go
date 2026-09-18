package mls

import (
	"bytes"
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
