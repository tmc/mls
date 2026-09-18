package mls

import (
	"errors"
	"fmt"
)

// ErrUnknownVariant reports a variant tag outside the ranges this
// package implements: a credential type, proposal type, wire format,
// or similar value from an extension or a future version. Callers
// distinguish it from a malformed encoding, which decoders report as
// [tlssyntax.ErrMalformed], with [errors.Is].
var ErrUnknownVariant = errors.New("mls: unknown variant")

// errUnknown reports a variant tag this package cannot encode or
// decode, such as a credential type outside the registry.
func errUnknown(kind string, v uint64) error {
	return fmt.Errorf("%w: %s %d", ErrUnknownVariant, kind, v)
}

// ErrMissingGroupContext is reported when signing or verifying
// content whose sender type requires the group context, without one.
var ErrMissingGroupContext = errors.New("mls: group context required for this sender type")

// ErrPSKCount is reported when the pre-shared key identifiers and the
// key material given for them do not correspond.
var ErrPSKCount = errors.New("mls: pre-shared key count does not match identifier count")

// ErrNotCommit is reported when a transcript hash is computed over
// content that is not a commit.
var ErrNotCommit = errors.New("mls: content is not a commit")

// ErrConsumed is reported for a secret that the deletion schedule of
// RFC 9420, Section 9.2 has already discarded.
var ErrConsumed = errors.New("mls: secret has already been consumed")

// ErrLeafRange is reported for a leaf index outside the group.
var ErrLeafRange = errors.New("mls: leaf index out of range")

// ErrApplicationNotEncrypted is reported when application data is
// framed as a PublicMessage. RFC 9420, Section 6.2 requires that
// application messages always be encrypted.
var ErrApplicationNotEncrypted = errors.New("mls: application data must be sent as a PrivateMessage")

// ErrBadMembershipTag is reported when the membership tag of a
// PublicMessage does not verify.
var ErrBadMembershipTag = errors.New("mls: membership tag does not verify")

// ErrNotMember is reported when content that only a member may send
// has some other sender type.
var ErrNotMember = errors.New("mls: sender is not a group member")

// ErrBadPadding is reported when the padding of a PrivateMessage is
// not all zero.
var ErrBadPadding = errors.New("mls: padding is not zero")

// errBlankParent is reported when a parent hash is computed for a
// node that holds no parent.
var errBlankParent = errors.New("mls: node is blank or is not a parent")

// ErrBadParentHash is reported when a parent node in a ratchet tree
// cannot be chained back to a leaf by parent hashes, which means it
// was not introduced by a member of the group.
var ErrBadParentHash = errors.New("mls: parent node is not parent-hash valid")

// ErrNotInWelcome is reported when a welcome message carries no
// secrets for the key package it was offered to.
var ErrNotInWelcome = errors.New("mls: welcome message has no secrets for this key package")

// ErrBadTreeKEM is reported for an update path that does not match
// the ratchet tree it is applied to: a wrong number of nodes, or a
// public key that does not match the path secret encrypted under it.
var ErrBadTreeKEM = errors.New("mls: malformed update path")

// ErrNotInPath is reported when an update path carries no path
// secret that the member can decrypt.
var ErrNotInPath = errors.New("mls: no path secret for this member")

// ErrNoRatchetTree is reported when a welcome message carries no
// ratchet_tree extension and the caller supplied no tree.
var ErrNoRatchetTree = errors.New("mls: no ratchet tree")

// ErrBadTreeHash is reported for a ratchet tree that does not match
// the tree hash in the group context that summarizes it.
var ErrBadTreeHash = errors.New("mls: tree hash does not match")

// ErrBadConfirmationTag is reported for a commit or group info whose
// confirmation tag does not match the key schedule.
var ErrBadConfirmationTag = errors.New("mls: confirmation tag does not verify")

// ErrUnknownPSK is reported for a pre-shared key the client cannot
// supply.
var ErrUnknownPSK = errors.New("mls: unknown pre-shared key")

// ErrUnknownProposal is reported for a proposal that a commit refers
// to but that the member never received.
var ErrUnknownProposal = errors.New("mls: unknown proposal")

// ErrRemoved is reported when a commit removes the member applying it.
var ErrRemoved = errors.New("mls: member was removed from the group")

// ErrNotProposal is reported for content that must be a proposal and
// is not.
var ErrNotProposal = errors.New("mls: content is not a proposal")

// ErrNotForGroup is reported for a message addressed to another group
// or to another epoch of this one.
var ErrNotForGroup = errors.New("mls: message is not for this group and epoch")

// ErrOwnCommit is reported when a member applies a commit it sent
// itself, which it cannot: [Group.Commit] already returned the state
// that commit begins.
var ErrOwnCommit = errors.New("mls: cannot apply one's own commit")

// ErrUnsupportedProposal is reported for a proposal type this package
// does not implement, which is external_init and reinit.
var ErrUnsupportedProposal = errors.New("mls: unsupported proposal type")

// ErrDuplicateExtension is reported for a list of extensions holding
// more than one extension of the same type, which RFC 9420,
// Section 13.4 forbids.
var ErrDuplicateExtension = errors.New("mls: duplicate extension")

