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

// errMissingGroupContext is reported when signing or verifying
// content whose sender type requires the group context, without one.
var errMissingGroupContext = errors.New("mls: group context required for this sender type")

// errPSKCount is reported when the pre-shared key identifiers and the
// key material given for them do not correspond.
var errPSKCount = errors.New("mls: pre-shared key count does not match identifier count")

// errNotCommit is reported when a transcript hash is computed over
// content that is not a commit.
var errNotCommit = errors.New("mls: content is not a commit")

// errConsumed is reported for a secret that the deletion schedule of
// RFC 9420, Section 9.2 has already discarded.
var errConsumed = errors.New("mls: secret has already been consumed")

// errLeafRange is reported for a leaf index outside the group.
var errLeafRange = errors.New("mls: leaf index out of range")

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
