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
