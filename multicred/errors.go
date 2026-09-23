package multicred

import "errors"

// ErrNoSignatureKey is reported when a binding is signed or verified
// without the signature key of the leaf node it binds.
var ErrNoSignatureKey = errors.New("multicred: no leaf node signature key")

// ErrNoBindings is reported for a multi-credential that presents no
// credentials at all.
var ErrNoBindings = errors.New("multicred: credential has no bindings")

// ErrNested is reported for a binding whose credential is itself a
// multi-credential.
var ErrNested = errors.New("multicred: binding holds a multi-credential")

// ErrTooManyBindings is reported for a multi-credential with more
// than [MaxBindings] bindings.
var ErrTooManyBindings = errors.New("multicred: too many bindings")

// ErrNoneVerified is reported when a weak multi-credential is
// verified but none of its bindings is one the caller supports.
var ErrNoneVerified = errors.New("multicred: no supported binding to verify")
