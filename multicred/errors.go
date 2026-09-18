package multicred

import "errors"

// ErrNoSignatureKey is reported when a binding is signed or verified
// without the signature key of the leaf node it binds.
var ErrNoSignatureKey = errors.New("multicred: no leaf node signature key")

// ErrNoBindings is reported for a multi-credential that presents no
// credentials at all.
var ErrNoBindings = errors.New("multicred: credential has no bindings")
