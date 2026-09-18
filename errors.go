package mls

import "fmt"

// errUnknown reports a variant tag this package cannot encode or
// decode, such as a credential type outside the registry.
func errUnknown(kind string, v uint64) error {
	return fmt.Errorf("mls: unknown %s %d", kind, v)
}
