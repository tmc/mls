package mls

import "github.com/tmc/mls/tlssyntax"

// An Add proposal requests that the client offering key_package be
// added to the group. See RFC 9420, Section 12.1.1.
type Add struct {
	KeyPackage KeyPackage
}

func (a *Add) MarshalTLS(w *tlssyntax.Writer)   { a.KeyPackage.MarshalTLS(w) }
func (a *Add) UnmarshalTLS(r *tlssyntax.Reader) { a.KeyPackage.UnmarshalTLS(r) }

// An Update proposal replaces the sender's leaf node with a fresh one.
// See RFC 9420, Section 12.1.2.
type Update struct {
	LeafNode LeafNode
}

func (u *Update) MarshalTLS(w *tlssyntax.Writer)   { u.LeafNode.MarshalTLS(w) }
func (u *Update) UnmarshalTLS(r *tlssyntax.Reader) { u.LeafNode.UnmarshalTLS(r) }

// A Remove proposal requests that the member at the given leaf index
// be removed from the group. See RFC 9420, Section 12.1.3.
type Remove struct {
	Removed uint32
}

func (rm *Remove) MarshalTLS(w *tlssyntax.Writer)   { w.WriteUint32(rm.Removed) }
func (rm *Remove) UnmarshalTLS(r *tlssyntax.Reader) { rm.Removed = r.ReadUint32() }

// A GroupContextExtensions proposal replaces the extensions in the
// group's [GroupContext]. See RFC 9420, Section 12.1.7.
type GroupContextExtensions struct {
	Extensions Extensions
}

func (g *GroupContextExtensions) MarshalTLS(w *tlssyntax.Writer)   { g.Extensions.MarshalTLS(w) }
func (g *GroupContextExtensions) UnmarshalTLS(r *tlssyntax.Reader) { g.Extensions.UnmarshalTLS(r) }
