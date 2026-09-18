package mls

import "github.com/tmc/mls/tlssyntax"

// A GroupContext summarizes the state of a group at one epoch. It is
// mixed into the key schedule and signed over, so members that
// disagree about it cannot talk to each other.
// See RFC 9420, Section 8.1.
type GroupContext struct {
	Version                 ProtocolVersion
	CipherSuite             CipherSuite
	GroupID                 []byte
	Epoch                   uint64
	TreeHash                []byte
	ConfirmedTranscriptHash []byte
	Extensions              Extensions
}

func (c *GroupContext) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint16(uint16(c.Version))
	w.WriteUint16(uint16(c.CipherSuite))
	w.WriteOpaque(c.GroupID)
	w.WriteUint64(c.Epoch)
	w.WriteOpaque(c.TreeHash)
	w.WriteOpaque(c.ConfirmedTranscriptHash)
	c.Extensions.MarshalTLS(w)
}

func (c *GroupContext) UnmarshalTLS(r *tlssyntax.Reader) {
	*c = GroupContext{}
	c.Version = ProtocolVersion(r.ReadUint16())
	c.CipherSuite = CipherSuite(r.ReadUint16())
	c.GroupID = r.ReadOpaque()
	c.Epoch = r.ReadUint64()
	c.TreeHash = r.ReadOpaque()
	c.ConfirmedTranscriptHash = r.ReadOpaque()
	c.Extensions.UnmarshalTLS(r)
}
