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

// A PSKType identifies where a [PreSharedKeyID] comes from.
type PSKType uint8

// PSK types. See RFC 9420, Section 8.4.
const (
	PSKTypeExternal   PSKType = 1
	PSKTypeResumption PSKType = 2
)

// String returns the name of the pre-shared key type.
func (t PSKType) String() string {
	return enumString("PSKType", uint64(t), []string{"reserved", "external", "resumption"})
}

// A ResumptionPSKUsage says why a resumption PSK is being used.
type ResumptionPSKUsage uint8

// Resumption PSK usages. See RFC 9420, Section 8.4.
const (
	ResumptionPSKUsageApplication ResumptionPSKUsage = 1
	ResumptionPSKUsageReinit      ResumptionPSKUsage = 2
	ResumptionPSKUsageBranch      ResumptionPSKUsage = 3
)

// String returns the name of the resumption key usage.
func (u ResumptionPSKUsage) String() string {
	return enumString("ResumptionPSKUsage", uint64(u), []string{"reserved", "application", "reinit", "branch"})
}

// A PreSharedKeyID names a pre-shared key to mix into the key
// schedule. Type decides whether it names an external key or an epoch
// of some group to resume from. The nonce makes each injection of the
// same key distinct. See RFC 9420, Section 8.4.
type PreSharedKeyID struct {
	Type PSKType

	PSKID []byte // Type == PSKTypeExternal

	Usage      ResumptionPSKUsage // Type == PSKTypeResumption
	PSKGroupID []byte             // Type == PSKTypeResumption
	PSKEpoch   uint64             // Type == PSKTypeResumption

	PSKNonce []byte
}

func (p *PreSharedKeyID) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint8(uint8(p.Type))
	switch p.Type {
	case PSKTypeExternal:
		w.WriteOpaque(p.PSKID)
	case PSKTypeResumption:
		w.WriteUint8(uint8(p.Usage))
		w.WriteOpaque(p.PSKGroupID)
		w.WriteUint64(p.PSKEpoch)
	default:
		w.SetError(errUnknown("psk type", uint64(p.Type)))
		return
	}
	w.WriteOpaque(p.PSKNonce)
}

func (p *PreSharedKeyID) UnmarshalTLS(r *tlssyntax.Reader) {
	*p = PreSharedKeyID{Type: PSKType(r.ReadUint8())}
	switch p.Type {
	case PSKTypeExternal:
		p.PSKID = r.ReadOpaque()
	case PSKTypeResumption:
		p.Usage = ResumptionPSKUsage(r.ReadUint8())
		p.PSKGroupID = r.ReadOpaque()
		p.PSKEpoch = r.ReadUint64()
	default:
		r.SetError(errUnknown("psk type", uint64(p.Type)))
		return
	}
	p.PSKNonce = r.ReadOpaque()
}

// A PreSharedKey proposal injects a pre-shared key into the key
// schedule at the next epoch. See RFC 9420, Section 12.1.4.
type PreSharedKey struct {
	PSK PreSharedKeyID
}

func (p *PreSharedKey) MarshalTLS(w *tlssyntax.Writer)   { p.PSK.MarshalTLS(w) }
func (p *PreSharedKey) UnmarshalTLS(r *tlssyntax.Reader) { p.PSK.UnmarshalTLS(r) }

// A Reinit proposal asks that the group be torn down and recreated
// with different parameters. See RFC 9420, Section 12.1.5.
type Reinit struct {
	GroupID     []byte
	Version     ProtocolVersion
	CipherSuite CipherSuite
	Extensions  Extensions
}

func (ri *Reinit) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteOpaque(ri.GroupID)
	w.WriteUint16(uint16(ri.Version))
	w.WriteUint16(uint16(ri.CipherSuite))
	ri.Extensions.MarshalTLS(w)
}

func (ri *Reinit) UnmarshalTLS(r *tlssyntax.Reader) {
	*ri = Reinit{}
	ri.GroupID = r.ReadOpaque()
	ri.Version = ProtocolVersion(r.ReadUint16())
	ri.CipherSuite = CipherSuite(r.ReadUint16())
	ri.Extensions.UnmarshalTLS(r)
}

// An ExternalInit proposal carries the KEM output a new member used
// to join by external commit. See RFC 9420, Section 12.1.6.
type ExternalInit struct {
	KEMOutput []byte
}

func (e *ExternalInit) MarshalTLS(w *tlssyntax.Writer)   { w.WriteOpaque(e.KEMOutput) }
func (e *ExternalInit) UnmarshalTLS(r *tlssyntax.Reader) { e.KEMOutput = r.ReadOpaque() }

// A GroupContextExtensions proposal replaces the extensions in the
// group's [GroupContext]. See RFC 9420, Section 12.1.7.
type GroupContextExtensions struct {
	Extensions Extensions
}

func (g *GroupContextExtensions) MarshalTLS(w *tlssyntax.Writer)   { g.Extensions.MarshalTLS(w) }
func (g *GroupContextExtensions) UnmarshalTLS(r *tlssyntax.Reader) { g.Extensions.UnmarshalTLS(r) }

// A Proposal is one requested change to a group. Type decides which
// of the remaining fields is present. See RFC 9420, Section 12.1.
type Proposal struct {
	Type ProposalType

	Add                    *Add
	Update                 *Update
	Remove                 *Remove
	PreSharedKey           *PreSharedKey
	Reinit                 *Reinit
	ExternalInit           *ExternalInit
	GroupContextExtensions *GroupContextExtensions
}

// body returns the proposal's variant body, or nil if Type and the
// populated field disagree.
func (p *Proposal) body() interface {
	tlssyntax.Marshaler
	tlssyntax.Unmarshaler
} {
	switch p.Type {
	case ProposalTypeAdd:
		if p.Add != nil {
			return p.Add
		}
	case ProposalTypeUpdate:
		if p.Update != nil {
			return p.Update
		}
	case ProposalTypeRemove:
		if p.Remove != nil {
			return p.Remove
		}
	case ProposalTypePreSharedKey:
		if p.PreSharedKey != nil {
			return p.PreSharedKey
		}
	case ProposalTypeReinit:
		if p.Reinit != nil {
			return p.Reinit
		}
	case ProposalTypeExternalInit:
		if p.ExternalInit != nil {
			return p.ExternalInit
		}
	case ProposalTypeGroupContextExtensions:
		if p.GroupContextExtensions != nil {
			return p.GroupContextExtensions
		}
	}
	return nil
}

func (p *Proposal) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint16(uint16(p.Type))
	b := p.body()
	if b == nil {
		w.SetError(errUnknown("proposal type", uint64(p.Type)))
		return
	}
	b.MarshalTLS(w)
}

func (p *Proposal) UnmarshalTLS(r *tlssyntax.Reader) {
	*p = Proposal{Type: ProposalType(r.ReadUint16())}
	switch p.Type {
	case ProposalTypeAdd:
		p.Add = new(Add)
	case ProposalTypeUpdate:
		p.Update = new(Update)
	case ProposalTypeRemove:
		p.Remove = new(Remove)
	case ProposalTypePreSharedKey:
		p.PreSharedKey = new(PreSharedKey)
	case ProposalTypeReinit:
		p.Reinit = new(Reinit)
	case ProposalTypeExternalInit:
		p.ExternalInit = new(ExternalInit)
	case ProposalTypeGroupContextExtensions:
		p.GroupContextExtensions = new(GroupContextExtensions)
	default:
		r.SetError(errUnknown("proposal type", uint64(p.Type)))
		return
	}
	p.body().UnmarshalTLS(r)
}

// A ProposalOrRefType says whether a commit carries a proposal inline
// or by reference. See RFC 9420, Section 12.4.
type ProposalOrRefType uint8

// Proposal-or-reference types.
const (
	ProposalOrRefTypeProposal  ProposalOrRefType = 1
	ProposalOrRefTypeReference ProposalOrRefType = 2
)

// String reports whether the proposal is carried inline or by
// reference.
func (t ProposalOrRefType) String() string {
	return enumString("ProposalOrRefType", uint64(t), []string{"reserved", "proposal", "reference"})
}

// A ProposalOrRef is one entry in a [Commit]: either a proposal
// carried inline, or a reference to one sent earlier in the epoch.
// See RFC 9420, Section 12.4.
type ProposalOrRef struct {
	Type ProposalOrRefType

	Proposal  *Proposal     // Type == ProposalOrRefTypeProposal
	Reference HashReference // Type == ProposalOrRefTypeReference
}

func (p *ProposalOrRef) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint8(uint8(p.Type))
	switch {
	case p.Type == ProposalOrRefTypeProposal && p.Proposal != nil:
		p.Proposal.MarshalTLS(w)
	case p.Type == ProposalOrRefTypeReference:
		w.WriteOpaque(p.Reference)
	default:
		w.SetError(errUnknown("proposal-or-ref type", uint64(p.Type)))
	}
}

func (p *ProposalOrRef) UnmarshalTLS(r *tlssyntax.Reader) {
	*p = ProposalOrRef{Type: ProposalOrRefType(r.ReadUint8())}
	switch p.Type {
	case ProposalOrRefTypeProposal:
		p.Proposal = new(Proposal)
		p.Proposal.UnmarshalTLS(r)
	case ProposalOrRefTypeReference:
		p.Reference = r.ReadOpaque()
	default:
		r.SetError(errUnknown("proposal-or-ref type", uint64(p.Type)))
	}
}
