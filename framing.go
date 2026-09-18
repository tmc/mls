package mls

import "github.com/tmc/mls/tlssyntax"

// A Sender identifies who sent a [FramedContent]. SenderType decides
// whether a leaf index is present. See RFC 9420, Section 6.
type Sender struct {
	Type SenderType

	LeafIndex   uint32 // Type == SenderTypeMember
	SenderIndex uint32 // Type == SenderTypeExternal
}

func (s *Sender) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint8(uint8(s.Type))
	switch s.Type {
	case SenderTypeMember:
		w.WriteUint32(s.LeafIndex)
	case SenderTypeExternal:
		w.WriteUint32(s.SenderIndex)
	case SenderTypeNewMemberProposal, SenderTypeNewMemberCommit:
		// no fields
	default:
		w.SetError(errUnknown("sender type", uint64(s.Type)))
	}
}

func (s *Sender) UnmarshalTLS(r *tlssyntax.Reader) {
	*s = Sender{Type: SenderType(r.ReadUint8())}
	switch s.Type {
	case SenderTypeMember:
		s.LeafIndex = r.ReadUint32()
	case SenderTypeExternal:
		s.SenderIndex = r.ReadUint32()
	case SenderTypeNewMemberProposal, SenderTypeNewMemberCommit:
		// no fields
	default:
		if r.Err() == nil {
			r.SetError(errUnknown("sender type", uint64(s.Type)))
		}
	}
}

// FramedContent is the content of a message together with the group
// and sender it belongs to. ContentType decides which of
// ApplicationData, Proposal, and Commit is present.
// See RFC 9420, Section 6.
type FramedContent struct {
	GroupID           []byte
	Epoch             uint64
	Sender            Sender
	AuthenticatedData []byte

	ContentType     ContentType
	ApplicationData []byte    // ContentType == ContentTypeApplication
	Proposal        *Proposal // ContentType == ContentTypeProposal
	Commit          *Commit   // ContentType == ContentTypeCommit
}

func (c *FramedContent) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteOpaque(c.GroupID)
	w.WriteUint64(c.Epoch)
	c.Sender.MarshalTLS(w)
	w.WriteOpaque(c.AuthenticatedData)
	w.WriteUint8(uint8(c.ContentType))
	c.marshalBody(w)
}

// marshalBody writes just the content_type variant, which
// PrivateMessageContent encodes without the surrounding fields.
func (c *FramedContent) marshalBody(w *tlssyntax.Writer) {
	switch {
	case c.ContentType == ContentTypeApplication:
		w.WriteOpaque(c.ApplicationData)
	case c.ContentType == ContentTypeProposal && c.Proposal != nil:
		c.Proposal.MarshalTLS(w)
	case c.ContentType == ContentTypeCommit && c.Commit != nil:
		c.Commit.MarshalTLS(w)
	default:
		w.SetError(errUnknown("content type", uint64(c.ContentType)))
	}
}

func (c *FramedContent) UnmarshalTLS(r *tlssyntax.Reader) {
	*c = FramedContent{}
	c.GroupID = r.ReadOpaque()
	c.Epoch = r.ReadUint64()
	c.Sender.UnmarshalTLS(r)
	c.AuthenticatedData = r.ReadOpaque()
	c.ContentType = ContentType(r.ReadUint8())
	c.unmarshalBody(r)
}

func (c *FramedContent) unmarshalBody(r *tlssyntax.Reader) {
	switch c.ContentType {
	case ContentTypeApplication:
		c.ApplicationData = r.ReadOpaque()
	case ContentTypeProposal:
		c.Proposal = new(Proposal)
		c.Proposal.UnmarshalTLS(r)
	case ContentTypeCommit:
		c.Commit = new(Commit)
		c.Commit.UnmarshalTLS(r)
	default:
		if r.Err() == nil {
			r.SetError(errUnknown("content type", uint64(c.ContentType)))
		}
	}
}

// FramedContentAuthData carries the signature over a [FramedContent],
// and for a commit the confirmation tag as well. The ContentType it
// was decoded under decides whether ConfirmationTag is present; keep
// it in sync with the content this authenticates.
// See RFC 9420, Section 6.1.
type FramedContentAuthData struct {
	ContentType ContentType // not encoded; selects the variant

	Signature       []byte
	ConfirmationTag []byte // ContentType == ContentTypeCommit
}

func (a *FramedContentAuthData) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteOpaque(a.Signature)
	switch a.ContentType {
	case ContentTypeCommit:
		w.WriteOpaque(a.ConfirmationTag)
	case ContentTypeApplication, ContentTypeProposal:
		// no fields
	default:
		w.SetError(errUnknown("content type", uint64(a.ContentType)))
	}
}

func (a *FramedContentAuthData) UnmarshalTLS(r *tlssyntax.Reader) {
	ct := a.ContentType
	*a = FramedContentAuthData{ContentType: ct}
	a.Signature = r.ReadOpaque()
	switch ct {
	case ContentTypeCommit:
		a.ConfirmationTag = r.ReadOpaque()
	case ContentTypeApplication, ContentTypeProposal:
		// no fields
	default:
		if r.Err() == nil {
			r.SetError(errUnknown("content type", uint64(ct)))
		}
	}
}

// A PublicMessage carries content that is authenticated but not
// encrypted. A message from a member also carries a membership tag.
// See RFC 9420, Section 6.2.
type PublicMessage struct {
	Content       FramedContent
	Auth          FramedContentAuthData
	MembershipTag []byte // Content.Sender.Type == SenderTypeMember
}

func (m *PublicMessage) MarshalTLS(w *tlssyntax.Writer) {
	m.Content.MarshalTLS(w)
	m.Auth.ContentType = m.Content.ContentType
	m.Auth.MarshalTLS(w)
	if m.Content.Sender.Type == SenderTypeMember {
		w.WriteOpaque(m.MembershipTag)
	}
}

func (m *PublicMessage) UnmarshalTLS(r *tlssyntax.Reader) {
	*m = PublicMessage{}
	m.Content.UnmarshalTLS(r)
	m.Auth.ContentType = m.Content.ContentType
	m.Auth.UnmarshalTLS(r)
	if m.Content.Sender.Type == SenderTypeMember {
		m.MembershipTag = r.ReadOpaque()
	}
}

// A PrivateMessage carries encrypted content. Its group, epoch, and
// content type stay in the clear so that a delivery service can route
// it without being able to read it.
// See RFC 9420, Section 6.3.
type PrivateMessage struct {
	GroupID             []byte
	Epoch               uint64
	ContentType         ContentType
	AuthenticatedData   []byte
	EncryptedSenderData []byte
	Ciphertext          []byte
}

func (m *PrivateMessage) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteOpaque(m.GroupID)
	w.WriteUint64(m.Epoch)
	w.WriteUint8(uint8(m.ContentType))
	w.WriteOpaque(m.AuthenticatedData)
	w.WriteOpaque(m.EncryptedSenderData)
	w.WriteOpaque(m.Ciphertext)
}

func (m *PrivateMessage) UnmarshalTLS(r *tlssyntax.Reader) {
	*m = PrivateMessage{}
	m.GroupID = r.ReadOpaque()
	m.Epoch = r.ReadUint64()
	m.ContentType = ContentType(r.ReadUint8())
	m.AuthenticatedData = r.ReadOpaque()
	m.EncryptedSenderData = r.ReadOpaque()
	m.Ciphertext = r.ReadOpaque()
}

// SenderData names the key a [PrivateMessage] was encrypted under. It
// travels encrypted in PrivateMessage.EncryptedSenderData.
// See RFC 9420, Section 6.3.2.
type SenderData struct {
	LeafIndex  uint32
	Generation uint32
	ReuseGuard [4]byte
}

func (d *SenderData) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint32(d.LeafIndex)
	w.WriteUint32(d.Generation)
	w.WriteRaw(d.ReuseGuard[:])
}

func (d *SenderData) UnmarshalTLS(r *tlssyntax.Reader) {
	*d = SenderData{}
	d.LeafIndex = r.ReadUint32()
	d.Generation = r.ReadUint32()
	copy(d.ReuseGuard[:], r.ReadRaw(4))
}
