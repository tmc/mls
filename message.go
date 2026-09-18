package mls

import "github.com/tmc/mls/tlssyntax"

// An MLSMessage is the outermost structure of the protocol: everything
// sent between clients and the delivery service is one of these.
// WireFormat decides which of the remaining fields is present.
// See RFC 9420, Section 6.
type MLSMessage struct {
	Version    ProtocolVersion
	WireFormat WireFormat

	PublicMessage  *PublicMessage  // WireFormat == WireFormatPublicMessage
	PrivateMessage *PrivateMessage // WireFormat == WireFormatPrivateMessage
	Welcome        *Welcome        // WireFormat == WireFormatWelcome
	GroupInfo      *GroupInfo      // WireFormat == WireFormatGroupInfo
	KeyPackage     *KeyPackage     // WireFormat == WireFormatKeyPackage
}

func (m *MLSMessage) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint16(uint16(m.Version))
	w.WriteUint16(uint16(m.WireFormat))
	switch {
	case m.WireFormat == WireFormatPublicMessage && m.PublicMessage != nil:
		m.PublicMessage.MarshalTLS(w)
	case m.WireFormat == WireFormatPrivateMessage && m.PrivateMessage != nil:
		m.PrivateMessage.MarshalTLS(w)
	case m.WireFormat == WireFormatWelcome && m.Welcome != nil:
		m.Welcome.MarshalTLS(w)
	case m.WireFormat == WireFormatGroupInfo && m.GroupInfo != nil:
		m.GroupInfo.MarshalTLS(w)
	case m.WireFormat == WireFormatKeyPackage && m.KeyPackage != nil:
		m.KeyPackage.MarshalTLS(w)
	default:
		w.SetError(errUnknown("wire format", uint64(m.WireFormat)))
	}
}

func (m *MLSMessage) UnmarshalTLS(r *tlssyntax.Reader) {
	*m = MLSMessage{}
	m.Version = ProtocolVersion(r.ReadUint16())
	m.WireFormat = WireFormat(r.ReadUint16())
	switch m.WireFormat {
	case WireFormatPublicMessage:
		m.PublicMessage = new(PublicMessage)
		m.PublicMessage.UnmarshalTLS(r)
	case WireFormatPrivateMessage:
		m.PrivateMessage = new(PrivateMessage)
		m.PrivateMessage.UnmarshalTLS(r)
	case WireFormatWelcome:
		m.Welcome = new(Welcome)
		m.Welcome.UnmarshalTLS(r)
	case WireFormatGroupInfo:
		m.GroupInfo = new(GroupInfo)
		m.GroupInfo.UnmarshalTLS(r)
	case WireFormatKeyPackage:
		m.KeyPackage = new(KeyPackage)
		m.KeyPackage.UnmarshalTLS(r)
	default:
		if r.Err() == nil {
			r.SetError(errUnknown("wire format", uint64(m.WireFormat)))
		}
	}
}

// An HPKECiphertext is a single-shot HPKE encryption: an encapsulated
// key and the ciphertext it protects. See RFC 9420, Section 7.6.
type HPKECiphertext struct {
	KEMOutput  []byte
	Ciphertext []byte
}

func (c *HPKECiphertext) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteOpaque(c.KEMOutput)
	w.WriteOpaque(c.Ciphertext)
}

func (c *HPKECiphertext) UnmarshalTLS(r *tlssyntax.Reader) {
	c.KEMOutput = r.ReadOpaque()
	c.Ciphertext = r.ReadOpaque()
}

// EncryptedGroupSecrets carries one new member's copy of the group
// secrets in a [Welcome], addressed by the hash of its key package.
// See RFC 9420, Section 12.4.3.1.
type EncryptedGroupSecrets struct {
	NewMember             HashReference
	EncryptedGroupSecrets HPKECiphertext
}

func (s *EncryptedGroupSecrets) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteOpaque(s.NewMember)
	s.EncryptedGroupSecrets.MarshalTLS(w)
}

func (s *EncryptedGroupSecrets) UnmarshalTLS(r *tlssyntax.Reader) {
	s.NewMember = r.ReadOpaque()
	s.EncryptedGroupSecrets.UnmarshalTLS(r)
}

// A Welcome brings new members into a group. It carries the group's
// secrets encrypted separately to each new member, and the group's
// [GroupInfo] encrypted under a key those secrets derive.
// See RFC 9420, Section 12.4.3.1.
type Welcome struct {
	CipherSuite        CipherSuite
	Secrets            []EncryptedGroupSecrets
	EncryptedGroupInfo []byte
}

func (m *Welcome) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint16(uint16(m.CipherSuite))
	w.WriteVector(func(w *tlssyntax.Writer) {
		for i := range m.Secrets {
			m.Secrets[i].MarshalTLS(w)
		}
	})
	w.WriteOpaque(m.EncryptedGroupInfo)
}

func (m *Welcome) UnmarshalTLS(r *tlssyntax.Reader) {
	*m = Welcome{}
	m.CipherSuite = CipherSuite(r.ReadUint16())
	r.ReadAll(func(r *tlssyntax.Reader) {
		var s EncryptedGroupSecrets
		s.UnmarshalTLS(r)
		m.Secrets = append(m.Secrets, s)
	})
	m.EncryptedGroupInfo = r.ReadOpaque()
}

// A GroupInfo tells a joining member the state of the group. It is
// signed by an existing member, named by Signer, over a GroupInfoTBS,
// which this package does not yet construct.
// See RFC 9420, Section 12.4.3.
type GroupInfo struct {
	GroupContext    GroupContext
	Extensions      Extensions
	ConfirmationTag []byte
	Signer          uint32
	Signature       []byte
}

func (g *GroupInfo) MarshalTLS(w *tlssyntax.Writer) {
	g.GroupContext.MarshalTLS(w)
	g.Extensions.MarshalTLS(w)
	w.WriteOpaque(g.ConfirmationTag)
	w.WriteUint32(g.Signer)
	w.WriteOpaque(g.Signature)
}

func (g *GroupInfo) UnmarshalTLS(r *tlssyntax.Reader) {
	*g = GroupInfo{}
	g.GroupContext.UnmarshalTLS(r)
	g.Extensions.UnmarshalTLS(r)
	g.ConfirmationTag = r.ReadOpaque()
	g.Signer = r.ReadUint32()
	g.Signature = r.ReadOpaque()
}
