package mls

import (
	"crypto/rand"
	"crypto/subtle"

	"github.com/tmc/mls/tlssyntax"
)

// PublicMessage frames c for sending in the clear, adding the
// membership tag that proves the sender belongs to the group. Only
// proposals and commits may be sent this way: application data must
// be encrypted. See RFC 9420, Section 6.2.
func (c *AuthenticatedContent) PublicMessage(cs CipherSuite, membershipKey []byte, ctx *GroupContext) (*PublicMessage, error) {
	if c.Content.ContentType == ContentTypeApplication {
		return nil, ErrApplicationNotEncrypted
	}
	m := &PublicMessage{Content: c.Content, Auth: c.Auth}
	m.Auth.ContentType = c.Content.ContentType
	if c.Content.Sender.Type == SenderTypeMember {
		tag, err := cs.MembershipTag(membershipKey, c, ctx.Version, ctx)
		if err != nil {
			return nil, err
		}
		m.MembershipTag = tag
	}
	return m, nil
}

// AuthenticatedContent recovers the content of a public message,
// checking the membership tag if there is one. The caller must still
// verify the signature; see [AuthenticatedContent.Verify].
func (m *PublicMessage) AuthenticatedContent(cs CipherSuite, membershipKey []byte, ctx *GroupContext) (*AuthenticatedContent, error) {
	c := &AuthenticatedContent{WireFormat: WireFormatPublicMessage, Content: m.Content, Auth: m.Auth}
	c.Auth.ContentType = m.Content.ContentType
	if m.Content.Sender.Type != SenderTypeMember {
		return c, nil
	}
	tag, err := cs.MembershipTag(membershipKey, c, ctx.Version, ctx)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(tag, m.MembershipTag) != 1 {
		return nil, ErrBadMembershipTag
	}
	return c, nil
}

// privateMessage encrypts c for sending. The sender must be a member,
// and r must be that member's ratchet for c's content type. If padTo
// is greater than one, zero bytes are appended to the plaintext until
// its length is a multiple of padTo, so that the ciphertext reveals
// the length of the message only to that granularity.
// See RFC 9420, Section 6.3.
func (c *AuthenticatedContent) privateMessage(cs CipherSuite, r *ratchet, senderDataSecret []byte, padTo int) (*PrivateMessage, error) {
	if c.Content.Sender.Type != SenderTypeMember {
		return nil, ErrNotMember
	}
	var guard [4]byte
	if _, err := rand.Read(guard[:]); err != nil {
		return nil, err
	}
	generation := r.Generation()
	key, nonce, err := r.Next()
	if err != nil {
		return nil, err
	}

	m := &PrivateMessage{
		GroupID:           c.Content.GroupID,
		Epoch:             c.Content.Epoch,
		ContentType:       c.Content.ContentType,
		AuthenticatedData: c.Content.AuthenticatedData,
	}
	plaintext, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		c.Content.marshalBody(w)
		c.Auth.ContentType = c.Content.ContentType
		c.Auth.MarshalTLS(w)
	}))
	if err != nil {
		return nil, err
	}
	if padTo > 1 {
		if n := len(plaintext) % padTo; n != 0 {
			plaintext = append(plaintext, make([]byte, padTo-n)...)
		}
	}
	aead, err := cs.AEAD(key)
	if err != nil {
		return nil, err
	}
	m.Ciphertext = aead.Seal(nil, applyGuard(nonce, guard), plaintext, m.contentAAD())

	data := &SenderData{
		LeafIndex:  c.Content.Sender.LeafIndex,
		Generation: generation,
		ReuseGuard: guard,
	}
	if m.EncryptedSenderData, err = m.sealSenderData(cs, senderDataSecret, data); err != nil {
		return nil, err
	}
	return m, nil
}

// authenticatedContent decrypts a private message whose sender data,
// recovered by openSenderData, is data. It takes the sender's ratchet
// from tree, so tree must be the secret tree of the epoch the message
// was sent in.
//
// The ratchet is left where it was: authenticatedContent returns a
// function that advances it past the message's generation, which the
// caller must call only once it has verified the signature; see
// [AuthenticatedContent.Verify]. Every member of the epoch can derive
// every leaf's keys, so a message that decrypts proves nothing about
// who sent it: only a valid signature from the leaf it names may
// spend that leaf's keys.
func (m *PrivateMessage) authenticatedContent(cs CipherSuite, tree *secretTree, data *SenderData) (*AuthenticatedContent, func(), error) {
	r, err := tree.ratchet(LeafIndex(data.LeafIndex), m.ContentType)
	if err != nil {
		return nil, nil, err
	}
	key, nonce, advance, err := r.Key(data.Generation)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cs.AEAD(key)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := aead.Open(nil, applyGuard(nonce, data.ReuseGuard), m.Ciphertext, m.contentAAD())
	if err != nil {
		return nil, nil, err
	}

	c := &AuthenticatedContent{
		WireFormat: WireFormatPrivateMessage,
		Content: FramedContent{
			GroupID:           m.GroupID,
			Epoch:             m.Epoch,
			Sender:            Sender{Type: SenderTypeMember, LeafIndex: data.LeafIndex},
			AuthenticatedData: m.AuthenticatedData,
			ContentType:       m.ContentType,
		},
	}
	c.Auth.ContentType = m.ContentType
	err = tlssyntax.Unmarshal(plaintext, tlssyntax.UnmarshalerFunc(func(r *tlssyntax.Reader) {
		c.Content.unmarshalBody(r)
		c.Auth.UnmarshalTLS(r)
		// The rest is padding, which must be all zero.
		for _, b := range r.ReadRaw(r.Len()) {
			if b != 0 {
				r.SetError(ErrBadPadding)
				return
			}
		}
	}))
	if err != nil {
		return nil, nil, err
	}
	return c, advance, nil
}

// contentAAD is the additional authenticated data for the content
// encryption: the fields of the message that travel in the clear.
func (m *PrivateMessage) contentAAD() []byte {
	b, _ := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteOpaque(m.GroupID)
		w.WriteUint64(m.Epoch)
		w.WriteUint8(uint8(m.ContentType))
		w.WriteOpaque(m.AuthenticatedData)
	}))
	return b
}

// senderDataAAD is the additional authenticated data for the sender
// data encryption.
func (m *PrivateMessage) senderDataAAD() []byte {
	b, _ := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteOpaque(m.GroupID)
		w.WriteUint64(m.Epoch)
		w.WriteUint8(uint8(m.ContentType))
	}))
	return b
}

func (m *PrivateMessage) sealSenderData(cs CipherSuite, secret []byte, data *SenderData) ([]byte, error) {
	key, nonce, err := cs.SenderDataKey(secret, m.Ciphertext)
	if err != nil {
		return nil, err
	}
	aead, err := cs.AEAD(key)
	if err != nil {
		return nil, err
	}
	b, err := Marshal(data)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, b, m.senderDataAAD()), nil
}

func (m *PrivateMessage) openSenderData(cs CipherSuite, secret []byte) (*SenderData, error) {
	key, nonce, err := cs.SenderDataKey(secret, m.Ciphertext)
	if err != nil {
		return nil, err
	}
	aead, err := cs.AEAD(key)
	if err != nil {
		return nil, err
	}
	b, err := aead.Open(nil, nonce, m.EncryptedSenderData, m.senderDataAAD())
	if err != nil {
		return nil, err
	}
	data := new(SenderData)
	if err := Unmarshal(b, data); err != nil {
		return nil, err
	}
	return data, nil
}

// applyGuard exclusive-ors the reuse guard into the first four bytes
// of the nonce, so that a nonce reused by a buggy sender still
// differs from the one the receiver expects.
// See RFC 9420, Section 6.3.1.
func applyGuard(nonce []byte, guard [4]byte) []byte {
	out := make([]byte, len(nonce))
	copy(out, nonce)
	for i, b := range guard {
		out[i] ^= b
	}
	return out
}
