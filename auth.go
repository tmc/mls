package mls

import "github.com/tmc/mls/tlssyntax"

// AuthenticatedContent is a [FramedContent] with the signature that
// covers it, independent of how it was carried on the wire. It is
// what the transcript hashes and proposal references are computed
// over. See RFC 9420, Section 6.1.
type AuthenticatedContent struct {
	WireFormat WireFormat
	Content    FramedContent
	Auth       FramedContentAuthData
}

func (c *AuthenticatedContent) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint16(uint16(c.WireFormat))
	c.Content.MarshalTLS(w)
	c.Auth.ContentType = c.Content.ContentType
	c.Auth.MarshalTLS(w)
}

func (c *AuthenticatedContent) UnmarshalTLS(r *tlssyntax.Reader) {
	*c = AuthenticatedContent{}
	c.WireFormat = WireFormat(r.ReadUint16())
	c.Content.UnmarshalTLS(r)
	c.Auth.ContentType = c.Content.ContentType
	c.Auth.UnmarshalTLS(r)
}

// signedContent returns the FramedContentTBS bytes that the signature
// in Auth covers. The group context is required when the sender is a
// member or is committing as a new member, and ignored otherwise.
// See RFC 9420, Section 6.1.
func (c *AuthenticatedContent) signedContent(version ProtocolVersion, ctx *GroupContext) ([]byte, error) {
	return tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteUint16(uint16(version))
		w.WriteUint16(uint16(c.WireFormat))
		c.Content.MarshalTLS(w)
		switch c.Content.Sender.Type {
		case SenderTypeMember, SenderTypeNewMemberCommit:
			if ctx == nil {
				w.SetError(ErrMissingGroupContext)
				return
			}
			ctx.MarshalTLS(w)
		}
	}))
}

// Sign signs the content with priv and records the signature in Auth.
func (c *AuthenticatedContent) Sign(cs CipherSuite, priv []byte, version ProtocolVersion, ctx *GroupContext) error {
	tbs, err := c.signedContent(version, ctx)
	if err != nil {
		return err
	}
	sig, err := cs.SignWithLabel(priv, "FramedContentTBS", tbs)
	if err != nil {
		return err
	}
	c.Auth.ContentType = c.Content.ContentType
	c.Auth.Signature = sig
	return nil
}

// Verify checks the signature in Auth against pub.
func (c *AuthenticatedContent) Verify(cs CipherSuite, pub SignaturePublicKey, version ProtocolVersion, ctx *GroupContext) error {
	tbs, err := c.signedContent(version, ctx)
	if err != nil {
		return err
	}
	return cs.VerifyWithLabel(pub, "FramedContentTBS", tbs, c.Auth.Signature)
}

// Ref returns the proposal reference for a proposal sent as c.
// See RFC 9420, Section 5.2.
func (c *AuthenticatedContent) Ref(cs CipherSuite) (HashReference, error) {
	b, err := Marshal(c)
	if err != nil {
		return nil, err
	}
	return cs.RefHash("MLS 1.0 Proposal Reference", b)
}
