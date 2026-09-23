package mls

import (
	"crypto/hmac"

	"github.com/tmc/mls/tlssyntax"
)

// The transcript hashes chain every commit in a group's history into
// two running values. The confirmed transcript hash covers the commit
// itself; the interim transcript hash extends it with the
// confirmation tag that proves the committer knew the epoch secrets.
// See RFC 9420, Section 8.2.

// ConfirmedTranscriptHash returns the confirmed transcript hash of
// the epoch that commit ends, given the interim transcript hash of
// the epoch before it. commit must be a commit.
func (cs CipherSuite) ConfirmedTranscriptHash(interim []byte, commit *AuthenticatedContent) ([]byte, error) {
	if commit.Content.ContentType != ContentTypeCommit {
		return nil, ErrNotCommit
	}
	b, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteRaw(interim)
		w.WriteUint16(uint16(commit.WireFormat))
		commit.Content.MarshalTLS(w)
		w.WriteOpaque(commit.Auth.Signature)
	}))
	if err != nil {
		return nil, err
	}
	return cs.Hash(b)
}

// InterimTranscriptHash extends a confirmed transcript hash with the
// confirmation tag of the same commit.
func (cs CipherSuite) InterimTranscriptHash(confirmed, confirmationTag []byte) ([]byte, error) {
	b, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteRaw(confirmed)
		w.WriteOpaque(confirmationTag)
	}))
	if err != nil {
		return nil, err
	}
	return cs.Hash(b)
}

// ConfirmationTag is the MAC that proves the sender of a commit knows
// the confirmation key of the epoch the commit creates.
// See RFC 9420, Section 6.1.
func (cs CipherSuite) ConfirmationTag(confirmationKey, confirmedTranscriptHash []byte) ([]byte, error) {
	p, err := cs.params()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(p.hash.New, confirmationKey)
	mac.Write(confirmedTranscriptHash)
	return mac.Sum(nil), nil
}

// MembershipTag is the MAC that proves the sender of a PublicMessage
// is a member of the group. See RFC 9420, Section 6.1.
func (cs CipherSuite) MembershipTag(membershipKey []byte, content *AuthenticatedContent, version ProtocolVersion, ctx *GroupContext) ([]byte, error) {
	p, err := cs.params()
	if err != nil {
		return nil, err
	}
	tbs, err := content.signedContent(version, ctx)
	if err != nil {
		return nil, err
	}
	b, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteRaw(tbs)
		content.Auth.marshal(w, content.Content.ContentType)
	}))
	if err != nil {
		return nil, err
	}
	mac := hmac.New(p.hash.New, membershipKey)
	mac.Write(b)
	return mac.Sum(nil), nil
}
