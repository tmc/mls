package mls

import (
	"slices"

	"github.com/tmc/mls/tlssyntax"
)

// SignedContent returns the GroupInfoTBS bytes that g.Signature
// covers. See RFC 9420, Section 12.4.3.
func (g *GroupInfo) SignedContent() ([]byte, error) {
	return tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		g.GroupContext.MarshalTLS(w)
		g.Extensions.MarshalTLS(w)
		w.WriteOpaque(g.ConfirmationTag)
		w.WriteUint32(g.Signer)
	}))
}

// Sign signs g with priv, the signature key of the member named by
// g.Signer.
func (g *GroupInfo) Sign(priv []byte) error {
	tbs, err := g.SignedContent()
	if err != nil {
		return err
	}
	sig, err := g.GroupContext.CipherSuite.SignWithLabel(priv, "GroupInfoTBS", tbs)
	if err != nil {
		return err
	}
	g.Signature = sig
	return nil
}

// Verify checks g.Signature against pub, which must be the signature
// key of the member at g.Signer.
func (g *GroupInfo) Verify(pub SignaturePublicKey) error {
	tbs, err := g.SignedContent()
	if err != nil {
		return err
	}
	return g.GroupContext.CipherSuite.VerifyWithLabel(pub, "GroupInfoTBS", tbs, g.Signature)
}

// welcomeKey derives the key and nonce that protect a welcome
// message's group info. See RFC 9420, Section 12.4.3.1.
func (cs CipherSuite) welcomeKey(welcomeSecret []byte) (key, nonce []byte, err error) {
	if key, err = cs.ExpandWithLabel(welcomeSecret, "key", nil, uint16(cs.AEADKeySize())); err != nil {
		return nil, nil, err
	}
	if nonce, err = cs.ExpandWithLabel(welcomeSecret, "nonce", nil, uint16(cs.AEADNonceSize())); err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}

// GroupSecrets decrypts the group secrets a welcome message carries
// for the holder of initPriv, the private half of the init key in the
// key package named by ref.
func (m *Welcome) GroupSecrets(ref HashReference, initPriv []byte) (*GroupSecrets, error) {
	i := slices.IndexFunc(m.Secrets, func(s EncryptedGroupSecrets) bool {
		return slices.Equal(s.NewMember, ref)
	})
	if i < 0 {
		return nil, ErrNotInWelcome
	}
	cs := m.CipherSuite
	b, err := cs.DecryptWithLabel(initPriv, "Welcome", m.EncryptedGroupInfo, &m.Secrets[i].EncryptedGroupSecrets)
	if err != nil {
		return nil, err
	}
	secrets := new(GroupSecrets)
	if err := Unmarshal(b, secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

// GroupInfo decrypts the group info a welcome message carries, under
// the welcome secret derived from the joiner secret and any
// pre-shared keys the commit injected.
func (m *Welcome) GroupInfo(welcomeSecret []byte) (*GroupInfo, error) {
	cs := m.CipherSuite
	key, nonce, err := cs.welcomeKey(welcomeSecret)
	if err != nil {
		return nil, err
	}
	aead, err := cs.AEAD(key)
	if err != nil {
		return nil, err
	}
	b, err := aead.Open(nil, nonce, m.EncryptedGroupInfo, nil)
	if err != nil {
		return nil, err
	}
	info := new(GroupInfo)
	if err := Unmarshal(b, info); err != nil {
		return nil, err
	}
	return info, nil
}

// SetGroupInfo encrypts info into the welcome message. Callers add
// the per-member secrets with [Welcome.AddMember] afterwards, since
// those are bound to the encrypted group info.
func (m *Welcome) SetGroupInfo(welcomeSecret []byte, info *GroupInfo) error {
	cs := m.CipherSuite
	key, nonce, err := cs.welcomeKey(welcomeSecret)
	if err != nil {
		return err
	}
	aead, err := cs.AEAD(key)
	if err != nil {
		return err
	}
	b, err := Marshal(info)
	if err != nil {
		return err
	}
	m.EncryptedGroupInfo = aead.Seal(nil, nonce, b, nil)
	m.Secrets = nil
	return nil
}

// AddMember encrypts secrets to the holder of the key package named
// by ref, whose init key is initKey.
func (m *Welcome) AddMember(ref HashReference, initKey HPKEPublicKey, secrets *GroupSecrets) error {
	b, err := Marshal(secrets)
	if err != nil {
		return err
	}
	ct, err := m.CipherSuite.EncryptWithLabel(initKey, "Welcome", m.EncryptedGroupInfo, b)
	if err != nil {
		return err
	}
	m.Secrets = append(m.Secrets, EncryptedGroupSecrets{
		NewMember:             ref,
		EncryptedGroupSecrets: *ct,
	})
	return nil
}
