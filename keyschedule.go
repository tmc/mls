package mls

import (
	"crypto/hpke"

	"github.com/tmc/mls/tlssyntax"
)

// A KeySchedule holds the secrets of one epoch. Each epoch's schedule
// is derived from the previous epoch's init secret, the commit secret
// produced by the commit that ended it, and the group context of the
// new epoch. See RFC 9420, Section 8.
type KeySchedule struct {
	CipherSuite CipherSuite

	JoinerSecret  []byte
	WelcomeSecret []byte
	EpochSecret   []byte

	SenderDataSecret   []byte
	EncryptionSecret   []byte
	ExporterSecret     []byte
	ExternalSecret     []byte
	ConfirmationKey    []byte
	MembershipKey      []byte
	ResumptionPSK      []byte
	EpochAuthenticator []byte
	InitSecret         []byte
}

// JoinerSecret derives the joiner secret that begins an epoch. It is
// the one part of the schedule a new member receives directly, in the
// [GroupSecrets] of a welcome message.
func (cs CipherSuite) JoinerSecret(initSecret, commitSecret []byte, ctx *GroupContext) ([]byte, error) {
	extracted, err := cs.Extract(initSecret, commitSecret)
	if err != nil {
		return nil, err
	}
	b, err := Marshal(ctx)
	if err != nil {
		return nil, err
	}
	return cs.ExpandWithLabel(extracted, "joiner", b, uint16(cs.HashSize()))
}

// NewKeySchedule derives the secrets of an epoch from its joiner
// secret, the PSK secret of any pre-shared keys the commit injected,
// and the epoch's group context. A nil pskSecret means no PSKs, which
// RFC 9420 treats as an all-zero secret.
func NewKeySchedule(cs CipherSuite, joinerSecret, pskSecret []byte, ctx *GroupContext) (*KeySchedule, error) {
	if pskSecret == nil {
		pskSecret = make([]byte, cs.HashSize())
	}
	member, err := cs.Extract(joinerSecret, pskSecret)
	if err != nil {
		return nil, err
	}
	b, err := Marshal(ctx)
	if err != nil {
		return nil, err
	}
	ks := &KeySchedule{CipherSuite: cs, JoinerSecret: joinerSecret}
	if ks.WelcomeSecret, err = cs.DeriveSecret(member, "welcome"); err != nil {
		return nil, err
	}
	if ks.EpochSecret, err = cs.ExpandWithLabel(member, "epoch", b, uint16(cs.HashSize())); err != nil {
		return nil, err
	}
	for _, d := range []struct {
		label string
		dst   *[]byte
	}{
		{"sender data", &ks.SenderDataSecret},
		{"encryption", &ks.EncryptionSecret},
		{"exporter", &ks.ExporterSecret},
		{"external", &ks.ExternalSecret},
		{"confirm", &ks.ConfirmationKey},
		{"membership", &ks.MembershipKey},
		{"resumption", &ks.ResumptionPSK},
		{"authentication", &ks.EpochAuthenticator},
		{"init", &ks.InitSecret},
	} {
		if *d.dst, err = cs.DeriveSecret(ks.EpochSecret, d.label); err != nil {
			return nil, err
		}
	}
	return ks, nil
}

// ExternalPub returns the public half of the external init key pair,
// which a GroupInfo publishes so that non-members can join by
// external commit. See RFC 9420, Section 8.
func (ks *KeySchedule) ExternalPub() (HPKEPublicKey, error) {
	p, err := ks.CipherSuite.params()
	if err != nil {
		return nil, err
	}
	priv, err := hpke.DHKEM(p.curve).DeriveKeyPair(ks.ExternalSecret)
	if err != nil {
		return nil, err
	}
	return priv.PublicKey().Bytes(), nil
}

// Export implements MLS-Exporter: it derives an application secret
// bound to label and context. See RFC 9420, Section 8.5.
func (ks *KeySchedule) Export(label string, context []byte, length uint16) ([]byte, error) {
	cs := ks.CipherSuite
	secret, err := cs.DeriveSecret(ks.ExporterSecret, label)
	if err != nil {
		return nil, err
	}
	h, err := cs.Hash(context)
	if err != nil {
		return nil, err
	}
	return cs.ExpandWithLabel(secret, "exported", h, length)
}

// PSKSecret combines the pre-shared keys a commit injects into the
// single secret that the key schedule consumes. ids and psks must be
// parallel: psks[i] is the key material named by ids[i].
// See RFC 9420, Section 8.4.
func (cs CipherSuite) PSKSecret(ids []PreSharedKeyID, psks [][]byte) ([]byte, error) {
	if len(ids) != len(psks) {
		return nil, errPSKCount
	}
	zero := make([]byte, cs.HashSize())
	secret := zero
	for i := range ids {
		extracted, err := cs.Extract(zero, psks[i])
		if err != nil {
			return nil, err
		}
		label, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
			ids[i].MarshalTLS(w)
			w.WriteUint16(uint16(i))
			w.WriteUint16(uint16(len(ids)))
		}))
		if err != nil {
			return nil, err
		}
		input, err := cs.ExpandWithLabel(extracted, "derived psk", label, uint16(cs.HashSize()))
		if err != nil {
			return nil, err
		}
		if secret, err = cs.Extract(input, secret); err != nil {
			return nil, err
		}
	}
	return secret, nil
}
