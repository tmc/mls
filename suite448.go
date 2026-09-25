package mls

import (
	"crypto/rand"
	"errors"

	"github.com/tmc/mls/internal/ed448"
	"github.com/tmc/mls/internal/hpkex448"
)

// This file holds the primitives of cipher suites 4 and 6, whose
// DHKEM(X448, HKDF-SHA512) and Ed448 crypto/hpke and crypto/ed25519
// do not cover. The private keys are those RFC 9180 and RFC 8032
// define: a 56-byte X448 scalar and a 57-byte Ed448 seed.

// aead448 returns the HPKE AEAD of a DHKEM(X448) cipher suite.
func (p *params) aead448() hpkex448.AEAD {
	if p.chacha {
		return hpkex448.ChaCha20Poly1305
	}
	return hpkex448.AES256GCM
}

// seal448 is SealBase for a DHKEM(X448) cipher suite.
func (p *params) seal448(pub HPKEPublicKey, info, plaintext []byte) (*HPKECiphertext, error) {
	var ct HPKECiphertext
	err := withDIT(func() error {
		enc, s, err := hpkex448.NewSender(pub, p.aead448(), info)
		if err != nil {
			return err
		}
		ct.KEMOutput = enc
		ct.Ciphertext, err = s.Seal(nil, plaintext)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &ct, nil
}

// open448 is OpenBase for a DHKEM(X448) cipher suite.
func (p *params) open448(priv, info []byte, ct *HPKECiphertext) ([]byte, error) {
	var pt []byte
	err := withDIT(func() error {
		r, err := hpkex448.NewRecipient(ct.KEMOutput, priv, p.aead448(), info)
		if err != nil {
			return err
		}
		pt, err = r.Open(nil, ct.Ciphertext)
		return err
	})
	return pt, err
}

// sendExport448 is SendExport of RFC 9180, Section 6.2, with an empty
// info, for a DHKEM(X448) cipher suite.
func (p *params) sendExport448(pub HPKEPublicKey, context string, length int) (enc, secret []byte, err error) {
	err = withDIT(func() error {
		var s *hpkex448.Context
		enc, s, err = hpkex448.NewSender(pub, p.aead448(), nil)
		if err != nil {
			return err
		}
		secret, err = s.Export([]byte(context), length)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return enc, secret, nil
}

// receiveExport448 is ReceiveExport, the counterpart of sendExport448.
func (p *params) receiveExport448(enc, priv []byte, context string, length int) ([]byte, error) {
	var secret []byte
	err := withDIT(func() error {
		r, err := hpkex448.NewRecipient(enc, priv, p.aead448(), nil)
		if err != nil {
			return err
		}
		secret, err = r.Export([]byte(context), length)
		return err
	})
	return secret, err
}

// hpkeKeyPair448 runs f, one of the key functions of hpkex448, with
// data-independent timing.
func hpkeKeyPair448(f func() (priv, pub []byte, err error)) (priv []byte, pub HPKEPublicKey, err error) {
	err = withDIT(func() error {
		priv, pub, err = f()
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// signEd448 signs msg with the Ed448 seed priv, as pure Ed448 with an
// empty context: RFC 9420 names the TLS signature scheme ed448, which
// RFC 8446, Section 4.2.3, defines that way.
func signEd448(priv, msg []byte) ([]byte, error) {
	if len(priv) != ed448.SeedSize {
		return nil, errors.New("mls: bad Ed448 private key size")
	}
	var sig []byte
	err := withDIT(func() error {
		key, err := ed448.NewKeyFromSeed(priv)
		if err != nil {
			return err
		}
		sig, err = ed448.Sign(key, msg, "")
		return err
	})
	return sig, err
}

// verifyEd448 checks an Ed448 signature made by signEd448.
func verifyEd448(pub SignaturePublicKey, msg, sig []byte) error {
	if len(pub) != ed448.PublicKeySize {
		return errors.New("mls: bad Ed448 public key size")
	}
	if !ed448.Verify(pub, msg, sig, "") {
		return ErrBadSignature
	}
	return nil
}

// generateEd448 returns a fresh Ed448 seed and its public key.
func generateEd448() (priv []byte, pub SignaturePublicKey, err error) {
	pub, key, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return key.Seed(), pub, nil
}
