package mls

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/rand"
	_ "crypto/sha256" // for crypto.SHA256.New
	_ "crypto/sha512" // for crypto.SHA384.New and crypto.SHA512.New
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/tmc/mls/tlssyntax"
	"golang.org/x/crypto/chacha20poly1305"
)

// ErrUnsupportedCipherSuite is reported for cipher suites this
// package cannot implement. RFC 9420 suites 4 and 6 use X448 and
// Ed448, which the Go standard library does not provide. In FIPS 140-3
// mode, the suites that use X25519 are unsupported too; see the
// package documentation.
var ErrUnsupportedCipherSuite = errors.New("mls: unsupported cipher suite")

// A signatureScheme is the signature algorithm of a cipher suite.
type signatureScheme int

const (
	signatureEd25519 signatureScheme = iota
	signatureECDSA
	signatureMLDSA
)

// params are the cryptographic primitives of a cipher suite.
// See RFC 9420, Section 17.1.
type params struct {
	hash      crypto.Hash
	curve     ecdh.Curve
	kdf       func() hpke.KDF
	aead      func() hpke.AEAD
	keySize   int  // AEAD key size, Nk
	nonceSize int  // AEAD nonce size, Nn
	chacha    bool // AEAD is ChaCha20-Poly1305
	fips      bool // every primitive is approved in FIPS 140-3 mode
	kemSize   int  // KEM private key size, Nsk
	sig       signatureScheme
	sigCurve  elliptic.Curve   // sig == signatureECDSA
	mldsa     mldsa.Parameters // sig == signatureMLDSA
	kem       func() hpke.KEM  // the KEM, if it is not DHKEM(curve)
}

// suiteParams[cs] is nil for cipher suites this package cannot
// implement.
var suiteParams = map[CipherSuite]*params{
	X25519AES128GCMSHA256Ed25519: {
		hash: crypto.SHA256, curve: ecdh.X25519(),
		kdf: hpke.HKDFSHA256, aead: hpke.AES128GCM, keySize: 16, nonceSize: 12, kemSize: 32,
		sig: signatureEd25519,
	},
	P256AES128GCMSHA256P256: {
		hash: crypto.SHA256, curve: ecdh.P256(),
		kdf: hpke.HKDFSHA256, aead: hpke.AES128GCM, keySize: 16, nonceSize: 12, kemSize: 32,
		sig: signatureECDSA, sigCurve: elliptic.P256(), fips: true,
	},
	X25519ChaCha20Poly1305SHA256Ed25519: {
		hash: crypto.SHA256, curve: ecdh.X25519(),
		kdf: hpke.HKDFSHA256, aead: hpke.ChaCha20Poly1305, keySize: 32, nonceSize: 12, chacha: true, kemSize: 32,
		sig: signatureEd25519,
	},
	P521AES256GCMSHA512P521: {
		hash: crypto.SHA512, curve: ecdh.P521(),
		kdf: hpke.HKDFSHA512, aead: hpke.AES256GCM, keySize: 32, nonceSize: 12, kemSize: 66,
		sig: signatureECDSA, sigCurve: elliptic.P521(), fips: true,
	},
	P384AES256GCMSHA384P384: {
		hash: crypto.SHA384, curve: ecdh.P384(),
		kdf: hpke.HKDFSHA384, aead: hpke.AES256GCM, keySize: 32, nonceSize: 12, kemSize: 48,
		sig: signatureECDSA, sigCurve: elliptic.P384(), fips: true,
	},

	// The post-quantum suites of draft-ietf-mls-pq-ciphersuites-06.
	// Their code points are provisional; see the package documentation.
	MLKEM768X25519AES128GCMSHA256Ed25519: {
		hash: crypto.SHA256, kem: hpke.MLKEM768X25519,
		kdf: hpke.HKDFSHA256, aead: hpke.AES128GCM, keySize: 16, nonceSize: 12, kemSize: 32,
		sig: signatureEd25519,
	},
	MLKEM768X25519AES256GCMSHA384Ed25519: {
		hash: crypto.SHA384, kem: hpke.MLKEM768X25519,
		kdf: hpke.HKDFSHA384, aead: hpke.AES256GCM, keySize: 32, nonceSize: 12, kemSize: 32,
		sig: signatureEd25519,
	},
	MLKEM768P256AES128GCMSHA256P256: {
		hash: crypto.SHA256, kem: hpke.MLKEM768P256,
		kdf: hpke.HKDFSHA256, aead: hpke.AES128GCM, keySize: 16, nonceSize: 12, kemSize: 32,
		sig: signatureECDSA, sigCurve: elliptic.P256(), fips: true,
	},
	MLKEM768P256AES256GCMSHA384P256: {
		hash: crypto.SHA384, kem: hpke.MLKEM768P256,
		kdf: hpke.HKDFSHA384, aead: hpke.AES256GCM, keySize: 32, nonceSize: 12, kemSize: 32,
		sig: signatureECDSA, sigCurve: elliptic.P256(), fips: true,
	},
	MLKEM1024P384AES256GCMSHA384P384: {
		hash: crypto.SHA384, kem: hpke.MLKEM1024P384,
		kdf: hpke.HKDFSHA384, aead: hpke.AES256GCM, keySize: 32, nonceSize: 12, kemSize: 32,
		sig: signatureECDSA, sigCurve: elliptic.P384(), fips: true,
	},
	MLKEM768AES256GCMSHA384Ed25519: {
		hash: crypto.SHA384, kem: hpke.MLKEM768,
		kdf: hpke.HKDFSHA384, aead: hpke.AES256GCM, keySize: 32, nonceSize: 12, kemSize: 64,
		sig: signatureEd25519, fips: true,
	},
	MLKEM768AES256GCMSHA384P256: {
		hash: crypto.SHA384, kem: hpke.MLKEM768,
		kdf: hpke.HKDFSHA384, aead: hpke.AES256GCM, keySize: 32, nonceSize: 12, kemSize: 64,
		sig: signatureECDSA, sigCurve: elliptic.P256(), fips: true,
	},
	MLKEM1024AES256GCMSHA384P384: {
		hash: crypto.SHA384, kem: hpke.MLKEM1024,
		kdf: hpke.HKDFSHA384, aead: hpke.AES256GCM, keySize: 32, nonceSize: 12, kemSize: 64,
		sig: signatureECDSA, sigCurve: elliptic.P384(), fips: true,
	},
	MLKEM768X25519ChaCha20Poly1305SHA384MLDSA44: {
		hash: crypto.SHA384, kem: hpke.MLKEM768X25519,
		kdf: hpke.HKDFSHA384, aead: hpke.ChaCha20Poly1305, keySize: 32, nonceSize: 12, chacha: true, kemSize: 32,
		sig: signatureMLDSA, mldsa: mldsa.MLDSA44(),
	},
	MLKEM768AES256GCMSHA384MLDSA65: {
		hash: crypto.SHA384, kem: hpke.MLKEM768,
		kdf: hpke.HKDFSHA384, aead: hpke.AES256GCM, keySize: 32, nonceSize: 12, kemSize: 64,
		sig: signatureMLDSA, mldsa: mldsa.MLDSA65(), fips: true,
	},
	MLKEM1024AES256GCMSHA384MLDSA87: {
		hash: crypto.SHA384, kem: hpke.MLKEM1024,
		kdf: hpke.HKDFSHA384, aead: hpke.AES256GCM, keySize: 32, nonceSize: 12, kemSize: 64,
		sig: signatureMLDSA, mldsa: mldsa.MLDSA87(), fips: true,
	},
}

func (cs CipherSuite) params() (*params, error) {
	p := suiteParams[cs]
	if p == nil {
		return nil, fmt.Errorf("%w %d", ErrUnsupportedCipherSuite, cs)
	}
	if fips140.Enabled() && !p.fips {
		return nil, fmt.Errorf("%w %v: not approved in FIPS 140-3 mode", ErrUnsupportedCipherSuite, cs)
	}
	if p.sig == signatureMLDSA && fips140.Version() == "v1.0.0" {
		return nil, fmt.Errorf("%w %v: ML-DSA is not in FIPS 140-3 module v1.0.0", ErrUnsupportedCipherSuite, cs)
	}
	return p, nil
}

// hpkeKEM returns the cipher suite's HPKE KEM.
func (p *params) hpkeKEM() hpke.KEM {
	if p.kem != nil {
		return p.kem()
	}
	return hpke.DHKEM(p.curve)
}

// ecdsaHash returns the hash of the TLS signature scheme for ECDSA on
// c, such as ecdsa_secp256r1_sha256. It is the suite's hash in the
// suites of RFC 9420, but not in all of draft-ietf-mls-pq-ciphersuites,
// which pairs P-256 signatures with SHA-384.
func ecdsaHash(c elliptic.Curve) crypto.Hash {
	switch c {
	case elliptic.P256():
		return crypto.SHA256
	case elliptic.P384():
		return crypto.SHA384
	}
	return crypto.SHA512
}

// Supported reports whether this package implements cs. In FIPS 140-3
// mode it reports false for the suites that use X25519, and built
// with GOFIPS140=v1.0.0 for the suites that use ML-DSA.
func (cs CipherSuite) Supported() bool {
	_, err := cs.params()
	return err == nil
}

// HashSize returns the output size of the cipher suite's hash
// function, called Nh in RFC 9420.
func (cs CipherSuite) HashSize() int {
	p, err := cs.params()
	if err != nil {
		return 0
	}
	return p.hash.Size()
}

// Hash returns the cipher suite's hash of data.
func (cs CipherSuite) Hash(data []byte) ([]byte, error) {
	p, err := cs.params()
	if err != nil {
		return nil, err
	}
	h := p.hash.New()
	h.Write(data)
	return h.Sum(nil), nil
}

// labeled prefixes label with "MLS 1.0 ", the domain separator every
// labeled operation in RFC 9420 uses.
func labeled(label string) []byte { return []byte("MLS 1.0 " + label) }

// ExpandWithLabel implements the function of the same name in
// RFC 9420, Section 8: it expands secret into length bytes, bound to
// label and context.
func (cs CipherSuite) ExpandWithLabel(secret []byte, label string, context []byte, length uint16) ([]byte, error) {
	p, err := cs.params()
	if err != nil {
		return nil, err
	}
	info, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteUint16(length)
		w.WriteOpaque(labeled(label))
		w.WriteOpaque(context)
	}))
	if err != nil {
		return nil, err
	}
	return hkdf.Expand(p.hash.New, secret, string(info), int(length))
}

// DeriveSecret is ExpandWithLabel with an empty context and an output
// the size of the cipher suite's hash. See RFC 9420, Section 8.
func (cs CipherSuite) DeriveSecret(secret []byte, label string) ([]byte, error) {
	return cs.ExpandWithLabel(secret, label, nil, uint16(cs.HashSize()))
}

// DeriveTreeSecret is ExpandWithLabel with the generation as context.
// See RFC 9420, Section 9.
func (cs CipherSuite) DeriveTreeSecret(secret []byte, label string, generation uint32, length uint16) ([]byte, error) {
	ctx, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteUint32(generation)
	}))
	if err != nil {
		return nil, err
	}
	return cs.ExpandWithLabel(secret, label, ctx, length)
}

// Extract is the HKDF extract step of the key schedule.
func (cs CipherSuite) Extract(salt, ikm []byte) ([]byte, error) {
	p, err := cs.params()
	if err != nil {
		return nil, err
	}
	return hkdf.Extract(p.hash.New, ikm, salt)
}

// RefHash computes the labeled hash used to reference key packages
// and proposals. See RFC 9420, Section 5.2.
func (cs CipherSuite) RefHash(label string, value []byte) ([]byte, error) {
	b, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteOpaque([]byte(label))
		w.WriteOpaque(value)
	}))
	if err != nil {
		return nil, err
	}
	return cs.Hash(b)
}

// signContent is the input to SignWithLabel and VerifyWithLabel.
func signContent(label string, content []byte) ([]byte, error) {
	return tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteOpaque(labeled(label))
		w.WriteOpaque(content)
	}))
}

// SignWithLabel signs content with priv, binding the signature to
// label. See RFC 9420, Section 5.1.2.
func (cs CipherSuite) SignWithLabel(priv []byte, label string, content []byte) ([]byte, error) {
	p, err := cs.params()
	if err != nil {
		return nil, err
	}
	msg, err := signContent(label, content)
	if err != nil {
		return nil, err
	}
	switch p.sig {
	case signatureEd25519:
		if len(priv) != ed25519.SeedSize {
			return nil, errors.New("mls: bad Ed25519 private key size")
		}
		var sig []byte
		withDIT(func() error {
			sig = ed25519.Sign(ed25519.NewKeyFromSeed(priv), msg)
			return nil
		})
		return sig, nil
	case signatureMLDSA:
		var sig []byte
		err := withDIT(func() error {
			key, err := mldsa.NewPrivateKey(p.mldsa, priv)
			if err != nil {
				return err
			}
			// Pure ML-DSA with an empty context, as
			// draft-ietf-tls-mldsa-05 specifies.
			sig, err = key.Sign(rand.Reader, msg, nil)
			return err
		})
		return sig, err
	default:
		h := ecdsaHash(p.sigCurve).New()
		h.Write(msg)
		digest := h.Sum(nil)
		var sig []byte
		err := withDIT(func() error {
			key, err := ecdsa.ParseRawPrivateKey(p.sigCurve, pad(priv, (p.sigCurve.Params().N.BitLen()+7)/8))
			if err != nil {
				return err
			}
			sig, err = ecdsa.SignASN1(rand.Reader, key, digest)
			return err
		})
		return sig, err
	}
}

// ErrBadSignature is reported when a signature does not verify.
var ErrBadSignature = errors.New("mls: signature does not verify")

// VerifyWithLabel checks a signature produced by SignWithLabel.
func (cs CipherSuite) VerifyWithLabel(pub SignaturePublicKey, label string, content, sig []byte) error {
	p, err := cs.params()
	if err != nil {
		return err
	}
	msg, err := signContent(label, content)
	if err != nil {
		return err
	}
	switch p.sig {
	case signatureEd25519:
		if len(pub) != ed25519.PublicKeySize {
			return errors.New("mls: bad Ed25519 public key size")
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			return ErrBadSignature
		}
	case signatureMLDSA:
		key, err := mldsa.NewPublicKey(p.mldsa, pub)
		if err != nil {
			return err
		}
		if mldsa.Verify(key, msg, sig, nil) != nil {
			return ErrBadSignature
		}
	default:
		key, err := ecdsa.ParseUncompressedPublicKey(p.sigCurve, pub)
		if err != nil {
			return err
		}
		h := ecdsaHash(p.sigCurve).New()
		h.Write(msg)
		if !ecdsa.VerifyASN1(key, h.Sum(nil), sig) {
			return ErrBadSignature
		}
	}
	return nil
}

// encryptContext is the HPKE info string for EncryptWithLabel.
func encryptContext(label string, context []byte) ([]byte, error) {
	return tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteOpaque(labeled(label))
		w.WriteOpaque(context)
	}))
}

// EncryptWithLabel encrypts plaintext to pub under label and context,
// returning the HPKE encapsulated key and the ciphertext.
// See RFC 9420, Section 5.1.3.
func (cs CipherSuite) EncryptWithLabel(pub HPKEPublicKey, label string, context, plaintext []byte) (*HPKECiphertext, error) {
	p, err := cs.params()
	if err != nil {
		return nil, err
	}
	info, err := encryptContext(label, context)
	if err != nil {
		return nil, err
	}
	key, err := p.hpkeKEM().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var enc, ct []byte
	err = withDIT(func() error {
		var sender *hpke.Sender
		var err error
		enc, sender, err = hpke.NewSender(key, p.kdf(), p.aead(), info)
		if err != nil {
			return err
		}
		ct, err = sender.Seal(nil, plaintext)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &HPKECiphertext{KEMOutput: enc, Ciphertext: ct}, nil
}

// DecryptWithLabel reverses EncryptWithLabel.
func (cs CipherSuite) DecryptWithLabel(priv []byte, label string, context []byte, ct *HPKECiphertext) ([]byte, error) {
	p, err := cs.params()
	if err != nil {
		return nil, err
	}
	info, err := encryptContext(label, context)
	if err != nil {
		return nil, err
	}
	var pt []byte
	err = withDIT(func() error {
		key, err := p.hpkeKEM().NewPrivateKey(pad(priv, p.kemSize))
		if err != nil {
			return err
		}
		r, err := hpke.NewRecipient(ct.KEMOutput, key, p.kdf(), p.aead(), info)
		if err != nil {
			return err
		}
		pt, err = r.Open(nil, ct.Ciphertext)
		return err
	})
	return pt, err
}

// AEADKeySize and AEADNonceSize return the key and nonce sizes of the
// cipher suite's AEAD, called Nk and Nn in RFC 9420.
func (cs CipherSuite) AEADKeySize() int {
	p, err := cs.params()
	if err != nil {
		return 0
	}
	return p.keySize
}

// AEADNonceSize is the nonce length of the cipher suite's AEAD, in
// bytes.
func (cs CipherSuite) AEADNonceSize() int {
	p, err := cs.params()
	if err != nil {
		return 0
	}
	return p.nonceSize
}

// AEAD returns the cipher suite's AEAD keyed with key: AES-GCM, or
// ChaCha20-Poly1305 from golang.org/x/crypto, since the standard
// library exposes that construction only through crypto/hpke.
//
// MLS derives the AEAD nonces itself (RFC 9420, Sections 6.3.1 and
// 9.1), which is not an approved GCM IV construction, so under
// GODEBUG=fips140=only AEAD reports [ErrUnsupportedCipherSuite].
func (cs CipherSuite) AEAD(key []byte) (cipher.AEAD, error) {
	p, err := cs.params()
	if err != nil {
		return nil, err
	}
	if fips140.Enforced() {
		return nil, fmt.Errorf("%w %v: MLS AEAD nonces are not an approved GCM IV construction in FIPS 140-only mode", ErrUnsupportedCipherSuite, cs)
	}
	if p.chacha {
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		return dataIndependent{aead}, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return dataIndependent{gcm}, nil
}

// withDIT runs f with the CPU's data-independent timing mode enabled,
// so that a private-key operation reads as a single statement.
// See dataIndependent for what the mode does and does not buy.
func withDIT(f func() error) error {
	var err error
	subtle.WithDataIndependentTiming(func() { err = f() })
	return err
}

// dataIndependent wraps an AEAD so that Seal and Open run with the
// CPU's data-independent timing mode enabled, on the CPUs that have
// one. The mode removes the operand dependence of instructions whose
// latency would otherwise vary, which is what the constant-time code
// underneath — GHASH, the field arithmetic, the tag comparison —
// already assumes. It is a floor, not a fix: it does not make
// variable-time code constant time, and in particular it does not
// hide the cache-timing signal of the table-driven AES the standard
// library falls back to on a CPU without AES instructions. Choose a
// cipher suite the CPU implements. See crypto/subtle.
type dataIndependent struct{ cipher.AEAD }

func (d dataIndependent) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	var out []byte
	subtle.WithDataIndependentTiming(func() {
		out = d.AEAD.Seal(dst, nonce, plaintext, additionalData)
	})
	return out
}

func (d dataIndependent) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	var out []byte
	var err error
	subtle.WithDataIndependentTiming(func() {
		out, err = d.AEAD.Open(dst, nonce, ciphertext, additionalData)
	})
	return out, err
}

// pad left-pads b with zeros to n bytes. Test vectors and other
// implementations sometimes strip the leading zeros of a NIST curve
// private key, which the crypto packages require in full.
func pad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// DeriveKeyPair derives an HPKE key pair from the input keying
// material ikm, as RFC 9180's DeriveKeyPair does. The ratchet tree
// uses it to turn a node secret into the node's key pair.
func (cs CipherSuite) DeriveKeyPair(ikm []byte) (priv []byte, pub HPKEPublicKey, err error) {
	p, err := cs.params()
	if err != nil {
		return nil, nil, err
	}
	err = withDIT(func() error {
		key, err := p.hpkeKEM().DeriveKeyPair(ikm)
		if err != nil {
			return err
		}
		pub = key.PublicKey().Bytes()
		priv, err = key.Bytes()
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// GenerateKeyPair returns a fresh HPKE key pair, as used for a leaf
// node's encryption key and for a key package's init key.
func (cs CipherSuite) GenerateKeyPair() (priv []byte, pub HPKEPublicKey, err error) {
	p, err := cs.params()
	if err != nil {
		return nil, nil, err
	}
	err = withDIT(func() error {
		key, err := p.hpkeKEM().GenerateKey()
		if err != nil {
			return err
		}
		pub = key.PublicKey().Bytes()
		priv, err = key.Bytes()
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// GenerateSignatureKeyPair returns a fresh signature key pair in the
// form SignWithLabel and VerifyWithLabel expect.
func (cs CipherSuite) GenerateSignatureKeyPair() (priv []byte, pub SignaturePublicKey, err error) {
	p, err := cs.params()
	if err != nil {
		return nil, nil, err
	}
	err = withDIT(func() error {
		switch p.sig {
		case signatureEd25519:
			edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			priv, pub = edPriv.Seed(), SignaturePublicKey(edPub)
			return nil
		case signatureMLDSA:
			key, err := mldsa.GenerateKey(p.mldsa)
			if err != nil {
				return err
			}
			priv, pub = key.Bytes(), key.PublicKey().Bytes()
			return nil
		default:
			key, err := ecdsa.GenerateKey(p.sigCurve, rand.Reader)
			if err != nil {
				return err
			}
			if priv, err = key.Bytes(); err != nil {
				return err
			}
			pub, err = key.PublicKey.Bytes()
			return err
		}
	})
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// PublicKey returns the HPKE public key matching the private key
// priv.
func (cs CipherSuite) PublicKey(priv []byte) (HPKEPublicKey, error) {
	p, err := cs.params()
	if err != nil {
		return nil, err
	}
	var pub HPKEPublicKey
	err = withDIT(func() error {
		key, err := p.hpkeKEM().NewPrivateKey(pad(priv, p.kemSize))
		if err != nil {
			return err
		}
		pub = key.PublicKey().Bytes()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// ExternalInit generates the init secret for an epoch begun by an
// external commit, along with the KEM output that lets the members of
// the group derive the same secret from their external key pair.
// See RFC 9420, Section 8.3.
func (cs CipherSuite) ExternalInit(externalPub HPKEPublicKey) (kemOutput, initSecret []byte, err error) {
	p, err := cs.params()
	if err != nil {
		return nil, nil, err
	}
	key, err := p.hpkeKEM().NewPublicKey(externalPub)
	if err != nil {
		return nil, nil, err
	}
	var enc, secret []byte
	err = withDIT(func() error {
		var sender *hpke.Sender
		var err error
		enc, sender, err = hpke.NewSender(key, p.kdf(), p.aead(), nil)
		if err != nil {
			return err
		}
		secret, err = sender.Export(externalInitLabel, cs.HashSize())
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return enc, secret, nil
}

// externalInitLabel is the HPKE exporter context that both sides of
// an external commit derive the init secret under.
const externalInitLabel = "MLS 1.0 external init secret"
