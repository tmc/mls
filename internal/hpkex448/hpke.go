// Package hpkex448 implements HPKE (RFC 9180) in base mode with the
// KEM DHKEM(X448, HKDF-SHA512) and the KDF HKDF-SHA512, the HPKE of
// MLS cipher suites 4 and 6, which crypto/hpke does not provide.
package hpkex448

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/tmc/mls/internal/x448"
	"golang.org/x/crypto/chacha20poly1305"
)

// An AEAD is an HPKE AEAD identifier. See RFC 9180, Section 7.3.
type AEAD uint16

const (
	AES128GCM        AEAD = 0x0001
	AES256GCM        AEAD = 0x0002
	ChaCha20Poly1305 AEAD = 0x0003
)

const (
	kemID  = 0x0021 // DHKEM(X448, HKDF-SHA512)
	kdfID  = 0x0003 // HKDF-SHA512
	nh     = 64     // Nh of HKDF-SHA512 and Nsecret of the KEM
	nn     = 12     // Nn of every supported AEAD
	keyLen = x448.Size
)

// keySize returns the AEAD's key size, Nk.
func (a AEAD) keySize() (int, error) {
	switch a {
	case AES128GCM:
		return 16, nil
	case AES256GCM, ChaCha20Poly1305:
		return 32, nil
	}
	return 0, errors.New("hpkex448: unsupported AEAD")
}

func (a AEAD) new(key []byte) (cipher.AEAD, error) {
	if a == ChaCha20Poly1305 {
		return chacha20poly1305.New(key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// labeledExtract and labeledExpand are the functions of RFC 9180,
// Section 4.
func labeledExtract(suiteID, salt []byte, label string, ikm []byte) ([]byte, error) {
	labeled := append([]byte("HPKE-v1"), suiteID...)
	labeled = append(labeled, label...)
	labeled = append(labeled, ikm...)
	return hkdf.Extract(sha512.New, labeled, salt)
}

func labeledExpand(suiteID, prk []byte, label string, info []byte, length int) ([]byte, error) {
	labeled := binary.BigEndian.AppendUint16(nil, uint16(length))
	labeled = append(labeled, "HPKE-v1"...)
	labeled = append(labeled, suiteID...)
	labeled = append(labeled, label...)
	labeled = append(labeled, info...)
	return hkdf.Expand(sha512.New, prk, string(labeled), length)
}

var kemSuiteID = binary.BigEndian.AppendUint16([]byte("KEM"), kemID)

// DeriveKeyPair derives a key pair from the input keying material
// ikm. See RFC 9180, Section 7.1.3.
func DeriveKeyPair(ikm []byte) (priv, pub []byte, err error) {
	prk, err := labeledExtract(kemSuiteID, nil, "dkp_prk", ikm)
	if err != nil {
		return nil, nil, err
	}
	priv, err = labeledExpand(kemSuiteID, prk, "sk", nil, keyLen)
	if err != nil {
		return nil, nil, err
	}
	pub, err = PublicKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// GenerateKey returns a random key pair.
func GenerateKey() (priv, pub []byte, err error) {
	priv = make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		return nil, nil, err
	}
	pub, err = PublicKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// PublicKey returns the public key of priv.
func PublicKey(priv []byte) ([]byte, error) {
	if len(priv) != keyLen {
		return nil, errors.New("hpkex448: bad private key length")
	}
	return x448.X448(priv, x448.Basepoint)
}

// extractAndExpand turns a Diffie-Hellman output into the KEM shared
// secret. See RFC 9180, Section 4.1.
func extractAndExpand(dh, enc, pubR []byte) ([]byte, error) {
	prk, err := labeledExtract(kemSuiteID, nil, "eae_prk", dh)
	if err != nil {
		return nil, err
	}
	kemContext := append(append([]byte(nil), enc...), pubR...)
	return labeledExpand(kemSuiteID, prk, "shared_secret", kemContext, nh)
}

// A Context is an HPKE encryption context. Its sequence number
// advances with each Seal or Open.
type Context struct {
	aead      cipher.AEAD
	baseNonce []byte
	exporter  []byte
	suiteID   []byte
	seq       uint64
}

// NewSender encapsulates a fresh shared secret to pubR and returns
// the encapsulated key and a context for sealing to it.
func NewSender(pubR []byte, aead AEAD, info []byte) (enc []byte, c *Context, err error) {
	ephemeral := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, ephemeral); err != nil {
		return nil, nil, err
	}
	return newSender(pubR, ephemeral, aead, info)
}

// newSender is NewSender with the ephemeral private key given.
func newSender(pubR, privE []byte, aead AEAD, info []byte) (enc []byte, c *Context, err error) {
	if len(pubR) != keyLen {
		return nil, nil, errors.New("hpkex448: bad public key length")
	}
	enc, err = PublicKey(privE)
	if err != nil {
		return nil, nil, err
	}
	dh, err := x448.X448(privE, pubR)
	if err != nil {
		return nil, nil, err
	}
	shared, err := extractAndExpand(dh, enc, pubR)
	if err != nil {
		return nil, nil, err
	}
	c, err = newContext(shared, aead, info)
	if err != nil {
		return nil, nil, err
	}
	return enc, c, nil
}

// NewRecipient decapsulates the shared secret in enc with privR and
// returns a context for opening what the sender sealed.
func NewRecipient(enc, privR []byte, aead AEAD, info []byte) (*Context, error) {
	if len(enc) != keyLen {
		return nil, errors.New("hpkex448: bad encapsulated key length")
	}
	pubR, err := PublicKey(privR)
	if err != nil {
		return nil, err
	}
	dh, err := x448.X448(privR, enc)
	if err != nil {
		return nil, err
	}
	shared, err := extractAndExpand(dh, enc, pubR)
	if err != nil {
		return nil, err
	}
	return newContext(shared, aead, info)
}

// newContext is the base-mode key schedule of RFC 9180, Section 5.1.
func newContext(shared []byte, aead AEAD, info []byte) (*Context, error) {
	nk, err := aead.keySize()
	if err != nil {
		return nil, err
	}
	suiteID := []byte("HPKE")
	suiteID = binary.BigEndian.AppendUint16(suiteID, kemID)
	suiteID = binary.BigEndian.AppendUint16(suiteID, kdfID)
	suiteID = binary.BigEndian.AppendUint16(suiteID, uint16(aead))

	pskIDHash, err := labeledExtract(suiteID, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, err
	}
	infoHash, err := labeledExtract(suiteID, nil, "info_hash", info)
	if err != nil {
		return nil, err
	}
	ksContext := append([]byte{0}, pskIDHash...) // mode_base
	ksContext = append(ksContext, infoHash...)
	secret, err := labeledExtract(suiteID, shared, "secret", nil)
	if err != nil {
		return nil, err
	}
	key, err := labeledExpand(suiteID, secret, "key", ksContext, nk)
	if err != nil {
		return nil, err
	}
	baseNonce, err := labeledExpand(suiteID, secret, "base_nonce", ksContext, nn)
	if err != nil {
		return nil, err
	}
	exporter, err := labeledExpand(suiteID, secret, "exp", ksContext, nh)
	if err != nil {
		return nil, err
	}
	a, err := aead.new(key)
	if err != nil {
		return nil, err
	}
	return &Context{aead: a, baseNonce: baseNonce, exporter: exporter, suiteID: suiteID}, nil
}

// nonce returns the nonce for the current sequence number.
// See RFC 9180, Section 5.2.
func (c *Context) nonce() ([]byte, error) {
	if c.seq == math.MaxUint64 {
		return nil, errors.New("hpkex448: message limit reached")
	}
	nonce := binary.BigEndian.AppendUint64(make([]byte, nn-8), c.seq)
	for i := range nonce {
		nonce[i] ^= c.baseNonce[i]
	}
	return nonce, nil
}

// Seal encrypts and authenticates plaintext and authenticates aad.
func (c *Context) Seal(aad, plaintext []byte) ([]byte, error) {
	nonce, err := c.nonce()
	if err != nil {
		return nil, err
	}
	c.seq++
	return c.aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open reverses Seal. A failed Open does not advance the sequence
// number.
func (c *Context) Open(aad, ciphertext []byte) ([]byte, error) {
	nonce, err := c.nonce()
	if err != nil {
		return nil, err
	}
	pt, err := c.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	c.seq++
	return pt, nil
}

// Export derives length bytes of secret bound to exporterContext.
// See RFC 9180, Section 5.3.
func (c *Context) Export(exporterContext []byte, length int) ([]byte, error) {
	if length < 0 || length > 255*nh {
		return nil, errors.New("hpkex448: bad export length")
	}
	return labeledExpand(c.suiteID, c.exporter, "sec", exporterContext, length)
}
