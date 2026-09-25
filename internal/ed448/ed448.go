// Package ed448 implements the Ed448 signature algorithm of RFC 8032,
// Section 5.2, in its pure form (not Ed448ph).
//
// Private-key operations run in constant time. The field arithmetic
// and scalar reduction are ported from github.com/cloudflare/circl;
// see the LICENSE file.
package ed448

import (
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"io"
)

const (
	// PublicKeySize is the length of a public key, in bytes.
	PublicKeySize = 57
	// SeedSize is the length of a private key seed, the private key
	// representation of RFC 8032, in bytes.
	SeedSize = 57
	// PrivateKeySize is the length of a PrivateKey, in bytes.
	PrivateKeySize = SeedSize + PublicKeySize
	// SignatureSize is the length of a signature, in bytes.
	SignatureSize = 114
	// MaxContextSize is the longest context string, in bytes.
	MaxContextSize = 255
)

// A PrivateKey is a seed followed by its public key.
type PrivateKey []byte

// Seed returns the RFC 8032 private key of priv.
func (priv PrivateKey) Seed() []byte { return append([]byte(nil), priv[:SeedSize]...) }

// Public returns the public key of priv.
func (priv PrivateKey) Public() []byte { return append([]byte(nil), priv[SeedSize:]...) }

// GenerateKey returns a key pair drawn from rand.
func GenerateKey(rand io.Reader) (pub []byte, priv PrivateKey, err error) {
	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}
	priv, err = NewKeyFromSeed(seed)
	if err != nil {
		return nil, nil, err
	}
	return priv.Public(), priv, nil
}

// NewKeyFromSeed returns the private key of seed.
// See RFC 8032, Section 5.2.5.
func NewKeyFromSeed(seed []byte) (PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("ed448: bad seed length")
	}
	s, _ := expand(seed)
	var a point
	a.scalarMult(s, generator)
	return append(append(PrivateKey(nil), seed...), a.bytes()...), nil
}

// expand hashes seed into the secret scalar s and the nonce prefix.
func expand(seed []byte) (s *scalar, prefix []byte) {
	h := sha3.SumSHAKE256(seed, 2*SeedSize)
	h[0] &= 0xfc
	h[55] |= 0x80
	h[56] = 0
	return new(scalar).setBytes(h[:SeedSize]), h[SeedSize:]
}

// dom4 writes the domain separator of RFC 8032, Section 5.2, for pure
// Ed448 with context to h.
func dom4(h *sha3.SHAKE, context string) {
	h.Write([]byte("SigEd448"))
	h.Write([]byte{0, byte(len(context))})
	h.Write([]byte(context))
}

// hashScalar returns SHAKE256(dom4(context) || parts..., 114) mod l.
func hashScalar(context string, parts ...[]byte) *scalar {
	h := sha3.NewSHAKE256()
	dom4(h, context)
	for _, p := range parts {
		h.Write(p)
	}
	var out [2 * SeedSize]byte
	h.Read(out[:])
	return new(scalar).setBytes(out[:])
}

// Sign signs message with priv under context, which is at most
// MaxContextSize bytes. See RFC 8032, Section 5.2.6.
func Sign(priv PrivateKey, message []byte, context string) ([]byte, error) {
	if len(priv) != PrivateKeySize {
		return nil, errors.New("ed448: bad private key length")
	}
	if len(context) > MaxContextSize {
		return nil, errors.New("ed448: context too long")
	}
	s, prefix := expand(priv[:SeedSize])
	pub := priv[SeedSize:]

	r := hashScalar(context, prefix, message)
	var rp point
	encR := rp.scalarMult(r, generator).bytes()

	k := hashScalar(context, encR, pub, message)
	var sig scalar
	sig.multiply(k, s).add(&sig, r)

	out := make([]byte, 0, SignatureSize)
	out = append(out, encR...)
	out = append(out, sig.bytes()...)
	return append(out, 0), nil
}

// Verify reports whether sig is a valid signature of message by pub
// under context. See RFC 8032, Section 5.2.7. It checks the
// cofactorless equation [S]B = R + [k]A, as Go's crypto/ed25519 does.
func Verify(pub, message, sig []byte, context string) bool {
	if len(pub) != PublicKeySize || len(sig) != SignatureSize || len(context) > MaxContextSize {
		return false
	}
	var a point
	if _, err := a.setBytes(pub); err != nil {
		return false
	}
	encR, encS := sig[:encodedSize], sig[encodedSize:]
	if encS[scalarSize] != 0 {
		return false
	}
	var s scalar
	s.setBytes(encS[:scalarSize])
	if subtle.ConstantTimeCompare(s.bytes(), encS[:scalarSize]) != 1 {
		return false // S >= l
	}
	k := hashScalar(context, encR, pub, message)

	// R' = [S]B - [k]A, which must encode as R.
	var check point
	a.negate(&a)
	check.doubleScalarMult(&s, generator, k, &a)
	return subtle.ConstantTimeCompare(check.bytes(), encR) == 1
}
