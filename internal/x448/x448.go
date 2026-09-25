// Package x448 implements the X448 Diffie-Hellman function of
// RFC 7748, Section 5, in constant time.
package x448

import (
	"crypto/subtle"
	"errors"

	"github.com/tmc/mls/internal/fp448"
)

// Size is the length of X448 scalars and points, in bytes.
const Size = 56

// Basepoint is the canonical Curve448 generator, u = 5.
var Basepoint = []byte{5, 55: 0}

// a24 is (A - 2) / 4 for Curve448's A = 156326.
var a24 = new(fp448.Element).SetUint64(39081)

// X448 returns the result of the scalar multiplication (scalar * point),
// following RFC 7748, Section 5.
//
// If point is Basepoint the result is the public key of scalar.
// Otherwise it is the shared secret of scalar and the peer's public
// key point. X448 reports an error if the result is all zeros, which
// happens exactly when point has small order (RFC 7748, Section 6.2).
func X448(scalar, point []byte) ([]byte, error) {
	if len(scalar) != Size {
		return nil, errors.New("x448: bad scalar length")
	}
	if len(point) != Size {
		return nil, errors.New("x448: bad point length")
	}
	var out [Size]byte
	x448(&out, scalar, point)
	if subtle.ConstantTimeCompare(out[:], make([]byte, Size)) == 1 {
		return nil, errors.New("x448: bad input point: low order point")
	}
	return out[:], nil
}

// x448 is the Montgomery ladder of RFC 7748, Section 5.
func x448(out *[Size]byte, scalar, point []byte) {
	var k [Size]byte
	copy(k[:], scalar)
	k[0] &= 252
	k[55] |= 128

	var x1, x2, z2, x3, z3 fp448.Element
	x1.SetBytes(point)
	x2.One()
	x3.Set(&x1)
	z3.One()

	var a, aa, b, bb, e, c, d, da, cb fp448.Element
	swap := 0
	for t := 8*Size - 1; t >= 0; t-- {
		kt := int(k[t/8]>>(t%8)) & 1
		swap ^= kt
		x2.Swap(&x3, swap)
		z2.Swap(&z3, swap)
		swap = kt

		a.Add(&x2, &z2)
		aa.Square(&a)
		b.Subtract(&x2, &z2)
		bb.Square(&b)
		e.Subtract(&aa, &bb)
		c.Add(&x3, &z3)
		d.Subtract(&x3, &z3)
		da.Multiply(&d, &a)
		cb.Multiply(&c, &b)
		x3.Add(&da, &cb)
		x3.Square(&x3)
		z3.Subtract(&da, &cb)
		z3.Square(&z3)
		z3.Multiply(&z3, &x1)
		x2.Multiply(&aa, &bb)
		z2.Multiply(a24, &e)
		z2.Add(&z2, &aa)
		z2.Multiply(&z2, &e)
	}
	x2.Swap(&x3, swap)
	z2.Swap(&z3, swap)

	z2.Invert(&z2)
	x2.Multiply(&x2, &z2)
	copy(out[:], x2.Bytes())
}
