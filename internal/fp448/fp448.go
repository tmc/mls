// Copyright (c) 2019 Cloudflare. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fp448 implements constant-time arithmetic modulo
// p = 2^448 - 2^224 - 1, the field of Curve448 and Edwards448.
//
// It is a port of github.com/cloudflare/circl/math/fp448 (v1.6.4),
// generic implementation only, with elements held as seven 64-bit
// limbs instead of bytes.
//
// Delete this package when packages x448 and ed448, its only users,
// are deleted.
package fp448

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

// Size is the length of an encoded element, in bytes.
const Size = 56

// An Element is an element of the field. Its limbs hold a
// little-endian value below 2^448 that may not be fully reduced;
// every operation accepts such values, and Bytes reduces.
//
// The zero value is a valid zero element.
type Element struct{ l [7]uint64 }

// p is the modulus.
var p = Element{[7]uint64{
	0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
	0xfffffffeffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
	0xffffffffffffffff,
}}

// Zero sets v = 0 and returns v.
func (v *Element) Zero() *Element { *v = Element{}; return v }

// One sets v = 1 and returns v.
func (v *Element) One() *Element { *v = Element{[7]uint64{1}}; return v }

// Set sets v = a and returns v.
func (v *Element) Set(a *Element) *Element { *v = *a; return v }

// SetUint64 sets v = x and returns v.
func (v *Element) SetUint64(x uint64) *Element { *v = Element{[7]uint64{x}}; return v }

// SetBytes sets v to the little-endian value of x, which must be
// Size bytes long. Values of p or more are accepted and reduced.
func (v *Element) SetBytes(x []byte) (*Element, error) {
	if len(x) != Size {
		return nil, errors.New("fp448: invalid element length")
	}
	for i := range v.l {
		v.l[i] = binary.LittleEndian.Uint64(x[8*i:])
	}
	return v, nil
}

// Bytes returns the canonical little-endian encoding of v.
func (v *Element) Bytes() []byte {
	var out [Size]byte
	return v.bytes(&out)
}

func (v *Element) bytes(out *[Size]byte) []byte {
	t := *v
	t.reduce()
	for i, l := range t.l {
		binary.LittleEndian.PutUint64(out[8*i:], l)
	}
	return out[:]
}

// reduce sets v to its value in [0, p).
func (v *Element) reduce() { v.Subtract(v, &p) }

// Equal returns 1 if v and u are equal and 0 otherwise.
func (v *Element) Equal(u *Element) int {
	var a, b [Size]byte
	return subtle.ConstantTimeCompare(v.bytes(&a), u.bytes(&b))
}

// IsZero returns 1 if v is zero and 0 otherwise.
func (v *Element) IsZero() int { return v.Equal(&Element{}) }

// IsNegative returns 1 if v is odd, the sign RFC 8032 encodes, and 0
// otherwise.
func (v *Element) IsNegative() int {
	t := *v
	t.reduce()
	return int(t.l[0] & 1)
}

// Select sets v to a if cond == 1 and to b if cond == 0, and returns v.
func (v *Element) Select(a, b *Element, cond int) *Element {
	m := -uint64(cond & 1)
	for i := range v.l {
		v.l[i] = (a.l[i] & m) | (b.l[i] &^ m)
	}
	return v
}

// Swap exchanges v and u if cond == 1 and leaves them if cond == 0.
func (v *Element) Swap(u *Element, cond int) {
	m := -uint64(cond & 1)
	for i := range v.l {
		t := m & (v.l[i] ^ u.l[i])
		v.l[i] ^= t
		u.l[i] ^= t
	}
}

// Add sets v = a + b and returns v.
func (v *Element) Add(a, b *Element) *Element {
	var z [7]uint64
	var c uint64
	for i := range z {
		z[i], c = bits.Add64(a.l[i], b.l[i], c)
	}
	// 2^448 = 2^224 + 1 mod p: fold the carry back in, twice.
	for range 2 {
		t := c
		z[0], c = bits.Add64(z[0], t, 0)
		z[1], c = bits.Add64(z[1], 0, c)
		z[2], c = bits.Add64(z[2], 0, c)
		z[3], c = bits.Add64(z[3], t<<32, c)
		z[4], c = bits.Add64(z[4], 0, c)
		z[5], c = bits.Add64(z[5], 0, c)
		z[6], c = bits.Add64(z[6], 0, c)
	}
	v.l = z
	return v
}

// Subtract sets v = a - b and returns v.
func (v *Element) Subtract(a, b *Element) *Element {
	var z [7]uint64
	var c uint64
	for i := range z {
		z[i], c = bits.Sub64(a.l[i], b.l[i], c)
	}
	// A borrow of 2^448 is a borrow of 2^224 + 1 mod p.
	for range 2 {
		t := c
		z[0], c = bits.Sub64(z[0], t, 0)
		z[1], c = bits.Sub64(z[1], 0, c)
		z[2], c = bits.Sub64(z[2], 0, c)
		z[3], c = bits.Sub64(z[3], t<<32, c)
		z[4], c = bits.Sub64(z[4], 0, c)
		z[5], c = bits.Sub64(z[5], 0, c)
		z[6], c = bits.Sub64(z[6], 0, c)
	}
	v.l = z
	return v
}

// Negate sets v = -a and returns v.
func (v *Element) Negate(a *Element) *Element { return v.Subtract(&p, a) }

// Square sets v = a² and returns v.
func (v *Element) Square(a *Element) *Element { return v.Multiply(a, a) }

// Multiply sets v = a × b and returns v.
func (v *Element) Multiply(a, b *Element) *Element {
	x := &a.l
	var lo [7]uint64

	h0, l0 := bits.Mul64(x[0], b.l[0])
	h1, l1 := bits.Mul64(x[1], b.l[0])
	h2, l2 := bits.Mul64(x[2], b.l[0])
	h3, l3 := bits.Mul64(x[3], b.l[0])
	h4, l4 := bits.Mul64(x[4], b.l[0])
	h5, l5 := bits.Mul64(x[5], b.l[0])
	h6, l6 := bits.Mul64(x[6], b.l[0])

	lo[0] = l0
	a0, c0 := bits.Add64(h0, l1, 0)
	a1, c1 := bits.Add64(h1, l2, c0)
	a2, c2 := bits.Add64(h2, l3, c1)
	a3, c3 := bits.Add64(h3, l4, c2)
	a4, c4 := bits.Add64(h4, l5, c3)
	a5, c5 := bits.Add64(h5, l6, c4)
	a6, _ := bits.Add64(h6, 0, c5)

	for i := 1; i < 7; i++ {
		yi := b.l[i]
		h0, l0 = bits.Mul64(x[0], yi)
		h1, l1 = bits.Mul64(x[1], yi)
		h2, l2 = bits.Mul64(x[2], yi)
		h3, l3 = bits.Mul64(x[3], yi)
		h4, l4 = bits.Mul64(x[4], yi)
		h5, l5 = bits.Mul64(x[5], yi)
		h6, l6 = bits.Mul64(x[6], yi)

		lo[i], c0 = bits.Add64(a0, l0, 0)
		a0, c1 = bits.Add64(a1, l1, c0)
		a1, c2 = bits.Add64(a2, l2, c1)
		a2, c3 = bits.Add64(a3, l3, c2)
		a3, c4 = bits.Add64(a4, l4, c3)
		a4, c5 = bits.Add64(a5, l5, c4)
		a5, a6 = bits.Add64(a6, l6, c5)

		a0, c0 = bits.Add64(a0, h0, 0)
		a1, c1 = bits.Add64(a1, h1, c0)
		a2, c2 = bits.Add64(a2, h2, c1)
		a3, c3 = bits.Add64(a3, h3, c2)
		a4, c4 = bits.Add64(a4, h4, c3)
		a5, c5 = bits.Add64(a5, h5, c4)
		a6, _ = bits.Add64(a6, h6, c5)
	}
	v.l = reduceWide(&lo, &[7]uint64{a0, a1, a2, a3, a4, a5, a6})
	return v
}

// reduceWide reduces the 896-bit value h·2^448 + l to below 2^448.
func reduceWide(l, h *[7]uint64) [7]uint64 {
	// With h = (C13, ..., C7) in 32-bit halves, add
	// (2C13, 2C12, 2C11, 2C10|C10, C9, C8, C7) to l.
	h0 := h[0]
	h1 := h[1]
	h2 := h[2]
	h3 := ((h[3] & (0xFFFFFFFF << 32)) << 1) | (h[3] & 0xFFFFFFFF)
	h4 := (h[3] >> 63) | (h[4] << 1)
	h5 := (h[4] >> 63) | (h[5] << 1)
	h6 := (h[5] >> 63) | (h[6] << 1)
	h7 := h[6] >> 63

	l0, c0 := bits.Add64(h0, l[0], 0)
	l1, c1 := bits.Add64(h1, l[1], c0)
	l2, c2 := bits.Add64(h2, l[2], c1)
	l3, c3 := bits.Add64(h3, l[3], c2)
	l4, c4 := bits.Add64(h4, l[4], c3)
	l5, c5 := bits.Add64(h5, l[5], c4)
	l6, c6 := bits.Add64(h6, l[6], c5)
	l7, _ := bits.Add64(h7, 0, c6)

	// Add (C10C9, C9C8, C8C7, C7C13, C13C12, C12C11, C11C10).
	h0 = (h[3] >> 32) | (h[4] << 32)
	h1 = (h[4] >> 32) | (h[5] << 32)
	h2 = (h[5] >> 32) | (h[6] << 32)
	h3 = (h[6] >> 32) | (h[0] << 32)
	h4 = (h[0] >> 32) | (h[1] << 32)
	h5 = (h[1] >> 32) | (h[2] << 32)
	h6 = (h[2] >> 32) | (h[3] << 32)

	l0, c0 = bits.Add64(l0, h0, 0)
	l1, c1 = bits.Add64(l1, h1, c0)
	l2, c2 = bits.Add64(l2, h2, c1)
	l3, c3 = bits.Add64(l3, h3, c2)
	l4, c4 = bits.Add64(l4, h4, c3)
	l5, c5 = bits.Add64(l5, h5, c4)
	l6, c6 = bits.Add64(l6, h6, c5)
	l7, _ = bits.Add64(l7, 0, c6)

	// Fold the top word back in, twice.
	for range 2 {
		l0, c0 = bits.Add64(l0, l7, 0)
		l1, c1 = bits.Add64(l1, 0, c0)
		l2, c2 = bits.Add64(l2, 0, c1)
		l3, c3 = bits.Add64(l3, l7<<32, c2)
		l4, c4 = bits.Add64(l4, 0, c3)
		l5, c5 = bits.Add64(l5, 0, c4)
		l6, l7 = bits.Add64(l6, 0, c5)
	}
	return [7]uint64{l0, l1, l2, l3, l4, l5, l6}
}

// Invert sets v = 1/a mod p and returns v. If a is zero, v is zero.
func (v *Element) Invert(a *Element) *Element {
	// a^(p-2) = a^(4k+1), where k = (p-3)/4.
	var t Element
	t.powPMinus3Div4(a)
	t.Square(&t)
	t.Square(&t)
	return v.Multiply(&t, a)
}

// SqrtRatio sets v to a square root of u/w and returns v and 1 if
// u/w is a square. Otherwise it returns v, set to a square root of
// -u/w, and 0.
func (v *Element) SqrtRatio(u, w *Element) (*Element, int) {
	// With k = (p-3)/4, u^(2(k+1)) = legendre(u)·u and
	// w^(6k+3) = legendre(w), so r = u^(k+1)·w^(3k+1) satisfies
	// r²w = legendre(u)·legendre(w)·u.
	var t0, t1, r Element
	t0.Multiply(u, w)     // uw
	t1.Square(w)          // w²
	t1.Multiply(&t0, &t1) // uw³
	r.powPMinus3Div4(&t1) // (uw³)^k
	r.Multiply(&r, &t0)   // uw(uw³)^k

	t0.Square(&r)
	t0.Multiply(&t0, w)
	ok := t0.Equal(u)
	*v = r
	return v, ok
}

// powPMinus3Div4 sets v = a^((p-3)/4).
func (v *Element) powPMinus3Div4(a *Element) {
	var x0, x1, z Element
	sq := func(e *Element, n int) {
		for range n {
			e.Square(e)
		}
	}
	z.Square(a)
	z.Multiply(&z, a)
	x0.Square(&z)
	x0.Multiply(&x0, a)
	z.Square(&x0)
	sq(&z, 2)
	z.Multiply(&z, &x0)
	x1.Square(&z)
	sq(&x1, 5)
	x1.Multiply(&x1, &z)
	z.Square(&x1)
	sq(&z, 11)
	z.Multiply(&z, &x1)
	sq(&z, 3)
	z.Multiply(&z, &x0)
	x1.Square(&z)
	sq(&x1, 26)
	x1.Multiply(&x1, &z)
	z.Square(&x1)
	sq(&z, 53)
	z.Multiply(&z, &x1)
	sq(&z, 3)
	z.Multiply(&z, &x0)
	x1.Square(&z)
	sq(&x1, 110)
	x1.Multiply(&x1, &z)
	z.Square(&x1)
	z.Multiply(&z, a)
	sq(&z, 223)
	z.Multiply(&z, &x1)
	*v = z
}
