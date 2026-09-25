// Copyright (c) 2019 Cloudflare. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is a port of github.com/cloudflare/circl/ecc/goldilocks
// scalar.go (v1.6.4), with scalars held as 64-bit limbs.

package ed448

import (
	"encoding/binary"
	"math/bits"
)

// scalarSize is the length of an encoded scalar without RFC 8032's
// trailing zero byte.
const scalarSize = 56

// A scalar is an integer modulo the group order l, as seven
// little-endian 64-bit limbs. Operations run in constant time.
type scalar [7]uint64

// order is l = 2^446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d,
// the order of the prime-order subgroup.
var order = scalar{
	0x2378c292ab5844f3, 0x216cc2728dc58f55, 0xc44edb49aed63690, 0xffffffff7cca23e9,
	0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff,
}

// residue448 is 2^448 mod l.
var residue448 = [4]uint64{
	0x721cf5b5529eec34, 0x7a4cf635c8e9c2ab, 0xeec492d944a725bf, 0x20cd77058,
}

// addWords sets z = x + y and returns the carry. len(x) >= len(y) and
// len(z) >= len(x).
func addWords(z, x, y []uint64) uint64 {
	var c uint64
	for i := range x {
		var yi uint64
		if i < len(y) {
			yi = y[i]
		}
		z[i], c = bits.Add64(x[i], yi, c)
	}
	return c
}

// subWords sets z = x - y and returns the borrow. len(x) == len(y)
// == len(z).
func subWords(z, x, y []uint64) uint64 {
	var c uint64
	for i := range x {
		z[i], c = bits.Sub64(x[i], y[i], c)
	}
	return c
}

// mulWord sets z = x × y. len(z) >= len(x)+1.
func mulWord(z, x []uint64, y uint64) {
	clear(z)
	var carry uint64
	for i := range x {
		hi, lo := bits.Mul64(x[i], y)
		lo, cc := bits.Add64(lo, carry, 0)
		z[i] = lo
		carry = hi + cc
	}
	z[len(x)] = carry
}

// cmov sets z = x if b == 1 and leaves z if b == 0.
func (z *scalar) cmov(b uint64, x *scalar) {
	m := -b
	for i := range z {
		z[i] = (z[i] &^ m) | (x[i] & m)
	}
}

// shiftIn sets z = z·2^64 + low and returns the word shifted out.
func (z *scalar) shiftIn(low uint64) uint64 {
	high := z[6]
	copy(z[1:], z[:6])
	z[0] = low
	return high
}

// reduceOneWord sets z to a value below 2^448 congruent to
// z + 2^448·x mod l.
func (z *scalar) reduceOneWord(x uint64) {
	var prod scalar
	mulWord(prod[:], residue448[:], x)
	cc := addWords(z[:], z[:], prod[:])
	mulWord(prod[:], residue448[:], cc)
	addWords(z[:], z[:], prod[:])
}

// modOrder reduces z, which is below 2^448 < 5l, modulo l.
func (z *scalar) modOrder() {
	var x scalar
	for range 4 {
		c := subWords(x[:], z[:], order[:])
		z.cmov(1-c, &x)
	}
}

// setBytes sets z to x mod l, where x is little-endian and at least
// 56 bytes long, and returns z.
func (z *scalar) setBytes(x []byte) *scalar {
	n := (len(x) + 7) / 8
	var top [scalarSize]byte
	copy(top[:], x[8*(n-7):])
	for i := range z {
		z[i] = binary.LittleEndian.Uint64(top[8*i:])
	}
	for i := n - 8; i >= 0; i-- {
		z.reduceOneWord(z.shiftIn(binary.LittleEndian.Uint64(x[8*i:])))
	}
	z.modOrder()
	return z
}

// bytes returns the 56-byte little-endian encoding of z.
func (z *scalar) bytes() []byte {
	out := make([]byte, scalarSize)
	for i, w := range z {
		binary.LittleEndian.PutUint64(out[8*i:], w)
	}
	return out
}

// add sets z = x + y mod l and returns z.
func (z *scalar) add(x, y *scalar) *scalar {
	var t scalar
	c := addWords(z[:], x[:], y[:])
	addWords(t[:], z[:], residue448[:])
	z.cmov(c, &t)
	z.modOrder()
	return z
}

// multiply sets z = x × y mod l and returns z.
func (z *scalar) multiply(x, y *scalar) *scalar {
	var acc scalar
	var prod [8]uint64
	mulWord(prod[:], x[:], y[6])
	copy(acc[:], prod[:7])
	acc.reduceOneWord(prod[7])
	for i := 5; i >= 0; i-- {
		acc.reduceOneWord(acc.shiftIn(0))
		mulWord(prod[:], x[:], y[i])
		c := addWords(acc[:], acc[:], prod[:7])
		acc.reduceOneWord(prod[7] + c)
	}
	acc.modOrder()
	*z = acc
	return z
}
