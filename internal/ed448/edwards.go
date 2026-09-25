package ed448

import (
	"crypto/subtle"
	"errors"

	"github.com/tmc/mls/internal/fp448"
)

// A point is a point on edwards448, x² + y² = 1 + d·x²·y², in
// projective coordinates (X:Y:Z) with x = X/Z and y = Y/Z.
// See RFC 8032, Section 5.2.4.
type point struct{ x, y, z fp448.Element }

// d is the curve constant -39081.
var d = new(fp448.Element).Negate(new(fp448.Element).SetUint64(39081))

// generator is the base point B of RFC 8032, Section 5.2.
var generator = func() *point {
	x, _ := new(fp448.Element).SetBytes([]byte{
		0x5e, 0xc0, 0x0c, 0xc7, 0x2b, 0xa8, 0x26, 0x26,
		0x8e, 0x93, 0x00, 0x8b, 0xe1, 0x80, 0x3b, 0x43,
		0x11, 0x65, 0xb6, 0x2a, 0xf7, 0x1a, 0xae, 0x12,
		0x64, 0xa4, 0xd3, 0xa3, 0x24, 0xe3, 0x6d, 0xea,
		0x67, 0x17, 0x0f, 0x47, 0x70, 0x65, 0x14, 0x9e,
		0xda, 0x36, 0xbf, 0x22, 0xa6, 0x15, 0x1d, 0x22,
		0xed, 0x0d, 0xed, 0x6b, 0xc6, 0x70, 0x19, 0x4f,
	})
	y, _ := new(fp448.Element).SetBytes([]byte{
		0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98,
		0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
		0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
		0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
		0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b,
		0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
		0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
	})
	p := &point{x: *x, y: *y}
	p.z.One()
	return p
}()

// identity sets p to the neutral element (0:1:1) and returns p.
func (p *point) identity() *point {
	p.x.Zero()
	p.y.One()
	p.z.One()
	return p
}

// add sets p = a + b and returns p. The formulas are complete: they
// hold for all inputs, including a == b and the identity.
func (p *point) add(a, b *point) *point {
	var aa, bb, c, dd, e, f, g, h, t fp448.Element
	aa.Multiply(&a.z, &b.z)
	bb.Square(&aa)
	c.Multiply(&a.x, &b.x)
	dd.Multiply(&a.y, &b.y)
	e.Multiply(&c, &dd)
	e.Multiply(&e, d)
	f.Subtract(&bb, &e)
	g.Add(&bb, &e)
	h.Add(&a.x, &a.y)
	t.Add(&b.x, &b.y)
	h.Multiply(&h, &t)

	h.Subtract(&h, &c)
	h.Subtract(&h, &dd)
	p.x.Multiply(&aa, &f)
	p.x.Multiply(&p.x, &h)
	t.Subtract(&dd, &c)
	p.y.Multiply(&aa, &g)
	p.y.Multiply(&p.y, &t)
	p.z.Multiply(&f, &g)
	return p
}

// double sets p = 2a and returns p.
func (p *point) double(a *point) *point {
	var b, c, dd, e, h, j fp448.Element
	b.Add(&a.x, &a.y)
	b.Square(&b)
	c.Square(&a.x)
	dd.Square(&a.y)
	e.Add(&c, &dd)
	h.Square(&a.z)
	j.Add(&h, &h)
	j.Subtract(&e, &j)
	b.Subtract(&b, &e)
	p.x.Multiply(&b, &j)
	c.Subtract(&c, &dd)
	p.y.Multiply(&e, &c)
	p.z.Multiply(&e, &j)
	return p
}

// negate sets p = -a and returns p.
func (p *point) negate(a *point) *point {
	p.x.Negate(&a.x)
	p.y = a.y
	p.z = a.z
	return p
}

// selectPoint sets p to a if cond == 1 and to b if cond == 0.
func (p *point) selectPoint(a, b *point, cond int) *point {
	p.x.Select(&a.x, &b.x, cond)
	p.y.Select(&a.y, &b.y, cond)
	p.z.Select(&a.z, &b.z, cond)
	return p
}

// table holds 0·P, 1·P, ..., 15·P for a 4-bit window.
type table [16]point

func (t *table) init(p *point) {
	t[0].identity()
	t[1] = *p
	for i := 2; i < 16; i++ {
		t[i].add(&t[i-1], p)
	}
}

// lookup sets p = t[i] in constant time.
func (t *table) lookup(p *point, i byte) {
	p.identity()
	for j := range t {
		p.selectPoint(&t[j], p, subtle.ConstantTimeByteEq(byte(j), i))
	}
}

// nibble returns the i-th 4-bit window of the little-endian k.
func nibble(k []byte, i int) byte { return k[i/2] >> (4 * (i % 2)) & 15 }

// scalarMult sets p = k·q and returns p, in constant time.
func (p *point) scalarMult(k *scalar, q *point) *point {
	var t table
	t.init(q)
	kb := k.bytes()
	var acc, sel point
	acc.identity()
	for i := 2*scalarSize - 1; i >= 0; i-- {
		for range 4 {
			acc.double(&acc)
		}
		t.lookup(&sel, nibble(kb, i))
		acc.add(&acc, &sel)
	}
	*p = acc
	return p
}

// doubleScalarMult sets p = a·A + b·B and returns p. It shares the
// doublings of the two multiplications.
func (p *point) doubleScalarMult(a *scalar, pa *point, b *scalar, pb *point) *point {
	var ta, tb table
	ta.init(pa)
	tb.init(pb)
	ab, bb := a.bytes(), b.bytes()
	var acc, sel point
	acc.identity()
	for i := 2*scalarSize - 1; i >= 0; i-- {
		for range 4 {
			acc.double(&acc)
		}
		ta.lookup(&sel, nibble(ab, i))
		acc.add(&acc, &sel)
		tb.lookup(&sel, nibble(bb, i))
		acc.add(&acc, &sel)
	}
	*p = acc
	return p
}

// encodedSize is the length of an encoded point.
const encodedSize = 57

// bytes returns the encoding of p. See RFC 8032, Section 5.2.2.
func (p *point) bytes() []byte {
	var zInv, x, y fp448.Element
	zInv.Invert(&p.z)
	x.Multiply(&p.x, &zInv)
	y.Multiply(&p.y, &zInv)
	out := make([]byte, encodedSize)
	copy(out, y.Bytes())
	out[encodedSize-1] = byte(x.IsNegative()) << 7
	return out
}

// setBytes sets p to the point encoded in b, which must be canonical.
// See RFC 8032, Section 5.2.3.
func (p *point) setBytes(b []byte) (*point, error) {
	if len(b) != encodedSize || b[encodedSize-1]&0x7f != 0 {
		return nil, errors.New("ed448: invalid point encoding")
	}
	var y fp448.Element
	y.SetBytes(b[:fp448.Size])
	if subtle.ConstantTimeCompare(y.Bytes(), b[:fp448.Size]) != 1 {
		return nil, errors.New("ed448: invalid point encoding")
	}
	var u, v, one, x fp448.Element
	one.One()
	u.Square(&y)
	v.Multiply(&u, d)
	u.Subtract(&u, &one) // y² - 1
	v.Subtract(&v, &one) // d·y² - 1
	if _, ok := x.SqrtRatio(&u, &v); ok != 1 {
		return nil, errors.New("ed448: invalid point encoding")
	}
	sign := int(b[encodedSize-1] >> 7)
	if x.IsZero() == 1 && sign == 1 {
		return nil, errors.New("ed448: invalid point encoding")
	}
	var negX fp448.Element
	negX.Negate(&x)
	p.x.Select(&negX, &x, x.IsNegative()^sign)
	p.y = y
	p.z.One()
	return p, nil
}
