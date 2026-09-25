package fp448

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

var bigP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 448), new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 224), big.NewInt(1)))

func toBig(v *Element) *big.Int {
	b := v.Bytes()
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return new(big.Int).SetBytes(b)
}

// rawBig is the unreduced value of v's limbs.
func rawBig(v *Element) *big.Int {
	n := new(big.Int)
	for i := 6; i >= 0; i-- {
		n.Lsh(n, 64)
		n.Or(n, new(big.Int).SetUint64(v.l[i]))
	}
	return n
}

// testElements are values that stress the carries and reductions:
// 0, 1, p-1, p, p+1, 2^448-1 and others near limb boundaries, plus
// random values.
func testElements(t *testing.T) []Element {
	m := ^uint64(0)
	es := []Element{
		{},
		{[7]uint64{1}},
		{[7]uint64{m - 1, m, m, m - 1<<32, m, m, m}}, // p-1
		p, // p
		{[7]uint64{0, 0, 0, m - 1<<32 + 1, m, m, m}}, // p+1
		{[7]uint64{m, m, m, m, m, m, m}},             // 2^448-1
		{[7]uint64{0, 0, 0, 1 << 32, 0, 0, 0}},       // 2^224
		{[7]uint64{m, m, m, 1<<32 - 1, 0, 0, 0}},     // 2^224-1
		{[7]uint64{0, 0, 0, 0, 0, 0, 1 << 63}},       // 2^447
		{[7]uint64{m, 0, m, 0, m, 0, m}},
		{[7]uint64{0, m, 0, m, 0, m, 0}},
		{[7]uint64{m, m, m, m - 1<<32, m, m, m}}, // p+2^64-1
		{[7]uint64{m - 1, m, m, m - 1<<32, m, m, m >> 1}},
	}
	for range 200 {
		var b [Size]byte
		rand.Read(b[:])
		var e Element
		if _, err := e.SetBytes(b[:]); err != nil {
			t.Fatal(err)
		}
		es = append(es, e)
	}
	return es
}

func TestArithmetic(t *testing.T) {
	es := testElements(t)
	mod := func(n *big.Int) *big.Int { return n.Mod(n, bigP) }
	for i := range es {
		a := &es[i]
		ab := rawBig(a)
		if got, want := toBig(a), mod(new(big.Int).Set(ab)); got.Cmp(want) != 0 {
			t.Fatalf("Bytes(%x) = %x, want %x", ab, got, want)
		}
		var inv Element
		inv.Invert(a)
		want := new(big.Int).ModInverse(mod(new(big.Int).Set(ab)), bigP)
		if want == nil {
			want = new(big.Int)
		}
		if got := toBig(&inv); got.Cmp(want) != 0 {
			t.Errorf("Invert(%x) = %x, want %x", ab, got, want)
		}
		for j := range es {
			b := &es[j]
			bb := rawBig(b)
			var v Element
			for _, op := range []struct {
				name string
				f    func() *Element
				want *big.Int
			}{
				{"Add", func() *Element { return v.Add(a, b) }, new(big.Int).Add(ab, bb)},
				{"Subtract", func() *Element { return v.Subtract(a, b) }, new(big.Int).Sub(ab, bb)},
				{"Multiply", func() *Element { return v.Multiply(a, b) }, new(big.Int).Mul(ab, bb)},
			} {
				r := op.f()
				if rawBig(r).BitLen() > 448 {
					t.Fatalf("%s(%x, %x) overflows", op.name, ab, bb)
				}
				if got, want := toBig(r), mod(op.want); got.Cmp(want) != 0 {
					t.Fatalf("%s(%x, %x) = %x, want %x", op.name, ab, bb, got, want)
				}
			}
		}
	}
}

func TestSqrtRatio(t *testing.T) {
	es := testElements(t)
	for i := range es {
		for j := range es[:20] {
			u, w := &es[i], &es[j]
			if w.IsZero() == 1 {
				continue
			}
			var r, check Element
			_, ok := r.SqrtRatio(u, w)
			// ok reports whether r²w = u.
			check.Square(&r)
			check.Multiply(&check, w)
			if got := check.Equal(u); got != ok {
				t.Errorf("SqrtRatio(%x, %x): ok = %d, r²w == u is %d", rawBig(u), rawBig(w), ok, got)
			}
			// Euler's criterion decides squareness.
			q := new(big.Int).Mul(toBig(u), new(big.Int).ModInverse(toBig(w), bigP))
			q.Mod(q, bigP)
			e := new(big.Int).Rsh(new(big.Int).Sub(bigP, big.NewInt(1)), 1)
			isSquare := q.Sign() == 0 || new(big.Int).Exp(q, e, bigP).Cmp(big.NewInt(1)) == 0
			if isSquare != (ok == 1) {
				t.Errorf("SqrtRatio(%x, %x): ok = %d, square = %v", rawBig(u), rawBig(w), ok, isSquare)
			}
		}
	}
}

func TestSelectSwap(t *testing.T) {
	a := Element{[7]uint64{1, 2, 3, 4, 5, 6, 7}}
	b := Element{[7]uint64{7, 6, 5, 4, 3, 2, 1}}
	var v Element
	if v.Select(&a, &b, 1); v != a {
		t.Error("Select(a, b, 1) != a")
	}
	if v.Select(&a, &b, 0); v != b {
		t.Error("Select(a, b, 0) != b")
	}
	x, y := a, b
	x.Swap(&y, 0)
	if x != a || y != b {
		t.Error("Swap(0) swapped")
	}
	x.Swap(&y, 1)
	if x != b || y != a {
		t.Error("Swap(1) did not swap")
	}
}

func TestBytes(t *testing.T) {
	var b [Size]byte
	for i := range b {
		b[i] = 0xff
	}
	var v Element
	if _, err := v.SetBytes(b[:]); err != nil {
		t.Fatal(err)
	}
	// 2^448-1 = p + 2^224.
	want := make([]byte, Size)
	want[28] = 1
	if got := v.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("Bytes(2^448-1) = %x, want %x", got, want)
	}
	if _, err := v.SetBytes(b[:Size-1]); err == nil {
		t.Error("SetBytes of 55 bytes succeeded")
	}
}

func BenchmarkMultiply(b *testing.B) {
	x := Element{[7]uint64{1, 2, 3, 4, 5, 6, 7}}
	for b.Loop() {
		x.Multiply(&x, &x)
	}
}

func BenchmarkInvert(b *testing.B) {
	x := Element{[7]uint64{1, 2, 3, 4, 5, 6, 7}}
	for b.Loop() {
		x.Invert(&x)
	}
}
