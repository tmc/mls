package ed448

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRFC8032(t *testing.T) {
	for _, tc := range rfc8032Vectors {
		t.Run(tc.name, func(t *testing.T) {
			seed, pub, msg, sig := unhex(t, tc.seed), unhex(t, tc.pub), unhex(t, tc.msg), unhex(t, tc.sig)
			ctx := string(unhex(t, tc.context))
			priv, err := NewKeyFromSeed(seed)
			if err != nil {
				t.Fatal(err)
			}
			if got := priv.Public(); !bytes.Equal(got, pub) {
				t.Fatalf("public key = %x, want %x", got, pub)
			}
			got, err := Sign(priv, msg, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, sig) {
				t.Errorf("Sign = %x, want %x", got, sig)
			}
			if !Verify(pub, msg, sig, ctx) {
				t.Error("Verify = false")
			}
			if Verify(pub, msg, sig, ctx+"x") {
				t.Error("Verify under another context = true")
			}
		})
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("test message")
	sig, err := Sign(priv, msg, "")
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, msg, sig, "") {
		t.Fatal("Verify = false")
	}

	// Every single-bit change to the message, key or signature must
	// be refused.
	for _, tc := range []struct {
		name string
		b    []byte
	}{
		{"message", msg},
		{"public key", pub},
		{"signature", sig},
	} {
		for i := range tc.b {
			for bit := range 8 {
				tc.b[i] ^= 1 << bit
				if Verify(pub, msg, sig, "") {
					t.Fatalf("Verify with %s bit %d.%d flipped = true", tc.name, i, bit)
				}
				tc.b[i] ^= 1 << bit
			}
		}
	}

	// S + l encodes the same scalar but is not canonical.
	var s scalar
	s.setBytes(sig[encodedSize : encodedSize+scalarSize])
	sPlusL := new(big.Int).Add(toBig(&s), toBig(&order))
	bad := append([]byte(nil), sig...)
	le := sPlusL.FillBytes(make([]byte, scalarSize))
	for i := range le {
		bad[encodedSize+i] = le[scalarSize-1-i]
	}
	if Verify(pub, msg, bad, "") {
		t.Error("Verify with S+l = true")
	}

	if _, err := Sign(priv, msg, string(make([]byte, MaxContextSize+1))); err == nil {
		t.Error("Sign with a 256-byte context succeeded")
	}
	if _, err := Sign(priv[:SeedSize], msg, ""); err == nil {
		t.Error("Sign with a bare seed succeeded")
	}
	if _, err := NewKeyFromSeed(priv[:SeedSize-1]); err == nil {
		t.Error("NewKeyFromSeed with a short seed succeeded")
	}
}

// TestPointEncoding checks that noncanonical and off-curve encodings
// are refused.
func TestPointEncoding(t *testing.T) {
	enc := generator.bytes()
	var p point
	if _, err := p.setBytes(enc); err != nil {
		t.Fatalf("generator: %v", err)
	}
	if !bytes.Equal(p.bytes(), enc) {
		t.Fatal("generator does not round-trip")
	}

	pEnc := bytes.Repeat([]byte{0xff}, encodedSize) // y = p
	pEnc[28] = 0xfe
	pEnc[56] = 0
	one := make([]byte, encodedSize) // y = 1, x = 0: the identity
	one[0] = 1
	negZero := append([]byte(nil), one...) // x = 0 with the sign bit set
	negZero[56] = 0x80
	highBits := append([]byte(nil), enc...)
	highBits[56] |= 0x01
	short := enc[:encodedSize-1]
	for _, tc := range []struct {
		name string
		b    []byte
		ok   bool
	}{
		{"identity", one, true},
		{"y = p", pEnc, false},
		{"-0", negZero, false},
		{"high bits", highBits, false},
		{"short", short, false},
	} {
		_, err := p.setBytes(tc.b)
		if (err == nil) != tc.ok {
			t.Errorf("%s: setBytes error = %v, want ok = %v", tc.name, err, tc.ok)
		}
	}

	// y decodes exactly when (y²-1)/(dy²-1) is a square mod p.
	bigP := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 448), new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 224), big.NewInt(1)))
	bigD := new(big.Int).Sub(bigP, big.NewInt(39081))
	half := new(big.Int).Rsh(new(big.Int).Sub(bigP, big.NewInt(1)), 1)
	failures := 0
	for y := int64(2); y < 50; y++ {
		y2 := big.NewInt(y * y)
		u := new(big.Int).Sub(y2, big.NewInt(1))
		v := new(big.Int).Mul(bigD, y2)
		v.Sub(v, big.NewInt(1)).Mod(v, bigP)
		x2 := u.Mul(u, v.ModInverse(v, bigP)).Mod(u, bigP)
		square := new(big.Int).Exp(x2, half, bigP).Cmp(big.NewInt(1)) == 0
		b := make([]byte, encodedSize)
		b[0] = byte(y)
		_, err := p.setBytes(b)
		if (err == nil) != square {
			t.Errorf("y = %d: setBytes error = %v, square = %v", y, err, square)
		}
		if err != nil {
			failures++
		}
	}
	if failures == 0 {
		t.Error("no y in [2, 50) is off the curve")
	}
}

// TestGroupOrder checks that l·B is the identity and (l-1)·B = -B.
func TestGroupOrder(t *testing.T) {
	var lMinus1, one scalar
	one[0] = 1
	lMinus1 = order
	lMinus1[0]--
	var p, negB point
	p.scalarMult(&lMinus1, generator)
	negB.negate(generator)
	if !bytes.Equal(p.bytes(), negB.bytes()) {
		t.Error("(l-1)·B != -B")
	}
	p.add(&p, generator)
	var id point
	if !bytes.Equal(p.bytes(), id.identity().bytes()) {
		t.Error("(l-1)·B + B != identity")
	}
	// Doubling agrees with adding a point to itself.
	var dbl, sum point
	dbl.double(generator)
	sum.add(generator, generator)
	if !bytes.Equal(dbl.bytes(), sum.bytes()) {
		t.Error("2B by double != B + B")
	}
	var two scalar
	two[0] = 2
	var a, b point
	a.doubleScalarMult(&one, generator, &two, generator)
	b.scalarMult(&scalar{3}, generator)
	if !bytes.Equal(a.bytes(), b.bytes()) {
		t.Error("1·B + 2·B != 3·B")
	}
}

var bigL = func() *big.Int { return toBig(&order) }()

func toBig(s *scalar) *big.Int {
	n := new(big.Int)
	for i := len(s) - 1; i >= 0; i-- {
		n.Lsh(n, 64)
		n.Or(n, new(big.Int).SetUint64(s[i]))
	}
	return n
}

func leBig(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func TestScalar(t *testing.T) {
	var inputs [][]byte
	for _, n := range []int{56, 57, 114} {
		inputs = append(inputs, make([]byte, n), bytes.Repeat([]byte{0xff}, n))
		for range 100 {
			b := make([]byte, n)
			rand.Read(b)
			inputs = append(inputs, b)
		}
	}
	lb := order.bytes()
	inputs = append(inputs, lb, append(lb, 0))
	var ss []scalar
	for _, in := range inputs {
		var s scalar
		s.setBytes(in)
		want := new(big.Int).Mod(leBig(in), bigL)
		if got := toBig(&s); got.Cmp(want) != 0 {
			t.Fatalf("setBytes(%x) = %x, want %x", in, got, want)
		}
		ss = append(ss, s)
	}
	for i := range ss {
		for j := range ss[:20] {
			x, y := &ss[i], &ss[j]
			var z scalar
			want := new(big.Int).Add(toBig(x), toBig(y))
			if got := toBig(z.add(x, y)); got.Cmp(want.Mod(want, bigL)) != 0 {
				t.Fatalf("add(%x, %x) = %x, want %x", toBig(x), toBig(y), got, want)
			}
			want = new(big.Int).Mul(toBig(x), toBig(y))
			if got := toBig(z.multiply(x, y)); got.Cmp(want.Mod(want, bigL)) != 0 {
				t.Fatalf("multiply(%x, %x) = %x, want %x", toBig(x), toBig(y), got, want)
			}
		}
	}
}

func BenchmarkSign(b *testing.B) {
	_, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 64)
	for b.Loop() {
		if _, err := Sign(priv, msg, ""); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 64)
	sig, err := Sign(priv, msg, "")
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if !Verify(pub, msg, sig, "") {
			b.Fatal("Verify = false")
		}
	}
}
