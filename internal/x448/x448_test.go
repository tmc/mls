package x448

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"testing"
)

var million = flag.Bool("million", false, "run the 1,000,000-iteration test of RFC 7748, Section 5.2")

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestVectors checks the vectors of RFC 7748, Sections 5.2 and 6.2.
func TestVectors(t *testing.T) {
	for _, tc := range []struct {
		name, scalar, point, want string
	}{
		{
			"5.2 first",
			"3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
			"06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
			"ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
		},
		{
			"5.2 second",
			"203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
			"0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
			"884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d",
		},
		{
			"6.2 alice public",
			"9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
			hex.EncodeToString(Basepoint),
			"9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
		},
		{
			"6.2 bob public",
			"1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
			hex.EncodeToString(Basepoint),
			"3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
		},
		{
			"6.2 alice shared",
			"9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
			"3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
			"07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
		},
		{
			"6.2 bob shared",
			"1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
			"9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
			"07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := X448(unhex(t, tc.scalar), unhex(t, tc.point))
			if err != nil {
				t.Fatal(err)
			}
			if want := unhex(t, tc.want); !bytes.Equal(got, want) {
				t.Errorf("X448 = %x, want %x", got, want)
			}
		})
	}
}

// TestIterated runs the iterated test of RFC 7748, Section 5.2. The
// 1,000,000-iteration step takes minutes and runs only with -million.
func TestIterated(t *testing.T) {
	steps := []struct {
		n    int
		want string
	}{
		{1, "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"},
		{1000, "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38"},
		{1000000, "077f453681caca3693198420bbe515cae0002472519b3e67661a7e89cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37"},
	}
	k := append([]byte(nil), Basepoint...)
	u := append([]byte(nil), Basepoint...)
	i := 0
	for _, s := range steps {
		if s.n == 1000000 && !*million {
			t.Log("skipping 1,000,000 iterations; run with -million")
			return
		}
		for ; i < s.n; i++ {
			var out [Size]byte
			x448(&out, k, u)
			u = k
			k = out[:]
		}
		if want := unhex(t, s.want); !bytes.Equal(k, want) {
			t.Fatalf("after %d iterations: %x, want %x", s.n, k, want)
		}
	}
}

// TestLowOrder checks that the points of small order, and their
// non-canonical encodings, are refused. See RFC 7748, Section 6.2.
func TestLowOrder(t *testing.T) {
	scalar := make([]byte, Size)
	rand.Read(scalar)
	one := make([]byte, Size)
	one[0] = 1
	pMinus1 := bytes.Repeat([]byte{0xff}, Size)
	pMinus1[0] = 0xfe
	pMinus1[28] = 0xfe
	p := bytes.Repeat([]byte{0xff}, Size) // p = 0 mod p
	p[28] = 0xfe
	pPlus1 := make([]byte, Size) // p+1 = 1 mod p
	pPlus1[28] = 0xff
	for i := 29; i < Size; i++ {
		pPlus1[i] = 0xff
	}
	for _, point := range [][]byte{make([]byte, Size), one, pMinus1, p, pPlus1} {
		if out, err := X448(scalar, point); err == nil {
			t.Errorf("X448(k, %x) = %x, want error", point, out)
		}
	}
}

func TestLengths(t *testing.T) {
	good := make([]byte, Size)
	good[0] = 5
	for _, tc := range []struct{ scalar, point []byte }{
		{good[:Size-1], good},
		{good, good[:Size-1]},
		{append(good, 0), good},
	} {
		if _, err := X448(tc.scalar, tc.point); err == nil {
			t.Errorf("X448 with lengths %d, %d succeeded", len(tc.scalar), len(tc.point))
		}
	}
}

func BenchmarkScalarMult(b *testing.B) {
	scalar := make([]byte, Size)
	rand.Read(scalar)
	point, err := X448(scalar, Basepoint)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, err := X448(scalar, point); err != nil {
			b.Fatal(err)
		}
	}
}
