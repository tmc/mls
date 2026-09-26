package x448

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

//go:generate curl -sfLo testdata/x448_test.json https://raw.githubusercontent.com/C2SP/wycheproof/3fa63dd0344abb611f1fb1d77e119938603ea230/testvectors_v1/x448_test.json

// TestWycheproof checks the XDH vectors of Project Wycheproof, which
// are under the Apache License 2.0. A vector whose result is all zero
// must be rejected, since X448 reports that as an error. Any other
// vector marked acceptable may be rejected only for a public key that
// is not Size bytes; otherwise the result must be right.
func TestWycheproof(t *testing.T) {
	b, err := os.ReadFile("testdata/x448_test.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		NumberOfTests int `json:"numberOfTests"`
		TestGroups    []struct {
			Tests []struct {
				TcID    int      `json:"tcId"`
				Comment string   `json:"comment"`
				Flags   []string `json:"flags"`
				Public  string   `json:"public"`
				Private string   `json:"private"`
				Shared  string   `json:"shared"`
				Result  string   `json:"result"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, g := range file.TestGroups {
		for _, tc := range g.Tests {
			n++
			priv, pub, want := unhex(t, tc.Private), unhex(t, tc.Public), unhex(t, tc.Shared)
			got, err := X448(priv, pub)
			zero := bytes.Equal(want, make([]byte, Size))
			switch {
			case zero && err == nil:
				t.Errorf("tcId %d (%s %v): accepted a low-order point", tc.TcID, tc.Comment, tc.Flags)
			case tc.Result == "invalid" && err == nil:
				t.Errorf("tcId %d (%s %v): accepted an invalid input", tc.TcID, tc.Comment, tc.Flags)
			case err != nil && (tc.Result == "valid" || len(pub) == Size && !zero):
				t.Errorf("tcId %d (%s %v): %v", tc.TcID, tc.Comment, tc.Flags, err)
			case tc.Result != "invalid" && err == nil && !bytes.Equal(got, want):
				t.Errorf("tcId %d (%s %v): got %s, want %s", tc.TcID, tc.Comment, tc.Flags, hex.EncodeToString(got), tc.Shared)
			}
		}
	}
	if n == 0 || n != file.NumberOfTests {
		t.Fatalf("ran %d vectors, file declares %d", n, file.NumberOfTests)
	}
}
