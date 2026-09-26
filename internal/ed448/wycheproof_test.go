package ed448

import (
	"encoding/json"
	"os"
	"testing"
)

//go:generate curl -sfLo testdata/ed448_test.json https://raw.githubusercontent.com/C2SP/wycheproof/3fa63dd0344abb611f1fb1d77e119938603ea230/testvectors_v1/ed448_test.json

// TestWycheproof checks the EdDSA verification vectors of Project
// Wycheproof, which are under the Apache License 2.0, with an empty
// context.
func TestWycheproof(t *testing.T) {
	b, err := os.ReadFile("testdata/ed448_test.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		NumberOfTests int `json:"numberOfTests"`
		TestGroups    []struct {
			PublicKey struct {
				PK string `json:"pk"`
			} `json:"publicKey"`
			Tests []struct {
				TcID    int      `json:"tcId"`
				Comment string   `json:"comment"`
				Flags   []string `json:"flags"`
				Msg     string   `json:"msg"`
				Sig     string   `json:"sig"`
				Result  string   `json:"result"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, g := range file.TestGroups {
		pub := unhex(t, g.PublicKey.PK)
		for _, tc := range g.Tests {
			n++
			want := tc.Result == "valid"
			if got := Verify(pub, unhex(t, tc.Msg), unhex(t, tc.Sig), ""); got != want {
				t.Errorf("tcId %d (%s %v): Verify = %v, want %v", tc.TcID, tc.Comment, tc.Flags, got, want)
			}
		}
	}
	if n == 0 || n != file.NumberOfTests {
		t.Fatalf("ran %d vectors, file declares %d", n, file.NumberOfTests)
	}
}
