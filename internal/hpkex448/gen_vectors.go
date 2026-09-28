//go:build ignore

// gen_vectors writes testdata/rfc9180-x448.json from the CFRG HPKE
// draft repository's test-vectors.json, keeping the base-mode vectors
// of DHKEM(X448, HKDF-SHA512) and HKDF-SHA512 with a real AEAD, and of
// each, the encryptions at sequence numbers 0, 1, 255 and 256.
//
//	go run gen_vectors.go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

const url = "https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb/test-vectors.json"

type encryption struct {
	AAD   string `json:"aad"`
	CT    string `json:"ct"`
	Nonce string `json:"nonce"`
	PT    string `json:"pt"`
	Seq   int    `json:"seq"`
}

type export struct {
	Context string `json:"exporter_context"`
	L       int    `json:"L"`
	Value   string `json:"exported_value"`
}

type vector struct {
	Mode  int `json:"mode,omitempty"`
	KEMID int `json:"kem_id,omitempty"`
	KDFID int `json:"kdf_id,omitempty"`

	AEADID         int          `json:"aead_id"`
	Info           string       `json:"info"`
	IKME           string       `json:"ikmE"`
	IKMR           string       `json:"ikmR"`
	SKRm           string       `json:"skRm"`
	PKRm           string       `json:"pkRm"`
	SKEm           string       `json:"skEm"`
	PKEm           string       `json:"pkEm"`
	Enc            string       `json:"enc"`
	SharedSecret   string       `json:"shared_secret"`
	Key            string       `json:"key"`
	BaseNonce      string       `json:"base_nonce"`
	ExporterSecret string       `json:"exporter_secret"`
	Encryptions    []encryption `json:"encryptions"`
	Exports        []export     `json:"exports"`
}

func main() {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("get %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var all []vector
	if err := json.Unmarshal(data, &all); err != nil {
		log.Fatal(err)
	}

	var out []vector
	for _, v := range all {
		if v.Mode != 0 || v.KEMID != 0x21 || v.KDFID != 3 || v.AEADID == 0xffff {
			continue
		}
		var encs []encryption
		for _, seq := range []int{0, 1, 255, 256} {
			e := v.Encryptions[seq]
			e.Seq = seq
			encs = append(encs, e)
		}
		v.Mode, v.KEMID, v.KDFID = 0, 0, 0
		v.Encryptions = encs
		out = append(out, v)
	}
	if len(out) == 0 {
		log.Fatal("no vectors")
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("testdata/rfc9180-x448.json", fmt.Appendf(b, "\n"), 0o666); err != nil {
		log.Fatal(err)
	}
}
