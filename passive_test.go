package mls

//go:generate curl -sSfo testdata/passive-client-welcome.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/passive-client-welcome.json
//go:generate curl -sSfo testdata/passive-client-random.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/passive-client-random.json
//go:generate curl -sSfo testdata/passive-client-handling-commit.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/passive-client-handling-commit.json

import (
	"bytes"
	"fmt"
	"testing"
)

type passiveVector struct {
	CipherSuite  CipherSuite `json:"cipher_suite"`
	ExternalPSKs []struct {
		PSKID hexBytes `json:"psk_id"`
		PSK   hexBytes `json:"psk"`
	} `json:"external_psks"`

	KeyPackage     hexBytes `json:"key_package"`
	SignaturePriv  hexBytes `json:"signature_priv"`
	EncryptionPriv hexBytes `json:"encryption_priv"`
	InitPriv       hexBytes `json:"init_priv"`

	Welcome                   hexBytes `json:"welcome"`
	RatchetTree               hexBytes `json:"ratchet_tree"`
	InitialEpochAuthenticator hexBytes `json:"initial_epoch_authenticator"`

	Epochs []struct {
		Proposals          []hexBytes `json:"proposals"`
		Commit             hexBytes   `json:"commit"`
		EpochAuthenticator hexBytes   `json:"epoch_authenticator"`
	} `json:"epochs"`
}

func TestPassiveClientVectors(t *testing.T) {
	for _, name := range []string{
		"passive-client-welcome",
		"passive-client-random",
		"passive-client-handling-commit",
	} {
		t.Run(name, func(t *testing.T) {
			var vectors []passiveVector
			loadVectors(t, name, &vectors)
			if len(vectors) == 0 {
				t.Fatal("no test vectors")
			}
			for i, vec := range vectors {
				t.Run(fmt.Sprintf("%d/%s", i, vec.CipherSuite), func(t *testing.T) {
					cs := vec.CipherSuite
					if !cs.Supported() {
						t.Skipf("%s is not implementable with the Go standard library", cs)
					}
					if _, err := cs.AEAD(make([]byte, cs.AEADKeySize())); err != nil {
						t.Skipf("%v", err)
					}
					testPassiveClient(t, &vec)
				})
			}
		})
	}
}

func testPassiveClient(t *testing.T, vec *passiveVector) {
	cs := vec.CipherSuite
	m := new(Message)
	if err := Unmarshal(vec.KeyPackage, m); err != nil {
		t.Fatalf("key_package: %v", err)
	}
	kp := m.KeyPackage
	if kp == nil {
		t.Fatal("key_package is not a KeyPackage message")
	}
	if pub, err := cs.PublicKey(vec.InitPriv); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(pub, kp.InitKey) {
		t.Error("init_priv does not match the key package's init key")
	}
	if pub, err := cs.PublicKey(vec.EncryptionPriv); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(pub, kp.LeafNode.EncryptionKey) {
		t.Error("encryption_priv does not match the leaf node's encryption key")
	}
	if err := kp.Verify(); err != nil {
		t.Errorf("key package signature: %v", err)
	}

	client := &Client{
		CipherSuite:    cs,
		KeyPackage:     kp,
		InitPriv:       vec.InitPriv,
		EncryptionPriv: vec.EncryptionPriv,
		SignaturePriv:  vec.SignaturePriv,
		PSK: func(id PreSharedKeyID) ([]byte, error) {
			for _, p := range vec.ExternalPSKs {
				if id.Type == PSKTypeExternal && bytes.Equal(id.PSKID, p.PSKID) {
					return p.PSK, nil
				}
			}
			return nil, ErrUnknownPSK
		},
	}

	welcome := new(Message)
	if err := Unmarshal(vec.Welcome, welcome); err != nil {
		t.Fatalf("welcome: %v", err)
	}
	if welcome.Welcome == nil {
		t.Fatal("welcome is not a Welcome message")
	}
	var tree RatchetTree
	if vec.RatchetTree != nil {
		if err := Unmarshal(vec.RatchetTree, &tree); err != nil {
			t.Fatalf("ratchet_tree: %v", err)
		}
	}
	g, err := client.Join(welcome.Welcome, tree)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if !bytes.Equal(g.EpochAuthenticator(), vec.InitialEpochAuthenticator) {
		t.Fatalf("initial epoch authenticator = %x, want %x", g.EpochAuthenticator(), vec.InitialEpochAuthenticator)
	}

	for i, epoch := range vec.Epochs {
		for j, raw := range epoch.Proposals {
			m := new(Message)
			if err := Unmarshal(raw, m); err != nil {
				t.Fatalf("epoch %d: proposal %d: %v", i, j, err)
			}
			if g, err = g.Handle(m); err != nil {
				t.Fatalf("epoch %d: proposal %d: %v", i, j, err)
			}
		}
		m := new(Message)
		if err := Unmarshal(epoch.Commit, m); err != nil {
			t.Fatalf("epoch %d: commit: %v", i, err)
		}
		if g, err = g.Handle(m); err != nil {
			t.Fatalf("epoch %d: commit: %v", i, err)
		}
		if !bytes.Equal(g.EpochAuthenticator(), epoch.EpochAuthenticator) {
			t.Fatalf("epoch %d: authenticator = %x, want %x", i, g.EpochAuthenticator(), epoch.EpochAuthenticator)
		}
	}
}
