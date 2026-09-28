package mls

//go:generate curl -sSfo testdata/welcome.json https://raw.githubusercontent.com/mlswg/mls-implementations/cfd450286d1bfd9cd2519b95c80f9771f94a5b1a/test-vectors/welcome.json

import (
	"bytes"
	"testing"
)

func TestWelcomeVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite CipherSuite `json:"cipher_suite"`
		InitPriv    hexBytes    `json:"init_priv"`
		SignerPub   hexBytes    `json:"signer_pub"`
		KeyPackage  hexBytes    `json:"key_package"`
		Welcome     hexBytes    `json:"welcome"`
	}
	loadVectors(t, "welcome", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}
	for _, vec := range vectors {
		cs := vec.CipherSuite
		t.Run(cs.String(), func(t *testing.T) {
			if !cs.Supported() {
				t.Skipf("%s is not supported", cs)
			}
			if _, err := cs.AEAD(make([]byte, cs.AEADKeySize())); err != nil {
				t.Skipf("%v", err)
			}
			var kpm, wm Message
			if err := Unmarshal(vec.KeyPackage, &kpm); err != nil {
				t.Fatalf("Unmarshal key package: %v", err)
			}
			if err := Unmarshal(vec.Welcome, &wm); err != nil {
				t.Fatalf("Unmarshal welcome: %v", err)
			}
			kp, w := kpm.KeyPackage, wm.Welcome

			ref, err := kp.Ref()
			if err != nil {
				t.Fatalf("KeyPackage.Ref: %v", err)
			}
			secrets, err := w.GroupSecrets(ref, vec.InitPriv)
			if err != nil {
				t.Fatalf("GroupSecrets: %v", err)
			}

			// With the joiner secret and no PSKs, the key
			// schedule gives the welcome secret that unwraps the
			// group info and the confirmation key that checks it.
			zero := make([]byte, cs.HashSize())
			member, err := cs.Extract(secrets.JoinerSecret, zero)
			if err != nil {
				t.Fatal(err)
			}
			welcomeSecret, err := cs.DeriveSecret(member, "welcome")
			if err != nil {
				t.Fatal(err)
			}
			info, err := w.GroupInfo(welcomeSecret)
			if err != nil {
				t.Fatalf("GroupInfo: %v", err)
			}
			if err := info.Verify(SignaturePublicKey(vec.SignerPub)); err != nil {
				t.Errorf("GroupInfo.Verify: %v", err)
			}

			ks, err := newKeySchedule(cs, secrets.JoinerSecret, nil, &info.GroupContext)
			if err != nil {
				t.Fatalf("newKeySchedule: %v", err)
			}
			tag, err := cs.ConfirmationTag(ks.ConfirmationKey, info.GroupContext.ConfirmedTranscriptHash)
			if err != nil {
				t.Fatalf("ConfirmationTag: %v", err)
			}
			if !bytes.Equal(tag, info.ConfirmationTag) {
				t.Errorf("confirmation tag = %x, want %x", tag, info.ConfirmationTag)
			}

			// Building the same welcome message again must round
			// trip back to the same group info and secrets.
			mine := &Welcome{CipherSuite: cs}
			if err := mine.SetGroupInfo(welcomeSecret, info); err != nil {
				t.Fatalf("SetGroupInfo: %v", err)
			}
			if err := mine.AddMember(ref, kp.InitKey, secrets); err != nil {
				t.Fatalf("AddMember: %v", err)
			}
			got, err := mine.GroupSecrets(ref, vec.InitPriv)
			if err != nil {
				t.Fatalf("GroupSecrets of our own welcome: %v", err)
			}
			if !bytes.Equal(got.JoinerSecret, secrets.JoinerSecret) {
				t.Errorf("joiner secret = %x, want %x", got.JoinerSecret, secrets.JoinerSecret)
			}
			if _, err := mine.GroupInfo(welcomeSecret); err != nil {
				t.Errorf("GroupInfo of our own welcome: %v", err)
			}
		})
	}
}
