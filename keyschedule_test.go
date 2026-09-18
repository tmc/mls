package mls

//go:generate curl -sSfo testdata/key-schedule.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/key-schedule.json
//go:generate curl -sSfo testdata/psk_secret.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/psk_secret.json
//go:generate curl -sSfo testdata/transcript-hashes.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/transcript-hashes.json

import (
	"bytes"
	"testing"
)

type keyScheduleVector struct {
	CipherSuite       CipherSuite `json:"cipher_suite"`
	GroupID           hexBytes    `json:"group_id"`
	InitialInitSecret hexBytes    `json:"initial_init_secret"`
	Epochs            []struct {
		TreeHash                hexBytes `json:"tree_hash"`
		CommitSecret            hexBytes `json:"commit_secret"`
		PSKSecret               hexBytes `json:"psk_secret"`
		ConfirmedTranscriptHash hexBytes `json:"confirmed_transcript_hash"`
		GroupContext            hexBytes `json:"group_context"`

		JoinerSecret  hexBytes `json:"joiner_secret"`
		WelcomeSecret hexBytes `json:"welcome_secret"`
		InitSecret    hexBytes `json:"init_secret"`

		SenderDataSecret   hexBytes `json:"sender_data_secret"`
		EncryptionSecret   hexBytes `json:"encryption_secret"`
		ExporterSecret     hexBytes `json:"exporter_secret"`
		EpochAuthenticator hexBytes `json:"epoch_authenticator"`
		ExternalSecret     hexBytes `json:"external_secret"`
		ConfirmationKey    hexBytes `json:"confirmation_key"`
		MembershipKey      hexBytes `json:"membership_key"`
		ResumptionPSK      hexBytes `json:"resumption_psk"`
		ExternalPub        hexBytes `json:"external_pub"`

		Exporter struct {
			Label   string   `json:"label"`
			Context hexBytes `json:"context"`
			Length  uint16   `json:"length"`
			Secret  hexBytes `json:"secret"`
		} `json:"exporter"`
	} `json:"epochs"`
}

func TestKeyScheduleVectors(t *testing.T) {
	var vectors []keyScheduleVector
	loadVectors(t, "key-schedule", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}
	for _, vec := range vectors {
		cs := vec.CipherSuite
		t.Run(cs.String(), func(t *testing.T) {
			if !cs.Supported() {
				t.Skipf("%s is not implementable with the Go standard library", cs)
			}
			initSecret := []byte(vec.InitialInitSecret)
			for i, e := range vec.Epochs {
				ctx := &GroupContext{
					Version:                 Version10,
					CipherSuite:             cs,
					GroupID:                 vec.GroupID,
					Epoch:                   uint64(i),
					TreeHash:                e.TreeHash,
					ConfirmedTranscriptHash: e.ConfirmedTranscriptHash,
				}
				if got, err := Marshal(ctx); err != nil {
					t.Fatalf("epoch %d: Marshal GroupContext: %v", i, err)
				} else if !bytes.Equal(got, e.GroupContext) {
					t.Fatalf("epoch %d: GroupContext = %x, want %x", i, got, e.GroupContext)
				}

				joiner, err := cs.JoinerSecret(initSecret, e.CommitSecret, ctx)
				if err != nil {
					t.Fatalf("epoch %d: JoinerSecret: %v", i, err)
				}
				if !bytes.Equal(joiner, e.JoinerSecret) {
					t.Errorf("epoch %d: joiner_secret = %x, want %x", i, joiner, e.JoinerSecret)
				}
				ks, err := NewKeySchedule(cs, joiner, e.PSKSecret, ctx)
				if err != nil {
					t.Fatalf("epoch %d: NewKeySchedule: %v", i, err)
				}
				for _, f := range []struct {
					name string
					got  []byte
					want hexBytes
				}{
					{"welcome_secret", ks.WelcomeSecret, e.WelcomeSecret},
					{"sender_data_secret", ks.SenderDataSecret, e.SenderDataSecret},
					{"encryption_secret", ks.EncryptionSecret, e.EncryptionSecret},
					{"exporter_secret", ks.ExporterSecret, e.ExporterSecret},
					{"epoch_authenticator", ks.EpochAuthenticator, e.EpochAuthenticator},
					{"external_secret", ks.ExternalSecret, e.ExternalSecret},
					{"confirmation_key", ks.ConfirmationKey, e.ConfirmationKey},
					{"membership_key", ks.MembershipKey, e.MembershipKey},
					{"resumption_psk", ks.ResumptionPSK, e.ResumptionPSK},
					{"init_secret", ks.InitSecret, e.InitSecret},
				} {
					if !bytes.Equal(f.got, f.want) {
						t.Errorf("epoch %d: %s = %x, want %x", i, f.name, f.got, f.want)
					}
				}
				if pub, err := ks.ExternalPub(); err != nil {
					t.Errorf("epoch %d: ExternalPub: %v", i, err)
				} else if !bytes.Equal(pub, e.ExternalPub) {
					t.Errorf("epoch %d: external_pub = %x, want %x", i, pub, e.ExternalPub)
				}
				x := e.Exporter
				if got, err := ks.Export(x.Label, x.Context, x.Length); err != nil {
					t.Errorf("epoch %d: Export: %v", i, err)
				} else if !bytes.Equal(got, x.Secret) {
					t.Errorf("epoch %d: Export = %x, want %x", i, got, x.Secret)
				}
				initSecret = ks.InitSecret
			}
		})
	}
}

func TestPSKSecretVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite CipherSuite `json:"cipher_suite"`
		PSKs        []struct {
			PSKID    hexBytes `json:"psk_id"`
			PSK      hexBytes `json:"psk"`
			PSKNonce hexBytes `json:"psk_nonce"`
		} `json:"psks"`
		PSKSecret hexBytes `json:"psk_secret"`
	}
	loadVectors(t, "psk_secret", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}
	for _, vec := range vectors {
		cs := vec.CipherSuite
		t.Run(cs.String(), func(t *testing.T) {
			if !cs.Supported() {
				t.Skipf("%s is not implementable with the Go standard library", cs)
			}
			ids := make([]PreSharedKeyID, len(vec.PSKs))
			psks := make([][]byte, len(vec.PSKs))
			for i, p := range vec.PSKs {
				ids[i] = PreSharedKeyID{
					Type:     PSKTypeExternal,
					PSKID:    p.PSKID,
					PSKNonce: p.PSKNonce,
				}
				psks[i] = p.PSK
			}
			got, err := cs.PSKSecret(ids, psks)
			if err != nil {
				t.Fatalf("PSKSecret: %v", err)
			}
			if !bytes.Equal(got, vec.PSKSecret) {
				t.Errorf("psk_secret = %x, want %x", got, vec.PSKSecret)
			}
		})
	}
}

func TestTranscriptHashVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite          CipherSuite `json:"cipher_suite"`
		ConfirmationKey      hexBytes    `json:"confirmation_key"`
		AuthenticatedContent hexBytes    `json:"authenticated_content"`
		InterimBefore        hexBytes    `json:"interim_transcript_hash_before"`
		ConfirmedAfter       hexBytes    `json:"confirmed_transcript_hash_after"`
		InterimAfter         hexBytes    `json:"interim_transcript_hash_after"`
	}
	loadVectors(t, "transcript-hashes", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}
	for _, vec := range vectors {
		cs := vec.CipherSuite
		t.Run(cs.String(), func(t *testing.T) {
			if !cs.Supported() {
				t.Skipf("%s is not implementable with the Go standard library", cs)
			}
			var c AuthenticatedContent
			if err := Unmarshal(vec.AuthenticatedContent, &c); err != nil {
				t.Fatalf("Unmarshal AuthenticatedContent: %v", err)
			}
			confirmed, err := cs.ConfirmedTranscriptHash(vec.InterimBefore, &c)
			if err != nil {
				t.Fatalf("ConfirmedTranscriptHash: %v", err)
			}
			if !bytes.Equal(confirmed, vec.ConfirmedAfter) {
				t.Errorf("confirmed transcript hash = %x, want %x", confirmed, vec.ConfirmedAfter)
			}
			tag, err := cs.ConfirmationTag(vec.ConfirmationKey, confirmed)
			if err != nil {
				t.Fatalf("ConfirmationTag: %v", err)
			}
			if !bytes.Equal(tag, c.Auth.ConfirmationTag) {
				t.Errorf("confirmation tag = %x, want %x", tag, c.Auth.ConfirmationTag)
			}
			interim, err := cs.InterimTranscriptHash(confirmed, c.Auth.ConfirmationTag)
			if err != nil {
				t.Fatalf("InterimTranscriptHash: %v", err)
			}
			if !bytes.Equal(interim, vec.InterimAfter) {
				t.Errorf("interim transcript hash = %x, want %x", interim, vec.InterimAfter)
			}
		})
	}
}
