package mls

//go:generate curl -sSfo testdata/message-protection.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/message-protection.json

import (
	"bytes"
	"errors"
	"testing"
)

type messageProtectionVector struct {
	CipherSuite             CipherSuite `json:"cipher_suite"`
	GroupID                 hexBytes    `json:"group_id"`
	Epoch                   uint64      `json:"epoch"`
	TreeHash                hexBytes    `json:"tree_hash"`
	ConfirmedTranscriptHash hexBytes    `json:"confirmed_transcript_hash"`

	SignaturePriv hexBytes `json:"signature_priv"`
	SignaturePub  hexBytes `json:"signature_pub"`

	EncryptionSecret hexBytes `json:"encryption_secret"`
	SenderDataSecret hexBytes `json:"sender_data_secret"`
	MembershipKey    hexBytes `json:"membership_key"`

	Proposal     hexBytes `json:"proposal"`
	ProposalPub  hexBytes `json:"proposal_pub"`
	ProposalPriv hexBytes `json:"proposal_priv"`

	Commit     hexBytes `json:"commit"`
	CommitPub  hexBytes `json:"commit_pub"`
	CommitPriv hexBytes `json:"commit_priv"`

	Application     hexBytes `json:"application"`
	ApplicationPriv hexBytes `json:"application_priv"`
}

// The vectors all use the member at leaf 1 of a two-member group.
const (
	protectionSender  = LeafIndex(1)
	protectionMembers = LeafIndex(2)
)

func (vec *messageProtectionVector) groupContext() *GroupContext {
	return &GroupContext{
		Version:                 Version10,
		CipherSuite:             vec.CipherSuite,
		GroupID:                 vec.GroupID,
		Epoch:                   vec.Epoch,
		TreeHash:                vec.TreeHash,
		ConfirmedTranscriptHash: vec.ConfirmedTranscriptHash,
	}
}

// content builds the framed content of one of the vector's messages.
func (vec *messageProtectionVector) content(t *testing.T, typ ContentType, raw []byte) *AuthenticatedContent {
	t.Helper()
	c := &AuthenticatedContent{
		Content: FramedContent{
			GroupID:     vec.GroupID,
			Epoch:       vec.Epoch,
			Sender:      Sender{Type: SenderTypeMember, LeafIndex: uint32(protectionSender)},
			ContentType: typ,
		},
	}
	switch typ {
	case ContentTypeApplication:
		c.Content.ApplicationData = raw
	case ContentTypeProposal:
		c.Content.Proposal = new(Proposal)
		if err := Unmarshal(raw, c.Content.Proposal); err != nil {
			t.Fatalf("Unmarshal Proposal: %v", err)
		}
	case ContentTypeCommit:
		c.Content.Commit = new(Commit)
		if err := Unmarshal(raw, c.Content.Commit); err != nil {
			t.Fatalf("Unmarshal Commit: %v", err)
		}
	}
	return c
}

// raw re-encodes the variant body of c, for comparison with the
// vector's plaintext.
func raw(t *testing.T, c *AuthenticatedContent) []byte {
	t.Helper()
	switch c.Content.ContentType {
	case ContentTypeApplication:
		return c.Content.ApplicationData
	case ContentTypeProposal:
		b, err := Marshal(c.Content.Proposal)
		if err != nil {
			t.Fatal(err)
		}
		return b
	default:
		b, err := Marshal(c.Content.Commit)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
}

func TestMessageProtectionVectors(t *testing.T) {
	var vectors []messageProtectionVector
	loadVectors(t, "message-protection", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}
	for _, vec := range vectors {
		cs := vec.CipherSuite
		t.Run(cs.String(), func(t *testing.T) {
			if !cs.Supported() {
				t.Skipf("%s is not implementable with the Go standard library", cs)
			}
			if _, err := cs.AEAD(make([]byte, cs.AEADKeySize())); err != nil {
				t.Skipf("%v", err)
			}
			ctx := vec.groupContext()
			pub := SignaturePublicKey(vec.SignaturePub)

			for _, tt := range []struct {
				name string
				typ  ContentType
				raw  hexBytes
				pub  hexBytes
				priv hexBytes
			}{
				{"proposal", ContentTypeProposal, vec.Proposal, vec.ProposalPub, vec.ProposalPriv},
				{"commit", ContentTypeCommit, vec.Commit, vec.CommitPub, vec.CommitPriv},
				{"application", ContentTypeApplication, vec.Application, nil, vec.ApplicationPriv},
			} {
				t.Run(tt.name, func(t *testing.T) {
					want := vec.content(t, tt.typ, tt.raw)

					if tt.pub != nil {
						var m Message
						if err := Unmarshal(tt.pub, &m); err != nil {
							t.Fatalf("Unmarshal public message: %v", err)
						}
						got, err := m.PublicMessage.AuthenticatedContent(cs, vec.MembershipKey, ctx)
						if err != nil {
							t.Fatalf("unprotect public message: %v", err)
						}
						if err := got.Verify(cs, pub, ctx.Version, ctx); err != nil {
							t.Errorf("verify public message: %v", err)
						}
						if !bytes.Equal(raw(t, got), tt.raw) {
							t.Errorf("public message content = %x, want %x", raw(t, got), tt.raw)
						}
					}

					// Protecting as a PublicMessage must round
					// trip, except for application data, which
					// may not be sent in the clear at all.
					want.WireFormat = WireFormatPublicMessage
					if err := want.Sign(cs, vec.SignaturePriv, ctx.Version, ctx); err != nil {
						t.Fatalf("Sign: %v", err)
					}
					mine, err := want.PublicMessage(cs, vec.MembershipKey, ctx)
					switch {
					case tt.typ == ContentTypeApplication:
						if !errors.Is(err, ErrApplicationNotEncrypted) {
							t.Errorf("PublicMessage of application data = %v, want ErrApplicationNotEncrypted", err)
						}
					case err != nil:
						t.Fatalf("PublicMessage: %v", err)
					default:
						got, err := mine.AuthenticatedContent(cs, vec.MembershipKey, ctx)
						if err != nil {
							t.Fatalf("unprotect our own public message: %v", err)
						}
						if err := got.Verify(cs, pub, ctx.Version, ctx); err != nil {
							t.Errorf("verify our own public message: %v", err)
						}
					}

					var m Message
					if err := Unmarshal(tt.priv, &m); err != nil {
						t.Fatalf("Unmarshal private message: %v", err)
					}
					tree := NewSecretTree(cs, protectionMembers, vec.EncryptionSecret)
					got, err := m.PrivateMessage.AuthenticatedContent(cs, tree, vec.SenderDataSecret)
					if err != nil {
						t.Fatalf("unprotect private message: %v", err)
					}
					if err := got.Verify(cs, pub, ctx.Version, ctx); err != nil {
						t.Errorf("verify private message: %v", err)
					}
					if !bytes.Equal(raw(t, got), tt.raw) {
						t.Errorf("private message content = %x, want %x", raw(t, got), tt.raw)
					}

					// And our own encryption must decrypt.
					send := NewSecretTree(cs, protectionMembers, vec.EncryptionSecret)
					r, err := send.Ratchet(protectionSender, tt.typ)
					if err != nil {
						t.Fatalf("Ratchet: %v", err)
					}
					want.WireFormat = WireFormatPrivateMessage
					if err := want.Sign(cs, vec.SignaturePriv, ctx.Version, ctx); err != nil {
						t.Fatalf("Sign: %v", err)
					}
					enc, err := want.PrivateMessage(cs, r, vec.SenderDataSecret, 16)
					if err != nil {
						t.Fatalf("PrivateMessage: %v", err)
					}
					recv := NewSecretTree(cs, protectionMembers, vec.EncryptionSecret)
					got, err = enc.AuthenticatedContent(cs, recv, vec.SenderDataSecret)
					if err != nil {
						t.Fatalf("unprotect our own private message: %v", err)
					}
					if err := got.Verify(cs, pub, ctx.Version, ctx); err != nil {
						t.Errorf("verify our own private message: %v", err)
					}
					if !bytes.Equal(raw(t, got), tt.raw) {
						t.Errorf("round trip content = %x, want %x", raw(t, got), tt.raw)
					}
				})
			}
		})
	}
}

// The sender data names the leaf a message comes from, and is sealed
// under a secret every member of the epoch holds. A member can
// therefore name another member's leaf; a message that does not
// decrypt must not spend that leaf's keys.
func TestSenderDataDoesNotSpendKeys(t *testing.T) {
	a, b, c := threeMember(t)
	cs := a.CipherSuite

	// Carol forges sender data naming Bob's leaf.
	m, err := c.Protect(nil, []byte("filler"))
	if err != nil {
		t.Fatal(err)
	}
	forged, err := m.PrivateMessage.sealSenderData(cs, c.Schedule.SenderDataSecret, &SenderData{
		LeafIndex:  uint32(b.Index),
		Generation: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	m.PrivateMessage.EncryptedSenderData = forged
	if _, err := a.Unprotect(send(t, m)); err == nil {
		t.Fatal("a forged message decrypted")
	}

	// Bob's own message must still be readable.
	real, err := b.Protect(nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Unprotect(send(t, real)); err != nil {
		t.Errorf("a rejected message silenced leaf %d: %v", b.Index, err)
	}
}

// A generation far ahead of the ratchet costs one derivation per
// step, so it must be refused rather than walked.
func TestSenderDataGenerationBound(t *testing.T) {
	a, b, _ := threeMember(t)
	cs := a.CipherSuite

	m, err := b.Protect(nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	forged, err := m.PrivateMessage.sealSenderData(cs, b.Schedule.SenderDataSecret, &SenderData{
		LeafIndex:  uint32(b.Index),
		Generation: 1 << 31,
	})
	if err != nil {
		t.Fatal(err)
	}
	m.PrivateMessage.EncryptedSenderData = forged
	if _, err := a.Unprotect(send(t, m)); err != ErrGenerationJump {
		t.Errorf("Unprotect = %v, want %v", err, ErrGenerationJump)
	}
}
