package mls

//go:generate curl -sSfo testdata/message-protection.json https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/message-protection.json

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
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

// openPrivate decrypts m under tree without checking the signature,
// spending the key it used.
func openPrivate(cs CipherSuite, m *PrivateMessage, tree *secretTree, senderDataSecret []byte) (*AuthenticatedContent, error) {
	data, err := m.openSenderData(cs, senderDataSecret)
	if err != nil {
		return nil, err
	}
	c, advance, err := m.authenticatedContent(cs, tree, data)
	if err != nil {
		return nil, err
	}
	advance()
	return c, nil
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
					tree := newSecretTree(cs, protectionMembers, vec.EncryptionSecret)
					got, err := openPrivate(cs, m.PrivateMessage, tree, vec.SenderDataSecret)
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
					send := newSecretTree(cs, protectionMembers, vec.EncryptionSecret)
					r, err := send.ratchet(protectionSender, tt.typ)
					if err != nil {
						t.Fatalf("ratchet: %v", err)
					}
					want.WireFormat = WireFormatPrivateMessage
					if err := want.Sign(cs, vec.SignaturePriv, ctx.Version, ctx); err != nil {
						t.Fatalf("Sign: %v", err)
					}
					enc, err := want.privateMessage(cs, r, vec.SenderDataSecret, 16)
					if err != nil {
						t.Fatalf("PrivateMessage: %v", err)
					}
					recv := newSecretTree(cs, protectionMembers, vec.EncryptionSecret)
					got, err = openPrivate(cs, enc, recv, vec.SenderDataSecret)
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
	forged, err := m.PrivateMessage.sealSenderData(cs, c.schedule.SenderDataSecret, &SenderData{
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

// Every member of an epoch can derive every leaf's keys, so a message
// that decrypts under Bob's keys may still come from Carol. Only Bob's
// signature may spend Bob's keys.
func TestForgedSignatureDoesNotSpendKeys(t *testing.T) {
	a, b, c := threeMember(t)
	cs := a.CipherSuite

	// Carol encrypts under Bob's ratchet, a few generations on,
	// content that names Bob but carries her own signature.
	r, err := c.keys.ratchet(b.Index, ContentTypeApplication)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, _, err := r.Next(); err != nil {
			t.Fatal(err)
		}
	}
	forged := &AuthenticatedContent{
		WireFormat: WireFormatPrivateMessage,
		Content: FramedContent{
			GroupID:         c.Context.GroupID,
			Epoch:           c.Context.Epoch,
			Sender:          Sender{Type: SenderTypeMember, LeafIndex: uint32(b.Index)},
			ContentType:     ContentTypeApplication,
			ApplicationData: []byte("from bob, honestly"),
		},
	}
	if err := forged.Sign(cs, c.client.SignaturePriv, c.Context.Version, &c.Context); err != nil {
		t.Fatal(err)
	}
	pm, err := forged.privateMessage(cs, r, c.schedule.SenderDataSecret, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := &Message{Version: c.Context.Version, WireFormat: WireFormatPrivateMessage, PrivateMessage: pm}
	if _, err := a.Unprotect(send(t, m)); err == nil {
		t.Fatal("a message with a forged signature was accepted")
	}

	real, err := b.Protect(nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Unprotect(send(t, real)); err != nil {
		t.Errorf("a forged signature spent leaf %d's keys: %v", b.Index, err)
	}
}

func TestUnprotectRejects(t *testing.T) {
	a, b, _ := threeMember(t)
	cs := b.CipherSuite

	// Application data in the clear, correctly signed and tagged.
	clear := &AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content: FramedContent{
			GroupID:         b.Context.GroupID,
			Epoch:           b.Context.Epoch,
			Sender:          Sender{Type: SenderTypeMember, LeafIndex: uint32(b.Index)},
			ContentType:     ContentTypeApplication,
			ApplicationData: []byte("hello"),
		},
	}
	if err := clear.Sign(cs, b.client.SignaturePriv, b.Context.Version, &b.Context); err != nil {
		t.Fatal(err)
	}
	tag, err := cs.MembershipTag(b.schedule.MembershipKey, clear, b.Context.Version, &b.Context)
	if err != nil {
		t.Fatal(err)
	}
	public := &Message{
		Version:       b.Context.Version,
		WireFormat:    WireFormatPublicMessage,
		PublicMessage: &PublicMessage{Content: clear.Content, Auth: clear.Auth, MembershipTag: tag},
	}

	private := func() *Message {
		m, err := b.Protect(nil, []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	version := private()
	version.Version = 0xff
	wire := private()
	wire.WireFormat = WireFormatPublicMessage

	for _, tt := range []struct {
		name string
		m    *Message
		want error
	}{
		{"public application", send(t, public), ErrApplicationNotEncrypted},
		{"version", send(t, version), ErrUnsupportedVersion},
		{"wire format", wire, ErrNotForGroup},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := a.Unprotect(tt.m); !errors.Is(err, tt.want) {
				t.Errorf("Unprotect = %v, want %v", err, tt.want)
			}
		})
	}
}

// Encoding a message only reads it, so one message may be encoded
// from several goroutines at once. Run under -race.
func TestMarshalConcurrent(t *testing.T) {
	a, _, _ := threeMember(t)
	cs := a.CipherSuite
	m, err := a.Propose(&Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 2}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.PublicMessage.AuthenticatedContent(cs, a.schedule.MembershipKey, &a.Context)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if _, err := Marshal(m); err != nil {
				t.Error(err)
			}
			if _, err := Marshal(c); err != nil {
				t.Error(err)
			}
			if _, err := cs.MembershipTag(a.schedule.MembershipKey, c, a.Context.Version, &a.Context); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

// Sender data that names a leaf no member occupies is refused before
// any key of that leaf is derived. See RFC 9420, Section 6.3.2.
func TestSenderDataBlankLeaf(t *testing.T) {
	a, b, _ := threeMember(t)
	cs := a.CipherSuite
	m, err := b.Protect(nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	forged, err := m.PrivateMessage.sealSenderData(cs, b.schedule.SenderDataSecret, &SenderData{LeafIndex: 3})
	if err != nil {
		t.Fatal(err)
	}
	m.PrivateMessage.EncryptedSenderData = forged
	if _, err := a.Unprotect(send(t, m)); err != ErrNotMember {
		t.Errorf("Unprotect = %v, want %v", err, ErrNotMember)
	}
	if _, ok := a.keys.ratchets[3]; ok {
		t.Error("Unprotect derived the ratchets of a blank leaf")
	}
}

// privateProposal frames p as a PrivateMessage from g's own leaf, as
// a client that encrypts its handshake messages would send it.
func privateProposal(t *testing.T, g *Group, p *Proposal) *Message {
	t.Helper()
	cs := g.CipherSuite
	c := &AuthenticatedContent{
		WireFormat: WireFormatPrivateMessage,
		Content: FramedContent{
			GroupID:     g.Context.GroupID,
			Epoch:       g.Context.Epoch,
			Sender:      Sender{Type: SenderTypeMember, LeafIndex: uint32(g.Index)},
			ContentType: ContentTypeProposal,
			Proposal:    p,
		},
	}
	if err := c.Sign(cs, g.client.SignaturePriv, g.Context.Version, &g.Context); err != nil {
		t.Fatal(err)
	}
	r, err := g.keys.ratchet(g.Index, ContentTypeProposal)
	if err != nil {
		t.Fatal(err)
	}
	pm, err := c.privateMessage(cs, r, g.schedule.SenderDataSecret, 0)
	if err != nil {
		t.Fatal(err)
	}
	return &Message{Version: g.Context.Version, WireFormat: WireFormatPrivateMessage, PrivateMessage: pm}
}

// A leaf's application and handshake ratchets grow from one leaf
// secret. Reading a member's application message must not use up the
// ratchet its encrypted handshake messages arrive on.
func TestPrivateHandshakeAfterApplication(t *testing.T) {
	a, b, c := threeMember(t)
	m, err := b.Protect(nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Unprotect(send(t, m)); err != nil {
		t.Fatalf("Unprotect application message: %v", err)
	}
	p := privateProposal(t, b, &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: uint32(c.Index)}})
	got, err := a.Unprotect(send(t, p))
	if err != nil {
		t.Fatalf("Unprotect private proposal: %v", err)
	}
	if got.Content.ContentType != ContentTypeProposal {
		t.Errorf("content type = %v, want %v", got.Content.ContentType, ContentTypeProposal)
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
	forged, err := m.PrivateMessage.sealSenderData(cs, b.schedule.SenderDataSecret, &SenderData{
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

// TestProtectPadding checks that Client.Padding quantizes the length a
// message puts on the wire, and that a padded message still decrypts.
func TestProtectPadding(t *testing.T) {
	for _, pad := range []int{0, 1, 64} {
		t.Run(fmt.Sprint(pad), func(t *testing.T) {
			// Ed25519 signatures have a fixed size, so only
			// the plaintext varies the padded length.
			cs := X25519AES128GCMSHA256Ed25519
			alice := newTestClient(t, cs, "alice")
			bob := newTestClient(t, cs, "bob")
			alice.Padding, bob.Padding = pad, pad
			g, err := alice.NewGroup([]byte("group"), nil)
			if err != nil {
				t.Fatal(err)
			}
			g, _, w, err := g.Commit([]*Proposal{{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *bob.KeyPackage}}})
			if err != nil {
				t.Fatal(err)
			}
			bg, err := bob.Join(send(t, w).Welcome, nil)
			if err != nil {
				t.Fatal(err)
			}

			var lens []int
			for _, n := range []int{1, 17, 60} {
				plaintext := bytes.Repeat([]byte("x"), n)
				m, err := g.Protect(nil, plaintext)
				if err != nil {
					t.Fatal(err)
				}
				lens = append(lens, len(m.PrivateMessage.Ciphertext))
				got, err := bg.Unprotect(send(t, m))
				if err != nil {
					t.Fatalf("Unprotect(%d bytes): %v", n, err)
				}
				if !bytes.Equal(got.Content.ApplicationData, plaintext) {
					t.Errorf("round trip changed the message")
				}
			}
			same := lens[0] == lens[1] && lens[1] == lens[2]
			if want := pad > 1; same != want {
				t.Errorf("padding %d: ciphertext lengths %v, want all equal = %v", pad, lens, want)
			}
		})
	}
}
