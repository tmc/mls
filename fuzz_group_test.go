package mls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"math"
	"os"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tmc/mls/tlssyntax"
)

// A fuzzFixture is a group of three members, alice at leaf 0, bob at
// leaf 1 and carol at leaf 2, in the epoch after alice added the
// other two. It is built once per process, since building a group
// costs key generation and HPKE; the fuzz targets work on clones of
// its groups, made by cloneGroup, so that one input cannot change
// what the next one sees.
type fuzzFixture struct {
	alice, bob, carol *Group
	dave              *Client // a client outside the group
	update            *LeafNode
}

var (
	fixtureOnce sync.Once
	fixture     *fuzzFixture
	fixtureErr  error
)

func loadFixture(tb testing.TB) *fuzzFixture {
	tb.Helper()
	fixtureOnce.Do(func() { fixture, fixtureErr = buildFixture() })
	if fixtureErr != nil {
		tb.Fatal(fixtureErr)
	}
	return fixture
}

func buildFixture() (*fuzzFixture, error) {
	cs := testSuite()
	var clients []*Client
	for _, name := range []string{"alice", "bob", "carol", "dave"} {
		c, err := NewClient(cs, Credential{Type: CredentialTypeBasic, Identity: []byte(name)}, time.Hour)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	a0, err := clients[0].NewGroup([]byte("group"), nil)
	if err != nil {
		return nil, err
	}
	a1, _, w, err := a0.Commit([]*Proposal{
		{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *clients[1].KeyPackage}},
		{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *clients[2].KeyPackage}},
	})
	if err != nil {
		return nil, err
	}
	b1, err := clients[1].Join(w.Welcome, nil)
	if err != nil {
		return nil, err
	}
	c1, err := clients[2].Join(w.Welcome, nil)
	if err != nil {
		return nil, err
	}

	// A key rotation bob could propose, for seeds that carry an
	// update from a member other than the committer.
	_, encPub, err := cs.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	update := *b1.Tree.Leaf(1)
	update.EncryptionKey = encPub
	update.Source = LeafNodeSourceUpdate
	update.Lifetime = Lifetime{}
	if err := update.Sign(cs, clients[1].SignaturePriv, b1.Context.GroupID, 1); err != nil {
		return nil, err
	}
	return &fuzzFixture{alice: a1, bob: b1, carol: c1, dave: clients[3], update: &update}, nil
}

// cloneGroup returns a copy of g that shares no mutable state with
// it. Within an epoch a Group changes only in its secret tree, whose
// ratchets Protect and Unprotect advance, and in the proposals it has
// staged; its tree, context and key schedule change only by building
// a new Group, which leaves them shared safely.
func cloneGroup(g *Group) *Group {
	c := *g
	c.keys = cloneSecretTree(g.keys)
	c.proposals = maps.Clone(g.proposals)
	c.updated = maps.Clone(g.updated)
	c.updates = maps.Clone(g.updates)
	return &c
}

func cloneSecretTree(t *secretTree) *secretTree {
	c := *t
	c.secrets = maps.Clone(t.secrets)
	c.ratchets = make(map[LeafIndex]*leafRatchets, len(t.ratchets))
	for i, r := range t.ratchets {
		c.ratchets[i] = new(*r)
	}
	return &c
}

// fuzzSender returns the sender of the i'th proposal of a fuzzed
// list, as chosen by the fuzzer's byte b: the committer itself, some
// member, an external sender, or a new member.
func fuzzSender(committer LeafIndex, b byte) Sender {
	switch b % 4 {
	case 1:
		return Sender{Type: SenderTypeMember, LeafIndex: uint32(b >> 2)}
	case 2:
		return Sender{Type: SenderTypeExternal, SenderIndex: uint32(b >> 2)}
	case 3:
		return Sender{Type: SenderTypeNewMemberProposal}
	}
	return Sender{Type: SenderTypeMember, LeafIndex: uint32(committer)}
}

// messageVectors returns the values of the named fields of the
// messages test vector.
func messageVectors(tb testing.TB, fields ...string) [][]byte {
	tb.Helper()
	data, err := os.ReadFile("testdata/messages.json")
	if err != nil {
		tb.Fatal(err)
	}
	var vectors []map[string]string
	if err := json.Unmarshal(data, &vectors); err != nil {
		tb.Fatal(err)
	}
	var out [][]byte
	for _, v := range vectors {
		for _, name := range fields {
			if b, err := hex.DecodeString(v[name]); err == nil && len(b) > 0 {
				out = append(out, b)
			}
		}
	}
	return out
}

// FuzzProposalList checks the rules of RFC 9420, Section 12.2 on the
// list of proposals a commit covers. The list is decoded from a
// Commit's encoding, the senders of its proposals are chosen by the
// fuzzer, and it is checked against the fixture's tree.
//
// Beyond not panicking, a list the checker accepts must be one the
// proposals can be applied from without panicking; and a list that
// alice commits must be one that bob and carol accept, since a commit
// the committer makes and its members reject splits the group.
func FuzzProposalList(f *testing.F) {
	fx := loadFixture(f)
	cs := fx.alice.CipherSuite
	inline := func(ps ...*Proposal) []byte {
		c := &Commit{}
		for _, p := range ps {
			c.Proposals = append(c.Proposals, ProposalOrRef{Type: ProposalOrRefTypeProposal, Proposal: p})
		}
		b, err := Marshal(c)
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	add := &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *fx.dave.KeyPackage}}
	remove := func(i uint32) *Proposal {
		return &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: i}}
	}
	update := &Proposal{Type: ProposalTypeUpdate, Update: &Update{LeafNode: *fx.update}}
	psk := &Proposal{Type: ProposalTypePreSharedKey, PreSharedKey: &PreSharedKey{PSK: PreSharedKeyID{
		Type: PSKTypeResumption, Usage: ResumptionPSKUsageApplication,
		PSKGroupID: []byte("group"), PSKEpoch: 1, PSKNonce: make([]byte, cs.HashSize()),
	}}}
	var ext Extensions
	if err := ext.Set(ExtensionTypeRequiredCapabilities, &RequiredCapabilities{}); err != nil {
		f.Fatal(err)
	}
	gce := &Proposal{Type: ProposalTypeGroupContextExtensions, GroupContextExtensions: &GroupContextExtensions{Extensions: ext}}
	reinit := &Proposal{Type: ProposalTypeReinit, Reinit: &Reinit{GroupID: []byte("new"), Version: Version10, CipherSuite: cs}}

	f.Add(uint8(0), []byte{0}, inline(add))
	f.Add(uint8(0), []byte{0, 0}, inline(add, remove(1)))
	f.Add(uint8(0), []byte{0, 0}, inline(remove(1), remove(2)))
	f.Add(uint8(0), []byte{0, 1 | 1<<2}, inline(remove(2), update))
	f.Add(uint8(0), []byte{0}, inline(psk))
	f.Add(uint8(0), []byte{0, 0}, inline(gce, add))
	f.Add(uint8(0), []byte{0}, inline(reinit))
	f.Add(uint8(1), []byte{2, 3}, inline(remove(2), add))
	f.Add(uint8(3), []byte{0}, inline(remove(0)))

	f.Fuzz(func(t *testing.T, committer uint8, senders, data []byte) {
		var commit Commit
		if err := Unmarshal(data, &commit); err != nil {
			return
		}
		// Committers beyond the tree's three leaves stand in for
		// a sender whose leaf is blank or out of range.
		c := LeafIndex(committer % 5)
		if committer >= 250 {
			c = LeafIndex(math.MaxUint32 - uint32(committer-250))
		}
		var ps []proposal
		var extra []*Proposal
		own := true
		for i := range commit.Proposals {
			p := &commit.Proposals[i]
			if p.Type != ProposalOrRefTypeProposal {
				continue
			}
			var b byte
			if i < len(senders) {
				b = senders[i]
			}
			from := fuzzSender(c, b)
			own = own && b%4 == 0
			ps = append(ps, proposal{p.Proposal, from})
			extra = append(extra, p.Proposal)
		}

		g := fx.alice
		err := g.Tree.validateProposals(ps, c, &g.Context)
		if err != nil {
			return
		}
		next := &Group{
			CipherSuite: g.CipherSuite,
			Context:     g.Context,
			Tree:        g.Tree.Clone(),
			Index:       g.Index,
			client:      g.client,
		}
		if _, err := next.apply(ps); err != nil {
			return
		}
		if !own || c != g.Index {
			return
		}

		// alice commits the list herself; bob and carol must
		// follow her. A list that removes one of them, or that
		// draws on a resumption key from before they joined, is
		// the one thing that may keep them out.
		a := cloneGroup(fx.alice)
		_, msg, _, err := a.Commit(extra)
		if err != nil {
			return
		}
		b, err := Marshal(msg)
		if err != nil {
			t.Fatalf("Marshal(commit): %v", err)
		}
		for _, m := range []*Group{fx.bob, fx.carol} {
			var wire Message
			if err := Unmarshal(b, &wire); err != nil {
				t.Fatalf("Unmarshal(commit): %v", err)
			}
			_, err := cloneGroup(m).Handle(&wire)
			if err != nil && !errors.Is(err, ErrRemoved) && !errors.Is(err, ErrUnknownPSK) {
				t.Fatalf("alice committed %d proposals that leaf %d rejects: %v", len(extra), m.Index, err)
			}
		}
	})
}

// FuzzTreeVerify decodes a ratchet tree and puts it through every
// check a joiner makes, with a group context that agrees with its
// tree hash so that the checks after the hash are reached, and
// through the accessors that read a tree, at leaves in range and out
// of it.
//
// A tree that verifies must also read consistently: each leaf is the
// one its node holds, every resolution is a list of non-blank nodes
// in the tree, and removing or adding a member leaves a tree of the
// same shape with consistent unmerged leaves.
func FuzzTreeVerify(f *testing.F) {
	seed(f, "ratchet_tree")
	fx := loadFixture(f)
	for _, g := range []*Group{fx.alice, fx.bob} {
		b, err := Marshal(&g.Tree)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	cs := fx.alice.CipherSuite
	f.Fuzz(func(t *testing.T, data []byte) {
		var tree RatchetTree
		if err := Unmarshal(data, &tree); err != nil {
			return
		}
		n := tree.Size()
		probe := []LeafIndex{n, n + 1, n * 2, 1 << 31, 1<<31 + 1, math.MaxUint32}
		for i := range min(n, 64) {
			probe = append(probe, i)
		}
		for _, i := range probe {
			tree.Leaf(i)
			tree.Resolution(i.NodeIndex())
			directPath(i.NodeIndex(), n)
			copath(i.NodeIndex(), n)
		}
		for x := NodeIndex(1); x < nodeWidth(min(n, 64)); x += 2 {
			tree.Resolution(x)
			directPath(x, n)
			copath(x, n)
		}
		// Parents outside the tree, whose subtrees are wholly
		// or partly beyond its end.
		for _, x := range []NodeIndex{root(2 * n), root(2*n) + 1, nodeWidth(n) | 1, math.MaxUint32 >> 1, math.MaxUint32 - 1} {
			tree.Resolution(x)
		}
		for range tree.Members() {
		}
		_ = tree.VerifyParentHashes(cs)
		_ = tree.verifyNodeKeys()
		_ = tree.verifyUnmergedLeaves()

		hash, err := tree.RootHash(cs)
		if err != nil {
			return
		}
		ctx := fx.alice.Context
		ctx.TreeHash = hash
		if err := tree.verify(cs, &ctx); err != nil {
			return
		}

		// The tree verified.
		for i := range n {
			leaf := tree.Leaf(i)
			if x := int(i.NodeIndex()); x < len(tree) && tree[x] != nil {
				if leaf != tree[x].Leaf {
					t.Fatalf("Leaf(%d) = %p, want the leaf at node %d", i, leaf, x)
				}
			} else if leaf != nil {
				t.Fatalf("Leaf(%d) is not blank", i)
			}
		}
		for x := range nodeWidth(n) {
			for _, y := range tree.Resolution(x) {
				if int(y) >= len(tree) || tree[y] == nil {
					t.Fatalf("Resolution(%d) holds blank node %d", x, y)
				}
			}
		}
		if _, err := tree.TreeHash(cs, root(n)); err != nil {
			t.Fatalf("TreeHash: %v", err)
		}
		c := tree.Clone()
		if !reflect.DeepEqual(c, tree) {
			t.Fatal("Clone differs from the tree")
		}
		out, err := Marshal(&c)
		if err != nil || !bytes.Equal(out, data) {
			t.Fatalf("clone re-encodes as %x, %v; want %x", out, err, data)
		}

		members := slices.Collect(func(yield func(LeafIndex) bool) {
			for i := range tree.Members() {
				if !yield(i) {
					return
				}
			}
		})
		for _, i := range members[:min(len(members), 8)] {
			c := tree.Clone()
			c.Remove(i)
			if len(c) == 0 {
				continue
			}
			if err := c.verifyShape(); err != nil {
				t.Fatalf("after Remove(%d): %v", i, err)
			}
			if err := c.verifyUnmergedLeaves(); err != nil {
				t.Fatalf("after Remove(%d): %v", i, err)
			}
		}
		c = tree.Clone()
		c.Add(new(fx.dave.KeyPackage.LeafNode))
		if err := c.verifyShape(); err != nil {
			t.Fatalf("after Add: %v", err)
		}
		if err := c.verifyUnmergedLeaves(); err != nil {
			t.Fatalf("after Add: %v", err)
		}
	})
}

// FuzzUnprotect hands a member of the fixture's group messages it
// must reject: arbitrary bytes decoded as a Message, and private
// messages sealed under the group's real keys, as any member of the
// epoch can seal them, whose plaintext and sender data the fuzzer
// chooses. In the second form the plaintext is either the fuzzer's
// bytes or an application message signed by carol that names any
// leaf and generation as its sender.
//
// Besides not panicking, a rejected message must leave the ratchets
// as they were: bob's and carol's next genuine messages must still
// decrypt, unless the input was itself a genuine message of theirs.
func FuzzUnprotect(f *testing.F) {
	fx := loadFixture(f)
	for _, b := range messageVectors(f, "public_message_application", "public_message_proposal", "public_message_commit", "private_message") {
		f.Add(b, uint8(0), uint32(0), uint32(0), []byte(nil))
	}
	msg, err := cloneGroup(fx.bob).Protect([]byte("ad"), []byte("hello"))
	if err != nil {
		f.Fatal(err)
	}
	b, err := Marshal(msg)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b, uint8(0), uint32(0), uint32(0), []byte(nil))
	prop, err := cloneGroup(fx.carol).Propose(&Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 1}})
	if err != nil {
		f.Fatal(err)
	}
	if b, err = Marshal(prop); err != nil {
		f.Fatal(err)
	}
	f.Add(b, uint8(0), uint32(0), uint32(0), []byte(nil))
	f.Add([]byte(nil), uint8(1), uint32(1), uint32(0), []byte{0, 0})
	f.Add([]byte(nil), uint8(2), uint32(2), uint32(0), []byte("hi"))
	f.Add([]byte(nil), uint8(2), uint32(1), uint32(3), []byte("hi"))
	f.Add([]byte(nil), uint8(3), uint32(1), uint32(0), []byte{2, 'h', 'i', 0})
	f.Add([]byte(nil), uint8(5), uint32(0), uint32(0), []byte{0})

	f.Fuzz(func(t *testing.T, raw []byte, mode uint8, leaf, gen uint32, plaintext []byte) {
		var m *Message
		if mode == 0 {
			m = new(Message)
			if err := Unmarshal(raw, m); err != nil {
				return
			}
		} else {
			m = sealFuzzMessage(t, fx, mode, leaf, gen, raw, plaintext)
		}

		// Handle takes the message through Unprotect and on to
		// whatever its content asks; neither may panic.
		_, _ = cloneGroup(fx.alice).Handle(m)

		a := cloneGroup(fx.alice)
		c, err := a.Unprotect(m)
		for _, s := range []*Group{fx.bob, fx.carol} {
			if err == nil && c.Content.Sender.Type == SenderTypeMember && LeafIndex(c.Content.Sender.LeafIndex) == s.Index {
				// A genuine message from s, which spent
				// the generation s sends next.
				continue
			}
			genuine, err := cloneGroup(s).Protect(nil, []byte("genuine"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := a.Unprotect(genuine)
			if err != nil {
				t.Fatalf("after the fuzzed message, leaf %d's next message: %v", s.Index, err)
			}
			if !bytes.Equal(got.Content.ApplicationData, []byte("genuine")) {
				t.Fatalf("leaf %d's next message decrypted to %q", s.Index, got.Content.ApplicationData)
			}
		}
	})
}

// sealFuzzMessage seals a private message under the fixture group's
// keys, from the given leaf at the given generation, with the content
// type and authenticated data the mode and aad choose. For mode%4 ==
// 1 the plaintext is sealed as given; otherwise it is the application
// data of a message signed by carol. A leaf and generation the group
// has no keys for are sealed under a key of zeros.
func sealFuzzMessage(t *testing.T, fx *fuzzFixture, mode uint8, leaf, gen uint32, aad, plaintext []byte) *Message {
	g := fx.carol
	cs := g.CipherSuite
	ct := ContentTypeApplication
	switch mode >> 2 % 4 {
	case 1:
		ct = ContentTypeProposal
	case 2:
		ct = ContentTypeCommit
	case 3:
		ct = ContentType(mode)
	}
	if mode%4 != 1 {
		c := &AuthenticatedContent{
			WireFormat: WireFormatPrivateMessage,
			Content: FramedContent{
				GroupID:           g.Context.GroupID,
				Epoch:             g.Context.Epoch,
				Sender:            Sender{Type: SenderTypeMember, LeafIndex: leaf},
				AuthenticatedData: aad,
				ContentType:       ContentTypeApplication,
				ApplicationData:   plaintext,
			},
			Auth: FramedContentAuthData{ContentType: ContentTypeApplication},
		}
		if err := c.Sign(cs, g.client.SignaturePriv, g.Context.Version, &g.Context); err != nil {
			t.Fatal(err)
		}
		b, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
			c.Content.marshalBody(w)
			c.Auth.marshal(w, c.Content.ContentType)
		}))
		if err != nil {
			t.Fatal(err)
		}
		plaintext, ct = b, ContentTypeApplication
	}
	pm := &PrivateMessage{
		GroupID:           g.Context.GroupID,
		Epoch:             g.Context.Epoch,
		ContentType:       ct,
		AuthenticatedData: aad,
	}
	key := make([]byte, cs.AEADKeySize())
	nonce := make([]byte, cs.AEADNonceSize())
	if r, err := cloneSecretTree(g.keys).ratchet(LeafIndex(leaf), ct); err == nil {
		if k, n, _, err := r.Key(gen); err == nil {
			key, nonce = k, n
		}
	}
	aead, err := cs.AEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	guard := [4]byte{byte(gen), byte(leaf), mode, 0}
	pm.Ciphertext = aead.Seal(nil, applyGuard(nonce, guard), plaintext, pm.contentAAD())
	data := &SenderData{LeafIndex: leaf, Generation: gen, ReuseGuard: guard}
	if pm.EncryptedSenderData, err = pm.sealSenderData(cs, g.schedule.SenderDataSecret, data); err != nil {
		t.Fatal(err)
	}
	return &Message{Version: g.Context.Version, WireFormat: WireFormatPrivateMessage, PrivateMessage: pm}
}
