package groupfuzz

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/tmc/fuzztape"
	"github.com/tmc/mls"
)

// The model is a delivery service in the style of RFC 9420, Section
// 14: it accepts a handshake message only for the current epoch, orders
// everything it accepts, and hands each member the messages sent after
// it joined, in that order. Members process their queues at their own
// pace, so at any moment some are behind; they keep the groups of
// earlier epochs to read application messages that arrive late.
//
// Every message the service accepts was sent by an honest member, so
// every one must be processed without error. The exceptions are the
// ones RFC 9420 prescribes: a handshake message from an epoch the
// receiver has left is dropped, and the commit that removes a member
// fails for that member with ErrRemoved.

// suites are the cipher suites a case may run in.
var suites = []mls.CipherSuite{
	mls.X25519AES128GCMSHA256Ed25519,
	mls.P256AES128GCMSHA256P256,
	mls.X25519ChaCha20Poly1305SHA256Ed25519,
	mls.X448AES256GCMSHA512Ed448,
	mls.P521AES256GCMSHA512P521,
	mls.X448ChaCha20Poly1305SHA512Ed448,
	mls.P384AES256GCMSHA384P384,
}

// An envelope is a message the delivery service accepted, as queued
// for one recipient.
type envelope struct {
	from   string
	epoch  uint64 // the epoch the message was sent in
	msg    *mls.Message
	commit bool
	leaf   uint32 // for an application message, the sender's leaf
	text   []byte // for an application message, the plaintext sent
}

// A member is one client's view of the group.
type member struct {
	name   string
	client *mls.Client
	g      *mls.Group
	past   map[uint64]*mls.Group // groups of earlier epochs
	joined uint64
	inbox  []envelope

	// removed reports that a commit the service accepted removes the
	// member: the commit that ends epoch removedIn. The member stays
	// in the model until it processes that commit.
	removed   bool
	removedIn uint64
}

// A world is the delivery service and the members it serves.
type world struct {
	cs      mls.CipherSuite
	epoch   uint64            // the latest epoch the service accepted
	auth    map[uint64][]byte // each epoch's authenticator, per its committer
	members []*member
	joining []*mls.Client // clients added by a proposal of this epoch
	names   int
	sent    int
}

var machine = fuzztape.Machine[*world]{
	Init: func(t *fuzztape.T) *world {
		w := &world{
			cs:   fuzztape.Pick(t.Tape, suites),
			auth: make(map[uint64][]byte),
		}
		c := w.newClient(t)
		g, err := c.NewGroup([]byte("group"), nil)
		if err != nil {
			t.Fatalf("new group: %v", err)
		}
		creator := &member{name: name(c), client: c, g: g, past: make(map[uint64]*mls.Group)}
		w.members = []*member{creator}
		w.epoch = g.Epoch()
		w.auth[w.epoch] = g.EpochAuthenticator()
		// Start most cases with a few members, so that ops are not
		// spent growing the group from one.
		var adds []*mls.Proposal
		for range t.IntN(4) {
			adds = append(adds, w.add(t))
		}
		if len(adds) > 0 {
			w.commit(t, creator, adds)
		}
		return w
	},
	Ops: []fuzztape.Op[*world]{
		fuzztape.OpOver("deliver", (*world).waiting, deliver),
		fuzztape.OpOver("deliver", (*world).waiting, deliver),
		fuzztape.OpOver("deliver", (*world).waiting, deliver),
		fuzztape.OpOver("protect", (*world).all, protect),
		fuzztape.OpOver("propose-add", (*world).current, proposeAdd),
		fuzztape.OpOver("propose-remove", (*world).current, proposeRemove),
		fuzztape.OpOver("propose-update", (*world).current, proposeUpdate),
		fuzztape.OpOver("commit", (*world).current, func(t *fuzztape.T, w *world, m *member) {
			var extra []*mls.Proposal
			if t.Bool() {
				extra = append(extra, w.add(t))
			}
			w.commit(t, m, extra)
		}),
	},
	Check: check,
	Name:  "FuzzGroup",
}

func FuzzGroup(f *testing.F) { machine.Fuzz(f) }

func TestGroup(t *testing.T) {
	n := 50
	if testing.Short() {
		n = 20
	}
	machine.Run(t, n)
}

func name(c *mls.Client) string { return string(c.KeyPackage.LeafNode.Credential.Identity) }

func (w *world) newClient(t *fuzztape.T) *mls.Client {
	cred := mls.Credential{Type: mls.CredentialTypeBasic, Identity: fmt.Appendf(nil, "m%d", w.names)}
	w.names++
	c, err := mls.NewClient(w.cs, cred, time.Hour)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

// add returns an Add proposal for a new client, which joins if a
// commit of this epoch carries it.
func (w *world) add(t *fuzztape.T) *mls.Proposal {
	c := w.newClient(t)
	w.joining = append(w.joining, c)
	return &mls.Proposal{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *c.KeyPackage}}
}

// waiting returns the members with messages to process.
func (w *world) waiting() []*member {
	return slices.DeleteFunc(slices.Clone(w.members), func(m *member) bool { return len(m.inbox) == 0 })
}

// all returns every member, including those behind the latest epoch,
// each of which can still send in the epoch it is in.
func (w *world) all() []*member { return w.members }

// current returns the members in the latest epoch, the only ones whose
// handshake messages the service accepts.
func (w *world) current() []*member {
	return slices.DeleteFunc(slices.Clone(w.members), func(m *member) bool {
		return m.removed || m.g.Epoch() != w.epoch
	})
}

// send hands e to every member but its sender. A member a commit
// removes receives that commit but nothing after it.
func (w *world) send(from *member, e envelope) {
	e.from = from.name
	for _, m := range w.members {
		if m != from && !m.removed {
			m.inbox = append(m.inbox, e)
		}
	}
}

func protect(t *fuzztape.T, w *world, m *member) {
	text := fmt.Appendf(nil, "%s:%d", m.name, w.sent)
	w.sent++
	msg, err := m.g.Protect(nil, text)
	if err != nil {
		t.Fatalf("%s: protect in epoch %d: %v", m.name, m.g.Epoch(), err)
	}
	w.send(m, envelope{epoch: m.g.Epoch(), msg: msg, leaf: uint32(m.g.Index), text: text})
}

func (w *world) propose(t *fuzztape.T, m *member, msg *mls.Message, err error) {
	if err != nil {
		t.Fatalf("%s: propose in epoch %d: %v", m.name, m.g.Epoch(), err)
	}
	w.send(m, envelope{epoch: m.g.Epoch(), msg: msg})
}

func proposeAdd(t *fuzztape.T, w *world, m *member) {
	msg, err := m.g.Propose(w.add(t))
	w.propose(t, m, msg, err)
}

func proposeRemove(t *fuzztape.T, w *world, m *member) {
	var others []mls.LeafIndex
	for i := range m.g.Tree.Members() {
		if i != m.g.Index {
			others = append(others, i)
		}
	}
	if len(others) == 0 {
		t.Reject("no other member")
	}
	i := fuzztape.Pick(t.Tape, others)
	msg, err := m.g.Propose(&mls.Proposal{Type: mls.ProposalTypeRemove, Remove: &mls.Remove{Removed: uint32(i)}})
	w.propose(t, m, msg, err)
}

func proposeUpdate(t *fuzztape.T, w *world, m *member) {
	priv, pub, err := w.cs.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	leaf := *m.g.Tree.Leaf(m.g.Index)
	leaf.EncryptionKey = pub
	leaf.Source = mls.LeafNodeSourceUpdate
	leaf.Lifetime = mls.Lifetime{}
	leaf.ParentHash = nil
	if err := leaf.Sign(w.cs, m.client.SignaturePriv, m.g.Context.GroupID, m.g.Index); err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	msg, err := m.g.ProposeUpdate(&leaf, priv)
	w.propose(t, m, msg, err)
}

// commit has m commit extra and the proposals it has seen, and has the
// service accept the commit: every other member will process it, the
// members it removes are marked, and the clients it adds join.
func (w *world) commit(t *fuzztape.T, m *member, extra []*mls.Proposal) {
	prev := m.g.Epoch()
	next, msg, welcome, err := m.g.Commit(extra)
	if err != nil {
		t.Fatalf("%s: commit in epoch %d: %v", m.name, prev, err)
	}
	if next.Epoch() != prev+1 {
		t.Fatalf("%s: commit in epoch %d led to epoch %d", m.name, prev, next.Epoch())
	}
	w.send(m, envelope{epoch: prev, msg: msg, commit: true})
	m.past[prev], m.g = m.g, next
	w.epoch = next.Epoch()
	w.auth[w.epoch] = next.EpochAuthenticator()

	roster := make(map[string]bool)
	for _, leaf := range next.Tree.Members() {
		roster[string(leaf.Credential.Identity)] = true
	}
	if !roster[m.name] {
		t.Fatalf("%s: commit in epoch %d removed its committer", m.name, prev)
	}
	for _, o := range w.members {
		if !o.removed && !roster[o.name] {
			o.removed, o.removedIn = true, prev
		}
	}
	for _, c := range w.joining {
		if !roster[name(c)] {
			continue // its Add was not committed, and dies with the epoch
		}
		if welcome == nil {
			t.Fatalf("%s: commit in epoch %d added %s but sent no welcome", m.name, prev, name(c))
		}
		g, err := c.Join(welcome.Welcome, nil)
		if err != nil {
			t.Fatalf("%s: join epoch %d: %v", name(c), w.epoch, err)
		}
		w.members = append(w.members, &member{name: name(c), client: c, g: g, past: make(map[uint64]*mls.Group), joined: w.epoch})
		w.checkEpoch(t, name(c), g)
	}
	w.joining = nil
}

func deliver(t *fuzztape.T, w *world, m *member) {
	e := m.inbox[0]
	m.inbox = m.inbox[1:]
	cur := m.g.Epoch()
	switch {
	case e.epoch > cur:
		t.Fatalf("%s: in epoch %d, received a message of epoch %d from %s", m.name, cur, e.epoch, e.from)

	case e.epoch < cur:
		if e.text == nil {
			return // a handshake message of an epoch m has left
		}
		g := m.past[e.epoch]
		if g == nil {
			return // sent before m joined
		}
		_, ac, err := g.Handle(e.msg)
		w.checkApplication(t, m, e, ac, err)

	case e.commit:
		next, _, err := m.g.Handle(e.msg)
		if m.removed && cur == m.removedIn {
			if !errors.Is(err, mls.ErrRemoved) {
				t.Fatalf("%s: commit of epoch %d from %s removes it, but processing it returned %v", m.name, cur, e.from, err)
			}
			w.members = slices.DeleteFunc(w.members, func(o *member) bool { return o == m })
			return
		}
		if err != nil {
			t.Fatalf("%s: commit of epoch %d from %s: %v", m.name, cur, e.from, err)
		}
		m.past[cur], m.g = m.g, next
		w.checkEpoch(t, m.name, next)

	case e.text != nil:
		_, ac, err := m.g.Handle(e.msg)
		w.checkApplication(t, m, e, ac, err)

	default:
		if _, _, err := m.g.Handle(e.msg); err != nil {
			t.Fatalf("%s: proposal of epoch %d from %s: %v", m.name, cur, e.from, err)
		}
	}
}

func (w *world) checkApplication(t *fuzztape.T, m *member, e envelope, ac *mls.AuthenticatedContent, err error) {
	if err != nil {
		t.Fatalf("%s: application message of epoch %d from %s: %v", m.name, e.epoch, e.from, err)
	}
	if ac.Content.ContentType != mls.ContentTypeApplication || !bytes.Equal(ac.Content.ApplicationData, e.text) {
		t.Fatalf("%s: application message of epoch %d from %s: got %q, want %q", m.name, e.epoch, e.from, ac.Content.ApplicationData, e.text)
	}
	if s := ac.Content.Sender; s.Type != mls.SenderTypeMember || s.LeafIndex != e.leaf {
		t.Fatalf("%s: application message of epoch %d from %s: sender %+v, want leaf %d", m.name, e.epoch, e.from, s, e.leaf)
	}
}

// checkEpoch checks that g, which a member has just entered, has the
// epoch authenticator of the member that committed it.
func (w *world) checkEpoch(t *fuzztape.T, who string, g *mls.Group) {
	want, ok := w.auth[g.Epoch()]
	if !ok {
		t.Fatalf("%s: entered epoch %d, which no commit began", who, g.Epoch())
	}
	if !bytes.Equal(g.EpochAuthenticator(), want) {
		t.Fatalf("%s: epoch %d authenticator differs from its committer's", who, g.Epoch())
	}
}

// check checks that the members in the latest epoch agree on its group
// context, tree and exported secrets, and that the tree holds exactly
// the members the model has not removed.
func check(t *fuzztape.T, w *world) {
	want := make(map[string]bool)
	for _, m := range w.members {
		if !m.removed {
			want[m.name] = true
		}
	}
	var first *member
	var ctx, tree, secret []byte
	for _, m := range w.members {
		if m.g.Epoch() > w.epoch {
			t.Fatalf("%s: in epoch %d, past the service's %d", m.name, m.g.Epoch(), w.epoch)
		}
		if m.removed || m.g.Epoch() != w.epoch {
			continue
		}
		if leaf := m.g.Tree.Leaf(m.g.Index); leaf == nil || string(leaf.Credential.Identity) != m.name {
			t.Fatalf("%s: own leaf %d does not hold it", m.name, m.g.Index)
		}
		got := make(map[string]bool)
		for _, leaf := range m.g.Tree.Members() {
			got[string(leaf.Credential.Identity)] = true
		}
		if !maps.Equal(got, want) {
			t.Fatalf("%s: epoch %d members are %v, want %v", m.name, w.epoch, slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want)))
		}
		c, err := mls.Marshal(&m.g.Context)
		if err != nil {
			t.Fatalf("%s: marshal group context: %v", m.name, err)
		}
		tr, err := mls.Marshal(&m.g.Tree)
		if err != nil {
			t.Fatalf("%s: marshal tree: %v", m.name, err)
		}
		s, err := m.g.Export("groupfuzz", nil, 32)
		if err != nil {
			t.Fatalf("%s: export: %v", m.name, err)
		}
		if first == nil {
			first, ctx, tree, secret = m, c, tr, s
			continue
		}
		switch {
		case !bytes.Equal(c, ctx):
			t.Fatalf("%s and %s disagree on the group context of epoch %d", first.name, m.name, w.epoch)
		case !bytes.Equal(tr, tree):
			t.Fatalf("%s and %s disagree on the tree of epoch %d", first.name, m.name, w.epoch)
		case !bytes.Equal(s, secret):
			t.Fatalf("%s and %s export different secrets in epoch %d", first.name, m.name, w.epoch)
		}
	}
}
