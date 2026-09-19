package mls

import (
	"fmt"
	"testing"
)

// benchSizes are the group sizes the benchmarks sweep. The tree is
// perfect, so the interesting sizes are the powers of two: the cost
// of a commit is the length of the committer's direct path.
var benchSizes = []int{2, 8, 64}

// benchGroup returns the founder's view of a group of n members,
// along with a second member's view of the same epoch.
func benchGroup(b *testing.B, cs CipherSuite, n int) (founder, member *Group) {
	b.Helper()
	alice := newTestClient(b, cs, "alice")
	g, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		b.Fatal(err)
	}
	if n == 1 {
		return g, nil
	}
	var ps []*Proposal
	clients := make([]*Client, 0, n-1)
	for i := 1; i < n; i++ {
		c := newTestClient(b, cs, fmt.Sprintf("member%d", i))
		clients = append(clients, c)
		ps = append(ps, &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *c.KeyPackage}})
	}
	g, _, w, err := g.Commit(ps)
	if err != nil {
		b.Fatal(err)
	}
	member, err = clients[0].Join(send(b, w).Welcome, nil)
	if err != nil {
		b.Fatal(err)
	}
	return g, member
}

// BenchmarkCommit measures an empty commit, which is the cost of the
// UpdatePath alone: one HPKE encryption per node in the resolution of
// each node on the committer's direct path.
func BenchmarkCommit(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			g, _ := benchGroup(b, X25519AES128GCMSHA256Ed25519, n)
			b.ReportAllocs()
			for b.Loop() {
				if _, _, _, err := g.Commit(nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkHandle measures the receiving side of that commit:
// validation, one HPKE decryption, and the key schedule. Every
// iteration handles the same message from the same epoch, since a
// Group is immutable and Handle returns a new one; the figure is the
// cost of a single transition at a fixed tree size, not of a group
// advancing through epochs.
func BenchmarkHandle(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			g, m := benchGroup(b, X25519AES128GCMSHA256Ed25519, n)
			_, commit, _, err := g.Commit(nil)
			if err != nil {
				b.Fatal(err)
			}
			wire := send(b, commit)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := m.Handle(wire); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkAdd measures a commit that adds one member and seals the
// welcome for it. As in BenchmarkHandle the group stays at one epoch
// and one size, so the figure is the cost of adding the (n+1)th
// member, not of growing a group from one member to n.
func BenchmarkAdd(b *testing.B) {
	cs := X25519AES128GCMSHA256Ed25519
	for _, n := range benchSizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			g, _ := benchGroup(b, cs, n)
			newbie := newTestClient(b, cs, "newbie")
			p := []*Proposal{{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *newbie.KeyPackage}}}
			b.ReportAllocs()
			for b.Loop() {
				if _, _, _, err := g.Commit(p); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkJoin measures processing a Welcome: opening the group
// secrets, validating the whole tree, and reconstructing the schedule.
func BenchmarkJoin(b *testing.B) {
	cs := X25519AES128GCMSHA256Ed25519
	for _, n := range benchSizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			g, _ := benchGroup(b, cs, n)
			newbie := newTestClient(b, cs, "newbie")
			_, _, w, err := g.Commit([]*Proposal{{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *newbie.KeyPackage}}})
			if err != nil {
				b.Fatal(err)
			}
			wire := send(b, w).Welcome
			b.ReportAllocs()
			for b.Loop() {
				if _, err := newbie.Join(wire, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkProtect measures sealing one application message, the
// operation a chat client performs most often.
func BenchmarkProtect(b *testing.B) {
	for _, cs := range []CipherSuite{
		X25519AES128GCMSHA256Ed25519,
		X25519ChaCha20Poly1305SHA256Ed25519,
	} {
		b.Run(cs.String(), func(b *testing.B) {
			g, _ := benchGroup(b, cs, 8)
			msg := []byte("the quick brown fox jumps over the lazy dog")
			b.SetBytes(int64(len(msg)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := g.Protect(nil, msg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkUnprotect measures the receiving side. Each iteration
// measures only the receiving side. The ratchet refuses a generation
// it has already spent, so the messages cannot be reused; they are
// sealed in batches off the clock instead, and sender and receiver
// stay in lockstep across batches.
func BenchmarkUnprotect(b *testing.B) {
	cs := X25519AES128GCMSHA256Ed25519
	sender, receiver := benchGroup(b, cs, 8)
	msg := []byte("the quick brown fox jumps over the lazy dog")

	const batch = 256
	wire := make([]*Message, batch)
	fill := func() {
		for i := range wire {
			m, err := sender.Protect(nil, msg)
			if err != nil {
				b.Fatal(err)
			}
			wire[i] = send(b, m)
		}
	}

	fill()
	i := 0
	b.ReportAllocs()
	for b.Loop() {
		if i == len(wire) {
			b.StopTimer()
			fill()
			i = 0
			b.StartTimer()
		}
		if _, err := receiver.Unprotect(wire[i]); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

// BenchmarkRatchetStep measures one step of an application ratchet.
// The generation field of a PrivateMessage asks the receiver to take
// as many of these steps as the gap it names, so this figure times
// maxGenerationJump is the cost a sender can impose.
func BenchmarkRatchetStep(b *testing.B) {
	cs := X25519AES128GCMSHA256Ed25519
	tr := newSecretTree(cs, 2, make([]byte, cs.HashSize()))
	r, err := tr.ratchet(0, ContentTypeApplication)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _, advance, err := r.Key(r.Generation())
		if err != nil {
			b.Fatal(err)
		}
		advance()
	}
}

// BenchmarkTreeHash measures a full root hash, which a joiner
// computes over the whole tree.
func BenchmarkTreeHash(b *testing.B) {
	cs := X25519AES128GCMSHA256Ed25519
	for _, n := range benchSizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			g, _ := benchGroup(b, cs, n)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := g.Tree.RootHash(cs); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
