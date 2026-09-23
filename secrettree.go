package mls

// A secretTree derives the keys that protect an epoch's messages. It
// has the same shape as the group's ratchet tree: the encryption
// secret sits at the root, each parent splits into two child secrets,
// and each leaf starts a pair of hash ratchets, one for handshake
// messages and one for application messages.
//
// Secrets are deleted as they are consumed, so a secretTree can be
// walked to each leaf only once, and each ratchet only forward.
// See RFC 9420, Section 9.
type secretTree struct {
	cs       CipherSuite
	n        LeafIndex
	secrets  map[NodeIndex][]byte
	ratchets map[LeafIndex]*leafRatchets
}

// leafRatchets are the two ratchets a member's leaf secret starts.
type leafRatchets struct {
	handshake   ratchet
	application ratchet
}

// newSecretTree returns the secret tree for an epoch of a group with
// n members, rooted at the epoch's encryption secret.
func newSecretTree(cs CipherSuite, n LeafIndex, encryptionSecret []byte) *secretTree {
	t := &secretTree{
		cs:       cs,
		n:        n,
		secrets:  make(map[NodeIndex][]byte),
		ratchets: make(map[LeafIndex]*leafRatchets),
	}
	t.secrets[root(n)] = encryptionSecret
	return t
}

// secret returns the secret at x, deriving it from its ancestors and
// deleting each secret it consumes on the way down.
func (t *secretTree) secret(x NodeIndex) ([]byte, error) {
	if s, ok := t.secrets[x]; ok {
		delete(t.secrets, x)
		if s == nil {
			return nil, ErrConsumed
		}
		return s, nil
	}
	if x == root(t.n) {
		return nil, ErrConsumed
	}
	p, err := t.secret(x.parent())
	if err != nil {
		return nil, err
	}
	nh := uint16(t.cs.HashSize())
	left, err := t.cs.ExpandWithLabel(p, "tree", []byte("left"), nh)
	if err != nil {
		return nil, err
	}
	right, err := t.cs.ExpandWithLabel(p, "tree", []byte("right"), nh)
	if err != nil {
		return nil, err
	}
	if sib := x.sibling(); sib < x {
		t.secrets[sib] = left
		return right, nil
	} else {
		t.secrets[sib] = right
		return left, nil
	}
}

// ratchet returns the hash ratchet that protects messages of the
// given content type sent by the member at leaf. Handshake messages
// (proposals and commits) and application messages use separate
// ratchets. Taking a leaf's secret consumes it, so the tree derives
// both of the leaf's ratchets at once and keeps them; repeated calls
// return the same ratchet, at whatever generation it has reached.
// See RFC 9420, Section 9.1.
func (t *secretTree) ratchet(leaf LeafIndex, typ ContentType) (*ratchet, error) {
	switch typ {
	case ContentTypeApplication, ContentTypeProposal, ContentTypeCommit:
	default:
		return nil, errUnknown("content type", uint64(typ))
	}
	if leaf >= t.n {
		return nil, ErrLeafRange
	}
	lr, ok := t.ratchets[leaf]
	if !ok {
		s, err := t.secret(leaf.NodeIndex())
		if err != nil {
			return nil, err
		}
		nh := uint16(t.cs.HashSize())
		hs, err := t.cs.ExpandWithLabel(s, "handshake", nil, nh)
		if err != nil {
			return nil, err
		}
		as, err := t.cs.ExpandWithLabel(s, "application", nil, nh)
		if err != nil {
			return nil, err
		}
		lr = &leafRatchets{
			handshake:   ratchet{cs: t.cs, secret: hs},
			application: ratchet{cs: t.cs, secret: as},
		}
		t.ratchets[leaf] = lr
	}
	if typ == ContentTypeApplication {
		return &lr.application, nil
	}
	return &lr.handshake, nil
}

// A ratchet produces the sequence of single-use keys and nonces that
// one member uses for one kind of message within one epoch.
// See RFC 9420, Section 9.1.
type ratchet struct {
	cs         CipherSuite
	secret     []byte
	generation uint32
}

// Generation is the generation the ratchet will next produce.
func (r *ratchet) Generation() uint32 { return r.generation }

// Next returns the key and nonce for the current generation and
// advances the ratchet. The caller must not reuse a key and nonce for
// more than one message.
func (r *ratchet) Next() (key, nonce []byte, err error) {
	cs := r.cs
	gen := r.generation
	if nonce, err = cs.DeriveTreeSecret(r.secret, "nonce", gen, uint16(cs.AEADNonceSize())); err != nil {
		return nil, nil, err
	}
	if key, err = cs.DeriveTreeSecret(r.secret, "key", gen, uint16(cs.AEADKeySize())); err != nil {
		return nil, nil, err
	}
	next, err := cs.DeriveTreeSecret(r.secret, "secret", gen, uint16(cs.HashSize()))
	if err != nil {
		return nil, nil, err
	}
	r.secret, r.generation = next, gen+1
	return key, nonce, nil
}

// maxGenerationJump bounds how far ahead of a ratchet a message may
// claim to be. Reaching a generation costs one derivation per step,
// so an unbounded jump is hours of work asked for by one message, and
// the sender data that carries the generation is authenticated only
// by a secret every member of the epoch holds. The bound is the run
// of lost messages a receiver is willing to ride out.
const maxGenerationJump = 1024

// Key returns the key and nonce for a generation at or after the one
// the ratchet has reached, along with a function that advances the
// ratchet past it. The caller must advance only once the message has
// been authenticated: a message that does not decrypt must not
// consume the keys of the member it claims to come from. Generations
// in between are skipped and their keys discarded, and a generation
// the ratchet has already passed is gone: RFC 9420, Section 9.2
// requires that keys be deleted as they are consumed.
func (r *ratchet) Key(generation uint32) (key, nonce []byte, advance func(), err error) {
	if generation < r.generation {
		return nil, nil, nil, ErrConsumed
	}
	if generation-r.generation > maxGenerationJump {
		return nil, nil, nil, ErrGenerationJump
	}
	ahead := &ratchet{cs: r.cs, secret: r.secret, generation: r.generation}
	for {
		key, nonce, err := ahead.Next()
		if err != nil {
			return nil, nil, nil, err
		}
		if ahead.generation == generation+1 {
			return key, nonce, func() { r.secret, r.generation = ahead.secret, ahead.generation }, nil
		}
	}
}

// SenderDataKey derives the key and nonce that protect the sender
// data of a [PrivateMessage]. Both are bound to a sample of the
// message's ciphertext, so that an attacker who has not seen the
// message cannot derive them. See RFC 9420, Section 6.3.2.
func (cs CipherSuite) SenderDataKey(senderDataSecret, ciphertext []byte) (key, nonce []byte, err error) {
	sample := ciphertext
	if n := cs.HashSize(); len(sample) > n {
		sample = sample[:n]
	}
	if key, err = cs.ExpandWithLabel(senderDataSecret, "key", sample, uint16(cs.AEADKeySize())); err != nil {
		return nil, nil, err
	}
	if nonce, err = cs.ExpandWithLabel(senderDataSecret, "nonce", sample, uint16(cs.AEADNonceSize())); err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}
