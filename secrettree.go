package mls

// A SecretTree derives the keys that protect an epoch's messages. It
// has the same shape as the group's ratchet tree: the encryption
// secret sits at the root, each parent splits into two child secrets,
// and each leaf starts a pair of hash ratchets, one for handshake
// messages and one for application messages.
//
// Secrets are deleted as they are consumed, so a SecretTree can be
// walked to each leaf only once, and each ratchet only forward.
// See RFC 9420, Section 9.
type SecretTree struct {
	cs       CipherSuite
	n        LeafIndex
	secrets  map[NodeIndex][]byte
	ratchets map[ratchetKey]*Ratchet
}

// A ratchetKey identifies one member's ratchet for one kind of
// message within an epoch.
type ratchetKey struct {
	leaf LeafIndex
	typ  ContentType
}

// NewSecretTree returns the secret tree for an epoch of a group with
// n members, rooted at the epoch's encryption secret.
func NewSecretTree(cs CipherSuite, n LeafIndex, encryptionSecret []byte) *SecretTree {
	t := &SecretTree{
		cs:       cs,
		n:        n,
		secrets:  make(map[NodeIndex][]byte),
		ratchets: make(map[ratchetKey]*Ratchet),
	}
	t.secrets[root(n)] = encryptionSecret
	return t
}

// secret returns the secret at x, deriving it from its ancestors and
// deleting each secret it consumes on the way down.
func (t *SecretTree) secret(x NodeIndex) ([]byte, error) {
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

// Ratchet returns the hash ratchet that protects messages of the
// given content type sent by the member at leaf. Handshake messages
// (proposals and commits) and application messages use separate
// ratchets. The tree keeps each ratchet it derives, so repeated calls
// return the same one, at whatever generation it has reached.
func (t *SecretTree) Ratchet(leaf LeafIndex, typ ContentType) (*Ratchet, error) {
	if r, ok := t.ratchets[ratchetKey{leaf, typ}]; ok {
		return r, nil
	}
	var label string
	switch typ {
	case ContentTypeApplication:
		label = "application"
	case ContentTypeProposal, ContentTypeCommit:
		label = "handshake"
	default:
		return nil, errUnknown("content type", uint64(typ))
	}
	if leaf >= t.n {
		return nil, ErrLeafRange
	}
	s, err := t.secret(leaf.NodeIndex())
	if err != nil {
		return nil, err
	}
	secret, err := t.cs.ExpandWithLabel(s, label, nil, uint16(t.cs.HashSize()))
	if err != nil {
		return nil, err
	}
	r := &Ratchet{cs: t.cs, secret: secret}
	t.ratchets[ratchetKey{leaf, typ}] = r
	return r, nil
}

// A Ratchet produces the sequence of single-use keys and nonces that
// one member uses for one kind of message within one epoch.
// See RFC 9420, Section 9.1.
type Ratchet struct {
	cs         CipherSuite
	secret     []byte
	generation uint32
}

// Generation is the generation the ratchet will next produce.
func (r *Ratchet) Generation() uint32 { return r.generation }

// Next returns the key and nonce for the current generation and
// advances the ratchet. The caller must not reuse a key and nonce for
// more than one message.
func (r *Ratchet) Next() (key, nonce []byte, err error) {
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

// Key returns the key and nonce for a particular generation,
// advancing the ratchet past it. Generations in between are skipped
// and their keys discarded, and a generation the ratchet has already
// passed is gone: RFC 9420, Section 9.2 requires that keys be deleted
// as they are consumed.
func (r *Ratchet) Key(generation uint32) (key, nonce []byte, err error) {
	if generation < r.generation {
		return nil, nil, ErrConsumed
	}
	for {
		key, nonce, err := r.Next()
		if err != nil {
			return nil, nil, err
		}
		if r.generation == generation+1 {
			return key, nonce, nil
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
