package mls

import (
	"bytes"
	"encoding/hex"
	"maps"
	"slices"
	"time"
)

// A Client holds the private keys of one member. It is the starting
// point for joining a group: the key package is published to whoever
// will add the client, and the three private keys are kept.
type Client struct {
	CipherSuite CipherSuite
	KeyPackage  *KeyPackage

	InitPriv       []byte // private half of KeyPackage.InitKey
	EncryptionPriv []byte // private half of KeyPackage.LeafNode.EncryptionKey
	SignaturePriv  []byte // private half of KeyPackage.LeafNode.SignatureKey

	// PSK returns the pre-shared key named by id. It is consulted
	// for external pre-shared keys; resumption keys come from the
	// group's own history. A nil PSK rejects any commit that needs
	// an external key.
	PSK func(id PreSharedKeyID) ([]byte, error)
}

// A Group is a member's view of an MLS group at one epoch. Processing
// a commit does not change a Group; it returns the group's state in
// the epoch that the commit begins.
type Group struct {
	CipherSuite CipherSuite
	Context     GroupContext
	Tree        RatchetTree
	Schedule    *KeySchedule
	Index       LeafIndex    // the member's own leaf
	Secrets     *TreeSecrets // the member's private view of the tree

	client     *Client
	interim    []byte // interim transcript hash
	keys       *SecretTree
	proposals  map[string]*AuthenticatedContent // by proposal reference
	resumption map[uint64][]byte                // resumption PSKs, by epoch
}

// EpochAuthenticator is the value that members compare out of band to
// confirm they agree on the history of the group.
// See RFC 9420, Section 8.
func (g *Group) EpochAuthenticator() []byte { return g.Schedule.EpochAuthenticator }

// Epoch is the number of the epoch g describes.
func (g *Group) Epoch() uint64 { return g.Context.Epoch }

// Join builds a member's view of a group from a welcome message. The
// ratchet tree comes from the welcome's group info if it carries a
// ratchet_tree extension, and otherwise must be supplied in tree.
// See RFC 9420, Section 12.4.3.1.
func (c *Client) Join(w *Welcome, tree RatchetTree) (*Group, error) {
	cs := c.CipherSuite
	if w.CipherSuite != cs {
		return nil, ErrUnsupportedCipherSuite
	}
	ref, err := c.KeyPackage.Ref()
	if err != nil {
		return nil, err
	}
	secrets, err := w.GroupSecrets(ref, c.InitPriv)
	if err != nil {
		return nil, err
	}
	pskSecret, err := c.pskSecret(secrets.PSKs, nil)
	if err != nil {
		return nil, err
	}
	welcomeSecret, err := cs.WelcomeSecret(secrets.JoinerSecret, pskSecret)
	if err != nil {
		return nil, err
	}
	info, err := w.GroupInfo(welcomeSecret)
	if err != nil {
		return nil, err
	}
	var carried RatchetTree
	if ok, err := info.Extensions.Get(ExtensionTypeRatchetTree, &carried); err != nil {
		return nil, err
	} else if ok {
		tree = carried
	}
	if tree == nil {
		return nil, ErrNoRatchetTree
	}
	if err := tree.verify(cs, &info.GroupContext); err != nil {
		return nil, err
	}
	signer := LeafIndex(info.Signer)
	leaf := tree.Leaf(signer)
	if leaf == nil {
		return nil, ErrLeafRange
	}
	if err := info.Verify(leaf.SignatureKey); err != nil {
		return nil, err
	}

	// Our own leaf is the one holding the key package's leaf node.
	index := LeafIndex(0)
	for ; ; index++ {
		if index >= tree.Size() {
			return nil, ErrNotMember
		}
		if l := tree.Leaf(index); l != nil && bytes.Equal(l.EncryptionKey, c.KeyPackage.LeafNode.EncryptionKey) {
			break
		}
	}

	schedule, err := NewKeySchedule(cs, secrets.JoinerSecret, pskSecret, &info.GroupContext)
	if err != nil {
		return nil, err
	}
	tag, err := cs.ConfirmationTag(schedule.ConfirmationKey, info.GroupContext.ConfirmedTranscriptHash)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(tag, info.ConfirmationTag) {
		return nil, ErrBadConfirmationTag
	}
	interim, err := cs.InterimTranscriptHash(info.GroupContext.ConfirmedTranscriptHash, info.ConfirmationTag)
	if err != nil {
		return nil, err
	}

	private := NewTreeSecrets(index, c.EncryptionPriv)
	if secrets.PathSecret != nil {
		x := commonAncestor(index, signer)
		if err := private.SetPath(cs, tree, x, secrets.PathSecret.PathSecret); err != nil {
			return nil, err
		}
	}
	if err := private.Consistent(cs, tree); err != nil {
		return nil, err
	}
	g := &Group{
		CipherSuite: cs,
		Context:     info.GroupContext,
		Tree:        tree,
		Schedule:    schedule,
		Index:       index,
		Secrets:     private,
		client:      c,
		interim:     interim,
		keys:        NewSecretTree(cs, tree.Size(), schedule.EncryptionSecret),
		proposals:   make(map[string]*AuthenticatedContent),
		resumption:  map[uint64][]byte{info.GroupContext.Epoch: schedule.ResumptionPSK},
	}
	return g, nil
}

// verify checks a ratchet tree against the group context that
// summarizes it, and against its own internal consistency.
func (t RatchetTree) verify(cs CipherSuite, ctx *GroupContext) error {
	hash, err := t.RootHash(cs)
	if err != nil {
		return err
	}
	if !bytes.Equal(hash, ctx.TreeHash) {
		return ErrBadTreeHash
	}
	if err := t.VerifyParentHashes(cs); err != nil {
		return err
	}
	return t.validateLeaves(cs, ctx)
}

// pskSecret resolves a list of pre-shared key identifiers against the
// group's own resumption keys and the client's PSK function.
func (c *Client) pskSecret(ids []PreSharedKeyID, g *Group) ([]byte, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	psks := make([][]byte, len(ids))
	for i, id := range ids {
		switch {
		case id.Type == PSKTypeResumption && g != nil && bytes.Equal(id.PSKGroupID, g.Context.GroupID):
			psk, ok := g.resumption[id.PSKEpoch]
			if !ok {
				return nil, ErrUnknownPSK
			}
			psks[i] = psk
		case c.PSK != nil:
			psk, err := c.PSK(id)
			if err != nil {
				return nil, err
			}
			psks[i] = psk
		default:
			return nil, ErrUnknownPSK
		}
	}
	return c.CipherSuite.PSKSecret(ids, psks)
}

// Unprotect recovers the authenticated content of a message sent to
// the group, checking that it comes from a member of this epoch.
func (g *Group) Unprotect(m *MLSMessage) (*AuthenticatedContent, error) {
	cs := g.CipherSuite
	var (
		c   *AuthenticatedContent
		err error
	)
	switch {
	case m.PublicMessage != nil:
		c, err = m.PublicMessage.AuthenticatedContent(cs, g.Schedule.MembershipKey, &g.Context)
	case m.PrivateMessage != nil:
		c, err = m.PrivateMessage.AuthenticatedContent(cs, g.keys, g.Schedule.SenderDataSecret)
	default:
		return nil, ErrNotForGroup
	}
	if err != nil {
		return nil, err
	}
	if c.Content.Epoch != g.Context.Epoch || !bytes.Equal(c.Content.GroupID, g.Context.GroupID) {
		return nil, ErrNotForGroup
	}
	var key SignaturePublicKey
	switch c.Content.Sender.Type {
	case SenderTypeMember:
		leaf := g.Tree.Leaf(LeafIndex(c.Content.Sender.LeafIndex))
		if leaf == nil {
			return nil, ErrNotMember
		}
		key = leaf.SignatureKey
	case SenderTypeNewMemberCommit:
		// An external commit is signed by the joiner, whose key
		// is in the leaf node of the update path it carries.
		// See RFC 9420, Section 6.1.
		if c.Content.ContentType != ContentTypeCommit || c.Content.Commit.Path == nil {
			return nil, ErrBadExternalCommit
		}
		key = c.Content.Commit.Path.LeafNode.SignatureKey
	default:
		return nil, ErrNotMember
	}
	if err := c.Verify(cs, key, g.Context.Version, &g.Context); err != nil {
		return nil, err
	}
	return c, nil
}

// Protect frames application data as a private message of this epoch.
func (g *Group) Protect(authenticatedData, plaintext []byte) (*MLSMessage, error) {
	cs := g.CipherSuite
	c := &AuthenticatedContent{
		WireFormat: WireFormatPrivateMessage,
		Content: FramedContent{
			GroupID:           g.Context.GroupID,
			Epoch:             g.Context.Epoch,
			Sender:            Sender{Type: SenderTypeMember, LeafIndex: uint32(g.Index)},
			AuthenticatedData: authenticatedData,
			ContentType:       ContentTypeApplication,
			ApplicationData:   plaintext,
		},
		Auth: FramedContentAuthData{ContentType: ContentTypeApplication},
	}
	if err := c.Sign(cs, g.client.SignaturePriv, g.Context.Version, &g.Context); err != nil {
		return nil, err
	}
	ratchet, err := g.keys.Ratchet(g.Index, ContentTypeApplication)
	if err != nil {
		return nil, err
	}
	pm, err := c.PrivateMessage(cs, ratchet, g.Schedule.SenderDataSecret, 0)
	if err != nil {
		return nil, err
	}
	return &MLSMessage{Version: g.Context.Version, WireFormat: WireFormatPrivateMessage, PrivateMessage: pm}, nil
}

// Handle processes a handshake message. A proposal is remembered
// until a commit refers to it, and Handle returns g unchanged; a
// commit ends the epoch, and Handle returns the group's state in the
// next one.
func (g *Group) Handle(m *MLSMessage) (*Group, error) {
	c, err := g.Unprotect(m)
	if err != nil {
		return nil, err
	}
	switch c.Content.ContentType {
	case ContentTypeProposal:
		return g, g.AddProposal(c)
	case ContentTypeCommit:
		return g.ApplyCommit(c)
	}
	return nil, ErrNotCommit
}

// AddProposal remembers a proposal so that a later commit can refer
// to it by reference.
func (g *Group) AddProposal(c *AuthenticatedContent) error {
	if c.Content.ContentType != ContentTypeProposal {
		return ErrNotProposal
	}
	ref, err := c.Ref(g.CipherSuite)
	if err != nil {
		return err
	}
	g.proposals[hex.EncodeToString(ref)] = c
	return nil
}

// a proposal together with the sender that sent it. A proposal a
// commit carries inline comes from the committer; one carried by
// reference comes from whoever sent it in the epoch, which may be a
// member or, under Section 12.1.8, a party outside the group.
type proposal struct {
	*Proposal
	from Sender
}

// leaf is the leaf the proposal's sender occupies. It is meaningful
// only for a proposal from a member.
func (p proposal) leaf() LeafIndex { return LeafIndex(p.from.LeafIndex) }

// resolve turns the proposals a commit refers to into the proposals
// themselves, in the order the commit lists them.
func (g *Group) resolve(commit *Commit, committer Sender) ([]proposal, error) {
	out := make([]proposal, 0, len(commit.Proposals))
	for i := range commit.Proposals {
		p := &commit.Proposals[i]
		switch p.Type {
		case ProposalOrRefTypeProposal:
			out = append(out, proposal{p.Proposal, committer})
		case ProposalOrRefTypeReference:
			c, ok := g.proposals[hex.EncodeToString(p.Reference)]
			if !ok {
				return nil, ErrUnknownProposal
			}
			out = append(out, proposal{c.Content.Proposal, c.Content.Sender})
		}
	}
	return out, nil
}

// ApplyCommit applies a commit sent in this epoch and returns the
// group's state in the epoch the commit begins. g is left unchanged.
// See RFC 9420, Section 12.4.2.
func (g *Group) ApplyCommit(c *AuthenticatedContent) (*Group, error) {
	cs := g.CipherSuite
	if c.Content.ContentType != ContentTypeCommit {
		return nil, ErrNotCommit
	}
	commit := c.Content.Commit
	external := c.Content.Sender.Type == SenderTypeNewMemberCommit
	if external {
		if err := externalCommitOK(commit); err != nil {
			return nil, err
		}
	}
	sender := LeafIndex(c.Content.Sender.LeafIndex)
	proposals, err := g.resolve(commit, c.Content.Sender)
	if err != nil {
		return nil, err
	}
	if !external {
		if err := g.Tree.validateProposals(proposals, sender, &g.Context); err != nil {
			return nil, err
		}
	}

	next := &Group{
		CipherSuite: cs,
		Context:     g.Context,
		Tree:        slices.Clone(g.Tree),
		Index:       g.Index,
		client:      g.client,
		proposals:   make(map[string]*AuthenticatedContent),
		resumption:  maps.Clone(g.resumption),
	}
	next.Secrets = NewTreeSecrets(g.Index, g.Secrets.Leaf)
	maps.Copy(next.Secrets.Secrets, g.Secrets.Secrets)

	ch, err := next.apply(proposals)
	if err != nil {
		return nil, err
	}
	if external {
		// The joiner takes the leftmost free leaf, as an Add
		// would give it. See RFC 9420, Section 12.4.3.2.
		if ch.kemOutput == nil {
			return nil, ErrBadExternalCommit
		}
		leaf := commit.Path.LeafNode
		sender = next.Tree.Add(&leaf)
	}
	if next.Tree.Leaf(g.Index) == nil {
		return nil, ErrRemoved
	}

	// The path secrets are encrypted under a provisional group
	// context: the new epoch and tree, but the old transcript hash.
	next.Context.Epoch = g.Context.Epoch + 1

	// The commit secret comes from the update path, if there is
	// one, and is otherwise all zero.
	commitSecret := make([]byte, cs.HashSize())
	if commit.Path != nil {
		if sender == g.Index && !external {
			return nil, ErrOwnCommit
		}
		if err := next.Tree.MergeUpdatePath(cs, sender, commit.Path); err != nil {
			return nil, err
		}
		if err := next.Tree.validateLeafInGroup(cs, &commit.Path.LeafNode, sender, &next.Context, LeafNodeSourceCommit); err != nil {
			return nil, err
		}
		next.Secrets.prune(cs, next.Tree)
		commitSecret, err = next.Tree.DecryptPathSecrets(cs, sender, commit.Path, &next.Context, next.Secrets, ch.added)
		if err != nil {
			return nil, err
		}
	} else {
		next.Secrets.prune(cs, next.Tree)
	}
	if next.Context.TreeHash, err = next.Tree.RootHash(cs); err != nil {
		return nil, err
	}
	if next.Context.ConfirmedTranscriptHash, err = cs.ConfirmedTranscriptHash(g.interim, c); err != nil {
		return nil, err
	}

	pskSecret, err := g.client.pskSecret(ch.psks, g)
	if err != nil {
		return nil, err
	}
	// An external commit replaces the previous epoch's init secret
	// with one the joiner sent. See RFC 9420, Section 8.3.
	initSecret := g.Schedule.InitSecret
	if external {
		if initSecret, err = g.Schedule.ExternalInit(ch.kemOutput); err != nil {
			return nil, err
		}
	}
	joiner, err := cs.JoinerSecret(initSecret, commitSecret, &next.Context)
	if err != nil {
		return nil, err
	}
	if next.Schedule, err = NewKeySchedule(cs, joiner, pskSecret, &next.Context); err != nil {
		return nil, err
	}
	tag, err := cs.ConfirmationTag(next.Schedule.ConfirmationKey, next.Context.ConfirmedTranscriptHash)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(tag, c.Auth.ConfirmationTag) {
		return nil, ErrBadConfirmationTag
	}
	if next.interim, err = cs.InterimTranscriptHash(next.Context.ConfirmedTranscriptHash, c.Auth.ConfirmationTag); err != nil {
		return nil, err
	}
	next.keys = NewSecretTree(cs, next.Tree.Size(), next.Schedule.EncryptionSecret)
	next.resumption[next.Context.Epoch] = next.Schedule.ResumptionPSK
	if err := next.Secrets.Consistent(cs, next.Tree); err != nil {
		return nil, err
	}
	return next, nil
}

// changes is what applying a commit's proposals did to a group,
// beyond the tree itself.
type changes struct {
	added     []LeafIndex      // leaves added, which receive no path secret
	psks      []PreSharedKeyID // pre-shared keys the commit injects
	kemOutput []byte           // set by an ExternalInit proposal
}

// apply applies a commit's proposals to the tree and the group
// context of the new epoch, in the order RFC 9420, Section 12.3
// prescribes.
func (g *Group) apply(proposals []proposal) (*changes, error) {
	var ch changes
	for _, p := range proposals {
		if p.Type == ProposalTypeGroupContextExtensions {
			g.Context.Extensions = p.GroupContextExtensions.Extensions
		}
	}
	for _, p := range proposals {
		if p.Type == ProposalTypeUpdate {
			leaf := p.Update.LeafNode
			old := g.Tree.Leaf(p.leaf())
			if old == nil {
				return nil, ErrLeafRange
			}
			// An update must change the leaf's encryption key;
			// otherwise it gives the group no new secrecy.
			if bytes.Equal(old.EncryptionKey, leaf.EncryptionKey) {
				return nil, ErrDuplicateLeafKey
			}
			if err := g.Tree.validateLeafInGroup(g.CipherSuite, &leaf, p.leaf(), &g.Context, LeafNodeSourceUpdate); err != nil {
				return nil, err
			}
			g.Tree.Update(p.leaf(), &leaf)
		}
	}
	for _, p := range proposals {
		if p.Type == ProposalTypeRemove {
			if g.Tree.Leaf(LeafIndex(p.Remove.Removed)) == nil {
				return nil, ErrLeafRange
			}
			g.Tree.Remove(LeafIndex(p.Remove.Removed))
		}
	}
	for _, p := range proposals {
		switch p.Type {
		case ProposalTypeAdd:
			if p.Add.KeyPackage.CipherSuite != g.CipherSuite {
				return nil, ErrUnsupportedCipherSuite
			}
			// The lifetime is not checked here: a key package
			// may expire between being sent and being applied,
			// and RFC 9420, Section 7.3 only recommends the
			// check on the receiving side.
			if err := p.Add.KeyPackage.Validate(time.Time{}); err != nil {
				return nil, err
			}
			leaf := p.Add.KeyPackage.LeafNode
			i := g.Tree.Add(&leaf)
			if err := g.Tree.validateLeafInGroup(g.CipherSuite, &leaf, i, &g.Context, LeafNodeSourceKeyPackage); err != nil {
				return nil, err
			}
			ch.added = append(ch.added, i)
		case ProposalTypePreSharedKey:
			ch.psks = append(ch.psks, p.PreSharedKey.PSK)
		case ProposalTypeExternalInit:
			if ch.kemOutput != nil {
				return nil, ErrBadExternalCommit
			}
			ch.kemOutput = p.ExternalInit.KEMOutput
		case ProposalTypeReInit:
			return nil, ErrUnsupportedProposal
		}
	}
	return &ch, nil
}
