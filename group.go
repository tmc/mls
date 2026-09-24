package mls

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
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

	// ExternalProposal decides whether to accept a proposal from
	// outside the group: from an external sender the group
	// provisioned, or from a client asking to be added (see
	// [ExternalClient.Propose] and [Client.ProposeAdd]). An accepted
	// proposal is committed by the member's next commit like any
	// other. RFC 9420, Section 12.1.8 leaves this decision to the
	// application; a nil ExternalProposal accepts none. Members
	// should share a policy, since a member that did not accept a
	// proposal cannot process a commit that covers it.
	//
	// Such a proposal names its group only by group ID and epoch:
	// its signature does not cover the group context (RFC 9420,
	// Section 6.1). A group whose ID is not unique, as Section 11
	// asks, accepts proposals meant for another group of that ID.
	ExternalProposal func(c *AuthenticatedContent) error

	// Padding blurs the length of the messages [Group.Protect]
	// produces: the plaintext is padded with zeros until its length
	// is a multiple of Padding. Zero or one means no padding, which
	// puts the exact length of every message on the wire. RFC 9420,
	// Section 15.1 leaves the policy to the application, since what
	// it costs and what it hides both depend on the traffic.
	Padding int
}

// A Group is a member's view of an MLS group at one epoch.
//
// A commit does not change a Group: [Group.Commit],
// [Group.ApplyCommit] and a [Group.Handle] of a commit return the
// group's state in the epoch the commit begins, and leave g as it
// was. The old Group remains usable for its own epoch, to decrypt
// messages that arrive late or to try again if the delivery service
// rejects the commit; a caller drops it once it no longer needs it,
// since it holds that epoch's secrets.
//
// Within an epoch a Group does change. [Group.Protect] and
// [Group.Unprotect] advance the secret tree's ratchets, and
// [Group.Propose], [Group.ProposeUpdate], [Group.AddProposal] and a
// [Group.Handle] of a proposal record the proposal. A Group is
// therefore not safe for concurrent use; a caller that shares one
// between goroutines must serialize its calls.
type Group struct {
	CipherSuite CipherSuite
	Context     GroupContext
	Tree        RatchetTree
	schedule    *keySchedule
	Index       LeafIndex    // the member's own leaf
	Secrets     *TreeSecrets // the member's private view of the tree

	client     *Client
	interim    []byte // interim transcript hash
	keys       *secretTree
	proposals  map[string]*AuthenticatedContent // by proposal reference
	updated    map[LeafIndex]string             // references of the staged updates, by leaf
	updates    map[string][]byte                // encryption keys of one's own updates, by public key
	resumption map[uint64][]byte                // resumption PSKs, by epoch
	prior      *Group                           // the group this one was resumed from
	resumed    *PreSharedKeyID                  // the key that links it to prior
	reinit     *Reinit                          // set by a commit that reinitializes
}

// EpochAuthenticator is the value that members compare out of band to
// confirm they agree on the history of the group.
// See RFC 9420, Section 8.
func (g *Group) EpochAuthenticator() []byte { return g.schedule.EpochAuthenticator }

// Export implements MLS-Exporter: it derives an application secret of
// the given length, bound to label and context, that only the members
// of this epoch can compute. Two members of the same epoch that pass
// the same arguments get the same secret, and no other epoch does.
// See RFC 9420, Section 8.5.
func (g *Group) Export(label string, context []byte, length uint16) ([]byte, error) {
	return g.schedule.Export(label, context, length)
}

// Epoch is the number of the epoch g describes.
func (g *Group) Epoch() uint64 { return g.Context.Epoch }

// Join builds a member's view of a group from a welcome message. The
// ratchet tree comes from the welcome's group info if it carries a
// ratchet_tree extension, and otherwise must be supplied in tree.
// See RFC 9420, Section 12.4.3.1.
func (c *Client) Join(w *Welcome, tree RatchetTree) (*Group, error) {
	return c.join(w, tree, nil)
}

// join builds a member's view of a group from a welcome message. old
// is the group the new one was resumed from, if any, whose resumption
// keys the welcome may draw on; see [Client.Resume].
func (c *Client) join(w *Welcome, tree RatchetTree, old *Group) (*Group, error) {
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
	// At most one pre-shared key links the group to one it
	// reinitializes or branches. See RFC 9420, Section 12.4.3.1.
	var resumed *PreSharedKeyID
	for i := range secrets.PSKs {
		if id := &secrets.PSKs[i]; id.Type == PSKTypeResumption && id.Usage != ResumptionPSKUsageApplication {
			if resumed != nil {
				return nil, ErrNotResumed
			}
			resumed = id
		}
	}
	pskSecret, err := c.pskSecret(secrets.PSKs, old)
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
	if info.GroupContext.CipherSuite != cs {
		return nil, ErrUnsupportedCipherSuite
	}
	if info.GroupContext.Version != Version10 {
		return nil, ErrUnsupportedVersion
	}
	var carried RatchetTree
	if ok, err := info.Extensions.Decode(ExtensionTypeRatchetTree, &carried); err != nil {
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

	// Our own leaf is the one holding the key package's leaf node,
	// all of it: a leaf that shares only its encryption key could
	// carry someone else's signature key or credential.
	own, err := Marshal(&c.KeyPackage.LeafNode)
	if err != nil {
		return nil, err
	}
	index := LeafIndex(0)
	for ; ; index++ {
		if index >= tree.Size() {
			return nil, ErrNotMember
		}
		l := tree.Leaf(index)
		if l == nil {
			continue
		}
		b, err := Marshal(l)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(b, own) {
			break
		}
	}

	schedule, err := newKeySchedule(cs, secrets.JoinerSecret, pskSecret, &info.GroupContext)
	if err != nil {
		return nil, err
	}
	tag, err := cs.ConfirmationTag(schedule.ConfirmationKey, info.GroupContext.ConfirmedTranscriptHash)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(tag, info.ConfirmationTag) != 1 {
		return nil, ErrBadConfirmationTag
	}
	interim, err := cs.InterimTranscriptHash(info.GroupContext.ConfirmedTranscriptHash, info.ConfirmationTag)
	if err != nil {
		return nil, err
	}

	private := NewTreeSecrets(index, c.EncryptionPriv)
	if secrets.PathSecret != nil {
		x := commonAncestor(index, signer)
		if err := private.SetPath(cs, tree, x, secrets.PathSecret); err != nil {
			return nil, err
		}
	}
	if err := private.Consistent(cs, tree); err != nil {
		return nil, err
	}
	// The tree is cloned because it comes from the caller, who may
	// be holding it as another group's tree.
	tree = tree.Clone()
	g := &Group{
		CipherSuite: cs,
		Context:     info.GroupContext,
		Tree:        tree,
		schedule:    schedule,
		Index:       index,
		Secrets:     private,
		client:      c,
		interim:     interim,
		keys:        newSecretTree(cs, tree.Size(), schedule.EncryptionSecret),
		proposals:   make(map[string]*AuthenticatedContent),
		updates:     make(map[string][]byte),
		resumption:  map[uint64][]byte{info.GroupContext.Epoch: schedule.ResumptionPSK},
		prior:       old,
		resumed:     resumed,
	}
	return g, nil
}

// verify checks a ratchet tree against the group context that
// summarizes it, and against its own internal consistency.
func (t RatchetTree) verify(cs CipherSuite, ctx *GroupContext) error {
	if err := t.verifyShape(); err != nil {
		return err
	}
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
	if err := t.verifyNodeKeys(); err != nil {
		return err
	}
	if err := t.verifyUnmergedLeaves(); err != nil {
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
		case id.Type == PSKTypeResumption && g.resumptionPSK(id) != nil:
			psks[i] = g.resumptionPSK(id)
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
// the group, checking that it comes from a member of this epoch and
// uses the group's protocol version. Decrypting a private message
// advances the sender's ratchet in g past the message's generation,
// so the same private message cannot be unprotected twice.
func (g *Group) Unprotect(m *Message) (*AuthenticatedContent, error) {
	cs := g.CipherSuite
	var (
		c       *AuthenticatedContent
		advance func()
		err     error
	)
	if m.Version != g.Context.Version {
		return nil, ErrUnsupportedVersion
	}
	public := m.WireFormat == WireFormatPublicMessage
	switch {
	case public && m.PublicMessage != nil:
		c, err = m.PublicMessage.AuthenticatedContent(cs, g.schedule.MembershipKey, &g.Context)
	case m.WireFormat == WireFormatPrivateMessage && m.PrivateMessage != nil:
		pm := m.PrivateMessage
		data, err := pm.openSenderData(cs, g.schedule.SenderDataSecret)
		if err != nil {
			return nil, err
		}
		// The sender must occupy its leaf, and is checked before
		// any key of that leaf is derived. See RFC 9420,
		// Section 6.3.2.
		if g.Tree.Leaf(LeafIndex(data.LeafIndex)) == nil {
			return nil, ErrNotMember
		}
		c, advance, err = pm.authenticatedContent(cs, g.keys, data)
		if err != nil {
			return nil, err
		}
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
		if !public || c.Content.ContentType != ContentTypeCommit || c.Content.Commit.Path == nil {
			return nil, ErrBadExternalCommit
		}
		key = c.Content.Commit.Path.LeafNode.SignatureKey
	case SenderTypeExternal:
		// A party outside the group signs with the key the
		// group provisioned for it, and may send only the
		// proposal types Section 12.1.8 allows.
		if !public || c.Content.ContentType != ContentTypeProposal || !externalProposalType(c.Content.Proposal.Type) {
			return nil, ErrBadExternalSender
		}
		s, err := g.externalSender(c.Content.Sender.SenderIndex)
		if err != nil {
			return nil, err
		}
		key = s.SignatureKey
	case SenderTypeNewMemberProposal:
		// A client proposing its own addition signs with the
		// key in the key package the proposal carries, which
		// the group has no other way to know.
		if !public || c.Content.ContentType != ContentTypeProposal || c.Content.Proposal.Type != ProposalTypeAdd {
			return nil, ErrBadExternalSender
		}
		key = c.Content.Proposal.Add.KeyPackage.LeafNode.SignatureKey
	default:
		return nil, ErrNotMember
	}
	if err := c.Verify(cs, key, g.Context.Version, &g.Context); err != nil {
		return nil, err
	}
	if advance != nil {
		advance()
	}
	return c, nil
}

// Protect frames application data as a private message of this epoch,
// padded as the client's [Client.Padding] asks. It advances the
// member's own application ratchet in g.
func (g *Group) Protect(authenticatedData, plaintext []byte) (*Message, error) {
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
	ratchet, err := g.keys.ratchet(g.Index, ContentTypeApplication)
	if err != nil {
		return nil, err
	}
	pm, err := c.privateMessage(cs, ratchet, g.schedule.SenderDataSecret, g.client.Padding)
	if err != nil {
		return nil, err
	}
	return &Message{Version: g.Context.Version, WireFormat: WireFormatPrivateMessage, PrivateMessage: pm}, nil
}

// maxProposals is the most proposals a group remembers in one epoch.
// It bounds what a sender, member or not, can make every member store
// and every committer consider.
const maxProposals = 1024

// Handle processes a handshake message, and is how a member follows
// the group. A proposal is remembered in g until a commit refers to
// it, and Handle returns g itself; a commit ends the epoch, and
// Handle returns the group's state in the next one, leaving g as it
// was.
func (g *Group) Handle(m *Message) (*Group, error) {
	c, err := g.Unprotect(m)
	if err != nil {
		return nil, err
	}
	switch c.Content.ContentType {
	case ContentTypeProposal:
		if err := g.AddProposal(c); err != nil {
			return nil, err
		}
		return g, nil
	case ContentTypeCommit:
		return g.ApplyCommit(c)
	}
	return nil, ErrNotCommit
}

// AddProposal remembers a proposal so that a later commit can refer
// to it by reference. [Group.Handle] calls it for a proposal message;
// call it directly only for a proposal whose content was already
// recovered and authenticated some other way, such as by
// [Group.Unprotect].
//
// A proposal from outside the group, whether from an external sender
// or from a client asking to be added, is remembered only if the
// client's [Client.ExternalProposal] accepts it. At most
// maxProposals proposals are remembered in one epoch.
//
// A member that rotates its keys twice in one epoch supersedes its
// own earlier update: only the later one is remembered. RFC 9420,
// Section 12.2 allows a commit to cover at most one update for any
// one leaf, and the order the proposals arrived in is known here and
// nowhere else, so this is where the choice between them belongs.
func (g *Group) AddProposal(c *AuthenticatedContent) error {
	if c.Content.ContentType != ContentTypeProposal {
		return ErrNotProposal
	}
	switch c.Content.Sender.Type {
	case SenderTypeExternal, SenderTypeNewMemberProposal:
		accept := g.client.ExternalProposal
		if accept == nil {
			return ErrExternalProposal
		}
		if err := accept(c); err != nil {
			return fmt.Errorf("%w: %w", ErrExternalProposal, err)
		}
	}
	// A key package is checked on receipt, so that one that could
	// never be committed is not kept. Its lifetime is checked when
	// it is committed.
	if p := c.Content.Proposal; p.Type == ProposalTypeAdd {
		if p.Add.KeyPackage.CipherSuite != g.CipherSuite {
			return ErrUnsupportedCipherSuite
		}
		if err := p.Add.KeyPackage.Validate(time.Time{}); err != nil {
			return err
		}
	}
	b, err := c.Ref(g.CipherSuite)
	if err != nil {
		return err
	}
	ref := hex.EncodeToString(b)
	if _, ok := g.proposals[ref]; ok {
		return nil
	}
	i, update := touchedLeaf(c.Content.Proposal, c.Content.Sender)
	update = update && c.Content.Proposal.Type == ProposalTypeUpdate
	superseded, ok := g.updated[i]
	ok = ok && update
	if !ok && len(g.proposals) >= maxProposals {
		return ErrTooManyProposals
	}
	if update {
		if ok {
			delete(g.proposals, superseded)
		}
		if g.updated == nil {
			g.updated = make(map[LeafIndex]string)
		}
		g.updated[i] = ref
	}
	g.proposals[ref] = c
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
// [Group.Handle] calls it for a commit message; call it directly only
// for a commit whose content was already recovered and authenticated
// some other way, such as by [Group.Unprotect], for example to
// inspect the commit before applying it.
// See RFC 9420, Section 12.4.2.
func (g *Group) ApplyCommit(c *AuthenticatedContent) (*Group, error) {
	if g.reinit != nil {
		return nil, ErrReinitialized
	}
	cs := g.CipherSuite
	if c.Content.ContentType != ContentTypeCommit {
		return nil, ErrNotCommit
	}
	commit := c.Content.Commit
	external := c.Content.Sender.Type == SenderTypeNewMemberCommit
	if external {
		if err := g.Tree.externalCommitOK(commit, &g.Context); err != nil {
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
		if commit.Path == nil && pathRequired(proposals) {
			return nil, ErrPathRequired
		}
	}

	next := &Group{
		CipherSuite: cs,
		Context:     g.Context,
		Tree:        g.Tree.Clone(),
		Index:       g.Index,
		client:      g.client,
		proposals:   make(map[string]*AuthenticatedContent),
		updates:     make(map[string][]byte),
		resumption:  maps.Clone(g.resumption),
		prior:       g.prior,
		resumed:     g.resumed,
	}
	next.Secrets = NewTreeSecrets(g.Index, g.Secrets.Leaf)
	maps.Copy(next.Secrets.Secrets, g.Secrets.Secrets)

	ch, err := next.apply(proposals)
	if err != nil {
		return nil, err
	}
	next.reinit = ch.reinit
	if external {
		// The joiner takes the leftmost free leaf, as an Add
		// would give it. See RFC 9420, Section 12.4.3.2. The
		// leaf is empty until the path is merged into it, so that
		// the merge sees the path's keys as new, which they are.
		if ch.kemOutput == nil {
			return nil, ErrBadExternalCommit
		}
		sender = next.Tree.Add(new(LeafNode))
	}
	// A member the commit removes may find its leaf occupied again,
	// by a client the same commit adds.
	if next.Tree.Leaf(g.Index) == nil || slices.Contains(ch.added, g.Index) {
		return nil, ErrRemoved
	}
	// An update the member itself proposed leaves a leaf whose
	// encryption key only the member holds the private half of,
	// kept by ProposeUpdate. Seat it before the path secrets are
	// decrypted, which is what the committer encrypted to it.
	if key := next.Tree.Leaf(g.Index).EncryptionKey; !bytes.Equal(key, g.Tree.Leaf(g.Index).EncryptionKey) {
		priv, ok := g.updates[string(key)]
		if !ok {
			return nil, ErrBadTreeKEM
		}
		next.Secrets = NewTreeSecrets(g.Index, priv)
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
	initSecret := g.schedule.InitSecret
	if external {
		if initSecret, err = g.schedule.ExternalInit(ch.kemOutput); err != nil {
			return nil, err
		}
	}
	joiner, err := cs.JoinerSecret(initSecret, commitSecret, &next.Context)
	if err != nil {
		return nil, err
	}
	if next.schedule, err = newKeySchedule(cs, joiner, pskSecret, &next.Context); err != nil {
		return nil, err
	}
	tag, err := cs.ConfirmationTag(next.schedule.ConfirmationKey, next.Context.ConfirmedTranscriptHash)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(tag, c.Auth.ConfirmationTag) != 1 {
		return nil, ErrBadConfirmationTag
	}
	if next.interim, err = cs.InterimTranscriptHash(next.Context.ConfirmedTranscriptHash, c.Auth.ConfirmationTag); err != nil {
		return nil, err
	}
	next.keys = newSecretTree(cs, next.Tree.Size(), next.schedule.EncryptionSecret)
	next.resumption[next.Context.Epoch] = next.schedule.ResumptionPSK
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
	reinit    *Reinit          // set by a Reinit proposal
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
	var updated []LeafIndex
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
			g.Tree.Update(p.leaf(), &leaf)
			updated = append(updated, p.leaf())
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
	// The updated leaves are checked against the members that
	// remain, so that a key held by a member the commit removes
	// does not count as taken.
	for _, i := range updated {
		leaf := g.Tree.Leaf(i)
		if leaf == nil {
			return nil, ErrLeafRange
		}
		if err := g.Tree.validateLeafInGroup(g.CipherSuite, leaf, i, &g.Context, LeafNodeSourceUpdate); err != nil {
			return nil, err
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
			leaf := new(p.Add.KeyPackage.LeafNode)
			i := g.Tree.Add(leaf)
			if err := g.Tree.validateLeafInGroup(g.CipherSuite, leaf, i, &g.Context, LeafNodeSourceKeyPackage); err != nil {
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
		case ProposalTypeReinit:
			ch.reinit = p.Reinit
		}
	}
	return &ch, nil
}
