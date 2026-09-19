package mls

import (
	"bytes"
	"crypto/rand"
	"maps"
	"slices"
	"time"
)

// NewClient generates the key material of one member: a signature key
// pair that outlives the group, and an init and encryption key pair
// for a single key package, which offers the client for addition to a
// group and is meant to be used once. The key package is valid from
// now until now plus lifetime.
func NewClient(cs CipherSuite, cred Credential, lifetime time.Duration) (*Client, error) {
	sigPriv, sigPub, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		return nil, err
	}
	initPriv, initPub, err := cs.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	encPriv, encPub, err := cs.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	kp := &KeyPackage{
		Version:     Version10,
		CipherSuite: cs,
		InitKey:     initPub,
		LeafNode: LeafNode{
			EncryptionKey: encPub,
			SignatureKey:  sigPub,
			Credential:    cred,
			Capabilities: Capabilities{
				Versions:     []ProtocolVersion{Version10},
				CipherSuites: []CipherSuite{cs},
				Credentials:  []CredentialType{cred.Type},
			},
			Source:   LeafNodeSourceKeyPackage,
			Lifetime: Lifetime{NotBefore: uint64(now.Unix()), NotAfter: uint64(now.Add(lifetime).Unix())},
		},
	}
	// A leaf node from a key package is signed without a group, so
	// the group ID and leaf index below do not enter the signature.
	if err := kp.LeafNode.Sign(cs, sigPriv, nil, 0); err != nil {
		return nil, err
	}
	if err := kp.Sign(sigPriv); err != nil {
		return nil, err
	}
	return &Client{
		CipherSuite:    cs,
		KeyPackage:     kp,
		InitPriv:       initPriv,
		EncryptionPriv: encPriv,
		SignaturePriv:  sigPriv,
	}, nil
}

// NewGroup creates a group whose only member is c. Other members join
// by being added in a later commit. The epoch secret of the first
// epoch is random rather than derived, since there is no previous
// epoch to derive it from. See RFC 9420, Section 11.
func (c *Client) NewGroup(groupID []byte, extensions Extensions) (*Group, error) {
	cs := c.CipherSuite
	leaf := c.KeyPackage.LeafNode
	tree := RatchetTree{{Type: NodeTypeLeaf, Leaf: &leaf}}
	root, err := tree.RootHash(cs)
	if err != nil {
		return nil, err
	}
	g := &Group{
		CipherSuite: cs,
		Context: GroupContext{
			Version:     Version10,
			CipherSuite: cs,
			GroupID:     groupID,
			TreeHash:    root,
			Extensions:  extensions,
		},
		Tree:       tree,
		Secrets:    NewTreeSecrets(0, c.EncryptionPriv),
		client:     c,
		proposals:  make(map[string]*AuthenticatedContent),
		updates:    make(map[string][]byte),
		resumption: make(map[uint64][]byte),
	}
	epochSecret := make([]byte, cs.HashSize())
	if _, err := rand.Read(epochSecret); err != nil {
		return nil, err
	}
	if g.Schedule, err = newEpochSchedule(cs, epochSecret); err != nil {
		return nil, err
	}
	tag, err := cs.ConfirmationTag(g.Schedule.ConfirmationKey, nil)
	if err != nil {
		return nil, err
	}
	if g.interim, err = cs.InterimTranscriptHash(nil, tag); err != nil {
		return nil, err
	}
	g.keys = NewSecretTree(cs, tree.Size(), g.Schedule.EncryptionSecret)
	g.resumption[0] = g.Schedule.ResumptionPSK
	return g, nil
}

// Propose frames a proposal as a handshake message of this epoch and
// remembers it, so that a commit made in this epoch - by g or by
// another member that receives the message - can refer to it by
// reference.
func (g *Group) Propose(p *Proposal) (*MLSMessage, error) {
	if g.reinit != nil {
		return nil, ErrReInitialized
	}
	c := &AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content: FramedContent{
			GroupID:     g.Context.GroupID,
			Epoch:       g.Context.Epoch,
			Sender:      Sender{Type: SenderTypeMember, LeafIndex: uint32(g.Index)},
			ContentType: ContentTypeProposal,
			Proposal:    p,
		},
		Auth: FramedContentAuthData{ContentType: ContentTypeProposal},
	}
	if err := c.Sign(g.CipherSuite, g.client.SignaturePriv, g.Context.Version, &g.Context); err != nil {
		return nil, err
	}
	if err := g.AddProposal(c); err != nil {
		return nil, err
	}
	pm, err := c.PublicMessage(g.CipherSuite, g.Schedule.MembershipKey, &g.Context)
	if err != nil {
		return nil, err
	}
	return &MLSMessage{Version: g.Context.Version, WireFormat: WireFormatPublicMessage, PublicMessage: pm}, nil
}

// ProposeUpdate proposes leaf as the sender's own new leaf node and
// keeps encPriv, the private half of leaf.EncryptionKey, so that the
// group can follow the commit that applies the proposal. A member
// that proposes an update any other way cannot process that commit:
// the committer encrypts the path secrets to the new key, and only
// the proposer holds the matching private key.
//
// The leaf must have source update and must be signed over the group
// ID and the member's own leaf index. Rotating the signature key and
// the credential along with the encryption key is what recovers from
// a compromised signature key.
//
// A commit must not carry its sender's own update, so a member with
// an update outstanding drops it when it commits.
func (g *Group) ProposeUpdate(leaf *LeafNode, encPriv []byte) (*MLSMessage, error) {
	if leaf.Source != LeafNodeSourceUpdate {
		return nil, ErrBadLeafNodeSource
	}
	pub, err := g.CipherSuite.PublicKey(encPriv)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pub, leaf.EncryptionKey) {
		return nil, ErrBadTreeKEM
	}
	m, err := g.Propose(&Proposal{Type: ProposalTypeUpdate, Update: &Update{LeafNode: *leaf}})
	if err != nil {
		return nil, err
	}
	g.updates[string(leaf.EncryptionKey)] = encPriv
	return m, nil
}

// Commit ends the epoch. It applies every proposal g has seen in this
// epoch, along with the extra proposals, which are carried in the
// commit itself. It returns the group's state in the new epoch, the
// commit to send to the other members, and a welcome for the members
// the commit adds, which is nil if it adds none. g is left unchanged,
// and remains usable until the commit is confirmed.
//
// The commit always updates the committer's direct path, which RFC
// 9420, Section 12.4 requires unless every proposal is an Add.
func (g *Group) Commit(extra []*Proposal) (*Group, *MLSMessage, *MLSMessage, error) {
	return g.commit(extra, SenderTypeMember)
}

// staged returns the proposals g has been given for this epoch that a
// commit carrying extra may also carry, in a stable order.
//
// RFC 9420, Section 12.2 allows a commit to cover at most one Update
// or Remove for any one leaf, so the ones that conflict have to be
// settled before the commit is built rather than rejected after. The
// commit's own proposals decide the leaves they touch, and a removal
// decides over an update of the leaf it removes; a staged proposal
// that loses is left behind for a later epoch. A commit never carries
// a proposal for its sender's own leaf either: the sender's leaf is
// replaced by the update path, and a member cannot remove itself.
func (g *Group) staged(extra []*Proposal, from Sender) []*AuthenticatedContent {
	touched := make(map[LeafIndex]bool)
	for _, p := range extra {
		if i, ok := touchedLeaf(p, from); ok {
			touched[i] = true
		}
	}
	refs := slices.Sorted(maps.Keys(g.proposals))
	out := make([]*AuthenticatedContent, 0, len(refs))
	// Removals first, so that an update of a leaf a staged removal
	// covers is the one left behind and not the other way round.
	for _, removes := range []bool{true, false} {
		for _, ref := range refs {
			c := g.proposals[ref]
			p := c.Content.Proposal
			if (p.Type == ProposalTypeRemove) != removes {
				continue
			}
			if i, ok := touchedLeaf(p, c.Content.Sender); ok {
				if touched[i] || i == g.Index {
					continue
				}
				touched[i] = true
			}
			out = append(out, c)
		}
	}
	return out
}

// commit builds a commit from the proposals g has seen and the extra
// proposals given, as a member or as a new member joining by external
// commit. The two differ in who signs the commit and in how the new
// epoch's init secret is reached, and not in anything below that.
func (g *Group) commit(extra []*Proposal, sender SenderType) (*Group, *MLSMessage, *MLSMessage, error) {
	if g.reinit != nil {
		return nil, nil, nil, ErrReInitialized
	}
	cs := g.CipherSuite
	commit := &Commit{}
	from := Sender{Type: sender}
	if sender == SenderTypeMember {
		from.LeafIndex = uint32(g.Index)
	}
	proposals := make([]proposal, 0, len(g.proposals)+len(extra))
	if sender == SenderTypeMember {
		for _, c := range g.staged(extra, from) {
			r, err := c.Ref(cs)
			if err != nil {
				return nil, nil, nil, err
			}
			commit.Proposals = append(commit.Proposals, ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: r})
			proposals = append(proposals, proposal{c.Content.Proposal, c.Content.Sender})
		}
	}
	now := time.Now()
	for _, p := range extra {
		// A member must not send a key package that has
		// expired, even though it may receive one.
		if p.Type == ProposalTypeAdd {
			if err := p.Add.KeyPackage.Validate(now); err != nil {
				return nil, nil, nil, err
			}
		}
		commit.Proposals = append(commit.Proposals, ProposalOrRef{Type: ProposalOrRefTypeProposal, Proposal: p})
		proposals = append(proposals, proposal{p, from})
	}
	if sender == SenderTypeNewMemberCommit {
		if err := externalProposalsOK(commit); err != nil {
			return nil, nil, nil, err
		}
	} else if err := g.Tree.validateProposals(proposals, g.Index, &g.Context); err != nil {
		return nil, nil, nil, err
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
	ch, err := next.apply(proposals)
	if err != nil {
		return nil, nil, nil, err
	}
	next.reinit = ch.reinit
	if next.Tree.Leaf(g.Index) == nil {
		return nil, nil, nil, ErrRemoved
	}
	// A resync commit removes the joiner's prior leaf, which may
	// have been to the left of the one it just took; the joiner
	// moves into the leftmost free leaf as the members will place
	// it when they apply the commit.
	if sender == SenderTypeNewMemberCommit {
		leaf := *next.Tree.Leaf(g.Index)
		next.Tree.Remove(g.Index)
		next.Index = next.Tree.Add(&leaf)
		next.Secrets = NewTreeSecrets(next.Index, g.Secrets.Leaf)
	}
	next.Context.Epoch = g.Context.Epoch + 1

	// The update path is built against the provisional group
	// context: the new epoch and tree, but the old transcript hash.
	// Members added by this commit are excluded from it; they
	// receive their path secret in the welcome instead.
	leafSecret := make([]byte, cs.HashSize())
	if _, err := rand.Read(leafSecret); err != nil {
		return nil, nil, nil, err
	}
	path, secrets, commitSecret, err := next.Tree.CreateUpdatePath(cs, next.Index, leafSecret, g.client.SignaturePriv, &next.Context, ch.added)
	if err != nil {
		return nil, nil, nil, err
	}
	commit.Path = path
	next.Secrets = secrets
	if next.Context.TreeHash, err = next.Tree.RootHash(cs); err != nil {
		return nil, nil, nil, err
	}

	// Sign the commit, which the transcript hash then covers, and
	// derive the new epoch's secrets from it.
	c := &AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content: FramedContent{
			GroupID:     g.Context.GroupID,
			Epoch:       g.Context.Epoch,
			Sender:      from,
			ContentType: ContentTypeCommit,
			Commit:      commit,
		},
		Auth: FramedContentAuthData{ContentType: ContentTypeCommit},
	}
	if err := c.Sign(cs, g.client.SignaturePriv, g.Context.Version, &g.Context); err != nil {
		return nil, nil, nil, err
	}
	if next.Context.ConfirmedTranscriptHash, err = cs.ConfirmedTranscriptHash(g.interim, c); err != nil {
		return nil, nil, nil, err
	}
	pskSecret, err := g.client.pskSecret(ch.psks, g)
	if err != nil {
		return nil, nil, nil, err
	}
	joiner, err := cs.JoinerSecret(g.Schedule.InitSecret, commitSecret, &next.Context)
	if err != nil {
		return nil, nil, nil, err
	}
	if next.Schedule, err = NewKeySchedule(cs, joiner, pskSecret, &next.Context); err != nil {
		return nil, nil, nil, err
	}
	if c.Auth.ConfirmationTag, err = cs.ConfirmationTag(next.Schedule.ConfirmationKey, next.Context.ConfirmedTranscriptHash); err != nil {
		return nil, nil, nil, err
	}
	if next.interim, err = cs.InterimTranscriptHash(next.Context.ConfirmedTranscriptHash, c.Auth.ConfirmationTag); err != nil {
		return nil, nil, nil, err
	}
	next.keys = NewSecretTree(cs, next.Tree.Size(), next.Schedule.EncryptionSecret)
	next.resumption[next.Context.Epoch] = next.Schedule.ResumptionPSK

	pm, err := c.PublicMessage(cs, g.Schedule.MembershipKey, &g.Context)
	if err != nil {
		return nil, nil, nil, err
	}
	msg := &MLSMessage{Version: g.Context.Version, WireFormat: WireFormatPublicMessage, PublicMessage: pm}

	welcome, err := next.welcome(c.Auth.ConfirmationTag, proposals, ch.added, ch.psks)
	if err != nil {
		return nil, nil, nil, err
	}
	return next, msg, welcome, nil
}

// welcome builds the welcome message for the members a commit added.
// It returns nil if the commit added none. The group info carries the
// ratchet tree, so that a joiner needs nothing but the welcome.
func (g *Group) welcome(confirmationTag []byte, proposals []proposal, added []LeafIndex, psks []PreSharedKeyID) (*MLSMessage, error) {
	if len(added) == 0 {
		return nil, nil
	}
	cs := g.CipherSuite
	info := &GroupInfo{
		GroupContext:    g.Context,
		ConfirmationTag: confirmationTag,
		Signer:          uint32(g.Index),
	}
	if err := info.Extensions.Set(ExtensionTypeRatchetTree, &g.Tree); err != nil {
		return nil, err
	}
	if err := info.Sign(g.client.SignaturePriv); err != nil {
		return nil, err
	}
	w := &Welcome{CipherSuite: cs}
	if err := w.SetGroupInfo(g.Schedule.WelcomeSecret, info); err != nil {
		return nil, err
	}

	// Each new member gets the path secret of the node where its
	// direct path meets the committer's, and nothing above it.
	keyPackages := make(map[LeafIndex]*KeyPackage)
	for _, p := range proposals {
		if p.Type == ProposalTypeAdd {
			for _, i := range added {
				if leaf := g.Tree.Leaf(i); leaf != nil && keyPackages[i] == nil &&
					string(leaf.EncryptionKey) == string(p.Add.KeyPackage.LeafNode.EncryptionKey) {
					keyPackages[i] = &p.Add.KeyPackage
				}
			}
		}
	}
	for _, i := range added {
		kp := keyPackages[i]
		if kp == nil {
			return nil, ErrUnknownProposal
		}
		ref, err := kp.Ref()
		if err != nil {
			return nil, err
		}
		secrets := &GroupSecrets{JoinerSecret: g.Schedule.JoinerSecret, PSKs: psks}
		if secret, ok := g.Secrets.Secrets[commonAncestor(i, g.Index)]; ok {
			secrets.PathSecret = &PathSecret{PathSecret: secret}
		}
		if err := w.AddMember(ref, kp.InitKey, secrets); err != nil {
			return nil, err
		}
	}
	return &MLSMessage{Version: g.Context.Version, WireFormat: WireFormatWelcome, Welcome: w}, nil
}
