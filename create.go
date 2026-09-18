package mls

import (
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
	cs := g.CipherSuite
	commit := &Commit{}
	proposals := make([]proposal, 0, len(g.proposals)+len(extra))
	for _, ref := range slices.Sorted(maps.Keys(g.proposals)) {
		c := g.proposals[ref]
		r, err := c.Ref(cs)
		if err != nil {
			return nil, nil, nil, err
		}
		commit.Proposals = append(commit.Proposals, ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: r})
		proposals = append(proposals, proposal{c.Content.Proposal, LeafIndex(c.Content.Sender.LeafIndex)})
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
		proposals = append(proposals, proposal{p, g.Index})
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
	added, psks, err := next.apply(proposals)
	if err != nil {
		return nil, nil, nil, err
	}
	if next.Tree.Leaf(g.Index) == nil {
		return nil, nil, nil, ErrRemoved
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
	path, secrets, commitSecret, err := next.Tree.CreateUpdatePath(cs, g.Index, leafSecret, g.client.SignaturePriv, &next.Context, added)
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
			Sender:      Sender{Type: SenderTypeMember, LeafIndex: uint32(g.Index)},
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
	pskSecret, err := g.client.pskSecret(psks, g)
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

	welcome, err := next.welcome(c.Auth.ConfirmationTag, proposals, added, psks)
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
