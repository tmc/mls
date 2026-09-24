package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/tmc/mls"
	pb "github.com/tmc/mls/interop/internal/mlsclient"
)

// keyPackageLifetime is how long the key packages this client makes
// stay valid.
const keyPackageLifetime = 24 * time.Hour

// A member is one mls.Client together with the external pre-shared
// keys the harness has given it.
type member struct {
	c    *mls.Client
	psks map[string][]byte
}

func newMember(c *mls.Client) *member {
	m := &member{c: c, psks: make(map[string][]byte)}
	c.PSK = func(id mls.PreSharedKeyID) ([]byte, error) {
		if psk, ok := m.psks[string(id.PSKID)]; ok {
			return psk, nil
		}
		return nil, mls.ErrUnknownPSK
	}
	// The harness commits every external proposal it makes.
	c.ExternalProposal = func(*mls.AuthenticatedContent) error { return nil }
	return m
}

func newIdentity(cs mls.CipherSuite, identity []byte) (*member, error) {
	if !cs.Supported() {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported cipher suite %d", cs)
	}
	c, err := mls.NewClient(cs, basic(identity), keyPackageLifetime)
	if err != nil {
		return nil, fmt.Errorf("new client: %w", err)
	}
	return newMember(c), nil
}

func basic(identity []byte) mls.Credential {
	return mls.Credential{Type: mls.CredentialTypeBasic, Identity: bytes.Clone(identity)}
}

// A state is one member's view of one group.
type state struct {
	m       *member
	group   *mls.Group
	pending *mls.Group            // the state after the member's own commit
	past    map[uint64]*mls.Group // earlier epochs, for late messages
	sent    map[string]bool       // handshake messages the member sent
}

// A reinit is a member between the commit of a Reinit proposal and
// joining the new group.
type reinit struct {
	old *mls.Group
	m   *member // the member's client for the new group
}

// A signer is an external sender.
type signer struct {
	cs   mls.CipherSuite
	priv []byte
	pub  mls.SignaturePublicKey
}

type server struct {
	pb.UnimplementedMLSClientServer

	mu      sync.Mutex
	next    uint32
	states  map[uint32]*state
	txs     map[uint32]*member
	reinits map[uint32]*reinit
	signers map[uint32]*signer
}

func newServer() *server {
	return &server{
		states:  make(map[uint32]*state),
		txs:     make(map[uint32]*member),
		reinits: make(map[uint32]*reinit),
		signers: make(map[uint32]*signer),
	}
}

// id returns a fresh identifier. States, transactions, reinits and
// signers share one counter, because StorePSK takes either a state or
// a transaction ID.
func (s *server) id() uint32 {
	s.next++
	return s.next
}

func (s *server) addState(m *member, g *mls.Group) uint32 {
	id := s.id()
	s.states[id] = &state{m: m, group: g, past: make(map[uint64]*mls.Group), sent: make(map[string]bool)}
	return id
}

func (s *server) state(id uint32) (*state, error) {
	st, ok := s.states[id]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown state %d", id)
	}
	return st, nil
}

func (s *server) tx(id uint32) (*member, error) {
	m, ok := s.txs[id]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown transaction %d", id)
	}
	return m, nil
}

func encode(m *mls.Message) ([]byte, error) {
	b, err := mls.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encode message: %w", err)
	}
	return b, nil
}

func decode(b []byte) (*mls.Message, error) {
	m := new(mls.Message)
	if err := mls.Unmarshal(b, m); err != nil {
		return nil, fmt.Errorf("decode message: %w", err)
	}
	return m, nil
}

func decodeKeyPackage(b []byte) (*mls.KeyPackage, error) {
	m, err := decode(b)
	if err != nil {
		return nil, err
	}
	if m.WireFormat != mls.WireFormatKeyPackage {
		return nil, fmt.Errorf("decode key package: wire format %d", m.WireFormat)
	}
	return m.KeyPackage, nil
}

func decodeGroupInfo(b []byte) (*mls.GroupInfo, error) {
	m, err := decode(b)
	if err != nil {
		return nil, err
	}
	if m.WireFormat != mls.WireFormatGroupInfo {
		return nil, fmt.Errorf("decode group info: wire format %d", m.WireFormat)
	}
	return m.GroupInfo, nil
}

func decodeWelcome(b []byte) (*mls.Welcome, error) {
	m, err := decode(b)
	if err != nil {
		return nil, err
	}
	if m.WireFormat != mls.WireFormatWelcome {
		return nil, fmt.Errorf("decode welcome: wire format %d", m.WireFormat)
	}
	return m.Welcome, nil
}

// decodeTree decodes an optional ratchet tree.
func decodeTree(b []byte) (mls.RatchetTree, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var t mls.RatchetTree
	if err := mls.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("decode ratchet tree: %w", err)
	}
	return t, nil
}

func encodeTree(t mls.RatchetTree) ([]byte, error) {
	b, err := mls.Marshal(&t)
	if err != nil {
		return nil, fmt.Errorf("encode ratchet tree: %w", err)
	}
	return b, nil
}

func extensions(es []*pb.Extension) mls.Extensions {
	out := make(mls.Extensions, len(es))
	for i, e := range es {
		out[i] = mls.Extension{Type: mls.ExtensionType(e.ExtensionType), Data: e.ExtensionData}
	}
	return out
}

func nonce(cs mls.CipherSuite) []byte {
	b := make([]byte, cs.HashSize())
	rand.Read(b)
	return b
}

// findMember returns the leaf of the member whose basic credential
// names identity.
func findMember(t mls.RatchetTree, identity []byte) (mls.LeafIndex, error) {
	for i, l := range t.Members() {
		if bytes.Equal(l.Credential.Identity, identity) {
			return i, nil
		}
	}
	return 0, fmt.Errorf("no member %q", identity)
}

// proposal builds the proposal a description asks for, in a group of
// the given suite, ID and tree.
func proposal(d *pb.ProposalDescription, cs mls.CipherSuite, groupID []byte, tree mls.RatchetTree) (*mls.Proposal, error) {
	switch string(d.ProposalType) {
	case "add":
		kp, err := decodeKeyPackage(d.KeyPackage)
		if err != nil {
			return nil, err
		}
		return &mls.Proposal{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *kp}}, nil
	case "remove":
		i, err := findMember(tree, d.RemovedId)
		if err != nil {
			return nil, err
		}
		return &mls.Proposal{Type: mls.ProposalTypeRemove, Remove: &mls.Remove{Removed: uint32(i)}}, nil
	case "externalPSK":
		return pskProposal(mls.PreSharedKeyID{Type: mls.PSKTypeExternal, PSKID: d.PskId, PSKNonce: nonce(cs)}), nil
	case "resumptionPSK":
		return pskProposal(mls.PreSharedKeyID{
			Type:       mls.PSKTypeResumption,
			Usage:      mls.ResumptionPSKUsageApplication,
			PSKGroupID: groupID,
			PSKEpoch:   d.EpochId,
			PSKNonce:   nonce(cs),
		}), nil
	case "groupContextExtensions":
		return &mls.Proposal{
			Type:                   mls.ProposalTypeGroupContextExtensions,
			GroupContextExtensions: &mls.GroupContextExtensions{Extensions: extensions(d.Extensions)},
		}, nil
	case "reinit":
		return &mls.Proposal{Type: mls.ProposalTypeReinit, Reinit: &mls.Reinit{
			GroupID:     d.GroupId,
			Version:     mls.Version10,
			CipherSuite: mls.CipherSuite(d.CipherSuite),
			Extensions:  extensions(d.Extensions),
		}}, nil
	}
	return nil, status.Errorf(codes.InvalidArgument, "unknown proposal type %q", d.ProposalType)
}

func pskProposal(id mls.PreSharedKeyID) *mls.Proposal {
	return &mls.Proposal{Type: mls.ProposalTypePreSharedKey, PreSharedKey: &mls.PreSharedKey{PSK: id}}
}

func (s *server) Name(context.Context, *pb.NameRequest) (*pb.NameResponse, error) {
	return &pb.NameResponse{Name: "tmc/mls"}, nil
}

func (s *server) SupportedCiphersuites(context.Context, *pb.SupportedCiphersuitesRequest) (*pb.SupportedCiphersuitesResponse, error) {
	var suites []uint32
	for cs := mls.CipherSuite(1); cs < 0x100; cs++ {
		if cs.Supported() {
			suites = append(suites, uint32(cs))
		}
	}
	return &pb.SupportedCiphersuitesResponse{Ciphersuites: suites}, nil
}

func (s *server) CreateGroup(_ context.Context, req *pb.CreateGroupRequest) (*pb.CreateGroupResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := newIdentity(mls.CipherSuite(req.CipherSuite), req.Identity)
	if err != nil {
		return nil, err
	}
	m.c.PublicHandshake = !req.EncryptHandshake
	g, err := m.c.NewGroup(req.GroupId, nil)
	if err != nil {
		return nil, fmt.Errorf("create group: %w", err)
	}
	return &pb.CreateGroupResponse{StateId: s.addState(m, g)}, nil
}

func (s *server) CreateKeyPackage(_ context.Context, req *pb.CreateKeyPackageRequest) (*pb.CreateKeyPackageResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := newIdentity(mls.CipherSuite(req.CipherSuite), req.Identity)
	if err != nil {
		return nil, err
	}
	kp, err := encode(&mls.Message{Version: mls.Version10, WireFormat: mls.WireFormatKeyPackage, KeyPackage: m.c.KeyPackage})
	if err != nil {
		return nil, err
	}
	id := s.id()
	s.txs[id] = m
	return &pb.CreateKeyPackageResponse{
		TransactionId:  id,
		KeyPackage:     kp,
		InitPriv:       m.c.InitPriv,
		EncryptionPriv: m.c.EncryptionPriv,
		SignaturePriv:  m.c.SignaturePriv,
	}, nil
}

func (s *server) JoinGroup(_ context.Context, req *pb.JoinGroupRequest) (*pb.JoinGroupResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.tx(req.TransactionId)
	if err != nil {
		return nil, err
	}
	w, err := decodeWelcome(req.Welcome)
	if err != nil {
		return nil, err
	}
	tree, err := decodeTree(req.RatchetTree)
	if err != nil {
		return nil, err
	}
	m.c.PublicHandshake = !req.EncryptHandshake
	g, err := m.c.Join(w, tree)
	if err != nil {
		return nil, fmt.Errorf("join: %w", err)
	}
	return &pb.JoinGroupResponse{StateId: s.addState(m, g), EpochAuthenticator: g.EpochAuthenticator()}, nil
}

func (s *server) ExternalJoin(_ context.Context, req *pb.ExternalJoinRequest) (*pb.ExternalJoinResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(req.Psks) > 0 {
		return nil, status.Error(codes.Unimplemented, "external join with pre-shared keys: mls.Client.JoinExternal takes none")
	}
	info, err := decodeGroupInfo(req.GroupInfo)
	if err != nil {
		return nil, err
	}
	tree, err := decodeTree(req.RatchetTree)
	if err != nil {
		return nil, err
	}
	cs := info.GroupContext.CipherSuite
	m, err := newIdentity(cs, req.Identity)
	if err != nil {
		return nil, err
	}
	if req.RemovePrior {
		// JoinExternal removes the leaf that holds the joiner's
		// signature key, so rejoin with the key of the prior state.
		prior := s.prior(info.GroupContext.GroupID, req.Identity)
		if prior == nil {
			return nil, fmt.Errorf("external join: no prior state for %q", req.Identity)
		}
		c := m.c
		c.SignaturePriv = prior.SignaturePriv
		c.KeyPackage.LeafNode.SignatureKey = prior.KeyPackage.LeafNode.SignatureKey
		if err := c.KeyPackage.LeafNode.Sign(cs, c.SignaturePriv, nil, 0); err != nil {
			return nil, fmt.Errorf("sign leaf node: %w", err)
		}
		if err := c.KeyPackage.Sign(c.SignaturePriv); err != nil {
			return nil, fmt.Errorf("sign key package: %w", err)
		}
	}
	m.c.PublicHandshake = !req.EncryptHandshake
	g, commit, err := m.c.JoinExternal(info, tree)
	if err != nil {
		return nil, fmt.Errorf("external join: %w", err)
	}
	b, err := encode(commit)
	if err != nil {
		return nil, err
	}
	return &pb.ExternalJoinResponse{StateId: s.addState(m, g), Commit: b, EpochAuthenticator: g.EpochAuthenticator()}, nil
}

// prior returns the client of a state in the group that belongs to
// identity.
func (s *server) prior(groupID, identity []byte) *mls.Client {
	for _, st := range s.states {
		g := st.group
		if !bytes.Equal(g.Context.GroupID, groupID) {
			continue
		}
		if l := g.Tree.Leaf(g.Index); l != nil && bytes.Equal(l.Credential.Identity, identity) {
			return st.m.c
		}
	}
	return nil
}

func (s *server) GroupInfo(_ context.Context, req *pb.GroupInfoRequest) (*pb.GroupInfoResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	g := st.group
	m, err := g.GroupInfo()
	if err != nil {
		return nil, fmt.Errorf("group info: %w", err)
	}
	resp := new(pb.GroupInfoResponse)
	if req.ExternalTree {
		// GroupInfo always embeds the tree; send it separately
		// instead.
		info := m.GroupInfo
		var es mls.Extensions
		for _, e := range info.Extensions {
			if e.Type != mls.ExtensionTypeRatchetTree {
				es = append(es, e)
			}
		}
		info.Extensions = es
		if err := info.Sign(st.m.c.SignaturePriv); err != nil {
			return nil, fmt.Errorf("sign group info: %w", err)
		}
		if resp.RatchetTree, err = encodeTree(g.Tree); err != nil {
			return nil, err
		}
	}
	if resp.GroupInfo, err = encode(m); err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *server) StateAuth(_ context.Context, req *pb.StateAuthRequest) (*pb.StateAuthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	return &pb.StateAuthResponse{StateAuthSecret: st.group.EpochAuthenticator()}, nil
}

func (s *server) Export(_ context.Context, req *pb.ExportRequest) (*pb.ExportResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	if req.KeyLength > 0xffff {
		return nil, status.Errorf(codes.InvalidArgument, "key length %d", req.KeyLength)
	}
	secret, err := st.group.Export(req.Label, req.Context, uint16(req.KeyLength))
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	return &pb.ExportResponse{ExportedSecret: secret}, nil
}

func (s *server) Protect(_ context.Context, req *pb.ProtectRequest) (*pb.ProtectResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	m, err := st.group.Protect(req.AuthenticatedData, req.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("protect: %w", err)
	}
	b, err := encode(m)
	if err != nil {
		return nil, err
	}
	return &pb.ProtectResponse{Ciphertext: b}, nil
}

func (s *server) Unprotect(_ context.Context, req *pb.UnprotectRequest) (*pb.UnprotectResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	h, err := mls.ParseHeader(req.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	g := st.group
	if h.Epoch != g.Epoch() {
		if old, ok := st.past[h.Epoch]; ok {
			g = old
		}
	}
	m, err := decode(req.Ciphertext)
	if err != nil {
		return nil, err
	}
	c, err := g.Unprotect(m)
	if err != nil {
		return nil, fmt.Errorf("unprotect: %w", err)
	}
	if c.Content.ContentType != mls.ContentTypeApplication {
		return nil, fmt.Errorf("unprotect: content type %d", c.Content.ContentType)
	}
	return &pb.UnprotectResponse{AuthenticatedData: c.Content.AuthenticatedData, Plaintext: c.Content.ApplicationData}, nil
}

func (s *server) StorePSK(_ context.Context, req *pb.StorePSKRequest) (*pb.StorePSKResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var m *member
	if st, ok := s.states[req.StateOrTransactionId]; ok {
		m = st.m
	} else if tx, ok := s.txs[req.StateOrTransactionId]; ok {
		m = tx
	} else {
		return nil, status.Errorf(codes.InvalidArgument, "unknown state or transaction %d", req.StateOrTransactionId)
	}
	m.psks[string(req.PskId)] = bytes.Clone(req.PskSecret)
	return &pb.StorePSKResponse{}, nil
}

// propose sends p in st's group.
func (s *server) propose(st *state, p *mls.Proposal) (*pb.ProposalResponse, error) {
	m, err := st.group.Propose(p)
	if err != nil {
		return nil, fmt.Errorf("propose: %w", err)
	}
	return st.proposalResponse(m)
}

func (st *state) proposalResponse(m *mls.Message) (*pb.ProposalResponse, error) {
	b, err := encode(m)
	if err != nil {
		return nil, err
	}
	st.sent[string(b)] = true
	return &pb.ProposalResponse{Proposal: b}, nil
}

// describe builds the proposal d describes in st's group.
func (st *state) describe(d *pb.ProposalDescription) (*mls.Proposal, error) {
	g := st.group
	return proposal(d, g.CipherSuite, g.Context.GroupID, g.Tree)
}

func (s *server) AddProposal(_ context.Context, req *pb.AddProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	p, err := st.describe(&pb.ProposalDescription{ProposalType: []byte("add"), KeyPackage: req.KeyPackage})
	if err != nil {
		return nil, err
	}
	return s.propose(st, p)
}

func (s *server) UpdateProposal(_ context.Context, req *pb.UpdateProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	g := st.group
	encPriv, encPub, err := g.CipherSuite.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}
	leaf := *g.Tree.Leaf(g.Index)
	leaf.EncryptionKey = encPub
	leaf.Source = mls.LeafNodeSourceUpdate
	leaf.Lifetime = mls.Lifetime{}
	leaf.ParentHash = nil
	if err := leaf.Sign(g.CipherSuite, st.m.c.SignaturePriv, g.Context.GroupID, g.Index); err != nil {
		return nil, fmt.Errorf("sign leaf node: %w", err)
	}
	m, err := g.ProposeUpdate(&leaf, encPriv)
	if err != nil {
		return nil, fmt.Errorf("propose update: %w", err)
	}
	return st.proposalResponse(m)
}

func (s *server) RemoveProposal(_ context.Context, req *pb.RemoveProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	p, err := st.describe(&pb.ProposalDescription{ProposalType: []byte("remove"), RemovedId: req.RemovedId})
	if err != nil {
		return nil, err
	}
	return s.propose(st, p)
}

func (s *server) ExternalPSKProposal(_ context.Context, req *pb.ExternalPSKProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	p, err := st.describe(&pb.ProposalDescription{ProposalType: []byte("externalPSK"), PskId: req.PskId})
	if err != nil {
		return nil, err
	}
	return s.propose(st, p)
}

func (s *server) ResumptionPSKProposal(_ context.Context, req *pb.ResumptionPSKProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	p, err := st.describe(&pb.ProposalDescription{ProposalType: []byte("resumptionPSK"), EpochId: req.EpochId})
	if err != nil {
		return nil, err
	}
	return s.propose(st, p)
}

func (s *server) GroupContextExtensionsProposal(_ context.Context, req *pb.GroupContextExtensionsProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	p, err := st.describe(&pb.ProposalDescription{ProposalType: []byte("groupContextExtensions"), Extensions: req.Extensions})
	if err != nil {
		return nil, err
	}
	return s.propose(st, p)
}

func (s *server) ReInitProposal(_ context.Context, req *pb.ReInitProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	p, err := st.describe(&pb.ProposalDescription{
		ProposalType: []byte("reinit"),
		GroupId:      req.GroupId,
		CipherSuite:  req.CipherSuite,
		Extensions:   req.Extensions,
	})
	if err != nil {
		return nil, err
	}
	return s.propose(st, p)
}

// handleProposals has st's group process proposals that other senders
// made. The member's own proposals are already in its group.
func (st *state) handleProposals(proposals [][]byte) error {
	for _, b := range proposals {
		if st.sent[string(b)] {
			continue
		}
		m, err := decode(b)
		if err != nil {
			return err
		}
		if _, err := st.group.Handle(m); err != nil {
			return fmt.Errorf("handle proposal: %w", err)
		}
	}
	return nil
}

func (s *server) Commit(_ context.Context, req *pb.CommitRequest) (*pb.CommitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	if err := st.handleProposals(req.ByReference); err != nil {
		return nil, err
	}
	var extra []*mls.Proposal
	for _, d := range req.ByValue {
		p, err := st.describe(d)
		if err != nil {
			return nil, err
		}
		extra = append(extra, p)
	}
	// Commit always includes a path, which satisfies force_path.
	next, commit, welcome, err := st.group.Commit(extra)
	if err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	resp := new(pb.CommitResponse)
	if resp.Commit, err = encode(commit); err != nil {
		return nil, err
	}
	if welcome != nil {
		if resp.Welcome, err = encode(welcome); err != nil {
			return nil, err
		}
	}
	if req.ExternalTree {
		if resp.RatchetTree, err = encodeTree(next.Tree); err != nil {
			return nil, err
		}
	}
	st.pending = next
	st.sent[string(resp.Commit)] = true
	return resp, nil
}

// advance moves st to the next epoch.
func (st *state) advance(next *mls.Group) {
	st.past[st.group.Epoch()] = st.group
	st.group = next
	st.pending = nil
}

func (s *server) HandlePendingCommit(_ context.Context, req *pb.HandlePendingCommitRequest) (*pb.HandleCommitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.handlePending(req.StateId)
	if err != nil {
		return nil, err
	}
	return &pb.HandleCommitResponse{StateId: req.StateId, EpochAuthenticator: st.group.EpochAuthenticator()}, nil
}

func (s *server) handlePending(id uint32) (*state, error) {
	st, err := s.state(id)
	if err != nil {
		return nil, err
	}
	if st.pending == nil {
		return nil, status.Error(codes.FailedPrecondition, "no pending commit")
	}
	st.advance(st.pending)
	return st, nil
}

func (s *server) HandleCommit(_ context.Context, req *pb.HandleCommitRequest) (*pb.HandleCommitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.handleCommit(req)
	if err != nil {
		return nil, err
	}
	return &pb.HandleCommitResponse{StateId: req.StateId, EpochAuthenticator: st.group.EpochAuthenticator()}, nil
}

func (s *server) handleCommit(req *pb.HandleCommitRequest) (*state, error) {
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	if err := st.handleProposals(req.Proposal); err != nil {
		return nil, err
	}
	m, err := decode(req.Commit)
	if err != nil {
		return nil, err
	}
	next, err := st.group.Handle(m)
	if err != nil {
		return nil, fmt.Errorf("handle commit: %w", err)
	}
	st.advance(next)
	return st, nil
}

func (s *server) ReInitCommit(ctx context.Context, req *pb.CommitRequest) (*pb.CommitResponse, error) {
	return s.Commit(ctx, req)
}

// startReinit makes a client for the group that st's reinitialized
// group moves to.
func (s *server) startReinit(st *state) (*pb.HandleReInitCommitResponse, error) {
	g := st.group
	ri := g.Reinit()
	if ri == nil {
		return nil, fmt.Errorf("reinit: %w", mls.ErrNotReinitialized)
	}
	m, err := newIdentity(ri.CipherSuite, g.Tree.Leaf(g.Index).Credential.Identity)
	if err != nil {
		return nil, err
	}
	m.c.PublicHandshake = st.m.c.PublicHandshake
	for k, v := range st.m.psks {
		m.psks[k] = v
	}
	kp, err := encode(&mls.Message{Version: mls.Version10, WireFormat: mls.WireFormatKeyPackage, KeyPackage: m.c.KeyPackage})
	if err != nil {
		return nil, err
	}
	id := s.id()
	s.reinits[id] = &reinit{old: g, m: m}
	return &pb.HandleReInitCommitResponse{ReinitId: id, KeyPackage: kp, EpochAuthenticator: g.EpochAuthenticator()}, nil
}

func (s *server) HandlePendingReInitCommit(_ context.Context, req *pb.HandlePendingCommitRequest) (*pb.HandleReInitCommitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.handlePending(req.StateId)
	if err != nil {
		return nil, err
	}
	return s.startReinit(st)
}

func (s *server) HandleReInitCommit(_ context.Context, req *pb.HandleCommitRequest) (*pb.HandleReInitCommitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.handleCommit(req)
	if err != nil {
		return nil, err
	}
	return s.startReinit(st)
}

func (s *server) ReInitWelcome(_ context.Context, req *pb.ReInitWelcomeRequest) (*pb.CreateSubgroupResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ri, ok := s.reinits[req.ReinitId]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown reinit %d", req.ReinitId)
	}
	kps, err := keyPackages(req.KeyPackage)
	if err != nil {
		return nil, err
	}
	if r := ri.old.Reinit(); r.CipherSuite != ri.old.CipherSuite {
		return nil, status.Error(codes.Unimplemented, "reinit to a new cipher suite: mls.Group.Reinitialize creates the new group with the old group's client")
	}
	g, w, err := ri.old.Reinitialize(kps)
	if err != nil {
		return nil, fmt.Errorf("reinitialize: %w", err)
	}
	return s.subgroup(ri.m, g, w, req.ExternalTree)
}

func (s *server) HandleReInitWelcome(_ context.Context, req *pb.HandleReInitWelcomeRequest) (*pb.JoinGroupResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ri, ok := s.reinits[req.ReinitId]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown reinit %d", req.ReinitId)
	}
	g, err := s.resume(ri.m, req.Welcome, req.RatchetTree, ri.old)
	if err != nil {
		return nil, err
	}
	return &pb.JoinGroupResponse{StateId: s.addState(ri.m, g), EpochAuthenticator: g.EpochAuthenticator()}, nil
}

func keyPackages(bs [][]byte) ([]*mls.KeyPackage, error) {
	kps := make([]*mls.KeyPackage, len(bs))
	for i, b := range bs {
		kp, err := decodeKeyPackage(b)
		if err != nil {
			return nil, err
		}
		kps[i] = kp
	}
	return kps, nil
}

// subgroup records the creator's state in a new group made by reinit
// or branch.
func (s *server) subgroup(m *member, g *mls.Group, w *mls.Message, externalTree bool) (*pb.CreateSubgroupResponse, error) {
	resp := &pb.CreateSubgroupResponse{EpochAuthenticator: g.EpochAuthenticator()}
	var err error
	if resp.Welcome, err = encode(w); err != nil {
		return nil, err
	}
	if externalTree {
		if resp.RatchetTree, err = encodeTree(g.Tree); err != nil {
			return nil, err
		}
	}
	resp.StateId = s.addState(m, g)
	return resp, nil
}

func (s *server) resume(m *member, welcome, tree []byte, old *mls.Group) (*mls.Group, error) {
	w, err := decodeWelcome(welcome)
	if err != nil {
		return nil, err
	}
	t, err := decodeTree(tree)
	if err != nil {
		return nil, err
	}
	g, err := m.c.Resume(w, t, old)
	if err != nil {
		return nil, fmt.Errorf("resume: %w", err)
	}
	return g, nil
}

func (s *server) CreateBranch(_ context.Context, req *pb.CreateBranchRequest) (*pb.CreateSubgroupResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	if len(req.Extensions) > 0 {
		return nil, status.Error(codes.Unimplemented, "branch with new extensions: mls.Group.Branch keeps the group's extensions")
	}
	kps, err := keyPackages(req.KeyPackages)
	if err != nil {
		return nil, err
	}
	g, w, err := st.group.Branch(req.GroupId, kps)
	if err != nil {
		return nil, fmt.Errorf("branch: %w", err)
	}
	return s.subgroup(st.m, g, w, req.ExternalTree)
}

func (s *server) HandleBranch(_ context.Context, req *pb.HandleBranchRequest) (*pb.HandleBranchResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	m, err := s.tx(req.TransactionId)
	if err != nil {
		return nil, err
	}
	m.c.PublicHandshake = st.m.c.PublicHandshake
	g, err := s.resume(m, req.Welcome, req.RatchetTree, st.group)
	if err != nil {
		return nil, err
	}
	return &pb.HandleBranchResponse{StateId: s.addState(m, g), EpochAuthenticator: g.EpochAuthenticator()}, nil
}

func (s *server) NewMemberAddProposal(_ context.Context, req *pb.NewMemberAddProposalRequest) (*pb.NewMemberAddProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := decodeGroupInfo(req.GroupInfo)
	if err != nil {
		return nil, err
	}
	m, err := newIdentity(info.GroupContext.CipherSuite, req.Identity)
	if err != nil {
		return nil, err
	}
	p, err := m.c.ProposeAdd(info.GroupContext.GroupID, info.GroupContext.Epoch)
	if err != nil {
		return nil, fmt.Errorf("propose add: %w", err)
	}
	b, err := encode(p)
	if err != nil {
		return nil, err
	}
	id := s.id()
	s.txs[id] = m
	return &pb.NewMemberAddProposalResponse{
		TransactionId:  id,
		Proposal:       b,
		InitPriv:       m.c.InitPriv,
		EncryptionPriv: m.c.EncryptionPriv,
		SignaturePriv:  m.c.SignaturePriv,
	}, nil
}

func (s *server) CreateExternalSigner(_ context.Context, req *pb.CreateExternalSignerRequest) (*pb.CreateExternalSignerResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs := mls.CipherSuite(req.CipherSuite)
	if !cs.Supported() {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported cipher suite %d", cs)
	}
	priv, pub, err := cs.GenerateSignatureKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate signature key pair: %w", err)
	}
	b, err := mls.Marshal(&mls.ExternalSender{SignatureKey: pub, Credential: basic(req.Identity)})
	if err != nil {
		return nil, fmt.Errorf("encode external sender: %w", err)
	}
	id := s.id()
	s.signers[id] = &signer{cs: cs, priv: priv, pub: pub}
	return &pb.CreateExternalSignerResponse{SignerId: id, ExternalSender: b}, nil
}

func (s *server) AddExternalSigner(_ context.Context, req *pb.AddExternalSignerRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.state(req.StateId)
	if err != nil {
		return nil, err
	}
	var sender mls.ExternalSender
	if err := mls.Unmarshal(req.ExternalSender, &sender); err != nil {
		return nil, fmt.Errorf("decode external sender: %w", err)
	}
	es := append(mls.Extensions(nil), st.group.Context.Extensions...)
	var senders mls.ExternalSenders
	if _, err := es.Decode(mls.ExtensionTypeExternalSenders, &senders); err != nil {
		return nil, fmt.Errorf("decode external senders: %w", err)
	}
	senders = append(senders, sender)
	if err := es.Set(mls.ExtensionTypeExternalSenders, &senders); err != nil {
		return nil, fmt.Errorf("encode external senders: %w", err)
	}
	return s.propose(st, &mls.Proposal{
		Type:                   mls.ProposalTypeGroupContextExtensions,
		GroupContextExtensions: &mls.GroupContextExtensions{Extensions: es},
	})
}

func (s *server) ExternalSignerProposal(_ context.Context, req *pb.ExternalSignerProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sg, ok := s.signers[req.SignerId]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown signer %d", req.SignerId)
	}
	info, err := decodeGroupInfo(req.GroupInfo)
	if err != nil {
		return nil, err
	}
	tree, err := decodeTree(req.RatchetTree)
	if err != nil {
		return nil, err
	}
	if tree == nil {
		if _, err := info.Extensions.Decode(mls.ExtensionTypeRatchetTree, &tree); err != nil {
			return nil, fmt.Errorf("decode ratchet tree: %w", err)
		}
	}
	gc := &info.GroupContext
	// The harness leaves signer_index at zero, so find the signer in
	// the group's list by its key.
	var senders mls.ExternalSenders
	if _, err := gc.Extensions.Decode(mls.ExtensionTypeExternalSenders, &senders); err != nil {
		return nil, fmt.Errorf("decode external senders: %w", err)
	}
	index := -1
	for i, es := range senders {
		if bytes.Equal(es.SignatureKey, sg.pub) {
			index = i
		}
	}
	if index < 0 {
		return nil, fmt.Errorf("external signer %d is not in the group's external senders", req.SignerId)
	}
	p, err := proposal(req.Description, gc.CipherSuite, gc.GroupID, tree)
	if err != nil {
		return nil, err
	}
	ec := &mls.ExternalClient{CipherSuite: gc.CipherSuite, Index: uint32(index), SignaturePriv: sg.priv}
	m, err := ec.Propose(gc.GroupID, gc.Epoch, p)
	if err != nil {
		return nil, fmt.Errorf("external propose: %w", err)
	}
	b, err := encode(m)
	if err != nil {
		return nil, err
	}
	return &pb.ProposalResponse{Proposal: b}, nil
}

func (s *server) Free(_ context.Context, req *pb.FreeRequest) (*pb.FreeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, req.StateId)
	return &pb.FreeResponse{}, nil
}
