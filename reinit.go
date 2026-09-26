package mls

import (
	"bytes"
	"crypto/rand"
	"slices"
)

// resumptionPSK returns the resumption key named by id, which may
// belong to g or to a group g was resumed from, or nil if g does not
// have it. See RFC 9420, Section 8.4.
func (g *Group) resumptionPSK(id PreSharedKeyID) []byte {
	for h := g; h != nil; h = h.prior {
		if !bytes.Equal(id.PSKGroupID, h.Context.GroupID) {
			continue
		}
		if psk, ok := h.resumption[id.PSKEpoch]; ok {
			return psk
		}
	}
	return nil
}

// Reinit returns the reinitialization a commit of this epoch carried,
// or nil if it carried none. A group that has committed a Reinit
// proposal is finished: its members send nothing further in it and
// move to the group [Group.Reinitialize] creates.
// See RFC 9420, Section 11.2.
func (g *Group) Reinit() *Reinit { return g.reinit }

// Reinitialize creates the group that the members of g move to, which
// is the third step of RFC 9420, Section 11.2: g must have committed
// a Reinit proposal, and the new group takes its group ID, version,
// cipher suite and extensions from it. c is the member's client in
// the new group, and members are the key packages of everyone else
// who is to join; since the new group may use a different cipher
// suite, all of them are made afresh, for the Reinit's suite.
//
// It returns the new group at epoch 1 and the welcome message that
// carries the rest of the membership into it. The members verify the
// link to g through a resumption pre-shared key; see [Client.Resume].
//
// Any member of g may do this, not only the one that committed the
// Reinit, so that a group is not stranded by whoever went offline.
// Section 11.2 makes the new group one "with the same membership", so
// c must identify the same member as g's own leaf, and c and members
// together must identify exactly g's members, as c.SameIdentity
// judges.
func (g *Group) Reinitialize(c *Client, members []*KeyPackage) (*Group, *Message, error) {
	if g.reinit == nil {
		return nil, nil, ErrNotReinitialized
	}
	ri := g.reinit
	if ri.Version != g.Context.Version {
		return nil, nil, ErrUnsupportedVersion
	}
	if c.CipherSuite != ri.CipherSuite {
		return nil, nil, ErrUnsupportedCipherSuite
	}
	self := g.Tree.Leaf(g.Index)
	if self == nil || !c.sameIdentity(&c.KeyPackage.LeafNode.Credential, &self.Credential) ||
		!c.sameMembers(g.Tree, joinerCredentials(c, members), true) {
		return nil, nil, ErrMembership
	}
	return g.resume(c, ri.GroupID, ri.Extensions, ResumptionPSKUsageReinit, members)
}

// Branch creates a new group holding a subset of g's members, with
// g's version and cipher suite but a new group ID, as RFC 9420,
// Section 11.3 describes. The new group's context carries extensions,
// which need not be g's; pass g.Context.Extensions to keep them.
// members are the key packages of the subgroup's members, which the
// caller fetches afresh, and each must identify a member of g, as
// g's client's SameIdentity judges; g's own member is the creator and
// needs none. It returns the new group at epoch 1 and the welcome
// message for the others.
//
// Unlike [Group.Reinitialize], Branch needs no new client: the
// suite is g's, and the commit that adds the members replaces the
// creator's leaf keys along its update path.
func (g *Group) Branch(groupID []byte, extensions Extensions, members []*KeyPackage) (*Group, *Message, error) {
	if bytes.Equal(groupID, g.Context.GroupID) {
		return nil, nil, ErrSameGroupID
	}
	if !g.client.sameMembers(g.Tree, joinerCredentials(g.client, members), false) {
		return nil, nil, ErrMembership
	}
	return g.resume(g.client, groupID, extensions, ResumptionPSKUsageBranch, members)
}

// joinerCredentials returns the credentials of c and of members.
func joinerCredentials(c *Client, members []*KeyPackage) []*Credential {
	creds := []*Credential{&c.KeyPackage.LeafNode.Credential}
	for _, kp := range members {
		creds = append(creds, &kp.LeafNode.Credential)
	}
	return creds
}

// resume has c create a new group linked to g by a resumption
// pre-shared key, which is how both reinitialization and branching
// work.
func (g *Group) resume(c *Client, groupID []byte, extensions Extensions, usage ResumptionPSKUsage, members []*KeyPackage) (*Group, *Message, error) {
	cs := c.CipherSuite
	next, err := c.NewGroup(groupID, extensions)
	if err != nil {
		return nil, nil, err
	}
	next.prior = g

	// To avoid key reuse the nonce must be fresh, since the
	// resumption key itself is reused by everyone joining.
	nonce := make([]byte, cs.HashSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	proposals := []*Proposal{{
		Type: ProposalTypePreSharedKey,
		PreSharedKey: &PreSharedKey{PSK: PreSharedKeyID{
			Type:       PSKTypeResumption,
			Usage:      usage,
			PSKGroupID: g.Context.GroupID,
			PSKEpoch:   g.Context.Epoch,
			PSKNonce:   nonce,
		}},
	}}
	for _, kp := range members {
		proposals = append(proposals, &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}})
	}
	joined, _, welcome, err := next.Commit(proposals)
	if err != nil {
		return nil, nil, err
	}
	return joined, welcome, nil
}

// Resume joins the group that old was reinitialized or branched into.
// It differs from [Client.Join] in that the welcome message carries a
// resumption pre-shared key drawn from old, and in the checks RFC
// 9420, Sections 11.2 and 11.3 require of the new group: it must be
// at epoch 1, it must match the parameters of the group it resumes,
// a reinitialized group must be resumed from the epoch that committed
// the Reinit, a reinitialized group must hold exactly the members of
// old, and a branch must hold only members of old, all as
// c.SameIdentity judges. A branch must also have a new group ID, since
// Section 11 asks that group IDs be unique.
func (c *Client) Resume(w *Welcome, tree RatchetTree, old *Group) (*Group, error) {
	g, err := c.join(w, tree, old)
	if err != nil {
		return nil, err
	}
	if g.Context.Epoch != 1 {
		return nil, ErrNotResumed
	}
	psk := g.resumed
	if psk == nil || !bytes.Equal(psk.PSKGroupID, old.Context.GroupID) {
		return nil, ErrNotResumed
	}
	switch psk.Usage {
	case ResumptionPSKUsageReinit:
		ri := old.Reinit()
		if ri == nil ||
			psk.PSKEpoch != old.Context.Epoch ||
			ri.Version != g.Context.Version ||
			ri.CipherSuite != g.CipherSuite ||
			!bytes.Equal(ri.GroupID, g.Context.GroupID) ||
			!sameExtensions(ri.Extensions, g.Context.Extensions) ||
			!c.sameMembers(old.Tree, g.memberCredentials(), true) {
			return nil, ErrNotResumed
		}
	case ResumptionPSKUsageBranch:
		if g.Context.Version != old.Context.Version || g.CipherSuite != old.CipherSuite ||
			bytes.Equal(g.Context.GroupID, old.Context.GroupID) {
			return nil, ErrNotResumed
		}
		if !c.sameMembers(old.Tree, g.memberCredentials(), false) {
			return nil, ErrNotResumed
		}
	default:
		return nil, ErrNotResumed
	}
	return g, nil
}

// memberCredentials returns the credentials of g's members.
func (g *Group) memberCredentials() []*Credential {
	var creds []*Credential
	for _, n := range g.Tree.Members() {
		creds = append(creds, &n.Credential)
	}
	return creds
}

// sameExtensions reports whether two extension lists are equal. The
// order of a list is not constrained, so it does not matter here.
func sameExtensions(a, b Extensions) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		i := slices.IndexFunc(b, func(y Extension) bool { return y.Type == x.Type })
		if i < 0 || !bytes.Equal(x.Data, b[i].Data) {
			return false
		}
	}
	return true
}

// sameIdentity reports whether a and b identify the same member,
// by c.SameIdentity if it is set and otherwise by comparing the
// credentials.
func (c *Client) sameIdentity(a, b *Credential) bool {
	if c.SameIdentity != nil {
		return c.SameIdentity(a, b)
	}
	x, err := Marshal(a)
	if err != nil {
		return false
	}
	y, err := Marshal(b)
	return err == nil && bytes.Equal(x, y)
}

// sameMembers reports whether creds can be matched one to one with
// members of t, each credential to a member it identifies, and, if
// all is set, whether that matching covers every member of t. A group
// may hold several leaves of one identity, one per device, so the
// matching counts them: a reinitialization carries as many of each as
// the old group held, and a branch no more. See RFC 9420, Sections
// 11.2 and 11.3.
func (c *Client) sameMembers(t RatchetTree, creds []*Credential, all bool) bool {
	var old []*Credential
	for _, n := range t.Members() {
		old = append(old, &n.Credential)
	}
	if len(creds) > len(old) || all && len(creds) != len(old) {
		return false
	}
	if c.SameIdentity == nil {
		// Byte equality partitions the credentials, so counting
		// each encoding suffices.
		count := make(map[string]int)
		for _, cred := range old {
			b, err := Marshal(cred)
			if err != nil {
				return false
			}
			count[string(b)]++
		}
		for _, cred := range creds {
			b, err := Marshal(cred)
			if err != nil || count[string(b)] == 0 {
				return false
			}
			count[string(b)]--
		}
		return true
	}
	// An application's SameIdentity need not partition credentials,
	// so find a maximum bipartite matching by augmenting paths.
	match := make([]int, len(old)) // match[j] is the cred holding old[j], or -1
	for j := range match {
		match[j] = -1
	}
	var augment func(i int, seen []bool) bool
	augment = func(i int, seen []bool) bool {
		for j, o := range old {
			if seen[j] || !c.sameIdentity(creds[i], o) {
				continue
			}
			seen[j] = true
			if match[j] < 0 || augment(match[j], seen) {
				match[j] = i
				return true
			}
		}
		return false
	}
	for i := range creds {
		if !augment(i, make([]bool, len(old))) {
			return false
		}
	}
	return true
}
