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
	return g.resume(c, ri.GroupID, ri.Extensions, ResumptionPSKUsageReinit, members)
}

// Branch creates a new group holding a subset of g's members, with
// the same parameters as g but a new group ID, as RFC 9420, Section
// 11.3 describes. members are the key packages of the subgroup's
// members, which the caller fetches afresh; g's own member is the
// creator and needs none. It returns the new group at epoch 1 and the
// welcome message for the others.
func (g *Group) Branch(groupID []byte, members []*KeyPackage) (*Group, *Message, error) {
	if bytes.Equal(groupID, g.Context.GroupID) {
		return nil, nil, ErrSameGroupID
	}
	return g.resume(g.client, groupID, g.Context.Extensions, ResumptionPSKUsageBranch, members)
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
// the Reinit, and a branch must have a new group ID and hold only
// members of old.
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
			!sameExtensions(ri.Extensions, g.Context.Extensions) {
			return nil, ErrNotResumed
		}
	case ResumptionPSKUsageBranch:
		if g.Context.Version != old.Context.Version || g.CipherSuite != old.CipherSuite ||
			bytes.Equal(g.Context.GroupID, old.Context.GroupID) {
			return nil, ErrNotResumed
		}
		// Every leaf of the subgroup must match one of the
		// original group's, which this package takes to mean
		// that it presents the same credential.
		for _, n := range g.Tree.Members() {
			if !old.Tree.hasCredential(&n.Credential) {
				return nil, ErrNotResumed
			}
		}
	default:
		return nil, ErrNotResumed
	}
	return g, nil
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

// hasCredential reports whether any member of t presents c. RFC 9420,
// Section 11.3 leaves the comparison of identifiers to the
// application; this package compares the credentials themselves.
func (t RatchetTree) hasCredential(c *Credential) bool {
	want, err := Marshal(c)
	if err != nil {
		return false
	}
	for _, n := range t.Members() {
		got, err := Marshal(&n.Credential)
		if err != nil {
			return false
		}
		if bytes.Equal(want, got) {
			return true
		}
	}
	return false
}
