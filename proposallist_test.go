package mls

import (
	"errors"
	"testing"
)

// TestProposalList checks the rules RFC 9420, Section 12.2 places on
// the list of proposals a commit covers.
func TestProposalList(t *testing.T) {
	cs := testSuite()
	alice := newTestClient(t, cs, "alice")
	bob := newTestClient(t, cs, "bob")
	carol := newTestClient(t, cs, "carol")

	g, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	add := func(c *Client) *Proposal {
		return &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *c.KeyPackage}}
	}
	g, _, _, err = g.Commit([]*Proposal{add(bob), add(carol)})
	if err != nil {
		t.Fatal(err)
	}
	dave := newTestClient(t, cs, "dave")

	psk := func(u ResumptionPSKUsage) *Proposal {
		return &Proposal{Type: ProposalTypePreSharedKey, PreSharedKey: &PreSharedKey{
			PSK: PreSharedKeyID{Type: PSKTypeResumption, Usage: u, PSKGroupID: []byte("group"), PSKEpoch: 1, PSKNonce: make([]byte, 32)},
		}}
	}
	ext := func() *Proposal {
		return &Proposal{Type: ProposalTypeGroupContextExtensions, GroupContextExtensions: &GroupContextExtensions{}}
	}
	remove := func(i uint32) *Proposal {
		return &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: i}}
	}

	tests := []struct {
		name string
		ps   []*Proposal
	}{
		{"remove the committer", []*Proposal{remove(uint32(g.Index))}},
		{"two removes for one leaf", []*Proposal{remove(1), remove(1)}},
		{"add an existing member", []*Proposal{add(bob)}},
		{"add the same client twice", []*Proposal{add(dave), add(dave)}},
		{"two group_context_extensions", []*Proposal{ext(), ext()}},
		{"external_init outside an external commit", []*Proposal{
			{Type: ProposalTypeExternalInit, ExternalInit: &ExternalInit{KEMOutput: []byte("x")}},
		}},
		{"reinit with another proposal", []*Proposal{
			{Type: ProposalTypeReinit, Reinit: &Reinit{GroupID: []byte("new"), Version: Version10, CipherSuite: cs}},
			remove(1),
		}},
		{"reinit to an older version", []*Proposal{
			{Type: ProposalTypeReinit, Reinit: &Reinit{GroupID: []byte("new"), Version: Version10 - 1, CipherSuite: cs}},
		}},
		{"resumption psk for reinit", []*Proposal{psk(ResumptionPSKUsageReinit)}},
		{"resumption psk for branching", []*Proposal{psk(ResumptionPSKUsageBranch)}},
		{"psk nonce shorter than the hash", []*Proposal{{Type: ProposalTypePreSharedKey, PreSharedKey: &PreSharedKey{
			PSK: PreSharedKeyID{Type: PSKTypeExternal, PSKID: []byte("k"), PSKNonce: make([]byte, 16)},
		}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, _, err := g.Commit(tt.ps); !errors.Is(err, ErrProposalList) {
				t.Errorf("Commit = %v, want %v", err, ErrProposalList)
			}
		})
	}

	// The same duplicate PreSharedKeyID twice is rejected, while
	// one on its own is only rejected for being unknown.
	dup := psk(ResumptionPSKUsageApplication)
	if _, _, _, err := g.Commit([]*Proposal{dup, dup}); !errors.Is(err, ErrProposalList) {
		t.Errorf("Commit = %v, want %v", err, ErrProposalList)
	}
}

// A group_context_extensions proposal need not be met by a member
// the same commit removes. See RFC 9420, Section 12.1.7.
func TestRequiredCapabilitiesRemoved(t *testing.T) {
	cs := testSuite()
	const custom ProposalType = 0xf000
	capable := func(name string) *Client {
		c := newTestClient(t, cs, name)
		c.KeyPackage.LeafNode.Capabilities.Proposals = []ProposalType{custom}
		if err := c.KeyPackage.LeafNode.Sign(cs, c.SignaturePriv, nil, 0); err != nil {
			t.Fatal(err)
		}
		if err := c.KeyPackage.Sign(c.SignaturePriv); err != nil {
			t.Fatal(err)
		}
		return c
	}
	alice, bob := capable("alice"), capable("bob")
	carol := newTestClient(t, cs, "carol")
	g, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}
	add := func(c *Client) *Proposal {
		return &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: *c.KeyPackage}}
	}
	g, _, _, err = g.Commit([]*Proposal{add(bob), add(carol)})
	if err != nil {
		t.Fatal(err)
	}
	var ext Extensions
	if err := ext.Set(ExtensionTypeRequiredCapabilities, &RequiredCapabilities{ProposalTypes: []ProposalType{custom}}); err != nil {
		t.Fatal(err)
	}
	require := &Proposal{Type: ProposalTypeGroupContextExtensions, GroupContextExtensions: &GroupContextExtensions{Extensions: ext}}
	if _, _, _, err := g.Commit([]*Proposal{require}); !errors.Is(err, ErrProposalList) {
		t.Errorf("Commit(require) = %v, want %v", err, ErrProposalList)
	}
	remove := &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 2}}
	if _, _, _, err := g.Commit([]*Proposal{remove, require}); err != nil {
		t.Errorf("Commit(remove carol, require) = %v", err)
	}
}
