package mls

import (
	"errors"
	"testing"
	"time"
)

func TestValidateKeyPackage(t *testing.T) {
	cs := testSuite()
	c := newTestClient(t, cs, "alice")
	if err := c.KeyPackage.Validate(time.Now()); err != nil {
		t.Fatalf("a fresh key package does not validate: %v", err)
	}

	for _, tc := range []struct {
		name string
		mung func(p *KeyPackage)
		want error
	}{
		{"expired", func(p *KeyPackage) {
			p.LeafNode.Lifetime.NotAfter = uint64(time.Now().Add(-time.Hour).Unix())
		}, ErrExpired},
		{"wrong source", func(p *KeyPackage) {
			p.LeafNode.Source = LeafNodeSourceUpdate
		}, ErrBadLeafNodeSource},
		{"init key reused", func(p *KeyPackage) {
			p.InitKey = p.LeafNode.EncryptionKey
		}, ErrDuplicateLeafKey},
		{"bad signature", func(p *KeyPackage) {
			p.Signature[0] ^= 1
		}, ErrBadSignature},
		{"extension not in capabilities", func(p *KeyPackage) {
			p.LeafNode.Extensions = Extensions{{Type: 0xff00, Data: []byte("x")}}
		}, ErrUnsupportedCapability},
		{"default extension not listed", func(p *KeyPackage) {
			// RFC 9420, Section 7.2: the default extension
			// types must not be listed, and are supported.
			p.LeafNode.Extensions = Extensions{{Type: ExtensionTypeApplicationID, Data: []byte("x")}}
		}, nil},
		{"credential not in capabilities", func(p *KeyPackage) {
			p.LeafNode.Capabilities.Credentials = nil
		}, ErrUnsupportedCapability},
	} {
		kp := *c.KeyPackage
		kp.LeafNode = c.KeyPackage.LeafNode
		kp.Signature = append([]byte(nil), c.KeyPackage.Signature...)
		tc.mung(&kp)
		// The leaf is signed as it was; changing it invalidates
		// the signature too, so re-sign where the test is not
		// about the signature.
		if tc.want != ErrBadSignature && tc.want != ErrBadLeafNodeSource {
			if err := kp.LeafNode.Sign(cs, c.SignaturePriv, nil, 0); err != nil {
				t.Fatal(err)
			}
			if err := kp.Sign(c.SignaturePriv); err != nil {
				t.Fatal(err)
			}
		}
		if err := kp.Validate(time.Now()); !errors.Is(err, tc.want) {
			t.Errorf("%s: Validate = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestCommitRejectsBadLeaf(t *testing.T) {
	cs := testSuite()
	alice := newTestClient(t, cs, "alice")
	bob := newTestClient(t, cs, "bob")
	g, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		t.Fatal(err)
	}

	// A key package whose leaf reuses the committer's encryption
	// key cannot join: RFC 9420, Section 7.3 requires signature
	// and encryption keys to be unique among the members.
	kp := *bob.KeyPackage
	kp.LeafNode.EncryptionKey = alice.KeyPackage.LeafNode.EncryptionKey
	if err := kp.LeafNode.Sign(cs, bob.SignaturePriv, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := kp.Sign(bob.SignaturePriv); err != nil {
		t.Fatal(err)
	}
	add := &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: kp}}
	if _, _, _, err := g.Commit([]*Proposal{add}); !errors.Is(err, ErrDuplicateLeafKey) {
		t.Errorf("Commit = %v, want %v", err, ErrDuplicateLeafKey)
	}

	// An expired key package cannot be sent, even though one may
	// be received.
	kp = *bob.KeyPackage
	kp.LeafNode.Lifetime.NotAfter = uint64(time.Now().Add(-time.Hour).Unix())
	if err := kp.LeafNode.Sign(cs, bob.SignaturePriv, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := kp.Sign(bob.SignaturePriv); err != nil {
		t.Fatal(err)
	}
	add = &Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: kp}}
	if _, _, _, err := g.Commit([]*Proposal{add}); !errors.Is(err, ErrExpired) {
		t.Errorf("Commit with an expired key package = %v, want %v", err, ErrExpired)
	}
}
