package mls_test

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/tmc/mls"
)

func Example() {
	kp := mls.KeyPackage{
		Version:     mls.Version10,
		CipherSuite: mls.X25519AES128GCMSHA256Ed25519,
		InitKey:     []byte("init key"),
		LeafNode: mls.LeafNode{
			EncryptionKey: []byte("encryption key"),
			SignatureKey:  []byte("signature key"),
			Credential:    mls.Credential{Type: mls.CredentialTypeBasic, Identity: []byte("alice")},
			Capabilities: mls.Capabilities{
				Versions:     []mls.ProtocolVersion{mls.Version10},
				CipherSuites: []mls.CipherSuite{mls.X25519AES128GCMSHA256Ed25519},
			},
			Source:   mls.LeafNodeSourceKeyPackage,
			Lifetime: mls.Lifetime{NotBefore: 0, NotAfter: 1 << 40},
		},
	}

	data, err := mls.Marshal(&kp)
	if err != nil {
		panic(err)
	}

	var back mls.KeyPackage
	if err := mls.Unmarshal(data, &back); err != nil {
		panic(err)
	}
	fmt.Printf("%d bytes, %s, %s, identity %q\n",
		len(data), back.Version, back.CipherSuite, back.LeafNode.Credential.Identity)
	// Output:
	// 80 bytes, mls10, MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, identity "alice"
}

func ExampleExtensions_Find() {
	exts := mls.Extensions{
		{Type: mls.ExtensionTypeApplicationID, Data: []byte("chat")},
		{Type: mls.ExtensionTypeRatchetTree, Data: []byte{0x00}},
	}
	e := exts.Find(mls.ExtensionTypeApplicationID)
	fmt.Printf("%s: %q\n", e.Type, e.Data)
	fmt.Println(exts.Find(mls.ExtensionTypeExternalPub))
	// Output:
	// application_id: "chat"
	// <nil>
}

// This example runs a group through its life: Alice creates it and
// adds Bob, they exchange a message, and Alice removes Bob. The
// messages pass through their encodings, as they would through a
// delivery service. The cipher suite is one that FIPS 140-3 mode also
// accepts.
func Example_group() {
	cs := mls.P256AES128GCMSHA256P256
	alice, err := mls.NewClient(cs, mls.Credential{Type: mls.CredentialTypeBasic, Identity: []byte("alice")}, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	bob, err := mls.NewClient(cs, mls.Credential{Type: mls.CredentialTypeBasic, Identity: []byte("bob")}, time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	// Alice creates the group and commits an Add of Bob's key
	// package. The commit returns Alice's state in the next epoch and
	// a Welcome for Bob.
	a0, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		log.Fatal(err)
	}
	add := &mls.Proposal{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *bob.KeyPackage}}
	a1, _, welcome, err := a0.Commit([]*mls.Proposal{add})
	if err != nil {
		log.Fatal(err)
	}
	b1, err := bob.Join(deliver(welcome).Welcome, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("bob joined at epoch", b1.Epoch())

	// Bob protects a message; Alice unprotects it.
	msg, err := b1.Protect(nil, []byte("hello, alice"))
	if err != nil {
		log.Fatal(err)
	}
	got, err := a1.Unprotect(deliver(msg))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("alice read %q from leaf %d\n", got.Content.ApplicationData, got.Content.Sender.LeafIndex)

	// Alice removes Bob, and handling the commit reports the removal
	// to Bob.
	remove := &mls.Proposal{Type: mls.ProposalTypeRemove, Remove: &mls.Remove{Removed: uint32(b1.Index)}}
	a2, commit, _, err := a1.Commit([]*mls.Proposal{remove})
	if err != nil {
		log.Fatal(err)
	}
	_, _, err = b1.Handle(deliver(commit))
	fmt.Println("alice is at epoch", a2.Epoch())
	fmt.Println("bob removed:", errors.Is(err, mls.ErrRemoved))
	// Output:
	// bob joined at epoch 1
	// alice read "hello, alice" from leaf 1
	// alice is at epoch 2
	// bob removed: true
}

// deliver passes m through its encoding, as a delivery service would.
func deliver(m *mls.Message) *mls.Message {
	b, err := mls.Marshal(m)
	if err != nil {
		log.Fatal(err)
	}
	var out mls.Message
	if err := mls.Unmarshal(b, &out); err != nil {
		log.Fatal(err)
	}
	return &out
}

// Members of the same epoch export the same secret for the same label
// and context, and no one outside the group can compute it.
func ExampleGroup_Export() {
	cs := mls.P256AES128GCMSHA256P256
	alice, err := mls.NewClient(cs, mls.Credential{Type: mls.CredentialTypeBasic, Identity: []byte("alice")}, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	bob, err := mls.NewClient(cs, mls.Credential{Type: mls.CredentialTypeBasic, Identity: []byte("bob")}, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	g, err := alice.NewGroup([]byte("group"), nil)
	if err != nil {
		log.Fatal(err)
	}
	a1, _, welcome, err := g.Commit([]*mls.Proposal{{Type: mls.ProposalTypeAdd, Add: &mls.Add{KeyPackage: *bob.KeyPackage}}})
	if err != nil {
		log.Fatal(err)
	}
	b1, err := bob.Join(deliver(welcome).Welcome, nil)
	if err != nil {
		log.Fatal(err)
	}

	ka, err := a1.Export("example call key", []byte("call 1"), 32)
	if err != nil {
		log.Fatal(err)
	}
	kb, err := b1.Export("example call key", []byte("call 1"), 32)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(ka), bytes.Equal(ka, kb))
	// Output:
	// 32 true
}
