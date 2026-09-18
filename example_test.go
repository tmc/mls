package mls_test

import (
	"fmt"

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
