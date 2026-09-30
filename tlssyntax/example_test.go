package tlssyntax_test

import (
	"fmt"
	"log"

	"github.com/tmc/mls/tlssyntax"
)

// An Extension is a type followed by an opaque vector:
//
//	struct {
//		uint16 extension_type;
//		opaque extension_data<V>;
//	} Extension;
type Extension struct {
	Type uint16
	Data []byte
}

func (e *Extension) MarshalTLS(w *tlssyntax.Writer) {
	w.WriteUint16(e.Type)
	w.WriteOpaque(e.Data)
}

func (e *Extension) UnmarshalTLS(r *tlssyntax.Reader) {
	e.Type = r.ReadUint16()
	e.Data = r.ReadOpaque()
}

func Example() {
	b, err := tlssyntax.Marshal(&Extension{Type: 1, Data: []byte("chat")})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x\n", b)

	var e Extension
	if err := tlssyntax.Unmarshal(b, &e); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d %q\n", e.Type, e.Data)
	// Output:
	// 00010463686174
	// 1 "chat"
}

// Unmarshal rejects input that does not decode to exactly one value:
// here, a vector whose length header claims more bytes than follow.
func ExampleUnmarshal() {
	var e Extension
	err := tlssyntax.Unmarshal([]byte{0x00, 0x01, 0x05, 'c', 'h'}, &e)
	fmt.Println(err)
	// Output:
	// tlssyntax: vector of 5 bytes exceeds 2 remaining
}

// A vector of structures is written with WriteVector and read back
// with ReadAll.
func ExampleWriter_WriteVector() {
	exts := []Extension{{Type: 1, Data: []byte("a")}, {Type: 2}}
	b, err := tlssyntax.Marshal(tlssyntax.MarshalerFunc(func(w *tlssyntax.Writer) {
		w.WriteVector(func(w *tlssyntax.Writer) {
			for i := range exts {
				exts[i].MarshalTLS(w)
			}
		})
	}))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x\n", b)

	var back []Extension
	err = tlssyntax.Unmarshal(b, tlssyntax.UnmarshalerFunc(func(r *tlssyntax.Reader) {
		r.ReadAll(func(r *tlssyntax.Reader) {
			var e Extension
			e.UnmarshalTLS(r)
			back = append(back, e)
		})
	}))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(back), back[0].Type, back[1].Type)
	// Output:
	// 0700010161000200
	// 2 1 2
}
