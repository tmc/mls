// Command interop serves the MLSClient gRPC service of the IETF MLS
// interop harness (https://github.com/mlswg/mls-implementations) on
// top of github.com/tmc/mls, so that the harness's test-runner can
// drive it against other implementations.
//
// Usage:
//
//	interop [-port 50061]
//
// See README.md for the test matrix and results.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "github.com/tmc/mls/interop/internal/mlsclient"
)

func main() {
	port := flag.Int("port", 50061, "TCP port to listen on")
	flag.Parse()
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal(err)
	}
	s := grpc.NewServer()
	pb.RegisterMLSClientServer(s, newServer())
	log.Printf("tmc/mls interop client listening on %s", l.Addr())
	log.Fatal(s.Serve(l))
}
