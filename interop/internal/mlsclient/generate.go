// Package mlsclient holds the gRPC bindings for the MLSClient service
// that the IETF MLS interop harness drives.
//
// mls_client.proto is copied unchanged from
// https://github.com/mlswg/mls-implementations/blob/cfd4502/interop/proto/mls_client.proto
// (commit cfd450286d1b, "Add mls-go (Go, RFC 9420) (#203)").
package mlsclient

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go_opt=Mmls_client.proto=github.com/tmc/mls/interop/internal/mlsclient;mlsclient --go-grpc_out=. --go-grpc_opt=paths=source_relative --go-grpc_opt=Mmls_client.proto=github.com/tmc/mls/interop/internal/mlsclient;mlsclient mls_client.proto
