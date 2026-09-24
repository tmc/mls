module github.com/tmc/mls/interop

go 1.27

replace github.com/tmc/mls => ../

require (
	github.com/tmc/mls v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.75.0
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
)
