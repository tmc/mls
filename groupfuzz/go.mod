module github.com/tmc/mls/groupfuzz

go 1.27

replace github.com/tmc/mls => ../

require (
	github.com/tmc/fuzztape v0.2.0
	github.com/tmc/mls v0.0.0-00010101000000-000000000000
)

require (
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
