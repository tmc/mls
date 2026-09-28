// Package groupfuzz fuzzes the evolution of an MLS group.
//
// Its only content is a test: a [github.com/tmc/fuzztape] state machine
// that drives several members of one group through sequences of
// proposals, commits, joins and application messages, delivered through
// a model delivery service, and checks after every step that the
// members who have reached the latest epoch agree on it.
//
// It is a separate module, so that fuzztape stays out of
// github.com/tmc/mls. It builds against the enclosing checkout through
// a replace directive and uses only the package's exported API.
//
// Run it as a fuzz target, or as a bounded number of random cases:
//
//	go test -fuzz FuzzGroup
//	go test -run TestGroup
package groupfuzz
