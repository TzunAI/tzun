module github.com/TzunAI/tzun/tests/cross-impl/go

go 1.25.0

// The same module against transparency-dev/merkle v0.0.2, the latest tag and
// what "go get github.com/transparency-dev/merkle@latest" resolves to. make
// test-v002 runs the tests with -modfile=go.v0.0.2.mod; they assert that this
// version accepts exactly the five first = 0 invalid entries. See README.md.
require github.com/transparency-dev/merkle v0.0.2

// transparency-dev/formats v0.1.1 (upstream f8d9dedb) holds the stock
// checkpoint parser, log.Checkpoint.Unmarshal. checkpoint-vectors.json states
// each invalid body's stockParserAccepts against this version, and the tests
// refuse any other. Its go.mod asks for go 1.25.0. See README.md.
require (
	github.com/transparency-dev/formats v0.1.1
	golang.org/x/mod v0.36.0 // indirect
)
