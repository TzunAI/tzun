module github.com/TzunAI/tzun/tests/cross-impl/go

go 1.25.0

// Pinned to transparency-dev/merkle main (upstream fbbcd741). The v0.0.2 tag accepts
// five of the invalid consistency vectors (first = 0 with an empty proof, and
// first = second = 0); this commit refuses all of them. See README.md.
require github.com/transparency-dev/merkle v0.0.3-0.20260921095310-fbbcd741c3d1

// transparency-dev/formats v0.1.1 (upstream f8d9dedb) holds the stock
// checkpoint parser, log.Checkpoint.Unmarshal. checkpoint-vectors.json states
// each invalid body's stockParserAccepts against this version, and the tests
// refuse any other. Its go.mod asks for go 1.25.0. See README.md.
require (
	github.com/transparency-dev/formats v0.1.1
	golang.org/x/mod v0.36.0 // indirect
)
