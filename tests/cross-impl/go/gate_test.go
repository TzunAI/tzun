package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const committedVectors = "../../../vectors"

// knownAccepted lists, for each library version the tests run against, the
// invalid entries that version accepts, as "<mutation> (<first>, <second>)".
// The pinned main commit refuses every invalid entry. v0.0.2, the latest tag
// and what "go get github.com/transparency-dev/merkle@latest" resolves to,
// accepts the five first = 0 entries below; make test-v002 runs every test
// against it.
var knownAccepted = map[string][]string{
	"v0.0.3-0.20260921095310-fbbcd741c3d1": nil,
	"v0.0.2": {
		"first = 0 with an empty proof (0, 1)",
		"first = 0 with an empty proof (0, 2)",
		"first = 0 with an empty proof (0, 7)",
		"first = 0 with an empty proof (0, 16)",
		"first = 0 and second = 0 (0, 0)",
	},
}

func linkedAccepts(t *testing.T) []string {
	t.Helper()
	v := libraryVersion()
	want, ok := knownAccepted[v]
	if !ok {
		t.Fatalf("no recorded expectation for %s %s; add its accepted invalid entries to knownAccepted", libraryPath, v)
	}
	return want
}

// The committed vectors pass under the pinned library, and under v0.0.2 fail
// on exactly the five first = 0 entries it accepts. Every summary line the
// gate prints is checked, so that each count it reports is the count it made.
func TestCommittedVectors(t *testing.T) {
	accepts := linkedAccepts(t)
	r := runGate(committedVectors)
	for _, l := range r.lines {
		t.Log(l)
	}
	cons := "merkle-consistency-vectors.json: "
	cp := "checkpoint-vectors.json: "
	e2e := "anchor-e2e-vectors.json: "
	wantLines := []string{
		"files: checked merkle-rfc6962-vectors.json, merkle-consistency-vectors.json, checkpoint-vectors.json, anchor-e2e-vectors.json",
		"files: outside the stock libraries' scope LICENSE, agent-descriptor-vectors.json, bundle-b1/, contributions-vectors.json, cross-sdk-parity-vectors.json, custody-entry-hash-vectors.json, decider-vectors.json, evidence-log-origin-vectors.json, evm-anchor-vectors.json, links-vectors.json, mandate-vectors.json, signoff-expectation-vectors.json, store-generation-vectors.json, v1.0-canonical-vectors.json, v1.0-integrity-vectors.json, v1.0-worked-example-vectors.json",
		"merkle-rfc6962-vectors.json: emptyTreeRoot equals the stock hasher's; 10 trees, every root and leaf hash equal; 61 audit paths, one for every leaf, verify and regenerate byte for byte; distinctness vectors hold: 1",
		cons + "64 leafDigests, derived as stated, the same leaves as merkle-rfc6962-vectors.json's trees",
		cons + "valid 237/237 verify, regenerate byte for byte, and match the stock roots; every pair with second <= 16 is present",
		cons + fmt.Sprintf("invalid %d/426 refused by the stock library", 426-len(accepts)),
		cons + "invalid 426/426 are their derivedFrom honest pair with only the named mutation applied",
		cons + "invalid has every mutation for every pair 0 < first < second <= 8",
		cons + "encoding 17/17 verdicts match (6 accepted; 11 refused, each by the encoding rule)",
		cons + "sizeMalleability 4 inclusion and 5 consistency exhibits exact; census recomputed and equal (inclusion 1984/2080 under another size; consistency 1984/2016 under another second, 0 under another first)",
		cp + "bodies.valid 11/11 read back by the stock parser to their origin, size and root, and hash to their checkpointDigest",
		cp + "bodies.invalid 30/30 stockParserAccepts flags are the stock parser's (it accepts 18, refuses 12)",
		cp + "bodies.nonString 4 entries, none a string, so none is a body a parser of bytes could read",
		cp + "anchorLog 2 epochs: 5 member checkpoints read back by the stock parser, each root the stock root of its source log; 2 anchor checkpoints read back, each root the stock root of anchorLeaves and P its SHA-256; the consistency proof (3, 5) verifies and regenerates byte for byte",
		cp + "outside a stock library's scope chainSegments, domain, artifacts (Tzun's origin rules and the steps of §10.3)",
		e2e + "2 epochs: every anchor checkpoint and 4 member checkpoints read back by the stock parser, P the SHA-256 of each anchor checkpoint, 2 consistency proofs verify with sizes and roots from the bodies",
		e2e + "8 records: canonicalDigest at sequenceNumber - 1 in its log checkpoint and SHA-256(logCheckpoint) in its anchor checkpoint, both verified by the stock library",
		e2e + "outside this module's scope: the publications' EVM material (checked with go-ethereum by evm/) and the canonical JSON of each payload",
	}
	if !slices.Equal(r.lines, wantLines) {
		t.Errorf("summary lines:\n%s\nwant:\n%s", strings.Join(r.lines, "\n"), strings.Join(wantLines, "\n"))
	}
	if !slices.Equal(r.accepted, accepts) {
		t.Errorf("%s %s accepted %q, want exactly %q", libraryPath, libraryVersion(), r.accepted, accepts)
	}
	if len(r.failures) != len(accepts) {
		t.Fatalf("%d failures, want %d:\n%s", len(r.failures), len(accepts), strings.Join(r.failures, "\n"))
	}
	for _, f := range r.failures {
		if !strings.Contains(f, "ACCEPTED by the stock library") {
			t.Errorf("unexpected failure: %s", f)
		}
	}
}

type doc = map[string]any

// corruption is one deliberate change to a copy of a committed vector file.
// The gate must fail on it with exactly the failures named in want: every
// want is part of some failure, and every failure contains some want.
type corruption struct {
	name string
	file string
	edit func(t *testing.T, d doc)
	want []string
}

func runCorruptions(t *testing.T, cases []corruption) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			dir := copyVectors(t)
			path := filepath.Join(dir, c.file)
			d := readDoc(t, path)
			c.edit(t, d)
			writeDoc(t, path, d)
			expectFailures(t, runGate(dir), c.want...)
		})
	}
}

// A deliberately corrupted vector makes the gate fail.
func TestCorruptedConsistencyVectorsFail(t *testing.T) {
	const f = consistencyFile
	runCorruptions(t, []corruption{
		// valid
		{"a valid proof element flipped", f, func(t *testing.T, d doc) {
			p := arr(findValid(t, d, 3, 7)["proof"])
			p[1] = flipHex(p[1].(string))
		}, []string{"valid (3, 7): the stock library refuses a valid proof", "valid (3, 7) proof differs from the stock library's"}},
		{"a valid proof element in uppercase", f, func(t *testing.T, d doc) {
			p := arr(findValid(t, d, 3, 7)["proof"])
			p[0] = strings.ToUpper(p[0].(string))
		}, []string{"valid (3, 7): proof[0]: uppercase hex digit"}},
		{"a valid proof that is null", f, func(t *testing.T, d doc) {
			findValid(t, d, 3, 7)["proof"] = nil
		}, []string{"valid (3, 7): proof is not a JSON array"}},
		{"a valid firstRoot replaced", f, func(t *testing.T, d doc) {
			c := findValid(t, d, 5, 9)
			c["firstRoot"] = flipHex(c["firstRoot"].(string))
		}, []string{"valid (5, 9) firstRoot is", "valid (5, 9): the stock library refuses a valid proof"}},
		{"a valid secondRoot replaced", f, func(t *testing.T, d doc) {
			c := findValid(t, d, 2, 11)
			c["secondRoot"] = flipHex(c["secondRoot"].(string))
		}, []string{"valid (2, 11) secondRoot is", "valid (2, 11): the stock library refuses a valid proof"}},
		{"a valid firstRoot that is not a string", f, func(t *testing.T, d doc) {
			findValid(t, d, 5, 9)["firstRoot"] = json.Number("7")
		}, []string{"valid (5, 9) firstRoot: not a JSON string"}},
		{"a valid secondRoot that is not a string", f, func(t *testing.T, d doc) {
			findValid(t, d, 5, 9)["secondRoot"] = json.Number("7")
		}, []string{"valid (5, 9) secondRoot: not a JSON string"}},
		{"a valid pair removed", f, func(t *testing.T, d doc) {
			removeWhere(t, d, "valid", func(c doc) bool { return num(c["first"]) == 2 && num(c["second"]) == 5 })
		}, []string{"valid lacks the pair (2, 5)"}},
		{"the valid pair (16, 16) removed", f, func(t *testing.T, d doc) {
			removeWhere(t, d, "valid", func(c doc) bool { return num(c["first"]) == 16 && num(c["second"]) == 16 })
		}, []string{"valid lacks the pair (16, 16)"}},
		{"a valid pair listed twice", f, func(t *testing.T, d doc) {
			d["valid"] = append(arr(d["valid"]), clone(findValid(t, d, 2, 5)))
		}, []string{"valid (2, 5): listed twice"}},
		{"a valid pair with first 0", f, func(t *testing.T, d doc) {
			findValid(t, d, 1, 1)["first"] = json.Number("0")
		}, []string{"valid (0, 1): sizes outside 0 < first <= second <= 64", "valid lacks the pair (1, 1)"}},
		{"a valid pair with first above second", f, func(t *testing.T, d doc) {
			findValid(t, d, 2, 5)["first"] = json.Number("6")
		}, []string{"valid (6, 5): sizes outside", "valid lacks the pair (2, 5)"}},
		{"a valid pair beyond the leaves", f, func(t *testing.T, d doc) {
			findValid(t, d, 62, 64)["second"] = json.Number("65")
		}, []string{"valid (62, 65): sizes outside"}},
		{"a valid pair without its first size", f, func(t *testing.T, d doc) {
			delete(findValid(t, d, 62, 64), "first")
		}, []string{"first or second missing"}},
		{"a valid pair without its second size", f, func(t *testing.T, d doc) {
			delete(findValid(t, d, 62, 64), "second")
		}, []string{"first or second missing"}},
		{"the valid section emptied", f, func(t *testing.T, d doc) { d["valid"] = []any{} }, []string{"valid is empty"}},

		// invalid: the library's verdict and decoding
		{"an invalid case replaced by its honest proof", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "proof[0] bit-flipped", 3, 7)
			c["proof"] = findValid(t, d, 3, 7)["proof"]
		}, []string{`"proof[0] bit-flipped" from (3, 7): ACCEPTED by the stock library`, "proof[0] is not one bit from the honest proof's", `invalid lacks "proof[0] bit-flipped" from (3, 7)`}},
		{"an invalid case that is not canonical hex", f, func(t *testing.T, d doc) {
			p := arr(arr(d["invalid"])[0].(doc)["proof"])
			p[0] = "0x" + p[0].(string)[2:]
		}, []string{"does not decode, so the library never sees it"}},
		{"an invalid case with an uppercase firstRoot", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "proof[0] bit-flipped", 3, 7)
			c["firstRoot"] = strings.ToUpper(c["firstRoot"].(string))
		}, []string{`"proof[0] bit-flipped" from (3, 7): does not decode`, `invalid lacks "proof[0] bit-flipped" from (3, 7)`}},
		{"an invalid case with an uppercase secondRoot", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "proof[0] bit-flipped", 3, 7)
			c["secondRoot"] = strings.ToUpper(c["secondRoot"].(string))
		}, []string{`"proof[0] bit-flipped" from (3, 7): does not decode`, `invalid lacks "proof[0] bit-flipped" from (3, 7)`}},
		{"an invalid case without its first size", f, func(t *testing.T, d doc) {
			delete(findInvalid(t, d, "first greater than second", 5, 6), "first")
		}, []string{`"first greater than second" from (5, 6): first or second missing`}},
		{"an invalid case without its second size", f, func(t *testing.T, d doc) {
			delete(findInvalid(t, d, "first greater than second", 5, 6), "second")
		}, []string{`"first greater than second" from (5, 6): first or second missing`}},
		{"the invalid section emptied", f, func(t *testing.T, d doc) { d["invalid"] = []any{} }, []string{"invalid is empty"}},
		{"an invalid entry listed twice", f, func(t *testing.T, d doc) {
			d["invalid"] = append(arr(d["invalid"]), clone(findInvalid(t, d, "proof[2] bit-flipped", 3, 7)))
		}, []string{`invalid[426] "proof[2] bit-flipped" from (3, 7): listed twice`}},

		// invalid: each entry is its derivedFrom pair with only the named mutation
		{"a bit-flip of two bits", f, func(t *testing.T, d doc) {
			p := arr(findInvalid(t, d, "proof[0] bit-flipped", 3, 7)["proof"])
			p[0] = flipHexAt(p[0].(string), 10)
		}, []string{"proof[0] is not one bit from the honest proof's", `invalid lacks "proof[0] bit-flipped" from (3, 7)`}},
		{"a bit-flip entry with another element changed too", f, func(t *testing.T, d doc) {
			p := arr(findInvalid(t, d, "proof[1] bit-flipped", 3, 7)["proof"])
			p[0] = flipHex(p[0].(string))
		}, []string{`is not derivedFrom with only "proof[1] bit-flipped" applied: proof is`, `invalid lacks "proof[1] bit-flipped" from (3, 7)`}},
		{"a bit-flip entry that lost an element", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "proof[1] bit-flipped", 3, 7)
			c["proof"] = arr(c["proof"])[:3]
		}, []string{"proof[1] is not one bit from the honest proof's", `invalid lacks "proof[1] bit-flipped" from (3, 7)`}},
		{"a bit-flip beyond the proof", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "proof[1] bit-flipped", 3, 7)["mutation"] = "proof[4] bit-flipped"
		}, []string{"proof[4] is not one bit from the honest proof's", `invalid lacks "proof[1] bit-flipped" from (3, 7)`}},
		{"a bit-flip name that is not canonical", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "proof[1] bit-flipped", 3, 7)["mutation"] = "proof[01] bit-flipped"
		}, []string{`the gate does not know the mutation "proof[01] bit-flipped"`, `invalid lacks "proof[1] bit-flipped" from (3, 7)`}},
		{"a bit-flip at a negative index", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "proof[1] bit-flipped", 3, 7)["mutation"] = "proof[-1] bit-flipped"
		}, []string{`the gate does not know the mutation "proof[-1] bit-flipped"`, `invalid lacks "proof[1] bit-flipped" from (3, 7)`}},
		{"a firstRoot bit-flip whose proof lost an element", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "firstRoot bit-flipped", 3, 7)
			c["proof"] = arr(c["proof"])[:3]
		}, []string{`is not derivedFrom with only "firstRoot bit-flipped" applied: proof is`, `invalid lacks "firstRoot bit-flipped" from (3, 7)`}},
		{"a firstRoot bit-flip that is another root", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "firstRoot bit-flipped", 3, 7)["firstRoot"] = findValid(t, d, 3, 7)["secondRoot"]
		}, []string{"firstRoot is not one bit from the honest root", `invalid lacks "firstRoot bit-flipped" from (3, 7)`}},
		{"a secondRoot bit-flip with its second size changed", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "secondRoot bit-flipped", 3, 7)["second"] = json.Number("8")
		}, []string{`is not derivedFrom with only "secondRoot bit-flipped" applied: sizes are (3, 8), want (3, 7)`, `invalid lacks "secondRoot bit-flipped" from (3, 7)`}},
		{"a secondRoot bit-flip with its first size changed", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "secondRoot bit-flipped", 3, 7)["first"] = json.Number("2")
		}, []string{`is not derivedFrom with only "secondRoot bit-flipped" applied: sizes are (2, 7), want (3, 7)`, `invalid lacks "secondRoot bit-flipped" from (3, 7)`}},
		{"a secondRoot bit-flip that is another root", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "secondRoot bit-flipped", 3, 7)["secondRoot"] = findValid(t, d, 3, 7)["firstRoot"]
		}, []string{"secondRoot is not one bit from the honest root", `invalid lacks "secondRoot bit-flipped" from (3, 7)`}},
		{"a secondRoot bit-flip whose firstRoot changed too", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "secondRoot bit-flipped", 3, 7)
			c["firstRoot"] = flipHex(c["firstRoot"].(string))
		}, []string{`is not derivedFrom with only "secondRoot bit-flipped" applied: firstRoot is`, `invalid lacks "secondRoot bit-flipped" from (3, 7)`}},
		{"a firstRoot bit-flip whose secondRoot changed too", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "firstRoot bit-flipped", 3, 7)
			c["secondRoot"] = flipHex(c["secondRoot"].(string))
		}, []string{`is not derivedFrom with only "firstRoot bit-flipped" applied: secondRoot is`, `invalid lacks "firstRoot bit-flipped" from (3, 7)`}},
		{"a swap whose roots are not swapped", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "first and second swapped", 3, 7)
			c["firstRoot"], c["secondRoot"] = c["secondRoot"], c["firstRoot"]
		}, []string{`is not derivedFrom with only "first and second swapped" applied: firstRoot is`, `invalid lacks "first and second swapped" from (3, 7)`}},
		{"a swap from equal sizes", f, func(t *testing.T, d doc) {
			setFrom(findInvalid(t, d, "first and second swapped", 3, 7), 3, 3)
		}, []string{"derivedFrom has equal sizes, so a swap changes nothing", `invalid lacks "first and second swapped" from (3, 7)`}},
		{"a last-element truncation that drops the first", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "proof truncated (last element dropped)", 3, 7)
			c["proof"] = arr(findValid(t, d, 3, 7)["proof"])[1:]
		}, []string{`only "proof truncated (last element dropped)" applied: proof is`, `invalid lacks "proof truncated (last element dropped)" from (3, 7)`}},
		{"a first-element truncation that drops the last", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "proof truncated (first element dropped)", 3, 7)
			c["proof"] = arr(findValid(t, d, 3, 7)["proof"])[:3]
		}, []string{`only "proof truncated (first element dropped)" applied: proof is`, `invalid lacks "proof truncated (first element dropped)" from (3, 7)`}},
		{"a secondRoot extension that appends the firstRoot", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "proof extended (secondRoot appended)", 3, 7)
			p := arr(c["proof"])
			p[len(p)-1] = c["firstRoot"]
		}, []string{`only "proof extended (secondRoot appended)" applied: proof is`, `invalid lacks "proof extended (secondRoot appended)" from (3, 7)`}},
		{"a repeat extension that repeats another element", f, func(t *testing.T, d doc) {
			p := arr(findInvalid(t, d, "proof extended (last element repeated)", 3, 7)["proof"])
			p[len(p)-1] = p[0]
		}, []string{`only "proof extended (last element repeated)" applied: proof is`, `invalid lacks "proof extended (last element repeated)" from (3, 7)`}},
		{"a last-element truncation of an empty honest proof", f, func(t *testing.T, d doc) {
			setFrom(findInvalid(t, d, "proof truncated (last element dropped)", 3, 7), 3, 3)
		}, []string{"the honest proof is empty", `invalid lacks "proof truncated (last element dropped)" from (3, 7)`}},
		{"a first-element truncation of an empty honest proof", f, func(t *testing.T, d doc) {
			setFrom(findInvalid(t, d, "proof truncated (first element dropped)", 3, 7), 3, 3)
		}, []string{"the honest proof is empty", `invalid lacks "proof truncated (first element dropped)" from (3, 7)`}},
		{"a repeat extension of an empty honest proof", f, func(t *testing.T, d doc) {
			setFrom(findInvalid(t, d, "proof extended (last element repeated)", 3, 7), 3, 3)
		}, []string{"the honest proof is empty", `invalid lacks "proof extended (last element repeated)" from (3, 7)`}},
		{"an equal-size non-empty proof emptied", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "equal sizes with a non-empty proof", 3, 3)["proof"] = []any{}
		}, []string{`"equal sizes with a non-empty proof" from (3, 3): ACCEPTED by the stock library`, "derivedFrom does not have equal sizes, or the proof is empty"}},
		{"an equal-size non-empty proof from unequal sizes", f, func(t *testing.T, d doc) {
			setFrom(findInvalid(t, d, "equal sizes with a non-empty proof", 3, 3), 3, 4)
		}, []string{"derivedFrom does not have equal sizes, or the proof is empty"}},
		{"an equal-size non-empty proof whose roots differ", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "equal sizes with a non-empty proof", 3, 3)
			c["secondRoot"] = flipHex(c["secondRoot"].(string))
		}, []string{`only "equal sizes with a non-empty proof" applied: secondRoot is`}},
		{"equal sizes with both roots changed", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "equal sizes with different roots", 3, 3)
			c["secondRoot"] = flipHex(c["secondRoot"].(string))
		}, []string{"not exactly one root differs from the honest root"}},
		{"equal sizes with neither root changed", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "equal sizes with different roots", 3, 3)
			c["firstRoot"] = c["secondRoot"]
		}, []string{`"equal sizes with different roots" from (3, 3): ACCEPTED by the stock library`, "not exactly one root differs from the honest root"}},
		{"equal sizes with different roots and a proof", f, func(t *testing.T, d doc) {
			c := findInvalid(t, d, "equal sizes with different roots", 3, 3)
			c["proof"] = []any{c["secondRoot"]}
		}, []string{`only "equal sizes with different roots" applied: proof is`}},
		{"equal sizes with different roots from unequal sizes", f, func(t *testing.T, d doc) {
			setFrom(findInvalid(t, d, "equal sizes with different roots", 3, 3), 3, 4)
		}, []string{"derivedFrom does not have equal sizes"}},
		{"a first = 0 empty proof with another secondRoot", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "first = 0 with an empty proof", 0, 7)["secondRoot"] = findValid(t, d, 6, 6)["firstRoot"]
		}, []string{`only "first = 0 with an empty proof" applied: secondRoot is`}},
		{"a first = 0 empty proof from second 0", f, func(t *testing.T, d doc) {
			setFrom(findInvalid(t, d, "first = 0 with an empty proof", 0, 7), 0, 0)
		}, []string{"derivedFrom has second = 0; this mutation starts from a non-empty second tree"}},
		{"a first = 0 empty proof from a non-zero first", f, func(t *testing.T, d doc) {
			setFrom(findInvalid(t, d, "first = 0 with an empty proof", 0, 7), 1, 7)
		}, []string{`derivedFrom has first = 1, which "first = 0 with an empty proof" does not start from`}},
		{"first = 0 and second = 0 from (0, 1)", f, func(t *testing.T, d doc) {
			setFrom(findInvalid(t, d, "first = 0 and second = 0", 0, 0), 0, 1)
		}, []string{"derivedFrom has second = 1, not 0"}},
		{"first = 0 and second = 0 with a secondRoot", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "first = 0 and second = 0", 0, 0)["secondRoot"] = findValid(t, d, 1, 1)["firstRoot"]
		}, []string{`only "first = 0 and second = 0" applied: secondRoot is`}},
		{"a first = 0 non-empty proof with another firstRoot", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "first = 0 with a non-empty proof", 0, 5)["firstRoot"] = findValid(t, d, 1, 1)["firstRoot"]
		}, []string{`only "first = 0 with a non-empty proof" applied: firstRoot is`}},
		{"a first = 0 non-empty proof from second 0", f, func(t *testing.T, d doc) {
			setFrom(findInvalid(t, d, "first = 0 with a non-empty proof", 0, 5), 0, 0)
		}, []string{"derivedFrom has second = 0, or the proof is empty"}},
		{"a mutation from first = 0 that does not start there", f, func(t *testing.T, d doc) {
			setFrom(findInvalid(t, d, "firstRoot bit-flipped", 3, 7), 0, 7)
		}, []string{`derivedFrom has first = 0, which "firstRoot bit-flipped" does not start from`, `invalid lacks "firstRoot bit-flipped" from (3, 7)`}},
		{"first above second with another firstRoot", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "first greater than second", 3, 7)["firstRoot"] = findValid(t, d, 7, 7)["firstRoot"]
		}, []string{`only "first greater than second" applied: firstRoot is`}},
		{"first above second with another proof", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "first greater than second", 3, 7)["proof"] = findValid(t, d, 2, 7)["proof"]
		}, []string{`only "first greater than second" applied: proof is`}},
		{"first above second that is not above it", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "first greater than second", 3, 7)["first"] = json.Number("7")
		}, []string{"first = 7 is not a size above second that the leaves reach"}},
		{"first above second beyond the leaves", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "first greater than second", 3, 7)["first"] = json.Number("65")
		}, []string{"first = 65 is not a size above second that the leaves reach"}},
		{"an unknown mutation", f, func(t *testing.T, d doc) {
			findInvalid(t, d, "firstRoot bit-flipped", 3, 7)["mutation"] = "firstRoot zeroed"
		}, []string{`the gate does not know the mutation "firstRoot zeroed"`, `invalid lacks "firstRoot bit-flipped" from (3, 7)`}},
		{"an invalid case without derivedFrom", f, func(t *testing.T, d doc) {
			delete(findInvalid(t, d, "firstRoot bit-flipped", 3, 7), "derivedFrom")
		}, []string{`"firstRoot bit-flipped" from (no derivedFrom): derivedFrom, or its first or second, missing`, `invalid lacks "firstRoot bit-flipped" from (3, 7)`}},
		{"a derivedFrom without first", f, func(t *testing.T, d doc) {
			delete(findInvalid(t, d, "firstRoot bit-flipped", 3, 7)["derivedFrom"].(doc), "first")
		}, []string{`"firstRoot bit-flipped" from (no derivedFrom): derivedFrom, or its first or second, missing`, `invalid lacks "firstRoot bit-flipped" from (3, 7)`}},
		{"a derivedFrom without second", f, func(t *testing.T, d doc) {
			delete(findInvalid(t, d, "firstRoot bit-flipped", 3, 7)["derivedFrom"].(doc), "second")
		}, []string{`"firstRoot bit-flipped" from (no derivedFrom): derivedFrom, or its first or second, missing`, `invalid lacks "firstRoot bit-flipped" from (3, 7)`}},
		{"a derivedFrom beyond the leaves", f, func(t *testing.T, d doc) {
			setFrom(findInvalid(t, d, "firstRoot bit-flipped", 3, 7), 3, 65)
		}, []string{"derivedFrom: (3, 65) is not a pair 0 <= first <= second <= 64", `invalid lacks "firstRoot bit-flipped" from (3, 7)`}},
		{"a derivedFrom with first above second", f, func(t *testing.T, d doc) {
			setFrom(findInvalid(t, d, "firstRoot bit-flipped", 3, 7), 8, 7)
		}, []string{"derivedFrom: (8, 7) is not a pair", `invalid lacks "firstRoot bit-flipped" from (3, 7)`}},

		// encoding
		{"an encoding verdict flipped", f, func(t *testing.T, d doc) {
			findEncoding(t, d, "proof[0] with a 0x prefix")["verifies"] = true
		}, []string{"harness verdict false, vector says true"}},
		{"an accepted encoding case flipped", f, func(t *testing.T, d doc) {
			findEncoding(t, d, "proof[0] in uppercase")["verifies"] = false
		}, []string{"harness verdict true, vector says false"}},
		{"an encoding case whose refusal comes from the math", f, func(t *testing.T, d doc) {
			c := findEncoding(t, d, "proof[0] in uppercase")
			c["verifies"] = false
			p := arr(c["proof"])
			p[1] = flipHex(p[1].(string))
		}, []string{"not by the encoding rule"}},
		{"an encoding case without verifies", f, func(t *testing.T, d doc) {
			delete(findEncoding(t, d, "proof is null"), "verifies")
		}, []string{`encoding[16] "proof is null": verifies, first or second missing`}},
		{"an encoding case without first", f, func(t *testing.T, d doc) {
			delete(findEncoding(t, d, "proof is null"), "first")
		}, []string{`encoding[16] "proof is null": verifies, first or second missing`}},
		{"an encoding case without second", f, func(t *testing.T, d doc) {
			delete(findEncoding(t, d, "proof is null"), "second")
		}, []string{`encoding[16] "proof is null": verifies, first or second missing`}},
		{"the encoding section emptied", f, func(t *testing.T, d doc) { d["encoding"] = []any{} }, []string{"encoding is empty"}},

		// leafDigests
		{"a consistency leaf digest replaced", f, func(t *testing.T, d doc) {
			l := arr(d["leafDigests"])
			l[7] = flipHex(l[7].(string))
		}, []string{`leafDigests[7]: is not SHA-256("tzun-merkle-vector-7")`}},
		{"a consistency leaf digest in uppercase", f, func(t *testing.T, d doc) {
			l := arr(d["leafDigests"])
			l[3] = strings.ToUpper(l[3].(string))
		}, []string{"leafDigests[3]: uppercase hex digit"}},
		{"the consistency leaves cut to 63", f, func(t *testing.T, d doc) {
			d["leafDigests"] = arr(d["leafDigests"])[:63]
		}, []string{"63 leafDigests, want at least 64"}},

		// sizeMalleability
		{"an inclusion exhibit list shortened", f, func(t *testing.T, d doc) {
			e := exhibit(d, "inclusion", 0)
			l := arr(e["alsoVerifiesUnderTreeSize"])
			e["alsoVerifiesUnderTreeSize"] = l[:len(l)-1]
		}, []string{"sizeMalleability.inclusion[0] (leaf 0, size 5): alsoVerifiesUnderTreeSize [6 7], the stock library accepts [6 7 8]"}},
		{"a consistency exhibit list shortened", f, func(t *testing.T, d doc) {
			e := exhibit(d, "consistency", 1)
			l := arr(e["alsoVerifiesUnderSecond"])
			e["alsoVerifiesUnderSecond"] = l[1:]
		}, []string{"sizeMalleability.consistency[1] (3, 5): alsoVerifiesUnderSecond [7 8], the stock library accepts [6 7 8]"}},
		{"sizeMalleability removed", f, func(t *testing.T, d doc) { delete(d, "sizeMalleability") }, []string{"sizeMalleability or its census is missing"}},
		{"the census removed", f, func(t *testing.T, d doc) { delete(d["sizeMalleability"].(doc), "census") }, []string{"sizeMalleability or its census is missing"}},
		{"the inclusion census removed", f, func(t *testing.T, d doc) {
			delete(d["sizeMalleability"].(doc)["census"].(doc), "inclusion")
		}, []string{"sizeMalleability or its census is missing"}},
		{"the consistency census removed", f, func(t *testing.T, d doc) {
			delete(d["sizeMalleability"].(doc)["census"].(doc), "consistency")
		}, []string{"sizeMalleability or its census is missing"}},
		{"the inclusion exhibits emptied", f, func(t *testing.T, d doc) {
			d["sizeMalleability"].(doc)["inclusion"] = []any{}
		}, []string{"sizeMalleability has no inclusion or no consistency exhibits"}},
		{"the consistency exhibits emptied", f, func(t *testing.T, d doc) {
			d["sizeMalleability"].(doc)["consistency"] = []any{}
		}, []string{"sizeMalleability has no inclusion or no consistency exhibits"}},
		{"an inclusion exhibit without leafIndex", f, func(t *testing.T, d doc) {
			delete(exhibit(d, "inclusion", 1), "leafIndex")
		}, []string{"sizeMalleability.inclusion[1]: leafIndex or treeSize missing or out of range"}},
		{"an inclusion exhibit without treeSize", f, func(t *testing.T, d doc) {
			delete(exhibit(d, "inclusion", 1), "treeSize")
		}, []string{"sizeMalleability.inclusion[1]: leafIndex or treeSize missing or out of range"}},
		{"an inclusion exhibit whose leaf is past its tree", f, func(t *testing.T, d doc) {
			exhibit(d, "inclusion", 1)["leafIndex"] = json.Number("3")
		}, []string{"sizeMalleability.inclusion[1]: leafIndex or treeSize missing or out of range"}},
		{"an inclusion exhibit beyond the census", f, func(t *testing.T, d doc) {
			exhibit(d, "inclusion", 1)["treeSize"] = json.Number("65")
		}, []string{"sizeMalleability.inclusion[1]: leafIndex or treeSize missing or out of range"}},
		{"an inclusion exhibit with another leaf's digest", f, func(t *testing.T, d doc) {
			exhibit(d, "inclusion", 1)["leafDigest"] = arr(d["leafDigests"])[2]
		}, []string{"sizeMalleability.inclusion[1] (leaf 1, size 3): leafDigest is not leafDigests[1]"}},
		{"an inclusion exhibit leafDigest in uppercase", f, func(t *testing.T, d doc) {
			e := exhibit(d, "inclusion", 1)
			e["leafDigest"] = strings.ToUpper(e["leafDigest"].(string))
		}, []string{"(leaf 1, size 3): leafDigest: uppercase hex digit"}},
		{"an inclusion exhibit root flipped", f, func(t *testing.T, d doc) {
			e := exhibit(d, "inclusion", 1)
			e["root"] = flipHex(e["root"].(string))
		}, []string{"(leaf 1, size 3) root is"}},
		{"an inclusion exhibit audit path flipped", f, func(t *testing.T, d doc) {
			p := arr(exhibit(d, "inclusion", 1)["auditPath"])
			p[0] = flipHex(p[0].(string))
		}, []string{"(leaf 1, size 3) auditPath differs from the stock library's", "(leaf 1, size 3): the honest audit path does not verify at its own size", "(leaf 1, size 3): alsoVerifiesUnderTreeSize [4], the stock library accepts []"}},
		{"an inclusion exhibit audit path that is null", f, func(t *testing.T, d doc) {
			exhibit(d, "inclusion", 1)["auditPath"] = nil
		}, []string{"(leaf 1, size 3): auditPath: proof is not a JSON array", "(leaf 1, size 3) auditPath: proof is not a JSON array"}},
		{"a consistency exhibit without first", f, func(t *testing.T, d doc) {
			delete(exhibit(d, "consistency", 0), "first")
		}, []string{"sizeMalleability.consistency[0]: first or second missing or out of range"}},
		{"a consistency exhibit without second", f, func(t *testing.T, d doc) {
			delete(exhibit(d, "consistency", 0), "second")
		}, []string{"sizeMalleability.consistency[0]: first or second missing or out of range"}},
		{"a consistency exhibit from size 0", f, func(t *testing.T, d doc) {
			exhibit(d, "consistency", 0)["first"] = json.Number("0")
		}, []string{"sizeMalleability.consistency[0]: first or second missing or out of range"}},
		{"a consistency exhibit with equal sizes", f, func(t *testing.T, d doc) {
			exhibit(d, "consistency", 0)["first"] = json.Number("3")
		}, []string{"sizeMalleability.consistency[0]: first or second missing or out of range"}},
		{"a consistency exhibit beyond the census", f, func(t *testing.T, d doc) {
			exhibit(d, "consistency", 0)["second"] = json.Number("65")
		}, []string{"sizeMalleability.consistency[0]: first or second missing or out of range"}},
		{"a consistency exhibit firstRoot flipped", f, func(t *testing.T, d doc) {
			e := exhibit(d, "consistency", 0)
			e["firstRoot"] = flipHex(e["firstRoot"].(string))
		}, []string{"sizeMalleability.consistency[0] (1, 3) firstRoot is"}},
		{"a consistency exhibit secondRoot flipped", f, func(t *testing.T, d doc) {
			e := exhibit(d, "consistency", 0)
			e["secondRoot"] = flipHex(e["secondRoot"].(string))
		}, []string{"sizeMalleability.consistency[0] (1, 3) secondRoot is"}},
		{"a consistency exhibit proof flipped", f, func(t *testing.T, d doc) {
			p := arr(exhibit(d, "consistency", 0)["proof"])
			p[0] = flipHex(p[0].(string))
		}, []string{"(1, 3) proof differs from the stock library's", "(1, 3): the honest proof does not verify at its own sizes", "(1, 3): alsoVerifiesUnderSecond [4], the stock library accepts []"}},
		{"a consistency exhibit proof that is null", f, func(t *testing.T, d doc) {
			exhibit(d, "consistency", 0)["proof"] = nil
		}, []string{"(1, 3): proof: proof is not a JSON array", "(1, 3) proof: proof is not a JSON array"}},

		// strict decoding
		{"an unknown section added", f, func(t *testing.T, d doc) { d["exhibits"] = []any{} }, []string{`top level: unknown field "exhibits"`}},
		{"a section renamed by case", f, func(t *testing.T, d doc) {
			d["Invalid"] = d["invalid"]
			delete(d, "invalid")
		}, []string{`top level: unknown field "Invalid"; keys match exactly, and the field is "invalid"`}},
		{"a nested field renamed by case", f, func(t *testing.T, d doc) {
			c := arr(d["valid"])[0].(doc)
			c["firstroot"] = c["firstRoot"]
			delete(c, "firstRoot")
		}, []string{`valid[0]: unknown field "firstroot"; keys match exactly, and the field is "firstRoot"`}},
		{"a field renamed by Unicode case folding", f, func(t *testing.T, d doc) {
			d["ſource"] = d["source"]
			delete(d, "source")
		}, []string{`top level: unknown field "ſource"; keys match exactly, and the field is "source"`}},
		{"a derivedFrom field renamed by case", f, func(t *testing.T, d doc) {
			df := findInvalid(t, d, "firstRoot bit-flipped", 3, 7)["derivedFrom"].(doc)
			df["First"] = df["first"]
			delete(df, "first")
		}, []string{`invalid[163].derivedFrom: unknown field "First"`}},
		{"a section of the wrong type", f, func(t *testing.T, d doc) { d["valid"] = doc{} }, []string{"cannot unmarshal object"}},
	})
}

// An invalid entry the library accepts is named in report.accepted, which
// the v0.0.2 expectation is checked against.
func TestAcceptedEntriesAreNamed(t *testing.T) {
	dir := copyVectors(t)
	path := filepath.Join(dir, consistencyFile)
	d := readDoc(t, path)
	findInvalid(t, d, "proof[0] bit-flipped", 3, 7)["proof"] = findValid(t, d, 3, 7)["proof"]
	writeDoc(t, path, d)
	r := runGate(dir)
	want := append([]string{"proof[0] bit-flipped (3, 7)"}, linkedAccepts(t)...)
	slices.Sort(want)
	got := slices.Sorted(slices.Values(r.accepted))
	if !slices.Equal(got, want) {
		t.Fatalf("accepted %q, want %q", got, want)
	}
}

// A missing mutation withholds the summary line that claims them all.
func TestCoverageLineOnlyWhenComplete(t *testing.T) {
	dir := copyVectors(t)
	path := filepath.Join(dir, consistencyFile)
	d := readDoc(t, path)
	removeWhere(t, d, "invalid", func(c doc) bool { return c["mutation"] == "proof[0] bit-flipped" && fromIs(c, 3, 7) })
	writeDoc(t, path, d)
	for _, l := range runGate(dir).lines {
		if strings.Contains(l, "invalid has every mutation") {
			t.Fatalf("summary line printed: %s", l)
		}
	}
}

// Every mutation the format promises for a pair 0 < first < second <= 8 is
// required: removing any one entry for (3, 7) fails the gate.
func TestEachCoveredMutationIsRequired(t *testing.T) {
	d := readDoc(t, filepath.Join(committedVectors, consistencyFile))
	var names []string
	for _, v := range arr(d["invalid"]) {
		c := v.(doc)
		if from := c["derivedFrom"].(doc); num(from["first"]) == 3 && num(from["second"]) == 7 && c["mutation"] != "first greater than second" {
			names = append(names, c["mutation"].(string))
		}
	}
	if len(names) != 11 {
		t.Fatalf("%d mutations from (3, 7), want 11: %q", len(names), names)
	}
	cases := []corruption{
		{"without proof[0] bit-flipped from (1, 2)", consistencyFile, func(t *testing.T, d doc) {
			removeWhere(t, d, "invalid", func(c doc) bool { return c["mutation"] == "proof[0] bit-flipped" && fromIs(c, 1, 2) })
		}, []string{`invalid lacks "proof[0] bit-flipped" from (1, 2)`}},
		{"without proof[0] bit-flipped from (7, 8)", consistencyFile, func(t *testing.T, d doc) {
			removeWhere(t, d, "invalid", func(c doc) bool { return c["mutation"] == "proof[0] bit-flipped" && fromIs(c, 7, 8) })
		}, []string{`invalid lacks "proof[0] bit-flipped" from (7, 8)`}},
	}
	for _, name := range names {
		cases = append(cases, corruption{"without " + name, consistencyFile, func(t *testing.T, d doc) {
			removeWhere(t, d, "invalid", func(c doc) bool {
				from := c["derivedFrom"].(doc)
				return c["mutation"] == name && num(from["first"]) == 3 && num(from["second"]) == 7
			})
		}, []string{fmt.Sprintf("invalid lacks %q from (3, 7)", name)}})
	}
	runCorruptions(t, cases)
}

// Each census count is compared, and each is required.
func TestCensusCounts(t *testing.T) {
	var cases []corruption
	for _, f := range []struct{ section, field string }{
		{"inclusion", "proofs"},
		{"inclusion", "verifyUnderAnotherTreeSize"},
		{"consistency", "proofs"},
		{"consistency", "verifyUnderAnotherSecondSize"},
		{"consistency", "verifyUnderAnotherFirstSize"},
	} {
		name := "census." + f.section + "." + f.field
		census := func(d doc) doc { return d["sizeMalleability"].(doc)["census"].(doc)[f.section].(doc) }
		cases = append(cases,
			corruption{name + " changed", consistencyFile, func(t *testing.T, d doc) {
				c := census(d)
				c[f.field] = json.Number(strconv.FormatUint(num(c[f.field])+1, 10))
			}, []string{"sizeMalleability." + name + " is "}},
			corruption{name + " removed", consistencyFile, func(t *testing.T, d doc) {
				delete(census(d), f.field)
			}, []string{"sizeMalleability." + name + " missing"}},
		)
	}
	runCorruptions(t, cases)
}

func TestCorruptedInclusionVectorsFail(t *testing.T) {
	const f = inclusionFile
	tree := func(d doc, i int) doc { return arr(d["trees"])[i].(doc) }
	proofAt := func(d doc, ti, pi int) doc { return arr(tree(d, ti)["proofs"])[pi].(doc) }
	dv := func(d doc) doc { return arr(d["distinctnessVectors"])[0].(doc) }
	runCorruptions(t, []corruption{
		{"an audit path element flipped", f, func(t *testing.T, d doc) {
			p := arr(proofAt(d, 4, 1)["auditPath"])
			p[0] = flipHex(p[0].(string))
		}, []string{"tree 5 leaf 1: the stock library refuses the audit path", "tree 5 leaf 1 auditPath differs from the stock library's"}},
		{"an audit path that is null", f, func(t *testing.T, d doc) {
			proofAt(d, 4, 1)["auditPath"] = nil
		}, []string{"tree 5 leaf 1: auditPath: proof is not a JSON array"}},
		{"an audit path for another leaf's digest", f, func(t *testing.T, d doc) {
			proofAt(d, 4, 1)["leafDigest"] = arr(tree(d, 4)["leafDigests"])[2]
		}, []string{"tree 5 leaf 1: leafDigest is not leafDigests[1]", "tree 5 leaf 1: the stock library refuses the audit path"}},
		{"an audit path leafDigest in uppercase", f, func(t *testing.T, d doc) {
			p := proofAt(d, 4, 1)
			p["leafDigest"] = strings.ToUpper(p["leafDigest"].(string))
		}, []string{"tree 5 leaf 1: leafDigest: uppercase hex digit"}},
		{"an audit path whose leafIndex is the tree size", f, func(t *testing.T, d doc) {
			proofAt(d, 4, 1)["leafIndex"] = json.Number("5")
		}, []string{"tree 5 proofs[1]: leafIndex missing or not below treeSize", "tree 5: no audit path for leaves [1]"}},
		{"an audit path without leafIndex", f, func(t *testing.T, d doc) {
			delete(proofAt(d, 4, 1), "leafIndex")
		}, []string{"tree 5 proofs[1]: leafIndex missing or not below treeSize", "tree 5: no audit path for leaves [1]"}},
		{"an audit path listed twice", f, func(t *testing.T, d doc) {
			tr := tree(d, 4)
			tr["proofs"] = append(arr(tr["proofs"]), clone(proofAt(d, 4, 0)))
		}, []string{"tree 5 leaf 0: listed twice"}},
		{"an audit path removed", f, func(t *testing.T, d doc) {
			tr := tree(d, 4)
			p := arr(tr["proofs"])
			tr["proofs"] = append(p[:2:2], p[3:]...)
		}, []string{"tree 5: no audit path for leaves [2]"}},
		{"a tree's audit paths removed", f, func(t *testing.T, d doc) {
			tree(d, 4)["proofs"] = []any{}
		}, []string{"tree 5: no audit path for leaves [0 1 2 3 4]"}},
		{"a tree root replaced", f, func(t *testing.T, d doc) {
			tr := tree(d, 3)
			tr["root"] = flipHex(tr["root"].(string))
		}, []string{"tree 4 root is"}},
		{"a leaf hash replaced", f, func(t *testing.T, d doc) {
			l := arr(tree(d, 4)["leafHashes"])
			l[2] = flipHex(l[2].(string))
		}, []string{"tree 5 leafHashes[2] is"}},
		{"a leaf hash removed", f, func(t *testing.T, d doc) {
			tr := tree(d, 4)
			tr["leafHashes"] = arr(tr["leafHashes"])[:4]
		}, []string{"tree 5: 4 leafHashes for 5 leaves"}},
		{"a tree leaf digest replaced", f, func(t *testing.T, d doc) {
			l := arr(tree(d, 4)["leafDigests"])
			l[1] = flipHex(l[1].(string))
		}, []string{`trees[4][1]: is not SHA-256("tzun-merkle-vector-1")`}},
		{"a tree leaf digest in uppercase", f, func(t *testing.T, d doc) {
			l := arr(tree(d, 4)["leafDigests"])
			l[1] = strings.ToUpper(l[1].(string))
		}, []string{"trees[4][1]: uppercase hex digit"}},
		{"a tree's leaves removed", f, func(t *testing.T, d doc) {
			tree(d, 4)["leafDigests"] = []any{}
		}, []string{"trees[4]: no leaf digests"}},
		{"a treeSize changed", f, func(t *testing.T, d doc) {
			tree(d, 4)["treeSize"] = json.Number("6")
		}, []string{"trees[4]: treeSize does not equal the 5 leafDigests"}},
		{"a treeSize removed", f, func(t *testing.T, d doc) {
			delete(tree(d, 4), "treeSize")
		}, []string{"trees[4]: treeSize does not equal the 5 leafDigests"}},
		{"the trees emptied", f, func(t *testing.T, d doc) { d["trees"] = []any{} }, []string{"trees is empty"}},
		{"the empty tree root replaced", f, func(t *testing.T, d doc) {
			e := d["emptyTreeRoot"].(doc)
			e["root"] = flipHex(e["root"].(string))
		}, []string{"differs from the stock hasher's EmptyRoot"}},
		{"the empty tree root in uppercase", f, func(t *testing.T, d doc) {
			e := d["emptyTreeRoot"].(doc)
			e["root"] = strings.ToUpper(e["root"].(string))
		}, []string{"emptyTreeRoot.root: uppercase hex digit"}},
		{"the empty tree root removed", f, func(t *testing.T, d doc) { delete(d, "emptyTreeRoot") }, []string{"emptyTreeRoot missing"}},
		{"a distinctness verdict flipped", f, func(t *testing.T, d doc) {
			dv(d)["rootsEqual"] = true
		}, []string{"distinctnessVectors[0]: rootsEqual is true, the stock library's roots say false"}},
		{"a distinctness verdict removed", f, func(t *testing.T, d doc) {
			delete(dv(d), "rootsEqual")
		}, []string{"distinctnessVectors[0]: rootsEqual missing"}},
		// These remove the verdict too, so that comparing the root of a tree
		// that failed would report a second failure.
		{"a distinctness tree removed", f, func(t *testing.T, d doc) {
			delete(dv(d), "a")
			delete(dv(d), "rootsEqual")
		}, []string{"distinctnessVectors[0].a: missing"}},
		{"the other distinctness tree removed", f, func(t *testing.T, d doc) {
			delete(dv(d), "b")
			delete(dv(d), "rootsEqual")
		}, []string{"distinctnessVectors[0].b: missing"}},
		{"a distinctness treeSize changed", f, func(t *testing.T, d doc) {
			dv(d)["a"].(doc)["treeSize"] = json.Number("4")
			delete(dv(d), "rootsEqual")
		}, []string{"distinctnessVectors[0].a: treeSize does not equal the 3 leafDigests"}},
		{"a distinctness leaf in uppercase", f, func(t *testing.T, d doc) {
			l := arr(dv(d)["a"].(doc)["leafDigests"])
			l[0] = strings.ToUpper(l[0].(string))
			delete(dv(d), "rootsEqual")
		}, []string{"distinctnessVectors[0].a[0]: uppercase hex digit"}},
		{"a distinctness root replaced", f, func(t *testing.T, d doc) {
			b := dv(d)["b"].(doc)
			b["root"] = flipHex(b["root"].(string))
		}, []string{"distinctnessVectors[0].b.root is"}},
		{"the distinctness vectors emptied", f, func(t *testing.T, d doc) {
			d["distinctnessVectors"] = []any{}
		}, []string{"distinctnessVectors is empty"}},
		{"an unknown field in a tree", f, func(t *testing.T, d doc) {
			tree(d, 0)["TreeSize"] = json.Number("1")
		}, []string{`trees[0]: unknown field "TreeSize"; keys match exactly, and the field is "treeSize"`}},
	})
}

// Edits to the bytes of a vector file that a decoded document cannot express.
func TestMalformedVectorFilesFail(t *testing.T) {
	cases := []struct {
		name string
		edit func(b []byte) []byte
		want string
	}{
		{"a section repeated", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`{`), []byte(`{"invalid":[],`), 1)
		}, `top level: key "invalid" appears twice in one object`},
		{"a key repeated in a free-form section", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"format":{`), []byte(`"format":{"valid":"x",`), 1)
		}, `format: key "valid" appears twice in one object`},
		{"a key repeated in an entry", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"valid":[{`), []byte(`"valid":[{"first":1,`), 1)
		}, `valid[0]: key "first" appears twice in one object`},
		{"a closing brace after the document", func(b []byte) []byte { return append(b, '}') }, "trailing data after the top-level value"},
		{"a second document", func(b []byte) []byte { return append(b, []byte("{}")...) }, "trailing data after the top-level value"},
		{"the file cut short", func(b []byte) []byte { return b[:len(b)/2] }, "unexpected EOF"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			dir := copyVectors(t)
			path := filepath.Join(dir, consistencyFile)
			writeDoc(t, path, readDoc(t, path))
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, c.edit(b), 0o644); err != nil {
				t.Fatal(err)
			}
			expectFailures(t, runGate(dir), c.want)
		})
	}
}

func TestInventory(t *testing.T) {
	write := func(t *testing.T, path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		edit func(t *testing.T, dir string)
		want []string
	}{
		{"an unknown vector file", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "unclassified-vectors.json"), "{}")
		}, []string{"vectors/unclassified-vectors.json is neither checked by this gate nor listed as out of its scope"}},
		{"a file with another extension", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "README.md"), "# vectors")
		}, []string{"vectors/README.md is neither checked by this gate nor listed as out of its scope"}},
		{"a subdirectory", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "planned", "case-1", "bundle.json"), "{}")
		}, []string{"vectors/planned/ is neither checked by this gate nor listed as out of its scope"}},
		{"a symbolic link", func(t *testing.T, dir string) {
			if err := os.Symlink(consistencyFile, filepath.Join(dir, "link.json")); err != nil {
				t.Fatal(err)
			}
		}, []string{"vectors/link.json is neither a regular file nor a directory"}},
		{"a checked vector file missing", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, inclusionFile)); err != nil {
				t.Fatal(err)
			}
		}, []string{"vectors/" + inclusionFile + " is missing"}},
		{"the checkpoint vector file missing", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, checkpointFile)); err != nil {
				t.Fatal(err)
			}
		}, []string{"vectors/" + checkpointFile + " is missing"}},
		{"a checked vector file that is a directory", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, inclusionFile)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, inclusionFile), 0o755); err != nil {
				t.Fatal(err)
			}
		}, []string{
			"vectors/" + inclusionFile + "/ is neither checked",
			"vectors/" + inclusionFile + " is missing",
			inclusionFile + ": read ",
		}},
		{"an out-of-scope file missing", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "custody-entry-hash-vectors.json")); err != nil {
				t.Fatal(err)
			}
		}, []string{"gate.go's outOfScope names vectors/custody-entry-hash-vectors.json, which does not exist; remove the entry"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			dir := copyVectors(t)
			c.edit(t, dir)
			expectFailures(t, runGate(dir), c.want...)
		})
	}

	t.Run("the vectors directory missing", func(t *testing.T) {
		expectFailures(t, runGate(filepath.Join(t.TempDir(), "vectors")), "vectors directory: open ")
	})

	t.Run("a subdirectory classified with a reason", func(t *testing.T) {
		dir := copyVectors(t)
		write(t, filepath.Join(dir, "planned", "case-1", "bundle.json"), "{}")
		scope := map[string]string{"planned/": "a reason"}
		for k, v := range outOfScope {
			scope[k] = v
		}
		r := &report{}
		checkInventory(r, dir, scope)
		if len(r.failures) != 0 {
			t.Fatalf("failures: %q", r.failures)
		}
		if want := "files: outside the stock libraries' scope LICENSE, agent-descriptor-vectors.json, bundle-b1/, contributions-vectors.json, cross-sdk-parity-vectors.json, custody-entry-hash-vectors.json, decider-vectors.json, evidence-log-origin-vectors.json, evm-anchor-vectors.json, links-vectors.json, mandate-vectors.json, planned/, signoff-expectation-vectors.json, store-generation-vectors.json, v1.0-canonical-vectors.json, v1.0-integrity-vectors.json, v1.0-worked-example-vectors.json"; r.lines[1] != want {
			t.Fatalf("got %q, want %q", r.lines[1], want)
		}
	})
}

// Stale outOfScope entries are reported in name order.
func TestStaleOutOfScopeEntriesInNameOrder(t *testing.T) {
	scope := map[string]string{"z-gone.json": "a reason", "a-gone.json": "a reason", "m-gone/": "a reason"}
	for k, v := range outOfScope {
		scope[k] = v
	}
	r := &report{}
	checkInventory(r, committedVectors, scope)
	want := []string{
		"gate.go's outOfScope names vectors/a-gone.json, which does not exist; remove the entry",
		"gate.go's outOfScope names vectors/m-gone/, which does not exist; remove the entry",
		"gate.go's outOfScope names vectors/z-gone.json, which does not exist; remove the entry",
	}
	if !slices.Equal(r.failures, want) {
		t.Fatalf("failures:\n%s\nwant:\n%s", strings.Join(r.failures, "\n"), strings.Join(want, "\n"))
	}
}

// Changes that keep the vectors true must keep the gate passing.
func TestFaithfulChangesPass(t *testing.T) {
	sizes := func(from, to uint64) []any {
		var l []any
		for s := from; s <= to; s++ {
			l = append(l, json.Number(strconv.FormatUint(s, 10)))
		}
		return l
	}
	cases := []struct {
		name string
		edit func(t *testing.T, d doc)
	}{
		// The file changes the first root; either one is the named mutation.
		{"an equal-size entry with the second root changed", func(t *testing.T, d doc) {
			c := findInvalid(t, d, "equal sizes with different roots", 3, 3)
			c["firstRoot"], c["secondRoot"] = c["secondRoot"], c["firstRoot"]
		}},
		// The file drops the first element only from proofs of two or more,
		// where it differs from dropping the last; from a one-element proof
		// it is still the named mutation.
		{"a first-element truncation of a one-element proof", func(t *testing.T, d doc) {
			c := clone(findInvalid(t, d, "proof truncated (last element dropped)", 1, 2))
			c["mutation"] = "proof truncated (first element dropped)"
			d["invalid"] = append(arr(d["invalid"]), c)
		}},
		{"first above second at the largest size the leaves reach", func(t *testing.T, d doc) {
			c := findInvalid(t, d, "first greater than second", 3, 7)
			c["first"] = json.Number("64")
			c["firstRoot"] = findValid(t, d, 64, 64)["firstRoot"]
		}},
		// Leaf 0 and first size 1 take six right-hand steps at every size from
		// 33 to 64, so an honest proof at one of those sizes verifies at all
		// the others, 64 included.
		{"size-malleability exhibits at sizes 33 and 64", func(t *testing.T, d doc) {
			tr := vectorTree(t, d)
			sm := d["sizeMalleability"].(doc)
			for _, n := range []uint64{33, 64} {
				path, err := tr.inclusionProof(0, n)
				if err != nil {
					t.Fatal(err)
				}
				also := sizes(33, 64)
				also = slices.DeleteFunc(also, func(v any) bool { return num(v) == n })
				sm["inclusion"] = append(arr(sm["inclusion"]), doc{
					"leafIndex": json.Number("0"), "leafDigest": arr(d["leafDigests"])[0],
					"treeSize": json.Number(strconv.FormatUint(n, 10)), "root": hexOf(tr.roots[n]),
					"auditPath": hexList(path), "alsoVerifiesUnderTreeSize": also,
				})
				p, err := tr.consistencyProof(1, n)
				if err != nil {
					t.Fatal(err)
				}
				sm["consistency"] = append(arr(sm["consistency"]), doc{
					"first": json.Number("1"), "second": json.Number(strconv.FormatUint(n, 10)),
					"firstRoot": hexOf(tr.roots[1]), "secondRoot": hexOf(tr.roots[n]),
					"proof": hexList(p), "alsoVerifiesUnderSecond": also,
				})
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			dir := copyVectors(t)
			path := filepath.Join(dir, consistencyFile)
			d := readDoc(t, path)
			c.edit(t, d)
			writeDoc(t, path, d)
			expectFailures(t, runGate(dir))
		})
	}
}

// ---- helpers

// acceptedLabel is the part of an ACCEPTED failure that names the entry's
// position, which a corruption elsewhere in the file can shift.
var acceptedLabel = regexp.MustCompile(`invalid\[\d+\] ("(?:[^"\\]|\\.)*") from \([^)]*\)`)

// linkedBaseline is the set of failures the linked library gives on the
// committed vectors (none under the pin; the five ACCEPTED entries under
// v0.0.2), with each entry's position removed.
var linkedBaseline = sync.OnceValue(func() map[string]bool {
	m := map[string]bool{}
	for _, f := range runGate(committedVectors).failures {
		m[acceptedLabel.ReplaceAllString(f, "invalid[] $1")] = true
	}
	return m
})

// expectFailures requires the gate's failures, apart from those the linked
// library gives on the committed vectors, to be exactly the ones wanted:
// every want is part of some failure, and every failure contains some want.
// With no wants, the gate must pass.
func expectFailures(t *testing.T, r *report, wants ...string) {
	t.Helper()
	var got []string
	for _, f := range r.failures {
		if !linkedBaseline()[acceptedLabel.ReplaceAllString(f, "invalid[] $1")] {
			got = append(got, f)
		}
	}
	for _, w := range wants {
		if !slices.ContainsFunc(got, func(f string) bool { return strings.Contains(f, w) }) {
			t.Errorf("no failure contains %q", w)
		}
	}
	for _, f := range got {
		if !slices.ContainsFunc(wants, func(w string) bool { return strings.Contains(f, w) }) {
			t.Errorf("unexpected failure: %s", f)
		}
	}
	if t.Failed() {
		t.Logf("all failures:\n%s", strings.Join(r.failures, "\n"))
	}
}

// copyVectors copies the committed vectors directory, its subdirectories
// included, into a fresh directory.
func copyVectors(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vectors")
	if err := os.CopyFS(dir, os.DirFS(committedVectors)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func readDoc(t *testing.T, path string) doc {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var d doc
	if err := dec.Decode(&d); err != nil {
		t.Fatal(err)
	}
	return d
}

func writeDoc(t *testing.T, path string, d doc) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(d); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func arr(v any) []any { return v.([]any) }

// clone deep-copies a decoded JSON value.
func clone(v doc) doc {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out doc
	if err := dec.Decode(&out); err != nil {
		panic(err)
	}
	return out
}

func removeWhere(t *testing.T, d doc, section string, match func(doc) bool) {
	t.Helper()
	l := arr(d[section])
	for i, v := range l {
		if match(v.(doc)) {
			d[section] = append(l[:i:i], l[i+1:]...)
			return
		}
	}
	t.Fatalf("no matching entry in %s", section)
}

func findValid(t *testing.T, d doc, first, second uint64) doc {
	t.Helper()
	for _, v := range arr(d["valid"]) {
		c := v.(doc)
		if num(c["first"]) == first && num(c["second"]) == second {
			return c
		}
	}
	t.Fatalf("no valid (%d, %d)", first, second)
	return nil
}

// findInvalid finds an invalid entry by its mutation and derivedFrom pair.
func findInvalid(t *testing.T, d doc, mutation string, first, second uint64) doc {
	t.Helper()
	for _, v := range arr(d["invalid"]) {
		c := v.(doc)
		from := c["derivedFrom"].(doc)
		if c["mutation"] == mutation && num(from["first"]) == first && num(from["second"]) == second {
			return c
		}
	}
	t.Fatalf("no invalid %q from (%d, %d)", mutation, first, second)
	return nil
}

func fromIs(c doc, first, second uint64) bool {
	from := c["derivedFrom"].(doc)
	return num(from["first"]) == first && num(from["second"]) == second
}

// vectorTree builds, with the library, the tree of the consistency file's leaves.
func vectorTree(t *testing.T, d doc) *tree {
	t.Helper()
	var leaves [][]byte
	for _, v := range arr(d["leafDigests"]) {
		b, err := hex.DecodeString(v.(string))
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, b)
	}
	tr, err := newTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func hexList(p [][]byte) []any {
	l := []any{}
	for _, h := range p {
		l = append(l, hexOf(h))
	}
	return l
}

func setFrom(c doc, first, second uint64) {
	c["derivedFrom"] = doc{"first": json.Number(strconv.FormatUint(first, 10)), "second": json.Number(strconv.FormatUint(second, 10))}
}

func findEncoding(t *testing.T, d doc, name string) doc {
	t.Helper()
	for _, v := range arr(d["encoding"]) {
		c := v.(doc)
		if c["case"] == name {
			return c
		}
	}
	t.Fatalf("no encoding case %q", name)
	return nil
}

func exhibit(d doc, kind string, i int) doc {
	return arr(d["sizeMalleability"].(doc)[kind])[i].(doc)
}

func num(v any) uint64 {
	n, err := strconv.ParseUint(string(v.(json.Number)), 10, 64)
	if err != nil {
		panic(fmt.Sprintf("not a size: %v", v))
	}
	return n
}

// flipHex flips the lowest bit of the last hex digit.
func flipHex(s string) string { return flipHexAt(s, len(s)-1) }

// flipHexAt flips the lowest bit of the hex digit at offset i.
func flipHexAt(s string, i int) string {
	c := s[i]
	var v byte
	switch {
	case c >= '0' && c <= '9':
		v = c - '0'
	default:
		v = c - 'a' + 10
	}
	return s[:i] + string("0123456789abcdef"[v^1]) + s[i+1:]
}
