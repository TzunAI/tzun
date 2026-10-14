package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/transparency-dev/merkle/proof"
)

const (
	inclusionFile   = "merkle-rfc6962-vectors.json"
	consistencyFile = "merkle-consistency-vectors.json"
	// censusMaxSize is the largest tree size sizeMalleability's census and
	// exhibits range over ("second size <= 64").
	censusMaxSize = 64
	// mutatedMaxSecond is the largest second size whose valid pairs carry
	// every mutation in invalid ("applied to every valid pair with second <= 8").
	mutatedMaxSecond = 8
)

// checkedFiles are the vector files this gate verifies with the stock
// libraries: the Merkle files with transparency-dev/merkle, and the checkpoint
// file and the Merkle half of the anvil end-to-end file with
// transparency-dev/formats and transparency-dev/merkle. The end-to-end file's
// EVM half is checked with go-ethereum by the module in evm/.
var checkedFiles = []string{inclusionFile, consistencyFile, checkpointFile, anchorE2EFile}

// outOfScope classifies the entries of the vectors directory that hold nothing
// for a Merkle or transparency-log library to check, each with its reason. A
// key ending in "/" names a subdirectory, and its reason covers everything in
// it. Every entry of the directory must be a checked file or a key here: any
// other file, whatever its extension, and any other subdirectory fails the
// gate until it is examined and given a checker or a reason. A key here that
// names nothing in the directory also fails the gate.
var outOfScope = map[string]string{
	"v1.0-canonical-vectors.json":      "canonical JSON serialisation; no tree, proof or log",
	"v1.0-integrity-vectors.json":      "digest form and chainLink of the integrity block; no tree, proof or log",
	"custody-entry-hash-vectors.json":  "length-prefixed custody entry hash chain; no tree, proof or log",
	"evidence-log-origin-vectors.json": "log origin strings; no tree, proof or log",
	"signoff-expectation-vectors.json": "a record's hashed signoff expectation against its sign-off material; no tree, proof or log",
	"evm-anchor-vectors.json": "publisher-manifest validity bounds (tzun-anchor/1 §9), which no stock library reads, and the signed transactions " +
		"at each edge of what §10.4 item 2 refuses, which stock libraries read differently from each other; no tree, proof or log. " +
		"Its one publication is anchor-e2e-vectors.json's epochs[0], byte for byte, whose EVM material evm/ checks with go-ethereum; " +
		"tests/ts/evm-anchor-vectors.test.ts and tests/cross-sdk/test_evm_anchor_vectors.py hold the copy to it and the SDKs to every case",
	"v1.0-worked-example-vectors.json": "the worked records W1 to W7 of the v1.0 revision: canonical bytes and digests of records; no tree, proof or log",
	"decider-vectors.json":             "the decider member's grammar, schemes, commitments and freshness references (Record §6); no tree, proof or log",
	"contributions-vectors.json":       "the contributions member's structure and binding rules (Record §7); no tree, proof or log",
	"links-vectors.json":               "the links member's grammar, relation registry and target rules (Record §8); no tree, proof or log",
	"mandate-vectors.json":             "mandate documents, predicates, statements, assertion digests and the mandate rows (Record §9.6 to §9.11); no tree, proof or log",
	"agent-descriptor-vectors.json":    "tzun-agent/1 descriptors and their digests (Record §6.9); no tree, proof or log",
	"store-generation-vectors.json":    "which hashed field set a stored digest recomputes under (Record §4.1); no tree, proof or log",
	"cross-sdk-parity-vectors.json":    "row outcomes TS, Python and Go must agree on for the revised record; no tree, proof or log",
	"LICENSE":                          "the CC0 1.0 licence text the vector files are released under; no tree, proof or log",
	"bundle-b1/": "b1 proof bundles and the verify reports expected for them (Bundle §13; Verification §6): Tzun's own report contract, " +
		"replayed by tests/ts/bundle-b1-corpus.test.ts; this gate decodes none of their anchoring material (checkpoints, paths, " +
		"proofs, block headers, trie proofs, raw transactions), some of which the corpus forges on purpose",
}

// report collects what the gate found. A gate run passes when failures is empty.
type report struct {
	lines    []string
	failures []string
	// accepted names each invalid entry the library accepted, as
	// "<mutation> (<first>, <second>)".
	accepted []string
}

func (r *report) notef(format string, a ...any) { r.lines = append(r.lines, fmt.Sprintf(format, a...)) }
func (r *report) failf(format string, a ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, a...))
}

// runGate checks every vector file in dir with the stock libraries.
func runGate(dir string) *report {
	r := &report{}
	checkInventory(r, dir, outOfScope)

	var incl inclusionVectors
	if loadStrict(r, filepath.Join(dir, inclusionFile), &incl) {
		checkInclusionFile(r, &incl)
	}
	var cons consistencyVectors
	if loadStrict(r, filepath.Join(dir, consistencyFile), &cons) {
		checkConsistencyFile(r, &cons)
	}
	var cp checkpointVectors
	if loadStrict(r, filepath.Join(dir, checkpointFile), &cp) {
		checkCheckpointFile(r, &cp)
	}
	var e2e anchorE2EVectors
	if loadStrict(r, filepath.Join(dir, anchorE2EFile), &e2e) {
		checkAnchorE2EFile(r, &e2e)
	}
	return r
}

// checkInventory fails on every entry of dir that is neither a checked file
// nor a key of scope, on an entry that is neither a regular file nor a
// directory, on a checked file that is missing, and on a key of scope that
// names nothing in dir. os.ReadDir returns the entries sorted by name.
func checkInventory(r *report, dir string, scope map[string]string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		r.failf("vectors directory: %v", err)
		return
	}
	present := map[string]bool{}
	var scoped []string
	for _, e := range entries {
		name := e.Name()
		switch {
		case e.Type().IsRegular():
		case e.IsDir():
			name += "/"
		default:
			r.failf("vectors/%s is neither a regular file nor a directory (mode %v); the gate does not follow it", name, e.Type())
			continue
		}
		present[name] = true
		switch {
		case slices.Contains(checkedFiles, name):
		case scope[name] != "":
			scoped = append(scoped, name)
		default:
			r.failf("vectors/%s is neither checked by this gate nor listed as out of its scope; add a checker or a reason in gate.go", name)
		}
	}
	for _, name := range checkedFiles {
		if !present[name] {
			r.failf("vectors/%s is missing", name)
		}
	}
	var stale []string
	for name := range scope {
		if !present[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	for _, name := range stale {
		r.failf("gate.go's outOfScope names vectors/%s, which does not exist; remove the entry", name)
	}
	r.notef("files: checked %s", strings.Join(checkedFiles, ", "))
	r.notef("files: outside the stock libraries' scope %s", strings.Join(scoped, ", "))
}

// loadStrict decodes a vector file into v, a pointer to one of the structs
// below. strictKeys (strict.go) first holds the file to the exact field names
// of v's type and to no repeated key, so that a renamed, case-changed, added
// or repeated field fails the gate instead of being read the way encoding/json
// reads it.
func loadStrict(r *report, path string, v any) bool {
	name := filepath.Base(path)
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			r.failf("%s: %v", name, err)
		}
		return false
	}
	if err := strictKeys(b, reflect.TypeOf(v).Elem()); err != nil {
		r.failf("%s: %v", name, err)
		return false
	}
	if err := json.Unmarshal(b, v); err != nil {
		r.failf("%s: %v", name, err)
		return false
	}
	return true
}

// ---- merkle-rfc6962-vectors.json

type inclusionVectors struct {
	Description          json.RawMessage `json:"description"`
	Source               json.RawMessage `json:"source"`
	LeafDigestDerivation json.RawMessage `json:"leafDigestDerivation"`
	EmptyTreeRoot        *struct {
		Note json.RawMessage `json:"note"`
		Root json.RawMessage `json:"root"`
	} `json:"emptyTreeRoot"`
	Trees []struct {
		TreeSize    *uint64           `json:"treeSize"`
		LeafDigests []json.RawMessage `json:"leafDigests"`
		Root        json.RawMessage   `json:"root"`
		LeafHashes  []json.RawMessage `json:"leafHashes"`
		Proofs      []struct {
			LeafIndex  *uint64         `json:"leafIndex"`
			LeafDigest json.RawMessage `json:"leafDigest"`
			AuditPath  json.RawMessage `json:"auditPath"`
		} `json:"proofs"`
	} `json:"trees"`
	DistinctnessVectors []struct {
		Name       string          `json:"name"`
		Why        json.RawMessage `json:"why"`
		A          *treeRoot       `json:"a"`
		B          *treeRoot       `json:"b"`
		RootsEqual *bool           `json:"rootsEqual"`
	} `json:"distinctnessVectors"`
}

type treeRoot struct {
	LeafDigests []json.RawMessage `json:"leafDigests"`
	TreeSize    *uint64           `json:"treeSize"`
	Root        json.RawMessage   `json:"root"`
}

func checkInclusionFile(r *report, v *inclusionVectors) {
	const f = inclusionFile
	before := len(r.failures)

	if v.EmptyTreeRoot == nil {
		r.failf("%s: emptyTreeRoot missing", f)
	} else if got, err := decodeHash(v.EmptyTreeRoot.Root, lowerOnly); err != nil {
		r.failf("%s: emptyTreeRoot.root: %v", f, err)
	} else if !bytes.Equal(got, hasher.EmptyRoot()) {
		r.failf("%s: emptyTreeRoot.root differs from the stock hasher's EmptyRoot %x", f, hasher.EmptyRoot())
	}

	if len(v.Trees) == 0 {
		r.failf("%s: trees is empty", f)
	}
	nProofs := 0
	for ti, tr := range v.Trees {
		where := fmt.Sprintf("%s: trees[%d]", f, ti)
		leaves, ok := decodeLeaves(r, where, tr.LeafDigests, derived)
		if !ok {
			continue
		}
		if tr.TreeSize == nil || *tr.TreeSize != uint64(len(leaves)) {
			r.failf("%s: treeSize does not equal the %d leafDigests", where, len(leaves))
			continue
		}
		size := *tr.TreeSize
		where = fmt.Sprintf("%s: tree %d", f, size)
		t, err := newTree(leaves)
		if err != nil {
			r.failf("%s: %v", where, err)
			continue
		}
		expectHex(r, where+" root", tr.Root, t.roots[size])
		if len(tr.LeafHashes) != len(leaves) {
			r.failf("%s: %d leafHashes for %d leaves", where, len(tr.LeafHashes), len(leaves))
		} else {
			for i := range leaves {
				expectHex(r, fmt.Sprintf("%s leafHashes[%d]", where, i), tr.LeafHashes[i], t.leafHashes[i])
			}
		}
		// The file gives one audit path for every leaf of every tree.
		listed := make([]bool, size)
		for pi, p := range tr.Proofs {
			pw := fmt.Sprintf("%s proofs[%d]", where, pi)
			if p.LeafIndex == nil || *p.LeafIndex >= size {
				r.failf("%s: leafIndex missing or not below treeSize", pw)
				continue
			}
			idx := *p.LeafIndex
			pw = fmt.Sprintf("%s leaf %d", where, idx)
			if listed[idx] {
				r.failf("%s: listed twice", pw)
			}
			listed[idx] = true
			d, err := decodeHash(p.LeafDigest, lowerOnly)
			if err != nil {
				r.failf("%s: leafDigest: %v", pw, err)
				continue
			}
			if !bytes.Equal(d, leaves[idx]) {
				r.failf("%s: leafDigest is not leafDigests[%d]", pw, idx)
			}
			path, err := decodeProof(p.AuditPath, lowerOnly)
			if err != nil {
				r.failf("%s: auditPath: %v", pw, err)
				continue
			}
			if err := proof.VerifyInclusion(hasher, idx, size, hasher.HashLeaf(d), path, t.roots[size]); err != nil {
				r.failf("%s: the stock library refuses the audit path: %v", pw, err)
			}
			expectRegenerated(r, pw+" auditPath", p.AuditPath, func() ([][]byte, error) { return t.inclusionProof(idx, size) })
			nProofs++
		}
		var missing []int
		for i, ok := range listed {
			if !ok {
				missing = append(missing, i)
			}
		}
		if len(missing) > 0 {
			r.failf("%s: no audit path for leaves %v; the file gives one for every leaf", where, missing)
		}
	}

	if len(v.DistinctnessVectors) == 0 {
		r.failf("%s: distinctnessVectors is empty", f)
	}
	for di, dv := range v.DistinctnessVectors {
		where := fmt.Sprintf("%s: distinctnessVectors[%d]", f, di)
		ra, okA := distinctRoot(r, where+".a", dv.A)
		rb, okB := distinctRoot(r, where+".b", dv.B)
		if !okA || !okB {
			continue
		}
		if dv.RootsEqual == nil {
			r.failf("%s: rootsEqual missing", where)
		} else if *dv.RootsEqual != bytes.Equal(ra, rb) {
			r.failf("%s: rootsEqual is %v, the stock library's roots say %v", where, *dv.RootsEqual, bytes.Equal(ra, rb))
		}
	}

	if len(r.failures) == before {
		r.notef("%s: emptyTreeRoot equals the stock hasher's; %d trees, every root and leaf hash equal; %d audit paths, one for every leaf, verify and regenerate byte for byte; distinctness vectors hold: %d",
			f, len(v.Trees), nProofs, len(v.DistinctnessVectors))
	}
}

func distinctRoot(r *report, where string, tr *treeRoot) ([]byte, bool) {
	if tr == nil {
		r.failf("%s: missing", where)
		return nil, false
	}
	leaves, ok := decodeLeaves(r, where, tr.LeafDigests, arbitrary)
	if !ok {
		return nil, false
	}
	if tr.TreeSize == nil || *tr.TreeSize != uint64(len(leaves)) {
		r.failf("%s: treeSize does not equal the %d leafDigests", where, len(leaves))
		return nil, false
	}
	t, err := newTree(leaves)
	if err != nil {
		r.failf("%s: %v", where, err)
		return nil, false
	}
	root := t.roots[len(leaves)]
	expectHex(r, where+".root", tr.Root, root)
	return root, true
}

// ---- merkle-consistency-vectors.json

// pairCase is a verifier input {first, second, firstRoot, secondRoot, proof}.
type pairCase struct {
	First      *uint64         `json:"first"`
	Second     *uint64         `json:"second"`
	FirstRoot  json.RawMessage `json:"firstRoot"`
	SecondRoot json.RawMessage `json:"secondRoot"`
	Proof      json.RawMessage `json:"proof"`
}

type invalidCase struct {
	pairCase
	Mutation    string       `json:"mutation"`
	DerivedFrom *derivedFrom `json:"derivedFrom"`
}

type derivedFrom struct {
	First  *uint64 `json:"first"`
	Second *uint64 `json:"second"`
}

type sizePair struct {
	First  uint64
	Second uint64
}

type encodingCase struct {
	Case       string          `json:"case"`
	Verifies   *bool           `json:"verifies"`
	First      *uint64         `json:"first"`
	Second     *uint64         `json:"second"`
	FirstRoot  json.RawMessage `json:"firstRoot"`
	SecondRoot json.RawMessage `json:"secondRoot"`
	Proof      json.RawMessage `json:"proof"`
}

type consistencyVectors struct {
	Description      json.RawMessage   `json:"description"`
	Source           json.RawMessage   `json:"source"`
	Format           json.RawMessage   `json:"format"`
	EdgeRules        json.RawMessage   `json:"edgeRules"`
	LeafDigests      []json.RawMessage `json:"leafDigests"`
	Valid            []pairCase        `json:"valid"`
	Invalid          []invalidCase     `json:"invalid"`
	Encoding         []encodingCase    `json:"encoding"`
	SizeMalleability *struct {
		Note   json.RawMessage `json:"note"`
		Census *struct {
			Inclusion *struct {
				Proofs                     *int `json:"proofs"`
				VerifyUnderAnotherTreeSize *int `json:"verifyUnderAnotherTreeSize"`
			} `json:"inclusion"`
			Consistency *struct {
				Proofs                       *int `json:"proofs"`
				VerifyUnderAnotherSecondSize *int `json:"verifyUnderAnotherSecondSize"`
				VerifyUnderAnotherFirstSize  *int `json:"verifyUnderAnotherFirstSize"`
			} `json:"consistency"`
		} `json:"census"`
		Inclusion []struct {
			LeafIndex                 *uint64         `json:"leafIndex"`
			LeafDigest                json.RawMessage `json:"leafDigest"`
			TreeSize                  *uint64         `json:"treeSize"`
			Root                      json.RawMessage `json:"root"`
			AuditPath                 json.RawMessage `json:"auditPath"`
			AlsoVerifiesUnderTreeSize []uint64        `json:"alsoVerifiesUnderTreeSize"`
		} `json:"inclusion"`
		Consistency []struct {
			First                   *uint64         `json:"first"`
			Second                  *uint64         `json:"second"`
			FirstRoot               json.RawMessage `json:"firstRoot"`
			SecondRoot              json.RawMessage `json:"secondRoot"`
			Proof                   json.RawMessage `json:"proof"`
			AlsoVerifiesUnderSecond []uint64        `json:"alsoVerifiesUnderSecond"`
		} `json:"consistency"`
	} `json:"sizeMalleability"`
}

// checkConsistencyFile checks the consistency file. Its leaf digests are held
// to the derivation the inclusion file's trees are held to, so the two files
// state the same leaves.
func checkConsistencyFile(r *report, v *consistencyVectors) {
	const f = consistencyFile
	leaves, ok := decodeLeaves(r, f+": leafDigests", v.LeafDigests, derived)
	if !ok {
		return
	}
	if len(leaves) < censusMaxSize {
		r.failf("%s: %d leafDigests, want at least %d", f, len(leaves), censusMaxSize)
		return
	}
	t, err := newTree(leaves)
	if err != nil {
		r.failf("%s: %v", f, err)
		return
	}
	r.notef("%s: %d leafDigests, derived as stated, the same leaves as %s's trees", f, len(leaves), inclusionFile)
	checkValid(r, t, v.Valid)
	checkInvalid(r, t, v.Invalid)
	checkEncoding(r, v.Encoding)
	checkMalleability(r, t, v)
}

func checkValid(r *report, t *tree, cases []pairCase) {
	const f = consistencyFile
	before := len(r.failures)
	if len(cases) == 0 {
		r.failf("%s: valid is empty", f)
		return
	}
	seen := map[sizePair]bool{}
	for i, c := range cases {
		where := fmt.Sprintf("%s: valid[%d]", f, i)
		if c.First == nil || c.Second == nil {
			r.failf("%s: first or second missing", where)
			continue
		}
		m, n := *c.First, *c.Second
		where = fmt.Sprintf("%s: valid (%d, %d)", f, m, n)
		if m == 0 || m > n || n > t.size() {
			r.failf("%s: sizes outside 0 < first <= second <= %d", where, t.size())
			continue
		}
		if seen[sizePair{m, n}] {
			r.failf("%s: listed twice", where)
		}
		seen[sizePair{m, n}] = true
		expectHex(r, where+" firstRoot", c.FirstRoot, t.roots[m])
		expectHex(r, where+" secondRoot", c.SecondRoot, t.roots[n])
		p, err := decodeProof(c.Proof, lowerOnly)
		if err != nil {
			r.failf("%s: %v", where, err)
			continue
		}
		r1, err1 := decodeHash(c.FirstRoot, lowerOnly)
		r2, err2 := decodeHash(c.SecondRoot, lowerOnly)
		if err1 != nil || err2 != nil {
			continue
		}
		if err := proof.VerifyConsistency(hasher, m, n, p, r1, r2); err != nil {
			r.failf("%s: the stock library refuses a valid proof: %v", where, err)
		}
		expectRegenerated(r, where+" proof", c.Proof, func() ([][]byte, error) { return t.consistencyProof(m, n) })
	}
	// The format promises every pair 0 < first <= second <= 16.
	for n := uint64(1); n <= 16; n++ {
		for m := uint64(1); m <= n; m++ {
			if !seen[sizePair{m, n}] {
				r.failf("%s: valid lacks the pair (%d, %d); the format promises every pair with second <= 16", f, m, n)
			}
		}
	}
	if len(r.failures) == before {
		r.notef("%s: valid %d/%d verify, regenerate byte for byte, and match the stock roots; every pair with second <= 16 is present", f, len(cases), len(cases))
	}
}

// invalidKey identifies an invalid entry: its mutation and derivedFrom pair.
type invalidKey struct {
	mutation string
	from     sizePair
}

// checkInvalid checks that the library refuses every invalid entry, that each
// entry is its derivedFrom honest pair with the named mutation applied and
// nothing else changed, and that the mutations cover the pairs the format
// says they do.
func checkInvalid(r *report, t *tree, cases []invalidCase) {
	const f = consistencyFile
	if len(cases) == 0 {
		r.failf("%s: invalid is empty", f)
		return
	}
	refused, derivedOK := 0, 0
	seen := map[invalidKey]bool{}
	for i, c := range cases {
		label := fmt.Sprintf("%s: invalid[%d] %q from %s", f, i, c.Mutation, describePair(c.DerivedFrom))
		if c.First == nil || c.Second == nil {
			r.failf("%s: first or second missing", label)
			continue
		}
		// Every invalid entry is canonical hex, so that its refusal is the
		// library's and never a decoding accident here.
		p, err := decodeProof(c.Proof, lowerOnly)
		r1, err1 := decodeHash(c.FirstRoot, lowerOnly)
		r2, err2 := decodeHash(c.SecondRoot, lowerOnly)
		if err := firstErr(err, err1, err2); err != nil {
			r.failf("%s: does not decode, so the library never sees it: %v", label, err)
			continue
		}
		if err := proof.VerifyConsistency(hasher, *c.First, *c.Second, p, r1, r2); err == nil {
			r.failf("%s: ACCEPTED by the stock library (first=%d, second=%d, %d proof elements)", label, *c.First, *c.Second, len(p))
			r.accepted = append(r.accepted, fmt.Sprintf("%s (%d, %d)", c.Mutation, *c.First, *c.Second))
		} else {
			refused++
		}
		got := newEntry(*c.First, *c.Second, r1, r2, p)
		from, err := checkDerivation(t, c.Mutation, c.DerivedFrom, got)
		if err != nil {
			r.failf("%s: %v", label, err)
			continue
		}
		derivedOK++
		k := invalidKey{c.Mutation, from}
		if seen[k] {
			r.failf("%s: listed twice", label)
		}
		seen[k] = true
	}
	r.notef("%s: invalid %d/%d refused by the stock library", f, refused, len(cases))
	r.notef("%s: invalid %d/%d are their derivedFrom honest pair with only the named mutation applied", f, derivedOK, len(cases))
	if checkInvalidCoverage(r, t, seen) {
		r.notef("%s: invalid has every mutation for every pair 0 < first < second <= %d", f, mutatedMaxSecond)
	}
}

// checkInvalidCoverage checks the format's promise that every mutation is
// applied to every valid pair with second <= 8, for 0 < first < second: each
// proof element and each root bit-flipped, the sizes swapped, the last element
// dropped, the first element dropped when that leaves a different proof, and
// the two extensions. For first = second the file carries its two mutations
// for a selected set of sizes (it has no (5, 5) or (6, 6) entry), so those
// entries are held only to their derivation.
func checkInvalidCoverage(r *report, t *tree, seen map[invalidKey]bool) bool {
	ok := true
	for n := uint64(2); n <= mutatedMaxSecond; n++ {
		for m := uint64(1); m < n; m++ {
			h, err := t.honestEntry(m, n)
			if err != nil {
				r.failf("%s: invalid coverage: %v", consistencyFile, err)
				return false
			}
			names := []string{
				"firstRoot bit-flipped", "secondRoot bit-flipped", "first and second swapped",
				"proof truncated (last element dropped)",
				"proof extended (secondRoot appended)", "proof extended (last element repeated)",
			}
			for i := range h.proof {
				names = append(names, fmt.Sprintf("proof[%d] bit-flipped", i))
			}
			if len(h.proof) > 1 {
				names = append(names, "proof truncated (first element dropped)")
			}
			for _, name := range names {
				if !seen[invalidKey{name, sizePair{m, n}}] {
					r.failf("%s: invalid lacks %q from (%d, %d); the format applies every mutation to every valid pair with second <= %d", consistencyFile, name, m, n, mutatedMaxSecond)
					ok = false
				}
			}
		}
	}
	return ok
}

// entry is a verifier input with every hash as lowercase hex.
type entry struct {
	first, second         uint64
	firstRoot, secondRoot string
	proof                 []string
}

func newEntry(first, second uint64, firstRoot, secondRoot []byte, p [][]byte) entry {
	e := entry{first: first, second: second, firstRoot: hex.EncodeToString(firstRoot), secondRoot: hex.EncodeToString(secondRoot), proof: []string{}}
	for _, h := range p {
		e.proof = append(e.proof, hex.EncodeToString(h))
	}
	return e
}

// honestEntry is the verifier input the library builds for (first, second):
// the roots of those sizes and the consistency proof between them. With
// first = 0 the first root is the empty root and the proof is empty.
func (t *tree) honestEntry(first, second uint64) (entry, error) {
	if first > second || second > t.size() {
		return entry{}, fmt.Errorf("(%d, %d) is not a pair 0 <= first <= second <= %d", first, second, t.size())
	}
	var p [][]byte
	if first > 0 {
		var err error
		if p, err = t.consistencyProof(first, second); err != nil {
			return entry{}, err
		}
	}
	return newEntry(first, second, t.roots[first], t.roots[second], p), nil
}

// checkDerivation checks that got is the honest entry for derivedFrom with
// the named mutation applied and nothing else changed, and returns the
// derivedFrom pair.
func checkDerivation(t *tree, mutation string, df *derivedFrom, got entry) (sizePair, error) {
	if df == nil || df.First == nil || df.Second == nil {
		return sizePair{}, errors.New("derivedFrom, or its first or second, missing")
	}
	from := sizePair{*df.First, *df.Second}
	h, err := t.honestEntry(from.First, from.Second)
	if err != nil {
		return from, fmt.Errorf("derivedFrom: %v", err)
	}
	want, err := derive(t, h, mutation, got)
	if err != nil {
		return from, err
	}
	if d := got.diff(want); d != "" {
		return from, fmt.Errorf("is not derivedFrom with only %q applied: %s", mutation, d)
	}
	return from, nil
}

// derive applies the named mutation to the honest entry h and returns what
// the invalid entry must be. A bit-flip takes the flipped value from got once
// it is exactly one bit from the honest value, and a mutation that says only
// "a non-empty proof" takes got's proof once it is non-empty.
func derive(t *tree, h entry, mutation string, got entry) (entry, error) {
	w := h
	w.proof = slices.Clone(h.proof)
	last := len(h.proof) - 1
	fromZero := strings.HasPrefix(mutation, "first = 0 ")
	if fromZero != (h.first == 0) {
		return w, fmt.Errorf("derivedFrom has first = %d, which %q does not start from", h.first, mutation)
	}
	var i int
	switch {
	case mutation == "first = 0 with an empty proof":
		if h.second == 0 {
			return w, errors.New("derivedFrom has second = 0; this mutation starts from a non-empty second tree")
		}
	case mutation == "first = 0 and second = 0":
		if h.second != 0 {
			return w, fmt.Errorf("derivedFrom has second = %d, not 0", h.second)
		}
	case mutation == "first = 0 with a non-empty proof":
		if h.second == 0 || len(got.proof) == 0 {
			return w, errors.New("derivedFrom has second = 0, or the proof is empty")
		}
		w.proof = got.proof
	case mutation == "equal sizes with a non-empty proof":
		if h.first != h.second || len(got.proof) == 0 {
			return w, errors.New("derivedFrom does not have equal sizes, or the proof is empty")
		}
		w.proof = got.proof
	case mutation == "equal sizes with different roots":
		if h.first != h.second {
			return w, errors.New("derivedFrom does not have equal sizes")
		}
		switch {
		case got.firstRoot != h.firstRoot && got.secondRoot == h.secondRoot:
			w.firstRoot = got.firstRoot
		case got.secondRoot != h.secondRoot && got.firstRoot == h.firstRoot:
			w.secondRoot = got.secondRoot
		default:
			return w, errors.New("not exactly one root differs from the honest root")
		}
	case mutation == "firstRoot bit-flipped":
		if !oneBitApart(got.firstRoot, h.firstRoot) {
			return w, errors.New("firstRoot is not one bit from the honest root")
		}
		w.firstRoot = got.firstRoot
	case mutation == "secondRoot bit-flipped":
		if !oneBitApart(got.secondRoot, h.secondRoot) {
			return w, errors.New("secondRoot is not one bit from the honest root")
		}
		w.secondRoot = got.secondRoot
	case parseProofFlip(mutation, &i):
		if i > last || len(got.proof) != len(h.proof) || !oneBitApart(got.proof[i], h.proof[i]) {
			return w, fmt.Errorf("proof[%d] is not one bit from the honest proof's", i)
		}
		w.proof[i] = got.proof[i]
	case mutation == "first and second swapped":
		if h.first == h.second {
			return w, errors.New("derivedFrom has equal sizes, so a swap changes nothing")
		}
		w.first, w.second, w.firstRoot, w.secondRoot = h.second, h.first, h.secondRoot, h.firstRoot
	case mutation == "proof truncated (last element dropped)":
		if last < 0 {
			return w, errors.New("the honest proof is empty")
		}
		w.proof = w.proof[:last]
	case mutation == "proof truncated (first element dropped)":
		if last < 0 {
			return w, errors.New("the honest proof is empty")
		}
		w.proof = w.proof[1:]
	case mutation == "proof extended (secondRoot appended)":
		w.proof = append(w.proof, h.secondRoot)
	case mutation == "proof extended (last element repeated)":
		if last < 0 {
			return w, errors.New("the honest proof is empty")
		}
		w.proof = append(w.proof, h.proof[last])
	case mutation == "first greater than second":
		if got.first <= h.second || got.first > t.size() {
			return w, fmt.Errorf("first = %d is not a size above second that the leaves reach", got.first)
		}
		w.first, w.firstRoot = got.first, hex.EncodeToString(t.roots[got.first])
	default:
		return w, fmt.Errorf("the gate does not know the mutation %q; add its derivation to derive in gate.go", mutation)
	}
	return w, nil
}

// parseProofFlip reports whether mutation is exactly "proof[i] bit-flipped"
// for a decimal i >= 0, and sets *i.
func parseProofFlip(mutation string, i *int) bool {
	var n int
	if _, err := fmt.Sscanf(mutation, "proof[%d] bit-flipped", &n); err != nil {
		return false
	}
	if n < 0 || mutation != fmt.Sprintf("proof[%d] bit-flipped", n) {
		return false
	}
	*i = n
	return true
}

// oneBitApart reports whether two lowercase hex hashes of equal length differ
// in exactly one bit.
func oneBitApart(a, b string) bool {
	x, errA := hex.DecodeString(a)
	y, errB := hex.DecodeString(b)
	if errA != nil || errB != nil || len(x) != len(y) {
		return false
	}
	n := 0
	for i := range x {
		n += bits.OnesCount8(x[i] ^ y[i])
	}
	return n == 1
}

// diff describes the first field in which e differs from want, or returns "".
func (e entry) diff(want entry) string {
	switch {
	case e.first != want.first || e.second != want.second:
		return fmt.Sprintf("sizes are (%d, %d), want (%d, %d)", e.first, e.second, want.first, want.second)
	case e.firstRoot != want.firstRoot:
		return fmt.Sprintf("firstRoot is %s, want %s", e.firstRoot, want.firstRoot)
	case e.secondRoot != want.secondRoot:
		return fmt.Sprintf("secondRoot is %s, want %s", e.secondRoot, want.secondRoot)
	case !slices.Equal(e.proof, want.proof):
		return fmt.Sprintf("proof is %v, want %v", e.proof, want.proof)
	}
	return ""
}

// checkEncoding gives each encoding case the harness's verdict: the encoding
// rule is applied to every hash first (hexrule.go), and a case that passes it
// goes to proof.VerifyConsistency. The verdict must equal "verifies". A case
// expected to fail must fail at the encoding rule: apart from its one
// malformed value it is the honest (3, 7) proof, so a refusal from the
// library would mean the case no longer tests encoding.
func checkEncoding(r *report, cases []encodingCase) {
	const f = consistencyFile
	before := len(r.failures)
	if len(cases) == 0 {
		r.failf("%s: encoding is empty", f)
		return
	}
	accepted, refused := 0, 0
	for i, c := range cases {
		where := fmt.Sprintf("%s: encoding[%d] %q", f, i, c.Case)
		if c.Verifies == nil || c.First == nil || c.Second == nil {
			r.failf("%s: verifies, first or second missing", where)
			continue
		}
		p, err := decodeProof(c.Proof, anyCase)
		r1, err1 := decodeHash(c.FirstRoot, anyCase)
		r2, err2 := decodeHash(c.SecondRoot, anyCase)
		encErr := firstErr(err, err1, err2)
		var libErr error
		if encErr == nil {
			libErr = proof.VerifyConsistency(hasher, *c.First, *c.Second, p, r1, r2)
		}
		verdict := encErr == nil && libErr == nil
		switch {
		case verdict != *c.Verifies:
			r.failf("%s: harness verdict %v, vector says %v (encoding: %v; library: %v)", where, verdict, *c.Verifies, encErr, libErr)
		case !verdict && encErr == nil:
			r.failf("%s: refused by the library (%v), not by the encoding rule, so the case does not test encoding", where, libErr)
		case verdict:
			accepted++
		default:
			refused++
		}
	}
	if len(r.failures) == before {
		r.notef("%s: encoding %d/%d verdicts match (%d accepted; %d refused, each by the encoding rule)", f, len(cases), len(cases), accepted, refused)
	}
}

// checkMalleability recomputes sizeMalleability with the stock library. The
// file calls it documentation, not conformance; it also says the exhibits hold
// under any RFC-correct verifier, and this is the check that they hold under
// transparency-dev/merkle. Each exhibit's list of other sizes must be exactly
// the sizes <= 64 under which the library accepts the honest proof.
func checkMalleability(r *report, t *tree, v *consistencyVectors) {
	const f = consistencyFile
	before := len(r.failures)
	sm := v.SizeMalleability
	if sm == nil || sm.Census == nil || sm.Census.Inclusion == nil || sm.Census.Consistency == nil {
		r.failf("%s: sizeMalleability or its census is missing", f)
		return
	}
	if len(sm.Inclusion) == 0 || len(sm.Consistency) == 0 {
		r.failf("%s: sizeMalleability has no inclusion or no consistency exhibits", f)
	}

	for i, e := range sm.Inclusion {
		where := fmt.Sprintf("%s: sizeMalleability.inclusion[%d]", f, i)
		if e.LeafIndex == nil || e.TreeSize == nil || *e.LeafIndex >= *e.TreeSize || *e.TreeSize > censusMaxSize {
			r.failf("%s: leafIndex or treeSize missing or out of range", where)
			continue
		}
		idx, n := *e.LeafIndex, *e.TreeSize
		where = fmt.Sprintf("%s (leaf %d, size %d)", where, idx, n)
		d, err := decodeHash(e.LeafDigest, lowerOnly)
		if err != nil {
			r.failf("%s: leafDigest: %v", where, err)
			continue
		}
		if !bytes.Equal(hasher.HashLeaf(d), t.leafHashes[idx]) {
			r.failf("%s: leafDigest is not leafDigests[%d]", where, idx)
		}
		expectHex(r, where+" root", e.Root, t.roots[n])
		expectRegenerated(r, where+" auditPath", e.AuditPath, func() ([][]byte, error) { return t.inclusionProof(idx, n) })
		path, err := decodeProof(e.AuditPath, lowerOnly)
		if err != nil {
			r.failf("%s: auditPath: %v", where, err)
			continue
		}
		var also []uint64
		for s := uint64(1); s <= censusMaxSize; s++ {
			if proof.VerifyInclusion(hasher, idx, s, t.leafHashes[idx], path, t.roots[n]) == nil && s != n {
				also = append(also, s)
			}
		}
		if proof.VerifyInclusion(hasher, idx, n, t.leafHashes[idx], path, t.roots[n]) != nil {
			r.failf("%s: the honest audit path does not verify at its own size", where)
		}
		if !slices.Equal(also, e.AlsoVerifiesUnderTreeSize) {
			r.failf("%s: alsoVerifiesUnderTreeSize %v, the stock library accepts %v", where, e.AlsoVerifiesUnderTreeSize, also)
		}
	}

	for i, e := range sm.Consistency {
		where := fmt.Sprintf("%s: sizeMalleability.consistency[%d]", f, i)
		if e.First == nil || e.Second == nil || *e.First == 0 || *e.First >= *e.Second || *e.Second > censusMaxSize {
			r.failf("%s: first or second missing or out of range", where)
			continue
		}
		m, n := *e.First, *e.Second
		where = fmt.Sprintf("%s (%d, %d)", where, m, n)
		expectHex(r, where+" firstRoot", e.FirstRoot, t.roots[m])
		expectHex(r, where+" secondRoot", e.SecondRoot, t.roots[n])
		expectRegenerated(r, where+" proof", e.Proof, func() ([][]byte, error) { return t.consistencyProof(m, n) })
		p, err := decodeProof(e.Proof, lowerOnly)
		if err != nil {
			r.failf("%s: proof: %v", where, err)
			continue
		}
		var also []uint64
		for s := uint64(1); s <= censusMaxSize; s++ {
			if s != n && proof.VerifyConsistency(hasher, m, s, p, t.roots[m], t.roots[n]) == nil {
				also = append(also, s)
			}
		}
		if proof.VerifyConsistency(hasher, m, n, p, t.roots[m], t.roots[n]) != nil {
			r.failf("%s: the honest proof does not verify at its own sizes", where)
		}
		if !slices.Equal(also, e.AlsoVerifiesUnderSecond) {
			r.failf("%s: alsoVerifiesUnderSecond %v, the stock library accepts %v", where, e.AlsoVerifiesUnderSecond, also)
		}
	}

	cs, err := t.census()
	if err != nil {
		r.failf("%s: census: %v", f, err)
		return
	}
	c := sm.Census
	expectCount(r, "census.inclusion.proofs", c.Inclusion.Proofs, cs.inclProofs)
	expectCount(r, "census.inclusion.verifyUnderAnotherTreeSize", c.Inclusion.VerifyUnderAnotherTreeSize, cs.inclOther)
	expectCount(r, "census.consistency.proofs", c.Consistency.Proofs, cs.consProofs)
	expectCount(r, "census.consistency.verifyUnderAnotherSecondSize", c.Consistency.VerifyUnderAnotherSecondSize, cs.consOtherSecond)
	expectCount(r, "census.consistency.verifyUnderAnotherFirstSize", c.Consistency.VerifyUnderAnotherFirstSize, cs.consOtherFirst)

	if len(r.failures) == before {
		r.notef("%s: sizeMalleability %d inclusion and %d consistency exhibits exact; census recomputed and equal (inclusion %d/%d under another size; consistency %d/%d under another second, %d under another first)",
			f, len(sm.Inclusion), len(sm.Consistency), cs.inclOther, cs.inclProofs, cs.consOtherSecond, cs.consProofs, cs.consOtherFirst)
	}
}

// censusCounts are sizeMalleability's census, as the library counts it.
type censusCounts struct {
	inclProofs, inclOther                       int
	consProofs, consOtherSecond, consOtherFirst int
}

// censusCache holds the census of each tree it has been computed for, keyed
// by the root of its first censusMaxSize leaves, which fixes those leaves. The
// census is most of a gate run's work, and the tests run the gate a few
// hundred times on the same leaves.
var censusCache sync.Map

// census counts, over every honest proof with second size <= 64, the proofs
// that the library also accepts under another claimed size.
func (t *tree) census() (censusCounts, error) {
	key := string(t.roots[censusMaxSize])
	if c, ok := censusCache.Load(key); ok {
		return c.(censusCounts), nil
	}
	var c censusCounts
	for n := uint64(1); n <= censusMaxSize; n++ {
		for idx := uint64(0); idx < n; idx++ {
			path, err := t.inclusionProof(idx, n)
			if err != nil {
				return c, fmt.Errorf("inclusion proof (%d, %d): %v", idx, n, err)
			}
			c.inclProofs++
			for s := uint64(1); s <= censusMaxSize; s++ {
				if s != n && proof.VerifyInclusion(hasher, idx, s, t.leafHashes[idx], path, t.roots[n]) == nil {
					c.inclOther++
					break
				}
			}
		}
	}
	for n := uint64(2); n <= censusMaxSize; n++ {
		for m := uint64(1); m < n; m++ {
			p, err := t.consistencyProof(m, n)
			if err != nil {
				return c, fmt.Errorf("consistency proof (%d, %d): %v", m, n, err)
			}
			c.consProofs++
			for s := uint64(1); s <= censusMaxSize; s++ {
				if s != n && proof.VerifyConsistency(hasher, m, s, p, t.roots[m], t.roots[n]) == nil {
					c.consOtherSecond++
					break
				}
			}
			for s := uint64(1); s <= censusMaxSize; s++ {
				if s != m && proof.VerifyConsistency(hasher, s, n, p, t.roots[m], t.roots[n]) == nil {
					c.consOtherFirst++
					break
				}
			}
		}
	}
	censusCache.Store(key, c)
	return c, nil
}

// ---- helpers

// leafRule says whether a list of leaf digests follows the stated derivation.
type leafRule int

const (
	// derived leaves are leafDigests[i] = SHA-256(UTF-8("tzun-merkle-vector-" + i)).
	derived leafRule = iota
	// arbitrary leaves are any digests, such as a distinctness vector's
	// repeated last leaf.
	arbitrary
)

// decodeLeaves reads leaf digests and, for derived leaves, checks each
// against the stated derivation.
func decodeLeaves(r *report, where string, raws []json.RawMessage, rule leafRule) ([][]byte, bool) {
	if len(raws) == 0 {
		r.failf("%s: no leaf digests", where)
		return nil, false
	}
	out := make([][]byte, len(raws))
	ok := true
	for i, raw := range raws {
		d, err := decodeHash(raw, lowerOnly)
		if err != nil {
			r.failf("%s[%d]: %v", where, i, err)
			ok = false
			continue
		}
		want := sha256.Sum256([]byte(fmt.Sprintf("tzun-merkle-vector-%d", i)))
		if rule == derived && !bytes.Equal(d, want[:]) {
			r.failf("%s[%d]: is not SHA-256(\"tzun-merkle-vector-%d\")", where, i, i)
			ok = false
		}
		out[i] = d
	}
	return out, ok
}

// expectHex compares a vector's hash with the stock library's value, as the
// exact lowercase string.
func expectHex(r *report, what string, raw json.RawMessage, want []byte) {
	if _, err := decodeHash(raw, lowerOnly); err != nil {
		r.failf("%s: %v", what, err)
		return
	}
	var got string
	_ = json.Unmarshal(raw, &got)
	if got != hex.EncodeToString(want) {
		r.failf("%s is %s, the stock library computes %x", what, got, want)
	}
}

// expectRegenerated compares a vector's proof with the one the stock library
// generates, element by element, as exact lowercase strings.
func expectRegenerated(r *report, what string, raw json.RawMessage, gen func() ([][]byte, error)) {
	want, err := proofStrings(raw)
	if err != nil {
		r.failf("%s: %v", what, err)
		return
	}
	got, err := gen()
	if err != nil {
		r.failf("%s: the stock library cannot generate it: %v", what, err)
		return
	}
	gotHex := make([]string, len(got))
	for i, g := range got {
		gotHex[i] = hex.EncodeToString(g)
	}
	if !slices.Equal(gotHex, want) {
		r.failf("%s differs from the stock library's: vector %v, library %v", what, want, gotHex)
	}
}

func expectCount(r *report, what string, stated *int, computed int) {
	if stated == nil {
		r.failf("%s: sizeMalleability.%s missing", consistencyFile, what)
	} else if *stated != computed {
		r.failf("%s: sizeMalleability.%s is %d, the stock library counts %d", consistencyFile, what, *stated, computed)
	}
}

func describePair(p *derivedFrom) string {
	if p == nil || p.First == nil || p.Second == nil {
		return "(no derivedFrom)"
	}
	return fmt.Sprintf("(%d, %d)", *p.First, *p.Second)
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
