package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
)

const checkpointFile = "checkpoint-vectors.json"

// checkpointVectors is checkpoint-vectors.json (tzun-anchor/1 §4 to §6,
// Anchor §13). The gate reads every checkpoint body in bodies and anchorLog
// with the stock parser, transparency-dev/formats log.Checkpoint.Unmarshal,
// and builds the anchor log's trees with transparency-dev/merkle.
//
// chainSegments, domain and artifacts hold Tzun's own rules: the chain
// segment, the origin binding of step 2b, and the steps of §10.3 over record
// artifacts. No stock library implements them, so the gate reads those
// sections only for the exact-key check; the TypeScript suite holds the SDK
// to them.
type checkpointVectors struct {
	Description json.RawMessage `json:"description"`
	Source      json.RawMessage `json:"source"`
	Format      json.RawMessage `json:"format"`
	Bodies      *struct {
		Valid     []validBody       `json:"valid"`
		Invalid   []invalidBody     `json:"invalid"`
		NonString []json.RawMessage `json:"nonString"`
	} `json:"bodies"`
	ChainSegments json.RawMessage   `json:"chainSegments"`
	Domain        json.RawMessage   `json:"domain"`
	AnchorLog     *anchorLogVectors `json:"anchorLog"`
	Artifacts     json.RawMessage   `json:"artifacts"`
}

// validBody is a body the stock parser must read back to its stated origin,
// size and root, and whose SHA-256 is its stated checkpointDigest.
type validBody struct {
	Case             string          `json:"case"`
	Origin           *string         `json:"origin"`
	Size             *uint64         `json:"size"`
	Root             json.RawMessage `json:"root"`
	Body             *string         `json:"body"`
	CheckpointDigest json.RawMessage `json:"checkpointDigest"`
}

// invalidBody is a body Tzun refuses. stockParserAccepts states what the
// stock parser makes of it, and the gate runs the parser to check that.
// c2spConforming is a reading of the C2SP text, which no library gives; the
// gate requires only that it is stated.
type invalidBody struct {
	Case               string  `json:"case"`
	Body               *string `json:"body"`
	C2spConforming     *bool   `json:"c2spConforming"`
	StockParserAccepts *bool   `json:"stockParserAccepts"`
}

type anchorLogVectors struct {
	DomainPrefix json.RawMessage `json:"domainPrefix"`
	SourceLogs   map[string]struct {
		Key    string            `json:"key"`
		Leaves []json.RawMessage `json:"leaves"`
	} `json:"sourceLogs"`
	Epochs []struct {
		Epoch   string `json:"epoch"`
		Members []struct {
			validBody
			AnchorLeafIndex *uint64 `json:"anchorLeafIndex"`
		} `json:"members"`
		AnchorOrigin     *string         `json:"anchorOrigin"`
		AnchorSize       *uint64         `json:"anchorSize"`
		AnchorRoot       json.RawMessage `json:"anchorRoot"`
		AnchorCheckpoint *string         `json:"anchorCheckpoint"`
		P                json.RawMessage `json:"p"`
	} `json:"epochs"`
	AnchorLeaves      []json.RawMessage `json:"anchorLeaves"`
	AnchorConsistency *pairCase         `json:"anchorConsistency"`
}

func checkCheckpointFile(r *report, v *checkpointVectors) {
	const f = checkpointFile
	if v.Bodies == nil {
		r.failf("%s: bodies missing", f)
	} else {
		checkValidBodies(r, v.Bodies.Valid)
		checkInvalidBodies(r, v.Bodies.Invalid)
		checkNonStringBodies(r, v.Bodies.NonString)
	}
	checkAnchorLog(r, v.AnchorLog)
	r.notef("%s: outside a stock library's scope chainSegments, domain, artifacts (Tzun's origin rules and the steps of §10.3)", f)
}

// readBody runs the stock parser over a valid body and compares what it reads
// with the stated origin, size and root, and the body's SHA-256 with its
// stated checkpointDigest. It returns the root the parser read.
func readBody(r *report, where string, b *validBody) ([]byte, bool) {
	before := len(r.failures)
	if b.Body == nil || b.Origin == nil || b.Size == nil {
		r.failf("%s: body, origin or size missing", where)
		return nil, false
	}
	root, err := decodeHash(b.Root, lowerOnly)
	if err != nil {
		r.failf("%s: root: %v", where, err)
		return nil, false
	}
	var c log.Checkpoint
	rest, err := c.Unmarshal([]byte(*b.Body))
	if err != nil {
		r.failf("%s: the stock parser refuses the body: %v", where, err)
		return nil, false
	}
	if len(rest) != 0 {
		r.failf("%s: the stock parser reads extension data %q after the body", where, clip(string(rest)))
	}
	if c.Origin != *b.Origin {
		r.failf("%s: origin is %q, the stock parser reads %q", where, *b.Origin, c.Origin)
	}
	if c.Size != *b.Size {
		r.failf("%s: size is %d, the stock parser reads %d", where, *b.Size, c.Size)
	}
	if !bytes.Equal(c.Hash, root) {
		r.failf("%s: root is %x, the stock parser reads %x", where, root, c.Hash)
	}
	digest := sha256.Sum256([]byte(*b.Body))
	expectHex(r, where+" checkpointDigest", b.CheckpointDigest, digest[:])
	return root, len(r.failures) == before
}

func checkValidBodies(r *report, bodies []validBody) {
	const f = checkpointFile
	if len(bodies) == 0 {
		r.failf("%s: bodies.valid is empty", f)
		return
	}
	read := 0
	for i := range bodies {
		if _, ok := readBody(r, fmt.Sprintf("%s: bodies.valid[%d] %q", f, i, bodies[i].Case), &bodies[i]); ok {
			read++
		}
	}
	r.notef("%s: bodies.valid %d/%d read back by the stock parser to their origin, size and root, and hash to their checkpointDigest", f, read, len(bodies))
}

func checkInvalidBodies(r *report, bodies []invalidBody) {
	const f = checkpointFile
	if len(bodies) == 0 {
		r.failf("%s: bodies.invalid is empty", f)
		return
	}
	agree, accepted := 0, 0
	for i, b := range bodies {
		where := fmt.Sprintf("%s: bodies.invalid[%d] %q", f, i, b.Case)
		if b.Body == nil || b.StockParserAccepts == nil || b.C2spConforming == nil {
			r.failf("%s: body, stockParserAccepts or c2spConforming missing", where)
			continue
		}
		var c log.Checkpoint
		_, err := c.Unmarshal([]byte(*b.Body))
		if err == nil {
			accepted++
		}
		switch {
		case *b.StockParserAccepts && err != nil:
			r.failf("%s: stockParserAccepts is true, the stock parser refuses it: %v", where, err)
		case !*b.StockParserAccepts && err == nil:
			r.failf("%s: stockParserAccepts is false, the stock parser accepts it (origin %q, size %d, %d-byte root)", where, clip(c.Origin), c.Size, len(c.Hash))
		default:
			agree++
		}
	}
	r.notef("%s: bodies.invalid %d/%d stockParserAccepts flags are the stock parser's (it accepts %d, refuses %d)", f, agree, len(bodies), accepted, len(bodies)-accepted)
}

func checkNonStringBodies(r *report, entries []json.RawMessage) {
	const f = checkpointFile
	if len(entries) == 0 {
		r.failf("%s: bodies.nonString is empty", f)
		return
	}
	for i, raw := range entries {
		if len(raw) == 0 || raw[0] == '"' {
			r.failf("%s: bodies.nonString[%d] is a string: %s", f, i, clip(string(raw)))
		}
	}
	r.notef("%s: bodies.nonString %d entries, none a string, so none is a body a parser of bytes could read", f, len(entries))
}

// checkAnchorLog rebuilds the anchor log of anchorLog with the stock libraries:
// every member checkpoint and every anchor checkpoint is read by the stock
// parser, each member's root is the stock root of its source log at its size,
// each anchor root is the stock root of anchorLeaves at the anchor size, P is
// the SHA-256 of the anchor checkpoint, and the consistency proof between the
// two anchor sizes verifies and regenerates byte for byte.
func checkAnchorLog(r *report, a *anchorLogVectors) {
	const f = checkpointFile
	before := len(r.failures)
	if a == nil {
		r.failf("%s: anchorLog missing", f)
		return
	}
	if len(a.Epochs) == 0 {
		r.failf("%s: anchorLog.epochs is empty", f)
		return
	}
	leaves, ok := decodeLeaves(r, f+": anchorLog.anchorLeaves", a.AnchorLeaves, arbitrary)
	if !ok {
		return
	}
	anchorTree, err := newTree(leaves)
	if err != nil {
		r.failf("%s: anchorLog.anchorLeaves: %v", f, err)
		return
	}

	sources := map[string]*tree{}
	origins := make([]string, 0, len(a.SourceLogs))
	for origin := range a.SourceLogs {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	for _, origin := range origins {
		where := fmt.Sprintf("%s: anchorLog.sourceLogs[%q]", f, origin)
		ls, ok := decodeLeaves(r, where+".leaves", a.SourceLogs[origin].Leaves, arbitrary)
		if !ok {
			continue
		}
		t, err := newTree(ls)
		if err != nil {
			r.failf("%s: %v", where, err)
			continue
		}
		sources[origin] = t
	}

	members, prevSize := 0, uint64(0)
	var sizes []uint64
	for ei, e := range a.Epochs {
		ew := fmt.Sprintf("%s: anchorLog.epochs[%d] %q", f, ei, e.Epoch)
		if e.AnchorSize == nil || *e.AnchorSize <= prevSize || *e.AnchorSize > anchorTree.size() {
			r.failf("%s: anchorSize missing, not above the previous epoch's %d, or beyond the %d anchorLeaves", ew, prevSize, anchorTree.size())
			continue
		}
		size := *e.AnchorSize
		if uint64(len(e.Members)) != size-prevSize {
			r.failf("%s: %d members, but the anchor log grows from %d to %d", ew, len(e.Members), prevSize, size)
		}
		for mi := range e.Members {
			m := &e.Members[mi]
			mw := fmt.Sprintf("%s members[%d] %q", ew, mi, strOr(m.Origin))
			root, ok := readBody(r, mw, &m.validBody)
			members++
			if !ok {
				continue
			}
			if t := sources[*m.Origin]; t == nil {
				r.failf("%s: no source log with this origin in anchorLog.sourceLogs", mw)
			} else if *m.Size > t.size() {
				r.failf("%s: size %d beyond the source log's %d leaves", mw, *m.Size, t.size())
			} else if !bytes.Equal(root, t.roots[*m.Size]) {
				r.failf("%s: root is %x, the stock library computes %x over the source log's first %d leaves", mw, root, t.roots[*m.Size], *m.Size)
			}
			if m.AnchorLeafIndex == nil || *m.AnchorLeafIndex < prevSize || *m.AnchorLeafIndex >= size {
				r.failf("%s: anchorLeafIndex missing or outside this epoch's leaves [%d, %d)", mw, prevSize, size)
				continue
			}
			expectHex(r, fmt.Sprintf("%s: anchorLog.anchorLeaves[%d]", f, *m.AnchorLeafIndex), a.AnchorLeaves[*m.AnchorLeafIndex], sha256Of(*m.Body))
		}
		anchor := validBody{Case: "anchor checkpoint", Origin: e.AnchorOrigin, Size: e.AnchorSize, Root: e.AnchorRoot, Body: e.AnchorCheckpoint, CheckpointDigest: e.P}
		if root, ok := readBody(r, ew+" anchorCheckpoint", &anchor); ok && !bytes.Equal(root, anchorTree.roots[size]) {
			r.failf("%s: anchorRoot is %x, the stock library computes %x over the first %d anchorLeaves", ew, root, anchorTree.roots[size], size)
		}
		sizes = append(sizes, size)
		prevSize = size
	}
	if prevSize != anchorTree.size() {
		r.failf("%s: the last epoch's anchorSize is %d, but there are %d anchorLeaves", f, prevSize, anchorTree.size())
	}

	c := a.AnchorConsistency
	switch {
	case c == nil || c.First == nil || c.Second == nil:
		r.failf("%s: anchorLog.anchorConsistency, or its first or second, missing", f)
	case len(sizes) < 2 || *c.First != sizes[len(sizes)-2] || *c.Second != sizes[len(sizes)-1]:
		r.failf("%s: anchorLog.anchorConsistency is (%d, %d), not between the last two anchor sizes %v", f, *c.First, *c.Second, sizes)
	default:
		cw := fmt.Sprintf("%s: anchorLog.anchorConsistency (%d, %d)", f, *c.First, *c.Second)
		expectHex(r, cw+" firstRoot", c.FirstRoot, anchorTree.roots[*c.First])
		expectHex(r, cw+" secondRoot", c.SecondRoot, anchorTree.roots[*c.Second])
		p, err := decodeProof(c.Proof, lowerOnly)
		if err != nil {
			r.failf("%s: %v", cw, err)
			break
		}
		if err := proof.VerifyConsistency(hasher, *c.First, *c.Second, p, anchorTree.roots[*c.First], anchorTree.roots[*c.Second]); err != nil {
			r.failf("%s: the stock library refuses the proof: %v", cw, err)
		}
		expectRegenerated(r, cw+" proof", c.Proof, func() ([][]byte, error) { return anchorTree.consistencyProof(*c.First, *c.Second) })
	}

	if len(r.failures) == before {
		r.notef("%s: anchorLog %d epochs: %d member checkpoints read back by the stock parser, each root the stock root of its source log; %d anchor checkpoints read back, each root the stock root of anchorLeaves and P its SHA-256; the consistency proof (%s) verifies and regenerates byte for byte",
			f, len(a.Epochs), members, len(a.Epochs), joinSizes(sizes[len(sizes)-2:]))
	}
}

func sha256Of(s string) []byte {
	d := sha256.Sum256([]byte(s))
	return d[:]
}

func strOr(s *string) string {
	if s == nil {
		return "(none)"
	}
	return *s
}

func joinSizes(sizes []uint64) string {
	parts := make([]string, len(sizes))
	for i, s := range sizes {
		parts[i] = fmt.Sprint(s)
	}
	return strings.Join(parts, ", ")
}
