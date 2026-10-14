package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
)

const anchorE2EFile = "anchor-e2e-vectors.json"

// anchorE2EVectors is anchor-e2e-vectors.json (tzun-anchor/1 §13): records anchored end to end on anvil by the SDK's anchor
// scheduler. This module checks the Merkle half with the stock libraries:
// every checkpoint body is read by transparency-dev/formats, and every
// inclusion and consistency proof is verified by transparency-dev/merkle,
// with sizes and roots taken from the parsed bodies. The EVM half (the
// header, the transactions-trie proof, the signed transaction and its
// calldata P) is checked with go-ethereum by the module in evm/, which the
// Makefile runs beside this one.
type anchorE2EVectors struct {
	Description  json.RawMessage `json:"description"`
	Source       json.RawMessage `json:"source"`
	Format       json.RawMessage `json:"format"`
	Chain        *string         `json:"chain"`
	AnchorOrigin *string         `json:"anchorOrigin"`
	// manifest, headerSource and each epoch's publication and canonicalBlock
	// are the EVM half's (evm/).
	Manifest     json.RawMessage `json:"manifest"`
	HeaderSource json.RawMessage `json:"headerSource"`
	Epochs       []e2eEpoch      `json:"epochs"`
	Records      []e2eRecord     `json:"records"`
}

type e2eEpoch struct {
	AnchorCheckpoint       *string         `json:"anchorCheckpoint"`
	P                      json.RawMessage `json:"p"`
	PreviousAnchorSize     *uint64         `json:"previousAnchorSize"`
	AnchorConsistencyProof json.RawMessage `json:"anchorConsistencyProof"`
	Members                []struct {
		LogCheckpoint         *string         `json:"logCheckpoint"`
		AnchorLeafIndex       *uint64         `json:"anchorLeafIndex"`
		PreviousLogCheckpoint *string         `json:"previousLogCheckpoint"`
		ConsistencyProof      json.RawMessage `json:"consistencyProof"`
	} `json:"members"`
	Publication    json.RawMessage `json:"publication"`
	CanonicalBlock json.RawMessage `json:"canonicalBlock"`
}

type e2eRecord struct {
	Case     string `json:"case"`
	ChainID  string `json:"chainId"`
	Epoch    *int   `json:"epoch"`
	Envelope struct {
		EnvelopeVersion json.RawMessage `json:"envelopeVersion"`
		// The payload is Tzun's canonical JSON, which no stock library
		// implements: the TypeScript and Python suites recompute the digest
		// from it. Only its sequence number is read here.
		Payload   json.RawMessage `json:"payload"`
		Integrity struct {
			CanonicalDigest json.RawMessage `json:"canonicalDigest"`
			ChainLink       json.RawMessage `json:"chainLink"`
		} `json:"integrity"`
		NonRepudiation struct {
			Anchor *struct {
				AnchorSpec       *string         `json:"anchorSpec"`
				MerkleSpec       *string         `json:"merkleSpec"`
				LeafIndex        *uint64         `json:"leafIndex"`
				LogCheckpoint    *string         `json:"logCheckpoint"`
				LogPath          json.RawMessage `json:"logPath"`
				AnchorLeafIndex  *uint64         `json:"anchorLeafIndex"`
				AnchorCheckpoint *string         `json:"anchorCheckpoint"`
				AnchorPath       json.RawMessage `json:"anchorPath"`
				Publications     json.RawMessage `json:"publications"`
			} `json:"anchor"`
		} `json:"nonRepudiation"`
		CustodyChain      json.RawMessage `json:"custodyChain"`
		AttestationStatus json.RawMessage `json:"attestationStatus"`
	} `json:"envelope"`
	// The verdicts the TypeScript verifier is held to
	// (tests/ts/anchor-e2e-vectors.test.ts).
	Expect json.RawMessage `json:"expect"`
}

// parsedBody is a checkpoint body as the stock parser reads it.
type parsedBody struct {
	origin string
	size   uint64
	root   []byte
}

// parseBody reads a body with transparency-dev/formats and refuses extension
// data, which Tzun never writes.
func parseBody(body *string) (parsedBody, error) {
	if body == nil {
		return parsedBody{}, fmt.Errorf("missing")
	}
	var c log.Checkpoint
	rest, err := c.Unmarshal([]byte(*body))
	if err != nil {
		return parsedBody{}, fmt.Errorf("the stock parser refuses it: %v", err)
	}
	if len(rest) != 0 {
		return parsedBody{}, fmt.Errorf("the stock parser reads extension data %q after it", clip(string(rest)))
	}
	return parsedBody{origin: c.Origin, size: c.Size, root: c.Hash}, nil
}

// checkConsistency verifies PROOF(first, second) between two parsed bodies of
// one origin with the stock library, taking both sizes and roots from the
// bodies (tzun-anchor/1 §10.8).
func checkConsistency(r *report, where string, first, second parsedBody, raw json.RawMessage) bool {
	if first.origin != second.origin {
		r.failf("%s: the two bodies name %q and %q", where, first.origin, second.origin)
		return false
	}
	p, err := decodeProof(raw, lowerOnly)
	if err != nil {
		r.failf("%s: %v", where, err)
		return false
	}
	if err := proof.VerifyConsistency(hasher, first.size, second.size, p, first.root, second.root); err != nil {
		r.failf("%s: the stock library refuses PROOF(%d, %d): %v", where, first.size, second.size, err)
		return false
	}
	return true
}

func checkAnchorE2EFile(r *report, v *anchorE2EVectors) {
	const f = anchorE2EFile
	before := len(r.failures)
	if v.AnchorOrigin == nil || !strings.HasSuffix(*v.AnchorOrigin, "/anchors") {
		r.failf("%s: anchorOrigin missing or not an anchor log origin", f)
		return
	}
	if len(v.Epochs) == 0 || len(v.Records) == 0 {
		r.failf("%s: no epochs or no records", f)
		return
	}

	// Each epoch: the anchor checkpoint reads back, P is its SHA-256, and its
	// consistency with the previous published size verifies; each member log
	// checkpoint reads back, and its consistency with that log's previous
	// anchored checkpoint verifies.
	anchors := make([]parsedBody, len(v.Epochs))
	consistency, members := 0, 0
	for ei := range v.Epochs {
		e := &v.Epochs[ei]
		ew := fmt.Sprintf("%s: epochs[%d]", f, ei)
		a, err := parseBody(e.AnchorCheckpoint)
		if err != nil {
			r.failf("%s anchorCheckpoint: %v", ew, err)
			continue
		}
		anchors[ei] = a
		if a.origin != *v.AnchorOrigin {
			r.failf("%s anchorCheckpoint: origin %q, not the file's anchorOrigin", ew, a.origin)
		}
		expectHex(r, ew+" p", e.P, sha256Of(*e.AnchorCheckpoint))
		switch {
		case ei == 0 && e.PreviousAnchorSize == nil:
		case ei > 0 && e.PreviousAnchorSize != nil && anchors[ei-1].size == *e.PreviousAnchorSize && anchors[ei-1].root != nil:
			if checkConsistency(r, ew+" anchorConsistencyProof", anchors[ei-1], a, e.AnchorConsistencyProof) {
				consistency++
			}
		default:
			r.failf("%s: previousAnchorSize is not the previous epoch's anchor size", ew)
		}
		for mi, m := range e.Members {
			mw := fmt.Sprintf("%s members[%d]", ew, mi)
			body, err := parseBody(m.LogCheckpoint)
			if err != nil {
				r.failf("%s logCheckpoint: %v", mw, err)
				continue
			}
			members++
			if m.AnchorLeafIndex == nil || *m.AnchorLeafIndex >= a.size {
				r.failf("%s: anchorLeafIndex missing or not below the anchor size %d", mw, a.size)
			}
			if m.PreviousLogCheckpoint == nil {
				continue
			}
			prev, err := parseBody(m.PreviousLogCheckpoint)
			if err != nil {
				r.failf("%s previousLogCheckpoint: %v", mw, err)
				continue
			}
			if checkConsistency(r, mw+" consistencyProof", prev, body, m.ConsistencyProof) {
				consistency++
			}
		}
	}

	// Each record: its digest at leafIndex = sequenceNumber - 1 in its log
	// checkpoint, and that checkpoint's SHA-256 at anchorLeafIndex in its
	// epoch's anchor checkpoint, both by proof.VerifyInclusion.
	proven := 0
	for i, rec := range v.Records {
		w := fmt.Sprintf("%s: records[%d] %q", f, i, rec.Case)
		a := rec.Envelope.NonRepudiation.Anchor
		if a == nil || a.LeafIndex == nil || a.AnchorLeafIndex == nil {
			r.failf("%s: nonRepudiation.anchor, its leafIndex or its anchorLeafIndex missing", w)
			continue
		}
		if rec.Epoch == nil || *rec.Epoch < 0 || *rec.Epoch >= len(v.Epochs) || v.Epochs[*rec.Epoch].AnchorCheckpoint == nil {
			r.failf("%s: epoch missing or out of range", w)
			continue
		}
		if a.AnchorCheckpoint == nil || *a.AnchorCheckpoint != *v.Epochs[*rec.Epoch].AnchorCheckpoint {
			r.failf("%s: the anchor's anchorCheckpoint is not its epoch's", w)
			continue
		}
		var payload struct {
			SequenceNumber *uint64 `json:"sequenceNumber"`
		}
		if err := json.Unmarshal(rec.Envelope.Payload, &payload); err != nil || payload.SequenceNumber == nil || *payload.SequenceNumber < 1 {
			r.failf("%s: payload.sequenceNumber missing or not a positive integer", w)
			continue
		}
		if *a.LeafIndex != *payload.SequenceNumber-1 {
			r.failf("%s: leafIndex %d is not sequenceNumber - 1 (%d)", w, *a.LeafIndex, *payload.SequenceNumber-1)
		}
		digest, err := decodeHash(rec.Envelope.Integrity.CanonicalDigest, lowerOnly)
		if err != nil {
			r.failf("%s: integrity.canonicalDigest: %v", w, err)
			continue
		}
		logBody, err := parseBody(a.LogCheckpoint)
		if err != nil {
			r.failf("%s logCheckpoint: %v", w, err)
			continue
		}
		anchorBody, err := parseBody(a.AnchorCheckpoint)
		if err != nil {
			r.failf("%s anchorCheckpoint: %v", w, err)
			continue
		}
		ok := true
		logPath, err := decodeProof(a.LogPath, lowerOnly)
		if err == nil {
			err = proof.VerifyInclusion(hasher, *a.LeafIndex, logBody.size, hasher.HashLeaf(digest), logPath, logBody.root)
		}
		if err != nil {
			r.failf("%s logPath: the stock library does not place the canonicalDigest at %d in %s: %v", w, *a.LeafIndex, logBody.origin, err)
			ok = false
		}
		anchorPath, err := decodeProof(a.AnchorPath, lowerOnly)
		if err == nil {
			err = proof.VerifyInclusion(hasher, *a.AnchorLeafIndex, anchorBody.size, hasher.HashLeaf(sha256Of(*a.LogCheckpoint)), anchorPath, anchorBody.root)
		}
		if err != nil {
			r.failf("%s anchorPath: the stock library does not place SHA-256(logCheckpoint) at %d in the anchor log: %v", w, *a.AnchorLeafIndex, err)
			ok = false
		}
		if ok {
			proven++
		}
	}

	if len(r.failures) == before {
		r.notef("%s: %d epochs: every anchor checkpoint and %d member checkpoints read back by the stock parser, P the SHA-256 of each anchor checkpoint, %d consistency proofs verify with sizes and roots from the bodies", f, len(v.Epochs), members, consistency)
		r.notef("%s: %d records: canonicalDigest at sequenceNumber - 1 in its log checkpoint and SHA-256(logCheckpoint) in its anchor checkpoint, both verified by the stock library", f, proven)
		r.notef("%s: outside this module's scope: the publications' EVM material (checked with go-ethereum by evm/) and the canonical JSON of each payload", f)
	}
}
