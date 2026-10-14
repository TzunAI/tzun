package main

import (
	"encoding/json"
	"testing"
)

// Anchor §13 in the gate: each deliberate corruption of the anvil end-to-end
// file makes the gate fail with exactly its expected failures. The EVM half
// has its own corruptions in evm/.
func TestCorruptedAnchorE2EVectorsFail(t *testing.T) {
	const f = anchorE2EFile
	record := func(d doc, i int) doc { return arr(d["records"])[i].(doc) }
	anchorOf := func(d doc, i int) doc {
		return record(d, i)["envelope"].(doc)["nonRepudiation"].(doc)["anchor"].(doc)
	}
	epoch := func(d doc, i int) doc { return arr(d["epochs"])[i].(doc) }
	flipFirst := func(v any) {
		l := arr(v)
		l[0] = flipHex(l[0].(string))
	}
	runCorruptions(t, []corruption{
		{"a log path element flipped", f, func(t *testing.T, d doc) {
			flipFirst(anchorOf(d, 1)["logPath"])
		}, []string{`records[1] "alpha #2, epoch 1" logPath: the stock library does not place the canonicalDigest at 1`}},
		{"an anchor path element flipped", f, func(t *testing.T, d doc) {
			flipFirst(anchorOf(d, 3)["anchorPath"])
		}, []string{`records[3] "beta #1, epoch 1" anchorPath: the stock library does not place SHA-256(logCheckpoint) at 1`}},
		{"a canonicalDigest flipped", f, func(t *testing.T, d doc) {
			integrity := record(d, 7)["envelope"].(doc)["integrity"].(doc)
			integrity["canonicalDigest"] = flipHex(integrity["canonicalDigest"].(string))
		}, []string{`records[7] "gamma #1, epoch 2" logPath: the stock library does not place the canonicalDigest at 0`}},
		{"a leafIndex moved off sequenceNumber - 1", f, func(t *testing.T, d doc) {
			anchorOf(d, 0)["leafIndex"] = json.Number("1")
		}, []string{
			`records[0] "alpha #1, epoch 1": leafIndex 1 is not sequenceNumber - 1 (0)`,
			`records[0] "alpha #1, epoch 1" logPath: the stock library does not place the canonicalDigest at 1`,
		}},
		{"P flipped", f, func(t *testing.T, d doc) {
			epoch(d, 0)["p"] = flipHex(epoch(d, 0)["p"].(string))
		}, []string{`epochs[0] p is`}},
		{"the anchor consistency proof flipped", f, func(t *testing.T, d doc) {
			flipFirst(epoch(d, 1)["anchorConsistencyProof"])
		}, []string{`epochs[1] anchorConsistencyProof: the stock library refuses PROOF(2, 4)`}},
		{"a source log's consistency proof flipped", f, func(t *testing.T, d doc) {
			flipFirst(arr(epoch(d, 1)["members"])[0].(doc)["consistencyProof"])
		}, []string{`epochs[1] members[0] consistencyProof: the stock library refuses PROOF(3, 5)`}},
		{"previousAnchorSize not the previous epoch's size", f, func(t *testing.T, d doc) {
			epoch(d, 1)["previousAnchorSize"] = json.Number("1")
		}, []string{`epochs[1]: previousAnchorSize is not the previous epoch's anchor size`}},
		{"a record naming another epoch", f, func(t *testing.T, d doc) {
			record(d, 0)["epoch"] = json.Number("1")
		}, []string{`records[0] "alpha #1, epoch 1": the anchor's anchorCheckpoint is not its epoch's`}},
		{"an unknown member in an anchor", f, func(t *testing.T, d doc) {
			anchorOf(d, 0)["blockchainAnchor"] = doc{}
		}, []string{`records[0].envelope.nonRepudiation.anchor: unknown field "blockchainAnchor"`}},
	})
}
