package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkpoint-vectors.json states each invalid body's stockParserAccepts
// against transparency-dev/formats v0.1.1. Another version may read a body
// differently, so the tests refuse to run against one.
const pinnedFormats = "v0.1.1"

func TestFormatsVersionIsPinned(t *testing.T) {
	if v := moduleVersion(formatsPath); v != pinnedFormats {
		t.Fatalf("%s %s is linked; checkpoint-vectors.json states stockParserAccepts against %s", formatsPath, v, pinnedFormats)
	}
}

// For the checkpoint file, each deliberate corruption makes the gate fail
// with exactly its expected failures.
func TestCorruptedCheckpointVectorsFail(t *testing.T) {
	const f = checkpointFile
	runCorruptions(t, []corruption{
		// bodies.valid: the stock parser's reading is compared with every stated value.
		{"a valid body's stated size changed", f, func(t *testing.T, d doc) {
			findBody(t, d, "valid", "size 1")["size"] = json.Number("2")
		}, []string{`bodies.valid[6] "size 1": size is 2, the stock parser reads 1`}},
		{"a valid body's stated origin changed", f, func(t *testing.T, d doc) {
			b := findBody(t, d, "valid", "SDK anchor log")
			b["origin"] = strings.TrimSuffix(b["origin"].(string), "anchors") + "anchor"
		}, []string{`bodies.valid[3] "SDK anchor log": origin is "local.invalid/25ac38d72cae99471b7346254f28ce88/anchor", the stock parser reads "local.invalid/25ac38d72cae99471b7346254f28ce88/anchors"`}},
		{"a valid body's stated root flipped", f, func(t *testing.T, d doc) {
			b := findBody(t, d, "valid", "root of all zero bytes")
			b["root"] = flipHex(b["root"].(string))
		}, []string{`bodies.valid[8] "root of all zero bytes": root is ` + strings.Repeat("0", 63) + "1, the stock parser reads " + strings.Repeat("0", 64)}},
		{"a valid body's stated root in uppercase", f, func(t *testing.T, d doc) {
			b := findBody(t, d, "valid", "root of all 0xff bytes (base64 uses \"/\")")
			b["root"] = strings.ToUpper(b["root"].(string))
		}, []string{`bodies.valid[9] "root of all 0xff bytes (base64 uses \"/\")": root: uppercase hex digit`}},
		{"a valid body's checkpointDigest flipped", f, func(t *testing.T, d doc) {
			b := findBody(t, d, "valid", "test namespace")
			b["checkpointDigest"] = flipHex(b["checkpointDigest"].(string))
		}, []string{`bodies.valid[4] "test namespace" checkpointDigest is`}},
		{"a valid body the stock parser refuses", f, func(t *testing.T, d doc) {
			b := findBody(t, d, "valid", "size 2^53 - 1")
			b["body"] = strings.TrimSuffix(b["body"].(string), "\n")
			b["body"] = strings.Replace(b["body"].(string), "\n", " ", 1)
		}, []string{`bodies.valid[7] "size 2^53 - 1": the stock parser refuses the body: invalid checkpoint - too few newlines`}},
		{"a valid body with an extension line", f, func(t *testing.T, d doc) {
			b := findBody(t, d, "valid", "platform opaque log")
			b["body"] = b["body"].(string) + "ext\n"
		}, []string{`bodies.valid[5] "platform opaque log": the stock parser reads extension data "ext\n" after the body`, `bodies.valid[5] "platform opaque log" checkpointDigest is`}},
		{"a valid body without its size", f, func(t *testing.T, d doc) {
			delete(findBody(t, d, "valid", "size 1"), "size")
		}, []string{`bodies.valid[6] "size 1": body, origin or size missing`}},
		{"bodies.valid emptied", f, func(t *testing.T, d doc) {
			d["bodies"].(doc)["valid"] = []any{}
		}, []string{"bodies.valid is empty"}},

		// bodies.invalid: stockParserAccepts is the stock parser's verdict.
		{"an accepted body marked refused", f, func(t *testing.T, d doc) {
			findBody(t, d, "invalid", "a CR at the end of the root line")["stockParserAccepts"] = false
		}, []string{`bodies.invalid[3] "a CR at the end of the root line": stockParserAccepts is false, the stock parser accepts it`}},
		{"a refused body marked accepted", f, func(t *testing.T, d doc) {
			findBody(t, d, "invalid", "size 2^64")["stockParserAccepts"] = true
		}, []string{`bodies.invalid[18] "size 2^64": stockParserAccepts is true, the stock parser refuses it: invalid checkpoint - size invalid`}},
		{"a refused body marked accepted, the base64 case", f, func(t *testing.T, d doc) {
			findBody(t, d, "invalid", "base64url alphabet")["stockParserAccepts"] = true
		}, []string{`bodies.invalid[26] "base64url alphabet": stockParserAccepts is true, the stock parser refuses it: invalid checkpoint - invalid hash`}},
		{"an invalid body changed so the stock parser reads it differently", f, func(t *testing.T, d doc) {
			// "no final newline" has three LFs once one is added: the parser accepts it.
			b := findBody(t, d, "invalid", "no final newline")
			b["body"] = b["body"].(string) + "\n"
		}, []string{`bodies.invalid[2] "no final newline": stockParserAccepts is false, the stock parser accepts it`}},
		{"stockParserAccepts missing", f, func(t *testing.T, d doc) {
			delete(findBody(t, d, "invalid", "empty body"), "stockParserAccepts")
		}, []string{`bodies.invalid[7] "empty body": body, stockParserAccepts or c2spConforming missing`}},
		{"c2spConforming missing", f, func(t *testing.T, d doc) {
			delete(findBody(t, d, "invalid", "empty body"), "c2spConforming")
		}, []string{`bodies.invalid[7] "empty body": body, stockParserAccepts or c2spConforming missing`}},
		{"stockParserAccepts that is not a boolean", f, func(t *testing.T, d doc) {
			findBody(t, d, "invalid", "empty body")["stockParserAccepts"] = "false"
		}, []string{"checkpoint-vectors.json: json: cannot unmarshal string into Go struct field"}},
		{"bodies.invalid emptied", f, func(t *testing.T, d doc) {
			d["bodies"].(doc)["invalid"] = []any{}
		}, []string{"bodies.invalid is empty"}},

		// bodies.nonString
		{"a string among the non-strings", f, func(t *testing.T, d doc) {
			b := d["bodies"].(doc)
			b["nonString"] = append(arr(b["nonString"]), "local.invalid/x/anchors\n1\nAAAA\n")
		}, []string{"bodies.nonString[4] is a string"}},

		// anchorLog: rebuilt with the stock libraries.
		{"a member checkpoint's root flipped in its body", f, func(t *testing.T, d doc) {
			m := member(d, 0, 1)
			m["root"] = flipHex(m["root"].(string))
		}, []string{`epochs[0] "E1" members[1]`, `root is`}},
		{"a member's stated size that its body does not carry", f, func(t *testing.T, d doc) {
			member(d, 1, 1)["size"] = json.Number("3")
		}, []string{`epochs[1] "E2" members[1] "local.invalid/25ac38d72cae99471b7346254f28ce88/k2": size is 3, the stock parser reads 2`}},
		{"a member checkpoint beyond its source log", f, func(t *testing.T, d doc) {
			// A body that reads back as stated, at a size the source log does not reach.
			m := member(d, 1, 1)
			body := strings.Replace(m["body"].(string), "\n2\n", "\n3\n", 1)
			m["body"], m["size"], m["checkpointDigest"] = body, json.Number("3"), hexOf(sha256Of(body))
		}, []string{
			`epochs[1] "E2" members[1] "local.invalid/25ac38d72cae99471b7346254f28ce88/k2": size 3 beyond the source log's 2 leaves`,
			"anchorLog.anchorLeaves[4] is",
		}},
		{"an epoch whose anchor log does not grow", f, func(t *testing.T, d doc) {
			epoch(d, 1)["anchorSize"] = json.Number("3")
		}, []string{
			`epochs[1] "E2": anchorSize missing, not above the previous epoch's 3, or beyond the 5 anchorLeaves`,
			"the last epoch's anchorSize is 3, but there are 5 anchorLeaves",
			"anchorLog.anchorConsistency is (3, 5), not between the last two anchor sizes [3]",
		}},
		{"an anchor leaf past the last epoch", f, func(t *testing.T, d doc) {
			a := d["anchorLog"].(doc)
			l := arr(a["anchorLeaves"])
			a["anchorLeaves"] = append(l, l[0])
		}, []string{"the last epoch's anchorSize is 5, but there are 6 anchorLeaves"}},
		{"the consistency proof's firstRoot flipped", f, func(t *testing.T, d doc) {
			c := d["anchorLog"].(doc)["anchorConsistency"].(doc)
			c["firstRoot"] = flipHex(c["firstRoot"].(string))
		}, []string{"anchorLog.anchorConsistency (3, 5) firstRoot is"}},
		{"the consistency proof's secondRoot flipped", f, func(t *testing.T, d doc) {
			c := d["anchorLog"].(doc)["anchorConsistency"].(doc)
			c["secondRoot"] = flipHex(c["secondRoot"].(string))
		}, []string{"anchorLog.anchorConsistency (3, 5) secondRoot is"}},
		{"a source-log leaf changed", f, func(t *testing.T, d doc) {
			sl := d["anchorLog"].(doc)["sourceLogs"].(doc)["local.invalid/25ac38d72cae99471b7346254f28ce88/evidence/736f6c6f"].(doc)
			l := arr(sl["leaves"])
			l[0] = flipHex(l[0].(string))
		}, []string{`epochs[0] "E1" members[2] "local.invalid/25ac38d72cae99471b7346254f28ce88/evidence/736f6c6f": root is`}},
		{"an anchor leaf changed", f, func(t *testing.T, d doc) {
			l := arr(d["anchorLog"].(doc)["anchorLeaves"])
			l[4] = flipHex(l[4].(string))
		}, []string{
			"anchorLog.anchorLeaves[4] is",
			`epochs[1] "E2": anchorRoot is`,
			"anchorLog.anchorConsistency (3, 5) secondRoot is",
			"anchorLog.anchorConsistency (3, 5): the stock library refuses the proof",
			"anchorLog.anchorConsistency (3, 5) proof differs from the stock library's",
		}},
		{"an anchor checkpoint's P flipped", f, func(t *testing.T, d doc) {
			e := epoch(d, 0)
			e["p"] = flipHex(e["p"].(string))
		}, []string{`epochs[0] "E1" anchorCheckpoint checkpointDigest is`}},
		{"an anchor checkpoint's stated size changed", f, func(t *testing.T, d doc) {
			epoch(d, 0)["anchorSize"] = json.Number("2")
		}, []string{
			`epochs[0] "E1": 3 members, but the anchor log grows from 0 to 2`,
			`epochs[0] "E1" members[2]`, "anchorLeafIndex missing or outside this epoch's leaves [0, 2)",
			`epochs[0] "E1" anchorCheckpoint: size is 2, the stock parser reads 3`,
			`epochs[1] "E2": 2 members, but the anchor log grows from 2 to 5`,
			"anchorLog.anchorConsistency is (3, 5), not between the last two anchor sizes [2 5]",
		}},
		{"a consistency proof element flipped", f, func(t *testing.T, d doc) {
			p := arr(d["anchorLog"].(doc)["anchorConsistency"].(doc)["proof"])
			p[2] = flipHex(p[2].(string))
		}, []string{
			"anchorLog.anchorConsistency (3, 5): the stock library refuses the proof",
			"anchorLog.anchorConsistency (3, 5) proof differs from the stock library's",
		}},

		// Exact keys, as for the Merkle files.
		{"a body key in another case", f, func(t *testing.T, d doc) {
			b := findBody(t, d, "invalid", "empty body")
			b["StockParserAccepts"] = b["stockParserAccepts"]
			delete(b, "stockParserAccepts")
		}, []string{`bodies.invalid[7]: unknown field "StockParserAccepts"; keys match exactly, and the field is "stockParserAccepts"`}},
		{"an unknown section", f, func(t *testing.T, d doc) {
			d["checkpoints"] = []any{}
		}, []string{`top level: unknown field "checkpoints"`}},
	})
}

// A copy of the committed file with every stockParserAccepts flag inverted
// fails on every invalid body, and on nothing else.
func TestEveryStockParserFlagIsChecked(t *testing.T) {
	dir := copyVectors(t)
	path := filepath.Join(dir, checkpointFile)
	d := readDoc(t, path)
	invalid := arr(d["bodies"].(doc)["invalid"])
	for _, v := range invalid {
		b := v.(doc)
		b["stockParserAccepts"] = !b["stockParserAccepts"].(bool)
	}
	writeDoc(t, path, d)
	r := runGate(dir)
	got := 0
	for _, f := range r.failures {
		if strings.Contains(f, "bodies.invalid[") && strings.Contains(f, "stockParserAccepts is") {
			got++
		} else if !linkedBaseline()[acceptedLabel.ReplaceAllString(f, "invalid[] $1")] {
			t.Errorf("unexpected failure: %s", f)
		}
	}
	if got != len(invalid) {
		t.Fatalf("%d stockParserAccepts failures, want one for each of the %d invalid bodies", got, len(invalid))
	}
}

// A body the gate reads is compared with its UTF-8 bytes: a non-ASCII origin
// reaches the stock parser as the bytes TypeScript and Python hash.
func TestNonASCIIBodyIsReadAsUTF8(t *testing.T) {
	dir := copyVectors(t)
	path := filepath.Join(dir, checkpointFile)
	d := readDoc(t, path)
	b := findBody(t, d, "invalid", "origin with a non-ASCII character")
	if !strings.Contains(b["body"].(string), "café") {
		t.Fatalf("the committed case changed: %q", b["body"])
	}
	writeDoc(t, path, d)
	expectFailures(t, runGate(dir))
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func findBody(t *testing.T, d doc, section, name string) doc {
	t.Helper()
	for _, v := range arr(d["bodies"].(doc)[section]) {
		if b, ok := v.(doc); ok && b["case"] == name {
			return b
		}
	}
	t.Fatalf("no bodies.%s case %q", section, name)
	return nil
}

func epoch(d doc, i int) doc {
	return arr(d["anchorLog"].(doc)["epochs"])[i].(doc)
}

func member(d doc, e, i int) doc {
	return arr(epoch(d, e)["members"])[i].(doc)
}
