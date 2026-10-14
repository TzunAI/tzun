package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const committed = "../../../../vectors/" + e2eFile

// The file states its EVM material against go-ethereum at the version go.mod
// pins; the tests refuse to run against another.
const pinnedGeth = "v1.17.6"

func TestGethVersionIsPinned(t *testing.T) {
	if v := moduleVersion(gethPath); v != pinnedGeth {
		t.Fatalf("%s %s is linked; pinned %s", gethPath, v, pinnedGeth)
	}
}

func TestCommittedVectors(t *testing.T) {
	r := checkFile(committed)
	if len(r.failures) != 0 {
		t.Fatalf("failures:\n%s", strings.Join(r.failures, "\n"))
	}
	want := []string{
		e2eFile + ": 2 publications: each header decoded by go-ethereum hashes to its blockHash at its blockNumber and time",
		e2eFile + ": each txProof (6 nodes in all) walked by go-ethereum's trie.VerifyProof from the header's transactionsRoot to the rawTransaction",
		e2eFile + ": each transaction decoded by go-ethereum: EIP-1559, signed for eip155:31337, its hash the transactionId, its sender the manifest's publisher, its calldata exactly P = SHA-256(anchorCheckpoint)",
	}
	if !slices.Equal(r.lines, want) {
		t.Fatalf("lines:\n%s\nwant:\n%s", strings.Join(r.lines, "\n"), strings.Join(want, "\n"))
	}
}

type doc = map[string]any

func publication(d doc, i int) doc {
	return d["epochs"].([]any)[i].(doc)["publication"].(doc)
}

// flipByte flips the low bit of the byte at offset i of a 0x-hex string.
func flipByte(s string, i int) string {
	at := 2 + 2*i + 1
	c := s[at]
	digits := "0123456789abcdef"
	v := strings.IndexByte(digits, c)
	return s[:at] + string(digits[v^1]) + s[at+1:]
}

// Each deliberate corruption must fail the check with exactly its expected failures.
func TestCorruptionsFail(t *testing.T) {
	cases := []struct {
		name string
		edit func(d doc)
		want []string
	}{
		{"a trie node changed", func(d doc) {
			p := publication(d, 0)
			proof := p["txProof"].([]any)
			proof[1] = flipByte(proof[1].(string), 40)
		}, []string{"epochs[0]: go-ethereum refuses the txProof"}},
		{"the proof for another index", func(d doc) {
			p := publication(d, 0)
			p["txIndex"] = json.Number("3")
		}, []string{"epochs[0]: go-ethereum refuses the txProof"}},
		{"a header byte changed", func(d doc) {
			p := publication(d, 1)
			p["blockHeader"] = flipByte(p["blockHeader"].(string), 200)
		}, []string{
			"epochs[1]: keccak256(blockHeader) is",
			"epochs[1]: go-ethereum hashes the decoded header to",
		}},
		{"another publisher in the manifest", func(d doc) {
			m := d["manifest"].(doc)["publishers"].(doc)
			for origin := range m {
				entries := m[origin].([]any)
				entries[0].(doc)["address"] = "0x" + strings.Repeat("42", 20)
			}
		}, []string{
			"epochs[0]: the sender 0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc is not a publisher the manifest names",
			"epochs[1]: the sender 0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc is not a publisher the manifest names",
		}},
		{"P not the anchor checkpoint's", func(d doc) {
			e := d["epochs"].([]any)[0].(doc)
			e["anchorCheckpoint"] = strings.Replace(e["anchorCheckpoint"].(string), "\n2\n", "\n3\n", 1)
		}, []string{
			"epochs[0]: p is",
			"epochs[0]: the calldata is",
		}},
		{"a transaction id of another transaction", func(d doc) {
			p := publication(d, 1)
			p["transactionId"] = flipByte(p["transactionId"].(string), 31)
		}, []string{"epochs[1]: the rawTransaction hashes to"}},
		{"a block above the finalized height", func(d doc) {
			d["headerSource"].(doc)["finalizedBlockNumber"] = json.Number("2")
		}, []string{"epochs[1]: block 5 is above headerSource.finalizedBlockNumber 2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := os.ReadFile(committed)
			if err != nil {
				t.Fatal(err)
			}
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.UseNumber()
			var d doc
			if err := dec.Decode(&d); err != nil {
				t.Fatal(err)
			}
			c.edit(d)
			out, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), e2eFile)
			if err := os.WriteFile(path, out, 0o644); err != nil {
				t.Fatal(err)
			}
			r := checkFile(path)
			for _, w := range c.want {
				if !slices.ContainsFunc(r.failures, func(f string) bool { return strings.Contains(f, w) }) {
					t.Errorf("no failure contains %q", w)
				}
			}
			for _, f := range r.failures {
				if !slices.ContainsFunc(c.want, func(w string) bool { return strings.Contains(f, w) }) {
					t.Errorf("unexpected failure: %s", f)
				}
			}
			if t.Failed() {
				t.Logf("all failures:\n%s", strings.Join(r.failures, "\n"))
			}
		})
	}
}
