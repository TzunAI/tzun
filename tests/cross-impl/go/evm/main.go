// The go-ethereum half of the gate for tzun-sdk's vectors/anchor-e2e-vectors.json
// (tzun-anchor/1 §13; Anchor §7.2, §11). For every
// epoch's evm-calldata/1 publication it checks, with go-ethereum and no Tzun
// code, that the stored block header decodes and hashes to the block hash at
// the block number, that the stored transactions-trie proof walks from the
// header's transactions root to the raw transaction, and that the raw
// transaction decodes, hashes to its transaction id, recovers to the
// manifest's publisher on the chain it signed, and carries exactly P. The
// Merkle half of the same file is checked by the gate module in the parent
// directory, with transparency-dev.
//
// Run it with go run (see ../README.md). Exit status: 0 when every check
// passes, 1 when any fails, 2 on a usage error.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
)

const gethPath = "github.com/ethereum/go-ethereum"

func main() {
	vectors := flag.String("vectors", "../../../../vectors", "the tzun-sdk vectors directory")
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	dir, err := filepath.Abs(*vectors)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Printf("library: %s %s\n", gethPath, moduleVersion(gethPath))
	fmt.Printf("vectors: %s\n", dir)
	r := checkFile(filepath.Join(dir, e2eFile))
	for _, l := range r.lines {
		fmt.Println("  " + l)
	}
	if len(r.failures) == 0 {
		fmt.Println("PASS")
		return
	}
	fmt.Printf("FAIL: %d check(s) failed\n", len(r.failures))
	for _, f := range r.failures {
		fmt.Println("  - " + f)
	}
	os.Exit(1)
}

// moduleVersion reports the version of the module at path linked into this
// binary, from its build information.
func moduleVersion(path string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "(version unknown)"
	}
	for _, d := range bi.Deps {
		if d.Path == path {
			return d.Version
		}
	}
	return "(version unknown)"
}
