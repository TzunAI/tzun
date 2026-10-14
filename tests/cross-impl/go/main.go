// The stock-library gate checks the vector files in tzun-sdk's
// vectors/ directory with github.com/transparency-dev/merkle and
// github.com/transparency-dev/formats, and no Tzun code. It verifies every
// inclusion and consistency vector, checks that the library refuses every
// invalid one, applies the vectors' hex encoding rule to the encoding cases,
// and regenerates every valid proof with the library, comparing it byte for
// byte. It reads every checkpoint body with the stock checkpoint parser, and
// rebuilds the checkpoint file's anchor log with the Merkle library.
//
// Run it with go run (see README.md); go build would name the binary "go",
// after this directory. Exit status: 0 when every check passes, 1 when any
// fails, 2 on a usage error.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
)

const (
	libraryPath = "github.com/transparency-dev/merkle"
	formatsPath = "github.com/transparency-dev/formats"
)

func main() {
	vectors := flag.String("vectors", "../../../vectors", "the tzun-sdk vectors directory")
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

	fmt.Printf("library: %s %s\n", libraryPath, libraryVersion())
	fmt.Printf("library: %s %s\n", formatsPath, moduleVersion(formatsPath))
	fmt.Printf("vectors: %s\n", dir)
	r := runGate(dir)
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

// libraryVersion reports the transparency-dev/merkle version linked into this
// binary, from its build information.
func libraryVersion() string { return moduleVersion(libraryPath) }

// moduleVersion reports the version of the module at path linked into this
// binary, from its build information.
func moduleVersion(path string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "(version unknown)"
	}
	for _, d := range bi.Deps {
		if d.Path == path {
			if d.Replace != nil {
				return d.Version + " => " + d.Replace.Path + " " + d.Replace.Version
			}
			return d.Version
		}
	}
	return "(version unknown)"
}
