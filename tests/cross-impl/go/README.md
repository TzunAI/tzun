# Go stock-library gate

This program checks this repository's Merkle, checkpoint and anvil end-to-end
vector files with
[`github.com/transparency-dev/merkle`](https://github.com/transparency-dev/merkle),
the transparency-dev project's Go Merkle library (used by Trillian and Tessera),
and [`github.com/transparency-dev/formats`](https://github.com/transparency-dev/formats),
its checkpoint parser, and with no Tzun code. A second module, `evm/`, checks
the EVM half of the end-to-end vectors with
[`github.com/ethereum/go-ethereum`](https://github.com/ethereum/go-ethereum).
It is what makes "verifiable with standard CT libraries"
([Tree §7](https://spec.tzun.ai/tree/2/#s7)) a tested sentence.

CI runs `make check` (`.github/workflows/go-gate.yml`) on pull requests and
pushes to main that change anything under `vectors/`, the two Merkle
generators or this directory. A new vector file fails the gate until
`gate.go` checks it or lists it in `outOfScope` with a reason.

## Running it

With Go 1.25 or later:

```sh
cd tests/cross-impl/go
make check        # gofmt, go vet, the tests against the pinned library and against v0.0.2, the gate, then evm-check
make evm-check    # the evm/ module: go vet, its tests, and its check of anchor-e2e-vectors.json
make gate         # the gate alone: go run . -vectors ../../../vectors
make test-v002    # the tests alone, linked against transparency-dev/merkle v0.0.2
```

Without Go, in a throwaway container (the repository is mounted read-only):

```sh
make docker-check
```

`docker-check` mounts the repository by its path on the Docker host. When make
itself runs inside a container whose paths differ from the host's, pass the host
path: `make docker-check HOST_REPO_ROOT=/host/path/to/tzun`.

The gate prints one line per section and `PASS`, or `FAIL` with every failed
check, and exits 0 or 1.

## What it checks

Every tree is built by the library itself: leaves are appended to a
`compact.Range`, whose visitor stores each perfect-subtree node as it is
created, and proofs are assembled from those stored nodes by the library's
planners (`proof.Inclusion`, `proof.Consistency`) and `Nodes.Rehash`. That is
how a transparency-dev log serves proofs. Verification is `proof.VerifyInclusion`
and `proof.VerifyConsistency`.

| File | Section | Check |
|---|---|---|
| `merkle-rfc6962-vectors.json` | `emptyTreeRoot` | equals the library's `EmptyRoot()` |
| | `trees` | each leaf digest follows the stated derivation; every leaf hash and root equals the library's; there is one audit path for every leaf; every audit path verifies, and the library regenerates it byte for byte |
| | `distinctnessVectors` | both roots equal the library's, and `rootsEqual` matches |
| `merkle-consistency-vectors.json` | `leafDigests` | the stated derivation, the one the inclusion file's trees are held to, so both files state the same leaves |
| | `valid` | both roots equal the library's; every proof verifies, and the library regenerates it byte for byte; every pair with second ≤ 16 is present, as the format promises |
| | `invalid` | the library refuses every entry. Each entry must first decode as canonical hex, so a refusal is the library's and never a decoding accident. Each entry must also be its `derivedFrom` honest pair, built by the library, with only the named mutation applied (see below). No entry is listed twice, and every mutation is present for every pair 0 < first < second <= 8, as the format promises |
| | `encoding` | the harness's verdict, under the encoding rule below, equals `verifies`. A case expected to fail must fail at the encoding rule, not in the library |
| | `sizeMalleability` | each exhibit's list of other sizes is exactly the sizes ≤ 64 under which the library accepts the honest proof, and the census recomputed with the library equals the stated counts. The file calls this section documentation; it also says the exhibits hold under any RFC-correct verifier, and this checks that they hold under this one |
| `checkpoint-vectors.json` | `bodies.valid` | the stock parser, `log.Checkpoint.Unmarshal`, reads each body with no extension data, to exactly its stated origin, size and root, and its SHA-256 is its stated `checkpointDigest` |
| | `bodies.invalid` | each body's `stockParserAccepts` is what the stock parser does with its UTF-8 bytes (no error, or an error), and `c2spConforming` is stated. Tzun refuses every one of these bodies; the flag records which of them a stock C2SP reader takes |
| | `bodies.nonString` | no entry is a string |
| | `anchorLog` | every member checkpoint and anchor checkpoint reads back through the stock parser as stated; each member's root is the library's root of its source log at its size; each epoch's members fill the anchor leaves from the last anchor size to its own, each at its `anchorLeafIndex` the SHA-256 of its body; each anchor root is the library's root of the anchor leaves, and P is the SHA-256 of the anchor checkpoint; the consistency proof between the last two anchor sizes verifies with `proof.VerifyConsistency` and the library regenerates it byte for byte |
| | `chainSegments`, `domain`, `artifacts` | not checked: they hold Tzun's own origin rules and the steps of tzun-anchor/1 §10.3, which no stock library implements. They are held to exact keys like every other section, and the TypeScript suite holds the SDK to them |
| `anchor-e2e-vectors.json` | `epochs` | every anchor checkpoint and member log checkpoint reads back through the stock parser; P is the SHA-256 of the anchor checkpoint; the consistency proof between consecutive published anchor sizes, and between a source log's anchored checkpoints, verifies with `proof.VerifyConsistency`, both sizes and both roots taken from the parsed bodies |
| | `records` | each record's `canonicalDigest` is at `leafIndex = sequenceNumber − 1` in its log checkpoint (`logPath`), and the SHA-256 of that checkpoint is at `anchorLeafIndex` in its epoch's anchor checkpoint (`anchorPath`), both by `proof.VerifyInclusion`. The canonical JSON the digest is computed from is Tzun's own, so the TypeScript and Python suites recompute it |
| | each epoch's `publication`, `manifest`, `headerSource` (in `evm/`, with go-ethereum) | the header RLP decodes (`types.Header`) and both go-ethereum's hash of it and keccak256 of the stored bytes are the block hash, at the block number and time; `trie.VerifyProof` walks `txProof` from the header's transactions root at key `rlp(txIndex)` to exactly the raw transaction; the raw transaction decodes, is EIP-1559, is signed for the file's chain, hashes to `transactionId`, recovers (`types.Sender`) to a publisher the manifest names for the anchor origin, and carries exactly P, to itself, with zero value |

Hashes in every section except `encoding` must be bare lowercase hex, the form
the generators write, and a regenerated proof is compared with the vector as
exact strings.

**Each invalid entry is what its name says.** The gate builds the honest entry
for `derivedFrom` with the library (the roots of both sizes and the consistency
proof between them; size 0 has the empty root and no proof), applies the named
mutation, and requires the entry to equal the result in every field. A
bit-flip must differ from the honest value in exactly one bit, in the named
place. "Swapped" swaps both sizes and both roots. A truncation or extension
changes only the proof, in the named way. "first greater than second" keeps
the honest second size, second root and proof, and gives the root of the
claimed first size. "equal sizes with different roots" changes exactly one
root. A mutation name the gate does not know fails it. So a vector cannot
carry an arbitrary proof under a mutation's name and pass merely because the
library refuses it. For first = second, the file carries its two mutations
for a selected set of sizes (there is no (5, 5) or (6, 6) entry), so those
pairs are held to their derivation but not to the coverage promise.

**Strict decoding.** Before `encoding/json` reads a file, `strict.go` holds it
to the exact field names of the Go types, byte for byte. `encoding/json` on its
own matches keys case-insensitively and with Unicode folding, so `"Invalid"` or
`"ſource"` (a long s) would fill a field, and it lets the last of two equal keys
win; the TypeScript and Python suites would read such a file differently. So an
unknown, renamed or case-changed field, a key repeated in any object (including
the free-form `format` and `note` sections), and anything after the top-level
value each fail the gate.

**Every entry of the vectors directory.** Each entry of `vectors/` must be a
checked file or be listed in `outOfScope` in `gate.go` with its reason. Any
other file, whatever its extension, and any subdirectory fails the gate until
it is examined and given a checker or a reason; a key ending in `/` classifies
a whole subdirectory. The `bundle-b1/` corpus is classified so: its bundles and
expected reports are Tzun's own report contract
([Bundle §13](https://spec.tzun.ai/bundle/b1/#s13);
[Verification §6](https://spec.tzun.ai/verification/1.0/#s6)), which
`tests/ts/bundle-b1-corpus.test.ts` replays. This gate decodes none of the
anchoring material in them (checkpoints, paths, proofs, block headers, trie
proofs and raw transactions), some of which the corpus forges on purpose. A
symbolic link fails too, and so does an `outOfScope` entry that names nothing,
so the list cannot carry exemptions for files that do not exist yet. The anvil
end-to-end vectors (`anchor-e2e-vectors.json`) are checked: their Merkle half
here, their EVM half in `evm/`. The EVM anchor vectors
(`evm-anchor-vectors.json`) hold the publisher-manifest validity cases of
tzun-anchor/1 §9, over one publication that is `anchor-e2e-vectors.json`'s
first, byte for byte, which `evm/` checks, and the transaction cases of §10.4
item 2: signed transactions at each edge of each rule item 2 states, on which
stock Ethereum libraries disagree with each other (go-ethereum recovers a sender
for a legacy `v` of 35, a tip above the fee cap or a `value` of 2^256, ethers
for a typed chain id of 0, a high `s`, non-canonical RLP or a `gasLimit` of
2^64). The file is classified out of scope, and the TypeScript and Python suites
hold its copy to the original and the SDKs to every case. Planned for
this gate: Sepolia end-to-end vectors, and the EVM anchor vectors' own
transactions (with go-ethereum).

## The encoding rule, as the Go harness applies it

The consistency file's `edgeRules` state it: every hash is a JSON string of
exactly 64 hexadecimal digits, matched against the whole string. Upper and mixed
case are accepted and normalised to lowercase. A trailing newline, surrounding
whitespace, 63 or 65 digits, a `0x` prefix, or a non-string is refused.

The library cannot apply this rule: it takes `[][]byte` and never sees hex. Nor
is Go's `hex.DecodeString` the rule on its own. It does accept uppercase, which
is the rule's normalisation, since `"AB"` and `"ab"` decode to the same byte.
But it accepts any even number of digits (66 digits decode to 33 bytes), and a
JSON number or `null` never reaches it as a string. So the harness
(`hexrule.go`) keeps each hash as raw JSON, requires a JSON string, requires
exactly 64 characters from `[0-9a-fA-F]`, and only then decodes it. A proof must
be a JSON array, so a `null` proof is refused rather than read as empty. The
rule applies to the JSON string's value, the same as `JSON.parse` in TypeScript
and `json.loads` in Python, so a digit written as a JSON escape (`\u0033`) is
that digit.

An encoding case gets the verdict "verifies" only when every hash passes the
rule and the library then accepts the proof. The 11 cases expected to fail all
fail at the rule, before the library sees them; apart from the one malformed
value, each is the honest (3, 7) proof.

## The pinned library version

`go.mod` pins the pseudo-version `v0.0.3-0.20260921095310-fbbcd741c3d1`, an
untagged commit on transparency-dev/merkle's main branch. Under that pin the
library refuses all 426 invalid consistency vectors.

The latest tag, v0.0.2, accepts five of them: the four "first = 0 with an empty
proof" cases and "first = 0 and second = 0". Its `VerifyConsistency` treats
size 0 as consistent with any size when the proof is empty, and it reaches its
equal-sizes branch before that one, so (0, 0) passes as equal sizes with equal
roots. On main, `RootFromConsistencyProof` refuses a first size of 0 before
either branch. Tzun refuses first = 0 because it never publishes an empty log
([Tree §3.5](https://spec.tzun.ai/tree/2/#s3-5), edge rule 1).

**What `@latest` gives an auditor.** `@latest` picks the highest tagged
release, and the pinned pseudo-version is untagged, so as of 2026-09-25
`go get github.com/transparency-dev/merkle@latest` resolves to v0.0.2. Checked
with v0.0.2, these vectors fail on exactly five entries, all of them `invalid`
entries the library accepts: the four "first = 0 with an empty proof" entries,
from (0, 1), (0, 2), (0, 7) and (0, 16), and "first = 0 and second = 0". Every
other check agrees with the pin. An auditor who sees those five and
no others is looking at v0.0.2's size-0 behaviour, not at a fault in the
vectors.

That is tested, not only stated. `go.v0.0.2.mod` and `go.v0.0.2.sum` are this
module with v0.0.2 in place of the pin, and `make test-v002` runs every test
with `-modfile=go.v0.0.2.mod`. The tests read the linked version from the build
information and look it up in `knownAccepted` in `gate_test.go`: under the pin
the committed vectors must pass, and under v0.0.2 they must fail with exactly
those five `ACCEPTED by the stock library` failures and the summary line
`invalid 421/426 refused by the stock library`. The corrupted-vector tests run
under both versions too. A version with no entry in `knownAccepted` fails the
tests.

To run the gate itself against v0.0.2:

```sh
go run -modfile=go.v0.0.2.mod . -vectors ../../../vectors
```

Moving the pin is a reviewed change to `go.mod`, `go.sum` and `knownAccepted`,
and the gate prints the linked version on its first line.

**transparency-dev/formats** is pinned at the tag v0.1.1 in both module
files. `checkpoint-vectors.json` states each invalid body's
`stockParserAccepts` against that version, whose `log.Checkpoint.Unmarshal`
the file's `format` block describes, so `TestFormatsVersionIsPinned` refuses
any other. The gate prints the linked version on its second line. Its
`go.mod` asks for go 1.25.0, so the module does too.

## The go-ethereum module (`evm/`)

go-ethereum pulls about 470 MB of modules into the cache (its KZG, BLS and
system-information dependencies among them), so its check lives in a module of
its own, `evm/`, with its own `go.mod` and `go.sum`, and the gate module keeps
its two dependencies. `make check` runs both. `evm/go.mod` pins
`github.com/ethereum/go-ethereum` v1.17.6, and `TestGethVersionIsPinned`
refuses any other. Its tests check the committed file's summary lines and seven
deliberate corruptions (a changed trie node, a proof for another index, a
changed header byte, another publisher in the manifest, a P that is not the
anchor checkpoint's, another transaction id, a block above the finalized
height), each of which must fail with exactly its expected failures.

## Files

- `main.go`: the command line.
- `gate.go`: the vectors directory's inventory, loading the vector files, and
  the checks of the two Merkle files.
- `checkpoint.go`: the checks of `checkpoint-vectors.json`.
- `anchore2e.go`: the Merkle half of the checks of `anchor-e2e-vectors.json`;
  `anchore2e_test.go`, ten deliberate corruptions of it.
- `evm/`: the go-ethereum module (`main.go`, `evm.go`, `evm_test.go`) that
  checks the EVM half.
- `strict.go`: the exact-key check that runs before `encoding/json`.
- `tree.go`: trees and proofs, built entirely with the library.
- `hexrule.go`: the encoding rule.
- `go.v0.0.2.mod`, `go.v0.0.2.sum`: this module linked against v0.0.2, for
  `make test-v002`.
- `gate_test.go`: every summary line the gate prints on the committed vectors,
  under the pin and under v0.0.2, and 180 deliberate corruptions of a copy of
  them, each of which must fail the gate with exactly its expected failures and
  no others: flipped, uppercase, null and missing values in every section; each
  kind of invalid entry changed away from its named mutation; each mutation
  promised for (3, 7) removed, and a promised valid pair removed; each census
  count changed or removed; case-renamed, Unicode-folded, repeated and unknown
  keys; trailing data; and unknown files, extensions, subdirectories and links
  in the vectors directory. Changes that keep the vectors true, such as an
  exhibit whose other sizes reach 64, must keep the gate passing.
- `checkpoint_test.go`: the pinned formats version, and 32 deliberate
  corruptions of the checkpoint file, each of which must fail the gate with
  exactly its expected failures: stated values the parser does not read back,
  flipped `stockParserAccepts` flags, a string among the non-strings, and
  changed source leaves, anchor leaves, anchor sizes, P and consistency
  proofs. Inverting every `stockParserAccepts` flag at once must fail on every
  invalid body.
- `strict_test.go`: the exact-key check, and what `encoding/json` alone lets
  through.
- `hexrule_test.go`: the encoding rule, case by case.
