# The b1 proof-bundle corpus

The conformance corpus of Bundle §13 for `b1` bundles: bundles exported by
`Tzun.exportBundle()` from a store anchored end to end on anvil, with the
auditor's inputs, and the report and exit code a verifier must produce. The TS
SDK's `verifyBundle()` replays it (`tests/ts/bundle-b1-corpus.test.ts`) and
matches every case exactly. `tzun-verify` (TzunAI/tzun-verify) replays its own
pinned copy, without the custody cases, in its own suite. The Python SDK has
no `verify_bundle()` yet.

`scripts/generate-bundle-b1-corpus.ts` writes it, from one anvil run. Every
record is timestamped by a local authority under a throwaway root, whose
tokens meet every rule of tzun-anchor/1 §10.5 as a public authority's do: a
DER `TimeStampResp` and `TSTInfo`, a `signingCertificateV2` over the signer
certificate, and a signer whose one extendedKeyUsage, marked critical, is
`id-kp-timeStamping`. The `record-token-*` cases each carry a token that
breaks, or tests the edge of, one rule of §10.5: not DER, a digestAlgorithms
member that is not an AlgorithmIdentifier, an added certificate whose key
does not decode, a signer whose P-256 point is off the curve, no signer
binding, no timestamping EKU, an issuer name that is the root's in another
string type (names match byte for byte), a key on the curve OID
1.2.840.10045.3.1.99, which is assigned to no curve and so is
`missing_dependency` in every verifier where a step needs it (the signer, an
intermediate) and not examined where none does, and the signer subjects that
shape the trust check's `authority` fact. The `anchor-token-*` cases give the
record's anchor a second publication, an `rfc3161/1` token over its P from a
second throwaway authority (tzun-anchor/1 §10.5): with that authority's root
supplied beside the first, with no root (steps 1 to 3 still hold), over another
value (`imprint_mismatch`), and not DER (`malformed_publication`). The
expected reports are stated in that script from Verification, Bundle and
tzun-anchor/1 §10, row by row; the values in them (digests, origins,
transaction ids, block times, the timestamp's genTime) are the run's own. The
script stops, writing nothing, unless `verifyBundle()` agrees with every row.

anvil's clock runs an hour behind the wall clock in that run, so every block
time precedes every genTime. Which proof `summary.existedBy` names is then
fixed by what the case proves: the record's anchor when it holds, the newer
anchor when only that holds, the record's timestamp when no anchor holds. The
script stops unless each of the three is named by some case.
A change to an expected report cites the spec section that moved it, and
every suite that replays the corpus moves in the same change.

## Layout

`index.json` lists every case with its exit code and what it pins. Each case
is a directory:

| File | What it holds |
|---|---|
| `bundle.json` | The bundle, as the exporter wrote it, or with the one change the case names |
| `inputs.json` | The auditor's own inputs (below) |
| `expected-report.json` | The report (Verification §6), without `checkedAt` |
| `expected-exit` | The exit code under the case's regime, and a newline |

## `inputs.json`

```jsonc
{
  "publisherManifest": { "publishers": { "<anchor origin>": [ { "address", "chain", "namespace", "validFrom"? } ] } } | null,
  "headerSources": {                       // keyed by CAIP-2 chain; {} for none
    "eip155:31337": {
      "chainId": 31337,
      "finality": "finalized",
      "finalizedBlockNumber": 13,          // the newest block the source calls final
      "blocks": [ { "number": 1, "hash": "0x…", "timestamp": 1790444377 } ]
    }
  },
  "trustAnchorsPem": [ "-----BEGIN CERTIFICATE-----…" ],   // RFC 3161 roots; [] for none
  "regime": { "require": [], "requireRung": [], "allowUnchecked": false }   // or a list of reasons
}
```

`allowUnchecked` is `true`, `false`, or a list of reasons (the scoped
allowance): with a list, only rows not checked or
abstaining for a reason it names stop counting toward exit 4.

A header source is static: its chain id, its finality, its finalized height, and
the canonical block (hash and unix timestamp) at each height it lists. It has no
block at any other height, and it looks up no transaction. No other input is
given: no environment trust store, no network registry beyond the verifier's own
(`eip155:31337` is in none, so `anchorNetwork` is `null`). Every root in
`trustAnchorsPem` reads as a certificate with a key the verifier implements: a
root that cannot be read is an input error, refused with no report and no exit
code from 0 to 4 (Verification §3.1, §6.6), so no case carries one.

## The report

```jsonc
{
  "reportVersion": "tzun-verify-report/1",
  "bundleVersion": <the bundle's bundleVersion as it stands> | null,
  "subject": <the bundle's subject as it stands, every member> | null,
  "inputs": {
    "trustAnchors": [ "<SHA-256 of each root's DER, hex>" ],  // sorted
    "evmHeaderSources": [ { "chain", "finality" } ],          // sorted by chain
    "publisherManifest": "<SHA-256 of the manifest in DEO canonical form>" | null,
    "frameOrigins": null, "vkeys": null, "mdsRoots": null
  },
  "checks": [ { "id", "outcome", "reason"?, "facts"? } ],
  "summary": {
    "mode": null, "coverage": null, "manifestEnforced": null, "rungs": [],
    "keyKind": null, "keyAssurance": null, "uv": null, "actorBound": null,
    "existedBy": { "at", "source": "evm-calldata" | "rfc3161" | "record-timestamp",
                   "check": "anchor" | "anchor.newer" | "ts.record.trust" } | null,
    "anchorNetwork", "anchorNamespace", "anchorOriginAuthenticated",
    "outcomes": { "checked-correct", "checked-wrong", "not-checked", "abstain" }
  }
}
```

Reports compare in DEO canonical form. The sign-off members of the summary stay
null until sign-off verification is implemented.

## The checks, in report order

| Id | Checks | Outcomes other than `checked-correct` |
|---|---|---|
| `bundle` | `bundleVersion` is `b1`, `profile` is `record`, every member is readable: among others, every checkpoint body parses and sits under the `anchoring` key of its own origin, once per log, and no member name a row id can carry (of the bundle, of `extensions`, of `envelope.nonRepudiation`, of `anchoring`) holds a lone surrogate (Bundle §4 step 9). When it is not correct it is the only row. | abstain `unsupported_bundle_version`, `unsupported_bundle_profile`; wrong `malformed_bundle` |
| `subject` | `subject` names the envelope's evidence id and stored digest | wrong `subject_mismatch` |
| `record.digest` | The payload, recomputed under its schema, is `integrity.canonicalDigest`. A `digest_mismatch` carries the fact `fieldSet` (`0.7`, `before-0.7`) when an earlier hashed field set reproduces the stored digest: it explains the mismatch and never excuses it | wrong `digest_mismatch`, `payload_unserializable`; abstain `unsupported_schema_version` |
| `record.chainLink` | `chainLink` = SHA-256(predecessor digest ‖ digest) over `chain.predecessor` at the previous sequence; a genesis record with no link holds | wrong `chain_link_mismatch`, `chain_link_missing`, `predecessor_mismatch`; not-checked `not_in_bundle:predecessor` |
| `custody.ledger` | The `custody` slot (Verification §4.3, Bundle §6). This version verifies no custody material, so the row is never correct. Its one finding: a slot that holds no row (`null`, or `entries` an empty array) beside an envelope whose `custodyChain` holds a mirror entry (an object with a 64-hex `entryHash`), which names a row the bundle leaves out. Nothing a bundle carries commits to the ledger, so a row left out together with its mirror entry leaves no trace | wrong `mirror_entry_unexpected`; not-checked `not_applicable` (no row and no mirror entry); abstain `unsupported_artifact` (any other slot) |
| `ts.record.token`, `ts.record.trust` | The record's RFC 3161 token, tzun-anchor/1 §10.5's steps in order: the base64 of a DER `TimeStampResp` carrying a DER `TSTInfo` and its signer's certificate; a SHA-256 imprint over the digest; the signature, a `signingCertificate` or `signingCertificateV2` that names the signer certificate, and a critical extendedKeyUsage on it whose only purpose is `id-kp-timeStamping` (`ts.record.token`); then a valid path to a supplied root (`ts.record.trust`) | token: wrong `malformed_token`, `imprint_mismatch`, `verification_failed`; not-checked `missing_dependency` (an algorithm, or the signer key's algorithm or curve, the verifier does not implement). Trust: wrong `verification_failed` (a path reaches a supplied root and none is valid); not-checked `no_matching_trust_anchor`, `missing_dependency` (a path that holds but for a signature under an issuing key or algorithm the verifier does not implement). Both: not-checked `absent`, `blocked_by:…` |
| `signoff.expectation` | The record's sign-off material against its hashed `payload.signoffExpectation`, by every check that needs no key (Record §9, Verification §5): a session record carries its `signoff` block, of its slot and statement, and an assertion that presented the statement's challenge; a record that names no session carries no session sign-off; a carried `signoff` block binds (a batch block: a `mode: 'batch'` statement, its challenge presented, the digest under its root); a policy record carries a signature | wrong `signoff_stripped`, `session_signoff_not_expected`, `session_seq_mismatch`, `statement_digest_mismatch`, `signoff_unbound`, `malformed_signoff_expectation`; not-checked `signature_missing` (a policy record's signature still to come, or stripped), `not_applicable` (a schema that does not hash the field), `blocked_by:record.digest` |
| `signoff.key` | A record that owes a signature and carries no assertion, as `signoff.expectation` says; otherwise a WebAuthn assertion's credential, which no slot of this version carries | not-checked `blocked_by:signoff.expectation`, `signature_missing`, `not_in_bundle:credential`, `absent`; abstain `unsupported_signoff` |
| `decider` | The record's `decider` (Record §6, Verification §4.9): grammar, kind, consistency of kind, identifier and agent, agreement with the signature expectation, the identifier scheme, and material of the other class bound to the record. Facts: `kind`, `scheme`, `level` (`human-asserted` or `agent-asserted`: this version verifies no signature), `levelUndetermined: human-proven` when human decision material is bound, `committed: true` for a `cmt` identifier, `kindContradiction: undetermined` | wrong `malformed_decider`, `decider_inconsistent`, `decider_kind_contradicted`; abstain `unsupported_decider_kind`, `unsupported_identifier_scheme`; not-checked `absent`, `material_unverified`, `blocked_by:signoff.expectation`, `blocked_by:record.digest` |
| `decider.freshness` | The decider's finalized-block reference against the auditor's header source for its chain: the source names that chain, calls the height final, and holds that hash there. Facts: `blockTime` (ISO 8601), `captureLag` (`capturedAt` − `blockTime`, in milliseconds; informative) | wrong `freshness_block_mismatch`; not-checked `absent`, `blocked_by:decider`, `input_not_supplied:evm_header_source`, `evm_header_source_chain_mismatch`, `evm_header_source_unavailable`, `evm_header_source_timeout`, `evm_block_not_finalized`, `evm_header_source_inconsistent`, `blocked_by:record.digest`; abstain `unsupported_freshness_chain` |
| `contributions`, `contributions.binding`, `contributions.pipeline` | The structure of `contributions` (Record §7.1, §7.3), then the process checks from the record alone (Record §7.5); a named pipeline is not verified. Facts: `steps`, `models` (the distinct step model digests), `decidingStep` (an index, or `record`); the binding's `approvals`, `staleApprovals`, `uncoveredReviews`, `proposals`, `decisionBinding`, and `failedStep`, `failedDigest` on a failure | contributions: wrong `malformed_contributions`, `step_chain_broken`, `decider_not_deciding_actor`, `deciding_output_mismatch`; abstain `unsupported_actor_kind`, `unsupported_identifier_scheme`; not-checked `absent`, `blocked_by:record.digest`. Binding: wrong `input_undeclared`, `review_unbound`, `decision_unbound`, `decided_output_differs`; not-checked `absent`, `blocked_by:contributions`, `blocked_by:record.digest`. Pipeline: abstain `unsupported_pipeline` |
| `links`, `links[<i>]`, `links[<i>].edge` | The grammar and list-level rules of `links` (Record §8.2, §8.3), then each link's relation rules in list order; a bundle holds no target (`targetHeld: false`), and no edge is proven in this version. Facts of `links`: `count`, `relations`, `extensions`; of a link: `targetHeld`, and `rule`, `member`, `missing`, `rootInconsistent` where they apply | links: wrong `malformed_links`, `link_rule_violated` (fact `rule`); not-checked `absent`, `blocked_by:record.digest`. A link: wrong `link_attrs_invalid`, `link_rule_violated`, `link_target_mismatch`; abstain `unsupported_link_relation`, `unsupported_link_rule`; not-checked `link_rule_undetermined`, `not_in_bundle:link_target`, `blocked_by:links`, `blocked_by:signoff.expectation`. An edge: abstain `unsupported_link_edge` |
| `mandate.issuance`, `mandate.scope`, `mandate.limits`, `mandate.key`, `mandate.assertionTimestamp` | An issuance record's material (when it carries `nonRepudiation.mandateIssuance`, or is `tzun:mandate` / `issue-mandate`); for the mandate form of the expectation, the record against its carried document's scope and limits (facts `slot`, `totals`), and the principal's key, which no slot of this version carries; a token over the assertion digest, which this version does not read | issuance: wrong `issuance_not_expected`, `issuance_material_stripped`, `issuance_material_mismatch` (fact `link`). Scope and limits: wrong `agent_not_in_mandate`, `outside_mandate_scope`, `confirmation_evaded`, `malformed_mandate_document`, `mandate_totals_malformed`, `mandate_limit_exceeded`; not-checked `scope_undeterminable`, `not_in_bundle:mandate_document`, `blocked_by:signoff.expectation`, `blocked_by:record.digest`. Key: not-checked `not_in_bundle:credential`; abstain `unsupported_signoff`. Timestamp: abstain `unsupported_artifact` |
| `anchor`, `anchor.spec` … `anchor.anchorInclusion`, `anchor.publication[i]`, `anchor.evm.tx[i]`, `anchor.evm.canonical[i]`, `anchor.tsa.token[i]`, `anchor.tsa.trust[i]` | The envelope's `nonRepudiation.anchor`, tzun-anchor/1 §10.3 to §10.7, over the recomputed digest, with the payload's sequence number, the bundle's chain id, and the heavy material of every carried publication joined in | tzun-anchor/1 §10.1 |
| `anchor.newer` | The subject's anchor into the newest carried anchor checkpoint (tzun-anchor/1 §10.8), composed from the evidence-log checkpoint that carries `logPath`, `anchorLeafIndex`, `anchorSize` and `anchorPath` | as `anchor` |
| `anchor.consistency[<origin>]` | For every origin the bundle carries or the anchors name: every carried checkpoint is one that `anchor` or `anchor.newer` authenticated, with one checkpoint per log as with two, and two authenticated checkpoints of the origin are consistent (tzun-anchor/1 §10.8). A carried checkpoint neither authenticates is `blocked_by:anchor` while the record's anchor does not hold, `blocked_by:anchor.newer` once it does | wrong `split_view`, `log_inconsistent_with_anchor`; not-checked `not_in_bundle:consistency_proof`, `blocked_by:anchor`, `blocked_by:anchor.newer` |
| `anchor.pending` | The bundle's `anchorPending` slot | not-checked `not_yet_published` |
| `extension[<key>]` | An extension with a value that this verifier does not implement | abstain `unsupported_extension` |
| `relatedRecords`, `policy` | A reserved slot (Bundle §8) this verifier does not read yet, when it is not `null` | abstain `unsupported_slot` |
| `payload.<name>` | A payload member outside the format's twelve names, in byte order of the name: it is not hashed, so it is never passed over in silence | abstain `unsupported_member` |
| `member[<key>]` | A top-level member a `record` bundle does not have | abstain `unsupported_member` |
| `ts.assertion.token`, `nonRepudiation.<name>` | Each member of `nonRepudiation` with a value that no row above reads (`mandate`, `mandateIssuance` and `confirmation` are read by the record-rule rows), in byte order of its name: `assertionTimestamp` is `ts.assertion.token`; a `blockchainAnchor` beside an `anchor` is `nonRepudiation.blockchainAnchor`; any other member is `nonRepudiation.<name>` | abstain `unsupported_artifact`; `legacy_blockchain_anchor` for the `blockchainAnchor` |

Checks that take the record's digest as their input (`ts.record.*`,
`signoff.expectation`, `anchor`, the step checks and `anchor.newer`) are
`blocked_by:record.digest` unless it is correct, except that an artifact that
is not there is `absent` first: no token, or neither `anchor` nor
`blockchainAnchor` (`tampered-payload-artifact-stripped`). Facts: `anchor.origin` (`originAuthenticated`, `namespace`,
`chainChecked`), `anchor.leafIndex` (`leafIndexChecked`), `anchor.evm.tx[i]`
(`transactionId`, `txType`, `sender`, `signedChainId`), `anchor.evm.canonical[i]`
(`chain`, `namespace`, `network`, `blockTime`, `inclusion`, `finality`; only
`finality` when not correct), `anchor.tsa.trust[i]` and `ts.record.trust`
(`genTime`, `authority`: the signer subject's first commonName as encoded, with
no escaping or trimming, and `""` with none), `anchor.newer` (`treeSize`, `anchorSize`) and
`anchor.consistency[…]` (`fromSize`, `toSize`).

## Exit codes (Verification §6.6)

2 when `bundle` is not correct, or the report cannot be written in canonical
form (a `subject` holding a lone surrogate: no case can state such a report);
else 1 when any check is wrong; else 3 when a
required check is not correct or a required rung is missing; else 4 when a
check abstained or is not checked for any reason but `not_applicable`,
`absent`, or `blocked_by` a check that failed, unless `allowUnchecked` is
`true` or lists that reason; else 0.

An absent artifact is not an unchecked one, so 0 does not say the record is
anchored or signed. A bundle with no anchor artifact, no anchoring and no
`anchorPending` is what a store that does not anchor exports, and an
unanchored record's bundle with its pending slot set to `null` reads the same
(`unanchored-pending-stripped`). An auditor who needs the record anchored
requires it: `anchor` for a record that carries its own artifact, or
`anchor.newer` for one exported before its artifact was filled
(`artifact-not-filled`).

## The bundle's anchoring members

`anchoring[<origin>]` is `{ checkpoints, consistency }` for the subject's
evidence log and its domain's anchor log, each keyed by the origin its
checkpoint bodies name. A record bundle carries at most two checkpoints per
log, in size order: the subject's own, and the newest anchored when it was
exported, with one direct `PROOF(m, n)` between them
(`{ fromSize, toSize, path }`). The subject's own checkpoints are carried only
when its artifact names them, since nothing else authenticates them: a record
whose envelope has no artifact yet carries the newest checkpoint of each log
alone. An anchor-log checkpoint carries
`publications`: every final publication of its P, the `evm-calldata/1` entry
joined with `rawTransaction`, `blockHeader`, `txIndex` and `txProof`. When the
bundle carries a checkpoint the record's artifact does not name, the largest
evidence-log checkpoint carries `logPath` (the subject's path in it),
`anchorLeafIndex`, `anchorSize` and `anchorPath` (its path into the anchor
checkpoint of that size). An unanchored subject carries `anchorPending`
(`{ origin, leafIndex, since }`) and no anchoring.
