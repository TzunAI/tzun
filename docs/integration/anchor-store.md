# Anchoring a store kept outside the SDK

The anchor scheduler (`createAnchorScheduler`) reads and writes a store through
two interfaces, `LogStore` and `AnchorStore`. The SDK's SQLite and Postgres
adapters implement both. A deployment that keeps its evidence logs and
anchoring tables in a schema of its own (a hosted deployment does) implements
them over its own tables and passes them in:

```ts
import { createAnchorScheduler, type AnchorStore, type LogStore } from '@tzun/sdk';

const scheduler = await createAnchorScheduler({ logStore, anchorStore, config, expectation });
```

Every rule stays in the SDK: epoch planning, proofs, checkpoint bodies, the
fill artifacts, the scheduler's state machine and the publisher. What such a
store restates is its storage guards, in its own SQL. This page lists what the
SDK exports for that, and the conformance kit that holds the restated guards to
the SDK's. The format the scheduler writes, and what a verifier checks of it,
is [tzun-anchor/1](https://spec.tzun.ai/anchor/1/).

## What the package root exports for it

| Need | Export |
|---|---|
| The interfaces and their rows | `LogStore`, `AnchorStore`, `LogRecord`, `LogLeaf`, `LogCheckpoint`, `StoredAnchorPublication`, `EpochWrite`, `AnchorFill`, `AnchorFillChunk` and the rest of the row types |
| The publication state machine | `ANCHOR_PUBLICATION_STATES_BY_KIND`, `ANCHOR_PUBLICATION_TRANSITIONS`, `isAllowedPublicationTransition` |
| The epoch guard's refusal | `AnchorEpochFenceError`: throw it (with its `reason`) when the guard refuses. The scheduler defers the epoch on it, and counts any other error as a failed pass |
| The fill-only merge | `filledEnvelope(envelope, fill, chunk)` and `fillStatus` |
| The accounted-transaction check | `assertAnchorWalletTx(tx)`: call it before storing a wallet transaction |
| Reading a record's anchor state | `readRecordLog(envelope, position, anchorStore)` |
| The hosted namespaces | `isPlatformNamespace(ns)`: `log.tzun.ai` and `test.log.tzun.ai`, whose source logs are named by opaque ids |

Origins ([Anchor §4.3.3](https://spec.tzun.ai/anchor/1/#s4-3-3)): a hosted
source log is `<ns>/<deploymentId>/<opaque id>`, the id 32 lowercase hex, and
its anchor log `<ns>/<deploymentId>/anchors`, with `getStoreIdentity()`
returning `{ storeId: deploymentId, ns }`. An evidence
log may report `chainId: null` (a view that spans tenants, whose chain ids are
unique only per tenant) or its chain id (a view of one tenant); `planEpoch`
anchors it either way, with the chain unchecked. One that reports a chain id
under a name that is not a 32-hex id is held to the SDK form of origin, and
refused. The fill sets `AnchorFill.logId` to the record's evidence log.

## What the scheduler checks, and what the store must restate

The scheduler trusts no anchoring row because it is stored. It authenticates
every publication by its signed transactions and a sender its configuration or
the publisher manifest names, inside that sender's validity window; it signs
only an epoch it planned or re-derives from the anchor log; and it explains
every anchor leaf above the published size as the digest of a source
checkpoint its log's leaves rebuild. A row it cannot explain stops it, and the
domain moves to a new identity. These are the writer obligations of
[Anchor §11](https://spec.tzun.ai/anchor/1/#s11). What a store restates, so
that no role but the anchor writer can reach that stop:

- an evidence leaf is a copy of the record stored at its position;
- every other log, leaf, checkpoint, publication, wallet, accounted
  transaction and lease is written only by the anchor writer;
- a publication's `created_at` and a leaf's `logged_at` are the insert's own
  time; superseding needs an attempt, every one rejected; an `accepted`
  broadcast stays accepted; `prepared → superseded` is not a transition;
- a lease holder starts `tzun-anchor/2:`;
- `fillAnchorArtifacts` checks each record against its leaf
  (`anchorFillConflict`) and reports the ones that do not match in
  `AnchorFillResult.conflicts`. `getRecordAnchor`, optional, lets the fill
  check its stored progress against the records.

Pass `sourceLogKinds` the kinds whose leaves the store binds to its rows. The
default is `['evidence']`; a store that also anchors its audit and custody logs
passes, for example, `['evidence', 'audit', 'custody']`. A leaf of any kind
other than evidence must hash a preimage that can never be a record's canonical
bytes (a fixed `tzun-<kind>/<n>\n` tag, or a `tzun_lp` length prefix), because a
hosted origin is opaque and step 2b of
[Anchor §10.3](https://spec.tzun.ai/anchor/1/#s10-3) cannot read its kind. Remove a kind only
while no epoch is in flight. A chain change needs a new domain: the scheduler
refuses a store that published on another chain.

Which checkpoint of a source log the anchor log committed to last is read from
the bodies of the checkpoints its verified leaves hash to, not from
`getLastAnchoredCheckpoint`: every anchor leaf below the published size must
have exactly one stored checkpoint whose body hashes to it, and the store's own
answer for a log's last anchored checkpoint must be that one. A store that
loses or renumbers an anchored checkpoint stops its scheduler.

The configured publisher signs only inside its own window in the publisher
manifest ([Anchor §9](https://spec.tzun.ai/anchor/1/#s9)): `createAnchorScheduler` refuses a manifest that lists it on its
chain with every window closed, and a pass whose clock is outside its windows
signs nothing and raises `anchor_publisher_outside_window`.

## The conformance kit

`anchorStoreConformanceCases(harness)` returns the cases, one storage rule each.
A case opens a new store through the harness, checks its rule with
`node:assert`, and closes the store; it needs no test framework. Under jest:

```ts
import { anchorStoreConformanceCases, type AnchorStoreConformanceHarness } from '@tzun/sdk';

const harness: AnchorStoreConformanceHarness = {
  async open() {
    await resetSchema();                       // a new, empty store every case
    const view = deploymentView(pool, await mintIdentity());
    return {
      logs: view,
      anchors: view,
      raw: (sql, params) => ownerPool.query(numbered(sql), params), // `?` placeholders; as the tables' owner
      sourceLog: () => view.ensureStoreLog('audit'),             // default: ensureStoreLog('custody')
      storeRecords: (chainId, envelopes) => insertCaptures(chainId, envelopes),
      readRecord: (evidenceId) => readEnvelope(evidenceId),
      evidenceLog: (chainId) => scopeView.getEvidenceLog(chainId), // default: logs.getEvidenceLog
      evidenceLogPosition: (id) => scopeView.getEvidenceLogPosition(id), // default: logs.getEvidenceLogPosition
      evidenceLogCoverage: () => scopeView.getEvidenceLogCoverage(),     // default: logs.getEvidenceLogCoverage
      close: async () => undefined,
    };
  },
  without: { presetAnchors: 'capture refuses a record that arrives with an anchor' },
  fillStatusFromChunk: false,                  // the store rates a record's status by its own rule
};

for (const c of anchorStoreConformanceCases(harness)) {
  (c.skip ? it.skip : it)(c.name, () => c.run(), 60_000);
}
```

`runAnchorStoreConformance(harness)` runs every case and returns which passed,
failed and were skipped. The kit is `src/testing/anchor-store-conformance.ts`,
and the SDK's own SQLite and Postgres stores pass every case
(`tests/ts/anchor-store-conformance.test.ts`), which also shows the kit failing
stores that break a rule.

The hooks:

- `raw(sql, params)` runs one statement outside the interfaces (`?`
  placeholders), for the writes every writer must be refused: an UPDATE or
  DELETE of an insert-only or fixed row, and an INSERT at an explicit id. The
  kit's statements name the SDK's tables and columns (`logs`, `log_leaves`,
  `log_checkpoints`, `anchor_publications`, `anchor_wallets`,
  `anchor_wallet_txs`, and `anchor_lease`). The two INSERT cases write
  `logs (log_id, origin, kind, created_at)` at `log_id` 0 and
  `anchor_publications (id, epoch_id, anchor_size, p, kind, state,
  created_at, updated_at)` at `id` 0, then the same row with no id, which must
  be accepted and read last; a table that lacks one of those columns fails the
  case. `raw()` must connect as the owner of the tables: a refusal for want of
  a grant says nothing about the triggers. The kit checks this before it
  counts any refusal. It first updates the lease's holder through `raw()` and
  requires `getAnchorLease` to read the change. It then runs each attack
  against a row that does not exist, which must succeed: an UPDATE or DELETE
  with `... AND 1 = 0`, an INSERT as `INSERT ... SELECT ... WHERE 1 = 0`. On a
  store whose guards are row triggers, that shows `raw()` has the grant and
  the columns, so the refusal that follows is the guard's. The kit cannot show
  that a guard ignores the inserting session's name resolution (a temporary
  table of the table's name, or an operator or function on a schema the
  session puts ahead of `pg_catalog`): `raw()` runs as the owner and creates
  no temporary objects. That is the store's own test; the SDK's are
  `tests/ts/postgres-trigger-search-path.test.ts` and
  `tests/ts/postgres-backdated-id-guards.test.ts`. A store's Postgres guard
  ignores the session's name resolution when its function pins `SET
  search_path = pg_catalog, pg_temp` and names its tables through
  `TG_TABLE_SCHEMA`, as the SDK's do ([postgres-store.md](./postgres-store.md)).
- `storeRecords(chainId, envelopes)` stores records the way the store's
  capture path does, evidence leaves included, and `readRecord(evidenceId)`
  reads one back. The kit's records are genuine (digests and chain links
  computed by the engine), start at sequence number 1, and carry no anchor.
- `sourceLog()` returns a source log that `appendLogLeaves` writes to, other
  than the anchor log and the evidence logs.
- `evidenceLog(chainId)`, `evidenceLogPosition(evidenceId)` and
  `evidenceLogCoverage()` answer the chain reads, for a view that cannot.

`raw`, `storeRecords` and `readRecord` have no default. A harness that lacks
them names the reason in `without: { raw, records }`, and the cases that need
them carry it as `skip`; otherwise they must be present, or their cases fail.
`sourceLog` and the three chain reads default to the store's own methods. One
fill case stores records whose anchor is already `null`, `''` or `false`: the
first two count as absent and are filled, and `false` is kept. A store whose
capture path cannot take such a record names the reason in
`without: { presetAnchors }`.

What the kit compares is observable behaviour: what the interfaces return, and
whether a write is refused, with the store read back after every refusal to
show nothing changed. It does not match error messages, except that a fenced
epoch must throw `AnchorEpochFenceError`. It does not check revision rows, a
store's capture trigger beyond the leaves it writes, or SQL hygiene
(`search_path`, grants); those are the store's own tests.
