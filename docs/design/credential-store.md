# Credential storage for signature checking at rest

This note explains how the TypeScript SDK stores the WebAuthn credentials a
verifier needs, why it is shaped the way it is, and what is not yet built.

## The question

Signature checking at rest needs key material the SDK does not hold. Should
there be a credential store, and where should it live?

The short answer is that two things are needed that are easily mistaken for
one: a **durable directory** (operational — who may sign, which keys are live,
is this one revoked) and an **anchored registration record** (evidentiary —
which key was valid at the moment this decision was signed, provable to
someone with no access to the operator). The first is a database, and the SDK
ships one. The second is an evidence record, and it is not a database problem
at all.

## Why a durable store

A credential store held only in memory loses every registered key when its
process restarts. The evidence records signed by those keys stay in the chain;
the keys that would let anyone check those signatures do not.

With no key material, `verifyAttestation()` reports `signatureValid: null`
with `signatureReason: 'no_credential_store'`. That is the honest answer, but a
signature nobody can ever check is not evidence of a signature; it is a claim
that one existed.

## The real design tension

An evidence product's verification should be **self-contained**: hand someone
an export bundle years from now, with no access to the systems that produced
it and no expectation that the company that ran them still exists, and they
should be able to check the signature. That pulls toward putting the public key
in the record.

But **a record that carries both the signature and the key it verifies against
proves only internal consistency.** A forger supplies both. Self-contained
verification of a self-supplied key pair is a tautology dressed as a proof.

So the key must be **anchored to something the forger does not control**. That
is the whole problem, and it is the axis the four options below differ on.

---

## Option 1 — Persistent credential store in the SDK

A table beside the evidence: append-only, revocations recorded, `verify()`
self-serves.

**Consequences.** Cheap, obvious, and it fixes the operational failure outright:
keys survive restarts, they live in the same file/database as the evidence, so
they are backed up, restored and moved together. `verify()` stops answering
"cannot check".

**What it does not do.** Verification now depends on **the store being present
and honest**. An offline auditor does not have it. Worse, an operator with write
access to that store could register a key *today*, backdate its `registeredAt`,
and manufacture a signature over an old decision — the store is the only witness
to when the key existed, and the store is the thing under suspicion. Append-only
triggers raise the cost but do not close it: a table owner can drop a trigger.

**Verdict: necessary, insufficient.** Built: the SQLite and Postgres stores each
carry a durable directory, and the memory store a faithful double of one (see
[What is built](#what-is-built)).

## Option 2 — The public key travels in the attestation artifact

Put the COSE key (or SPKI) next to the assertion in
`nonRepudiation.webauthnAssertion`.

**Consequences.** Offline-verifiable with no systems access. Fixes the "years
later, company gone" case for *mechanical* verification.

**What it does not do.** Unanchored. It proves "whoever made this record had a
key pair and used it", which is a statement about nobody. It is *only* useful
once the key is anchored by something else — and then it is useful, because it
removes the auditor's dependency on reaching the operator's directory at
verification time.

**Verdict: a carrier, not a proof.** Adopt it *with* option 3, never instead.
Not yet built: the assertion a record carries today holds the signature, the
credential id, the algorithm, `authenticatorData` and `clientDataJSON`, and no
public key.

## Option 3 — Credential registration is itself an evidence record in the chain

Registering a credential writes an evidence record: `{credentialId, publicKey,
algorithm, userId, registeredAt}` captured through the normal capture path, so
it gets a sequence number, a chain link, a canonical digest and an RFC 3161
timestamp. Capture does not anchor it: an anchor (`nonRepudiation.anchor`,
tzun-anchor/1) covers a batch of records after they are stored.

An auditor then checks, with no access to the operator:

1. this assertion verifies against key **K**;
2. **K** was registered in record **R**;
3. **R** is in the chain, its digest is covered by an anchored Merkle root, and
   its timestamp verifies.

The key is anchored by exactly the machinery that already anchors everything
else — no new trust root, no new infrastructure, no second thing to explain to
a regulator. And the backdating attack dies: a registration record cannot be
inserted into the past without breaking the chain link and contradicting an
anchor the forger does not control. Tying a signature to the time its key was
registered or revoked also needs a bound on when the signature was made, which
the signed record's own timestamp does not give (see
[Revocation must not be retroactive](#revocation-must-not-be-retroactive)).

Revocation is the same move: a revocation record in the chain, timestamped. "Was
this key live when it signed?" becomes a comparison of two anchored timestamps
rather than a lookup in a mutable column.

The record format already has a place for the reference. A record's decider
carries a `credential` member, "the digest of the decider's credential
registration" ([Record §6.1](https://spec.tzun.ai/record/1.0/#s6-1)), and
version 1.0 of the specification does not read the registration it names
([Record §6.2](https://spec.tzun.ai/record/1.0/#s6-2);
[Verification §4.8](https://spec.tzun.ai/verification/1.0/#s4-8)).

**Costs, honestly.** Registration becomes a chain append, which means it takes a
chain-head compare-and-swap and can conflict; it means a registration ceremony
now depends on the attestation path being up (a timestamp failure must degrade,
not block enrolment); and it puts a `userId` and a public key into the evidence
chain, which is a data-retention and GDPR surface to look at before building
it. It also means the credential lives in **two** places — the chain
(evidentiary) and the directory (operational) — and something has to keep them
consistent. The directory becomes a *derived* index over the chain, which is a
clean story but a real piece of work.

**Verdict: recommended, and the thing that actually answers the question.** Not
yet built: it changes the capture path, and the retention question deserves an
answer first.

## Option 4 — The combination, and what a customer with an IdP does instead

The design combines the three:

- **Durable directory** (option 1) for the operational question, behind an
  interface, so it can be the SDK's or the customer's.
- **Key in the bundle** (option 2) so an auditor need not reach the operator.
- **Anchored registration** (option 3) so the bundled key means something.

Of these, the durable directory is built; the other two are not yet built.

A customer who already runs Okta/Entra/a passkey directory will not accept a
second credential store, and should not have to. The durable directory is
`AsyncCredentialStore`, eight methods, and nothing in its shape assumes a
database:

```ts
interface AsyncCredentialStore {
  register(credential: StoredCredential): Promise<void>;
  getByCredentialId(id: string): Promise<StoredCredential | undefined>;
  getByUserId(userId: string): Promise<StoredCredential[]>;
  revoke(id: string, options?: RevocationOptions): Promise<void>;
  updateCounter(id: string, newCounter: number): Promise<void>;
  list(): Promise<StoredCredential[]>;
  history(id?: string): Promise<CredentialEvent[]>;
  snapshot(ids?: readonly string[]): Promise<CredentialStore>;
}
```

`history()` is the one method an IdP may not be able to answer fully; returning
the registration and revocation it does know about is an acceptable partial
answer, and the anchored chain records of option 3 are where the complete
history would live.

Today the SDK obtains its directory only from its own storage
(`tzun.getCredentialStore()`), and the package root does not export
`AsyncCredentialStore` by name. A customer with their own directory implements
the synchronous `CredentialStore` interface, which the package root does
export, over a point-in-time read of it, and passes that where the SDK accepts
one: `tzun.verify(id, undefined, { attestation: { credentialStore } })`,
`ScheduledScanner`'s attestation dependencies, and `new TzunWebAuthn(config,
credentialStore)`.

Note the split that makes this work: the **verifier** consumes a *synchronous*
`CredentialStore`, because `verifyAttestation()` and `ScheduledScanner` are
synchronous at the point of lookup. `snapshot()` bridges the two — one async
read of the directory, then a frozen sync view for the whole pass. Frozen on
purpose: a scan of 10,000 records that re-reads the directory per record can
return two different verdicts for two records signed by the same key, because
somebody revoked it halfway through the scan.

---

## The four semantics questions

### Revocation must not be retroactive

A key revoked in June must not invalidate what it signed in March. A cancelled
passport does not invalidate the visa stamps it collected while valid.

A `status: 'active' | 'revoked'` field records only the key's state **now**.
A verifier that returns `signatureValid: false` / `'revoked_credential'` on it
reports every record the key ever signed as **forged** the moment the key is
revoked, and the verdict on a record *changes* because of something that
happened after it was captured. That is not a conservative default; it is a
false accusation, and it is the single most damaging thing an evidence verifier
can do.

The store records `revokedAt` (caller-supplied, defaulting to now, because the
key was untrustworthy from the moment it was lost, not from the moment IT
processed the ticket), and `src/attestation/credential-store.ts` provides:

```ts
credentialStatusAt(cred, at): 'active' | 'revoked' | 'not_yet_registered'
```

`not_yet_registered` is the genuinely suspicious case — a signature that
predates its own key.

**Known limitation.** `verifySignature()` in
`src/attestation/verify-attestation.ts` still consults `status`, not
`credentialStatusAt`. So today a revocation makes every earlier signature by
that key report as `revoked_credential`. Applying revocation as of the signing
instant needs a decision on *which instant* to compare against — the record's
`capturedAt` (supplied by the writer: hashed, so it cannot change after
capture, but nothing independent vouches for it) or its RFC 3161 timestamp
(issued by an independent authority, sometimes absent, and dating the record
rather than the signature). Where there is no defensible instant, the honest
verdict is `null`, not `true`.

### Key rotation

Rotation is a **new credential id**, never a rewrite. The event log enforces it:
the first `registered` event fixes identity and key material, and
`credential_events` refuses UPDATE at the database level. It also refuses an
insert written ahead of a registration: on SQLite an explicit `seq` below the
last; on Postgres a `seq` below one the insert can see or one its sequence did
not hand the insert, and every event takes a `seq` drawn as it is written, after
every event committed before it. On SQLite it refuses an insert that would
replace a registration too (REPLACE over its `seq` or `event_id`). So no second
key can take the first registration's place. An old key is revoked with its
instant, so the records it signed keep verifying once revocation is applied as
of the signing instant, and nothing signed after the rotation verifies against
it. `getByUserId()` returns every credential registered to a person, active and
revoked, which is what an auditor asking "who could sign in March" needs.

### The WebAuthn signature counter

The counter is a **clone-detection signal**, not evidence. If it fails to
increase, either the authenticator does not implement one (many do not; it stays
0) or there are two copies of it in the world.

An `updateCounter()` that assigns whatever arrives lets a cloned authenticator
presenting a *lower* counter write the lower value into the store — and the
next assertion from the genuine device then looks like an increase. The signal
is erased before anyone can look for it.

Every store keeps a monotonic high-water mark and records the regression
(`counterRegressedAt`, and in the durable stores a `counter_regressed` event
row). It deliberately does **not** throw: refusing the ceremony on a counter
regression is a policy decision for the relying party. The failure to avoid is
silently swallowing the signal, not failing to act on it.

### What the export bundle must carry

`exportEvidence()` returns an `ExportedEvidenceEnvelope`: `{envelope,
resolvedModelDescriptors, resolvedAgentDescriptors, exportedAt, exportedBy,
verdict, chain, custody, assertionProvenance, server}`. It resolves the
**AI-BOM** (model and agent descriptors), the record's **predecessor** and its
**custody ledger** for offline verification, and states where the record's
WebAuthn ceremony ran and what kind of key signed (`assertionProvenance`). It
carries **no key**. An auditor with it can re-hash the payload, check the
descriptors, recompute the chain link and the custody trail, and cannot check
the signature in `webauthnAssertion`.

The `b1` proof bundle (`exportBundle()`,
[Bundle b1](https://spec.tzun.ai/bundle/b1/)) adds the record's anchoring
material, and reserves slots for sign-off material: `credentials` and
`relatedRecords`, which the SDK's bundle types describe as the slots for the
sign-off credentials and for their registration and revocation records. An
exporter of `b1` writes `null` in both
([Bundle §8](https://spec.tzun.ai/bundle/b1/#s8)), and a verifier of this
version never treats a filled slot as a pass: a `credentials` slot that is not
`null` makes `signoff.key` abstain
([Verification §4.5](https://spec.tzun.ai/verification/1.0/#s4-5)). Carrying
credential material in those slots is not yet built.

What they need to carry:

- the **public key** for every credential the bundled records reference;
- the **registration record(s)** for those credentials — the option-3 evidence
  records, with their own digests, chain links and timestamps;
- the **revocation records**, if any, so the auditor can apply revocation as of
  the right instant themselves rather than trusting a status the exporter
  computed;
- the **anchor material** covering those records: Merkle proof and root, and the
  RFC 3161 tokens.

---

## What is built

Reachable from the package root (`@tzun/sdk`):

| | |
|---|---|
| `CredentialStore` | in type position, the synchronous interface: lookup plus the three ceremony writes (register, revoke, bump the counter). In value position, a deprecated alias for the in-memory implementation, so `new CredentialStore()` gives an in-memory store |
| `StoredCredential` | the credential type: key material, `status`, `registeredAt`, `revokedAt`, `revocationReason`, `counterRegressedAt` |
| `tzun.getCredentialStore()` | the durable directory (`AsyncCredentialStore`) behind the instance's storage, or `undefined` on the cloud transport |
| `tzun.verify(id, undefined, { attestation: { credentialStore } })` | checks the record's signature against a synchronous `CredentialStore`, for example a `snapshot()` of the directory |
| `TzunWebAuthn` | the ceremony helper; takes a synchronous `CredentialStore` and defaults to an in-memory one |

Internal (in `src/attestation/credential-store.ts` and
`src/storage/credential-stores.ts`, not exported from the package root):

| | |
|---|---|
| `CredentialLookup` | sync read surface — all a verifier needs |
| `InMemoryCredentialStore` | the reference implementation of `CredentialStore` |
| `CredentialSnapshot` | frozen read-only view for one verification pass; writes throw |
| `AsyncCredentialStore` | the durable directory interface |
| `MemoryCredentialStore` / `SqliteCredentialStore` / `PostgresCredentialStore` | its three implementations, one per storage adapter |
| `CredentialStoreProvider`, `credentialStoreFor(storage)` | how the SDK finds a storage adapter's directory |
| `credentialStatusAt()` | as-of revocation semantics |
| `foldCredentialEvents()` | the single state derivation all three backends share |

**Schema** (created beside the evidence when the SQLite or Postgres store is
opened):

- `credential_events` — append-only. Registration is a row, revocation is a row,
  a counter regression is a row. UPDATE, DELETE and (Postgres) TRUNCATE refused
  by triggers, matching `custody_entries`. On SQLite the triggers also refuse
  an insert over an existing `seq` or `event_id` whatever its conflict clause,
  a row at a negative `seq`, and an explicit `seq` below the last. On Postgres
  `credential_events_block_backdated_seq` refuses a `seq` below one the INSERT
  can see, or one the sequence did not hand the insert, and gives every event a
  `seq` it draws as the event is written, so the event lands after every event
  committed before it.
- `credential_counters` — the one genuinely mutable thing. An anti-replay
  high-water mark, not evidence, so it is a small mutable table rather than a
  row per signature.

**Why an event log rather than a mutable credential row.** A `status` column
answers "is this key good now". An auditor asks "was it good on the 4th of
March, when it signed this". Only a log answers that — and a log of rows that
carry their own timestamps is the first half of option 3 already in place.

**Deliberately not on `StorageAdapter`.** `CredentialStoreProvider` is an
optional capability interface. The cloud `HttpStorageAdapter` holds no
credentials, and widening the main interface would force it and every future
adapter to grow a method that throws.
`VerifyingStorageProxy` passes its inner adapter's directory through when the
inner adapter has one. `credentialStoreFor(storage)` returns `undefined` for an
adapter with none, and `undefined` is a real answer: it is what keeps
`no_credential_store` reachable instead of the SDK inventing a verdict it
cannot support.

## Not yet built

- **Registration as an evidence record in the chain** (option 3). The piece
  that actually answers the question; it waits on the retention question and
  changes the capture path.
- **Revocation as of the signing instant in `verifySignature()`.** Until then a
  revocation makes earlier signatures by that key report as revoked (see the
  known limitation above).
- **The public key in the attestation artifact** (option 2).
- **Credential material in the proof bundle**: public keys, registration and
  revocation records and the anchor material covering them, in the `b1`
  bundle's reserved slots, which carry `null` today.
- **An async registration path through `TzunWebAuthn`.** It writes to a
  synchronous `CredentialStore`, so registering into a durable directory needs
  a path through it that awaits the directory.
- **A way to hand the SDK a customer's own directory.** The SDK reads its
  directory only from its own storage adapter, and the package root does not
  export `AsyncCredentialStore`.
