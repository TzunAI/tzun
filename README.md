# Tzun SDK

**Cryptographic evidence capture for human-in-the-loop AI decisions.**

TypeScript (`@tzun/sdk` and `@tzun/engine`, Node.js 22 or later) and Python
(`tzun-sdk`, Python 3.11 or later) · source published to be read, with no
licence granted ([License](#license)) · the specification at
[spec.tzun.ai](https://spec.tzun.ai)

When a human acts on an AI recommendation — approving a loan, rejecting a
candidate, overriding a triage score — Tzun records a tamper-evident **Decision
Evidence Object**: canonical serialization, a SHA-256 digest, an append-only
hash chain, and optionally a WebAuthn signature from the reviewer, an RFC 3161
timestamp, and an **AI Bill of Materials** describing the model that produced
the recommendation.

The point is not logging. It is that months later, someone who does not trust
you — a regulator, an opposing counsel, an auditor — can check the record.

```
decision ──▶ canonical bytes ──▶ SHA-256 digest ──▶ append-only chain
                                        │
                                        └──▶ RFC 3161 timestamp · WebAuthn signature · AI-BOM
```

- **Domain-agnostic.** Hiring, lending, insurance, healthcare, housing — the
  payload shape is yours; the integrity guarantees are the same.
- **Two implementations, one wire format.** TypeScript and Python produce
  byte-identical canonical bytes and digests, enforced by a conformance-vector
  suite in CI.
- **Storage-agnostic.** In-memory, SQLite, or Postgres; the mode controls
  attestation requirements, not the backend.

> **Status:** pre-1.0. APIs may change, and anything that changes a computed
> digest is a breaking change. See [`CHANGELOG.md`](./CHANGELOG.md).

## The API

The packages are not on npm or PyPI, and no licence to use this code is
granted ([License](#license)). Pilots receive the SDK under a written
agreement: **hello@tzun.ai**. The examples below show what an integration
looks like.

Capture a decision:

```ts
import { Tzun } from '@tzun/sdk';

const tzun = await Tzun.init({ dbPath: './tzun.db' });   // dev/local; see Modes

const result = await tzun.capture({
  aiSystemId: 'underwriting-assistant',
  aiOutput:   { recommendation: 'decline', score: 42, rationale: ['debt ratio'] },
  action:     'override',
  reason:     'Applicant provided updated income documentation.',
  decider:    { kind: 'human', id: 'acct:u-4821' },   // an opaque account id, never an email or a name
});

console.log(result.stored, result.envelope.integrity.canonicalDigest);
```

Read it back. Every local read carries the verdict of its own integrity check,
and never withholds the record:

```ts
const read = await tzun.get(result.envelope.payload.evidenceId);
// { envelope, verdict }, or null when the store holds no such record
read!.verdict.status;              // 'valid' | 'invalid' | 'unmeasured'
read!.verdict.digest;              // { status, stored, recomputed, reason? }
read!.verdict.custodyTrail;        // the custody_entries rows against the envelope's mirror
read!.verdict.chainLink;           // { status: 'unmeasured', reason: 'not_checked_on_read' } — see verify() below

const page = await tzun.list({ limit: 100, order: 'desc' });  // one { envelope, verdict } each
```

A record that fails comes back all the same, with `verdict.status: 'invalid'`
and the reason: a read that refused would break the recovery path on exactly
the records that need it, and one UPDATE could then deny reads of a whole
range. The checks cost one canonical serialization plus one SHA-256 of the
payload (~10 µs) and one indexed read of the record's custody rows — a round
trip on Postgres, which measures as ~+0.24 ms per `get()` and ~+0.06 ms per
record listed. `Tzun.init({ verifyReads: false })` turns them off; reads then
report every check `unmeasured` rather than passing.

Verify it later — including the chain link to its predecessor:

```ts
const verification = await tzun.verify(result.envelope.payload.evidenceId);
// { verified, storedDigest, recomputedDigest, chainLinkValid,
//   signatureValid, timestampValid, anchorValid, attestationStatus, ... }

const completeness = await tzun.verifyChainCompleteness();
// { valid, totalRecords, sequenceGaps, duplicateSequences, brokenLinks,
//   digestMismatches, digestSuperseded, timeRegressions, custodyTrailInvalid,
//   digestDiffersFromLoggedLeaf?, anchorStripped?, firstRecord, lastRecord, chainId }
```

`verifyChainCompleteness()` walks one chain. These findings make it `valid:
false`:

- `sequenceGaps`: a sequence number is missing (a record was deleted);
- `duplicateSequences`: a sequence number repeats or moves backwards (a record
  was inserted);
- `brokenLinks`: a `chainLink` is not `SHA-256(previousDigest ‖ currentDigest)`
  (a link was rewritten);
- `digestMismatches`: a record no longer hashes to its own stored digest (a
  payload was rewritten);
- `digestSuperseded`: a record's digest is not the one it was captured with,
  read from the append-only revision log (a payload was rewritten and its digest
  recomputed to match);
- `digestDiffersFromLoggedLeaf`: a record's digest is not the leaf the chain's
  evidence log holds at its position. Every local store keeps evidence logs;
  over the cloud transport this finding, and `anchorStripped`, are absent.

The others are reported without changing `valid`: `timeRegressions`, a
`capturedAt` earlier than the record before it (suspicious, but an NTP
correction produces one honestly); `custodyTrailInvalid`, a custody trail that
fails verification; and `anchorStripped`, a record missing the anchor its
finished epoch gave it. The digest check has no opt-out, and it costs one
canonical serialization plus one SHA-256 per record — ~10-16 µs each, so ~3 ms
for a 250-record chain and ~205 ms for 20 000.

`capture()` does **not** throw when storage rejects a record — it returns
`{ stored: false, failure }` so your application keeps working. Check `stored`.

### Python

The same capture in Python. `SqliteAdapter` needs the package's `sqlite` extra
(aiosqlite).

```python
import asyncio

from tzun_sdk import Tzun
from tzun_sdk.storage import SqliteAdapter


async def main() -> None:
    tzun = await Tzun.init(storage=SqliteAdapter("./tzun.db"))
    result = await tzun.capture(
        ai_system_id="underwriting-assistant",
        ai_output={"recommendation": "decline", "score": 42},
        action="override",
        reason="Applicant provided updated income documentation.",
        decider={"kind": "human", "id": "acct:u-4821"},  # an opaque account id, never an email or a name
    )
    print(result.evidenceId, result.canonicalDigest)
    await tzun.close()


asyncio.run(main())
```

[`python/README.md`](python/README.md) covers the Python package.

## Modes

Mode controls **attestation enforcement**, not storage. Storage is chosen
independently: `dbUrl` → Postgres, `dbPath` → SQLite, neither → in-memory in `dev` mode.
A Postgres store is owned by the role the SDK connects as, and asks two
things of the other database roles that write it (no temporary tables, no
`CREATE` on the store's schema or on a schema in the SDK role's
`search_path`): [docs/integration/postgres-store.md](./docs/integration/postgres-store.md).

| Mode | Chosen when | Attestation |
|---|---|---|
| `dev` | no API key and no URL | none required |
| `local` | explicit | RFC 3161 timestamp for every record |
| `cloud` | `apiKey` only | RFC 3161 timestamp for every record |
| `self-hosted` | `apiKey` + `apiUrl` | RFC 3161 timestamp for every record |

On a local store (`dbUrl`, `dbPath`) a production mode obtains the timestamp
itself, and by default it is **deferrable**: a capture tries each timestamp
authority in turn, and when none of them issues a token the decision is still
stored, with `attestationStatus: 'pending'`, and the SDK retries it in the
background until it has one; it stays `'pending'` until then. A retry pass
runs every minute and requests attestation for at most 100 records; while
every authority is failing the wait doubles after each pass, up to 15 minutes.
`close()` waits for a pass in flight.

```ts
const tzun = await Tzun.init({
  mode: 'local',
  attestation: { retry: { intervalMs: 30_000, batchSize: 500, maxBackoffMs: 600_000 } },
});
tzun.getAttestationRetryState(); // { running, nextDelayMs, lastPass, ... }
```

`retry: { intervalMs: 0 }` or `{ autoStart: false }` leaves retrying to you:
call `tzun.retryPendingAttestations({ limit })`, which never overlaps a
scheduled pass. The retry runs whether or not the monitoring scanner is
enabled. To refuse a capture that cannot be timestamped at once instead, make
the timestamp a hard requirement:

```ts
await Tzun.init({ mode: 'local', attestation: { require: ['timestamp'] } });
// a TSA outage now returns { stored: false, failure: attestation_failure }
```

A production config that never asks for a timestamp (`require: []`, or a
`require` list without it and a `deferrable` list without it) is refused at
`init()`. On the cloud transport (`apiKey`) the hosted service's attestation
worker timestamps every record, and the SDK makes no TSA request unless
`attestation` is configured.

## Signing a decision (WebAuthn)

A WebAuthn signature is only evidence about a decision if the reviewer's
authenticator signed **that decision**. A signature over a random login nonce
verifies against every record equally, which is the same as verifying against
none — so the challenge is derived from the record's canonical digest:

```
challenge = base64url( SHA-256( "tzun-decision-v1" || canonicalDigest ) )
```

The digest covers the record's sequence number, id and capture time, so it does
not exist until the record has been built at a chain position. The ceremony
therefore comes **after** the record, not before:

```ts
// 1. build the record the next capture() would build — nothing is stored
const prepared = await tzun.prepareAssertionChallenge(decision);

// 2. run the ceremony against THAT record
const options = await webauthn.startAuthentication(credentialId, {
  digest: prepared.digest,
});                                     // options.challenge === prepared.challenge
const { artifact } = await webauthn.verifyAssertion(browserResponse, {
  digest: prepared.digest,
});

// 3. capture the record the reviewer actually signed
await tzun.capture(
  { ...decision, attestationInputs: { webauthnAssertion: artifact } },
  { prepared },
);
```

If another writer appends between steps 1 and 3 the record moves to a new chain
position, its digest changes, and the capture is **refused** —
`chain_conflict` with `retryRefused: 'caller_attestation_is_digest_bound'` —
rather than storing a genuine signature that reads as forged against its own
record. Re-run the ceremony and capture again.

Verification checks the binding with nothing in hand, and the signature itself
when you supply the credential store:

```ts
const v = await tzun.verify(evidenceId, undefined, {
  attestation: { credentialStore, allowedOrigins: ['https://app.example'], rpId: 'example' },
});
v.signatureValid   // true | false | null
v.signatureReason  // 'assertion_not_bound_to_digest' | 'challenge_mismatch' | …
```

`signatureValid: null` is never a pass — it means "not verified", and the
reason says why. An assertion whose challenge is not the one derived from the
record's digest reports `assertion_not_bound_to_digest`; `verified` is
unaffected, because it means "the record and its chain link are intact".

## Timestamp authorities

Every production mode obtains an RFC 3161 timestamp for every record, which
means an **independent third party** attests that a record's digest existed at
time T.
Tzun does not operate that party and never will: a timestamp Tzun issued over
evidence Tzun's SDK captured would be circular, and it is the first thing
opposing counsel would attack. The authority is yours to choose.

**The default is FreeTSA, falling over to Sectigo.** With nothing configured,
a capture asks FreeTSA for its token and asks Sectigo only when FreeTSA does
not issue one (an error, a bad reply, a timeout, or FreeTSA's circuit breaker
being open). Verification with nothing configured trusts exactly those two
roots. Both halves are derived from one list, `DEFAULT_TRUST_ANCHOR_AUTHORITIES`,
so a token the default capture obtains always chains to a root the default
trust store holds. If FreeTSA hangs rather than refusing, it is cut off at its share of the
timestamp budget (10 s of the default 20 s) and Sectigo gets the rest.

**What a TSA is told about you: only a hash.** An RFC 3161 request carries a
`MessageImprint` — a hash algorithm OID and a digest — and a random nonce, and
nothing else (RFC 3161 §2.4.1). Not the decision, not the payload, not the
actor, not the model, not the record. The authority cannot invert SHA-256, so
the cost of a second authority is *timing and volume* metadata — that your
deployment asked for N timestamps at these moments — never content. Under the
default, Sectigo learns even that only for the captures FreeTSA could not
serve.

**Choosing other authorities: two settings, and they must agree.** Capture asks
an authority for a token; verification decides whose tokens it accepts. Setting
`rfc3161Url` or `rfc3161Urls` replaces the default capture list entirely
(`rfc3161Url` alone means exactly one authority and no failover), and the
default trust store still holds only FreeTSA's and Sectigo's roots. Change only
the capture side and every capture succeeds while the records read
`untrusted_chain` the first time anyone checks them.

```ts
import { Tzun, timestampAuthorityUrls, verifyAttestation } from '@tzun/sdk';

const AUTHORITIES = ['freetsa', 'digicert'];

const tzun = await Tzun.init({
  attestation: { timestamp: { rfc3161Urls: timestampAuthorityUrls(AUTHORITIES) } },
});                                                      // capture side

const v = await verifyAttestation(
  envelope.nonRepudiation,
  envelope.integrity.canonicalDigest,
  undefined,
  { authorities: AUTHORITIES, capturedAt: envelope.payload.capturedAt },
);                                                       // verify side
v.timestampValid   // true | false | null
v.timestampReason  // 'untrusted_chain' | 'imprint_mismatch' | …
```

One constant, named on both lines. That is the whole discipline: if you have to
write the capture list and the trust store as two unrelated expressions, they
drift, and the drift is silent until somebody verifies.

`authorities` takes a registry key **or** the URL already sitting in your
config, so `{ authorities: ['https://timestamp.sectigo.com'] }` works too. An
unknown name throws immediately rather than being ignored — a silently dropped
authority does not fail at start-up, it fails months later on evidence that is
perfectly genuine. Process-wide, `TZUN_TSA_AUTHORITIES=freetsa,digicert` does the
verify half with no code change, and `TZUN_TSA_TRUST_ANCHORS` still takes raw
PEM or file paths for a root this registry does not ship.

### The registry

Each endpoint below was probed on 2026-09-12 with a real `openssl ts -query`
over a freshly generated arbitrary SHA-256 and returned `Status: Granted` with
the imprint and per-request nonce echoed. **All of them are free and
unauthenticated** — no account, no API key, no payment — including Sectigo and
DigiCert, whose certificate businesses are commercial but whose timestamping
endpoints are open to anyone.

| Key | Endpoint | Operator | TLS | Notes |
|---|---|---|---|---|
| `freetsa` | `https://freetsa.org/tsr` | FreeTSA (DE) | yes | **Default primary.** Exists for exactly this use; outside the commercial CA ecosystem. |
| `sectigo` | `https://timestamp.sectigo.com` | Sectigo (GB) | yes | **Default fallback**, asked only when FreeTSA does not issue a token: different operator, country and hierarchy, and the only other TLS endpoint found. Slow and variable — four samples ran 514 ms, 524 ms, 3.4 s, 2.7 s. |
| `digicert` | `http://timestamp.digicert.com` | DigiCert (US) | no | Fast (84 ms). Port 443 has no listener at all. |
| `sslcom` | `http://ts.ssl.com` | SSL Corp (US) | no | `:443` answers TLS but with a certificate that does not cover the hostname. |
| `globalsign` | `http://timestamp.globalsign.com/tsa/r6advanced1` | GlobalSign (BE) | no | EU-operated. |
| `certum` | `http://time.certum.pl` | Certum / Asseco (PL) | no | EU-operated. Certum's **qualified eIDAS** service is a separate paid product; this free endpoint is not it. |
| `identrust` | `http://timestamp.identrust.com` | IdenTrust (US) | no | Fast. Its tokens carry no root, so the bundled anchor is the only way one can verify. |
| `apple` | `http://timestamp.apple.com/ts01` | Apple (US) | no | Fastest probed, but **last resort**: it exists for Apple code signing, its policy OID is the placeholder `1.2.3`, and Apple publishes no reliance terms. |
| `mesign` | `http://tsa.mesign.com` | MeSince (CN) | no | Slowest by an order of magnitude (2 s) and its root is not in the public trust programmes. |
| `entrust` | `http://timestamp.entrust.net/TSS/RFC3161sha2TS` | **relays Sectigo** | no | Not an independent authority — see below. |
| `aimoda` | `http://rfc3161.ai.moda` | **relays DigiCert** | no | Not an independent authority — see below. |

**Two of these are not authorities.** Entrust's public timestamp endpoint
returns tokens signed by *Sectigo Public Time Stamping Signer R37* under
Sectigo's policy OID; `rfc3161.ai.moda` is a load balancer that answered the
probe with DigiCert's signer. Pairing either with the operator it fronts looks
like two independent attesters and is one: the outage that takes out the
operator takes out both, and an extra organisation sees every digest for
nothing. Both are recorded with `relayOf` and excluded from
`independentAuthorities()`, which is the list to build a failover set from.

Plaintext (`tls: false`) does not leak your records — the body is still only a
hash — but it does tell anyone on the path that a timestamp was requested and
for which digest. An attacker who swaps the response cannot forge anything: the
verifier checks that the token's imprint equals your digest.

### Why the default trust store is exactly the default pair

All nine roots ship inside the package, so naming another authority costs one
line and no PEM hunting. Only two are **trusted** unless you say otherwise:
the roots of the two authorities the default captures against.

- **Every trusted root can make a token verify.** A root whose key is
  compromised — or any TSA key it certifies — can sign a token with any
  genTime it likes, a backdated one included, and the verifier accepts it. So
  the default trusts the roots it captures against and none of the other
  seven.
- **A narrow store does not stop someone who can rewrite your store, and does
  not claim to.** FreeTSA is a free public service, so an attacker who
  rewrites a stored envelope can also get a genuine FreeTSA token over the
  rewritten digest. What catches that rewrite is elsewhere. The fresh token's
  genTime is the day of the rewrite, and `verifyAttestation`, given the
  record's `capturedAt`, compares it with the genTime inside the token (a
  token newer than its record is reported as `capturedAtSkewMs`, not failed,
  because a retried attestation looks the same). And the rewrite breaks the
  chain: the next
  record's link was computed over the original digest, and a rewrite that
  reseats that link too shows up in `verifyChainCompleteness()` as
  `digestSuperseded`.
- **A wider store would buy no resilience.** Resilience comes from the
  capture-side list. Trusting an issuer does not conjure a token you never
  obtained.

So: ship broadly, trust what you capture against, and name anything else on
both sides.

### Anchors are pinned, not discovered

The certificate that arrives *inside* a token is usually the wrong thing to
pin. Sectigo's token carries a Public Time Stamping Root R46 cross-signed by
USERTrust; DigiCert's carries a Trusted Root G4 cross-signed by DigiCert
Assured ID Root CA. Pin those and your trust path runs up into a
general-purpose public CA — silently, because tokens keep verifying. Every
anchor here is instead the **self-signed root** that stops the path at the
timestamping hierarchy, fetched from the CA's own published AIA `caIssuers`
URL, with its provenance in the PEM header and its SHA-256 asserted by
`tests/ts/tsa-registry.test.ts` against a real token from the live endpoint.
Swap a PEM and the suite fails.

For a TSA this registry does not ship — a contracted provider, a qualified
eIDAS one, an internal one — register it yourself:

```ts
import { addTimestampAuthority } from '@tzun/sdk';

addTimestampAuthority({
  key: 'acme-qualified',
  url: 'https://tsa.acme.example/rfc3161',
  operator: 'Acme Qualified TSA',
  tls: true,
  access: 'commercial',
  anchorCommonName: 'Acme Timestamping Root',
  anchorPem: fs.readFileSync('acme-root.pem', 'utf-8'),
  policyOid: '1.3.6.1.4.1.99999.1.1',
  publiclyTrustedRoot: true,
  probedAt: '2026-09-12',
  note: 'Contracted, SLA-backed.',
});
```

A token verifies only when it passes the token checks of
[Anchor §10.5](https://spec.tzun.ai/anchor/1/#s10-5), which
[Record §10](https://spec.tzun.ai/record/1.0/#s10) applies to a record's own
token. Every authority above passes them:
- it is a DER `TimeStampResp` that carries its signer's certificate;
- its imprint is SHA-256;
- a `signingCertificate` or `signingCertificateV2` attribute names that
  certificate, whose one extendedKeyUsage, marked critical, is
  `id-kp-timeStamping`;
- every certificate between the signer and the root is a CA.

Capture checks every token it obtains against the same rules: a token that
breaks one is still stored, and the capture reports
`attestation_timestamp_nonconformant` on `onLog` (or the console), naming the
authority and the rule. Run a trial capture against a new authority, and watch
for that event, before relying on it.

None of the free endpoints above offers an SLA, and FreeTSA's operator asks
users not to abuse the service. A deployment with a real evidentiary or
retention requirement should put a contracted authority at the head of its list
and keep a free endpoint as the tail.

## AI Bill of Materials

A capture can carry a content-addressed, tamper-evident record of the model
behind the recommendation — vendor, model, version, inference parameters, and
where known its lineage and integrity tier.

Eight inference vendors are covered through one extraction API — OpenAI, Azure
OpenAI, Anthropic, AWS Bedrock, GCP Vertex, Azure AI Foundry, NVIDIA NIM and HF
Inference Endpoints:

```ts
import { singleModel } from '@tzun/sdk';

const response = await openai.chat.completions.create(params);
const aiBom = await tzun.hook('openai', params, response);   // null when the model cannot be recorded
await tzun.capture({ ...decision, contributions: aiBom === null ? null : singleModel(aiBom) });
```

A record states its model as a step of `contributions`
([Record §7](https://spec.tzun.ai/record/1.0/#s7)); `singleModel()` builds the
list of one step that a single model call makes. Or wrap the client once and
pass `tzun_capture` per call with `tzun.attach(client)`. See the
[AI-BOM runbook](docs/integration/ai-bom-runbook.md).

## Architecture

Five layers:

| Layer | Where | What |
|---|---|---|
| **Evidence engine** | `packages/engine` → `@tzun/engine` | Canonical serializer, digest pipeline, chain, schema registry, verification. Pure functions, no I/O, zero runtime dependencies. |
| **Attestation** | `src/attestation` | WebAuthn, RFC 3161, Merkle trees, checkpoints, and anchor verification (`nonRepudiation.anchor`, tzun-anchor/1; never on the capture path). |
| **Anchoring** | `src/anchoring` | The anchor scheduler `Tzun.init({ anchoring })` runs on a SQLite or Postgres store: one `evm-calldata/1` transaction per epoch of the store's logs, through a crash-safe outbox, signed by a private key or an external signer (an ethers `Signer`, a KMS or HSM signer), and each record's anchor filled once the block is final. |
| **SDK** | `src/sdk` | The `Tzun` class: `init`, `capture`, `get`, `list`, `verify`, `exportEvidence`, `exportBundle` (a `b1` proof bundle; `verifyBundle()` checks one), `hook`, `attach`. |
| **API** | `src/api` | Thin Express REST layer for self-hosted deployments. |

## Documentation

| | |
|---|---|
| The specification: record format, verification, proof bundle, anchor format, tree profile, conformance vectors | [spec.tzun.ai](https://spec.tzun.ai) |
| Python package | [`python/README.md`](python/README.md) |
| AI-BOM integration | [`docs/integration/ai-bom-runbook.md`](docs/integration/ai-bom-runbook.md) |
| Postgres stores and their database roles | [`docs/integration/postgres-store.md`](docs/integration/postgres-store.md) |
| Anchoring a store kept outside the SDK | [`docs/integration/anchor-store.md`](docs/integration/anchor-store.md) |
| Credential storage for signature checking (design note) | [`docs/design/credential-store.md`](docs/design/credential-store.md) |
| How the repository is built and tested, and how contributions are handled | [`CONTRIBUTING.md`](./CONTRIBUTING.md) |
| Security policy | [`SECURITY.md`](./SECURITY.md) |
| Support channels | [`SUPPORT.md`](./SUPPORT.md) |
| Changelog | [`CHANGELOG.md`](./CHANGELOG.md) |

## Security

Tzun's value is that the record can be checked by someone who does not trust
the person who produced it. If you find a way to forge, alter or silently drop
evidence — or a verifier that reports success without performing its check —
please report it privately. **Do not open a public issue.** See
[`SECURITY.md`](./SECURITY.md).

## License

No licence is granted. The source is published here so that it can be read:
[`LICENSE.md`](./LICENSE.md) grants no right to copy, modify, distribute or use
the SDK, the engine or the Python package, and [`NOTICE`](./NOTICE) says the
same.

The packages are not on npm or PyPI. Pilots receive the SDK under a written
agreement.

The conformance vectors in `vectors/` are CC0-1.0
([`vectors/LICENSE`](./vectors/LICENSE)), the root certificates bundled for
offline timestamp verification belong to their issuers
([`LICENSES/LicenseRef-Root-Certificates.txt`](./LICENSES/LicenseRef-Root-Certificates.txt)),
and the code of conduct is the Contributor Covenant 2.1 under CC BY 4.0
([`LICENSES/CC-BY-4.0.txt`](./LICENSES/CC-BY-4.0.txt));
[`REUSE.toml`](./REUSE.toml) records the terms of every path. The DEO
specification is published at [spec.tzun.ai](https://spec.tzun.ai) under
CC BY 4.0.

This section and [`NOTICE`](./NOTICE) are descriptive: `LICENSE.md` governs.

For a licence: **licensing@tzun.ai**. For pilots or commercial enquiries:
**hello@tzun.ai**.
