/**
 * The custody entry hash — ONE implementation, shared by every writer and
 * every reader, applying the same rule as the hosted service.
 *
 * A 'relinked' / 'chain_forked' / 'reviewed' custody entry is appended to
 * `envelope.custodyChain`, which sits OUTSIDE the v1.0 hashed field set
 * (types/evidence.ts, schema-registry.ts) and stays there — widening the
 * digest takes a new schema version. As an unhashed object, a custody entry
 * could be rewritten, reordered or deleted without `verifyEnvelope` seeing
 * it, and a store-write insider who removed the `relinked` entry would leave
 * a record that presented as never repaired. So every entry a Tzun writer
 * appends is bound by its own hash:
 *
 *   entryHash = sha256( lp(prevEntryHash) ‖ lp(evidenceId)
 *                     ‖ lp(canonicalDigest) ‖ lp(action) ‖ lp(actor)
 *                     ‖ lp(timestamp) ‖ lp(systemId) ‖ lp(canonical(metadata)) )
 *
 * where `lp(v)` is `"<Unicode code-point count>:" + v`, or `"-:"` for
 * null/absent — length-prefixed so adjacent fields cannot be re-split to
 * collide, and CODE-POINT length because the platform's SQL twin
 * (`tzun_lp`, Postgres `length(text)`) counts characters, not bytes or
 * UTF-16 units — and `canonical(metadata)` is this engine's `canonicalSerialize`
 * over the whole metadata object (keys sorted by UTF-16 code unit at every
 * level, no whitespace) applied to the JSON round-tripped value, i.e. to
 * exactly what a verifier reading the envelope back will see. The hash is
 * bare lowercase hex, no `sha256:` prefix.
 *
 * `prevEntryHash` is the previous HASHED entry on the SAME record (null for
 * the first), so the chain is per record and an exported envelope carries
 * everything needed to verify it. `canonicalDigest` is the record's digest at
 * the moment of the action: a record whose content moves after a repair no
 * longer recomputes, which is the tamper-after-repair signal.
 *
 * This file must agree byte-for-byte with the hosted service's implementation
 * and its SQL twin (the INSERT trigger there refuses a row where the two
 * disagree). `vectors/custody-entry-hash-vectors.json` pins values computed
 * by the hosted service's implementation; the Python port
 * (`python/src/tzun_sdk/custody_hash.py`) and this file are both held to
 * them. Do not add a second copy of this rule anywhere — import this.
 */

import { createHash } from 'crypto';
import { canonicalSerialize } from './canonical';
import type { CustodyEntry, EvidenceEnvelope } from './types/evidence';
import type { CustodyTrailFailure, CustodyTrailVerdict } from './types/verification';

/** A custody entry as a writer mirrors it into `envelope.custodyChain`. */
export interface HashedCustodyEntry extends CustodyEntry {
  entryHash: string;
  prevEntryHash: string | null;
}

export interface CustodyEntryPreimage {
  prevEntryHash: string | null;
  evidenceId: string;
  canonicalDigest: string;
  action: string;
  actor: string;
  timestamp: string;
  systemId: string;
  metadata?: Record<string, unknown> | null;
}

/** Unicode code points in `s` — what Postgres `length(text)` and Python `len()` return. */
export function codePointLength(s: string): number {
  let n = 0;
  for (const _ of s) n += 1;
  return n;
}

/** `tzun_lp`: `<code-point length>:<value>`, `-:` for null/absent. */
export function lengthPrefix(v: string | null | undefined): string {
  return v == null ? '-:' : `${codePointLength(v)}:${v}`;
}

/**
 * Normalise metadata to what a JSON round trip yields (drops undefined-valued
 * keys, materialises array holes) so the hashed bytes are those of the value
 * every reader — SQLite text, Postgres JSONB, the export, the other SDK —
 * will actually see.
 */
export function normaliseCustodyMetadata(
  metadata: Record<string, unknown> | null | undefined,
): Record<string, unknown> | null {
  if (metadata == null) return null;
  return JSON.parse(JSON.stringify(metadata)) as Record<string, unknown>;
}

/** Engine-canonical bytes of the metadata object, or null when absent. */
export function canonicalCustodyMetadata(
  metadata: Record<string, unknown> | null | undefined,
): string | null {
  const m = normaliseCustodyMetadata(metadata);
  if (m == null) return null;
  return canonicalSerialize(m, Object.keys(m));
}

export function custodyEntryPreimage(p: CustodyEntryPreimage): string {
  return (
    lengthPrefix(p.prevEntryHash) +
    lengthPrefix(p.evidenceId) +
    lengthPrefix(p.canonicalDigest) +
    lengthPrefix(p.action) +
    lengthPrefix(p.actor) +
    lengthPrefix(p.timestamp) +
    lengthPrefix(p.systemId) +
    lengthPrefix(canonicalCustodyMetadata(p.metadata))
  );
}

export function computeCustodyEntryHash(p: CustodyEntryPreimage): string {
  return createHash('sha256').update(custodyEntryPreimage(p), 'utf8').digest('hex');
}

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * True when `e` is an object carrying a well-formed `entryHash`.
 *
 * Same rule as the platform: an entry is "hashed" only by a 64-hex
 * `entryHash`. Anything else — no key, a null, a prefixed or malformed string
 * — is the client-attested or legacy unhashed form, counted but not vouched for.
 */
export function isHashedCustodyEntry(e: unknown): e is HashedCustodyEntry {
  return (
    typeof e === 'object' && e !== null && !Array.isArray(e)
    && typeof (e as { entryHash?: unknown }).entryHash === 'string'
    && HEX64.test((e as { entryHash: string }).entryHash)
  );
}

/**
 * True when `v` is a plain JSON object — the only shape `canonicalCustodyMetadata`
 * can hash. Arrays, `null` and class instances are not.
 */
function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === null || proto === Object.prototype;
}

/** The four entry fields `computeCustodyEntryHash` length-prefixes as strings. */
const CUSTODY_STRING_FIELDS = ['action', 'actor', 'timestamp', 'systemId'] as const;

/**
 * Whether every field the hash rule reads off this entry is the type the rule
 * requires.
 *
 * The hash preimage runs each of `action` / `actor` / `timestamp` / `systemId`
 * through `lengthPrefix` -> `codePointLength` -> `for (const _ of s)`, so a
 * number, a boolean or a plain object there would throw `TypeError: s is not
 * iterable` from inside the engine — and an ARRAY is worse than a throw: it
 * is iterable, so `["a","b"]` would silently length-prefix as `2:a,b` and the
 * entry would be reported as an ordinary `entry_hash_mismatch`, as though the
 * two had been compared. `custodyChain` is client-supplied JSON on every
 * server that verifies what a client sent, and JSON guarantees none of these
 * types.
 *
 * `metadata` is checked here too even though a wrong type there does not
 * throw: a non-object metadata would canonicalize as `{}` (via
 * `Object.keys(5)` -> `[]`), which is the same silent coercion.
 */
function custodyEntryFieldsWellTyped(entry: HashedCustodyEntry): boolean {
  const e = entry as unknown as Record<string, unknown>;
  for (const field of CUSTODY_STRING_FIELDS) {
    if (typeof e[field] !== 'string') return false;
  }
  if (!custodyPrevEntryHashWellTyped(entry)) return false;
  const metadata = e.metadata;
  if (metadata !== undefined && metadata !== null && !isPlainObject(metadata)) return false;
  return true;
}

/** `prevEntryHash` is a string, `null`, or absent (absent reads as null). */
function custodyPrevEntryHashWellTyped(entry: HashedCustodyEntry): boolean {
  const prev = (entry as unknown as Record<string, unknown>).prevEntryHash;
  return prev === undefined || prev === null || typeof prev === 'string';
}

/**
 * Build the mirrored entry a writer appends to `envelope.custodyChain` for a
 * freshly hashed row: the caller's entry with its metadata normalised, plus
 * `entryHash` / `prevEntryHash`. `metadata` is omitted (not null) when absent,
 * so the wire shape is the one `canonicalCustodyMetadata` hashed.
 */
export function mirrorCustodyEntry(
  entry: CustodyEntry,
  entryHash: string,
  prevEntryHash: string | null,
): HashedCustodyEntry {
  const metadata = normaliseCustodyMetadata(entry.metadata);
  const mirrored: HashedCustodyEntry = { ...entry, entryHash, prevEntryHash };
  if (metadata === null) {
    delete (mirrored as { metadata?: unknown }).metadata;
  } else {
    mirrored.metadata = metadata;
  }
  return mirrored;
}

/**
 * Verify the hashed custody trail an envelope carries — the offline,
 * export-bundle-only twin of the platform's `verifyCustodyTrailOf` mirror
 * check. Pure: reads nothing but the envelope.
 *
 *   1. Every entry WITHOUT an `entryHash` must precede the first entry WITH
 *      one (`unhashed_after_hashed`). Unhashed entries are the client-attested
 *      `decision_captured` entry and any repair written before entries were
 *      hashed; once a record has a hashed trail, an unhashed append after it
 *      is exactly the shape a forged "reviewed" entry takes.
 *   2. For hashed entries in order, `prevEntryHash` must equal the previous
 *      hashed entry's `entryHash`, `null` for the first
 *      (`prev_entry_hash_mismatch`). An ABSENT `prevEntryHash` is treated as
 *      null: a Python round trip cannot tell the two apart.
 *   3. `entryHash` must recompute from the entry's own fields, the envelope's
 *      `payload.evidenceId` and `integrity.canonicalDigest`
 *      (`entry_hash_mismatch`). A rewritten actor, a reordered entry, a
 *      removed middle entry, or a record whose content moved after the
 *      repair all land here.
 *   4. Every field the hash rule consumes must be the type the rule requires
 *      (`entry_field_type`), and a plain-object `metadata` must actually
 *      canonicalize (`entry_metadata_unserializable`). NEVER THROWS on a
 *      malformed entry: `custodyChain` arrives as client-supplied JSON on
 *      every server that verifies what a client sent, and JSON guarantees no
 *      type at all. A `{"actor": 123}` entry is a finding here; a throw
 *      (`TypeError: s is not iterable` out of `lengthPrefix` ->
 *      `codePointLength`) would go straight through `verifyEnvelope` and out
 *      of the engine, which is a denial of service on the verifying server
 *      rather than a verdict: a server's `POST /v1/evidence` would answer 500
 *      instead of 202 on exactly this input.
 *
 * `valid` is `null` when the chain carries no hashed entry at all —
 * grandfathering: records from before entries were hashed and
 * client-attested trails are UNVERIFIED, not invalid, and never a vacuous
 * `true`.
 *
 * Deliberately NOT a forgery proof. A writer who can append a correctly
 * chained entry can still append one; what it cannot do without leaving a
 * trace is rewrite, reorder or remove an entry that a later entry, a recovery
 * record or an exported envelope already names. Deleting the LAST hashed
 * entry is invisible to this offline check by construction — the local
 * `custody_entries` row (SDK adapters) and the platform's ledger are what
 * catch that.
 */
export function verifyCustodyTrail(
  envelope: Pick<EvidenceEnvelope, 'payload' | 'integrity' | 'custodyChain'>,
): CustodyTrailVerdict {
  const failures: CustodyTrailFailure[] = [];
  // `envelope?.` — a verifier is reachable with whatever a client sent, and
  // reading `.custodyChain` off a null threw before it could answer.
  const chain = Array.isArray(envelope?.custodyChain) ? envelope.custodyChain : [];
  const hashed: Array<{ index: number; entry: HashedCustodyEntry }> = [];
  let unhashed = 0;
  let seenHashed = false;

  chain.forEach((e, index) => {
    if (isHashedCustodyEntry(e)) {
      seenHashed = true;
      hashed.push({ index, entry: e });
    } else {
      unhashed += 1;
      if (seenHashed) failures.push({ reason: 'unhashed_after_hashed', index });
    }
  });

  const rawEvidenceId: unknown = envelope?.payload?.evidenceId ?? '';
  const rawCanonicalDigest: unknown = envelope?.integrity?.canonicalDigest ?? '';
  // Both are length-prefixed into EVERY entry's preimage, so an ill-typed one
  // makes no entry on the record recomputable — not one of them.
  const recordFieldsWellTyped =
    typeof rawEvidenceId === 'string' && typeof rawCanonicalDigest === 'string';
  const evidenceId = recordFieldsWellTyped ? (rawEvidenceId as string) : '';
  const canonicalDigest = recordFieldsWellTyped ? (rawCanonicalDigest as string) : '';

  let prev: string | null = null;
  for (const { index, entry } of hashed) {
    const prevWellTyped = custodyPrevEntryHashWellTyped(entry);
    // A wrong-typed prevEntryHash is reported as a field-type failure, not as
    // a chain break: "5 is not the previous entryHash" is true but says less
    // than "5 is not a hash at all".
    if (prevWellTyped) {
      const claimedPrev = entry.prevEntryHash ?? null;
      if (claimedPrev !== prev) {
        failures.push({ reason: 'prev_entry_hash_mismatch', index });
      }
    }

    if (!recordFieldsWellTyped || !custodyEntryFieldsWellTyped(entry)) {
      failures.push({ reason: 'entry_field_type', index });
      prev = entry.entryHash;
      continue;
    }

    let recomputed: string;
    try {
      recomputed = computeCustodyEntryHash({
        prevEntryHash: entry.prevEntryHash ?? null,
        evidenceId,
        canonicalDigest,
        action: entry.action,
        actor: entry.actor,
        timestamp: entry.timestamp,
        systemId: entry.systemId,
        metadata: entry.metadata ?? null,
      });
    } catch {
      // metadata is a plain object the canonical serializer still refuses —
      // a lone surrogate, nesting past MAX_DEPTH, a non-plain nested value.
      // There is no preimage, so there is no hash to compare; that is a
      // verdict, not an exception to raise at the caller.
      failures.push({ reason: 'entry_metadata_unserializable', index });
      prev = entry.entryHash;
      continue;
    }

    if (recomputed !== entry.entryHash) {
      failures.push({ reason: 'entry_hash_mismatch', index });
    }
    // Continue from the STORED hash so one bad entry is reported once, not
    // cascaded onto every later entry (same choice as the platform).
    prev = entry.entryHash;
  }

  return {
    valid: hashed.length === 0 ? null : failures.length === 0,
    hashedEntries: hashed.length,
    unhashedEntries: unhashed,
    failures,
  };
}
