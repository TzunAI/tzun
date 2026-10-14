/**
 * The custody entry hash and the offline trail verifier.
 *
 * The values in vectors/custody-entry-hash-vectors.json were computed with
 * the hosted service's implementation (whose SQL twin its INSERT trigger
 * enforces), so agreement here is agreement with what the hosted ledger will
 * accept and what its export sidecar's `hashPreimage` states. The
 * `custodyTrailValid` assertions below also prove that `verifyEnvelope` runs
 * the trail verifier: without it each one reports `Received: undefined`.
 */
import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  canonicalCustodyMetadata,
  codePointLength,
  computeCustodyEntryHash,
  custodyEntryPreimage,
  isHashedCustodyEntry,
  lengthPrefix,
  mirrorCustodyEntry,
  verifyCustodyTrail,
} from './custody-hash';
import { verifyEnvelope } from './verify';
import { assembleEnvelope } from './envelope';
import { SchemaRegistry } from './schema-registry';
import type { CustodyEntry, EvidenceEnvelope } from './types/evidence';

interface Vector {
  name: string;
  input: {
    prevEntryHash: string | null;
    evidenceId: string;
    canonicalDigest: string;
    action: string;
    actor: string;
    timestamp: string;
    systemId: string;
    metadata: Record<string, unknown> | null;
  };
  preimage: string;
  entryHash: string;
}

const vectors = (
  JSON.parse(readFileSync(join(__dirname, '..', '..', '..', 'vectors', 'custody-entry-hash-vectors.json'), 'utf-8')) as {
    vectors: Vector[];
  }
).vectors;

// The platform's own unit fixture (backend/tests/app/custody-hash.test.ts),
// with the hash the platform computes for it — pinned here as a literal, not
// read from the vectors file, so the two pins have to be edited together.
const PLATFORM_FIXTURE_HASH = '5c7467b1eecfd9f3541d3cf51fa3a68c2eeba4388ccde8b240bf4ed4e882c193';

describe('custody entry hash — the one rule', () => {
  it('reproduces every platform-computed vector, preimage and hash', () => {
    expect(vectors.length).toBeGreaterThanOrEqual(3);
    for (const v of vectors) {
      expect({ name: v.name, preimage: custodyEntryPreimage(v.input) }).toEqual({ name: v.name, preimage: v.preimage });
      expect({ name: v.name, hash: computeCustodyEntryHash(v.input) }).toEqual({ name: v.name, hash: v.entryHash });
      // And the hash really is sha256 of the utf-8 preimage, bare hex.
      expect(v.entryHash).toBe(createHash('sha256').update(v.preimage, 'utf8').digest('hex'));
    }
  });

  it('the platform test fixture hashes to the value the platform computes for it', () => {
    expect(
      computeCustodyEntryHash({
        prevEntryHash: null, evidenceId: 'ev-1', canonicalDigest: 'd'.repeat(64), action: 'relinked',
        actor: 'ünï 😀', timestamp: '2026-09-09T00:00:00.000Z', systemId: 'rec-1', metadata: { newChainId: 'c2' },
      }),
    ).toBe(PLATFORM_FIXTURE_HASH);
    expect(vectors[0].entryHash).toBe(PLATFORM_FIXTURE_HASH);
  });

  it('length-prefixes by code point, as Postgres length(text) and Python len() do — not by UTF-16 unit or byte', () => {
    expect(codePointLength('😀')).toBe(1);
    expect('😀'.length).toBe(2);
    expect(Buffer.byteLength('😀')).toBe(4);
    expect(lengthPrefix('😀ab')).toBe('3:😀ab');
    expect(lengthPrefix(null)).toBe('-:');
    expect(lengthPrefix(undefined)).toBe('-:');
    expect(lengthPrefix('')).toBe('0:');
  });

  it('canonicalises metadata with the engine rules: sorted keys at every level, no whitespace, undefined dropped', () => {
    expect(canonicalCustodyMetadata({ b: 1, a: { d: [1, null], c: 'x' }, u: undefined }))
      .toBe('{"a":{"c":"x","d":[1,null]},"b":1}');
    expect(canonicalCustodyMetadata({ a: 1, b: 2 })).toBe(canonicalCustodyMetadata({ b: 2, a: 1 }));
    expect(canonicalCustodyMetadata(null)).toBeNull();
    expect(canonicalCustodyMetadata(undefined)).toBeNull();
  });

  it('chaining: the previous hash changes the next', () => {
    const p = vectors[0].input;
    expect(computeCustodyEntryHash({ ...p, prevEntryHash: 'a'.repeat(64) })).not.toBe(computeCustodyEntryHash(p));
  });

  it('recognises a hashed entry only by a well-formed bare-hex entryHash — same rule as the platform', () => {
    expect(isHashedCustodyEntry({ action: 'relinked', entryHash: 'a'.repeat(64) })).toBe(true);
    expect(isHashedCustodyEntry({ action: 'relinked' })).toBe(false);
    expect(isHashedCustodyEntry({ action: 'relinked', entryHash: null })).toBe(false);
    expect(isHashedCustodyEntry({ action: 'relinked', entryHash: 'sha256:' + 'a'.repeat(64) })).toBe(false);
    expect(isHashedCustodyEntry({ action: 'relinked', entryHash: 'not-hex' })).toBe(false);
    expect(isHashedCustodyEntry(null)).toBe(false);
    expect(isHashedCustodyEntry([])).toBe(false);
  });

  it('mirrorCustodyEntry normalises metadata and omits it (never null) when absent', () => {
    const base = { timestamp: 't', actor: 'a', action: 'reviewed' as const, systemId: 's' };
    const withMeta = mirrorCustodyEntry({ ...base, metadata: { z: 1, u: undefined } }, 'h', null);
    expect(withMeta).toEqual({ ...base, metadata: { z: 1 }, entryHash: 'h', prevEntryHash: null });
    const without = mirrorCustodyEntry(base, 'h', 'p');
    expect(Object.prototype.hasOwnProperty.call(without, 'metadata')).toBe(false);
    expect(without).toEqual({ ...base, entryHash: 'h', prevEntryHash: 'p' });
  });
});

// ── the offline trail verifier ─────────────────────────────────────

const input = {
  aiSystemId: 'sys-1',
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'criteria met',
  decider: { kind: 'human' as const, id: 'acct:u-jane', agent: null, credential: null, freshness: null },
};
const registry = new SchemaRegistry();

/** Append `n` correctly chained hashed entries to a copy of `envelope`. */
function withHashedTrail(envelope: EvidenceEnvelope, n: number): EvidenceEnvelope {
  const copy = JSON.parse(JSON.stringify(envelope)) as EvidenceEnvelope;
  let prev: string | null = null;
  for (let i = 0; i < n; i += 1) {
    const entry: CustodyEntry = {
      timestamp: `2026-09-09T10:0${i}:00.000Z`,
      actor: 'admin@acme.example',
      action: i === 0 ? 'relinked' : 'reviewed',
      systemId: 'tzun-recovery',
      metadata: { step: i, recoveryTier: i === 0 ? 'relink' : 'annotation' },
    };
    const entryHash = computeCustodyEntryHash({
      prevEntryHash: prev,
      evidenceId: copy.payload.evidenceId,
      canonicalDigest: copy.integrity.canonicalDigest,
      action: entry.action,
      actor: entry.actor,
      timestamp: entry.timestamp,
      systemId: entry.systemId,
      metadata: entry.metadata,
    });
    copy.custodyChain.push(mirrorCustodyEntry(entry, entryHash, prev));
    prev = entryHash;
  }
  return copy;
}

describe('verifyCustodyTrail / verifyEnvelope.custodyTrailValid', () => {
  const first = assembleEnvelope(input, { sequenceNumber: 1 });
  const second = assembleEnvelope(input, { previousDigest: first.integrity.canonicalDigest, sequenceNumber: 2 });

  it('answers null — unverified, never a vacuous true — for a trail with no hashed entry', () => {
    expect(verifyCustodyTrail(second)).toEqual({ valid: null, hashedEntries: 0, unhashedEntries: 1, failures: [] });
    const r = verifyEnvelope(second, first.integrity.canonicalDigest, registry);
    expect(r.custodyTrailValid).toBeNull();
    expect(r.custodyTrailFailures).toBeUndefined();
    expect(r.verified).toBe(true);
  });

  it('a prefixed or malformed entryHash is not a hashed entry (platform rule), so such a trail is unverified, not invalid', () => {
    const copy = JSON.parse(JSON.stringify(second)) as EvidenceEnvelope;
    copy.custodyChain.push({ ...withHashedTrail(second, 1).custodyChain[1], entryHash: 'sha256:' + 'a'.repeat(64) });
    expect(verifyCustodyTrail(copy).valid).toBeNull();
  });

  it('verifies a correctly chained trail: true, and the client-attested entry before it is counted, not vouched for', () => {
    const env = withHashedTrail(second, 3);
    expect(verifyCustodyTrail(env)).toEqual({ valid: true, hashedEntries: 3, unhashedEntries: 1, failures: [] });
    const r = verifyEnvelope(env, first.integrity.canonicalDigest, registry);
    expect(r.custodyTrailValid).toBe(true);
    expect(r.custodyTrailFailures).toBeUndefined();
    expect(r.verified).toBe(true);
  });

  it('an absent prevEntryHash on the first hashed entry reads as null (a Python round trip cannot tell them apart)', () => {
    const env = withHashedTrail(second, 2);
    delete (env.custodyChain[1] as { prevEntryHash?: unknown }).prevEntryHash;
    expect(verifyCustodyTrail(env).valid).toBe(true);
  });

  it('a rewritten actor no longer recomputes: entry_hash_mismatch at that index, reported once', () => {
    const env = withHashedTrail(second, 3);
    env.custodyChain[2].actor = 'mallory@acme.example';
    const v = verifyCustodyTrail(env);
    expect(v.valid).toBe(false);
    expect(v.failures).toEqual([{ reason: 'entry_hash_mismatch', index: 2 }]);
    const r = verifyEnvelope(env, first.integrity.canonicalDigest, registry);
    expect(r.custodyTrailValid).toBe(false);
    expect(r.custodyTrailFailures).toEqual([{ reason: 'entry_hash_mismatch', index: 2 }]);
    // `verified` is about the decision record and its chain link, which are
    // intact; the custody trail is reported on its own field. See the
    // VerificationResult doc for why the two are not folded together.
    expect(r.verified).toBe(true);
  });

  it('a rewritten metadata value no longer recomputes (canonical(metadata) is in the preimage)', () => {
    const env = withHashedTrail(second, 1);
    (env.custodyChain[1].metadata as Record<string, unknown>).step = 99;
    expect(verifyCustodyTrail(env).failures).toEqual([{ reason: 'entry_hash_mismatch', index: 1 }]);
  });

  it('a removed middle entry breaks the next entry\'s prevEntryHash link', () => {
    const env = withHashedTrail(second, 3);
    env.custodyChain.splice(2, 1);
    const v = verifyCustodyTrail(env);
    expect(v.valid).toBe(false);
    expect(v.failures).toEqual([{ reason: 'prev_entry_hash_mismatch', index: 2 }]);
  });

  it('reordered entries fail on the link and, where the swapped entry is now first, on prev as well', () => {
    const env = withHashedTrail(second, 2);
    const [a, b] = [env.custodyChain[1], env.custodyChain[2]];
    env.custodyChain[1] = b;
    env.custodyChain[2] = a;
    const v = verifyCustodyTrail(env);
    expect(v.valid).toBe(false);
    expect(v.failures.map((f) => f.reason)).toContain('prev_entry_hash_mismatch');
  });

  it('an unhashed entry appended AFTER a hashed one is invalid — the shape a forged review takes', () => {
    const env = withHashedTrail(second, 1);
    env.custodyChain.push({ timestamp: 't', actor: 'mallory', action: 'reviewed', systemId: 'x' });
    const v = verifyCustodyTrail(env);
    expect(v.valid).toBe(false);
    expect(v.failures).toEqual([{ reason: 'unhashed_after_hashed', index: 2 }]);
  });

  it('a record whose canonicalDigest moved after the repair no longer recomputes (the tamper-after-repair signal)', () => {
    const env = withHashedTrail(second, 1);
    env.integrity.canonicalDigest = 'e'.repeat(64);
    const v = verifyCustodyTrail(env);
    expect(v.failures).toEqual([{ reason: 'entry_hash_mismatch', index: 1 }]);
    const r = verifyEnvelope(env, first.integrity.canonicalDigest, registry);
    expect(r.verified).toBe(false);
    expect(r.custodyTrailValid).toBe(false);
  });

  it('is reported even when the schema version is unknown (the trail hashes the stored digest, not the payload)', () => {
    const env = withHashedTrail(second, 1);
    env.payload.schemaVersion = 'v9.9';
    const r = verifyEnvelope(env, first.integrity.canonicalDigest, registry);
    expect(r.schemaValid).toBe(false);
    expect(r.custodyTrailValid).toBe(true);
  });

  it('custodyChain — and so entryHash / prevEntryHash — stays OUTSIDE the v1.0 hashed field set', () => {
    const hashed = registry.get('v1.0')!.hashedFieldSet;
    expect(hashed).not.toContain('custodyChain');
    const env = withHashedTrail(second, 2);
    const r = verifyEnvelope(env, first.integrity.canonicalDigest, registry);
    expect(r.recomputedDigest).toBe(second.integrity.canonicalDigest);
  });
});
