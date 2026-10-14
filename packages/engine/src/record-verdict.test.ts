/**
 * The custody ledger check and the verdict a read carries.
 *
 * `verifyCustodyLedger` is the engine twin of the hosted service's
 * `verifyCustodyTrailOf`: the same ten reasons over the rows an export bundle
 * carries. The case that makes it necessary is the first one below the clean
 * pass: the LAST hashed entry deleted from the mirror, which the envelope-only
 * `verifyCustodyTrail` reports as valid by construction.
 *
 * `recordVerdict` is what every local read, every export and the offline
 * verifier compute; its digest and chain-link statuses are `verifyEnvelope`'s,
 * with the reasons named.
 */
import {
  CUSTODY_ENTRY_HASH_PREIMAGE,
  toCustodyLedgerEntry,
  verifyCustodyLedger,
} from './custody-ledger';
import { computeCustodyEntryHash, mirrorCustodyEntry, verifyCustodyTrail } from './custody-hash';
import { recordDigestCheck, recordVerdict, unmeasuredRecordVerdict } from './record-verdict';
import { assembleEnvelope } from './envelope';
import { EvidenceChain } from './evidence-chain';
import { SchemaRegistry } from './schema-registry';
import type { CustodyEntry, EnvelopeInput, EvidenceEnvelope } from './types/evidence';
import type { CustodyLedgerEntry } from './types/verification';
import type { StoredCustodyEntry } from './types/storage-interface';

const registry = new SchemaRegistry();
const input: EnvelopeInput = {
  aiSystemId: 'ledger-test',
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'fits policy',
  decider: { kind: 'human', id: 'acct:u-reviewer', agent: null, credential: null, freshness: null },
};

const first = assembleEnvelope(input, { sequenceNumber: 1 });
const second = assembleEnvelope(input, { previousDigest: first.integrity.canonicalDigest, sequenceNumber: 2 });

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

/**
 * `envelope` after `n` custody actions, each written the way an SDK adapter
 * writes one: a hashed, chained ledger row, and its mirror in `custodyChain`.
 */
function repaired(envelope: EvidenceEnvelope, n: number): { envelope: EvidenceEnvelope; rows: CustodyLedgerEntry[] } {
  const copy = clone(envelope);
  const rows: CustodyLedgerEntry[] = [];
  let prev: string | null = null;
  for (let i = 0; i < n; i++) {
    const entry: CustodyEntry = {
      timestamp: `2026-09-19T10:0${i}:00.000Z`,
      actor: `operator-${i}@acme.example`,
      action: i === 0 ? 'relinked' : 'reviewed',
      systemId: 'ledger-test',
      metadata: { step: i },
    };
    const entryHash = computeCustodyEntryHash({
      prevEntryHash: prev,
      evidenceId: copy.payload.evidenceId,
      canonicalDigest: copy.integrity.canonicalDigest,
      ...entry,
    });
    const stored: StoredCustodyEntry = {
      id: i + 1,
      evidenceId: copy.payload.evidenceId,
      chainId: 'default',
      canonicalDigest: copy.integrity.canonicalDigest,
      action: entry.action,
      actor: entry.actor,
      timestamp: entry.timestamp,
      systemId: entry.systemId,
      metadata: entry.metadata ?? null,
      prevEntryHash: prev,
      entryHash,
      recoveryId: `rec-${i}`,
    };
    rows.push(toCustodyLedgerEntry(stored));
    copy.custodyChain.push(mirrorCustodyEntry(entry, entryHash, prev));
    prev = entryHash;
  }
  return { envelope: copy, rows };
}

function reasons(envelope: EvidenceEnvelope | null, rows: CustodyLedgerEntry[]): string[] {
  return verifyCustodyLedger(second.payload.evidenceId, envelope, undefined, rows).failures.map((f) => f.reason);
}

describe('verifyCustodyLedger — rows against the mirror', () => {
  it('a record never repaired: valid, with nothing counted but the capture entry', () => {
    expect(verifyCustodyLedger(second.payload.evidenceId, second, undefined, [])).toEqual({
      evidenceId: second.payload.evidenceId,
      valid: true,
      rows: 0,
      hashedEntries: 0,
      unhashedEntries: 1,
      failures: [],
    });
  });

  it('a repaired record whose rows and mirror agree: valid', () => {
    const { envelope, rows } = repaired(second, 3);
    const v = verifyCustodyLedger(second.payload.evidenceId, envelope, undefined, rows);
    expect(v).toMatchObject({ valid: true, rows: 3, hashedEntries: 3, unhashedEntries: 1, failures: [] });
  });

  it('the LAST hashed entry deleted from the mirror: the envelope alone says valid, the ledger says mirror_entry_missing', () => {
    const { envelope, rows } = repaired(second, 2);
    envelope.custodyChain.pop();
    expect(verifyCustodyTrail(envelope).valid).toBe(true);
    expect(reasons(envelope, rows)).toEqual(['mirror_entry_missing']);
  });

  it('every hashed entry stripped from the mirror: the envelope alone says unverified, the ledger names each row', () => {
    const { envelope, rows } = repaired(second, 2);
    envelope.custodyChain.splice(1);
    expect(verifyCustodyTrail(envelope).valid).toBeNull();
    const v = verifyCustodyLedger(second.payload.evidenceId, envelope, undefined, rows);
    expect(v.failures).toEqual([
      { reason: 'mirror_entry_missing', rowId: '1' },
      { reason: 'mirror_entry_missing', rowId: '2' },
    ]);
  });

  it('a hashed mirror entry with no row behind it: mirror_entry_unexpected', () => {
    const { envelope, rows } = repaired(second, 2);
    expect(reasons(envelope, rows.slice(0, 1))).toEqual(['mirror_entry_unexpected']);
  });

  it('an actor rewritten in the row alone: row_hash_mismatch', () => {
    const { envelope, rows } = repaired(second, 2);
    rows[1] = { ...rows[1], actor: 'mallory@acme.example' };
    expect(reasons(envelope, rows)).toEqual(['row_hash_mismatch']);
  });

  it('an actor rewritten in the mirror alone: mirror_fields_mismatch', () => {
    const { envelope, rows } = repaired(second, 2);
    envelope.custodyChain[2].actor = 'mallory@acme.example';
    expect(verifyCustodyLedger(second.payload.evidenceId, envelope, undefined, rows).failures).toEqual([
      { reason: 'mirror_fields_mismatch', index: 2, rowId: '2' },
    ]);
  });

  it("a row whose prevEntryHash is not the previous row's hash: row_prev_mismatch", () => {
    const { envelope, rows } = repaired(second, 2);
    rows[1] = { ...rows[1], prevEntryHash: 'f'.repeat(64) };
    expect(reasons(envelope, rows)).toEqual(['row_prev_mismatch', 'row_hash_mismatch', 'mirror_prev_mismatch']);
  });

  it('a record whose digest moved after the action: digest_moved_since_entry on every row', () => {
    const { envelope, rows } = repaired(second, 2);
    envelope.integrity.canonicalDigest = 'e'.repeat(64);
    expect(reasons(envelope, rows)).toEqual(['digest_moved_since_entry', 'digest_moved_since_entry']);
  });

  it('an unhashed entry after a hashed one: unhashed_after_hashed', () => {
    const { envelope, rows } = repaired(second, 1);
    envelope.custodyChain.push({ timestamp: 't', actor: 'mallory', action: 'reviewed', systemId: 'x' });
    expect(reasons(envelope, rows)).toEqual(['unhashed_after_hashed']);
  });

  it('rows for a record that is not there: record_missing', () => {
    const { rows } = repaired(second, 1);
    expect(reasons(null, rows)).toEqual(['record_missing']);
  });

  it('never throws on rows or entries whose fields the hash rule cannot consume', () => {
    const { envelope, rows } = repaired(second, 2);
    const badRow = { ...rows[0], actor: 5 } as unknown as CustodyLedgerEntry;
    (envelope.custodyChain[2] as unknown as Record<string, unknown>).metadata = [1, 2];
    const v = verifyCustodyLedger(second.payload.evidenceId, envelope, undefined, [badRow, rows[1]]);
    expect(v.valid).toBe(false);
    expect(v.failures.map((f) => f.reason)).toEqual(['row_hash_mismatch', 'mirror_fields_mismatch']);
    expect(v.failures.every((f) => typeof f.detail === 'string')).toBe(true);
  });

  it('states the hash rule in the words the platform export uses', () => {
    expect(CUSTODY_ENTRY_HASH_PREIMAGE).toBe(
      'sha256(lp(prevEntryHash)||lp(evidenceId)||lp(canonicalDigest)||lp(action)||lp(actor)||lp(timestamp)||lp(systemId)||lp(canonicalMetadata)); lp = "<code points>:<value>" or "-:" for null; canonicalMetadata = engine canonical JSON of metadata',
    );
  });
});

describe('recordVerdict — what a read carries', () => {
  it('an untouched record read on its own: valid digest, nothing to measure in custody, the link left to the chain checks', () => {
    const v = recordVerdict(second, { custody: { entries: [] } });
    expect(v.status).toBe('valid');
    expect(v.digest).toEqual({
      status: 'valid',
      stored: second.integrity.canonicalDigest,
      recomputed: second.integrity.canonicalDigest,
    });
    expect(v.custodyTrail).toMatchObject({ status: 'unmeasured', reason: 'nothing_to_measure' });
    expect(v.chainLink).toEqual({ status: 'unmeasured', reason: 'not_checked_on_read', predecessorDigest: null });
  });

  it('a rewritten payload: the record comes back invalid, with both digests and the reason', () => {
    const tampered = clone(second);
    tampered.payload.reason = 'rewritten';
    const v = recordVerdict(tampered, { custody: { entries: [] } });
    expect(v.status).toBe('invalid');
    expect(v.digest.status).toBe('invalid');
    expect(v.digest.reason).toBe('digest_mismatch');
    expect(v.digest.stored).toBe(second.integrity.canonicalDigest);
    expect(v.digest.recomputed).not.toBe(second.integrity.canonicalDigest);
    expect(v.digest.recomputed).toMatch(/^[0-9a-f]{64}$/);
  });

  it('an unknown schema version is invalid, not unverifiable', () => {
    const tampered = clone(second);
    tampered.payload.schemaVersion = 'v9.9';
    const v = recordVerdict(tampered, { custody: { entries: [] } });
    expect(v.digest).toEqual({
      status: 'invalid',
      stored: second.integrity.canonicalDigest,
      recomputed: '',
      reason: 'unknown_schema_version',
    });
  });

  it('a payload the serializer refuses is invalid, and the verdict is still returned', () => {
    const tampered = clone(second);
    tampered.payload.reason = '\ud800';
    const v = recordVerdict(tampered, { custody: { entries: [] } });
    expect(v.digest.status).toBe('invalid');
    expect(v.digest.reason).toBe('payload_unserializable');
  });

  it('a repaired record whose trail holds: custody valid, with the ledger verdict attached', () => {
    const { envelope, rows } = repaired(second, 2);
    const v = recordVerdict(envelope, { custody: { entries: rows } });
    expect(v.status).toBe('valid');
    expect(v.custodyTrail.status).toBe('valid');
    expect(v.custodyTrail.reason).toBeUndefined();
    expect(v.custodyTrail.ledger).toMatchObject({ valid: true, rows: 2, hashedEntries: 2 });
  });

  it('a custody trail that fails: invalid, the first failure as the reason and all of them in the ledger verdict', () => {
    const { envelope, rows } = repaired(second, 2);
    envelope.custodyChain.pop();
    const v = recordVerdict(envelope, { custody: { entries: rows } });
    expect(v.status).toBe('invalid');
    expect(v.custodyTrail).toMatchObject({ status: 'invalid', reason: 'mirror_entry_missing' });
    expect(v.custodyTrail.ledger!.failures).toHaveLength(1);
  });

  it('a ledger that could not be read: custody unmeasured with the error, and the record still returned', () => {
    const v = recordVerdict(second, { custody: { error: 'SQLITE_CORRUPT: database disk image is malformed' } });
    expect(v.status).toBe('valid');
    expect(v.custodyTrail).toEqual({
      status: 'unmeasured',
      reason: 'custody_ledger_unreadable',
      ledger: null,
      detail: 'SQLITE_CORRUPT: database disk image is malformed',
    });
  });

  describe('chain link, when the predecessor was looked up', () => {
    it('genesis with no predecessor: valid', () => {
      const v = recordVerdict(first, { custody: { entries: [] }, predecessor: { digest: null } });
      expect(v.chainLink).toEqual({ status: 'valid', predecessorDigest: null });
    });

    it('the right predecessor: valid', () => {
      const v = recordVerdict(second, {
        custody: { entries: [] },
        predecessor: { digest: first.integrity.canonicalDigest },
      });
      expect(v.chainLink).toEqual({ status: 'valid', predecessorDigest: first.integrity.canonicalDigest });
    });

    it('another predecessor: chain_link_mismatch', () => {
      const v = recordVerdict(second, { custody: { entries: [] }, predecessor: { digest: 'a'.repeat(64) } });
      expect(v.status).toBe('invalid');
      expect(v.chainLink).toEqual({ status: 'invalid', reason: 'chain_link_mismatch', predecessorDigest: 'a'.repeat(64) });
    });

    it('a linked record whose predecessor the store no longer holds: predecessor_missing', () => {
      const v = recordVerdict(second, { custody: { entries: [] }, predecessor: { digest: null } });
      expect(v.chainLink).toEqual({ status: 'invalid', reason: 'predecessor_missing', predecessorDigest: null });
    });

    it('a record past genesis whose link was nulled: chain_link_missing, whether or not the predecessor is there', () => {
      const unlinked = clone(second);
      unlinked.integrity.chainLink = null;
      for (const digest of [null, first.integrity.canonicalDigest]) {
        const v = recordVerdict(unlinked, { custody: { entries: [] }, predecessor: { digest } });
        expect(v.chainLink).toMatchObject({ status: 'invalid', reason: 'chain_link_missing' });
      }
    });

    it('a predecessor that could not be read: unmeasured with the error', () => {
      const v = recordVerdict(second, { custody: { entries: [] }, predecessor: { error: 'connection reset' } });
      expect(v.status).toBe('valid');
      expect(v.chainLink).toEqual({
        status: 'unmeasured',
        reason: 'predecessor_unreadable',
        predecessorDigest: null,
        detail: 'connection reset',
      });
    });
  });

  it('with read verification off: every check unmeasured, and the verdict says so rather than passing', () => {
    const v = unmeasuredRecordVerdict(second);
    expect(v.status).toBe('unmeasured');
    expect(v.digest).toEqual({
      status: 'unmeasured',
      stored: second.integrity.canonicalDigest,
      recomputed: '',
      reason: 'read_verification_off',
    });
    expect(v.custodyTrail).toEqual({ status: 'unmeasured', reason: 'read_verification_off', ledger: null });
    expect(v.chainLink).toEqual({ status: 'unmeasured', reason: 'read_verification_off', predecessorDigest: null });
  });
});

describe('recordVerdict for a store whose identity lives in columns', () => {
  // The hosted service reads the record's id and its frozen `canonical_digest`
  // column rather than the envelope's own claims, because those are what its
  // INSERT trigger bound the custody rows to, and its list and export return
  // rows whose envelope column is null.

  it('hashes the custody rows under an explicit evidenceId, the id the store filed them under', () => {
    // A payload whose evidenceId was rewritten: the rows were keyed by the
    // store's id, so they recompute under it, and the mirror — checked against
    // the envelope's own fields — is what disagrees.
    const { envelope, rows } = repaired(second, 2);
    const renamed = clone(envelope);
    renamed.payload.evidenceId = 'ev_someone_else';

    const fromEnvelope = recordVerdict(renamed, { registry, custody: { entries: rows } });
    expect(fromEnvelope.custodyTrail.ledger?.failures.map((f) => f.reason)).toContain('row_hash_mismatch');

    const fromColumn = recordVerdict(renamed, {
      registry,
      custody: { entries: rows },
      evidenceId: second.payload.evidenceId,
    });
    expect(fromColumn.custodyTrail.ledger).toEqual(
      verifyCustodyLedger(second.payload.evidenceId, renamed, undefined, rows),
    );
    expect(fromColumn.custodyTrail.ledger?.evidenceId).toBe(second.payload.evidenceId);
    expect(fromColumn.custodyTrail.ledger?.failures.map((f) => f.reason)).not.toContain('row_hash_mismatch');
  });

  it('checks the ledger against an explicit currentDigest, not the envelope claim', () => {
    // A row inserted directly with a claim that differs from its column: the
    // custody rows were bound to the column.
    const { envelope, rows } = repaired(second, 2);
    const reclaimed = clone(envelope);
    reclaimed.integrity.canonicalDigest = 'f'.repeat(64);

    const fromClaim = recordVerdict(reclaimed, { registry, custody: { entries: rows } });
    expect(fromClaim.custodyTrail.reason).toBe('digest_moved_since_entry');

    const fromColumn = recordVerdict(reclaimed, {
      registry,
      custody: { entries: rows },
      currentDigest: second.integrity.canonicalDigest,
    });
    expect(fromColumn.custodyTrail.status).toBe('valid');
  });

  /**
   * `second` after `n` custody actions, then rewritten the way an insider with
   * write access to the envelope column would: the payload changed and
   * `canonicalDigest` and `chainLink` recomputed to match it. The ledger rows
   * and the store's frozen digest still hold the original.
   */
  function rewritten(n: number): { envelope: EvidenceEnvelope; rows: CustodyLedgerEntry[] } {
    const { envelope, rows } = repaired(second, n);
    const forged = clone(envelope);
    forged.payload.reason = 'rewritten after capture';
    forged.integrity.canonicalDigest = recordDigestCheck(forged, registry).recomputed;
    const chain = new EvidenceChain();
    chain.restore(first.integrity.canonicalDigest);
    forged.integrity.chainLink = chain.computeLink(forged.integrity.canonicalDigest);
    return { envelope: forged, rows };
  }

  it('reports an envelope rewritten consistently invalid when the store holds a different digest', () => {
    const { envelope, rows } = rewritten(2);
    const predecessor = { digest: first.integrity.canonicalDigest };
    // The envelope agrees with itself: its own checks pass.
    expect(recordDigestCheck(envelope, registry).status).toBe('valid');

    const v = recordVerdict(envelope, {
      registry,
      custody: { entries: rows },
      currentDigest: second.integrity.canonicalDigest,
      predecessor,
    });
    expect(v.status).toBe('invalid');
    expect(v.digest).toEqual({
      status: 'invalid',
      stored: envelope.integrity.canonicalDigest,
      recomputed: envelope.integrity.canonicalDigest,
      reason: 'stored_digest_mismatch',
    });
  });

  it('never gives a weaker verdict for supplying the store digest than for supplying none', () => {
    const { envelope, rows } = rewritten(2);
    const predecessor = { digest: first.integrity.canonicalDigest };
    const withNone = recordVerdict(envelope, { registry, custody: { entries: rows }, predecessor });
    const withColumn = recordVerdict(envelope, {
      registry,
      custody: { entries: rows },
      currentDigest: second.integrity.canonicalDigest,
      predecessor,
    });
    expect(withNone.status).toBe('invalid');
    expect(withColumn.status).toBe('invalid');
  });

  it('reports a payload that no longer matches its own claim as digest_mismatch, even when the store digest differs too', () => {
    const { envelope, rows } = repaired(second, 1);
    const edited = clone(envelope);
    edited.payload.reason = 'edited, claim left alone';
    edited.integrity.canonicalDigest = 'e'.repeat(64);
    const v = recordVerdict(edited, {
      registry,
      custody: { entries: rows },
      currentDigest: second.integrity.canonicalDigest,
    });
    expect(v.digest.reason).toBe('digest_mismatch');
  });

  it('reads currentDigest: null as absent — the ledger is checked against the envelope, not skipped', () => {
    const { envelope, rows } = rewritten(2);
    const predecessor = { digest: first.integrity.canonicalDigest };
    const withNull = recordVerdict(envelope, {
      registry,
      custody: { entries: rows },
      currentDigest: null,
      predecessor,
    });
    const withNone = recordVerdict(envelope, { registry, custody: { entries: rows }, predecessor });
    expect(withNull.status).toBe('invalid');
    expect(withNull.custodyTrail.reason).toBe('digest_moved_since_entry');
    expect({ ...withNull, checkedAt: '' }).toEqual({ ...withNone, checkedAt: '' });
  });

  it('falls back to the envelope when neither is given', () => {
    const { envelope, rows } = repaired(second, 2);
    const explicit = recordVerdict(envelope, {
      registry,
      custody: { entries: rows },
      evidenceId: envelope.payload.evidenceId,
      currentDigest: envelope.integrity.canonicalDigest,
    });
    const implicit = recordVerdict(envelope, { registry, custody: { entries: rows } });
    expect({ ...implicit, checkedAt: '' }).toEqual({ ...explicit, checkedAt: '' });
  });

  describe('a row that holds no record', () => {
    it('reports the digest invalid, record_missing, against the digest the store holds', () => {
      const v = recordVerdict(null, {
        registry,
        custody: { entries: [] },
        evidenceId: second.payload.evidenceId,
        currentDigest: second.integrity.canonicalDigest,
      });
      expect(v.status).toBe('invalid');
      expect(v.digest).toEqual({
        status: 'invalid',
        stored: second.integrity.canonicalDigest,
        recomputed: '',
        reason: 'record_missing',
      });
      expect(v.custodyTrail.status).toBe('invalid');
      expect(v.custodyTrail.reason).toBe('record_missing');
    });

    it('reports the chain link it cannot check as unmeasured, record_missing — never valid', () => {
      const v = recordVerdict(null, {
        registry,
        custody: { entries: [] },
        evidenceId: second.payload.evidenceId,
        currentDigest: second.integrity.canonicalDigest,
        predecessor: { digest: first.integrity.canonicalDigest },
      });
      expect(v.chainLink).toEqual({
        status: 'unmeasured',
        reason: 'record_missing',
        predecessorDigest: first.integrity.canonicalDigest,
      });
    });

    it('reads an undefined envelope, from a JavaScript caller, as no record', () => {
      const v = recordVerdict(undefined as unknown as null, {
        registry,
        custody: { entries: [] },
        evidenceId: second.payload.evidenceId,
        predecessor: { digest: null },
      });
      expect(v.digest.reason).toBe('record_missing');
      expect(v.chainLink.reason).toBe('record_missing');
    });

    it('still reports an unread predecessor or ledger as unreadable', () => {
      const v = recordVerdict(null, {
        registry,
        custody: { error: 'ledger down' },
        evidenceId: second.payload.evidenceId,
        predecessor: { error: 'connection reset' },
      });
      expect(v.custodyTrail.reason).toBe('custody_ledger_unreadable');
      expect(v.chainLink.reason).toBe('predecessor_unreadable');
      expect(v.digest.stored).toBe('');
    });
  });
});

describe('recordVerdict — the sign-off expectation beside the integrity checks', () => {
  const custody = { entries: [] };

  it('reports checkSignoffExpectation for the record, outside status', () => {
    const owed = clone(first);
    owed.payload.signoffExpectation = { policyDigest: 'c'.repeat(64) };
    owed.integrity.canonicalDigest = recordDigestCheck(owed, registry).recomputed;
    const verdict = recordVerdict(owed, { registry, custody });
    expect(verdict.signoffExpectation).toEqual({ valid: null, reason: 'signature_missing' });
    expect(verdict.status).toBe('valid');
  });

  it('a session sign-off on a record that names no session: false, and status stays valid', () => {
    const moved = clone(first);
    moved.nonRepudiation = {
      signoff: { statement: { mode: 'session' }, sessionSeq: 1 },
    } as unknown as EvidenceEnvelope['nonRepudiation'];
    const verdict = recordVerdict(moved, { registry, custody });
    expect(verdict.signoffExpectation).toEqual({ valid: false, reason: 'session_signoff_not_expected' });
    expect(verdict.status).toBe('valid');
  });

  it('not read when the digest does not recompute: an expectation rewritten to null is null, digest_invalid', () => {
    const owed = clone(first);
    owed.payload.signoffExpectation = { policyDigest: 'c'.repeat(64) };
    owed.integrity.canonicalDigest = recordDigestCheck(owed, registry).recomputed;
    owed.payload.signoffExpectation = null;
    const verdict = recordVerdict(owed, { registry, custody });
    expect(verdict.digest).toMatchObject({ status: 'invalid', reason: 'digest_mismatch' });
    expect(verdict.signoffExpectation).toEqual({ valid: null, reason: 'digest_invalid' });
  });

  it('not read when the envelope disagrees with the digest the store holds', () => {
    // Rewritten consistently: the payload recomputes to the envelope's own
    // digest, which is not the one the store froze.
    const rewritten = clone(first);
    rewritten.payload.signoffExpectation = null;
    rewritten.payload.reason = 'rewritten';
    rewritten.integrity.canonicalDigest = recordDigestCheck(rewritten, registry).recomputed;
    const verdict = recordVerdict(rewritten, { registry, custody, currentDigest: first.integrity.canonicalDigest });
    expect(verdict.digest).toMatchObject({ status: 'invalid', reason: 'stored_digest_mismatch' });
    expect(verdict.signoffExpectation).toEqual({ valid: null, reason: 'digest_invalid' });
  });

  it('not read under an unknown schema version, nor for a payload that cannot be serialized', () => {
    const unknown = clone(first);
    unknown.payload.schemaVersion = 'v9';
    expect(recordVerdict(unknown, { registry, custody }).signoffExpectation).toEqual({ valid: null, reason: 'digest_invalid' });
    const unserializable = clone(first);
    unserializable.payload.reason = 'lone \ud800';
    expect(recordVerdict(unserializable, { registry, custody }).signoffExpectation).toEqual({ valid: null, reason: 'digest_invalid' });
  });

  it('absent for a row the store holds no record for, and when reads are unmeasured', () => {
    expect(recordVerdict(null, { registry, custody })).not.toHaveProperty('signoffExpectation');
    expect(unmeasuredRecordVerdict(first)).not.toHaveProperty('signoffExpectation');
  });
});
