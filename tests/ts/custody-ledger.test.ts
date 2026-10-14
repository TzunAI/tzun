import { testEvidenceId } from './helpers/evidence-id';
/**
 * `verifyCustodyLedger` — a record's custody trail against its
 * `custody_entries` rows, the engine twin of the platform's
 * `verifyCustodyTrailOf`, reason for reason. Pure, so tested on built rows.
 *
 * The rows here are built in the ADAPTER's form (`StoredCustodyEntry`, what
 * `listCustodyEntries` returns) and carried into the check through
 * `toCustodyLedgerEntry`, which is the path the scanner and the chain walk
 * take. `packages/engine/src/record-verdict.test.ts` drives the same function
 * over rows in the export-bundle form a read and an offline verifier use.
 */
import {
  CustodyEntry,
  EvidenceEnvelope,
  StoredCustodyEntry,
  assembleEnvelope,
  computeCustodyEntryHash,
  mirrorCustodyEntry,
  toCustodyLedgerEntry,
  verifyCustodyLedger,
} from '@tzun/engine';

const envelope = (): EvidenceEnvelope =>
  assembleEnvelope({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiSystemId: 's', aiOutput: { r: 1 }, action: 'approved', reason: 'r' }, { sequenceNumber: 1, signoffExpectation: null, evidenceId: testEvidenceId('ev-1') });

const entry = (actor: string): CustodyEntry => ({
  timestamp: '2026-09-19T10:00:00.000Z',
  actor,
  action: 'reviewed',
  systemId: 'tzun-recovery',
  metadata: { incidentId: 'inc-1' },
});

/** Rows and a mirrored envelope for `actors`, exactly as an adapter writes them. */
function trail(actors: string[]): { env: EvidenceEnvelope; rows: StoredCustodyEntry[] } {
  const env = envelope();
  const rows: StoredCustodyEntry[] = [];
  let prev: string | null = null;
  actors.forEach((actor, i) => {
    const e = entry(actor);
    const entryHash = computeCustodyEntryHash({
      prevEntryHash: prev,
      evidenceId: env.payload.evidenceId,
      canonicalDigest: env.integrity.canonicalDigest,
      action: e.action,
      actor: e.actor,
      timestamp: e.timestamp,
      systemId: e.systemId,
      metadata: e.metadata ?? null,
    });
    rows.push({
      id: i + 1,
      evidenceId: env.payload.evidenceId,
      chainId: 'default',
      canonicalDigest: env.integrity.canonicalDigest,
      action: e.action,
      actor: e.actor,
      timestamp: e.timestamp,
      systemId: e.systemId,
      metadata: e.metadata ?? null,
      prevEntryHash: prev,
      entryHash,
      recoveryId: null,
    });
    env.custodyChain.push(mirrorCustodyEntry(e, entryHash, prev));
    prev = entryHash;
  });
  return { env, rows };
}

/** The verdict over adapter rows, exactly as the scanner and the walk take it. */
const verdict = (env: EvidenceEnvelope, rows: StoredCustodyEntry[]) =>
  verifyCustodyLedger(env.payload.evidenceId, env, undefined, rows.map(toCustodyLedgerEntry));

const failures = (env: EvidenceEnvelope, rows: StoredCustodyEntry[]) => verdict(env, rows).failures;

const reasons = (env: EvidenceEnvelope, rows: StoredCustodyEntry[]) =>
  failures(env, rows).map((f) => f.reason);

describe('verifyCustodyLedger', () => {
  it('agrees with an intact trail', () => {
    const { env, rows } = trail(['a', 'b']);
    expect(verdict(env, rows)).toEqual({
      evidenceId: env.payload.evidenceId,
      valid: true,
      rows: 2,
      hashedEntries: 2,
      // `custodyChain[0]` is the client-attested capture entry: counted, and
      // legal before the hashed ones.
      unhashedEntries: 1,
      failures: [],
    });
  });

  it('row_hash_mismatch: a row rewritten in the ledger', () => {
    const { env, rows } = trail(['a', 'b']);
    rows[0] = { ...rows[0], actor: 'x' };
    // The mirror still recomputes from its own fields; only the row moved.
    expect(failures(env, rows)).toEqual([{ reason: 'row_hash_mismatch', rowId: '1' }]);
  });

  it('row_prev_mismatch: a row that does not extend the one before it', () => {
    const { env, rows } = trail(['a', 'b']);
    rows[1] = { ...rows[1], prevEntryHash: null };
    // The row no longer extends row 1, no longer recomputes to its own hash,
    // and no longer carries the prev its mirror entry does.
    expect(reasons(env, rows)).toEqual([
      'row_prev_mismatch',
      'row_hash_mismatch',
      'mirror_prev_mismatch',
    ]);
  });

  it('digest_moved_since_entry: the record changed after the custody action', () => {
    const { env, rows } = trail(['a']);
    env.integrity.canonicalDigest = 'f'.repeat(64);
    expect(reasons(env, rows)).toEqual(['digest_moved_since_entry']);
  });

  it('mirror_entry_missing: the last entry deleted from the envelope', () => {
    const { env, rows } = trail(['a', 'b']);
    env.custodyChain.pop();
    expect(failures(env, rows)).toEqual([{ reason: 'mirror_entry_missing', rowId: '2' }]);
  });

  it('mirror_entry_unexpected: a hashed entry with no row behind it', () => {
    const { env, rows } = trail(['a', 'b']);
    const index = env.custodyChain.length - 1;
    expect(failures(env, rows.slice(0, 1))).toEqual([{ reason: 'mirror_entry_unexpected', index }]);
  });

  it('mirror_hash_mismatch and mirror_fields_mismatch: an entry that is not its row', () => {
    const { env, rows } = trail(['a']);
    const index = env.custodyChain.length - 1;
    (env.custodyChain[index] as { entryHash: string }).entryHash = 'e'.repeat(64);
    expect(failures(env, rows)).toEqual([
      { reason: 'mirror_hash_mismatch', index, rowId: '1' },
      { reason: 'mirror_fields_mismatch', index, rowId: '1' },
    ]);
  });

  it('mirror_prev_mismatch: an entry whose prevEntryHash is not its row\'s', () => {
    const { env, rows } = trail(['a', 'b']);
    const index = env.custodyChain.length - 1;
    (env.custodyChain[index] as { prevEntryHash: string | null }).prevEntryHash = null;
    expect(failures(env, rows)).toEqual([
      { reason: 'mirror_prev_mismatch', index, rowId: '2' },
      { reason: 'mirror_fields_mismatch', index, rowId: '2' },
    ]);
  });

  it('reports, and does not throw on, an entry whose fields the hash rule cannot consume', () => {
    const { env, rows } = trail(['a']);
    const index = env.custodyChain.length - 1;
    (env.custodyChain[index] as unknown as { actor: unknown }).actor = 123;
    expect(() => verdict(env, rows)).not.toThrow();
    expect(failures(env, rows)).toEqual([
      { reason: 'mirror_fields_mismatch', index, rowId: '1', detail: expect.any(String) },
    ]);
  });
});
