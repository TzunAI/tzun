/**
 * Server-minted custody-entry hashes ride inside the envelope.
 *
 * The platform's custody ledger hash-chains every relink/fork custody entry
 * into a `custody_entries` row and mirrors that row into
 * `envelope.custodyChain[i]` as `{ ...entry, entryHash, prevEntryHash }`.
 * `CustodyEntry` declares both keys, so a repaired record's export is an
 * envelope the published SDK can type and the generated Python model
 * (`extra="forbid"`) accepts; without them that model would refuse the export
 * with `extra_forbidden` on `entryHash`. The keys are OUTSIDE the hashed field
 * set: present or absent, they change no canonical byte and no digest. These
 * tests pin exactly that, plus the storage adapters carrying them through
 * unchanged.
 *
 * If `CustodyEntry` dropped the keys, ts-jest would fail this file at compile
 * time on `serverMinted` below (TS2353: 'entryHash' does not exist in type
 * 'CustodyEntry').
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  assembleEnvelope,
  verifyEnvelope,
  SchemaRegistry,
  canonicalSerialize,
  computeDigest,
} from '@tzun/engine';
import type { EnvelopeInput, CustodyAction, CustodyEntry, EvidenceEnvelope } from '@tzun/engine';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';

const input: EnvelopeInput = {
  aiSystemId: 'sys-1',
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'criteria met',
  decider: { kind: 'human' as const, id: 'acct:jane-acme.com', agent: null, credential: null, freshness: null },
};

const ENTRY_HASH_1 = 'sha256:' + 'a'.repeat(64);
const ENTRY_HASH_2 = 'sha256:' + 'b'.repeat(64);

/** The shape the platform mirrors into the envelope for a hash-chained custody row. */
function serverMinted(
  entryHash: string,
  prevEntryHash: string | null,
  action: CustodyAction = 'relinked',
): CustodyEntry {
  return {
    timestamp: '2026-09-09T10:00:00.000Z',
    actor: 'admin@acme.example',
    action,
    systemId: 'hosted-platform',
    metadata: { recoveryId: 'rec-1' },
    entryHash,
    prevEntryHash,
  };
}

/** A deep copy of `envelope` with two server-minted entries appended after the client one. */
function withServerEntries(envelope: EvidenceEnvelope): EvidenceEnvelope {
  const copy = JSON.parse(JSON.stringify(envelope)) as EvidenceEnvelope;
  copy.custodyChain.push(
    serverMinted(ENTRY_HASH_1, null),
    serverMinted(ENTRY_HASH_2, ENTRY_HASH_1, 'chain_forked'),
  );
  return copy;
}

describe('server-minted entryHash / prevEntryHash on CustodyEntry', () => {
  const registry = new SchemaRegistry();

  it('custodyChain — and therefore entryHash / prevEntryHash — is outside the v1.0 hashed field set', () => {
    const hashed = registry.get('v1.0')!.hashedFieldSet;
    expect(hashed).not.toContain('custodyChain');
    expect(hashed).not.toContain('entryHash');
    expect(hashed).not.toContain('prevEntryHash');
    // The set the two keys are outside of, spelled out so a v1.1 that hashes
    // the custody chain has to come through here.
    expect([...hashed].sort()).toEqual([
      'action', 'aiOutput', 'aiSystemId', 'capturedAt', 'contributions', 'decider', 'evidenceId', 'links', 'reason',
      'sequenceNumber', 'signoffExpectation',
    ]);
  });

  it('an envelope whose custodyChain carries the keys canonicalises to the SAME digest and passes verifyEnvelope', () => {
    const first = assembleEnvelope(input, { sequenceNumber: 1 });
    const second = assembleEnvelope(input, { previousDigest: first.integrity.canonicalDigest, sequenceNumber: 2 });
    const mirrored = withServerEntries(second);

    // The copy really carries the keys (a silent drop would make the rest vacuous).
    expect(mirrored.custodyChain).toHaveLength(3);
    expect(mirrored.custodyChain[1].entryHash).toBe(ENTRY_HASH_1);
    expect(mirrored.custodyChain[1].prevEntryHash).toBeNull();
    expect(mirrored.custodyChain[2].entryHash).toBe(ENTRY_HASH_2);
    expect(mirrored.custodyChain[2].prevEntryHash).toBe(ENTRY_HASH_1);

    const hashed = registry.get('v1.0')!.hashedFieldSet;
    const bytesBefore = canonicalSerialize(second.payload as unknown as Record<string, unknown>, hashed);
    const bytesAfter = canonicalSerialize(mirrored.payload as unknown as Record<string, unknown>, hashed);
    expect(bytesAfter).toBe(bytesBefore);
    expect(computeDigest(bytesAfter)).toBe(second.integrity.canonicalDigest);

    const before = verifyEnvelope(second, first.integrity.canonicalDigest, registry);
    const after = verifyEnvelope(mirrored, first.integrity.canonicalDigest, registry);
    expect(before.verified).toBe(true);
    expect(after.verified).toBe(true);
    expect(after.recomputedDigest).toBe(before.recomputedDigest);
    expect(after.recomputedDigest).toBe(second.integrity.canonicalDigest);
    expect(after.chainLinkValid).toBe(true);
    expect(after.schemaValid).toBe(true);
  });

  it('a client-attested entry has neither key — they are optional, never defaulted', () => {
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });
    const [captured] = envelope.custodyChain;
    expect(captured.action).toBe('decision_captured');
    expect(Object.prototype.hasOwnProperty.call(captured, 'entryHash')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(captured, 'prevEntryHash')).toBe(false);
    // What goes on the wire for a fresh capture: exactly the keys the platform's
    // capture allowlist (envelope-schema.ts CUSTODY_ENTRY_KEYS) accepts.
    const wire = JSON.parse(JSON.stringify(envelope)) as EvidenceEnvelope;
    expect(Object.keys(wire.custodyChain[0]).sort()).toEqual(['action', 'actor', 'systemId', 'timestamp']);
  });

  describe('storage adapters carry the keys through unchanged', () => {
    let dbPath: string;
    let sqlite: SqliteStorageAdapter;

    beforeEach(() => {
      dbPath = path.join(os.tmpdir(), `tzun-test-custody-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
      sqlite = new SqliteStorageAdapter(dbPath);
    });

    afterEach(() => {
      sqlite.close();
      for (const suffix of ['', '-wal', '-shm']) {
        try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
      }
    });

    it.each([
      ['memory', () => new MemoryStorageAdapter()],
      ['sqlite', () => sqlite],
    ])('%s: store → retrieve preserves entryHash / prevEntryHash; appendCustodyEntry mints its own', async (_name, make) => {
      const adapter = make();
      const envelope = withServerEntries(assembleEnvelope(input, { sequenceNumber: 1 }));
      await adapter.store(envelope);

      const stored = await adapter.retrieve(envelope.payload.evidenceId);
      expect(stored).not.toBeNull();
      expect(stored!.custodyChain).toEqual(envelope.custodyChain);

      // appendCustodyEntry mints the hash itself, chained to the record's
      // previous custody row and bound to its digest; a caller-supplied
      // entryHash / prevEntryHash is ignored and replaced. Storing the
      // caller's value verbatim would be a forgery path: any code with the
      // adapter in hand could append an entry that LOOKED authenticated.
      const forged = serverMinted('sha256:' + 'c'.repeat(64), ENTRY_HASH_2, 'reviewed');
      await adapter.appendCustodyEntry(envelope.payload.evidenceId, forged);
      const appended = await adapter.retrieve(envelope.payload.evidenceId);
      expect(appended!.custodyChain).toHaveLength(4);
      const minted = appended!.custodyChain[3];
      expect(minted.entryHash).toMatch(/^[0-9a-f]{64}$/);
      expect(minted.entryHash).not.toBe(forged.entryHash);
      // First writer-hashed entry on this record: the platform's mirrored
      // entries above carry a prefixed (non-hex) entryHash and are therefore
      // not part of the local ledger's chain.
      expect(minted.prevEntryHash).toBeNull();
      expect(minted).toMatchObject({ timestamp: forged.timestamp, actor: forged.actor, action: 'reviewed', systemId: forged.systemId, metadata: forged.metadata });
      // And the record still verifies with them in place.
      expect(verifyEnvelope(appended!, undefined, registry).verified).toBe(true);
    });
  });
});
