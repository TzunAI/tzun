/**
 * `exportEvidence()` ships an offline-verifiable bundle:
 * the verdict, the record's custody ledger rows, and its predecessor, so an
 * auditor holding only the file can check the digest, the custody trail and
 * the chain link.
 *
 * Every bundle below is verified by `verifyExported` after a JSON round trip
 * — the file an auditor is handed — with no store in reach.
 *
 * Legs: memory and sqlite always; postgres when the Postgres legs run
 * (tests/ts/helpers/postgres-test-db.ts), in a schema of this file's own,
 * emptied before each case.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  CUSTODY_ENTRY_HASH_PREIMAGE,
  EvidenceChain,
  verifyCustodyTrail,
} from '@tzun/engine';
import type { EvidenceEnvelope, ExportedEvidenceEnvelope, TamperIncident, TzunConfig } from '@tzun/engine';
import { Tzun } from '../../src/sdk/index';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
import { PlatformExportBundle, verifyExported } from './helpers/verify-exported';

const HEX64 = /^[0-9a-f]{64}$/;
// A schema of this file's own, emptied before each Postgres case.
const pgSchema = pgSuiteSchema('export_verdict');

interface Leg {
  name: 'memory' | 'sqlite' | 'postgres';
  config: () => Promise<{ config: TzunConfig; teardown: () => Promise<void> }>;
}

const legs: Leg[] = [
  { name: 'memory', config: async () => ({ config: {}, teardown: async () => undefined }) },
  {
    name: 'sqlite',
    config: async () => {
      const dbPath = path.join(os.tmpdir(), `tzun-test-export-verdict-${process.pid}-${Math.random().toString(36).slice(2)}.db`);
      return {
        config: { dbPath },
        teardown: async () => {
          for (const suffix of ['', '-wal', '-shm']) {
            try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
          }
        },
      };
    },
  },
];
if (PG_TESTS_ENABLED) {
  legs.push({
    name: 'postgres',
    config: async () => {
      await pgSchema.empty();
      return { config: { dbUrl: pgSchema.url }, teardown: async () => undefined };
    },
  });
}

/** The bundle as an auditor receives it: a file, parsed. */
function asFile<T>(bundle: T): T {
  return JSON.parse(JSON.stringify(bundle)) as T;
}

function errorsOf(result: Awaited<ReturnType<typeof verifyExported>>): string[] {
  return result.ok ? [] : result.errors;
}

async function captureThree(tzun: Tzun): Promise<EvidenceEnvelope[]> {
  const out: EvidenceEnvelope[] = [];
  for (let i = 1; i <= 3; i++) {
    const r = await tzun.capture({
      aiOutput: { step: i },
      action: 'approved',
      reason: `step ${i}`,
      decider: { kind: 'human' as const, id: 'acct:reviewer-acme.com', agent: null, credential: null, freshness: null },
    });
    expect(r.stored).toBe(true);
    out.push(r.envelope);
  }
  return out;
}

async function annotate(tzun: Tzun, evidenceId: string, incidentId = 'inc-export'): Promise<string> {
  const incident: TamperIncident = {
    id: incidentId,
    detectedAt: new Date().toISOString(),
    severity: 'warning',
    type: 'digest_mismatch',
    affectedRecords: [evidenceId],
    details: 'reviewed before export',
    status: 'open',
  };
  await tzun.getStorage().storeIncident(incident);
  const result = await tzun.recovery.annotate(incidentId, { authorizedBy: 'auditor@acme.example', notes: 'reviewed' });
  return result.annotation.id;
}

describe.each(legs)('exportEvidence ships a bundle an auditor can verify offline — $name', (leg) => {
  let tzun: Tzun;
  let teardown: () => Promise<void>;

  beforeEach(async () => {
    const made = await leg.config();
    teardown = made.teardown;
    tzun = await Tzun.init(made.config);
  });

  afterEach(async () => {
    await tzun.close();
    await teardown();
  });

  it('carries the predecessor, the custody ledger and a valid verdict, and verifies with no store', async () => {
    const [first, second] = await captureThree(tzun);
    const bundle = await tzun.exportEvidence(second.payload.evidenceId);

    expect(bundle.chain).toEqual({
      chainId: await tzun.getActiveChainId(),
      predecessor: {
        evidenceId: first.payload.evidenceId,
        sequenceNumber: 1,
        canonicalDigest: first.integrity.canonicalDigest,
      },
    });
    expect(bundle.verdict.status).toBe('valid');
    expect(bundle.verdict.digest.status).toBe('valid');
    expect(bundle.verdict.chainLink).toEqual({
      status: 'valid',
      predecessorDigest: first.integrity.canonicalDigest,
    });
    expect(bundle.custody).toEqual({
      hashPreimage: CUSTODY_ENTRY_HASH_PREIMAGE,
      entries: [],
      trail: {
        evidenceId: second.payload.evidenceId,
        valid: true,
        rows: 0,
        hashedEntries: 0,
        unhashedEntries: 1,
        failures: [],
      },
      offlineTrail: { valid: null, hashedEntries: 0, unhashedEntries: 1, failures: [] },
    });

    expect(await verifyExported(asFile(bundle))).toEqual({ ok: true });
  });

  it('a genesis record has no predecessor and a valid link', async () => {
    const [first] = await captureThree(tzun);
    const bundle = await tzun.exportEvidence(first.payload.evidenceId);
    expect(bundle.chain.predecessor).toBeNull();
    expect(bundle.verdict.chainLink).toEqual({ status: 'valid', predecessorDigest: null });
    expect(await verifyExported(asFile(bundle))).toEqual({ ok: true });
  });

  it('a swapped predecessor digest fails the offline chain-link check', async () => {
    const [, second] = await captureThree(tzun);
    const bundle = asFile(await tzun.exportEvidence(second.payload.evidenceId));
    bundle.chain.predecessor!.canonicalDigest = 'a'.repeat(64);

    const errors = errorsOf(await verifyExported(bundle));
    expect(errors.some((e) => /chain: integrity\.chainLink .* does not recompute from the bundled predecessor digest/.test(e))).toBe(true);
    // The exporter said valid; the bundle as received no longer recomputes to that.
    expect(errors.some((e) => /verdict: the bundle's verdict says "valid" but the bundle recomputes to "invalid"/.test(e))).toBe(true);
  });

  it('a record presented without its predecessor cannot pass as standalone', async () => {
    const [, second] = await captureThree(tzun);
    const lifted = asFile(await tzun.exportEvidence(second.payload.evidenceId));
    lifted.chain.predecessor = null;
    expect(errorsOf(await verifyExported(lifted))).toContain(
      'chain: integrity.chainLink is set but the bundle names no predecessor to check it against',
    );

    const noChain = asFile(await tzun.exportEvidence(second.payload.evidenceId)) as Partial<ExportedEvidenceEnvelope>;
    delete noChain.chain;
    expect(errorsOf(await verifyExported(noChain as ExportedEvidenceEnvelope))).toContain(
      'chain: the bundle carries no predecessor, so integrity.chainLink cannot be checked',
    );
  });

  it('a predecessor from another position is reported even when its digest is right', async () => {
    const [, second] = await captureThree(tzun);
    const bundle = asFile(await tzun.exportEvidence(second.payload.evidenceId));
    bundle.chain.predecessor!.sequenceNumber = 7;
    expect(errorsOf(await verifyExported(bundle)).some((e) => /predecessor is at sequence 7, not at the one before 2/.test(e))).toBe(true);
  });

  it('a repaired record ships its ledger rows in the platform export shape, and they verify', async () => {
    const [first] = await captureThree(tzun);
    const annotationId = await annotate(tzun, first.payload.evidenceId);
    const bundle = await tzun.exportEvidence(first.payload.evidenceId);

    expect(bundle.custody.entries).toHaveLength(1);
    const [row] = bundle.custody.entries!;
    expect(Object.keys(row).sort()).toEqual(
      ['action', 'actor', 'actorParty', 'canonicalDigest', 'entryHash', 'id', 'metadata', 'prevEntryHash', 'recordedAt', 'recoveryId', 'systemId', 'timestamp'],
    );
    expect(row).toMatchObject({
      action: 'reviewed',
      actor: 'auditor@acme.example',
      actorParty: null,
      canonicalDigest: first.integrity.canonicalDigest,
      prevEntryHash: null,
      recoveryId: annotationId,
      recordedAt: null,
      systemId: 'tzun-recovery',
    });
    expect(typeof row.id).toBe('string');
    expect(row.entryHash).toMatch(HEX64);
    expect(bundle.custody.trail).toMatchObject({ valid: true, rows: 1, hashedEntries: 1 });
    expect(bundle.custody.offlineTrail).toMatchObject({ valid: true, hashedEntries: 1 });
    expect(bundle.verdict.custodyTrail.status).toBe('valid');

    expect(await verifyExported(asFile(bundle))).toEqual({ ok: true });
  });

  it('the last custody entry cut from the bundled envelope passes the envelope-only check and fails the ledger check', async () => {
    const [first] = await captureThree(tzun);
    await annotate(tzun, first.payload.evidenceId, 'inc-1');
    await annotate(tzun, first.payload.evidenceId, 'inc-2');
    const bundle = asFile(await tzun.exportEvidence(first.payload.evidenceId));
    bundle.envelope.custodyChain.pop();

    expect(verifyCustodyTrail(bundle.envelope).valid).toBe(true);
    expect(errorsOf(await verifyExported(bundle)).some((e) => e.startsWith('custody: mirror_entry_missing (row '))).toBe(true);
  });

  it('a ledger row rewritten in the bundle does not recompute', async () => {
    const [first] = await captureThree(tzun);
    await annotate(tzun, first.payload.evidenceId);
    const bundle = asFile(await tzun.exportEvidence(first.payload.evidenceId));
    bundle.custody.entries![0].actor = 'mallory@acme.example';
    expect(errorsOf(await verifyExported(bundle)).some((e) => e.startsWith('custody: row_hash_mismatch'))).toBe(true);
  });

  it('a record tampered in the store is exported all the same, with the verdict saying so', async () => {
    const [, second] = await captureThree(tzun);
    await rewriteStoredEnvelope(tzun.getStorage(), second.payload.evidenceId, (e) => {
      e.payload.reason = 'rewritten in the store';
    });

    const bundle = await tzun.exportEvidence(second.payload.evidenceId);
    expect(bundle.envelope.payload.reason).toBe('rewritten in the store');
    expect(bundle.verdict.status).toBe('invalid');
    expect(bundle.verdict.digest.reason).toBe('digest_mismatch');
    expect(errorsOf(await verifyExported(asFile(bundle))).some((e) => /integrity digest mismatch/.test(e))).toBe(true);
  });

  it('a custody ledger that cannot be read does not stop the export; the bundle says what is missing', async () => {
    const [first] = await captureThree(tzun);
    tzun.getStorage().listCustodyEntries = async () => {
      throw new Error('custody_entries is unreadable');
    };

    const bundle = await tzun.exportEvidence(first.payload.evidenceId);
    expect(bundle.custody.entries).toBeNull();
    expect(bundle.custody.trail).toBeNull();
    expect(bundle.verdict.custodyTrail).toEqual({
      status: 'unmeasured',
      reason: 'custody_ledger_unreadable',
      ledger: null,
      detail: 'custody_entries is unreadable',
    });
    expect(errorsOf(await verifyExported(asFile(bundle)))).toEqual([
      'custody: the bundle carries no custody ledger rows, so the custody trail cannot be checked',
    ]);
  });

  it('verifyReads: false does not weaken the export', async () => {
    await tzun.close();
    const made = await leg.config();
    teardown = made.teardown;
    tzun = await Tzun.init({ ...made.config, verifyReads: false });
    const [, second] = await captureThree(tzun);
    const bundle = await tzun.exportEvidence(second.payload.evidenceId);
    expect(bundle.verdict.status).toBe('valid');
    expect(bundle.verdict.digest.recomputed).toBe(second.integrity.canonicalDigest);
    expect(await verifyExported(asFile(bundle))).toEqual({ ok: true });
  });

  it('one offline verifier reads the platform export shape too, and names what it lacks', async () => {
    const [first, second] = await captureThree(tzun);
    const asPlatform = async (evidenceId: string): Promise<PlatformExportBundle> => {
      const b = await tzun.exportEvidence(evidenceId);
      return asFile({
        envelope: b.envelope,
        server: { receivedAt: b.exportedAt ?? null, attestation: {}, custody: b.custody },
      });
    };

    expect(await verifyExported(await asPlatform(first.payload.evidenceId))).toEqual({ ok: true });
    expect(errorsOf(await verifyExported(await asPlatform(second.payload.evidenceId)))).toEqual([
      'chain: the bundle carries no predecessor, so integrity.chainLink cannot be checked',
    ]);
  });
});

describe('exportEvidence when the predecessor is gone', () => {
  it('ships a null predecessor and a verdict naming it missing', async () => {
    const tzun = await Tzun.init();
    try {
      const [first, second] = await captureThree(tzun);
      const rows = (tzun.getStorage() as unknown as { envelopes: Map<string, EvidenceEnvelope> }).envelopes;
      expect(tzun.getStorage()).toBeInstanceOf(MemoryStorageAdapter);
      rows.delete(first.payload.evidenceId);

      const bundle = await tzun.exportEvidence(second.payload.evidenceId);
      expect(bundle.chain.predecessor).toBeNull();
      expect(bundle.verdict.status).toBe('invalid');
      expect(bundle.verdict.chainLink).toEqual({
        status: 'invalid',
        reason: 'predecessor_missing',
        predecessorDigest: null,
      });
      // The link is still what the store captured: with the deleted record's
      // digest, an auditor who has it elsewhere can check it.
      const chain = new EvidenceChain();
      chain.restore(first.integrity.canonicalDigest);
      expect(bundle.envelope.integrity.chainLink).toBe(chain.computeLink(second.integrity.canonicalDigest));
    } finally {
      await tzun.close();
    }
  });
});
