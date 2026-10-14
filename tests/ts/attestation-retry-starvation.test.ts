/**
 * The retry pass lists records by the retry-obtainable component they are
 * missing, never by the status word, and it never anchors.
 *
 * Why that matters: a pass that read the oldest `limit` records whose status
 * is 'pending' would starve. A record waiting for something the pass cannot
 * obtain (an anchor, which only an anchor scheduler fills, or a human
 * signature) is still 'pending' and still old, so enough of them fill every
 * page, and a record behind them that only needs a timestamp is never read.
 *
 * Here 200 records waiting for an anchor and 200 waiting for a signature, all
 * parked 'pending' and all older, stand in front of one record missing its
 * timestamp. One pass with `limit: 100` must timestamp it.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tzun } from '../../src/sdk/index';
import type { CaptureInput, TzunConfig } from '@tzun/engine';
import { mockTsaFetch } from './helpers/mock-tsa';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

const decision = (label: string): CaptureInput => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve', label },
  action: 'approved',
  reason: `Decision ${label}`,
});

const WAITING_FOR_ANCHOR = 200;
const WAITING_FOR_SIGNATURE = 200;
// 401 captures. On Postgres under a full parallel run they queue behind other
// workers' DDL (ensureTables() holds a database-wide advisory lock), so the
// case gets well past the time it takes alone.
const CASE_TIMEOUT_MS = 240_000;

interface Leg {
  name: string;
  config: () => Promise<Partial<TzunConfig>>;
  cleanup: () => Promise<void>;
}

const pgSchema = PG_TESTS_ENABLED ? pgSuiteSchema('retry_starvation') : null;

let dir: string;
const legs: Leg[] = [
  {
    name: 'memory',
    config: async () => ({ mode: 'dev' }),
    cleanup: async () => { /* nothing on disk */ },
  },
  {
    name: 'sqlite',
    config: async () => {
      dir = mkdtempSync(join(tmpdir(), 'tzun-test-retry-starvation-'));
      return { mode: 'dev', dbPath: join(dir, 'starvation.db') };
    },
    cleanup: async () => rmSync(dir, { recursive: true, force: true }),
  },
  ...(pgSchema
    ? [{
        name: 'postgres',
        config: async () => {
          await pgSchema.empty();
          return { mode: 'dev' as const, dbUrl: pgSchema.url };
        },
        cleanup: async () => { /* the schema helper drops it */ },
      }]
    : []),
];

describe.each(legs)('the retry pass is not starved by records it cannot help ($name)', (leg) => {
  let savedFetch: typeof globalThis.fetch;
  let tsaUp: boolean;
  let tzun: Tzun;

  beforeEach(async () => {
    savedFetch = globalThis.fetch;
    tsaUp = true;
    const tsa = mockTsaFetch();
    globalThis.fetch = jest.fn(async (...args: Parameters<typeof fetch>) => {
      if (!tsaUp) throw new Error('TSA unreachable');
      return tsa(...args);
    }) as unknown as typeof fetch;

    tzun = await Tzun.init({
      ...(await leg.config()),
      attestation: {
        deferrable: ['timestamp'],
        timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
      },
    });
  });

  afterEach(async () => {
    await tzun.close();
    globalThis.fetch = savedFetch;
    await leg.cleanup();
  });

  it('a record missing its timestamp is timestamped in the first pass, behind 400 older waiting records', async () => {
    const storage = tzun.getStorage();

    // Four hundred records that hold their timestamp and wait for something
    // the retry pass cannot obtain. Each is parked 'pending', the status of a
    // record awaiting its anchor, and the signature-awaiting ones are parked
    // the same way so that they, too, would sit in a status-keyed page.
    const waiting: string[] = [];
    for (let i = 0; i < WAITING_FOR_ANCHOR + WAITING_FOR_SIGNATURE; i++) {
      const kind = i < WAITING_FOR_ANCHOR ? 'anchor' : 'signature';
      const { envelope, stored } = await tzun.capture(decision(`${kind}-${i}`));
      expect(stored).toBe(true);
      expect(envelope.nonRepudiation.rfc3161Token).toBeDefined();
      await storage.updateAttestation(envelope.payload.evidenceId, {}, 'pending');
      waiting.push(envelope.payload.evidenceId);
    }

    // The newest record: no authority answered, so it has no timestamp.
    tsaUp = false;
    const late = await tzun.capture(decision('missing-timestamp'));
    expect(late.stored).toBe(true);
    expect(late.envelope.attestationStatus).toBe('pending');
    expect(late.envelope.nonRepudiation.rfc3161Token).toBeUndefined();
    const lateId = late.envelope.payload.evidenceId;

    // Every one of the 401 is 'pending', and the late one is the newest.
    const pending = await storage.listByAttestationStatus('pending');
    expect(pending).toHaveLength(waiting.length + 1);
    expect(pending[pending.length - 1].payload.evidenceId).toBe(lateId);

    tsaUp = true;
    const result = await tzun.retryPendingAttestations({ limit: 100 });

    expect(result).toMatchObject({ attempted: 1, succeeded: 1, failed: 0 });
    expect(result.details).toEqual([{ evidenceId: lateId, success: true }]);
    const after = await storage.retrieve(lateId);
    expect(after!.nonRepudiation.rfc3161Token).toBeDefined();
    expect(after!.attestationStatus).toBe('partial');

    // The waiting records were neither listed nor touched.
    for (const id of [waiting[0], waiting[WAITING_FOR_ANCHOR], waiting[waiting.length - 1]]) {
      const rec = await storage.retrieve(id);
      expect(rec!.attestationStatus).toBe('pending');
    }
  }, CASE_TIMEOUT_MS);

  it('the pass lists what it can obtain, not what is pending', async () => {
    const storage = tzun.getStorage();
    const listByStatus = jest.spyOn(storage, 'listByAttestationStatus');
    const listByMissing = jest.spyOn(storage, 'listByMissingObtainable');

    tsaUp = false;
    await tzun.capture(decision('one'));
    tsaUp = true;
    await tzun.retryPendingAttestations({ limit: 7 });

    expect(listByStatus).not.toHaveBeenCalled();
    expect(listByMissing).toHaveBeenCalledWith(['timestamp'], 7);
  });
});
