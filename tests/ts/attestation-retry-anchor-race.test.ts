/**
 * A pending-attestation retry that races the anchor fill.
 *
 * On an instance that anchors, a record captured while its timestamp
 * authority is down is `pending` for two components: the timestamp, which
 * the retry obtains, and the anchor, which the anchor scheduler fills. When
 * the authority comes back while an epoch's fill is running, the retry can
 * list the record, wait on the authority, and write the token after the fill
 * has written the anchor. The status must then come from the record as
 * stored (timestamp and anchor: `partial`), not from the copy the retry
 * listed (no anchor: `pending`); a record left `pending` with both would
 * never be listed again, by the retry or by the fill.
 *
 * `updateAttestation()` takes the status as a function of the envelope as it
 * will be stored, and computes it under its own lock. On SQLite always, on
 * Postgres when its legs run, and on the memory adapter at the storage level.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Wallet } from 'ethers';
import type { CaptureInput, EvidenceEnvelope, TzunConfig } from '@tzun/engine';
import { determineAttestationStatus } from '@tzun/engine';
import { Tzun } from '../../src/sdk/index';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { FakeEvmChain } from './helpers/anchoring-fake-chain';
import { mockTsaFetch } from './helpers/mock-tsa';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

const CHAIN = 'eip155:31337';
const NS = 'test.retry-race.tzun';
const ETH = 10n ** 18n;

const decision = (i: number): CaptureInput => ({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: `record ${i}` });

interface Backend {
  name: string;
  fresh(): Promise<Record<string, unknown>>;
  dispose(): void;
}

function sqliteBackend(): Backend {
  let dir: string | undefined;
  return {
    name: 'sqlite',
    async fresh() {
      if (dir) rmSync(dir, { recursive: true, force: true });
      dir = mkdtempSync(join(tmpdir(), 'tzun-test-retry-race-'));
      return { dbPath: join(dir, 'store.db') };
    },
    dispose() {
      if (dir) rmSync(dir, { recursive: true, force: true });
    },
  };
}

function postgresBackend(): Backend | undefined {
  const schema = pgSuiteSchema('retry_anchor_race');
  if (!PG_TESTS_ENABLED) return undefined;
  return {
    name: 'postgres',
    async fresh() {
      await schema.reset();
      return { dbUrl: schema.url };
    },
    dispose: () => undefined,
  };
}

const backends = [sqliteBackend(), postgresBackend()].filter((b): b is Backend => b !== undefined);

describe.each(backends.map((b) => [b.name, b] as const))('a retry that races the anchor fill, on %s', (_name, backend) => {
  jest.setTimeout(60_000);
  const savedFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = savedFetch;
  });
  afterAll(() => backend.dispose());

  it('the timestamp lands after the fill wrote the anchor: the record is partial, not pending for good', async () => {
    const tsa = mockTsaFetch();
    let tsaUp = false;
    let whileAsked: (() => Promise<void>) | null = null;
    globalThis.fetch = (async (...args: Parameters<typeof fetch>) => {
      if (!tsaUp) throw new Error('TSA unreachable');
      if (whileAsked) {
        const during = whileAsked;
        whileAsked = null;
        await during();
      }
      return tsa(...args);
    }) as unknown as typeof fetch;

    const chain = new FakeEvmChain();
    const wallet = Wallet.createRandom();
    chain.fund(wallet.address, ETH);
    const tzun = await Tzun.init({
      mode: 'dev',
      ...(await backend.fresh()),
      logNamespace: NS,
      attestation: { deferrable: ['timestamp'], timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' } },
      anchoring: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, privateKey: wallet.privateKey } }, autoStart: false },
      _anchorChainClient: chain,
    } as unknown as TzunConfig);
    try {
      const { envelope } = await tzun.capture(decision(1));
      const id = envelope.payload.evidenceId;
      expect(envelope.attestationStatus).toBe('pending');
      expect(envelope.nonRepudiation.rfc3161Token).toBeFalsy();
      await tzun.anchorNow({ force: true });

      // The authority is back. The retry lists the record (no anchor yet) and,
      // while it waits on the authority, the epoch finalizes and is filled.
      tsaUp = true;
      let duringRetry: EvidenceEnvelope | null = null;
      whileAsked = async () => {
        for (let i = 0; i < 6; i++) {
          chain.mine(3);
          await tzun.anchorNow();
        }
        duringRetry = await tzun.getStorage().retrieve(id);
      };
      const result = await tzun.retryPendingAttestations();

      expect(duringRetry).toMatchObject({ attestationStatus: 'pending', nonRepudiation: { anchor: expect.any(Object) } });
      expect(result.details).toEqual([{ evidenceId: id, success: true }]);
      const after = (await tzun.getStorage().retrieve(id))!;
      expect(after.nonRepudiation.rfc3161Token).toBeTruthy();
      expect(after.nonRepudiation.anchor).toBeTruthy();
      expect(after.attestationStatus).toBe('partial');
      expect(after.attestationStatus).toBe(
        determineAttestationStatus(after.nonRepudiation, after.integrity.canonicalDigest, { timestamp: true, anchor: true }),
      );
    } finally {
      await tzun.close();
    }
  });
});

describe('updateAttestation() with a status function, on the memory adapter', () => {
  it('computes the status from the stored record with the fill applied', async () => {
    const source = await Tzun.init({ mode: 'dev' });
    const { envelope } = await source.capture(decision(1));
    await source.close();
    const store = new MemoryStorageAdapter();
    const pending: EvidenceEnvelope = { ...envelope, attestationStatus: 'pending', nonRepudiation: {} };
    await store.store(pending);
    // Another writer fills the anchor first; the caller's copy still lacks it.
    await store.updateAttestation(envelope.payload.evidenceId, { anchor: { anchorSpec: 'x' } as never }, 'pending');
    const seen: EvidenceEnvelope[] = [];
    await store.updateAttestation(envelope.payload.evidenceId, { rfc3161Token: 'dG9rZW4=' }, (stored) => {
      seen.push(stored);
      return determineAttestationStatus(stored.nonRepudiation, stored.integrity.canonicalDigest, { timestamp: true, anchor: true });
    });
    expect(seen).toHaveLength(1);
    expect(seen[0].nonRepudiation).toEqual({ anchor: { anchorSpec: 'x' }, rfc3161Token: 'dG9rZW4=' });
    expect((await store.retrieve(envelope.payload.evidenceId))!.attestationStatus).toBe('partial');
  });
});
