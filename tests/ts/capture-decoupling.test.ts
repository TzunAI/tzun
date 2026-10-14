/**
 * `capture()` performs no chain I/O.
 *
 * The orchestrator obtains the record's RFC 3161 token and passes pre-verified
 * inputs through. It holds no anchor client, no batch and no flush, so a
 * capture never waits on a chain, whatever the chain is doing. `Tzun.close()`
 * anchors nothing.
 *
 * The chain here is a stub that never answers: every `ethers` provider or
 * wallet call hangs. A capture that reached it would never return, so each
 * case races the capture against a deadline and fails with a message rather
 * than a jest timeout.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as orchestratorModule from '../../src/attestation/orchestrator';
import { AttestationOrchestrator, OrchestratorConfig } from '../../src/attestation/orchestrator';
import type { RFC3161Client } from '../../src/attestation/rfc3161';
import { Tzun } from '../../src/sdk/index';
import type { CaptureInput, TzunConfig } from '@tzun/engine';
import { mockTsaFetch } from './helpers/mock-tsa';

const chainCalls: string[] = [];
const never = <T>(): Promise<T> => new Promise<T>(() => { /* the chain never answers */ });

jest.mock('ethers', () => {
  const hang = (name: string) => () => {
    chainCalls.push(name);
    return never();
  };
  return {
    JsonRpcProvider: jest.fn().mockImplementation(() => {
      chainCalls.push('JsonRpcProvider');
      return { getTransaction: hang('getTransaction'), getTransactionCount: hang('getTransactionCount') };
    }),
    Wallet: jest.fn().mockImplementation(() => {
      chainCalls.push('Wallet');
      return { address: '0x' + '1'.repeat(40), sendTransaction: hang('sendTransaction') };
    }),
  };
});

const decision = (i: number): CaptureInput => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve', i },
  action: 'approved',
  reason: `Concurrent capture ${i}`,
});

/** Settle `p` or fail with `what` after `ms`. */
async function within<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not settle within ${ms} ms`)), ms);
  });
  try {
    return await Promise.race([p, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

const ANCHOR_KEY = {
  anchorRpcUrl: 'https://ethereum-sepolia-rpc.publicnode.com',
  anchorPrivateKey: '0x' + 'ab'.repeat(32),
};

let savedFetch: typeof globalThis.fetch;
let dir: string;

beforeEach(() => {
  chainCalls.length = 0;
  savedFetch = globalThis.fetch;
  globalThis.fetch = jest.fn(mockTsaFetch()) as unknown as typeof fetch;
  dir = mkdtempSync(join(tmpdir(), 'tzun-test-capture-decoupling-'));
});

afterEach(() => {
  globalThis.fetch = savedFetch;
  rmSync(dir, { recursive: true, force: true });
});

describe('the orchestrator has no chain on its path', () => {
  const timestampClient = {
    requestTimestamp: jest.fn().mockResolvedValue({ token: 'tsa-token', metadata: null }),
    breakerState: jest.fn().mockReturnValue('closed'),
  } as unknown as RFC3161Client;

  it('attest() resolves while a chain client handed to it hangs, and never calls it', async () => {
    const hanging = { anchor: jest.fn(() => never()) };
    // An untyped caller can pass a `blockchainClient` the config type does not
    // declare; the orchestrator ignores it.
    const orchestrator = new AttestationOrchestrator({
      timestampClient,
      blockchainClient: hanging,
      batchSize: 1,
    } as unknown as OrchestratorConfig);

    const artifacts = await within(orchestrator.attest('a'.repeat(64)), 1000, 'attest()');

    expect(artifacts.rfc3161Token).toBe('tsa-token');
    expect(artifacts.anchor).toBeUndefined();
    expect((hanging.anchor as jest.Mock)).not.toHaveBeenCalled();
  });

  it('has no batching API: no flush, no batch, no batch deadline', () => {
    const orchestrator = new AttestationOrchestrator({ timestampClient });
    const surface = orchestrator as unknown as Record<string, unknown>;
    for (const member of ['flush', 'flushBatch', 'queueForAnchoring', 'pendingBatch', 'batchSize', 'batchMaxWaitMs']) {
      expect(surface[member]).toBeUndefined();
    }
    expect(orchestratorModule).not.toHaveProperty('DEFAULT_BATCH_MAX_WAIT_MS');
  });
});

describe('capture() completes while the chain hangs', () => {
  it('50 concurrent captures on SQLite complete, and nothing reaches the chain', async () => {
    const tzun = await Tzun.init({
      mode: 'local',
      dbPath: join(dir, 'decoupled.db'),
      attestation: { timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' } },
    });
    try {
      const results = await within(
        Promise.all(Array.from({ length: 50 }, (_, i) => tzun.capture(decision(i)))),
        10_000,
        '50 concurrent captures',
      );
      expect(results.every((r) => r.stored)).toBe(true);
      expect(results.every((r) => r.envelope.nonRepudiation.rfc3161Token)).toBe(true);
      expect(results.every((r) => r.envelope.nonRepudiation.anchor === undefined)).toBe(true);
    } finally {
      await within(tzun.close(), 2000, 'close()');
    }
    expect(chainCalls).toEqual([]);
  }, 20_000);

  // Every configuration that names a chain for capture: anchor credentials,
  // and a deferrable or required blockchain attestation. Init refuses each of
  // these; the case holds either way: a config init accepts must not make a
  // capture wait on the chain.
  it.each<[string, TzunConfig['attestation']]>([
    ['anchor credentials alone', { blockchain: ANCHOR_KEY } as TzunConfig['attestation']],
    [
      "the demo's config when anchor credentials are set",
      { deferrable: ['timestamp', 'blockchain'], blockchain: ANCHOR_KEY } as unknown as TzunConfig['attestation'],
    ],
    [
      'a required anchor',
      { require: ['timestamp', 'blockchain'], blockchain: ANCHOR_KEY } as unknown as TzunConfig['attestation'],
    ],
  ])('%s: init refuses it, or a capture completes without touching the chain', async (_label, attestation) => {
    let tzun: Tzun;
    try {
      tzun = await Tzun.init({
        mode: 'local',
        dbPath: join(dir, 'legacy.db'),
        attestation: { ...attestation, timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' } },
      });
    } catch {
      expect(chainCalls).toEqual([]);
      return;
    }
    try {
      const result = await within(tzun.capture(decision(0)), 2000, 'capture()');
      expect(result.stored).toBe(true);
    } finally {
      await within(tzun.close(), 2000, 'close()').catch(() => { /* reported by the capture */ });
    }
    expect(chainCalls.filter((c) => c === 'sendTransaction')).toEqual([]);
  });
});
