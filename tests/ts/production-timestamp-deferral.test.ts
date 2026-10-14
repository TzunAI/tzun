/**
 * A production mode on a local store keeps recording decisions through a
 * timestamp-authority outage.
 *
 * With nothing configured, a production mode obtains the timestamp as a
 * DEFERRABLE component: the capture tries every authority in turn (FreeTSA,
 * then Sectigo), and only when none of them issues a token is the record
 * stored with attestationStatus 'pending', for the retry to timestamp later.
 * `require: ['timestamp']` is the hard requirement: the same outage refuses
 * the capture. A config that never seeks a timestamp is refused at init.
 */
import { Tzun, DEFAULT_TIMESTAMP_AUTHORITIES } from '../../src/sdk/index';
import type { CaptureInput } from '@tzun/engine';
import { mockTsaFetch } from './helpers/mock-tsa';

const decision: CaptureInput = {
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'Meets all criteria',
};

const [PRIMARY, FALLBACK] = DEFAULT_TIMESTAMP_AUTHORITIES;

/** A fetch that answers as a TSA for the URLs in `up`, and refuses the rest. */
function tsaFetch(up: Set<string>, calls: string[]): typeof fetch {
  const tsa = mockTsaFetch();
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    if (!up.has(url)) throw new Error(`connect ECONNREFUSED (${url})`);
    return tsa(url, init);
  }) as unknown as typeof fetch;
}

describe('a production mode on a local store during a timestamp-authority outage', () => {
  let savedFetch: typeof globalThis.fetch;
  let calls: string[];
  let tzun: Tzun | undefined;

  beforeEach(() => {
    savedFetch = globalThis.fetch;
    calls = [];
    tzun = undefined;
  });

  afterEach(async () => {
    await tzun?.close();
    globalThis.fetch = savedFetch;
  });

  describe.each(['local', 'self-hosted', 'cloud'] as const)('%s mode, nothing configured', (mode) => {
    it('stores the decision pending when every authority fails, after trying each of them', async () => {
      globalThis.fetch = tsaFetch(new Set(), calls);
      tzun = await Tzun.init({ mode, dbPath: ':memory:' });

      const result = await tzun.capture(decision);

      expect(result.failure).toBeUndefined();
      expect(result.stored).toBe(true);
      expect(result.envelope.attestationStatus).toBe('pending');
      expect(result.envelope.nonRepudiation.rfc3161Token).toBeUndefined();
      // Failover first: pending only after both default authorities failed.
      expect(calls).toEqual([PRIMARY, FALLBACK]);

      const pending = await tzun.getStorage().listByAttestationStatus('pending');
      expect(pending.map((e) => e.payload.evidenceId)).toEqual([
        result.envelope.payload.evidenceId,
      ]);
    });

    it('is not pending when the fallback authority answers', async () => {
      globalThis.fetch = tsaFetch(new Set([FALLBACK]), calls);
      tzun = await Tzun.init({ mode, dbPath: ':memory:' });

      const result = await tzun.capture(decision);

      expect(result.stored).toBe(true);
      expect(result.envelope.nonRepudiation.rfc3161Token).toBeDefined();
      expect(result.envelope.attestationStatus).toBe('partial');
      expect(calls).toEqual([PRIMARY, FALLBACK]);
    });
  });

  it("require: ['timestamp'] refuses the capture when no authority answers", async () => {
    globalThis.fetch = tsaFetch(new Set(), calls);
    tzun = await Tzun.init({
      mode: 'local',
      dbPath: ':memory:',
      attestation: { require: ['timestamp'] },
    });

    const result = await tzun.capture(decision);

    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('attestation_failure');
    expect(result.failure?.diagnosticMetadata.missingServices).toEqual(['timestamp']);
    expect(calls).toEqual([PRIMARY, FALLBACK]);
    expect(await tzun.getStorage().getLastSequence()).toBe(0);
  });

  it('refuses at init a production config that never seeks a timestamp', async () => {
    await expect(
      Tzun.init({ mode: 'local', dbPath: ':memory:', attestation: { require: [] } }),
    ).rejects.toThrow(/Production modes must obtain an RFC 3161 timestamp for every record/);
  });
});
