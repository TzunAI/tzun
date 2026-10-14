// the platform refuses a capture aimed at a sealed chain
// (the read-only remainder of a fork) with
//
//   409 { ok: false, error: 'chain_sealed', chainId, sealedAt }
//
// (backend/src/app/capture-evidence.ts, mapped in app-capture-routes.ts). The
// transport must report it as `chain_sealed`, not retryable, with the chain and
// its seal time in `context`, and Tzun.capture() as `cloud_chain_sealed`: the
// cloud twin of the local `chain_sealed` failure, carrying the same fields. A
// seal is never lifted, so a retry of the same append is refused every time.

import {
  HttpTransport,
  TzunCaptureError,
  type FetchFn,
} from '../../src/sdk/http-transport';
import { Tzun } from '../../src/sdk/index';
import type { CaptureInput, EvidenceEnvelope } from '@tzun/engine';

const SECRET_KEY = 'sk_test_chain_sealed_secret_789';
const SEALED_AT = '2026-09-18T22:40:16.123Z';

const decision: CaptureInput = {
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { text: 'do the thing' },
  action: 'approved',
  reason: 'looks good',
};

function makeEnvelope(): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      links: null,
      evidenceId: 'ev-1',
      schemaVersion: 'v1.0',
      aiSystemId: 'default',
      aiOutput: { text: 'do the thing' },
      action: 'approved',
      reason: 'looks good',
      capturedAt: '2026-06-07T00:00:00.000Z',
      sequenceNumber: 1,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: { canonicalDigest: 'sha256:abc', chainLink: null },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  };
}

/** A fetch answering every request with the platform's 409, counting the calls. */
function sealedFetch(chainId: string): FetchFn & { calls: number } {
  const fn = Object.assign(
    async (): Promise<Response> => {
      fn.calls += 1;
      return {
        ok: false,
        status: 409,
        headers: new Headers(),
        async json() {
          return { ok: false, error: 'chain_sealed', chainId, sealedAt: SEALED_AT };
        },
      } as unknown as Response;
    },
    { calls: 0 },
  );
  return fn;
}

describe('HttpTransport — 409 chain_sealed', () => {
  it('reports code chain_sealed, not retryable, with the chain and seal time in context', async () => {
    const transport = new HttpTransport({ apiKey: SECRET_KEY, fetchFn: sealedFetch('c-forked') });

    const err = await transport.capture({ envelope: makeEnvelope(), chainId: 'c-forked' }).then(
      () => { throw new Error('expected capture to reject'); },
      (e: unknown) => e,
    );

    expect(err).toBeInstanceOf(TzunCaptureError);
    const e = err as TzunCaptureError;
    expect(e.code).toBe('chain_sealed');
    expect(e.status).toBe(409);
    expect(e.retryable).toBe(false);
    expect(e.context).toEqual({ chainId: 'c-forked', sealedAt: SEALED_AT });
    expect(e.message).not.toContain(SECRET_KEY);
  });
});

describe('Tzun.capture() — a cloud capture to a sealed chain', () => {
  async function cloudCapture(fetchFn: FetchFn) {
    const tzun = await Tzun.init({
      mode: 'dev',
      apiKey: SECRET_KEY,
      apiUrl: 'https://example.test',
      attestation: { require: [] },
      _httpFetchFn: fetchFn,
    } as Parameters<typeof Tzun.init>[0]);
    try {
      return await tzun.capture(decision);
    } finally {
      await tzun.close();
    }
  }

  it('is cloud_chain_sealed, not retryable, with chainId and sealedAt, and is sent once', async () => {
    const fetchFn = sealedFetch('default');

    const result = await cloudCapture(fetchFn);

    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('cloud_chain_sealed');
    expect(result.failure?.diagnosticMetadata).toMatchObject({
      code: 'chain_sealed',
      status: 409,
      retryable: false,
      chainId: 'default',
      sealedAt: SEALED_AT,
    });
    // Only a chain_conflict is retried in place; a sealed chain is not.
    expect(fetchFn.calls).toBe(1);
    expect(JSON.stringify(result.failure)).not.toContain(SECRET_KEY);
  });

  it('carries the fields the local chain_sealed failure carries, with the same values', async () => {
    const local = await Tzun.init({ mode: 'dev' });
    let localMeta: Record<string, unknown>;
    try {
      const storage = local.getStorage();
      await storage.storeChain({ chainId: 'default', status: 'active', createdAt: SEALED_AT });
      await storage.sealChain('default', SEALED_AT);
      const refused = await local.capture(decision);
      expect(refused.failure?.failureType).toBe('chain_sealed');
      localMeta = refused.failure!.diagnosticMetadata;
    } finally {
      await local.close();
    }

    const cloud = await cloudCapture(sealedFetch('default'));
    const cloudMeta = cloud.failure!.diagnosticMetadata;

    for (const field of ['code', 'retryable', 'chainId', 'sealedAt']) {
      expect(field in localMeta).toBe(true);
      expect(cloudMeta[field]).toEqual(localMeta[field]);
    }
  });
});
