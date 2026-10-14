import { modelOf } from './helpers/step-model';
import { singleModel } from '@tzun/engine';
// a cloud capture retried with its Idempotency-Key gets the
// first capture's receipt.
//
// The platform fingerprints a keyed capture over what the caller chose, and
// over nothing the SDK fills in per attempt (the hosted service's capture
// path, `requestFingerprint` and `callerDecision`):
//
//   completeness, chainId ('default' when absent), and from the envelope:
//   payload.aiSystemId, .aiOutput, .humanAction, .humanReason, .aiBom;
//   each custodyChain entry's action, actor, systemId and metadata;
//   nonRepudiation.webauthnAssertion and .signerIdentity.
//
// The same key with the same fingerprint answers 202 with the first success's
// body. The same key with a different fingerprint answers
// 422 { ok: false, error: 'idempotency_conflict' }.
//
// This file pins the SDK half: two capture() calls of one input send the same
// key and the same fingerprinted fields (while evidenceId and capturedAt
// differ), a replayed 202 is reported as stored with the original receipt, and
// the conflict is `cloud_idempotency_conflict`, not retryable.

import type { FetchFn } from '../../src/sdk/http-transport';
import { Tzun } from '../../src/sdk/index';
import type { CaptureInput, EvidenceEnvelope } from '@tzun/engine';

const API_KEY = 'sk_test_idempotent_replay';

const input: CaptureInput = {
  aiSystemId: 'underwriter-v2',
  aiOutput: { recommendation: 'approve', score: 0.92 },
  action: 'approved',
  reason: 'meets policy',
  decider: { kind: 'human' as const, id: 'acct:reviewer-bank.example', agent: null, credential: null, freshness: null },
  attestationInputs: { signerIdentity: { idpToken: 'idp-token', idpIssuer: 'https://idp.example' } },
};

interface SentRequest {
  headers: Record<string, string>;
  body: { completeness: string; chainId?: string; envelope: EvidenceEnvelope };
}

/** The fields the platform's fingerprint reads from a capture body. */
function fingerprinted(body: SentRequest['body']) {
  const e = body.envelope;
  const d = e.payload.decider;
  return {
    completeness: body.completeness,
    chainId: body.chainId ?? 'default',
    aiSystemId: e.payload.aiSystemId,
    aiOutput: e.payload.aiOutput,
    action: e.payload.action,
    reason: e.payload.reason,
    decider: d == null ? null : { kind: d.kind, id: d.id, agent: d.agent, credential: d.credential },
    ...(e.payload.contributions != null && { contributions: e.payload.contributions }),
    ...(e.payload.links != null && { links: e.payload.links }),
    custody: e.custodyChain.map(({ action, actor, systemId, metadata }) => ({
      action, actor, systemId, metadata: metadata ?? null,
    })),
    webauthnAssertion: e.nonRepudiation.webauthnAssertion ?? null,
    signerIdentity: e.nonRepudiation.signerIdentity ?? null,
  };
}

/** A fetch that records each request and answers with `respond(n)` for the n-th (0-based). */
function recordingFetch(respond: (n: number, sent: SentRequest) => { status: number; body: unknown } | 'network-error') {
  const sent: SentRequest[] = [];
  const fetchFn: FetchFn = async (_url, init) => {
    const request: SentRequest = {
      headers: { ...((init?.headers ?? {}) as Record<string, string>) },
      body: JSON.parse(String(init?.body)),
    };
    sent.push(request);
    const answer = respond(sent.length - 1, request);
    if (answer === 'network-error') throw new TypeError('fetch failed');
    return {
      ok: answer.status >= 200 && answer.status < 300,
      status: answer.status,
      headers: new Headers(),
      async json() { return answer.body; },
    } as unknown as Response;
  };
  return { fetchFn, sent };
}

const receipt = (sent: SentRequest) => ({
  ok: true,
  state: 'captured',
  verification: { digestValid: true, chainLinkValid: true },
  evidenceId: sent.body.envelope.payload.evidenceId,
  chainId: 'default',
  sequence: 1,
  canonicalDigest: sent.body.envelope.integrity.canonicalDigest,
  headDigest: sent.body.envelope.integrity.canonicalDigest,
});

async function cloudTzun(fetchFn: FetchFn, onLog?: (event: string, fields: Record<string, unknown>) => void): Promise<Tzun> {
  return Tzun.init({
    mode: 'dev',
    apiKey: API_KEY,
    apiUrl: 'https://example.test',
    attestation: { require: [] },
    _httpFetchFn: fetchFn,
    ...(onLog ? { onLog } : {}),
  } as Parameters<typeof Tzun.init>[0]);
}

describe('a keyed cloud capture retried after a lost response', () => {
  it('sends the same key and the same fingerprinted fields; only what the SDK mints differs', async () => {
    const { fetchFn, sent } = recordingFetch((n, req) => (n === 0 ? 'network-error' : { status: 202, body: receipt(req) }));
    const tzun = await cloudTzun(fetchFn);
    try {
      const lost = await tzun.capture(input, { idempotencyKey: 'order-7781' });
      expect(lost.stored).toBe(false);
      expect(lost.failure?.diagnosticMetadata).toMatchObject({ code: 'transport_error', retryable: true });

      await tzun.capture(input, { idempotencyKey: 'order-7781' });
    } finally {
      await tzun.close();
    }

    expect(sent).toHaveLength(2);
    expect(sent.map((s) => s.headers['Idempotency-Key'])).toEqual(['order-7781', 'order-7781']);
    expect(fingerprinted(sent[1]!.body)).toEqual(fingerprinted(sent[0]!.body));
    // The reviewer and the signer identity are the caller's, and are in it.
    expect(fingerprinted(sent[0]!.body).custody[0]!.actor).toBe('acct:reviewer-bank.example');
    expect(fingerprinted(sent[0]!.body).signerIdentity).toEqual(input.attestationInputs!.signerIdentity);
    // What the SDK mints per call is not the same, which is why the platform
    // leaves it out.
    expect(sent[1]!.body.envelope.payload.evidenceId).not.toBe(sent[0]!.body.envelope.payload.evidenceId);
  });

  it('a replayed 202 is reported stored and replayed, with the first capture\'s receipt', async () => {
    let original: ReturnType<typeof receipt> | undefined;
    const { fetchFn, sent } = recordingFetch((n, req) => {
      if (n === 0) {
        // The first attempt commits; its response never arrives.
        original = receipt(req);
        return 'network-error';
      }
      return { status: 202, body: original };
    });
    const logged: Array<{ event: string; fields: Record<string, unknown> }> = [];
    const tzun = await cloudTzun(fetchFn, (event, fields) => logged.push({ event, fields }));
    let retried;
    try {
      await tzun.capture(input, { idempotencyKey: 'order-7782' });
      retried = await tzun.capture(input, { idempotencyKey: 'order-7782' });
    } finally {
      await tzun.close();
    }

    expect(retried.stored).toBe(true);
    expect(retried.serverReceipt).toMatchObject({
      evidenceId: original!.evidenceId,
      canonicalDigest: original!.canonicalDigest,
      sequence: 1,
    });
    // The retry's own envelope was never stored; the receipt names the record that was.
    expect(sent[1]!.body.envelope.payload.evidenceId).not.toBe(original!.evidenceId);

    // a receipt naming another record is a replay, and the caller
    // can tell it from a fresh capture. It is NOT a restamp — the server did not
    // re-seat this envelope onto its head, it stored nothing at all — and
    // reporting it as one described an event that did not happen.
    expect(retried.replayed).toBe(true);
    expect(logged.map((l) => l.event)).not.toContain('capture_receipt_restamped');
    const replay = logged.filter((l) => l.event === 'capture_idempotency_replay');
    expect(replay).toHaveLength(1);
    expect(replay[0]!.fields).toMatchObject({
      idempotencyKey: 'order-7782',
      evidenceId: original!.evidenceId,
      discardedEvidenceId: sent[1]!.body.envelope.payload.evidenceId,
    });
  });

  it('a restamped receipt for the record we submitted is still a restamp, not a replay', async () => {
    // The server re-seats a `partial` capture onto its own head: same
    // evidenceId, different sequence and digest. That is the case
    // `capture_receipt_restamped` exists for, and the replay check must not
    // swallow it.
    const { fetchFn } = recordingFetch((_n, req) => ({
      status: 202,
      body: { ...receipt(req), sequence: 9, canonicalDigest: 'b'.repeat(64), headDigest: 'b'.repeat(64) },
    }));
    const logged: string[] = [];
    const tzun = await cloudTzun(fetchFn, (event) => logged.push(event));
    let result;
    try {
      result = await tzun.capture(input, { idempotencyKey: 'order-7785' });
    } finally {
      await tzun.close();
    }

    expect(result.stored).toBe(true);
    expect(result.replayed).toBeUndefined();
    expect(logged).toContain('capture_receipt_restamped');
    expect(logged).not.toContain('capture_idempotency_replay');
  });

  it('a 422 idempotency_conflict is cloud_idempotency_conflict, not retryable, and sent once', async () => {
    const { fetchFn, sent } = recordingFetch(() => ({
      status: 422, body: { ok: false, error: 'idempotency_conflict' },
    }));
    const tzun = await cloudTzun(fetchFn);
    let result;
    try {
      result = await tzun.capture(input, { idempotencyKey: 'order-7783' });
    } finally {
      await tzun.close();
    }

    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('cloud_idempotency_conflict');
    expect(result.failure?.diagnosticMetadata).toMatchObject({
      code: 'idempotency_conflict', status: 422, retryable: false,
    });
    expect(sent).toHaveLength(1);
    expect(JSON.stringify(result.failure)).not.toContain(API_KEY);
  });

  it('every chain-conflict attempt inside one capture carries the same key', async () => {
    const { fetchFn, sent } = recordingFetch((n, req) =>
      n === 0
        ? { status: 409, body: { ok: false, error: 'chain_conflict', expectedPreviousDigest: 'a'.repeat(64) } }
        : { status: 202, body: receipt(req) });
    const tzun = await cloudTzun(fetchFn);
    let result;
    try {
      result = await tzun.capture(input, { idempotencyKey: 'order-7784' });
    } finally {
      await tzun.close();
    }

    expect(result.stored).toBe(true);
    expect(sent.map((s) => s.headers['Idempotency-Key'])).toEqual(['order-7784', 'order-7784']);
    // A refused attempt leaves the key unused on the platform, so the rebuilt
    // record under the same key is captured, not refused as a conflict: it is
    // the same decision, fingerprinted the same.
    expect(fingerprinted(sent[1]!.body)).toEqual(fingerprinted(sent[0]!.body));
  });
});
