// tests/ts/capture-idempotency.test.ts — the capture idempotency key a retry queue
// relies on, in both halves: the key reaches the wire on the cloud transport, and
// the adapter's claim-or-replay runs on a local store. What the SDK
// makes of each outcome is pinned in capture-idempotency-local.test.ts.
import { Tzun } from '../../src/sdk/index';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { VerifyingStorageProxy } from '../../src/monitoring/storage-proxy';
import {
  captureIdempotencyFingerprint,
  type IdempotencyOutcome,
  type IdempotentStoreOptions,
  type EvidenceEnvelope,
} from '@tzun/engine';

describe('capture idempotencyKey threading', () => {
  it('threads the key to the Idempotency-Key header on every POST', async () => {
    const headersSeen: Array<Record<string, string>> = [];
    const fetchFn = (async (_url: string, init: { headers?: Record<string, string> }) => {
      headersSeen.push({ ...(init.headers ?? {}) });
      return new Response(
        JSON.stringify({ evidenceId: 'e1', canonicalDigest: 'a'.repeat(64), sequenceNumber: 1 }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ); // the exact success shape the HTTP transport tests mock
    }) as unknown as typeof fetch;

    // NOTE: a bare apiKey init performs no TSA I/O (http-attestation-default.test.ts).
    const tzun = await Tzun.init({ apiKey: 'tk_test', _httpFetchFn: fetchFn });
    const input = { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 1 }, action: 'approved', reason: 'ok' };
    await tzun.capture(input, { idempotencyKey: 'retry-abc-1' });
    await tzun.capture(input, { idempotencyKey: 'retry-abc-1' }); // SDK-level retry
    const withKey = headersSeen.filter((h) => h['Idempotency-Key'] === 'retry-abc-1');
    expect(withKey.length).toBe(2); // header on BOTH posts; replay semantics are the server's
  });

  it('a local adapter claims the key instead of ignoring it', async () => {
    const tzun = await Tzun.init(); // memory adapter, dev mode
    const input = { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 1 }, action: 'approved', reason: 'ok' };
    const first = await tzun.capture(input, { idempotencyKey: 'retry-abc-1' });
    expect(first.stored).toBe(true);
    expect(first.replayed).toBeUndefined();

    const retry = await tzun.capture(input, { idempotencyKey: 'retry-abc-1' });
    expect(retry.stored).toBe(true);
    expect(retry.replayed).toBe(true);
    expect(await tzun.getStorage().getChainLength()).toBe(1);
    await tzun.close();
  });

  // The verifying proxy is what Tzun.init() wraps around every local adapter by
  // default, so a keyed capture reaches the inner adapter through it. What has
  // to arrive is the whole claim — the key, the fingerprint of the caller's
  // input, and the conditional-append guard — or the key is dropped on every
  // local capture. The cloud transport, where the key reaches the wire instead,
  // has no proxy (it has no read path to verify) and asking for one is refused
  // (pinned below).
  it('VerifyingStorageProxy forwards the whole idempotency claim to the inner adapter', async () => {
    const seen: IdempotentStoreOptions[] = [];
    const proto = MemoryStorageAdapter.prototype as unknown as {
      storeIdempotent: (
        e: EvidenceEnvelope,
        c: string | undefined,
        o: IdempotentStoreOptions,
      ) => Promise<IdempotencyOutcome>;
    };
    const original = proto.storeIdempotent;
    proto.storeIdempotent = async function patched(
      this: MemoryStorageAdapter,
      envelope: EvidenceEnvelope,
      chainId: string | undefined,
      options: IdempotentStoreOptions,
    ): Promise<IdempotencyOutcome> {
      seen.push(options);
      return original.call(this, envelope, chainId, options);
    };

    let captured;
    try {
      const tzun = await Tzun.init({ mode: 'dev' });
      expect((tzun as unknown as { storage: unknown }).storage).toBeInstanceOf(VerifyingStorageProxy);

      captured = await tzun.capture(
        { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 1 }, action: 'approved', reason: 'ok' },
        { idempotencyKey: 'proxy-test-key' },
      );
      await tzun.close();
    } finally {
      proto.storeIdempotent = original;
    }

    expect(seen).toHaveLength(1);
    expect(seen[0]!.idempotency.key).toBe('proxy-test-key');
    expect(seen[0]!.expectChainHead).toEqual({ sequence: 0, digest: null });
    // The fingerprint is the engine's one rule over the record as the platform
    // would be sent it, so a local claim and a cloud claim are the same claim.
    expect(seen[0]!.idempotency.fingerprint).toBe(
      captureIdempotencyFingerprint({
        completeness: 'partial',
        chainId: 'default',
        envelope: captured.envelope,
      }),
    );
  });

  it('refuses verifyReads on the cloud transport instead of verifying nothing', async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify({ evidenceId: 'e1' }), { status: 200 })) as unknown as typeof fetch;

    await expect(
      Tzun.init({
        apiKey: 'tk_test',
        _httpFetchFn: fetchFn,
        verifyReads: true,
      } as never),
    ).rejects.toThrow(/verifyReads is not supported on the cloud transport/);
  });
});
