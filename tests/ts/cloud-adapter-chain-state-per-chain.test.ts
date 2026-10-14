// tests/ts/cloud-adapter-chain-state-per-chain.test.ts
//
// Per-chain chain state on the cloud transport.
//
// `getLastDigest(chainId)`, `getLastSequence(chainId)` and
// `resetChainState(chainId)` are documented on `StorageAdapter` as naming one
// chain, and the memory/SQLite/Postgres adapters implement them that way.
// `HttpStorageAdapter` caches the server's head per chain too, not one cached
// head for the whole adapter.
//
// One shared head would be invisible while one instance writes one chain — the
// shape `Tzun.init({ chainId })` produces — and wrong the moment an adapter is
// handed two chains, which is exactly what a caller driving the adapter
// directly (or a future multi-chain instance) does. The failure would not be a
// thrown error: chain B's append would link from chain A's head, the server
// would refuse it with `chain_conflict`, and the adopted head would then be
// written over A's. So the two chains would take turns invalidating each
// other's cached head, and every capture would pay a wasted round trip — or,
// with a client-side attestation, a wasted TSA round trip — for the life of
// the process.
//
// The fake server here holds a head PER CHAIN, which is what the real backend
// does (`chain_state` is keyed by chain), so a cache that is not keyed the same
// way cannot pass.
import {
  HttpTransport,
  HttpStorageAdapter,
  type FetchFn,
} from '../../src/sdk/http-transport';
import { computeDigest, type EvidenceEnvelope } from '@tzun/engine';

const SECRET_KEY = 'sk_test_cloud_chain_state';
const API_URL = 'https://example.test';

interface PerChainServer {
  fetchFn: FetchFn;
  /** Heads the server holds, by chain id. */
  heads: Map<string, { digest: string; sequence: number }>;
  /** Every POST in order: the chain named on the wire and the answer. */
  submissions: Array<{ chainId: string; status: number }>;
  /** Simulate another writer appending to one chain. */
  appendForeign(chainId: string): void;
  /** Next POST to this chain is refused with `chain_conflict`. */
  refuseNext(chainId: string): void;
}

/**
 * A `POST /v1/evidence` whose chain state is keyed by chain id.
 *
 * Deliberately NOT a digest-verifying copy of the backend (cloud-adapter-head
 * .test.ts already pins that): this test is about which chain the adapter
 * attributes an answer to, so the server's own bookkeeping is the whole point
 * and the envelope's contents are not.
 */
function makePerChainServer(): PerChainServer {
  const heads = new Map<string, { digest: string; sequence: number }>();
  const submissions: PerChainServer['submissions'] = [];
  const refusals = new Set<string>();

  const advance = (chainId: string): { digest: string; sequence: number } => {
    const prior = heads.get(chainId);
    const sequence = (prior?.sequence ?? 0) + 1;
    const head = { digest: computeDigest(`${chainId}-record-${sequence}`), sequence };
    heads.set(chainId, head);
    return head;
  };

  const json = (status: number, body: unknown): Response =>
    ({
      ok: status >= 200 && status < 300,
      status,
      async json() {
        return body;
      },
      async text() {
        return JSON.stringify(body);
      },
    }) as unknown as Response;

  const fetchFn: FetchFn = async (_url, init) => {
    const body = JSON.parse(String(init?.body ?? '{}')) as {
      envelope?: EvidenceEnvelope;
      chainId?: string;
    };
    // The wire omits `chainId` for the default chain; the server resolves the
    // omission to `'default'`, as the backend does.
    const chainId = body.chainId ?? 'default';

    if (refusals.has(chainId)) {
      refusals.delete(chainId);
      submissions.push({ chainId, status: 409 });
      return json(409, {
        ok: false,
        error: 'chain_conflict',
        expectedPreviousDigest: heads.get(chainId)?.digest ?? null,
        expectedSequence: (heads.get(chainId)?.sequence ?? 0) + 1,
      });
    }

    const head = advance(chainId);
    submissions.push({ chainId, status: 202 });
    return json(202, {
      ok: true,
      evidenceId: body.envelope?.payload.evidenceId ?? 'e',
      chainId,
      sequence: head.sequence,
      state: 'captured',
      canonicalDigest: head.digest,
      headDigest: head.digest,
    });
  };

  return {
    fetchFn,
    heads,
    submissions,
    appendForeign: (chainId) => {
      advance(chainId);
    },
    refuseNext: (chainId) => {
      refusals.add(chainId);
    },
  };
}

/** A minimal envelope — this suite's server does not read it. */
function envelope(evidenceId: string): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      links: null,
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId,
      schemaVersion: 'v1.0',
      aiSystemId: 'test',
      aiOutput: {},
      action: 'approved',
      reason: 'per-chain cloud head',
      capturedAt: new Date().toISOString(),
      sequenceNumber: 1,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: { canonicalDigest: computeDigest(evidenceId), chainLink: null },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  } as EvidenceEnvelope;
}

function adapter(server: PerChainServer): HttpStorageAdapter {
  return new HttpStorageAdapter(
    new HttpTransport({ apiKey: SECRET_KEY, apiUrl: API_URL, fetchFn: server.fetchFn }),
  );
}

describe('the cloud adapter caches a head PER CHAIN', () => {
  it('two chains through one adapter each keep their own head', async () => {
    const server = makePerChainServer();
    const a = adapter(server);

    await a.store(envelope('a-1'), 'tenant-acme');
    await a.store(envelope('b-1'), 'tenant-globex');
    await a.store(envelope('a-2'), 'tenant-acme');

    // Each chain reports the head the SERVER holds for it. With one shared
    // cache both of these would answer the last chain written, so
    // `tenant-globex` would read `tenant-acme`'s digest at sequence 2.
    expect(await a.getLastDigest('tenant-acme')).toBe(server.heads.get('tenant-acme')!.digest);
    expect(await a.getLastSequence('tenant-acme')).toBe(2);
    expect(await a.getLastDigest('tenant-globex')).toBe(server.heads.get('tenant-globex')!.digest);
    expect(await a.getLastSequence('tenant-globex')).toBe(1);
  });

  it('a chain this adapter has not written reports the honest genesis default', async () => {
    const server = makePerChainServer();
    const a = adapter(server);

    await a.store(envelope('a-1'), 'tenant-acme');

    // Not "we have not been told yet about ANY chain" — "we have not been told
    // yet about THIS one". A head invented for an unwritten chain would make
    // its first append link from a foreign digest.
    expect(await a.getLastDigest('tenant-globex')).toBeNull();
    expect(await a.getLastSequence('tenant-globex')).toBe(0);
  });

  it('omitting the chain id names the default chain, which is a chain like any other', async () => {
    const server = makePerChainServer();
    const a = adapter(server);

    await a.store(envelope('d-1'));
    await a.store(envelope('n-1'), 'tenant-acme');

    // `store()` with no chain writes the default chain, and the argument-less
    // reads must name that same chain — not the most recent write.
    expect(await a.getLastDigest()).toBe(server.heads.get('default')!.digest);
    expect(await a.getLastSequence()).toBe(1);
    expect(await a.getLastDigest('default')).toBe(server.heads.get('default')!.digest);

    // And `'default'` passed explicitly is the same chain as omitting it.
    await a.store(envelope('d-2'), 'default');
    expect(await a.getLastSequence()).toBe(2);
    expect(await a.getLastSequence('default')).toBe(2);
  });

  it('resetChainState(chainId) drops only that chain’s cached view', async () => {
    const server = makePerChainServer();
    const a = adapter(server);

    await a.store(envelope('a-1'), 'tenant-acme');
    await a.store(envelope('b-1'), 'tenant-globex');

    await a.resetChainState('tenant-acme');

    expect(await a.getLastDigest('tenant-acme')).toBeNull();
    expect(await a.getLastSequence('tenant-acme')).toBe(0);
    // The other chain's head is untouched: a fork on one chain must not clear
    // every chain's high-water mark, and the SQL adapters reset only the named
    // chain as well.
    expect(await a.getLastDigest('tenant-globex')).toBe(server.heads.get('tenant-globex')!.digest);
    expect(await a.getLastSequence('tenant-globex')).toBe(1);
  });

  it('resetChainState() with no argument resets the default chain only', async () => {
    const server = makePerChainServer();
    const a = adapter(server);

    await a.store(envelope('d-1'));
    await a.store(envelope('n-1'), 'tenant-acme');

    await a.resetChainState();

    expect(await a.getLastDigest()).toBeNull();
    expect(await a.getLastDigest('tenant-acme')).toBe(server.heads.get('tenant-acme')!.digest);
  });

  it('a chain_conflict adopts the head for the chain it names, and no other', async () => {
    const server = makePerChainServer();
    const a = adapter(server);

    await a.store(envelope('a-1'), 'tenant-acme');
    await a.store(envelope('b-1'), 'tenant-globex');
    const acmeHeadBefore = await a.getLastDigest('tenant-acme');

    // Another writer moves globex's head; our next globex append is refused
    // and the 409 names globex's real head.
    server.appendForeign('tenant-globex');
    server.refuseNext('tenant-globex');
    await expect(a.store(envelope('b-2'), 'tenant-globex')).rejects.toThrow();

    expect(await a.getLastDigest('tenant-globex')).toBe(
      server.heads.get('tenant-globex')!.digest,
    );
    expect(await a.getLastSequence('tenant-globex')).toBe(2);
    // acme was not a party to that conflict. A shared cache would overwrite its
    // head with globex's, so acme's next append would link from a foreign
    // digest and be refused in turn — the two chains taking turns invalidating
    // each other.
    expect(await a.getLastDigest('tenant-acme')).toBe(acmeHeadBefore);
    expect(await a.getLastSequence('tenant-acme')).toBe(1);
  });

  it('alternating writes to two chains never conflict', async () => {
    // The end-to-end consequence. Every one of these appends links from the
    // head its OWN chain reported, so the server accepts all eight first time.
    const server = makePerChainServer();
    const a = adapter(server);

    for (let round = 0; round < 4; round++) {
      await a.store(envelope(`x-${round}`), 'tenant-acme');
      await a.store(envelope(`y-${round}`), 'tenant-globex');
    }

    expect(server.submissions.filter((s) => s.status === 409)).toEqual([]);
    expect(await a.getLastSequence('tenant-acme')).toBe(4);
    expect(await a.getLastSequence('tenant-globex')).toBe(4);
  });

  it('getActiveChainId() still answers the constant, and a write does not change it', async () => {
    // Not a resolution and not affected by the per-chain cache: the server owns
    // chain state, so the transport reads no chain rows to resolve anything.
    const server = makePerChainServer();
    const a = adapter(server);

    expect(await a.getActiveChainId()).toBe('default');
    await a.store(envelope('n-1'), 'tenant-acme');
    expect(await a.getActiveChainId()).toBe('default');
  });
});
