// tests/ts/cloud-adapter-head.test.ts
//
// Two evidence-integrity properties of the cloud adapter:
//
//   The head. `HttpStorageAdapter.store()` keeps the server's `CaptureSuccess`,
//      and `getLastDigest()`/`getLastSequence()` answer the head the server
//      recorded, so `Tzun.capture()` links from and advances the SERVER's
//      chain head, not a purely local one. With a local head, against any
//      server chain that was not virgin at process boot, the first capture
//      would come back with an untrue receipt and every capture after it
//      would be rejected with `chain_conflict` — permanently, because the
//      local head only advances on a successful store. With `attach()` the
//      application would keep working while no evidence was recorded.
//
//   The reads. List-shaped reads the cloud adapter cannot answer throw
//      `TzunCloudReadUnsupportedError` instead of returning empty data. Empty
//      data would make `verifyChainCompleteness()` report
//      `{ valid: true, totalRecords: 0 }`, the scheduled scanner emit
//      `scan_completed` with zero issues on every pass, and `retrieve()` say
//      "not found" for evidence the server holds: completeness verification
//      passing vacuously, forever.
//
// The fake server below is a faithful copy of the hosted service's capture
// path: it locks a head, verifies the client's self-consistent digest, REJECTS
// a non-null `chainLink` that does not verify against ITS head (409
// `chain_conflict` carrying `expectedPreviousDigest`), assigns
// `sequence = headSeq + 1`, and re-stamps the envelope — which changes the
// canonical digest, because `sequenceNumber` is a hashed field. It also
// REFUSES to re-stamp an envelope that carries a digest-bound attestation (a
// TSA token or a WebAuthn assertion attests one digest, and a re-stamped
// record has another): 409
// `chain_conflict` with `reason: 'attested_envelope_cannot_be_restamped'` and
// the `expectedSequence` it would have assigned, so the client can rebuild and
// re-attest at exactly that position.
import {
  HttpTransport,
  HttpStorageAdapter,
  TzunCloudReadUnsupportedError,
  type FetchFn,
} from '../../src/sdk/http-transport';
import { Tzun } from '../../src/sdk/index';
import type { LogSink } from '../../src/sdk/log';
import {
  canonicalSerialize,
  computeDigest,
  EvidenceChain,
  SchemaRegistry,
  verifyEnvelope,
  type EvidenceEnvelope,
} from '@tzun/engine';

const SECRET_KEY = 'sk_test_cloud_head';
const API_URL = 'https://example.test';

const registry = new SchemaRegistry();

/** Byte-for-byte the backend's `restampEnvelope`. */
function restampEnvelope(
  clientEnvelope: EvidenceEnvelope,
  sequence: number,
  headDigest: string | null,
): EvidenceEnvelope {
  const schema = registry.get(clientEnvelope.payload.schemaVersion)!;
  const payload = { ...clientEnvelope.payload, sequenceNumber: sequence };
  const canonicalDigest = computeDigest(
    canonicalSerialize(payload as unknown as Record<string, unknown>, schema.hashedFieldSet),
  );
  const chain = new EvidenceChain();
  if (headDigest) chain.restore(headDigest);
  return {
    ...clientEnvelope,
    payload,
    integrity: { canonicalDigest, chainLink: chain.computeLink(canonicalDigest) },
  };
}

/** Byte-for-byte the backend's `carriesDigestBoundAttestation`. */
function carriesDigestBoundAttestation(envelope: EvidenceEnvelope): boolean {
  const nr = envelope.nonRepudiation;
  const hasArtifact = nr != null && Object.keys(nr).length > 0;
  return hasArtifact || envelope.attestationStatus !== 'none';
}

interface FakeServer {
  fetchFn: FetchFn;
  /** Records as the SERVER stored them, in chain order. */
  stored: EvidenceEnvelope[];
  /** Every POST in order: the sequence the client submitted, and the answer. */
  submissions: Array<{ sequenceNumber: number; status: number; reason?: string }>;
  /** Simulate another writer (a second replica, a raw batch) appending. */
  appendForeignRecord(): void;
  headDigest: () => string | null;
  headSeq: () => number;
}

/**
 * A fake `POST /v1/evidence` that mirrors the backend's capture handler.
 *
 * `seedRecords` pre-populates the chain, which is the ordinary case for any
 * long-lived deployment: a process restart, a redeploy, or a second replica all
 * meet a chain that already has rows.
 */
function makeFakeServer(seedRecords = 0): FakeServer {
  const stored: EvidenceEnvelope[] = [];
  const submissions: FakeServer['submissions'] = [];
  let headDigest: string | null = null;
  let headSeq = 0;

  const appendForeignRecord = (): void => {
    headSeq += 1;
    const digest = computeDigest(`foreign-record-${headSeq}`);
    headDigest = digest;
    stored.push({
      envelopeVersion: 'e1',
      payload: {
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        links: null,
        evidenceId: `foreign-${headSeq}`,
        schemaVersion: 'v1.0',
        aiSystemId: 'foreign',
        aiOutput: {},
        action: 'approved',
        reason: 'foreign writer',
        capturedAt: new Date().toISOString(),
        sequenceNumber: headSeq,
        contributions: null,
        signoffExpectation: null,
      },
      integrity: { canonicalDigest: digest, chainLink: null },
      nonRepudiation: {},
      custodyChain: [],
      attestationStatus: 'none',
    });
  };

  for (let i = 0; i < seedRecords; i++) appendForeignRecord();

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
      completeness: string;
      envelope?: EvidenceEnvelope;
      chainId?: string;
    };
    const clientEnvelope = body.envelope!;

    // Digest self-consistency check (verification_failed on mismatch).
    const v = verifyEnvelope(clientEnvelope, undefined, registry);
    if (v.recomputedDigest !== v.storedDigest) {
      return json(422, { ok: false, error: 'verification_failed', failedCheck: 'digest' });
    }

    // A partial envelope that CARRIES chain linkage must link to OUR head.
    if (clientEnvelope.integrity.chainLink !== null) {
      const linked = verifyEnvelope(clientEnvelope, headDigest ?? undefined, registry);
      if (headDigest === null || linked.chainLinkValid !== true) {
        submissions.push({ sequenceNumber: clientEnvelope.payload.sequenceNumber, status: 409 });
        return json(409, {
          ok: false,
          error: 'chain_conflict',
          expectedPreviousDigest: headDigest,
        });
      }
    }

    const sequence = headSeq + 1;

    // `sequenceNumber` is a hashed field, so re-stamping an envelope that carries a digest-bound
    // attestation would store an artifact attesting a digest that exists
    // nowhere. The backend refuses and names the sequence it WOULD assign.
    if (
      clientEnvelope.payload.sequenceNumber !== sequence &&
      carriesDigestBoundAttestation(clientEnvelope)
    ) {
      submissions.push({
        sequenceNumber: clientEnvelope.payload.sequenceNumber,
        status: 409,
        reason: 'attested_envelope_cannot_be_restamped',
      });
      return json(409, {
        ok: false,
        error: 'chain_conflict',
        reason: 'attested_envelope_cannot_be_restamped',
        expectedSequence: sequence,
        actualSequence: clientEnvelope.payload.sequenceNumber,
        expectedPreviousDigest: headDigest,
      });
    }

    const restamped = restampEnvelope(clientEnvelope, sequence, headDigest);
    stored.push(restamped);
    headSeq = sequence;
    headDigest = restamped.integrity.canonicalDigest;
    submissions.push({ sequenceNumber: clientEnvelope.payload.sequenceNumber, status: 202 });

    return json(202, {
      ok: true,
      evidenceId: restamped.payload.evidenceId,
      chainId: body.chainId ?? 'default',
      sequence,
      state: 'captured',
      canonicalDigest: restamped.integrity.canonicalDigest,
      headDigest: restamped.integrity.canonicalDigest,
    });
  };

  return {
    fetchFn,
    stored,
    submissions,
    appendForeignRecord,
    headDigest: () => headDigest,
    headSeq: () => headSeq,
  };
}

const input = (label: string) => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { text: label },
  action: 'approved',
  reason: `because ${label}`,
});

async function cloudTzun(server: FakeServer, onLog?: LogSink): Promise<Tzun> {
  return Tzun.init({
    mode: 'dev',
    apiKey: SECRET_KEY,
    apiUrl: API_URL,
    attestation: { require: [] },
    _httpFetchFn: server.fetchFn,
    ...(onLog ? { onLog } : {}),
  });
}

type LogLine = [string, Record<string, unknown>];
function logSink(): { lines: LogLine[]; onLog: LogSink } {
  const lines: LogLine[] = [];
  return { lines, onLog: (e, f) => { lines.push([e, f]); } };
}
const retriesIn = (lines: LogLine[]) =>
  lines.filter(([event]) => event === 'capture_chain_conflict_retry');

/**
 * A cloud client with an EXPLICIT client-side attestation — the shape the
 * re-stamp refusal is about (the cloud default is server-side attestation; an
 * explicit config is honoured verbatim). The orchestrator is a
 * stub that records every digest it is asked to attest and returns a
 * timestamp token for it, so the envelope carries a digest-bound artifact
 * (`attestationStatus: 'partial'`) and the test can count TSA round trips.
 */
async function attestingCloudTzun(
  server: FakeServer,
  onLog?: LogSink,
): Promise<{ tzun: Tzun; attested: string[] }> {
  const tzun = await cloudTzun(server, onLog);
  const attested: string[] = [];
  (tzun as unknown as { orchestrator: unknown }).orchestrator = {
    attest: async (digest: string) => {
      attested.push(digest);
      return { rfc3161Token: `tok-${digest.slice(0, 12)}` };
    },
    flush: async () => {},
  };
  return { tzun, attested };
}

describe('cloud capture keeps the server head (HttpStorageAdapter)', () => {
  it('stores three sequential captures against a VIRGIN server chain', async () => {
    const server = makeFakeServer(0);
    const tzun = await cloudTzun(server);

    for (const label of ['one', 'two', 'three']) {
      const r = await tzun.capture(input(label));
      expect(r.stored).toBe(true);
    }
    expect(server.stored.map((e) => e.payload.sequenceNumber)).toEqual([1, 2, 3]);
    await tzun.close();
  });

  it('stores three sequential captures against a NON-VIRGIN chain (restart / second replica)', async () => {
    // The ordinary shape for any long-lived deployment. With a purely local
    // head, the first capture would be stored at the wrong sequence with an
    // untrue receipt, and the second and third would be rejected with
    // chain_conflict and dropped, permanently, for the life of the process.
    const server = makeFakeServer(3);
    const tzun = await cloudTzun(server);

    const results = [];
    for (const label of ['one', 'two', 'three']) {
      results.push(await tzun.capture(input(label)));
    }

    expect(results.map((r) => r.stored)).toEqual([true, true, true]);
    expect(server.stored.map((e) => e.payload.sequenceNumber)).toEqual([1, 2, 3, 4, 5, 6]);
    await tzun.close();
  });

  it('reports the sequence and digest the SERVER recorded, not the ones we submitted', async () => {
    const server = makeFakeServer(3);
    const tzun = await cloudTzun(server);

    const r = await tzun.capture(input('first-after-restart'));

    // The local envelope still says sequence 1 — it was built before the
    // server could be consulted, and sequenceNumber is a hashed field.
    expect(r.envelope.payload.sequenceNumber).toBe(1);

    // The receipt must nonetheless tell the truth about what was stored.
    expect(r.serverReceipt).toBeDefined();
    expect(r.serverReceipt!.sequence).toBe(4);
    const serverRecord = server.stored[3];
    expect(r.serverReceipt!.canonicalDigest).toBe(serverRecord.integrity.canonicalDigest);
    expect(r.serverReceipt!.canonicalDigest).not.toBe(r.envelope.integrity.canonicalDigest);
    expect(r.serverReceipt!.evidenceId).toBe(r.envelope.payload.evidenceId);
    // The platform's evidence logs are its own: the receipt names the record,
    // and no local log position is reported.
    expect(r).not.toHaveProperty('logPosition');
    await tzun.close();
  });

  it('omits serverReceipt on local adapters (the envelope IS the stored record)', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    const r = await tzun.capture(input('local'));
    expect(r.stored).toBe(true);
    expect(r.serverReceipt).toBeUndefined();
    await tzun.close();
  });

  it('retries onto the head a chain_conflict reports, so one conflict costs a round trip, not the decision', async () => {
    // The 409 body carries the server's real head precisely so the client can
    // rebuild against it, so the conflicted capture itself is stored in the
    // same call. Adopting the head only for the NEXT capture would throw away
    // the decision in hand: one decision lost per conflict, and two cloud
    // clients on one chain (two replicas with one API key) would lose every
    // other capture.
    const server = makeFakeServer(0);
    const tzun = await cloudTzun(server);

    expect((await tzun.capture(input('one'))).stored).toBe(true);

    // Another writer appends to the same chain between our captures.
    server.appendForeignRecord();

    // Ours links to a stale head → the server rejects it (correctly) and
    // tells us the head → we rebuild against it and resend, in the same call.
    const recovered = await tzun.capture(input('two'));
    expect(recovered.stored).toBe(true);
    expect(recovered.failure).toBeUndefined();
    expect(recovered.serverReceipt!.sequence).toBe(3);

    // And the view is current afterwards.
    const next = await tzun.capture(input('three'));
    expect(next.stored).toBe(true);
    expect(next.serverReceipt!.sequence).toBe(4);
    expect(server.stored.map((e) => e.payload.sequenceNumber)).toEqual([1, 2, 3, 4]);
    await tzun.close();
  });

  it('two cloud clients on one chain both store every capture', async () => {
    // The two-replica shape on the cloud transport: each client's cached head
    // goes stale every time the other one writes. Without the retry, every
    // capture after the first round from whichever client wrote second would
    // come back `stored: false` as `cloud_chain_conflict`.
    const server = makeFakeServer(0);
    const a = await cloudTzun(server);
    const b = await cloudTzun(server);

    const results = [];
    for (let round = 0; round < 4; round++) {
      results.push(await a.capture(input(`a${round}`)));
      results.push(await b.capture(input(`b${round}`)));
    }
    expect(results.map((r) => r.stored)).toEqual(Array(8).fill(true));
    expect(results.map((r) => r.serverReceipt!.sequence)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(server.stored.map((e) => e.payload.sequenceNumber)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    // Every stored record links to the one before it, as the server restamped it.
    for (let i = 1; i < server.stored.length; i++) {
      const chain = new EvidenceChain();
      chain.restore(server.stored[i - 1].integrity.canonicalDigest);
      expect(server.stored[i].integrity.chainLink).toBe(
        chain.computeLink(server.stored[i].integrity.canonicalDigest),
      );
    }
    await a.close();
    await b.close();
  });

  it('exposes the server head through getLastDigest()/getLastSequence()', async () => {
    const server = makeFakeServer(3);
    const transport = new HttpTransport({
      apiKey: SECRET_KEY,
      apiUrl: API_URL,
      fetchFn: server.fetchFn,
    });
    const adapter = new HttpStorageAdapter(transport);
    const tzun = await cloudTzun(server); // separate instance, just to build an envelope
    const built = (await tzun.capture(input('probe'))).envelope;
    await tzun.close();

    // Nothing stored through THIS adapter yet — genesis defaults are honest.
    expect(await adapter.getLastDigest()).toBeNull();
    expect(await adapter.getLastSequence()).toBe(0);

    await adapter.store(built, 'default');

    expect(await adapter.getLastSequence()).toBe(server.headSeq());
    expect(await adapter.getLastDigest()).toBe(server.headDigest());
    expect(adapter.getLastStoredReceipt()!.sequence).toBe(server.headSeq());

    // resetChainState drops the cached view (the server owns chain state).
    await adapter.resetChainState();
    expect(await adapter.getLastDigest()).toBeNull();
  });
});

describe('cloud reads throw instead of reporting a vacuous clean bill of health', () => {
  it('verifyChainCompleteness() rejects rather than returning valid:true over nothing', async () => {
    const server = makeFakeServer(3);
    const tzun = await cloudTzun(server);
    await tzun.capture(input('one'));

    await expect(tzun.verifyChainCompleteness()).rejects.toThrow(TzunCloudReadUnsupportedError);
    await tzun.close();
  });

  it('verifyRange() rejects rather than reporting 0 records / 0 issues', async () => {
    const server = makeFakeServer(0);
    const tzun = await cloudTzun(server);
    await tzun.capture(input('one'));

    await expect(tzun.verifyRange(1)).rejects.toThrow(TzunCloudReadUnsupportedError);
    await tzun.close();
  });

  it('storage.list() rejects rather than returning an empty listing', async () => {
    // `tzun.list()` is served by the backend (pinned in
    // http-transport-reads.test.ts). The `StorageAdapter.list()` contract
    // refuses, and for the reason the adapter gives: it returns BARE
    // envelopes, so answering it would discard the verdict the server computed
    // and leave the caller holding a record it cannot report the checks on.
    const server = makeFakeServer(0);
    const tzun = await cloudTzun(server);
    await tzun.capture(input('one'));

    await expect(tzun.getStorage().list()).rejects.toThrow(TzunCloudReadUnsupportedError);
    await tzun.close();
  });

  it('retryPendingAttestations() rejects rather than reporting attempted:0', async () => {
    const server = makeFakeServer(0);
    const tzun = await cloudTzun(server);

    await expect(tzun.retryPendingAttestations()).rejects.toThrow(TzunCloudReadUnsupportedError);
    await tzun.close();
  });

  it('getSealedChainCount() rejects rather than counting an empty chain list', async () => {
    const server = makeFakeServer(0);
    const tzun = await cloudTzun(server);

    await expect(tzun.getSealedChainCount()).rejects.toThrow(TzunCloudReadUnsupportedError);
    await tzun.close();
  });

  it('storage.retrieve() rejects rather than reporting "not found" for evidence the server holds', async () => {
    const server = makeFakeServer(0);
    const tzun = await cloudTzun(server);
    const r = await tzun.capture(input('one'));

    await expect(
      tzun.getStorage().retrieve(r.envelope.payload.evidenceId),
    ).rejects.toThrow(TzunCloudReadUnsupportedError);
    await tzun.close();
  });

  it('the thrown error carries a stable code and names the method', async () => {
    const server = makeFakeServer(0);
    const tzun = await cloudTzun(server);
    try {
      await tzun.getStorage().list();
      throw new Error('expected storage.list() to reject');
    } catch (err) {
      expect(err).toBeInstanceOf(TzunCloudReadUnsupportedError);
      expect((err as TzunCloudReadUnsupportedError).code).toBe('cloud_read_unsupported');
      expect((err as TzunCloudReadUnsupportedError).method).toBe('list');
    }
    await tzun.close();
  });

  it('refuses monitoring.scanner at init instead of scanning nothing forever', async () => {
    const server = makeFakeServer(0);
    await expect(
      Tzun.init({
        mode: 'dev',
        apiKey: SECRET_KEY,
        apiUrl: API_URL,
        attestation: { require: [] },
        _httpFetchFn: server.fetchFn,
        monitoring: { enabled: true, scanner: { intervalMs: 1000 } },
      } as never),
    ).rejects.toThrow(/monitoring\.scanner is not supported on the cloud transport/);
  });

  it('still allows monitoring without a scanner or proxy (event bus only)', async () => {
    const server = makeFakeServer(0);
    const tzun = await Tzun.init({
      mode: 'dev',
      apiKey: SECRET_KEY,
      apiUrl: API_URL,
      attestation: { require: [] },
      _httpFetchFn: server.fetchFn,
      monitoring: { enabled: true },
    });
    expect((await tzun.capture(input('one'))).stored).toBe(true);
    await tzun.close();
  });
});

describe('an attested cloud capture is rebuilt at the sequence the server names', () => {
  it('one refusal, one re-attest, stored at head+1 — not ten rebuilds at the same stale sequence', async () => {
    // Any process restart on a non-empty chain, or any second replica: the
    // client's first record is built at sequence 1 against a chain at 40.
    // The envelope is attested, so the server cannot re-stamp it; it refuses
    // with `expectedSequence: 41`, and the retry rebuilds at that sequence.
    // Adopting only the digest from that body would rebuild the record at
    // sequence 1 again on every retry — ten times, one paid TSA round trip
    // each — and surface `cloud_chain_conflict attempts: 10` with nothing
    // stored, on every capture, for the life of the process.
    const server = makeFakeServer(40);
    const log = logSink();
    const { tzun, attested } = await attestingCloudTzun(server, log.onLog);

    const r = await tzun.capture(input('after-restart'));

    expect(r.failure).toBeUndefined();
    expect(r.stored).toBe(true);
    expect(server.submissions).toEqual([
      { sequenceNumber: 1, status: 409, reason: 'attested_envelope_cannot_be_restamped' },
      { sequenceNumber: 41, status: 202 },
    ]);
    // Two attestations: the refused one and the one that landed. Not ten.
    expect(attested).toHaveLength(2);
    expect(retriesIn(log.lines)).toHaveLength(1);

    // Stored at the sequence the server named, exactly as attested — the
    // server had nothing to re-stamp, so the receipt matches the envelope.
    expect(r.serverReceipt!.sequence).toBe(41);
    expect(r.envelope.payload.sequenceNumber).toBe(41);
    const stored = server.stored[40];
    expect(stored.payload.sequenceNumber).toBe(41);
    expect(stored.integrity.canonicalDigest).toBe(attested[1]);
    expect(r.envelope.integrity.canonicalDigest).toBe(attested[1]);
    expect(stored.nonRepudiation.rfc3161Token).toBe(`tok-${attested[1].slice(0, 12)}`);
    expect(log.lines.filter(([e]) => e === 'capture_receipt_restamped')).toEqual([]);

    // And the client's view is current: the next capture lands first time.
    const next = await tzun.capture(input('next'));
    expect(next.stored).toBe(true);
    expect(next.serverReceipt!.sequence).toBe(42);
    expect(server.submissions.slice(2)).toEqual([{ sequenceNumber: 42, status: 202 }]);
    await tzun.close();
  });

  it('two attested cloud clients on one chain both store every capture, each as attested', async () => {
    // The two-replica shape with client-side attestation. A stale client is
    // refused twice per round — once for its chain link (that 409 names only
    // the digest) and once for its sequence (that one names the sequence) —
    // and lands on the third build. Bounded, and every stored record is one
    // its own client attested at that exact sequence.
    const server = makeFakeServer(0);
    const log = logSink();
    const a = await attestingCloudTzun(server, log.onLog);
    const b = await attestingCloudTzun(server, log.onLog);

    const results = [];
    for (let round = 0; round < 4; round++) {
      results.push(await a.tzun.capture(input(`a${round}`)));
      results.push(await b.tzun.capture(input(`b${round}`)));
    }
    expect(results.map((r) => r.stored)).toEqual(Array(8).fill(true));
    expect(results.map((r) => r.serverReceipt!.sequence)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(server.stored.map((e) => e.payload.sequenceNumber)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);

    const attestedDigests = new Set([...a.attested, ...b.attested]);
    for (const e of server.stored) {
      expect(attestedDigests.has(e.integrity.canonicalDigest)).toBe(true);
      expect(e.nonRepudiation.rfc3161Token).toBe(`tok-${e.integrity.canonicalDigest.slice(0, 12)}`);
    }
    // Never more than two refusals before a build lands.
    const attempts = retriesIn(log.lines).map(([, f]) => f.attempt as number);
    expect(attempts.length).toBeGreaterThan(0);
    expect(Math.max(...attempts)).toBeLessThanOrEqual(2);
    expect(server.submissions.filter((s) => s.status === 202)).toHaveLength(8);
    await a.tzun.close();
    await b.tzun.close();
  });
});
