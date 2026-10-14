import { builtModel } from './helpers/step-model';
/**
 * The four customer reads, through the `Tzun` class, against the hosted service.
 *
 * `HttpStorageAdapter` has `retrieveWithVerdict`, `listWithVerdicts`,
 * `verifyRecord` and `exportEvidence`, named to match the
 * verifying proxy's. This file pins what the public surface makes of them:
 *
 *   - `get()` / `list()` take the verdict path on either storage layer, because
 *     the check is structural, not `instanceof VerifyingStorageProxy`. The
 *     cloud adapter is not a proxy; on the fallback, `storage.retrieve()`
 *     throws and a cloud read would report "no read path" though it has one.
 *   - `verify()` recomputes the record HERE, against the predecessor the server
 *     measured against. The server's verdict is not passed through as if this
 *     process had checked it; `get()` returns it for a caller who wants it.
 *   - `exportEvidence()` re-homes the platform's bundle into
 *     `ExportedEvidenceEnvelope`, so one offline verifier
 *     (`helpers/verify-exported.ts`) reads either side's export. Nothing is
 *     invented: no `exportedAt`/`exportedBy`, every referenced descriptor marked
 *     as the gap it is, and the platform's own receipt block carried rather than
 *     dropped.
 *
 * No network: every case drives an injected fetch that routes on the URL.
 */
import { assembleEnvelope, SchemaRegistry } from '@tzun/engine';
import type { EvidenceEnvelope, RecordVerdict } from '@tzun/engine';
import { Tzun } from '../../src/sdk/index';
import type { CloudExportBundle, FetchFn } from '../../src/sdk/http-transport';
import { TzunCloudReadUnsupportedError } from '../../src/sdk/http-transport';
import { verifyExported } from './helpers/verify-exported';
import { makeGenuineAssertion } from './attestation-assertion-helpers';
import { webauthnChallengeForDigest } from '../../src/attestation/verify-attestation';

const API_KEY = 'sk_test_cloud_reads';
const API_URL = 'https://api.example.test';
const registry = new SchemaRegistry();

const genesis = assembleEnvelope({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiSystemId: 'underwriter', aiOutput: { r: 1 }, action: 'approved', reason: 'first' }, { sequenceNumber: 1 });
const second = assembleEnvelope({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiSystemId: 'underwriter', aiOutput: { r: 2 }, action: 'approved', reason: 'second' }, { previousDigest: genesis.integrity.canonicalDigest, sequenceNumber: 2 });

/** A verdict in the engine's shape, as the platform sends it. */
function verdictFor(envelope: EvidenceEnvelope, over: Partial<RecordVerdict> = {}): RecordVerdict {
  return {
    status: 'valid',
    digest: {
      status: 'valid',
      stored: envelope.integrity.canonicalDigest,
      recomputed: envelope.integrity.canonicalDigest,
    },
    custodyTrail: {
      status: 'valid',
      ledger: {
        evidenceId: envelope.payload.evidenceId,
        valid: true,
        rows: 0,
        hashedEntries: 0,
        unhashedEntries: 1,
        failures: [],
      },
    },
    chainLink: {
      status: 'valid',
      predecessorDigest: genesis.integrity.canonicalDigest,
    },
    checkedAt: '2026-09-19T01:00:00.000Z',
    ...over,
  } as RecordVerdict;
}

const chainBlock = {
  chainId: 'default',
  predecessor: {
    evidenceId: genesis.payload.evidenceId,
    sequenceNumber: 1,
    canonicalDigest: genesis.integrity.canonicalDigest,
  },
};

function exportBundle(over: Partial<CloudExportBundle> = {}): CloudExportBundle {
  return {
    envelope: second,
    verdict: verdictFor(second),
    chain: chainBlock,
    server: {
      receivedAt: '2026-09-19T00:00:01.000Z',
      attestation: {
        state: 'attested',
        status: 'complete',
        claimedStatus: 'none',
        rfc3161Token: 'c2VydmVyLXRva2Vu',
        artifact: { authority: 'freetsa' },
      },
      custody: {
        hashPreimage: 'server-preimage',
        entries: [],
        trail: {
          evidenceId: second.payload.evidenceId,
          valid: true,
          rows: 0,
          hashedEntries: 0,
          unhashedEntries: 1,
          failures: [],
        },
        offlineTrail: null,
      },
    },
    ...over,
  } as CloudExportBundle;
}

interface Routes {
  record?: { status: number; body?: unknown };
  page?: { status: number; body?: unknown };
  verify?: { status: number; body?: unknown };
  export?: { status: number; body?: unknown };
}

/** A fetch that routes on the URL and records every request. */
function routingFetch(routes: Routes): { fetchFn: FetchFn; urls: string[] } {
  const urls: string[] = [];
  const fetchFn: FetchFn = async (url) => {
    urls.push(url);
    const path = new URL(url).pathname;
    const answer = path.endsWith('/verify')
      ? routes.verify
      : path.endsWith('/export')
        ? routes.export
        : path === '/v1/app/evidence'
          ? routes.page
          : routes.record;
    if (!answer) throw new Error(`routingFetch: no route for ${url}`);
    return {
      ok: answer.status >= 200 && answer.status < 300,
      status: answer.status,
      headers: new Headers(),
      async json() {
        return answer.body;
      },
    } as unknown as Response;
  };
  return { fetchFn, urls };
}

async function cloudTzun(fetchFn: FetchFn): Promise<Tzun> {
  return Tzun.init({
    mode: 'dev',
    apiKey: API_KEY,
    apiUrl: API_URL,
    attestation: { require: [] },
    _httpFetchFn: fetchFn,
  } as Parameters<typeof Tzun.init>[0]);
}

const NOT_FOUND = { status: 404, body: { ok: false, error: 'not_found' } };

describe('Tzun.get() / Tzun.list() on the cloud transport', () => {
  it('get() returns the record with the server verdict, at the record URL', async () => {
    const verdict = verdictFor(second);
    const { fetchFn, urls } = routingFetch({ record: { status: 200, body: { envelope: second, verdict } } });
    const tzun = await cloudTzun(fetchFn);
    try {
      const read = await tzun.get(second.payload.evidenceId);
      expect(read).toEqual({ envelope: second, verdict });
    } finally {
      await tzun.close();
    }
    expect(urls).toEqual([
      `${API_URL}/v1/app/evidence/${encodeURIComponent(second.payload.evidenceId)}`,
    ]);
  });

  it('get() of a record the key cannot see is null, not an error', async () => {
    const { fetchFn } = routingFetch({ record: NOT_FOUND });
    const tzun = await cloudTzun(fetchFn);
    try {
      expect(await tzun.get('nobody-elses-record')).toBeNull();
    } finally {
      await tzun.close();
    }
  });

  it('list() returns the page, each record with its verdict', async () => {
    const rows = [genesis, second].map((envelope) => ({ envelope, verdict: verdictFor(envelope) }));
    const { fetchFn, urls } = routingFetch({ page: { status: 200, body: { evidence: rows } } });
    const tzun = await cloudTzun(fetchFn);
    try {
      const page = await tzun.list({ limit: 2 });
      expect(page).toEqual(rows);
    } finally {
      await tzun.close();
    }
    expect(urls[0]).toContain('include=envelope');
    expect(urls[0]).toContain('limit=2');
  });

  it('list() refuses a filter the server does not apply rather than ignoring it', async () => {
    const { fetchFn, urls } = routingFetch({ page: { status: 200, body: { evidence: [] } } });
    const tzun = await cloudTzun(fetchFn);
    try {
      await expect(tzun.list({ aiSystemId: 'underwriter' })).rejects.toThrow(
        TzunCloudReadUnsupportedError,
      );
    } finally {
      await tzun.close();
    }
    expect(urls).toEqual([]);
  });
});

describe('Tzun.verify() on the cloud transport', () => {
  it('recomputes the record here, against the predecessor the server measured against', async () => {
    const { fetchFn, urls } = routingFetch({
      record: { status: 200, body: { envelope: second, verdict: verdictFor(second) } },
      verify: {
        status: 200,
        body: { evidenceId: second.payload.evidenceId, verdict: verdictFor(second), chain: chainBlock },
      },
    });
    const tzun = await cloudTzun(fetchFn);
    let result;
    try {
      result = await tzun.verify(second.payload.evidenceId);
    } finally {
      await tzun.close();
    }

    expect(result.verified).toBe(true);
    expect(result.chainLinkValid).toBe(true);
    // Every field computed from bytes this process held, not copied from the
    // server's verdict: the schema version and the recomputed digest are not in
    // the verify response at all.
    expect(result.schemaVersion).toBe('v1.0');
    expect(result.schemaValid).toBe(true);
    expect(result.recomputedDigest).toBe(second.integrity.canonicalDigest);
    expect(result.storedDigest).toBe(second.integrity.canonicalDigest);
    expect(urls.filter((u) => u.endsWith('/verify'))).toHaveLength(1);
  });

  it('does not take the server\'s word for it: a rewritten record fails here even when the server says valid', async () => {
    const rewritten = JSON.parse(JSON.stringify(second)) as EvidenceEnvelope;
    rewritten.payload.reason = 'rewritten in flight';
    const { fetchFn } = routingFetch({
      record: { status: 200, body: { envelope: rewritten, verdict: verdictFor(second) } },
      verify: {
        status: 200,
        body: { evidenceId: second.payload.evidenceId, verdict: verdictFor(second), chain: chainBlock },
      },
    });
    const tzun = await cloudTzun(fetchFn);
    let result;
    try {
      result = await tzun.verify(second.payload.evidenceId);
    } finally {
      await tzun.close();
    }

    expect(result.verified).toBe(false);
    expect(result.storedDigest).toBe(second.integrity.canonicalDigest);
    expect(result.recomputedDigest).not.toBe(second.integrity.canonicalDigest);
    expect(result.recomputedDigest).toMatch(/^[0-9a-f]{64}$/);
  });

  it('a caller-supplied previousDigest wins, and spends no round trip on the server verdict', async () => {
    const { fetchFn, urls } = routingFetch({
      record: { status: 200, body: { envelope: second, verdict: verdictFor(second) } },
    });
    const tzun = await cloudTzun(fetchFn);
    try {
      const result = await tzun.verify(second.payload.evidenceId, genesis.integrity.canonicalDigest);
      expect(result.verified).toBe(true);
      expect(result.chainLinkValid).toBe(true);
    } finally {
      await tzun.close();
    }
    expect(urls.filter((u) => u.endsWith('/verify'))).toHaveLength(0);
  });

  it('a record the key cannot see throws, as it does locally', async () => {
    const { fetchFn } = routingFetch({ record: NOT_FOUND });
    const tzun = await cloudTzun(fetchFn);
    try {
      await expect(tzun.verify('nobody-elses-record')).rejects.toThrow(/not found/);
    } finally {
      await tzun.close();
    }
  });
});

describe('Tzun.exportEvidence() on the cloud transport', () => {
  it('re-homes the platform bundle, invents nothing, and keeps the server receipt', async () => {
    const bundle = exportBundle();
    const { fetchFn, urls } = routingFetch({ export: { status: 200, body: bundle } });
    const tzun = await cloudTzun(fetchFn);
    let exported;
    try {
      exported = await tzun.exportEvidence(second.payload.evidenceId);
    } finally {
      await tzun.close();
    }

    expect(urls[0]).toContain('/export');
    expect(exported.envelope).toEqual(second);
    expect(exported.verdict).toEqual(bundle.verdict);
    expect(exported.chain).toEqual(chainBlock);

    // The exporter's claims about itself are absent: the server did not send
    // them, and this SDK did not assemble the bundle.
    expect(exported.exportedAt).toBeUndefined();
    expect(exported.exportedBy).toBeUndefined();

    // The custody block is the server's, under this bundle's names.
    expect(exported.custody.hashPreimage).toBe('server-preimage');
    expect(exported.custody.entries).toEqual([]);
    expect(exported.custody.trail).toEqual(bundle.server.custody.trail);
    // offlineTrail is a pure function of the envelope in the bundle, so a
    // server that sent none is answered here rather than left null.
    expect(exported.custody.offlineTrail).not.toBeNull();
    expect(exported.custody.offlineTrail.valid).not.toBe(false);

    // The platform's own receipt — including a token IT obtained, which the
    // client envelope does not carry — is kept, not dropped.
    expect(exported.server).toEqual(bundle.server);
    expect(exported.server!.attestation.rfc3161Token).toBe('c2VydmVyLXRva2Vu');
    expect(exported.server!.attestation.claimedStatus).toBe('none');
  });

  it('keeps an offlineTrail the server did send', async () => {
    const bundle = exportBundle();
    bundle.server.custody.offlineTrail = {
      valid: true,
      hashedEntries: 1,
      unhashedEntries: 0,
      failures: [],
    } as CloudExportBundle['server']['custody']['offlineTrail'];
    const { fetchFn } = routingFetch({ export: { status: 200, body: bundle } });
    const tzun = await cloudTzun(fetchFn);
    try {
      const exported = await tzun.exportEvidence(second.payload.evidenceId);
      expect(exported.custody.offlineTrail).toEqual(bundle.server.custody.offlineTrail);
    } finally {
      await tzun.close();
    }
  });

  it('the one offline verifier reads the re-homed bundle', async () => {
    const { fetchFn } = routingFetch({ export: { status: 200, body: exportBundle() } });
    const tzun = await cloudTzun(fetchFn);
    try {
      const exported = await tzun.exportEvidence(second.payload.evidenceId);
      expect(await verifyExported(exported)).toEqual({ ok: true });
    } finally {
      await tzun.close();
    }
  });

  it('a referenced descriptor is marked as the gap it is, never omitted', async () => {
    const digest = `sha256:${'ab'.repeat(32)}`;
    const third = { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiSystemId: 'underwriter', aiOutput: { r: 3 }, action: 'approved', reason: 'third' };
    const withAiBom = assembleEnvelope(
      { ...third, contributions: builtModel({ modelDescriptorDigest: digest }, third) },
      { previousDigest: genesis.integrity.canonicalDigest, sequenceNumber: 2 },
    );
    const bundle = exportBundle({ envelope: withAiBom, verdict: verdictFor(withAiBom) });
    const { fetchFn } = routingFetch({ export: { status: 200, body: bundle } });
    const tzun = await cloudTzun(fetchFn);
    let exported;
    try {
      exported = await tzun.exportEvidence(withAiBom.payload.evidenceId);
    } finally {
      await tzun.close();
    }

    expect(exported.resolvedModelDescriptors).toEqual({
      [digest]: { canonicalBytes: '', enrichedView: null, annotations: [], missing: true },
    });
    // And the offline verifier reports it, which is the point of marking it.
    const verified = await verifyExported(exported);
    expect(verified.ok).toBe(false);
    expect((verified as { errors: string[] }).errors.join('\n')).toContain(
      'missing from bundle (catalog gap at export time)',
    );
  });

  it('a record with no aiBom bundles no descriptors', async () => {
    const { fetchFn } = routingFetch({ export: { status: 200, body: exportBundle() } });
    const tzun = await cloudTzun(fetchFn);
    try {
      const exported = await tzun.exportEvidence(second.payload.evidenceId);
      expect(exported.resolvedModelDescriptors).toEqual({});
    } finally {
      await tzun.close();
    }
  });

  it('records the provenance of the envelope\'s assertion, read here from the envelope', async () => {
    const { assertion } = makeGenuineAssertion({
      challenge: webauthnChallengeForDigest(second.integrity.canonicalDigest),
      credentialId: 'cred-panel',
      origin: 'https://panel.example',
      flags: 0x1d,
      clientData: { crossOrigin: true, topOrigin: 'chrome-extension://cjdhdebnabcamkngfcpipeapbpgdfjlg' },
    });
    const signed = { ...second, nonRepudiation: { ...second.nonRepudiation, webauthnAssertion: assertion } };
    const { fetchFn } = routingFetch({
      export: { status: 200, body: exportBundle({ envelope: signed, verdict: verdictFor(signed) }) },
    });
    const tzun = await cloudTzun(fetchFn);
    let exported;
    try {
      exported = await tzun.exportEvidence(second.payload.evidenceId, {
        assertion: { requireDeviceBound: true },
      });
    } finally {
      await tzun.close();
    }

    expect(exported.assertionProvenance).toMatchObject({
      origin: 'https://panel.example',
      crossOrigin: true,
      topOrigin: 'chrome-extension://cjdhdebnabcamkngfcpipeapbpgdfjlg',
      flags: { UP: true, UV: true, BE: true, BS: true },
      deviceBound: false,
      deviceBoundReason: 'credential_synced',
    });
    expect(await verifyExported(exported)).toEqual({ ok: true });
  });

  it('records null provenance for a platform bundle whose envelope carries no assertion', async () => {
    const { fetchFn } = routingFetch({ export: { status: 200, body: exportBundle() } });
    const tzun = await cloudTzun(fetchFn);
    try {
      const exported = await tzun.exportEvidence(second.payload.evidenceId);
      expect(exported.assertionProvenance).toBeNull();
    } finally {
      await tzun.close();
    }
  });

  it('a record the key cannot see throws, as it does locally', async () => {
    const { fetchFn } = routingFetch({ export: NOT_FOUND });
    const tzun = await cloudTzun(fetchFn);
    try {
      await expect(tzun.exportEvidence('nobody-elses-record')).rejects.toThrow(/not found/);
    } finally {
      await tzun.close();
    }
  });
});

describe('the verifyReads refusal says what is actually local-only', () => {
  it('refuses verifyReads on the cloud transport, without claiming there is no read path', async () => {
    const { fetchFn } = routingFetch({ record: { status: 200, body: {} } });
    const attempt = Tzun.init({
      mode: 'dev',
      apiKey: API_KEY,
      apiUrl: API_URL,
      attestation: { require: [] },
      _httpFetchFn: fetchFn,
      verifyReads: true,
    } as Parameters<typeof Tzun.init>[0]);

    await expect(attempt).rejects.toThrow(/verifyReads is not supported on the cloud transport/);
    const message = await attempt.then(
      () => '',
      (err: unknown) => (err as Error).message,
    );
    // The mechanism is local-only — the proxy wraps a local adapter — and that
    // is what the refusal has to say. It must not claim the cloud transport
    // has no read path: get() and list() carry the server's verdict.
    expect(message).toContain('wraps a LOCAL adapter');
    expect(message).not.toContain('no read path');
    expect(message).toContain('get() and list() carry the verdict the server computed');
  });
});
