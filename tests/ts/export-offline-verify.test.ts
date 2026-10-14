import { modelOf, modelInput } from './helpers/step-model';
/**
 * Export pipeline tests.
 *
 * Covers:
 *   - `tzun.exportEvidence` produces a self-contained ExportedEvidenceEnvelope.
 *   - `walkLineage: true` (default) bundles the full ancestor DAG.
 *   - `walkLineage: false` bundles only the leaf descriptor.
 *   - `aiBom: null` envelopes produce an empty `resolvedModelDescriptors`.
 *   - Missing-from-catalog descriptors are surfaced as `{ missing: true }`.
 *   - `verifyExported(bundle)` round-trips with NO catalog access on the
 *     verifier side (fresh Tzun instance with empty memory backend).
 *   - Tampered-bundle detection (mutate canonicalBytes after export).
 *   - REST endpoint:
 *       - returns 200 + JSON bundle + Content-Disposition for known IDs;
 *       - honors ?walkLineage=false;
 *       - returns 404 for unknown evidence IDs.
 *   - Verification §3.1 (offline verification): a `b1` proof bundle of
 *     an anchored record, exported from a SQLite or Postgres store, verifies
 *     end to end in a fresh process state (an empty memory store and no
 *     credential store) with `verifyBundle()` and the auditor's own inputs.
 */

import request from 'supertest';
import { Tzun } from '../../src/sdk/index';
import { createServer } from '../../src/api/server';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { registerModel } from '../../src/models/register';
import { ModelDescriptor, ModelDescriptorRow, AiBom } from '@tzun/engine';
import { verifyExported } from './helpers/verify-exported';
import { verifyBundle, bundleExitCode } from '../../src/sdk/index';
import {
  anchoredStore,
  BUNDLE_CHAIN,
  fakeHeaderSource,
  postgresBundleBackend,
  sqliteBundleBackend,
  type BundleBackend,
} from './helpers/bundle-fixtures';

function descriptorFixture(overrides: Partial<ModelDescriptor> = {}): Partial<ModelDescriptor> {
  return {
    vendor: 'Acme AI',
    modelName: 'acme-export-test',
    modelVersion: '1.0',
    modelType: 'language-model',
    integrityTier: 'vendor-asserted',
    license: 'Apache-2.0',
    modelCardUrl: null,
    regulatoryMarkings: [],
    externalIdentifiers: [],
    ...overrides,
  };
}

function baseCaptureInput() {
  return {
    decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
    aiSystemId: 'export-test-system',
    aiOutput: { decision: 'approved', confidence: 0.91 },
    action: 'approved',
    reason: 'matches risk profile',
  };
}

/**
 * Build a parent/child descriptor pair on a given Tzun, capture a DEO that
 * references the child via `aiBom`, and return the relevant identifiers.
 */
async function setupParentChildAndCapture(tzun: Tzun): Promise<{
  parentDigest: string;
  childDigest: string;
  evidenceId: string;
}> {
  const storage = tzun.getStorage();
  const parent = await registerModel(
    storage,
    descriptorFixture({ vendor: 'Acme AI', modelName: 'base', modelVersion: '1.0' }),
  );
  const child = await registerModel(
    storage,
    descriptorFixture({
      vendor: 'Acme AI',
      modelName: 'fine-tuned',
      modelVersion: '2.0',
      parentModelDescriptorDigest: parent.digest,
      derivation: 'fine-tune',
    }),
  );

  const aiBom: AiBom = {
    modelDescriptorDigest: child.digest,
    vendorFingerprint: 'fp_export_test',
    promptTemplate: null,
    inferenceParameters: null,
    infrastructure: null,
  };

  const result = await tzun.capture({ ...baseCaptureInput(), contributions: modelInput(aiBom) });
  if (!result.stored) {
    throw new Error('setup capture failed: ' + JSON.stringify(result.failure));
  }
  return {
    parentDigest: parent.digest,
    childDigest: child.digest,
    evidenceId: result.envelope.payload.evidenceId,
  };
}

describe('tzun.exportEvidence', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('bundles both child and parent descriptors when walkLineage is true (default)', async () => {
    const { parentDigest, childDigest, evidenceId } = await setupParentChildAndCapture(tzun);

    const bundle = await tzun.exportEvidence(evidenceId);

    expect(bundle.envelope.payload.evidenceId).toBe(evidenceId);
    expect(bundle.exportedBy).toBe('tzun-sdk');
    expect(typeof bundle.exportedAt).toBe('string');
    expect(bundle.resolvedModelDescriptors[childDigest]).toBeDefined();
    expect(bundle.resolvedModelDescriptors[parentDigest]).toBeDefined();
    const childEntry = bundle.resolvedModelDescriptors[childDigest];
    if ('missing' in childEntry && childEntry.missing) {
      throw new Error('child entry unexpectedly missing');
    }
    expect(childEntry.canonicalBytes.length).toBeGreaterThan(0);
    expect(childEntry.enrichedView).not.toBeNull();
  });

  it('verifyExported round-trip succeeds on a fresh Tzun with empty memory backend', async () => {
    const { evidenceId } = await setupParentChildAndCapture(tzun);

    const bundle = await tzun.exportEvidence(evidenceId, { walkLineage: true });

    // Simulate an offline verifier: a fresh Tzun instance with empty storage.
    // The helper itself does not touch storage — we construct the empty
    // instance only to assert (via type system and by passing storage=memory)
    // that the verifier could run with no catalog at all. The helper accepts
    // only the bundle.
    const offlineVerifier = await Tzun.init();
    try {
      expect(offlineVerifier.getStorage() instanceof MemoryStorageAdapter).toBe(true);
      const result = await verifyExported(bundle);
      expect(result).toEqual({ ok: true });
    } finally {
      await offlineVerifier.close();
    }
  });

  it('walkLineage: false bundles only the leaf descriptor', async () => {
    const { parentDigest, childDigest, evidenceId } = await setupParentChildAndCapture(tzun);

    const bundle = await tzun.exportEvidence(evidenceId, { walkLineage: false });

    expect(bundle.resolvedModelDescriptors[childDigest]).toBeDefined();
    expect(bundle.resolvedModelDescriptors[parentDigest]).toBeUndefined();
  });

  it('aiBom: null envelope yields an empty resolvedModelDescriptors map', async () => {
    const result = await tzun.capture({ ...baseCaptureInput(), contributions: modelInput(null) });
    expect(result.stored).toBe(true);

    const bundle = await tzun.exportEvidence(result.envelope.payload.evidenceId);

    expect(modelOf(bundle.envelope.payload)).toBeNull();
    expect(Object.keys(bundle.resolvedModelDescriptors)).toHaveLength(0);

    // And the offline verifier should be happy with this bundle.
    const verify = await verifyExported(bundle);
    expect(verify).toEqual({ ok: true });
  });

  it('exportedBy defaults to "tzun-sdk" and is overridable', async () => {
    const result = await tzun.capture({ ...baseCaptureInput(), contributions: modelInput(null) });
    const evidenceId = result.envelope.payload.evidenceId;

    const defaultBundle = await tzun.exportEvidence(evidenceId);
    expect(defaultBundle.exportedBy).toBe('tzun-sdk');

    const overridden = await tzun.exportEvidence(evidenceId, { exportedBy: 'court@example.com' });
    expect(overridden.exportedBy).toBe('court@example.com');
  });

  it('throws a clear error when evidenceId is unknown', async () => {
    await expect(tzun.exportEvidence('nonexistent-evidence-id')).rejects.toThrow(
      /not found.*non-existent/i,
    );
  });

  it('surfaces missing-from-catalog descriptors as { missing: true } rather than dropping silently', async () => {
    const { parentDigest, childDigest, evidenceId } = await setupParentChildAndCapture(tzun);

    // Reach into the memory adapter and delete the parent row, simulating
    // a real-world catalog gap (descriptor pruned, env mismatch, etc.).
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const internal = storage as unknown as { modelDescriptors: Map<string, unknown> };
    expect(internal.modelDescriptors.has(parentDigest)).toBe(true);
    internal.modelDescriptors.delete(parentDigest);

    const bundle = await tzun.exportEvidence(evidenceId, { walkLineage: true });

    expect(bundle.resolvedModelDescriptors[childDigest]).toBeDefined();
    const parentEntry = bundle.resolvedModelDescriptors[parentDigest];
    expect(parentEntry).toBeDefined();
    expect(parentEntry.missing).toBe(true);
    expect(parentEntry.canonicalBytes).toBe('');
    expect(parentEntry.enrichedView).toBeNull();

    // The offline verifier MUST flag the missing parent.
    const verify = await verifyExported(bundle);
    expect(verify.ok).toBe(false);
    if (verify.ok) throw new Error('expected verification failure');
    expect(verify.errors.some((e) => e.includes(parentDigest) && /missing/.test(e))).toBe(true);
  });

  it('tampered-bundle detection: mutating canonicalBytes surfaces a digest mismatch', async () => {
    const { childDigest, evidenceId } = await setupParentChildAndCapture(tzun);

    const bundle = await tzun.exportEvidence(evidenceId, { walkLineage: true });
    const childEntry = bundle.resolvedModelDescriptors[childDigest];
    if (childEntry.missing) throw new Error('child entry was unexpectedly missing');

    // Mutate the canonical bytes after export — the digest no longer matches.
    childEntry.canonicalBytes = childEntry.canonicalBytes.replace('"d1"', '"d2"');

    const verify = await verifyExported(bundle);
    expect(verify.ok).toBe(false);
    if (verify.ok) throw new Error('expected verification failure');
    expect(verify.errors.some((e) => /digest mismatch/.test(e) && e.includes(childDigest))).toBe(true);
  });

  it('tampered envelope payload: mutating capturedAt surfaces an integrity-digest mismatch', async () => {
    const { evidenceId } = await setupParentChildAndCapture(tzun);

    const bundle = await tzun.exportEvidence(evidenceId);
    // Mutate the envelope payload post-export.
    bundle.envelope.payload.capturedAt = '2099-01-01T00:00:00.000Z';

    const verify = await verifyExported(bundle);
    expect(verify.ok).toBe(false);
    if (verify.ok) throw new Error('expected verification failure');
    expect(verify.errors.some((e) => /envelope.*integrity digest mismatch/i.test(e))).toBe(true);
  });
});

describe('GET /v1/evidence/:id/export', () => {
  let tzun: Tzun;
  let app: ReturnType<typeof createServer>;

  beforeEach(async () => {
    tzun = await Tzun.init();
    app = createServer(tzun, { allowUnauthenticated: true });
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('returns a valid JSON bundle with Content-Disposition for a known evidence ID', async () => {
    const { parentDigest, childDigest, evidenceId } = await setupParentChildAndCapture(tzun);

    const res = await request(app).get(`/v1/evidence/${evidenceId}/export`).expect(200);

    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.headers['content-disposition']).toMatch(/attachment/);
    expect(res.headers['content-disposition']).toContain(`evidence-${evidenceId}.json`);

    expect(res.body).toHaveProperty('envelope');
    expect(res.body).toHaveProperty('resolvedModelDescriptors');
    expect(res.body).toHaveProperty('exportedAt');
    expect(res.body).toHaveProperty('exportedBy');
    expect(res.body.envelope.payload.evidenceId).toBe(evidenceId);
    expect(res.body.resolvedModelDescriptors[childDigest]).toBeDefined();
    expect(res.body.resolvedModelDescriptors[parentDigest]).toBeDefined();
  });

  it('honors ?walkLineage=false by bundling only the leaf descriptor', async () => {
    const { parentDigest, childDigest, evidenceId } = await setupParentChildAndCapture(tzun);

    const res = await request(app)
      .get(`/v1/evidence/${evidenceId}/export?walkLineage=false`)
      .expect(200);

    expect(res.body.resolvedModelDescriptors[childDigest]).toBeDefined();
    expect(res.body.resolvedModelDescriptors[parentDigest]).toBeUndefined();
  });

  it('returns 404 for an unknown evidence ID', async () => {
    const res = await request(app).get('/v1/evidence/no-such-evidence-id/export').expect(404);
    expect(res.body).toHaveProperty('error');
  });

  it('JSON output round-trips through verifyExported successfully', async () => {
    const { evidenceId } = await setupParentChildAndCapture(tzun);

    const res = await request(app).get(`/v1/evidence/${evidenceId}/export`).expect(200);
    const bundle = res.body;

    const verify = await verifyExported(bundle);
    expect(verify).toEqual({ ok: true });
  });

  it('returns the b1 proof bundle with ?bundle=b1, and refuses another bundle version', async () => {
    const { evidenceId } = await setupParentChildAndCapture(tzun);

    const res = await request(app).get(`/v1/evidence/${evidenceId}/export?bundle=b1`).expect(200);
    expect(res.headers['content-disposition']).toContain(`evidence-${evidenceId}.json`);
    expect(res.body).toMatchObject({
      bundleVersion: 'b1',
      profile: 'record',
      subject: { evidenceId },
      anchoring: {},
      anchorPending: null,
      exporter: { exportedBy: 'rest-export' },
    });
    const report = await verifyBundle(res.body);
    expect(report.checks.find((c) => c.id === 'record.digest')).toMatchObject({ outcome: 'checked-correct' });

    const refused = await request(app).get(`/v1/evidence/${evidenceId}/export?bundle=b2`).expect(400);
    expect(refused.body.error).toMatch(/unsupported bundle version "b2"/);
    await request(app).get('/v1/evidence/no-such-evidence-id/export?bundle=b1').expect(404);
  });
});

/**
 * Lineage must be resolved from the digest-covered bytes, never from a
 * pointer no digest covers (the export-side twin of the verifier's rule).
 *
 * Two such pointers exist on the export path:
 *   - `ModelDescriptorRow.parentModelDescriptorDigest` — a denormalized SQL
 *     column an exporter could be tempted to queue ancestors from;
 *   - `ExportedDescriptorEntry.enrichedView.parentModelDescriptorDigest` —
 *     the annotation-applied view an offline verifier could be tempted to walk.
 *
 * Both are writable without disturbing any digest, so both tests below
 * leave every digest in the bundle re-hashing correctly and move only the
 * uncovered pointer.
 */
describe('export lineage is resolved from digest-covered bytes', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  /** Reach the adapter's row table directly — this is the DB-write attacker. */
  function rowTable(t: Tzun): Map<string, ModelDescriptorRow> {
    return (t.getStorage() as unknown as {
      modelDescriptors: Map<string, ModelDescriptorRow>;
    }).modelDescriptors;
  }

  it('exportEvidence bundles the ancestor named in canonicalBytes, not the one in the mutable parent column', async () => {
    const { parentDigest, childDigest, evidenceId } = await setupParentChildAndCapture(tzun);

    // A decoy base model the attacker would like the export to name.
    const decoy = await registerModel(
      tzun.getStorage(),
      descriptorFixture({ vendor: 'Acme AI', modelName: 'decoy-base', modelVersion: '9.9' }),
    );

    // The single UPDATE: repoint the denormalized column only. canonicalBytes
    // and the digest key are untouched, so the row still re-hashes.
    const rows = rowTable(tzun);
    const childRow = rows.get(childDigest);
    if (!childRow) throw new Error('child row missing from adapter table');
    expect(childRow.parentModelDescriptorDigest).toBe(parentDigest);
    childRow.parentModelDescriptorDigest = decoy.digest;

    const bundle = await tzun.exportEvidence(evidenceId);

    // The true ancestor is bundled; the attacker's is not.
    expect(bundle.resolvedModelDescriptors[parentDigest]).toBeDefined();
    expect(bundle.resolvedModelDescriptors[decoy.digest]).toBeUndefined();
    expect(Object.keys(bundle.resolvedModelDescriptors).sort()).toEqual(
      [childDigest, parentDigest].sort(),
    );

    // And the bundle still verifies offline — the tamper never reached it.
    expect(await verifyExported(bundle)).toEqual({ ok: true });
  });

  it('verifyExported rejects a bundle whose enrichedView re-parents a descriptor', async () => {
    const { parentDigest, childDigest, evidenceId } = await setupParentChildAndCapture(tzun);
    const bundle = await tzun.exportEvidence(evidenceId);
    expect(await verifyExported(bundle)).toEqual({ ok: true });

    const childEntry = bundle.resolvedModelDescriptors[childDigest];
    if ('missing' in childEntry && childEntry.missing) {
      throw new Error('child entry unexpectedly missing');
    }
    expect(childEntry.enrichedView.parentModelDescriptorDigest).toBe(parentDigest);

    // Re-parent the shipped view to "no parent": the bundle now claims a
    // fine-tuned model is a base model. Every digest still re-hashes and no
    // dangling reference is introduced, so nothing but the uncovered
    // pointer has moved.
    childEntry.enrichedView.parentModelDescriptorDigest = null;

    const verify = await verifyExported(bundle);
    expect(verify.ok).toBe(false);
    if (verify.ok) throw new Error('unreachable');
    expect(
      verify.errors.some(
        (e) => e.includes(childDigest) && /enrichedView\.parentModelDescriptorDigest/.test(e),
      ),
    ).toBe(true);
  });

  it('verifyExported rejects a prefixed envelope digest rather than normalizing it away', async () => {
    const { evidenceId } = await setupParentChildAndCapture(tzun);
    const bundle = await tzun.exportEvidence(evidenceId);
    expect(await verifyExported(bundle)).toEqual({ ok: true });

    // The envelope digest is bare hex on the wire (computeDigest ->
    // digest('hex')); a `sha256:`-prefixed one is a spelling the SDK never
    // emits. Normalizing it away would accept a bundle the SDK cannot have
    // produced, so it is refused.
    bundle.envelope.integrity.canonicalDigest =
      'sha256:' + bundle.envelope.integrity.canonicalDigest;

    const verify = await verifyExported(bundle);
    expect(verify.ok).toBe(false);
    if (verify.ok) throw new Error('unreachable');
    expect(verify.errors.some((e) => /integrity digest .* is not in the required/.test(e))).toBe(
      true,
    );
  });

  it('verifyExported rejects a bare-hex descriptor key rather than normalizing it away', async () => {
    const { childDigest, evidenceId } = await setupParentChildAndCapture(tzun);
    const bundle = await tzun.exportEvidence(evidenceId);

    const entry = bundle.resolvedModelDescriptors[childDigest];
    delete bundle.resolvedModelDescriptors[childDigest];
    bundle.resolvedModelDescriptors[childDigest.replace(/^sha256:/, '')] = entry;

    const verify = await verifyExported(bundle);
    expect(verify.ok).toBe(false);
    if (verify.ok) throw new Error('unreachable');
    expect(verify.errors.some((e) => /key is not in the required/.test(e))).toBe(true);
  });
});

const bundleBackends = [sqliteBundleBackend(), postgresBundleBackend('export_offline_b1')].filter(
  (b): b is BundleBackend => b !== undefined,
);

describe.each(bundleBackends.map((b) => [b.name, b] as const))(
  'Verification §3.1: a b1 bundle exported from %s verifies with no store',
  (_name, backend) => {
    jest.setTimeout(120_000);
    afterAll(() => backend.dispose());

    it('verifies a bundled, anchored record end to end in a fresh instance with an empty store', async () => {
      const store = await anchoredStore(await backend.fresh());
      let file: string;
      let manifest: Awaited<ReturnType<typeof store.manifest>>;
      try {
        const [evidenceId] = await store.capture(1);
        await store.epoch();
        await store.capture(1);
        await store.epoch();
        // The file an auditor is handed.
        file = JSON.stringify(await store.tzun.exportBundle(evidenceId));
        manifest = await store.manifest();
      } finally {
        await store.close();
      }

      // The auditor: a fresh instance whose memory store holds nothing, no
      // credential store, the bundle, the manifest and their own view of the chain.
      const fresh = await Tzun.init();
      try {
        expect(fresh.getStorage() instanceof MemoryStorageAdapter).toBe(true);
        const report = await verifyBundle(JSON.parse(file), {
          publisherManifest: manifest,
          evmHeaderSources: { [BUNDLE_CHAIN]: fakeHeaderSource(store.chain) },
        });
        expect(report.checks.filter((c) => c.outcome === 'checked-wrong')).toEqual([]);
        for (const id of ['bundle', 'subject', 'record.digest', 'record.chainLink', 'anchor', 'anchor.inclusion', 'anchor.anchorInclusion', 'anchor.evm.tx[0]', 'anchor.evm.canonical[0]']) {
          expect(report.checks.find((c) => c.id === id)).toMatchObject({ outcome: 'checked-correct' });
        }
        expect(report.summary).toMatchObject({ anchorOriginAuthenticated: true, anchorNamespace: 'test', existedBy: { source: 'evm-calldata' } });
        expect(bundleExitCode(report)).toBe(0);
        // Nothing was read from, or written to, the verifier's store.
        expect(await fresh.list()).toEqual([]);
      } finally {
        await fresh.close();
      }
    });
  },
);
