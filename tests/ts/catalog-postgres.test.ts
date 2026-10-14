/**
 * Live-DB parity tests for the Postgres catalog.
 *
 * Mirrors the 14 parity tests from `tests/catalog-memory.test.ts` plus one
 * extra durability test that proves the catalog survives a fresh
 * PostgresStorageAdapter pointing at the same DB.
 *
 * Runs when the Postgres legs do (tests/ts/helpers/postgres-test-db.ts), in a
 * schema of this file's own.
 */
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { ModelDescriptor, ModelDescriptorAnnotationRow } from '@tzun/engine';

const mkDescriptor = (overrides: Partial<ModelDescriptor> = {}): ModelDescriptor => ({
  descriptorVersion: 'd1',
  vendor: 'anthropic',
  modelName: 'claude-opus-4-7',
  modelVersion: '2026-01-15',
  modelType: null,
  integrityTier: 'vendor-asserted',
  modelDigest: null,
  parentModelDescriptorDigest: null,
  derivation: null,
  trainedBy: null,
  license: null,
  modelCardUrl: null,
  training: { trainingDataDigest: null, trainingDataRef: null, lastTrainingDate: null, evaluations: [] },
  regulatoryMarkings: [],
  externalIdentifiers: [],
  ...overrides,
});

const mkAnnotation = (
  digest: string,
  overrides: Partial<ModelDescriptorAnnotationRow> = {},
): ModelDescriptorAnnotationRow => ({
  annotationId: overrides.annotationId ?? `ann-${Math.random().toString(36).slice(2)}`,
  modelDescriptorDigest: digest,
  annotatedAt: '2026-05-01T00:00:00Z',
  annotatedBy: 'admin',
  annotationType: 'freeform-note',
  valueJson: '{}',
  retractsAnnotationId: null,
  signature: null,
  note: null,
  ...overrides,
});

const pgSchema = pgSuiteSchema('catalog');
const d = PG_TESTS_ENABLED ? describe : describe.skip;

d('Postgres catalog (live DB) — parity', () => {
  let store: PostgresStorageAdapter;

  beforeAll(async () => {
    store = new PostgresStorageAdapter(pgSchema.url);
    await store.ensureTables();
  }, 30000);

  beforeEach(async () => {
    // TRUNCATE the catalog tables (FK from annotations → descriptors requires
    // CASCADE or correct ordering; use CASCADE for safety).
    await store.truncateCatalogForTests();
  });

  afterAll(async () => {
    if (store) await store.close();
  }, 30000);

  it('registers a descriptor and assigns a digest', async () => {
    const r = await store.registerModelDescriptor(mkDescriptor(), 'manual', 'tester');
    expect(r.digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(r.alreadyExisted).toBe(false);
  });

  it('register is idempotent on identical descriptor bytes', async () => {
    const r1 = await store.registerModelDescriptor(mkDescriptor(), 'manual', 'tester');
    const r2 = await store.registerModelDescriptor(mkDescriptor(), 'connector-auto', 'wrapper');
    expect(r2.digest).toBe(r1.digest);
    expect(r2.alreadyExisted).toBe(true);
  });

  it('different descriptors produce different digests', async () => {
    const a = await store.registerModelDescriptor(mkDescriptor({ modelVersion: '1' }), 'manual', 't');
    const b = await store.registerModelDescriptor(mkDescriptor({ modelVersion: '2' }), 'manual', 't');
    expect(a.digest).not.toBe(b.digest);
  });

  it('canonical view returns exact canonical bytes that were hashed', async () => {
    const { digest } = await store.registerModelDescriptor(mkDescriptor(), 'manual', 't');
    const row = await store.getModelDescriptor(digest);
    expect(row).not.toBeNull();
    expect(row!.canonicalBytes.length).toBeGreaterThan(0);
    const { createHash } = await import('crypto');
    const recomputed = 'sha256:' + createHash('sha256').update(row!.canonicalBytes).digest('hex');
    expect(recomputed).toBe(digest);
  });

  it('listModelDescriptors filters by vendor', async () => {
    await store.registerModelDescriptor(mkDescriptor({ vendor: 'anthropic' }), 'manual', 't');
    await store.registerModelDescriptor(
      mkDescriptor({ vendor: 'openai', modelName: 'gpt-4o', modelVersion: '2024' }),
      'manual',
      't',
    );
    const onlyAnthropic = await store.listModelDescriptors({ vendor: 'anthropic' });
    expect(onlyAnthropic.length).toBe(1);
    expect(onlyAnthropic[0].vendor).toBe('anthropic');
  });

  it('listModelDescriptors filters by hasRegulatoryMarking', async () => {
    await store.registerModelDescriptor(mkDescriptor({ modelVersion: 'plain' }), 'manual', 't');
    await store.registerModelDescriptor(
      mkDescriptor({
        modelVersion: 'reg',
        regulatoryMarkings: [
          { authority: 'eu', identifier: 'X1', status: 'active', effectiveDate: null, expiresAt: null, scope: null, evidenceUrl: null },
        ],
      }),
      'manual',
      't',
    );
    const withReg = await store.listModelDescriptors({ hasRegulatoryMarking: true });
    expect(withReg.length).toBe(1);
    expect(withReg[0].modelVersion).toBe('reg');
  });

  it('listDescendantDescriptors returns children', async () => {
    const parent = await store.registerModelDescriptor(
      mkDescriptor({ modelName: 'base', modelVersion: '1' }),
      'manual',
      't',
    );
    await store.registerModelDescriptor(
      mkDescriptor({
        modelName: 'fine-tune',
        modelVersion: '1',
        parentModelDescriptorDigest: parent.digest,
      }),
      'manual',
      't',
    );
    const descendants = await store.listDescendantDescriptors(parent.digest);
    expect(descendants.length).toBe(1);
    expect(descendants[0].descriptor.modelName).toBe('fine-tune');
  });

  it('annotations append-only; enriched view applies them', async () => {
    const { digest } = await store.registerModelDescriptor(mkDescriptor(), 'manual', 't');
    await store.appendModelDescriptorAnnotation(
      mkAnnotation(digest, {
        annotationId: 'a1',
        annotationType: 'set-license',
        valueJson: JSON.stringify({ license: 'apache-2.0' }),
      }),
    );
    const enriched = await store.getEnrichedModelDescriptor(digest);
    expect(enriched).not.toBeNull();
    expect(enriched!.license).toBe('apache-2.0');
  });

  it('retraction voids prior annotation but preserves log', async () => {
    const { digest } = await store.registerModelDescriptor(mkDescriptor(), 'manual', 't');
    await store.appendModelDescriptorAnnotation(
      mkAnnotation(digest, {
        annotationId: 'a1',
        annotatedAt: '2026-05-01T00:00:00Z',
        annotationType: 'set-license',
        valueJson: JSON.stringify({ license: 'mit' }),
      }),
    );
    await store.appendModelDescriptorAnnotation(
      mkAnnotation(digest, {
        annotationId: 'a2',
        annotatedAt: '2026-05-02T00:00:00Z',
        annotationType: 'retract',
        valueJson: '{}',
        retractsAnnotationId: 'a1',
      }),
    );
    const enriched = await store.getEnrichedModelDescriptor(digest);
    expect(enriched!.license).toBeNull();

    const log = await store.listModelDescriptorAnnotations(digest);
    expect(log.length).toBe(2);
    expect(log.map((a) => a.annotationId)).toEqual(['a1', 'a2']);
  });

  it('unknown annotation types are preserved but ignored by the view', async () => {
    const { digest } = await store.registerModelDescriptor(mkDescriptor(), 'manual', 't');
    await store.appendModelDescriptorAnnotation(
      mkAnnotation(digest, {
        annotationId: 'a1',
        annotationType: 'custom-vendor-extension',
        valueJson: JSON.stringify({ foo: 'bar' }),
      }),
    );
    const enriched = await store.getEnrichedModelDescriptor(digest);
    const canonicalRow = await store.getModelDescriptor(digest);
    expect(enriched).toEqual(canonicalRow!.descriptor);
    const log = await store.listModelDescriptorAnnotations(digest);
    expect(log.length).toBe(1);
  });

  it('alias resolves to most-recent setAt', async () => {
    const a = await store.registerModelDescriptor(mkDescriptor({ modelVersion: '1' }), 'manual', 't');
    const b = await store.registerModelDescriptor(mkDescriptor({ modelVersion: '2' }), 'manual', 't');
    await store.setModelDescriptorAlias('current', a.digest, 'admin');
    await new Promise((r) => setTimeout(r, 5));
    await store.setModelDescriptorAlias('current', b.digest, 'admin');
    expect(await store.resolveModelDescriptorAlias('current')).toBe(b.digest);
  });

  it('alias resolves to null when no binding exists', async () => {
    expect(await store.resolveModelDescriptorAlias('nope')).toBeNull();
  });

  it('getEnrichedModelDescriptor returns null for unknown digest', async () => {
    expect(await store.getEnrichedModelDescriptor('sha256:nonexistent')).toBeNull();
  });

  it('register does not mutate the caller descriptor', async () => {
    const input = mkDescriptor({
      regulatoryMarkings: [
        { authority: 'b', identifier: 'b1', status: 'active', effectiveDate: null, expiresAt: null, scope: null, evidenceUrl: null },
        { authority: 'a', identifier: 'a1', status: 'active', effectiveDate: null, expiresAt: null, scope: null, evidenceUrl: null },
      ],
    });
    await store.registerModelDescriptor(input, 'manual', 't');
    expect(input.regulatoryMarkings.map((m) => m.authority)).toEqual(['b', 'a']);
  });

  it('descriptor + annotation + alias persist across a fresh PostgresStorageAdapter on the same DB', async () => {
    const { digest } = await store.registerModelDescriptor(
      mkDescriptor({ vendor: 'persisted-vendor', modelVersion: 'p1' }),
      'manual',
      'tester',
    );
    await store.appendModelDescriptorAnnotation(
      mkAnnotation(digest, {
        annotationId: 'persist-1',
        annotationType: 'set-license',
        valueJson: JSON.stringify({ license: 'bsd-3-clause' }),
      }),
    );
    await store.setModelDescriptorAlias('persist-slug', digest, 'admin');

    // Connect a NEW adapter to the same DB and verify reads.
    const fresh = new PostgresStorageAdapter(pgSchema.url);
    try {
      await fresh.ensureTables();

      const row = await fresh.getModelDescriptor(digest);
      expect(row).not.toBeNull();
      expect(row!.vendor).toBe('persisted-vendor');

      const annotations = await fresh.listModelDescriptorAnnotations(digest);
      expect(annotations.length).toBe(1);
      expect(annotations[0].annotationId).toBe('persist-1');

      const resolved = await fresh.resolveModelDescriptorAlias('persist-slug');
      expect(resolved).toBe(digest);

      const enriched = await fresh.getEnrichedModelDescriptor(digest);
      expect(enriched!.license).toBe('bsd-3-clause');
    } finally {
      await fresh.close();
    }
  });
});
