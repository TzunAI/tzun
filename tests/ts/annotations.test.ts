/**
 * Annotation runtime tests, plus alias pass-throughs.
 *
 * The annotateModelDescriptor() entry point is in src/models/annotations.ts.
 * It is also exposed on the SDK as tzun.models.annotate (the SDK is exercised
 * here for the public-surface assertions; the bulk of the cases drive the
 * standalone function with a MemoryStorageAdapter).
 */

import { MemoryStorageAdapter } from '../../src/storage/memory';
import {
  annotateModelDescriptor,
  ModelAnnotateInput,
  ModelAnnotateOptions,
} from '../../src/models/annotations';
import { runCli, CliDependencies } from '../../src/models/cli';
import { Tzun } from '../../src/sdk/index';
import { ModelDescriptor, ModelDescriptorAnnotationRow } from '@tzun/engine';

// ── helpers ────────────────────────────────────────────────────────

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
  training: {
    trainingDataDigest: null,
    trainingDataRef: null,
    lastTrainingDate: null,
    evaluations: [],
  },
  regulatoryMarkings: [],
  externalIdentifiers: [],
  ...overrides,
});

async function makeStoreWithDescriptor(): Promise<{
  storage: MemoryStorageAdapter;
  digest: string;
}> {
  const storage = new MemoryStorageAdapter();
  const { digest } = await storage.registerModelDescriptor!(
    mkDescriptor(),
    'manual',
    'tester',
  );
  return { storage, digest };
}

const ADMIN: ModelAnnotateOptions = { isAdmin: true, annotatedBy: 'admin' };

// ── tests ──────────────────────────────────────────────────────────

describe('annotations runtime', () => {
  // ── Auth ──────────────────────────────────────

  it('typed annotation requires isAdmin: true', async () => {
    const { storage, digest } = await makeStoreWithDescriptor();
    const input: ModelAnnotateInput = {
      annotationType: 'set-license',
      value: { license: 'mit' },
    };
    await expect(
      annotateModelDescriptor(storage, digest, input, { annotatedBy: 'user' }),
    ).rejects.toThrow(/admin/i);
  });

  it('all seven typed annotation types require admin', async () => {
    const { storage, digest } = await makeStoreWithDescriptor();
    const typed: ModelAnnotateInput[] = [
      { annotationType: 'add-regulatory-marking',  value: {} },
      { annotationType: 'add-evaluation',          value: {} },
      { annotationType: 'set-model-card-url',      value: { url: 'x' } },
      { annotationType: 'set-license',             value: { license: 'mit' } },
      { annotationType: 'add-training-disclosure', value: {} },
      { annotationType: 'add-external-identifier', value: {} },
      { annotationType: 'retract',                 value: { retractsAnnotationId: 'a1' } },
    ];
    for (const input of typed) {
      await expect(
        annotateModelDescriptor(storage, digest, input, { annotatedBy: 'user' }),
      ).rejects.toThrow(/admin/i);
    }
  });

  it('freeform-note is allowed without admin', async () => {
    const { storage, digest } = await makeStoreWithDescriptor();
    const row = await annotateModelDescriptor(
      storage,
      digest,
      { annotationType: 'freeform-note', value: { text: 'hello' } },
      { annotatedBy: 'anyuser' },
    );
    expect(row.annotationType).toBe('freeform-note');
    expect(row.annotatedBy).toBe('anyuser');
  });

  it('custom annotation type still requires admin', async () => {
    const { storage, digest } = await makeStoreWithDescriptor();
    await expect(
      annotateModelDescriptor(
        storage,
        digest,
        { annotationType: 'vendor-custom-type', value: { foo: 'bar' } },
        { annotatedBy: 'user' },
      ),
    ).rejects.toThrow(/admin/i);

    // Same call succeeds with admin.
    const row = await annotateModelDescriptor(
      storage,
      digest,
      { annotationType: 'vendor-custom-type', value: { foo: 'bar' } },
      ADMIN,
    );
    expect(row.annotationType).toBe('vendor-custom-type');
  });

  // ── Enriched-view interaction ─────────────────

  it('add-* to a list field appends; latest is at end', async () => {
    const { storage, digest } = await makeStoreWithDescriptor();
    await annotateModelDescriptor(
      storage,
      digest,
      {
        annotationType: 'add-regulatory-marking',
        value: {
          authority: 'eu',
          identifier: 'A1',
          status: 'active',
          effectiveDate: null,
          expiresAt: null,
          scope: null,
          evidenceUrl: null,
        },
      },
      { ...ADMIN, annotatedBy: 'admin', annotatedAt: '2026-05-01T00:00:00.000Z' },
    );
    await annotateModelDescriptor(
      storage,
      digest,
      {
        annotationType: 'add-regulatory-marking',
        value: {
          authority: 'us',
          identifier: 'B2',
          status: 'pending',
          effectiveDate: null,
          expiresAt: null,
          scope: null,
          evidenceUrl: null,
        },
      },
      { ...ADMIN, annotatedBy: 'admin', annotatedAt: '2026-05-02T00:00:00.000Z' },
    );

    const enriched = await storage.getEnrichedModelDescriptor!(digest);
    expect(enriched!.regulatoryMarkings.length).toBe(2);
    // Latest at end.
    expect(enriched!.regulatoryMarkings[1].authority).toBe('us');
  });

  it('set-* uses latest-wins on the scalar', async () => {
    const { storage, digest } = await makeStoreWithDescriptor();
    // Pin annotatedAt explicitly so replay order is deterministic even if
    // both calls land in the same millisecond.
    await annotateModelDescriptor(
      storage,
      digest,
      { annotationType: 'set-license', value: { license: 'mit' } },
      { ...ADMIN, annotatedBy: 'admin', annotatedAt: '2026-05-01T00:00:00.000Z' },
    );
    await annotateModelDescriptor(
      storage,
      digest,
      { annotationType: 'set-license', value: { license: 'apache-2.0' } },
      { ...ADMIN, annotatedBy: 'admin', annotatedAt: '2026-05-02T00:00:00.000Z' },
    );

    const enriched = await storage.getEnrichedModelDescriptor!(digest);
    expect(enriched!.license).toBe('apache-2.0');
  });

  it('retract voids the targeted annotation but log remains complete', async () => {
    const { storage, digest } = await makeStoreWithDescriptor();
    const first = await annotateModelDescriptor(
      storage,
      digest,
      { annotationType: 'set-license', value: { license: 'mit' } },
      { ...ADMIN, annotatedAt: '2026-05-01T00:00:00.000Z' },
    );
    await annotateModelDescriptor(
      storage,
      digest,
      { annotationType: 'retract', value: { retractsAnnotationId: first.annotationId } },
      { ...ADMIN, annotatedAt: '2026-05-02T00:00:00.000Z' },
    );

    const enriched = await storage.getEnrichedModelDescriptor!(digest);
    expect(enriched!.license).toBeNull();

    const log = await storage.listModelDescriptorAnnotations!(digest);
    expect(log.length).toBe(2);
    expect(log[0].annotationType).toBe('set-license');
    expect(log[1].annotationType).toBe('retract');
  });

  it('annotations apply in annotatedAt ascending order regardless of insertion order', async () => {
    const { storage, digest } = await makeStoreWithDescriptor();
    // Insert in reverse-time order: second call's annotatedAt comes BEFORE
    // the first call's. The enriched view must still apply them in
    // annotatedAt ASC.
    await annotateModelDescriptor(
      storage,
      digest,
      { annotationType: 'set-license', value: { license: 'apache-2.0' } },
      { ...ADMIN, annotatedAt: '2026-05-15T12:00:00Z' },
    );
    await annotateModelDescriptor(
      storage,
      digest,
      { annotationType: 'set-license', value: { license: 'mit' } },
      { ...ADMIN, annotatedAt: '2026-05-01T00:00:00Z' },
    );

    const enriched = await storage.getEnrichedModelDescriptor!(digest);
    // annotatedAt-ASC means MIT was first, Apache-2.0 wins.
    expect(enriched!.license).toBe('apache-2.0');
  });

  // ── Storage contract ──────────────────────────

  it('annotation is appended via storage.appendModelDescriptorAnnotation', async () => {
    const { storage, digest } = await makeStoreWithDescriptor();
    const spy = jest.spyOn(storage, 'appendModelDescriptorAnnotation');
    await annotateModelDescriptor(
      storage,
      digest,
      { annotationType: 'freeform-note', value: { text: 'hi' } },
      { annotatedBy: 'user' },
    );
    expect(spy).toHaveBeenCalledTimes(1);
    const arg = spy.mock.calls[0][0] as ModelDescriptorAnnotationRow;
    expect(arg.modelDescriptorDigest).toBe(digest);
    expect(arg.annotationType).toBe('freeform-note');
  });

  it('signature is stored verbatim (stored not verified in v1)', async () => {
    const { storage, digest } = await makeStoreWithDescriptor();
    const sig = 'ed25519:aabbccddeeff';
    const row = await annotateModelDescriptor(
      storage,
      digest,
      { annotationType: 'set-license', value: { license: 'mit' } },
      { ...ADMIN, signature: sig },
    );
    expect(row.signature).toBe(sig);

    // And the persisted row carries it too.
    const log = await storage.listModelDescriptorAnnotations!(digest);
    expect(log[0].signature).toBe(sig);
  });

  it('annotations do not change modelDescriptorDigest', async () => {
    const { storage, digest } = await makeStoreWithDescriptor();
    await annotateModelDescriptor(
      storage,
      digest,
      { annotationType: 'set-license', value: { license: 'mit' } },
      ADMIN,
    );
    // The catalog key did not change: the same digest still resolves.
    const row = await storage.getModelDescriptor!(digest);
    expect(row).not.toBeNull();
    expect(row!.modelDescriptorDigest).toBe(digest);
  });

  it('annotationId is generated when not provided (UUID shape)', async () => {
    const { storage, digest } = await makeStoreWithDescriptor();
    const row = await annotateModelDescriptor(
      storage,
      digest,
      { annotationType: 'freeform-note', value: {} },
      { annotatedBy: 'user' },
    );
    // RFC4122-ish: 8-4-4-4-12 hex.
    expect(row.annotationId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
  });

  it('note is stored on the row regardless of annotation type', async () => {
    const { storage, digest } = await makeStoreWithDescriptor();
    const row = await annotateModelDescriptor(
      storage,
      digest,
      { annotationType: 'set-license', value: { license: 'mit' } },
      { ...ADMIN, note: 'license verified against the model card' },
    );
    expect(row.note).toBe('license verified against the model card');
  });

  // ── Aliases ────────────────────────────────────────────

  it('setAlias appends a new row each time; resolveAlias returns most recent', async () => {
    const storage = new MemoryStorageAdapter();
    const a = await storage.registerModelDescriptor!(
      mkDescriptor({ modelVersion: '1' }),
      'manual',
      't',
    );
    const b = await storage.registerModelDescriptor!(
      mkDescriptor({ modelVersion: '2' }),
      'manual',
      't',
    );
    await storage.setModelDescriptorAlias!('current', a.digest, 'admin');
    await new Promise((r) => setTimeout(r, 5));
    await storage.setModelDescriptorAlias!('current', b.digest, 'admin');

    expect(await storage.resolveModelDescriptorAlias!('current')).toBe(b.digest);
  });

  it('resolveAlias returns null for unknown slug', async () => {
    const storage = new MemoryStorageAdapter();
    expect(await storage.resolveModelDescriptorAlias!('nope')).toBeNull();
  });
});

// ── ModelsApi (sdk) surface ────────────────────────────────────────

describe('tzun.models.annotate / setAlias / resolveAlias — ModelsApi surface', () => {
  it('exposes annotate as a typed callable on tzun.models', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    const { digest } = await tzun.models.register({
      vendor: 'anthropic',
      modelName: 'claude-opus-4-7',
      modelVersion: '2026-01',
    });

    const row = await tzun.models.annotate(
      digest,
      { annotationType: 'set-license', value: { license: 'mit' } },
      { isAdmin: true, annotatedBy: 'admin' },
    );
    expect(row.annotationType).toBe('set-license');

    const enriched = await tzun.models.getEnriched(digest);
    expect(enriched!.license).toBe('mit');

    await tzun.close();
  });

  it('exposes setAlias and resolveAlias on tzun.models', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    const { digest } = await tzun.models.register({
      vendor: 'anthropic',
      modelName: 'claude-opus-4-7',
      modelVersion: '2026-01',
    });

    await tzun.models.setAlias('latest', digest, 'admin');
    expect(await tzun.models.resolveAlias('latest')).toBe(digest);
    expect(await tzun.models.resolveAlias('does-not-exist')).toBeNull();
    await tzun.close();
  });
});

// ── CLI surface ────────────────────────────────────────────────────

function makeDeps(): { storage: MemoryStorageAdapter; lines: string[]; deps: CliDependencies } {
  const storage = new MemoryStorageAdapter();
  const lines: string[] = [];
  const deps: CliDependencies = {
    storage,
    prompt: async () => '',
    stdout: (m: string) => lines.push(m),
  };
  return { storage, lines, deps };
}

describe('runCli(annotate / alias)', () => {
  async function registerOne(deps: CliDependencies): Promise<string> {
    await runCli(
      [
        'register', '--quick',
        '--vendor', 'anthropic',
        '--model', 'claude-opus-4-7',
        '--version', '2026-01',
      ],
      deps,
    );
    const rows = await deps.storage.listModelDescriptors!({});
    return rows[0].modelDescriptorDigest;
  }

  it('typed annotation requires --admin', async () => {
    const { deps, lines } = makeDeps();
    const digest = await registerOne(deps);
    const code = await runCli(
      [
        'annotate', digest,
        '--type', 'set-license',
        '--value', JSON.stringify({ license: 'mit' }),
      ],
      deps,
    );
    expect(code).toBe(2);
    expect(lines.join('\n')).toMatch(/admin/i);
  });

  it('typed annotation with --admin succeeds', async () => {
    const { deps, storage, lines } = makeDeps();
    const digest = await registerOne(deps);
    lines.length = 0;
    const code = await runCli(
      [
        'annotate', digest,
        '--type', 'set-license',
        '--value', JSON.stringify({ license: 'apache-2.0' }),
        '--admin',
        '--reviewer', 'jane@acme',
      ],
      deps,
    );
    expect(code).toBe(0);
    const log = await storage.listModelDescriptorAnnotations!(digest);
    expect(log.length).toBe(1);
    expect(log[0].annotatedBy).toBe('jane@acme');
  });

  it('freeform-note without --admin succeeds', async () => {
    const { deps, storage } = makeDeps();
    const digest = await registerOne(deps);
    const code = await runCli(
      [
        'annotate', digest,
        '--type', 'freeform-note',
        '--value', JSON.stringify({ text: 'hi' }),
        '--reviewer', 'someone',
      ],
      deps,
    );
    expect(code).toBe(0);
    const log = await storage.listModelDescriptorAnnotations!(digest);
    expect(log.length).toBe(1);
    expect(log[0].annotationType).toBe('freeform-note');
  });

  it('--signature is stored on the row', async () => {
    const { deps, storage } = makeDeps();
    const digest = await registerOne(deps);
    const sig = 'ed25519:deadbeef';
    const code = await runCli(
      [
        'annotate', digest,
        '--type', 'set-license',
        '--value', JSON.stringify({ license: 'mit' }),
        '--admin',
        '--signature', sig,
      ],
      deps,
    );
    expect(code).toBe(0);
    const log = await storage.listModelDescriptorAnnotations!(digest);
    expect(log[0].signature).toBe(sig);
  });

  it('alias set + resolve subcommands', async () => {
    const { deps, lines } = makeDeps();
    const digest = await registerOne(deps);

    const setCode = await runCli(
      ['alias', 'set', 'latest', digest, '--set-by', 'admin'],
      deps,
    );
    expect(setCode).toBe(0);

    lines.length = 0;
    const resolveCode = await runCli(['alias', 'resolve', 'latest'], deps);
    expect(resolveCode).toBe(0);
    expect(lines.join('\n')).toContain(digest);
  });

  it('alias resolve for unknown slug prints "(unbound)" and exits 0', async () => {
    const { deps, lines } = makeDeps();
    const code = await runCli(['alias', 'resolve', 'mystery'], deps);
    expect(code).toBe(0);
    expect(lines.join('\n')).toMatch(/unbound|no binding|null/i);
  });

  it('annotate with bad JSON in --value errors out (usage)', async () => {
    const { deps } = makeDeps();
    const digest = await registerOne(deps);
    const code = await runCli(
      [
        'annotate', digest,
        '--type', 'set-license',
        '--value', '{not-json',
        '--admin',
      ],
      deps,
    );
    expect(code).toBe(1);
  });
});
