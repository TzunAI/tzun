/**
 * `tzun models` CLI + programmatic `tzun.models.*` API tests.
 *
 * The CLI is driven through its exported `runCli(argv, deps)` entry point with
 * a `MemoryStorageAdapter` so the tests don't need to spawn a subprocess.
 */

import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import * as path from 'path';

import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { runCli, CliDependencies } from '../../src/models/cli';
import { registerModel } from '../../src/models/register';
import { computeModelDigest } from '../../src/models/compute-model-digest';
import { importFromVendor } from '../../src/models/import-vendor';
import { loadKnownModels } from '../../src/models/known-models';
import { Tzun } from '../../src/sdk/index';
import { ModelDescriptor } from '@tzun/engine';

const WEIGHTS_FIXTURE = path.resolve(__dirname, 'fixtures/model-weights');

function makeDeps(opts: { prompt?: CliDependencies['prompt'] } = {}): {
  storage: MemoryStorageAdapter;
  lines: string[];
  deps: CliDependencies;
} {
  const storage = new MemoryStorageAdapter();
  const lines: string[] = [];
  const deps: CliDependencies = {
    storage,
    prompt: opts.prompt ?? (async () => ''),
    stdout: (m: string) => lines.push(m),
  };
  return { storage, lines, deps };
}

describe('runCli(register)', () => {
  it('1. --quick registers an MVD; second invocation reports alreadyExisted', async () => {
    const { storage, lines, deps } = makeDeps();
    const argv = [
      'register', '--quick',
      '--vendor', 'anthropic',
      '--model', 'claude-opus-4-7',
      '--version', '2026-01',
    ];

    const code1 = await runCli(argv, deps);
    expect(code1).toBe(0);
    const firstOut = lines.join('\n');
    expect(firstOut).toMatch(/sha256:[a-f0-9]{64}/);
    expect(firstOut).toMatch(/alreadyExisted:\s*false/i);

    lines.length = 0;
    const code2 = await runCli(argv, deps);
    expect(code2).toBe(0);
    const secondOut = lines.join('\n');
    expect(secondOut).toMatch(/alreadyExisted:\s*true/i);

    const rows = await storage.listModelDescriptors!({});
    expect(rows.length).toBe(1);
    expect(rows[0].vendor).toBe('anthropic');
    expect(rows[0].modelName).toBe('claude-opus-4-7');
    expect(rows[0].modelVersion).toBe('2026-01');
    expect(rows[0].descriptor.integrityTier).toBe('vendor-asserted');
    expect(rows[0].descriptor.modelDigest).toBeNull();
    expect(rows[0].descriptor.modelType).toBeNull();
    expect(rows[0].descriptor.regulatoryMarkings).toEqual([]);
    expect(rows[0].descriptor.externalIdentifiers).toEqual([]);
    expect(rows[0].descriptor.training.evaluations).toEqual([]);
  });

  it('2. --quick --weights computes modelDigest and sets weight-attested', async () => {
    const { storage, lines, deps } = makeDeps();
    const code = await runCli(
      [
        'register', '--quick',
        '--vendor', 'meta',
        '--model', 'llama-3.1-8b',
        '--version', '2024-07',
        '--weights', WEIGHTS_FIXTURE,
      ],
      deps,
    );
    expect(code).toBe(0);
    const out = lines.join('\n');
    expect(out).toMatch(/weight-attested/);
    expect(out).toMatch(/sha256:[a-f0-9]{64}/);

    const rows = await storage.listModelDescriptors!({});
    expect(rows.length).toBe(1);
    expect(rows[0].descriptor.integrityTier).toBe('weight-attested');
    expect(rows[0].descriptor.modelDigest).toMatch(/^sha256:[a-f0-9]{64}$/);

    const { modelDigest } = await computeModelDigest(WEIGHTS_FIXTURE);
    expect(rows[0].descriptor.modelDigest).toBe(modelDigest);
  });

  it('3. --from-file <json> reads a JSON descriptor and registers it', async () => {
    const tmp = mkdtempSync(path.join(tmpdir(), 'tzun-test-cli-'));
    const filePath = path.join(tmp, 'descriptor.json');
    try {
      const inputDescriptor: Partial<ModelDescriptor> = {
        vendor: 'openai',
        modelName: 'gpt-4o',
        modelVersion: '2024-08-06',
        modelType: 'chat',
        license: 'proprietary',
      };
      writeFileSync(filePath, JSON.stringify(inputDescriptor));

      const { storage, lines, deps } = makeDeps();
      const code = await runCli(['register', '--from-file', filePath], deps);
      expect(code).toBe(0);
      expect(lines.join('\n')).toMatch(/sha256:/);

      const rows = await storage.listModelDescriptors!({});
      expect(rows.length).toBe(1);
      expect(rows[0].vendor).toBe('openai');
      expect(rows[0].modelName).toBe('gpt-4o');
      expect(rows[0].modelVersion).toBe('2024-08-06');
      expect(rows[0].descriptor.modelType).toBe('chat');
      expect(rows[0].descriptor.license).toBe('proprietary');
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('4. full interactive uses prompt() for each field', async () => {
    const answers = [
      'anthropic',                       // vendor
      'claude-sonnet-4-5',               // modelName
      '2026-02',                         // modelVersion
      'chat',                            // modelType
      'Anthropic',                       // trainedBy
      'proprietary',                     // license
      'https://example.com/card',        // modelCardUrl
    ];
    let i = 0;
    const prompt = async () => answers[i++] ?? '';
    const { storage, deps } = makeDeps({ prompt });

    const code = await runCli(['register'], deps);
    expect(code).toBe(0);

    const rows = await storage.listModelDescriptors!({});
    expect(rows.length).toBe(1);
    const d = rows[0].descriptor;
    expect(d.vendor).toBe('anthropic');
    expect(d.modelName).toBe('claude-sonnet-4-5');
    expect(d.modelVersion).toBe('2026-02');
    expect(d.modelType).toBe('chat');
    expect(d.trainedBy).toBe('Anthropic');
    expect(d.license).toBe('proprietary');
    expect(d.modelCardUrl).toBe('https://example.com/card');
    expect(d.integrityTier).toBe('vendor-asserted');
    expect(d.modelDigest).toBeNull();
  });

  it('5. list prints registered descriptors and respects --vendor filter', async () => {
    const { storage, lines, deps } = makeDeps();
    await registerModel(storage, { vendor: 'anthropic', modelName: 'claude', modelVersion: '1' });
    await registerModel(storage, { vendor: 'openai', modelName: 'gpt-4o', modelVersion: '2024' });

    lines.length = 0;
    const code = await runCli(['list'], deps);
    expect(code).toBe(0);
    const all = lines.join('\n');
    expect(all).toMatch(/anthropic/);
    expect(all).toMatch(/openai/);

    lines.length = 0;
    const code2 = await runCli(['list', '--vendor', 'anthropic'], deps);
    expect(code2).toBe(0);
    const filtered = lines.join('\n');
    expect(filtered).toMatch(/anthropic/);
    expect(filtered).not.toMatch(/openai/);
  });

  it('6. show <digest> prints the descriptor', async () => {
    const { storage, lines, deps } = makeDeps();
    const { digest } = await registerModel(storage, {
      vendor: 'anthropic', modelName: 'claude', modelVersion: '1',
    });

    lines.length = 0;
    const code = await runCli(['show', digest], deps);
    expect(code).toBe(0);
    const out = lines.join('\n');
    expect(out).toMatch(/anthropic/);
    expect(out).toMatch(/claude/);
    expect(out).toContain(digest);
  });

  it('7. compute-digest prints a sha256 digest', async () => {
    const { lines, deps } = makeDeps();
    const code = await runCli(['compute-digest', WEIGHTS_FIXTURE], deps);
    expect(code).toBe(0);
    const out = lines.join('\n');
    expect(out).toMatch(/sha256:[a-f0-9]{64}/);

    const { modelDigest } = await computeModelDigest(WEIGHTS_FIXTURE);
    expect(out).toContain(modelDigest);
  });

  it('8. --quick missing required field exits 1 with a usage error', async () => {
    const { storage, lines, deps } = makeDeps();
    const code = await runCli(
      ['register', '--quick', '--vendor', 'anthropic', '--model', 'x'],
      deps,
    );
    expect(code).toBe(1);
    const out = lines.join('\n');
    expect(out.toLowerCase()).toMatch(/required|missing|usage/);
    // Nothing must have been registered.
    const rows = await storage.listModelDescriptors!({});
    expect(rows.length).toBe(0);
  });

  it('unknown flag exits 1 with a usage error', async () => {
    const { lines, deps } = makeDeps();
    const code = await runCli(['register', '--quick', '--bogus', 'x'], deps);
    expect(code).toBe(1);
    expect(lines.join('\n').toLowerCase()).toMatch(/unknown|usage/);
  });

  it('--from-file with .yaml errors cleanly when yaml dep is absent', async () => {
    const tmp = mkdtempSync(path.join(tmpdir(), 'tzun-test-cli-'));
    const filePath = path.join(tmp, 'descriptor.yaml');
    try {
      writeFileSync(filePath, 'vendor: x\nmodelName: y\nmodelVersion: z\n');
      const { lines, deps } = makeDeps();
      const code = await runCli(['register', '--from-file', filePath], deps);
      expect(code).toBe(2);
      expect(lines.join('\n').toLowerCase()).toMatch(/yaml/);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('tzun.models.* programmatic API', () => {
  it('9. tzun.models.register matches the CLI register path', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    try {
      const r = await tzun.models.register({
        vendor: 'anthropic',
        modelName: 'claude-opus-4-7',
        modelVersion: '2026-01',
      });
      expect(r.digest).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(r.alreadyExisted).toBe(false);
      expect(r.descriptor.integrityTier).toBe('vendor-asserted');
      expect(r.descriptor.modelDigest).toBeNull();

      const row = await tzun.models.get(r.digest);
      expect(row).not.toBeNull();
      expect(row!.vendor).toBe('anthropic');

      const enriched = await tzun.models.getEnriched(r.digest);
      expect(enriched).not.toBeNull();
      expect(enriched!.modelName).toBe('claude-opus-4-7');

      const rows = await tzun.models.list({ vendor: 'anthropic' });
      expect(rows.length).toBe(1);

      const desc = await tzun.models.listDescendants(r.digest);
      expect(desc).toEqual([]);
    } finally {
      await tzun.close();
    }
  });

  it('10. tzun.models.computeModelDigest matches the CLI compute-digest', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    try {
      const a = await tzun.models.computeModelDigest(WEIGHTS_FIXTURE);
      const b = await computeModelDigest(WEIGHTS_FIXTURE);
      expect(a.modelDigest).toBe(b.modelDigest);
    } finally {
      await tzun.close();
    }
  });
});

describe('integrity tier + modelDigest invariant', () => {
  let storage: MemoryStorageAdapter;
  beforeEach(() => { storage = new MemoryStorageAdapter(); });

  it('rejects weight-attested with null modelDigest', async () => {
    await expect(
      registerModel(storage, {
        vendor: 'anthropic',
        modelName: 'claude',
        modelVersion: '1',
        integrityTier: 'weight-attested',
        modelDigest: null,
      }),
    ).rejects.toThrow(/inconsistent with modelDigest/);
  });

  it('rejects vendor-asserted with a non-null modelDigest', async () => {
    await expect(
      registerModel(storage, {
        vendor: 'self-hosted',
        modelName: 'llama',
        modelVersion: '1',
        integrityTier: 'vendor-asserted',
        modelDigest: 'sha256:' + 'a'.repeat(64),
      }),
    ).rejects.toThrow(/inconsistent with modelDigest/);
  });

  it('accepts internally-consistent caller-supplied pair (weight-attested + digest)', async () => {
    const digest = 'sha256:' + 'b'.repeat(64);
    const { descriptor } = await registerModel(storage, {
      vendor: 'self-hosted',
      modelName: 'llama',
      modelVersion: '1',
      integrityTier: 'weight-attested',
      modelDigest: digest,
    });
    expect(descriptor.integrityTier).toBe('weight-attested');
    expect(descriptor.modelDigest).toBe(digest);
  });

  it('derives vendor-asserted when integrityTier omitted and modelDigest absent', async () => {
    const { descriptor } = await registerModel(storage, {
      vendor: 'anthropic',
      modelName: 'claude',
      modelVersion: '1',
    });
    expect(descriptor.integrityTier).toBe('vendor-asserted');
    expect(descriptor.modelDigest).toBeNull();
  });

  it('derives weight-attested when integrityTier omitted but modelDigest provided', async () => {
    const digest = 'sha256:' + 'c'.repeat(64);
    const { descriptor } = await registerModel(storage, {
      vendor: 'self-hosted',
      modelName: 'llama',
      modelVersion: '1',
      modelDigest: digest,
    });
    expect(descriptor.integrityTier).toBe('weight-attested');
    expect(descriptor.modelDigest).toBe(digest);
  });

  it('rejects malformed modelDigest (wrong prefix)', async () => {
    await expect(
      registerModel(storage, {
        vendor: 'x', modelName: 'y', modelVersion: '1',
        modelDigest: 'md5:' + 'a'.repeat(32),
      }),
    ).rejects.toThrow(/modelDigest must match/);
  });

  it('rejects malformed modelDigest (wrong length)', async () => {
    await expect(
      registerModel(storage, {
        vendor: 'x', modelName: 'y', modelVersion: '1',
        modelDigest: 'sha256:abc',
      }),
    ).rejects.toThrow(/modelDigest must match/);
  });

  it('rejects malformed modelDigest (uppercase hex)', async () => {
    await expect(
      registerModel(storage, {
        vendor: 'x', modelName: 'y', modelVersion: '1',
        modelDigest: 'sha256:' + 'A'.repeat(64),
      }),
    ).rejects.toThrow(/modelDigest must match/);
  });
});

// ── --enable-known-models-fetch ──────────────────────────────────────────────

describe('runCli --enable-known-models-fetch', () => {
  it('default: the injected fetcher is never called (no network by default)', async () => {
    const { storage, deps } = makeDeps();
    const fetcher = jest.fn();
    const depsWithFetch = { ...deps, knownModelsFetchFn: fetcher as never };
    const code = await runCli(
      ['register', '--quick', '--vendor', 'openai', '--model', 'm', '--version', '1'],
      depsWithFetch,
    );
    expect(code).toBe(0);
    expect(fetcher).not.toHaveBeenCalled();
  });

  /**
   * Asserting only that `fetcher` was called and the exit code was 0 would
   * pass for a flag that does nothing: a fetch that succeeded, timed out,
   * 404'd or was never attempted would all produce byte-identical CLI output.
   * This case pins the outcome line, so a silent fallback is visible.
   */
  it('--enable-known-models-fetch calls the fetcher; failure falls back to bundled AND says so', async () => {
    const { storage, deps } = makeDeps();
    const out: string[] = [];
    const fetcher = jest.fn().mockRejectedValue(new Error('net down'));
    const depsWithFetch = { ...deps, knownModelsFetchFn: fetcher as never, stdout: (m: string) => out.push(m) };
    const code = await runCli(
      [
        'register', '--quick', '--vendor', 'openai', '--model', 'm', '--version', '1',
        '--enable-known-models-fetch', '--known-models-url', 'https://models.example.test/ref.json',
      ],
      depsWithFetch,
    );
    expect(fetcher).toHaveBeenCalled();   // fetch attempted
    expect(code).toBe(0);                 // bundled fallback kept the command working
    const line = out.find((m) => m.startsWith('known-models:'));
    expect(line).toMatch(/fetch failed \(Error\); using bundled version /);
    // Never the error message — it can echo a URL carrying credentials.
    expect(out.join('\n')).not.toContain('net down');
  });

  it('reports a SUCCESSFUL fetch distinguishably from the fallback', async () => {
    const { storage, deps } = makeDeps();
    const out: string[] = [];
    const fetcher = jest.fn().mockResolvedValue({ version: '9.9.9-test', entries: [] });
    const depsWithFetch = { ...deps, knownModelsFetchFn: fetcher as never, stdout: (m: string) => out.push(m) };
    const code = await runCli(
      [
        'register', '--quick', '--vendor', 'openai', '--model', 'm', '--version', '1',
        '--enable-known-models-fetch', '--known-models-url', 'https://models.example.test/ref.json',
      ],
      depsWithFetch,
    );
    expect(code).toBe(0);
    expect(out.find((m) => m.startsWith('known-models:'))).toBe(
      'known-models: fetched version 9.9.9-test from https://models.example.test/ref.json',
    );
  });

  it('--enable-known-models-fetch without --known-models-url keeps the bundled copy AND says so', async () => {
    // There is no default fetch URL, so nothing is fetched and the operator is told.
    const { deps } = makeDeps();
    const out: string[] = [];
    const fetcher = jest.fn();
    const depsWithFetch = { ...deps, knownModelsFetchFn: fetcher as never, stdout: (m: string) => out.push(m) };
    const code = await runCli(
      ['register', '--quick', '--vendor', 'openai', '--model', 'm', '--version', '1', '--enable-known-models-fetch'],
      depsWithFetch,
    );
    expect(code).toBe(0);
    expect(fetcher).not.toHaveBeenCalled();
    expect(out.find((m) => m.startsWith('known-models:'))).toMatch(
      /^known-models: no --known-models-url given; using bundled version /,
    );
  });

  it('says nothing about known-models when the flag was not passed', async () => {
    // Non-vacuity guard: the outcome line must not appear on every command.
    const { storage, deps } = makeDeps();
    const out: string[] = [];
    const code = await runCli(
      ['register', '--quick', '--vendor', 'openai', '--model', 'm', '--version', '1'],
      { ...deps, stdout: (m: string) => out.push(m) },
    );
    expect(code).toBe(0);
    expect(out.filter((m) => m.startsWith('known-models:'))).toEqual([]);
  });

  /**
   * The reference enriches the descriptor, so the usage text must say what is
   * filled and must not carry a "does NOT enrich" disclaimer: an operator
   * reading the help has to learn which fields the reference can fill and that
   * their own values and the integrity fields are never overwritten.
   */
  it('usage text says the reference fills the fields the operator did not supply', async () => {
    const out: string[] = [];
    const { deps } = makeDeps();
    await runCli(['--help'], { ...deps, stdout: (m: string) => out.push(m) });
    const usage = out.join('\n');
    expect(usage).toMatch(/--enable-known-models-fetch/);
    expect(usage).not.toMatch(/NOT enrich/i);
    expect(usage).toMatch(/fills the descriptive[\s\S]*fields it was not given/);
    expect(usage).toMatch(/supplied values always win/);
    expect(usage).toMatch(/integrity fields are never taken from it/);
    // Enrichment is flag-gated, and the usage text says what the default
    // path does instead.
    expect(usage).toMatch(/Without the flag[\s\S]*writes exactly the descriptor it was[\s\S]*given/);
    expect(usage).toMatch(/tzun\.models\.register\(\) writes for that triple/);
    // The fetch URL has no default.
    expect(usage).toMatch(/--known-models-url[\s\S]*There is no default/);
    expect(usage).not.toMatch(/known-models\.tzun\.ai/);
  });

  it('non-HTTPS --known-models-url is a usage error (threat-model row)', async () => {
    const { storage, deps } = makeDeps();
    const out: string[] = [];
    const code = await runCli(
      [
        'register', '--quick', '--vendor', 'v', '--model', 'm', '--version', '1',
        '--enable-known-models-fetch', '--known-models-url', 'http://insecure.example/ref.json',
      ],
      { ...deps, stdout: (m: string) => out.push(m) },
    );
    expect(code).toBe(1);
    expect(out.join('\n')).toMatch(/https/i);
  });
});

// ── The loaded reference must reach the registered descriptor ────────────────
//
// `--enable-known-models-fetch --known-models-url https://…` performs an HTTPS
// request; the reference it loads must then fill the registered descriptor,
// or the fetch costs a network round trip and changes nothing. These run on
// the SQLite adapter (a real catalog, not the memory double) because the
// assertion is about what lands in the catalog row and which
// content-addressed digest it gets.

function makeSqliteDeps(): {
  storage: SqliteStorageAdapter;
  lines: string[];
  deps: CliDependencies;
  dbPath: string;
  cleanup: () => void;
} {
  const dir = mkdtempSync(path.join(tmpdir(), 'tzun-test-cli-sqlite-'));
  const dbPath = path.join(dir, 'catalog.db');
  const storage = new SqliteStorageAdapter(dbPath);
  const lines: string[] = [];
  const deps: CliDependencies = {
    storage,
    prompt: async () => '',
    stdout: (m: string) => lines.push(m),
  };
  return {
    storage,
    lines,
    deps,
    dbPath,
    cleanup: () => {
      storage.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

describe('runCli register applies the known-models reference (SQLite)', () => {
  const FETCHED_URL = 'https://models.example.test/ref.json';

  it('fills the descriptive fields from a FETCHED reference when --enable-known-models-fetch is passed', async () => {
    const { storage, lines, deps, cleanup } = makeSqliteDeps();
    try {
      const fetcher = jest.fn().mockResolvedValue({
        version: '9.9.9-test',
        entries: [
          {
            vendor: 'openai',
            modelName: 'gpt-4o',
            modelVersion: '2024-08-06',
            modelType: 'llm',
            trainedBy: 'Fetched Inc',
            license: 'fetched-license',
            modelCardUrl: 'https://fetched.example/card',
          },
        ],
      });
      const code = await runCli(
        [
          'register', '--quick', '--vendor', 'openai', '--model', 'gpt-4o', '--version', '2024-08-06',
          '--enable-known-models-fetch', '--known-models-url', FETCHED_URL,
        ],
        { ...deps, knownModelsFetchFn: fetcher as never },
      );
      expect(code).toBe(0);
      expect(fetcher).toHaveBeenCalledWith(FETCHED_URL);

      const rows = await storage.listModelDescriptors!({});
      expect(rows.length).toBe(1);
      const d = rows[0].descriptor;
      // The fetched entry — not the bundled one (whose license is
      // 'openai-commercial') — is what reached the catalog.
      expect(d.license).toBe('fetched-license');
      expect(d.trainedBy).toBe('Fetched Inc');
      expect(d.modelType).toBe('llm');
      expect(d.modelCardUrl).toBe('https://fetched.example/card');
      expect(d.integrityTier).toBe('vendor-asserted');

      expect(lines).toContain(`known-models: fetched version 9.9.9-test from ${FETCHED_URL}`);
      expect(lines).toContain(
        'known-models: enriched openai/gpt-4o@2024-08-06 from reference 9.9.9-test (modelType, trainedBy, license, modelCardUrl)',
      );
      expect(lines.join('\n')).toMatch(/license:\s+fetched-license/);
    } finally {
      cleanup();
    }
  });

  /**
   * Enrichment is scoped to invocations that pass
   * `--enable-known-models-fetch`. Without the flag the CLI writes exactly the
   * descriptor it was given: the same row and the same digest as
   * `tzun.models.register()`, the API the CLI fronts. Enriching on the default
   * path would move the digest of every flag-less registration that hit the
   * reference while the API kept registering bare: one triple, two digests,
   * depending on which door it came in through.
   */
  it('without the flag, the CLI and tzun.models.register() write ONE bare row with ONE digest for the same triple', async () => {
    const { storage, lines, deps, dbPath, cleanup } = makeSqliteDeps();
    try {
      const code = await runCli(
        ['register', '--quick', '--vendor', 'openai', '--model', 'gpt-4o', '--version', '2024-08-06'],
        deps,
      );
      expect(code).toBe(0);
      expect(lines.filter((m) => m.startsWith('known-models:'))).toEqual([]);

      const rows = await storage.listModelDescriptors!({});
      expect(rows.length).toBe(1);
      const cliDigest = rows[0].modelDescriptorDigest;
      // A triple the bundled reference knows — and nothing was taken from it.
      expect(rows[0].descriptor.license).toBeNull();
      expect(rows[0].descriptor.trainedBy).toBeNull();
      expect(rows[0].descriptor.modelType).toBeNull();
      expect(rows[0].descriptor.modelCardUrl).toBeNull();

      // The programmatic API, on the same catalog file, lands on that row.
      const tzun = await Tzun.init({ dbPath });
      try {
        const viaApi = await tzun.models.register({
          vendor: 'openai',
          modelName: 'gpt-4o',
          modelVersion: '2024-08-06',
        });
        expect(viaApi.alreadyExisted).toBe(true);
        expect(viaApi.digest).toBe(cliDigest);
        expect(viaApi.descriptor).toEqual(rows[0].descriptor);
      } finally {
        await tzun.close();
      }
      expect((await storage.listModelDescriptors!({})).length).toBe(1);

      // What `tzun.attach()`'s connector path writes for the same model IS
      // enriched, so it is a different row. That divergence is deliberate
      // for now — opt-in enrichment on the programmatic path is not built
      // yet — and the flagged case below is how the CLI reaches the connector row.
      const connectorDescriptor = importFromVendor({
        vendor: 'openai',
        modelId: 'gpt-4o-2024-08-06',
        knownModels: await loadKnownModels(),
      }).descriptor;
      expect(connectorDescriptor.license).toBe('openai-commercial');
      const viaConnector = await registerModel(storage, connectorDescriptor);
      expect(viaConnector.alreadyExisted).toBe(false);
      expect(viaConnector.digest).not.toBe(cliDigest);
      expect((await storage.listModelDescriptors!({})).length).toBe(2);
    } finally {
      cleanup();
    }
  });

  it('with --enable-known-models-fetch the CLI enriches and lands on the connector-path row', async () => {
    const { storage, lines, deps, cleanup } = makeSqliteDeps();
    try {
      // The fetcher hands back the bundled reference: the flag is what opts
      // into enrichment; the reference is the one attach() itself uses.
      const fetcher = jest.fn().mockResolvedValue(await loadKnownModels());
      const code = await runCli(
        [
          'register', '--quick', '--vendor', 'openai', '--model', 'gpt-4o', '--version', '2024-08-06',
          '--enable-known-models-fetch', '--known-models-url', FETCHED_URL,
        ],
        { ...deps, knownModelsFetchFn: fetcher as never },
      );
      expect(code).toBe(0);

      const rows = await storage.listModelDescriptors!({});
      expect(rows.length).toBe(1);
      const cliDigest = rows[0].modelDescriptorDigest;
      expect(rows[0].descriptor.license).toBe('openai-commercial');
      expect(rows[0].descriptor.trainedBy).toBe('OpenAI');

      // The descriptor `tzun.attach()` would register for the same model, via
      // the connector path. The CLI must land on that same row and digest, not
      // write a second, bare row for the very same model.
      const connectorDescriptor = importFromVendor({
        vendor: 'openai',
        modelId: 'gpt-4o-2024-08-06',
        knownModels: await loadKnownModels(),
      }).descriptor;
      expect(rows[0].descriptor).toEqual(connectorDescriptor);
      const again = await registerModel(storage, connectorDescriptor);
      expect(again.alreadyExisted).toBe(true);
      expect(again.digest).toBe(cliDigest);
      expect((await storage.listModelDescriptors!({})).length).toBe(1);

      expect(lines).toContain(
        'known-models: enriched openai/gpt-4o@2024-08-06 from reference 2026-09-09 (modelType, trainedBy, license, modelCardUrl)',
      );
    } finally {
      cleanup();
    }
  });

  it('operator-supplied values win; only the fields that were absent are filled', async () => {
    const tmp = mkdtempSync(path.join(tmpdir(), 'tzun-test-cli-'));
    const filePath = path.join(tmp, 'descriptor.json');
    const { storage, lines, deps, cleanup } = makeSqliteDeps();
    try {
      writeFileSync(filePath, JSON.stringify({
        vendor: 'openai',
        modelName: 'gpt-4o',
        modelVersion: '2024-08-06',
        modelType: 'chat',
        license: 'proprietary',
      }));
      const fetcher = jest.fn().mockResolvedValue(await loadKnownModels());
      const code = await runCli(
        ['register', '--from-file', filePath, '--enable-known-models-fetch', '--known-models-url', FETCHED_URL],
        { ...deps, knownModelsFetchFn: fetcher as never },
      );
      expect(code).toBe(0);

      const d = (await storage.listModelDescriptors!({}))[0].descriptor;
      expect(d.modelType).toBe('chat');          // supplied — kept
      expect(d.license).toBe('proprietary');     // supplied — kept
      expect(d.trainedBy).toBe('OpenAI');        // absent — filled
      expect(d.modelCardUrl).toBe('https://platform.openai.com/docs/models/gpt-4o');
      expect(lines).toContain(
        'known-models: enriched openai/gpt-4o@2024-08-06 from reference 2026-09-09 (trainedBy, modelCardUrl)',
      );
    } finally {
      cleanup();
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('reports "adds nothing" only when the entry has no absent field left to fill', async () => {
    const tmp = mkdtempSync(path.join(tmpdir(), 'tzun-test-cli-'));
    const filePath = path.join(tmp, 'descriptor.json');
    const { lines, deps, cleanup } = makeSqliteDeps();
    try {
      // Every field the bundled gpt-4o entry carries is supplied, so there is
      // nothing for the entry to fill — which is what the line has to say.
      // "(all fields supplied)" would not say it: those words fit an empty
      // ENTRY just as well.
      writeFileSync(filePath, JSON.stringify({
        vendor: 'openai',
        modelName: 'gpt-4o',
        modelVersion: '2024-08-06',
        modelType: 'chat',
        trainedBy: 'Me',
        license: 'proprietary',
        modelCardUrl: 'https://example.com/card',
      }));
      const fetcher = jest.fn().mockResolvedValue(await loadKnownModels());
      const code = await runCli(
        ['register', '--from-file', filePath, '--enable-known-models-fetch', '--known-models-url', FETCHED_URL],
        { ...deps, knownModelsFetchFn: fetcher as never },
      );
      expect(code).toBe(0);
      expect(lines).toContain(
        'known-models: entry for openai/gpt-4o@2024-08-06 in reference 2026-09-09 adds nothing (no absent field the entry could fill)',
      );
      expect(lines.join('\n')).not.toMatch(/all fields supplied/);
    } finally {
      cleanup();
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('a reference entry cannot mint integrity fields on the registered descriptor', async () => {
    const { storage, deps, cleanup } = makeSqliteDeps();
    try {
      const fetcher = jest.fn().mockResolvedValue({
        version: '9.9.9-test',
        entries: [
          {
            vendor: 'openai',
            modelName: 'gpt-4o',
            modelVersion: '2024-08-06',
            license: 'fetched-license',
            integrityTier: 'weight-attested',
            modelDigest: 'sha256:' + 'a'.repeat(64),
            parentModelDescriptorDigest: 'sha256:' + 'b'.repeat(64),
            derivation: 'fine-tune',
          },
        ],
      });
      const code = await runCli(
        [
          'register', '--quick', '--vendor', 'openai', '--model', 'gpt-4o', '--version', '2024-08-06',
          '--enable-known-models-fetch', '--known-models-url', FETCHED_URL,
        ],
        { ...deps, knownModelsFetchFn: fetcher as never },
      );
      expect(code).toBe(0);
      const d = (await storage.listModelDescriptors!({}))[0].descriptor;
      expect(d.license).toBe('fetched-license');   // descriptive: applied
      expect(d.integrityTier).toBe('vendor-asserted');
      expect(d.modelDigest).toBeNull();
      expect(d.parentModelDescriptorDigest).toBeNull();
      expect(d.derivation).toBeNull();
    } finally {
      cleanup();
    }
  });

  it('reports a lookup MISS when the operator asked for a fetch, and stays silent otherwise', async () => {
    const { lines, deps, cleanup } = makeSqliteDeps();
    try {
      const fetcher = jest.fn().mockResolvedValue({ version: '9.9.9-test', entries: [] });
      const code = await runCli(
        [
          'register', '--quick', '--vendor', 'openai', '--model', 'm', '--version', '1',
          '--enable-known-models-fetch', '--known-models-url', FETCHED_URL,
        ],
        { ...deps, knownModelsFetchFn: fetcher as never },
      );
      expect(code).toBe(0);
      expect(lines).toContain(
        'known-models: no entry for openai/m@1 in reference 9.9.9-test; registering as supplied',
      );

      lines.length = 0;
      const code2 = await runCli(
        ['register', '--quick', '--vendor', 'openai', '--model', 'm2', '--version', '1'],
        deps,
      );
      expect(code2).toBe(0);
      expect(lines.filter((m) => m.startsWith('known-models:'))).toEqual([]);
    } finally {
      cleanup();
    }
  });
});
