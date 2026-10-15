import { createServer } from 'net';
import type { AddressInfo, Socket } from 'net';
/**
 * Known-models reference loader + seed data tests.
 *
 * The loader returns the bundled `data/known-models.json` by default.
 * Runtime fetch is opt-in, reads only the URL the caller names, and falls back
 * to the bundled copy without one or on any error.
 */

import {
  loadKnownModels,
  lookupKnownModel,
  KnownModelsReference,
} from '../../src/models/known-models';

describe('known-models reference', () => {
  it('1. bundled reference parses and has a version + entries array', async () => {
    const ref = await loadKnownModels();
    expect(typeof ref.version).toBe('string');
    expect(ref.version.length).toBeGreaterThan(0);
    expect(Array.isArray(ref.entries)).toBe(true);
    expect(ref.entries.length).toBeGreaterThanOrEqual(20);
  });

  it('2. seed contains entries for all nine logical vendor surfaces', async () => {
    const ref = await loadKnownModels();
    const vendors = new Set(ref.entries.map((e) => e.vendor));
    // Eight conventional vendor strings cover the nine logical surfaces
    // (Azure OpenAI is served by the `openai` vendor; HF Inference uses
    // `hf-inference`; models served through the OpenRouter gateway use
    // `openrouter`).
    const expected = [
      'openai',
      'anthropic',
      'bedrock',
      'vertex',
      'azure-ai',
      'nvidia-nim',
      'hf-inference',
      'openrouter',
    ];
    for (const v of expected) {
      expect(vendors.has(v)).toBe(true);
    }
  });

  it('3. lookupKnownModel finds an exact (vendor, modelName, modelVersion) match', async () => {
    const ref = await loadKnownModels();
    // Pick a seeded entry: anthropic claude-opus-4-7. Use the version that
    // is actually in the seed (look up the first matching entry by name).
    const anthropicOpus = ref.entries.find(
      (e) => e.vendor === 'anthropic' && e.modelName === 'claude-opus-4-7',
    );
    expect(anthropicOpus).toBeDefined();
    const hit = lookupKnownModel(
      ref,
      'anthropic',
      'claude-opus-4-7',
      anthropicOpus!.modelVersion as string,
    );
    expect(hit).not.toBeNull();
    expect(hit?.vendor).toBe('anthropic');
    expect(hit?.modelName).toBe('claude-opus-4-7');
  });

  it('4. lookupKnownModel returns null for unknown (vendor, name, version)', async () => {
    const ref = await loadKnownModels();
    expect(lookupKnownModel(ref, 'nope', 'nope', 'nope')).toBeNull();
    // Right vendor + name, wrong version
    expect(lookupKnownModel(ref, 'anthropic', 'claude-opus-4-7', 'not-a-real-version')).toBeNull();
  });

  it('5. runtime fetch is DISABLED by default', async () => {
    const fetcher = jest.fn();
    const ref = await loadKnownModels({ fetcher });
    expect(fetcher).not.toHaveBeenCalled();
    expect(ref.entries.length).toBeGreaterThan(0);
  });

  it('6. runtime fetch falls back to bundled on fetcher error', async () => {
    const fetcher = jest.fn().mockRejectedValue(new Error('network down'));
    const ref = await loadKnownModels({
      enableRuntimeFetch: true,
      runtimeFetchUrl: 'https://models.example.test/ref.json',
      fetcher,
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    // Bundled copy has entries — confirms fallback happened
    expect(ref.entries.length).toBeGreaterThan(0);
  });

  it('7. runtime fetch returns fetched reference on success', async () => {
    const fetched: KnownModelsReference = {
      version: '2099-01-01',
      entries: [{ vendor: 'x', modelName: 'y', modelVersion: 'z' }],
    };
    const fetcher = jest.fn().mockResolvedValue(fetched);
    const ref = await loadKnownModels({
      enableRuntimeFetch: true,
      runtimeFetchUrl: 'https://models.example.test/ref.json',
      fetcher,
    });
    expect(fetcher).toHaveBeenCalledWith('https://models.example.test/ref.json');
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(ref.version).toBe('2099-01-01');
    expect(ref.entries).toEqual([{ vendor: 'x', modelName: 'y', modelVersion: 'z' }]);
  });

  it('8. runtime fetch with no URL keeps the bundled copy and reports no-url', async () => {
    // There is no default fetch URL: a runtime fetch must name its source.
    const fetcher = jest.fn();
    const outcomes: unknown[] = [];
    const ref = await loadKnownModels({
      enableRuntimeFetch: true,
      fetcher,
      onOutcome: (o) => outcomes.push(o),
    });
    expect(fetcher).not.toHaveBeenCalled();
    expect(outcomes).toEqual([{ source: 'bundled', version: ref.version, reason: 'no-url' }]);
    expect(ref.entries.length).toBeGreaterThan(0);
  });
});

/**
 * The loader's own guards.
 *
 * The HTTPS-only rule was enforced in the CLI argument parser only, so every
 * library caller of `loadKnownModels` could pass an `http://` URL and feed a
 * plaintext, attacker-modifiable reference into descriptor enrichment. And the
 * default fetcher used bare `fetch`, which has no default timeout, so a
 * black-holed host hung the caller forever on a code path whose whole contract
 * is "best-effort".
 */
describe('loadKnownModels transport guards', () => {
  it('refuses a non-HTTPS runtimeFetchUrl without calling the fetcher', async () => {
    const fetcher = jest.fn();
    const outcomes: unknown[] = [];
    const ref = await loadKnownModels({
      enableRuntimeFetch: true,
      runtimeFetchUrl: 'http://models.example.test/ref.json',
      fetcher: fetcher as never,
      onOutcome: (o) => outcomes.push(o),
    });
    expect(fetcher).not.toHaveBeenCalled();
    expect(outcomes).toEqual([
      { source: 'bundled', version: ref.version, reason: 'url-not-https', url: 'http://models.example.test/ref.json' },
    ]);
    // Still usable — the guard degrades, it does not throw.
    expect(Array.isArray(ref.entries)).toBe(true);
  });

  it('reports fetched vs bundled so a silent fallback is detectable', async () => {
    const fetched: unknown[] = [];
    await loadKnownModels({
      enableRuntimeFetch: true,
      runtimeFetchUrl: 'https://models.example.test/ref.json',
      fetcher: async () => ({ version: '7.7.7', entries: [] }),
      onOutcome: (o) => fetched.push(o),
    });
    expect(fetched).toEqual([
      { source: 'fetched', version: '7.7.7', url: 'https://models.example.test/ref.json' },
    ]);

    const failed: Array<Record<string, unknown>> = [];
    await loadKnownModels({
      enableRuntimeFetch: true,
      runtimeFetchUrl: 'https://models.example.test/ref.json',
      fetcher: async () => { throw new TypeError('boom secret-url'); },
      onOutcome: (o) => failed.push(o as Record<string, unknown>),
    });
    expect(failed[0].reason).toBe('fetch-failed');
    // Class name only — never the message.
    expect(failed[0].error).toBe('TypeError');
    expect(JSON.stringify(failed)).not.toContain('secret-url');
  });

  it('the default fetcher carries an abort deadline', async () => {
    // A host that accepts the TCP connection and then says nothing. Before the
    // fix this hung forever: `fetch` has no default timeout, so `tzun models
    // register --enable-known-models-fetch` against a black-holed host never
    // returned and printed nothing.
    const sockets: Socket[] = [];
    const server = createServer((sock) => { sockets.push(sock); });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const port = (server.address() as AddressInfo).port;
    try {
      const outcomes: Array<Record<string, unknown>> = [];
      const started = Date.now();
      const ref = await loadKnownModels({
        enableRuntimeFetch: true,
        runtimeFetchUrl: `https://127.0.0.1:${port}/ref.json`,
        fetchTimeoutMs: 150,
        onOutcome: (o) => outcomes.push(o as Record<string, unknown>),
      });
      const elapsed = Date.now() - started;
      // The deadline is what makes this return at all. A generous ceiling: the
      // point is bounded, not precise.
      expect(elapsed).toBeLessThan(5000);
      expect(outcomes[0].reason).toBe('fetch-failed');
      // Still degraded-usable rather than thrown.
      expect(Array.isArray(ref.entries)).toBe(true);
    } finally {
      for (const s of sockets) s.destroy();
      await new Promise<void>((r) => server.close(() => r()));
    }
  }, 20000);
});
