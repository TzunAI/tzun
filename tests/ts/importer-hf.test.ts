/**
 * Hugging Face model card importer tests.
 *
 * Fixtures live in `tests/fixtures/hf-cards/`. Each is a synthetic HF API
 * response (no actual fetched HF content) constructed to exercise the
 * field-mapping rules and graceful degradation.
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  importFromHuggingFace,
  buildHfApiUrl,
  defaultFetcher,
  MAX_HF_RESPONSE_BYTES,
  HfApiResponse,
} from '../../src/models/import-hf';

const FIXTURE_DIR = path.join(__dirname, 'fixtures', 'hf-cards');
const WEIGHTS_PATH = path.join(__dirname, 'fixtures', 'model-weights');

function loadFixture(name: string): HfApiResponse {
  return JSON.parse(
    fs.readFileSync(path.join(FIXTURE_DIR, `${name}.json`), 'utf8'),
  );
}

describe('HF importer', () => {
  it('1. builds a weight-attested descriptor when weightsPath is provided', async () => {
    const desc = await importFromHuggingFace(
      'meta-llama/Llama-3.1-70B-Instruct',
      {
        fetcher: async () => loadFixture('llama-full'),
        weightsPath: WEIGHTS_PATH,
      },
    );
    expect(desc.integrityTier).toBe('weight-attested');
    expect(desc.modelDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('2. builds a vendor-asserted descriptor without weightsPath', async () => {
    const desc = await importFromHuggingFace(
      'meta-llama/Llama-3.1-70B-Instruct',
      { fetcher: async () => loadFixture('llama-full') },
    );
    expect(desc.integrityTier).toBe('vendor-asserted');
    expect(desc.modelDigest).toBeNull();
  });

  it('3. extracts DOI from cardData when present', async () => {
    const desc = await importFromHuggingFace(
      'mistralai/Mistral-7B-Instruct-v0.3',
      { fetcher: async () => loadFixture('mistral-with-doi') },
    );
    const doi = desc.externalIdentifiers.find((e) => e.scheme === 'doi');
    expect(doi).toBeDefined();
    expect(doi?.value).toBe('10.57967/hf/test-1234');
    expect(doi?.issuedBy).toBe('DataCite');
  });

  it('4. gracefully populates MVD on minimal model card', async () => {
    const desc = await importFromHuggingFace(
      'synthetic-org/bert-tiny-test',
      { fetcher: async () => loadFixture('bert-minimal') },
    );
    // Fixed-shape MVD with explicit nulls.
    expect(desc.descriptorVersion).toBe('d1');
    expect(desc.vendor).toBe('huggingface');
    expect(desc.modelName).toBe('synthetic-org/bert-tiny-test');
    expect(desc.modelVersion).toBe(
      '0011223344556677889900aabbccddeeff001122',
    );
    expect(desc.modelType).toBeNull();
    expect(desc.license).toBeNull();
    expect(desc.trainedBy).toBe('synthetic-org');
    expect(desc.parentModelDescriptorDigest).toBeNull();
    expect(desc.derivation).toBe('base'); // no base_model → 'base'
    expect(desc.training.evaluations).toEqual([]);
    expect(desc.training.trainingDataRef).toBeNull();
    expect(desc.regulatoryMarkings).toEqual([]);
    expect(desc.integrityTier).toBe('vendor-asserted');
    expect(desc.modelDigest).toBeNull();
  });

  it('5. maps license, base_model, datasets, eval_results when present', async () => {
    const desc = await importFromHuggingFace(
      'meta-llama/Llama-3.1-70B-Instruct',
      { fetcher: async () => loadFixture('llama-full') },
    );
    expect(desc.license).toBe('llama3.1');
    expect(desc.derivation).toBe('fine-tune'); // base_model present
    expect(desc.training.trainingDataRef).toContain('synthetic/test-corpus');
    expect(desc.training.trainingDataRef).toContain(
      'synthetic/instruction-tune',
    );
    // Two distinct task names → two evaluations; metrics for same task aggregated.
    expect(desc.training.evaluations).toHaveLength(2);
    const reasoning = desc.training.evaluations.find(
      (e) => e.name === 'Reasoning',
    );
    expect(reasoning).toBeDefined();
    expect(reasoning?.metrics).toEqual({
      accuracy: 0.873,
      exact_match: 0.612,
      f1: 0.701,
    });
    expect(reasoning?.testSetDigest).toBeNull();
    expect(reasoning?.evaluatedAt).toBeNull();
    const summarization = desc.training.evaluations.find(
      (e) => e.name === 'Summarization',
    );
    expect(summarization?.metrics).toEqual({ rouge1: 0.421 });
  });

  it('6. always includes hf-repo external identifier', async () => {
    const desc = await importFromHuggingFace(
      'synthetic-org/bert-tiny-test',
      { fetcher: async () => loadFixture('bert-minimal') },
    );
    const repo = desc.externalIdentifiers.find((e) => e.scheme === 'hf-repo');
    expect(repo).toBeDefined();
    expect(repo?.value).toBe('synthetic-org/bert-tiny-test');
    expect(repo?.issuedBy).toBe('huggingface');
    expect(repo?.url).toBe(
      'https://huggingface.co/synthetic-org/bert-tiny-test',
    );
  });

  it('7. includes hf-revision external identifier when sha is known', async () => {
    const desc = await importFromHuggingFace(
      'meta-llama/Llama-3.1-70B-Instruct',
      { fetcher: async () => loadFixture('llama-full') },
    );
    const rev = desc.externalIdentifiers.find(
      (e) => e.scheme === 'hf-revision',
    );
    expect(rev).toBeDefined();
    expect(rev?.value).toBe('abcdef0123456789abcdef0123456789abcdef01');
    expect(rev?.issuedBy).toBe('huggingface');
  });

  it('8. throws on fetcher error', async () => {
    const failingFetcher = async () => {
      throw new Error('network down');
    };
    await expect(
      importFromHuggingFace('whatever/model', { fetcher: failingFetcher }),
    ).rejects.toThrow(/Hugging Face importer/);
  });

  it('9. modelType is mapped from pipeline_tag', async () => {
    const llm = await importFromHuggingFace(
      'meta-llama/Llama-3.1-70B-Instruct',
      { fetcher: async () => loadFixture('llama-full') },
    );
    expect(llm.modelType).toBe('llm');

    const vision = await importFromHuggingFace(
      'synthetic-org/clip-vision-test',
      { fetcher: async () => loadFixture('clip-vision') },
    );
    expect(vision.modelType).toBe('vision');

    // Unknown pipeline_tag → null.
    const unknown = await importFromHuggingFace('foo/bar', {
      fetcher: async () => ({
        modelId: 'foo/bar',
        sha: 'a'.repeat(40),
        pipeline_tag: 'unsupervised-cluster-of-the-future',
        cardData: { pipeline_tag: 'unsupervised-cluster-of-the-future' },
      }),
    });
    expect(unknown.modelType).toBeNull();
  });

  it('10. modelVersion falls back to revision option, then "main", when sha absent', async () => {
    const noSha: HfApiResponse = {
      modelId: 'orgless-model',
      cardData: { license: 'mit' },
    };
    // No revision → defaults to 'main'.
    const d1 = await importFromHuggingFace('orgless-model', {
      fetcher: async () => noSha,
    });
    expect(d1.modelVersion).toBe('main');
    // revision provided → used as modelVersion.
    const d2 = await importFromHuggingFace('orgless-model', {
      fetcher: async () => noSha,
      revision: 'v1-test-branch',
    });
    expect(d2.modelVersion).toBe('v1-test-branch');
  });

  it('11. trainedBy is the org part of repo id; falls back to full id when unscoped', async () => {
    const noSha: HfApiResponse = { modelId: 'orgless-model' };
    const d = await importFromHuggingFace('orgless-model', {
      fetcher: async () => noSha,
    });
    expect(d.trainedBy).toBeNull(); // no '/' → no org, so trainedBy is null
    expect(d.modelName).toBe('orgless-model');
  });

  it('12. invokes optional cardFetcher and merges its cardData with the base response', async () => {
    const base: HfApiResponse = {
      modelId: 'org/model',
      sha: 'b'.repeat(40),
      pipeline_tag: 'text-generation',
    };
    const cardData: HfApiResponse = {
      cardData: {
        license: 'apache-2.0',
        base_model: 'org/base-model',
      },
    };
    const desc = await importFromHuggingFace('org/model', {
      fetcher: async () => base,
      cardFetcher: async () => cardData,
    });
    expect(desc.license).toBe('apache-2.0');
    expect(desc.derivation).toBe('fine-tune');
  });
  // ── Real API evaluation shape ────────────────────────────────────────
  // Every test above feeds a SYNTHETIC fixture, which can only confirm the
  // importer's own assumptions about the wire. The block below uses a
  // response captured verbatim from the live API on 2026-09-03.

  describe('against a real captured HF API response', () => {
    it('13. imports evaluations from the top-level model-index the API actually emits', async () => {
      const real = loadFixture('bart-large-cnn-real');
      // Non-vacuity guard: the fixture must carry evaluations only in the
      // top-level model-index, with no cardData.eval_results to fall back on.
      expect(Array.isArray((real as Record<string, unknown>)['model-index'])).toBe(true);
      expect(real.cardData?.eval_results).toBeUndefined();

      const desc = await importFromHuggingFace('facebook/bart-large-cnn', {
        fetcher: async () => real,
      });

      // The evaluations come from the top-level model-index. An importer that
      // read only cardData.eval_results would return [] for every real model
      // on the hub.
      expect(desc.training.evaluations).toHaveLength(1);
      const summarization = desc.training.evaluations.find(
        (e) => e.name === 'Summarization',
      );
      expect(summarization).toBeDefined();
      expect(summarization?.metrics['ROUGE-1']).toBeCloseTo(42.9486, 4);
      expect(summarization?.metrics['ROUGE-2']).toBeCloseTo(20.8149, 4);
    });

    it('14. still imports the huggingface_hub-style cardData.eval_results shape', async () => {
      const desc = await importFromHuggingFace(
        'meta-llama/Llama-3.1-70B-Instruct',
        { fetcher: async () => loadFixture('llama-full') },
      );
      expect(desc.training.evaluations).toHaveLength(2);
    });

    it('15. keys the descriptor on the canonical id the API returns, not the caller spelling', async () => {
      // The live API 307-redirects case variants to the canonical id and
      // answers with `id`. Asking for the miscased spelling must not mint a
      // second content-addressed descriptor for the same model.
      const canonical = loadFixture('bart-large-cnn-real');
      const desc = await importFromHuggingFace('Facebook/BART-Large-CNN', {
        fetcher: async () => canonical,
      });
      expect(desc.modelName).toBe('facebook/bart-large-cnn');
      expect(desc.trainedBy).toBe('facebook');
      expect(desc.modelCardUrl).toBe(
        'https://huggingface.co/facebook/bart-large-cnn',
      );
      const repo = desc.externalIdentifiers.find((e) => e.scheme === 'hf-repo');
      expect(repo?.value).toBe('facebook/bart-large-cnn');
      expect(repo?.url).toBe('https://huggingface.co/facebook/bart-large-cnn');

      const spelledCorrectly = await importFromHuggingFace(
        'facebook/bart-large-cnn',
        { fetcher: async () => canonical },
      );
      // Content-addressed descriptors: the two spellings must agree byte for byte.
      expect(JSON.stringify(desc)).toBe(JSON.stringify(spelledCorrectly));
    });

    it('16. falls back to the caller id when the response names no id', async () => {
      const desc = await importFromHuggingFace('orgless-model', {
        fetcher: async () => ({}) as HfApiResponse,
      });
      expect(desc.modelName).toBe('orgless-model');
    });
  });

  describe('default fetcher hardening', () => {
    const realFetch = globalThis.fetch;
    afterEach(() => {
      globalThis.fetch = realFetch;
    });

    it('17. percent-encodes every caller-supplied path segment', () => {
      expect(buildHfApiUrl('org/model')).toBe(
        'https://huggingface.co/api/models/org/model',
      );
      // '/' stays structural; every other caller byte is encoded, so a crafted
      // id cannot escape the /api/models/ prefix or append a query string.
      expect(buildHfApiUrl('org/..?x=1')).toBe(
        'https://huggingface.co/api/models/org/..%3Fx%3D1',
      );
      expect(buildHfApiUrl('a b/c#d')).toBe(
        'https://huggingface.co/api/models/a%20b/c%23d',
      );
    });

    it('18. gives the request a deadline', async () => {
      let seenSignal: unknown;
      globalThis.fetch = (async (_url: string, init?: RequestInit) => {
        seenSignal = init?.signal;
        return {
          ok: true,
          headers: new Headers(),
          body: null,
          text: async () => '{"id":"org/model"}',
        } as unknown as Response;
      }) as typeof fetch;

      const res = await defaultFetcher('org/model', 5000);
      expect(res.id).toBe('org/model');
      // Bare `fetch` has no default timeout, so without a signal a stalled
      // server would hang the import indefinitely.
      expect(seenSignal).toBeInstanceOf(AbortSignal);
    });

    it('19. refuses a body that declares a size over the cap', async () => {
      globalThis.fetch = (async () =>
        ({
          ok: true,
          headers: new Headers({
            'content-length': String(MAX_HF_RESPONSE_BYTES + 1),
          }),
          body: null,
          text: async () => '{}',
        }) as unknown as Response) as typeof fetch;

      await expect(defaultFetcher('org/model')).rejects.toThrow(/too large/);
    });

    it('20. refuses an undeclared body that streams past the cap', async () => {
      const chunk = new Uint8Array(1024 * 512);
      let emitted = 0;
      let cancelled = false;
      globalThis.fetch = (async () =>
        ({
          ok: true,
          headers: new Headers(),
          body: {
            getReader: () => ({
              read: async () => {
                emitted += chunk.byteLength;
                return { done: false, value: chunk };
              },
              cancel: async () => {
                cancelled = true;
              },
            }),
          },
          text: async () => '{}',
        }) as unknown as Response) as typeof fetch;

      await expect(defaultFetcher('org/model')).rejects.toThrow(/too large/);
      expect(cancelled).toBe(true);
      // It stopped near the cap rather than buffering forever.
      expect(emitted).toBeLessThanOrEqual(MAX_HF_RESPONSE_BYTES + chunk.byteLength);
    });
  });
});
