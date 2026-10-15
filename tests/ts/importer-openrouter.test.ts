/**
 * The `openrouter` vendor in the importer: id parsing, the maker taken from
 * the author prefix, and the variant fallback that lets a `:free` or
 * `:batch` id enrich from its base model's entry.
 *
 * The helper tables are the reference for the Python port
 * (`openrouter_author`, `openrouter_variant_base`), which must give the same
 * result for every row.
 */

import {
  importFromVendor,
  parseModelId,
  openRouterAuthor,
  openRouterVariantBase,
} from '../../src/models/import-vendor';
import { loadKnownModels, KnownModelsReference } from '../../src/models/known-models';

describe('openRouterAuthor', () => {
  it.each<[string, string | null]>([
    ['openai/gpt-6.1-sol', 'openai'],
    ['meta-llama/llama-4-maverick', 'meta-llama'],
    ['x-ai/grok-4.7', 'x-ai'],
    ['nvidia/nemotron-3-super-120b-a12b:free', 'nvidia'],
    ['google/gemini-4-argon:batch', 'google'],
    // One alias tilde is dropped: the alias lives in the maker's namespace.
    ['~anthropic/claude-opus-latest', 'anthropic'],
    ['~~anthropic/claude-opus-latest', '~anthropic'],
    // Routers are not makers.
    ['openrouter/auto', null],
    ['openrouter/free', null],
    ['~openrouter/auto', null],
    // Case is kept: the comparison with `openrouter` is exact.
    ['OpenRouter/auto', 'OpenRouter'],
    ['no-prefix', null],
    ['/leading-slash', null],
    ['~/x', null],
    ['~', null],
    ['', null],
    ['a/b/c', 'a'],
    ['author:x/model', 'author:x'],
  ])('%j → %j', (id, expected) => {
    expect(openRouterAuthor(id)).toBe(expected);
  });
});

describe('openRouterVariantBase', () => {
  it.each<[string, string | null]>([
    ['nvidia/nemotron-3-super-120b-a12b:free', 'nvidia/nemotron-3-super-120b-a12b'],
    ['google/gemini-4-argon:batch', 'google/gemini-4-argon'],
    ['openai/gpt-6.1-sol', null],
    // The last colon separates the variant.
    ['a/b:c:d', 'a/b:c'],
    // A colon before the slash is not a variant.
    ['a:b/c', null],
    ['a/b:', null],
    ['a/:free', 'a/'],
    ['no-slash:free', null],
    ['~anthropic/claude-opus-latest:free', '~anthropic/claude-opus-latest'],
    ['', null],
  ])('%j → %j', (id, expected) => {
    expect(openRouterVariantBase(id)).toBe(expected);
  });
});

describe('parseModelId — openrouter', () => {
  it.each<[string, string]>([
    ['nvidia/nemotron-3-super-120b-a12b:free', 'nvidia/nemotron-3-super-120b-a12b:free'],
    // A dated id is kept whole: no date is split out for this vendor.
    ['openai/gpt-4o-2024-08-06', 'openai/gpt-4o-2024-08-06'],
    ['deepseek/deepseek-v4-pro-0813', 'deepseek/deepseek-v4-pro-0813'],
    ['~anthropic/claude-opus-latest', '~anthropic/claude-opus-latest'],
    ['openrouter/auto', 'openrouter/auto'],
    ['no-prefix', 'no-prefix'],
    ['openai/gpt-oss-120b\n', 'openai/gpt-oss-120b\n'],
  ])('%j is the whole modelName, version unknown', (id, name) => {
    expect(parseModelId('openrouter', id)).toEqual({ modelName: name, modelVersion: 'unknown' });
  });

  it('takes a string apiMetadata.modelVersion as the version hint, nothing else', () => {
    expect(parseModelId('openrouter', 'x/y', { modelVersion: 'v9' })).toEqual({
      modelName: 'x/y',
      modelVersion: 'v9',
    });
    expect(
      parseModelId('openrouter', 'x/y', { modelVersion: 9 as unknown as string }),
    ).toEqual({ modelName: 'x/y', modelVersion: 'unknown' });
  });
});

describe('importFromVendor — openrouter', () => {
  let known: KnownModelsReference;

  beforeAll(async () => {
    known = await loadKnownModels();
  });

  it('enriches a base id and names the maker by its author prefix', () => {
    const { descriptor, source, enriched } = importFromVendor({
      vendor: 'openrouter',
      modelId: 'meta-llama/llama-3.3-70b-instruct',
      knownModels: known,
    });
    expect(enriched).toBe(true);
    expect(source).toBe('openrouter-known-models');
    expect(descriptor.vendor).toBe('openrouter');
    expect(descriptor.modelName).toBe('meta-llama/llama-3.3-70b-instruct');
    expect(descriptor.modelVersion).toBe('unknown');
    expect(descriptor.trainedBy).toBe('meta-llama');
    expect(descriptor.license).toBe('llama3.3');
    expect(descriptor.modelType).toBe('llm');
    expect(descriptor.modelCardUrl).toBe('https://openrouter.ai/meta-llama/llama-3.3-70b-instruct');
    expect(descriptor.integrityTier).toBe('vendor-asserted');
    expect(descriptor.modelDigest).toBeNull();
  });

  it.each([
    ['nvidia/nemotron-3-super-120b-a12b:free', 'nvidia/nemotron-3-super-120b-a12b', 'nvidia-nemotron-open-model-license'],
    ['google/gemma-4-31b-it:free', 'google/gemma-4-31b-it', 'apache-2.0'],
    ['anthropic/claude-opus-5.5:batch', 'anthropic/claude-opus-5.5', 'anthropic-commercial'],
    ['deepseek/deepseek-v4.1-flash:batch', 'deepseek/deepseek-v4.1-flash', 'mit'],
  ])('%s enriches from %s and keeps the variant in modelName', (id, base, license) => {
    const { descriptor, source, enriched } = importFromVendor({
      vendor: 'openrouter',
      modelId: id,
      knownModels: known,
    });
    expect(enriched).toBe(true);
    expect(source).toBe('openrouter-known-models');
    expect(descriptor.modelName).toBe(id);
    expect(descriptor.modelVersion).toBe('unknown');
    expect(descriptor.license).toBe(license);
    expect(descriptor.modelCardUrl).toBe(`https://openrouter.ai/${base}`);
  });

  it('the variant and its base are distinct descriptors', () => {
    const base = importFromVendor({ vendor: 'openrouter', modelId: 'google/gemma-4-31b-it', knownModels: known });
    const free = importFromVendor({ vendor: 'openrouter', modelId: 'google/gemma-4-31b-it:free', knownModels: known });
    expect(free.descriptor).toEqual({ ...base.descriptor, modelName: 'google/gemma-4-31b-it:free' });
  });

  it('an exact :free entry wins over the base entry', () => {
    const ref: KnownModelsReference = {
      version: 'test',
      entries: [
        { vendor: 'openrouter', modelName: 'acme/m', modelVersion: 'unknown', license: 'base-license' },
        { vendor: 'openrouter', modelName: 'acme/m:free', modelVersion: 'unknown', license: 'free-license' },
      ],
    };
    const r = importFromVendor({ vendor: 'openrouter', modelId: 'acme/m:free', knownModels: ref });
    expect(r.enriched).toBe(true);
    expect(r.descriptor.license).toBe('free-license');
  });

  it('a variant of an unknown base is not enriched', () => {
    const r = importFromVendor({ vendor: 'openrouter', modelId: 'acme/unknown:free', knownModels: known });
    expect(r.enriched).toBe(false);
    expect(r.descriptor.modelName).toBe('acme/unknown:free');
    expect(r.descriptor.trainedBy).toBe('acme');
    expect(r.descriptor.license).toBeNull();
  });

  it('an alias is not enriched from its current target', () => {
    const r = importFromVendor({ vendor: 'openrouter', modelId: '~anthropic/claude-opus-latest', knownModels: known });
    expect(r.enriched).toBe(false);
    expect(r.descriptor.trainedBy).toBe('anthropic');
  });

  it('the variant fallback applies to openrouter only', () => {
    const ref: KnownModelsReference = {
      version: 'test',
      entries: [{ vendor: 'nvidia-nim', modelName: 'meta/m', modelVersion: 'unknown', license: 'x' }],
    };
    const r = importFromVendor({ vendor: 'nvidia-nim', modelId: 'meta/m:free', knownModels: ref });
    expect(r.enriched).toBe(false);
    expect(r.descriptor.trainedBy).toBeNull();
  });

  it('the bundled openrouter entries carry no trainedBy, so the author prefix stands', () => {
    const entries = known.entries.filter((e) => e.vendor === 'openrouter');
    expect(entries).toHaveLength(39);
    for (const e of entries) {
      expect(e.trainedBy).toBeUndefined();
      expect(e.integrityTier).toBeUndefined();
      expect(e.modelDigest).toBeUndefined();
      expect(e.parentModelDescriptorDigest).toBeUndefined();
      expect(e.derivation).toBeUndefined();
      expect(e.modelVersion).toBe('unknown');
      expect(e.modelType).toBe('llm');
      expect(typeof e.license).toBe('string');
      expect(e.modelCardUrl).toBe(`https://openrouter.ai/${e.modelName}`);
      // Base ids only: no variant and no alias.
      expect(openRouterVariantBase(e.modelName as string)).toBeNull();
      expect((e.modelName as string).startsWith('~')).toBe(false);
      // Every external identifier spells out all five keys, so the TS and
      // Python descriptors serialize to the same bytes.
      for (const id of e.externalIdentifiers ?? []) {
        expect(Object.keys(id).sort()).toEqual(['issuedAt', 'issuedBy', 'scheme', 'url', 'value']);
        expect(id.scheme).toBe('hf-repo');
        expect(id.url).toBe(`https://huggingface.co/${id.value}`);
      }
      // `<maker>-commercial` means the weights are not published, so such an
      // entry names no repository, and every other entry names exactly one.
      const commercial = (e.license as string).endsWith('-commercial');
      expect([e.modelName, (e.externalIdentifiers ?? []).length]).toEqual([e.modelName, commercial ? 0 : 1]);
    }
  });

  it('never takes the tier, digest, parent or derivation from an entry', () => {
    const ref: KnownModelsReference = {
      version: 'test',
      entries: [
        {
          vendor: 'openrouter',
          modelName: 'acme/m',
          modelVersion: 'unknown',
          integrityTier: 'weight-attested',
          modelDigest: `sha256:${'a'.repeat(64)}`,
          parentModelDescriptorDigest: `sha256:${'b'.repeat(64)}`,
          license: 'x',
        },
      ],
    };
    const r = importFromVendor({ vendor: 'openrouter', modelId: 'acme/m:free', knownModels: ref });
    expect(r.enriched).toBe(true);
    expect(r.descriptor.integrityTier).toBe('vendor-asserted');
    expect(r.descriptor.modelDigest).toBeNull();
    expect(r.descriptor.parentModelDescriptorDigest).toBeNull();
  });
});
