/**
 * OpenRouter gateway connector tests.
 *
 * Every request and response here is synthetic, on the shape of an OpenRouter
 * `/api/v1/chat/completions` response (`id`, `object`, `created`, `model`,
 * `provider`, `system_fingerprint`, `service_tier`, `choices[]`, `usage`);
 * generation ids, content and account fields are placeholders. Upstream
 * provider names are written the way OpenRouter reports them (`"Nvidia"`,
 * `"Google AI Studio"`); the connector records them verbatim, so the tests
 * do not depend on any particular spelling.
 *
 * The cases named after a fixture (`happy`, `optional_fields_populated`, ...)
 * use the values of the shared connector fixtures the cross-SDK parity gate
 * runs through both SDKs.
 */

import { aiBomViolation } from '@tzun/engine';
import {
  openRouterConnector,
  openRouterEndpoint,
  isOpenRouterBaseUrl,
} from '../../../src/sdk/connectors/openrouter';
import { AiBomSkeleton } from '../../../src/sdk/connectors/base';
import {
  loadKnownModels,
  KnownModelsReference,
} from '../../../src/models/known-models';

function okResponse(model: unknown, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'gen-0000000000-scrubbed000000000000',
    object: 'chat.completion',
    created: 1790000000,
    model,
    system_fingerprint: null,
    service_tier: null,
    choices: [
      {
        index: 0,
        finish_reason: 'stop',
        native_finish_reason: 'stop',
        logprobs: null,
        message: { role: 'assistant', content: 'approve', refusal: null, reasoning: null },
      },
    ],
    usage: { prompt_tokens: 10, completion_tokens: 1, total_tokens: 11 },
    ...extra,
  };
}

/** The skeleton as the wire `aiBom` it becomes, with a placeholder digest. */
function asWireAiBom(s: AiBomSkeleton): Record<string, unknown> {
  return {
    modelDescriptorDigest: `sha256:${'0'.repeat(64)}`,
    vendorFingerprint: s.vendorFingerprint,
    promptTemplate: s.promptTemplate,
    inferenceParameters: s.inferenceParameters,
    infrastructure: s.infrastructure,
  };
}

const HF = (repo: string) => ({
  scheme: 'hf-repo',
  value: repo,
  issuedBy: null,
  issuedAt: null,
  url: `https://huggingface.co/${repo}`,
});

describe('OpenRouter connector', () => {
  let known: KnownModelsReference;

  beforeAll(async () => {
    known = await loadKnownModels();
  });

  function build(params: Record<string, unknown>, response: Record<string, unknown>): AiBomSkeleton {
    const skel = openRouterConnector.buildAiBom(params, response, known);
    expect(skel).not.toBeNull();
    return skel as AiBomSkeleton;
  }

  it('exposes vendor = "openrouter"', () => {
    expect(openRouterConnector.vendor).toBe('openrouter');
  });

  // ── The shared fixture cases ───────────────────────────────────────

  it('happy: a :free Nemotron call through the gateway', () => {
    const s = build(
      {
        model: 'nvidia/nemotron-3-super-120b-a12b:free',
        messages: [{ role: 'user', content: 'Approve?' }],
        temperature: 0.2,
        max_tokens: 1200,
        openrouter_endpoint: 'https://openrouter.ai/api/v1',
      },
      okResponse('nvidia/nemotron-3-super-120b-a12b:free', { provider: 'Nvidia' }),
    );
    expect(s).toEqual({
      modelDescriptor: {
        descriptorVersion: 'd1',
        vendor: 'openrouter',
        modelName: 'nvidia/nemotron-3-super-120b-a12b:free',
        modelVersion: 'unknown',
        modelType: 'llm',
        integrityTier: 'vendor-asserted',
        modelDigest: null,
        parentModelDescriptorDigest: null,
        derivation: null,
        trainedBy: 'nvidia',
        license: 'nvidia-nemotron-open-model-license',
        modelCardUrl: 'https://openrouter.ai/nvidia/nemotron-3-super-120b-a12b',
        training: {
          trainingDataDigest: null,
          trainingDataRef: null,
          lastTrainingDate: null,
          evaluations: [],
        },
        regulatoryMarkings: [],
        externalIdentifiers: [HF('nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16')],
      },
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: {
        temperature: 0.2,
        topP: null,
        maxTokens: 1200,
        seed: null,
        stopSequences: null,
      },
      infrastructure: {
        provider: 'Nvidia',
        region: null,
        apiVersion: null,
        endpoint: 'https://openrouter.ai/api/v1',
      },
    });
  });

  it('optional_fields_populated: every parameter, a fingerprint and a provider', () => {
    const s = build(
      {
        model: 'google/gemini-3.8-flash',
        temperature: 0.7,
        top_p: 0.9,
        max_tokens: 256,
        seed: 42,
        stop: ['END', 'STOP'],
        openrouter_endpoint: 'https://openrouter.ai/api/v1',
      },
      okResponse('google/gemini-3.8-flash', {
        provider: 'Google AI Studio',
        system_fingerprint: 'fp_synthetic01',
      }),
    );
    expect(s.modelDescriptor.vendor).toBe('openrouter');
    expect(s.modelDescriptor.modelName).toBe('google/gemini-3.8-flash');
    expect(s.modelDescriptor.trainedBy).toBe('google');
    expect(s.modelDescriptor.license).toBe('google-commercial');
    expect(s.modelDescriptor.externalIdentifiers).toEqual([]);
    expect(s.vendorFingerprint).toBe('fp_synthetic01');
    expect(s.inferenceParameters).toEqual({
      temperature: 0.7,
      topP: 0.9,
      maxTokens: 256,
      seed: 42,
      stopSequences: ['END', 'STOP'],
    });
    expect(s.infrastructure).toEqual({
      provider: 'Google AI Studio',
      region: null,
      apiVersion: null,
      endpoint: 'https://openrouter.ai/api/v1',
    });
  });

  it('optional_fields_absent: no provider, fingerprint, usage, hint or parameters', () => {
    const response = okResponse('qwen/qwen3.8-27b');
    delete response.system_fingerprint;
    delete response.usage;
    const s = build({ model: 'qwen/qwen3.8-27b' }, response);
    expect(s.modelDescriptor.trainedBy).toBe('qwen');
    expect(s.modelDescriptor.license).toBe('apache-2.0');
    expect(s.vendorFingerprint).toBeNull();
    expect(s.inferenceParameters).toEqual({
      temperature: null,
      topP: null,
      maxTokens: null,
      seed: null,
      stopSequences: null,
    });
    // Always an object for this connector, with nothing assumed.
    expect(s.infrastructure).toEqual({
      provider: null,
      region: null,
      apiVersion: null,
      endpoint: null,
    });
  });

  it('zero_valued: zeros are kept, not dropped as falsy', () => {
    const s = build(
      { model: 'deepseek/deepseek-v4.1-flash', temperature: 0, top_p: 0, max_tokens: 0, seed: 0 },
      okResponse('deepseek/deepseek-v4.1-flash', { provider: 'DeepSeek' }),
    );
    expect(s.inferenceParameters).toEqual({
      temperature: 0,
      topP: 0,
      maxTokens: 0,
      seed: 0,
      stopSequences: null,
    });
    expect(s.infrastructure?.provider).toBe('DeepSeek');
    expect(s.modelDescriptor.license).toBe('mit');
  });

  it('stop_string: a string stop becomes a one-element array', () => {
    const s = build(
      { model: 'openai/gpt-5.4-mini', stop: 'END' },
      okResponse('openai/gpt-5.4-mini', { provider: 'OpenAI' }),
    );
    expect(s.inferenceParameters?.stopSequences).toEqual(['END']);
  });

  it('stop_over_limits: a stop list the AI-BOM cannot carry is null as a whole', () => {
    const s = build(
      { model: 'cohere/command-a-plus', stop: ['END', 'x'.repeat(257)] },
      okResponse('cohere/command-a-plus', { provider: 'Cohere' }),
    );
    expect(s.inferenceParameters?.stopSequences).toBeNull();
    expect(aiBomViolation(asWireAiBom(s))).toBeNull();
    // An open-weights entry: the license of the Hugging Face card, and its repo.
    expect(s.modelDescriptor.license).toBe('apache-2.0');
    expect(s.modelDescriptor.externalIdentifiers).toEqual([HF('CohereLabs/command-a-plus-05-2026-bf16')]);
  });

  it('alias_id: a ~alias is recorded verbatim, maker from its namespace, not enriched', () => {
    const s = build(
      { model: '~anthropic/claude-opus-latest' },
      okResponse('~anthropic/claude-opus-latest', { provider: 'Anthropic' }),
    );
    expect(s.modelDescriptor.modelName).toBe('~anthropic/claude-opus-latest');
    expect(s.modelDescriptor.modelVersion).toBe('unknown');
    expect(s.modelDescriptor.trainedBy).toBe('anthropic');
    expect(s.modelDescriptor.license).toBeNull();
    expect(s.modelDescriptor.modelCardUrl).toBeNull();
    expect(s.infrastructure?.provider).toBe('Anthropic');
  });

  it('router_id: an openrouter/* router names no maker and is not enriched', () => {
    const s = build({ model: 'openrouter/auto' }, okResponse('openrouter/auto'));
    expect(s.modelDescriptor.vendor).toBe('openrouter');
    expect(s.modelDescriptor.modelName).toBe('openrouter/auto');
    expect(s.modelDescriptor.trainedBy).toBeNull();
    expect(s.modelDescriptor.license).toBeNull();
  });

  it('endpoint_normalized: userinfo, query, fragment, trailing / and default port dropped, host lowercased', () => {
    const s = build(
      {
        model: 'openai/gpt-oss-120b',
        openrouter_endpoint: 'https://alice:pw@Gateway.Example.COM:443/api/v1/?trace=1#frag',
      },
      okResponse('openai/gpt-oss-120b', { provider: 'Nvidia' }),
    );
    expect(s.infrastructure?.endpoint).toBe('https://gateway.example.com/api/v1');
  });

  it('overlong_strings: a provider or endpoint over 256 UTF-16 code units is null', () => {
    const s = build(
      { model: 'minimax/minimax-m3', openrouter_endpoint: 'https://openrouter.ai/' + 'a'.repeat(250) },
      okResponse('minimax/minimax-m3', { provider: 'P'.repeat(257) }),
    );
    expect(s.infrastructure).toEqual({ provider: null, region: null, apiVersion: null, endpoint: null });
    // Exactly 256 is allowed.
    const at = build(
      { model: 'minimax/minimax-m3' },
      okResponse('minimax/minimax-m3', { provider: 'P'.repeat(256) }),
    );
    expect(at.infrastructure?.provider).toBe('P'.repeat(256));
    // UTF-16 code units, not code points: 128 astral characters are 256 units,
    // 129 are 258.
    const astral = '\u{1F600}';
    expect(
      build({ model: 'minimax/minimax-m3' }, okResponse('minimax/minimax-m3', { provider: astral.repeat(128) }))
        .infrastructure?.provider,
    ).toBe(astral.repeat(128));
    expect(
      build({ model: 'minimax/minimax-m3' }, okResponse('minimax/minimax-m3', { provider: astral.repeat(129) }))
        .infrastructure?.provider,
    ).toBeNull();
  });

  it('non_integer_tokens: a fractional max_tokens or seed is null', () => {
    const s = build(
      { model: 'z-ai/glm-5.3', max_tokens: 100.5, seed: 1.5 },
      okResponse('z-ai/glm-5.3', { provider: 'Z.AI' }),
    );
    expect(s.inferenceParameters?.maxTokens).toBeNull();
    expect(s.inferenceParameters?.seed).toBeNull();
  });

  // ── Parameter edges (unit tests only) ─────────────────────────────

  it.each([
    ['2^53 max_tokens', { max_tokens: 9007199254740992 }, 'maxTokens', null],
    ['negative max_tokens', { max_tokens: -1 }, 'maxTokens', null],
    ['string max_tokens', { max_tokens: '100' }, 'maxTokens', null],
    ['integral-float max_tokens', { max_tokens: 64.0 }, 'maxTokens', 64],
    ['max safe max_tokens', { max_tokens: 9007199254740991 }, 'maxTokens', 9007199254740991],
    ['negative seed', { seed: -7 }, 'seed', -7],
    ['min safe seed', { seed: -9007199254740991 }, 'seed', -9007199254740991],
    ['seed below -(2^53-1)', { seed: -9007199254740992 }, 'seed', null],
    ['boolean seed', { seed: true }, 'seed', null],
    ['NaN temperature', { temperature: NaN }, 'temperature', null],
    ['Infinity top_p', { top_p: Infinity }, 'topP', null],
    ['string temperature', { temperature: '0.5' }, 'temperature', null],
    ['empty stop array', { stop: [] }, 'stopSequences', null],
    ['stop array with non-strings', { stop: ['A', 1, null, 'B'] }, 'stopSequences', ['A', 'B']],
    ['stop number', { stop: 5 }, 'stopSequences', null],
    // The AI-BOM bound: at most 16 stop sequences of at most 256 UTF-16 code
    // units each, counted after non-strings are dropped; past it, null.
    ['16 stops', { stop: Array(16).fill('S') }, 'stopSequences', Array(16).fill('S')],
    ['17 stops', { stop: Array(17).fill('S') }, 'stopSequences', null],
    ['16 stops and a non-string', { stop: [...Array(16).fill('S'), 7] }, 'stopSequences', Array(16).fill('S')],
    ['a 256-unit stop', { stop: 'x'.repeat(256) }, 'stopSequences', ['x'.repeat(256)]],
    ['a 257-unit stop', { stop: 'x'.repeat(257) }, 'stopSequences', null],
    ['one 257-unit stop among short ones', { stop: ['END', 'x'.repeat(257)] }, 'stopSequences', null],
    ['128 astral characters (256 units)', { stop: ['\u{1F600}'.repeat(128)] }, 'stopSequences', ['\u{1F600}'.repeat(128)]],
    ['129 astral characters (258 units)', { stop: ['\u{1F600}'.repeat(129)] }, 'stopSequences', null],
  ])('%s', (_label, extra, member, expected) => {
    const s = build({ model: 'openai/gpt-5.4-mini', ...extra }, okResponse('openai/gpt-5.4-mini'));
    expect((s.inferenceParameters as Record<string, unknown>)[member]).toEqual(expected);
  });

  it('every skeleton passes the engine aiBom exact-members rule', () => {
    const cases: Array<[Record<string, unknown>, Record<string, unknown>]> = [
      [{ max_tokens: 100.5, seed: 1.5 }, { provider: 'x'.repeat(300) }],
      [{ max_tokens: -1, seed: 2 ** 53, openrouter_endpoint: 'https://openrouter.ai/' + 'a'.repeat(300) }, {}],
      [{ temperature: 0, top_p: 0, max_tokens: 0, seed: 0, stop: 'END' }, { provider: 'Nvidia' }],
      [{ openrouter_endpoint: 'ftp://openrouter.ai' }, { provider: 42 }],
      [{ stop: Array(17).fill('S') }, {}],
      [{ stop: ['x'.repeat(300)] }, {}],
    ];
    for (const [params, extra] of cases) {
      const s = build({ model: 'qwen/qwen3.8-27b', ...params }, okResponse('qwen/qwen3.8-27b', extra));
      expect(aiBomViolation(asWireAiBom(s))).toBeNull();
    }
  });

  // ── No AI-BOM without a served model ──────────────────────────────

  it('returns null when the response has no model', () => {
    const response = okResponse('x');
    delete response.model;
    expect(openRouterConnector.buildAiBom({ model: 'openai/gpt-5.4-mini' }, response, known)).toBeNull();
  });

  it('returns null when response.model is empty or not a string', () => {
    expect(openRouterConnector.buildAiBom({ model: 'openai/gpt-5.4-mini' }, okResponse(''), known)).toBeNull();
    expect(openRouterConnector.buildAiBom({ model: 'openai/gpt-5.4-mini' }, okResponse(42), known)).toBeNull();
    expect(openRouterConnector.buildAiBom({ model: 'openai/gpt-5.4-mini' }, okResponse(null), known)).toBeNull();
  });

  it('records the served model, never the requested one', () => {
    // A fallback list or a router: the gateway served another model.
    const s = build(
      { model: 'openrouter/auto', models: ['anthropic/claude-opus-5.5', 'openai/gpt-6-astra'] },
      okResponse('openai/gpt-6-astra', { provider: 'OpenAI' }),
    );
    expect(s.modelDescriptor.modelName).toBe('openai/gpt-6-astra');
    expect(s.modelDescriptor.trainedBy).toBe('openai');
    expect(s.modelDescriptor.license).toBe('openai-commercial');
  });

  it('is deterministic: the same input twice gives deep-equal output', () => {
    const params = { model: 'x-ai/grok-4.7', temperature: 0.1, openrouter_endpoint: 'https://openrouter.ai/api/v1/' };
    const response = okResponse('x-ai/grok-4.7', { provider: 'xAI' });
    expect(openRouterConnector.buildAiBom(params, response, known)).toEqual(
      openRouterConnector.buildAiBom(params, response, known),
    );
  });

  // ── Every major vendor through the gateway ─────────────────────────

  /**
   * One served id per major author on OpenRouter, with the license the
   * bundled entry gives it (null: no entry, so the descriptor is truthful but
   * unenriched). Provider names are illustrative; the connector copies them.
   */
  const majorVendors: Array<[author: string, served: string, provider: string, license: string | null]> = [
    ['openai', 'openai/gpt-6.1-sol', 'OpenAI', 'openai-commercial'],
    ['openai', 'openai/gpt-oss-120b', 'Nvidia', 'apache-2.0'],
    ['anthropic', 'anthropic/claude-sonnet-5.5', 'Anthropic', 'anthropic-commercial'],
    ['google', 'google/gemini-4-argon', 'Google Vertex', 'google-commercial'],
    ['google', 'google/gemma-4-31b-it:free', 'Google AI Studio', 'apache-2.0'],
    ['meta-llama', 'meta-llama/llama-4-maverick', 'Groq', 'llama4'],
    ['meta', 'meta/muse-spark-1.3', 'Meta', 'meta-commercial'],
    ['meta', 'meta/muse-glimmer-30b', 'Meta', 'apache-2.0'],
    // A major author's id without an entry: truthful, unenriched.
    ['meta', 'meta/muse-spark-1.3-contributor', 'Meta', null],
    ['mistralai', 'mistralai/mistral-large-4-0', 'Mistral', 'mistral-commercial'],
    ['mistralai', 'mistralai/mistral-medium-3-5:batch', 'Mistral', 'mistral-modified-mit'],
    ['x-ai', 'x-ai/grok-4.7', 'xAI', 'xai-commercial'],
    ['deepseek', 'deepseek/deepseek-v4-pro-0813', 'DeepSeek', 'mit'],
    ['qwen', 'qwen/qwen3.8-2.4t-a95b', 'Alibaba', 'qwen3.8-max'],
    ['nvidia', 'nvidia/nemotron-3-ultra-550b-a55b:free', 'Nvidia', 'openmdw-1.1'],
    ['microsoft', 'microsoft/phi-4', 'DeepInfra', 'mit'],
    ['amazon', 'amazon/nova-premier-v1', 'Amazon Bedrock', 'amazon-commercial'],
    ['cohere', 'cohere/command-a', 'Cohere', 'cc-by-nc-4.0'],
    ['cohere', 'cohere/command-a-plus', 'Cohere', 'apache-2.0'],
    ['moonshotai', 'moonshotai/kimi-k3', 'Moonshot AI', 'kimi-k3'],
    ['z-ai', 'z-ai/glm-5.3-flash', 'Z.AI', 'mit'],
    ['minimax', 'minimax/minimax-m3', 'Minimax', 'minimax-community'],
  ];

  it.each(majorVendors)('%s: %s via %s', (author, served, provider, license) => {
    const s = build(
      { model: served, openrouter_endpoint: 'https://openrouter.ai/api/v1' },
      okResponse(served, { provider }),
    );
    const d = s.modelDescriptor;
    // Served by the gateway, made by the author, run by the upstream.
    expect(d.vendor).toBe('openrouter');
    expect(d.modelName).toBe(served);
    expect(d.modelVersion).toBe('unknown');
    expect(d.trainedBy).toBe(author);
    expect(d.integrityTier).toBe('vendor-asserted');
    expect(d.modelDigest).toBeNull();
    expect(d.license).toBe(license);
    if (license !== null) {
      expect(d.modelType).toBe('llm');
      const base = served.includes(':') ? served.slice(0, served.lastIndexOf(':')) : served;
      expect(d.modelCardUrl).toBe(`https://openrouter.ai/${base}`);
    }
    expect(s.infrastructure).toEqual({
      provider,
      region: null,
      apiVersion: null,
      endpoint: 'https://openrouter.ai/api/v1',
    });
  });

  it('open-weights entries name their Hugging Face repo; closed ones name none', () => {
    const open = build({}, okResponse('meta-llama/llama-3.3-70b-instruct'));
    expect(open.modelDescriptor.externalIdentifiers).toEqual([HF('meta-llama/Llama-3.3-70B-Instruct')]);
    const closed = build({}, okResponse('anthropic/claude-opus-5.5'));
    expect(closed.modelDescriptor.externalIdentifiers).toEqual([]);
  });

  // ── Unknown authors: no false vendor, no false maker ───────────────

  it.each([
    ['unbiased/pareto-26.9', 'unbiased'],
    ['tencent/hunyuan-a13b-instruct', 'tencent'],
    ['some-new-lab/model-x', 'some-new-lab'],
  ])('unknown author %s: vendor stays openrouter, maker is the prefix, nothing enriched', (served, author) => {
    const s = build({}, okResponse(served, { provider: 'Some Host' }));
    expect(s.modelDescriptor.vendor).toBe('openrouter');
    expect(s.modelDescriptor.trainedBy).toBe(author);
    expect(s.modelDescriptor.license).toBeNull();
    expect(s.modelDescriptor.modelType).toBeNull();
    expect(s.modelDescriptor.modelCardUrl).toBeNull();
    expect(s.modelDescriptor.externalIdentifiers).toEqual([]);
  });

  it.each(['no-prefix', '/leading-slash', '~', ''])(
    'an id with no author prefix (%j) names no maker',
    (served) => {
      const skel = openRouterConnector.buildAiBom({}, okResponse(served), known);
      if (served === '') {
        expect(skel).toBeNull();
        return;
      }
      expect((skel as AiBomSkeleton).modelDescriptor.trainedBy).toBeNull();
      expect((skel as AiBomSkeleton).modelDescriptor.vendor).toBe('openrouter');
    },
  );

  it('an author that is also a vendor label elsewhere does not become that vendor', () => {
    // `amazon/*` is not a Bedrock call, `nvidia/*` not a NIM call, `openai/*`
    // not an OpenAI call: the gateway served them.
    for (const served of ['amazon/nova-2-lite-v1', 'nvidia/nemotron-3.5-lightning', 'openai/gpt-6-luna']) {
      const s = build({}, okResponse(served, { provider: 'Upstream' }));
      expect(s.modelDescriptor.vendor).toBe('openrouter');
      expect(s.infrastructure?.provider).toBe('Upstream');
    }
  });

  // ── No infrastructure the gateway did not report ───────────────────

  it('claims no infrastructure it was not told about', () => {
    const s = build(
      {
        model: 'nvidia/nemotron-3-super-120b-a12b',
        // Routing preferences are a request option, not the upstream that ran it.
        provider: { order: ['Nvidia'], allow_fallbacks: false },
        // Other connectors' hint keys are not this connector's endpoint.
        azure_endpoint: 'https://example.openai.azure.com',
        nim_endpoint: 'https://integrate.api.nvidia.com/v1',
        base_url: 'https://openrouter.ai/api/v1',
        api_version: '2024-10-21',
        azure_region: 'eastus',
        region: 'us-east-1',
      },
      okResponse('nvidia/nemotron-3-super-120b-a12b'),
    );
    expect(s.infrastructure).toEqual({ provider: null, region: null, apiVersion: null, endpoint: null });
  });

  it('never names the gateway or the maker as the provider', () => {
    const s = build({ openrouter_endpoint: 'https://openrouter.ai/api/v1' }, okResponse('google/gemini-4-argon'));
    expect(s.infrastructure?.provider).toBeNull();
    expect(s.infrastructure?.provider).not.toBe('openrouter');
    expect(s.infrastructure?.provider).not.toBe('google');
  });

  it('takes the provider from the response only, verbatim', () => {
    expect(build({}, okResponse('openai/gpt-6-astra', { provider: 'Azure' })).infrastructure?.provider).toBe('Azure');
    expect(build({}, okResponse('openai/gpt-6-astra', { provider: '' })).infrastructure?.provider).toBeNull();
    expect(build({}, okResponse('openai/gpt-6-astra', { provider: 42 })).infrastructure?.provider).toBeNull();
    expect(build({}, okResponse('openai/gpt-6-astra', { provider: { name: 'Azure' } })).infrastructure?.provider).toBeNull();
    expect(build({}, okResponse('openai/gpt-6-astra', { provider: null })).infrastructure?.provider).toBeNull();
  });

  it('vendorFingerprint is system_fingerprint only, never the generation id or provider', () => {
    const s = build({}, okResponse('openai/gpt-6-astra', { provider: 'OpenAI', system_fingerprint: null }));
    expect(s.vendorFingerprint).toBeNull();
    const n = build({}, okResponse('openai/gpt-6-astra', { system_fingerprint: 7 }));
    expect(n.vendorFingerprint).toBeNull();
  });
});

describe('openRouterEndpoint', () => {
  it.each<[unknown, string | null]>([
    ['https://openrouter.ai/api/v1', 'https://openrouter.ai/api/v1'],
    // openai-python's base_url carries a trailing slash; both SDKs record the same.
    ['https://openrouter.ai/api/v1/', 'https://openrouter.ai/api/v1'],
    ['https://openrouter.ai/api/v1///', 'https://openrouter.ai/api/v1'],
    ['https://openrouter.ai', 'https://openrouter.ai'],
    ['https://openrouter.ai/', 'https://openrouter.ai'],
    ['http://localhost:8080/v1', 'http://localhost:8080/v1'],
    // The host's ASCII letters are lowercased and the scheme's default port is
    // dropped, as openai-python's httpx.URL does; any other port, and the
    // path's case, are kept.
    ['https://OpenRouter.AI:443/api/v1', 'https://openrouter.ai/api/v1'],
    ['https://OpenRouter.AI:443/api/v1/', 'https://openrouter.ai/api/v1'],
    ['https://openrouter.ai:443', 'https://openrouter.ai'],
    ['http://openrouter.ai:80/x', 'http://openrouter.ai/x'],
    ['http://openrouter.ai:443/x', 'http://openrouter.ai:443/x'],
    ['https://openrouter.ai:80/x', 'https://openrouter.ai:80/x'],
    ['https://openrouter.ai:8443/api/v1', 'https://openrouter.ai:8443/api/v1'],
    ['https://openrouter.ai:1443/api/v1', 'https://openrouter.ai:1443/api/v1'],
    ['https://[::1]:443/api/v1', 'https://[::1]/api/v1'],
    ['https://Gateway.Example.COM/API/V1', 'https://gateway.example.com/API/V1'],
    ['https://Key:@OpenRouter.AI/api/v1', 'https://openrouter.ai/api/v1'],
    // Only ASCII letters: other characters are kept as given.
    ['https://\u0130penrouter.ai/v1', 'https://\u0130penrouter.ai/v1'],
    ['https://:443/api/v1', null],
    ['https://openrouter.ai?x=1', 'https://openrouter.ai'],
    ['https://openrouter.ai/api/v1#frag', 'https://openrouter.ai/api/v1'],
    ['https://openrouter.ai/api/v1/?a=b/c#d', 'https://openrouter.ai/api/v1'],
    // Userinfo is dropped (written with an empty password here: `user:@host`).
    ['https://user:@openrouter.ai/api/v1', 'https://openrouter.ai/api/v1'],
    ['https://a@b:c:@openrouter.ai/api/v1', 'https://openrouter.ai/api/v1'],
    // The scheme match is case-sensitive.
    ['HTTPS://openrouter.ai/api/v1', null],
    ['ftp://openrouter.ai/api/v1', null],
    ['openrouter.ai/api/v1', null],
    ['https://', null],
    ['https:///api/v1', null],
    ['https://user@/api/v1', null],
    ['https://?q', null],
    ['', null],
    [null, null],
    [undefined, null],
    [42, null],
    [{ href: 'https://openrouter.ai/api/v1' }, null],
  ])('%j → %j', (input, expected) => {
    expect(openRouterEndpoint(input)).toBe(expected);
  });

  it('allows exactly 256 UTF-16 code units and refuses 257', () => {
    const prefix = 'https://openrouter.ai/';
    const at = prefix + 'a'.repeat(256 - prefix.length);
    expect(openRouterEndpoint(at)).toBe(at);
    expect(openRouterEndpoint(at + 'a')).toBeNull();
    // Trailing slashes are stripped before the length is measured.
    expect(openRouterEndpoint(at + '/')).toBe(at);
  });
});

describe('isOpenRouterBaseUrl', () => {
  it.each<[unknown, boolean]>([
    ['https://openrouter.ai/api/v1', true],
    ['https://openrouter.ai/api/v1/', true],
    ['https://openrouter.ai', true],
    ['http://openrouter.ai/api/v1', true],
    ['https://OpenRouter.AI/api/v1', true],
    ['https://openrouter.ai:443/api/v1', true],
    ['https://key:@openrouter.ai/api/v1', true],
    ['https://openrouter.ai?x=1', true],
    // A subdomain is OpenRouter's too: the data-region hosts among them.
    ['https://eu.openrouter.ai/api/v1', true],
    ['https://us.openrouter.ai/api/v1', true],
    ['https://EU.OpenRouter.AI:443/api/v1', true],
    ['https://api.openrouter.ai/v1', true],
    ['https://a.b-c.openrouter.ai/v1', true],
    // One trailing dot: the fully qualified form of the same host.
    ['https://openrouter.ai./api/v1', true],
    ['https://eu.openrouter.ai.:443/api/v1', true],
    ['https://openrouter.ai../api/v1', false],
    ['https://.openrouter.ai/api/v1', false],
    ['https://eu..openrouter.ai/api/v1', false],
    ['https://eu_1.openrouter.ai/api/v1', false],
    ['https://evil.example.com\\.openrouter.ai/v1', false],
    ['https://notopenrouter.ai/api/v1', false],
    ['https://eu.openrouter.ai.example.com/api/v1', false],
    ['https://api.openai.com/v1', false],
    ['https://openrouter.ai.example.com/api/v1', false],
    ['https://openrouter.ai@gateway.example.com/api/v1', false],
    ['https://gateway.example.com/openrouter.ai', false],
    ['https://gateway.example.com/?u=openrouter.ai', false],
    ['openrouter.ai', false],
    ['HTTPS://openrouter.ai', false],
    ['', false],
    [undefined, false],
    [null, false],
    [123, false],
  ])('%j → %s', (input, expected) => {
    expect(isOpenRouterBaseUrl(input)).toBe(expected);
  });
});
