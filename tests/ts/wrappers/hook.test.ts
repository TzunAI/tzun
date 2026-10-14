/**
 * `Tzun#hook(vendor, request, response)` core tests.
 *
 * Covers the public `hook()` surface: vendor dispatch,
 * null-result for no-AI-BOM, unknown-vendor error path, and the
 * no-implicit-capture guarantee.
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests } from '../../../src/sdk/wrappers';
import type { AiBom } from '@tzun/engine';

describe('Tzun#hook', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  describe('exports', () => {
    it('exposes a hook(vendor, request, response) method on Tzun', () => {
      expect(typeof tzun.hook).toBe('function');
    });

    it('hook() returns a Promise', () => {
      const promise = tzun.hook(
        'openai',
        { model: 'gpt-4o-2024-08-06' },
        { model: 'gpt-4o-2024-08-06', id: 'cmpl' },
      );
      expect(promise).toBeInstanceOf(Promise);
      // Drain it so we don't leak an unhandled rejection if it fails.
      return promise.catch(() => undefined);
    });
  });

  describe('hook() returns a populated AI-BOM for valid input', () => {
    it('returns a non-null AiBom for an OpenAI call', async () => {
      const aiBom = (await tzun.hook(
        'openai',
        {
          model: 'gpt-4o-2024-08-06',
          temperature: 0.3,
          max_tokens: 256,
          messages: [{ role: 'user', content: 'hi' }],
        },
        {
          id: 'chatcmpl-x',
          model: 'gpt-4o-2024-08-06',
          system_fingerprint: 'fp_xyz',
          choices: [],
        },
      )) as AiBom;
      expect(aiBom).not.toBeNull();
      expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
      expect(aiBom.vendorFingerprint).toBe('fp_xyz');
      expect(aiBom.inferenceParameters?.temperature).toBe(0.3);
      expect(aiBom.inferenceParameters?.maxTokens).toBe(256);
    });
  });

  describe('no-aibom: connector returning null skeleton causes hook() to return null', () => {
    it('returns null when the connector cannot extract a model', async () => {
      // No `model` field on the response — OpenAI connector returns null.
      const result = await tzun.hook(
        'openai',
        { input: 'hello' },
        { id: 'chatcmpl-no-model', choices: [] },
      );
      expect(result).toBeNull();
    });
  });

  describe('unknown-vendor: hook() throws with a helpful message listing supported vendors', () => {
    it('throws on unknown vendor with all seven vendors named in the message', async () => {
      await expect(tzun.hook('does-not-exist', {}, {})).rejects.toThrow(
        /openai.*anthropic.*bedrock.*vertex.*azure-ai.*nvidia-nim.*hf-inference/,
      );
    });

    it('throws with an Error mentioning the unknown vendor', async () => {
      await expect(tzun.hook('made-up-vendor', {}, {})).rejects.toThrow(
        /Unknown vendor.*made-up-vendor/,
      );
    });
  });

  describe('no-implicit-capture: hook() does not persist an envelope', () => {
    it('calling hook() alone does not register an evidence envelope', async () => {
      await tzun.hook(
        'openai',
        {
          model: 'gpt-4o-2024-08-06',
          messages: [{ role: 'user', content: 'hi' }],
        },
        {
          id: 'chatcmpl-x',
          model: 'gpt-4o-2024-08-06',
          choices: [],
        },
      );
      const records = await tzun.list({});
      expect(records).toEqual([]);
    });
  });
});
