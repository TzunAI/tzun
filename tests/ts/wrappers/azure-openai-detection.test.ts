import { modelOf } from '../helpers/step-model';
/**
 * Azure OpenAI captures made through attach() are recorded as Azure, not as
 * direct OpenAI.
 *
 * `isAzure(params)` (src/sdk/connectors/openai.ts) tests `params.__tzunIsAzure`
 * and `params.azure_endpoint`. The openai package keeps the endpoint,
 * deployment and api-version on the client INSTANCE (`AzureOpenAI` sets
 * `this.baseURL` / `this.deploymentName` / `this.apiVersion`), never in the
 * `chat.completions.create` payload, so attach() reads them off the instance
 * (`extractAzureClientHints`) and hands them to the connector with the call
 * kwargs. Forwarding the call kwargs alone would give a regulated customer
 * running every inference through Azure OpenAI in a named region for
 * data-residency reasons `infrastructure: null` — no endpoint, no region,
 * no API version — the one fact their auditor asks for.
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests, extractAzureClientHints } from '../../../src/sdk/wrappers';
import type { AiBom } from '@tzun/engine';

class AzureOpenAI {
  baseURL = 'https://contoso.openai.azure.com';
  apiVersion = '2024-08-01-preview';
  deploymentName = 'gpt4o-swedencentral';
  chat = {
    completions: {
      create: jest.fn().mockResolvedValue({
        id: 'chatcmpl-test',
        choices: [{ index: 0, message: { role: 'assistant', content: 'Approve.' } }],
        model: 'gpt-4o-2024-08-06',
      }),
    },
  };
}

function plainOpenAI() {
  return {
    baseURL: 'https://api.openai.com/v1',
    chat: {
      completions: {
        create: jest.fn().mockResolvedValue({
          id: 'chatcmpl-test',
          choices: [{ index: 0, message: { role: 'assistant', content: 'Approve.' } }],
          model: 'gpt-4o-2024-08-06',
          system_fingerprint: 'fp_abc',
        }),
      },
    },
  };
}

describe('Azure OpenAI detection through attach()', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });
  afterEach(async () => {
    await tzun.close();
  });

  it('reads the Azure facts off the client instance', () => {
    expect(extractAzureClientHints(new AzureOpenAI())).toEqual({
      __tzunIsAzure: true,
      azure_endpoint: 'https://contoso.openai.azure.com',
      api_version: '2024-08-01-preview',
      azure_deployment: 'gpt4o-swedencentral',
    });
  });

  it('leaves a plain OpenAI client untouched', () => {
    expect(extractAzureClientHints(plainOpenAI())).toEqual({});
  });

  it('records the Azure endpoint and API version in the captured AI-BOM', async () => {
    const wrapped = tzun.attach(new AzureOpenAI(), { vendor: 'openai' });

    const captureSpy = jest.spyOn(tzun, 'capture');
    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: {
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        action: 'approved',
        reason: 'looks right',
      },
    });

    expect(captureSpy).toHaveBeenCalledTimes(1);
    const aiBom = modelOf(captureSpy.mock.calls[0]![0]!) as AiBom;
    expect(aiBom.infrastructure).not.toBeNull();
    expect(aiBom.infrastructure!.endpoint).toBe('https://contoso.openai.azure.com');
    expect(aiBom.infrastructure!.apiVersion).toBe('2024-08-01-preview');
  });

  it('a direct OpenAI capture still has no infrastructure block', async () => {
    const wrapped = tzun.attach(plainOpenAI());

    const captureSpy = jest.spyOn(tzun, 'capture');
    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const aiBom = modelOf(captureSpy.mock.calls[0]![0]!) as AiBom;
    expect(aiBom.infrastructure).toBeNull();
  });
});
