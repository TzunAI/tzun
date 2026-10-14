/**
 * `Tzun#hook` LRU cache behavior tests.
 *
 * Verifies that calling `hook()` repeatedly with the same vendor/model only
 * registers the descriptor once — the per-Tzun-instance LRU cache
 * short-circuits the catalog registration for subsequent calls.
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests } from '../../../src/sdk/wrappers';

describe('Tzun#hook — LRU cache', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('same vendor + model called 100x registers descriptor once', async () => {
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );

    const request = {
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
    };
    const response = {
      id: 'chatcmpl-x',
      model: 'gpt-4o-2024-08-06',
      system_fingerprint: 'fp_xyz',
      choices: [],
    };

    for (let i = 0; i < 100; i++) {
      await tzun.hook('openai', request, response);
    }

    expect(registerSpy).toHaveBeenCalledTimes(1);
  });
});
