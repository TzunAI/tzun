// tests/ts/wrappers/attach-preservation.test.ts — attach() keeps the client's prototype
// chain, own properties, getters and non-intercepted methods.
import { Tzun } from '../../../src/sdk/index';

class FakeClient {
  apiKey = 'k-123';
  private secret = 'own-prop';
  chat = { completions: { create: async () => ({ model: 'gpt-4o-2024-08-06' }) } };
  get masked(): string { return this.apiKey.slice(0, 2) + '***'; }
  helper(): string { return 'proto-method'; }
}

describe('attach() preservation', () => {
  it('preserves prototype chain, own props, getters, and non-intercepted methods', async () => {
    const tzun = await Tzun.init();
    const original = new FakeClient();
    const wrapped = tzun.attach(original);
    expect(wrapped).toBeInstanceOf(FakeClient);                    // (a) prototype chain
    expect(wrapped.apiKey).toBe('k-123');                          // (b) own props by value
    expect(wrapped.helper()).toBe('proto-method');                 // (c) prototype dispatch
    expect(wrapped.masked).toBe('k-***');                          // getter still works
    expect(wrapped.chat.completions.create).not.toBe(original.chat.completions.create); // (d) wrapper-only replace
    const fresh = new FakeClient();
    expect(fresh.chat.completions.create).toBeDefined();           // original class untouched
  });
});
