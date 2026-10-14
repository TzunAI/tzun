/**
 * `attach()` keeps the prototypes of nested vendor resources.
 *
 * `attachClient` rebuilds the nested vendor resources it intercepts
 * (`chat`, `chat.completions`, `messages`). Vendor SDKs put their resource
 * methods on the class prototype — openai@4.104.0 defines
 * `retrieve/update/list/del` on `Completions.prototype`, Anthropic puts
 * `stream` on `Messages.prototype` — and object spread copies own enumerable
 * properties only. A rebuild by spread would drop every non-intercepted
 * method from the wrapped client and leave the resulting object's prototype
 * as plain `Object.prototype`.
 *
 * A developer who wraps their client once at startup
 * (`const openai = tzun.attach(new OpenAI(...))`) and later calls
 * `openai.chat.completions.list()` would get `TypeError: ... is not a
 * function` in production. The preservation test
 * (attach-preservation.test.ts) checks only the ROOT object's prototype, with
 * a plain-object fake, so it cannot see the nested resources; these fakes are
 * class-based.
 */
import { Tzun } from '../../../src/sdk/index';

// Class-based, like the real SDKs: only `create` is an own property; the rest
// live on the prototype, where spread cannot reach them.
class Completions {
  ownFlag = 'own';
  create = async (): Promise<unknown> => ({ model: 'gpt-4o-2024-08-06' });
  retrieve(): string { return 'retrieve'; }
  update(): string { return 'update'; }
  list(): string { return 'list'; }
  del(): string { return 'del'; }
}
class Chat {
  completions = new Completions();
  someChatProtoMethod(): string { return 'chat-proto'; }
}
class FakeOpenAI {
  apiKey = 'k-123';
  chat = new Chat();
}

class Messages {
  create = async (): Promise<unknown> => ({ model: 'claude-3-5-sonnet-20241022' });
  stream(): string { return 'stream'; }
  countTokens(): string { return 'count'; }
}
class FakeAnthropic {
  apiKey = 'k-456';
  messages = new Messages();
}

describe('attach() preserves nested resource prototypes', () => {
  it('keeps every prototype method of chat.completions (openai shape)', async () => {
    const tzun = await Tzun.init();
    const original = new FakeOpenAI();
    const wrapped = tzun.attach(original);

    // The intercept is still installed …
    expect(wrapped.chat.completions.create).not.toBe(original.chat.completions.create);
    // … and nothing else was lost.
    expect(typeof wrapped.chat.completions.retrieve).toBe('function');
    expect(typeof wrapped.chat.completions.update).toBe('function');
    expect(typeof wrapped.chat.completions.list).toBe('function');
    expect(typeof wrapped.chat.completions.del).toBe('function');
    expect(wrapped.chat.completions.list()).toBe('list');

    // Own props survive too, and the prototype identity is the real one.
    expect(wrapped.chat.completions.ownFlag).toBe('own');
    expect(Object.getPrototypeOf(wrapped.chat.completions)).toBe(
      Object.getPrototypeOf(original.chat.completions),
    );
    expect(wrapped.chat.completions).toBeInstanceOf(Completions);
  });

  it('keeps chat\'s own prototype methods, not just completions\'', async () => {
    const tzun = await Tzun.init();
    const wrapped = tzun.attach(new FakeOpenAI());
    expect(typeof wrapped.chat.someChatProtoMethod).toBe('function');
    expect(wrapped.chat.someChatProtoMethod()).toBe('chat-proto');
    expect(wrapped.chat).toBeInstanceOf(Chat);
  });

  it('keeps every prototype method of messages (anthropic shape)', async () => {
    const tzun = await Tzun.init();
    const original = new FakeAnthropic();
    const wrapped = tzun.attach(original);

    expect(wrapped.messages.create).not.toBe(original.messages.create);
    expect(typeof wrapped.messages.stream).toBe('function');
    expect(typeof wrapped.messages.countTokens).toBe('function');
    expect(wrapped.messages.stream()).toBe('stream');
    expect(Object.getPrototypeOf(wrapped.messages)).toBe(
      Object.getPrototypeOf(original.messages),
    );
    expect(wrapped.messages).toBeInstanceOf(Messages);
  });

  it('does not mutate the original client', async () => {
    const tzun = await Tzun.init();
    const original = new FakeOpenAI();
    const originalCreate = original.chat.completions.create;
    tzun.attach(original);
    expect(original.chat.completions.create).toBe(originalCreate);
    expect(new FakeOpenAI().chat.completions.create).toBeDefined();
  });
});
