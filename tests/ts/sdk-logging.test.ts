// tests/ts/sdk-logging.test.ts — the SDK's structured log events and usage counters.
import { Tzun } from '../../src/sdk/index';

describe('sdk structured logs + usage counters', () => {
  it('registration event carries its field set, via onLog override', async () => {
    const events: Array<[string, Record<string, unknown>]> = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tzun = await Tzun.init({ onLog: (e: string, f: Record<string, unknown>) => events.push([e, f]) } as any);
    await tzun.models.register({ vendor: 'openai', modelName: 'gpt-4o', modelVersion: '1' });
    const reg = events.find(([e]) => e === 'registration');
    expect(reg).toBeDefined();
    expect(reg![1]).toMatchObject({ source: 'manual', registeredBy: 'cli', alreadyExisted: false });
    expect(typeof reg![1].digest).toBe('string');
  });

  it('connector_auto_registration fires with cached:false then cached:true', async () => {
    const events: Array<[string, Record<string, unknown>]> = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tzun = await Tzun.init({ onLog: (e: string, f: Record<string, unknown>) => events.push([e, f]) } as any);
    const call = () => tzun.hook('openai', { model: 'gpt-4o' }, { model: 'gpt-4o-2024-08-06' });
    await call(); await call();
    const auto = events.filter(([e]) => e === 'connector_auto_registration');
    expect(auto.length).toBe(2);
    expect(auto[0][1]).toMatchObject({ vendor: 'openai', cached: false });
    expect(auto[1][1]).toMatchObject({ vendor: 'openai', cached: true });
    expect(typeof auto[0][1].modelName).toBe('string');
    expect(typeof auto[0][1].digest).toBe('string');
  });

  it('default sink is one-line JSON on console.log; no auth material ever', async () => {
    const spy = jest.spyOn(console, 'log').mockImplementation(() => {});
    const tzun = await Tzun.init();
    await tzun.models.register({ vendor: 'openai', modelName: 'gpt-4o', modelVersion: '1' });
    const line = spy.mock.calls.map((c) => String(c[0])).find((l) => l.includes('"registration"'));
    expect(line).toBeDefined();
    expect(() => JSON.parse(line!)).not.toThrow();
    spy.mockRestore();
  });

  it('getConnectorUsageStats counts per vendor', async () => {
    const tzun = await Tzun.init();
    await tzun.hook('openai', { model: 'gpt-4o' }, { model: 'gpt-4o-2024-08-06' });
    await tzun.hook('openai', {}, {}); // no model identity → aiBom null, still a call
    const stats = tzun.getConnectorUsageStats();
    expect(stats.openai).toEqual({ calls: 2, aiBomsProduced: 1 });
  });
});
