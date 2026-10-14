import { Tzun } from '../../src/sdk/index';
import { resolveMode } from '../../src/sdk/mode-resolver';

/**
 * Mode/credential resolution fails closed. An empty `apiKey` (the env var it
 * was read from is unset), a mistyped TZUN_MODE, or a production mode with no
 * storage is refused with an error naming the option to fix. Resolving any of
 * them to `dev` mode with in-memory storage would make every capture return
 * `stored: true` while the evidence sat in RAM until the next deploy.
 */
describe('mode/credential resolution fails closed', () => {
  const originalMode = process.env.TZUN_MODE;
  const originalDbUrl = process.env.DATABASE_URL;

  afterEach(() => {
    if (originalMode === undefined) delete process.env.TZUN_MODE;
    else process.env.TZUN_MODE = originalMode;
    if (originalDbUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = originalDbUrl;
  });

  describe('path 2: apiKey present but empty (the marketed snippet with the env var unset)', () => {
    it.each([
      ['undefined', undefined],
      ['empty string', ''],
    ])('rejects apiKey: %s instead of inferring dev mode', async (_label, value) => {
      const init = Tzun.init({ apiKey: value as unknown as string });
      await expect(init).rejects.toThrow(/`apiKey` was provided but is empty or undefined/);
      // The remedy names the option the caller passes; the SDK reads no API-key
      // environment variable.
      await expect(init).rejects.toThrow(/Pass a non-empty `apiKey` to Tzun\.init\(\)/);
      await expect(init).rejects.not.toThrow(/TZUN_API_KEY/);
    });

    it('still accepts a config that simply omits apiKey', async () => {
      const tzun = await Tzun.init({ mode: 'dev' });
      expect(tzun.getStorage().constructor.name).toBe('MemoryStorageAdapter');
      await tzun.close();
    });
  });

  describe('path 3: unrecognised TZUN_MODE', () => {
    it.each(['prod', 'production', 'Cloud', 'DEV'])(
      'rejects TZUN_MODE=%s rather than silently resolving to dev',
      (bad) => {
        process.env.TZUN_MODE = bad;
        expect(() => resolveMode(undefined)).toThrow(
          new RegExp(`TZUN_MODE="${bad}" is not a recognised mode`),
        );
      },
    );

    it('treats an empty TZUN_MODE as unset', () => {
      process.env.TZUN_MODE = '';
      expect(resolveMode(undefined)).toBe('dev');
    });

    it('still honours every valid value', () => {
      for (const good of ['dev', 'local', 'cloud', 'self-hosted']) {
        process.env.TZUN_MODE = good;
        expect(resolveMode(undefined)).toBe(good);
      }
    });

    it('explicit config.mode still wins over a bad env value', () => {
      process.env.TZUN_MODE = 'prod';
      expect(resolveMode({ mode: 'local' })).toBe('local');
    });
  });

  describe('path 1: production mode with no storage at all', () => {
    it.each(['cloud', 'self-hosted'] as const)(
      'refuses to init in %s mode with no credential and no database',
      async (mode) => {
        delete process.env.DATABASE_URL;
        await expect(Tzun.init({ mode })).rejects.toThrow(
          /no persistent storage configured/,
        );
      },
    );

    it('names the API key, not just the database URL, in the remedy', async () => {
      const init = Tzun.init({ mode: 'cloud' });
      await expect(init).rejects.toThrow(/Pass `apiKey` for the managed backend/);
      await expect(init).rejects.not.toThrow(/TZUN_API_KEY/);
    });

    it('a production mode WITH a database is unaffected', async () => {
      const tzun = await Tzun.init({
        mode: 'self-hosted',
        dbPath: ':memory:',
      });
      expect(tzun.getStorage().constructor.name).toBe('SqliteStorageAdapter');
      await tzun.close();
    });

    it('local mode still gets its default SQLite file', async () => {
      const tzun = await Tzun.init({ mode: 'local', dbPath: ':memory:' });
      expect(tzun.getStorage().constructor.name).toBe('SqliteStorageAdapter');
      await tzun.close();
    });
  });
});
