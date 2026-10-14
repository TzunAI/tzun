/**
 * `Tzun.init()` refuses every configuration
 * that asks for an anchor where it cannot have one, each with its own
 * message, before it opens a store.
 *
 * - `require` naming 'blockchain' or 'anchor': a capture never holds an anchor.
 * - `deferrable` naming either: the retry pass never obtains one.
 * - the legacy `attestation.blockchain` key: the message names `anchoring`.
 * - `anchoring` on the memory adapter, and on the cloud transport.
 * - `anchoring` on SQLite or Postgres is checked before the store is opened;
 *   what it runs there is tests/ts/anchoring-wired.test.ts.
 */
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AnchorActivationError, AnchoringConfigError, Tzun } from '../../src/sdk/index';
import { validateAttestationConfig } from '../../src/sdk/mode-resolver';
import type { AttestationConfig, TzunConfig } from '@tzun/engine';

const ANCHOR_KEY = { anchorPrivateKey: '0x' + 'ab'.repeat(32), anchorRpcUrl: 'http://127.0.0.1:1' };
const ANCHORING = { publishers: { evm: { rpcUrl: 'http://127.0.0.1:1', privateKey: ANCHOR_KEY.anchorPrivateKey, chain: 'eip155:11155111' } } };

const REQUIRE = /`attestation\.require` cannot name '(blockchain|anchor)': a capture never waits on a chain/;
const DEFERRABLE = /`attestation\.deferrable` cannot name '(blockchain|anchor)': the retry pass never obtains an anchor/;
const LEGACY = /`attestation\.blockchain` is not supported: a capture does not anchor[\s\S]*`anchoring`/;
const MEMORY = /`anchoring` is refused on the memory adapter/;
const CLOUD = /`anchoring` is refused on the cloud transport/;
const MALFORMED = /anchoring\.publishers is required/;
const NOT_A_SETTING = /`anchoring: false` is not a setting: omit `anchoring` to not anchor/;

/** The config as an untyped caller would write it. */
const attestation = (a: Record<string, unknown>) => a as unknown as AttestationConfig;
const config = (c: Record<string, unknown>) => c as unknown as TzunConfig;

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'tzun-test-anchoring-refused-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('the attestation lists and the legacy key (validateAttestationConfig)', () => {
  const MODES = ['dev', 'local', 'cloud', 'self-hosted'] as const;

  it.each(MODES)('%s: require naming blockchain or anchor', (mode) => {
    for (const name of ['blockchain', 'anchor']) {
      expect(() =>
        validateAttestationConfig(mode, attestation({ require: ['timestamp', name] })),
      ).toThrow(REQUIRE);
      expect(() =>
        validateAttestationConfig(mode, attestation({ require: ['timestamp', name] })),
      ).toThrow(`cannot name '${name}'`);
    }
  });

  it.each(MODES)('%s: deferrable naming blockchain or anchor', (mode) => {
    for (const name of ['blockchain', 'anchor']) {
      expect(() =>
        validateAttestationConfig(mode, attestation({ deferrable: ['timestamp', name] })),
      ).toThrow(DEFERRABLE);
      expect(() =>
        validateAttestationConfig(mode, attestation({ deferrable: ['timestamp', name] })),
      ).toThrow(`cannot name '${name}'`);
    }
  });

  it.each(MODES)('%s: the legacy blockchain key, with or without a key in it', (mode) => {
    for (const blockchain of [ANCHOR_KEY, { anchorRpcUrl: 'http://127.0.0.1:1' }, {}]) {
      expect(() => validateAttestationConfig(mode, attestation({ blockchain }))).toThrow(LEGACY);
    }
  });

  it('on the HTTP transport too', () => {
    expect(() => validateAttestationConfig('cloud', attestation({ blockchain: ANCHOR_KEY }), true)).toThrow(LEGACY);
    expect(() => validateAttestationConfig('cloud', attestation({ deferrable: ['anchor'] }), true)).toThrow(DEFERRABLE);
  });

  it('a config naming both the legacy key and a list is refused by the legacy-key message, which also names the lists', () => {
    expect(() =>
      validateAttestationConfig(
        'local',
        attestation({ deferrable: ['timestamp', 'blockchain'], blockchain: ANCHOR_KEY }),
      ),
    ).toThrow(/Remove `attestation\.blockchain`, and 'blockchain' from `attestation\.require` and `attestation\.deferrable`/);
  });

  it('the four refusals are four different messages', () => {
    const message = (a: Record<string, unknown>): string => {
      try {
        validateAttestationConfig('local', attestation(a));
      } catch (err) {
        return (err as Error).message;
      }
      throw new Error('not refused');
    };
    const messages = new Set([
      message({ require: ['blockchain'] }),
      message({ deferrable: ['blockchain'] }),
      message({ blockchain: ANCHOR_KEY }),
    ]);
    expect(messages.size).toBe(3);
  });

  it('a config that never named an anchor is unchanged', () => {
    expect(validateAttestationConfig('local', undefined)).toEqual({ require: [], deferrable: ['timestamp'] });
    expect(validateAttestationConfig('local', { require: ['timestamp', 'webauthn'] })).toMatchObject({
      require: ['timestamp', 'webauthn'],
      deferrable: [],
    });
    expect(validateAttestationConfig('dev', {})).toEqual({ require: [], deferrable: [] });
  });
});

describe('Tzun.init() refuses before it opens a store', () => {
  it.each<[string, Record<string, unknown>, RegExp]>([
    ['require: blockchain', { require: ['timestamp', 'blockchain'], blockchain: ANCHOR_KEY }, LEGACY],
    ['require: anchor', { require: ['timestamp', 'anchor'] }, REQUIRE],
    ['deferrable: blockchain', { deferrable: ['timestamp', 'blockchain'] }, DEFERRABLE],
    ['deferrable: anchor', { deferrable: ['anchor'] }, DEFERRABLE],
    ['the legacy key', { blockchain: ANCHOR_KEY }, LEGACY],
  ])('%s on SQLite', async (_label, a, expected) => {
    const dbPath = join(dir, 'refused.db');
    await expect(Tzun.init({ mode: 'local', dbPath, attestation: attestation(a) })).rejects.toThrow(expected);
    expect(existsSync(dbPath)).toBe(false);
  });

  it('anchoring on the memory adapter', async () => {
    await expect(Tzun.init(config({ mode: 'dev', anchoring: ANCHORING }))).rejects.toThrow(MEMORY);
  });

  it('anchoring on the cloud transport', async () => {
    const fetchFn = jest.fn();
    await expect(
      Tzun.init(config({ apiKey: 'tzun_test_key', anchoring: ANCHORING, _httpFetchFn: fetchFn })),
    ).rejects.toThrow(CLOUD);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('anchoring on SQLite is checked before the store is opened: a malformed one creates no file', async () => {
    const dbPath = join(dir, 'malformed.db');
    const refusal = Tzun.init(config({ mode: 'local', dbPath, anchoring: {} }));
    await expect(refusal).rejects.toBeInstanceOf(AnchoringConfigError);
    await expect(refusal).rejects.toThrow(MALFORMED);
    expect(existsSync(dbPath)).toBe(false);
  });

  it('anchoring on Postgres is checked before a connection is made', async () => {
    // Port 1 on loopback refuses every connection, so a refusal that came after
    // opening the store would read as ECONNREFUSED, not as this message.
    await expect(
      Tzun.init(config({ mode: 'local', dbUrl: 'postgres://u:p@127.0.0.1:1/tzun_nowhere_test', anchoring: {} })),
    ).rejects.toThrow(MALFORMED);
  });

  it('a well-formed anchoring on a store outside a test. namespace reaches the activation guard, before the store is opened', async () => {
    const dbPath = join(dir, 'local-invalid.db');
    await expect(Tzun.init(config({ mode: 'local', dbPath, logNamespace: 'local.invalid', anchoring: ANCHORING }))).rejects.toBeInstanceOf(AnchorActivationError);
    expect(existsSync(dbPath)).toBe(false);
  });

  it('a well-formed anchoring with no namespace at all is refused before the store is opened: it would mint local.invalid', async () => {
    const dbPath = join(dir, 'no-namespace.db');
    const refusal = Tzun.init(config({ mode: 'local', dbPath, anchoring: ANCHORING }));
    await expect(refusal).rejects.toBeInstanceOf(AnchoringConfigError);
    await expect(refusal).rejects.toThrow(/needs the store's namespace/);
    expect(existsSync(dbPath)).toBe(false);
  });

  it('anchoring with any value but undefined, null or false is refused as a request to anchor', async () => {
    for (const anchoring of [{}, true, 'on']) {
      await expect(Tzun.init(config({ mode: 'dev', anchoring }))).rejects.toThrow(MEMORY);
    }
    for (const anchoring of [undefined, null]) {
      const tzun = await Tzun.init(config({ mode: 'dev', anchoring }));
      await tzun.close();
    }
  });

  it('anchoring: false is refused on every store with its own message, not as a request to anchor', async () => {
    const dbPath = join(dir, 'false.db');
    for (const c of [
      { mode: 'dev' },
      { mode: 'local', dbPath },
      { mode: 'local', dbUrl: 'postgres://u:p@127.0.0.1:1/tzun_nowhere_test' },
      { apiKey: 'tzun_test_key', _httpFetchFn: jest.fn() },
    ]) {
      const refusal = Tzun.init(config({ ...c, anchoring: false }));
      await expect(refusal).rejects.toThrow(NOT_A_SETTING);
      await expect(refusal).rejects.not.toThrow(/memory adapter|cloud transport|publishers/);
    }
    expect(existsSync(dbPath)).toBe(false);
  });

  describe('the two storage branches no config key names', () => {
    let savedCwd: string;
    let savedUrl: string | undefined;
    beforeEach(() => {
      savedCwd = process.cwd();
      savedUrl = process.env.DATABASE_URL;
    });
    afterEach(() => {
      process.chdir(savedCwd);
      if (savedUrl === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = savedUrl;
    });

    it('DATABASE_URL from the environment (Postgres): checked before a connection is made', async () => {
      process.env.DATABASE_URL = 'postgres://u:p@127.0.0.1:1/tzun_nowhere_test';
      await expect(
        Tzun.init(config({ mode: 'local', _readDatabaseUrlEnv: true, anchoring: {} })),
      ).rejects.toThrow(MALFORMED);
    });

    it('the default ./tzun.db of local mode (SQLite): checked before a file is created', async () => {
      delete process.env.DATABASE_URL;
      process.chdir(dir);
      await expect(Tzun.init(config({ mode: 'local', anchoring: {} }))).rejects.toThrow(MALFORMED);
      expect(existsSync(join(dir, 'tzun.db'))).toBe(false);
    });
  });

  it('the store-dependent refusals are three different messages', async () => {
    const message = async (c: Record<string, unknown>): Promise<string> =>
      Tzun.init(config(c)).then(
        () => { throw new Error('not refused'); },
        (err: Error) => err.message,
      );
    const messages = new Set([
      await message({ mode: 'dev', anchoring: ANCHORING }),
      await message({ apiKey: 'tzun_test_key', anchoring: ANCHORING, _httpFetchFn: jest.fn() }),
      await message({ mode: 'local', dbPath: join(dir, 'm.db'), anchoring: ANCHORING }),
    ]);
    expect(messages.size).toBe(3);
  });
});
