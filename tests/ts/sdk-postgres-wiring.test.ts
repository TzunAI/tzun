import { Tzun } from '../../src/sdk/index';

// Mock pg Pool to avoid needing a real database
jest.mock('pg', () => {
  const mockQuery = jest.fn().mockResolvedValue({ rows: [], rowCount: 0 });
  const mockPool = {
    query: mockQuery,
    connect: jest.fn().mockResolvedValue({
      query: mockQuery,
      release: jest.fn(),
    }),
    end: jest.fn(),
  };
  return { Pool: jest.fn(() => mockPool) };
});

describe('PostgreSQL storage wiring', () => {
  afterEach(() => {
    // Clean up DATABASE_URL after each test
    delete process.env.DATABASE_URL;
  });

  it('uses PostgresStorageAdapter when dbUrl is provided', async () => {
    const tzun = await Tzun.init({
      mode: 'dev',
      dbUrl: 'postgresql://localhost:5432/tzun_test',
    });

    // The storage adapter should be PostgresStorageAdapter
    const storage = tzun.getStorage();
    expect(storage.constructor.name).toBe('PostgresStorageAdapter');
  });

  it('reads DATABASE_URL env var when dbUrl is not provided', async () => {
    process.env.DATABASE_URL = 'postgresql://localhost:5432/tzun_env';

    // _readDatabaseUrlEnv: true opts back into the env-var fallback that
    // is suppressed by default under Jest. This is the test API documented
    // in TzunConfig for exactly this case — verifying production wiring
    // from inside a test environment.
    const tzun = await Tzun.init({ mode: 'dev', _readDatabaseUrlEnv: true });
    const storage = tzun.getStorage();
    expect(storage.constructor.name).toBe('PostgresStorageAdapter');
  });

  it('prefers explicit dbUrl over DATABASE_URL env var', async () => {
    process.env.DATABASE_URL = 'postgresql://localhost:5432/env_db';

    const tzun = await Tzun.init({
      mode: 'dev',
      dbUrl: 'postgresql://localhost:5432/explicit_db',
    });

    const storage = tzun.getStorage();
    expect(storage.constructor.name).toBe('PostgresStorageAdapter');

    // Verify the explicit URL was used (check Pool constructor args)
    const { Pool } = require('pg');
    const lastCall = Pool.mock.calls[Pool.mock.calls.length - 1][0];
    expect(lastCall.connectionString).toBe('postgresql://localhost:5432/explicit_db');
  });

  it('falls back to in-memory when no dbUrl or dbPath provided in dev mode', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    const storage = tzun.getStorage();
    expect(storage.constructor.name).toBe('MemoryStorageAdapter');
  });

  it('uses SQLite when dbPath is provided', async () => {
    const tzun = await Tzun.init({
      mode: 'dev',
      dbPath: ':memory:',
    });
    const storage = tzun.getStorage();
    expect(storage.constructor.name).toBe('SqliteStorageAdapter');
  });

  it('dev mode with dbUrl uses PostgreSQL (not forced to memory)', async () => {
    const tzun = await Tzun.init({
      mode: 'dev',
      dbUrl: 'postgresql://localhost:5432/tzun_dev',
    });
    const storage = tzun.getStorage();
    expect(storage.constructor.name).toBe('PostgresStorageAdapter');
  });

  it('dbUrl takes precedence over dbPath when both provided', async () => {
    const tzun = await Tzun.init({
      mode: 'dev',
      dbUrl: 'postgresql://localhost:5432/tzun_test',
      dbPath: ':memory:',
    });
    const storage = tzun.getStorage();
    expect(storage.constructor.name).toBe('PostgresStorageAdapter');
  });

  it('local mode without explicit storage config defaults to SQLite', async () => {
    const tzun = await Tzun.init({ mode: 'local' });
    const storage = tzun.getStorage();
    expect(storage.constructor.name).toBe('SqliteStorageAdapter');
  });

  it('apiKey selects the cloud HttpStorageAdapter', async () => {
    // Selection is by the PRESENCE of apiKey, decoupled from the mode enum:
    // an apiKey routes captures to the backend over the HTTP transport.
    const tzun = await Tzun.init({
      mode: 'cloud',
      apiKey: 'test-key',
    });

    const storage = tzun.getStorage();
    expect(storage.constructor.name).toBe('HttpStorageAdapter');

    await tzun.close();
  });

  // Cloud mode with no credential must not warn and fall back to in-memory
  // storage: the process would boot healthy and report `stored: true` for
  // every decision while the evidence lives in RAM. Init refuses instead.
  it('cloud mode WITHOUT an apiKey refuses to start rather than using memory', async () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation();

    await expect(Tzun.init({ mode: 'cloud' })).rejects.toThrow(
      /no persistent storage configured/
    );
    // And it is an error, not a warning that the operator can miss.
    expect(warnSpy).not.toHaveBeenCalled();

    warnSpy.mockRestore();
  });
});
