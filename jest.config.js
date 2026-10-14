module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.ts'],
  // tests/anvil/ runs a real EVM node in Docker (the anchor scheduler's anvil
  // suite): `pnpm run test:anvil` (jest.anvil.config.js) runs it, and so does
  // .github/workflows/anvil.yml, path-filtered. The default run leaves it out.
  testPathIgnorePatterns: ['/node_modules/', '<rootDir>/.worktrees/', '<rootDir>/tests/anvil/'],
  verbose: true,
  // No unit test reaches a live host. Five files captured under
  // `mode: 'local'`, which obtains an RFC 3161 timestamp for every record, so every
  // capture() was a round trip to https://freetsa.org/tsr — 58 per CI run —
  // and a TSA hiccup failed them as "Expected: true, Received: false" with no
  // other trace. The setup file replaces `globalThis.fetch` with a guard that
  // passes loopback, refuses everything else unless RUN_INTEGRATION_TESTS=true,
  // and fails the offending test by name even when the SDK swallowed the
  // refusal. Live-service tests gate themselves on the same flag.
  setupFilesAfterEnv: ['<rootDir>/tests/ts/setup/no-live-network.ts'],
  // An integration run (RUN_INTEGRATION_TESTS=true) gets 30 s per test and
  // hook instead of jest's 5 s. It waits on live services, and its Postgres
  // legs queue on one another: `ensureTables()` holds an advisory lock that is
  // database-wide, so a case on one worker can wait out several other
  // workers' DDL before its own starts (tests/ts/helpers/postgres-test-db.ts).
  testTimeout: process.env.RUN_INTEGRATION_TESTS === 'true' ? 30_000 : 5_000,
  // Worker-pool tuning: `maxWorkers: '50%'` eliminates the
  // "worker process has failed to exit gracefully" / "Jest did not exit"
  // warnings observed under jest's default (= CPU count) worker pool.
  //
  // Diagnosis (2026-05-25):
  //   - Every src/ and demo/ setInterval/setTimeout is properly .unref()'d
  //     (rate-limit, gate-rate-limit, contact-retention, webauthn challenge,
  //     tracker prune, scanner setTimeout).
  //   - `jest --detectOpenHandles` reports ZERO open-handle traces — the
  //     handle that delays clean exit IS closed; it's just slightly past
  //     jest's 1-second grace period under the default worker count.
  //   - `--runInBand` produces no warning.
  //   - `--maxWorkers=2` produces no warning.
  //   - `--maxWorkers=50%` produces no warning.
  //   - The warning correlates with multi-worker IPC pipe + ts-jest module-
  //     loader-cache teardown contention — jest infrastructure, not test code.
  //
  // 50% is the sweet spot in this dev container: avoids contention while
  // preserving most of the parallel-execution speedup (~14s vs ~36s
  // single-worker for the full 1228-test suite).
  maxWorkers: '50%',

  // forceExit silences the "worker process has failed to exit gracefully"
  // warning when worker IPC + TCP socket teardown takes longer than jest's
  // 1-second grace period. Verified safe via `npx jest --detectOpenHandles`
  // showing ZERO open-handle traces — handles DO close, just slightly past
  // the grace period under multi-worker contention. Re-run --detectOpenHandles
  // before each release to confirm nothing new has crept in.
  forceExit: true,
  // The demo's browser ESM modules under demo/public/js are imported by a
  // handful of test files (e.g. tests/demo-ui-ai-bom.test.ts) for unit-level
  // assertions on pure render functions. ts-jest needs to transpile those
  // .js files from ESM to CJS so Node's require() can load them.
  transform: {
    '^.+\\.[tj]sx?$': ['ts-jest', { tsconfig: { allowJs: true } }],
  },
};
