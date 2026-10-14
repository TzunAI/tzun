/**
 * The anvil suite (tests/anvil/): the anchor scheduler, and anchoring wired
 * into Tzun, against a real EVM node in one Docker container
 * (tests/anvil/harness.ts). `pnpm run test:anvil`; the default `pnpm test`
 * leaves it out. One worker: the suite shares one node, and its cases move
 * that node's clock, mining and base fee.
 */
const base = require('./jest.config');

module.exports = {
  ...base,
  testMatch: ['<rootDir>/tests/anvil/**/*.test.ts'],
  testPathIgnorePatterns: ['/node_modules/', '<rootDir>/.worktrees/'],
  maxWorkers: 1,
};
