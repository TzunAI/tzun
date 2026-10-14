/**
 * Where the anvil suite runs (tests/anvil/): not in the default `pnpm test`,
 * which every CI run of ci.yml makes, and in one path-filtered workflow,
 * .github/workflows/anvil.yml, that asks for it with TZUN_ANVIL=1. The trigger
 * shape every workflow shares (push on main and release/**, a PR leg,
 * workflow_dispatch) is ci-workflow-triggers.test.ts's.
 *
 * No YAML library, as in ci-workflow-triggers.test.ts: the checks read the
 * shapes this repository writes.
 */
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.join(__dirname, '..', '..');
const workflow = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'anvil.yml'), 'utf8');

/** The `paths:` list under the trigger `trigger:` (a direct child of `on:`). */
function pathsOf(trigger: 'push' | 'pull_request'): string[] {
  const lines = workflow.split('\n');
  const at = lines.findIndex((l) => l === `  ${trigger}:`);
  expect(at).toBeGreaterThan(0);
  const out: string[] = [];
  let inPaths = false;
  for (let i = at + 1; i < lines.length && /^ {4}|^\s*$/.test(lines[i]); i++) {
    if (/^ {4}paths:\s*$/.test(lines[i])) {
      inPaths = true;
      continue;
    }
    if (/^ {4}\S/.test(lines[i])) inPaths = false;
    const m = lines[i].match(/^ {6}- '([^']+)'\s*$/);
    if (inPaths && m) out.push(m[1]);
  }
  return out;
}

const PATHS = [
  'src/anchoring/**',
  'src/storage/**',
  'src/attestation/**',
  // The Tzun-wired cases run src/sdk/index.ts: anchoring and the scanner in Tzun.init.
  'src/sdk/**',
  // scanner-anvil.test.ts runs ScheduledScanner and its anchoring checks.
  'src/monitoring/**',
  'tests/anvil/**',
  'vectors/anchor-e2e-vectors.json',
  '.github/workflows/anvil.yml',
];

describe('the anvil suite runs in its own workflow, and never in the default test run', () => {
  it('the default jest config leaves tests/anvil out, and jest.anvil.config.js runs only it, on one worker', () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const base = require(path.join(ROOT, 'jest.config.js'));
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const anvil = require(path.join(ROOT, 'jest.anvil.config.js'));
    expect(base.testPathIgnorePatterns).toContain('<rootDir>/tests/anvil/');
    expect(anvil.testMatch).toEqual(['<rootDir>/tests/anvil/**/*.test.ts']);
    expect(anvil.testPathIgnorePatterns).not.toContain('<rootDir>/tests/anvil/');
    expect(anvil.maxWorkers).toBe(1);
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    expect(pkg.scripts.test).not.toMatch(/anvil/);
    expect(pkg.scripts['test:anvil']).toBe('jest --config jest.anvil.config.js --verbose');
  });

  it('runs on pushes to main and release/** and on PRs to main that touch the code it exercises, and on demand', () => {
    expect(pathsOf('push')).toEqual(PATHS);
    expect(pathsOf('pull_request')).toEqual(PATHS);
    expect(workflow).toMatch(/^ {4}branches: \[main, 'release\/\*\*'\]$/m);
    expect(workflow).toMatch(/^ {2}pull_request:\n {4}branches: \[main\]$/m);
    expect(workflow).toMatch(/^ {2}workflow_dispatch:$/m);
  });

  it('asks the harness for the suite with TZUN_ANVIL=1, through the package script', () => {
    expect(workflow).toMatch(/TZUN_ANVIL: '1'\n\s+run: pnpm run test:anvil/);
  });

  it('then verifies a store anchored on anvil in both SDKs, asking for it with TZUN_ANVIL=1', () => {
    const suite = workflow.indexOf('run: pnpm run test:anvil');
    const store = workflow.search(
      /TZUN_ANVIL: '1'\n\s+run: python -m pytest tests\/cross-sdk\/test_anchor_anvil_store\.py/,
    );
    expect(suite).toBeGreaterThan(0);
    expect(store).toBeGreaterThan(suite);
    expect(workflow).toMatch(/pip install -e '\.\[anchor\]' pytest pytest-asyncio/);
    expect(workflow).toContain('actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97');
  });

  it("follows ci.yml's conventions: read-only token, one run per ref, actions pinned by SHA", () => {
    expect(workflow).toMatch(/^permissions:\n {2}contents: read$/m);
    expect(workflow).toMatch(/group: \$\{\{ github\.workflow \}\}-\$\{\{ github\.ref \}\}/);
    expect(workflow).toMatch(/cancel-in-progress: \$\{\{ github\.ref_name != 'main' \}\}/);
    const uses = [...workflow.matchAll(/uses: (\S+)/g)].map((m) => m[1]);
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u).toMatch(/@[0-9a-f]{40}$/);
    expect(uses).toContain('actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1');
    expect(uses).toContain('actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1');
    expect(workflow).toMatch(/persist-credentials: false/);
  });

  it('pulls the image the harness pins', () => {
    const harness = fs.readFileSync(path.join(ROOT, 'tests', 'anvil', 'harness.ts'), 'utf8');
    const pinned = harness.match(/'(ghcr\.io\/foundry-rs\/foundry:v[0-9.]+)'/)![1];
    expect(workflow).toContain(`docker pull ${pinned}`);
  });
});
