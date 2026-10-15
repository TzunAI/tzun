/**
 * The dependency audit gate.
 *
 * `pnpm audit --audit-level high --prod` gates every release (release.yml's
 * build job, which the publish job needs) and runs on every CI push
 * (ci.yml), so a new HIGH advisory turns CI red before it can block a release
 * tag. Dependabot watches every ecosystem. The lockfile must stay at or above
 * the patched version of every known advisory listed below; ethers@6.16.0,
 * for one, pins ws@8.17.1 exactly, and ws < 8.21.0 carries
 * GHSA-96hv-2xvq-fx4p.
 *
 * These assert against the lockfile and the workflow files rather than at
 * runtime because that is where a vulnerable version or a missing gate would
 * show — `pnpm audit` itself needs the network and would make the suite
 * flaky.
 */
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

const ROOT = join(__dirname, '..', '..');
const lockfile = readFileSync(join(ROOT, 'pnpm-lock.yaml'), 'utf-8');

function read(rel: string): string {
  return readFileSync(join(ROOT, rel), 'utf-8');
}

/** `major.minor.patch` compare; returns <0, 0, >0. */
function cmpSemver(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

/**
 * Known advisories against this dependency tree, each with the first version
 * that resolves it. A failure here means a dependency bump walked the tree
 * back onto a known-vulnerable version.
 */
const MINIMUM_RESOLVED_VERSIONS: Array<{ pkg: string; min: string; advisory: string }> = [
  { pkg: 'ws', min: '8.21.0', advisory: 'GHSA-96hv-2xvq-fx4p (memory-exhaustion DoS)' },
  { pkg: 'ethers', min: '6.17.0', advisory: 'transitively pins ws; 6.16.0 pinned ws@8.17.1 exactly' },
  // The chain pnpm.overrides removes:
  // test-exclude@6 -> glob@7 -> minimatch@3 -> brace-expansion@1.
  { pkg: 'test-exclude', min: '8.0.0', advisory: 'pulls glob@7 -> minimatch@3 -> vulnerable brace-expansion' },
  { pkg: 'glob', min: '13.0.0', advisory: 'glob@7 pulls minimatch@3 -> vulnerable brace-expansion' },
  { pkg: 'brace-expansion', min: '2.1.4', advisory: 'CVE-2026-13149 / -14257 / -69152 (ReDoS)' },
];

describe('dependency audit gate', () => {
  it('resolves every package with a known advisory at or above its patched version', () => {
    const offenders: string[] = [];
    for (const { pkg, min, advisory } of MINIMUM_RESOLVED_VERSIONS) {
      // pnpm lockfile v9 keys packages as `  <name>@<version>:` at the top
      // of the `packages:`/`snapshots:` maps.
      const re = new RegExp(`^\\s{2}${pkg.replace(/[/\\^$*+?.()|[\]{}]/g, '\\$&')}@(\\d+\\.\\d+\\.\\d+[^:\\s]*):`, 'gm');
      const found = new Set<string>();
      let m: RegExpExecArray | null;
      while ((m = re.exec(lockfile)) !== null) found.add(m[1]);
      if (found.size === 0) {
        offenders.push(`${pkg}: no version resolved in pnpm-lock.yaml — test would be vacuous`);
        continue;
      }
      for (const v of found) {
        if (cmpSemver(v.split('-')[0], min) < 0) {
          offenders.push(`${pkg}@${v} < ${min} — ${advisory}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it('runs the release audit gate on every push, not only on release tags', () => {
    const ci = read('.github/workflows/ci.yml');
    expect(ci).toMatch(/pnpm audit --audit-level high --prod/);
  });

  it('gates the one publish job on the audit, so a red gate publishes neither package', () => {
    const release = read('.github/workflows/release.yml');
    const build = release.slice(release.indexOf('\n  build:'), release.indexOf('\n  publish:'));
    const publish = release.slice(release.indexOf('\n  publish:'), release.indexOf('\n  github-release:'));
    expect(build.length).toBeGreaterThan(0);
    expect(publish.length).toBeGreaterThan(0);
    // The audit runs before the packages are packed, in the job publish needs.
    const audit = build.indexOf('pnpm audit --audit-level high --prod');
    expect(audit).toBeGreaterThan(0);
    expect(build.indexOf('pnpm pack --pack-destination')).toBeGreaterThan(audit);
    expect(publish).toMatch(/needs: \[authorize, build\]/);
    // Both packages are staged by that one job: there is no second publish
    // path that could ship one package while the other's gate is red.
    expect(release.match(/^\s+run: npm stage publish /gm)?.length).toBe(2);
  });

  it('publishes @tzun/engine before @tzun/sdk, which depends on it', () => {
    const release = read('.github/workflows/release.yml');
    const publish = release.slice(release.indexOf('\n  publish:'), release.indexOf('\n  github-release:'));
    const engine = publish.indexOf('- name: Stage @tzun/engine on npm');
    const sdk = publish.indexOf('- name: Stage @tzun/sdk on npm');
    expect(engine).toBeGreaterThan(0);
    expect(sdk).toBeGreaterThan(engine);
  });

  /**
   * This repo installs with pnpm, and pnpm reads only `pnpm.overrides`: a
   * top-level npm-style `"overrides"` block in package.json is ignored without
   * a warning, so a production override for a live CVE written there would
   * leave the lockfile unmoved and nobody told why.
   */
  it('declares overrides under pnpm.overrides and nowhere else', () => {
    const pkg = JSON.parse(read('package.json')) as {
      overrides?: Record<string, string>;
      pnpm?: { overrides?: Record<string, string> };
    };
    expect(pkg.pnpm?.overrides).toBeDefined();
    expect(Object.keys(pkg.pnpm!.overrides!).length).toBeGreaterThan(0);
    // One mechanism only. A leftover top-level block is the trap: it reads as
    // authoritative and does nothing.
    expect(pkg.overrides).toBeUndefined();
  });

  it('every declared override actually reaches the lockfile', () => {
    // Asserting the OUTCOME — pnpm recorded the override — rather than where
    // the JSON key sits, so this cannot pass while the block is inert.
    const pkg = JSON.parse(read('package.json')) as {
      pnpm?: { overrides?: Record<string, string> };
    };
    const overrides = pkg.pnpm?.overrides ?? {};
    const section = lockfile.match(/^overrides:\n((?: {2}.*\n)+)/m);
    expect(section).not.toBeNull();
    const missing = Object.entries(overrides)
      .filter(([name, range]) => {
        // pnpm quotes ranges that would otherwise be YAML-ambiguous.
        const esc = (v: string) => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        return !new RegExp(`^ {2}${esc(name)}: '?${esc(range)}'?$`, 'm').test(section![1]);
      })
      .map(([name, range]) => `${name}: ${range}`);
    expect(missing).toEqual([]);
  });

  it('ships a dependabot config covering npm, pip and github-actions', () => {
    const path = join(ROOT, '.github', 'dependabot.yml');
    expect(existsSync(path)).toBe(true);
    const cfg = readFileSync(path, 'utf-8');
    for (const ecosystem of ['npm', 'pip', 'github-actions']) {
      expect(cfg).toMatch(new RegExp(`package-ecosystem:\\s*['"]?${ecosystem}['"]?`));
    }
  });

  it('checks every ecosystem monthly, at directories that exist', () => {
    const cfg = readFileSync(join(ROOT, '.github', 'dependabot.yml'), 'utf-8');
    const ecosystems = cfg.match(/package-ecosystem:/g) ?? [];
    const intervals = [...cfg.matchAll(/^\s*interval:\s*['"]?(\w+)['"]?\s*$/gm)].map((m) => m[1]);
    expect(ecosystems.length).toBeGreaterThanOrEqual(3);
    expect(intervals).toEqual(ecosystems.map(() => 'monthly'));
    const dirs = [...cfg.matchAll(/^\s*directory:\s*['"]?([^'"\s]+)['"]?\s*$/gm)].map((m) => m[1]);
    expect(dirs.length).toBe(ecosystems.length);
    expect(dirs.filter((d) => !existsSync(join(ROOT, d)))).toEqual([]);
  });
});
