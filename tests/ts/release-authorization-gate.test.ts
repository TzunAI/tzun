/**
 * The release authorization gate, asserted against the workflow files, which
 * is where it lives.
 *
 * Two workflows can push bytes to a package registry: release.yml (npm) and
 * python-publish.yml (PyPI). Each one:
 *
 *  - runs an `authorize` job first: a v*.*.* tag of the public repository,
 *    an actor on the RELEASE_ACTORS allowlist (a required repository variable
 *    with no default, so an unset variable refuses everyone), a typed
 *    PUBLISH-<version> token on a manual run, and a tagged commit reachable
 *    from main;
 *  - builds and scans in a job that holds no OIDC capability;
 *  - publishes from one job, the only one with `id-token: write`, which
 *    deploys to an environment (`npm`, `pypi`) whose required reviewers
 *    approve every release, and which the registry's trusted publisher names.
 */
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

const WORKFLOW_DIR = join(__dirname, '..', '..', '.github', 'workflows');

function read(file: string): string {
  return readFileSync(join(WORKFLOW_DIR, file), 'utf-8');
}

/** The jobs under `jobs:`, in file order, each with its text. */
function jobs(wf: string): Array<{ name: string; text: string }> {
  const lines = wf.split('\n');
  const at = lines.findIndex((l) => /^jobs:\s*$/.test(l));
  const out: Array<{ name: string; text: string }> = [];
  let current: { name: string; lines: string[] } | null = null;
  for (let i = at + 1; i < lines.length; i++) {
    const line = lines[i];
    if (/^\S/.test(line)) break;
    const m = line.match(/^ {2}([A-Za-z0-9_-]+):\s*$/);
    if (m) {
      if (current) out.push({ name: current.name, text: current.lines.join('\n') });
      current = { name: m[1], lines: [line] };
    } else if (current) {
      current.lines.push(line);
    }
  }
  if (current) out.push({ name: current.name, text: current.lines.join('\n') });
  return out;
}

function job(wf: string, name: string): string {
  const j = jobs(wf).find((x) => x.name === name);
  expect({ name, found: Boolean(j) }).toEqual({ name, found: true });
  return j!.text;
}

/** Lines that are not YAML or shell comments. */
const code = (text: string): string =>
  text
    .split('\n')
    .filter((l) => !/^\s*#/.test(l))
    .join('\n');

/** Workflows that can push bytes to a package registry, and the environment each publishes through. */
const PUBLISHING: Record<string, string> = {
  'release.yml': 'npm',
  'python-publish.yml': 'pypi',
};

describe('release authorization gate', () => {
  it('every publishing workflow is present, and no other workflow can publish (guards against a vacuous pass)', () => {
    const present = readdirSync(WORKFLOW_DIR).filter((f) => /\.ya?ml$/.test(f));
    for (const f of Object.keys(PUBLISHING)) expect(present).toContain(f);
    for (const f of present.filter((x) => !(x in PUBLISHING))) {
      const wf = code(read(f));
      expect({ f, publishes: /id-token:\s*write|npm (stage )?publish|pnpm publish|twine upload|gh-action-pypi-publish/.test(wf) }).toEqual({
        f,
        publishes: false,
      });
    }
  });

  it.each(Object.keys(PUBLISHING))('%s checks the actor against RELEASE_ACTORS and fails closed when it is unset', (file) => {
    const gate = job(read(file), 'authorize');
    expect(gate).toMatch(/ACTOR: \$\{\{ github\.actor \}\}/);
    expect(gate).toMatch(/ALLOWED: \$\{\{ vars\.RELEASE_ACTORS \}\}/);
    // No default login: unset or empty (or only commas and spaces) refuses everyone.
    expect(gate).toMatch(/allowed="\$\{ALLOWED:-\}"/);
    expect(gate).not.toMatch(/\$\{ALLOWED:-[^}]/);
    expect(gate).toMatch(/if \[ -z "\$\(printf '%s' "\$allowed" \| tr -d '\[:space:\],'\)" \]; then\n\s+echo "::error::The RELEASE_ACTORS repository variable is not set\.[^\n]*\n\s+exit 1/);
  });

  it.each(Object.keys(PUBLISHING))('%s demands a typed confirmation token on a manual run', (file) => {
    const gate = job(read(file), 'authorize');
    expect(gate).toMatch(/inputs\.confirm/);
    expect(gate).toMatch(/expected="PUBLISH-\$\{REF_NAME#v\}"/);
  });

  it.each(Object.keys(PUBLISHING))('%s refuses a non-tag ref, a repository that is not public, and a commit that is not on main', (file) => {
    const gate = job(read(file), 'authorize');
    expect(gate).toMatch(/github\.ref_type/);
    expect(gate).toMatch(/PRIVATE: \$\{\{ github\.event\.repository\.private \}\}\n\s+run: \|\n(?:\s*#.*\n)*\s+if \[ "\$PRIVATE" != "false" \]/);
    // Without the ancestry check, a tag on an unreviewed commit publishes it:
    // the tag trigger does not care which branch the commit is on.
    expect(gate).toMatch(/merge-base --is-ancestor "\$commit" origin\/main/);
  });

  it.each(Object.entries(PUBLISHING))('%s runs authorize, then build, then publish (environment %s)', (file, environment) => {
    const wf = read(file);
    const names = jobs(wf).map((j) => j.name);
    expect(names.slice(0, 3)).toEqual(['authorize', 'build', 'publish']);
    expect(job(wf, 'build')).toMatch(/needs: authorize\n/);
    const publish = job(wf, 'publish');
    expect(publish).toMatch(/needs: \[authorize, build\]/);
    expect(publish).toMatch(new RegExp(`environment:\\n\\s+name: ${environment}\\n`));
    // Trusted publishing works from GitHub-hosted runners only.
    expect(publish).toMatch(/runs-on: ubuntu-latest\n/);
  });

  it.each(Object.keys(PUBLISHING))('%s grants id-token: write to the publish job alone', (file) => {
    const wf = read(file);
    for (const { name, text } of jobs(wf)) {
      expect({ name, oidc: /^\s*id-token:\s*write/m.test(text) }).toEqual({ name, oidc: name === 'publish' });
    }
    // Never at the workflow level.
    expect(wf.slice(0, wf.indexOf('\njobs:'))).not.toMatch(/id-token/);
  });

  it('release.yml publishes with npm trusted publishing and staging: no token, no other registry, no .npmrc', () => {
    const release = read('release.yml');
    const publish = code(job(release, 'publish'));
    expect(publish).toMatch(/run: npm stage publish "\$RUNNER_TEMP\/npm-pack\/\$ENGINE_TARBALL" --access public --provenance --registry "\$REGISTRY"/);
    expect(publish).toMatch(/run: npm stage publish "\$RUNNER_TEMP\/npm-pack\/\$SDK_TARBALL" --access public --provenance --registry "\$REGISTRY"/);
    expect(publish).toMatch(/REGISTRY: https:\/\/registry\.npmjs\.org\//);
    for (const banned of [/NODE_AUTH_TOKEN/, /npm\.pkg\.github\.com/, /registry-url:/, /\.npmrc/, /_authToken/, /secrets\.NPM/, /pnpm publish/, /packages:\s*write/]) {
      expect({ banned: String(banned), found: banned.test(code(release)) }).toEqual({ banned: String(banned), found: false });
    }
    // Plain `npm publish` appears only in the commented-out variant.
    expect(publish).not.toMatch(/npm publish /);
  });

  it('release.yml installs a pinned npm new enough for staging (11.15.0+) and requires Node 22.14+', () => {
    const publish = job(read('release.yml'), 'publish');
    const v = publish.match(/NPM_VERSION: (\d+)\.(\d+)\.(\d+)\n/);
    expect(v).not.toBeNull();
    const [maj, min] = [Number(v![1]), Number(v![2])];
    expect(maj > 11 || (maj === 11 && min >= 15)).toBe(true);
    expect(publish).toMatch(/NPM_INTEGRITY: sha512-[A-Za-z0-9+/]+=*\n/);
    expect(publish).toMatch(/openssl dgst -sha512 -binary "npm-\$\{NPM_VERSION\}\.tgz"/);
    expect(publish).toMatch(/npm install --global --ignore-scripts "\.\/npm-\$\{NPM_VERSION\}\.tgz"/);
    expect(publish).toMatch(/\[22, 14, 0\]/);
  });

  it('python-publish.yml publishes with pypa/gh-action-pypi-publish and attestations, from the scanned files', () => {
    const publish = job(read('python-publish.yml'), 'publish');
    expect(publish).toMatch(/uses: pypa\/gh-action-pypi-publish@[0-9a-f]{40} # v\d/);
    expect(publish).toMatch(/attestations: true/);
    expect(publish).toMatch(/sha256sum --check SHA256SUMS/);
    expect(code(publish)).not.toMatch(/password:|PYPI_API_TOKEN|secrets\./);
  });
});
