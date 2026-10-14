/**
 * Version skew between the tag, the three packages and the registries.
 *
 * The tag v<version> must name the version in package.json,
 * packages/engine/package.json and python/pyproject.toml, which move in
 * lockstep; and a version that is already on the registry fails a first
 * release attempt rather than going green having published nothing. Only a
 * re-run of a partially failed attempt treats "already published" as a no-op.
 */
import { readFileSync } from 'fs';
import { join } from 'path';

const ROOT = join(__dirname, '..', '..');
const release = readFileSync(join(ROOT, '.github', 'workflows', 'release.yml'), 'utf-8');
const python = readFileSync(join(ROOT, '.github', 'workflows', 'python-publish.yml'), 'utf-8');
const ci = readFileSync(join(ROOT, '.github', 'workflows', 'ci.yml'), 'utf-8');

const sdkPkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf-8'));
const enginePkg = JSON.parse(readFileSync(join(ROOT, 'packages', 'engine', 'package.json'), 'utf-8'));
const pyproject = readFileSync(join(ROOT, 'python', 'pyproject.toml'), 'utf-8');

/** The text of job `name`: from its `  name:` line to the next job, or the end of the file. */
function jobBlock(wf: string, name: string): string {
  const lines = wf.split('\n');
  const start = lines.findIndex((l) => l === `  ${name}:`);
  expect({ name, found: start >= 0 }).toEqual({ name, found: true });
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^ {2}[A-Za-z0-9_-]+:\s*$/.test(lines[i]) || /^\S/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join('\n');
}

/** The steps of a job, each from its `- name:` line to the next. */
function steps(job: string): string[] {
  return job.split(/\n(?= {6}- name: )/).slice(1);
}

describe('release version skew', () => {
  it('keeps @tzun/sdk, @tzun/engine and tzun-sdk (Python) on the same version', () => {
    // pnpm rewrites `workspace:*` to the engine's exact version at pack time.
    // If they drift, the published SDK declares a dependency on an engine
    // version the same tag never publishes.
    expect(enginePkg.version).toBe(sdkPkg.version);
    const py = pyproject.match(/^version\s*=\s*"([^"]+)"/m);
    expect(py).not.toBeNull();
    expect(py![1]).toBe(sdkPkg.version);
  });

  it('release.yml refuses to publish a tag that does not name package.json version', () => {
    expect(release).toMatch(/Tag \$REF_NAME does not match package\.json version/);
    expect(release).toMatch(/v\$\{SDK_VERSION\}.*!=.*\$REF_NAME/);
  });

  it('release.yml refuses to publish when the engine, SDK and Python versions have drifted', () => {
    expect(release).toMatch(/\$ENGINE_VERSION" != "\$SDK_VERSION/);
    expect(release).toMatch(/\$PY_VERSION" != "\$SDK_VERSION/);
  });

  it('python-publish.yml refuses a tag that does not name pyproject.toml version, or npm versions that differ', () => {
    expect(python).toMatch(/Tag \$REF_NAME does not match python\/pyproject\.toml version/);
    expect(python).toMatch(/v\$\{PY_VERSION\}.*!=.*\$REF_NAME/);
    expect(python).toMatch(/\$SDK_VERSION" != "\$PY_VERSION" \] \|\| \[ "\$ENGINE_VERSION" != "\$PY_VERSION/);
  });

  it('release.yml checks the packed SDK depends on exactly this engine version, not a workspace specifier', () => {
    const build = jobBlock(release, 'build');
    expect(build).toMatch(/\(cd packages\/engine && pnpm pack --pack-destination "\$out"\)\n\s+pnpm pack --pack-destination "\$out"/);
    expect(build).toMatch(/dependencies\["@tzun\/engine"\]/);
    expect(build).toMatch(/startsWith\("workspace:"\)/);
  });

  it('treats "already published" on npm as a failure on a first attempt, not a green no-op, for each package', () => {
    const guards = steps(jobBlock(release, 'publish')).filter((s) => /idempotency guard/.test(s));
    expect(guards.map((s) => (s.match(/@tzun\/(engine|sdk)@/) ?? [])[1])).toEqual(['engine', 'sdk']);
    for (const step of guards) {
      expect(step).toMatch(/npm view "@tzun\/(engine|sdk)@\$\{VERSION\}" version --registry "\$REGISTRY"/);
      // npm view of a missing version of an existing package exits 0 with no
      // output, so both the status and the output are checked.
      expect(step).toMatch(/if \[ "\$rc" = "0" \] && \[ -n "\$published" \]; then/);
      expect(step).toMatch(/GITHUB_RUN_ATTEMPT/);
      expect(step).toMatch(/is already published[\s\S]{0,300}?exit 1/);
    }
  });

  it('treats "already published" on PyPI the same way', () => {
    const guard = steps(jobBlock(python, 'publish')).find((s) => /idempotency guard/.test(s));
    expect(guard).toBeDefined();
    expect(guard).toMatch(/https:\/\/pypi\.org\/pypi\/tzun-sdk\/\$\{VERSION\}\/json/);
    expect(guard).toMatch(/GITHUB_RUN_ATTEMPT/);
    expect(guard).toMatch(/is already published[\s\S]{0,300}?exit 1/);
    // Anything but 200 or 404 is an answer the guard cannot read: fail.
    expect(guard).toMatch(/elif \[ "\$code" = "404" \]; then[\s\S]*?else[\s\S]*?exit 1/);
  });

  it('python-publish.yml checks the built metadata says the tag version and the licence expression pyproject.toml declares', () => {
    const build = jobBlock(python, 'build');
    expect(build).toMatch(/'Version': \(meta\.get\('Version'\), version\)/);
    const declared = pyproject.match(/^license = "([^"]+)"$/m);
    expect(declared).not.toBeNull();
    expect(build).toContain(`'License-Expression': (meta.get('License-Expression'), '${declared![1]}'),`);
    expect(build).toMatch(/'Name': \(meta\.get\('Name'\), 'tzun-sdk'\)/);
  });

  it('fails CI on a branch that changes publishable source without a version bump, or lets the versions drift', () => {
    expect(ci).toMatch(/version-bump-guard:/);
    expect(ci).toMatch(/packages\/engine\/src changed but @tzun\/engine is still/);
    expect(ci).toMatch(/src\/ changed but @tzun\/sdk is still/);
    expect(ci).toMatch(/python\/pyproject\.toml \(\$python_head\) and @tzun\/sdk \(\$sdk_head\) must stay on the same version/);
  });
});
