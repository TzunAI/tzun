/**
 * "Merged to main" means "published".
 *
 * release.yml and python-publish.yml run on a `v*.*.*` tag; ci.yml's
 * version-bump guard makes every src/ merge bump the version; and
 * .github/workflows/auto-release.yml closes the loop: on every push to main it
 * tags the version (if the tag does not exist yet and the CHANGELOG has its
 * section) and dispatches both publishing workflows on the tag, because a tag
 * created with the workflow token does not trigger `on: push: tags`.
 * release.yml's github-release job then drafts the GitHub Release from the
 * CHANGELOG section.
 *
 * The decision logic lives in scripts/release/release-state.cjs so it can be
 * tested here without pushing anything; the workflow-file assertions pin the
 * wiring the script cannot see.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const releaseState = require('../../scripts/release/release-state.cjs') as {
  lockstepError(v: { sdk: unknown; engine: unknown }): string | null;
  changelogSection(changelog: string, version: string): { heading: string; body: string } | null;
  plan(s: {
    sdk: string;
    engine: string;
    tagExists: boolean;
    releaseRunExists: boolean;
    changelog: string;
  }): { action: string; version: string; tag: string; reason: string; notes?: string };
};

const REPO_ROOT = resolve(__dirname, '..', '..');
const SCRIPT = join(REPO_ROOT, 'scripts', 'release', 'release-state.cjs');
const WORKFLOWS = join(REPO_ROOT, '.github', 'workflows');

function read(rel: string): string {
  return readFileSync(join(REPO_ROOT, rel), 'utf-8');
}

/** The text of job `name`: from its `  name:` line to the next job, or the end of the file. */
function jobBlock(wf: string, name: string): string {
  const lines = wf.split('\n');
  const start = lines.findIndex((l) => l === `  ${name}:`);
  if (start < 0) return '';
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^ {2}[A-Za-z0-9_-]+:\s*$/.test(lines[i]) || /^\S/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join('\n');
}

const CHANGELOG_FIXTURE = [
  '# Changelog',
  '',
  '## [Unreleased]',
  '',
  '## [0.3.15] — 2026-09-10',
  '',
  '### Fixed',
  '- the thing',
  '',
  '## [0.3.14] — 2026-09-09',
  '',
  '### Added',
  '- `CustodyEntry` gains two optional fields.',
  '',
  '## [0.3.1] — 2026-09-01',
  '',
  '### Fixed',
  '- older',
].join('\n');

/** A throwaway repo root with the three files the CLI reads. */
function fixtureRoot(opts: { sdk: string; engine?: string; changelog?: string }): string {
  const root = mkdtempSync(join(tmpdir(), 'release-state-'));
  mkdirSync(join(root, 'packages', 'engine'), { recursive: true });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: '@tzun/sdk', version: opts.sdk }));
  writeFileSync(
    join(root, 'packages', 'engine', 'package.json'),
    JSON.stringify({ name: '@tzun/engine', version: opts.engine ?? opts.sdk })
  );
  writeFileSync(join(root, 'CHANGELOG.md'), opts.changelog ?? CHANGELOG_FIXTURE);
  return root;
}

function runCli(args: string[], env: Record<string, string> = {}): { code: number; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync(process.execPath, [SCRIPT, ...args], {
      encoding: 'utf-8',
      env: { ...process.env, GITHUB_OUTPUT: '', ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { code: 0, stdout, stderr: '' };
  } catch (e) {
    const err = e as { status: number; stdout: string; stderr: string };
    return { code: err.status, stdout: String(err.stdout ?? ''), stderr: String(err.stderr ?? '') };
  }
}

describe('release-state: lockstep', () => {
  it('accepts matching MAJOR.MINOR.PATCH versions', () => {
    expect(releaseState.lockstepError({ sdk: '0.3.14', engine: '0.3.14' })).toBeNull();
  });

  it('refuses an engine that has drifted from the SDK (a split publish strands consumers)', () => {
    const err = releaseState.lockstepError({ sdk: '0.3.15', engine: '0.3.14' });
    expect(err).toMatch(/engine is at 0\.3\.14 but @tzun\/sdk is at 0\.3\.15/);
  });

  it('refuses a version that is not a plain semver triple (the tag is v<MAJOR.MINOR.PATCH>)', () => {
    expect(releaseState.lockstepError({ sdk: '0.3.15-rc.1', engine: '0.3.15-rc.1' })).toMatch(/MAJOR\.MINOR\.PATCH/);
    expect(releaseState.lockstepError({ sdk: undefined, engine: undefined })).toMatch(/MAJOR\.MINOR\.PATCH/);
  });
});

describe('release-state: CHANGELOG section', () => {
  it('returns the body of the exact `## [version]` section, up to the next heading', () => {
    const s = releaseState.changelogSection(CHANGELOG_FIXTURE, '0.3.14');
    expect(s).not.toBeNull();
    expect(s!.heading).toBe('## [0.3.14] — 2026-09-09');
    expect(s!.body).toBe('### Added\n- `CustodyEntry` gains two optional fields.');
  });

  it('matches the version exactly — 0.3.1 must not match 0.3.14 or 0.3.15', () => {
    expect(releaseState.changelogSection(CHANGELOG_FIXTURE, '0.3.1')!.body).toBe('### Fixed\n- older');
    expect(releaseState.changelogSection(CHANGELOG_FIXTURE, '0.3.1')!.heading).toContain('[0.3.1]');
  });

  it('returns the last section in the file when there is no following heading', () => {
    expect(releaseState.changelogSection(CHANGELOG_FIXTURE, '0.3.1')).not.toBeNull();
  });

  it('returns null for a version without a section, and never treats [Unreleased] as one', () => {
    expect(releaseState.changelogSection(CHANGELOG_FIXTURE, '0.3.16')).toBeNull();
    expect(releaseState.changelogSection(CHANGELOG_FIXTURE, 'Unreleased')).not.toBeNull(); // literal lookup works…
    expect(releaseState.plan({ sdk: '0.3.16', engine: '0.3.16', tagExists: false, releaseRunExists: false, changelog: CHANGELOG_FIXTURE }).action).toBe('fail'); // …but plan() only ever asks for the version
  });

  it('reports an empty section as empty, not as missing', () => {
    const empty = '# Changelog\n\n## [0.3.15] — 2026-09-10\n\n## [0.3.14] — 2026-09-09\n\n- x\n';
    expect(releaseState.changelogSection(empty, '0.3.15')).toEqual({ heading: '## [0.3.15] — 2026-09-10', body: '' });
  });
});

describe('release-state: plan (the decision table)', () => {
  const base = { sdk: '0.3.15', engine: '0.3.15', changelog: CHANGELOG_FIXTURE };

  it('tag missing + CHANGELOG section present → tag-and-dispatch, carrying the section as the release note', () => {
    const p = releaseState.plan({ ...base, tagExists: false, releaseRunExists: false });
    expect(p.action).toBe('tag-and-dispatch');
    expect(p.tag).toBe('v0.3.15');
    expect(p.version).toBe('0.3.15');
    expect(p.notes).toBe('### Fixed\n- the thing');
  });

  it('tag missing + no CHANGELOG section → fail, saying the section is the release note', () => {
    const p = releaseState.plan({ ...base, sdk: '0.3.16', engine: '0.3.16', tagExists: false, releaseRunExists: false });
    expect(p.action).toBe('fail');
    expect(p.reason).toMatch(/no "## \[0\.3\.16\]" section/);
    expect(p.reason).toMatch(/release note/);
  });

  it('tag missing + empty CHANGELOG section → fail', () => {
    const changelog = '# Changelog\n\n## [0.3.15] — 2026-09-10\n\n## [0.3.14] — 2026-09-09\n\n- x\n';
    const p = releaseState.plan({ ...base, changelog, tagExists: false, releaseRunExists: false });
    expect(p.action).toBe('fail');
    expect(p.reason).toMatch(/is empty/);
  });

  it('tag exists + release.yml already ran for it → noop', () => {
    const p = releaseState.plan({ ...base, tagExists: true, releaseRunExists: true });
    expect(p.action).toBe('noop');
    expect(p.reason).toMatch(/already exists and release\.yml has already run/);
  });

  it('tag exists + release.yml never ran for it → dispatch without re-tagging (heals a run that died between the two)', () => {
    const p = releaseState.plan({ ...base, tagExists: true, releaseRunExists: false });
    expect(p.action).toBe('dispatch');
    expect(p.tag).toBe('v0.3.15');
  });

  it('a tag that exists does not need a CHANGELOG section to reach dispatch/noop (the section is checked before tagging)', () => {
    const p = releaseState.plan({ ...base, sdk: '0.3.16', engine: '0.3.16', tagExists: true, releaseRunExists: false });
    expect(p.action).toBe('dispatch');
  });

  it('lockstep mismatch → fail before anything else, whatever the tag state', () => {
    for (const tagExists of [true, false]) {
      const p = releaseState.plan({ ...base, engine: '0.3.14', tagExists, releaseRunExists: false });
      expect(p.action).toBe('fail');
      expect(p.reason).toMatch(/Both must move together/);
    }
  });
});

describe('release-state: CLI (what the workflows actually call)', () => {
  it('`version` prints the lockstep version, or fails loudly with an ::error:: annotation', () => {
    expect(runCli(['version', `--root=${fixtureRoot({ sdk: '0.3.15' })}`])).toMatchObject({ code: 0, stdout: '0.3.15\n' });
    const bad = runCli(['version', `--root=${fixtureRoot({ sdk: '0.3.15', engine: '0.3.14' })}`]);
    expect(bad.code).toBe(1);
    expect(bad.stderr).toMatch(/^::error::@tzun\/engine is at 0\.3\.14/m);
  });

  it('`notes <version>` prints the section body, or fails with ::error:: when there is none', () => {
    const root = fixtureRoot({ sdk: '0.3.15' });
    expect(runCli(['notes', '0.3.14', `--root=${root}`])).toMatchObject({
      code: 0,
      stdout: '### Added\n- `CustodyEntry` gains two optional fields.\n',
    });
    const missing = runCli(['notes', '0.3.16', `--root=${root}`]);
    expect(missing.code).toBe(1);
    expect(missing.stderr).toMatch(/^::error::CHANGELOG\.md has no non-empty "## \[0\.3\.16\]" section/m);
  });

  it('`plan` writes action/tag/version/reason to GITHUB_OUTPUT and exits 0 on a releasable state', () => {
    const root = fixtureRoot({ sdk: '0.3.15' });
    const out = join(root, 'gh-output.txt');
    writeFileSync(out, '');
    const r = runCli(['plan', '--tag-exists=false', '--release-run-exists=false', `--root=${root}`], { GITHUB_OUTPUT: out });
    expect(r.code).toBe(0);
    const written = readFileSync(out, 'utf-8');
    expect(written).toMatch(/^action=tag-and-dispatch$/m);
    expect(written).toMatch(/^tag=v0\.3\.15$/m);
    expect(written).toMatch(/^version=0\.3\.15$/m);
    expect(written).toMatch(/^reason=v0\.3\.15 does not exist yet/m);
    // The multi-line release note never goes through GITHUB_OUTPUT (it would
    // need the heredoc form); the github-release job re-extracts it.
    expect(written).not.toMatch(/notes=/);
    expect(JSON.parse(r.stdout)).toMatchObject({ action: 'tag-and-dispatch', tag: 'v0.3.15' });
  });

  it('`plan` exits 1 with an ::error:: on a failing state, still recording the action', () => {
    const root = fixtureRoot({ sdk: '0.3.16' });
    const out = join(root, 'gh-output.txt');
    writeFileSync(out, '');
    const r = runCli(['plan', '--tag-exists=false', '--release-run-exists=false', `--root=${root}`], { GITHUB_OUTPUT: out });
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/^::error::CHANGELOG\.md has no "## \[0\.3\.16\]" section/m);
    expect(readFileSync(out, 'utf-8')).toMatch(/^action=fail$/m);
  });

  it('`plan` refuses a malformed boolean rather than guessing (a typo must not become a no-op)', () => {
    const root = fixtureRoot({ sdk: '0.3.15' });
    const r = runCli(['plan', '--tag-exists=yes', '--release-run-exists=false', `--root=${root}`]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/--tag-exists must be exactly "true" or "false"/);
    const missing = runCli(['plan', '--tag-exists=true', `--root=${root}`]);
    expect(missing.code).toBe(1);
    expect(missing.stderr).toMatch(/--release-run-exists must be exactly/);
  });
});

describe('release-on-main: this repo is in a releasable state', () => {
  it('package.json and packages/engine/package.json agree, and the version has its CHANGELOG section (the release note the next merge will ship)', () => {
    const sdk = JSON.parse(read('package.json')).version as string;
    const engine = JSON.parse(read('packages/engine/package.json')).version as string;
    expect(releaseState.lockstepError({ sdk, engine })).toBeNull();
    const section = releaseState.changelogSection(read('CHANGELOG.md'), sdk);
    expect(section).not.toBeNull();
    expect(section!.body.length).toBeGreaterThan(0);
  });
});

describe('release-on-main: workflow wiring', () => {
  const auto = read('.github/workflows/auto-release.yml');
  const release = read('.github/workflows/release.yml');
  const python = read('.github/workflows/python-publish.yml');

  it('auto-release runs on every push to main and can be re-run by hand', () => {
    expect(auto).toMatch(/^on:\n\s+push:\n\s+branches: \[main\]\n\s+workflow_dispatch:/m);
  });

  it('auto-release serialises itself and never cancels a run mid-tag', () => {
    // Comment lines between the key and its fields are allowed; a group or
    // a cancel policy other than these is not.
    expect(auto).toMatch(/^concurrency:\n(?:\s*#.*\n)*\s+group: auto-release-main\n\s+cancel-in-progress: false/m);
  });

  it('auto-release holds write scopes on the job only, and only the two it needs', () => {
    expect(auto).toMatch(/^permissions:\n\s+contents: read\n/m);
    expect(auto).toMatch(/^\s{4}permissions:\n\s+contents: write\s+#.*\n\s+actions: write/m);
    expect(auto).not.toMatch(/packages:\s*write/);
    expect(auto).not.toMatch(/id-token:/);
  });

  it('auto-release refuses to tag from anything but main, and enforces the release allowlist with no default', () => {
    expect(auto).toMatch(/if \[ "\$REF" != "refs\/heads\/main" \]/);
    for (const wf of [auto, release, python]) {
      expect(wf).toMatch(/ALLOWED: \$\{\{ vars\.RELEASE_ACTORS \}\}/);
      expect(wf).toMatch(/allowed="\$\{ALLOWED:-\}"/);
      // No fallback login anywhere: an unset variable refuses every actor.
      expect(wf).not.toMatch(/\$\{ALLOWED:-[^}]/);
    }
  });

  it('auto-release decides through the tested script, not inline shell', () => {
    expect(auto).toMatch(/node scripts\/release\/release-state\.cjs version/);
    expect(auto).toMatch(/node scripts\/release\/release-state\.cjs plan \\\n\s+--tag-exists="\$TAG_EXISTS" \\\n\s+--release-run-exists="\$RELEASE_RUN_EXISTS"/);
  });

  it('auto-release creates an annotated tag object, then its ref, via the exact-match ref endpoints', () => {
    expect(auto).toMatch(/gh api "repos\/\$REPO\/git\/tags"/);
    expect(auto).toMatch(/-f ref="refs\/tags\/\$TAG" -f sha="\$tag_sha"/);
    expect(auto).toMatch(/gh api "repos\/\$REPO\/git\/ref\/tags\/\$TAG"/);
    expect(auto).not.toMatch(/git\/refs\/tags/);
  });

  it('auto-release dispatches release.yml on the tag ref with the confirmation token release.yml checks', () => {
    // release.yml: expected="PUBLISH-${REF_NAME#v}" compared to inputs.confirm.
    expect(release).toMatch(/expected="PUBLISH-\$\{REF_NAME#v\}"/);
    expect(auto).toMatch(/gh workflow run release\.yml --ref "\$TAG" -f confirm="PUBLISH-\$VERSION" -f reason="\$reason"/);
    expect(auto).toMatch(/reason="auto-release on main by \$ACTOR \(\$RUN_URL\)"/);
  });

  it('auto-release also dispatches python-publish.yml on the tag, once, with the same confirmation token', () => {
    expect(python).toMatch(/expected="PUBLISH-\$\{REF_NAME#v\}"/);
    expect(auto).toMatch(/gh run list --workflow python-publish\.yml --branch "\$TAG"/);
    expect(auto).toMatch(/gh workflow run python-publish\.yml --ref "\$TAG" -f confirm="PUBLISH-\$VERSION" -f reason="\$reason"/);
    expect(auto).toMatch(/if: steps\.plan\.outputs\.action != 'fail' && steps\.lookup\.outputs\.python_run_exists != 'true'/);
  });

  it('both publishing workflows accept the workflow token as actor only for an auto-release dispatch', () => {
    for (const wf of [release, python]) {
      expect(wf).toMatch(/\[ "\$EVENT" = "workflow_dispatch" \] && \[ "\$ACTOR" = "github-actions\[bot\]" \]/);
      expect(wf).toMatch(/"auto-release on main by "\*\)/);
    }
  });

  it('release.yml drafts the GitHub Release only after the publish job, from the CHANGELOG section, with contents: write on that job alone', () => {
    const job = jobBlock(release, 'github-release');
    expect(job.length).toBeGreaterThan(0);
    expect(job).toMatch(/needs: \[authorize, publish\]/);
    expect(job).toMatch(/contents: write/);
    expect(job).toMatch(/node scripts\/release\/release-state\.cjs notes "\$\{REF_NAME#v\}" > "\$RUNNER_TEMP\/release-notes\.md"/);
    // The note is public text; the hygiene guard reads it before it is posted.
    expect(job).toMatch(/scripts\/check-public-hygiene\.sh text "release note" < "\$RUNNER_TEMP\/release-notes\.md"/);
    // A draft: the staged packages are not installable until a maintainer
    // approves them on npm, so the Release is published by hand after that.
    expect(job).toMatch(/gh release create "\$TAG" --repo "\$REPO" --title "\$TAG" --notes-file "\$RUNNER_TEMP\/release-notes\.md" --verify-tag --draft/);
    // github-release is the last job, and nothing before it holds contents: write.
    const jobs = [...release.slice(release.indexOf('\njobs:')).matchAll(/^ {2}([A-Za-z0-9_-]+):\s*$/gm)].map((m) => m[1]);
    expect(jobs).toEqual(['authorize', 'build', 'publish', 'github-release']);
    const before = release.slice(0, release.indexOf('\n  github-release:'));
    expect(before).not.toMatch(/contents: write/);
  });

  it('there is no dependents, push-audit, npm-deprecate or Python-stub workflow, and no workflow refers to the dependents, push-audit or Python-stub one', () => {
    const files = readdirSync(WORKFLOWS);
    for (const gone of ['notify-dependents.yml', 'main-push-audit.yml', 'npm-deprecate.yml', 'python-stub-publish.yml']) {
      expect(files).not.toContain(gone);
      expect(existsSync(join(WORKFLOWS, gone))).toBe(false);
    }
    for (const f of files) {
      expect({ f, refs: /notify-dependents|main-push-audit|python-stub/.test(read(`.github/workflows/${f}`)) }).toEqual({ f, refs: false });
    }
  });
});

describe('release-on-main: the rule is written where maintainers read', () => {
  const RULE = /merging a version bump to main publishes it/i;
  const NOTE = /CHANGELOG section is the release note/i;

  it('CONTRIBUTING.md states the rule and where the release note comes from', () => {
    // Markdown wraps at 80 columns; the sentence may straddle a line break.
    const text = read('CONTRIBUTING.md').replace(/\s+/g, ' ');
    expect(text).toMatch(RULE);
    expect(text).toMatch(NOTE);
  });

  it('no document in this repo tells a maintainer that pushing a tag is the release', () => {
    const offenders: string[] = [];
    for (const file of ['CONTRIBUTING.md', 'README.md', 'CHANGELOG.md']) {
      read(file)
        .split('\n')
        .forEach((line, i) => {
          if (/\b(?:push|create)\s+(?:a|the)\s+(?:git\s+)?tag\b.*\bto\s+(?:release|publish)\b/i.test(line)) {
            offenders.push(`${file}:${i + 1} ${line.trim()}`);
          }
        });
    }
    expect(offenders).toEqual([]);
  });
});
