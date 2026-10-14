/**
 * Structural pins on .github/workflows.
 *
 *  1. Push CI runs on main and release/** only. Any other branch gets the
 *     same jobs from its pull request against main, on the same SHA, so
 *     listing it under `push` too would run every job twice;
 *     workflow_dispatch is the escape hatch for a branch that has no PR.
 *
 *  2. One flaky leg must not hide the rest. Under the default fail-fast, one
 *     red leg of a matrix cancels the others and skips the jobs that `need`
 *     it. One red leg fails the workflow regardless; cancelling the others
 *     only removes data. Every matrix declares fail-fast: false.
 *
 *  3. Where jobs run. Every job of every workflow runs on ubuntu-latest,
 *     written out: a pull request from a fork runs these workflows, so no job
 *     may take its runner from a repository or organisation variable that
 *     could point it at a machine the project keeps. npm trusted publishing
 *     also works from GitHub-hosted runners only.
 *
 *  4. Draft PRs run the build only when marked ready. A workflow with a
 *     pull_request trigger lists ready_for_review among its types, and every
 *     job in it skips while the PR is a draft, except public-hygiene.yml's: a
 *     draft's title, body and commits are as public as any other.
 *
 *  5. public-hygiene.yml runs the guard's self-test, then the guard over the
 *     tree, the commit range and the pull request text, and .githooks/commit-msg
 *     runs it over each commit message.
 *
 * Deliberately no YAML library: a test of the CI surface must not add
 * anything to the lockfile. The parser below understands exactly the shapes
 * this repo writes — a top-level `on:` block, a `push:` or `pull_request:`
 * mapping under it, a `branches:` or `types:` flow sequence or block list,
 * `strategy:` mappings, and the jobs under `jobs:`.
 */
import * as fs from 'fs';
import * as path from 'path';

const WF = path.join(__dirname, '..', '..', '.github', 'workflows');
const files = fs.readdirSync(WF).filter((f) => /\.ya?ml$/.test(f)).sort();

const indentOf = (line: string): number => (line.match(/^ */) as RegExpMatchArray)[0].length;
const isBlankOrComment = (line: string): boolean => /^\s*(#.*)?$/.test(line);

/** Lines of the block a `key:` line at index `at` opens (deeper indent only). */
function blockAfter(lines: string[], at: number): string[] {
  const base = indentOf(lines[at]);
  const out: string[] = [];
  for (let i = at + 1; i < lines.length; i++) {
    if (isBlankOrComment(lines[i])) continue;
    if (indentOf(lines[i]) <= base) break;
    out.push(lines[i]);
  }
  return out;
}

const unquote = (s: string): string => s.trim().replace(/^['"]|['"]$/g, '');

/** The list under `key:` in a trigger's block (flow sequence or block list), or null. */
function listIn(block: string[], key: string): string[] | null {
  if (block.length === 0) return null;
  const base = indentOf(block[0]);
  const at = block.findIndex((l) => indentOf(l) === base && new RegExp(`^\\s*${key}:`).test(l));
  if (at < 0) return null;
  const flow = block[at].match(new RegExp(`${key}:\\s*\\[(.*)\\]\\s*$`));
  if (flow) return flow[1].split(',').map(unquote).filter(Boolean);
  const items: string[] = [];
  for (let i = at + 1; i < block.length && indentOf(block[i]) > base; i++) {
    const m = block[i].match(/^\s*-\s*(.+)$/);
    if (m) items.push(unquote(m[1]));
  }
  return items;
}

/**
 * Direct children of `on:`, the push trigger's branch list and the
 * pull_request trigger's types, each null when the trigger or key is absent.
 */
function triggers(text: string): {
  names: string[];
  pushBranches: string[] | null;
  prTypes: string[] | null;
} {
  const lines = text.split('\n');
  const onAt = lines.findIndex((l) => /^on:\s*$/.test(l));
  if (onAt < 0) return { names: [], pushBranches: null, prTypes: null };
  const on = blockAfter(lines, onAt);
  const childIndent = indentOf(on[0]);
  const names = on
    .filter((l) => indentOf(l) === childIndent)
    .map((l) => l.trim().replace(/:.*$/, ''));
  const child = (name: string): string[] | null => {
    const at = lines.findIndex(
      (l, i) => i > onAt && indentOf(l) === childIndent && new RegExp(`^\\s*${name}:\\s*$`).test(l),
    );
    return at < 0 ? null : blockAfter(lines, at);
  };
  const push = child('push');
  const pr = child('pull_request');
  return {
    names,
    pushBranches: push ? listIn(push, 'branches') : null,
    prTypes: pr ? listIn(pr, 'types') : null,
  };
}

/** Each job under `jobs:` with its `runs-on:` and `if:` values (null when absent). */
function jobsOf(text: string): Array<{ job: string; runsOn: string | null; cond: string | null }> {
  const lines = text.split('\n');
  const at = lines.findIndex((l) => /^jobs:\s*$/.test(l));
  if (at < 0) return [];
  const out: Array<{ job: string; runsOn: string | null; cond: string | null }> = [];
  for (let i = at + 1; i < lines.length; i++) {
    if (isBlankOrComment(lines[i])) continue;
    if (indentOf(lines[i]) === 0) break;
    const j = lines[i].match(/^  ([A-Za-z0-9_-]+):\s*$/);
    if (!j) continue;
    const body = blockAfter(lines, i);
    const key = (k: string): string | null => {
      const l = body.find((x) => indentOf(x) === 4 && new RegExp(`^\\s*${k}:`).test(x));
      return l ? l.replace(new RegExp(`^\\s*${k}:\\s*`), '').trim() : null;
    };
    out.push({ job: j[1], runsOn: key('runs-on'), cond: key('if') });
  }
  return out;
}

/** Every `strategy:` block, as { job, failFast } where failFast is the declared value or null. */
function strategies(text: string): Array<{ job: string; failFast: string | null }> {
  const lines = text.split('\n');
  const out: Array<{ job: string; failFast: string | null }> = [];
  let job = '?';
  lines.forEach((line, i) => {
    const j = line.match(/^  ([A-Za-z0-9_-]+):\s*$/);
    if (j) job = j[1];
    if (!/^\s+strategy:\s*$/.test(line)) return;
    const ff = blockAfter(lines, i)
      .map((l) => l.match(/^\s*fail-fast:\s*(\S+)/))
      .find(Boolean);
    out.push({ job, failFast: ff ? ff[1] : null });
  });
  return out;
}

describe('.github/workflows trigger policy', () => {
  it('finds the workflows', () => {
    expect(files).toContain('ci.yml');
  });

  for (const f of files) {
    const text = fs.readFileSync(path.join(WF, f), 'utf8');
    const { names, pushBranches } = triggers(text);
    if (pushBranches === null) continue; // tag-push / dispatch-only workflows are out of scope

    it(`${f}: push CI does not run on merge/** — the candidate's PR already runs these jobs`, () => {
      expect(pushBranches.filter((b) => b.startsWith('merge/'))).toEqual([]);
    });

    // Only the commit check suites (the workflows a PR runs) carry this
    // shape; auto-release.yml runs on main alone and has no PR leg.
    if (!names.includes('pull_request')) continue;

    it(`${f}: push CI still covers main and release/**, with workflow_dispatch as the escape hatch`, () => {
      expect(pushBranches).toEqual(expect.arrayContaining(['main', 'release/**']));
      expect(names).toContain('workflow_dispatch');
    });
  }
});

describe('.github/workflows matrix policy', () => {
  const ci = fs.readFileSync(path.join(WF, 'ci.yml'), 'utf8');
  const found = strategies(ci);

  it('ci.yml still has the Python matrix this pins (non-vacuity)', () => {
    expect(found.map((s) => s.job)).toContain('python');
  });

  for (const { job, failFast } of found) {
    it(`ci.yml job "${job}": matrix declares fail-fast: false so one flaky leg cannot cancel the others`, () => {
      expect(failFast).toBe('false');
    });
  }
});

/** The only repository variable a workflow may read: the release allowlist. */
const ALLOWED_VARS = ['RELEASE_ACTORS'];

describe('.github/workflows runner policy', () => {
  it('finds the workflows this policy covers (non-vacuity)', () => {
    expect(files).toEqual(expect.arrayContaining(['ci.yml', 'release.yml', 'python-publish.yml', 'public-hygiene.yml']));
  });

  for (const f of files) {
    const text = fs.readFileSync(path.join(WF, f), 'utf8');
    const jobs = jobsOf(text);

    it(`${f}: declares jobs`, () => {
      expect(jobs.length).toBeGreaterThan(0);
    });

    for (const { job, runsOn } of jobs) {
      it(`${f} job "${job}": runs-on is ubuntu-latest, written out`, () => {
        expect(runsOn).toBe('ubuntu-latest');
      });
    }

    it(`${f}: reads no repository variable but ${ALLOWED_VARS.join(', ')}, and names no self-hosted runner`, () => {
      const vars = [...text.matchAll(/vars\.([A-Za-z0-9_]+)/g)].map((m) => m[1]);
      expect(vars.filter((v) => !ALLOWED_VARS.includes(v))).toEqual([]);
      expect(text).not.toMatch(/self-hosted/);
    });
  }
});

/**
 * Workflows exempt from the draft-PR skip, and why. Their pull_request types
 * may add to the default four.
 */
const DRAFT_EXEMPT: Record<string, { why: string; extraTypes: string[] }> = {
  'public-hygiene.yml': {
    why: "a draft's title, body and commits are public; `edited` re-checks a title or body changed without a push",
    extraTypes: ['edited'],
  },
};

describe('.github/workflows skip draft PRs', () => {
  const DRAFT_GUARD = 'github.event.pull_request.draft != true';
  const withPr = files.filter((f) =>
    triggers(fs.readFileSync(path.join(WF, f), 'utf8')).names.includes('pull_request'),
  );

  it('ci.yml has a pull_request trigger (non-vacuity)', () => {
    expect(withPr).toContain('ci.yml');
  });

  it('every DRAFT_EXEMPT entry is a workflow with a pull_request trigger (no stale exemptions)', () => {
    expect(Object.keys(DRAFT_EXEMPT).filter((f) => !withPr.includes(f))).toEqual([]);
  });

  for (const f of withPr) {
    const text = fs.readFileSync(path.join(WF, f), 'utf8');
    const exempt = DRAFT_EXEMPT[f];

    it(`${f}: pull_request runs on ready_for_review as well as the default types`, () => {
      const expected = ['opened', 'synchronize', 'reopened', ...(exempt?.extraTypes ?? []), 'ready_for_review'];
      expect(triggers(text).prTypes).toEqual(expected);
    });

    for (const { job, cond } of jobsOf(text)) {
      if (exempt) {
        it(`${f} job "${job}": runs on draft PRs too (${exempt.why})`, () => {
          expect(cond ?? '').not.toContain(DRAFT_GUARD);
        });
        continue;
      }
      it(`${f} job "${job}": skips on a draft PR`, () => {
        expect(cond ?? '').toContain(DRAFT_GUARD);
      });
    }
  }
});

describe('public hygiene: the workflow and the commit-msg hook', () => {
  const ROOT = path.join(__dirname, '..', '..');
  const hygiene = fs.readFileSync(path.join(WF, 'public-hygiene.yml'), 'utf8');

  it('runs on pushes to main, release/** and v* tags, on pull requests to main, and on demand', () => {
    const t = triggers(hygiene);
    expect(t.names).toEqual(['push', 'pull_request', 'workflow_dispatch']);
    expect(t.pushBranches).toEqual(['main', 'release/**']);
    expect(hygiene).toMatch(/^ {4}tags: \['v\*'\]$/m);
    expect(hygiene).toMatch(/^ {2}pull_request:\n {4}branches: \[main\]$/m);
  });

  it("runs the guard's self-test, then the tree, the commit range and the pull request text, in that order", () => {
    const order = [
      'run: scripts/test-public-hygiene.sh',
      'run: scripts/check-public-hygiene.sh tree',
      'scripts/check-public-hygiene.sh commits "$range"',
      'scripts/check-public-hygiene.sh text "pull request"',
    ].map((s) => hygiene.indexOf(s));
    expect(order.every((i) => i > 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    // A failing self-test or tree check must not hide the later checks.
    expect(hygiene.match(/if: \$\{\{ !cancelled\(\)/g)?.length).toBe(3);
  });

  it('checks the commits of the pushed or pull request range, with the full history checked out', () => {
    expect(hygiene).toMatch(/fetch-depth: 0/);
    expect(hygiene).toMatch(/range="\$PR_BASE\.\.\$PR_HEAD"/);
    expect(hygiene).toMatch(/range="\$BEFORE\.\.\$AFTER"/);
  });

  it('passes the pull request title and body in the environment, never into the script', () => {
    expect(hygiene).toMatch(/PR_TITLE: \$\{\{ github\.event\.pull_request\.title \}\}/);
    expect(hygiene).toMatch(/PR_BODY: \$\{\{ github\.event\.pull_request\.body \}\}/);
    // No expression in any run: line or block reads event text.
    for (const m of hygiene.matchAll(/run: [^\n]*(?:\n(?: {10}|\s*$)[^\n]*)*/g)) {
      expect(m[0]).not.toMatch(/\$\{\{\s*github\.event/);
    }
    expect(hygiene).toMatch(/printf '%s\\n\\n%s\\n' "\$PR_TITLE" "\$PR_BODY" \| scripts\/check-public-hygiene\.sh text "pull request"/);
  });

  it('has an executable commit-msg hook that checks the message with the same guard', () => {
    const hook = path.join(ROOT, '.githooks', 'commit-msg');
    expect(fs.existsSync(hook)).toBe(true);
    expect(fs.statSync(hook).mode & 0o111).not.toBe(0);
    const text = fs.readFileSync(hook, 'utf8');
    expect(text.startsWith('#!/usr/bin/env bash\n')).toBe(true);
    expect(text).toMatch(/"\$1"/);
    expect(text).toMatch(/scripts\/check-public-hygiene\.sh" text commit-msg/);
  });
});
