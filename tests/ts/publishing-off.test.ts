/**
 * The publishing workflows stop while a package is marked unpublishable.
 *
 * npm refuses to publish a package whose package.json sets "private": true, and
 * PyPI refuses an upload that carries the classifier "Private :: Do Not
 * Upload". release.yml and python-publish.yml each check both markers in the
 * first step of their `authorize` job, before anything is built, and fail with
 * a message that says why. auto-release.yml reads the same markers in a job of
 * its own and, while one is set, skips the job that tags and dispatches, and
 * passes with a notice. This file runs those steps' scripts against small
 * trees, and checks where each step sits.
 */
import { spawnSync } from 'child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, join } from 'path';

const WORKFLOW_DIR = join(__dirname, '..', '..', '.github', 'workflows');
const WORKFLOWS = ['release.yml', 'python-publish.yml'];
const STEP = 'Refuse to publish while a package is marked unpublishable';
const MESSAGE = /^::error::Publishing is off while a package is marked unpublishable: see LICENSE\.md\./m;

const readWorkflow = (file: string): string => readFileSync(join(WORKFLOW_DIR, file), 'utf-8');

/** Job `name` of a workflow, from its `  name:` line to the next job or top-level key. */
function jobText(wf: string, name: string): string {
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

/** The steps of job `name`, in file order, each from its `- name:` line to the next. */
function jobSteps(wf: string, name: string): string[] {
  return jobText(wf, name).split(/\n(?= {6}- name: )/).slice(1);
}

/** The jobs of a workflow, in file order. */
function jobNames(wf: string): string[] {
  return [...wf.slice(wf.indexOf('\njobs:')).matchAll(/^ {2}([A-Za-z0-9_-]+):\s*$/gm)].map((m) => m[1]);
}

const stepName = (step: string): string => step.match(/^ {6}- name: (.*)$/m)![1];

/** The shell script of step `stepTitle` of job `job` in `file`, dedented. */
function stepScript(file: string, job: string, stepTitle: string): string {
  const step = jobSteps(readWorkflow(file), job).find((s) => stepName(s) === stepTitle);
  expect({ file, stepTitle, found: Boolean(step) }).toEqual({ file, stepTitle, found: true });
  const lines = step!.split('\n');
  const at = lines.findIndex((l) => /^ {8}run: \|\s*$/.test(l));
  expect(at).toBeGreaterThan(0);
  return lines
    .slice(at + 1)
    .map((l) => l.replace(/^ {10}/, ''))
    .join('\n');
}

/** The shell script of the guard step in `file`, dedented. */
const guardScript = (file: string): string => stepScript(file, 'authorize', STEP);

/** The part of a marker script that reads the three markers into `off`. */
function markerReading(script: string): string {
  const from = script.indexOf('off=""');
  const to = script.indexOf('if [ -n "$off" ]');
  expect({ from: from >= 0, to: to > from }).toEqual({ from: true, to: true });
  return script.slice(from, to);
}

interface Tree {
  sdk?: object | string;
  engine?: object | string;
  pyproject?: string | null;
}

const PYPROJECT_PUBLISHABLE = '[project]\nname = "tzun-sdk"\nclassifiers = [\n  "Topic :: Security :: Cryptography",\n]\n';
const PYPROJECT_PRIVATE = '[project]\nname = "tzun-sdk"\nclassifiers = [\n  "Topic :: Security :: Cryptography",\n  "Private :: Do Not Upload",\n]\n';

/** Trees with one marker set, and how the marker scripts name it. */
const MARKED: Array<[string, Tree, RegExp]> = [
  ['package.json sets private', { sdk: { private: true } }, / package\.json sets private;/],
  ['packages/engine/package.json sets private', { engine: { private: true } }, / packages\/engine\/package\.json sets private;/],
  ['python/pyproject.toml carries the classifier', { pyproject: PYPROJECT_PRIVATE }, /python\/pyproject\.toml carries Private :: Do Not Upload;/],
  ['python/pyproject.toml is missing', { pyproject: null }, /python\/pyproject\.toml carries Private :: Do Not Upload;/],
  ['a package.json cannot be parsed', { engine: '{ not json' }, / packages\/engine\/package\.json sets private;/],
];

/**
 * Runs `script` in a directory holding `tree`; returns its exit status, its
 * output, and what it wrote to $GITHUB_OUTPUT.
 */
function run(script: string, tree: Tree): { status: number | null; out: string; output: string } {
  const dir = mkdtempSync(join(tmpdir(), 'publishing-off-'));
  const outputDir = mkdtempSync(join(tmpdir(), 'publishing-off-output-'));
  const githubOutput = join(outputDir, 'github-output');
  writeFileSync(githubOutput, '');
  try {
    const json = (v: object | string) => (typeof v === 'string' ? v : JSON.stringify(v));
    writeFileSync(join(dir, 'package.json'), json(tree.sdk ?? { name: '@tzun/sdk' }));
    mkdirSync(join(dir, 'packages', 'engine'), { recursive: true });
    writeFileSync(join(dir, 'packages', 'engine', 'package.json'), json(tree.engine ?? { name: '@tzun/engine' }));
    if (tree.pyproject !== null) {
      mkdirSync(join(dir, 'python'));
      writeFileSync(join(dir, 'python', 'pyproject.toml'), tree.pyproject ?? PYPROJECT_PUBLISHABLE);
    }
    return runIn(dir, script, githubOutput);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(outputDir, { recursive: true, force: true });
  }
}

/** Runs `script` in `cwd` as a workflow step runs it, with $GITHUB_OUTPUT at `githubOutput`. */
function runIn(cwd: string, script: string, githubOutput: string): { status: number | null; out: string; output: string } {
  const r = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', script], {
    cwd,
    encoding: 'utf-8',
    env: { PATH: `${dirname(process.execPath)}:${process.env.PATH ?? ''}`, GITHUB_OUTPUT: githubOutput },
  });
  return { status: r.status, out: `${r.stdout}${r.stderr}`, output: readFileSync(githubOutput, 'utf-8') };
}

describe.each(WORKFLOWS)('%s: the unpublishable-package guard', (file) => {
  const script = guardScript(file);

  it('passes when neither package.json sets private and the classifier is absent', () => {
    expect(run(script, {})).toEqual({ status: 0, out: '', output: '' });
    expect(run(script, { sdk: { private: false }, engine: { private: false } })).toEqual({ status: 0, out: '', output: '' });
  });

  it.each(MARKED)('fails, saying publishing is off, when %s', (_label, tree, names) => {
    const r = run(script, tree);
    expect(r.status).toBe(1);
    expect(r.out).toMatch(MESSAGE);
    expect(r.out).toMatch(names);
  });

  it('names every marker that is set', () => {
    const r = run(script, { sdk: { private: true }, engine: { private: true }, pyproject: PYPROJECT_PRIVATE });
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/ package\.json sets private; packages\/engine\/package\.json sets private; python\/pyproject\.toml carries Private :: Do Not Upload;/);
  });

  it('is the first step of the authorize job after the checkout, so nothing is built before it', () => {
    const names = jobSteps(readWorkflow(file), 'authorize').map(stepName);
    expect(names.slice(0, 3)).toEqual(['Checkout code', STEP, 'Require the public repository']);
  });
});

it('release.yml and python-publish.yml run the same guard script', () => {
  expect(guardScript('python-publish.yml')).toBe(guardScript('release.yml'));
});

it('release.yml also refuses a packed manifest that sets private', () => {
  // A second check, on the package.json inside each tarball npm would read.
  expect(readWorkflow('release.yml')).toMatch(/if \(p\.private\) errors\.push\("private is set"\);/);
});

describe('auto-release.yml: no tag while a package is marked unpublishable', () => {
  const AUTO = 'auto-release.yml';
  const MARKERS = 'Read the unpublishable markers';
  const NOTICE = /^::notice title=Auto-release skipped::Publishing is off while a package is marked unpublishable: see LICENSE\.md\./m;
  const script = stepScript(AUTO, 'publishable', MARKERS);

  it('reads the markers exactly as the guard in release.yml and python-publish.yml does', () => {
    expect(markerReading(script)).toBe(markerReading(guardScript('release.yml')));
  });

  it('writes off=false, and says nothing, when no marker is set', () => {
    expect(run(script, {})).toEqual({ status: 0, out: '', output: 'off=false\n' });
    expect(run(script, { sdk: { private: false }, engine: { private: false } })).toEqual({ status: 0, out: '', output: 'off=false\n' });
  });

  it.each(MARKED)('writes off=true and passes with a notice, not an error, when %s', (_label, tree, names) => {
    const r = run(script, tree);
    expect(r.status).toBe(0);
    expect(r.out).toMatch(NOTICE);
    expect(r.out).toMatch(names);
    expect(r.out).not.toMatch(/::error::/);
    expect(r.output).toBe('off=true\n');
  });

  it('writes off=true on this tree, naming all three markers', () => {
    const outputDir = mkdtempSync(join(tmpdir(), 'publishing-off-output-'));
    try {
      const githubOutput = join(outputDir, 'github-output');
      writeFileSync(githubOutput, '');
      const r = runIn(join(__dirname, '..', '..'), script, githubOutput);
      expect(r.status).toBe(0);
      expect(r.out).toMatch(NOTICE);
      expect(r.out).toContain(' package.json sets private; packages/engine/package.json sets private; python/pyproject.toml carries Private :: Do Not Upload;');
      expect(r.output).toBe('off=true\n');
    } finally {
      rmSync(outputDir, { recursive: true, force: true });
    }
  });

  it('the publishable job comes first, reads the markers right after the checkout, holds contents: read only, and exports off', () => {
    const wf = readWorkflow(AUTO);
    expect(jobNames(wf)).toEqual(['publishable', 'release-on-main']);
    const job = jobText(wf, 'publishable');
    expect(jobSteps(wf, 'publishable').map(stepName)).toEqual(['Checkout code', MARKERS]);
    expect(job).toMatch(/^ {4}permissions:\n {6}contents: read\n {4}outputs:\n {6}off: \$\{\{ steps\.markers\.outputs\.off \}\}$/m);
    expect(job).toMatch(/^ {8}id: markers$/m);
    expect(job).not.toMatch(/write/);
  });

  it('the job that tags and dispatches needs it, and runs only when it wrote off=false', () => {
    const job = jobText(readWorkflow(AUTO), 'release-on-main');
    expect(job).toMatch(/^ {4}needs: publishable$/m);
    // An absent or unexpected output skips the job as surely as off=true does.
    expect(job).toMatch(/^ {4}if: needs\.publishable\.outputs\.off == 'false'$/m);
  });
});
