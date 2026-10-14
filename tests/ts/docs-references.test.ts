/**
 * Integrator-facing docs must reference things that exist.
 *
 * The README quick start, the AI-BOM runbook, the anchoring guide and
 * python/README are the first commands an integrator runs, and docs are not
 * compiled: a path that moved, an import from a subpath the package cannot
 * resolve, or an install line for a name that is not published goes unnoticed
 * unless something checks it. This is that check. It is deliberately
 * mechanical: every claim it makes is decidable from the filesystem.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO_ROOT = resolve(__dirname, '..', '..');

/** Docs an integrator is told to follow, in the order they hit them. */
const INTEGRATOR_DOCS = [
  'README.md',
  'python/README.md',
  'packages/engine/README.md',
  'docs/integration/ai-bom-runbook.md',
  'docs/integration/anchor-store.md',
];

/** A command that installs JavaScript packages. */
const INSTALL = String.raw`\b(?:npm (?:install|add|ci|i)|pnpm (?:install|add|i)|yarn (?:install|add))\b`;

/** Every tracked Markdown file. */
function trackedMarkdown(): string[] {
  return execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', '*.md'], { cwd: REPO_ROOT, encoding: 'utf-8' })
    .split('\0')
    .filter((f) => f && existsSync(join(REPO_ROOT, f)));
}

/** Illustrative paths in example snippets that are the reader's, not ours. */
const READER_OWNED = [/^\.\//, /^\//, /^my-/, /example/i, /your-/i, /<[^>]+>/];

function read(rel: string): string {
  return readFileSync(join(REPO_ROOT, rel), 'utf-8');
}

/** Each line of `doc` that matches `re`, as "doc:line: text". */
function linesMatching(doc: string, re: RegExp): string[] {
  const out: string[] = [];
  read(doc)
    .split('\n')
    .forEach((line, i) => {
      if (re.test(line)) out.push(`${doc}:${i + 1}: ${line.trim()}`);
    });
  return out;
}

/**
 * Backticked tokens that look like a path into this repository: they contain a
 * `/`, end in a source/asset extension, and are not marked as the reader's.
 */
function repoPathsIn(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/`([A-Za-z0-9_@./\\-]+\.(?:ts|tsx|py|json|md|mjs|yml))`/g)) {
    const p = m[1];
    if (!p.includes('/')) continue;
    if (READER_OWNED.some((re) => re.test(p))) continue;
    out.add(p);
  }
  return [...out];
}

describe('integrator-facing docs reference things that exist', () => {
  it('names at least one checkable repo path (guard against a vacuous scan)', () => {
    const all = INTEGRATOR_DOCS.flatMap((d) => repoPathsIn(read(d)));
    // If the extraction regex ever stops matching, every assertion below
    // silently passes over an empty list. Fail here instead.
    expect(all.length).toBeGreaterThan(3);
  });

  it.each(INTEGRATOR_DOCS)('%s: every in-repo path it cites exists', (doc) => {
    const missing = repoPathsIn(read(doc)).filter((p) => !existsSync(join(REPO_ROOT, p)));
    expect(missing).toEqual([]);
  });

  it('no Markdown file tells a reader to install a package from npm or PyPI, where none is published', () => {
    // Both package.json files set "private": true and python/pyproject.toml
    // carries "Private :: Do Not Upload" (tests/ts/license-declaration.test.ts),
    // so an install line or a registry page for @tzun/sdk, @tzun/engine or
    // tzun-sdk names nothing a registry holds.
    expect(JSON.parse(read('package.json')).private).toBe(true);
    const docs = trackedMarkdown();
    // Guard: an empty listing would make the check below vacuous.
    expect(docs).toEqual(expect.arrayContaining([...INTEGRATOR_DOCS, 'python/MIGRATION.md', 'clients/py-example/README.md']));
    const offenders = docs.flatMap((doc) => [
      // An install command and an @tzun/ package on one line, in either order
      // (`npm ci   # depends on @tzun/sdk` counts).
      ...linesMatching(doc, new RegExp(`${INSTALL}.*@tzun/|@tzun/.*${INSTALL}`)),
      ...linesMatching(doc, /\bpip install\s+["']?tzun-sdk\b/),
      ...linesMatching(doc, /npmjs\.com\/package\/@tzun\/|pypi\.org\/project\/tzun-sdk/),
    ]);
    expect(offenders).toEqual([]);
  });

  it('README and python/README say the packages are not on the registries yet', () => {
    expect(read('README.md').replace(/\s+/g, ' ')).toMatch(/The packages are not on npm or PyPI\b/);
    expect(read('python/README.md').replace(/\s+/g, ' ')).toMatch(/The package is not on PyPI\b/);
  });

  it('no doc installs from a private package registry, or from git other than this public repository', () => {
    const offenders = INTEGRATOR_DOCS.flatMap((doc) => [
      ...linesMatching(doc, /\bgit\+(?!https:\/\/github\.com\/TzunAI\/tzun\.git[#@"\s])/),
      ...linesMatching(doc, /npm\.pkg\.github\.com/),
    ]);
    expect(offenders).toEqual([]);
  });

  it('no doc imports from a `@tzun/sdk/...` subpath (no exports map to resolve it)', () => {
    const offenders = INTEGRATOR_DOCS.flatMap((doc) => linesMatching(doc, /from\s+'@tzun\/sdk\/[^']+'/));
    expect(offenders).toEqual([]);
  });
});
