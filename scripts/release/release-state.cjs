#!/usr/bin/env node
/**
 * release-state — the decision logic behind "merged to main means published".
 *
 * The CI version-bump guard makes every change to shipped code bump
 * package.json, and a bump that reaches main must also be tagged and published,
 * or the version sits on main unshipped. This module is the pure, unit-testable
 * core of the workflow that guarantees it (.github/workflows/auto-release.yml):
 * given the versions on main, whether the tag exists, whether release.yml
 * already ran for it, and the CHANGELOG, decide exactly one of: fail loudly,
 * no-op, dispatch the publish, or tag + dispatch.
 *
 * Deliberately dependency-free CommonJS: the workflow runs it with the runner's
 * stock `node` before any `pnpm install`, and tests/ts/release-on-main.test.ts
 * requires it through ts-jest (allowJs).
 *
 * CLI (all read package.json / packages/engine/package.json / CHANGELOG.md
 * under --root, default cwd):
 *
 *   release-state.cjs version
 *       Print the version to publish. Exit 1 if @tzun/sdk and @tzun/engine
 *       disagree (they version in lockstep; a split publish strands consumers).
 *   release-state.cjs notes <version>
 *       Print the CHANGELOG `## [<version>]` section body — the release note.
 *       Exit 1 if there is no such section.
 *   release-state.cjs plan --tag-exists=<true|false> --release-run-exists=<true|false>
 *       Print the decision as JSON and, when GITHUB_OUTPUT is set, append
 *       action/tag/version/reason to it. Exit 1 when the decision is `fail`.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const SEMVER_RE = /^\d+\.\d+\.\d+$/;

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/** @returns {{ sdk: string, engine: string }} */
function readVersions(root) {
  return {
    sdk: readJson(path.join(root, 'package.json')).version,
    engine: readJson(path.join(root, 'packages', 'engine', 'package.json')).version,
  };
}

/**
 * The reason the two manifests cannot be released as they stand, or null.
 * @param {{ sdk: string, engine: string }} v
 */
function lockstepError(v) {
  if (typeof v.sdk !== 'string' || !SEMVER_RE.test(v.sdk)) {
    return `package.json version ${JSON.stringify(v.sdk)} is not a plain MAJOR.MINOR.PATCH version; release.yml tags are v<MAJOR.MINOR.PATCH>.`;
  }
  if (v.engine !== v.sdk) {
    return `@tzun/engine is at ${v.engine} but @tzun/sdk is at ${v.sdk}. Both must move together: @tzun/sdk depends on the engine through workspace:*, which pack rewrites to the engine's exact version, so a split publish ships an SDK pinned to an engine this release never publishes.`;
  }
  return null;
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * The body of the Keep-a-Changelog `## [<version>]` section: everything after
 * its heading up to the next `## ` heading (or end of file), trimmed. Null when
 * there is no such heading. `[Unreleased]` is never a match.
 *
 * @param {string} changelog
 * @param {string} version
 * @returns {{ heading: string, body: string } | null}
 */
function changelogSection(changelog, version) {
  const lines = changelog.split(/\r?\n/);
  const headingRe = new RegExp(`^##\\s+\\[${escapeRegExp(version)}\\](\\s|$)`);
  const start = lines.findIndex((l) => headingRe.test(l));
  if (start === -1) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^##\s/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return { heading: lines[start].trim(), body: lines.slice(start + 1, end).join('\n').trim() };
}

/**
 * The decision. Exactly one action; every branch names its reason so the
 * workflow log reads as a sentence.
 *
 * @param {{ sdk: string, engine: string, tagExists: boolean, releaseRunExists: boolean, changelog: string }} s
 * @returns {{ action: 'fail'|'noop'|'dispatch'|'tag-and-dispatch', version: string, tag: string, reason: string, notes?: string }}
 */
function plan(s) {
  const version = s.sdk;
  const tag = `v${version}`;
  const err = lockstepError({ sdk: s.sdk, engine: s.engine });
  if (err) return { action: 'fail', version, tag, reason: err };

  if (s.tagExists) {
    if (s.releaseRunExists) {
      return {
        action: 'noop',
        version,
        tag,
        reason: `${tag} already exists and release.yml has already run for it; nothing to do.`,
      };
    }
    return {
      action: 'dispatch',
      version,
      tag,
      reason: `${tag} exists but release.yml has never run for it (a tag created by the API does not trigger release.yml's tag-push event, and an earlier auto-release may have died between tagging and dispatching). Dispatching the publish.`,
    };
  }

  const section = changelogSection(s.changelog, version);
  if (!section) {
    return {
      action: 'fail',
      version,
      tag,
      reason: `CHANGELOG.md has no "## [${version}]" section. That section is the release note: add it (move the [Unreleased] entries under a "## [${version}] — YYYY-MM-DD" heading) and merge again. Until then ${version} sits on main untagged and unpublished.`,
    };
  }
  if (section.body === '') {
    return {
      action: 'fail',
      version,
      tag,
      reason: `CHANGELOG.md's "## [${version}]" section is empty. It is the release note; write what shipped.`,
    };
  }
  return {
    action: 'tag-and-dispatch',
    version,
    tag,
    reason: `${tag} does not exist yet; tagging ${version} on main and dispatching release.yml with its CHANGELOG section as the release note.`,
    notes: section.body,
  };
}

function parseFlag(args, name) {
  const prefix = `--${name}=`;
  const hit = args.find((a) => a.startsWith(prefix));
  if (hit === undefined) return undefined;
  return hit.slice(prefix.length);
}

function parseBool(raw, name) {
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  throw new Error(`--${name} must be exactly "true" or "false" (got ${JSON.stringify(raw)})`);
}

function appendGithubOutput(entries) {
  const out = process.env.GITHUB_OUTPUT;
  if (!out) return;
  const text = Object.entries(entries)
    .map(([k, v]) => `${k}=${String(v).replace(/\r?\n/g, ' ')}`)
    .join('\n');
  fs.appendFileSync(out, `${text}\n`);
}

function main(argv) {
  const [cmd, ...rest] = argv;
  const root = parseFlag(rest, 'root') ?? process.cwd();
  switch (cmd) {
    case 'version': {
      const v = readVersions(root);
      const err = lockstepError(v);
      if (err) {
        process.stderr.write(`::error::${err}\n`);
        return 1;
      }
      process.stdout.write(`${v.sdk}\n`);
      return 0;
    }
    case 'notes': {
      const version = rest.find((a) => !a.startsWith('--'));
      if (!version) {
        process.stderr.write('usage: release-state.cjs notes <version>\n');
        return 2;
      }
      const section = changelogSection(fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8'), version);
      if (!section || section.body === '') {
        process.stderr.write(`::error::CHANGELOG.md has no non-empty "## [${version}]" section; it is the release note.\n`);
        return 1;
      }
      process.stdout.write(`${section.body}\n`);
      return 0;
    }
    case 'plan': {
      const v = readVersions(root);
      const decision = plan({
        sdk: v.sdk,
        engine: v.engine,
        tagExists: parseBool(parseFlag(rest, 'tag-exists'), 'tag-exists'),
        releaseRunExists: parseBool(parseFlag(rest, 'release-run-exists'), 'release-run-exists'),
        changelog: fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8'),
      });
      const { notes, ...summary } = decision;
      process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
      appendGithubOutput(summary);
      if (decision.action === 'fail') {
        process.stderr.write(`::error::${decision.reason}\n`);
        return 1;
      }
      return 0;
    }
    default:
      process.stderr.write('usage: release-state.cjs <version|notes <version>|plan --tag-exists=<bool> --release-run-exists=<bool>> [--root=<dir>]\n');
      return 2;
  }
}

module.exports = { readVersions, lockstepError, changelogSection, plan, main, SEMVER_RE };

if (require.main === module) {
  let code;
  try {
    code = main(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`::error::${e && e.message ? e.message : e}\n`);
    code = 1;
  }
  process.exit(code);
}
