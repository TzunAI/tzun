/**
 * Supply-chain tests for .github/workflows.
 *
 * These assert against the workflow files themselves because the failure
 * mode is not reachable from runtime code: a mutable action tag (`@v5`) is
 * a standing promise to execute whatever the upstream repo points that tag
 * at, in a job that may hold a publishing credential. The tj-actions/
 * changed-files compromise (CVE-2025-30066) is exactly this shape, and no
 * change to this repo is needed for it to fire.
 */
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

const WORKFLOW_DIR = join(__dirname, '..', '..', '.github', 'workflows');

const workflowFiles = readdirSync(WORKFLOW_DIR).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'));

/**
 * Workflows with a job that holds a credential that can publish bytes or
 * write to this repository. A floating dependency in one of these is remote
 * code execution with that credential in scope.
 */
const CREDENTIAL_HOLDING = [
  // id-token: write (npm trusted publishing) and contents: write (the Release).
  'release.yml',
  // id-token: write (PyPI trusted publishing).
  'python-publish.yml',
  // contents: write (creates tags) + actions: write (dispatches the publishes).
  'auto-release.yml',
];

function read(file: string): string {
  return readFileSync(join(WORKFLOW_DIR, file), 'utf-8');
}

/** Every `uses:` line, with its file and 1-based line number. */
function usesLines(): Array<{ file: string; line: number; text: string }> {
  const out: Array<{ file: string; line: number; text: string }> = [];
  for (const file of workflowFiles) {
    read(file)
      .split('\n')
      .forEach((text, i) => {
        // Skip local composite actions (./.github/actions/...) — they are
        // this repo's own content, already pinned by the checked-out commit.
        if (/^\s*-?\s*uses:\s*[^.\s]/.test(text)) {
          out.push({ file, line: i + 1, text: text.trim() });
        }
      });
  }
  return out;
}

/** The jobs of a workflow that hold id-token: write, each as its text. */
function oidcJobs(file: string): Array<{ job: string; text: string }> {
  const lines = read(file).split('\n');
  const out: Array<{ job: string; text: string }> = [];
  const jobsAt = lines.findIndex((l) => /^jobs:\s*$/.test(l));
  const starts = lines.map((l, i) => (i > jobsAt && /^ {2}[A-Za-z0-9_-]+:\s*$/.test(l) ? i : -1)).filter((i) => i >= 0);
  starts.forEach((s, k) => {
    const text = lines.slice(s, k + 1 < starts.length ? starts[k + 1] : lines.length).join('\n');
    if (/^\s*id-token:\s*write/m.test(text)) out.push({ job: lines[s].trim().replace(/:$/, ''), text });
  });
  return out;
}

describe('workflow supply chain', () => {
  it('finds workflow files to check (guards against a vacuous pass)', () => {
    expect(workflowFiles.length).toBeGreaterThanOrEqual(5);
    expect(usesLines().length).toBeGreaterThanOrEqual(20);
    for (const f of CREDENTIAL_HOLDING) expect(workflowFiles).toContain(f);
  });

  it('pins every third-party action to a full 40-hex commit SHA', () => {
    const offenders = usesLines().filter(
      ({ text }) => !/uses:\s*[A-Za-z0-9._-]+\/[A-Za-z0-9._/-]+@[0-9a-f]{40}(\s|$)/.test(text)
    );
    expect(
      offenders.map((o) => `${o.file}:${o.line} ${o.text}`)
    ).toEqual([]);
  });

  it('annotates every SHA pin with the human-readable version it corresponds to', () => {
    const offenders = usesLines().filter(({ text }) => !/@[0-9a-f]{40}\s+#\s*v?\d/.test(text));
    expect(offenders.map((o) => `${o.file}:${o.line} ${o.text}`)).toEqual([]);
  });

  it('uses one SHA per action and version across all workflows', () => {
    const seen = new Map<string, string>();
    const offenders: string[] = [];
    for (const { file, line, text } of usesLines()) {
      const m = text.match(/uses:\s*([^@\s]+)@([0-9a-f]{40})\s+#\s*(\S+)/);
      if (!m) continue;
      const key = `${m[1]} ${m[3]}`;
      const prev = seen.get(key);
      if (prev && prev !== m[2]) offenders.push(`${file}:${line} ${key} is ${m[2]}, elsewhere ${prev}`);
      seen.set(key, m[2]);
    }
    expect(offenders).toEqual([]);
  });

  it('never runs `npx --yes` / `npx -y` (unlocked registry execution)', () => {
    const offenders: string[] = [];
    for (const file of workflowFiles) {
      read(file)
        .split('\n')
        .forEach((text, i) => {
          if (/\bnpx\s+(--yes|-y)\b/.test(text) || /\bpnpm\s+dlx\b/.test(text) || /\buvx\b/.test(text)) {
            offenders.push(`${file}:${i + 1} ${text.trim()}`);
          }
        });
    }
    expect(offenders).toEqual([]);
  });

  it('does not persist the job credential into .git/config on checkout', () => {
    // actions/checkout writes the token it was given into
    // <path>/.git/config unless persist-credentials is false; any later
    // step (including a compromised action) can then read it.
    const offenders: string[] = [];
    for (const file of workflowFiles) {
      const lines = read(file).split('\n');
      lines.forEach((text, i) => {
        if (!/uses:\s*actions\/checkout@/.test(text)) return;
        // Look ahead over the step's `with:` block.
        const stepIndent = text.search(/\S/);
        let persisted = false;
        for (let j = i + 1; j < lines.length; j++) {
          const nxt = lines[j];
          if (nxt.trim() === '') continue;
          const indent = nxt.search(/\S/);
          // A new step starts at a `- ` bullet, or at a shallower indent.
          if (indent < stepIndent || (indent <= stepIndent && nxt.trim().startsWith('- '))) break;
          if (/persist-credentials:\s*false/.test(nxt)) {
            persisted = true;
            break;
          }
        }
        if (!persisted) offenders.push(`${file}:${i + 1}`);
      });
    }
    expect(offenders).toEqual([]);
  });

  it('pins every tool installed by a credential-holding workflow to an exact version', () => {
    const offenders: string[] = [];
    for (const file of CREDENTIAL_HOLDING) {
      read(file)
        .split('\n')
        .forEach((text, i) => {
          // Strip trailing YAML/shell comments; a `#` inside a run: block
          // is a shell comment, not an install argument.
          const code = text.replace(/#.*$/, '');
          if (/^\s*#/.test(text)) return;
          const pip = code.match(/\bpip install\s+(.*)$/);
          if (pip) {
            for (const rawTok of pip[1].split(/\s+/)) {
              const tok = rawTok.replace(/^["']|["']$/g, '');
              if (!tok || tok.startsWith('-') || tok === '.' || tok.startsWith('./')) continue;
              if (!/[=<>~!]=|===/.test(tok)) {
                offenders.push(`${file}:${i + 1} unpinned '${tok}'`);
              } else if (!/==/.test(tok) || /^[^=]*[<>~!]=/.test(tok)) {
                offenders.push(`${file}:${i + 1} floating range '${tok}'`);
              }
            }
          }
          // A global npm install takes a local tarball (whose integrity the
          // workflow checks) or an exact version, never a range or a tag.
          const npmGlobal = code.match(/\bnpm (?:install|i)\s+(.*(?:-g|--global)\b.*)$/);
          if (npmGlobal) {
            for (const rawTok of npmGlobal[1].split(/\s+/)) {
              const tok = rawTok.replace(/^["']|["']$/g, '');
              if (!tok || tok.startsWith('-')) continue;
              if (!/^\.\/.+\.tgz$/.test(tok) && !/^[@a-z0-9./_-]+@\d+\.\d+\.\d+$/.test(tok)) {
                offenders.push(`${file}:${i + 1} global npm install of '${tok}'`);
              }
            }
          }
        });
    }
    expect(offenders).toEqual([]);
  });

  it('the npm CLI the publish job installs is checked against a pinned integrity first', () => {
    const publish = oidcJobs('release.yml');
    expect(publish.map((j) => j.job)).toEqual(['publish']);
    const text = publish[0].text;
    const check = text.indexOf('if [ "$got" != "$NPM_INTEGRITY" ]; then');
    const install = text.indexOf('npm install --global --ignore-scripts');
    expect(check).toBeGreaterThan(0);
    expect(install).toBeGreaterThan(check);
  });

  it('a job that can mint an OIDC token runs no install of the repository and no package script', () => {
    // The OIDC job uploads the bytes an earlier job built and scanned; it
    // never checks out and installs the workspace, whose dependencies'
    // lifecycle scripts would run with the token in reach.
    const offenders: string[] = [];
    for (const file of workflowFiles) {
      for (const { job, text } of oidcJobs(file)) {
        const code = text
          .split('\n')
          .filter((l) => !/^\s*#/.test(l))
          .join('\n');
        for (const banned of [/pnpm install/, /\bnpm ci\b/, /pip install/, /actions\/checkout@/, /pnpm (run|test|build)/, /npm run /]) {
          if (banned.test(code)) offenders.push(`${file} job ${job}: ${banned}`);
        }
        for (const m of code.matchAll(/npm install[^\n]*/g)) {
          if (!/--ignore-scripts/.test(m[0])) offenders.push(`${file} job ${job}: ${m[0]} without --ignore-scripts`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
