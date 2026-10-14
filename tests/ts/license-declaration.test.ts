// tests/ts/license-declaration.test.ts
//
// What this repository grants is stated in several places across two
// languages: the LICENSE.md copies, the NOTICE copies, LICENSES/ and
// REUSE.toml, both npm manifests, the Python project metadata, CITATION.cff and
// the README licence sections. Today they all say one thing: the source is
// published to be read, no licence is granted, and no package is published.
// Any one of them could be changed without the others, and a repository whose
// LICENSE.md and package.json disagree invites the question a security product
// should never invite: which one is true?
import { execFileSync, spawnSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.join(__dirname, '..', '..');
const read = (p: string) => fs.readFileSync(path.join(ROOT, p), 'utf-8');
/** Text with every run of whitespace folded to one space, so wrapped prose compares as written. */
const flat = (s: string) => s.replace(/\s+/g, ' ');

/** Every tracked (or would-be-added) text file but `except`, with its contents. */
function trackedText(except: string[]): Array<{ file: string; text: string }> {
  const files = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd: ROOT, encoding: 'utf-8' })
    .split('\0')
    .filter((f) => f && !except.includes(f) && fs.existsSync(path.join(ROOT, f)));
  // Guard: an empty listing would make every check over it vacuous.
  expect(files.length).toBeGreaterThan(500);
  return files
    .map((file) => ({ file, bytes: fs.readFileSync(path.join(ROOT, file)) }))
    .filter(({ bytes }) => !bytes.includes(0))
    .map(({ file, bytes }) => ({ file, text: bytes.toString('utf-8') }));
}

const LICENCE_REF = 'LicenseRef-Tzun-All-Rights-Reserved';
const NPM_LICENSE = 'SEE LICENSE IN LICENSE.md';
const CONTACT = 'licensing@tzun.ai';

describe('LICENSE.md grants no licence', () => {
  it('states the copyright, that the source is published to be read, and that nothing is licensed', () => {
    const l = flat(read('LICENSE.md'));
    expect(l).toContain('Copyright 2026 Tzun, Inc. All rights reserved.');
    expect(l).toContain('The source code in this repository is published so that it can be read.');
    expect(l).toContain(
      'Except for the files listed under "Files under other terms" below, and except as GitHub\'s Terms of Service require for content in a public repository, no licence is granted, by its publication or by any file in this repository: no right to copy, modify, distribute or use the software, and no licence under any patent or patent application.',
    );
    // The heading that sentence names.
    expect(read('LICENSE.md')).toMatch(/^## Files under other terms$/m);
    expect(l).toContain(`For a licence, contact ${CONTACT}.`);
  });

  it('names the files under other terms: the CC0 vectors, the third-party certificates and the CC BY 4.0 code of conduct', () => {
    const l = flat(read('LICENSE.md'));
    expect(l).toContain('The conformance vectors in `vectors/` are dedicated to the public domain under CC0 1.0 Universal');
    expect(l).toContain('(CC0 1.0, section 4(a))');
    expect(l).toContain('CC BY 4.0 grants no patent or trademark rights (CC BY 4.0, section 2(b)(2)).');
    expect(l).toContain('The root and intermediate certificates in `src/attestation/certs/` belong to the certification and time-stamping authorities that issued them');
    expect(l).toContain(
      'The code of conduct in `CODE_OF_CONDUCT.md` is the Contributor Covenant, version 2.1, created by Coraline Ada Ehmke and stewarded by the Organization for Ethical Source. It is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0): see `LICENSES/CC-BY-4.0.txt`.',
    );
  });

  it('there is no second, conflicting LICENSE file', () => {
    expect(fs.existsSync(path.join(ROOT, 'LICENSE'))).toBe(false);
  });

  it.each(['packages/engine/LICENSE.md', 'python/LICENSE.md', `LICENSES/${LICENCE_REF}.txt`])('%s is identical to LICENSE.md', (file) => {
    expect(read(file)).toBe(read('LICENSE.md'));
  });
});

describe('NOTICE says the same', () => {
  it.each(['packages/engine/NOTICE', 'python/NOTICE'])('%s is identical to NOTICE', (file) => {
    expect(read(file)).toBe(read('NOTICE'));
  });

  it('states the copyright, that no licence is granted, and the factual line about the applications', () => {
    const n = flat(read('NOTICE'));
    expect(n).toContain('Copyright 2026 Tzun, Inc. All rights reserved.');
    expect(n).toContain('No licence is granted to copy, modify, distribute or use it.');
    expect(n).toContain('Tzun, Inc. owns United States patent applications covering aspects of the methods implemented here. No licence under them is granted.');
    expect(n).toContain(CONTACT);
    expect(n).toContain('This notice is descriptive. LICENSE.md governs.');
  });

  it('grants nothing for any purpose and names no promise', () => {
    const n = read('NOTICE');
    expect(n).not.toMatch(/Permitted Purpose/i);
    expect(n).not.toMatch(/promise/i);
    expect(n).not.toMatch(/licenses? them to you/i);
  });
});

describe('LICENSES/ and REUSE.toml', () => {
  it('LICENSES/ holds the notice, CC-BY-4.0, CC0-1.0 and the root-certificate statement, and nothing else', () => {
    expect(fs.readdirSync(path.join(ROOT, 'LICENSES')).sort()).toEqual([
      'CC-BY-4.0.txt',
      'CC0-1.0.txt',
      'LicenseRef-Root-Certificates.txt',
      `${LICENCE_REF}.txt`,
    ]);
  });

  it('the root-certificate statement points at LICENSE.md, not at a licence', () => {
    const c = flat(read('LICENSES/LicenseRef-Root-Certificates.txt'));
    expect(c).toContain('They are the property of their issuers, and LICENSE.md does not apply to them.');
  });

  /** REUSE.toml's [[annotations]] tables, each as its path line and its licence identifier. */
  function annotations(): Array<{ path: string; license: string }> {
    return read('REUSE.toml')
      .split(/^\[\[annotations\]\]$/m)
      .slice(1)
      .map((block) => ({
        path: block.match(/^path = (.+)$/m)![1],
        license: block.match(/^SPDX-License-Identifier = "([^"]+)"$/m)![1],
      }));
  }

  it('Tzun source falls under the notice, the vectors under CC0-1.0, the certificates under their statement, the code of conduct under CC-BY-4.0', () => {
    expect(annotations()).toEqual([
      { path: '"**"', license: LICENCE_REF },
      { path: '["vectors/**"]', license: 'CC0-1.0' },
      { path: '"src/attestation/certs/*.pem"', license: 'LicenseRef-Root-Certificates' },
      { path: '"CODE_OF_CONDUCT.md"', license: 'CC-BY-4.0' },
    ]);
  });

  it('the code of conduct is the Contributor Covenant 2.1 under CC-BY-4.0, and REUSE.toml, NOTICE, the README and the file itself say so', () => {
    const reuse = read('REUSE.toml');
    expect(reuse).toContain(
      '[[annotations]]\npath = "CODE_OF_CONDUCT.md"\nprecedence = "override"\nSPDX-FileCopyrightText = "Contributor Covenant, created by Coraline Ada Ehmke and stewarded by the Organization for Ethical Source"\nSPDX-License-Identifier = "CC-BY-4.0"\n',
    );
    expect(flat(read('NOTICE'))).toContain('The code of conduct in CODE_OF_CONDUCT.md, the Contributor Covenant 2.1, is CC-BY-4.0.');
    const coc = read('CODE_OF_CONDUCT.md');
    expect(coc.startsWith('# Contributor Covenant Code of Conduct\n')).toBe(true);
    expect(flat(coc)).toContain(
      'Contributor Covenant was created by Coraline Ada Ehmke in 2014 and is stewarded by the Organization for Ethical Source. It is licensed under the Creative Commons Attribution 4.0 International licence (<https://creativecommons.org/licenses/by/4.0/>), whose text is in [`LICENSES/CC-BY-4.0.txt`](LICENSES/CC-BY-4.0.txt).',
    );
    expect(flat(licenceSection('README.md'))).toContain('the code of conduct is the Contributor Covenant 2.1 under CC BY 4.0');
  });

  it('the code of conduct and the CC BY 4.0 text are the exact copies REUSE.toml describes', () => {
    // REUSE.toml says how CODE_OF_CONDUCT.md differs from the Covenant as
    // published. These are the bytes of tzun-verify's copy, which differs in
    // only those ways, and of the licence text as `reuse download CC-BY-4.0`
    // fetches it. Any edit to either file makes that description untrue.
    const sha256 = (p: string) => crypto.createHash('sha256').update(fs.readFileSync(path.join(ROOT, p))).digest('hex');
    expect(sha256('CODE_OF_CONDUCT.md')).toBe('bd1619b0666ab16e6eefff0f472f6fe0587638ee97ee6a1474d46d4413f529c5');
    expect(sha256('LICENSES/CC-BY-4.0.txt')).toBe('d557539df68e771cc1eedcc91d13f70fca930e508d11eedcafa4b15db49e3744');
  });
});

describe('no package can be published', () => {
  it.each(['package.json', 'packages/engine/package.json'])('%s is private, points at LICENSE.md and ships LICENSE.md and NOTICE', (file) => {
    const pkg = JSON.parse(read(file));
    // npm refuses to publish a package that sets "private": true.
    expect(pkg.private).toBe(true);
    expect(pkg.license).toBe(NPM_LICENSE);
    expect(pkg.files).toEqual(expect.arrayContaining(['LICENSE.md', 'NOTICE']));
  });

  it('python/pyproject.toml declares the notice, ships the licence files and carries the classifier PyPI refuses', () => {
    const t = read('python/pyproject.toml');
    expect(t).toMatch(new RegExp(`^license = "${LICENCE_REF}"$`, 'm'));
    expect(t).toMatch(/^license-files = \["LICENSE\.md", "NOTICE"\]$/m);
    const classifiers = t.match(/^classifiers = \[\n([\s\S]*?)\n\]$/m);
    expect(classifiers).not.toBeNull();
    expect(classifiers![1]).toMatch(/^ {2}"Private :: Do Not Upload",$/m);
    // PEP 639 deprecates licence classifiers.
    expect(t).not.toMatch(/License :: /);
  });

  it.each(['release.yml', 'python-publish.yml'])('%s stops on this tree: its unpublishable-package guard fails, naming all three markers', (wf) => {
    // The guard step's script, run in this repository as the workflow runs it
    // (tests/ts/publishing-off.test.ts runs it against fixture trees).
    const text = read(`.github/workflows/${wf}`);
    const at = text.indexOf('      - name: Refuse to publish while a package is marked unpublishable\n');
    expect(at).toBeGreaterThan(0);
    const lines = text.slice(at).split('\n');
    const run = lines.findIndex((l) => /^ {8}run: \|\s*$/.test(l));
    const end = lines.findIndex((l, i) => i > run && /^ {6}- name: /.test(l));
    const script = lines
      .slice(run + 1, end)
      .map((l) => l.replace(/^ {10}/, ''))
      .join('\n');
    const r = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', script], {
      cwd: ROOT,
      encoding: 'utf-8',
      env: { PATH: `${path.dirname(process.execPath)}:${process.env.PATH ?? ''}` },
    });
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/^::error::Publishing is off while a package is marked unpublishable: see LICENSE\.md\./m);
    expect(r.stdout).toContain(
      ' package.json sets private; packages/engine/package.json sets private; python/pyproject.toml carries Private :: Do Not Upload;',
    );
  });

  it('release.yml expects the packed manifests to carry the licence field package.json declares', () => {
    expect(read('.github/workflows/release.yml')).toContain(
      `if (p.license !== "${NPM_LICENSE}") errors.push(\`license is \${p.license}, expected ${NPM_LICENSE}\`);`,
    );
  });

  it('CITATION.cff names no licence', () => {
    const c = read('CITATION.cff');
    expect(c).not.toMatch(/^license(?:-url)?:/m);
  });
});

describe('no file says that licence terms are coming', () => {
  it('no tracked text file says a licence will be published or granted later, or that the packages will be published', () => {
    // What the repository grants is what LICENSE.md grants today. A statement
    // that terms will follow would describe something that does not exist.
    const FUTURE =
      /licen[cs]e terms will|will be published with the licen|until the licen[cs]e(?: terms)? (?:is|are) published|licen[cs]e (?:is )?granted yet|not on (?:npm|PyPI)(?: or PyPI)? yet|packages will be published/i;
    const offenders = trackedText(['tests/ts/license-declaration.test.ts'])
      .filter(({ text }) => FUTURE.test(text.replace(/\s+/g, ' ')))
      .map(({ file }) => file);
    expect(offenders).toEqual([]);
  });
});

describe('nothing left of the previous licence', () => {
  const PREVIOUS = /FSL-1\.1|Functional Source License|Permitted Purpose|ALv2 Future License/;

  it('no tracked text file names it', () => {
    const offenders = trackedText(['tests/ts/license-declaration.test.ts'])
      .filter(({ text }) => PREVIOUS.test(text))
      .map(({ file }) => file);
    expect(offenders).toEqual([]);
    expect(fs.existsSync(path.join(ROOT, 'LICENSES', 'FSL-1.1-ALv2.txt'))).toBe(false);
  });

  it('no manifest or citation advertises Apache-2.0 as the licence of this code', () => {
    for (const f of ['package.json', 'packages/engine/package.json', 'python/pyproject.toml', 'CITATION.cff']) {
      expect(read(f)).not.toMatch(/Apache-2\.0|Apache Software License/i);
    }
  });
});

/** `file` from its `## License` heading to the next `## ` heading or the end. */
function licenceSection(file: string): string {
  const readme = read(file);
  const start = readme.search(/^## Licen[cs]e\s*$/m);
  expect({ file, found: start >= 0 }).toEqual({ file, found: true });
  const rest = readme.slice(start);
  const next = rest.slice(3).search(/^## /m);
  return next < 0 ? rest : rest.slice(0, next + 3);
}

/** The targets of a section's Markdown links, without any #fragment. */
function linkTargets(section: string): string[] {
  return [...section.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1].split('#')[0]);
}

describe('the README licence sections say what LICENSE.md says', () => {
  it.each([
    ['README.md', /The packages are not on npm or PyPI\./],
    ['packages/engine/README.md', /The package is not on npm\./],
    ['python/README.md', /The package is not on PyPI\./],
  ])('%s: no licence is granted, the source is published to be read, the package is not published, the vectors are CC0', (file, notPublished) => {
    const s = flat(licenceSection(file));
    expect(s).toMatch(/No licence is granted\. The source is published (?:here )?so that it can be read/);
    expect(s).toMatch(notPublished);
    expect(s).toContain('CC0-1.0');
    expect(s).toContain(CONTACT);
    const targets = linkTargets(s).map((t) => t.replace(/^\.\//, '').replace(/^https:\/\/github\.com\/TzunAI\/tzun\/blob\/main\//, ''));
    expect(targets).toEqual(expect.arrayContaining(['LICENSE.md', 'NOTICE']));
    expect(s).not.toMatch(/promise/i);
    expect(s).not.toMatch(/\bApache\b/);
    expect(s).not.toMatch(/\blicensed under\b/i);
  });

  it('every file the root README licence section links exists in this repository', () => {
    const local = linkTargets(licenceSection('README.md')).filter((t) => !/^[a-z]+:/i.test(t));
    // Guard: if the link regex stops matching, the check below is vacuous.
    expect(local.length).toBeGreaterThan(1);
    const missing = local.filter((t) => !fs.existsSync(path.join(ROOT, t)));
    expect(missing).toEqual([]);
  });
});

describe('the SECURITY.md safe harbour is not a licence', () => {
  /** SECURITY.md from its `## Safe harbour` heading to the next `## ` heading or the end. */
  function harbour(): string {
    const text = read('SECURITY.md');
    const start = text.search(/^## Safe harbour\s*$/m);
    expect(start).toBeGreaterThan(0);
    const rest = text.slice(start);
    const next = rest.slice(3).search(/^## /m);
    return flat(next < 0 ? rest : rest.slice(0, next + 3));
  }

  it('covers only computer-misuse, anti-circumvention and similar laws and research within the policy scope, names what it does not cover, and says it is not a licence', () => {
    const s = harbour();
    expect(s).toContain(
      'We will not pursue or support legal action under computer-misuse, anti-circumvention or similar laws against anyone who, in good faith, researches what is in scope above and reports it under this policy, who avoids privacy violations and service degradation, and who gives us reasonable time to remediate before disclosing publicly.',
    );
    expect(s).toContain(
      "This safe harbour does not cover testing any system you do not own or have permission to test, Tzun's hosted services among them.",
    );
    expect(s).toContain("Listing something as in scope above is not permission to test Tzun's own instance of it.");
    expect(s).toContain('This safe harbour is not a licence under any patent, patent application or copyright: see [`LICENSE.md`](./LICENSE.md).');
    expect(s).not.toMatch(/legal action against anyone/);
  });

  it('no other file says Tzun will not take legal action', () => {
    // A promise not to sue can be read as a licence. The safe harbour above is
    // the only one in the repository; CC0 is the vectors' dedication.
    const PROMISE = /\blegal action\b|\bnot to sue\b|\bcovenant not to\b|\b(?:will not|won't|shall not) (?:sue|pursue)\b/i;
    const offenders = trackedText(['SECURITY.md', 'tests/ts/license-declaration.test.ts', 'LICENSES/CC0-1.0.txt', 'vectors/LICENSE'])
      .filter(({ text }) => PROMISE.test(text))
      .map(({ file }) => file);
    expect(offenders).toEqual([]);
  });
});
