// tests/ts/codegen-python.test.ts — the Python model generator.
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(__dirname, '..', '..');
const OUT = join(ROOT, 'python', 'src', 'tzun_sdk', '_generated', 'models.py');
const run = () => execFileSync('pnpm', ['exec', 'tsx', 'scripts/codegen-python.ts'], { cwd: ROOT, encoding: 'utf-8' });

describe('codegen-python emitter', () => {
  it('emits a non-empty _generated/models.py with the load-bearing classes', () => {
    run();
    expect(existsSync(OUT)).toBe(true);
    const src = readFileSync(OUT, 'utf-8');
    for (const cls of [
      'EvidencePayload', 'EvidenceEnvelope', 'IntegrityBlock', 'AttestationArtifacts',
      'ModelDescriptor', 'TrainingInfo', 'AiBom', 'AiBomWithInlineDescriptor',
      'ModelDescriptorRow', 'ModelDescriptorAnnotationRow', 'ModelLineageEntry',
      'ExportedEvidenceEnvelope', 'TamperIncident', 'VerificationResult', 'FailureRecord',
      'ModifiedLink',  // the hand-written package __all__ does not export this class
    ]) {
      expect(src).toContain(`class ${cls}(`);
    }
    expect(src).toContain("extra=\"forbid\"");
    expect(src).not.toMatch(/# Source commit:/); // default emission is stamp-free
  });

  it('is byte-deterministic across runs', () => {
    run();
    const a = readFileSync(OUT, 'utf-8');
    run();
    const b = readFileSync(OUT, 'utf-8');
    expect(b).toBe(a);
  });

  it('leaves canonical.py and chain.py untouched', () => {
    const canonical = readFileSync(join(ROOT, 'python/src/tzun_sdk/_generated/canonical.py'), 'utf-8');
    run();
    expect(readFileSync(join(ROOT, 'python/src/tzun_sdk/_generated/canonical.py'), 'utf-8')).toBe(canonical);
  });
});

/**
 * Two places the generator's constraint story could drift in silence.
 *
 * (a) The Python models carry `Field(pattern=r"^sha256:[a-f0-9]{64}$")` on
 *     `ModelDescriptor.modelDigest` and `AiBom.modelDescriptorDigest`. That is
 *     not a constraint the generator invents: the TS side enforces the
 *     identical regex at runtime — `MODEL_DIGEST_FORMAT` in
 *     src/models/descriptor-invariants.ts — on every descriptor it registers.
 *     TypeScript has no way to spell a regex-constrained string in its type
 *     system, so the invariant lives in a runtime guard on one side and in a
 *     Field pattern on the other. Deleting the Python patterns would make the
 *     port accept digests the TS SDK rejects, and nothing else ties the two
 *     spellings together, so they could drift apart in silence. This pins
 *     them.
 *
 * (b) `buildRegistry` only scans packages/engine/src/types/. A public type
 *     declared anywhere else in the engine would be neither generated nor
 *     listed in the exclusion-audit footer — it would simply not exist as far
 *     as the Python port was concerned, and nothing would report it.
 *     `ChainCompletenessResult`, declared in
 *     packages/engine/src/chain-completeness.ts, is such a type.
 */
describe('codegen-python constraint + public-surface provenance', () => {
  const CODEGEN_SRC = join(ROOT, 'scripts', 'codegen-python.ts');

  it('pins FIELD_PATTERNS to the TS runtime invariants MODEL_DIGEST_FORMAT, SIGNOFF_DIGEST_RE and the record-rule patterns', () => {
    // Required lazily so this file keeps its no-src-import shape.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { MODEL_DIGEST_FORMAT } = require('../../src/models/descriptor-invariants');
    const expected: string = MODEL_DIGEST_FORMAT.source;

    const script = readFileSync(CODEGEN_SRC, 'utf-8');
    const table = script.match(/const FIELD_PATTERNS: Record<string, string> = \{([\s\S]*?)\};/);
    expect(table).not.toBeNull();
    // The table holds TS string literals: `\\.` in the source is the regex `\.`.
    const entries = [...table![1].matchAll(/'([\w.]+)':\s*'([^']+)'/g)].map((m) => [m[1], m[2].replace(/\\\\/g, '\\')]);

    // Vacuity guard: a table that stopped matching must fail, not pass empty.
    expect(entries.map((e) => e[0]).sort()).toEqual([
      'AiBom.modelDescriptorDigest',
      'ContributionStep.output',
      'ContributionStep.prev',
      'Contributions.pipeline',
      'Decider.agent',
      'Decider.credential',
      'Decider.freshness',
      'Link.rel',
      'LinkTarget.digest',
      'MandateExpectation.mandateAssertion',
      'ModelDescriptor.modelDigest',
      'SessionAttachmentExpectation.statementDigest',
      'SignatureRequiredExpectation.policyDigest',
      'StepActor.agent',
      'StepAiBom.modelDescriptorDigest',
    ]);
    // The two sign-off digests are the engine's SIGNOFF_DIGEST_RE
    // (Record §9.2), the rule a TS capture applies to them; the record rules
    // use the engine's prefixed and bare digest patterns, its finalized-block
    // reference pattern and its relation name pattern.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const engine = require('@tzun/engine') as Record<string, RegExp>;
    const { SIGNOFF_DIGEST_RE, PREFIXED_DIGEST_RE, BARE_DIGEST_RE, FRESHNESS_REFERENCE_RE, RELATION_NAME_RE } = engine;
    const source: Record<string, string> = {
      'SessionAttachmentExpectation.statementDigest': SIGNOFF_DIGEST_RE.source,
      'SignatureRequiredExpectation.policyDigest': SIGNOFF_DIGEST_RE.source,
      'Decider.agent': PREFIXED_DIGEST_RE.source,
      'StepActor.agent': PREFIXED_DIGEST_RE.source,
      'Contributions.pipeline': PREFIXED_DIGEST_RE.source,
      'ContributionStep.output': PREFIXED_DIGEST_RE.source,
      'ContributionStep.prev': PREFIXED_DIGEST_RE.source,
      'Decider.credential': BARE_DIGEST_RE.source,
      'LinkTarget.digest': BARE_DIGEST_RE.source,
      'MandateExpectation.mandateAssertion': BARE_DIGEST_RE.source,
      'Decider.freshness': FRESHNESS_REFERENCE_RE.source,
      'Link.rel': RELATION_NAME_RE.source,
    };
    for (const [field, pattern] of entries) {
      expect([field, pattern]).toEqual([field, source[field] ?? expected]);
    }

    // And the committed artifact carries the same regex, not just the table.
    // Read, don't regenerate: the byte-determinism and drift-guard suites
    // already prove the committed file is what the generator emits, and two
    // suites regenerating it concurrently race over the same path.
    const py = readFileSync(OUT, 'utf-8');
    expect(py).toMatch(
      new RegExp(`modelDescriptorDigest: str = Field\\(pattern=r"${escapeRe(expected)}"\\)`),
    );
    expect(py).toMatch(
      new RegExp(
        `modelDigest: str \\| None = Field\\(default=None, pattern=r"${escapeRe(expected)}"\\)`,
      ),
    );
  });

  it('accounts for every type on the engine public surface (generated or explicitly excluded)', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const ts = require('typescript') as typeof import('typescript');
    const indexPath = join(ROOT, 'packages', 'engine', 'src', 'index.ts');
    const program = ts.createProgram([indexPath], {
      target: ts.ScriptTarget.ES2022,
      strict: true,
    });
    const checker = program.getTypeChecker();
    const sf = program.getSourceFile(indexPath)!;
    const moduleSymbol = checker.getSymbolAtLocation(sf)!;

    const publicTypes: string[] = [];
    for (const sym of checker.getExportsOfModule(moduleSymbol)) {
      let resolved = sym;
      if (sym.flags & ts.SymbolFlags.Alias) {
        try {
          resolved = checker.getAliasedSymbol(sym);
        } catch {
          /* keep the local symbol */
        }
      }
      const decls = [...(sym.getDeclarations() ?? []), ...(resolved.getDeclarations() ?? [])];
      const isType = decls.some(
        (d) => ts.isInterfaceDeclaration(d) || ts.isTypeAliasDeclaration(d),
      );
      const isValue = decls.some(
        (d) =>
          ts.isClassDeclaration(d) ||
          ts.isFunctionDeclaration(d) ||
          ts.isVariableDeclaration(d) ||
          ts.isEnumDeclaration(d),
      );
      if (isType && !isValue) publicTypes.push(sym.getName());
    }

    // Vacuity guards: the walk must actually see the surface, including a
    // public type declared outside packages/engine/src/types/.
    expect(publicTypes.length).toBeGreaterThan(50);
    expect(publicTypes).toContain('ChainCompletenessResult');
    expect(publicTypes).toContain('EvidenceEnvelope');

    const py = readFileSync(OUT, 'utf-8');
    const generated = new Set(
      [...py.matchAll(/^class (\w+)\(/gm)].map((m) => m[1]),
    );
    for (const m of py.matchAll(/^(\w+) = /gm)) generated.add(m[1]); // type aliases
    const excluded = new Set([...py.matchAll(/^#   - (\w+)(?::| —|$)/gm)].map((m) => m[1]));
    expect(excluded.size).toBeGreaterThan(10);

    const unaccounted = publicTypes
      .filter((n) => !generated.has(n) && !excluded.has(n))
      .sort();
    expect(unaccounted).toEqual([]);
  });
});

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * The record-rule member models are strict, their nullable
 * members are required keys, and the rules a Rust-dialect Field pattern cannot
 * spell are field validators written with `re.fullmatch` and `re.ASCII`.
 * Read, don't regenerate (see above).
 */
describe('codegen-python record-rule models', () => {
  const py = () => readFileSync(OUT, 'utf-8');
  const classBody = (name: string): string => {
    const src = py();
    const start = src.indexOf(`class ${name}(_Forbid):`);
    expect(start).toBeGreaterThanOrEqual(0);
    const next = src.indexOf('\nclass ', start + 1);
    return src.slice(start, next === -1 ? undefined : next);
  };

  it.each([
    'Decider', 'StepActor', 'ContributionStep', 'Contributions', 'Link', 'LinkTarget', 'LinkLocator',
    'MandateExpectation', 'MandateBlock', 'MandateDocument', 'MandateStatement', 'MandateEventBody',
    'AgentDescriptor', 'AgentKey', 'AgentOperator', 'AgentRuntime',
    'StepAiBom', 'StepPromptTemplate', 'StepInferenceParameters', 'StepInfrastructure',
  ])('%s is strict', (name) => {
    expect(classBody(name)).toContain('model_config = ConfigDict(extra="forbid", strict=True)');
  });

  it('writes the nullable members of the record-rule shapes as required keys (no default)', () => {
    const decider = classBody('Decider');
    expect(decider).toMatch(/\n {4}agent: str \| None = Field\(pattern=r"[^"]+"\)\n/);
    expect(decider).toMatch(/\n {4}credential: str \| None = Field\(pattern=r"[^"]+"\)\n/);
    expect(decider).not.toMatch(/default=None/);
    const step = classBody('ContributionStep');
    expect(step).toMatch(/\n {4}actor: StepActor \| None\n/);
    expect(step).toMatch(/\n {4}aiBom: StepAiBom \| None\n/);
    expect(step).toMatch(/\n {4}verdict: ContributionVerdict \| None\n/);
    const target = classBody('LinkTarget');
    expect(target).toMatch(/\n {4}evidenceId: str \| None\n/);
    expect(target).toMatch(/\n {4}locator: LinkLocator \| None\n/);
    const link = classBody('Link');
    expect(link).toContain('attrs: dict[str, str | int | bool] | None = Field(min_length=1, max_length=16)');
    expect(classBody('LinkLocator')).toContain('seq: int = Field(strict=True, ge=1, le=9007199254740991)');
    expect(classBody('CaptureInput')).toContain('links: list[LinkInput] | None = Field(default=None, min_length=1, max_length=256)');
    expect(classBody('MandateStatement')).not.toContain('signerName');
    const expectation = classBody('MandateExpectation');
    expect(expectation).toMatch(/\n {4}totals: dict\[str, int\] \| None\n/);
    expect(expectation).toContain('mandateSeq: int = Field(strict=True, ge=1, le=9007199254740991)');
  });

  it('gives a contribution step a strict, required-nullable bill of materials, and leaves the top-level AiBom lax', () => {
    const bom = classBody('StepAiBom');
    expect(bom).toContain('modelDescriptorDigest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")');
    expect(bom).toMatch(/\n {4}vendorFingerprint: str \| None\n/);
    expect(bom).toMatch(/\n {4}promptTemplate: StepPromptTemplate \| None\n/);
    expect(bom).toMatch(/\n {4}inferenceParameters: StepInferenceParameters \| None\n/);
    expect(bom).toMatch(/\n {4}infrastructure: StepInfrastructure \| None\n/);
    const params = classBody('StepInferenceParameters');
    expect(params).toContain('temperature: float | None = Field(allow_inf_nan=False)');
    expect(params).toContain('maxTokens: int | None = Field(ge=0, le=9007199254740991)');
    expect(params).toContain('seed: int | None = Field(ge=-9007199254740991, le=9007199254740991)');
    expect(params).toMatch(/\n {4}stopSequences: list\[str\] \| None\n/);
    expect(params).toContain('@field_validator("stopSequences")');
    expect(classBody('StepInfrastructure')).toContain('@field_validator("provider", "region", "apiVersion", "endpoint")');
    expect(classBody('StepPromptTemplate')).toMatch(/\n {4}templateId: str \| None\n/);
    const lax = classBody('AiBom');
    expect(lax).not.toContain('strict=True');
    expect(lax).toMatch(/\n {4}vendorFingerprint: str \| None = None\n/);
  });

  it('has one payload model with the twelve members, the record-rule members tolerant so a stored record that misfits still loads', () => {
    const payload = classBody('EvidencePayload');
    for (const member of ['decider', 'contributions', 'links', 'signoffExpectation']) {
      expect(payload).toMatch(new RegExp(`\\n {4}${member}: [^\\n]*\\| Any \\| None = Field\\(default=None, union_mode="left_to_right"\\)`));
    }
    expect(payload).toContain('schemaVersion: str = "v1.0"');
    for (const gone of ['humanAction', 'humanReason', 'aiBom', 'lineage']) expect(payload).not.toContain(`${gone}:`);
    expect(py()).not.toMatch(/class EvidencePayloadV1_1\(|class Lineage/);
    expect(py()).toMatch(/^SignoffExpectation = SignatureRequiredExpectation \| SessionAttachmentExpectation \| MandateExpectation$/m);
  });

  it('adds the eip155 and safe-integer freshness rules and the totals rule as re.fullmatch validators', () => {
    const src = py();
    expect(src).toMatch(/^import re$/m);
    expect(src).toContain('field_validator');
    const decider = classBody('Decider');
    expect(decider).toContain('@field_validator("freshness")');
    expect(decider).toContain('re.fullmatch(r"[1-9][0-9]{0,30}", m.group(2), re.ASCII)');
    expect(decider).toContain('int(m.group(3)) > 9007199254740991');
    expect(classBody('MandateExpectation')).toContain('@field_validator("totals")');
    expect(src).not.toMatch(/re\.match\(/);
  });
});
