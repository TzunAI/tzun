/**
 * The record-rule rows of a `b1` report: `decider`, `decider.freshness`,
 * `contributions`, `contributions.binding`, `links` with `links[<i>]` and
 * `links[<i>].edge`, the mandate rows, the `payload.<name>` rows, and the
 * `fieldSet` fact of a `digest_mismatch`, on bundles exported from a SQLite
 * store.
 */
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  FIELD_SET_0_7,
  canonicalSerialize,
  computeDigest,
  SchemaRegistry,
  type AgentDescriptor,
  type CaptureInput,
} from '@tzun/engine';
import { Tzun, bundleExitCode, verifyBundle, type BundleVerificationReport, type ProofBundle } from '../../src/sdk/index';
import type { EvmHeaderSource } from '../../src/attestation/blockchain';
import { CLAIMS_AGENT_DESCRIPTOR, claim, enrol, issue, mandateDocument, person } from './mandates/fixtures';

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const find = (r: BundleVerificationReport, id: string) => r.checks.find((c) => c.id === id);
const ids = (r: BundleVerificationReport) => r.checks.map((c) => c.id);
/** The rows between `signoff.key` and the first anchor row. */
const ruleRows = (r: BundleVerificationReport) => {
  const list = ids(r);
  return r.checks.slice(list.indexOf('signoff.key') + 1, list.indexOf('anchor'));
};
const hex = (label: string) => createHash('sha256').update(label).digest('hex');

/** The payload's digest under v1.0 again, after an edit to a hashed member. */
function reseal(bundle: ProofBundle): void {
  const schema = new SchemaRegistry().get(bundle.envelope.payload.schemaVersion)!;
  bundle.envelope.integrity.canonicalDigest = computeDigest(
    canonicalSerialize(bundle.envelope.payload as unknown as Record<string, unknown>, schema.hashedFieldSet),
  );
  (bundle as unknown as { subject: { canonicalDigest: string } }).subject.canonicalDigest = bundle.envelope.integrity.canonicalDigest;
}

const decision = (i: number): CaptureInput => ({
  aiSystemId: 'record-rule-rows',
  aiOutput: { recommendation: 'approve', i },
  action: 'approve',
  reason: `record-rule rows #${i}`,
  decider: { kind: 'human', id: 'acct:u-rows', freshness: null },
});

const MODEL_BOM = {
  modelDescriptor: {
    descriptorVersion: 'd1', vendor: 'tzun-tests', modelName: 'rows-model', modelVersion: '1', modelType: null, integrityTier: 'vendor-asserted',
    modelDigest: null, parentModelDescriptorDigest: null, derivation: null, trainedBy: null, license: null, modelCardUrl: null,
    training: { trainingDataDigest: null, trainingDataRef: null, lastTrainingDate: null, evaluations: [] },
    regulatoryMarkings: [], externalIdentifiers: [],
  },
  vendorFingerprint: null,
  promptTemplate: null,
  inferenceParameters: null,
  infrastructure: null,
};

/** A header source that holds one block at `height`, final up to `finalized`. */
function headerSource(chainId: bigint, finalized: number, height: number, hash: string, timestamp: number): EvmHeaderSource {
  return {
    finality: 'finalized',
    chainId: async () => chainId,
    finalizedBlockNumber: async () => finalized,
    canonicalBlock: async (n: number) => (n === height ? { hash, timestamp } : null),
  };
}

describe('verifyBundle: the record-rule rows', () => {
  let dir: string;
  let tzun: Tzun;
  let n = 0;
  const capture = async (edit: Partial<CaptureInput> = {}) => {
    const r = await tzun.capture({ ...decision(++n), ...edit } as CaptureInput);
    if (!r.stored) throw new Error(`capture ${n} was not stored: ${JSON.stringify(r.failure)}`);
    return r.envelope.payload.evidenceId;
  };
  const bundleOf = async (evidenceId: string) => clone(await tzun.exportBundle(evidenceId)) as ProofBundle;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-bundle-rules-'));
    tzun = await Tzun.init({ mode: 'dev', dbPath: join(dir, 'store.db') });
  });
  afterAll(async () => {
    await tzun.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('a human decision recording no model and no link: the decider holds, the rest absent, in report order', async () => {
    const report = await verifyBundle(await bundleOf(await capture()));
    expect(ruleRows(report)).toEqual([
      { id: 'decider', outcome: 'checked-correct', facts: { kind: 'human', scheme: 'acct', level: 'human-asserted' } },
      { id: 'decider.freshness', outcome: 'not-checked', reason: 'absent' },
      { id: 'contributions', outcome: 'not-checked', reason: 'absent' },
      { id: 'contributions.binding', outcome: 'not-checked', reason: 'absent' },
      { id: 'links', outcome: 'not-checked', reason: 'absent' },
    ]);
    expect(ids(report).some((id) => id.startsWith('mandate.') || id.startsWith('payload.'))).toBe(false);
  });

  it('a contributions list of one: contributions and its binding hold, with their facts', async () => {
    const id = await capture({ contributions: { steps: [{ role: 'propose', actor: null, aiBom: MODEL_BOM, inputs: [] }] } as CaptureInput['contributions'] });
    const bundle = await bundleOf(id);
    const model = (bundle.envelope.payload.contributions as { steps: Array<{ aiBom: { modelDescriptorDigest: string } }> }).steps[0].aiBom.modelDescriptorDigest;
    const report = await verifyBundle(bundle);
    expect(find(report, 'contributions')).toEqual({ id: 'contributions', outcome: 'checked-correct', facts: { steps: 1, models: [model], decidingStep: 'record' } });
    expect(find(report, 'contributions.binding')).toEqual({
      id: 'contributions.binding',
      outcome: 'checked-correct',
      facts: { approvals: [], staleApprovals: [], uncoveredReviews: [], proposals: [0], decisionBinding: 'checked' },
    });
  });

  it('a derivedFrom link: the links rows, each edge abstaining; exit 4, 0 under the scoped allowance', async () => {
    const parent = await capture();
    const report = await verifyBundle(await bundleOf(await capture({ links: [{ rel: 'derivedFrom', target: { evidenceId: parent } }] })));
    expect(ruleRows(report).slice(4)).toEqual([
      { id: 'links', outcome: 'checked-correct', facts: { count: 2, relations: ['derivedFrom', 'root'], extensions: 0 } },
      { id: 'links[0]', outcome: 'checked-correct', facts: { targetHeld: false } },
      { id: 'links[0].edge', outcome: 'abstain', reason: 'unsupported_link_edge' },
      { id: 'links[1]', outcome: 'checked-correct', facts: { targetHeld: false } },
      { id: 'links[1].edge', outcome: 'abstain', reason: 'unsupported_link_edge' },
    ]);
    const unanchored = { allowUnchecked: ['unsupported_link_edge', 'not_yet_published'] };
    expect(bundleExitCode(report)).toBe(4);
    expect(bundleExitCode(report, unanchored)).toBe(0);
  });

  it('decider.freshness against the auditor header source: correct with its facts, mismatch, not final, no source, another chain', async () => {
    const hash = `0x${hex('block 7')}`;
    const bundle = await bundleOf(await capture({ decider: { kind: 'human', id: 'acct:u-rows', freshness: `eip155:31337@7:${hash}` } }));
    const capturedAt = Date.parse(bundle.envelope.payload.capturedAt);
    const blockTime = Math.floor(capturedAt / 1000) - 30;
    const at = (source: EvmHeaderSource) => verifyBundle(bundle, { evmHeaderSources: { 'eip155:31337': source } });

    expect(find(await at(headerSource(31337n, 9, 7, hash, blockTime)), 'decider.freshness')).toEqual({
      id: 'decider.freshness',
      outcome: 'checked-correct',
      facts: { blockTime: new Date(blockTime * 1000).toISOString(), captureLag: capturedAt - blockTime * 1000 },
    });
    expect(find(await at(headerSource(31337n, 9, 7, `0x${hex('another block')}`, blockTime)), 'decider.freshness')).toEqual({
      id: 'decider.freshness', outcome: 'checked-wrong', reason: 'freshness_block_mismatch',
    });
    expect(find(await at(headerSource(31337n, 6, 7, hash, blockTime)), 'decider.freshness')).toMatchObject({ outcome: 'not-checked', reason: 'evm_block_not_finalized' });
    expect(find(await at(headerSource(1n, 9, 7, hash, blockTime)), 'decider.freshness')).toMatchObject({ outcome: 'not-checked', reason: 'evm_header_source_chain_mismatch' });
    expect(find(await at(headerSource(31337n, 9, 8, hash, blockTime)), 'decider.freshness')).toMatchObject({ outcome: 'not-checked', reason: 'evm_header_source_inconsistent' });
    const failing: EvmHeaderSource = { chainId: async () => { throw new Error('down'); }, finalizedBlockNumber: async () => 9, canonicalBlock: async () => null };
    expect(find(await at(failing), 'decider.freshness')).toMatchObject({ outcome: 'not-checked', reason: 'evm_header_source_unavailable' });
    expect(find(await verifyBundle(bundle), 'decider.freshness')).toEqual({ id: 'decider.freshness', outcome: 'not-checked', reason: 'input_not_supplied:evm_header_source' });

    const other = clone(bundle);
    (other.envelope.payload.decider as { freshness: string }).freshness = `bip122:000000000019d6689c085ae165831e93@7:${hash}`;
    reseal(other);
    const otherReport = await verifyBundle(other);
    expect(find(otherReport, 'decider')).toMatchObject({ outcome: 'checked-correct' });
    expect(find(otherReport, 'decider.freshness')).toEqual({ id: 'decider.freshness', outcome: 'abstain', reason: 'unsupported_freshness_chain' });
  });

  it('a payload edited under its digest: every row that reads the payload is blocked by record.digest', async () => {
    const bundle = await bundleOf(await capture());
    bundle.envelope.payload.reason = 'edited after capture';
    const report = await verifyBundle(bundle);
    expect(find(report, 'record.digest')).toEqual({ id: 'record.digest', outcome: 'checked-wrong', reason: 'digest_mismatch' });
    expect(ruleRows(report)).toEqual(
      ['decider', 'decider.freshness', 'contributions', 'contributions.binding', 'links'].map((id) => ({
        id,
        outcome: 'not-checked',
        reason: 'blocked_by:record.digest',
      })),
    );
  });

  it('a record rewritten into the 0.7 field set: digest_mismatch with the fieldSet fact, and a payload row per unhashed member', async () => {
    const bundle = await bundleOf(await capture());
    const p = bundle.envelope.payload as unknown as Record<string, unknown>;
    const legacy: Record<string, unknown> = {
      evidenceId: p.evidenceId,
      schemaVersion: p.schemaVersion,
      aiSystemId: p.aiSystemId,
      aiOutput: p.aiOutput,
      humanAction: p.action,
      humanReason: p.reason,
      capturedAt: p.capturedAt,
      sequenceNumber: p.sequenceNumber,
      aiBom: null,
      signoffExpectation: null,
    };
    (bundle.envelope as { payload: unknown }).payload = legacy;
    bundle.envelope.integrity.canonicalDigest = computeDigest(canonicalSerialize(legacy, [...FIELD_SET_0_7]));
    (bundle as unknown as { subject: { canonicalDigest: string } }).subject.canonicalDigest = bundle.envelope.integrity.canonicalDigest;
    const report = await verifyBundle(bundle);
    expect(find(report, 'record.digest')).toEqual({ id: 'record.digest', outcome: 'checked-wrong', reason: 'digest_mismatch', facts: { fieldSet: '0.7' } });
    expect(report.checks.filter((c) => c.id.startsWith('payload.'))).toEqual(
      ['aiBom', 'humanAction', 'humanReason'].map((name) => ({ id: `payload.${name}`, outcome: 'abstain', reason: 'unsupported_member' })),
    );
    expect(bundleExitCode(report)).toBe(1);
  });

  it('an unhashed payload member beside an intact digest: its own row, before member rows, and exit 4', async () => {
    const bundle = await bundleOf(await capture());
    (bundle.envelope.payload as unknown as Record<string, unknown>).zNote = 'not hashed';
    (bundle.envelope.payload as unknown as Record<string, unknown>).aNote = 'not hashed';
    (bundle as unknown as Record<string, unknown>).stray = 1;
    const report = await verifyBundle(bundle);
    expect(find(report, 'record.digest')).toMatchObject({ outcome: 'checked-correct' });
    const tail = ids(report).filter((id) => id.startsWith('payload.') || id.startsWith('member['));
    expect(tail).toEqual(['payload.aNote', 'payload.zNote', 'member[stray]']);
    expect(find(report, 'payload.aNote')).toEqual({ id: 'payload.aNote', outcome: 'abstain', reason: 'unsupported_member' });
    expect(bundleExitCode(report, { allowUnchecked: ['not_yet_published', 'absent'] })).toBe(4);
  });
});

describe('verifyBundle: the mandate rows', () => {
  let dir: string;
  let tzun: Tzun;
  const principal = person('user-rows');

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-bundle-mandate-'));
    tzun = await Tzun.init({ mode: 'dev', dbPath: join(dir, 'store.db') });
    await enrol(tzun, principal);
    await tzun.agents.register(CLAIMS_AGENT_DESCRIPTOR as AgentDescriptor);
  });
  afterAll(async () => {
    await tzun.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('an issuance record and a record under the mandate: mandate.issuance, then scope, limits and key; no nonRepudiation row for the mandate members', async () => {
    const document = mandateDocument(principal.userId);
    const issued = await issue(tzun, document, principal);
    const issuance = await verifyBundle(clone(await tzun.exportBundle(issued.issuance.envelope.payload.evidenceId)));
    expect(find(issuance, 'mandate.issuance')).toEqual({ id: 'mandate.issuance', outcome: 'checked-correct' });
    expect(ids(issuance).some((id) => id === 'mandate.scope' || id === 'mandate.key')).toBe(false);
    expect(ids(issuance).some((id) => id.startsWith('nonRepudiation.mandate'))).toBe(false);

    const result = await tzun.capture(claim(5), { mandate: { mandateId: document.mandateId } });
    expect(result.stored).toBe(true);
    const report = await verifyBundle(clone(await tzun.exportBundle(result.envelope.payload.evidenceId)));
    const rules = ruleRows(report).map((c) => c.id);
    expect(rules.slice(rules.indexOf('mandate.scope'))).toEqual(['mandate.scope', 'mandate.limits', 'mandate.key']);
    expect(find(report, 'mandate.scope')).toEqual({ id: 'mandate.scope', outcome: 'checked-correct' });
    expect(find(report, 'mandate.limits')).toEqual({ id: 'mandate.limits', outcome: 'checked-correct', facts: { slot: 1, totals: { paid: 5 } } });
    expect(find(report, 'mandate.key')).toEqual({ id: 'mandate.key', outcome: 'not-checked', reason: 'not_in_bundle:credential' });
    expect(find(report, 'decider')).toMatchObject({ outcome: 'checked-correct', facts: { kind: 'agent-mandated', scheme: 'desc', level: 'agent-asserted' } });
    expect(ids(report).some((id) => id.startsWith('nonRepudiation.'))).toBe(false);

    const withCredentials = { ...clone(await tzun.exportBundle(result.envelope.payload.evidenceId)), credentials: { any: 'thing' } };
    expect(find(await verifyBundle(withCredentials), 'mandate.key')).toEqual({ id: 'mandate.key', outcome: 'abstain', reason: 'unsupported_signoff' });

    const edited = clone(await tzun.exportBundle(result.envelope.payload.evidenceId));
    edited.envelope.payload.reason = 'edited after capture';
    const blocked = await verifyBundle(edited);
    expect(['mandate.scope', 'mandate.limits'].map((id) => find(blocked, id))).toEqual([
      { id: 'mandate.scope', outcome: 'not-checked', reason: 'blocked_by:record.digest' },
      { id: 'mandate.limits', outcome: 'not-checked', reason: 'blocked_by:record.digest' },
    ]);
  });
});
