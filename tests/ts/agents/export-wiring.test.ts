/**
 * `tzun.exportEvidence()` bundles the agent descriptors a record references
 * (`resolvedAgentDescriptors`), and the reference offline
 * verifier (tests/ts/helpers/verify-exported.ts) resolves them from the
 * bundle alone: a row rewritten in the bundle, or left out of it, is
 * reported.
 */
import type { ExportedEvidenceEnvelope } from '@tzun/engine';
import { Tzun } from '../../../src/sdk';
import { decidersExtension } from '../../../src/storage/ddl/deciders';
import { verifyExported } from '../helpers/verify-exported';
import { X12, policyEngineDescriptor } from './fixtures';

const decision = { aiOutput: { recommendation: 'pay' }, action: 'pay', reason: 'within the automatic-payment limit' };

/** The bundle as a file would carry it. */
const asFile = (bundle: ExportedEvidenceEnvelope): ExportedEvidenceEnvelope => JSON.parse(JSON.stringify(bundle));
const errorsOf = (r: Awaited<ReturnType<typeof verifyExported>>): string[] => (r.ok ? [] : r.errors);

describe('tzun.exportEvidence: resolvedAgentDescriptors', () => {
  it('bundles every referenced descriptor once, and the offline verifier resolves them', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    try {
      const engine = (await tzun.agents.register(policyEngineDescriptor())).digest;
      const model = (await tzun.agents.register(X12)).digest;
      const step = { role: 'other', actor: { kind: 'agent' as const, agent: model }, aiBom: null, inputs: [], outputOf: { n: 1 } };
      const r = await tzun.capture({ ...decision, decider: { kind: 'policy-engine', agent: engine }, contributions: { steps: [step] } });
      expect(r.failure).toBeUndefined();

      const bundle = asFile(await tzun.exportEvidence(r.envelope.payload.evidenceId));
      expect(Object.keys(bundle.resolvedAgentDescriptors!)).toEqual([engine, model]);
      expect(bundle.resolvedAgentDescriptors![model]).toMatchObject({ canonicalBytes: (await tzun.agents.get(model))!.canonicalBytes, name: X12.name });
      expect(errorsOf(await verifyExported(bundle))).toEqual([]);

      const rewritten = asFile(bundle);
      const entry = rewritten.resolvedAgentDescriptors![model] as { canonicalBytes: string };
      entry.canonicalBytes = entry.canonicalBytes.replace('Example', 'Other');
      expect(errorsOf(await verifyExported(rewritten))).toEqual([`agent "${model}" (contributions.steps[0].actor): digest_mismatch`]);

      const dropped = asFile(bundle);
      delete dropped.resolvedAgentDescriptors![engine];
      expect(errorsOf(await verifyExported(dropped))).toEqual([`agent "${engine}" (decider): not_registered`]);

      // An entry the record does not name is reported, and does not relabel the record's own entries.
      const junk = `sha256:${'f'.repeat(64)}`;
      const padded = asFile(rewritten);
      padded.resolvedAgentDescriptors![junk] = { canonicalBytes: '', missing: true, reason: 'catalog_absent' };
      expect(errorsOf(await verifyExported(padded))).toEqual([
        `bundle: resolvedAgentDescriptors names ${junk}, which the record does not`,
        `agent "${model}" (contributions.steps[0].actor): digest_mismatch`,
      ]);
    } finally {
      await tzun.close();
    }
  });

  it('a record that names no agent bundles none', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    try {
      const r = await tzun.capture({ ...decision, decider: { kind: 'human', id: 'acct:u-4821' } });
      const bundle = await tzun.exportEvidence(r.envelope.payload.evidenceId);
      expect(bundle.resolvedAgentDescriptors).toEqual({});
      expect(errorsOf(await verifyExported(asFile(bundle)))).toEqual([]);
    } finally {
      await tzun.close();
    }
  });

  it('a store without the catalog marks each reference catalog_absent, which the offline verifier reports', async () => {
    const tzun = await Tzun.init({ mode: 'dev', _sdkExtensions: [], _storageExtensions: [decidersExtension] });
    try {
      const agent = `sha256:${'ab'.repeat(32)}`;
      const r = await tzun.capture({ ...decision, decider: { kind: 'agent', agent } });
      const bundle = await tzun.exportEvidence(r.envelope.payload.evidenceId);
      expect(bundle.resolvedAgentDescriptors).toEqual({ [agent]: { canonicalBytes: '', missing: true, reason: 'catalog_absent' } });
      expect(errorsOf(await verifyExported(asFile(bundle)))).toEqual([`agent "${agent}" (decider): catalog_absent`]);
    } finally {
      await tzun.close();
    }
  });
});

describe('a prepared capture', () => {
  it('is refused when this store\'s catalog does not hold an agent it references, wherever it was prepared', async () => {
    const agent = `sha256:${'ab'.repeat(32)}`;
    const input = { ...decision, decider: { kind: 'agent' as const, agent } };
    // Prepared on an instance whose store keeps no catalog, so nothing refused the reference there.
    const without = await Tzun.init({ mode: 'dev', _sdkExtensions: [], _storageExtensions: [decidersExtension] });
    const withCatalog = await Tzun.init({ mode: 'dev' });
    try {
      const prepared = await without.prepareAssertionChallenge(input);
      const r = await withCatalog.capture(input, { prepared });
      expect(r.stored).toBe(false);
      expect(r.failure?.diagnosticMetadata).toMatchObject({ code: 'agent_not_registered', field: 'decider.agent' });
      // No sequence number was taken: the next record takes the one the prepared record named.
      const next = await withCatalog.capture({ ...decision, decider: { kind: 'human', id: 'acct:u-4821' } });
      expect(next.envelope.payload.sequenceNumber).toBe(prepared.sequenceNumber);
    } finally {
      await without.close();
      await withCatalog.close();
    }
  });

  it('is stored when the catalog holds every agent it references', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    try {
      const { digest } = await tzun.agents.register(X12);
      const input = { ...decision, decider: { kind: 'agent' as const, agent: digest } };
      const prepared = await tzun.prepareAssertionChallenge(input);
      const r = await tzun.capture(input, { prepared });
      expect(r.failure).toBeUndefined();
      expect(r.stored).toBe(true);
      expect(r.envelope.integrity.canonicalDigest).toBe(prepared.digest);
    } finally {
      await tzun.close();
    }
  });
});
