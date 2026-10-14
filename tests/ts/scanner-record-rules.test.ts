/**
 * The scheduled scanner's record rules and mandate checks, on a SQLite store
 * as the SDK installs it: a record whose digest holds and breaks a structure
 * rule raises `record_rule_violated` (`decider`, `links.target`,
 * `payload.members`); a digest that an earlier field set reproduces carries
 * `fieldSet`; open mandates past their window are expired; a mandate's records
 * missing a slot raise `mandate_slot_gap`. A conforming store raises none of
 * them.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EvidenceChain,
  FIELD_SET_0_7,
  SchemaRegistry,
  canonicalSerialize,
  computeDigest,
  type CaptureInput,
  type EvidenceEnvelope,
  type MonitoringEvent,
  type ScanCompletedEvent,
} from '@tzun/engine';
import { Tzun } from '../../src/sdk';
import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { ScheduledScanner } from '../../src/monitoring/scheduled-scanner';
import { deleteStoredEnvelope, rewriteStoredEnvelope } from './helpers/tamper-store';
import { CLAIMS_AGENT_DESCRIPTOR, HOUR, claim, enrol, issue, mandateDocument, person } from './mandates/fixtures';

const registry = new SchemaRegistry();
const decision = (i: number, edit: Partial<CaptureInput> = {}): CaptureInput =>
  ({
    aiSystemId: 'scanner-rules',
    aiOutput: { recommendation: 'approve', i },
    action: 'approve',
    reason: `scanner rules #${i}`,
    decider: { kind: 'human', id: 'acct:u-scan', freshness: null },
    ...edit,
  }) as CaptureInput;

describe('the scheduled scanner: record rules and mandates', () => {
  let dir: string;
  let tzun: Tzun;
  let n = 0;
  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-scan-rules-'));
    tzun = await Tzun.init({ mode: 'dev', dbPath: join(dir, 'store.db') });
  });
  afterEach(async () => {
    await tzun.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const capture = async (edit: Partial<CaptureInput> = {}): Promise<EvidenceEnvelope> => {
    const r = await tzun.capture(decision(++n, edit));
    if (!r.stored) throw new Error(`capture ${n} was not stored: ${JSON.stringify(r.failure)}`);
    return r.envelope;
  };
  const pass = async (): Promise<{ events: MonitoringEvent[]; completed: ScanCompletedEvent }> => {
    const bus = new MonitoringEventBus();
    const events: MonitoringEvent[] = [];
    bus.subscribe((e) => events.push(e));
    const scanner = new ScheduledScanner(tzun.getStorage(), bus, registry, {
      batchSize: 100,
      workers: 2,
      mode: 'interval',
      intervalMs: 0,
      verifyAttestation: false,
      verifyChainCompleteness: true,
    });
    await scanner.runFullPass();
    const completed = events.find((e): e is ScanCompletedEvent => e.type === 'scan_completed')!;
    return { events, completed };
  };
  const ofType = <T extends MonitoringEvent['type']>(events: MonitoringEvent[], type: T) =>
    events.filter((e): e is Extract<MonitoringEvent, { type: T }> => e.type === type);

  it('raises nothing on records a conforming writer made: links, contributions and mandates', async () => {
    const parent = await capture();
    await capture({ links: [{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId } }] });
    const principal = person('user-scan');
    await enrol(tzun, principal);
    await tzun.agents.register(CLAIMS_AGENT_DESCRIPTOR);
    const document = mandateDocument(principal.userId);
    await issue(tzun, document, principal);
    expect((await tzun.capture(claim(5), { mandate: { mandateId: document.mandateId } })).stored).toBe(true);

    const { events, completed } = await pass();
    expect(ofType(events, 'record_rule_violated')).toEqual([]);
    expect(events.filter((e) => e.type.startsWith('mandate_'))).toEqual([]);
    expect(completed).toMatchObject({ issuesFound: 0, recordRuleViolations: 0, mandateFindings: 0 });
  });

  it('a held link target rewritten after capture: links.target on the record that links it, beside its digest_mismatch', async () => {
    const parent = await capture();
    const child = await capture({ links: [{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId } }] });
    await rewriteStoredEnvelope(tzun.getStorage(), parent.payload.evidenceId, (e) => {
      e.payload.reason = 'rewritten after capture';
    });
    const { events, completed } = await pass();
    expect(ofType(events, 'digest_mismatch').map((e) => e.evidenceId)).toEqual([parent.payload.evidenceId]);
    expect(ofType(events, 'record_rule_violated')).toEqual([
      { type: 'record_rule_violated', evidenceId: child.payload.evidenceId, rule: 'links.target', reason: 'link_target_mismatch' },
      { type: 'record_rule_violated', evidenceId: child.payload.evidenceId, rule: 'links.target', reason: 'link_target_mismatch' },
    ]);
    expect(completed.recordRuleViolations).toBe(2);
  });

  it('an unhashed payload member beside an intact digest: payload.members', async () => {
    const record = await capture();
    await rewriteStoredEnvelope(tzun.getStorage(), record.payload.evidenceId, (e) => {
      (e.payload as unknown as Record<string, unknown>).humanReason = 'unhashed, editable';
    });
    const { events } = await pass();
    expect(ofType(events, 'digest_mismatch')).toEqual([]);
    expect(ofType(events, 'record_rule_violated')).toEqual([
      { type: 'record_rule_violated', evidenceId: record.payload.evidenceId, rule: 'payload.members', reason: 'unsupported_member' },
    ]);
  });

  it('a decider a conforming writer refuses, under a digest that holds: rule decider', async () => {
    const first = await capture();
    const last = await capture();
    await rewriteStoredEnvelope(tzun.getStorage(), last.payload.evidenceId, (e) => {
      // A human decider that names an agent: inconsistent.
      (e.payload.decider as unknown as Record<string, unknown>).agent = `sha256:${'a'.repeat(64)}`;
      e.integrity.canonicalDigest = computeDigest(canonicalSerialize(e.payload as unknown as Record<string, unknown>, registry.get('v1.0')!.hashedFieldSet));
      const chain = new EvidenceChain();
      chain.restore(first.integrity.canonicalDigest);
      e.integrity.chainLink = chain.computeLink(e.integrity.canonicalDigest);
    });
    const { events } = await pass();
    expect(ofType(events, 'digest_mismatch')).toEqual([]);
    expect(ofType(events, 'record_rule_violated')).toEqual([
      expect.objectContaining({ evidenceId: last.payload.evidenceId, rule: 'decider' }),
    ]);
  });

  it('a record rewritten into the 0.7 field set: digest_mismatch with fieldSet 0.7, and no rule finding', async () => {
    const record = await capture();
    await rewriteStoredEnvelope(tzun.getStorage(), record.payload.evidenceId, (e) => {
      const p = e.payload as unknown as Record<string, unknown>;
      const legacy = {
        evidenceId: p.evidenceId, schemaVersion: p.schemaVersion, aiSystemId: p.aiSystemId, aiOutput: p.aiOutput,
        humanAction: p.action, humanReason: p.reason, capturedAt: p.capturedAt, sequenceNumber: p.sequenceNumber,
        aiBom: null, signoffExpectation: null,
      };
      (e as { payload: unknown }).payload = legacy;
      e.integrity.canonicalDigest = computeDigest(canonicalSerialize(legacy, [...FIELD_SET_0_7]));
    });
    const { events } = await pass();
    expect(ofType(events, 'digest_mismatch')).toEqual([expect.objectContaining({ evidenceId: record.payload.evidenceId, fieldSet: '0.7' })]);
    expect(ofType(events, 'record_rule_violated')).toEqual([]);
  });

  it('expires an open mandate past its window, once, with its event', async () => {
    const principal = person('user-scan');
    await enrol(tzun, principal);
    const ended = mandateDocument(principal.userId, {
      validity: { notBefore: new Date(Date.now() - 3 * HOUR).toISOString(), notAfter: new Date(Date.now() - HOUR).toISOString() },
    });
    await issue(tzun, ended, principal);
    expect(await tzun.getStorage().getMandate!(ended.mandateId)).toMatchObject({ state: 'open' });
    await pass();
    expect(await tzun.getStorage().getMandate!(ended.mandateId)).toMatchObject({ state: 'expired' });
    const events = await tzun.getStorage().listMandateEvents!(ended.mandateId);
    expect(events.map((e) => e.body.event)).toEqual(['issued', 'expired']);
    await pass();
    expect((await tzun.getStorage().listMandateEvents!(ended.mandateId)).map((e) => e.body.event)).toEqual(['issued', 'expired']);
  });

  it("a record under a mandate deleted from the store: mandate_slot_gap names the slot and what its totals leave unexplained", async () => {
    const principal = person('user-scan');
    await enrol(tzun, principal);
    await tzun.agents.register(CLAIMS_AGENT_DESCRIPTOR);
    const document = mandateDocument(principal.userId);
    const issued = await issue(tzun, document, principal);
    const one = await tzun.capture(claim(5), { mandate: { mandateId: document.mandateId } });
    const two = await tzun.capture(claim(7), { mandate: { mandateId: document.mandateId } });
    expect([one.mandate?.slot, two.mandate?.slot]).toEqual([1, 2]);
    await deleteStoredEnvelope(tzun.getStorage(), one.envelope.payload.evidenceId);
    const { events, completed } = await pass();
    expect(ofType(events, 'mandate_slot_gap')).toEqual([
      { type: 'mandate_slot_gap', mandateDigest: issued.mandateDigest, from: 1, to: 1, unexplained: { paid: 5 } },
    ]);
    expect(completed.mandateFindings).toBe(1);
  });
});

describe('the scheduled scanner on a memory store a record was deleted from', () => {
  it('the link index scan skips the deleted record, and the gap is reported', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    try {
      const principal = person('user-scan-memory');
      await enrol(tzun, principal);
      await tzun.agents.register(CLAIMS_AGENT_DESCRIPTOR);
      const document = mandateDocument(principal.userId);
      const issued = await issue(tzun, document, principal);
      const one = await tzun.capture(claim(5), { mandate: { mandateId: document.mandateId } });
      await tzun.capture(claim(7), { mandate: { mandateId: document.mandateId } });
      await deleteStoredEnvelope(tzun.getStorage(), one.envelope.payload.evidenceId);
      const page = await tzun.getStorage().listLinksTo!(issued.issuance.envelope.integrity.canonicalDigest, { rels: ['mandate'] });
      expect(page.rows).toHaveLength(1);

      const bus = new MonitoringEventBus();
      const events: MonitoringEvent[] = [];
      bus.subscribe((e) => events.push(e));
      await new ScheduledScanner(tzun.getStorage(), bus, registry, {
        batchSize: 100, workers: 1, mode: 'interval', intervalMs: 0, verifyAttestation: false, verifyChainCompleteness: true,
      }).runFullPass();
      expect(events.filter((e) => e.type === 'mandate_slot_gap')).toEqual([
        { type: 'mandate_slot_gap', mandateDigest: issued.mandateDigest, from: 1, to: 1, unexplained: { paid: 5 } },
      ]);
    } finally {
      await tzun.close();
    }
  });
});
