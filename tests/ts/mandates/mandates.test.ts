/**
 * Mandates end to end, on every backend: prepare
 * and issue, capture under a mandate (the slot claim, the expectation, the
 * `mandate` link, the block, the custody entries), the refusals, expiry,
 * revocation, succession, and the confirmation.
 */
import {
  checkMandateIssuance,
  mandateConfirmationChallenge,
  mandateDigest,
  mandateEventBodyDigest,
  webauthnChallengeForDigest,
} from '@tzun/engine';
import { singleModel } from '@tzun/engine';
import type { AiBom, CaptureResult, MandateEventBody, ModelDescriptor, TzunConfig } from '@tzun/engine';
import { randomUUID } from 'node:crypto';
import { Wallet } from 'ethers';
import { FakeEvmChain } from '../helpers/anchoring-fake-chain';
import { Tzun } from '../../../src/sdk';
import { MandateError, type PreparedMandateRevocation } from '../../../src/sdk/mandates';
import { mandateErrorOfFailure } from '../../../src/sdk/mandates/errors';
import { AGENT, HOUR, OTHER_AGENT, assert, backends, claim, enrol, issue, mandateDocument, person, type Person } from './fixtures';

const failureCode = (r: CaptureResult): unknown => r.failure?.diagnosticMetadata.code;
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

describe.each(backends('mandates_e2e'))('mandates on $name', (backend) => {
  let tzun: Tzun;
  let principal: Person;
  let auditor: Person;

  beforeEach(async () => {
    tzun = await backend.fresh();
    principal = person('user-2c9d');
    auditor = person('user-7702');
    await enrol(tzun, principal);
    await enrol(tzun, auditor);
  });
  afterEach(async () => {
    await tzun.close();
  });

  describe('prepare and issue', () => {
    it('prepare forms the statement the principal signs and persists nothing', async () => {
      const document = mandateDocument(principal.userId);
      const prepared = await tzun.mandates.prepare(document);
      expect(prepared.statement).toEqual({
        v: 'tzun-signoff-mandate/1',
        mode: 'mandate',
        mandateDigest: mandateDigest(document),
        signer: principal.userId,
        signerKind: 'human',
        meaning: 'responsibility',
        policyDigest: 'none',
        notBefore: 'none',
      });
      expect(prepared.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(await tzun.mandates.get(document.mandateId)).toBeNull();
    });

    it('issue captures the issuance record, and writes the mandate and its issued event with it', async () => {
      const document = mandateDocument(principal.userId);
      const issued = await issue(tzun, document, principal);
      expect(issued.mandateId).toBe(document.mandateId);
      expect(issued.mandateDigest).toBe(mandateDigest(document));

      const record = issued.issuance.envelope;
      expect(record.payload.aiSystemId).toBe('tzun:mandate');
      expect(record.payload.action).toBe('issue-mandate');
      expect(record.payload.aiOutput).toEqual({
        assertionDigest: expect.stringMatching(/^[0-9a-f]{64}$/),
        mandateDigest: issued.mandateDigest,
        statementDigest: expect.stringMatching(/^[0-9a-f]{64}$/),
      });
      expect(record.payload.decider).toMatchObject({ kind: 'human', id: `acct:${principal.userId}`, agent: null });
      expect(record.payload.contributions).toBeNull();
      expect(record.payload.links).toBeNull();
      expect(record.payload.signoffExpectation).toBeNull();
      expect(record.nonRepudiation.mandateIssuance?.document).toEqual(document);
      expect(checkMandateIssuance(record)).toEqual({ outcome: 'checked-correct', valid: true });
      expect((await tzun.verify(record.payload.evidenceId)).verified).toBe(true);

      const row = await tzun.mandates.get(document.mandateId);
      expect(row).toMatchObject({
        mandateId: document.mandateId,
        mandateDigest: issued.mandateDigest,
        state: 'open',
        used: 0,
        maxRecords: 3,
        notBefore: document.validity.notBefore,
        notAfter: document.validity.notAfter,
        issuanceEvidenceId: record.payload.evidenceId,
        issuanceDigest: record.integrity.canonicalDigest,
        assertionTimestamp: null,
      });
      // The row is also found by the mandate's digest, as a successor names its predecessor.
      expect((await tzun.mandates.get(issued.mandateDigest))?.mandateId).toBe(document.mandateId);

      const events = await tzun.mandates.events(document.mandateId);
      expect(events.map((e) => e.body)).toEqual([
        {
          v: 'tzun-mandate-event/1',
          event: 'issued',
          mandateDigest: issued.mandateDigest,
          record: record.integrity.canonicalDigest,
          successor: null,
          used: null,
          totals: null,
        },
      ]);
      expect(events[0].digest).toBe(mandateEventBodyDigest(events[0].body));
    });

    it('refuses a document prepare would refuse, a statement not of the document, and an assertion that does not verify', async () => {
      const document = mandateDocument(principal.userId);
      const prepared = await tzun.mandates.prepare(document);
      const sub = { ...document, delegation: { allowed: true, maxDepth: 1, attenuation: 'subset' as const } };
      await expect(tzun.mandates.prepare(sub)).rejects.toMatchObject({ code: 'invalid_document', field: 'document.delegation' });

      const otherStatement = { ...prepared.statement, signer: auditor.userId };
      await expect(
        tzun.mandates.issue({ document, statement: otherStatement, assertion: assert(principal, prepared.challenge) }),
      ).rejects.toMatchObject({ code: 'invalid_statement' });

      const byAuditor = tzun.mandates.issue({ document, statement: prepared.statement, assertion: assert(auditor, prepared.challenge) });
      await expect(byAuditor).rejects.toMatchObject({ code: 'assertion_not_verified', details: { reason: 'credential_not_principal' } });

      const noUv = tzun.mandates.issue({ document, statement: prepared.statement, assertion: assert(principal, prepared.challenge, { uv: false }) });
      await expect(noUv).rejects.toMatchObject({ code: 'assertion_not_verified', details: { reason: 'user_not_verified' } });

      const wrongChallenge = tzun.mandates.issue({ document, statement: prepared.statement, assertion: assert(principal, 'x'.repeat(43)) });
      await expect(wrongChallenge).rejects.toMatchObject({ code: 'assertion_not_verified', details: { reason: 'challenge_mismatch' } });

      const stranger = person('user-unknown');
      const unknown = tzun.mandates.issue({ document, statement: prepared.statement, assertion: assert(stranger, prepared.challenge) });
      await expect(unknown).rejects.toMatchObject({ code: 'assertion_not_verified', details: { reason: 'unknown_credential' } });

      // Nothing was issued and no sequence number was taken.
      expect(await tzun.mandates.get(document.mandateId)).toBeNull();
      expect((await tzun.capture(claim(1, { kind: 'agent' }))).envelope.payload.sequenceNumber).toBe(1);
    });

    it('refuses to issue one mandate twice', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      await expect(issue(tzun, document, principal)).rejects.toMatchObject({ code: 'mandate_already_issued', failureType: 'mandate_refused' });
      const again = mandateDocument(principal.userId, { mandateId: document.mandateId, review: { maxAgeMs: 1 } });
      await expect(issue(tzun, again, principal)).rejects.toBeInstanceOf(MandateError);
    });
  });

  describe('capture under a mandate', () => {
    it('claims the next slot and the running totals, and records the mandate four ways', async () => {
      const document = mandateDocument(principal.userId);
      const issued = await issue(tzun, document, principal);
      const issuance = issued.issuance.envelope;

      const first = await tzun.capture(claim(200_000), { mandate: { mandateId: document.mandateId } });
      expect(first.failure).toBeUndefined();
      expect(first.mandate).toEqual({ mandateId: document.mandateId, slot: 1, totals: { paid: 200_000 } });
      const p = first.envelope.payload;
      expect(p.decider).toMatchObject({ kind: 'agent-mandated', id: `desc:${AGENT}`, agent: AGENT });
      expect(p.signoffExpectation).toEqual({
        mandateAssertion: issuance.payload.aiOutput.assertionDigest,
        mandateSeq: 1,
        totals: { paid: 200_000 },
        confirm: false,
      });
      expect(p.links).toEqual([
        {
          rel: 'mandate',
          target: {
            digest: issuance.integrity.canonicalDigest,
            evidenceId: issuance.payload.evidenceId,
            locator: { origin: expect.stringMatching(/\/evidence\/[0-9a-f]+$/), seq: issuance.payload.sequenceNumber },
          },
          attrs: null,
        },
      ]);
      expect(first.envelope.nonRepudiation.mandate).toEqual({
        statement: issuance.nonRepudiation.mandateIssuance!.statement,
        assertion: issuance.nonRepudiation.mandateIssuance!.assertion,
        assertionTimestamp: null,
        document,
      });
      expect(first.envelope.custodyChain.map((e) => [e.action, e.actor])).toEqual([
        ['decision_captured', `desc:${AGENT}`],
        ['captured_under_mandate', `desc:${AGENT}`],
      ]);
      expect(first.envelope.custodyChain[1].metadata).toEqual({
        mandateId: document.mandateId,
        slot: 1,
        statementDigest: issuance.payload.aiOutput.statementDigest,
        assertionDigest: issuance.payload.aiOutput.assertionDigest,
      });
      const verified = await tzun.verify(p.evidenceId);
      expect(verified.verified).toBe(true);
      expect(verified.signoffExpectationValid).toBe(true);

      const second = await tzun.capture(claim(300_000, { fraudFlag: true, action: 'refer' }), { mandate: { mandateId: document.mandateId } });
      expect(second.mandate).toEqual({ mandateId: document.mandateId, slot: 2, totals: { paid: 500_000 } });
      expect(second.envelope.payload.signoffExpectation).toMatchObject({ mandateSeq: 2, confirm: true });
      expect(second.envelope.custodyChain.map((e) => e.action)).toEqual(['decision_captured', 'captured_under_mandate', 'confirmation_required']);
      expect(second.envelope.custodyChain[2].metadata).toEqual({ mandateId: document.mandateId, slot: 2, predicates: ['fraud'] });
      expect((await tzun.verify(second.envelope.payload.evidenceId)).signoffExpectationReason).toBe('confirmation_missing');

      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ state: 'open', used: 2 });
      expect((await tzun.getStorage().getMandateTotals!(document.mandateId))).toEqual({ paid: 500_000 });
    });

    it('refuses before any sequence number: scope, agent, kind, caps, slots, confirm and an unknown mandate', async () => {
      const document = mandateDocument(principal.userId, {
        limits: { maxRecords: 2, cumulative: { paid: { path: '/aiOutput/amountMinor', max: 600_000 } } },
      });
      await issue(tzun, document, principal);
      const under = { mandate: { mandateId: document.mandateId } };
      const head = (await tzun.getStorage().getLastSequence());

      expect(failureCode(await tzun.capture(claim(1, { action: 'reject' }), under))).toBe('outside_scope');
      expect(failureCode(await tzun.capture(claim(600_001), under))).toBe('outside_scope');
      expect(failureCode(await tzun.capture(claim(1, { agent: OTHER_AGENT }), under))).toBe('agent_not_in_mandate');
      expect(failureCode(await tzun.capture(claim(1, { kind: 'agent' }), under))).toBe('agent_not_in_mandate');
      const undeterminable = { ...claim(1), aiOutput: { amountMinor: 1 } };
      expect(failureCode(await tzun.capture(undeterminable, under))).toBe('confirm_undeterminable');
      expect(failureCode(await tzun.capture(claim(1), { mandate: { mandateId: '00000000-0000-4000-8000-000000000000' } }))).toBe('mandate_not_found');
      const refusal = await tzun.capture(claim(1, { action: 'reject' }), under);
      expect(refusal.failure?.failureType).toBe('mandate_refused');
      expect(refusal.failure?.diagnosticMetadata.findings).toEqual([{ constraint: 'actions' }]);
      expect(await tzun.getStorage().getLastSequence()).toBe(head);

      expect((await tzun.capture(claim(400_000), under)).mandate?.slot).toBe(1);
      expect(failureCode(await tzun.capture(claim(250_000), under))).toBe('cap_exceeded');
      expect((await tzun.capture(claim(200_000), under)).mandate).toEqual({ mandateId: document.mandateId, slot: 2, totals: { paid: 600_000 } });
      expect(failureCode(await tzun.capture(claim(0), under))).toBe('mandate_full');
      // A full mandate stays open.
      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ state: 'open', used: 2 });
      expect(await tzun.getStorage().getLastSequence()).toBe(head + 2);
    });

    // Anchoring needs an evidence log, which the memory store does not keep.
    (backend.name === 'memory' ? it.skip : it)(
      'with anchoring configured, a mandated capture needs a finalized-block reference younger than the greatest age, and takes no slot without one',
      async () => {
        await tzun.close();
        const chain = new FakeEvmChain();
        const wallet = Wallet.createRandom();
        chain.fund(wallet.address, 10n ** 18n);
        tzun = await backend.fresh({
          logNamespace: 'test.mandates.tzun',
          anchoring: {
            publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: 'eip155:31337', privateKey: wallet.privateKey } },
            autoStart: false,
            freshnessMaxAgeMs: 600_000,
          },
          _anchorChainClient: chain,
        } as Partial<TzunConfig>);
        await enrol(tzun, principal);
        const document = mandateDocument(principal.userId);
        await issue(tzun, document, principal);
        const under = { mandate: { mandateId: document.mandateId } };
        const head = await tzun.getStorage().getLastSequence();

        // The follower has read the finalized block, and it is older than the greatest age.
        chain.mine(3);
        await tzun.anchorNow();
        const refused = await tzun.capture(claim(1), under);
        expect(refused.failure?.diagnosticMetadata).toMatchObject({ code: 'freshness_required', field: 'decider.freshness' });
        expect(await tzun.getStorage().getLastSequence()).toBe(head);
        expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ state: 'open', used: 0 });
        // Implied for agent-mandated only: an agent's capture outside a mandate is stored without a reference.
        const agent = await tzun.capture(claim(1, { kind: 'agent' }));
        expect(agent.stored).toBe(true);
        expect(agent.envelope.payload.decider?.freshness).toBeNull();

        // A finalized block younger than the greatest age: the reference is written and the slot taken.
        (chain as unknown as { time: number }).time = Math.floor(Date.now() / 1000) - 120;
        chain.mine(3);
        await tzun.anchorNow();
        const stored = await tzun.capture(claim(1), under);
        expect(stored.mandate).toMatchObject({ slot: 1 });
        expect(stored.envelope.payload.decider?.freshness).toMatch(/^eip155:31337@\d+:0x[0-9a-f]{64}$/);
      },
    );

    it('a keyed retry replays: no second slot, no second record, the same receipt', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      const under = { mandate: { mandateId: document.mandateId }, idempotencyKey: 'claim-4471' };
      const first = await tzun.capture(claim(100_000), under);
      expect(first.mandate?.slot).toBe(1);
      const retry = await tzun.capture(claim(100_000), under);
      expect(retry.replayed).toBe(true);
      expect(retry.envelope.payload.evidenceId).toBe(first.envelope.payload.evidenceId);
      expect(retry.envelope.integrity.canonicalDigest).toBe(first.envelope.integrity.canonicalDigest);
      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ used: 1 });
      expect(await tzun.getStorage().getMandateTotals!(document.mandateId)).toEqual({ paid: 100_000 });
      // The same key with another decision is a conflict, and takes no slot either.
      const other = await tzun.capture(claim(200_000), under);
      expect(other.stored).toBe(false);
      expect(other.failure?.failureType).toBe('idempotency_conflict');
      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ used: 1 });
      // The next capture under another key takes the next slot.
      expect((await tzun.capture(claim(1), { mandate: { mandateId: document.mandateId }, idempotencyKey: 'claim-4472' })).mandate?.slot).toBe(2);
    });

    describe('a keyed retry after the mandate moved on replays the first record', () => {
      /** Capture under `key`, then retry it after `between`: the retry replays, and the mandate's slots and totals are as the first left them. */
      async function retried(document: ReturnType<typeof mandateDocument>, amount: number, between: () => Promise<void>) {
        const under = { mandate: { mandateId: document.mandateId }, idempotencyKey: `claim-${randomUUID()}` };
        const first = await tzun.capture(claim(amount), under);
        expect(first.mandate?.slot).toBe(1);
        const totals = await tzun.getStorage().getMandateTotals!(document.mandateId);
        await between();
        const head = await tzun.getStorage().getLastSequence();
        const retry = await tzun.capture(claim(amount), under);
        expect(retry.failure).toBeUndefined();
        expect(retry.replayed).toBe(true);
        expect(retry.envelope.payload.evidenceId).toBe(first.envelope.payload.evidenceId);
        expect(retry.envelope.integrity.canonicalDigest).toBe(first.envelope.integrity.canonicalDigest);
        expect(await tzun.getStorage().getLastSequence()).toBe(head);
        expect((await tzun.getStorage().getMandate!(document.mandateId))?.used).toBe(1);
        expect(await tzun.getStorage().getMandateTotals!(document.mandateId)).toEqual(totals);
        // The same key with another decision is still a conflict.
        const other = await tzun.capture(claim(amount + 1), under);
        expect(other.failure?.failureType).toBe('idempotency_conflict');
        return { under, head };
      }

      it('after the capture that took the last slot; a new key is refused mandate_full and takes nothing', async () => {
        const document = mandateDocument(principal.userId, { limits: { maxRecords: 1, cumulative: null } });
        await issue(tzun, document, principal);
        const { head } = await retried(document, 100, async () => undefined);
        const fresh = await tzun.capture(claim(100), { mandate: { mandateId: document.mandateId }, idempotencyKey: 'claim-fresh' });
        expect(fresh.failure?.failureType).toBe('mandate_refused');
        expect(failureCode(fresh)).toBe('mandate_full');
        expect(await tzun.getStorage().getLastSequence()).toBe(head);
        // The refused key was not consumed: the same key under a mandate with room stores.
        const roomy = mandateDocument(principal.userId);
        await issue(tzun, roomy, principal);
        expect((await tzun.capture(claim(100), { mandate: { mandateId: roomy.mandateId }, idempotencyKey: 'claim-fresh' })).mandate?.slot).toBe(1);
      });

      it('after the capture that filled a cap; a new key is refused cap_exceeded', async () => {
        const document = mandateDocument(principal.userId, {
          limits: { maxRecords: null, cumulative: { paid: { path: '/aiOutput/amountMinor', max: 100_000 } } },
        });
        await issue(tzun, document, principal);
        await retried(document, 100_000, async () => undefined);
        expect(failureCode(await tzun.capture(claim(1), { mandate: { mandateId: document.mandateId }, idempotencyKey: 'claim-fresh' }))).toBe('cap_exceeded');
      });

      it('after the mandate was revoked; a new key is refused mandate_not_open', async () => {
        const document = mandateDocument(principal.userId);
        await issue(tzun, document, principal);
        await retried(document, 100, async () => {
          const prepared = await tzun.mandates.prepareRevocation({ mandateId: document.mandateId, reason: 'r', revoker: principal.userId });
          await tzun.mandates.revoke({ mandateId: document.mandateId, reason: 'r' }, { prepared, assertion: assert(principal, prepared.challenge) });
        });
        expect(failureCode(await tzun.capture(claim(1), { mandate: { mandateId: document.mandateId }, idempotencyKey: 'claim-fresh' }))).toBe('mandate_not_open');
        expect(failureCode(await tzun.capture(claim(1), { mandate: { mandateId: document.mandateId } }))).toBe('mandate_not_open');
      });

      it("after the mandate's window ended; a new key is refused outside_validity, and the mandate expires", async () => {
        const notAfter = new Date(Date.now() + 2_000).toISOString();
        const document = mandateDocument(principal.userId, { validity: { notBefore: new Date(Date.now() - HOUR).toISOString(), notAfter } });
        await issue(tzun, document, principal);
        await retried(document, 100, async () => {
          while (Date.now() <= Date.parse(notAfter) + 5) await sleep(50);
        });
        // The retry's plan observed the end of the window and moved the mandate to expired.
        expect(await tzun.getStorage().getMandate!(document.mandateId)).toMatchObject({ state: 'expired', used: 1 });
        expect(failureCode(await tzun.capture(claim(1), { mandate: { mandateId: document.mandateId }, idempotencyKey: 'claim-fresh' }))).toBe('mandate_not_open');

        const ended = mandateDocument(principal.userId, { validity: { notBefore: new Date(Date.now() - 3 * HOUR).toISOString(), notAfter: new Date(Date.now() - HOUR).toISOString() } });
        await issue(tzun, ended, principal);
        const head = await tzun.getStorage().getLastSequence();
        const late = await tzun.capture(claim(1), { mandate: { mandateId: ended.mandateId }, idempotencyKey: 'claim-late' });
        expect(late.failure?.failureType).toBe('mandate_refused');
        expect(failureCode(late)).toBe('outside_validity');
        expect(await tzun.getStorage().getLastSequence()).toBe(head);
        expect(await tzun.getStorage().getMandate!(ended.mandateId)).toMatchObject({ state: 'expired', used: 0 });
      });
    });

    it('a capture names its mandate by id, never by digest', async () => {
      const document = mandateDocument(principal.userId);
      const issued = await issue(tzun, document, principal);
      const r = await tzun.capture(claim(1), { mandate: { mandateId: issued.mandateDigest } });
      expect(failureCode(r)).toBe('mandate_not_found');
      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ used: 0 });
    });

    it('a capture past the window moves the mandate to expired, with its event, and is refused', async () => {
      const document = mandateDocument(principal.userId, { validity: { notBefore: new Date(Date.now() - 3 * HOUR).toISOString(), notAfter: new Date(Date.now() - HOUR).toISOString() } });
      const issued = await issue(tzun, document, principal);
      const r = await tzun.capture(claim(1), { mandate: { mandateId: document.mandateId } });
      expect(r.failure?.failureType).toBe('mandate_refused');
      expect(failureCode(r)).toBe('outside_validity');
      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ state: 'expired', used: 0 });
      const events = (await tzun.mandates.events(document.mandateId)).map((e) => e.body);
      expect(events.map((e) => e.event)).toEqual(['issued', 'expired']);
      expect(events[1]).toEqual({
        v: 'tzun-mandate-event/1',
        event: 'expired',
        mandateDigest: issued.mandateDigest,
        record: issued.issuance.envelope.integrity.canonicalDigest,
        successor: null,
        used: 0,
        totals: { paid: 0 },
      });
      expect(failureCode(await tzun.capture(claim(1), { mandate: { mandateId: document.mandateId } }))).toBe('mandate_not_open');
    });

    it('a capture before the window is refused and leaves the mandate open', async () => {
      const document = mandateDocument(principal.userId, { validity: { notBefore: new Date(Date.now() + HOUR).toISOString(), notAfter: null } });
      await issue(tzun, document, principal);
      expect(failureCode(await tzun.capture(claim(1), { mandate: { mandateId: document.mandateId } }))).toBe('outside_validity');
      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ state: 'open' });
    });

    it('a read of a mandate whose window ended moves it to expired, with its event, though no capture touched it', async () => {
      const document = mandateDocument(principal.userId, { validity: { notBefore: new Date(Date.now() - 3 * HOUR).toISOString(), notAfter: new Date(Date.now() - HOUR).toISOString() } });
      const issued = await issue(tzun, document, principal);
      expect(await tzun.getStorage().getMandate!(document.mandateId)).toMatchObject({ state: 'open' });
      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ state: 'expired', used: 0 });
      const events = await tzun.mandates.events(document.mandateId);
      expect(events.map((e) => e.body)).toEqual([
        expect.objectContaining({ event: 'issued' }),
        { v: 'tzun-mandate-event/1', event: 'expired', mandateDigest: issued.mandateDigest, record: issued.issuance.envelope.integrity.canonicalDigest, successor: null, used: 0, totals: { paid: 0 } },
      ]);

      const other = mandateDocument(principal.userId, { validity: { notBefore: new Date(Date.now() - 3 * HOUR).toISOString(), notAfter: new Date(Date.now() - HOUR).toISOString() } });
      await issue(tzun, other, principal);
      expect((await tzun.mandates.events(other.mandateId)).map((e) => e.body.event)).toEqual(['issued', 'expired']);
      expect(await tzun.getStorage().getMandate!(other.mandateId)).toMatchObject({ state: 'expired' });
    });

    it("scope.models admits a record only when every step's model is in it", async () => {
      const descriptor = (modelName: string): ModelDescriptor => ({
        descriptorVersion: 'd1',
        vendor: 'acme',
        modelName,
        modelVersion: 'v1',
        modelType: 'llm',
        integrityTier: 'vendor-asserted',
        modelDigest: null,
        parentModelDescriptorDigest: null,
        derivation: null,
        trainedBy: null,
        license: null,
        modelCardUrl: null,
        training: { trainingDataDigest: null, trainingDataRef: null, lastTrainingDate: null, evaluations: [] },
        regulatoryMarkings: [],
        externalIdentifiers: [],
      });
      const storage = tzun.getStorage();
      const allowed = (await storage.registerModelDescriptor!(descriptor('claims-model'), 'connector-auto', 'test')).digest;
      const other = (await storage.registerModelDescriptor!(descriptor('other-model'), 'connector-auto', 'test')).digest;
      const document = mandateDocument(principal.userId, {
        scope: { aiSystemIds: ['claims-triage'], actions: ['approve', 'refer'], models: [allowed], predicates: null },
      });
      await issue(tzun, document, principal);
      const under = { mandate: { mandateId: document.mandateId } };
      const withModel = (digest: string) => ({ ...claim(10), contributions: singleModel({ modelDescriptorDigest: digest } as AiBom) });

      const ok = await tzun.capture(withModel(allowed), under);
      expect(ok.failure).toBeUndefined();
      expect(ok.envelope.payload.contributions?.steps[0].aiBom?.modelDescriptorDigest).toBe(allowed);
      const outside = await tzun.capture(withModel(other), under);
      expect(failureCode(outside)).toBe('outside_scope');
      expect(outside.failure?.diagnosticMetadata.findings).toEqual([{ constraint: 'models' }]);
      // A model set with no model recorded cannot be judged.
      expect(failureCode(await tzun.capture(claim(10), under))).toBe('scope_undeterminable');
    });

    it('the signoffExpectation option beside a mandate is refused', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      const r = await tzun.capture(claim(1), { mandate: { mandateId: document.mandateId }, signoffExpectation: { policyDigest: 'a'.repeat(64) } });
      expect(failureCode(r)).toBe('expectation_with_mandate');
    });
  });

  describe('revocation', () => {
    async function revoke(mandateId: string, revoker: Person, opts: { effectiveAt?: string; signer?: Person } = {}) {
      const prepared = await tzun.mandates.prepareRevocation({
        mandateId,
        reason: 'Claims agent retired',
        revoker: revoker.userId,
        ...(opts.effectiveAt !== undefined && { effectiveAt: opts.effectiveAt }),
      });
      return tzun.mandates.revoke(
        { mandateId, reason: 'Claims agent retired' },
        { prepared, assertion: assert(opts.signer ?? revoker, prepared.challenge) },
      );
    }

    it('captures the revocation record, closes the mandate with its event, and later claims are refused', async () => {
      const document = mandateDocument(principal.userId);
      const issued = await issue(tzun, document, principal);
      await tzun.capture(claim(100_000), { mandate: { mandateId: document.mandateId } });

      const r = await revoke(document.mandateId, principal);
      const p = r.envelope.payload;
      expect(p.aiSystemId).toBe('tzun:mandate');
      expect(p.action).toBe('revoke-mandate');
      expect(p.aiOutput).toEqual({
        claimedRevocationInstant: expect.any(String),
        mandateDigest: issued.mandateDigest,
        reason: 'Claims agent retired',
        statementDigest: issued.issuance.envelope.payload.aiOutput.statementDigest,
      });
      expect(Date.parse(p.aiOutput.claimedRevocationInstant as string)).toBeLessThanOrEqual(Date.parse(p.capturedAt));
      expect(p.decider).toMatchObject({ kind: 'human', id: `acct:${principal.userId}` });
      expect(p.links?.map((l) => [l.rel, l.target.digest])).toEqual([['revokes', issued.issuance.envelope.integrity.canonicalDigest]]);
      expect(r.envelope.nonRepudiation.webauthnAssertion?.credentialKeyId).toBe(principal.credentialId);
      expect((await tzun.verify(p.evidenceId)).verified).toBe(true);

      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ state: 'revoked', used: 1 });
      const events = (await tzun.mandates.events(document.mandateId)).map((e) => e.body as MandateEventBody);
      expect(events.map((e) => e.event)).toEqual(['issued', 'revoked']);
      expect(events[1]).toMatchObject({ record: r.envelope.integrity.canonicalDigest, used: 1, totals: { paid: 100_000 }, successor: null });

      expect(failureCode(await tzun.capture(claim(1), { mandate: { mandateId: document.mandateId } }))).toBe('mandate_not_open');
      await expect(revoke(document.mandateId, principal)).rejects.toMatchObject({ code: 'mandate_not_open' });
    });

    it('any account with a verified, user-verifying assertion may revoke; the record names the revoker', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      const r = await revoke(document.mandateId, auditor);
      expect(r.envelope.payload.decider?.id).toBe(`acct:${auditor.userId}`);
      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ state: 'revoked' });
    });

    it('refuses an assertion by another account than the revoker, a future instant, and a mandate it does not hold', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      await expect(revoke(document.mandateId, auditor, { signer: principal })).rejects.toMatchObject({
        code: 'assertion_not_verified',
        details: { reason: 'credential_not_revoker' },
      });
      const prepared = await tzun.mandates.prepareRevocation({ mandateId: document.mandateId, reason: 'r', revoker: principal.userId });
      await expect(
        tzun.mandates.revoke({ mandateId: document.mandateId, reason: 'r' }, { prepared, assertion: assert(principal, prepared.challenge, { uv: false }) }),
      ).rejects.toMatchObject({ code: 'assertion_not_verified', details: { reason: 'user_not_verified' } });
      await expect(
        tzun.mandates.prepareRevocation({ mandateId: document.mandateId, reason: 'r', revoker: principal.userId, effectiveAt: new Date(Date.now() + HOUR).toISOString() }),
      ).rejects.toMatchObject({ code: 'invalid_revocation_instant' });
      await expect(
        tzun.mandates.prepareRevocation({ mandateId: '00000000-0000-4000-8000-000000000000', reason: 'r', revoker: principal.userId }),
      ).rejects.toMatchObject({ code: 'mandate_not_found' });
      await expect(
        tzun.mandates.prepareRevocation({ mandateId: document.mandateId, reason: 'r', revoker: 'jane@example.com' }),
      ).rejects.toMatchObject({ code: 'invalid_identifier', field: 'revoker' });
      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ state: 'open' });
    });

    it('refuses a prepared revocation of another mandate or reason', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      const prepared = await tzun.mandates.prepareRevocation({ mandateId: document.mandateId, reason: 'r', revoker: principal.userId });
      const assertion = assert(principal, prepared.challenge);
      await expect(tzun.mandates.revoke({ mandateId: document.mandateId, reason: 'other' }, { prepared, assertion })).rejects.toMatchObject({ code: 'invalid_prepared' });
      await expect(tzun.mandates.revoke({ mandateId: randomUUID(), reason: 'r' }, { prepared, assertion })).rejects.toMatchObject({ code: 'invalid_prepared' });
      await expect(tzun.mandates.revoke({ mandateId: document.mandateId, reason: 'r' }, { prepared: null as never, assertion })).rejects.toMatchObject({ code: 'invalid_prepared' });
      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ state: 'open' });
    });

    it("refuses a prepared revocation whose revokes link was pointed at another mandate's issuance, whatever digest it carries", async () => {
      const a = mandateDocument(principal.userId);
      const b = mandateDocument(principal.userId);
      await issue(tzun, a, principal);
      const issuedB = await issue(tzun, b, principal);
      const head = await tzun.getStorage().getLastSequence();
      const prepared = (await tzun.mandates.prepareRevocation({ mandateId: a.mandateId, reason: 'stop', revoker: principal.userId })) as PreparedMandateRevocation;
      const bEnvelope = issuedB.issuance.envelope;
      const pointAtB = (p: PreparedMandateRevocation): PreparedMandateRevocation => {
        const out = JSON.parse(JSON.stringify(p)) as PreparedMandateRevocation;
        out.links = out.links!.map((l) =>
          l.rel === 'revokes'
            ? {
                ...l,
                target: {
                  digest: bEnvelope.integrity.canonicalDigest,
                  evidenceId: bEnvelope.payload.evidenceId,
                  locator: l.target.locator === null ? null : { origin: l.target.locator.origin, seq: bEnvelope.payload.sequenceNumber },
                },
              }
            : l,
        );
        return out;
      };
      // The digest the ceremony signed, and a digest replaced with the challenge re-signed over it.
      const altered = pointAtB(prepared);
      const rebuilt = { ...pointAtB(prepared), digest: 'e'.repeat(64), challenge: webauthnChallengeForDigest('e'.repeat(64)) };
      for (const candidate of [altered, rebuilt]) {
        const refusal = await tzun.mandates
          .revoke({ mandateId: a.mandateId, reason: 'stop' }, { prepared: candidate, assertion: assert(principal, candidate.challenge) })
          .catch((e: unknown) => e);
        expect(refusal).toMatchObject({ name: 'MandateError', code: 'invalid_prepared', field: 'prepared.links' });
        expect((refusal as MandateError).failure?.failureType).toBe('validation_failure');
      }
      expect(await tzun.getStorage().getLastSequence()).toBe(head);
      expect(await tzun.mandates.get(a.mandateId)).toMatchObject({ state: 'open' });
      expect(await tzun.mandates.get(b.mandateId)).toMatchObject({ state: 'open' });
      // The prepared record as formed still revokes A.
      const r = await tzun.mandates.revoke({ mandateId: a.mandateId, reason: 'stop' }, { prepared, assertion: assert(principal, prepared.challenge) });
      expect(r.envelope.integrity.canonicalDigest).toBe(prepared.digest);
      expect(await tzun.mandates.get(a.mandateId)).toMatchObject({ state: 'revoked' });
      expect(await tzun.mandates.get(b.mandateId)).toMatchObject({ state: 'open' });
    });

    it('records an earlier claimed instant as given', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      const earlier = new Date(Date.now() - 10 * 60_000).toISOString();
      const r = await revoke(document.mandateId, principal, { effectiveAt: earlier });
      expect(r.envelope.payload.aiOutput.claimedRevocationInstant).toBe(earlier);
    });

    it('refuses a reason a record may not carry, before anything is prepared or stored', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      const head = await tzun.getStorage().getLastSequence();
      for (const reason of [undefined, '', 'x'.repeat(16_385), 'lone \ud800 surrogate']) {
        const attempt = tzun.mandates.prepareRevocation({ mandateId: document.mandateId, reason: reason as string, revoker: principal.userId });
        await expect(attempt).rejects.toMatchObject({ name: 'MandateError', code: 'invalid_reason', field: 'reason' });
      }
      const prepared = await tzun.mandates.prepareRevocation({ mandateId: document.mandateId, reason: 'r', revoker: principal.userId });
      await expect(
        tzun.mandates.revoke({ mandateId: document.mandateId, reason: 7 as unknown as string }, { prepared, assertion: assert(principal, prepared.challenge) }),
      ).rejects.toMatchObject({ code: 'invalid_reason' });
      expect(await tzun.getStorage().getLastSequence()).toBe(head);
      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ state: 'open' });
    });

    it('refuses an instant other than the prepared one as invalid_prepared, and a prepared record the chain moved past as prepared_record_stale', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      const prepared = (await tzun.mandates.prepareRevocation({ mandateId: document.mandateId, reason: 'r', revoker: principal.userId })) as PreparedMandateRevocation;
      const assertion = assert(principal, prepared.challenge);
      const earlier = new Date(Date.parse(prepared.capturedAt) - HOUR).toISOString();
      const refusedEarly = await tzun.mandates.revoke({ mandateId: document.mandateId, reason: 'r', effectiveAt: earlier }, { prepared, assertion }).catch((e: unknown) => e);
      // Refused before any capture: no failure record.
      expect(refusedEarly).toMatchObject({ name: 'MandateError', code: 'invalid_prepared', field: 'prepared' });
      expect((refusedEarly as MandateError).failure).toBeUndefined();
      // The prepared record without what prepareRevocation() added: the capture finds the request is not the one prepared.
      const { revocation: _revocation, ...bare } = prepared;
      const unprepared = await tzun.mandates
        .revoke({ mandateId: document.mandateId, reason: 'r', effectiveAt: earlier }, { prepared: bare, assertion })
        .catch((e: unknown) => e);
      expect(unprepared).toMatchObject({ code: 'invalid_prepared', failureType: 'validation_failure' });
      expect((unprepared as MandateError).failure?.failureType).toBe('chain_conflict');
      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ state: 'open' });

      // A record appended after the revocation was prepared moves the chain head the prepared record was built on.
      await tzun.capture(claim(1, { kind: 'agent' }));
      const stale = tzun.mandates.revoke({ mandateId: document.mandateId, reason: 'r' }, { prepared, assertion });
      await expect(stale).rejects.toMatchObject({ code: 'prepared_record_stale' });
      expect(await tzun.mandates.get(document.mandateId)).toMatchObject({ state: 'open' });
    });

    it('the prepared revocation carries its instant; revoke reuses it', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      const prepared = (await tzun.mandates.prepareRevocation({ mandateId: document.mandateId, reason: 'r', revoker: principal.userId })) as PreparedMandateRevocation;
      expect(prepared.revocation).toMatchObject({ mandateId: document.mandateId, reason: 'r', revoker: principal.userId });
      expect(prepared.challenge).toBe(webauthnChallengeForDigest(prepared.digest));
      const r = await tzun.mandates.revoke({ mandateId: document.mandateId, reason: 'r' }, { prepared, assertion: assert(principal, prepared.challenge) });
      expect(r.envelope.integrity.canonicalDigest).toBe(prepared.digest);
      expect(r.envelope.payload.aiOutput.claimedRevocationInstant).toBe(prepared.revocation.effectiveAt);
    });
  });

  describe('succession', () => {
    it('a successor supersedes its predecessor in the issuing transaction, and starts with nothing used', async () => {
      const first = mandateDocument(principal.userId);
      const issuedFirst = await issue(tzun, first, principal);
      await tzun.capture(claim(400_000), { mandate: { mandateId: first.mandateId } });

      const second = mandateDocument(principal.userId, { predecessor: issuedFirst.mandateDigest });
      const issuedSecond = await issue(tzun, second, principal);
      const record = issuedSecond.issuance.envelope;
      expect(record.payload.links?.find((l) => l.rel === 'supersedes')?.target).toMatchObject({
        digest: issuedFirst.issuance.envelope.integrity.canonicalDigest,
        evidenceId: issuedFirst.issuance.envelope.payload.evidenceId,
      });

      expect(await tzun.mandates.get(first.mandateId)).toMatchObject({ state: 'superseded', used: 1 });
      const events = (await tzun.mandates.events(first.mandateId)).map((e) => e.body);
      expect(events[1]).toEqual({
        v: 'tzun-mandate-event/1',
        event: 'superseded',
        mandateDigest: issuedFirst.mandateDigest,
        record: record.integrity.canonicalDigest,
        successor: issuedSecond.mandateDigest,
        used: 1,
        totals: { paid: 400_000 },
      });
      expect(await tzun.mandates.get(second.mandateId)).toMatchObject({ state: 'open', used: 0 });
      expect(failureCode(await tzun.capture(claim(1), { mandate: { mandateId: first.mandateId } }))).toBe('mandate_not_open');
      expect((await tzun.capture(claim(700_000 - 300_000), { mandate: { mandateId: second.mandateId } })).mandate).toMatchObject({ slot: 1, totals: { paid: 400_000 } });
    });

    it('refuses a successor naming another principal, and a predecessor that is not open', async () => {
      const first = mandateDocument(principal.userId);
      const issuedFirst = await issue(tzun, first, principal);
      const other = mandateDocument(auditor.userId, { predecessor: issuedFirst.mandateDigest });
      await expect(tzun.mandates.prepare(other)).rejects.toMatchObject({ code: 'predecessor_principal_mismatch' });
      const prepared = await tzun.mandates.prepare(mandateDocument(auditor.userId));
      await expect(
        tzun.mandates.issue({ document: other, statement: { ...prepared.statement, mandateDigest: mandateDigest(other)! }, assertion: assert(auditor, prepared.challenge) }),
      ).rejects.toMatchObject({ code: 'predecessor_principal_mismatch' });

      await issue(tzun, mandateDocument(principal.userId, { predecessor: issuedFirst.mandateDigest }), principal);
      await expect(tzun.mandates.prepare(mandateDocument(principal.userId, { predecessor: issuedFirst.mandateDigest }))).rejects.toMatchObject({
        code: 'mandate_not_open',
      });
      await expect(tzun.mandates.prepare(mandateDocument(principal.userId, { predecessor: 'f'.repeat(64) }))).rejects.toMatchObject({
        code: 'mandate_not_found',
      });
    });
  });

  describe('confirmation', () => {
    it('fills the confirmation once, names who confirmed, and the expectation then reads correct', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      const r = await tzun.capture(claim(1, { fraudFlag: true }), { mandate: { mandateId: document.mandateId } });
      const id = r.envelope.payload.evidenceId;
      const challenge = mandateConfirmationChallenge(r.envelope.integrity.canonicalDigest);

      await expect(tzun.mandates.confirm(id, assert(auditor, 'y'.repeat(43)))).rejects.toMatchObject({ code: 'assertion_not_verified' });
      await tzun.mandates.confirm(id, assert(auditor, challenge));
      const stored = (await tzun.getStorage().retrieve(id))!;
      expect(stored.nonRepudiation.confirmation?.credentialKeyId).toBe(auditor.credentialId);
      const last = stored.custodyChain[stored.custodyChain.length - 1];
      expect(last).toMatchObject({ action: 'mandate_confirmed', actor: `acct:${auditor.userId}`, metadata: { mandateId: document.mandateId, slot: 1 } });
      const verified = await tzun.verify(id);
      expect(verified.verified).toBe(true);
      expect(verified.signoffExpectationValid).toBe(true);

      await expect(tzun.mandates.confirm(id, assert(principal, challenge))).rejects.toMatchObject({ code: 'already_confirmed' });
      expect((await tzun.getStorage().retrieve(id))!.nonRepudiation.confirmation?.credentialKeyId).toBe(auditor.credentialId);
    });

    it('two confirmations of one record at once: one is filled and recorded, the other is refused already_confirmed', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      const owed = async (): Promise<{ id: string; challenge: string }> => {
        const r = await tzun.capture(claim(1, { fraudFlag: true }), { mandate: { mandateId: document.mandateId } });
        return { id: r.envelope.payload.evidenceId, challenge: mandateConfirmationChallenge(r.envelope.integrity.canonicalDigest) };
      };
      const once = await owed();
      const same = assert(auditor, once.challenge);
      const twice = await owed();
      for (const [id, a, b] of [
        [once.id, same, same],
        [twice.id, assert(principal, twice.challenge), assert(auditor, twice.challenge)],
      ] as const) {
        const outcomes = await Promise.allSettled([tzun.mandates.confirm(id, a), tzun.mandates.confirm(id, b)]);
        // Either call may win: on Postgres the two race for the record's row
        // lock, so the one called first is not always the one filled.
        expect(outcomes.map((o) => o.status).sort()).toEqual(['fulfilled', 'rejected']);
        const won = outcomes[0].status === 'fulfilled' ? 0 : 1;
        const winner = won === 0 ? a : b;
        expect((outcomes[1 - won] as PromiseRejectedResult).reason).toMatchObject({ name: 'MandateError', code: 'already_confirmed' });
        const stored = (await tzun.getStorage().retrieve(id))!;
        expect(stored.nonRepudiation.confirmation?.credentialKeyId).toBe(winner.credentialKeyId);
        const confirmedBy = winner.credentialKeyId === auditor.credentialId ? auditor : principal;
        expect(stored.custodyChain.filter((e) => e.action === 'mandate_confirmed').map((e) => e.actor)).toEqual([`acct:${confirmedBy.userId}`]);
      }
    });

    // Two instances on one store: SQLite and Postgres (a memory store is not shared).
    (backend.name === 'memory' ? it.skip : it)(
      'two instances confirming one record at once: exactly one fills it and appends the custody entry',
      async () => {
        const document = mandateDocument(principal.userId);
        await issue(tzun, document, principal);
        const other = await backend.again();
        try {
          const owed = async (): Promise<{ id: string; challenge: string }> => {
            const r = await tzun.capture(claim(1, { fraudFlag: true }), { mandate: { mandateId: document.mandateId } });
            return { id: r.envelope.payload.evidenceId, challenge: mandateConfirmationChallenge(r.envelope.integrity.canonicalDigest) };
          };
          const once = await owed();
          const same = assert(auditor, once.challenge);
          const twice = await owed();
          for (const [id, a, b] of [
            [once.id, same, same],
            [twice.id, assert(principal, twice.challenge), assert(auditor, twice.challenge)],
          ] as const) {
            const outcomes = await Promise.allSettled([tzun.mandates.confirm(id, a), other.mandates.confirm(id, b)]);
            expect(outcomes.filter((o) => o.status === 'fulfilled')).toHaveLength(1);
            const lost = outcomes.find((o): o is PromiseRejectedResult => o.status === 'rejected')!;
            expect(lost.reason).toMatchObject({ name: 'MandateError', code: 'already_confirmed' });
            const stored = (await tzun.getStorage().retrieve(id))!;
            const confirmed = stored.custodyChain.filter((e) => e.action === 'mandate_confirmed');
            expect(confirmed).toHaveLength(1);
            const winner = outcomes[0].status === 'fulfilled' ? a : b;
            expect(stored.nonRepudiation.confirmation?.credentialKeyId).toBe(winner.credentialKeyId);
            expect(confirmed[0].actor).toBe(`acct:${winner.credentialKeyId === principal.credentialId ? principal.userId : auditor.userId}`);
            expect((await tzun.verify(id)).verified).toBe(true);
          }
        } finally {
          await other.close();
        }
      },
    );

    it('confirmRecord fills once, with its custody entry, and appends nothing when the record is already confirmed', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      const r = await tzun.capture(claim(1, { fraudFlag: true }), { mandate: { mandateId: document.mandateId } });
      const id = r.envelope.payload.evidenceId;
      const challenge = mandateConfirmationChallenge(r.envelope.integrity.canonicalDigest);
      const storage = tzun.getStorage();
      const entry = (actor: string) => ({ timestamp: new Date().toISOString(), actor, action: 'mandate_confirmed' as const, systemId: 'claims-triage', metadata: { slot: 1 } });
      expect(await storage.confirmRecord!(id, assert(auditor, challenge), entry(`acct:${auditor.userId}`))).toEqual({ filled: true });
      expect(await storage.confirmRecord!(id, assert(principal, challenge), entry(`acct:${principal.userId}`))).toEqual({ filled: false });
      const stored = (await storage.retrieve(id))!;
      expect(stored.nonRepudiation.confirmation?.credentialKeyId).toBe(auditor.credentialId);
      expect(stored.custodyChain.filter((e) => e.action === 'mandate_confirmed').map((e) => e.actor)).toEqual([`acct:${auditor.userId}`]);
      expect((await tzun.verify(id)).verified).toBe(true);
      await expect(storage.confirmRecord!('00000000-0000-4000-8000-000000000000', assert(auditor, challenge), entry('acct:x'))).rejects.toThrow(/not found/);
    });

    it('refuses a record that owes no confirmation, and one it does not hold', async () => {
      const document = mandateDocument(principal.userId);
      await issue(tzun, document, principal);
      const r = await tzun.capture(claim(1), { mandate: { mandateId: document.mandateId } });
      const challenge = mandateConfirmationChallenge(r.envelope.integrity.canonicalDigest);
      await expect(tzun.mandates.confirm(r.envelope.payload.evidenceId, assert(auditor, challenge))).rejects.toMatchObject({ code: 'confirmation_not_owed' });
      const plain = await tzun.capture(claim(1, { kind: 'agent' }));
      await expect(tzun.mandates.confirm(plain.envelope.payload.evidenceId, assert(auditor, challenge))).rejects.toMatchObject({ code: 'confirmation_not_owed' });
      await expect(tzun.mandates.confirm('00000000-0000-4000-8000-000000000000', assert(auditor, challenge))).rejects.toMatchObject({ code: 'record_not_found' });
    });
  });
});

describe('a store without the mandate tables', () => {
  it('refuses capture under a mandate, and every mandate call, with mandate_not_supported_by_store', async () => {
    const { mandatesExtension } = await import('../../../src/sdk/mandates');
    const { decidersExtension } = await import('../../../src/storage/ddl/deciders');
    const tzun = await Tzun.init({ mode: 'dev', _sdkExtensions: [mandatesExtension], _storageExtensions: [decidersExtension] });
    try {
      const r = await tzun.capture(claim(1), { mandate: { mandateId: '00000000-0000-4000-8000-000000000000' } });
      expect(failureCode(r)).toBe('mandate_not_supported_by_store');
      await expect(tzun.mandates.prepare(mandateDocument('user-2c9d'))).rejects.toMatchObject({ code: 'mandate_not_supported_by_store' });
      await expect(tzun.mandates.get('x')).rejects.toMatchObject({ code: 'mandate_not_supported_by_store' });
    } finally {
      await tzun.close();
    }
  });
});

describe('MandateError of a failed system record', () => {
  const at = '2026-10-01T00:00:00.000Z';
  it('never takes a message as its code', () => {
    const e = mandateErrorOfFailure({ failureType: 'serialization_failure', diagnosticMetadata: { reason: "mandate m's slots or totals moved since they were read" }, capturedAt: at }, 'the revocation record');
    expect(e).toMatchObject({ code: 'serialization_failure', field: 'record', message: 'the revocation record could not be stored (serialization_failure)' });
  });
  it("names the swap the record's own write lost", () => {
    const failure = { failureType: 'serialization_failure', diagnosticMetadata: { reason: 'moved' }, capturedAt: at };
    expect(mandateErrorOfFailure(failure, 'the revocation record', 'mandate_state_conflict')).toMatchObject({ code: 'mandate_state_conflict' });
  });
  it('tells a prepared record of another request from one the chain moved past', () => {
    const head = { sequence: 4, digest: 'a'.repeat(64) };
    const refused = (actualHead: unknown) => ({
      failureType: 'chain_conflict',
      diagnosticMetadata: { code: 'chain_conflict', retryRefused: 'caller_attestation_is_digest_bound', expectedHead: head, actualHead },
      capturedAt: at,
    });
    expect(mandateErrorOfFailure(refused({ ...head }), 'the revocation record').code).toBe('invalid_prepared');
    expect(mandateErrorOfFailure(refused({ sequence: 5, digest: 'b'.repeat(64) }), 'the revocation record').code).toBe('prepared_record_stale');
    expect(mandateErrorOfFailure({ ...refused({ ...head }), diagnosticMetadata: { code: 'chain_conflict' } }, 'the record').code).toBe('chain_conflict');
  });
  it("keeps a refusal's code and message", () => {
    const failure = { failureType: 'mandate_refused', diagnosticMetadata: { field: 'mandateId', reason: 'mandate_not_open', code: 'mandate_not_open', message: 'the mandate is no longer open' }, capturedAt: at };
    expect(mandateErrorOfFailure(failure, 'the revocation record')).toMatchObject({
      code: 'mandate_not_open',
      field: 'mandateId',
      failureType: 'mandate_refused',
      message: 'the revocation record: the mandate is no longer open',
    });
  });
});
