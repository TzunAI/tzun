import { modelInput } from './helpers/step-model';
import type { EnvelopeInput } from '@tzun/engine';
import { assembleEnvelope } from '@tzun/engine';
import { verifyEnvelope } from '@tzun/engine';
import { CaptureInput, EvidenceEnvelope } from '@tzun/engine';
import { Tzun } from '../../src/sdk/index';
import { MemoryStorageAdapter } from '../../src/storage/memory';

describe('verifyEnvelope', () => {
  const input: EnvelopeInput = {
    aiSystemId: 'openai-gpt4',
    aiOutput: { recommendation: 'approve', confidence: 0.94 },
    action: 'approved',
    reason: 'All criteria met',
    decider: { kind: 'human' as const, id: 'acct:jane-acme.com', agent: null, credential: null, freshness: null },
  };

  it('verifies an unmodified envelope as valid', () => {
    const envelope = assembleEnvelope(input);
    const result = verifyEnvelope(envelope);
    expect(result.verified).toBe(true);
    expect(result.storedDigest).toBe(result.recomputedDigest);
    expect(result.schemaValid).toBe(true);
  });

  it('detects tampering with humanReason', () => {
    const envelope = assembleEnvelope(input);
    envelope.payload.reason = 'TAMPERED';
    const result = verifyEnvelope(envelope);
    expect(result.verified).toBe(false);
    expect(result.storedDigest).not.toBe(result.recomputedDigest);
  });

  it('detects tampering with aiOutput', () => {
    const envelope = assembleEnvelope(input);
    envelope.payload.aiOutput = { recommendation: 'deny' };
    const result = verifyEnvelope(envelope);
    expect(result.verified).toBe(false);
  });

  it('detects tampering with evidenceId', () => {
    const envelope = assembleEnvelope(input);
    envelope.payload.evidenceId = 'tampered-id';
    const result = verifyEnvelope(envelope);
    expect(result.verified).toBe(false);
  });

  it('detects tampering with capturedAt', () => {
    const envelope = assembleEnvelope(input);
    envelope.payload.capturedAt = '2099-01-01T00:00:00Z';
    const result = verifyEnvelope(envelope);
    expect(result.verified).toBe(false);
  });

  it('returns correct schema version in result', () => {
    const envelope = assembleEnvelope(input);
    const result = verifyEnvelope(envelope);
    expect(result.schemaVersion).toBe('v1.0');
  });

  it('returns null for signature/timestamp/anchor validation (deferred)', () => {
    const envelope = assembleEnvelope(input);
    const result = verifyEnvelope(envelope);
    expect(result.signatureValid).toBeNull();
    expect(result.timestampValid).toBeNull();
    expect(result.anchorValid).toBeNull();
    expect(result).not.toHaveProperty('blockchainAnchorValid');
  });

  it('validates chain link when present', () => {
    const e1 = assembleEnvelope(input);
    const e2 = assembleEnvelope({ ...input, reason: 'Second decision' }, { previousDigest: e1.integrity.canonicalDigest });
    const result = verifyEnvelope(e2, e1.integrity.canonicalDigest);
    expect(result.verified).toBe(true);
    expect(result.chainLinkValid).toBe(true);
  });

  it('detects invalid chain link', () => {
    const e1 = assembleEnvelope(input);
    const e2 = assembleEnvelope({ ...input, reason: 'Second decision' }, { previousDigest: e1.integrity.canonicalDigest });
    // Provide wrong previous digest for verification
    const result = verifyEnvelope(e2, 'wrong-previous-digest');
    expect(result.chainLinkValid).toBe(false);
  });

  it('returns chainLinkValid as null when no chain link exists', () => {
    const envelope = assembleEnvelope(input);
    const result = verifyEnvelope(envelope);
    expect(result.chainLinkValid).toBeNull();
  });

  it('rejects a nulled chainLink when a predecessor IS supplied', () => {
    const e1 = assembleEnvelope(input);
    const e2 = assembleEnvelope({ ...input, reason: 'Second decision' }, { previousDigest: e1.integrity.canonicalDigest });

    // Sanity: the honest record verifies.
    const honest = verifyEnvelope(e2, e1.integrity.canonicalDigest);
    expect(honest.verified).toBe(true);
    expect(honest.chainLinkValid).toBe(true);

    // Attacker detaches the record from its chain by nulling the link.
    // Supplying previousDigest is proof a predecessor exists, so a null
    // chainLink is a contradiction — not a genesis marker.
    e2.integrity.chainLink = null;
    const stripped = verifyEnvelope(e2, e1.integrity.canonicalDigest);

    // A null link beside a supplied predecessor fails the link and the record;
    // it must not score chainLinkValid:null and verify as a genesis record.
    expect(stripped.chainLinkValid).toBe(false);
    expect(stripped.verified).toBe(false);
  });

  it('rejects a nulled chainLink on a seq>1 record even when NO predecessor is supplied', () => {
    // The case above supplies a previousDigest. The attacker-reachable case is
    // the opposite one: null the link AND make the predecessor unresolvable, so
    // the SDK hands the engine `undefined`, and a check that looked only at the
    // link would send the record down the genesis branch.
    //
    // sequenceNumber is in v1.0's hashedFieldSet, so `sequenceNumber: 2` is
    // covered by canonicalDigest and cannot be forged down to 1 — it is the
    // signal that proves this record is not genesis.
    const e1 = assembleEnvelope(input, { sequenceNumber: 1 });
    const e2 = assembleEnvelope({ ...input, reason: 'Second decision' }, { previousDigest: e1.integrity.canonicalDigest, sequenceNumber: 2 });
    expect(e2.payload.sequenceNumber).toBe(2);

    // Sanity: honest record with its predecessor verifies.
    expect(verifyEnvelope(e2, e1.integrity.canonicalDigest).verified).toBe(true);

    e2.integrity.chainLink = null;
    const detached = verifyEnvelope(e2);

    expect(detached.chainLinkValid).toBe(false);
    expect(detached.verified).toBe(false);
    // The digest itself is untouched — only the link check may fail it.
    expect(detached.storedDigest).toBe(detached.recomputedDigest);
  });

  it('refuses a record whose predecessor is gone, even with the link intact', () => {
    // The half the spec above does not cover. The attacker there
    // NULLS the chainLink; here they leave it alone and delete the predecessor
    // instead — repoint chain_id, drop the row, or hand the verifier a store
    // that cannot resolve it. Either way `previousDigest` arrives undefined.
    //
    // If that scored `null` the record would present as a clean standalone
    // record and `verified` would stay true, which is deletion of evidence with
    // no detection. It must be an explicit false: a record carrying a link is
    // asserting a predecessor, and an assertion we cannot check is not one we
    // may report as satisfied.
    const e1 = assembleEnvelope(input, { sequenceNumber: 1 });
    const e2 = assembleEnvelope({ ...input, reason: 'Second decision' }, { previousDigest: e1.integrity.canonicalDigest, sequenceNumber: 2 });

    // Sanity: with its predecessor present it verifies, so the assertion below
    // is about the missing predecessor and nothing else.
    expect(verifyEnvelope(e2, e1.integrity.canonicalDigest).verified).toBe(true);
    expect(e2.integrity.chainLink).not.toBeNull();

    const orphaned = verifyEnvelope(e2);   // predecessor unresolvable

    expect(orphaned.chainLinkValid).toBe(false);
    expect(orphaned.chainLinkValid).not.toBeNull();
    expect(orphaned.verified).toBe(false);
    // The record's own bytes are untouched — only the link check fails it.
    expect(orphaned.storedDigest).toBe(orphaned.recomputedDigest);
  });

  it('treats an empty-string previousDigest as supplied, not as absent', () => {
    // '' is falsy, so a truthiness test such as `else if (previousDigest)`
    // would read a supplied-but-empty predecessor as "no predecessor" and fall
    // back to the genesis branch.
    const e1 = assembleEnvelope(input, { sequenceNumber: 1 });
    const e2 = assembleEnvelope({ ...input, reason: 'Second decision' }, { previousDigest: e1.integrity.canonicalDigest, sequenceNumber: 2 });
    e2.integrity.chainLink = null;

    expect(verifyEnvelope(e2, '').chainLinkValid).toBe(false);
    expect(verifyEnvelope(e2, '').verified).toBe(false);
  });

  it('genesis (seq 1) with a null chainLink and no predecessor still scores null', () => {
    // Guard against the link checks over-firing: a genuine genesis record must keep
    // chainLinkValid === null and verify clean.
    const genesis = assembleEnvelope(input, { sequenceNumber: 1 });
    const result = verifyEnvelope(genesis);
    expect(result.chainLinkValid).toBeNull();
    expect(result.verified).toBe(true);
  });

  it('end-to-end: nulling a link and deleting the predecessor fails verification', async () => {
    // The full attack, through the real Tzun.verify() path:
    // the store-write attacker nulls record 2's chainLink and removes record 1,
    // so resolvePredecessorDigest() returns undefined.
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;

    const c1 = await tzun.capture({ ...input, contributions: modelInput(null) });
    const c2 = await tzun.capture({ ...input, reason: 'Second decision', contributions: modelInput(null) });
    expect(c1.stored).toBe(true);
    expect(c2.stored).toBe(true);
    const id1 = c1.envelope!.payload.evidenceId;
    const id2 = c2.envelope!.payload.evidenceId;
    expect(c2.envelope!.payload.sequenceNumber).toBe(2);

    // Sanity: the honest store verifies.
    expect((await tzun.verify(id2)).verified).toBe(true);

    // Store-write tamper: detach record 2 and remove its predecessor.
    const rawEnvelopes = (
      storage as unknown as { envelopes: Map<string, EvidenceEnvelope> }
    ).envelopes;
    rawEnvelopes.get(id2)!.integrity.chainLink = null;
    rawEnvelopes.delete(id1);

    const result = await tzun.verify(id2);

    // Not verified:true / chainLinkValid:null, which would present a detached
    // record as a clean standalone genesis record.
    expect(result.chainLinkValid).toBe(false);
    expect(result.verified).toBe(false);
  });

  it('fails verification for unknown schema version', () => {
    const envelope = assembleEnvelope(input);
    envelope.payload.schemaVersion = 'v99.0';
    const result = verifyEnvelope(envelope);
    expect(result.verified).toBe(false);
    expect(result.schemaValid).toBe(false);
  });

  it('includes verifiedAt timestamp', () => {
    const envelope = assembleEnvelope(input);
    const result = verifyEnvelope(envelope);
    expect(result.verifiedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});
