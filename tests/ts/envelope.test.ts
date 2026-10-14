import { assembleEnvelope } from '@tzun/engine';
import { EnvelopeInput, AttestationArtifacts, webauthnChallengeForDigest } from '@tzun/engine';
import type { AnchorArtifact } from '@tzun/engine';
import { anchoredRecord } from './helpers/anchor-fixtures';

describe('assembleEnvelope', () => {
  const input: EnvelopeInput = {
    aiSystemId: 'openai-gpt4',
    aiOutput: { recommendation: 'approve', confidence: 0.94 },
    action: 'approved',
    reason: 'All criteria met',
    decider: { kind: 'human' as const, id: 'acct:jane-acme.com', agent: null, credential: null, freshness: null },
  };

  it('assembles envelope with correct structure', () => {
    const envelope = assembleEnvelope(input);
    expect(envelope.envelopeVersion).toBe('e1');
    expect(envelope.payload.evidenceId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
    );
    expect(envelope.payload.schemaVersion).toBe('v1.0');
    expect(envelope.payload.aiSystemId).toBe('openai-gpt4');
    expect(envelope.payload.aiOutput).toEqual({ recommendation: 'approve', confidence: 0.94 });
    expect(envelope.payload.action).toBe('approved');
    expect(envelope.payload.reason).toBe('All criteria met');
    expect(envelope.payload.capturedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(envelope.payload.sequenceNumber).toBe(1); // default
  });

  it('computes digest from canonical serialization', () => {
    const envelope = assembleEnvelope(input);
    expect(envelope.integrity.canonicalDigest).toMatch(/^[a-f0-9]{64}$/);
  });

  it('produces different digests for different inputs', () => {
    const e1 = assembleEnvelope(input);
    const e2 = assembleEnvelope({ ...input, reason: 'Different reason' });
    expect(e1.integrity.canonicalDigest).not.toBe(e2.integrity.canonicalDigest);
  });

  it('sets chain link to null (no chain context provided)', () => {
    const envelope = assembleEnvelope(input);
    expect(envelope.integrity.chainLink).toBeNull();
  });

  it('includes chain link when previous digest is provided', () => {
    const envelope = assembleEnvelope(input, { previousDigest: 'previous-digest-hex' });
    expect(envelope.integrity.chainLink).toMatch(/^[a-f0-9]{64}$/);
  });

  it('creates initial custody entry with decision_captured action', () => {
    const envelope = assembleEnvelope(input);
    expect(envelope.custodyChain).toHaveLength(1);
    expect(envelope.custodyChain[0].action).toBe('decision_captured');
    expect(envelope.custodyChain[0].actor).toBe('acct:jane-acme.com');
    expect(envelope.custodyChain[0].systemId).toBe('openai-gpt4');
  });

  it('defaults aiSystemId to "default" when not provided', () => {
    const noSystem: EnvelopeInput = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { r: 'approve' },
      action: 'approved',
      reason: 'ok',
    };
    const envelope = assembleEnvelope(noSystem);
    expect(envelope.payload.aiSystemId).toBe('default');
  });

  it("the custody entry's actor is the decider's identifier", () => {
    const other: EnvelopeInput = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { r: 'approve' },
      action: 'approved',
      reason: 'ok',
    };
    const envelope = assembleEnvelope(other);
    expect(envelope.custodyChain[0].actor).toBe('acct:u-test');
  });

  it('sets attestation status to none when no artifacts provided', () => {
    const envelope = assembleEnvelope(input);
    expect(envelope.attestationStatus).toBe('none');
  });

  // A `webauthnAssertion` that carries no clientDataJSON — the shape these
  // fixtures have always used — makes no statement about what was signed, so
  // it cannot be a signature over this record. See the inversions below.
  const unboundAssertion: NonNullable<AttestationArtifacts['webauthnAssertion']> = {
    signature: 'sig-hex',
    credentialKeyId: 'key-123',
    algorithm: 'Ed25519',
  };

  /** A ceremony that really did sign `digest`, as a 0.3.16 capture produces. */
  function boundAssertion(
    digest: string,
  ): NonNullable<AttestationArtifacts['webauthnAssertion']> {
    return {
      signature: 'sig-hex',
      credentialKeyId: 'key-123',
      algorithm: 'Ed25519',
      authenticatorData: Buffer.alloc(37, 1).toString('base64'),
      clientDataJSON: Buffer.from(
        JSON.stringify({
          type: 'webauthn.get',
          challenge: webauthnChallengeForDigest(digest),
          origin: 'https://app.example',
        }),
      ).toString('base64'),
    };
  }

  // ── Anchor fixture ────────────────────────────────────────────────────────
  //
  // A tzun-anchor/1 artifact (`nonRepudiation.anchor`, §8.1) built with the
  // engine's Merkle functions and the SDK's checkpoint formatter: both paths
  // are genuine RFC 6962 audit paths and both bodies parse. The assembler
  // counts an anchor by presence alone, so a junk artifact would pass these
  // tests too; a real one keeps what the assembler is handed checkable.
  function vectorAnchor(): AnchorArtifact {
    return anchoredRecord().anchor;
  }

  it('accepts attestation artifacts and sets status', () => {
    // This fixture's assertion is a bare
    // `{signature, credentialKeyId, algorithm}` with no clientDataJSON, so
    // nothing in it says what was signed. Its presence alone must not make
    // the record 'complete' — fully attested, reviewer named — or a login
    // assertion, or any string in `signature`, would buy the strongest
    // status a record can carry.
    const artifacts: AttestationArtifacts = {
      webauthnAssertion: unboundAssertion,
      rfc3161Token: 'token-data',
      anchor: vectorAnchor(),
    };
    const envelope = assembleEnvelope(input, { attestation: artifacts });
    expect(envelope.attestationStatus).toBe('partial');
    // The artifact is still stored verbatim — it is a real thing that
    // happened, and dropping it would destroy evidence. It just is not
    // counted as a signature over this record.
    expect(envelope.nonRepudiation.webauthnAssertion).toBeDefined();
    expect(envelope.nonRepudiation.rfc3161Token).toBeDefined();
    expect(envelope.nonRepudiation.anchor).toBeDefined();
  });

  it('reaches complete only when the assertion is bound to this record', () => {
    // The over-correction guard: a genuinely bound ceremony must still count,
    // or the whole mechanism is dead weight. Two-pass, because the challenge
    // is a function of the digest the assembler is about to compute.
    const probe = assembleEnvelope(input, { sequenceNumber: 1, signoffExpectation: null, capturedAt: '2026-09-12T00:00:00.000Z', evidenceId: 'a1b2c3d4-0000-4000-8000-000000000000' });
    const artifacts: AttestationArtifacts = {
      webauthnAssertion: boundAssertion(probe.integrity.canonicalDigest),
      rfc3161Token: 'token-data',
      anchor: vectorAnchor(),
    };
    const envelope = assembleEnvelope(input, { attestation: artifacts, sequenceNumber: 1, signoffExpectation: null, capturedAt: '2026-09-12T00:00:00.000Z', evidenceId: 'a1b2c3d4-0000-4000-8000-000000000000' });
    expect(envelope.integrity.canonicalDigest).toBe(probe.integrity.canonicalDigest);
    expect(envelope.attestationStatus).toBe('complete');
  });

  it('sets partial attestation status when only some artifacts present', () => {
    // An unbound assertion on its own is not 'partial' — "this record is
    // attested" — because nothing about it attests this record.
    const partial: AttestationArtifacts = {
      webauthnAssertion: unboundAssertion,
    };
    const envelope = assembleEnvelope(input, { attestation: partial });
    expect(envelope.attestationStatus).toBe('none');

    // A bound one, alone, is the real 'partial'.
    const probe = assembleEnvelope(input, { sequenceNumber: 1, signoffExpectation: null, capturedAt: '2026-09-12T00:00:00.000Z', evidenceId: 'b1b2c3d4-0000-4000-8000-000000000000' });
    const bound = assembleEnvelope(input, { attestation: { webauthnAssertion: boundAssertion(probe.integrity.canonicalDigest) }, sequenceNumber: 1, signoffExpectation: null, capturedAt: '2026-09-12T00:00:00.000Z', evidenceId: 'b1b2c3d4-0000-4000-8000-000000000000' });
    expect(bound.attestationStatus).toBe('partial');
  });

  it('refuses a schema version string where the options object goes', () => {
    expect(() => assembleEnvelope(input, 'v99.0' as never)).toThrow(/options object/);
  });

  it('writes the one registered schema version', () => {
    expect(assembleEnvelope(input).payload.schemaVersion).toBe('v1.0');
  });

  it('custody chain action is a valid CustodyAction value', () => {
    const envelope = assembleEnvelope(input);
    const validActions = [
      'decision_captured', 'verified', 'exported', 'relinked',
      'chain_forked', 'attested', 'reviewed',
    ];
    for (const entry of envelope.custodyChain) {
      expect(validActions).toContain(entry.action);
    }
  });

  it('defaults sequenceNumber to 1 when not provided', () => {
    const envelope = assembleEnvelope(input);
    expect(envelope.payload.sequenceNumber).toBe(1);
  });

  it('uses custom sequenceNumber when provided', () => {
    const envelope = assembleEnvelope(input, { sequenceNumber: 42 });
    expect(envelope.payload.sequenceNumber).toBe(42);
  });

  it('different sequenceNumbers produce different digests', () => {
    const e1 = assembleEnvelope(input, { sequenceNumber: 1 });
    const e2 = assembleEnvelope(input, { sequenceNumber: 2 });
    // Same input but different sequence numbers must produce different digests
    // (evidenceId also differs due to randomUUID, but sequenceNumber is in the hashed set)
    expect(e1.payload.sequenceNumber).toBe(1);
    expect(e2.payload.sequenceNumber).toBe(2);
    expect(e1.integrity.canonicalDigest).not.toBe(e2.integrity.canonicalDigest);
  });

  it('carries every tzun-anchor/1 member through to nonRepudiation, and no other', () => {
    // Assembly is the last hop before storage, and a verifier holding a stored
    // record needs every member of §8.1: `leafIndex` places the record in its
    // evidence log, the side of each audit step is derived from the index and
    // the size in the checkpoint body, and the tags decide whether it is read
    // at all. `toBeDefined()` on the object does not pin that; the members do.
    const anchor = vectorAnchor();
    const envelope = assembleEnvelope(input, { attestation: { anchor } });

    expect(envelope.nonRepudiation.anchor).toEqual(anchor);
    const stored = envelope.nonRepudiation.anchor!;
    expect(Object.keys(stored).sort()).toEqual([
      'anchorCheckpoint',
      'anchorLeafIndex',
      'anchorPath',
      'anchorSpec',
      'leafIndex',
      'logCheckpoint',
      'logPath',
      'merkleSpec',
      'publications',
    ]);
    expect(stored.anchorSpec).toBe('tzun-anchor/1');
    expect(stored.merkleSpec).toBe('rfc6962');
    for (const step of [...stored.logPath, ...stored.anchorPath]) {
      expect(step).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(stored.logPath.length).toBeGreaterThan(0);
    expect(stored.anchorPath.length).toBeGreaterThan(0);
  });

  it('the anchor does not move canonicalDigest', () => {
    // `nonRepudiation` sits outside the v1.0 hashed field set (aiBom,
    // aiOutput, aiSystemId, capturedAt, evidenceId, humanAction, humanReason,
    // sequenceNumber), so the anchor is filled into a stored record without
    // moving its identity (tzun-anchor/1 §8.4). If it ever leaked into the
    // digest, every record's chainLink would break the first time an epoch
    // was filled, and the breakage would look like tampering.
    const fixed = ['2026-09-15T00:00:00.000Z', 'c1b2c3d4-0000-4000-8000-000000000000'] as const;
    const bare = assembleEnvelope(input, { sequenceNumber: 7, signoffExpectation: null, capturedAt: fixed[0], evidenceId: fixed[1] });
    const anchored = assembleEnvelope(input, { attestation: { anchor: vectorAnchor() }, sequenceNumber: 7, signoffExpectation: null, capturedAt: fixed[0], evidenceId: fixed[1] });
    expect(anchored.integrity.canonicalDigest).toBe(bare.integrity.canonicalDigest);
    // ...and the anchor is still counted, so the equality above is not an
    // artifact of the anchor having been ignored altogether.
    expect(bare.attestationStatus).toBe('none');
    expect(anchored.attestationStatus).toBe('partial');
  });
});
