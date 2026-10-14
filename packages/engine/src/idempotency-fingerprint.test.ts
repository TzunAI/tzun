import { assembleEnvelope } from './envelope';
import { captureCallerDecision, captureIdempotencyFingerprint } from './idempotency-fingerprint';
import type { EnvelopeInput, EvidenceEnvelope } from './types/evidence';

const AGENT = 'sha256:' + 'a1'.repeat(32);
const ISSUANCE = { digest: 'fb'.repeat(32), evidenceId: '7a2c0d4e-1111-4a1a-8a1a-000000000001', locator: null };

function input(freshness: string | null, over: Partial<EnvelopeInput> = {}): EnvelopeInput {
  return {
    aiSystemId: 'claims-triage-v4',
    aiOutput: { amountMinor: 120000 },
    action: 'approve',
    reason: 'Policy active',
    decider: { kind: 'agent', id: `desc:${AGENT}`, agent: AGENT, credential: null, freshness },
    contributions: null,
    links: null,
    ...over,
  };
}

/** One attempt of a capture: the SDK mints the id, time and position per attempt. */
function attempt(i: number, envelopeInput: EnvelopeInput, options: Record<string, unknown> = {}): EvidenceEnvelope {
  return assembleEnvelope(envelopeInput, {
    evidenceId: `5f0c1f0e-2222-4b2b-9b2b-00000000000${i}`,
    sequenceNumber: i,
    capturedAt: `2026-11-20T10:14:5${i}.000Z`,
    ...options,
  });
}

const fingerprint = (envelope: EvidenceEnvelope) => captureIdempotencyFingerprint({ completeness: 'partial', envelope });

describe('captureIdempotencyFingerprint over a 0.8.0 record', () => {
  it('leaves out the decider freshness: a retry that reads a newer block replays', () => {
    const first = attempt(1, input('eip155:1@23652000:0x' + '5e'.repeat(32)));
    const retry = attempt(2, input('eip155:1@23652012:0x' + '6f'.repeat(32)));
    expect(fingerprint(retry)).toBe(fingerprint(first));
    expect(captureCallerDecision(first).decider).toEqual({ kind: 'agent', id: `desc:${AGENT}`, agent: AGENT, credential: null });
  });

  it('covers the decider, the decision and the links: another of any is another capture', () => {
    const base = fingerprint(attempt(1, input(null)));
    const otherAgent = 'sha256:' + 'b2'.repeat(32);
    expect(fingerprint(attempt(1, input(null, { decider: { kind: 'agent', id: `desc:${otherAgent}`, agent: otherAgent, credential: null, freshness: null } })))).not.toBe(base);
    expect(fingerprint(attempt(1, input(null, { action: 'deny' })))).not.toBe(base);
    expect(fingerprint(attempt(1, input(null, { reason: 'Another reason' })))).not.toBe(base);
    const linked = input(null, { links: [{ rel: 'derivedFrom', target: { digest: '71'.repeat(32), evidenceId: null, locator: null }, attrs: null }] });
    expect(fingerprint(attempt(1, linked))).not.toBe(base);
  });

  it('reads the mandate form as the mandate id, never its slot, totals or confirmation flag', () => {
    const mandated = (slot: number, total: number, confirm: boolean) =>
      attempt(
        slot,
        input(null, {
          decider: { kind: 'agent-mandated', id: `desc:${AGENT}`, agent: AGENT, credential: null, freshness: null },
          links: [{ rel: 'mandate', target: ISSUANCE, attrs: null }],
        }),
        {
          signoffExpectation: { mandateAssertion: '79'.repeat(32), mandateSeq: slot, totals: { paid: total }, confirm },
          attestation: { mandate: { document: { mandateId: 'm-1' } } as never },
        },
      );
    const first = mandated(1, 120000, false);
    expect(fingerprint(mandated(2, 240000, true))).toBe(fingerprint(first));
    expect(captureCallerDecision(first).signoffExpectation).toEqual({ mandate: { mandateId: 'm-1' } });
  });
});
