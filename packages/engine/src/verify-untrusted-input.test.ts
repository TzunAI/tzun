/**
 * The engine-suite half of the "a verifier never throws" table.
 *
 * The full table (every field x every wrong type, plus the SQLite round trip,
 * `verifyAttestation` and the export-bundle verifier) lives in the root suite at
 * `tests/ts/verifier-never-throws-on-untrusted-input.test.ts`. This file keeps
 * the engine's OWN `jest` run — `pnpm --filter @tzun/engine test`, a separate
 * CI step that never loads the root suite — honest about the three pure
 * functions it ships: a regression reintroduced in the engine package must fail
 * here too, and fail as the TypeError itself.
 *
 * What a throwing implementation reports here instead of a verdict:
 *   TypeError: s is not iterable                                  (actor: 123)
 *   TypeError: Cannot read properties of undefined (reading 'schemaVersion')
 *   Error: Canonical serialization error: lone surrogate U+D800 in string. ...
 */
import { canonicalSerialize } from './canonical';
import { computeCustodyEntryHash, verifyCustodyTrail } from './custody-hash';
import { computeDigest } from './digest';
import { SchemaRegistry } from './schema-registry';
import { verifyEnvelope } from './verify';
import type { EvidenceEnvelope } from './types/evidence';
import type { CustodyTrailVerdict, VerificationResult } from './types/verification';

const registry = new SchemaRegistry();

function makeEnvelope(): EvidenceEnvelope {
  const payload = {
    evidenceId: 'ev-untrusted',
    schemaVersion: 'v1.0',
    aiSystemId: 'test-system',
    aiOutput: { recommendation: 'approve' },
    action: 'approved',
    reason: 'Test',
    capturedAt: '2026-09-12T10:00:00.000Z',
    sequenceNumber: 1,
    decider: { kind: 'human' as const, id: 'acct:u-1', agent: null, credential: null, freshness: null },
    contributions: null,
    links: null,
    signoffExpectation: null,
  };
  const digest = computeDigest(
    canonicalSerialize(
      payload as unknown as Record<string, unknown>,
      registry.get('v1.0')!.hashedFieldSet,
    ),
  );
  return {
    envelopeVersion: 'e1',
    payload,
    integrity: { canonicalDigest: digest, chainLink: null },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  };
}

const base = makeEnvelope();

function hashedEntry(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const fields = {
    action: 'reviewed',
    actor: 'jane@acme.example',
    timestamp: '2026-09-12T10:00:00.000Z',
    systemId: 'tzun-test',
  };
  return {
    ...fields,
    prevEntryHash: null,
    entryHash: computeCustodyEntryHash({
      prevEntryHash: null,
      evidenceId: base.payload.evidenceId,
      canonicalDigest: base.integrity.canonicalDigest,
      ...fields,
      metadata: null,
    }),
    ...overrides,
  };
}

function withChain(chain: unknown[]): EvidenceEnvelope {
  return { ...base, custodyChain: chain as unknown as EvidenceEnvelope['custodyChain'] };
}

describe('verifyCustodyTrail never throws on untrusted input', () => {
  it('verifies a well-formed hashed entry', () => {
    expect(verifyCustodyTrail(withChain([hashedEntry()])).valid).toBe(true);
  });

  for (const field of ['action', 'actor', 'timestamp', 'systemId'] as const) {
    it(`reports entry_field_type for a numeric ${field}`, () => {
      let verdict!: CustodyTrailVerdict;
      expect(() => {
        verdict = verifyCustodyTrail(withChain([hashedEntry({ [field]: 123 })]));
      }).not.toThrow();
      expect(verdict.valid).toBe(false);
      expect(verdict.failures.map((f) => f.reason)).toEqual(['entry_field_type']);
    });
  }

  it('reports entry_field_type for an ARRAY actor (iterable, so it never threw — it coerced)', () => {
    const verdict = verifyCustodyTrail(withChain([hashedEntry({ actor: ['a', 'b'] })]));
    expect(verdict.failures.map((f) => f.reason)).toEqual(['entry_field_type']);
  });

  it('reports entry_metadata_unserializable for a lone surrogate in metadata', () => {
    let verdict!: CustodyTrailVerdict;
    expect(() => {
      verdict = verifyCustodyTrail(withChain([hashedEntry({ metadata: { s: '\uD800' } })]));
    }).not.toThrow();
    expect(verdict.failures.map((f) => f.reason)).toEqual(['entry_metadata_unserializable']);
  });

  it('answers "unverified" on a null envelope', () => {
    expect(verifyCustodyTrail(null as unknown as EvidenceEnvelope).valid).toBeNull();
  });
});

describe('verifyEnvelope never throws on untrusted input', () => {
  it('verifies the control envelope', () => {
    expect(verifyEnvelope(base, undefined, registry).verified).toBe(true);
  });

  it('reports custodyTrailValid:false for a numeric actor', () => {
    const result = verifyEnvelope(withChain([hashedEntry({ actor: 123 })]), undefined, registry);
    expect(result.custodyTrailValid).toBe(false);
    // custodyChain is outside the hashed field set: the decision record itself
    // is still intact, which is why the two fields are separate.
    expect(result.verified).toBe(true);
  });

  it('reports payloadSerializationError for a lone surrogate in the payload', () => {
    let result!: VerificationResult;
    expect(() => {
      result = verifyEnvelope(
        { ...base, payload: { ...base.payload, reason: '\uD800' } },
        undefined,
        registry,
      );
    }).not.toThrow();
    expect(result.verified).toBe(false);
    expect(result.recomputedDigest).toBe('');
    expect(result.payloadSerializationError).toMatch(/lone surrogate U\+D800/);
  });

  for (const [label, envelope] of [
    ['null', null],
    ['an empty object', {}],
    ['no payload key', { integrity: { canonicalDigest: 'x', chainLink: null } }],
    ['no integrity key', { payload: base.payload }],
  ] as Array<[string, unknown]>) {
    it(`reports verified:false for an envelope that is ${label}`, () => {
      let result!: VerificationResult;
      expect(() => {
        result = verifyEnvelope(envelope as EvidenceEnvelope, undefined, registry);
      }).not.toThrow();
      expect(result.verified).toBe(false);
    });
  }
});
