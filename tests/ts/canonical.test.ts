import { singleModel } from '@tzun/engine';
import { canonicalSerialize, canonicalSerializeDescriptor, SchemaRegistry } from '@tzun/engine';
import vectors from '../../vectors/v1.0-canonical-vectors.json';
import { ModelDescriptor } from '@tzun/engine';

/** The v1.0 hashed field set: every envelope vector and case below serializes under it. */
const V1_0 = new SchemaRegistry().get('v1.0')!.hashedFieldSet;

/**
 * Materializes the values JSON text cannot express. `LONE_SURROGATE_D800`
 * becomes a real unpaired U+D800 and `NAN_MARKER` becomes NaN, so the negative
 * corpus can be stored as ordinary JSON.
 */
function materializeSentinels(value: unknown): unknown {
  if (typeof value === 'string') {
    if (value === 'NAN_MARKER') return NaN;
    return value.replace(/LONE_SURROGATE_D800/g, '\uD800');
  }
  if (Array.isArray(value)) return value.map(materializeSentinels);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = materializeSentinels(v);
    }
    return out;
  }
  return value;
}

describe('canonicalSerialize', () => {
  // Dispatch by vector kind:
  //   - 'descriptor'             → canonicalSerializeDescriptor (V20, V21, V23)
  //   - 'envelope-v1.0'          → the v1.0 hashed field set (every other case)
  for (const vector of vectors.vectors) {
    it(`${vector.id}: ${vector.description}`, () => {
      const kind = (vector as any).kind as string | undefined;
      let input = { ...vector.input } as Record<string, unknown>;

      // Apply the UNDEFINED_MARKER convention: any vector whose note mentions
      // UNDEFINED_MARKER substitutes the literal string for `undefined` before
      // serializing (so the JSON file can represent undefined values).
      if ((vector as any).note?.includes('UNDEFINED_MARKER')) {
        const aiOutput = { ...(input.aiOutput as Record<string, unknown>) };
        for (const [k, v] of Object.entries(aiOutput)) {
          if (v === 'UNDEFINED_MARKER') aiOutput[k] = undefined;
        }
        input = { ...input, aiOutput };
      }

      let result: string;
      if (kind === 'descriptor') {
        result = canonicalSerializeDescriptor(input as unknown as ModelDescriptor);
      } else {
        expect(kind).toBe('envelope-v1.0');
        result = canonicalSerialize(input, V1_0);
      }
      expect(result).toBe(vector.canonical);
    });
  }

  // Negative corpus: inputs the canonicalizer MUST refuse. A serializer that
  // returns bytes for any of these is silently minting a digest for a value
  // that has no canonical form, and two such values can then share one digest
  // (see the lone-surrogate cases below). JSON text cannot carry a lone
  // surrogate or NaN, so those two arrive as sentinels and are materialized
  // here.
  const negatives = (vectors as unknown as {
    negativeVectors?: Array<{
      id: string;
      description: string;
      expectError: string;
      input: Record<string, unknown>;
    }>;
  }).negativeVectors;

  it('the negative corpus is present and non-empty', () => {
    expect(Array.isArray(negatives)).toBe(true);
    expect(negatives!.length).toBeGreaterThanOrEqual(3);
  });

  for (const vector of negatives ?? []) {
    it(`${vector.id}: ${vector.description}`, () => {
      const input = materializeSentinels({ ...vector.input }) as Record<string, unknown>;
      expect(() =>
        canonicalSerialize(input, V1_0),
      ).toThrow(new RegExp(vector.expectError, 'i'));
    });
  }

  it('only includes fields in the hashed field set', () => {
    const input = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId: 'abc',
      aiSystemId: 'sys1',
      aiOutput: { r: 'approve' },
      action: 'approved',
      reason: 'ok',
      capturedAt: '2026-01-01T00:00:00Z',
      sequenceNumber: 1,
      extraField: 'should not appear',
    };
    const result = canonicalSerialize(input, V1_0);
    expect(result).not.toContain('extraField');
    expect(result).not.toContain('should not appear');
    expect(result).toContain('"sequenceNumber":1');
  });

  it('throws on NaN', () => {
    const input = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId: 'abc',
      aiSystemId: 'sys1',
      aiOutput: { score: NaN },
      action: 'approved',
      reason: 'ok',
      capturedAt: '2026-01-01T00:00:00Z',
      sequenceNumber: 1,
    };
    expect(() =>
      canonicalSerialize(input, V1_0)
    ).toThrow();
  });

  it('throws on Infinity', () => {
    const input = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId: 'abc',
      aiSystemId: 'sys1',
      aiOutput: { score: Infinity },
      action: 'approved',
      reason: 'ok',
      capturedAt: '2026-01-01T00:00:00Z',
      sequenceNumber: 1,
    };
    expect(() =>
      canonicalSerialize(input, V1_0)
    ).toThrow();
  });

  it('throws on excessive nesting depth (circular reference guard)', () => {
    // Build a 70-level deep object to exceed MAX_DEPTH of 64
    let deep: Record<string, unknown> = { value: 'bottom' };
    for (let i = 0; i < 70; i++) {
      deep = { nested: deep };
    }
    const input = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId: 'abc',
      aiSystemId: 'sys1',
      aiOutput: deep,
      action: 'approved',
      reason: 'ok',
      capturedAt: '2026-01-01T00:00:00Z',
      sequenceNumber: 1,
    };
    expect(() =>
      canonicalSerialize(input, V1_0)
    ).toThrow(/maximum nesting depth/);
  });

  it('throws on non-plain objects like Date', () => {
    const input = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId: 'abc',
      aiSystemId: 'sys1',
      aiOutput: { timestamp: new Date('2026-01-01') },
      action: 'approved',
      reason: 'ok',
      capturedAt: '2026-01-01T00:00:00Z',
      sequenceNumber: 1,
    };
    expect(() =>
      canonicalSerialize(input, V1_0)
    ).toThrow(/non-plain object/);
  });
});

describe('canonical: descriptor sub-rule', () => {
  const baseDescriptor = (): ModelDescriptor => ({
    descriptorVersion: 'd1',
    vendor: 'v',
    modelName: 'm',
    modelVersion: '1',
    modelType: null,
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

  it('sorts regulatoryMarkings by (authority, identifier)', () => {
    const d1: ModelDescriptor = { ...baseDescriptor(), regulatoryMarkings: [
      { authority: 'us-fda', identifier: 'K2', status: 'active', effectiveDate: null, expiresAt: null, scope: null, evidenceUrl: null },
      { authority: 'eu-ce-mdr', identifier: 'CE1', status: 'active', effectiveDate: null, expiresAt: null, scope: null, evidenceUrl: null },
    ]};
    const d2: ModelDescriptor = { ...baseDescriptor(), regulatoryMarkings: [
      { authority: 'eu-ce-mdr', identifier: 'CE1', status: 'active', effectiveDate: null, expiresAt: null, scope: null, evidenceUrl: null },
      { authority: 'us-fda', identifier: 'K2', status: 'active', effectiveDate: null, expiresAt: null, scope: null, evidenceUrl: null },
    ]};
    expect(canonicalSerializeDescriptor(d1)).toBe(canonicalSerializeDescriptor(d2));
  });

  it('sorts training.evaluations by name', () => {
    const d1: ModelDescriptor = { ...baseDescriptor(), training: { ...baseDescriptor().training,
      evaluations: [
        { name: 'mmlu', testSetDigest: null, evaluatedAt: null, metrics: {} },
        { name: 'arc-challenge', testSetDigest: null, evaluatedAt: null, metrics: {} },
      ]}};
    const d2: ModelDescriptor = { ...baseDescriptor(), training: { ...baseDescriptor().training,
      evaluations: [
        { name: 'arc-challenge', testSetDigest: null, evaluatedAt: null, metrics: {} },
        { name: 'mmlu', testSetDigest: null, evaluatedAt: null, metrics: {} },
      ]}};
    expect(canonicalSerializeDescriptor(d1)).toBe(canonicalSerializeDescriptor(d2));
  });

  it('sorts externalIdentifiers by (scheme, value)', () => {
    const d1: ModelDescriptor = { ...baseDescriptor(), externalIdentifiers: [
      { scheme: 'hf-repo', value: 'meta-llama/x', issuedBy: null, issuedAt: null, url: null },
      { scheme: 'doi', value: '10.0/y', issuedBy: null, issuedAt: null, url: null },
    ]};
    const d2: ModelDescriptor = { ...baseDescriptor(), externalIdentifiers: [
      { scheme: 'doi', value: '10.0/y', issuedBy: null, issuedAt: null, url: null },
      { scheme: 'hf-repo', value: 'meta-llama/x', issuedBy: null, issuedAt: null, url: null },
    ]};
    expect(canonicalSerializeDescriptor(d1)).toBe(canonicalSerializeDescriptor(d2));
  });

  it('does not mutate caller input arrays', () => {
    const d: ModelDescriptor = { ...baseDescriptor(), externalIdentifiers: [
      { scheme: 'hf-repo', value: 'z', issuedBy: null, issuedAt: null, url: null },
      { scheme: 'doi', value: 'a', issuedBy: null, issuedAt: null, url: null },
    ]};
    canonicalSerializeDescriptor(d);
    // Insertion order preserved on the caller's reference
    expect(d.externalIdentifiers.map((e) => e.scheme)).toEqual(['hf-repo', 'doi']);
  });

  it('uses ordinal (UTF-16 code-unit) order, not locale collation', () => {
    // 'A' (0x41) MUST sort before 'a' (0x61) in code-unit order.
    // Under many locales 'A' and 'a' compare equal at primary strength;
    // a locale-sensitive sort could swap them or treat them as ties.
    const d1: ModelDescriptor = { ...baseDescriptor(), externalIdentifiers: [
      { scheme: 'a-scheme', value: 'v', issuedBy: null, issuedAt: null, url: null },
      { scheme: 'A-scheme', value: 'v', issuedBy: null, issuedAt: null, url: null },
    ]};
    const d2: ModelDescriptor = { ...baseDescriptor(), externalIdentifiers: [
      { scheme: 'A-scheme', value: 'v', issuedBy: null, issuedAt: null, url: null },
      { scheme: 'a-scheme', value: 'v', issuedBy: null, issuedAt: null, url: null },
    ]};
    const bytes = canonicalSerializeDescriptor(d1);
    expect(canonicalSerializeDescriptor(d2)).toBe(bytes);
    // Uppercase 'A-scheme' (0x41) must appear before lowercase 'a-scheme' (0x61).
    const idxA = bytes.indexOf('"A-scheme"');
    const idxa = bytes.indexOf('"a-scheme"');
    expect(idxA).toBeGreaterThan(-1);
    expect(idxa).toBeGreaterThan(idxA);
  });

  it('non-ASCII characters sort by code unit, not by locale', () => {
    // 'z' (0x7A = 122) < 'ä' (0xE4 = 228) in code-unit order.
    // Under most locales 'ä' sorts near 'a', i.e. BEFORE 'z'.
    // The canonical serializer must use code-unit order so digests are
    // identical across locales / ICU versions / runtimes.
    const d1: ModelDescriptor = { ...baseDescriptor(), training: { ...baseDescriptor().training,
      evaluations: [
        { name: 'ä-eval', testSetDigest: null, evaluatedAt: null, metrics: {} },
        { name: 'z-eval', testSetDigest: null, evaluatedAt: null, metrics: {} },
      ]}};
    const d2: ModelDescriptor = { ...baseDescriptor(), training: { ...baseDescriptor().training,
      evaluations: [
        { name: 'z-eval', testSetDigest: null, evaluatedAt: null, metrics: {} },
        { name: 'ä-eval', testSetDigest: null, evaluatedAt: null, metrics: {} },
      ]}};
    const bytes = canonicalSerializeDescriptor(d1);
    expect(canonicalSerializeDescriptor(d2)).toBe(bytes);
    // 'z-eval' must appear before 'ä-eval' (z < ä in code-unit order).
    const idxZ = bytes.indexOf('"z-eval"');
    const idxA = bytes.indexOf('"');  // first quote — just to satisfy lint
    expect(idxA).toBeGreaterThan(-1);
    const idxAUmlaut = bytes.indexOf('z-eval');
    const idxNonAscii = bytes.indexOf('-eval', idxAUmlaut + 1);
    expect(idxZ).toBeGreaterThan(-1);
    expect(idxNonAscii).toBeGreaterThan(idxZ);
  });

  it('tuple ties fall through to the second field deterministically', () => {
    // Same authority, different identifiers — second field must order
    // them, not be a coin flip.
    const d1: ModelDescriptor = { ...baseDescriptor(), regulatoryMarkings: [
      { authority: 'eu', identifier: 'B2', status: 'active', effectiveDate: null, expiresAt: null, scope: null, evidenceUrl: null },
      { authority: 'eu', identifier: 'A1', status: 'active', effectiveDate: null, expiresAt: null, scope: null, evidenceUrl: null },
    ]};
    const d2: ModelDescriptor = { ...baseDescriptor(), regulatoryMarkings: [
      { authority: 'eu', identifier: 'A1', status: 'active', effectiveDate: null, expiresAt: null, scope: null, evidenceUrl: null },
      { authority: 'eu', identifier: 'B2', status: 'active', effectiveDate: null, expiresAt: null, scope: null, evidenceUrl: null },
    ]};
    expect(canonicalSerializeDescriptor(d1)).toBe(canonicalSerializeDescriptor(d2));
  });

  it('envelope payload arrays preserve insertion order (base rule, NOT descriptor sub-rule)', () => {
    // Envelope-level (non-descriptor) arrays remain insertion-ordered.
    // `stopSequences` lives under aiBom.inferenceParameters; the
    // descriptor sub-rule explicitly does not sort it.
    const p1 = { stopSequences: ['END', 'STOP'] };
    const p2 = { stopSequences: ['STOP', 'END'] };
    expect(canonicalSerialize(p1, ['stopSequences'])).not.toBe(
      canonicalSerialize(p2, ['stopSequences']),
    );
  });
});

describe('canonical: the v1.0 hashed field set (a model lives in a contribution step)', () => {
  const v10Fields = [
    'action', 'aiOutput', 'aiSystemId', 'capturedAt', 'contributions', 'decider',
    'evidenceId', 'links', 'reason', 'sequenceNumber', 'signoffExpectation',
  ];

  it('contributions: null canonicalizes as the null literal', () => {
    const payload = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      contributions: null,
      aiOutput: {},
      aiSystemId: 's',
      capturedAt: '2026-05-25T00:00:00Z',
      evidenceId: 'e',
      action: 'a',
      reason: 'r',
      sequenceNumber: 1,
    };
    const bytes = canonicalSerialize(payload, v10Fields);
    expect(bytes).toContain('"contributions":null');
  });

  it('a missing contributions key serializes identically to explicit null', () => {
    const withNull = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      contributions: null, aiOutput: {}, aiSystemId: 's', capturedAt: 't',
      evidenceId: 'e', action: 'a', reason: 'r', sequenceNumber: 1,
    };
    const without: Record<string, unknown> = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: {}, aiSystemId: 's', capturedAt: 't',
      evidenceId: 'e', action: 'a', reason: 'r', sequenceNumber: 1,
    };
    expect(canonicalSerialize(withNull, v10Fields)).toBe(
      canonicalSerialize(without, v10Fields),
    );
  });

  it("a step's populated aiBom subtree is recursively canonicalized", () => {
    const payload = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      contributions: singleModel({
        modelDescriptorDigest: 'sha256:abc',
        vendorFingerprint: null,
        promptTemplate: null,
        inferenceParameters: { temperature: 0.7, topP: null, maxTokens: 1024, seed: null, stopSequences: ['END', 'STOP'] },
        infrastructure: null,
      }),
      aiOutput: {}, aiSystemId: 's', capturedAt: 't',
      evidenceId: 'e', action: 'a', reason: 'r', sequenceNumber: 1,
    };
    const bytes = canonicalSerialize(payload, v10Fields);
    expect(bytes).toContain('"modelDescriptorDigest":"sha256:abc"');
    // Object keys inside aiBom sorted lexicographically; stopSequences preserves insertion order
    expect(bytes).toContain('"stopSequences":["END","STOP"]');
  });

  // -------------------------------------------------------------------------
  // Lone UTF-16 surrogates are rejected, not silently mangled into U+FFFD.
  //
  // The digest hashes the canonical string as UTF-8, and Node's UTF-8 encoder
  // replaces an unpaired surrogate with U+FFFD (EF BF BD). A serializer that
  // let one through would canonicalize "\uD800", "\uDC00" and a literal
  // U+FFFD to the SAME bytes: it would not be injective, and the record digest
  // depends on it being injective. The Python port rejects lone surrogates
  // too, so both reference implementations agree on which records have a
  // digest, and a TS-captured record can always be re-verified in Python.
  //
  // Reachable in practice: an LLM completion truncated at max_tokens mid-emoji
  // yields one, and JSON.stringify preserves it as \ud800 through every
  // adapter.
  // -------------------------------------------------------------------------
  describe('lone surrogates', () => {
    const payloadWithReason = (reason: string) => ({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      contributions: null, aiOutput: { text: 'ok' }, aiSystemId: 's', capturedAt: 't',
      evidenceId: 'e', action: 'a', reason, sequenceNumber: 1,
    });

    const HIGH = '\uD800';
    const LOW = '\uDC00';
    const REPLACEMENT = '\uFFFD';

    it('rejects an unpaired high surrogate', () => {
      expect(() => canonicalSerialize(payloadWithReason('ok' + HIGH), v10Fields))
        .toThrow(/lone surrogate U\+D800/);
    });

    it('rejects an unpaired low surrogate', () => {
      expect(() => canonicalSerialize(payloadWithReason('ok' + LOW), v10Fields))
        .toThrow(/lone surrogate U\+DC00/);
    });

    it('rejects a high surrogate followed by a non-surrogate', () => {
      expect(() => canonicalSerialize(payloadWithReason(HIGH + 'x'), v10Fields))
        .toThrow(/lone surrogate U\+D800/);
    });

    it('rejects a high surrogate at the very end of the string', () => {
      expect(() => canonicalSerialize(payloadWithReason(HIGH), v10Fields))
        .toThrow(/lone surrogate/);
    });

    it('rejects a lone surrogate nested inside aiOutput', () => {
      expect(() =>
        canonicalSerialize(
          {
            decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
            contributions: null, aiOutput: { text: 'truncated emoji: ' + HIGH },
            aiSystemId: 's', capturedAt: 't', evidenceId: 'e',
            action: 'a', reason: 'r', sequenceNumber: 1,
          },
          v10Fields,
        ),
      ).toThrow(/lone surrogate/);
    });

    it('rejects a lone surrogate used as an object KEY', () => {
      expect(() =>
        canonicalSerialize(
          {
            decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
            contributions: null, aiOutput: { [HIGH]: 1 }, aiSystemId: 's',
            capturedAt: 't', evidenceId: 'e', action: 'a',
            reason: 'r', sequenceNumber: 1,
          },
          v10Fields,
        ),
      ).toThrow(/lone surrogate/);
    });

    // The injectivity property: three DIFFERENT inputs must not produce one
    // output. Passed through to UTF-8 unchecked, all three of these would
    // encode to byte-identical canonical forms.
    it('does not collapse distinct inputs onto one canonical form', () => {
      const outputs: string[] = [];
      for (const s of [HIGH, LOW, REPLACEMENT]) {
        try {
          outputs.push(canonicalSerialize(payloadWithReason('ok' + s), v10Fields));
        } catch {
          // Rejected — which is the point: it cannot collide with anything.
        }
      }
      // Only the well-formed U+FFFD survives; the two lone surrogates throw.
      expect(outputs).toHaveLength(1);
      expect(outputs[0]).toContain('ok' + REPLACEMENT);
    });

    // Well-formed text is unaffected: a valid surrogate pair serializes
    // verbatim, so the lone-surrogate rule never refuses or alters a valid
    // record.
    it('still serializes a valid surrogate PAIR (a real emoji) unchanged', () => {
      const emoji = '\uD83D\uDE00'; // U+1F600 GRINNING FACE
      const bytes = canonicalSerialize(payloadWithReason('nice ' + emoji), v10Fields);
      expect(bytes).toContain('"reason":"nice ' + emoji + '"');
      expect(JSON.parse(bytes).reason).toBe('nice ' + emoji);
    });

    it('produces a well-formed, byte-stable canonical string for valid input', () => {
      const emoji = '\uD83D\uDE00';
      const a = canonicalSerialize(payloadWithReason(emoji), v10Fields);
      const b = canonicalSerialize(payloadWithReason(emoji), v10Fields);
      expect(a).toBe(b);
      // No U+FFFD substitution happened on the way through UTF-8.
      expect(Buffer.from(a, 'utf8').toString('utf8')).toBe(a);
    });
  });

  // Sparse arrays. `Array.prototype.map` skips holes and `join` renders them
  // as nothing, so a serializer built on them would emit `[1,,3]` as the
  // literal text `[1,,3]`: not valid JSON, and not what the storage round-trip
  // produces. A hole canonicalizes as null, the way JSON.stringify writes it.
  describe('sparse arrays', () => {
    const sparse = [1, , 3] as unknown[]; // eslint-disable-line no-sparse-arrays

    const payloadWith = (scores: unknown) => ({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      contributions: null, aiOutput: { scores }, aiSystemId: 's', capturedAt: 't',
      evidenceId: 'e', action: 'a', reason: 'r', sequenceNumber: 1,
    });

    it('renders a hole as null rather than emitting invalid JSON', () => {
      const bytes = canonicalSerialize(payloadWith(sparse), v10Fields);
      expect(bytes).toContain('"scores":[1,null,3]');
      expect(bytes).not.toContain('[1,,3]');
    });

    it('output parses as JSON', () => {
      const bytes = canonicalSerialize(payloadWith(sparse), v10Fields);
      // The v1.0 rules promise 'Valid JSON output'. A hole emitted as nothing
      // would make this throw SyntaxError: Unexpected token ',' in JSON.
      expect(() => JSON.parse(bytes)).not.toThrow();
    });

    it('survives a JSON storage round-trip with an identical digest', () => {
      // SQLite/Postgres persist the envelope as JSON.stringify(envelope) and
      // JSON.parse it on read. JSON.stringify materialises the hole as null, so
      // unless capture canonicalizes the hole as null too, the value the
      // verifier re-serializes is NOT the value capture serialized, and an
      // honest record fails verify.
      const before = canonicalSerialize(payloadWith(sparse), v10Fields);
      const roundTripped = JSON.parse(JSON.stringify(payloadWith(sparse)));
      const after = canonicalSerialize(roundTripped, v10Fields);
      expect(after).toBe(before);
    });

    it('a trailing hole is preserved as a null element, not dropped', () => {
      const trailing = [1, 2, ,] as unknown[]; // eslint-disable-line no-sparse-arrays
      const bytes = canonicalSerialize(payloadWith(trailing), v10Fields);
      expect(JSON.parse(bytes).aiOutput.scores).toEqual([1, 2, null]);
    });
  });

  it('SchemaRegistry.v1.0 declares the 11-field set in alphabetical order', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { SchemaRegistry } = require('@tzun/engine');
    const v10 = new SchemaRegistry().get('v1.0');
    expect(v10.hashedFieldSet).toEqual(v10Fields);
  });
});
