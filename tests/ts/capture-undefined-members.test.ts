import { modelInput } from './helpers/step-model';
/**
 * What capture() hashes is exactly what storage keeps.
 *
 * The canonical serializer writes an `undefined` object member as `null`;
 * every store (and the cloud transport) serialises the envelope with
 * `JSON.stringify`, which drops the key. A capture of `{ b: undefined }`
 * therefore hashed `{"b":null}`, stored `{}`, reported `stored: true`, and
 * then failed its own digest on every read-back — an honest record reported
 * as tampered, forever.
 *
 * capture() now normalises the hashed payload into the JSON data model before
 * hashing it: an `undefined` object member is dropped, an `undefined` array
 * element (or a hole) becomes `null`. That is what `JSON.stringify` does, so
 * the bytes hashed are the bytes every store and transport keeps.
 */
import { Tzun } from '../../src/sdk/index';
import {
  canonicalSerialize,
  computeDigest,
  SchemaRegistry,
  type CaptureInput,
  type EvidenceEnvelope,
  type ModelDescriptor,
} from '@tzun/engine';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

const HASHED = new SchemaRegistry().get('v1.0')!.hashedFieldSet;

/** Recompute the digest of an envelope as a store would see it after a JSON round trip. */
function digestAfterJsonRoundTrip(envelope: EvidenceEnvelope): string {
  const reread = JSON.parse(JSON.stringify(envelope)) as EvidenceEnvelope;
  return computeDigest(
    canonicalSerialize(reread.payload as unknown as Record<string, unknown>, HASHED),
  );
}

function input(aiOutput: Record<string, unknown>): CaptureInput {
  return { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput, action: 'approved', reason: 'Meets all criteria' };
}

function descriptorFixture(): ModelDescriptor {
  return {
    descriptorVersion: 'd1',
    vendor: 'openai',
    modelName: 'undefined-members-model',
    modelVersion: 'v1',
    modelType: 'llm',
    integrityTier: 'vendor-asserted',
    modelDigest: null,
    parentModelDescriptorDigest: null,
    derivation: null,
    trainedBy: 'TestCorp',
    license: 'mit',
    modelCardUrl: null,
    training: {
      trainingDataDigest: null,
      trainingDataRef: null,
      lastTrainingDate: null,
      evaluations: [],
    },
    regulatoryMarkings: [],
    externalIdentifiers: [],
  };
}

function sharedCases(makeTzun: () => Promise<Tzun>) {
  let tzun: Tzun;

  beforeEach(async () => {
    tzun = await makeTzun();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('a nested undefined member stores and verifies', async () => {
    const result = await tzun.capture(input({ a: 1, b: undefined }));
    expect(result.stored).toBe(true);

    const verification = await tzun.verify(result.envelope.payload.evidenceId);
    expect(verification.verified).toBe(true);
    expect(verification.recomputedDigest).toBe(verification.storedDigest);
  });

  it('the stored record is the hashed record', async () => {
    const result = await tzun.capture(
      input({ a: 1, b: undefined, nested: { keep: 'x', drop: undefined, list: [1, undefined, 3] } }),
    );
    expect(result.stored).toBe(true);

    const stored = await tzun.getStorage().retrieve(result.envelope.payload.evidenceId);
    expect(stored!.payload.aiOutput).toEqual({ a: 1, nested: { keep: 'x', list: [1, null, 3] } });
    expect(Object.keys(stored!.payload.aiOutput)).not.toContain('b');
    expect(Object.keys(stored!.payload.aiOutput.nested as object)).not.toContain('drop');

    // The envelope handed back to the caller is the one that was stored.
    expect(result.envelope.payload.aiOutput).toStrictEqual(stored!.payload.aiOutput);

    const recomputed = computeDigest(
      canonicalSerialize(stored!.payload as unknown as Record<string, unknown>, HASHED),
    );
    expect(recomputed).toBe(result.envelope.integrity.canonicalDigest);
  });

  it('an undefined member inside an array element is dropped too', async () => {
    const result = await tzun.capture(input({ rows: [{ id: 1, note: undefined }] }));
    expect(result.stored).toBe(true);
    expect((await tzun.verify(result.envelope.payload.evidenceId)).verified).toBe(true);
  });

  it('a sparse array stores and verifies', async () => {
    // eslint-disable-next-line no-sparse-arrays
    const result = await tzun.capture(input({ sparse: [1, , 3] }));
    expect(result.stored).toBe(true);
    expect((await tzun.verify(result.envelope.payload.evidenceId)).verified).toBe(true);
  });
}

describe('undefined members: hashed == stored', () => {
  describe('memory store', () => {
    sharedCases(() => Tzun.init({ mode: 'dev' }));
  });

  describe('SQLite store', () => {
    sharedCases(() => Tzun.init({ mode: 'dev', dbPath: ':memory:' }));
  });

  const pgSchema = pgSuiteSchema('undefined_members');
  (PG_TESTS_ENABLED ? describe : describe.skip)('Postgres store', () => {
    sharedCases(() => Tzun.init({ mode: 'dev', dbUrl: pgSchema.url }));
  });

  describe('the capture path itself', () => {
    let tzun: Tzun;

    beforeEach(async () => {
      tzun = await Tzun.init({ mode: 'dev' });
    });

    afterEach(async () => {
      await tzun.close();
    });

    it('the digest survives the JSON round trip every transport makes', async () => {
      const result = await tzun.capture(input({ a: 1, b: undefined, c: { d: undefined } }));
      expect(digestAfterJsonRoundTrip(result.envelope)).toBe(
        result.envelope.integrity.canonicalDigest,
      );
    });

    it("the caller's object is left as it was", async () => {
      const aiOutput = { a: 1, b: undefined, nested: { c: undefined } };
      await tzun.capture(input(aiOutput));
      expect(Object.keys(aiOutput)).toEqual(['a', 'b', 'nested']);
      expect(Object.keys(aiOutput.nested)).toEqual(['c']);
    });

    it('an undefined member in the aiBom is dropped the same way', async () => {
      const result = await tzun.capture({
        ...input({ a: 1 }),
        contributions: modelInput({
          modelDescriptor: descriptorFixture(),
          vendorFingerprint: null,
          promptTemplate: { templateId: 'tmpl-1', templateDigest: undefined as unknown as null },
          inferenceParameters: null,
          infrastructure: null,
        }),
      });
      expect(result.stored).toBe(true);
      expect(digestAfterJsonRoundTrip(result.envelope)).toBe(
        result.envelope.integrity.canonicalDigest,
      );
      expect((await tzun.verify(result.envelope.payload.evidenceId)).verified).toBe(true);
    });

    it('an own __proto__ member stays a member through normalisation', async () => {
      const aiOutput = JSON.parse('{"__proto__":{"x":1},"a":1,"b":null}') as Record<string, unknown>;
      const result = await tzun.capture(input(aiOutput));
      expect(result.stored).toBe(true);
      expect(Object.keys(result.envelope.payload.aiOutput)).toEqual(['__proto__', 'a', 'b']);
      expect(digestAfterJsonRoundTrip(result.envelope)).toBe(
        result.envelope.integrity.canonicalDigest,
      );
      expect((await tzun.verify(result.envelope.payload.evidenceId)).verified).toBe(true);
    });

    it('a cyclic aiOutput is refused as a failure, not a stack overflow', async () => {
      const aiOutput: Record<string, unknown> = { a: 1 };
      aiOutput.self = aiOutput;
      const result = await tzun.capture(input(aiOutput));
      expect(result.stored).toBe(false);
      expect(result.failure?.failureType).toBe('serialization_failure');
      expect(String(result.failure?.diagnosticMetadata.reason ?? JSON.stringify(result.failure)))
        .toMatch(/nesting depth/);
    });

    it('prepareAssertionChallenge() hashes the same normalised record capture() stores', async () => {
      const decision = input({ a: 1, b: undefined });
      const prepared = await tzun.prepareAssertionChallenge(decision);
      const result = await tzun.capture(decision, { prepared });
      expect(result.stored).toBe(true);
      expect(result.envelope.integrity.canonicalDigest).toBe(prepared.digest);
      expect((await tzun.verify(result.envelope.payload.evidenceId)).verified).toBe(true);
    });
  });
});
