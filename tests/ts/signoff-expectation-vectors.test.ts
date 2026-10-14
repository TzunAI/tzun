/**
 * vectors/signoff-expectation-vectors.json (Record §9, Verification §5): the TS
 * engine gives every answer the file states. The Python SDK is held to the
 * same file by python/tests/verify/test_signoff_expectation_vectors.py.
 */
import vectors from '../../vectors/signoff-expectation-vectors.json';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  checkSignoffExpectation,
  recordPredatesSignoffExpectation,
  recordVerdict,
  signoffExpectationViolation,
  signoffStatementChallenge,
  signoffStatementDigest,
  verifyEnvelope,
  type EvidenceEnvelope,
} from '@tzun/engine';
import { Tzun } from '../../src/sdk/index';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';

interface Vectors {
  shapes: Array<{ case: string; value: unknown; violation: string | null }>;
  statementDigests: Array<{ case: string; statement: unknown; digest: string | null; challenge: string | null }>;
  checks: Array<{ case: string; envelope: unknown; expect: { valid: boolean | null; reason?: string } }>;
  predates: Array<{ case: string; envelope: unknown; expect: boolean }>;
  verifications: Array<{
    case: string;
    envelope: unknown;
    expect: { verified: boolean; signoffExpectation: { valid: boolean | null; reason?: string } };
  }>;
}
const v = vectors as unknown as Vectors;

describe('signoff-expectation vectors', () => {
  it('the file holds every part', () => {
    expect(v.shapes.length).toBeGreaterThan(20);
    expect(v.statementDigests.length).toBeGreaterThan(0);
    expect(v.checks.length).toBeGreaterThan(15);
    expect(v.predates.length).toBeGreaterThan(2);
    expect(v.verifications.length).toBeGreaterThan(5);
  });

  it.each(v.shapes)('shape: $case', ({ value, violation }) => {
    expect(signoffExpectationViolation(value)).toBe(violation);
  });

  it.each(v.statementDigests)('statement digest: $case', ({ statement, digest, challenge }) => {
    expect(signoffStatementDigest(statement)).toBe(digest);
    expect(digest === null ? null : signoffStatementChallenge(digest)).toBe(challenge);
  });

  it.each(v.checks)('check: $case', ({ envelope, expect: expected }) => {
    expect(checkSignoffExpectation(envelope)).toEqual(expected);
    // verifyEnvelope reports the same answer, and every case is an intact record.
    const result = verifyEnvelope(envelope as EvidenceEnvelope);
    expect(result.verified).toBe(true);
    expect(result.signoffExpectationValid).toBe(expected.valid);
    expect(result.signoffExpectationReason).toBe(expected.reason);
  });

  it.each(v.predates)('predates 0.7.0: $case', ({ envelope, expect: expected }) => {
    expect(recordPredatesSignoffExpectation(envelope)).toBe(expected);
  });

  it.each(v.verifications)('verification: $case', ({ envelope, expect: expected }) => {
    const result = verifyEnvelope(envelope as EvidenceEnvelope);
    expect(result.verified).toBe(expected.verified);
    expect(result.signoffExpectationValid).toBe(expected.signoffExpectation.valid);
    expect(result.signoffExpectationReason).toBe(expected.signoffExpectation.reason);
    const verdict = recordVerdict(envelope as EvidenceEnvelope, { custody: { entries: [] } });
    expect(verdict.signoffExpectation).toEqual(expected.signoffExpectation);
    expect(verdict.digest.status === 'valid').toBe(expected.verified);
  });

  it('the verifications are not vacuous: a record whose digest does not hold reads another answer off its rewritten expectation', () => {
    const differs = v.verifications.filter(
      (c) => !c.expect.verified && JSON.stringify(checkSignoffExpectation(c.envelope)) !== JSON.stringify(c.expect.signoffExpectation),
    );
    expect(differs.map((c) => checkSignoffExpectation(c.envelope).valid)).toEqual(expect.arrayContaining([true, false, null]));
  });
});

// The same answers from Tzun.verify() and get() over a SQLite store holding
// each case's record, as the Python suite asks its verify() for them.
describe('signoff-expectation vectors: verify() and get() on SQLite', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-signoff-expectation-vectors-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it.each(v.verifications)('$case', async ({ envelope, expect: expected }) => {
    const dbPath = join(dir, 'store.db');
    // Opened first, so the store check sees an empty store; the record is then
    // written as a store writer would write it.
    const tzun = await Tzun.init({ mode: 'dev', dbPath });
    try {
      const writer = new SqliteStorageAdapter(dbPath);
      await writer.store(envelope as EvidenceEnvelope);
      await writer.close();
      const id = (envelope as EvidenceEnvelope).payload.evidenceId;
      const result = await tzun.verify(id);
      expect(result.verified).toBe(expected.verified);
      expect(result.signoffExpectationValid).toBe(expected.signoffExpectation.valid);
      expect(result.signoffExpectationReason).toBe(expected.signoffExpectation.reason);
      expect((await tzun.get(id))!.verdict.signoffExpectation).toEqual(expected.signoffExpectation);
    } finally {
      await tzun.close();
    }
  });
});
