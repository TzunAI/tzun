/**
 * The RFC 3161 token BINDS capturedAt without CHECKING it.
 *
 * `capturedAt` is minted from the capturing machine's clock (sdk/index.ts) and
 * IS in the v1.0 hashed field set, so the token commits to it transitively via
 * the canonicalDigest — it cannot be altered after capture. That is the half
 * that already worked. The half that did not: nothing compared the TSA's
 * genTime against the capturedAt it had just notarised, so a record minted on
 * a skewed clock verified clean and the attestation layer certified the false
 * time.
 *
 * WHAT IS CHECKABLE, AND WHAT IS NOT. The token is issued over a digest that
 * commits to capturedAt, so capturedAt necessarily existed BEFORE the TSA
 * stamped it. `capturedAt > genTime` means the capturing clock ran ahead of the
 * TSA's — usually drift, not dishonesty — so the tolerance matches the 5-minute
 * forward skew the hosted service accepts at capture.
 *
 * The opposite direction is NOT a sound check on its own. A token obtained by
 * retryPendingAttestations() legitimately carries a genTime hours after
 * capture, so a large positive skew cannot distinguish backdating from a
 * retried attestation. The skew is therefore REPORTED rather than judged, and
 * backdating is caught independently by chain monotonicity, which needs no TSA.
 */
import { createHash } from 'crypto';
import { verifyAttestation } from '../../src/attestation/verify-attestation';
import { makeTsaFixture } from './rfc3161-fixture';
import type { AttestationArtifacts } from '@tzun/engine';

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
const DIGEST = sha256('captured-at-vs-gentime');

describe('capturedAt is checked against the TSA genTime that notarised it', () => {
  const genTime = new Date('2026-09-17T12:00:00.000Z');

  // A genuine TimeStampResp over DIGEST whose TSTInfo genTime is exactly
  // genTime, from the offline authority the rfc3161 suites use, so the token
  // is read by the real code path rather than a stub.
  let token: string;
  beforeAll(async () => {
    token = (await makeTsaFixture({ digestHex: DIGEST, genTime })).tokenBase64;
  });

  const artifacts = (): AttestationArtifacts => ({ rfc3161Token: token }) as AttestationArtifacts;

  it('accepts a capturedAt a moment before the TSA stamped it', async () => {
    // The honest shape: mint capturedAt, build the record, round-trip to the
    // TSA. genTime trails capturedAt by the network latency.
    const capturedAt = new Date(genTime.getTime() - 800).toISOString();
    const result = await verifyAttestation(artifacts(), DIGEST, undefined, {
      timestampVerification: 'structural',
      capturedAt,
    });
    expect(result.timestampValid).toBe(true);
    expect(result.capturedAtReason).toBeUndefined();
  });

  it('rejects a capturedAt LATER than the genTime that notarised it', async () => {
    // Impossible honestly: the token is over a digest that commits to
    // capturedAt, so capturedAt existed before the stamp. A record claiming
    // otherwise was minted on a clock running ahead.
    const capturedAt = new Date(genTime.getTime() + 60 * 60 * 1000).toISOString();
    const result = await verifyAttestation(artifacts(), DIGEST, undefined, {
      timestampVerification: 'structural',
      capturedAt,
    });
    expect(result.capturedAtValid).toBe(false);
    expect(result.capturedAtReason).toBe('captured_after_timestamp');
  });

  it('tolerates sub-second forward skew rather than failing on clock jitter', async () => {
    const capturedAt = new Date(genTime.getTime() + 250).toISOString();
    const result = await verifyAttestation(artifacts(), DIGEST, undefined, {
      timestampVerification: 'structural',
      capturedAt,
    });
    expect(result.capturedAtValid).toBe(true);
  });

  it('tolerates a clock up to 5 minutes fast, the skew the hosted service accepts at capture', async () => {
    // A cloud record the platform accepted must not be flagged by a
    // verifier running the same rule a layer later.
    const capturedAt = new Date(genTime.getTime() + 4 * 60 * 1000 + 59 * 1000).toISOString();
    const result = await verifyAttestation(artifacts(), DIGEST, undefined, {
      timestampVerification: 'structural',
      capturedAt,
    });
    expect(result.capturedAtValid).toBe(true);
  });

  it('flags a clock running more than 5 minutes fast', async () => {
    const capturedAt = new Date(genTime.getTime() + 5 * 60 * 1000 + 1000).toISOString();
    const result = await verifyAttestation(artifacts(), DIGEST, undefined, {
      timestampVerification: 'structural',
      capturedAt,
    });
    expect(result.capturedAtValid).toBe(false);
    expect(result.capturedAtReason).toBe('captured_after_timestamp');
  });

  it('reports the skew without judging it, so a retried attestation is not called a forgery', async () => {
    // retryPendingAttestations() can stamp a record hours after capture. That
    // is a large positive skew and it is legitimate, so the verifier surfaces
    // the magnitude and declines to rule.
    const capturedAt = new Date(genTime.getTime() - 6 * 60 * 60 * 1000).toISOString();
    const result = await verifyAttestation(artifacts(), DIGEST, undefined, {
      timestampVerification: 'structural',
      capturedAt,
    });
    expect(result.capturedAtValid).toBe(true);
    expect(result.capturedAtSkewMs).toBe(6 * 60 * 60 * 1000);
  });

  it('says nothing about capturedAt when the caller supplied none', async () => {
    // Additive: every existing caller passes no capturedAt and must be
    // unaffected — not silently downgraded to "unchecked means invalid".
    const result = await verifyAttestation(artifacts(), DIGEST, undefined, {
      timestampVerification: 'structural',
    });
    expect(result.timestampValid).toBe(true);
    expect(result.capturedAtValid).toBeNull();
    expect(result.capturedAtReason).toBeUndefined();
  });

  it('cannot check capturedAt with no token, and says so rather than passing it', async () => {
    const result = await verifyAttestation({} as AttestationArtifacts, DIGEST, undefined, {
      capturedAt: new Date().toISOString(),
    });
    expect(result.timestampValid).toBeNull();
    expect(result.capturedAtValid).toBeNull();
    expect(result.capturedAtReason).toBe('no_timestamp_to_compare');
  });

  it('returns a verdict rather than throwing on an unparsable capturedAt', async () => {
    // capturedAt reaches here as client-supplied JSON like everything else
    //. A malformed value is a reported reason, never a throw.
    for (const bad of ['not-a-date', '', 123 as unknown as string, null as unknown as string]) {
      const result = await verifyAttestation(artifacts(), DIGEST, undefined, {
        timestampVerification: 'structural',
        capturedAt: bad,
      });
      expect(result.capturedAtValid).toBe(false);
      expect(result.capturedAtReason).toBe('unparsable_captured_at');
    }
  });

  it('derives genTime from the TOKEN, not from the unhashed parsed metadata', async () => {
    // rfc3161Metadata lives under nonRepudiation, which is OUTSIDE the hashed
    // field set — a store-writer can edit the parsed copy. The token is
    // TSA-signed, so it is the only trustworthy source. A record whose metadata
    // has been doctored to excuse a bad capturedAt must still fail.
    const capturedAt = new Date(genTime.getTime() + 60 * 60 * 1000).toISOString();
    const doctored = {
      rfc3161Token: token,
      rfc3161Metadata: { genTime: capturedAt, status: 'granted' },
    } as unknown as AttestationArtifacts;

    const result = await verifyAttestation(doctored, DIGEST, undefined, {
      timestampVerification: 'structural',
      capturedAt,
    });
    expect(result.capturedAtValid).toBe(false);
    expect(result.capturedAtReason).toBe('captured_after_timestamp');
  });
});
