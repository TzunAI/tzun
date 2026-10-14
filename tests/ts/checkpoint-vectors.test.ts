/**
 * tzun-anchor/1 §4 to §6, §10.3 steps 1 to 5, and §13: the SDK against
 * vectors/checkpoint-vectors.json.
 *
 * The vectors are an INDEPENDENT pin: scripts/generate-checkpoint-vectors.mjs
 * imports nothing but node:crypto and hand-writes base64, UTF-8 and the RFC
 * 6962 recursion. Nothing here may regenerate them from the code under test.
 */
import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  buildMerkleTree,
  getConsistencyProof,
  getMerkleRoot,
  verifyConsistencyProof,
} from '../../src/attestation/merkle';
import {
  chainIdFromSegment,
  chainSegment,
  checkOriginBinding,
  checkpointDigest,
  evidenceLogOrigin,
  formatCheckpoint,
  isPlatformNamespace,
  parseCheckpoint,
  parseOrigin,
} from '../../src/attestation/checkpoint';
import { verifyAnchor } from '../../src/attestation/anchor-verify';

interface Vectors {
  format: Record<string, string>;
  bodies: {
    valid: Array<{ case: string; origin: string; size: number; root: string; body: string; checkpointDigest: string }>;
    invalid: Array<{ case: string; body: string; c2spConforming: boolean; stockParserAccepts: boolean }>;
    nonString: unknown[];
  };
  chainSegments: {
    valid: Array<{ case: string; chainId: string; segment: string }>;
    invalid: Array<{ case: string; segment: string }>;
    unencodable: Array<{ case: string; chainId: string }>;
  };
  domain: Array<{
    case: string;
    anchorOrigin: string;
    logOrigin: string;
    chainId: string | null;
    expect: { result: 'ok' | 'origin_not_in_domain' | 'chain_id_mismatch'; namespace?: string; chainChecked?: boolean };
  }>;
  anchorLog: {
    domainPrefix: string;
    sourceLogs: Record<string, { key: string; leaves: string[] }>;
    epochs: Array<{
      epoch: string;
      members: Array<{ origin: string; size: number; root: string; body: string; checkpointDigest: string; anchorLeafIndex: number }>;
      anchorOrigin: string;
      anchorSize: number;
      anchorRoot: string;
      anchorCheckpoint: string;
      p: string;
    }>;
    anchorLeaves: string[];
    anchorConsistency: { first: number; second: number; firstRoot: string; secondRoot: string; proof: string[] };
  };
  artifacts: Array<{
    case: string;
    digest: string;
    sequenceNumber: number | null;
    chainId: string | null;
    artifacts: Record<string, unknown>;
    expect: {
      anchorValid: boolean | null;
      reason?: string;
      merkleProofValid: boolean | null;
      p: string | null;
      anchorPosition?: Record<string, unknown>;
      anchorNamespace: 'test' | null;
      /** tzun-anchor/1 §10.7, as a report carries it. */
      checks: Array<{ id: string; outcome: string; reason?: string; facts?: Record<string, unknown> }>;
    };
  }>;
}

const vectors: Vectors = JSON.parse(readFileSync(join(__dirname, '../../vectors/checkpoint-vectors.json'), 'utf8'));

describe('checkpoint bodies (vectors)', () => {
  it.each(vectors.bodies.valid.map((v) => [v.case, v] as const))('reads and writes: %s', (_name, v) => {
    const parsed = parseCheckpoint(v.body);
    expect(parsed).toEqual({ ok: true, checkpoint: { origin: v.origin, size: v.size, root: v.root, body: v.body } });
    expect(formatCheckpoint(v.origin, v.size, v.root)).toBe(v.body);
    expect(checkpointDigest(v.body)).toBe(v.checkpointDigest);
  });

  it.each(vectors.bodies.invalid.map((v) => [v.case, v] as const))('refuses: %s', (_name, v) => {
    expect(parseCheckpoint(v.body).ok).toBe(false);
    expect(() => checkpointDigest(v.body)).toThrow();
  });

  it('refuses every body that is not a string', () => {
    for (const body of vectors.bodies.nonString) {
      expect(parseCheckpoint(body)).toEqual({ ok: false, reason: 'not_a_string' });
    }
  });

  it('covers the body refusals of Anchor §4.2', () => {
    const names = vectors.bodies.invalid.map((v) => v.case).join('\n');
    for (const needle of ['CRLF', 'no final newline', 'leading zero', 'non-canonical base64', 'an extension line']) {
      expect(names).toContain(needle);
    }
    expect(vectors.chainSegments.invalid.map((v) => v.case)).toContain('uppercase hex');
    expect(vectors.domain.some((d) => d.expect.result === 'origin_not_in_domain')).toBe(true);
  });
});

/**
 * The two readings each invalid body records, transcribed a second time from
 * their sources with Node's Buffer, not the generator's hand-written base64.
 */
function c2spConforming(body: string): boolean {
  // signed-note v1.0.0: valid UTF-8, no character below U+0020 but LF, a final LF.
  if (Buffer.from(body, 'utf8').toString('utf8') !== body) return false;
  if (/[\u0000-\u0009\u000b-\u001f]/.test(body) || !body.endsWith('\n')) return false;
  // tlog-checkpoint: three or more lines, none empty; decimal size without a
  // leading zero; the padded base64 of a 32-byte root, the empty tree's at size 0.
  const lines = body.slice(0, -1).split('\n');
  if (lines.length < 3 || lines.includes('')) return false;
  const [, size, root] = lines;
  if (!/^(?:0|[1-9]\d*)$/.test(size)) return false;
  const bytes = Buffer.from(root, 'base64');
  if (bytes.length !== 32 || bytes.toString('base64') !== root) return false;
  return size !== '0' || bytes.equals(createHash('sha256').digest());
}

/** transparency-dev/formats log.Checkpoint.Unmarshal at v0.1.1: no error. */
function stockParserAccepts(body: string): boolean {
  // bytes.SplitN(data, "\n", 4) gives four parts exactly when there are three LFs or more.
  const [origin, size, root, ...rest] = body.split('\n');
  if (rest.length === 0 || origin === '') return false;
  // strconv.ParseUint(size, 10, 64).
  if (!/^\d+$/.test(size) || BigInt(size) >= 1n << 64n) return false;
  // base64.StdEncoding.DecodeString: CR and LF skipped, whole quanta, padding at the end only.
  const text = root.replace(/[\r\n]/g, '');
  return text.length % 4 === 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(text);
}

describe('what C2SP and the stock parser make of each body (vectors)', () => {
  it('names the stock parser and the version it pins', () => {
    expect(vectors.format.stockParserAccepts).toContain('transparency-dev/formats log.Checkpoint.Unmarshal at v0.1.1');
    expect(vectors.format.c2spConforming).toContain('signed-note v1.0.0');
    expect(vectors.format).not.toHaveProperty('tzunOnly');
  });

  it.each(vectors.bodies.invalid.map((v) => [v.case, v] as const))('both flags recompute: %s', (_name, v) => {
    expect(v).not.toHaveProperty('tzunOnly');
    expect(v.c2spConforming).toBe(c2spConforming(v.body));
    expect(v.stockParserAccepts).toBe(stockParserAccepts(v.body));
  });

  it('every valid body is conforming C2SP that the stock parser reads', () => {
    for (const v of vectors.bodies.valid) {
      expect([v.case, c2spConforming(v.body), stockParserAccepts(v.body)]).toEqual([v.case, true, true]);
    }
  });

  it('the two readings are independent: every combination occurs', () => {
    const seen = new Set(vectors.bodies.invalid.map((v) => `${v.c2spConforming}/${v.stockParserAccepts}`));
    expect([...seen].sort()).toEqual(['false/false', 'false/true', 'true/false', 'true/true']);
  });
});

describe('chain segments (vectors)', () => {
  it.each(vectors.chainSegments.valid.map((v) => [v.case, v] as const))('both ways: %s', (_name, v) => {
    expect(chainSegment(v.chainId)).toBe(v.segment);
    expect(chainIdFromSegment(v.segment)).toBe(v.chainId);
    expect(evidenceLogOrigin(vectors.anchorLog.domainPrefix, v.chainId)).toBe(
      `${vectors.anchorLog.domainPrefix}/evidence/${v.segment}`,
    );
  });

  it.each(vectors.chainSegments.invalid.map((v) => [v.case, v] as const))('refuses: %s', (_name, v) => {
    expect(chainIdFromSegment(v.segment)).toBeNull();
  });

  it.each(vectors.chainSegments.unencodable.map((v) => [v.case, v] as const))('cannot encode: %s', (_name, v) => {
    expect(() => chainSegment(v.chainId)).toThrow();
  });
});

describe('the domain rule, Anchor §10.3 step 2b (vectors)', () => {
  it.each(vectors.domain.map((v) => [v.case, v] as const))('%s', (_name, v) => {
    const got = checkOriginBinding(v.anchorOrigin, v.logOrigin, v.chainId);
    if (v.expect.result === 'ok') {
      expect(got).toEqual({ ok: true, namespace: v.expect.namespace, chainChecked: v.expect.chainChecked });
    } else {
      expect(got).toEqual({ ok: false, reason: v.expect.result });
    }
  });
});

// With a chain id, a source log that is not an evidence log binds exactly when
// its namespace is the platform's: isPlatformNamespace is that half of the rule.
describe("the platform's namespaces, read off the domain vectors", () => {
  const opaque = vectors.domain.filter((v) => v.chainId !== null && v.expect.result !== 'origin_not_in_domain' && parseOrigin(v.logOrigin)?.kind === 'log');

  it('the vectors hold both outcomes', () => {
    expect(opaque.some((v) => v.expect.result === 'ok')).toBe(true);
    expect(opaque.some((v) => v.expect.result === 'chain_id_mismatch')).toBe(true);
  });

  it.each(opaque.map((v) => [v.case, v] as const))('%s', (_name, v) => {
    expect(isPlatformNamespace(parseOrigin(v.logOrigin)!.namespace)).toBe(v.expect.result === 'ok');
  });
});

describe('the anchor log (vectors)', () => {
  const { sourceLogs, epochs, anchorLeaves, anchorConsistency } = vectors.anchorLog;

  it.each(epochs.map((e) => [e.epoch, e] as const))('epoch %s: members, order, the anchor checkpoint and P', (_name, e) => {
    // Members are appended in ascending bytewise origin order.
    const origins = e.members.map((m) => m.origin);
    expect(origins).toEqual([...origins].sort((x, y) => Buffer.compare(Buffer.from(x), Buffer.from(y))));

    for (const m of e.members) {
      const leaves = sourceLogs[m.origin].leaves.slice(0, m.size);
      const root = getMerkleRoot(buildMerkleTree(leaves));
      expect(root).toBe(m.root);
      expect(formatCheckpoint(m.origin, m.size, root)).toBe(m.body);
      expect(checkpointDigest(m.body)).toBe(m.checkpointDigest);
      expect(anchorLeaves[m.anchorLeafIndex]).toBe(m.checkpointDigest);
    }

    const anchorRoot = getMerkleRoot(buildMerkleTree(anchorLeaves.slice(0, e.anchorSize)));
    expect(anchorRoot).toBe(e.anchorRoot);
    expect(formatCheckpoint(e.anchorOrigin, e.anchorSize, anchorRoot)).toBe(e.anchorCheckpoint);
    expect(checkpointDigest(e.anchorCheckpoint)).toBe(e.p);
  });

  it('grows append-only between the two published sizes', () => {
    const c = anchorConsistency;
    const generated = getConsistencyProof(buildMerkleTree(anchorLeaves), c.first, c.second);
    expect(generated).toEqual({ ok: true, proof: c.proof });
    expect(verifyConsistencyProof(c.first, c.second, c.proof, c.firstRoot, c.secondRoot)).toEqual({
      valid: true,
      reason: null,
    });
  });
});

describe('verifyAnchor, steps 1 to 5, the step 6 dispatch and the check catalogue (vectors)', () => {
  it.each(vectors.artifacts.map((v) => [v.case, v] as const))('%s', async (_name, v) => {
    const got = await verifyAnchor(v.artifacts, v.digest, {
      ...(v.sequenceNumber !== null && { sequenceNumber: v.sequenceNumber }),
      ...(v.chainId !== null && { chainId: v.chainId }),
    });
    expect(got.anchorValid).toBe(v.expect.anchorValid);
    expect(got.anchorReason).toBe(v.expect.reason);
    expect(got.merkleProofValid).toBe(v.expect.merkleProofValid);
    expect(got.p).toBe(v.expect.p);
    // No case carries a publication that can be true.
    expect(got.anchorPublication).toBeNull();
    expect(got.anchorOriginAuthenticated).toBe(false);
    expect(got.existedBy).toBeNull();
    // Anchor §10.6: 'test' for a test origin whatever the verdict, so every case states it.
    expect(got.anchorNamespace).toBe(v.expect.anchorNamespace);
    if (v.expect.anchorPosition) {
      expect(got.anchorPosition).toEqual(v.expect.anchorPosition);
    } else {
      expect(got.anchorPosition).toBeNull();
    }
    // Anchor §10.7: every check, in report order, as a report carries it. `value` is
    // the SDK's boolean view of the outcome, which a report does not carry.
    expect(got.checks.map(({ value: _value, ...reported }) => reported)).toEqual(v.expect.checks);
    // Each publication's checks are its slice of the catalogue.
    expect(got.publications.flatMap((p) => p.checks)).toEqual(got.checks.filter((c) => /\[\d+\]$/.test(c.id)));
  });
});
