/**
 * The revision log changes NOTHING on the wire.
 *
 * The log is a second table beside the evidence, never a field inside it. That
 * is the load-bearing property of the whole design: the hashed field set, the
 * canonical bytes, the digest, the chain link and the envelope shape are the
 * cross-language contract (`python/src/tzun_sdk`, the platform backend, every
 * RFC 3161 token and Merkle anchor already issued), and the revision log must
 * move none of them. A defence that moved any of them would invalidate every
 * attestation in existence in order to catch a tamper — a cure worse than the
 * disease.
 *
 * This file asserts that, rather than leaving it to be believed. The integrity
 * corpus (`vectors/v1.0-integrity-vectors.json`) is run here as well as from
 * the Python cross-SDK suite, so a TS-side digest or canonicalization change
 * fails in the TS suite too.
 */
import integrityVectors from '../../vectors/v1.0-integrity-vectors.json';
import { Tzun } from '../../src/sdk/index';
import {
  EvidenceChain,
  SchemaRegistry,
  canonicalSerialize,
  computeDigest,
} from '@tzun/engine';

interface DigestVector {
  id: string;
  kind: 'digest';
  canonical?: string;
  input?: Record<string, unknown>;
  hashedFields?: string[];
  expectedCanonical?: string;
  expectedDigest: string;
}
interface ChainLinkVector {
  id: string;
  kind: 'chain-link';
  previousDigest: string | null;
  currentDigest: string;
  expectedChainLink: string | null;
}
type Vector = DigestVector | ChainLinkVector;

const vectors = integrityVectors.vectors as unknown as Vector[];

describe('no hashed-field, digest, canonicalization or envelope wire change', () => {
  it("v1.0's hashed field set is exactly the eleven documented fields, in order", () => {
    // The revision log records the digest; it never participates in it. If
    // this list gains a field, every digest, RFC 3161 token and Merkle anchor
    // already issued stops verifying — which is why CONTRIBUTING.md calls v1.0
    // frozen at first customer deployment and why the field set is pinned
    // here beside the feature that might have been tempted to add to it (a
    // `revisionNo` in the payload, say).
    expect(new SchemaRegistry().get('v1.0')!.hashedFieldSet).toEqual([
      'action',
      'aiOutput',
      'aiSystemId',
      'capturedAt',
      'contributions',
      'decider',
      'evidenceId',
      'links',
      'reason',
      'sequenceNumber',
      'signoffExpectation',
    ]);
  });

  it('the envelope and its integrity block carry no new field', async () => {
    const tzun = await Tzun.init();
    try {
      const { envelope } = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { recommendation: 'approve' },
        action: 'approved',
        reason: 'All criteria met',
      });
      expect(Object.keys(envelope).sort()).toEqual([
        'attestationStatus',
        'custodyChain',
        'envelopeVersion',
        'integrity',
        'nonRepudiation',
        'payload',
      ]);
      // Two fields, and only two. A `capturedDigest` or `revisionNo` here
      // would be a wire change dressed up as a defence — and a self-attested
      // one at that, since an attacker rewriting the payload would rewrite it
      // in the same UPDATE. The whole point of a separate append-only table
      // is that it is not inside the blob the attacker is editing.
      expect(Object.keys(envelope.integrity).sort()).toEqual(['canonicalDigest', 'chainLink']);
      expect(Object.keys(envelope.payload).sort()).toEqual([
        'action',
        'aiOutput',
        'aiSystemId',
        'capturedAt',
        'contributions',
        'decider',
        'evidenceId',
        'links',
        'reason',
        'schemaVersion',
        'sequenceNumber',
        'signoffExpectation',
      ]);
      expect(envelope.envelopeVersion).toBe('e1');
    } finally {
      await tzun.close();
    }
  });

  it.each(vectors.filter((v): v is DigestVector => v.kind === 'digest'))(
    'integrity vector $id still produces its pinned canonical bytes and digest',
    (vector) => {
      const canonical =
        vector.canonical ??
        canonicalSerialize(vector.input as Record<string, unknown>, vector.hashedFields!);
      if (vector.expectedCanonical !== undefined) {
        expect(canonical).toBe(vector.expectedCanonical);
      }
      expect(computeDigest(canonical)).toBe(vector.expectedDigest);
    },
  );

  it.each(vectors.filter((v): v is ChainLinkVector => v.kind === 'chain-link'))(
    'integrity vector $id still produces its pinned chain link',
    (vector) => {
      const chain = new EvidenceChain();
      if (vector.previousDigest !== null) chain.restore(vector.previousDigest);
      expect(chain.computeLink(vector.currentDigest)).toBe(vector.expectedChainLink);
    },
  );

  it('the digest of a fixed payload is pinned', () => {
    // A belt-and-braces pin, hard-coded here, so the invariance claim does not
    // rest on the corpus files staying put either.
    const payload = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      links: null,
      evidenceId: '00000000-0000-4000-8000-000000000001',
      schemaVersion: 'v1.0',
      aiSystemId: 'wire-invariance',
      aiOutput: { recommendation: 'approve', confidence: 0.94 },
      action: 'approved',
      reason: 'All criteria met',
      capturedAt: '2026-09-12T10:00:00.000Z',
      sequenceNumber: 7,
      contributions: null,
      signoffExpectation: null,
    };
    const schema = new SchemaRegistry().get('v1.0')!;
    const canonical = canonicalSerialize(payload, schema.hashedFieldSet);
    expect(canonical).toBe(
      '{"action":"approved","aiOutput":{"confidence":0.94,"recommendation":"approve"},' +
        '"aiSystemId":"wire-invariance","capturedAt":"2026-09-12T10:00:00.000Z","contributions":null,' +
        '"decider":{"agent":null,"credential":null,"freshness":null,"id":"acct:u-test","kind":"human"},' +
        '"evidenceId":"00000000-0000-4000-8000-000000000001","links":null,' +
        '"reason":"All criteria met","sequenceNumber":7,"signoffExpectation":null}',
    );
    expect(computeDigest(canonical)).toBe(FIXED_PAYLOAD_DIGEST);
  });
});

/**
 * SHA-256 of the canonical bytes above, produced twice and independently: by
 * the engine, and by `printf '%s' <bytes> | sha256sum`, which involves no code
 * from this repository at all. If both this constant and the literal bytes
 * above have to change, that is a wire break, and nothing but a decision to
 * change the v1.0 hashed field set is entitled to cause one.
 */
const FIXED_PAYLOAD_DIGEST = 'ddcb03287e72380d6f17ee5ac4aac0fdb1a9c67230b4792a763f802a88087997';
