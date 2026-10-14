/**
 * What the v1.0 record vector generators share: the comparison that stops a
 * generator when the engine disagrees with the answer written from the rule,
 * the example identities and digests, a builder for whole v1.0 payloads and
 * envelopes, WebAuthn assertions that present a chosen challenge, and the
 * worked example W4's mandate material.
 *
 * Not a generator itself: scripts/regenerate-vectors.ts lists the generators
 * it runs by name.
 */
import { createHash, createPrivateKey, sign } from 'node:crypto';
import {
  V1_0_HASHED_FIELDS,
  canonicalSerialize,
  canonicalSerializeValue,
  determineAttestationStatus,
  webauthnChallengeForDigest,
  type AiBom,
  type EvidenceEnvelope,
  type MandateDocument,
  type MandateStatement,
  type WebauthnAssertion,
} from '@tzun/engine';

/** The v1.0 hashed field set as revised in 0.8.0: eleven names in byte order. */
export const FIELDS: string[] = [...V1_0_HASHED_FIELDS];

export const sha256Hex = (data: string | Buffer): string => createHash('sha256').update(data).digest('hex');
/** `sha256:` and the hex SHA-256 of the canonical bytes of a whole value (an output or step digest). */
export const prefixed = (value: unknown): string => 'sha256:' + sha256Hex(canonicalSerializeValue(value));
/** The bare record digest of a payload under the v1.0 hashed field set. */
export const recordDigest = (payload: unknown): string =>
  sha256Hex(canonicalSerialize(payload as Record<string, unknown>, FIELDS));

/**
 * A JSON text of `value` with every object's keys sorted, `undefined` members
 * dropped (as JSON.stringify drops them): two values with the same members
 * in another order compare equal.
 */
export function stable(value: unknown): string {
  return JSON.stringify(value, (_key, v) => {
    if (v === null || typeof v !== 'object' || Array.isArray(v)) return v;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) out[k] = (v as Record<string, unknown>)[k];
    return out;
  });
}

/** A generator's stop and agree: `agree` stops the generator when the engine's answer is not the rule's. */
export function checker(generator: string) {
  const stop = (message: string): never => {
    process.stderr.write(`${generator}: ${message}\n`);
    process.exit(1);
  };
  const agree = (label: string, engine: unknown, expected: unknown): void => {
    if (stable(engine) !== stable(expected)) {
      stop(`${label}: the engine says ${stable(engine)}, the rule says ${stable(expected)}`);
    }
  };
  return { stop, agree };
}

/**
 * A value written into a vector file as the JSON text given, verbatim: for
 * numbers whose spelling matters (`1e+20` parses as a float in every
 * language; `100000000000000000000`, which JSON.stringify writes for it,
 * parses as an integer in Python).
 */
export class RawJson {
  readonly value: unknown;
  constructor(readonly text: string) {
    this.value = JSON.parse(text);
  }
}

/**
 * JSON text with two-space indentation, except that an array holding only
 * strings, numbers, booleans and nulls is written on one line: the files
 * hold arrays of thousands of such elements (limits are tested at their
 * bound), and one per line would multiply their size for no reader's sake.
 * A `RawJson` value is written as its text.
 */
export function formatVectorFile(value: unknown): string {
  const write = (v: unknown, depth: number): string => {
    if (v instanceof RawJson) return v.text;
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    const pad = '  '.repeat(depth + 1);
    const close = '  '.repeat(depth);
    if (Array.isArray(v)) {
      if (v.length === 0) return '[]';
      if (v.every((e) => e === null || typeof e !== 'object')) return JSON.stringify(v);
      return '[\n' + v.map((e) => pad + write(e === undefined ? null : e, depth + 1)).join(',\n') + '\n' + close + ']';
    }
    const entries = Object.entries(v as Record<string, unknown>).filter(([, e]) => e !== undefined);
    if (entries.length === 0) return '{}';
    return '{\n' + entries.map(([k, e]) => `${pad}${JSON.stringify(k)}: ${write(e, depth + 1)}`).join(',\n') + '\n' + close + '}';
  };
  return write(value, 0) + '\n';
}

/** Print a vector file (`formatVectorFile`) on stdout. */
export function emit(file: unknown): void {
  process.stdout.write(formatVectorFile(file));
}

// ── Example identities and digests ───────────────────────────────────────

/** The example agent descriptor's digest (729 canonical bytes; vectors/v1.0-worked-example-vectors.json). */
export const AGENT = 'sha256:eed92bfa7577d6f66e26fed38c35ebbec3b663a25fd6cc4c6af7d8c7475a250f';
/** A second agent descriptor digest, never resolved. */
export const AGENT_B = 'sha256:' + 'b2'.repeat(32);
/** The example model descriptor digest. */
export const MODEL = 'sha256:6c9556bc8e35e7701b44ecee10c605a4db9fdf082e6856681db7d7dd1ca3a947';
export const MODEL_B = 'sha256:' + '0b'.repeat(32);
/** An evidence-log origin of a store in a `test.` namespace (chain `lending`). */
export const LENDER_ORIGIN = 'test.lender.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/evidence/6c656e64696e67';
/** Another store's origin (chain `claims`). */
export const CLAIMS_ORIGIN = 'test.insurer.example/9a8b7c6d5e4f30211203f4e5d6c7b8a9/evidence/636c61696d73';
/** An RFC 7638 thumbprint (43 base64url characters): RFC 8037 Appendix A's key. */
export const JKT = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k';
export const SPIFFE = 'spiffe://claims.example/agent/triage';
export const ACCT = 'acct:u-4821';
/** A commitment identifier (any 64 lowercase hex is one; this one opens to ACCT under salt 0x00..0x1f). */
export const CMT = 'cmt:68912cfb4b69d6b38fa0b954aa41794a8e1359afc929ee1147a4fc94ef4c14d9';
export const BLOCK_HASH = '0x' + '8ae3e2d5ddeee120de1e2e58f78ed0ed9c7b7ead28098938757d597d09c3f64c';
export const FRESHNESS = `eip155:1@9123456:${BLOCK_HASH}`;
export const POLICY = createHash('sha256').update('vector policy').digest('hex');
export const OTHER = createHash('sha256').update('another digest').digest('hex');

/** A bare digest from a label, for targets that need only to be well formed. */
export const digestOf = (label: string): string => sha256Hex(`vector ${label}`);

type InferenceParameters = NonNullable<AiBom['inferenceParameters']>;
/** An exact AiBom naming `md`, every nullable member written. */
export const bom = (md: string = MODEL, ip: InferenceParameters | null = null): AiBom => ({
  modelDescriptorDigest: md,
  vendorFingerprint: null,
  promptTemplate: null,
  inferenceParameters: ip,
  infrastructure: null,
});

export const human = (id: string = ACCT) => ({ kind: 'human' as const, id, agent: null, credential: null, freshness: null });
export const agentDecider = (kind: 'agent' | 'agent-mandated' | 'policy-engine' = 'agent', agent: string = AGENT) => ({
  kind,
  id: `desc:${agent}`,
  agent,
  credential: null,
  freshness: null,
});

let evidenceCounter = 0;
/** A fresh v4 evidence id, in sequence, so a file regenerates byte for byte. */
export function nextEvidenceId(prefix = '00000000-0000-4000-8000'): string {
  evidenceCounter++;
  return `${prefix}-${String(evidenceCounter).padStart(12, '0')}`;
}

/**
 * A whole v1.0 payload, every one of its twelve keys written: a human's
 * decision with no contributions, no links and no expectation, unless
 * `overrides` says otherwise. It is not checked: reader vectors hold payloads
 * a writer refuses.
 */
export function payload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    evidenceId: nextEvidenceId(),
    schemaVersion: 'v1.0',
    aiSystemId: 'vectors',
    aiOutput: { recommendation: 'approve', score: 82 },
    action: 'approve',
    reason: 'Reviewed',
    capturedAt: '2026-10-05T10:00:00.000Z',
    sequenceNumber: 1,
    decider: human(),
    contributions: null,
    links: null,
    signoffExpectation: null,
    ...overrides,
  };
}

/**
 * An envelope around `p`: its digest under the v1.0 hashed field set, no chain
 * link (a genesis record when its sequence number is 1), `nonRepudiation` as
 * given, and no custody entry. `nonRepudiation` may be a function of the
 * digest, for material that must bind to it.
 */
export function envelope(
  p: Record<string, unknown>,
  nonRepudiation: Record<string, unknown> | ((digest: string) => Record<string, unknown>) = {},
): EvidenceEnvelope {
  const digest = recordDigest(p);
  const nr = typeof nonRepudiation === 'function' ? nonRepudiation(digest) : nonRepudiation;
  return {
    envelopeVersion: 'e1',
    payload: p,
    integrity: { canonicalDigest: digest, chainLink: null },
    nonRepudiation: nr,
    custodyChain: [],
    attestationStatus: determineAttestationStatus(nr as EvidenceEnvelope['nonRepudiation'], digest),
  } as unknown as EvidenceEnvelope;
}

// ── WebAuthn material ─────────────────────────────────────────────────────

/**
 * An assertion whose `clientDataJSON` presents `challenge`. The signature is a
 * placeholder: the keyless checks read which challenge an assertion presents,
 * never whether a signature verifies.
 */
export function assertionPresenting(challenge: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const clientDataJSON = Buffer.from(
    JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://rp.example', crossOrigin: false }),
  ).toString('base64url');
  return {
    signature: Buffer.from(createHash('sha256').update(`signature over ${challenge}`).digest()).toString('base64url'),
    credentialKeyId: 'credential-1',
    algorithm: 'Ed25519',
    authenticatorData: Buffer.concat([createHash('sha256').update('rp.example').digest(), Buffer.from([0x05, 0, 0, 0, 1])]).toString(
      'base64url',
    ),
    clientDataJSON,
    ...extra,
  };
}

/** The per-record assertion over the record whose digest is `digest`. */
export const recordAssertion = (digest: string) => assertionPresenting(webauthnChallengeForDigest(digest));

// ── W4: the mandate document, statement and assertion ───────────────────

/** RFC 8037 Appendix A's Ed25519 key: Ed25519 signs deterministically, so the assertion is reproducible. */
const RFC8037_KEY = createPrivateKey({
  key: { kty: 'OKP', crv: 'Ed25519', d: 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' },
  format: 'jwk',
});

/** A real Ed25519 assertion by the RFC 8037 key over `challenge`, as the worked example W4 builds it. */
export function signedAssertion(challenge: string, rpId = 'demo.tzun.ai'): WebauthnAssertion {
  const authData = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([0x05, 0, 0, 0, 1])]);
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: `https://${rpId}`, crossOrigin: false }));
  const signature = sign(null, Buffer.concat([authData, createHash('sha256').update(clientData).digest()]), RFC8037_KEY);
  return {
    signature: signature.toString('base64url'),
    credentialKeyId: JKT,
    algorithm: 'Ed25519',
    authenticatorData: authData.toString('base64url'),
    clientDataJSON: clientData.toString('base64url'),
  };
}

/** W4's mandate document, the example of Record §9.7: an opaque principal, no policy digest. */
export const W4_DOCUMENT: MandateDocument = {
  v: 'tzun-mandate/1',
  mandateId: '6b1f0e2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b',
  principal: { signer: 'user-2c9d', credential: null },
  agents: [`desc:${AGENT}`],
  schemaVersion: 'v1.0',
  scope: {
    aiSystemIds: ['claims-triage-v4'],
    actions: ['approve', 'refer'],
    models: [MODEL],
    predicates: { cap: { op: 'le', path: '/aiOutput/amountMinor', quant: null, value: 500000 } },
  },
  confirm: { fraud: { op: 'eq', path: '/aiOutput/fraudFlag', quant: null, value: true } },
  validity: { notBefore: '2026-10-01T00:00:00.000Z', notAfter: '2026-12-31T23:59:59.999Z' },
  limits: { maxRecords: 10000, cumulative: { paid: { path: '/aiOutput/amountMinor', max: 250000000 } } },
  delegation: { allowed: false, maxDepth: 0, attenuation: 'subset' },
  review: { maxAgeMs: 604800000 },
  policyDigest: null,
  predecessor: null,
  parent: null,
} as unknown as MandateDocument;
export const W4_MANDATE_DIGEST = sha256Hex(canonicalSerializeValue(W4_DOCUMENT));
export const W4_STATEMENT: MandateStatement = {
  v: 'tzun-signoff-mandate/1',
  mode: 'mandate',
  mandateDigest: W4_MANDATE_DIGEST,
  signer: 'user-2c9d',
  signerKind: 'human',
  meaning: 'responsibility',
  policyDigest: 'none',
  notBefore: 'eip155:1@23400000:0x9709713cdb609ef086959f42eb4a56159cb9ac637e3f32fb381796e68b2c7efb',
} as unknown as MandateStatement;
export const W4_STATEMENT_DIGEST = sha256Hex(canonicalSerializeValue(W4_STATEMENT));
export const W4_CHALLENGE = createHash('sha256').update('tzun-signoff-v1' + W4_STATEMENT_DIGEST).digest('base64url');
export const W4_ASSERTION = signedAssertion(W4_CHALLENGE);
/** `hex(SHA-256("tzun-assertion-v1" ‖ SHA-256(authenticatorData) ‖ SHA-256(clientDataJSON) ‖ SHA-256(signature)))`, Ed25519 as given. */
export function assertionDigestOf(a: { authenticatorData?: string; clientDataJSON?: string; signature: string }, signature?: Buffer): string {
  return createHash('sha256')
    .update('tzun-assertion-v1', 'utf8')
    .update(createHash('sha256').update(Buffer.from(a.authenticatorData ?? '', 'base64url')).digest())
    .update(createHash('sha256').update(Buffer.from(a.clientDataJSON ?? '', 'base64url')).digest())
    .update(createHash('sha256').update(signature ?? Buffer.from(a.signature, 'base64url')).digest())
    .digest('hex');
}
export const W4_ASSERTION_DIGEST = assertionDigestOf(W4_ASSERTION as { authenticatorData: string; clientDataJSON: string; signature: string });
/** W4's mandate block: what a record under the mandate, and the issuance record, carry. */
export const W4_BLOCK = { statement: W4_STATEMENT, assertion: W4_ASSERTION, assertionTimestamp: null, document: W4_DOCUMENT };

/** The confirmation challenge of a record's digest: `B64URL(SHA-256("tzun-confirm-v1" ‖ digest))`. */
export const confirmationChallengeOf = (digest: string): string =>
  createHash('sha256').update('tzun-confirm-v1' + digest).digest('base64url');

/**
 * Sentinels for values JSON text does not carry: a harness substitutes them
 * before it hashes or checks (the convention of v1.0-canonical-vectors.json).
 */
export const LONE_SURROGATE = 'LONE_SURROGATE_D800';
