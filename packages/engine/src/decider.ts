/**
 * The decider member (Record §6): its grammar, its consistency, its
 * agreement with the signature expectation and with the material a capture
 * presents, identifier commitments, and the reader's `decider` row. One
 * implementation for every writer and reader in this repository.
 *
 * Writers refuse (`deciderViolation`, `deciderMaterialViolation`); readers
 * report (`checkDecider`). They differ on purpose in two places: a reader
 * abstains on a kind or an identifier scheme it does not implement, where a
 * writer refuses one.
 */
import { createHash, createHmac } from 'crypto';
import {
  BARE_DIGEST_RE,
  canonicalValue,
  hasExactKeys,
  isBareDigest,
  isPlainObject,
  isPrefixedDigest,
} from './record-rules-util';
import { assertionBindsDigest } from './webauthn-binding';
import { carriesBatchSignoff, signoffExpectationForm, signoffExpectationViolation } from './signoff-expectation';
import type { DeciderKind, DeciderOpening, DeciderViolation, DeciderViolationCode, FreshnessReference } from './types/decider';
import type { DeciderCheck } from './types/verification';

/** The kinds a 0.8.0 writer states. */
export const DECIDER_KINDS: readonly DeciderKind[] = Object.freeze(['human', 'agent', 'agent-mandated', 'policy-engine']);

/** The identifier schemes this version implements. */
export const DECIDER_SCHEMES: readonly string[] = Object.freeze(['acct', 'spiffe', 'jkt', 'desc', 'cmt']);

/** The members of a decider, all required. */
export const DECIDER_MEMBERS: readonly string[] = Object.freeze(['kind', 'id', 'agent', 'credential', 'freshness']);

/** An identifier: 3 to 1,024 characters of 0x21–0x7E, `<scheme>:<value>`, the scheme `[a-z][a-z0-9+.-]{0,15}`. */
const IDENTIFIER_RE = /^[a-z][a-z0-9+.-]{0,15}:[\x21-\x7e]+$/;
export const DECIDER_ID_MIN_LENGTH = 3;
export const DECIDER_ID_MAX_LENGTH = 1024;

/** `acct` value: the relying party's account id. No `@`, so an email address is refused. */
export const ACCT_VALUE_RE = /^[A-Za-z0-9._-]{1,128}$/;
/** `spiffe` value: `//<trust domain>/<path>`, the path one or more segments. */
const SPIFFE_VALUE_RE = /^\/\/[a-z0-9._-]{1,255}(\/[A-Za-z0-9._-]+)+$/;
/** `jkt` value: an RFC 7638 thumbprint, 43 characters of base64url. */
const JKT_VALUE_RE = /^[A-Za-z0-9_-]{43}$/;

/**
 * A finalized-block reference: `<CAIP-2 chain>@<block number>:0x<64 hex>`.
 * The block number is a safe integer with no leading zero; under the
 * `eip155` namespace the chain reference has no leading zero either, so one
 * chain has one spelling.
 */
export const FRESHNESS_REFERENCE_RE =
  /^([-a-z0-9]{3,8}):([-_a-zA-Z0-9]{1,32})@(0|[1-9][0-9]{0,15}):(0x[0-9a-f]{64})$/;
const EIP155_REFERENCE_RE = /^[1-9][0-9]{0,30}$/;

/** The domain separator of an identifier commitment (19 bytes). */
const COMMITMENT_DOMAIN = 'tzun-decider-cmt-v1';
/** The salt of an identifier commitment, in bytes. */
export const DECIDER_COMMITMENT_SALT_BYTES = 32;

const PERMITTED_SCHEMES: Readonly<Record<DeciderKind, readonly string[]>> = {
  human: ['acct', 'cmt'],
  agent: ['spiffe', 'jkt', 'desc', 'cmt'],
  'agent-mandated': ['spiffe', 'jkt', 'desc', 'cmt'],
  'policy-engine': ['spiffe', 'jkt', 'desc', 'cmt'],
};

export function isDeciderKind(value: unknown): value is DeciderKind {
  return typeof value === 'string' && (DECIDER_KINDS as readonly string[]).includes(value);
}

/** The scheme of an identifier that meets the general grammar, or `null`. */
export function identifierScheme(id: unknown): string | null {
  if (typeof id !== 'string' || id.length < DECIDER_ID_MIN_LENGTH || id.length > DECIDER_ID_MAX_LENGTH) return null;
  if (!IDENTIFIER_RE.test(id)) return null;
  return id.slice(0, id.indexOf(':'));
}

/**
 * Whether `id` meets the identifier grammar of its scheme, for a scheme this
 * version implements (the writer's rule). `desc` is checked against the agent
 * reference separately.
 */
export function isKnownSchemeIdentifier(id: string): boolean {
  const scheme = identifierScheme(id);
  if (scheme === null) return false;
  const value = id.slice(scheme.length + 1);
  switch (scheme) {
    case 'acct':
      return ACCT_VALUE_RE.test(value);
    case 'spiffe':
      return SPIFFE_VALUE_RE.test(value) && !value.split('/').slice(3).some((s) => s === '.' || s === '..');
    case 'jkt':
      return JKT_VALUE_RE.test(value);
    case 'desc':
      return isPrefixedDigest(value);
    case 'cmt':
      return BARE_DIGEST_RE.test(value);
    default:
      return false;
  }
}

/**
 * Parse a finalized-block reference, or `null` when it is not one: the
 * pattern above, a block number no greater than 2^53 − 1, and the `eip155`
 * reference rule.
 */
export function parseFreshnessReference(value: unknown): FreshnessReference | null {
  if (typeof value !== 'string') return null;
  const m = FRESHNESS_REFERENCE_RE.exec(value);
  if (m === null) return null;
  const [, namespace, reference, blockText, blockHash] = m;
  if (namespace === 'eip155' && !EIP155_REFERENCE_RE.test(reference)) return null;
  const blockNumber = Number(blockText);
  if (!Number.isSafeInteger(blockNumber)) return null;
  return { chain: `${namespace}:${reference}`, namespace, reference, blockNumber, blockHash };
}

/** Whether `value` is a finalized-block reference. */
export function isFreshnessReference(value: unknown): value is string {
  return parseFreshnessReference(value) !== null;
}

/** Format a finalized-block reference from its parts. @throws when the parts do not make one. */
export function formatFreshnessReference(chain: string, blockNumber: number, blockHash: string): string {
  const ref = `${chain}@${blockNumber}:${blockHash}`;
  if (!isFreshnessReference(ref)) {
    throw new Error('A freshness reference is a CAIP-2 chain, a safe block number and 0x followed by 64 lowercase hex.');
  }
  return ref;
}

const MESSAGES: Record<DeciderViolationCode, (field: string) => string> = {
  not_an_object: (f) => `${f} is required: an object with the members ${DECIDER_MEMBERS.join(', ')}`,
  unknown_members: (f) => `${f} may have only the members ${DECIDER_MEMBERS.join(', ')}`,
  missing_members: (f) => `${f} must have every member (${DECIDER_MEMBERS.join(', ')}), null where it does not apply`,
  invalid_kind: (f) => `${f} must be one of ${DECIDER_KINDS.join(', ')}`,
  invalid_identifier: (f) =>
    `${f} must be <scheme>:<value> of 3 to 1024 characters 0x21-0x7E, in one of the schemes ` +
    `${DECIDER_SCHEMES.join(', ')} and that scheme's value grammar (acct: [A-Za-z0-9._-]{1,128})`,
  scheme_not_permitted: (f) => `${f}: this identifier scheme is not permitted for this kind`,
  invalid_agent_reference: (f) => `${f} must be null or sha256: followed by 64 lowercase hex characters`,
  agent_reference_required: (f) => `${f} is required (an agent descriptor digest) for every kind but human`,
  agent_reference_forbidden: (f) => `${f} must be null for a human`,
  desc_identifier_mismatch: (f) => `${f}: a desc identifier must name the agent reference`,
  invalid_credential_reference: (f) => `${f} must be null or 64 lowercase hex characters`,
  invalid_freshness_reference: (f) =>
    `${f} must be null or a finalized-block reference <CAIP-2>@<block number>:0x<64 lowercase hex>`,
  freshness_required: (f) => `${f} is required: no acceptable finalized-block reference is available`,
  kind_contradicts_expectation: (f) => `${f}: the kind contradicts the record's signature expectation`,
  kind_contradicts_material: (f) => `${f}: the kind contradicts the attestation material presented with the capture`,
  identity_contradicts_assertion: (f) =>
    `${f}: the acct identifier differs from the user the assertion's credential is registered to`,
  commitment_not_supported_by_store: (f) => `${f}: this store cannot keep a commitment opening`,
};

/** A decider violation with its message. */
export function deciderViolationOf(code: DeciderViolationCode, field: string): DeciderViolation {
  return { code, field, message: MESSAGES[code](field) };
}

/**
 * Why `value` is not a decider a writer may write, first failure first, or
 * `null` when it is one. `prefix` is the field it sits at.
 *
 * `null` and `undefined` are refused (`not_an_object`): every 0.8.0 writer
 * requires a decider.
 */
export function deciderViolation(value: unknown, prefix = 'decider'): DeciderViolation | null {
  if (!isPlainObject(value)) return deciderViolationOf('not_an_object', prefix);
  if (Object.keys(value).some((k) => !DECIDER_MEMBERS.includes(k))) return deciderViolationOf('unknown_members', prefix);
  if (!hasExactKeys(value, DECIDER_MEMBERS)) return deciderViolationOf('missing_members', prefix);
  return actorViolation(value, prefix, true);
}

/**
 * The checks shared by a decider and a contribution step's actor: kind,
 * identifier, agent reference and consistency; for a decider also the
 * credential and freshness references.
 */
export function actorViolation(
  value: Record<string, unknown>,
  prefix: string,
  isDecider: boolean,
): DeciderViolation | null {
  const kind = value.kind;
  if (!isDeciderKind(kind)) return deciderViolationOf('invalid_kind', `${prefix}.kind`);
  const id = value.id;
  if (typeof id !== 'string' || !isKnownSchemeIdentifier(id)) return deciderViolationOf('invalid_identifier', `${prefix}.id`);
  const agent = value.agent;
  if (agent !== null && !isPrefixedDigest(agent)) return deciderViolationOf('invalid_agent_reference', `${prefix}.agent`);
  if (isDecider) {
    if (value.credential !== null && !isBareDigest(value.credential)) {
      return deciderViolationOf('invalid_credential_reference', `${prefix}.credential`);
    }
    if (value.freshness !== null && !isFreshnessReference(value.freshness)) {
      return deciderViolationOf('invalid_freshness_reference', `${prefix}.freshness`);
    }
  }
  if (kind === 'human' && agent !== null) return deciderViolationOf('agent_reference_forbidden', `${prefix}.agent`);
  if (kind !== 'human' && agent === null) return deciderViolationOf('agent_reference_required', `${prefix}.agent`);
  const scheme = identifierScheme(id)!;
  if (!PERMITTED_SCHEMES[kind].includes(scheme)) return deciderViolationOf('scheme_not_permitted', `${prefix}.id`);
  if (scheme === 'desc' && id.slice('desc:'.length) !== agent) {
    return deciderViolationOf('desc_identifier_mismatch', `${prefix}.id`);
  }
  return null;
}

/** The identifier a writer gives an agent kind that names none: `desc:<agent>`. */
export function defaultAgentDeciderId(agent: string): string {
  return `desc:${agent}`;
}

/**
 * Whether a decider of `kind` agrees with the record's signature expectation
 * (Record §6.5), from the record alone: `true`, `false` (the kind is contradicted),
 * or `null` for a kind or expectation this version does not read.
 *
 * | kind                    | null / policy | session | mandate |
 * | human                   | agrees        | agrees  | no      |
 * | agent, policy-engine    | agrees        | no      | no      |
 * | agent-mandated          | no            | no      | agrees  |
 */
export function deciderAgreesWithExpectation(kind: unknown, expectation: unknown): boolean | null {
  if (!isDeciderKind(kind)) return null;
  const form = signoffExpectationForm(expectation);
  if (form === null) return null;
  if (kind === 'human') return form !== 'mandate';
  if (kind === 'agent-mandated') return form === 'mandate';
  return form === 'none' || form === 'policy';
}

/** What a capture presents beside its decider (Record §6.5). */
export interface DeciderMaterial {
  /** The record's canonical digest, once built. */
  digest?: string;
  /** The capture's `attestationInputs.webauthnAssertion`. */
  assertion?: unknown;
  /** The user id the credential store registers the assertion's credential to. */
  assertionUserId?: string | null;
}

/**
 * Why a capture's decider is refused for the material presented with it
 * (Record §6.5), or `null`:
 *
 *   - `kind_contradicts_material`: an agent kind (`agent`, `agent-mandated`,
 *     `policy-engine`) with an assertion whose client data present this
 *     record's per-record challenge — a human signed this record;
 *   - `identity_contradicts_assertion`: an `acct` decider whose value differs
 *     from the user the assertion's credential is registered to.
 */
export function deciderMaterialViolation(decider: unknown, material: DeciderMaterial): DeciderViolation | null {
  if (!isPlainObject(decider)) return null;
  const kind = decider.kind;
  const assertion = material.assertion;
  if (kind !== 'human' && isDeciderKind(kind) && isPlainObject(assertion) && typeof material.digest === 'string' && material.digest !== '') {
    if (assertionBindsDigest(assertion as unknown as Parameters<typeof assertionBindsDigest>[0], material.digest)) {
      return deciderViolationOf('kind_contradicts_material', 'decider.kind');
    }
  }
  const id = decider.id;
  if (
    typeof id === 'string' &&
    identifierScheme(id) === 'acct' &&
    typeof material.assertionUserId === 'string' &&
    material.assertionUserId !== id.slice('acct:'.length)
  ) {
    return deciderViolationOf('identity_contradicts_assertion', 'decider.id');
  }
  return null;
}

function decodeSalt(salt: Uint8Array | string): Buffer | null {
  if (typeof salt === 'string') {
    if (!/^[A-Za-z0-9_-]*$/.test(salt)) return null;
    const bytes = Buffer.from(salt, 'base64url');
    return bytes.toString('base64url') === salt ? bytes : null;
  }
  return Buffer.from(salt);
}

/**
 * The commitment identifier `cmt:<hex(SHA-256("tzun-decider-cmt-v1" ‖ salt ‖
 * UTF8(innerId)))>`. `salt` is 32 bytes, or their unpadded base64url;
 * `innerId` is an identifier of another scheme this version implements.
 *
 * @throws when the salt is not 32 bytes or `innerId` is not such an identifier.
 */
export function deciderCommitment(innerId: string, salt: Uint8Array | string): string {
  const saltBytes = decodeSalt(salt);
  if (saltBytes === null || saltBytes.length !== DECIDER_COMMITMENT_SALT_BYTES) {
    throw new Error(`A decider commitment's salt is ${DECIDER_COMMITMENT_SALT_BYTES} bytes.`);
  }
  if (typeof innerId !== 'string' || !isKnownSchemeIdentifier(innerId) || identifierScheme(innerId) === 'cmt') {
    throw new Error('A decider commitment commits to an identifier of another scheme.');
  }
  const hash = createHash('sha256')
    .update(COMMITMENT_DOMAIN, 'utf8')
    .update(saltBytes)
    .update(innerId, 'utf8')
    .digest('hex');
  return `cmt:${hash}`;
}

/** The domain separator of a derived commitment salt. */
const COMMITMENT_SALT_DOMAIN = 'tzun-cmt-salt-v1';
/** The fewest bytes a commitment-salt secret has. */
export const DECIDER_COMMITMENT_SECRET_MIN_BYTES = 32;

function lengthPrefixed(text: string): Buffer {
  const bytes = Buffer.from(text, 'utf8');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

/**
 * The salt of a decider commitment made under an idempotency key, so a retry
 * of one capture commits to the same identifier with the same salt, and its
 * idempotency fingerprint (which reads `decider.id`) replays rather than
 * conflicts:
 *
 *   HMAC-SHA256(secret, "tzun-cmt-salt-v1" ‖ len ‖ UTF8(idempotencyKey) ‖ len ‖ UTF8(innerId))
 *
 * where each `len` is the 4-byte big-endian byte length of the field after
 * it. `secret` is a store secret of at least 32 bytes that never leaves the
 * store; without it the salt cannot be recomputed, so the commitment stays
 * hiding to anyone who reads the record or the idempotency table. A capture
 * with no idempotency key draws a random salt. Returns the 32 bytes as
 * unpadded base64url, the form a `DeciderOpening` carries.
 *
 * @throws when the secret is shorter than 32 bytes, the key is empty, or
 *   `innerId` is not an identifier `deciderCommitment` commits to.
 */
export function deciderCommitmentSalt(secret: Uint8Array, idempotencyKey: string, innerId: string): string {
  if (!(secret instanceof Uint8Array) || secret.length < DECIDER_COMMITMENT_SECRET_MIN_BYTES) {
    throw new Error(`A commitment-salt secret is at least ${DECIDER_COMMITMENT_SECRET_MIN_BYTES} bytes.`);
  }
  if (typeof idempotencyKey !== 'string' || idempotencyKey.length === 0) {
    throw new Error('A derived commitment salt needs a non-empty idempotency key.');
  }
  if (typeof innerId !== 'string' || !isKnownSchemeIdentifier(innerId) || identifierScheme(innerId) === 'cmt') {
    throw new Error('A decider commitment commits to an identifier of another scheme.');
  }
  return createHmac('sha256', secret)
    .update(COMMITMENT_SALT_DOMAIN, 'utf8')
    .update(lengthPrefixed(idempotencyKey))
    .update(lengthPrefixed(innerId))
    .digest()
    .toString('base64url');
}

/** Whether `opening` opens the commitment identifier `id`. Never throws. */
export function verifyDeciderOpening(id: unknown, opening: unknown): boolean {
  if (typeof id !== 'string' || identifierScheme(id) !== 'cmt' || !isPlainObject(opening)) return false;
  const { salt, id: innerId } = opening as Partial<DeciderOpening>;
  if (typeof salt !== 'string' || typeof innerId !== 'string') return false;
  try {
    return deciderCommitment(innerId, salt) === id;
  } catch {
    return false;
  }
}

/**
 * The reader's consistency test (Record §6.4) for a decider or a contribution step's
 * actor of a known kind: `agent` is `null` exactly for `human`; a scheme this
 * version implements is one the kind permits; a `desc` identifier names the
 * agent reference. The per-scheme value grammars of Record §6.3 (`acct`, `spiffe`,
 * `jkt`, `cmt`) are writer rules, which a reader does not apply: the
 * `decider` and `contributions` rows judge one identifier the same way.
 */
export function readerActorInconsistent(kind: DeciderKind, id: string, agent: unknown): boolean {
  const scheme = identifierScheme(id);
  if (scheme === null) return true;
  if (kind === 'human' ? agent !== null : agent === null) return true;
  if (DECIDER_SCHEMES.includes(scheme) && !PERMITTED_SCHEMES[kind].includes(scheme)) return true;
  return scheme === 'desc' && id.slice('desc:'.length) !== agent;
}

/** The reader's grammar of a decider: shape and patterns, with any kind string and any scheme. */
function deciderMalformed(value: Record<string, unknown>): boolean {
  if (!hasExactKeys(value, DECIDER_MEMBERS)) return true;
  if (typeof value.kind !== 'string') return true;
  if (identifierScheme(value.id) === null) return true;
  if (value.agent !== null && !isPrefixedDigest(value.agent)) return true;
  if (value.credential !== null && !isBareDigest(value.credential)) return true;
  if (value.freshness !== null && !isFreshnessReference(value.freshness)) return true;
  return false;
}

/** Whether a record carries human decision material bound to its digest, with no key: a per-record assertion, or a batch sign-off whose meaning is not `review`. */
export function bindsHumanDecisionMaterial(envelope: unknown): boolean {
  if (!isPlainObject(envelope)) return false;
  const nr = isPlainObject(envelope.nonRepudiation) ? envelope.nonRepudiation : {};
  const integrity = isPlainObject(envelope.integrity) ? envelope.integrity : {};
  const assertion = nr.webauthnAssertion;
  const digest = integrity.canonicalDigest;
  if (!isPlainObject(assertion) || typeof digest !== 'string' || digest === '') return false;
  const signoff = isPlainObject(nr.signoff) ? nr.signoff : null;
  if (signoff === null) {
    return assertionBindsDigest(assertion as unknown as Parameters<typeof assertionBindsDigest>[0], digest);
  }
  const statement = isPlainObject(signoff.statement) ? signoff.statement : null;
  return statement !== null && statement.meaning !== 'review' && carriesBatchSignoff(signoff, assertion, digest);
}

/**
 * The reader's `decider` row (Verification §4.9) for a record whose digest holds, read
 * from the record alone. Never throws.
 *
 *   1. the expectation is malformed      → not-checked, blocked_by:signoff.expectation
 *   2. `null`                            → not-checked, absent
 *   3. grammar                           → checked-wrong, malformed_decider
 *   4. a kind this version does not know → abstain, unsupported_decider_kind
 *   5. consistency                       → checked-wrong, decider_inconsistent
 *   6. agreement with the expectation    → checked-wrong, decider_kind_contradicted
 *   7. a scheme this version does not know → abstain, unsupported_identifier_scheme
 *   8. an agent kind with human decision material bound
 *                                        → not-checked, material_unverified
 *   9. otherwise                         → checked-correct
 */
export function checkDecider(envelope: unknown): DeciderCheck {
  const env = isPlainObject(envelope) ? envelope : {};
  const payload = isPlainObject(env.payload) ? env.payload : {};
  if (signoffExpectationViolation(payload.signoffExpectation) !== null) {
    return { outcome: 'not-checked', valid: null, reason: 'blocked_by:signoff.expectation' };
  }
  const decider = payload.decider;
  if (decider === null || decider === undefined) return { outcome: 'not-checked', valid: null, reason: 'absent' };
  if (!isPlainObject(decider) || deciderMalformed(decider)) {
    return { outcome: 'checked-wrong', valid: false, reason: 'malformed_decider' };
  }
  const kind = decider.kind as string;
  if (!isDeciderKind(kind)) return { outcome: 'abstain', valid: null, reason: 'unsupported_decider_kind', kind };
  const id = decider.id as string;
  const scheme = identifierScheme(id)!;
  const knownScheme = DECIDER_SCHEMES.includes(scheme);
  if (readerActorInconsistent(kind, id, decider.agent)) {
    return { outcome: 'checked-wrong', valid: false, reason: 'decider_inconsistent', kind, scheme };
  }
  if (deciderAgreesWithExpectation(kind, payload.signoffExpectation) === false) {
    return { outcome: 'checked-wrong', valid: false, reason: 'decider_kind_contradicted', kind, scheme };
  }
  if (!knownScheme) return { outcome: 'abstain', valid: null, reason: 'unsupported_identifier_scheme', kind, scheme };
  const humanMaterial = bindsHumanDecisionMaterial(envelope);
  if (kind !== 'human' && humanMaterial) {
    return {
      outcome: 'not-checked',
      valid: null,
      reason: 'material_unverified',
      kind,
      scheme,
      kindContradiction: 'undetermined',
    };
  }
  return {
    outcome: 'checked-correct',
    valid: true,
    kind,
    scheme,
    level: kind === 'human' ? 'human-asserted' : 'agent-asserted',
    ...(kind === 'human' && humanMaterial && { levelUndetermined: 'human-proven' as const }),
    ...(scheme === 'cmt' && { committed: true }),
  };
}

/**
 * Whether a decider and a step actor (or two actors) are the same: equal
 * `kind`, `id` and `agent`, compared as canonical bytes.
 */
export function sameActor(a: unknown, b: unknown): boolean {
  if (!isPlainObject(a) || !isPlainObject(b)) return false;
  try {
    return (
      canonicalValue({ kind: a.kind, id: a.id, agent: a.agent }) === canonicalValue({ kind: b.kind, id: b.id, agent: b.agent })
    );
  } catch {
    return false;
  }
}
