/**
 * The agent descriptor `tzun-agent/1` (Record §6.9): its grammar and its
 * digest.
 *
 *   agentDescriptorDigest = "sha256:" ‖ hex(SHA-256(C(d)))
 *
 * with the set members sorted before serialization, the model-descriptor
 * sub-rule applied to `identities`, `keys` (by `kid`), `models` and
 * `runtime.measurements`, so the order a set was assembled in does not change
 * the digest.
 */
import {
  canonicalValue,
  compareBytes,
  hasExactKeys,
  hasLoneSurrogate,
  isBareDigest,
  isPlainObject,
  isPrefixedDigest,
  isStrictlyIncreasing,
  sha256Hex,
  utf8Length,
} from './record-rules-util';
import type { AgentDescriptor } from './types/agent';

export const AGENT_DESCRIPTOR_VERSION = 'tzun-agent/1';

/** The most canonical bytes a descriptor a writer registers may have. */
export const AGENT_DESCRIPTOR_MAX_BYTES = 16 * 1024;
/** The most elements of each set (`identities`, `keys`, `models`, `runtime.measurements`). */
export const AGENT_DESCRIPTOR_MAX_SET = 64;
/** The longest `name`, `operator.organization`, `runtime.format` and set string, in UTF-16 code units. */
export const AGENT_DESCRIPTOR_MAX_STRING = 256;
/** The longest `keys[].attestation`, in UTF-16 code units. */
export const AGENT_DESCRIPTOR_MAX_ATTESTATION = 8192;

const DESCRIPTOR_KEYS = [
  'v', 'name', 'operator', 'identities', 'keys', 'models', 'instructions', 'tools', 'runtime', 'policy', 'parent',
  'derivation',
] as const;
const KEY_KEYS = ['kid', 'alg', 'custody', 'attestation'] as const;
const JKT_RE = /^[A-Za-z0-9_-]{43}$/;
const ALGS = ['EdDSA', 'ES256', 'PS256'];
const CUSTODY = ['hsm', 'tee', 'workload', 'software'];
const DERIVATIONS = ['base', 'revision', 'fork', 'clone'];

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/** The descriptor with its set members sorted, as it is hashed. */
export function sortAgentDescriptorSets(descriptor: AgentDescriptor): AgentDescriptor {
  const runtime = descriptor.runtime === null
    ? null
    : { ...descriptor.runtime, measurements: [...descriptor.runtime.measurements].sort(compareBytes) };
  return {
    ...descriptor,
    operator: { ...descriptor.operator },
    identities: [...descriptor.identities].sort(compareBytes),
    keys: descriptor.keys.map((k) => ({ ...k })).sort((a, b) => compareBytes(a.kid, b.kid)),
    models: [...descriptor.models].sort(compareBytes),
    runtime,
  };
}

/** The canonical bytes of an agent descriptor, its sets sorted. */
export function canonicalSerializeAgentDescriptor(descriptor: AgentDescriptor): string {
  return canonicalValue(sortAgentDescriptorSets(descriptor));
}

/** `sha256:` and the lowercase hex SHA-256 of the descriptor's canonical bytes. */
export function agentDescriptorDigest(descriptor: AgentDescriptor): string {
  return 'sha256:' + sha256Hex(canonicalSerializeAgentDescriptor(descriptor));
}

/**
 * Why `descriptor` is not an agent descriptor, or `null` when it is one:
 * exactly the twelve members; `v` the version tag; `name` a non-empty string;
 * `operator` exactly `organization` and `owner` (64 lowercase hex or `null`);
 * `identities` non-empty strings; `keys` with exactly `kid` (an RFC 7638
 * thumbprint), `alg`, `custody` and `attestation`; `models` model descriptor
 * digests; `instructions`, `tools`, `policy` and `parent` prefixed digests or
 * `null`; `runtime` `null` or exactly `format` and `measurements`;
 * `derivation` one of four or `null`. No set holds an element twice: a
 * duplicate is refused, never removed.
 *
 * With `limits` (the default; `register` applies them), also the writer
 * limits (Record §6.9, §11): at most 16 KiB of canonical bytes, 64 elements per set, 256
 * UTF-16 code units per string (8,192 for `attestation`), and no lone
 * surrogate. Store-level verification re-hashes whatever is stored and
 * passes `limits: false`. `name` and `organization` name a product and an
 * organisation, never a person. Never throws.
 */
export function agentDescriptorViolation(descriptor: unknown, options: { limits?: boolean } = {}): string | null {
  const grammar = agentDescriptorGrammarViolation(descriptor);
  if (grammar !== null || options.limits === false) return grammar;
  return agentDescriptorLimitViolation(descriptor as AgentDescriptor);
}

function agentDescriptorLimitViolation(d: AgentDescriptor): string | null {
  const sets: [string, unknown[]][] = [
    ['identities', d.identities],
    ['keys', d.keys],
    ['models', d.models],
    ['runtime.measurements', d.runtime?.measurements ?? []],
  ];
  for (const [name, set] of sets) {
    if (set.length > AGENT_DESCRIPTOR_MAX_SET) return `${name} holds at most ${AGENT_DESCRIPTOR_MAX_SET} elements`;
  }
  const strings: [string, string, number][] = [
    ['name', d.name, AGENT_DESCRIPTOR_MAX_STRING],
    ['operator.organization', d.operator.organization, AGENT_DESCRIPTOR_MAX_STRING],
    ...d.identities.map((v): [string, string, number] => ['identities', v, AGENT_DESCRIPTOR_MAX_STRING]),
    ...(d.runtime === null
      ? []
      : [
          ['runtime.format', d.runtime.format, AGENT_DESCRIPTOR_MAX_STRING] as [string, string, number],
          ...d.runtime.measurements.map((v): [string, string, number] => ['runtime.measurements', v, AGENT_DESCRIPTOR_MAX_STRING]),
        ]),
    ...d.keys
      .filter((k) => k.attestation !== null)
      .map((k): [string, string, number] => ['keys[].attestation', k.attestation as string, AGENT_DESCRIPTOR_MAX_ATTESTATION]),
  ];
  for (const [name, value, max] of strings) {
    if (value.length > max) return `${name} is at most ${max} UTF-16 code units`;
    if (hasLoneSurrogate(value)) return `${name} holds a lone surrogate`;
  }
  let bytes: number;
  try {
    bytes = utf8Length(canonicalSerializeAgentDescriptor(d));
  } catch {
    return 'an agent descriptor must be canonically serializable';
  }
  if (bytes > AGENT_DESCRIPTOR_MAX_BYTES) return `an agent descriptor's canonical bytes are at most ${AGENT_DESCRIPTOR_MAX_BYTES}`;
  return null;
}

/**
 * Whether a decider or step actor of `kind` contradicts the descriptor its
 * agent reference names: a `policy-engine` whose descriptor names a model
 * (`agent_kind_mismatch`, Record §6.9).
 */
export function agentKindMismatch(kind: unknown, descriptor: AgentDescriptor): boolean {
  return kind === 'policy-engine' && descriptor.models.length > 0;
}

function agentDescriptorGrammarViolation(descriptor: unknown): string | null {
  if (!isPlainObject(descriptor)) return 'an agent descriptor must be an object';
  if (!hasExactKeys(descriptor, DESCRIPTOR_KEYS)) return `an agent descriptor has exactly the members ${DESCRIPTOR_KEYS.join(', ')}`;
  const d = descriptor;
  if (d.v !== AGENT_DESCRIPTOR_VERSION) return `v must be ${AGENT_DESCRIPTOR_VERSION}`;
  if (!nonEmptyString(d.name)) return 'name must be a non-empty string';
  const operator = d.operator;
  if (
    !isPlainObject(operator) ||
    !hasExactKeys(operator, ['organization', 'owner']) ||
    !nonEmptyString(operator.organization) ||
    (operator.owner !== null && !isBareDigest(operator.owner))
  ) {
    return 'operator has exactly organization (a non-empty string) and owner (64 lowercase hex or null)';
  }
  const uniqueSorted = (values: string[]) => isStrictlyIncreasing([...values].sort(compareBytes));
  if (!Array.isArray(d.identities) || !d.identities.every(nonEmptyString) || !uniqueSorted(d.identities)) {
    return 'identities must be a set of non-empty strings';
  }
  if (
    !Array.isArray(d.keys) ||
    !d.keys.every(
      (k) =>
        isPlainObject(k) &&
        hasExactKeys(k, KEY_KEYS) &&
        typeof k.kid === 'string' &&
        JKT_RE.test(k.kid) &&
        ALGS.includes(k.alg as string) &&
        CUSTODY.includes(k.custody as string) &&
        (k.attestation === null || nonEmptyString(k.attestation)),
    ) ||
    !uniqueSorted((d.keys as { kid: string }[]).map((k) => k.kid))
  ) {
    return 'keys must be a set, by kid, of { kid, alg, custody, attestation }';
  }
  if (!Array.isArray(d.models) || !d.models.every(isPrefixedDigest) || !uniqueSorted(d.models as string[])) {
    return 'models must be a set of model descriptor digests';
  }
  for (const key of ['instructions', 'tools', 'policy', 'parent'] as const) {
    if (d[key] !== null && !isPrefixedDigest(d[key])) return `${key} must be null or a prefixed digest`;
  }
  const runtime = d.runtime;
  if (
    runtime !== null &&
    (!isPlainObject(runtime) ||
      !hasExactKeys(runtime, ['format', 'measurements']) ||
      !nonEmptyString(runtime.format) ||
      !Array.isArray(runtime.measurements) ||
      !runtime.measurements.every(nonEmptyString) ||
      !uniqueSorted(runtime.measurements as string[]))
  ) {
    return 'runtime must be null or exactly format and a set of measurements';
  }
  if (d.derivation !== null && !DERIVATIONS.includes(d.derivation as string)) {
    return `derivation must be null or one of ${DERIVATIONS.join(', ')}`;
  }
  return null;
}
