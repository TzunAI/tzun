import { randomUUID } from 'crypto';
import { canonicalSerialize } from './canonical';
import { computeDigest } from './digest';
import { CURRENT_SCHEMA_VERSION, V1_0_HASHED_FIELDS } from './schema-registry';
import { EvidenceChain } from './evidence-chain';
import {
  EnvelopeInput,
  EvidencePayload,
  EvidenceEnvelope,
  AttestationArtifacts,
  SignoffExpectation,
} from './types/evidence';
import { determineAttestationStatus } from './attestation-status';
import { movedFieldViolation, renamedFieldViolation } from './payload-rules';
import type { SystemRecordKind } from './payload-rules';
import { isPlainObject } from './record-rules-util';
import { mandateBlockViolation } from './mandate/expectation';
import { payloadRecordRuleViolation } from './record-rules';
import type { EnvelopeInputRule } from './record-rules';

export type { EnvelopeInputRule } from './record-rules';

/**
 * Thrown by `assembleEnvelope` and `buildEvidencePayload` for input a writer
 * refuses, before any digest exists. `code` is from the closed list of
 * `rule`; `field` names the member; the message never echoes a value.
 */
export class EnvelopeInputError extends Error {
  readonly rule: EnvelopeInputRule;
  readonly code: string;
  readonly field: string;
  /** For a `links` refusal that names a rule: the rule (`mandate_link`, `subject_link`, `at_most_one`, ...). */
  readonly linkRule?: string;
  constructor(rule: EnvelopeInputRule, code: string, field: string, message: string, linkRule?: string) {
    super(message);
    this.name = 'EnvelopeInputError';
    this.rule = rule;
    this.code = code;
    this.field = field;
    if (linkRule !== undefined) this.linkRule = linkRule;
  }
}

/** Options of `assembleEnvelope` and `buildEvidencePayload`. */
export interface AssembleEnvelopeOptions {
  /** Last digest in the evidence chain (absent for the first record). */
  previousDigest?: string;
  /**
   * Attestation artifacts from external services. A `mandate` or
   * `mandateIssuance` block over 48 KiB of canonical bytes is refused
   * (`mandate`/`mandate_block_too_large`).
   */
  attestation?: AttestationArtifacts;
  /** A safe integer of at least 1. Defaults to 1; a production caller supplies the chain's next sequence number. */
  sequenceNumber?: number;
  /** A raw-backfill capture time, ISO-8601. Defaults to now. */
  capturedAt?: string;
  /**
   * A pre-minted record id, a v4 UUID; defaults to a fresh one. The SDK mints
   * one per capture and threads it through every build of that capture, so a
   * record rebuilt at a new chain position keeps its id.
   */
  evidenceId?: string;
  /** What signature the record expects; `null` (the default) for none. */
  signoffExpectation?: SignoffExpectation | null;
  /**
   * A system record only, admitting the reserved `aiSystemId` of its kind:
   * `mandate` for the SDK's mandate issuance and revocation records
   * (`tzun:mandate`), `link` for link records (`tzun:link`). Never set from a
   * caller's ordinary capture; by default the `tzun:` prefix is refused
   * (`payload`/`reserved_ai_system_id`).
   */
  systemRecord?: SystemRecordKind;
}

function refuse(rule: EnvelopeInputRule, v: { code: string; field: string; message: string; linkRule?: string }): never {
  throw new EnvelopeInputError(rule, v.code, v.field, v.message, v.linkRule);
}

/**
 * Build and check a record's payload, with no digest: what the SDK's
 * two-phase capture hashes before it attests. An input naming a renamed 0.7
 * field (`humanAction`, `humanReason`, `reviewer`) is refused
 * (`renamed_field`), and one naming a moved field (`aiBom`, `lineage`)
 * (`moved_field`). The payload is built with every key written: absent
 * `aiSystemId` (or an empty one) as `default`, absent `contributions`,
 * `links` and expectation as `null`. Then every writer rule is applied by
 * `payloadRecordRuleViolation`, first failure first.
 *
 * @throws EnvelopeInputError
 */
export function buildEvidencePayload(input: EnvelopeInput, options: AssembleEnvelopeOptions = {}): EvidencePayload {
  if (!isPlainObject(input)) {
    refuse('payload', { code: 'missing_members', field: 'input', message: 'the capture input must be an object' });
  }
  const renamed = renamedFieldViolation(input) ?? movedFieldViolation(input);
  if (renamed) refuse('payload', renamed);
  const payload = {
    evidenceId: options.evidenceId ?? randomUUID(),
    schemaVersion: CURRENT_SCHEMA_VERSION,
    aiSystemId: input.aiSystemId === undefined || input.aiSystemId === '' ? 'default' : input.aiSystemId,
    aiOutput: input.aiOutput,
    action: input.action,
    reason: input.reason,
    capturedAt: options.capturedAt ?? new Date().toISOString(),
    sequenceNumber: options.sequenceNumber ?? 1,
    decider: isPlainObject(input.decider) ? { ...input.decider } : input.decider,
    contributions: input.contributions ?? null,
    links: input.links ?? null,
    signoffExpectation: options.signoffExpectation ?? null,
  } as EvidencePayload;
  const issue = payloadRecordRuleViolation(payload, { systemRecord: options.systemRecord });
  if (issue) refuse(issue.rule, issue);
  return payload;
}

/**
 * Assemble a complete evidence envelope: the payload `buildEvidencePayload`
 * builds, its digest under the v1.0 hashed field set, the chain link, the
 * attestation status, and the client-attested `decision_captured` custody
 * entry, whose actor is the decider's identifier. A `mandate` or
 * `mandateIssuance` block in `attestation` is held to its 48 KiB cap.
 *
 * The Evidence Engine receives attestation artifacts as inputs from
 * external services. It does not call external services directly.
 *
 * Who decided is hashed, as `payload.decider`. The custody entry, like every
 * custody entry, is outside the digest: a store-write attacker can change its
 * `actor` and every verifier still passes the record, so a reader takes who
 * decided from the decider, never from the custody trail.
 *
 * @throws EnvelopeInputError for input a writer refuses, before any digest exists.
 */
export function assembleEnvelope(input: EnvelopeInput, options: AssembleEnvelopeOptions = {}): EvidenceEnvelope {
  if (typeof (options as unknown) === 'string') {
    refuse('payload', {
      code: 'missing_members',
      field: 'options',
      message: 'assembleEnvelope takes an options object as its second argument, not a schema version string',
    });
  }
  const payload = buildEvidencePayload(input, options);
  for (const key of ['mandate', 'mandateIssuance'] as const) {
    const block = options.attestation?.[key];
    if (block !== undefined && block !== null) {
      const blockIssue = mandateBlockViolation(block, `nonRepudiation.${key}`);
      if (blockIssue) refuse('mandate', blockIssue);
    }
  }
  const digest = computeDigest(canonicalSerialize(payload as unknown as Record<string, unknown>, [...V1_0_HASHED_FIELDS]));
  let chainLink: string | null = null;
  if (options.previousDigest) {
    const chain = new EvidenceChain();
    chain.restore(options.previousDigest);
    chainLink = chain.computeLink(digest);
  }
  const attestation = options.attestation;
  return {
    envelopeVersion: 'e1',
    payload,
    integrity: { canonicalDigest: digest, chainLink },
    nonRepudiation: attestation || {},
    custodyChain: [
      {
        timestamp: payload.capturedAt,
        actor: payload.decider!.id,
        action: 'decision_captured',
        systemId: payload.aiSystemId,
      },
    ],
    attestationStatus: determineAttestationStatus(attestation, digest),
  };
}
