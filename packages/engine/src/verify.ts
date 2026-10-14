import { createHash } from 'crypto';
import { canonicalSerialize } from './canonical';
import { verifyCustodyTrail } from './custody-hash';
import { computeDigest } from './digest';
import { EvidenceChain } from './evidence-chain';
import { SchemaRegistry } from './schema-registry';
import { checkSignoffExpectation, signoffExpectationForm } from './signoff-expectation';
import { checkDecider, identifierScheme, verifyDeciderOpening } from './decider';
import { checkContributions } from './contributions';
import { checkLinks } from './links';
import { agentDescriptorDigest, agentDescriptorViolation, agentKindMismatch } from './agent';
import { checkMandateIssuance } from './mandate/issuance';
import { mandateDocumentViolation } from './mandate/document';
import { checkMandateLimits, evaluateMandateScope } from './mandate/scope';
import { earlierFieldSet } from './store-schema';
import { unhashedPayloadMembers } from './payload-rules';
import { isPlainObject } from './record-rules-util';
import { EvidenceEnvelope } from './types/evidence';
import type { AgentDescriptor } from './types/agent';
import type { HeldLinkTarget, Link, LinkTargetResolver } from './types/links';
import {
  AgentReferenceCheck,
  MandateCheck,
  ModelLineageEntry,
  VerificationResult,
  VerifierTamperIncident,
} from './types/verification';
import { StorageAdapter } from './types/storage-interface';
import { ModelDescriptor } from './types/ai-bom';

const defaultRegistry = new SchemaRegistry();

/**
 * Options for the store-level extension to `verifyEnvelope`.
 *
 * When `storage` is provided, the verifier:
 *   - Resolves each contribution step's `aiBom.modelDescriptorDigest`
 *     against the catalog and re-hashes its `canonicalBytes`.
 *   - When `walkLineage === true`, follows each step model's
 *     `parentModelDescriptorDigest` up to `maxLineageDepth` (default 16),
 *     with cycle detection.
 *   - Resolves the decider's and every step actor's agent reference against
 *     the agent catalog (`agents`).
 *   - Resolves same-store link targets by digest and checks them
 *     (`links`), when the adapter can look a record up by digest.
 *
 * Without `storage`, none of this runs (the synchronous entry).
 */
export interface VerifyEnvelopeOptions {
  /** Storage adapter used to fetch descriptor rows, agent descriptors and link targets. */
  storage?: StorageAdapter;
  /**
   * If true, walk each step model's `parentModelDescriptorDigest` and
   * populate `modelLineage`. Default: `false`.
   */
  walkLineage?: boolean;
  /**
   * Maximum number of lineage entries per step (including the leaf).
   * Default: 16. Cycle detection short-circuits before this limit when a
   * digest is encountered twice.
   */
  maxLineageDepth?: number;
  /**
   * The evidence-log origin of a chain of this store
   * (`<ns>/<store id>/evidence/<hex of the chain id>`): lets the verifier
   * compare a link's locator with a held target's chain, and recognise a
   * locator that names a position of this store. Without it, a locator's
   * origin is not compared.
   */
  evidenceLogOrigin?: (chainId: string) => string;
  /**
   * What the caller already holds, in place of the lookups the verifier would
   * make through `storage` for link targets.
   */
  linkTargets?: LinkTargetResolver;
}

/**
 * Verify an evidence envelope's integrity by recomputing the digest
 * and validating the chain link, and check its record rules.
 *
 * Signature, timestamp and anchor validation are deferred to the
 * Attestation Services implementation and return null here.
 *
 * Callers without `options.storage` receive a synchronous
 * `VerificationResult`. When `options.storage` is provided, the function
 * performs async lookups and returns a Promise.
 *
 * @param envelope - The evidence envelope to verify
 * @param previousDigest - The previous record's digest (for chain link validation)
 * @param registry - Schema registry (uses default if not provided)
 * @param options - Store-level lookups
 */
export function verifyEnvelope(
  envelope: EvidenceEnvelope,
  previousDigest?: string,
  registry?: SchemaRegistry,
): VerificationResult;
export function verifyEnvelope(
  envelope: EvidenceEnvelope,
  previousDigest: string | undefined,
  registry: SchemaRegistry | undefined,
  options: VerifyEnvelopeOptions,
): Promise<VerificationResult>;
export function verifyEnvelope(
  envelope: EvidenceEnvelope,
  previousDigest?: string,
  registry: SchemaRegistry = defaultRegistry,
  options?: VerifyEnvelopeOptions,
): VerificationResult | Promise<VerificationResult> {
  const baseResult = computeBaseResult(envelope, previousDigest, registry, options?.linkTargets);

  if (!options || !options.storage) {
    return baseResult;
  }

  return resolveStorePath(envelope, baseResult, options);
}

/**
 * Compute the base verification result: digest recomputation, chain-link
 * validation, and schema-version sanity. The descriptor-resolution path
 * (when `options.storage` is provided) layers on top of this.
 */
function computeBaseResult(
  envelope: EvidenceEnvelope,
  previousDigest: string | undefined,
  registry: SchemaRegistry,
  linkTargets?: LinkTargetResolver,
): VerificationResult {
  // Every read below goes through these, never through `envelope.x.y`. A
  // verifier is reachable with whatever a client sent: an envelope with no
  // `payload` key, or no `integrity` key, or no envelope at all, would
  // otherwise throw `TypeError: Cannot read properties of undefined` out of
  // the engine before it could report anything. A verifier that throws on
  // malformed input is a denial of service on every server that verifies what
  // a client sent.
  const payload = (envelope?.payload ?? {}) as EvidenceEnvelope['payload'];
  const integrity = (envelope?.integrity ?? {}) as EvidenceEnvelope['integrity'];
  // A non-string stored digest can never equal a recomputed hex digest, so
  // reporting '' loses nothing and keeps the declared result type true.
  const storedDigest =
    typeof integrity.canonicalDigest === 'string' ? integrity.canonicalDigest : '';

  const schema = registry.get(payload.schemaVersion);

  // The custody trail is checked whatever the schema says: it hashes the
  // record's STORED digest and evidenceId, not the payload, so it needs no
  // serialization rules. See `custodyTrailValid` on VerificationResult for why
  // a false here does not flip `verified`.
  const custody = verifyCustodyTrail(envelope);
  const custodyFields = custody.valid === false
    ? { custodyTrailValid: false as const, custodyTrailFailures: custody.failures }
    : { custodyTrailValid: custody.valid };

  if (!schema) {
    return {
      verified: false,
      storedDigest,
      recomputedDigest: '',
      schemaVersion: payload.schemaVersion,
      schemaValid: false,
      chainLinkValid: null,
      signatureValid: null,
      timestampValid: null,
      anchorValid: null,
      attestationStatus: envelope?.attestationStatus,
      verifiedAt: new Date().toISOString(),
      ...custodyFields,
      ...signoffExpectationFields(envelope, false),
    };
  }

  // Recompute digest from payload using the schema version's rules.
  //
  // canonicalSerialize THROWS by design on input it cannot render injectively
  // — a lone UTF-16 surrogate, nesting past MAX_DEPTH, a non-finite number, a
  // non-plain object. That is right for the WRITER (`assembleEnvelope` must
  // refuse to mint a digest it cannot reproduce) and wrong to propagate out of
  // a VERIFIER: a lone surrogate survives JSON.stringify as `\ud800` and rides
  // into the store through every adapter, so `verifyEnvelope` on a stored or
  // client-supplied record threw instead of answering. A payload this
  // implementation cannot canonicalize is a payload whose stored digest cannot
  // be true of it, which is a `verified: false` with the reason attached.
  let recomputedDigest = '';
  let payloadSerializationError: string | undefined;
  try {
    const canonical = canonicalSerialize(
      payload as unknown as Record<string, unknown>,
      schema.hashedFieldSet,
    );
    recomputedDigest = computeDigest(canonical);
  } catch (err) {
    payloadSerializationError = err instanceof Error ? err.message : String(err);
  }
  // `payloadSerializationError === undefined` guards the case where BOTH sides
  // are '': an envelope with no integrity block must not verify against a
  // payload that produced no digest.
  const digestMatch =
    payloadSerializationError === undefined && recomputedDigest === storedDigest;

  // Validate chain link if present.
  //
  // chainLinkValid stays null ONLY when there is genuinely nothing to check:
  // a genesis record (sequenceNumber === 1) whose chainLink is null and for
  // which no predecessor was supplied.
  //
  // Two independent signals turn a null chainLink from a genesis marker into a
  // contradiction, and either one must drive chainLinkValid to false:
  //
  //   1. The caller supplied a previousDigest at all. That is proof a
  //      predecessor exists. Note the `!== undefined` test: the empty string is
  //      a *supplied* digest, and treating it as "nothing supplied" let an
  //      attacker who could force an empty predecessor through the callers
  //      re-enter the genesis branch.
  //
  //   2. `payload.sequenceNumber > 1`. sequenceNumber is a member of v1.0's
  //      hashedFieldSet, so it is covered by canonicalDigest and cannot be
  //      edited without breaking the digest. A record that says it is the Nth
  //      record of a chain can therefore never legitimately carry a null
  //      chainLink. Without this check, an attacker who nulls the link AND
  //      detaches the predecessor (delete the row, or repoint the record's
  //      chain_id at a chain with no seq-1 record) makes the SDK's
  //      resolvePredecessorDigest return `undefined`, and the record then
  //      presented as a clean standalone genesis record with verified:true.
  let chainLinkValid: boolean | null = null;
  if (integrity.chainLink !== null) {
    if (previousDigest) {
      const chain = new EvidenceChain();
      chain.restore(previousDigest);
      const expectedLink = chain.computeLink(storedDigest);
      chainLinkValid = expectedLink === integrity.chainLink;
    } else {
      chainLinkValid = false;
    }
  } else if (previousDigest !== undefined || payload.sequenceNumber > 1) {
    chainLinkValid = false;
  }

  const expectationFields = signoffExpectationFields(envelope, digestMatch);
  const fieldSet = digestMatch ? null : earlierFieldSet(payload, storedDigest);
  return {
    verified: digestMatch && (chainLinkValid === null || chainLinkValid),
    storedDigest,
    recomputedDigest,
    schemaVersion: payload.schemaVersion,
    schemaValid: true,
    chainLinkValid,
    signatureValid: null,
    timestampValid: null,
    anchorValid: null,
    attestationStatus: envelope?.attestationStatus,
    verifiedAt: new Date().toISOString(),
    ...custodyFields,
    ...expectationFields,
    ...(fieldSet !== null && { fieldSet }),
    unhashedPayloadMembers: unhashedPayloadMembers(payload),
    ...recordRuleFields(envelope, digestMatch, registry, expectationFields, linkTargets),
    ...(payloadSerializationError !== undefined && { payloadSerializationError }),
  };
}

/**
 * The record rules (Verification §4.9 to §4.12): the decider, contributions, links and
 * mandate rows, read from the record alone and only where its digest holds.
 * `linkTargets` is what a store-level verifier holds for the link rows.
 */
function recordRuleFields(
  envelope: EvidenceEnvelope,
  digestHolds: boolean,
  registry: SchemaRegistry,
  expectation: Pick<VerificationResult, 'signoffExpectationValid' | 'signoffExpectationReason'>,
  linkTargets?: LinkTargetResolver,
): Pick<VerificationResult, 'decider' | 'contributions' | 'links' | 'mandate'> {
  const env = envelope as unknown as Record<string, unknown>;
  const payload = (env?.payload ?? {}) as Record<string, unknown>;
  const nonRepudiation = (env?.nonRepudiation ?? {}) as Record<string, unknown>;
  const mandateMaterial =
    nonRepudiation.mandate != null ||
    nonRepudiation.mandateIssuance != null ||
    payload.aiSystemId === 'tzun:mandate';
  if (!digestHolds) {
    const invalid = { outcome: 'not-checked' as const, valid: null, reason: 'digest_invalid' };
    const binding = {
      ...invalid,
      approvals: [],
      staleApprovals: [],
      uncoveredReviews: [],
      proposals: [],
      decisionBinding: 'not-applicable' as const,
    };
    return {
      decider: invalid,
      contributions: { ...invalid, binding },
      links: { ...invalid, relations: [], edges: [] },
      ...((mandateMaterial || signoffExpectationForm(payload.signoffExpectation) === 'mandate') && {
        mandate: { reason: 'digest_invalid' },
      }),
    };
  }
  const mandate = mandateRows(envelope, registry, expectation);
  return {
    decider: checkDecider(envelope),
    contributions: checkContributions(payload),
    links: checkLinks(payload, { resolver: linkTargets }),
    ...(mandate !== null && { mandate }),
  };
}

/**
 * The `mandate.issuance`, `mandate.scope` and `mandate.limits` rows (Verification §4.12),
 * or `null` when none is reported. Scope and limits are reported for the
 * mandate form, against `nonRepudiation.mandate.document`, once the
 * expectation check holds (or awaits only the confirmation).
 */
function mandateRows(
  envelope: EvidenceEnvelope,
  registry: SchemaRegistry,
  expectation: Pick<VerificationResult, 'signoffExpectationValid' | 'signoffExpectationReason'>,
): MandateCheck | null {
  const env = envelope as unknown as Record<string, unknown>;
  const payload = (env.payload ?? {}) as Record<string, unknown>;
  const nonRepudiation = (env.nonRepudiation ?? {}) as Record<string, unknown>;
  const issuance = checkMandateIssuance(envelope);
  const out: MandateCheck = {};
  if (issuance !== null) out.issuance = issuance;
  if (signoffExpectationForm(payload.signoffExpectation) === 'mandate') {
    const ready =
      expectation.signoffExpectationValid === true ||
      (expectation.signoffExpectationValid === null && expectation.signoffExpectationReason === 'confirmation_missing');
    if (!ready) {
      const blocked = { outcome: 'not-checked' as const, valid: null, reason: 'blocked_by:signoff.expectation' };
      out.scope = blocked;
      out.limits = blocked;
    } else {
      const block = (nonRepudiation.mandate ?? {}) as Record<string, unknown>;
      const document = block.document;
      if (document === undefined || document === null) {
        const missing = { outcome: 'not-checked' as const, valid: null, reason: 'not_in_bundle:mandate_document' };
        out.scope = missing;
        out.limits = missing;
      } else if (mandateDocumentViolation(document, { registry, prepare: false }) !== null) {
        const malformed = { outcome: 'checked-wrong' as const, valid: false, reason: 'malformed_mandate_document' };
        out.scope = malformed;
        out.limits = malformed;
      } else {
        const scope = evaluateMandateScope(document, payload, { registry });
        if (!scope.agentInMandate) {
          out.scope = { outcome: 'checked-wrong', valid: false, reason: 'agent_not_in_mandate', failures: scope.failures };
        } else if (scope.verdict === 'outside') {
          out.scope = { outcome: 'checked-wrong', valid: false, reason: 'outside_mandate_scope', failures: scope.failures };
        } else if (scope.confirmationEvaded) {
          out.scope = { outcome: 'checked-wrong', valid: false, reason: 'confirmation_evaded' };
        } else if (scope.verdict === 'undeterminable') {
          out.scope = {
            outcome: 'not-checked',
            valid: null,
            reason: 'scope_undeterminable',
            undeterminable: scope.undeterminable,
          };
        } else {
          out.scope = { outcome: 'checked-correct', valid: true };
        }
        const limits = checkMandateLimits(document, payload);
        out.limits = limits.valid
          ? { outcome: 'checked-correct', valid: true, slot: limits.slot, totals: limits.totals }
          : { outcome: 'checked-wrong', valid: false, reason: limits.reason, slot: limits.slot, totals: limits.totals };
      }
    }
  }
  return Object.keys(out).length === 0 ? null : out;
}

/**
 * The record's sign-off material against its hashed expectation
 * (Record §9.1; Verification §5), by `checkSignoffExpectation`. Like the custody
 * trail, not folded into `verified`.
 *
 * `payload.signoffExpectation` is authenticated only by the digest
 * recomputed over it, so it is read only when that digest holds. Otherwise
 * anyone could have written it (an owed signature stripped and the
 * expectation rewritten to `null` would read `true`), and the answer is
 * `null`, `digest_invalid`, as `verifyBundle` reports `signoff.expectation`
 * `blocked_by:record.digest`.
 */
function signoffExpectationFields(
  envelope: EvidenceEnvelope,
  digestHolds: boolean,
): Pick<VerificationResult, 'signoffExpectationValid' | 'signoffExpectationReason'> {
  if (!digestHolds) return { signoffExpectationValid: null, signoffExpectationReason: 'digest_invalid' };
  const expectation = checkSignoffExpectation(envelope);
  return expectation.valid === true
    ? { signoffExpectationValid: true }
    : { signoffExpectationValid: expectation.valid, signoffExpectationReason: expectation.reason };
}

/**
 * The store-level path: each step model's descriptor (and, when asked, its
 * lineage), the agent references, and the link rows with the targets the
 * store holds. Mutates a copy of `baseResult` and returns it.
 */
async function resolveStorePath(
  envelope: EvidenceEnvelope,
  baseResult: VerificationResult,
  options: VerifyEnvelopeOptions,
): Promise<VerificationResult> {
  const result: VerificationResult = {
    ...baseResult,
    tamperIncidents: [],
  };
  await resolveStepDescriptors(envelope, result, options);
  if (baseResult.schemaValid) {
    result.agents = await resolveAgentReferences(envelope, options.storage!);
    if (baseResult.recomputedDigest === baseResult.storedDigest && baseResult.links !== undefined && !options.linkTargets) {
      const resolver = await prefetchLinkTargets(envelope, options);
      if (resolver !== null) result.links = checkLinks(envelope?.payload, { resolver });
    }
  }
  return result;
}

/**
 * Each contribution step's model: its
 * `aiBom.modelDescriptorDigest` is resolved against the catalog and its bytes
 * re-hashed, every incident naming the step; with `walkLineage`, the model's
 * ancestry is walked into one `modelLineage` entry per model-bearing step, in
 * step order (`lineage: []` for a model that does not resolve).
 */
async function resolveStepDescriptors(
  envelope: EvidenceEnvelope,
  result: VerificationResult,
  options: VerifyEnvelopeOptions,
): Promise<void> {
  const payload = (envelope?.payload ?? {}) as unknown as Record<string, unknown>;
  const contributions = isPlainObject(payload.contributions) ? payload.contributions : null;
  const storage = options.storage!;
  if (contributions === null || !Array.isArray(contributions.steps) || typeof storage.getModelDescriptor !== 'function') return;
  const evidenceId = payload.evidenceId as string;
  const lineages: NonNullable<VerificationResult['modelLineage']> = [];
  for (let step = 0; step < contributions.steps.length; step++) {
    const stepBom = (contributions.steps[step] as { aiBom?: unknown } | null)?.aiBom;
    // Absent and explicit null are the same: the step records no model.
    if (stepBom == null || typeof stepBom !== 'object' || Array.isArray(stepBom)) continue;
    // `modelDescriptorDigest` is JSON off the wire and a catalog KEY: an
    // unusable reference is a resolution failure, never a lookup with a key
    // the adapter never promised to accept.
    const digest: unknown = (stepBom as { modelDescriptorDigest?: unknown }).modelDescriptorDigest;
    if (typeof digest !== 'string') {
      pushIncident(result, { type: 'descriptor_resolution_failure', evidenceId, modelDescriptorDigest: String(digest), step });
      lineages.push({ step, descriptorDigest: String(digest), lineage: [] });
      continue;
    }
    const row = await storage.getModelDescriptor(digest);
    if (!row) {
      pushIncident(result, { type: 'descriptor_resolution_failure', evidenceId, modelDescriptorDigest: digest, step });
      lineages.push({ step, descriptorDigest: digest, lineage: [] });
      continue;
    }
    const recomputed = hashCanonicalBytes(row.canonicalBytes);
    if (recomputed !== digest) {
      pushIncident(result, { type: 'descriptor_digest_mismatch', evidenceId, claimedDigest: digest, recomputedDigest: recomputed, step });
    }
    if (options.walkLineage === true) {
      const lineage = await walkModelLineage(digest, row.canonicalBytes, evidenceId, step, result, options);
      lineages.push({ step, descriptorDigest: digest, lineage: lineage ?? [] });
    }
  }
  if (options.walkLineage === true) result.modelLineage = lineages;
}

/**
 * The lineage of one step model from its leaf to the root, read out of the
 * digest-covered `canonicalBytes` only — never out of a row's denormalized
 * columns (`parent_model_descriptor_digest` and the others are not covered by
 * the digest, so a DB-write attacker could repoint a leaf at another root with
 * one UPDATE). `null` when the leaf's bytes are not a descriptor.
 */
async function walkModelLineage(
  leafDigest: string,
  leafBytes: unknown,
  evidenceId: string,
  step: number,
  result: VerificationResult,
  options: VerifyEnvelopeOptions,
): Promise<ModelLineageEntry[] | null> {
  const storage = options.storage!;
  const maxDepth = options.maxLineageDepth ?? 16;
  const leafDescriptor = parseDescriptorBytes(leafBytes);
  if (!leafDescriptor) {
    pushIncident(result, { type: 'descriptor_resolution_failure', evidenceId, modelDescriptorDigest: leafDigest, step });
    return null;
  }
  const lineage: ModelLineageEntry[] = [
    {
      descriptorDigest: leafDigest,
      integrityTier: leafDescriptor.integrityTier,
      derivation: leafDescriptor.derivation,
      trainedBy: leafDescriptor.trainedBy,
    },
  ];
  const visited = new Set<string>([leafDigest]);
  let currentDescriptor = leafDescriptor;
  while (lineage.length < maxDepth) {
    const parentDigest: unknown = currentDescriptor.parentModelDescriptorDigest;
    if (parentDigest === null || parentDigest === undefined) break;
    if (typeof parentDigest !== 'string') {
      // The pointer lives in digest-covered bytes, but JSON guarantees no type.
      pushIncident(result, {
        type: 'parent_descriptor_resolution_failure',
        evidenceId,
        modelDescriptorDigest: String(parentDigest),
        note: 'parentModelDescriptorDigest is not a string',
        step,
      });
      break;
    }
    if (visited.has(parentDigest)) {
      // Content addressing makes a cycle impossible by construction; stop and report.
      pushIncident(result, {
        type: 'parent_descriptor_resolution_failure',
        evidenceId,
        modelDescriptorDigest: parentDigest,
        note: 'cycle detected',
        step,
      });
      break;
    }
    const parentRow = await storage.getModelDescriptor!(parentDigest);
    if (!parentRow) {
      pushIncident(result, { type: 'parent_descriptor_resolution_failure', evidenceId, modelDescriptorDigest: parentDigest, step });
      break;
    }
    const parentRecomputed = hashCanonicalBytes(parentRow.canonicalBytes);
    const parentDescriptor = parseDescriptorBytes(parentRow.canonicalBytes);
    if (parentRecomputed !== parentDigest) {
      pushIncident(result, {
        type: 'parent_descriptor_digest_mismatch',
        evidenceId,
        claimedDigest: parentDigest,
        recomputedDigest: parentRecomputed,
        step,
      });
      // The path that triggered the incident stays visible; the walk stops.
      lineage.push({
        descriptorDigest: parentDigest,
        integrityTier: parentDescriptor?.integrityTier ?? parentRow.descriptor.integrityTier,
        derivation: parentDescriptor?.derivation ?? parentRow.descriptor.derivation,
        trainedBy: parentDescriptor?.trainedBy ?? parentRow.descriptor.trainedBy,
      });
      break;
    }
    if (!parentDescriptor) {
      pushIncident(result, {
        type: 'parent_descriptor_resolution_failure',
        evidenceId,
        modelDescriptorDigest: parentDigest,
        note: 'canonicalBytes are not parseable as a ModelDescriptor',
        step,
      });
      break;
    }
    lineage.push({
      descriptorDigest: parentDigest,
      integrityTier: parentDescriptor.integrityTier,
      derivation: parentDescriptor.derivation,
      trainedBy: parentDescriptor.trainedBy,
    });
    visited.add(parentDigest);
    currentDescriptor = parentDescriptor;
  }
  return lineage;
}

/**
 * The decider's and every step actor's agent reference, resolved against the
 * store's agent catalog (Record §6.9): the stored bytes re-hashed, read
 * as a descriptor, and a `policy-engine`'s `models` checked empty. A store
 * without the catalog reports each reference `catalog_absent`.
 */
async function resolveAgentReferences(envelope: EvidenceEnvelope, storage: StorageAdapter): Promise<AgentReferenceCheck[]> {
  const payload = (envelope?.payload ?? {}) as unknown as Record<string, unknown>;
  const refs: { field: string; kind: unknown; reference: string }[] = [];
  const decider = isPlainObject(payload.decider) ? payload.decider : null;
  if (decider !== null && typeof decider.agent === 'string') refs.push({ field: 'decider', kind: decider.kind, reference: decider.agent });
  const contributions = isPlainObject(payload.contributions) ? payload.contributions : null;
  if (contributions !== null && Array.isArray(contributions.steps)) {
    contributions.steps.forEach((step, i) => {
      const actor = isPlainObject(step) && isPlainObject(step.actor) ? step.actor : null;
      if (actor !== null && typeof actor.agent === 'string') {
        refs.push({ field: `contributions.steps[${i}].actor`, kind: actor.kind, reference: actor.agent });
      }
    });
  }
  const out: AgentReferenceCheck[] = [];
  for (const ref of refs) {
    const base = { reference: ref.reference, field: ref.field };
    if (typeof storage.getAgentDescriptor !== 'function') {
      out.push({ ...base, resolved: false, reason: 'catalog_absent' });
      continue;
    }
    const row = await storage.getAgentDescriptor(ref.reference);
    if (!row) {
      out.push({ ...base, resolved: false, reason: 'not_registered' });
      continue;
    }
    if (hashCanonicalBytes(row.canonicalBytes) !== ref.reference) {
      out.push({ ...base, resolved: false, reason: 'digest_mismatch' });
      continue;
    }
    let descriptor: AgentDescriptor | null = null;
    try {
      const parsed = JSON.parse(row.canonicalBytes) as unknown;
      descriptor = agentDescriptorViolation(parsed, { limits: false }) === null ? (parsed as AgentDescriptor) : null;
    } catch {
      descriptor = null;
    }
    if (descriptor === null || agentDescriptorDigest(descriptor) !== ref.reference) {
      out.push({ ...base, resolved: false, reason: 'malformed_descriptor' });
      continue;
    }
    if (agentKindMismatch(ref.kind, descriptor)) {
      out.push({ ...base, resolved: false, reason: 'agent_kind_mismatch' });
      continue;
    }
    out.push({ ...base, resolved: true });
  }
  return out;
}

/**
 * What the store holds for this record's links (Record §8.8): each
 * target (and, for a link record, the subject) resolved by digest, each
 * held record's chain origin, the record at a locator that names this store,
 * and the openings of `cmt:` deciders. Resolution never crosses the store.
 * `null` when the adapter cannot look a record up by digest.
 */
async function prefetchLinkTargets(envelope: EvidenceEnvelope, options: VerifyEnvelopeOptions): Promise<LinkTargetResolver | null> {
  const storage = options.storage!;
  if (typeof storage.retrieveByDigest !== 'function') return null;
  const payload = (envelope?.payload ?? {}) as unknown as Record<string, unknown>;
  const links = Array.isArray(payload.links) ? (payload.links as Link[]) : [];
  const originOf = options.evidenceLogOrigin;
  const ownPrefix = originOf ? originOf('').replace(/[^/]*$/, '') : null;
  const held = new Map<string, HeldLinkTarget | null>();
  const positions = new Map<string, string | null>();
  const openings = new Map<string, string | null>();
  const addOpening = async (record: Record<string, unknown>) => {
    const d = isPlainObject(record.decider) ? record.decider : null;
    if (d === null || typeof d.id !== 'string' || identifierScheme(d.id) !== 'cmt' || openings.has(d.id)) return;
    let inner: string | null = null;
    if (typeof storage.getDeciderOpening === 'function' && typeof record.evidenceId === 'string') {
      const opening = await storage.getDeciderOpening(record.evidenceId);
      if (opening && verifyDeciderOpening(d.id, opening)) inner = opening.id;
    }
    openings.set(d.id, inner);
  };
  await addOpening(payload);
  for (const link of links) {
    if (!isPlainObject(link) || !isPlainObject(link.target) || typeof link.target.digest !== 'string') continue;
    const digest = link.target.digest;
    if (!held.has(digest)) {
      const env = await storage.retrieveByDigest(digest);
      if (env && isPlainObject(env.payload) && typeof env.integrity?.canonicalDigest === 'string') {
        const chainId = originOf ? await storage.getChainForRecord(env.payload.evidenceId) : null;
        const target: HeldLinkTarget = {
          payload: env.payload as unknown as Record<string, unknown>,
          digest: env.integrity.canonicalDigest,
          origin: originOf && chainId !== null ? originOf(chainId) : null,
        };
        held.set(digest, target);
        await addOpening(target.payload);
      } else {
        held.set(digest, null);
      }
    }
    const locator = link.target.locator;
    if (ownPrefix !== null && isPlainObject(locator) && typeof locator.origin === 'string' && locator.origin.startsWith(ownPrefix)) {
      const key = `${locator.origin}#${String(locator.seq)}`;
      if (!positions.has(key) && Number.isSafeInteger(locator.seq)) {
        const chainHex = locator.origin.slice(ownPrefix.length);
        const chainId = Buffer.from(chainHex, 'hex').toString('utf8');
        const rows = await storage.getBySequenceRange(locator.seq as number, locator.seq as number, chainId);
        positions.set(key, rows.length > 0 && typeof rows[0].integrity?.canonicalDigest === 'string' ? rows[0].integrity.canonicalDigest : null);
      }
    }
  }
  return {
    byDigest: (digest) => held.get(digest) ?? null,
    isOwnOrigin: (origin) => ownPrefix !== null && origin.startsWith(ownPrefix),
    digestAt: (origin, seq) => positions.get(`${origin}#${String(seq)}`) ?? null,
    openCommitment: (id) => openings.get(id) ?? null,
  };
}

/**
 * Hash a catalog row's bytes.
 *
 * `unknown` rather than `string`: the row comes back from an adapter over a
 * JSONB / TEXT column, and `createHash().update(5)` throws rather than
 * returning a digest. A row whose bytes are not a string cannot hash to the
 * digest that keys it, so '' is the honest answer and the caller turns it into
 * a `descriptor_digest_mismatch`.
 */
function hashCanonicalBytes(canonicalBytes: unknown): string {
  if (typeof canonicalBytes !== 'string') return '';
  return 'sha256:' + createHash('sha256').update(canonicalBytes).digest('hex');
}

/**
 * Parse the digest-covered descriptor out of a catalog row's `canonicalBytes`.
 *
 * These bytes are the only part of a descriptor row that `modelDescriptorDigest`
 * commits to, so they are the only part the verifier may report from. Returns
 * null when the bytes are not a JSON object, which the caller turns into a
 * resolution-failure incident rather than falling back to the row's columns.
 */
function parseDescriptorBytes(canonicalBytes: unknown): ModelDescriptor | null {
  if (typeof canonicalBytes !== 'string') return null;
  try {
    const parsed = JSON.parse(canonicalBytes) as unknown;
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null;
    }
    return parsed as ModelDescriptor;
  } catch {
    return null;
  }
}

function pushIncident(
  result: VerificationResult,
  incident: VerifierTamperIncident,
): void {
  if (!result.tamperIncidents) {
    result.tamperIncidents = [];
  }
  result.tamperIncidents.push(incident);

  // Any descriptor / parent-descriptor incident MUST flip the top-level
  // `verified` boolean to false. Centralizing the flip here covers every
  // emission site uniformly — the four AI-BOM incident types are the only
  // values `VerifierTamperIncident.type` can hold, so any incident emitted
  // by the verifier's descriptor path lands in this branch.
  if (
    incident.type === 'descriptor_resolution_failure' ||
    incident.type === 'descriptor_digest_mismatch' ||
    incident.type === 'parent_descriptor_resolution_failure' ||
    incident.type === 'parent_descriptor_digest_mismatch'
  ) {
    result.verified = false;
  }
}
