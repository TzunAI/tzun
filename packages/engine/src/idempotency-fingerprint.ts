/**
 * The idempotency fingerprint the SDK's local adapters compute.
 *
 * The replay rule: the same idempotency key with the same fingerprint replays
 * the first capture's receipt; with a different fingerprint it is a conflict.
 * So the fingerprint must cover what the CALLER chose for the capture and
 * nothing the SDK fills in per attempt. `capture()` mints a new `evidenceId`
 * and `capturedAt` on every call and builds the record at the chain position
 * it holds, so a retry of one decision is a different envelope every time,
 * and a fingerprint over the whole envelope never matches.
 *
 * What is fingerprinted:
 *   - `completeness`, and `chainId` (absent is `'default'`);
 *   - raw: the whole `payload` (all of it is the caller's; the server mints
 *     the record's identity) and a present `capturedAt` claim, which on raw
 *     is the caller's own backfill claim;
 *   - partial / sealed: the caller's decision inside the envelope, as
 *     {@link captureCallerDecision} reads it.
 *
 * Serialised with the engine's canonical serializer (keys sorted at every
 * level), so the order of keys in the caller's JSON does not matter, and
 * hashed: `'sha256:' + hex`.
 *
 * It is the hosted service's `requestFingerprint`, and
 * `tests/ts/idempotency-fingerprint.test.ts` pins vectors computed by the
 * service's own function. The service computes its own copy
 * (`requestFingerprint` and `callerDecision`) rather than calling this one,
 * so a rule added here, such as fingerprinting `signoffExpectation`, holds on
 * the service only once it adds the rule or switches to this function. The
 * SDK fingerprints a local capture with
 * `completeness: 'partial'` and the envelope it built — exactly what
 * `HttpStorageAdapter.store()` sends the platform — so one capture has one
 * fingerprint on either path.
 */

import { createHash } from 'crypto';
import { canonicalSerialize } from './canonical';
import type { EvidenceEnvelope } from './types/evidence';

/** What a capture request carries that the fingerprint reads. */
export interface IdempotencyFingerprintInput {
  completeness: 'raw' | 'partial' | 'sealed';
  /** The chain the capture targets; absent is `'default'`. */
  chainId?: string;
  /** raw only: the caller's payload. */
  payload?: unknown;
  /** raw only: the caller's backfill claim of the capture time. */
  capturedAt?: string;
  /** partial / sealed: the envelope the caller (or the SDK for the caller) built. */
  envelope?: EvidenceEnvelope;
}

export function captureIdempotencyFingerprint(input: IdempotencyFingerprintInput): string {
  const fingerprinted: Record<string, unknown> = {
    completeness: input.completeness,
    chainId: input.chainId ?? 'default',
  };
  if (input.completeness === 'raw') {
    fingerprinted.payload = input.payload ?? null;
    if (input.capturedAt != null) fingerprinted.capturedAt = input.capturedAt;
  } else {
    fingerprinted.decision = captureCallerDecision(input.envelope);
  }
  const canonical = canonicalSerialize(fingerprinted, Object.keys(fingerprinted));
  return 'sha256:' + createHash('sha256').update(canonical).digest('hex');
}

/** The custody actions the SDK derives under a mandate: not the caller's choice. */
const SDK_DERIVED_CUSTODY_ACTIONS = new Set(['captured_under_mandate', 'confirmation_required']);

/**
 * The caller's decision inside a partial or sealed envelope:
 *
 *   payload.aiSystemId, .aiOutput, .action, .reason
 *   payload.decider's kind, id, agent and credential — not its freshness,
 *     which a retry legitimately reads newer
 *   payload.contributions and .links, when they are not null (the parts the
 *     SDK derives, a filled locator or a mandate link, are deterministic, so
 *     they are the same on a retry)
 *   payload.signoffExpectation, when it is not null: a policy or session
 *     form as it is; the mandate form as `{ mandate: { mandateId } }` (from
 *     the mandate block's document), never its slot, totals or confirmation
 *     flag, which the SDK fills per attempt
 *   custodyChain[*].action, .actor, .systemId, .metadata, except the
 *     SDK-derived `captured_under_mandate` and `confirmation_required` entries
 *   nonRepudiation.webauthnAssertion, .signerIdentity — the caller's
 *     `attestationInputs`, passed through verbatim
 *
 * So a retry that names another decider (another kind, identifier, agent or
 * credential) is another capture, and a retry under a mandate replays the
 * first receipt rather than claiming a second slot. A capture that expects
 * no signature leaves `signoffExpectation` out.
 *
 * Left out, because the SDK fills them in per attempt: payload.evidenceId,
 * .capturedAt, .sequenceNumber and .schemaVersion; all of `integrity`
 * (canonicalDigest, chainLink); envelopeVersion; attestationStatus; the
 * attestation artifacts the SDK obtains itself (rfc3161Token,
 * rfc3161Metadata, anchor, the mandate block and any other); and each
 * custody entry's timestamp (the capturedAt), entryHash and prevEntryHash.
 */
export function captureCallerDecision(envelope: EvidenceEnvelope | undefined): Record<string, unknown> {
  const payload = (envelope?.payload ?? {}) as Partial<EvidenceEnvelope['payload']>;
  const nonRepudiation = (envelope?.nonRepudiation ?? {}) as EvidenceEnvelope['nonRepudiation'];
  const custody = Array.isArray(envelope?.custodyChain) ? envelope!.custodyChain : [];
  const decider = payload.decider;
  const expectation = payload.signoffExpectation;
  let fingerprintedExpectation: unknown = expectation;
  if (expectation != null && typeof expectation === 'object' && 'mandateAssertion' in expectation) {
    const document = (nonRepudiation.mandate as { document?: { mandateId?: unknown } | null } | undefined)?.document;
    fingerprintedExpectation = { mandate: { mandateId: document?.mandateId ?? null } };
  }
  return {
    aiSystemId: payload.aiSystemId,
    aiOutput: payload.aiOutput,
    action: payload.action,
    reason: payload.reason,
    decider:
      decider == null
        ? null
        : { kind: decider.kind, id: decider.id, agent: decider.agent ?? null, credential: decider.credential ?? null },
    ...(payload.contributions != null && { contributions: payload.contributions }),
    ...(payload.links != null && { links: payload.links }),
    ...(expectation != null && { signoffExpectation: fingerprintedExpectation }),
    custody: custody
      .filter((entry) => !SDK_DERIVED_CUSTODY_ACTIONS.has(entry.action))
      .map((entry) => ({
        action: entry.action,
        actor: entry.actor,
        systemId: entry.systemId,
        metadata: entry.metadata ?? null,
      })),
    webauthnAssertion: nonRepudiation.webauthnAssertion ?? null,
    signerIdentity: nonRepudiation.signerIdentity ?? null,
  };
}
