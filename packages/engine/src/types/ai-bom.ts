/**
 * AI Bill of Materials (AI-BOM) types — schema d1.
 *
 * Pure type definitions: this module MUST NOT import from runtime code.
 *
 * Forward reference: `ExportedEvidenceEnvelope` refers to `EvidenceEnvelope`
 * from `./evidence`. This is a one-way reference for the export bundle shape;
 * `./evidence` does not depend on this type, so no cycle is created.
 */

import type { EvidenceEnvelope } from './evidence';
import type { ExportedAgentDescriptorEntry } from './agent';
import type {
  AssertionProvenance,
  CustodyLedgerEntry,
  CustodyLedgerVerdict,
  CustodyTrailVerdict,
  RecordVerdict,
} from './verification';

// ── AI-BOM descriptor sub-shapes ────────────────────────────────────

/** A named evaluation (benchmark, eval suite, red-team result) tied to a ModelDescriptor. */
export interface Evaluation {
  name: string;
  testSetDigest: string | null;
  evaluatedAt: string | null;
  metrics: Record<string, number>;
}

/** A regulatory marking (e.g. EU AI Act registration, FDA clearance) attached to a model. */
export interface RegulatoryMarking {
  authority: string;
  identifier: string;
  status: 'active' | 'pending' | 'expired' | 'withdrawn' | 'other';
  effectiveDate: string | null;
  expiresAt: string | null;
  scope: string | null;
  evidenceUrl: string | null;
}

/** A vendor- or standards-body external identifier (e.g. HF repo id, OpenAI model id, ARN). */
export interface ExternalIdentifier {
  scheme: string;
  value: string;
  issuedBy: string | null;
  issuedAt: string | null;
  url: string | null;
}

// ── ModelDescriptor ─────────────────────────────────────────────────

/**
 * Canonical, digest-addressable description of a single model.
 *
 * `descriptorVersion: 'd1'` is the schema discriminator for the initial
 * AI-BOM release. New schema versions get a new `dN` literal.
 *
 * Integrity tiers:
 *   - `weight-attested`  — `modelDigest` is non-null and cryptographically
 *                          binds the actual model weights/artifact.
 *   - `vendor-asserted`  — identity is asserted by the vendor; `modelDigest`
 *                          may be null (closed/hosted models). The vendor is
 *                          the API that served the call; for a gateway (such
 *                          as `openrouter`) that is the gateway, not the
 *                          model's maker.
 *
 * @tzun-canonical-sort utf16
 */
export interface ModelDescriptor {
  descriptorVersion: 'd1';
  vendor: string;
  modelName: string;
  modelVersion: string;
  modelType: string | null;
  integrityTier: 'weight-attested' | 'vendor-asserted';
  /**
   * INVARIANT: when non-null, `sha256:` + 64 lowercase hex — the exact
   * `MODEL_DIGEST_FORMAT` regex in src/models/descriptor-invariants.ts, which
   * `assertDescriptorIntegrityInvariants()` applies to every descriptor this
   * SDK registers (and src/models/register.ts re-applies).
   *
   * TypeScript cannot express a regex-constrained string, so the type here is
   * a plain `string | null` and the invariant lives in that runtime guard.
   * The generated Python port CAN express it and does, as
   * `Field(pattern=r"^sha256:[a-f0-9]{64}$")`. That is the same invariant in
   * the notation each language has for it — not a generator-invented
   * constraint, and not a TS/Python divergence to be normalized away by
   * dropping the Python pattern. Dropping it would make the port
   * accept digests this SDK rejects. `tests/ts/codegen-python.test.ts` pins
   * the two spellings together.
   */
  modelDigest: string | null;
  parentModelDescriptorDigest: string | null;
  derivation: 'base' | 'fine-tune' | 'quantization' | 'merge' | 'distillation' | 'other' | null;
  trainedBy: string | null;
  license: string | null;
  modelCardUrl: string | null;
  training: {
    trainingDataDigest: string | null;
    trainingDataRef: string | null;
    lastTrainingDate: string | null;
    evaluations: Evaluation[];
  };
  regulatoryMarkings: RegulatoryMarking[];
  externalIdentifiers: ExternalIdentifier[];
}

// ── AiBom (the payload-embedded shape) ──────────────────────────────

/**
 * The AI-BOM that rides inside an EvidencePayload. References a
 * ModelDescriptor by digest (the descriptor itself lives in the catalog).
 *
 * @tzun-canonical-sort utf16
 */
export interface AiBom {
  /**
   * INVARIANT: `sha256:` + 64 lowercase hex. Same `MODEL_DIGEST_FORMAT`
   * invariant, same reason it is a runtime guard here and a
   * `Field(pattern=...)` in the Python port — see `ModelDescriptor.modelDigest`
   * above.
   */
  modelDescriptorDigest: string;
  vendorFingerprint: string | null;
  promptTemplate: {
    templateId: string | null;
    templateDigest: string | null;
  } | null;
  inferenceParameters: {
    temperature: number | null;
    topP: number | null;
    maxTokens: number | null;
    seed: number | null;
    stopSequences: string[] | null;
  } | null;
  infrastructure: {
    provider: string | null;
    region: string | null;
    apiVersion: string | null;
    endpoint: string | null;
  } | null;
}

/** Why a value is not an exact `AiBom`: the dotted field and the rule, never the value. */
export interface AiBomViolation {
  field: string;
  message: string;
}

/**
 * Convenience escape hatch for a contribution step's `aiBom` at capture.
 *
 * Carries a full ModelDescriptor inline instead of a digest reference.
 * The SDK register-if-absent's the descriptor and substitutes the resulting
 * digest before envelope assembly, so both forms converge on the same
 * canonical `AiBom` shape on the wire.
 */
export interface AiBomWithInlineDescriptor {
  modelDescriptor: ModelDescriptor;
  vendorFingerprint: string | null;
  promptTemplate: AiBom['promptTemplate'];
  inferenceParameters: AiBom['inferenceParameters'];
  infrastructure: AiBom['infrastructure'];
}

// ── Catalog rows ────────────────────────────────────────────────────

/**
 * Source of a catalog entry. Used for provenance + audit; not part of the
 * digested descriptor itself.
 */
export type ModelDescriptorSource =
  | 'manual'
  | 'hf-import'
  | 'connector-auto'
  | 'openai-known-models'
  | 'anthropic-known-models'
  | 'bedrock-known-models'
  | 'vertex-known-models'
  | 'azure-ai-known-models'
  | 'nim-known-models'
  | 'hf-inference-known-models'
  | 'openrouter-known-models'
  | 'imported-by-digest';

/**
 * A row in the model descriptor catalog. `modelDescriptorDigest` is the
 * primary key; `canonicalBytes` is the exact byte sequence the digest was
 * computed over (so verifiers can re-hash and confirm).
 *
 * `vendor` / `modelName` / `modelVersion` / `parentModelDescriptorDigest`
 * are denormalized from `descriptor` for indexed lookup.
 */
export interface ModelDescriptorRow {
  modelDescriptorDigest: string;
  canonicalBytes: string;
  descriptor: ModelDescriptor;
  vendor: string;
  modelName: string;
  modelVersion: string;
  parentModelDescriptorDigest: string | null;
  source: ModelDescriptorSource;
  firstRegisteredAt: string;
  firstRegisteredBy: string;
}

/**
 * Append-only annotation attached to a descriptor. Annotations carry
 * mutable-after-the-fact data (e.g. regulatory updates, retraction notes)
 * without changing the digested descriptor itself.
 *
 * `retractsAnnotationId` non-null indicates this annotation supersedes/voids
 * an earlier one (still append-only: the earlier annotation row remains).
 */
export interface ModelDescriptorAnnotationRow {
  annotationId: string;
  modelDescriptorDigest: string;
  annotatedAt: string;
  annotatedBy: string;
  annotationType: string;
  valueJson: string;
  retractsAnnotationId: string | null;
  signature: string | null;
  note: string | null;
}

/**
 * Human-friendly slug → descriptor digest mapping. Slugs are mutable
 * (one slug, latest binding wins), but each rebind appends a new row
 * with a fresh `setAt`; nothing is overwritten in place.
 */
export interface ModelDescriptorAliasRow {
  slug: string;
  setAt: string;
  modelDescriptorDigest: string;
  setBy: string;
}

// ── Export shape ────────────────────────────────────────────────────

/**
 * One descriptor entry inside the bundle. The success shape carries the
 * canonical bytes + enriched view + annotations; the failure shape (when
 * the descriptor was referenced from the envelope but is absent from the
 * source catalog at export time) carries `missing: true`.
 *
 * The offline verifier MUST treat `missing: true` as a verification gap —
 * silently dropping the entry would hide a real data-loss event.
 */
export type ExportedDescriptorEntry =
  | {
      canonicalBytes: string;
      enrichedView: ModelDescriptor;
      annotations: ModelDescriptorAnnotationRow[];
      missing?: false;
    }
  | {
      canonicalBytes: '';
      enrichedView: null;
      annotations: ModelDescriptorAnnotationRow[];
      missing: true;
    };

/** The record an exported record's `integrity.chainLink` was computed over. */
export interface ExportedChainPredecessor {
  evidenceId: string;
  sequenceNumber: number;
  canonicalDigest: string;
}

/**
 * Where the exported record sits in its chain: what an offline verifier needs
 * to recompute `integrity.chainLink` as
 * SHA-256(predecessor.canonicalDigest ‖ envelope.integrity.canonicalDigest).
 */
export interface ExportedChainPosition {
  /** The chain the store files the record under; null when it names none. */
  chainId: string | null;
  /**
   * The record at the previous sequence number of the same chain. `null` for
   * a genesis record, and for a record whose predecessor the store does not
   * hold — `verdict.chainLink` says which.
   */
  predecessor: ExportedChainPredecessor | null;
}

/**
 * The record's custody ledger. The shape the hosted service's customer export
 * ships as `server.custody`, so one offline verifier reads both.
 */
export interface ExportedCustody {
  /** The entry hash rule, in words (`CUSTODY_ENTRY_HASH_PREIMAGE`). */
  hashPreimage: string;
  /**
   * The record's `custody_entries` rows, in id order — the source of every
   * `entryHash` in `envelope.custodyChain`. `null` when the store could not
   * read them; `verdict.custodyTrail.detail` carries the error.
   */
  entries: CustodyLedgerEntry[] | null;
  /** `verifyCustodyLedger` over `entries` and the envelope; `null` when `entries` is. */
  trail: CustodyLedgerVerdict | null;
  /**
   * `verifyCustodyTrail` over the envelope alone — what a holder of the bare
   * envelope can check. It cannot see a hashed entry deleted from the end of
   * the mirror; `trail` can.
   */
  offlineTrail: CustodyTrailVerdict;
}

/**
 * Self-contained DEO bundle for export: everything an auditor needs to verify
 * the record with no access to the store it came from.
 *
 *   - `envelope` — the record, verbatim.
 *   - `resolvedModelDescriptors` — every ModelDescriptor the envelope
 *     references (canonical bytes + annotations), keyed by
 *     `modelDescriptorDigest`; with `walkLineage: true` the ancestors too.
 *     Missing-from-catalog entries are surfaced as `{ missing: true }` rather
 *     than dropped, so the offline verifier can flag the gap.
 *   - `chain` — the predecessor digest, so the chain link can be recomputed.
 *   - `custody` — the custody ledger rows and the verdicts on them.
 *   - `verdict` — what the exporting store's checks found (`recordVerdict`).
 *     A claim by the exporter; an offline verifier recomputes it from the
 *     rest of the bundle.
 *   - `assertionProvenance` — where the record's WebAuthn ceremony ran and
 *     what kind of key signed it, read from the assertion in `envelope`.
 *   - `server` — a remote store's own receipt block, when the bundle came from
 *     one. Absent for a bundle this SDK assembled from its own store.
 */
export interface ExportedEvidenceEnvelope {
  envelope: EvidenceEnvelope;
  resolvedModelDescriptors: {
    [digest: string]: ExportedDescriptorEntry;
  };
  /**
   * Every agent descriptor the record's decider and step actors reference
   * (Record §6.9), keyed by the reference: the catalog row's bytes
   * verbatim, or `{ missing: true, reason }`. Optional on the type because a
   * bundle assembled before 0.8.0 carries none.
   */
  resolvedAgentDescriptors?: {
    [digest: string]: ExportedAgentDescriptorEntry;
  };
  /**
   * When the bundle was assembled, and by whom. Both are the EXPORTER's claim
   * about itself, so both are absent on a bundle re-homed from a remote store's
   * own export: the server does not send them, and stamping them here would say
   * this SDK assembled a bundle it only relayed.
   */
  exportedAt?: string;
  exportedBy?: string;
  verdict: RecordVerdict;
  chain: ExportedChainPosition;
  custody: ExportedCustody;
  /**
   * What the record's WebAuthn assertion states about where the ceremony ran
   * (`origin`, `crossOrigin`, `topOrigin`) and the key that signed (`UP`,
   * `UV`, `BE`, `BS`), with the checks the exporter asked for
   *. `null` for a record with no assertion.
   *
   * An exporter verifies no signature, so no check here is `true`: an offline
   * verifier holding the registered public key recomputes the rest. Optional
   * on the type because a bundle assembled before 0.4.7 carries none.
   */
  assertionProvenance?: AssertionProvenance | null;
  /**
   * The remote store's receipt for the record — present only on a bundle that
   * came from one (the hosted service's `GET /v1/app/evidence/:id/export`).
   *
   * It is an INDEPENDENT WITNESS's statement, which is why it is carried rather
   * than folded into the blocks above: when the platform received the record,
   * and the attestation state its own worker recorded for it, including an RFC
   * 3161 token the platform obtained that the client's envelope need not hold.
   * `custody` repeats `server.custody` under this bundle's own names so one
   * offline verifier reads either bundle; nothing else here is duplicated.
   *
   * A bundle this SDK assembled from its own store has none: this SDK is not a
   * witness to its own store, and an empty block would imply it had asked one.
   */
  server?: ExportedServerReceipt;
}

/**
 * A remote store's receipt block on an exported record, verbatim as the platform
 * sends it (the hosted service's `GET /v1/app/evidence/:id/export`, `server`).
 *
 * `attestation.claimedStatus` is what the CLIENT said the record's attestation
 * status was; `status` and `state` are what the platform recorded. The two
 * differing is the platform disagreeing with the client about the record's own
 * claim, which is a thing an auditor needs to be able to see.
 */
export interface ExportedServerReceipt {
  /** When the remote store received the record; null when it does not record it. */
  receivedAt: string | null;
  attestation: {
    state: 'pending' | 'attested' | 'failed';
    status: string;
    /** The status the client's envelope claimed, when the store kept it. */
    claimedStatus: string | null;
    /** An RFC 3161 token the remote store obtained itself, when it did. */
    rfc3161Token: string | null;
    artifact: unknown;
  };
  custody: {
    hashPreimage: string;
    entries: CustodyLedgerEntry[] | null;
    trail: CustodyLedgerVerdict | null;
    offlineTrail: CustodyTrailVerdict | null;
  };
}
