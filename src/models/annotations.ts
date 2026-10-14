/**
 * Annotation runtime.
 *
 * Single entry point: `annotateModelDescriptor()`. Builds a
 * `ModelDescriptorAnnotationRow`, enforces the admin gate, and appends via
 * `storage.appendModelDescriptorAnnotation()`. `src/models/enriched-view.ts`
 * is the read-side companion that replays the log.
 *
 * Authorization (v1):
 *   - The seven typed annotation types require admin auth:
 *       add-regulatory-marking, add-evaluation, set-model-card-url,
 *       set-license, add-training-disclosure, add-external-identifier,
 *       retract.
 *   - `freeform-note` is allowed for any authenticated actor — no admin gate.
 *   - Unknown / custom annotation types ARE admin-gated and stored as-is;
 *     the enriched-view builder ignores them.
 *
 * Signatures:
 *   - Optional `signature` is stored verbatim on the row. v1 does NOT
 *     verify it; that's a server-side concern (and ultimately a per-issuer
 *     trust-store decision out of scope for the SDK).
 *
 * Retraction:
 *   - Encoded as `annotationType: 'retract'` with
 *     `value.retractsAnnotationId` pointing at the prior annotationId. The
 *     log preserves both rows; the enriched-view builder skips the targeted
 *     annotation's effect.
 *
 * Digest invariance:
 *   - Annotations never participate in `modelDescriptorDigest`. They live
 *     in `model_descriptor_annotations`, alongside but separate from the
 *     canonical row.
 */

import { randomUUID } from 'crypto';
import { ModelDescriptorAnnotationRow } from '@tzun/engine';
import { StorageAdapter } from '@tzun/engine';

/**
 * The seven typed annotation types that mutate the enriched view. All
 * require admin auth in v1. Mirrors the known-set in `enriched-view.ts`
 * minus `freeform-note`.
 */
export const TYPED_ANNOTATION_TYPES: ReadonlySet<string> = new Set([
  'add-regulatory-marking',
  'add-evaluation',
  'set-model-card-url',
  'set-license',
  'add-training-disclosure',
  'add-external-identifier',
  'retract',
]);

/** The single special case that bypasses the admin gate. */
const FREEFORM_NOTE = 'freeform-note';

export interface ModelAnnotateInput {
  /**
   * Annotation type. One of the seven typed values, `freeform-note`, or a
   * vendor-defined string. Typed and custom types are admin-gated; only
   * `freeform-note` is open to any authenticated actor.
   */
  annotationType: string;
  /**
   * The annotation's effect-bearing JSON. Serialized to `valueJson` on the
   * stored row. For `retract`, `{ retractsAnnotationId }` MUST point to a
   * prior annotation's `annotationId`.
   */
  value: Record<string, unknown>;
}

export interface ModelAnnotateOptions {
  /** Required for typed and custom types; optional for `freeform-note`. */
  isAdmin?: boolean;
  /** Required. The actor identity recorded on the row. */
  annotatedBy: string;
  /** Optional: actor's signature over the annotation. v1 stores; does not verify. */
  signature?: string;
  /** Optional: freeform note text on the row, regardless of annotation type. */
  note?: string;
  /**
   * Optional: override `annotatedAt`. Defaults to `new Date().toISOString()`.
   * Mostly useful in tests that need a deterministic replay order.
   */
  annotatedAt?: string;
  /**
   * Optional: override `annotationId`. Defaults to a fresh `randomUUID()`.
   * Mostly useful for tests / replay; production callers should let the
   * runtime generate the id so it's globally unique.
   */
  annotationId?: string;
}

/**
 * Appends an annotation row for the given `modelDescriptorDigest`.
 *
 * Auth:
 *   - `freeform-note`        → no admin gate.
 *   - any other type         → throws unless `options.isAdmin === true`.
 *
 * Retraction:
 *   - For `annotationType: 'retract'`, the `value.retractsAnnotationId`
 *     pointer is mirrored to the row's `retractsAnnotationId` column so
 *     downstream readers (incl. SQL filters) don't need to parse JSON.
 *
 * Signatures:
 *   - `signature` is stored verbatim. v1 does not verify it; the row
 *     remains valid regardless of signature presence/correctness.
 */
export async function annotateModelDescriptor(
  storage: StorageAdapter,
  modelDescriptorDigest: string,
  input: ModelAnnotateInput,
  options: ModelAnnotateOptions,
): Promise<ModelDescriptorAnnotationRow> {
  if (!storage.appendModelDescriptorAnnotation) {
    throw new Error(
      'annotations are not supported by this storage adapter ' +
        '(appendModelDescriptorAnnotation is undefined)',
    );
  }

  if (typeof options.annotatedBy !== 'string' || options.annotatedBy.length === 0) {
    throw new Error('annotateModelDescriptor: options.annotatedBy is required');
  }

  // Admin gate. `freeform-note` is the single exception.
  if (input.annotationType !== FREEFORM_NOTE && options.isAdmin !== true) {
    throw new Error(
      `annotateModelDescriptor: annotationType '${input.annotationType}' requires admin auth. ` +
        `Only 'freeform-note' may be created without admin.`,
    );
  }

  const annotationId = options.annotationId ?? randomUUID();
  const annotatedAt = options.annotatedAt ?? new Date().toISOString();

  // For retraction we mirror value.retractsAnnotationId onto the column so
  // downstream consumers can filter without parsing JSON. For other types
  // the column stays null.
  let retractsAnnotationId: string | null = null;
  if (input.annotationType === 'retract') {
    const raw = (input.value as { retractsAnnotationId?: unknown }).retractsAnnotationId;
    if (typeof raw !== 'string' || raw.length === 0) {
      throw new Error(
        "annotateModelDescriptor: 'retract' annotation requires value.retractsAnnotationId",
      );
    }
    retractsAnnotationId = raw;
  }

  const row: ModelDescriptorAnnotationRow = {
    annotationId,
    modelDescriptorDigest,
    annotatedAt,
    annotatedBy: options.annotatedBy,
    annotationType: input.annotationType,
    valueJson: JSON.stringify(input.value ?? {}),
    retractsAnnotationId,
    signature: options.signature ?? null,
    note: options.note ?? null,
  };

  await storage.appendModelDescriptorAnnotation(row);
  return row;
}
