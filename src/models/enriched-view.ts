/**
 * Enriched-view builder.
 *
 * Applies annotation history to a canonical `ModelDescriptor` to produce the
 * post-hoc enriched view. The canonical descriptor itself is never mutated
 * by the caller; this function returns a fresh object.
 *
 * Ordering & semantics:
 *   - Annotations are applied in `annotatedAt` ASC.
 *   - `add-*` to list-valued fields APPENDS to the list.
 *   - `set-*` to scalar fields uses latest-wins.
 *   - `retract` marks the referenced annotation's effect as voided; the
 *     prior annotation row is preserved on disk, but its contribution is
 *     skipped here.
 *   - Unknown annotation types are preserved in the log but ignored by this
 *     builder.
 *   - `freeform-note` has no enriched-view effect.
 */

import {
  ModelDescriptor,
  ModelDescriptorAnnotationRow,
  RegulatoryMarking,
  Evaluation,
  ExternalIdentifier,
} from '@tzun/engine';

const KNOWN_ANNOTATION_TYPES = new Set<string>([
  'add-regulatory-marking',
  'add-evaluation',
  'set-model-card-url',
  'set-license',
  'add-training-disclosure',
  'add-external-identifier',
  'retract',
  'freeform-note',
]);

export function buildEnrichedView(
  descriptor: ModelDescriptor,
  annotations: ModelDescriptorAnnotationRow[],
): ModelDescriptor {
  // Shallow clone preserving plain-object identity (see canonical.ts notes on structuredClone).
  const enriched: ModelDescriptor = {
    ...descriptor,
    training: {
      ...descriptor.training,
      evaluations: [...descriptor.training.evaluations],
    },
    regulatoryMarkings: [...descriptor.regulatoryMarkings],
    externalIdentifiers: [...descriptor.externalIdentifiers],
  };

  const retractedIds = new Set<string>();
  for (const ann of annotations) {
    if (ann.annotationType === 'retract' && ann.retractsAnnotationId) {
      retractedIds.add(ann.retractsAnnotationId);
    }
  }

  const sorted = [...annotations].sort((a, b) =>
    a.annotatedAt < b.annotatedAt ? -1 : a.annotatedAt > b.annotatedAt ? 1 : 0,
  );

  for (const ann of sorted) {
    if (retractedIds.has(ann.annotationId)) continue;
    if (ann.annotationType === 'retract') continue;
    if (ann.annotationType === 'freeform-note') continue;
    if (!KNOWN_ANNOTATION_TYPES.has(ann.annotationType)) continue;
    applyAnnotation(enriched, ann);
  }

  return enriched;
}

function applyAnnotation(d: ModelDescriptor, ann: ModelDescriptorAnnotationRow): void {
  const value = parseValue(ann.valueJson);
  switch (ann.annotationType) {
    case 'add-regulatory-marking':
      d.regulatoryMarkings.push(value as RegulatoryMarking);
      return;
    case 'add-evaluation':
      d.training.evaluations.push(value as Evaluation);
      return;
    case 'add-external-identifier':
      d.externalIdentifiers.push(value as ExternalIdentifier);
      return;
    case 'set-model-card-url':
      d.modelCardUrl = (value as { url: string | null }).url ?? null;
      return;
    case 'set-license':
      d.license = (value as { license: string | null }).license ?? null;
      return;
    case 'add-training-disclosure': {
      const v = value as {
        trainingDataDigest?: string | null;
        trainingDataRef?: string | null;
        lastTrainingDate?: string | null;
      };
      if (v.trainingDataDigest !== undefined) d.training.trainingDataDigest = v.trainingDataDigest;
      if (v.trainingDataRef !== undefined) d.training.trainingDataRef = v.trainingDataRef;
      if (v.lastTrainingDate !== undefined) d.training.lastTrainingDate = v.lastTrainingDate;
      return;
    }
  }
}

function parseValue(json: string): unknown {
  try {
    return JSON.parse(json);
  } catch {
    return null;
  }
}
