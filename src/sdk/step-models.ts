/**
 * The models a record names (Record §7.4): a model's bill of materials
 * lives only in a contribution step, so every reader that resolves model
 * descriptors (verification, the export, the scanner, the decision walks)
 * reads `payload.contributions.steps[*].aiBom` and nothing else.
 */
import type { EvidenceEnvelope } from '@tzun/engine';

/**
 * The model descriptor digest of every step that records one, in step order,
 * each once. A stored row is whatever was written, so anything that is not a
 * string digest names no model.
 */
export function stepModelDigests(envelope: EvidenceEnvelope | null | undefined): string[] {
  const contributions = (envelope?.payload as { contributions?: unknown } | undefined)?.contributions;
  const steps = (contributions as { steps?: unknown } | null | undefined)?.steps;
  if (!Array.isArray(steps)) return [];
  const digests: string[] = [];
  for (const step of steps) {
    const aiBom = (step as { aiBom?: unknown } | null)?.aiBom;
    if (aiBom === null || typeof aiBom !== 'object' || Array.isArray(aiBom)) continue;
    const digest = (aiBom as { modelDescriptorDigest?: unknown }).modelDescriptorDigest;
    if (typeof digest === 'string' && digest.length > 0 && !digests.includes(digest)) digests.push(digest);
  }
  return digests;
}

/** Whether a record's verification reads the store: a step model, a link or an agent reference to resolve. */
export function needsStoreLevelVerification(envelope: EvidenceEnvelope | null | undefined): boolean {
  const payload = envelope?.payload as { links?: unknown; decider?: unknown; contributions?: unknown } | undefined;
  if (!payload) return false;
  if (Array.isArray(payload.links) && payload.links.length > 0) return true;
  if (typeof (payload.decider as { agent?: unknown } | null | undefined)?.agent === 'string') return true;
  const steps = (payload.contributions as { steps?: unknown } | null | undefined)?.steps;
  return Array.isArray(steps) && steps.length > 0;
}
