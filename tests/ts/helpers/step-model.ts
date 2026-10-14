/**
 * A record names a model only in a contribution step.
 * These helpers read and write the one model of a list of one, so a test of
 * a single model call says what it means.
 */
import { buildContributions, fillAiBomNulls, singleModel } from '@tzun/engine';
import type { AiBom, AiBomWithInlineDescriptor, Contributions, ContributionsInput } from '@tzun/engine';

/**
 * The bill of materials of the first step of a capture input's or a
 * payload's contributions, or `null` when they record no model.
 */
export function modelOf(value: unknown): AiBom | AiBomWithInlineDescriptor | null {
  const contributions = (value as { contributions?: unknown } | null | undefined)?.contributions;
  const steps = (contributions as { steps?: unknown } | null | undefined)?.steps;
  if (!Array.isArray(steps) || steps.length === 0) return null;
  return ((steps[0] as { aiBom?: unknown } | null)?.aiBom ?? null) as AiBom | AiBomWithInlineDescriptor | null;
}

/** `contributions` for a capture of one model: a list of one, or `null` for no model. */
export function modelInput(aiBom: AiBom | AiBomWithInlineDescriptor | null | undefined): ContributionsInput | null {
  return aiBom == null ? null : singleModel(aiBom);
}

/**
 * `contributions` for an `EnvelopeInput` that records one model: the list of
 * one, built against the record it belongs to (its absent nullable `aiBom`
 * members written as `null`).
 */
export function builtModel(
  aiBom: Partial<AiBom> & { modelDescriptorDigest: string },
  record: { decider: unknown; action: string; reason: string; aiOutput: Record<string, unknown> },
): Contributions {
  return buildContributions(singleModel(fillAiBomNulls({ ...aiBom }) as AiBom), record);
}
