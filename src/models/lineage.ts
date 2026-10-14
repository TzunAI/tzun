/**
 * The single `walkLineage` implementation shared by the REST route
 * (`src/api/models-routes.ts`) and `ModelsApi.getLineage`.
 *
 * Leaf→root walk, depth cap 16, cycle-safe, partial-on-missing-ancestor,
 * null on unknown leaf.
 */
import type { StorageAdapter, ModelLineageEntry } from '@tzun/engine';

/** Maximum descriptors walked in a lineage (matches models-routes + verifier). */
export const MAX_LINEAGE_DEPTH = 16;

/** Why the walk stopped. Only `'root'` means the lineage is complete. */
export type LineageTerminal = 'root' | 'missing-parent' | 'cycle' | 'depth-cap';

export interface LineageWalkResult {
  /** Ordered leaf→root, leaf first. */
  entries: ModelLineageEntry[];
  /** True iff the walk reached an actual root (`parentModelDescriptorDigest === null`). */
  complete: boolean;
  /** Which of the four stop conditions ended the walk. */
  terminal: LineageTerminal;
  /**
   * The parent digest the walk could not resolve. Present only when
   * `terminal === 'missing-parent'` — this is the ancestor the catalog does
   * not have, which is exactly what a partial lineage cannot otherwise say.
   */
  missingParentDigest?: string;
}

/**
 * Walk the parent DAG from `leafDigest` to the root, reporting why it stopped.
 *
 * The bare-array version cannot distinguish "this is a base model" from "this
 * fine-tune's parent was never registered": both come back as a one-entry
 * array. `ModelLineageEntry` carries no `parentModelDescriptorDigest`, so the
 * caller has nothing to reconstruct it from either. A compliance report that
 * has to name the base model a system derives from therefore silently states
 * there is no parent. `terminal` + `complete` make the truncation explicit.
 *
 * Returns `null` if the leaf digest is not in the catalog, or if the storage
 * adapter does not implement `getModelDescriptor`.
 */
export async function walkLineageDetailed(
  storage: StorageAdapter,
  leafDigest: string,
): Promise<LineageWalkResult | null> {
  if (!storage.getModelDescriptor) {
    return null;
  }
  const leafRow = await storage.getModelDescriptor(leafDigest);
  if (!leafRow) {
    return null;
  }

  const entries: ModelLineageEntry[] = [
    {
      descriptorDigest: leafDigest,
      integrityTier: leafRow.descriptor.integrityTier,
      derivation: leafRow.descriptor.derivation,
      trainedBy: leafRow.descriptor.trainedBy,
    },
  ];
  const visited = new Set<string>([leafDigest]);

  let currentRow = leafRow;
  while (entries.length < MAX_LINEAGE_DEPTH) {
    const parentDigest = currentRow.parentModelDescriptorDigest;
    if (parentDigest === null) {
      return { entries, complete: true, terminal: 'root' };
    }
    if (visited.has(parentDigest)) {
      // Defensive cycle break — content-addressing makes cycles impossible by
      // construction. Unlike the verifier we just stop; no incident.
      return { entries, complete: false, terminal: 'cycle' };
    }
    const parentRow = await storage.getModelDescriptor(parentDigest);
    if (!parentRow) {
      // Missing parent: stop walking. Don't fail the whole response — the leaf
      // exists and the partial lineage is still meaningful — but say so, and
      // name the digest, so a consumer can tell an unregistered ancestor from
      // a genuine root.
      return {
        entries,
        complete: false,
        terminal: 'missing-parent',
        missingParentDigest: parentDigest,
      };
    }
    entries.push({
      descriptorDigest: parentDigest,
      integrityTier: parentRow.descriptor.integrityTier,
      derivation: parentRow.descriptor.derivation,
      trainedBy: parentRow.descriptor.trainedBy,
    });
    visited.add(parentDigest);
    currentRow = parentRow;
  }

  // Loop bound hit. The chain may or may not continue past the cap; either way
  // this is not a root-reaching lineage.
  return { entries, complete: false, terminal: 'depth-cap' };
}

/**
 * Entries-only view of {@link walkLineageDetailed}, kept for callers that only
 * need the chain. Prefer `walkLineageDetailed` anywhere the completeness of
 * the lineage is part of the answer.
 */
export async function walkLineage(
  storage: StorageAdapter,
  leafDigest: string,
): Promise<ModelLineageEntry[] | null> {
  const result = await walkLineageDetailed(storage, leafDigest);
  return result === null ? null : result.entries;
}
