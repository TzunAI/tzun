/**
 * The agent descriptors an exported record bundles
 * (`ExportedEvidenceEnvelope.resolvedAgentDescriptors`): for every agent
 * reference the record names, the catalog row as stored, keyed by the
 * reference.
 *
 *   - A row is exported with its bytes verbatim, whether or not they hash to
 *     the reference: the offline verifier re-hashes them and reports a row
 *     that was rewritten, which an exporter that dropped it would hide.
 *   - A reference the catalog does not hold is exported as
 *     `{ missing: true, reason: 'not_registered' }`, and every reference of a
 *     store without the catalog as `{ missing: true, reason:
 *     'catalog_absent' }`: the gap is surfaced, never dropped.
 *
 * `exportedAgentCatalog(entries)` turns the entries back into the one
 * catalog method store-level verification reads, so an offline verifier
 * resolves the bundle's references exactly as the exporting store would:
 * `(await verifyEnvelope(envelope, undefined, undefined, { storage:
 * exportedAgentCatalog(bundle.resolvedAgentDescriptors) as StorageAdapter
 * })).agents` (the engine reads only the methods a storage object has).
 */
import type { AgentDescriptorRow, EvidenceEnvelope, ExportedAgentDescriptorEntry, StorageAdapter } from '@tzun/engine';
import { isCatalogUnsupported } from './resolve';

export type { ExportedAgentDescriptorEntry };

/** One agent reference of a stored record. */
export interface RecordAgentReference {
  /** `decider`, or `contributions.steps[<i>].actor`, as store-level verification names it. */
  field: string;
  kind: unknown;
  reference: string;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Every agent reference a stored record names: the decider's, then each step
 * actor's, in step order. Read defensively, since a stored record is whatever
 * was written: a member that is not an object, or an `agent` that is not a
 * string, names none.
 */
export function recordAgentReferences(envelope: EvidenceEnvelope): RecordAgentReference[] {
  const payload = isObject(envelope?.payload) ? (envelope.payload as unknown as Record<string, unknown>) : {};
  const refs: RecordAgentReference[] = [];
  const decider = isObject(payload.decider) ? payload.decider : null;
  if (decider !== null && typeof decider.agent === 'string') refs.push({ field: 'decider', kind: decider.kind, reference: decider.agent });
  const contributions = isObject(payload.contributions) ? payload.contributions : null;
  if (contributions !== null && Array.isArray(contributions.steps)) {
    contributions.steps.forEach((step, i) => {
      const actor = isObject(step) && isObject(step.actor) ? step.actor : null;
      if (actor !== null && typeof actor.agent === 'string') {
        refs.push({ field: `contributions.steps[${i}].actor`, kind: actor.kind, reference: actor.agent });
      }
    });
  }
  return refs;
}

/** The `resolvedAgentDescriptors` of an export of `envelope` from `storage`. A read the store fails is thrown. */
export async function exportAgentDescriptors(
  envelope: EvidenceEnvelope,
  storage: Pick<StorageAdapter, 'getAgentDescriptor'>,
): Promise<{ [reference: string]: ExportedAgentDescriptorEntry }> {
  const entries: { [reference: string]: ExportedAgentDescriptorEntry } = {};
  const references = [...new Set(recordAgentReferences(envelope).map((r) => r.reference))];
  let catalogAbsent = typeof storage.getAgentDescriptor !== 'function';
  for (const reference of references) {
    if (catalogAbsent) {
      entries[reference] = { canonicalBytes: '', missing: true, reason: 'catalog_absent' };
      continue;
    }
    let row: AgentDescriptorRow | null;
    try {
      row = await storage.getAgentDescriptor!(reference);
    } catch (error) {
      if (!isCatalogUnsupported(error)) throw error;
      catalogAbsent = true;
      entries[reference] = { canonicalBytes: '', missing: true, reason: 'catalog_absent' };
      continue;
    }
    entries[reference] =
      row === null
        ? { canonicalBytes: '', missing: true, reason: 'not_registered' }
        : {
            canonicalBytes: row.canonicalBytes,
            name: row.name,
            organization: row.organization,
            parent: row.parent,
            registeredAt: row.registeredAt,
          };
  }
  return entries;
}

/**
 * The bundled descriptors as the catalog method store-level verification
 * reads (`getAgentDescriptor`). When the exporting store kept no catalog,
 * every entry is `catalog_absent`, and the view has no method either, so
 * verification reports `catalog_absent` as it would have there. Otherwise
 * each reference is read from its own entry: a `catalog_absent` entry among
 * others, or any missing entry, reads as not registered, as do entries that
 * are not objects or whose bytes are not a string.
 */
export function exportedAgentCatalog(
  entries: { [reference: string]: ExportedAgentDescriptorEntry } | null | undefined,
): Pick<StorageAdapter, 'getAgentDescriptor'> {
  const held = isObject(entries) ? entries : {};
  const values = Object.values(held);
  const absent = values.length > 0 && values.every((e) => isObject(e) && e.missing === true && e.reason === 'catalog_absent');
  if (absent) return {};
  return {
    async getAgentDescriptor(digest: string): Promise<AgentDescriptorRow | null> {
      const entry: unknown = Object.prototype.hasOwnProperty.call(held, digest) ? held[digest] : undefined;
      if (!isObject(entry) || entry.missing === true || typeof entry.canonicalBytes !== 'string') return null;
      return {
        digest,
        canonicalBytes: entry.canonicalBytes,
        name: typeof entry.name === 'string' ? entry.name : '',
        organization: typeof entry.organization === 'string' ? entry.organization : '',
        parent: typeof entry.parent === 'string' ? entry.parent : null,
        registeredAt: typeof entry.registeredAt === 'string' ? entry.registeredAt : '',
      };
    },
  };
}
