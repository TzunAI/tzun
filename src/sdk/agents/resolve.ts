/**
 * Resolving an agent reference against a store's agent catalog
 * (Record §6.9): the row the catalog holds under the digest, its bytes
 * re-hashed and read as a `tzun-agent/1` descriptor.
 *
 * The states are the reasons store-level verification reports for a
 * reference (`AgentReferenceCheck.reason` of the engine's `verifyEnvelope`
 * with `{ storage }`), so a reference capture accepts is one verification
 * resolves, and the other way round. They agree on the reason; the field
 * names differ (capture's hook names `decider.agent`, verification
 * `decider`):
 *
 *   - `catalog_absent`        the store keeps no catalog (no
 *                             `getAgentDescriptor`, or one that answers
 *                             `agent_not_supported_by_store`);
 *   - `not_registered`        the catalog holds no row under the digest;
 *   - `digest_mismatch`       the row's bytes do not hash to the digest;
 *   - `malformed_descriptor`  the bytes are not a descriptor, or not its
 *                             canonical form;
 *   - `resolved`              the descriptor the reference names.
 */
import { agentDescriptorDigest, agentDescriptorViolation } from '@tzun/engine';
import type { AgentDescriptor, AgentDescriptorRow, StorageAdapter } from '@tzun/engine';
import { prefixedSha256 } from '../../storage/agent-sql';

/** What the catalog holds for one agent reference. */
export type AgentResolution =
  | { state: 'resolved'; row: AgentDescriptorRow; descriptor: AgentDescriptor }
  | { state: 'catalog_absent' }
  | { state: 'not_registered' }
  | { state: 'digest_mismatch'; row: AgentDescriptorRow }
  | { state: 'malformed_descriptor'; row: AgentDescriptorRow };

/** Whether an error is a store's answer that it keeps no agent catalog. */
export function isCatalogUnsupported(error: unknown): boolean {
  return typeof error === 'object' && error !== null && (error as { code?: unknown }).code === 'agent_not_supported_by_store';
}

/**
 * Read a catalog row as the descriptor it stores: its bytes must hash to
 * `digest`, parse as a descriptor (the grammar, without the writer limits,
 * which bind registration only) and be that descriptor's canonical form.
 */
export function readAgentDescriptorRow(digest: string, row: AgentDescriptorRow): AgentResolution {
  if (prefixedSha256(row.canonicalBytes) !== digest) return { state: 'digest_mismatch', row };
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.canonicalBytes);
  } catch {
    return { state: 'malformed_descriptor', row };
  }
  if (agentDescriptorViolation(parsed, { limits: false }) !== null) return { state: 'malformed_descriptor', row };
  const descriptor = parsed as AgentDescriptor;
  if (agentDescriptorDigest(descriptor) !== digest) return { state: 'malformed_descriptor', row };
  return { state: 'resolved', row, descriptor };
}

/** Resolve one agent reference against `storage`'s catalog. A read the store fails is thrown. */
export async function resolveAgentDescriptor(
  storage: Pick<StorageAdapter, 'getAgentDescriptor'>,
  digest: string,
): Promise<AgentResolution> {
  if (typeof storage.getAgentDescriptor !== 'function') return { state: 'catalog_absent' };
  let row: AgentDescriptorRow | null;
  try {
    row = await storage.getAgentDescriptor(digest);
  } catch (error) {
    if (isCatalogUnsupported(error)) return { state: 'catalog_absent' };
    throw error;
  }
  if (row === null) return { state: 'not_registered' };
  return readAgentDescriptorRow(digest, row);
}
