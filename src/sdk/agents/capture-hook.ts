/**
 * The agent catalog's capture hook (Record §6.9): `capture()` calls it
 * once, before any sequence number is taken, with every agent reference the
 * record names (the decider's, then each step actor's).
 *
 * In a store with the catalog, a reference is accepted only when the catalog
 * holds a descriptor that hashes to it:
 *
 *   - no row under the digest → `agent_not_registered`;
 *   - a row whose bytes do not hash to the digest, or are not a descriptor's
 *     canonical form → `agent_not_registered`, with the fact `catalog`
 *     naming which (store-level verification would report the same
 *     reference unresolved, so capture does not write it);
 *   - a `policy-engine` decider or actor whose descriptor names a model →
 *     `agent_kind_mismatch` (a policy engine's `models` set is empty).
 *
 * A store without the catalog (an adapter without `getAgentDescriptor`, or
 * one whose `getAgentDescriptor` answers `agent_not_supported_by_store`)
 * accepts every reference as given.
 *
 * The cloud transport leaves the check to the platform, which keeps the
 * key's own agent catalog and refuses the same two cases at capture
 * (`400 invalid_request`, `reason` `agent_not_registered` or
 * `agent_kind_mismatch`): the hook reads nothing there, so a capture costs
 * no catalog request and cannot fail on one.
 *
 * The first reference that fails decides the refusal. A digest named twice
 * is read once. A refusal names the field as capture's input does
 * (`decider.agent`, `contributions.steps[<i>].actor.agent`); store-level
 * verification names the member (`decider`, `contributions.steps[<i>].actor`)
 * and reports the same reason.
 */
import { agentKindMismatch } from '@tzun/engine';
import type { AgentCaptureHook, AgentReference, CaptureRefusal } from '../extension-points';
import { isCloudStore } from '../links/store-reads';
import { resolveAgentDescriptor, type AgentResolution } from './resolve';

function refusal(code: 'agent_not_registered' | 'agent_kind_mismatch', ref: AgentReference, message: string, details?: Record<string, unknown>): CaptureRefusal {
  return { failureType: 'validation_failure', code, field: ref.field, message, ...(details && { details }) };
}

/** The refusal one reference earns, or `null` when the catalog accepts it. */
export function agentReferenceRefusal(ref: AgentReference, resolution: AgentResolution): CaptureRefusal | null {
  switch (resolution.state) {
    case 'catalog_absent':
      return null;
    case 'not_registered':
      return refusal(
        'agent_not_registered',
        ref,
        `${ref.field} names an agent descriptor this store's catalog does not hold; register it first (tzun.agents.register).`,
      );
    case 'digest_mismatch':
    case 'malformed_descriptor':
      return refusal(
        'agent_not_registered',
        ref,
        `${ref.field} names an agent descriptor whose catalog row ${
          resolution.state === 'digest_mismatch' ? 'does not hash to the reference' : 'is not a descriptor in canonical form'
        }.`,
        { catalog: resolution.state },
      );
    case 'resolved':
      return agentKindMismatch(ref.kind, resolution.descriptor)
        ? refusal('agent_kind_mismatch', ref, `${ref.field}: a policy-engine's agent descriptor must name no model.`)
        : null;
  }
}

/** The hook `agentsSdkExtension` installs. */
export function agentCaptureHook(): AgentCaptureHook {
  return {
    async checkReferences(refs, ctx) {
      if (refs.length === 0) return null;
      const storage = ctx.host.storage;
      if (typeof storage.getAgentDescriptor !== 'function' || isCloudStore(storage)) return null;
      const read = new Map<string, AgentResolution>();
      for (const ref of refs) {
        let resolution = read.get(ref.agent);
        if (resolution === undefined) {
          resolution = await resolveAgentDescriptor(storage, ref.agent);
          read.set(ref.agent, resolution);
        }
        if (resolution.state === 'catalog_absent') return null;
        const refused = agentReferenceRefusal(ref, resolution);
        if (refused !== null) {
          ctx.host.log('agent_reference_refused', { field: ref.field, code: refused.code });
          return refused;
        }
      }
      return null;
    },
  };
}
