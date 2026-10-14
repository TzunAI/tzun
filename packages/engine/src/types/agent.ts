/**
 * The agent descriptor `tzun-agent/1` (Record §6.9): a content-addressed
 * description of one agent as configured at a moment. A decider or a step
 * actor names an agent by the descriptor's digest. Pure type definitions; the
 * rules are in `packages/engine/src/agent.ts`.
 */

/** @tzun-canonical-sort utf16 */
export interface AgentOperator {
  organization: string;
  /** The digest of the responsible person's credential registration record, or `null`. */
  owner: string | null;
}

/** One of the agent's keys. @tzun-canonical-sort utf16 */
export interface AgentKey {
  /** The RFC 7638 thumbprint, 43 characters of base64url. */
  kid: string;
  alg: 'EdDSA' | 'ES256' | 'PS256';
  custody: 'hsm' | 'tee' | 'workload' | 'software';
  attestation: string | null;
}

/** @tzun-canonical-sort utf16 */
export interface AgentRuntime {
  format: string;
  /** A set, sorted before hashing. */
  measurements: string[];
}

/**
 * Every member is present, `null` or an empty set where it does not apply.
 * Set members (`identities`, `keys` by `kid`, `models`, `runtime.measurements`)
 * are sorted before hashing. The digest is `sha256:` and the lowercase hex
 * SHA-256 of the canonical bytes.
 *
 * @tzun-canonical-sort utf16
 */
export interface AgentDescriptor {
  v: 'tzun-agent/1';
  name: string;
  operator: AgentOperator;
  /** Workload identities, e.g. SPIFFE IDs. */
  identities: string[];
  keys: AgentKey[];
  /** Model descriptor digests; `[]` for a policy engine. */
  models: string[];
  instructions: string | null;
  tools: string | null;
  runtime: AgentRuntime | null;
  policy: string | null;
  parent: string | null;
  derivation: 'base' | 'revision' | 'fork' | 'clone' | null;
}

/**
 * Why an agent descriptor or an agent reference is refused:
 *
 *   - `invalid_agent_descriptor`     the grammar or a writer limit;
 *   - `agent_not_registered`         a reference the store's catalog does not hold;
 *   - `agent_kind_mismatch`          a `policy-engine` whose descriptor names a model;
 *   - `agent_not_supported_by_store` a store that cannot keep the catalog.
 */
export type AgentViolationCode =
  | 'invalid_agent_descriptor'
  | 'agent_not_registered'
  | 'agent_kind_mismatch'
  | 'agent_not_supported_by_store';

/**
 * One agent descriptor an exported record bundles
 * (`ExportedEvidenceEnvelope.resolvedAgentDescriptors`), keyed by the agent
 * reference. A row is bundled with the bytes the catalog holds, verbatim, so
 * an offline verifier re-hashes them; a reference with no row is marked
 * `missing`, with `catalog_absent` when the exporting store keeps no catalog
 * and `not_registered` when its catalog holds no row under the reference.
 */
export type ExportedAgentDescriptorEntry =
  | {
      /** The bytes the catalog holds, verbatim. */
      canonicalBytes: string;
      name: string;
      organization: string;
      parent: string | null;
      registeredAt: string;
      missing?: false;
    }
  | {
      canonicalBytes: '';
      missing: true;
      reason: 'catalog_absent' | 'not_registered';
    };
