/**
 * Connector base — defines the `Connector` interface shape.
 *
 * A `Connector` extracts a per-decision AI-BOM from a vendor SDK call's
 * `(params, response)` pair. Connectors do **not** register the descriptor —
 * the wrapper layer handles registration + caching. Connectors are pure
 * transforms: same `(params, response, knownModels)` input → same
 * `AiBomSkeleton` output.
 *
 * Why a skeleton instead of the wire `AiBom`: the wrapper needs to register
 * the descriptor before it has a digest. The connector's job ends at
 * "here's the descriptor and the per-call envelope"; the wrapper substitutes
 * the digest, producing the canonical `AiBom` shape on the wire.
 */

import type { AiBom, ModelDescriptor } from '@tzun/engine';
import type { KnownModelsReference } from '../../models/known-models';

/**
 * Pre-registration shape returned by `Connector.buildAiBom`.
 *
 * `modelDescriptor` is the *unregistered* descriptor — its `modelDigest` may
 * be null (closed-vendor case); the wrapper layer computes the
 * `modelDescriptorDigest` over its canonical bytes and substitutes the
 * resulting digest into the wire `AiBom`.
 */
export interface AiBomSkeleton {
  modelDescriptor: ModelDescriptor;
  vendorFingerprint: string | null;
  promptTemplate: AiBom['promptTemplate'];
  inferenceParameters: AiBom['inferenceParameters'];
  infrastructure: AiBom['infrastructure'];
}

/**
 * A pure (params, response, knownModels) → AiBomSkeleton transform for a
 * single vendor surface. Implementations MUST be deterministic and MUST
 * NOT perform blocking I/O.
 *
 * Returning `null` is the canonical "this call has no AI-BOM" signal — e.g.
 * an embeddings call whose response carries no `model` field on the OpenAI
 * surface. The wrapper interprets `null` as "capture without `aiBom`".
 */
export interface Connector {
  /** Conventional vendor string (e.g., `'openai'`, `'anthropic'`). */
  vendor: string;
  /**
   * Pure transform from `(params, response, knownModels)` to an
   * `AiBomSkeleton`. Returns `null` when the call carries no resolvable
   * model identity.
   */
  buildAiBom(
    params: Record<string, unknown>,
    response: Record<string, unknown>,
    knownModels: KnownModelsReference,
  ): AiBomSkeleton | null;
}
