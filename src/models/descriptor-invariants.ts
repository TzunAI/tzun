/**
 * The two integrity invariants every `ModelDescriptor` must satisfy before it
 * can enter the catalog, in one place so every registration path enforces
 * them.
 *
 *   modelDigest !== null  ↔  integrityTier === 'weight-attested'
 *   modelDigest === null  ↔  integrityTier === 'vendor-asserted'
 *   modelDigest, when set, matches ^sha256:[a-f0-9]{64}$
 *
 * `register.ts`'s `mvdFrom` has always checked this, but it is only on the
 * `tzun.models.register` path. The connector path
 * (`wrappers.ts` → `storage.registerModelDescriptor`) and the inline-AI-BOM
 * capture path (`sdk/index.ts` → `storage.registerModelDescriptor`) bypass it
 * entirely, so an enrichment entry or an embedder catalog could mint a
 * `weight-attested` descriptor carrying `modelDigest: null` — the strongest
 * integrity claim the product makes, attached to nothing, and a state
 * `register.ts` refuses outright. Asserting inside the adapters makes the
 * catalog write itself the choke point.
 */
import type { ModelDescriptor } from '@tzun/engine';

/** Strict `sha256:` + 64 lowercase hex chars — the format `computeModelDigest` produces. */
export const MODEL_DIGEST_FORMAT = /^sha256:[a-f0-9]{64}$/;

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n) + '…';
}

/**
 * Throws if `descriptor` violates the tier↔digest correspondence or carries a
 * malformed `modelDigest`. Silently rewriting either would let a buggy or
 * hostile caller misrepresent the integrity guarantee to the UI, the lineage
 * walk and the export bundle, so this fails loudly instead.
 */
export function assertDescriptorIntegrityInvariants(
  descriptor: Pick<ModelDescriptor, 'integrityTier' | 'modelDigest'>,
  context = 'descriptor',
): void {
  const modelDigest = descriptor.modelDigest ?? null;

  if (modelDigest !== null && !MODEL_DIGEST_FORMAT.test(modelDigest)) {
    throw new Error(
      `${context}: modelDigest must match "sha256:<64 hex chars>" — got: ${truncate(String(modelDigest), 24)}`,
    );
  }

  const derivedTier: 'weight-attested' | 'vendor-asserted' =
    modelDigest !== null ? 'weight-attested' : 'vendor-asserted';

  if (descriptor.integrityTier !== derivedTier) {
    throw new Error(
      `${context}: integrityTier "${descriptor.integrityTier}" is inconsistent with ` +
        `modelDigest (${modelDigest === null ? 'null' : 'set'}). The tier is derived from ` +
        `the digest: weight-attested iff modelDigest !== null.`,
    );
  }
}
