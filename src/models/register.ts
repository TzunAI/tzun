/**
 * tzun.models.register — programmatic descriptor registration.
 *
 * Builds a fixed-shape `ModelDescriptor` (explicit nulls for unknown fields,
 * never `undefined`) from a partial input, optionally attaches a `modelDigest`
 * computed from a weights directory, then hands off to the storage adapter's
 * catalog (idempotent on identical canonical bytes).
 */
import { ModelDescriptor, ModelDescriptorRow } from '@tzun/engine';
import { StorageAdapter } from '@tzun/engine';
import { computeModelDigest } from './compute-model-digest';
import { MODEL_DIGEST_FORMAT as DESCRIPTOR_MODEL_DIGEST_FORMAT } from './descriptor-invariants';

export interface RegisterOptions {
  /**
   * When provided, the importer computes `modelDigest` via
   * `tzun-model-manifest-v1` and sets `integrityTier = 'weight-attested'`.
   */
  weightsPath?: string;
  /** Used for the catalog row's `firstRegisteredBy`. Defaults to `'cli'`. */
  registeredBy?: string;
  /** Provenance for the catalog row. Defaults to `'manual'`. */
  source?: ModelDescriptorRow['source'];
}

export async function registerModel(
  storage: StorageAdapter,
  descriptorIn: Partial<ModelDescriptor>,
  options: RegisterOptions = {},
): Promise<{ digest: string; descriptor: ModelDescriptor; alreadyExisted: boolean }> {
  const descriptor = await assembleDescriptor(descriptorIn, options);

  if (!storage.registerModelDescriptor) {
    // Safety net: every concrete in-tree adapter implements this, but a
    // custom user-supplied adapter might not.
    throw new Error(
      'catalog not supported by this storage adapter (registerModelDescriptor is undefined)',
    );
  }

  const { digest, alreadyExisted } = await storage.registerModelDescriptor(
    descriptor,
    options.source ?? 'manual',
    options.registeredBy ?? 'cli',
  );
  return { digest, descriptor, alreadyExisted };
}

async function assembleDescriptor(
  input: Partial<ModelDescriptor>,
  opts: RegisterOptions,
): Promise<ModelDescriptor> {
  const base = mvdFrom(input);
  if (opts.weightsPath) {
    const { modelDigest } = await computeModelDigest(opts.weightsPath);
    base.modelDigest = modelDigest;
    base.integrityTier = 'weight-attested';
  }
  return base;
}

/**
 * Build a fixed-shape ModelDescriptor with explicit nulls for fields the
 * caller didn't supply. Throws if any MVD field (vendor / modelName /
 * modelVersion) is missing.
 *
 * Integrity invariants enforced here:
 *
 *   modelDigest !== null  ↔  integrityTier === 'weight-attested'
 *   modelDigest === null  ↔  integrityTier === 'vendor-asserted'
 *
 * `integrityTier` is derived from `modelDigest`, never accepted as an
 * independent caller-supplied value. A caller that supplies a contradictory
 * pair (e.g. `weight-attested` with null digest, or `vendor-asserted` with
 * a digest attached) gets a hard error — silently rewriting the tier would
 * let a malicious or buggy caller misrepresent the integrity guarantee to
 * downstream UI / lineage / audit consumers.
 *
 * `modelDigest`, when non-null, MUST match `^sha256:[a-f0-9]{64}$` — the
 * exact shape produced by `computeModelDigest` / the model-manifest
 * algorithm. Garbage digests are rejected at registration so they cannot
 * reach storage.
 */
function mvdFrom(i: Partial<ModelDescriptor>): ModelDescriptor {
  const missing: string[] = [];
  if (!isNonEmptyString(i.vendor)) missing.push('vendor');
  if (!isNonEmptyString(i.modelName)) missing.push('modelName');
  if (!isNonEmptyString(i.modelVersion)) missing.push('modelVersion');
  if (missing.length > 0) {
    throw new Error(
      `Minimum Viable Descriptor requires non-empty string for: ${missing.join(', ')}`,
    );
  }

  const modelDigest = i.modelDigest ?? null;

  // Validate digest format BEFORE deriving the tier, so a malformed digest
  // produces a clear error rather than silently flipping the tier.
  if (modelDigest !== null && !MODEL_DIGEST_FORMAT.test(modelDigest)) {
    throw new Error(
      `modelDigest must match "sha256:<64 hex chars>" — got: ${truncate(modelDigest, 24)}`,
    );
  }

  const derivedTier: 'weight-attested' | 'vendor-asserted' =
    modelDigest !== null ? 'weight-attested' : 'vendor-asserted';

  if (i.integrityTier !== undefined && i.integrityTier !== derivedTier) {
    throw new Error(
      `integrityTier "${i.integrityTier}" is inconsistent with modelDigest ` +
      `(${modelDigest === null ? 'null' : 'set'}). The tier is derived from ` +
      `the digest: weight-attested iff modelDigest !== null. Omit integrityTier ` +
      `or align it with modelDigest.`,
    );
  }
  const integrityTier = derivedTier;

  const trainingIn = i.training ?? {
    trainingDataDigest: null,
    trainingDataRef: null,
    lastTrainingDate: null,
    evaluations: [],
  };

  return {
    descriptorVersion: 'd1',
    vendor: i.vendor as string,
    modelName: i.modelName as string,
    modelVersion: i.modelVersion as string,
    modelType: i.modelType ?? null,
    integrityTier,
    modelDigest,
    parentModelDescriptorDigest: i.parentModelDescriptorDigest ?? null,
    derivation: i.derivation ?? null,
    trainedBy: i.trainedBy ?? null,
    license: i.license ?? null,
    modelCardUrl: i.modelCardUrl ?? null,
    training: {
      trainingDataDigest: trainingIn.trainingDataDigest ?? null,
      trainingDataRef: trainingIn.trainingDataRef ?? null,
      lastTrainingDate: trainingIn.lastTrainingDate ?? null,
      evaluations: trainingIn.evaluations ?? [],
    },
    regulatoryMarkings: i.regulatoryMarkings ?? [],
    externalIdentifiers: i.externalIdentifiers ?? [],
  };
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

/**
 * Strict `sha256:` + 64 lowercase hex chars — the format `computeModelDigest`
 * produces. Shared with `assertDescriptorIntegrityInvariants`, which enforces
 * the same rule at the storage-adapter choke point for the paths that never
 * reach `mvdFrom`.
 */
const MODEL_DIGEST_FORMAT = DESCRIPTOR_MODEL_DIGEST_FORMAT;

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n) + '…';
}
