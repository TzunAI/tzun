/**
 * The argument rule for `StorageAdapter.listByMissingObtainable()`, stated
 * once for every backend.
 *
 * The query is the pending-attestation retry's work queue, so it takes only
 * components the retry obtains. `'anchor'` is refused like any other: an
 * anchor is published for a batch of records and filled in by the anchor
 * scheduler, and listing records by it would put every record waiting for an
 * epoch back on the retry's page.
 */
import { isRetryObtainableComponent } from '@tzun/engine';
import type { AttestationArtifacts, RetryObtainableComponent } from '@tzun/engine';
import { isAbsent } from './attestation-fill';

/** The artifact that holds each retry-obtainable component. */
const ARTIFACT_OF: Record<RetryObtainableComponent, keyof AttestationArtifacts> = {
  timestamp: 'rfc3161Token',
};

/**
 * Whether a record lacks `component`: its artifact is absent, null or an
 * empty string. That is the fill rule's absence (`isAbsent`), so every record
 * listed is one `updateAttestation()` can fill. The SQL adapters state the
 * same test in SQL.
 */
export function lacksRetryObtainable(
  artifacts: AttestationArtifacts | undefined,
  component: RetryObtainableComponent,
): boolean {
  return isAbsent(artifacts?.[ARTIFACT_OF[component]]);
}

/**
 * Return `components` without repeats, or throw a TypeError naming the first
 * entry that is not a retry-obtainable component.
 */
export function assertRetryObtainableComponents(
  components: readonly unknown[],
): RetryObtainableComponent[] {
  if (!Array.isArray(components)) {
    throw new TypeError(
      `listByMissingObtainable: components must be an array (got ${typeof components}).`,
    );
  }
  for (const component of components) {
    if (!isRetryObtainableComponent(component)) {
      throw new TypeError(
        `listByMissingObtainable: '${String(component)}' is not a retry-obtainable component. ` +
          "The retry obtains 'timestamp'. An anchor is published for a batch of records, " +
          'never obtained for one, so no record is listed by it.',
      );
    }
  }
  return [...new Set(components as RetryObtainableComponent[])];
}
