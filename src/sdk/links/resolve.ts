/**
 * Link-target resolution at capture (Record §8.7): the link service's
 * capture hook. For each link input, in input order, the record of this
 * store the target names, which the engine's `buildLinks` then fills the
 * target from and checks the caller's members against.
 *
 *   - Without `external`: by `evidenceId` when the input gives one,
 *     otherwise by `digest` (Record §8.7). A target this store does not hold
 *     is answered `null`, which `buildLinks` refuses
 *     (`link_target_not_found`): a mistyped same-store target never becomes
 *     a link to a record that does not exist.
 *   - With `external: true`: the same reads, each tried in turn (evidence
 *     id, digest), then a locator naming an evidence log of this store. A
 *     target that resolves here is a same-store target. A locator naming a
 *     position of this store that holds no record is refused
 *     (`link_target_not_found`); any other unresolved target is written as
 *     given.
 *
 * A list longer than the engine's 256-link limit is refused
 * (`too_many_links`) before the first read, so no capture reads the store
 * more than a bounded number of times.
 *
 * A held record is checked digest first: its stored payload must recompute
 * to its stored digest, or the capture is refused (`link_target_mismatch`
 * on `target.digest`), so a record is never linked to bytes that are not the
 * ones its digest names. The one exception is an `external` target the
 * caller named by that record's stored digest: it is written as given, and
 * store-level verification reports the damaged copy on that link, so a
 * damaged copy cannot block a record that names it (a revocation).
 * `buildLinks` then compares every member the caller supplied with the held
 * record: the digest, the evidence id, the locator's origin and sequence
 * number.
 *
 * On a store that cannot read a record's log origin (the cloud transport),
 * a supplied locator's origin is taken as the held record's, so the locator
 * is written when its `seq` is the record's sequence number and refused
 * otherwise; the hosted service checks the locator of every held target
 * when it takes the record. An omitted locator stays `null` there.
 *
 * Every read is of the instance's own store (`store-reads.ts`): resolution
 * never crosses a store, or, on the cloud transport, a tenant.
 */
import { LINKS_MAX, isEvidenceLogOrigin, type HeldLinkTarget, type LinkInput } from '@tzun/engine';
import type { CaptureRefusal, LinkCaptureHook } from '../extension-points';
import { heldTargetOf, recordIntact, type LinkStoreReads } from './store-reads';

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

function refusal(code: string, field: string, message: string): CaptureRefusal {
  return { failureType: 'validation_failure', code, field, message: `${field}: ${message}` };
}

/** The held record one input names, `null` when this store holds none, or a refusal. */
async function resolveOne(reads: LinkStoreReads, input: unknown, i: number): Promise<HeldLinkTarget | null | CaptureRefusal> {
  // A malformed input is left to `buildLinks`, which refuses it by its shape.
  if (!isPlainObject(input) || !isPlainObject(input.target)) return null;
  const t = input.target;
  const field = `links[${i}].target`;
  const external = t.external === true;
  const hasId = typeof t.evidenceId === 'string';
  const hasDigest = typeof t.digest === 'string';

  let envelope = hasId ? await reads.byId(t.evidenceId as string) : null;
  if (envelope === null && hasDigest && (external || !hasId)) {
    if (reads.byDigest !== null) {
      envelope = await reads.byDigest(t.digest as string);
    } else if (!external) {
      return refusal(
        'links_not_supported_by_store',
        field,
        'this store cannot look a record up by digest: name the target by evidenceId, or pass external: true for a record of another store',
      );
    }
  }
  if (envelope === null && external && isPlainObject(t.locator)) {
    const at = await reads.atLocator({ origin: t.locator.origin, seq: t.locator.seq });
    if (at.own && at.envelope === null) {
      return refusal('link_target_not_found', field, 'the locator names a position of this store that holds no record');
    }
    envelope = at.envelope;
  }
  if (envelope === null) return null;
  if (!recordIntact(envelope)) {
    // The store's copy is damaged. A target the caller marked external and
    // named by the record's stored digest is written as given; store-level
    // verification reports the damaged copy on this link.
    if (external && hasDigest && t.digest === envelope.integrity?.canonicalDigest) return null;
    return refusal(
      'link_target_mismatch',
      `${field}.digest`,
      'the record the target names does not recompute to its stored digest; it cannot be linked',
    );
  }
  const held = await heldTargetOf(reads, envelope);
  if (held.origin === null && !reads.confirmsOrigin && isPlainObject(t.locator) && isEvidenceLogOrigin(t.locator.origin)) {
    // This store cannot read the record's log origin: the supplied one is
    // taken, and `buildLinks` still refuses a `seq` that is not the record's.
    return { ...held, origin: t.locator.origin };
  }
  return held;
}

/**
 * Resolve every input's target, in input order (`LinkCaptureHook.resolveTargets`).
 * Called before any sequence number is taken and outside the chain-head
 * transaction (inside the instance's capture queue): a stored record never
 * changes, so the reads cannot go stale. A list `buildLinks` refuses without
 * a read (not an array, empty, over the 256-link limit) reads nothing.
 */
export async function resolveLinkTargets(
  reads: LinkStoreReads,
  inputs: readonly LinkInput[],
): Promise<ReadonlyArray<HeldLinkTarget | null> | CaptureRefusal> {
  if (!Array.isArray(inputs) || inputs.length === 0) return [];
  if (inputs.length > LINKS_MAX) return refusal('too_many_links', 'links', `links holds at most ${LINKS_MAX} links`);
  const held: Array<HeldLinkTarget | null> = [];
  for (let i = 0; i < inputs.length; i++) {
    const one = await resolveOne(reads, inputs[i], i);
    if (one !== null && 'failureType' in one) return one;
    held.push(one);
  }
  return held;
}

/** The link service's capture hook over `reads`. */
export function linkCaptureHook(reads: LinkStoreReads): LinkCaptureHook {
  return {
    resolveTargets: (inputs) => resolveLinkTargets(reads, inputs),
  };
}
