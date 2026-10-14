import { EvidenceEnvelope } from '@tzun/engine';

/**
 * Shared rules for the append-only revision log.
 *
 * ONE PLACE. Three adapters write these rows and a fourth (the Python twin)
 * mirrors the capture write. The revision number a write lands on and the
 * actor it is attributed to are decisions, not incidental details — get them
 * wrong in one adapter and a store's answer to "was this record rewritten
 * after capture" changes with the backend it happens to be on, which is
 * precisely the class of divergence the conformance suite exists to stop.
 * So the rules live here and the adapters call them.
 */

/**
 * The revision number `store()` always writes. Nothing else may write it.
 *
 * WRITE-ONCE PER `evidenceId`, EVER. `store()` normally refuses a duplicate
 * id long before it reaches this row, so the only way a second capture
 * revision could be attempted is a record that was DELETED and re-stored under
 * the same id — which on every adapter means the demo tamper hook, and in a
 * customer deployment means something that has no business happening. Every
 * adapter therefore inserts revision 0 conditionally and keeps the row that is
 * already there. Overwriting it would let "delete the row, put a rewritten
 * copy back under its id" redefine what the record was captured as, which is
 * the laundering this log exists to refuse — the original capture digest is
 * exactly the evidence that makes that rewrite visible.
 */
export const CAPTURE_REVISION_NO = 0;

/** Attribution for an unattended attestation re-stamp. */
export const REVISION_ACTOR_ATTESTATION = 'tzun-attestation';

/** Attribution for a link rewrite with no named operator. */
export const REVISION_ACTOR_RECOVERY = 'tzun-recovery';

/** Attribution for a capture whose envelope carries no custody entry. */
export const REVISION_ACTOR_SDK = 'tzun-sdk';

/**
 * Who the capture revision is attributed to.
 *
 * The first custody entry on a freshly assembled envelope is the
 * `decision_captured` one, and its actor is the human the evidence is about.
 * An envelope built by a caller that supplied no custody chain falls back to
 * the SDK itself rather than to an empty string — a revision row with a blank
 * actor reads as "nobody", which is a worse statement than "the SDK".
 */
export function captureRevisionActor(envelope: EvidenceEnvelope): string {
  return envelope.custodyChain[0]?.actor ?? REVISION_ACTOR_SDK;
}

/**
 * The revision number a NON-capture write lands on, given the highest
 * revision number the record already has (or `null` when it has none).
 *
 * The `null` case is the one that matters. A record captured before 0.3.16
 * has no revision rows at all, and the tempting thing to do is to write its
 * first row as revision 0 — "backfill the capture revision". That would be
 * laundering by migration: revision 0 is the assertion "this is the digest
 * the record was captured with", and at relink time the only digest available
 * is the one the record carries NOW, which is exactly the value in dispute.
 * Numbering the first row 1 instead leaves revision 0 absent, so
 * `getCaptureDigests()` keeps answering "unprovable" for that record and no
 * verifier is ever told a rewritten legacy record is clean.
 */
export function nextRevisionNo(highestExisting: number | null): number {
  return (highestExisting ?? CAPTURE_REVISION_NO) + 1;
}
