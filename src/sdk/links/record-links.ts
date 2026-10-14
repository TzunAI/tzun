/**
 * The links a stored record carries, read from its payload
 * (Record §8.2, §8.6): what `tzun.links.to` and the decision-graph walk
 * confirm an index row against. Nothing here reads the link index.
 */
import { isLinkRecord, isRelationName, type EvidenceEnvelope, type Link } from '@tzun/engine';

const BARE_DIGEST_RE = /^[0-9a-f]{64}$/;

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** A well-formed link: a relation name and a 64-hex target digest. */
export function wellFormedLink(link: unknown): link is Link {
  return (
    isPlainObject(link) &&
    isRelationName(link.rel) &&
    isPlainObject(link.target) &&
    typeof link.target.digest === 'string' &&
    BARE_DIGEST_RE.test(link.target.digest)
  );
}

/** A stored record's `links`, or `[]` when it has none or the member is not an array. */
export function linksOf(envelope: EvidenceEnvelope): unknown[] {
  return Array.isArray(envelope.payload?.links) ? (envelope.payload.links as unknown[]) : [];
}

/** A link record's first well-formed `subject` link, or `null` (also for a record that is not a link record). */
export function subjectLinkOf(envelope: EvidenceEnvelope): Link | null {
  if (!isLinkRecord(envelope.payload)) return null;
  const subject = linksOf(envelope).find((l) => wellFormedLink(l) && l.rel === 'subject');
  return subject !== undefined && wellFormedLink(subject) ? subject : null;
}

/**
 * The link at `idx` of a stored record when it is well formed, has the
 * relation `rel` and names `digest`; otherwise `null`. An index row is
 * confirmed this way before anything is drawn from it.
 */
export function carriedLink(envelope: EvidenceEnvelope, idx: number, rel: string, digest: string): Link | null {
  const link = linksOf(envelope)[idx];
  return wellFormedLink(link) && link.rel === rel && link.target.digest === digest ? link : null;
}
