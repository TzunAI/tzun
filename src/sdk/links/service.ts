/**
 * `tzun.links`: link records (Record §8.6), a record's links with their
 * resolution in this store, and the records that link to a digest.
 */
import {
  LINK_RECORD_ACTION,
  isLinkRecord,
  verifyEnvelope,
  type CaptureResult,
  type DeciderInput,
  type EvidenceEnvelope,
  type Link,
  type LinkInput,
  type LinkRelationCheck,
  type LinksCheck,
  type StorageAdapter,
} from '@tzun/engine';
import type { LinksApi, SdkHost, SystemRecordCapture, SystemRecordCaptureOptions } from '../extension-points';
import type { PreparedAssertionChallenge } from '../index';
import { checkLinkIndexQuery, type LinkIndexQuery, type LinkIndexRow } from '../../storage/links-sql';
import { carriedLink, subjectLinkOf } from './record-links';
import { originBuilder, recordIntact, type LinkStoreReads } from './store-reads';

/** `tzun.links.to` or the decision-graph walk on a store without the link index (the cloud transport, or an adapter without it). */
export class LinksNotSupportedError extends Error {
  readonly code = 'links_not_supported_by_store' as const;
  constructor(what: string) {
    super(`${what} is not available: this store has no link index (tzun.links.to and the decision-graph walk need one).`);
    this.name = 'LinksNotSupportedError';
    Object.setPrototypeOf(this, LinksNotSupportedError.prototype);
  }
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** What `tzun.links.relate` captures: a link record stating relations of `subject` (Record §8.6). */
export interface RelateRequest {
  /** The record the relations are about. A record held in another store is passed with `external: true`. */
  subject: LinkInput['target'];
  /** At least one relation; never `subject`, `root`, `mandate`, `revokes`, `closes` or `fanoutOf`. */
  relations: Array<{ rel: string; target: LinkInput['target']; attrs?: Link['attrs'] }>;
  /** Why the relationship is recorded: the record's `reason`. */
  reason: string;
  /** Who asserts it: the link record's decider. */
  decider: DeciderInput;
}

/** Where a held target is in this store. */
export interface HeldTargetPosition {
  evidenceId: string;
  /** The chain the target belongs to; `null` when the store does not say. */
  chainId: string | null;
  sequenceNumber: number;
}

/** One link of a record with its resolution in this store and its row of the store-level verdict. */
export interface LinkResolution {
  index: number;
  link: Link;
  /** Whether this store holds a record with the target's digest. */
  held: boolean;
  /** Where the held target is; `null` when it is not held. */
  target: HeldTargetPosition | null;
  /** The `links[<i>]` row of store-level verification (Verification §4.11). */
  check: LinkRelationCheck;
}

/**
 * One row of `tzun.links.to`: a link a stored record carries towards the
 * digest, read from the record. `linkRecord` says the record is a link
 * record; `statement` that the link is one of its statements, a relation of
 * its subject (`subjectDigest`) rather than of the link record itself;
 * `intact` that the record's payload recomputes to its stored digest.
 */
export interface LinkToRow extends LinkIndexRow {
  linkRecord: boolean;
  statement: boolean;
  intact: boolean;
}

/** `tzun.links` as this module serves it: `LinksApi` and what it adds. */
export interface LinksService extends LinksApi {
  relate(request: RelateRequest, options?: SystemRecordCaptureOptions): Promise<CaptureResult>;
  /** The link record `relate(request)` would capture next, and the challenge a per-record signature over it signs. */
  prepareRelate(request: RelateRequest): Promise<PreparedAssertionChallenge>;
  of(evidenceId: string): Promise<LinkResolution[] | null>;
  /**
   * A page of the link index for `digest`, each row confirmed against the
   * record it names: a row whose record is gone, or whose link at `idx` is
   * not a well-formed link with that relation towards `digest`, is left out.
   * A page can therefore hold fewer rows than `limit` while `cursor` still
   * continues the index.
   */
  to(digest: string, options?: Omit<LinkIndexQuery, 'statements'>): Promise<{ rows: LinkToRow[]; cursor: string | null }>;
}

/** The system record `relate` captures. */
function linkRecordRequest(request: RelateRequest): SystemRecordCapture {
  const r = isPlainObject(request) ? request : ({} as RelateRequest);
  const relations = Array.isArray(r.relations) ? r.relations : [];
  const links: LinkInput[] = [
    ...relations.map((relation) => {
      const x = isPlainObject(relation) ? relation : ({} as RelateRequest['relations'][number]);
      return { rel: x.rel, target: x.target, ...(x.attrs !== undefined && { attrs: x.attrs }) } as LinkInput;
    }),
    { rel: 'subject', target: r.subject },
  ];
  return {
    kind: 'link',
    aiOutput: {},
    action: LINK_RECORD_ACTION,
    reason: r.reason,
    decider: r.decider,
    links,
    allowReserved: ['subject'],
    linkRecord: true,
  };
}

/** The store, with model descriptors left out: `of` reports links, and resolves no step model. */
function withoutDescriptors(storage: StorageAdapter): StorageAdapter {
  return Object.create(storage, { getModelDescriptor: { value: undefined } }) as StorageAdapter;
}

/** The `links` row of store-level verification for a stored record (of bundle-level verification when the store cannot look a digest up). */
async function linksCheck(host: SdkHost, reads: LinkStoreReads, envelope: EvidenceEnvelope): Promise<LinksCheck | undefined> {
  if (reads.byDigest === null) return verifyEnvelope(envelope).links;
  const prefix = await reads.ownOriginPrefix();
  const result = await verifyEnvelope(envelope, undefined, undefined, {
    storage: withoutDescriptors(host.storage),
    walkLineage: false,
    ...(prefix !== null && { evidenceLogOrigin: originBuilder(prefix) }),
  });
  return result.links;
}

/**
 * An index row as the record it names states it, or `null` when the record
 * is gone or does not carry that link (an index row alone never makes a
 * row of `to`).
 */
async function confirmRow(
  reads: LinkStoreReads,
  row: LinkIndexRow,
  digest: string,
  cache: Map<string, EvidenceEnvelope | null>,
): Promise<LinkToRow | null> {
  if (!cache.has(row.evidenceId)) cache.set(row.evidenceId, await reads.byId(row.evidenceId));
  const envelope = cache.get(row.evidenceId) ?? null;
  if (envelope === null) return null;
  const link = carriedLink(envelope, row.idx, row.rel, digest);
  if (link === null) return null;
  const linkRecord = isLinkRecord(envelope.payload);
  const statement = linkRecord && link.rel !== 'subject';
  const subject = statement ? subjectLinkOf(envelope) : null;
  return {
    evidenceId: row.evidenceId,
    idx: row.idx,
    rel: link.rel,
    targetDigest: digest,
    subjectDigest: subject === null ? null : subject.target.digest,
    linkRecord,
    statement,
    intact: recordIntact(envelope),
  };
}

/** `tzun.links` over `host`'s store. */
export function linksService(host: SdkHost, reads: LinkStoreReads): LinksService {
  return {
    relate(request, options) {
      return host.captureSystemRecord(linkRecordRequest(request), options);
    },

    prepareRelate(request) {
      return host.prepareSystemRecord(linkRecordRequest(request));
    },

    async of(evidenceId) {
      if (typeof evidenceId !== 'string' || evidenceId.length === 0) return null;
      const envelope = await reads.byId(evidenceId);
      if (envelope === null) return null;
      const links = Array.isArray(envelope.payload?.links) ? (envelope.payload.links as Link[]) : [];
      if (links.length === 0) return [];
      const check = await linksCheck(host, reads, envelope);
      const rows = check?.relations ?? [];
      const positions = new Map<string, HeldTargetPosition | null>();
      const out: LinkResolution[] = [];
      for (let index = 0; index < links.length; index++) {
        const link = links[index];
        const digest = isPlainObject(link) && isPlainObject(link.target) ? link.target.digest : undefined;
        let position: HeldTargetPosition | null = null;
        if (typeof digest === 'string' && reads.byDigest !== null) {
          if (!positions.has(digest)) {
            const held = await reads.byDigest(digest);
            positions.set(
              digest,
              held === null
                ? null
                : {
                    evidenceId: held.payload.evidenceId,
                    chainId: await host.storage.getChainForRecord(held.payload.evidenceId),
                    sequenceNumber: held.payload.sequenceNumber,
                  },
            );
          }
          position = positions.get(digest) ?? null;
        }
        out.push({
          index,
          link,
          held: position !== null,
          target: position,
          // A link without a row of its own is blocked by the `links` row (Verification §4.11), which
          // is itself blocked when the record does not recompute to its stored digest.
          check: rows[index] ?? { index, rel: isPlainObject(link) ? String(link.rel) : '', outcome: 'not-checked', valid: null, reason: 'blocked_by:links' },
        });
      }
      return out;
    },

    async to(digest, options) {
      const checked = checkLinkIndexQuery(digest, options);
      if (reads.linksTo === null) throw new LinksNotSupportedError('tzun.links.to');
      const page = await reads.linksTo(checked.digest, {
        ...(options?.rels !== undefined && { rels: options.rels }),
        ...(options?.limit !== undefined && { limit: options.limit }),
        ...(options?.cursor !== undefined && { cursor: options.cursor }),
      });
      const cache = new Map<string, EvidenceEnvelope | null>();
      const rows: LinkToRow[] = [];
      for (const row of page.rows) {
        const confirmed = await confirmRow(reads, row, checked.digest, cache);
        if (confirmed !== null) rows.push(confirmed);
      }
      return { rows, cursor: page.cursor };
    },
  };
}
