/**
 * The decision graph: a bounded walk over the links of this store's records
 * and the statements of link records.
 *
 * From a record, the walk follows:
 *
 *   - its own links: an edge from the record to each target, asserted by the
 *     record itself;
 *   - when the record is a link record, its statements (an edge from its
 *     subject to each target, asserted by the link record) and its `subject`
 *     link;
 *   - the statements of link records about it, found through the link index
 *     (`evidence_links`): link records that state a relation towards it (an
 *     edge from their subject to it), and link records whose subject it is
 *     (an edge from it to each target they name). Such a link record is the
 *     asserter of those edges, not a node of the walk.
 *
 * It does not follow a link towards the record from a record that is not a
 * link record: the records derived from a decision are found with
 * `tzun.links.to`, a page at a time.
 *
 * Every edge names the record that asserts it (`assertedBy`) and that
 * record's decider, and says whether it is a link record's statement, so a
 * relation a third party stated is never shown as the target's own. The
 * index is used to find link records only: each one is read, and an edge is
 * drawn from the link the record actually carries, never from an index row
 * alone. A node and an asserting record each say whether their payload
 * recomputes to their stored digest (`intact`, `assertedByIntact`).
 *
 * Depth counts the steps of the walk, not edges: a link record found from a
 * node contributes all of its statements in that step, so every endpoint
 * they name is one deeper than that node, including a target two edges away
 * through the link record's subject.
 *
 * Bounds: a depth (default 16; the root is at depth 0, and edges between
 * nodes already found are still drawn at the last depth), a node budget
 * (`maxNodes`, default 1,000), a visited set (records can state cycles:
 * one link record says A supersedes B, another B supersedes A), and one page
 * of the index per node and kind (100 rows), so a flood of link records at
 * one target costs one bounded page, not a scan. A walk that stops early for
 * any of these reports `truncated: true` and names the bounds in
 * `truncatedBy`.
 *
 * Nodes are record digests (64 lowercase hex), so a target held in another
 * store is a node too (`held: false`).
 */
import {
  isLinkRecord,
  isRelationName,
  type EvidenceEnvelope,
  type Link,
} from '@tzun/engine';
import type { DecisionGraphApi, DecisionGraphEdge, DecisionGraphWalk } from './extension-points';
import { LINK_INDEX_MAX_RELS } from '../storage/links-sql';
import { carriedLink, linksOf, subjectLinkOf, wellFormedLink } from './links/record-links';
import { LinksNotSupportedError } from './links/service';
import { recordIntact, type LinkStoreReads } from './links/store-reads';

/** The depth a walk goes to when the caller names none. */
export const DECISION_GRAPH_DEFAULT_DEPTH = 16;
/** The deepest walk. */
export const DECISION_GRAPH_MAX_DEPTH = 256;
/** The node budget when the caller names none. */
export const DECISION_GRAPH_DEFAULT_MAX_NODES = 1_000;
/** The largest node budget. */
export const DECISION_GRAPH_MAX_NODES = 100_000;
/** Index rows read per node and kind (statements towards it; link records about it). */
export const DECISION_GRAPH_PAGE = 100;

/** Why a walk is refused. */
export type DecisionGraphErrorCode = 'invalid_evidence_id' | 'record_not_found' | 'invalid_depth' | 'invalid_max_nodes' | 'invalid_relation';

/** A walk the decision graph refuses. Never echoes the value. */
export class DecisionGraphError extends Error {
  constructor(
    readonly code: DecisionGraphErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'DecisionGraphError';
    Object.setPrototypeOf(this, DecisionGraphError.prototype);
  }
}

/** A record found by the walk. */
export interface DecisionGraphNode {
  /** The record's digest: its stored canonical digest when held, else the digest a link names. */
  digest: string;
  /** Its evidence id: the held record's, else the one a link names, else `null`. */
  evidenceId: string | null;
  /** Whether this store holds it. */
  held: boolean;
  /** How many edges from the root it was found at. */
  depth: number;
  /** A held record's `aiSystemId`. */
  aiSystemId?: string;
  /** Whether a held record's payload recomputes to its stored digest. */
  intact?: boolean;
}

/** One edge: `from` has the relation `rel` to `to`, as the record `assertedBy` states. */
export interface DecisionGraphEdgeDetail extends DecisionGraphEdge {
  /** The evidence id of the record that carries the link. */
  assertedBy: string;
  /** That record's digest. */
  assertedByDigest: string;
  /** The link's index in that record's `links`. */
  linkIndex: number;
  /** Whether the edge is a link record's statement about its subject (a relation a third party stated). */
  statement: boolean;
  /** The asserting record's decider (`kind` and `id`), or `null` when it has none. */
  decider: { kind: string; id: string } | null;
  /** Whether the asserting record's payload recomputes to its stored digest. */
  assertedByIntact: boolean;
}

/** What a walk found. */
export interface DecisionGraphResult extends DecisionGraphWalk {
  /** The root record's digest. */
  root: string;
  rootEvidenceId: string;
  /** Every node's digest, in the order found, the root first. */
  nodes: string[];
  /** Each node, by digest. */
  details: Record<string, DecisionGraphNode>;
  edges: DecisionGraphEdgeDetail[];
  truncated: boolean;
  /** Which bounds stopped the walk: `depth`, `maxNodes`, `page`. */
  truncatedBy: Array<'depth' | 'maxNodes' | 'page'>;
}

/** The options of a walk. */
export interface DecisionGraphOptions {
  /** Follow only these relations (a link record's `subject` link included). */
  rels?: string[];
  /** 0 to 256; default 16. */
  depth?: number;
  /** 1 to 100,000; default 1,000. */
  maxNodes?: number;
}

/** `tzun.decisionGraph` as this module serves it. */
export interface DecisionGraphService extends DecisionGraphApi {
  walk(evidenceId: string, options?: DecisionGraphOptions): Promise<DecisionGraphResult>;
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

function deciderOf(envelope: EvidenceEnvelope): { kind: string; id: string } | null {
  const d = envelope.payload?.decider as unknown;
  return isPlainObject(d) && typeof d.kind === 'string' && typeof d.id === 'string' ? { kind: d.kind, id: d.id } : null;
}

function checkOptions(evidenceId: unknown, options: DecisionGraphOptions | undefined): { depth: number; maxNodes: number; rels: Set<string> | null } {
  if (typeof evidenceId !== 'string' || evidenceId.length === 0) {
    throw new DecisionGraphError('invalid_evidence_id', 'evidenceId must be a non-empty string');
  }
  const o = isPlainObject(options) ? options : {};
  const depth = o.depth ?? DECISION_GRAPH_DEFAULT_DEPTH;
  if (typeof depth !== 'number' || !Number.isSafeInteger(depth) || depth < 0 || depth > DECISION_GRAPH_MAX_DEPTH) {
    throw new DecisionGraphError('invalid_depth', `depth must be an integer from 0 to ${DECISION_GRAPH_MAX_DEPTH}`);
  }
  const maxNodes = o.maxNodes ?? DECISION_GRAPH_DEFAULT_MAX_NODES;
  if (typeof maxNodes !== 'number' || !Number.isSafeInteger(maxNodes) || maxNodes < 1 || maxNodes > DECISION_GRAPH_MAX_NODES) {
    throw new DecisionGraphError('invalid_max_nodes', `maxNodes must be an integer from 1 to ${DECISION_GRAPH_MAX_NODES}`);
  }
  let rels: Set<string> | null = null;
  if (o.rels !== undefined) {
    if (!Array.isArray(o.rels) || o.rels.length > LINK_INDEX_MAX_RELS || !o.rels.every((r) => isRelationName(r))) {
      throw new DecisionGraphError('invalid_relation', `rels must be an array of at most ${LINK_INDEX_MAX_RELS} relation names`);
    }
    rels = new Set(o.rels as string[]);
  }
  return { depth, maxNodes, rels };
}

/** `tzun.decisionGraph` over `reads`. */
export function decisionGraphService(reads: LinkStoreReads): DecisionGraphService {
  return {
    async walk(evidenceId, options) {
      const { depth: maxDepth, maxNodes, rels } = checkOptions(evidenceId, options);
      if (reads.linksTo === null || reads.byDigest === null) throw new LinksNotSupportedError('tzun.decisionGraph.walk');
      const linksTo = reads.linksTo;
      const byDigest = reads.byDigest;

      const rootEnvelope = await reads.byId(evidenceId);
      if (rootEnvelope === null) throw new DecisionGraphError('record_not_found', 'the store holds no record with this evidence id');

      // Records read once per walk: by digest for nodes, by evidence id for asserting link records.
      const byDigestCache = new Map<string, EvidenceEnvelope | null>();
      const byIdCache = new Map<string, EvidenceEnvelope | null>();
      const recordAt = async (digest: string): Promise<EvidenceEnvelope | null> => {
        if (!byDigestCache.has(digest)) byDigestCache.set(digest, await byDigest(digest));
        return byDigestCache.get(digest) ?? null;
      };
      const recordById = async (id: string): Promise<EvidenceEnvelope | null> => {
        if (!byIdCache.has(id)) byIdCache.set(id, await reads.byId(id));
        return byIdCache.get(id) ?? null;
      };
      const intact = new Map<string, boolean>();
      const intactOf = (envelope: EvidenceEnvelope): boolean => {
        const key = envelope.payload.evidenceId;
        if (!intact.has(key)) intact.set(key, recordIntact(envelope));
        return intact.get(key)!;
      };

      const root = rootEnvelope.integrity.canonicalDigest;
      byDigestCache.set(root, rootEnvelope);
      const nodes: string[] = [];
      const details: Record<string, DecisionGraphNode> = {};
      const edges: DecisionGraphEdgeDetail[] = [];
      const edgeKeys = new Set<string>();
      const truncatedBy = new Set<'depth' | 'maxNodes' | 'page'>();
      const queue: string[] = [];

      const known = (digest: string): boolean => Object.prototype.hasOwnProperty.call(details, digest);

      const addNode = (digest: string, depth: number, evidenceId: string | null): void => {
        if (known(digest)) {
          const node = details[digest];
          if (node.evidenceId === null && evidenceId !== null && !node.held) node.evidenceId = evidenceId;
          return;
        }
        nodes.push(digest);
        details[digest] = { digest, evidenceId, held: false, depth };
        queue.push(digest);
      };

      /**
       * Whether the walk may take the endpoints `digests` at `depth`: each is
       * already a node, or every new one fits the depth bound and the node
       * budget together. When not, the bound that stops it is recorded.
       */
      const fits = (digests: readonly string[], depth: number): boolean => {
        const fresh = new Set(digests.filter((d) => !known(d)));
        if (fresh.size === 0) return true;
        if (depth > maxDepth) {
          truncatedBy.add('depth');
          return false;
        }
        if (nodes.length + fresh.size > maxNodes) {
          truncatedBy.add('maxNodes');
          return false;
        }
        return true;
      };

      /** Draw an edge from a link `asserter` carries; its endpoints become nodes one deeper than `depth`. */
      const addEdge = (
        asserter: EvidenceEnvelope,
        linkIndex: number,
        from: { digest: string; evidenceId: string | null },
        to: { digest: string; evidenceId: string | null },
        rel: string,
        statement: boolean,
        depth: number,
      ): void => {
        if (rels !== null && !rels.has(rel)) return;
        const assertedByDigest = asserter.integrity.canonicalDigest;
        const key = `${assertedByDigest}#${linkIndex}`;
        if (edgeKeys.has(key)) return;
        // Both endpoints or neither: an edge never leaves a node behind without it.
        if (!fits([from.digest, to.digest], depth + 1)) return;
        addNode(from.digest, depth + 1, from.evidenceId);
        addNode(to.digest, depth + 1, to.evidenceId);
        edgeKeys.add(key);
        edges.push({
          from: from.digest,
          to: to.digest,
          rel,
          assertedBy: asserter.payload.evidenceId,
          assertedByDigest,
          linkIndex,
          statement,
          decider: deciderOf(asserter),
          assertedByIntact: intactOf(asserter),
        });
      };

      const targetOf = (link: Link) => ({
        digest: link.target.digest,
        evidenceId: typeof link.target.evidenceId === 'string' ? link.target.evidenceId : null,
      });

      /**
       * The edges a link record states, drawn from the record itself: each
       * statement (from its subject to the target), and, when the link record
       * is itself a node of the walk, its own `subject` link. A link record
       * found through the index is the asserter of its statements, not a node.
       */
      const linkRecordEdges = (record: EvidenceEnvelope, depth: number, asNode: boolean): void => {
        const subject = subjectLinkOf(record);
        if (subject === null) return;
        const self = { digest: record.integrity.canonicalDigest, evidenceId: record.payload.evidenceId };
        linksOf(record).forEach((link, j) => {
          if (!wellFormedLink(link)) return;
          if (link.rel !== 'subject') addEdge(record, j, targetOf(subject), targetOf(link), link.rel, true, depth);
          else if (asNode) addEdge(record, j, self, targetOf(link), 'subject', false, depth);
        });
      };

      addNode(root, 0, rootEnvelope.payload.evidenceId);
      while (queue.length > 0) {
        const digest = queue.shift()!;
        const node = details[digest];
        const record = await recordAt(digest);
        if (record !== null) {
          node.held = true;
          node.evidenceId = record.payload.evidenceId;
          node.aiSystemId = record.payload.aiSystemId;
          node.intact = intactOf(record);
          if (isLinkRecord(record.payload)) {
            linkRecordEdges(record, node.depth, true);
          } else {
            const self = { digest, evidenceId: record.payload.evidenceId };
            linksOf(record).forEach((link, j) => {
              if (wellFormedLink(link)) addEdge(record, j, self, targetOf(link), link.rel, false, node.depth);
            });
          }
        }

        // Link records' statements towards this node, and link records about it.
        const towards = await linksTo(digest, { statements: true, limit: DECISION_GRAPH_PAGE, ...(rels !== null && { rels: [...rels] }) });
        const about = await linksTo(digest, { rels: ['subject'], limit: DECISION_GRAPH_PAGE });
        if (towards.cursor !== null || about.cursor !== null) truncatedBy.add('page');
        for (const row of [...towards.rows, ...about.rows]) {
          const asserter = await recordById(row.evidenceId);
          if (asserter === null) continue;
          // Only what the record itself carries: an index row that does not
          // match the record's link (or a record that is not a link record)
          // draws nothing.
          if (carriedLink(asserter, row.idx, row.rel, digest) === null || subjectLinkOf(asserter) === null) continue;
          linkRecordEdges(asserter, node.depth, false);
        }
      }

      return {
        root,
        rootEvidenceId: rootEnvelope.payload.evidenceId,
        nodes,
        details,
        edges,
        truncated: truncatedBy.size > 0,
        truncatedBy: [...truncatedBy],
      };
    },
  };
}
