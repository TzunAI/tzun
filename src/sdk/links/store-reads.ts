/**
 * What the link service reads of its own store (Record §8.7, §8.8): a
 * record by evidence id, by digest, or at a position of one of its evidence
 * logs, and the evidence-log origin of a record's chain. Every read goes
 * through the instance's store and nothing else, so resolution never crosses
 * a store (and, on the cloud transport, never leaves the API key's tenant:
 * the hosted service answers another tenant's id as it answers an id that
 * exists nowhere). The chains of one store are not tenants: resolution,
 * `tzun.links.to` and the walk read every chain of the store, so an
 * integrator who must keep customers apart keeps them in separate stores.
 */
import {
  V1_0_HASHED_FIELDS,
  canonicalSerialize,
  computeDigest,
  isEvidenceLogOrigin,
  type EvidenceEnvelope,
  type HeldLinkTarget,
  type StorageAdapter,
} from '@tzun/engine';
import { VerifyingStorageProxy } from '../../monitoring/storage-proxy';
import { HttpStorageAdapter } from '../http-transport';
import type { SdkHost } from '../extension-points';
import type { LinkIndexPage, LinkIndexQuery } from '../../storage/links-sql';

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** The store's reads the link service uses. */
export interface LinkStoreReads {
  /** The record with this evidence id, or `null`. */
  byId(evidenceId: string): Promise<EvidenceEnvelope | null>;
  /** The record whose stored digest is `digest`, or `null`; absent when the store cannot look a record up by digest. */
  readonly byDigest: ((digest: string) => Promise<EvidenceEnvelope | null>) | null;
  /** A page of the link index; absent when the store has no link index. */
  readonly linksTo: ((digest: string, query: LinkIndexQuery) => Promise<LinkIndexPage>) | null;
  /** The evidence-log origin of the chain a stored record belongs to, or `null` (a store without evidence logs, or one that cannot say). */
  originOf(envelope: EvidenceEnvelope): Promise<string | null>;
  /**
   * Whether `originOf` reads the record's origin from the store. False on
   * the cloud transport, whose evidence read does not carry it: there a
   * supplied locator's origin is taken as given (`resolve.ts`).
   */
  readonly confirmsOrigin: boolean;
  /** `<ns>/<storeId>/evidence/`: what every evidence-log origin of this store starts with, or `null`. */
  ownOriginPrefix(): Promise<string | null>;
  /**
   * The record at `(origin, seq)` when `origin` names an evidence log of this
   * store and `seq` is a position (`own: true`, `envelope` `null` when that
   * position holds none), or `own: false` for an origin of another store, one
   * that is not an evidence-log origin, or a `seq` that is not an integer of
   * at least 1 (which `buildLinks` refuses by the locator grammar).
   */
  atLocator(locator: { origin: unknown; seq: unknown }): Promise<{ own: boolean; envelope: EvidenceEnvelope | null }>;
}

/** The adapter under the verifying proxy, when there is one. */
function innerAdapter(storage: StorageAdapter): StorageAdapter {
  return storage instanceof VerifyingStorageProxy ? storage.unwrap() : storage;
}

/** Whether the store is the cloud transport, whose reads go through the hosted service's evidence read. */
export function isCloudStore(storage: StorageAdapter): boolean {
  return innerAdapter(storage) instanceof HttpStorageAdapter;
}

/** The chain id an evidence-log chain segment names (the lowercase hex of its UTF-8 bytes), or `null`. */
function chainOfSegment(segment: string): string | null {
  if (!/^(?:[0-9a-f]{2})+$/.test(segment)) return null;
  const chainId = Buffer.from(segment, 'hex').toString('utf8');
  return Buffer.from(chainId, 'utf8').toString('hex') === segment ? chainId : null;
}

/** The reads of `host`'s store. */
export function linkStoreReads(host: SdkHost): LinkStoreReads {
  const storage = host.storage;
  const inner = innerAdapter(storage);
  const cloud = inner instanceof HttpStorageAdapter;
  let prefix: Promise<string | null> | null = null;

  const ownOriginPrefix = (): Promise<string | null> => {
    // Read once per service; a failed read is not kept, so the next call reads again.
    prefix ??= host.evidenceLogOrigin(host.activeChainId()).then(
      (origin) => (origin === null ? null : origin.slice(0, origin.lastIndexOf('/') + 1)),
      (error: unknown) => {
        prefix = null;
        throw error;
      },
    );
    return prefix;
  };

  const listLinksTo = storage.listLinksTo;
  return {
    async byId(evidenceId) {
      if (cloud) {
        // A URL path segment of `.` or `..` is resolved away by the URL
        // parser, so the request would not name the record: no record has it.
        if (evidenceId === '.' || evidenceId === '..') return null;
        return (await (inner as HttpStorageAdapter).retrieveWithVerdict(evidenceId))?.envelope ?? null;
      }
      return storage.retrieve(evidenceId);
    },
    byDigest: typeof storage.retrieveByDigest === 'function' ? (digest) => storage.retrieveByDigest!(digest) : null,
    linksTo:
      typeof listLinksTo === 'function'
        ? // The link index's adapters take the engine's options plus `statements`, and carry `subjectDigest` on each row.
          (digest, query) =>
            listLinksTo.call(storage, digest, query as Parameters<typeof listLinksTo>[1]) as Promise<LinkIndexPage>
        : null,
    async originOf(envelope) {
      if (cloud) return null;
      const evidenceId = envelope.payload?.evidenceId;
      if (typeof evidenceId !== 'string') return null;
      const chainId = await storage.getChainForRecord(evidenceId);
      return chainId === null ? null : host.evidenceLogOrigin(chainId);
    },
    confirmsOrigin: !cloud,
    ownOriginPrefix,
    async atLocator(locator) {
      const seq = locator.seq;
      if (cloud || !isEvidenceLogOrigin(locator.origin) || typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 1) {
        return { own: false, envelope: null };
      }
      const own = await ownOriginPrefix();
      if (own === null || !locator.origin.startsWith(own)) return { own: false, envelope: null };
      const chainId = chainOfSegment(locator.origin.slice(own.length));
      if (chainId === null) return { own: false, envelope: null };
      const rows = await storage.getBySequenceRange(seq, seq, chainId);
      return { own: true, envelope: rows[0] ?? null };
    },
  };
}

/** Whether a stored record's payload recomputes to its stored canonical digest under the v1.0 field set. */
export function recordIntact(envelope: EvidenceEnvelope): boolean {
  const payload = envelope?.payload as unknown;
  const stored = envelope?.integrity?.canonicalDigest;
  if (!isPlainObject(payload) || typeof stored !== 'string') return false;
  try {
    return computeDigest(canonicalSerialize(payload, [...V1_0_HASHED_FIELDS])) === stored;
  } catch {
    return false;
  }
}

/** A stored record as a held link target: its payload, its stored digest and its chain's origin. */
export async function heldTargetOf(reads: LinkStoreReads, envelope: EvidenceEnvelope): Promise<HeldLinkTarget> {
  return {
    payload: envelope.payload as unknown as Record<string, unknown>,
    digest: envelope.integrity.canonicalDigest,
    origin: await reads.originOf(envelope),
  };
}

/** The origin of every chain of this store: `prefix` and the lowercase hex of the chain id's UTF-8 bytes. */
export function originBuilder(prefix: string): (chainId: string) => string {
  return (chainId) => `${prefix}${Buffer.from(chainId, 'utf8').toString('hex')}`;
}
