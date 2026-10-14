/**
 * What the mandate service reads of a store: the mandate methods a store
 * with the mandate tables has, the mandate's parts as the row keeps them,
 * its running totals, the `mandate`/`revokes`/`supersedes` link target of
 * its issuance record, and the event rows it writes.
 */
import { createHash } from 'crypto';
import { canonicalSerializeValue, mandateEventBodyDigest } from '@tzun/engine';
import type {
  LinkTarget,
  MandateDocument,
  MandateEventBody,
  MandateEventRow,
  MandateExpireStore,
  MandateRow,
  MandateStatement,
  WebauthnAssertion,
} from '@tzun/engine';
import type { MandateListFilter, MandateListPage } from '../../storage/mandate-sql';
import type { SdkHost } from '../extension-points';
import { MandateError } from './errors';

/** The mandate methods of a store with the mandate tables. */
export interface MandateStore {
  getMandate(mandateIdOrDigest: string): Promise<MandateRow | null>;
  getMandateTotals(mandateId: string): Promise<Record<string, number>>;
  listMandateEvents(mandateId: string): Promise<MandateEventRow[]>;
  expireMandate(expiry: MandateExpireStore): Promise<void>;
  /** Present when the store lists its mandates (`listMandates`). */
  listMandates?(filter?: MandateListFilter): Promise<MandateListPage>;
}

/** The store's mandate methods, or `null` for a store without the mandate tables (the cloud transport, a custom adapter). */
export function mandateStoreOf(host: SdkHost): MandateStore | null {
  const s = host.storage;
  if (
    typeof s.getMandate !== 'function' ||
    typeof s.getMandateTotals !== 'function' ||
    typeof s.listMandateEvents !== 'function' ||
    typeof s.expireMandate !== 'function'
  ) {
    return null;
  }
  const list = (s as unknown as { listMandates?: (filter?: MandateListFilter) => Promise<MandateListPage> }).listMandates;
  return {
    getMandate: (key) => s.getMandate!(key),
    getMandateTotals: (id) => s.getMandateTotals!(id),
    listMandateEvents: (id) => s.listMandateEvents!(id),
    expireMandate: (expiry) => s.expireMandate!(expiry),
    ...(typeof list === 'function' && { listMandates: (filter?: MandateListFilter) => list.call(s, filter) }),
  };
}

/** The store's mandate methods, or a {@link MandateError} `mandate_not_supported_by_store`. */
export function requireMandateStore(host: SdkHost): MandateStore {
  const store = mandateStoreOf(host);
  if (store === null) {
    throw new MandateError('mandate_not_supported_by_store', 'mandate', 'this store does not hold mandates');
  }
  return store;
}

/** The parts of a mandate as its row keeps them. */
export interface MandateParts {
  document: MandateDocument;
  statement: MandateStatement;
  assertion: WebauthnAssertion;
}

/** The document, statement and assertion of a mandate row. */
export function mandatePartsOf(row: MandateRow): MandateParts {
  return {
    document: JSON.parse(row.documentBytes) as MandateDocument,
    statement: JSON.parse(row.statementJson) as MandateStatement,
    assertion: JSON.parse(row.assertionJson) as WebauthnAssertion,
  };
}

/** Whether a mandate's document has caps: its totals are then an object with every cap, otherwise `null`. */
export function hasCaps(document: MandateDocument): boolean {
  return document.limits.cumulative !== null;
}

/** A mandate's running totals as an expectation or event body writes them: every cap, or `null` when it has none. */
export async function totalsOf(store: MandateStore, row: MandateRow, document: MandateDocument): Promise<Record<string, number> | null> {
  if (!hasCaps(document)) return null;
  const held = await store.getMandateTotals(row.mandateId);
  const out: Record<string, number> = {};
  for (const cap of Object.keys(document.limits.cumulative!).sort()) out[cap] = held[cap] ?? 0;
  return out;
}

/**
 * The link target of a mandate's issuance record: its digest and evidence id
 * from the mandate row, and its locator (its chain's evidence-log origin and
 * its sequence number) from the store. `locator` is `null` when the store has
 * no evidence logs or no longer holds the record.
 */
export async function issuanceTargetOf(host: SdkHost, row: MandateRow): Promise<LinkTarget> {
  let locator: LinkTarget['locator'] = null;
  const record = await host.storage.retrieve(row.issuanceEvidenceId);
  const chainId = record ? await host.storage.getChainForRecord(row.issuanceEvidenceId) : null;
  if (record && chainId !== null) {
    const origin = await host.evidenceLogOrigin(chainId);
    if (origin !== null) locator = { origin, seq: record.payload.sequenceNumber };
  }
  return { digest: row.issuanceDigest, evidenceId: row.issuanceEvidenceId, locator };
}

/** A mandate event row: the body, its canonical bytes and their SHA-256. */
export function mandateEventRow(mandateId: string, body: MandateEventBody): MandateEventRow {
  const canonical = canonicalSerializeValue(body);
  const digest = createHash('sha256').update(canonical, 'utf8').digest('hex');
  if (mandateEventBodyDigest(body) !== digest) throw new Error('A mandate event body must be well formed.');
  return { mandateId, body, canonical, digest };
}

/** The bytes of a value as a row keeps them: its canonical serialization. */
export function canonicalJson(value: unknown): string {
  return canonicalSerializeValue(value);
}
