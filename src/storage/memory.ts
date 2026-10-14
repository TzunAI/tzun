import { createHash } from 'crypto';
import { AttestationArtifacts, CustodyEntry, EvidenceEnvelope } from '@tzun/engine';
import type { AttestationStatusOf, RetryObtainableComponent } from '@tzun/engine';
import { FailureRecord } from '@tzun/engine';
import { ListOptions } from '@tzun/engine';
import { TamperIncident, TamperIncidentStatus } from '@tzun/engine';
import { ChainIdentity, AnnotationRecord, RelinkRecord, ForkRecord } from '@tzun/engine';
import {
  ModelDescriptor,
  ModelDescriptorRow,
  ModelDescriptorAnnotationRow,
  ModelDescriptorAliasRow,
} from '@tzun/engine';
import { canonicalSerializeDescriptor } from '@tzun/engine';
import { computeCustodyEntryHash, mirrorCustodyEntry, normaliseCustodyMetadata } from '@tzun/engine';
import { buildEnrichedView } from '../models/enriched-view';
import {
  CustodyAppendOptions,
  EnvelopeRevision,
  IdempotencyOutcome,
  IdempotencyReceipt,
  IdempotentStoreOptions,
  RelinkCustodyAppend,
  RevisionCause,
  StorageAdapter,
  StoreOptions,
  StoredCustodyEntry,
} from '@tzun/engine';
import { DEFAULT_CHAIN_ID, resolveActiveChainId } from '@tzun/engine';
import { ChainStateResetRefusedError, assertChainHead, assertChainNotSealed } from './chain-head-guard';
import {
  assertUniqueExtensionNames,
  installExtensionMethods,
  mergeExtensionMethods,
  type MemoryStoreReads,
  type StorageExtension,
  type StoreWrite,
} from './extensions';
import { DEFAULT_STORAGE_EXTENSIONS } from './extensions-registry';
import { fillAbsentArtifacts, statusAfterFill } from './attestation-fill';
import {
  assertArmed,
  DEMO_SENTINEL_OWNER,
  DemoTamperStoreView,
  tryArmDemoTamperHooks,
} from './demo-tamper-guard';
import { assertDescriptorIntegrityInvariants } from '../models/descriptor-invariants';
import { DuplicateRecordError, MissingReferenceError } from './append-only';
import { compareForList } from './list-order';
import { assertNonNegativeInteger } from './pagination-guard';
import { assertRetryObtainableComponents, lacksRetryObtainable } from './missing-obtainable';
import { AsyncCredentialStore } from '../attestation/credential-store';
import {
  CredentialStoreProvider,
  MemoryCredentialStore,
} from './credential-stores';
import {
  CAPTURE_REVISION_NO,
  REVISION_ACTOR_ATTESTATION,
  REVISION_ACTOR_RECOVERY,
  captureRevisionActor,
  nextRevisionNo,
} from './revision-log';
import {
  LogSchemaOptions,
  LogStore,
  LogStoreProvider,
  MemoryLogStore,
  EvidenceLogRefusalError,
  assertEvidenceLogChainId,
} from './log-store';

/** Options of {@link MemoryStorageAdapter}. */
export interface MemoryAdapterOptions extends LogSchemaOptions {
  /**
   * The storage extensions this adapter installs (`extensions.ts`): their
   * state, their `store()` hooks and the optional adapter methods they
   * provide. Default: `DEFAULT_STORAGE_EXTENSIONS`.
   */
  extensions?: readonly StorageExtension[];
}

/** The key of a chain position in {@link MemoryStorageAdapter}'s position index. */
function positionKey(chainId: string, sequenceNumber: number): string {
  return `${sequenceNumber}\u0000${chainId}`;
}

/**
 * Detach a value from every reference the caller or the store still holds.
 *
 * A JSON round trip, deliberately, rather than `structuredClone`: it is what
 * the SQLite adapter does on every read (`JSON.parse(row.envelope)`) and what
 * Postgres JSONB does on every write, so it reproduces their semantics
 * exactly — `undefined`-valued keys vanish, `-0` becomes `0`, Dates become
 * strings. Anything `structuredClone` would preserve that JSON does not is
 * precisely a difference between this adapter and a real store, and the whole
 * point of this file is to have none.
 */
function jsonClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/**
 * Ordinal (UTF-16 code unit) string comparison. The ledger and incident lists
 * below order on ISO-8601 UTC timestamps the SDK stamps itself, exactly as the
 * SQL adapters' `ORDER BY <text column>` does; `localeCompare` would make the
 * order ICU-version-dependent.
 */
function cmpString(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * The catalog row as it is held in memory. `descriptor` is NOT stored: both
 * SQL adapters derive it from `canonical_bytes` on every read
 * (`JSON.parse(row.canonical_bytes)`), so a row's descriptor IS its bytes.
 * Keeping a second, independent copy of the descriptor object beside the
 * bytes would let `overwriteModelDescriptorBytesForDemo` change
 * `canonicalBytes` while `descriptor.modelName` kept reporting the clean
 * value: a descriptor tamper would show a clean model name on memory and the
 * tampered one on a real store.
 */
type StoredModelDescriptorRow = Omit<ModelDescriptorRow, 'descriptor'>;

/**
 * In-memory storage adapter for dev mode and testing.
 *
 * Stores envelopes in a Map keyed by evidenceId.
 * All data is lost when the process exits.
 *
 * FAITHFUL DOUBLE. This adapter exists so that a test written against it
 * means something about SQLite and Postgres. Every read therefore returns a
 * fresh detached object, and every write stores a detached copy of the
 * caller's argument — exactly as a store that serialises to a row does. A
 * live reference into its own Maps would let a caller rewrite stored evidence
 * with a property assignment, would let `VerifyingStorageProxy` verify a
 * digest and then hand back a writable pointer to the verified object, and
 * would make a tamper that mutates what `retrieve()` returned "work" on memory
 * while doing nothing at all on SQLite. The shared conformance suite in
 * tests/ts/storage-conformance asserts the detachment on every read and write
 * path, for all three adapters.
 */
export class MemoryStorageAdapter implements StorageAdapter, CredentialStoreProvider, LogStoreProvider {
  private envelopes: Map<string, EvidenceEnvelope> = new Map();
  private failures: FailureRecord[] = [];
  private incidents: Map<string, TamperIncident> = new Map();
  private chains: Map<string, ChainIdentity> = new Map();
  private recordChainMap: Map<string, string> = new Map();
  private annotations: Map<string, AnnotationRecord> = new Map();
  private relinks: Map<string, RelinkRecord> = new Map();
  private forks: Map<string, ForkRecord> = new Map();
  // The append-only custody ledger: one list of rows per
  // record, in insertion order. Nothing on this class removes or rewrites a
  // row — the SQL adapters enforce the same with triggers.
  private custodyEntries: Map<string, StoredCustodyEntry[]> = new Map();
  private custodyEntrySeq = 0;
  // The append-only revision log: one list per record, in
  // revision order. Nothing on this class removes or rewrites a row — the SQL
  // adapters enforce the same with triggers, and a memory adapter that let a
  // caller edit one would be the kind of unfaithful double that made a demo
  // tamper "work" on memory and do nothing on SQLite.
  private envelopeRevisions: Map<string, EnvelopeRevision[]> = new Map();
  /** Idempotency key -> the fingerprint it was claimed with and the record it names. */
  private idempotencyKeys: Map<string, { fingerprint: string; receipt: IdempotencyReceipt }> = new Map();
  /**
   * One head per chain: the digest of the last record appended
   * to it and the highest sequence number it has reached. A chain with no
   * entry has never held a record — which is a different fact from "reached
   * sequence 0", and the reason this is a Map rather than two fields.
   *
   * The high-water mark does NOT fall when a record is removed. That is what
   * makes a deleted tail detectable: with no survivor after the missing
   * records, the bound is the only thing left to compare against.
   */
  private chainHeads: Map<string, { digest: string; sequence: number }> = new Map();

  // AI-BOM catalog tables (descriptors / annotations / aliases).
  private modelDescriptors: Map<string, StoredModelDescriptorRow> = new Map();
  private modelDescriptorAnnotations: Map<string, ModelDescriptorAnnotationRow[]> = new Map();
  private modelDescriptorAliases: Map<string, ModelDescriptorAliasRow[]> = new Map();

  // Demo-tamper hooks state.
  private demoHooksArmed = false;

  private demoSentinelWritten = false;
  /** Lazily created so an adapter that never registers a credential holds none. */
  private credentials?: MemoryCredentialStore;

  // Insertion-order list of evidence IDs for head() and chain traversal.
  private insertionOrder: string[] = [];

  /**
   * The evidence logs (Tree §5.2): one per chain, a leaf per record,
   * written in code in the same synchronous section as the record, under the
   * rules the SQL adapters' trigger applies. Minted with its own identity, so
   * every adapter instance is a new store with new origins.
   */
  private readonly logs: MemoryLogStore;

  /** The record at each chain position: one record per position, as the SQL adapters' `envelopes_position` index holds. */
  private positions: Map<string, string> = new Map();

  /** The storage extensions this adapter installed, each with its state. */
  private readonly extensions: ReadonlyArray<{ ext: StorageExtension; state: unknown }>;

  // The optional methods a storage extension provides (extensions.ts),
  // installed at construction: present exactly when an installed extension
  // provides them.
  declare putAgentDescriptor?: StorageAdapter['putAgentDescriptor'];
  declare getAgentDescriptor?: StorageAdapter['getAgentDescriptor'];
  declare listAgentDescriptors?: StorageAdapter['listAgentDescriptors'];
  declare getMandate?: StorageAdapter['getMandate'];
  declare getMandateTotals?: StorageAdapter['getMandateTotals'];
  declare listMandateEvents?: StorageAdapter['listMandateEvents'];
  declare expireMandate?: StorageAdapter['expireMandate'];
  declare listMandates?: StorageAdapter['listMandates'];
  declare getDeciderOpening?: StorageAdapter['getDeciderOpening'];
  declare getDeciderCommitmentSecret?: StorageAdapter['getDeciderCommitmentSecret'];
  declare listLinksTo?: StorageAdapter['listLinksTo'];

  /** What an extension reads of the records this adapter holds. */
  private readonly extensionReads: MemoryStoreReads = {
    retrieve: (evidenceId) => {
      const held = this.envelopes.get(evidenceId);
      return held ? jsonClone(held) : null;
    },
    // A record taken out of the map behind the adapter (the tamper hooks, a
    // test's insider delete) is not held: it is skipped, never read as undefined.
    all: () => this.insertionOrder.flatMap((id) => {
      const held = this.envelopes.get(id);
      return held ? [jsonClone(held)] : [];
    }),
    chainOf: (evidenceId) => this.recordChainMap.get(evidenceId) ?? null,
  };

  /**
   * @param options - `logNamespace`: the namespace this store's identity is
   *   minted with (default `local.invalid`); `extensions`: the storage
   *   extensions to install.
   */
  constructor(options: MemoryAdapterOptions = {}) {
    this.logs = new MemoryLogStore(options, (chainId) => this.chainHeads.get(chainId)?.sequence ?? 0);
    const extensions = options.extensions ?? DEFAULT_STORAGE_EXTENSIONS;
    assertUniqueExtensionNames(extensions);
    this.extensions = extensions.map((ext) => ({ ext, state: ext.memory?.createState() }));
    installExtensionMethods(
      this,
      mergeExtensionMethods(
        this.extensions.map(({ ext, state }) => ({ name: ext.name, methods: ext.memory?.methods?.(state, this.extensionReads) })),
      ),
    );
  }

  /**
   * Store an envelope.
   *
   * When `options.expectChainHead` is supplied this is a conditional append:
   * the head is compared and the record written in one synchronous block, with
   * no `await` in between, so two overlapping `capture()` calls on this
   * instance cannot both observe the same head. Without that check both
   * would succeed at the same sequence number, linking to the same
   * predecessor, and each would report `stored: true`.
   */
  async store(
    envelope: EvidenceEnvelope,
    chainId?: string,
    options?: StoreOptions,
  ): Promise<void> {
    // A chain id that names no evidence log is refused before anything else.
    assertEvidenceLogChainId(chainId ?? DEFAULT_CHAIN_ID, envelope.payload?.sequenceNumber);
    this.storeSync(envelope, chainId, options);
  }

  /**
   * `store()` under an idempotency key. The lookup, the write
   * and the claim run in one synchronous block — no `await` anywhere — so two
   * overlapping calls with one key cannot both find it free. A `storeSync()`
   * refusal throws before the claim, so a failed store leaves the key free.
   * Keys are never expired, as on the platform.
   */
  async storeIdempotent(
    envelope: EvidenceEnvelope,
    chainId: string | undefined,
    options: IdempotentStoreOptions,
  ): Promise<IdempotencyOutcome> {
    assertEvidenceLogChainId(chainId ?? DEFAULT_CHAIN_ID, envelope.payload?.sequenceNumber);
    const { key, fingerprint } = options.idempotency;
    const held = this.idempotencyKeys.get(key);
    if (held) {
      return held.fingerprint === fingerprint
        ? { kind: 'replay', receipt: { ...held.receipt } }
        : { kind: 'conflict' };
    }
    this.storeSync(envelope, chainId, options);
    const receipt: IdempotencyReceipt = {
      evidenceId: envelope.payload.evidenceId,
      chainId: chainId ?? DEFAULT_CHAIN_ID,
      sequenceNumber: envelope.payload.sequenceNumber,
      canonicalDigest: envelope.integrity.canonicalDigest,
    };
    this.idempotencyKeys.set(key, { fingerprint, receipt });
    return { kind: 'claimed', receipt: { ...receipt } };
  }

  /** The body of `store()`, synchronous so `storeIdempotent()` can share its critical section. */
  private storeSync(envelope: EvidenceEnvelope, chainId?: string, options?: StoreOptions): void {
    const id = envelope.payload.evidenceId;
    if (this.envelopes.has(id)) {
      throw new DuplicateRecordError('Evidence record', id);
    }
    // ── atomic section: no await between the head check and the head update ──
    const targetChainId = chainId ?? DEFAULT_CHAIN_ID;
    const targetChain = this.chains.get(targetChainId);
    assertChainNotSealed(targetChainId, targetChain?.status, targetChain?.sealedAt);
    // The TARGET chain's head, not the store's: an append to one chain is
    // never refused because another chain moved.
    const head = this.chainHeads.get(targetChainId);
    assertChainHead(options?.expectChainHead, {
      sequence: head?.sequence ?? 0,
      digest: head?.digest ?? null,
    });
    // One record per chain position: the SQL adapters' envelopes_position
    // index, in code.
    const position = positionKey(targetChainId, envelope.payload.sequenceNumber);
    if (this.positions.has(position)) {
      throw new EvidenceLogRefusalError('position_taken', targetChainId, envelope.payload.sequenceNumber);
    }
    // The evidence-log leaf is decided before anything is written, so a
    // refusal (a gap, a malformed position) leaves the store untouched, and
    // written with the record below: the SQL adapters' trigger, in code.
    const leaf = this.logs.planEvidenceLeaf(envelope, targetChainId);
    // The storage extensions' checks (a mandate slot), before anything is
    // written: a refusal leaves the store untouched.
    const write: StoreWrite = { envelope, chainId: targetChainId, options: options ?? {} };
    for (const { ext, state } of this.extensions) ext.memory?.check?.(state, write, this.extensionReads);
    // A detached copy: the caller keeps its object, the store keeps its row.
    this.envelopes.set(id, jsonClone(envelope));
    this.recordChainMap.set(id, targetChainId);
    this.positions.set(position, id);
    this.insertionOrder.push(id);
    this.chainHeads.set(targetChainId, {
      digest: envelope.integrity.canonicalDigest,
      // High-water mark: never decrease after a fork restarts this chain at 1.
      sequence: Math.max(head?.sequence ?? 0, envelope.payload.sequenceNumber),
    });
    // The capture revision, written in the SAME critical
    // section as the record it describes — the SQL adapters put it in the
    // same transaction, and a record that could exist without one would be
    // indistinguishable from a legacy record, which every verifier must treat
    // as unprovable rather than tampered.
    this.appendRevision(
      id,
      CAPTURE_REVISION_NO,
      envelope.integrity.canonicalDigest,
      envelope.integrity.chainLink,
      'capture',
      captureRevisionActor(envelope),
    );
    this.logs.commitEvidenceLeaf(leaf);
    // The extensions' rows written with the record, in the same critical
    // section.
    for (const { ext, state } of this.extensions) ext.memory?.apply?.(state, write, this.extensionReads);
  }

  /**
   * Append one revision row. `revisionNo` is explicit for the
   * capture row and derived from the record's own highest for every other
   * cause — never from a global counter, and never backfilled to 0; see
   * `nextRevisionNo` for why.
   */
  private appendRevision(
    evidenceId: string,
    revisionNo: number,
    canonicalDigest: string,
    chainLink: string | null,
    cause: RevisionCause,
    actor: string,
  ): void {
    const rows = this.envelopeRevisions.get(evidenceId) ?? [];
    // The SQL adapters write revision 0 only where the record has none
    // (Postgres with ON CONFLICT DO NOTHING, SQLite with INSERT ... WHERE NOT
    // EXISTS); this is the same rule, so a record deleted and re-stored under
    // its id keeps the capture revision it already has on every backend. See
    // CAPTURE_REVISION_NO.
    if (rows.some((r) => r.revisionNo === revisionNo)) return;
    rows.push({
      evidenceId,
      revisionNo,
      canonicalDigest,
      chainLink,
      recordedAt: new Date().toISOString(),
      cause,
      actor,
    });
    this.envelopeRevisions.set(evidenceId, rows);
  }

  /** The next revision number for a non-capture write on this record. */
  private nextRevisionFor(evidenceId: string): number {
    const rows = this.envelopeRevisions.get(evidenceId);
    if (!rows || rows.length === 0) return nextRevisionNo(null);
    return nextRevisionNo(rows.reduce((max, r) => Math.max(max, r.revisionNo), 0));
  }

  async retrieve(evidenceId: string): Promise<EvidenceEnvelope | null> {
    const stored = this.envelopes.get(evidenceId);
    return stored ? jsonClone(stored) : null;
  }

  async list(options?: ListOptions): Promise<EvidenceEnvelope[]> {
    let results = Array.from(this.envelopes.values());

    // Filter by aiSystemId
    if (options?.aiSystemId) {
      results = results.filter(
        (e) => e.payload.aiSystemId === options.aiSystemId
      );
    }

    // Filter by chainId
    if (options?.chainId) {
      results = results.filter(
        (e) => this.recordChainMap.get(e.payload.evidenceId) === options.chainId
      );
    }

    // The ordering contract lives in list-order.ts: UTC instant of capturedAt
    // at ms precision, then sequenceNumber, then evidenceId; 'desc' is the
    // exact reverse.
    const order = options?.order ?? 'desc';
    results.sort((a, b) => {
      const cmp = compareForList(a.payload, b.payload);
      return order === 'desc' ? -cmp : cmp;
    });

    // Pagination. Validated, as on the SQL adapters: unvalidated, `Array.slice(0, -1)`
    // would silently drop the last row for `limit: -1`, and a forwarded
    // `req.query.limit` string would be coerced rather than refused.
    const offset = options?.offset != null ? assertNonNegativeInteger(options.offset, 'offset') : 0;
    const limit = options?.limit != null ? assertNonNegativeInteger(options.limit, 'limit') : results.length;
    return results.slice(offset, offset + limit).map(jsonClone);
  }

  async storeFailure(failure: FailureRecord): Promise<void> {
    this.failures.push(jsonClone(failure));
  }

  async getLastDigest(chainId: string = DEFAULT_CHAIN_ID): Promise<string | null> {
    return this.chainHeads.get(chainId)?.digest ?? null;
  }

  async getLastSequence(chainId: string = DEFAULT_CHAIN_ID): Promise<number> {
    return this.chainHeads.get(chainId)?.sequence ?? 0;
  }

  async listBySequence(fromSequence?: number, toSequence?: number, chainId?: string): Promise<EvidenceEnvelope[]> {
    let results = Array.from(this.envelopes.values());

    const from = fromSequence ?? 1;
    results = results.filter((e) => e.payload.sequenceNumber >= from);

    if (toSequence != null) {
      results = results.filter((e) => e.payload.sequenceNumber <= toSequence);
    }

    if (chainId) {
      results = results.filter(
        (e) => this.recordChainMap.get(e.payload.evidenceId) === chainId,
      );
    }

    results.sort((a, b) => a.payload.sequenceNumber - b.payload.sequenceNumber);

    return results.map(jsonClone);
  }

  async updateAttestation(
    evidenceId: string,
    artifacts: AttestationArtifacts,
    newStatus: EvidenceEnvelope['attestationStatus'] | AttestationStatusOf
  ): Promise<void> {
    const envelope = this.envelopes.get(evidenceId);
    if (!envelope) {
      throw new Error(
        `Evidence record "${evidenceId}" not found. Cannot update attestation.`
      );
    }
    // Same shape as the SQL adapters: read the row, rewrite it, write it back —
    // filling only the components the record does not have yet, in one
    // synchronous block, so a second pass cannot replace what has landed.
    const { merged, filled } = fillAbsentArtifacts(envelope.nonRepudiation, jsonClone(artifacts));
    const status = statusAfterFill(envelope, merged, newStatus);
    if (!filled && status === envelope.attestationStatus) return;
    const updated = jsonClone(envelope);
    updated.nonRepudiation = merged;
    updated.attestationStatus = status;
    this.envelopes.set(evidenceId, updated);
    // An attestation retry is a legitimate envelope write, so it leaves a
    // revision row, carrying the digest UNCHANGED — which is
    // what makes the row prove the retry superseded nothing.
    this.appendRevision(
      evidenceId,
      this.nextRevisionFor(evidenceId),
      updated.integrity.canonicalDigest,
      updated.integrity.chainLink,
      'attestation_retry',
      REVISION_ACTOR_ATTESTATION,
    );
  }

  async listByAttestationStatus(
    status: EvidenceEnvelope['attestationStatus'],
    limit?: number,
  ): Promise<EvidenceEnvelope[]> {
    // Oldest first, bounded: a caller reads a backlog a batch at a time. The
    // order is list()'s ascending contract.
    const matching = Array.from(this.envelopes.values())
      .filter((e) => e.attestationStatus === status)
      .sort((a, b) => compareForList(a.payload, b.payload));
    const bounded = limit != null
      ? matching.slice(0, assertNonNegativeInteger(limit, 'limit'))
      : matching;
    return bounded.map(jsonClone);
  }

  async listByMissingObtainable(
    components: readonly RetryObtainableComponent[],
    limit?: number,
  ): Promise<EvidenceEnvelope[]> {
    // The retry pass's queue: 'pending' records missing a component it can
    // obtain, oldest first. A record waiting only for an anchor or a
    // signature is not listed.
    const wanted = assertRetryObtainableComponents(components);
    const bound = limit != null ? assertNonNegativeInteger(limit, 'limit') : undefined;
    if (wanted.length === 0) return [];
    const matching = Array.from(this.envelopes.values())
      .filter((e) =>
        e.attestationStatus === 'pending' &&
        wanted.some((c) => lacksRetryObtainable(e.nonRepudiation, c)))
      .sort((a, b) => compareForList(a.payload, b.payload));
    return (bound !== undefined ? matching.slice(0, bound) : matching).map(jsonClone);
  }

  async storeIncident(incident: TamperIncident): Promise<void> {
    if (this.incidents.has(incident.id)) {
      throw new DuplicateRecordError('Tamper incident', incident.id);
    }
    // A deep copy: a one-level spread would share `affectedRecords` and
    // `affectedSequenceRange` with the caller, so a later push onto the
    // caller's array would show up in the stored incident.
    this.incidents.set(incident.id, jsonClone(incident));
  }

  async getIncident(id: string): Promise<TamperIncident | null> {
    const incident = this.incidents.get(id);
    if (!incident) return null;
    return jsonClone(incident);
  }

  async listIncidents(filter?: { status?: TamperIncidentStatus; severity?: string }): Promise<TamperIncident[]> {
    let results = Array.from(this.incidents.values());

    if (filter?.status) {
      results = results.filter((i) => i.status === filter.status);
    }
    if (filter?.severity) {
      results = results.filter((i) => i.severity === filter.severity);
    }

    // detectedAt DESC, then id DESC — the SQL adapters' order, made total.
    results.sort((a, b) => cmpString(b.detectedAt, a.detectedAt) || cmpString(b.id, a.id));
    return results.map(jsonClone);
  }

  async recordIncidentObservation(id: string, observedAt: string): Promise<void> {
    const incident = this.incidents.get(id);
    if (!incident) {
      throw new Error(
        `Tamper incident "${id}" not found. Cannot record an observation.`
      );
    }
    incident.lastObservedAt = observedAt;
  }

  async updateIncidentStatus(
    id: string,
    status: TamperIncidentStatus,
    metadata?: { resolvedBy?: string; resolutionNotes?: string }
  ): Promise<void> {
    const incident = this.incidents.get(id);
    if (!incident) {
      throw new Error(
        `Tamper incident "${id}" not found. Cannot update status.`
      );
    }
    incident.status = status;
    if (status === 'resolved') {
      // Resolution metadata is audit evidence: who signed off on a detected
      // integrity break, when, and what they said. A second resolve without
      // metadata — an idempotent retry, an ops-console double-submit, a
      // replayed queue message — must not erase any of it: resolvedAt
      // is stamped on the FIRST transition only, and each field is replaced
      // only when the caller supplies a new value. Transitioning away from
      // 'resolved' leaves the three fields as they are on every adapter.
      incident.resolvedAt = incident.resolvedAt ?? new Date().toISOString();
      if (metadata?.resolvedBy) {
        incident.resolvedBy = metadata.resolvedBy;
      }
      if (metadata?.resolutionNotes) {
        incident.resolutionNotes = metadata.resolutionNotes;
      }
    }
  }

  async getChainForRecord(evidenceId: string): Promise<string | null> {
    return this.recordChainMap.get(evidenceId) ?? null;
  }

  // The six append-only tables below refuse a second write for an existing
  // key exactly as the SQL adapters' bare INSERT against a primary key or a
  // foreign key does, with the same error class. A plain `Map.set` would be an
  // upsert: a second storeChain() for an existing id would silently REPLACE
  // the chain identity (status, sealedAt, parentChainId, forkPoint) in dev
  // while production throws.

  async storeChain(chain: ChainIdentity): Promise<void> {
    if (this.chains.has(chain.chainId)) {
      throw new DuplicateRecordError('Chain', chain.chainId);
    }
    this.chains.set(chain.chainId, jsonClone(chain));
  }

  async getChain(chainId: string): Promise<ChainIdentity | null> {
    const chain = this.chains.get(chainId);
    return chain ? jsonClone(chain) : null;
  }

  async listChains(): Promise<ChainIdentity[]> {
    return this.readChains();
  }

  private readChains(): ChainIdentity[] {
    return Array.from(this.chains.values())
      .sort((a, b) => cmpString(a.createdAt, b.createdAt) || cmpString(a.chainId, b.chainId))
      .map(jsonClone);
  }

  /**
   * Seal a chain. A seal is final: sealing a sealed chain changes nothing and
   * keeps its first `sealedAt`, as the SQL adapters' `chains` triggers require.
   */
  async sealChain(chainId: string, sealedAt: string): Promise<void> {
    const chain = this.chains.get(chainId);
    if (!chain) {
      throw new Error(`Chain "${chainId}" not found.`);
    }
    if (chain.status === 'sealed') return;
    chain.status = 'sealed';
    chain.sealedAt = sealedAt;
  }

  /**
   * Both reads the rule runs over come from one synchronous step: with an
   * `await` between them, another in-process operation's continuation (a
   * fork's, say) can land in the gap and the rule runs over the chains of one
   * store and the records of another. SQLite and Postgres wrap the same pair
   * in a transaction for the same reason; this is the memory adapter's
   * equivalent, so it stays a faithful double of them.
   */
  async getActiveChainId(): Promise<string> {
    return resolveActiveChainId(this.readChains(), this.readRecordChainIds());
  }

  async listRecordChainIds(): Promise<string[]> {
    return this.readRecordChainIds();
  }

  private readRecordChainIds(): string[] {
    return Array.from(new Set(this.recordChainMap.values())).sort(cmpString);
  }

  async storeAnnotation(annotation: AnnotationRecord): Promise<void> {
    if (this.annotations.has(annotation.id)) {
      throw new DuplicateRecordError('Annotation', annotation.id);
    }
    this.annotations.set(annotation.id, jsonClone(annotation));
  }

  async getAnnotation(id: string): Promise<AnnotationRecord | null> {
    const ann = this.annotations.get(id);
    return ann ? jsonClone(ann) : null;
  }

  async listAnnotations(incidentId: string): Promise<AnnotationRecord[]> {
    return Array.from(this.annotations.values())
      .filter((a) => a.incidentId === incidentId)
      .sort((a, b) => cmpString(a.annotatedAt, b.annotatedAt) || cmpString(a.id, b.id))
      .map(jsonClone);
  }

  async listAnnotationsForRecord(evidenceId: string): Promise<AnnotationRecord[]> {
    return Array.from(this.annotations.values())
      .filter((a) => a.affectedRecords.includes(evidenceId))
      .sort((a, b) => cmpString(a.annotatedAt, b.annotatedAt) || cmpString(a.id, b.id))
      .map(jsonClone);
  }

  async storeRelink(relink: RelinkRecord): Promise<void> {
    if (this.relinks.has(relink.id)) {
      throw new DuplicateRecordError('Relink', relink.id);
    }
    this.relinks.set(relink.id, jsonClone(relink));
  }

  async getRelink(id: string): Promise<RelinkRecord | null> {
    const rlk = this.relinks.get(id);
    return rlk ? jsonClone(rlk) : null;
  }

  async listRelinks(incidentId: string): Promise<RelinkRecord[]> {
    return Array.from(this.relinks.values())
      .filter((r) => r.incidentId === incidentId)
      .sort((a, b) => cmpString(a.relinkedAt, b.relinkedAt) || cmpString(a.id, b.id))
      .map(jsonClone);
  }

  async storeFork(fork: ForkRecord): Promise<void> {
    if (this.forks.has(fork.id)) {
      throw new DuplicateRecordError('Fork', fork.id);
    }
    this.forks.set(fork.id, jsonClone(fork));
  }

  async getFork(id: string): Promise<ForkRecord | null> {
    const frk = this.forks.get(id);
    return frk ? jsonClone(frk) : null;
  }

  async listForks(incidentId: string): Promise<ForkRecord[]> {
    return Array.from(this.forks.values())
      .filter((f) => f.incidentId === incidentId)
      .sort((a, b) => cmpString(a.forkedAt, b.forkedAt) || cmpString(a.id, b.id))
      .map(jsonClone);
  }

  async listForksForChain(chainId: string): Promise<ForkRecord[]> {
    return Array.from(this.forks.values())
      .filter((f) => f.oldChainId === chainId || f.newChainId === chainId)
      .sort((a, b) => cmpString(a.forkedAt, b.forkedAt) || cmpString(a.id, b.id))
      .map(jsonClone);
  }

  async updateEnvelopeChainLink(evidenceId: string, newChainLink: string | null): Promise<void> {
    const envelope = this.envelopes.get(evidenceId);
    if (!envelope) {
      throw new Error(`Evidence record "${evidenceId}" not found.`);
    }
    const updated = jsonClone(envelope);
    updated.integrity.chainLink = newChainLink;
    this.envelopes.set(evidenceId, updated);
    // The repair, recorded: digest carried forward unchanged,
    // new link written down.
    this.appendRevision(
      evidenceId,
      this.nextRevisionFor(evidenceId),
      updated.integrity.canonicalDigest,
      newChainLink,
      'relink',
      REVISION_ACTOR_RECOVERY,
    );
  }

  /**
   * Stage one hashed custody append against `envelope` — a detached copy the
   * caller owns — without touching the store. `prevEntryHash` is the tail the
   * caller resolved (the stored tail, or a row staged earlier in the same
   * critical section, so a relink that appends twice to one record chains
   * correctly). Returns the row to commit; `id` is assigned at commit.
   */
  private stageCustodyEntry(
    envelope: EvidenceEnvelope,
    entry: CustodyEntry,
    prevEntryHash: string | null,
    recoveryId: string | null,
  ): StoredCustodyEntry {
    const evidenceId = envelope.payload.evidenceId;
    const canonicalDigest = envelope.integrity.canonicalDigest;
    const metadata = normaliseCustodyMetadata(entry.metadata);
    const entryHash = computeCustodyEntryHash({
      prevEntryHash,
      evidenceId,
      canonicalDigest,
      action: entry.action,
      actor: entry.actor,
      timestamp: entry.timestamp,
      systemId: entry.systemId,
      metadata,
    });
    envelope.custodyChain.push(mirrorCustodyEntry(entry, entryHash, prevEntryHash));
    return {
      id: 0,
      evidenceId,
      chainId: this.recordChainMap.get(evidenceId) ?? null,
      canonicalDigest,
      action: entry.action,
      actor: entry.actor,
      timestamp: entry.timestamp,
      systemId: entry.systemId,
      metadata,
      prevEntryHash,
      entryHash,
      recoveryId,
    };
  }

  private commitCustodyRow(row: StoredCustodyEntry): void {
    this.custodyEntrySeq += 1;
    const rows = this.custodyEntries.get(row.evidenceId) ?? [];
    rows.push({ ...row, id: this.custodyEntrySeq });
    this.custodyEntries.set(row.evidenceId, rows);
  }

  private custodyTail(evidenceId: string): string | null {
    const rows = this.custodyEntries.get(evidenceId);
    return rows && rows.length > 0 ? rows[rows.length - 1].entryHash : null;
  }

  /**
   * Hashed, chained append. The tail read, the hash, the row
   * and the envelope rewrite happen in one synchronous block with no `await`,
   * which is this adapter's transaction.
   */
  async confirmRecord(
    evidenceId: string,
    confirmation: NonNullable<AttestationArtifacts['confirmation']>,
    custodyEntry: CustodyEntry,
  ): Promise<{ filled: boolean }> {
    const envelope = this.envelopes.get(evidenceId);
    if (!envelope) {
      throw new Error(`Evidence record "${evidenceId}" not found. Cannot confirm it.`);
    }
    // ── critical section: no await between the read and the commit ──
    const merged = fillAbsentArtifacts(envelope.nonRepudiation, jsonClone({ confirmation }));
    if (!merged.filled) return { filled: false };
    const updated = jsonClone(envelope);
    updated.nonRepudiation = merged.merged;
    updated.attestationStatus = statusAfterFill(updated, merged.merged, (stored) => stored.attestationStatus);
    const row = this.stageCustodyEntry(updated, custodyEntry, this.custodyTail(evidenceId), null);
    this.envelopes.set(evidenceId, updated);
    this.appendRevision(
      evidenceId,
      this.nextRevisionFor(evidenceId),
      updated.integrity.canonicalDigest,
      updated.integrity.chainLink,
      'attestation_retry',
      REVISION_ACTOR_ATTESTATION,
    );
    this.commitCustodyRow(row);
    return { filled: true };
  }

  async appendCustodyEntry(
    evidenceId: string,
    entry: CustodyEntry,
    options?: CustodyAppendOptions,
  ): Promise<void> {
    const envelope = this.envelopes.get(evidenceId);
    if (!envelope) {
      throw new Error(`Evidence record "${evidenceId}" not found.`);
    }
    // ── critical section: no await between the tail read and the commit ──
    const updated = jsonClone(envelope);
    const row = this.stageCustodyEntry(updated, entry, this.custodyTail(evidenceId), options?.recoveryId ?? null);
    this.commitCustodyRow(row);
    this.envelopes.set(evidenceId, updated);
  }

  /**
   * One critical section: every link, the relink record and
   * every custody entry are staged on detached copies first and committed at
   * the end with no `await` in between, so a throw anywhere — an unknown
   * record, a duplicate relink id — leaves the store exactly as it was.
   */
  async applyRelink(relink: RelinkRecord, custodyEntries: RelinkCustodyAppend[]): Promise<void> {
    if (this.relinks.has(relink.id)) {
      throw new DuplicateRecordError('Relink', relink.id);
    }
    const staged = new Map<string, EvidenceEnvelope>();
    const stagedEnvelope = (evidenceId: string): EvidenceEnvelope => {
      const already = staged.get(evidenceId);
      if (already) return already;
      const stored = this.envelopes.get(evidenceId);
      if (!stored) {
        throw new Error(`Evidence record "${evidenceId}" not found.`);
      }
      const copy = jsonClone(stored);
      staged.set(evidenceId, copy);
      return copy;
    };
    // Staged with the links, committed with them: a relink
    // that rewrote links without leaving revision rows would be a repair the
    // store cannot later account for.
    const stagedRevisions: Array<{ evidenceId: string; chainLink: string | null }> = [];
    for (const link of relink.modifiedLinks) {
      stagedEnvelope(link.evidenceId).integrity.chainLink = link.newChainLink;
      stagedRevisions.push({ evidenceId: link.evidenceId, chainLink: link.newChainLink });
    }
    const rows: StoredCustodyEntry[] = [];
    const tails = new Map<string, string | null>();
    for (const { evidenceId, entry } of custodyEntries) {
      const envelope = stagedEnvelope(evidenceId);
      const prev = tails.has(evidenceId) ? tails.get(evidenceId)! : this.custodyTail(evidenceId);
      const row = this.stageCustodyEntry(envelope, entry, prev, relink.id);
      tails.set(evidenceId, row.entryHash);
      rows.push(row);
    }
    // ── commit ──
    this.relinks.set(relink.id, jsonClone(relink));
    for (const [evidenceId, envelope] of staged) {
      this.envelopes.set(evidenceId, envelope);
    }
    for (const row of rows) {
      this.commitCustodyRow(row);
    }
    for (const { evidenceId, chainLink } of stagedRevisions) {
      this.appendRevision(
        evidenceId,
        this.nextRevisionFor(evidenceId),
        staged.get(evidenceId)!.integrity.canonicalDigest,
        chainLink,
        'relink',
        relink.relinkedBy,
      );
    }
  }

  async listCustodyEntries(evidenceId: string): Promise<StoredCustodyEntry[]> {
    return (this.custodyEntries.get(evidenceId) ?? []).map(jsonClone);
  }

  async listEnvelopeRevisions(evidenceId: string): Promise<EnvelopeRevision[]> {
    return (this.envelopeRevisions.get(evidenceId) ?? [])
      .slice()
      .sort((a, b) => a.revisionNo - b.revisionNo)
      .map(jsonClone);
  }

  async getCaptureDigests(evidenceIds: string[]): Promise<Record<string, string>> {
    const out: Record<string, string> = {};
    for (const evidenceId of evidenceIds) {
      const capture = (this.envelopeRevisions.get(evidenceId) ?? []).find(
        (r) => r.revisionNo === CAPTURE_REVISION_NO,
      );
      // Absent stays absent: a record with no capture revision is one this
      // store cannot speak for, not one it is vouching for.
      if (capture) out[evidenceId] = capture.canonicalDigest;
    }
    return out;
  }

  async getBySequenceRange(fromSequence: number, toSequence: number, chainId?: string): Promise<EvidenceEnvelope[]> {
    return Array.from(this.envelopes.values())
      .filter((e) => {
        const seq = e.payload.sequenceNumber;
        const inRange = seq >= fromSequence && seq <= toSequence;
        if (!inRange) return false;
        if (chainId) {
          return this.recordChainMap.get(e.payload.evidenceId) === chainId;
        }
        return true;
      })
      .sort((a, b) => a.payload.sequenceNumber - b.payload.sequenceNumber)
      .map(jsonClone);
  }

  /**
   * Clear one chain's state. Refused with `ChainStateResetRefusedError` when
   * the chain's evidence log holds leaves, as the SQL adapters' `chain_state`
   * trigger refuses it.
   */
  async resetChainState(chainId: string = DEFAULT_CHAIN_ID): Promise<void> {
    if (this.logs.hasEvidenceLeaves(chainId)) throw new ChainStateResetRefusedError(chainId);
    this.chainHeads.delete(chainId);
  }

  /** The record whose stored canonical digest is `digest`, or `null`; the oldest when several share it. */
  async retrieveByDigest(digest: string): Promise<EvidenceEnvelope | null> {
    for (const id of this.insertionOrder) {
      const held = this.envelopes.get(id);
      if (held && held.integrity.canonicalDigest === digest) return jsonClone(held);
    }
    return null;
  }

  async getChainLength(chainId?: string): Promise<number> {
    if (chainId) {
      return Array.from(this.envelopes.values())
        .filter((e) => this.recordChainMap.get(e.payload.evidenceId) === chainId)
        .length;
    }
    return this.envelopes.size;
  }

  // ── AI-BOM model-descriptor catalog ────────────────────────────────

  /** The row as the SQL adapters return it: `descriptor` parsed from the bytes. */
  private rowToModelDescriptorRow(row: StoredModelDescriptorRow): ModelDescriptorRow {
    return {
      ...row,
      descriptor: JSON.parse(row.canonicalBytes) as ModelDescriptor,
    };
  }

  async registerModelDescriptor(
    descriptor: ModelDescriptor,
    source: ModelDescriptorRow['source'],
    registeredBy: string,
  ): Promise<{ digest: string; alreadyExisted: boolean }> {
    // The catalog write is the choke point: the connector path
    // (wrappers.ts) and the inline-AI-BOM capture path (sdk/index.ts) both
    // land here WITHOUT passing through register.ts's `mvdFrom`, so this is
    // the only place that sees every descriptor before it is stored.
    assertDescriptorIntegrityInvariants(descriptor, 'registerModelDescriptor');
    const canonicalBytes = canonicalSerializeDescriptor(descriptor);
    const digest = 'sha256:' + createHash('sha256').update(canonicalBytes).digest('hex');
    const existing = this.modelDescriptors.get(digest);
    if (existing) {
      return { digest, alreadyExisted: true };
    }
    const row: StoredModelDescriptorRow = {
      modelDescriptorDigest: digest,
      canonicalBytes,
      vendor: descriptor.vendor,
      modelName: descriptor.modelName,
      modelVersion: descriptor.modelVersion,
      parentModelDescriptorDigest: descriptor.parentModelDescriptorDigest,
      source,
      firstRegisteredAt: new Date().toISOString(),
      firstRegisteredBy: registeredBy,
    };
    this.modelDescriptors.set(digest, row);
    return { digest, alreadyExisted: false };
  }

  async getModelDescriptor(digest: string): Promise<ModelDescriptorRow | null> {
    const row = this.modelDescriptors.get(digest);
    return row ? this.rowToModelDescriptorRow(row) : null;
  }

  async getEnrichedModelDescriptor(digest: string): Promise<ModelDescriptor | null> {
    const row = this.modelDescriptors.get(digest);
    if (!row) return null;
    const annotations = await this.listModelDescriptorAnnotations(digest);
    return buildEnrichedView(this.rowToModelDescriptorRow(row).descriptor, annotations);
  }

  async listModelDescriptors(filter: {
    vendor?: string;
    modelName?: string;
    modelVersion?: string;
    integrityTier?: 'weight-attested' | 'vendor-asserted';
    hasRegulatoryMarking?: boolean;
    limit?: number;
    offset?: number;
  } = {}): Promise<ModelDescriptorRow[]> {
    let rows = Array.from(this.modelDescriptors.values()).map((r) => this.rowToModelDescriptorRow(r));
    if (filter.vendor !== undefined) rows = rows.filter((r) => r.vendor === filter.vendor);
    if (filter.modelName !== undefined) rows = rows.filter((r) => r.modelName === filter.modelName);
    if (filter.modelVersion !== undefined) rows = rows.filter((r) => r.modelVersion === filter.modelVersion);
    if (filter.integrityTier !== undefined) {
      rows = rows.filter((r) => r.descriptor.integrityTier === filter.integrityTier);
    }
    if (filter.hasRegulatoryMarking === true) {
      rows = rows.filter((r) => r.descriptor.regulatoryMarkings.length > 0);
    } else if (filter.hasRegulatoryMarking === false) {
      rows = rows.filter((r) => r.descriptor.regulatoryMarkings.length === 0);
    }
    const offset = filter.offset !== undefined ? assertNonNegativeInteger(filter.offset, 'offset') : 0;
    const end = filter.limit !== undefined ? offset + assertNonNegativeInteger(filter.limit, 'limit') : undefined;
    return rows.slice(offset, end);
  }

  async listDescendantDescriptors(parentDigest: string): Promise<ModelDescriptorRow[]> {
    return Array.from(this.modelDescriptors.values())
      .filter((r) => r.parentModelDescriptorDigest === parentDigest)
      .map((r) => this.rowToModelDescriptorRow(r));
  }

  async appendModelDescriptorAnnotation(annotation: ModelDescriptorAnnotationRow): Promise<void> {
    // FK to model_descriptors, then PK on annotation_id — the order the SQL
    // adapters report them in. An orphan annotation is data the enriched view
    // can never reach.
    if (!this.modelDescriptors.has(annotation.modelDescriptorDigest)) {
      throw new MissingReferenceError(
        'Model descriptor annotation', 'model descriptor', annotation.modelDescriptorDigest,
      );
    }
    for (const list of this.modelDescriptorAnnotations.values()) {
      if (list.some((a) => a.annotationId === annotation.annotationId)) {
        throw new DuplicateRecordError('Model descriptor annotation', annotation.annotationId);
      }
    }
    const list = this.modelDescriptorAnnotations.get(annotation.modelDescriptorDigest) ?? [];
    list.push(jsonClone(annotation));
    this.modelDescriptorAnnotations.set(annotation.modelDescriptorDigest, list);
  }

  async listModelDescriptorAnnotations(digest: string): Promise<ModelDescriptorAnnotationRow[]> {
    // annotatedAt ASC, annotationId ASC — what both SQL adapters produce.
    const list = this.modelDescriptorAnnotations.get(digest) ?? [];
    return [...list]
      .sort((a, b) => cmpString(a.annotatedAt, b.annotatedAt) || cmpString(a.annotationId, b.annotationId))
      .map(jsonClone);
  }

  async setModelDescriptorAlias(slug: string, digest: string, setBy: string): Promise<void> {
    // The alias table's key is (slug, setAt) at millisecond resolution. A
    // rebind in the same millisecond REPLACES that instant's row — last
    // writer wins — on every adapter.
    const setAt = new Date().toISOString();
    const row: ModelDescriptorAliasRow = { slug, setAt, modelDescriptorDigest: digest, setBy };
    const list = this.modelDescriptorAliases.get(slug) ?? [];
    const sameInstant = list.findIndex((a) => a.setAt === setAt);
    if (sameInstant === -1) list.push(row);
    else list[sameInstant] = row;
    this.modelDescriptorAliases.set(slug, list);
  }

  async resolveModelDescriptorAlias(slug: string): Promise<string | null> {
    const list = this.modelDescriptorAliases.get(slug);
    if (!list || list.length === 0) return null;
    // Latest setAt wins; `>=` so an equal instant resolves to the later write.
    const latest = list.reduce((acc, cur) => (cur.setAt >= acc.setAt ? cur : acc));
    return latest.modelDescriptorDigest;
  }

  /**
   * Returns the most recently stored evidence envelope (last by insertion order),
   * or null if the store is empty.
   */
  async head(): Promise<EvidenceEnvelope | null> {
    if (this.insertionOrder.length === 0) return null;
    const lastId = this.insertionOrder[this.insertionOrder.length - 1];
    const stored = this.envelopes.get(lastId);
    return stored ? jsonClone(stored) : null;
  }

  // ── Demo-tamper hooks ──────────────────────────────

  private demoTamperView(): DemoTamperStoreView {
    return {
      hasSentinel: async () => this.demoSentinelWritten,
      writeSentinel: async () => { this.demoSentinelWritten = true; },
      envelopeCount: async () => this.envelopes.size,
      // the store IS this process's heap. There is no host it could be
      // pointed at, so it is local by construction, not by assumption.
      target: () => ({ kind: 'local', what: 'in-process memory' }),
    };
  }

  async armDemoTamperHooks(): Promise<void> {
    this.demoHooksArmed = await tryArmDemoTamperHooks(this.demoTamperView(), 'memory');
  }

  async deleteEnvelopeForDemo(evidenceId: string): Promise<void> {
    assertArmed(this.demoHooksArmed);
    const held = this.envelopes.get(evidenceId);
    const chainId = this.recordChainMap.get(evidenceId);
    if (held && chainId !== undefined) {
      const position = positionKey(chainId, held.payload.sequenceNumber);
      if (this.positions.get(position) === evidenceId) this.positions.delete(position);
    }
    this.envelopes.delete(evidenceId);
    this.recordChainMap.delete(evidenceId);
    const idx = this.insertionOrder.indexOf(evidenceId);
    if (idx !== -1) this.insertionOrder.splice(idx, 1);
  }

  async overwriteModelDescriptorBytesForDemo(digest: string, canonicalBytes: string): Promise<string> {
    assertArmed(this.demoHooksArmed);
    const row = this.modelDescriptors.get(digest);
    if (!row) throw new Error(`No model descriptor row for digest ${digest}`);
    const previous = row.canonicalBytes;
    row.canonicalBytes = canonicalBytes;
    return previous;
  }

  /**
   * The credential directory for this adapter.
   *
   * Cached, unlike the SQL adapters: there is no shared file or pool behind
   * it, so a fresh instance per call would be a fresh EMPTY directory and
   * `register()` then `getByCredentialId()` would disagree — precisely the
   * kind of divergence between the double and the real stores that the
   * conformance suites exist to catch.
   */
  credentialStore(): AsyncCredentialStore {
    if (!this.credentials) this.credentials = new MemoryCredentialStore();
    return this.credentials;
  }

  /**
   * The store's identity and evidence logs. There is no anchor store on this
   * adapter: anchoring is refused on memory, so nothing here cuts
   * checkpoints or publishes.
   */
  logStore(): LogStore {
    return this.logs;
  }

  /**
   * No-op for the in-memory backend — nothing external to release. Implements
   * the optional `StorageAdapter.close()` contract so `Tzun.close()` can call
   * it uniformly without backend-specific branching.
   */
  async close(): Promise<void> {
    /* no-op */
  }
}
