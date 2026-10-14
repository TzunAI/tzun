import { AttestationStatusOf, StorageAdapter, StoreOptions } from '@tzun/engine';
import { MonitoringEventBus } from './event-bus';
import { SchemaRegistry } from '@tzun/engine';
import { recordDigestCheck, recordVerdict, toCustodyLedgerEntry } from '@tzun/engine';
import { EvidenceEnvelope, AttestationArtifacts, CustodyEntry } from '@tzun/engine';
import { FailureRecord } from '@tzun/engine';
import { ListOptions, RetryObtainableComponent } from '@tzun/engine';
import { TamperIncident, TamperIncidentStatus } from '@tzun/engine';
import { ChainIdentity, AnnotationRecord, RelinkRecord, ForkRecord } from '@tzun/engine';
import type {
  EvidenceRead,
  IdempotencyOutcome,
  IdempotentStoreOptions,
  ModelDescriptor,
  ModelDescriptorRow,
  ModelDescriptorAnnotationRow,
  CustodyAppendOptions,
  EnvelopeRevision,
  RecordCustodyCheck,
  RecordDigestCheck,
  RecordVerdict,
  RecordVerdictInput,
  RelinkCustodyAppend,
  StoredCustodyEntry,
} from '@tzun/engine';
import type { AsyncCredentialStore } from '../attestation/credential-store';
import type { CredentialStoreProvider } from '../storage/credential-stores';
import type { AnchorStore, AnchorStoreProvider, LogStore, LogStoreProvider } from '../storage/log-store';
import { LruCache } from '../models/lru-cache';

/**
 * VerifyingStorageProxy — a StorageAdapter wrapper that checks every evidence
 * record it reads.
 *
 * `Tzun.init()` wraps every local adapter in one unless the caller passes
 * `verifyReads: false`. Two read paths, one set of checks:
 *
 *   - `retrieveWithVerdict()` / `listWithVerdicts()` — what `tzun.get()` and
 *     `tzun.list()` return: each record with its `RecordVerdict` (the engine's
 *     `recordVerdict`: the digest recomputed, and the custody ledger rows
 *     checked against the `custodyChain` mirror). Cost per record: one
 *     canonical serialization and SHA-256 of the payload, and one indexed
 *     `custody_entries` read.
 *   - `retrieve()` / `list()` — the `StorageAdapter` contract, for everything
 *     else that reads through the SDK's storage (recovery, the scanner's
 *     record reads, the models catalog): the digest check only, no extra I/O.
 *
 * On either path a record whose digest check is not `valid` is reported on the
 * monitoring bus as `digest_mismatch`, when the instance has a bus
 * (`monitoring.enabled`). On the verdict path — the only one that reads the
 * custody ledger — a record whose custody trail is `invalid` is reported as
 * `custody_trail_invalid`, once per record.
 *
 * The proxy never blocks a read. A tampered record is returned to the caller
 * with its verdict; a check whose input cannot be read (the custody ledger)
 * is reported `unmeasured` with the error, never thrown. Blocking would break
 * `RecoveryManager.annotate()` on exactly the records that need it, and would
 * let a single UPDATE deny reads of a whole range.
 *
 * All write methods and non-evidence reads delegate directly to the wrapped
 * inner adapter.
 */
/**
 * How many records the custody-trail dedupe remembers. A store with more
 * broken trails than this re-raises the oldest one on the next read that
 * touches it, which is the safe direction: a finding is reported again rather
 * than dropped.
 */
const CUSTODY_DEDUPE_CAPACITY = 1024;

/** The optional `StorageAdapter` methods the proxy forwards when its inner adapter has them. */
const FORWARDED_OPTIONAL_METHODS = [
  'putAgentDescriptor',
  'getAgentDescriptor',
  'listAgentDescriptors',
  'getMandate',
  'getMandateTotals',
  'listMandateEvents',
  'expireMandate',
  'listMandates',
  'confirmRecord',
  'getDeciderOpening',
  'getDeciderCommitmentSecret',
  'retrieveByDigest',
  'listLinksTo',
] as const satisfies readonly (keyof StorageAdapter)[];

export class VerifyingStorageProxy implements StorageAdapter {
  /**
   * Records whose `custody_trail_invalid` has already been raised on this
   * proxy, keyed as `TamperDetector` keys the incident it opens for the event
   * (`incidentDedupeKey`: the event type and the record it names). Without it
   * every `get()` of a tampered record — and every `list()` that includes it —
   * would put another event on the bus, so one edited custody row became one
   * event per read for the life of the process, and a read loop became a
   * stream. The detector deduplicates the INCIDENT; this deduplicates the
   * event, which is what every other bus subscriber sees.
   */
  private readonly custodyRaised = new LruCache<string, true>(CUSTODY_DEDUPE_CAPACITY);

  constructor(
    private readonly inner: StorageAdapter,
    private readonly eventBus: MonitoringEventBus | null,
    private readonly registry: SchemaRegistry,
  ) {
    if (typeof inner.recordIncidentObservation === 'function') {
      this.recordIncidentObservation = (id, observedAt) =>
        inner.recordIncidentObservation!(id, observedAt);
    }
    // The optional methods a storage extension provides (the agent catalog,
    // mandates, decider openings, the link index) and the digest lookup, each
    // present on the proxy exactly when the inner adapter has it: the SDK
    // tells a store with a feature from one without by the method's presence.
    for (const name of FORWARDED_OPTIONAL_METHODS) {
      const fn = (inner as unknown as Record<string, unknown>)[name];
      if (typeof fn === 'function') {
        Object.defineProperty(this, name, {
          value: (...args: unknown[]) => (fn as (...a: unknown[]) => unknown).apply(inner, args),
          enumerable: false,
          writable: true,
          configurable: true,
        });
      }
    }
  }

  /** The adapter this proxy reads through. */
  unwrap(): StorageAdapter {
    return this.inner;
  }

  // ---------------------------------------------------------------------------
  // Reads with a verdict — what tzun.get() / tzun.list() return
  // ---------------------------------------------------------------------------

  async retrieveWithVerdict(evidenceId: string): Promise<EvidenceRead | null> {
    const envelope = await this.inner.retrieve(evidenceId);
    if (!envelope) return null;
    return { envelope, verdict: await this.verdictFor(envelope, evidenceId) };
  }

  async listWithVerdicts(options?: ListOptions): Promise<EvidenceRead[]> {
    const envelopes = await this.inner.list(options);
    // Concurrent, so a pooled adapter overlaps the per-record ledger reads.
    return Promise.all(
      envelopes.map(async (envelope) => ({
        envelope,
        verdict: await this.verdictFor(envelope, envelope.payload?.evidenceId),
      })),
    );
  }

  // ---------------------------------------------------------------------------
  // StorageAdapter reads — digest check only
  // ---------------------------------------------------------------------------

  async retrieve(evidenceId: string): Promise<EvidenceEnvelope | null> {
    const envelope = await this.inner.retrieve(evidenceId);
    if (envelope) {
      this.report(envelope, recordDigestCheck(envelope, this.registry));
    }
    return envelope;
  }

  async list(options?: ListOptions): Promise<EvidenceEnvelope[]> {
    const envelopes = await this.inner.list(options);
    for (const envelope of envelopes) {
      this.report(envelope, recordDigestCheck(envelope, this.registry));
    }
    return envelopes;
  }

  // ---------------------------------------------------------------------------
  // Checks
  // ---------------------------------------------------------------------------

  private async verdictFor(envelope: EvidenceEnvelope, evidenceId: unknown): Promise<RecordVerdict> {
    const verdict = recordVerdict(envelope, {
      registry: this.registry,
      custody: await this.readCustody(evidenceId),
    });
    this.report(envelope, verdict.digest);
    this.reportCustody(evidenceId, verdict.custodyTrail);
    return verdict;
  }

  /** The record's ledger rows, or the error reading them failed with. Never throws. */
  private async readCustody(evidenceId: unknown): Promise<RecordVerdictInput['custody']> {
    if (typeof evidenceId !== 'string') {
      return { error: 'the stored record carries no evidenceId to read its custody ledger by' };
    }
    try {
      const rows = await this.inner.listCustodyEntries(evidenceId);
      return { entries: rows.map(toCustodyLedgerEntry) };
    } catch (err) {
      return { error: err instanceof Error ? err.message : String(err) };
    }
  }

  /**
   * Emit `digest_mismatch` for a digest check that is not `valid`.
   *
   * An unknown `schemaVersion` and an unserializable payload are reported
   * here too, with `recomputed: ''`: `schemaVersion` is outside the v1.0
   * hashed field set and the registry only holds the versions a writer can
   * produce, so an unknown one is itself evidence of modification, and a
   * payload with no canonical form has no digest that can be true of it.
   */
  private report(envelope: EvidenceEnvelope, digest: RecordDigestCheck): void {
    if (!this.eventBus || digest.status === 'valid') return;
    this.eventBus.emit({
      type: 'digest_mismatch',
      evidenceId: envelope.payload?.evidenceId,
      stored: digest.stored,
      recomputed: digest.recomputed,
    });
  }

  /**
   * Emit `custody_trail_invalid` for a read whose custody-trail check failed,
   * at most once per record on this proxy.
   *
   * `custodyChain` sits outside the v1.0 hashed field set, so an insider who
   * rewrites, reorders or deletes a custody entry changes no digest and breaks
   * no chain link: the read's own verdict was the only place that said so, and
   * a monitoring bus that heard `digest_mismatch` from this same method heard
   * nothing about custody. Nothing raised an incident until the next scheduled
   * scan, and a store with no scanner never raised one at all.
   *
   * `unmeasured` is not a finding — a record with no ledger rows and no hashed
   * entries has nothing to measure, and an unreadable ledger is reported in the
   * verdict with its error. Only `invalid` is emitted, carrying the ledger
   * failures the verdict names; the scanner's event additionally carries the
   * envelope-only trail check and the relink-digest check, which a read does
   * not make.
   */
  private reportCustody(evidenceId: unknown, custody: RecordCustodyCheck): void {
    if (!this.eventBus || custody.status !== 'invalid') return;
    const id = typeof evidenceId === 'string' ? evidenceId : '';
    const key = `custody_trail_invalid|${id}`;
    if (this.custodyRaised.has(key)) return;
    this.custodyRaised.set(key, true);
    this.eventBus.emit({
      type: 'custody_trail_invalid',
      evidenceId: id,
      failures: custody.ledger?.failures ?? [],
    });
  }

  // ---------------------------------------------------------------------------
  // Direct delegations — all other StorageAdapter methods
  // ---------------------------------------------------------------------------

  async store(envelope: EvidenceEnvelope, chainId?: string, options?: StoreOptions): Promise<void> {
    return this.inner.store(envelope, chainId, options);  // forward StoreOptions
  }

  /**
   * Forwarded so a keyed capture reaches the adapter's claim-or-replay. Without
   * it the method would be invisible whenever the monitoring proxy is on, and a
   * retried capture would store a second record. An inner adapter that does not
   * implement it — the HTTP adapter, which sends the key as a header — is
   * reported as not implementing it here too.
   */
  async storeIdempotent(
    envelope: EvidenceEnvelope,
    chainId: string | undefined,
    options: IdempotentStoreOptions,
  ): Promise<IdempotencyOutcome> {
    if (!this.inner.storeIdempotent) {
      throw new Error(
        'This storage adapter does not implement storeIdempotent (an idempotency key cannot be claimed locally).',
      );
    }
    return this.inner.storeIdempotent(envelope, chainId, options);
  }

  async storeFailure(failure: FailureRecord): Promise<void> {
    return this.inner.storeFailure(failure);
  }

  async getLastDigest(chainId?: string): Promise<string | null> {
    return this.inner.getLastDigest(chainId);
  }

  async getLastSequence(chainId?: string): Promise<number> {
    return this.inner.getLastSequence(chainId);
  }

  async listBySequence(fromSequence?: number, toSequence?: number, chainId?: string): Promise<EvidenceEnvelope[]> {
    return this.inner.listBySequence(fromSequence, toSequence, chainId);
  }

  async updateAttestation(
    evidenceId: string,
    artifacts: AttestationArtifacts,
    newStatus: EvidenceEnvelope['attestationStatus'] | AttestationStatusOf,
  ): Promise<void> {
    return this.inner.updateAttestation(evidenceId, artifacts, newStatus);
  }

  async listByAttestationStatus(
    status: EvidenceEnvelope['attestationStatus'],
    limit?: number,
  ): Promise<EvidenceEnvelope[]> {
    // `limit` is forwarded, not dropped: swallowing it here would turn every
    // bounded read into a read of the whole status.
    return this.inner.listByAttestationStatus(status, limit);
  }

  async listByMissingObtainable(
    components: readonly RetryObtainableComponent[],
    limit?: number,
  ): Promise<EvidenceEnvelope[]> {
    // Forwarded whole, `limit` included: this is the retry pass's queue read.
    return this.inner.listByMissingObtainable(components, limit);
  }

  async storeIncident(incident: TamperIncident): Promise<void> {
    return this.inner.storeIncident(incident);
  }

  async getIncident(id: string): Promise<TamperIncident | null> {
    return this.inner.getIncident(id);
  }

  async listIncidents(filter?: { status?: TamperIncidentStatus; severity?: string }): Promise<TamperIncident[]> {
    return this.inner.listIncidents(filter);
  }

  async updateIncidentStatus(
    id: string,
    status: TamperIncidentStatus,
    metadata?: { resolvedBy?: string; resolutionNotes?: string },
  ): Promise<void> {
    return this.inner.updateIncidentStatus(id, status, metadata);
  }

  /**
   * Present only when the wrapped adapter has it — assigned in the constructor
   * — so that the detector's
   * `typeof storage.recordIncidentObservation === 'function'` check sees the
   * inner adapter's own answer. An unconditional method here would claim the
   * capability for a store that does not have it and then throw on every
   * observation.
   */
  recordIncidentObservation?: (id: string, observedAt: string) => Promise<void>;

  // ---------------------------------------------------------------------------
  // Chain identity delegations
  // ---------------------------------------------------------------------------

  async getChainForRecord(evidenceId: string): Promise<string | null> {
    return this.inner.getChainForRecord(evidenceId);
  }

  async storeChain(chain: ChainIdentity): Promise<void> {
    return this.inner.storeChain(chain);
  }

  async getChain(chainId: string): Promise<ChainIdentity | null> {
    return this.inner.getChain(chainId);
  }

  async listChains(): Promise<ChainIdentity[]> {
    return this.inner.listChains();
  }

  async sealChain(chainId: string, sealedAt: string): Promise<void> {
    return this.inner.sealChain(chainId, sealedAt);
  }

  async getActiveChainId(): Promise<string> {
    return this.inner.getActiveChainId();
  }

  async listRecordChainIds(): Promise<string[]> {
    return this.inner.listRecordChainIds();
  }

  // ---------------------------------------------------------------------------
  // Recovery storage delegations
  // ---------------------------------------------------------------------------

  async storeAnnotation(annotation: AnnotationRecord): Promise<void> {
    return this.inner.storeAnnotation(annotation);
  }

  async getAnnotation(id: string): Promise<AnnotationRecord | null> {
    return this.inner.getAnnotation(id);
  }

  async listAnnotations(incidentId: string): Promise<AnnotationRecord[]> {
    return this.inner.listAnnotations(incidentId);
  }

  async listAnnotationsForRecord(evidenceId: string): Promise<AnnotationRecord[]> {
    return this.inner.listAnnotationsForRecord(evidenceId);
  }

  async storeRelink(relink: RelinkRecord): Promise<void> {
    return this.inner.storeRelink(relink);
  }

  async getRelink(id: string): Promise<RelinkRecord | null> {
    return this.inner.getRelink(id);
  }

  async listRelinks(incidentId: string): Promise<RelinkRecord[]> {
    return this.inner.listRelinks(incidentId);
  }

  async storeFork(fork: ForkRecord): Promise<void> {
    return this.inner.storeFork(fork);
  }

  async getFork(id: string): Promise<ForkRecord | null> {
    return this.inner.getFork(id);
  }

  async listForks(incidentId: string): Promise<ForkRecord[]> {
    return this.inner.listForks(incidentId);
  }

  async listForksForChain(chainId: string): Promise<ForkRecord[]> {
    return this.inner.listForksForChain(chainId);
  }

  // ---------------------------------------------------------------------------
  // Envelope mutation delegations (recovery operations)
  // ---------------------------------------------------------------------------

  async updateEnvelopeChainLink(evidenceId: string, newChainLink: string | null): Promise<void> {
    return this.inner.updateEnvelopeChainLink(evidenceId, newChainLink);
  }

  async appendCustodyEntry(
    evidenceId: string,
    entry: CustodyEntry,
    options?: CustodyAppendOptions,
  ): Promise<void> {
    return this.inner.appendCustodyEntry(evidenceId, entry, options);
  }

  async applyRelink(relink: RelinkRecord, custodyEntries: RelinkCustodyAppend[]): Promise<void> {
    return this.inner.applyRelink(relink, custodyEntries);
  }

  async listCustodyEntries(evidenceId: string): Promise<StoredCustodyEntry[]> {
    return this.inner.listCustodyEntries(evidenceId);
  }

  async listEnvelopeRevisions(evidenceId: string): Promise<EnvelopeRevision[]> {
    return this.inner.listEnvelopeRevisions(evidenceId);
  }

  async getCaptureDigests(evidenceIds: string[]): Promise<Record<string, string>> {
    return this.inner.getCaptureDigests(evidenceIds);
  }

  async getBySequenceRange(fromSequence: number, toSequence: number, chainId?: string): Promise<EvidenceEnvelope[]> {
    return this.inner.getBySequenceRange(fromSequence, toSequence, chainId);
  }

  async getChainLength(chainId?: string): Promise<number> {
    return this.inner.getChainLength(chainId);
  }

  async resetChainState(chainId?: string): Promise<void> {
    return this.inner.resetChainState(chainId);
  }

  // ---------------------------------------------------------------------------
  // Catalog delegations (AI-BOM model descriptors)
  //
  // The proxy intentionally forwards every model-descriptor optional method
  // to the inner storage. If the underlying adapter does not implement a
  // given method, the proxy simply does not expose it either — preserving
  // the optional-method contract on the StorageAdapter interface. This
  // matters because consumers (the SDK's inline-descriptor capture path,
  // the REST `/v1/models` router, the AI-BOM panel) check method presence
  // before calling, and would otherwise see a proxy that silently hides
  // every catalog operation behind monitoring.
  // ---------------------------------------------------------------------------

  registerModelDescriptor = this.inner.registerModelDescriptor
    ? (descriptor: ModelDescriptor, source: ModelDescriptorRow['source'], registeredBy: string) =>
        this.inner.registerModelDescriptor!(descriptor, source, registeredBy)
    : undefined;

  getModelDescriptor = this.inner.getModelDescriptor
    ? (digest: string) => this.inner.getModelDescriptor!(digest)
    : undefined;

  getEnrichedModelDescriptor = this.inner.getEnrichedModelDescriptor
    ? (digest: string) => this.inner.getEnrichedModelDescriptor!(digest)
    : undefined;

  listModelDescriptors = this.inner.listModelDescriptors
    ? (filter?: Parameters<NonNullable<StorageAdapter['listModelDescriptors']>>[0]) =>
        this.inner.listModelDescriptors!(filter)
    : undefined;

  listDescendantDescriptors = this.inner.listDescendantDescriptors
    ? (parentDigest: string) => this.inner.listDescendantDescriptors!(parentDigest)
    : undefined;

  appendModelDescriptorAnnotation = this.inner.appendModelDescriptorAnnotation
    ? (annotation: ModelDescriptorAnnotationRow) =>
        this.inner.appendModelDescriptorAnnotation!(annotation)
    : undefined;

  listModelDescriptorAnnotations = this.inner.listModelDescriptorAnnotations
    ? (digest: string) => this.inner.listModelDescriptorAnnotations!(digest)
    : undefined;

  setModelDescriptorAlias = this.inner.setModelDescriptorAlias
    ? (slug: string, digest: string, setBy: string) =>
        this.inner.setModelDescriptorAlias!(slug, digest, setBy)
    : undefined;

  resolveModelDescriptorAlias = this.inner.resolveModelDescriptorAlias
    ? (slug: string) => this.inner.resolveModelDescriptorAlias!(slug)
    : undefined;

  head = this.inner.head
    ? () => this.inner.head!()
    : undefined;

  // ── Demo-tamper hook forwarding ───────────────────────────────────────
  // Conditionally bound — `'deleteEnvelopeForDemo' in proxy` stays truthy
  // only when the inner adapter implements it (mirrors the catalog pattern).

  deleteEnvelopeForDemo = this.inner.deleteEnvelopeForDemo
    ? (evidenceId: string) => this.inner.deleteEnvelopeForDemo!(evidenceId)
    : undefined;

  overwriteModelDescriptorBytesForDemo = this.inner.overwriteModelDescriptorBytesForDemo
    ? (digest: string, canonicalBytes: string) =>
        this.inner.overwriteModelDescriptorBytesForDemo!(digest, canonicalBytes)
    : undefined;

  /**
   * The inner adapter's durable credential directory, when it has one
   * (`CredentialStoreProvider`), so `Tzun.getCredentialStore()` finds it
   * through the proxy.
   */
  credentialStore = typeof (this.inner as Partial<CredentialStoreProvider>).credentialStore === 'function'
    ? (): AsyncCredentialStore => (this.inner as unknown as CredentialStoreProvider).credentialStore()
    : undefined;

  /**
   * The inner adapter's evidence logs and anchoring tables, when it has them
   * (`LogStoreProvider`, `AnchorStoreProvider`), so `logStoreFor()` and
   * `anchorStoreFor()` find them through the proxy, and the anchor scheduler
   * `Tzun.init()` creates works on the store as the rest of the SDK sees it,
   * never on the raw adapter.
   */
  logStore = typeof (this.inner as Partial<LogStoreProvider>).logStore === 'function'
    ? (): LogStore => (this.inner as unknown as LogStoreProvider).logStore()
    : undefined;

  anchorStore = typeof (this.inner as Partial<AnchorStoreProvider>).anchorStore === 'function'
    ? (): AnchorStore => (this.inner as unknown as AnchorStoreProvider).anchorStore()
    : undefined;

  /**
   * Propagate close() to the wrapped adapter so resources (Postgres pool,
   * SQLite file handle) are released. The proxy holds nothing of its own.
   */
  close = this.inner.close
    ? () => this.inner.close!()
    : undefined;
}
