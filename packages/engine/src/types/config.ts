import { MonitoringConfig } from './monitoring-events';

/**
 * Re-export of `CaptureInput` from `./evidence`. The canonical declaration
 * lives in `evidence.ts` (alongside the payload/envelope shapes it relates
 * to); this re-export keeps the historical `types/config` import path
 * usable for callers that group "input-side" types here, including the
 * AI-BOM test suite.
 */
export type { CaptureInput } from './evidence';

/**
 * Deployment mode for the Tzun SDK.
 *
 * - dev: In-memory storage, no attestation, no network. Default.
 * - local: SQLite-backed by default, explicit opt-in via mode: 'local'.
 * - cloud: Managed permanent ledger at api.tzun.io.
 * - self-hosted: Docker/Kubernetes in customer VPC.
 */
export type Mode = 'dev' | 'local' | 'cloud' | 'self-hosted';

/** Which attestation components a capture can require (`AttestationConfig.require`). */
export type CaptureAttestation = 'timestamp' | 'webauthn';

/**
 * A component the pending-attestation retry obtains for a record after it is
 * stored, and so the components `AttestationConfig.deferrable` may name. The
 * retry lists records by the one they are missing
 * (`StorageAdapter.listByMissingObtainable`).
 *
 * An anchor is not one of these. It is published for a batch of records,
 * never obtained for one, so neither capture nor the retry requests it.
 */
export type RetryObtainableComponent = 'timestamp';

/** Which attestation components a capture obtains, and from where (`TzunConfig.attestation`). */
export interface AttestationConfig {
  /** RFC 3161 timestamp service configuration. */
  timestamp?: {
    /**
     * The primary Timestamp Authority.
     *
     * Setting ONLY this key pins capture to exactly one authority, so that
     * authority's outage is your outage: with the timestamp deferrable (the
     * default in every production mode) every record captured during it is
     * stored 'pending' until the retry obtains its token, and with
     * `require: ['timestamp']` `capture()` returns
     * `{ stored: false, failure: attestation_failure }` for the duration. Pair
     * it with `rfc3161Urls` unless you specifically want a single authority.
     */
    rfc3161Url?: string;
    /**
     * Fallback Timestamp Authorities, tried in order after `rfc3161Url`.
     *
     * A token from ANY of them satisfies the timestamp component: what it
     * asserts is that an independent third party attested the digest at time
     * T, and each of these is such a party. Which one issued a given token is
     * recoverable from the token itself — its signing certificate is embedded
     * in the response — and surfaces as `nonRepudiation.rfc3161Metadata.tsaName`.
     *
     * When neither key is set the SDK uses `DEFAULT_TIMESTAMP_AUTHORITIES`.
     */
    rfc3161Urls?: string[];
  };
  /** WebAuthn (FIDO2) relying-party configuration. */
  webauthn?: {
    rpId?: string;
    rpName?: string;
  };
  /**
   * Components a record is not stored without. When one is not obtained,
   * `capture()` stores nothing and returns
   * `{ stored: false, failure: attestation_failure }`.
   *
   * `'webauthn'` here means a signature bound to the record's digest; an
   * assertion over anything else does not satisfy it.
   *
   * `Tzun.init()` refuses `'blockchain'` or `'anchor'` here: a capture never
   * waits on a chain, so no record holds an anchor when `capture()` returns.
   */
  require?: CaptureAttestation[];
  /**
   * Components obtained for every record, which a capture may store without
   * when no service answers. Such a record is stored with
   * `attestationStatus: 'pending'`, and the SDK requests what it lacks again,
   * on the `retry` schedule or when `Tzun.retryPendingAttestations()` is
   * called, until it holds every component; it stays 'pending' until then. A
   * deferrable component is never given up on.
   *
   * Only `'timestamp'` ({@link RetryObtainableComponent}). A WebAuthn
   * signature is a human ceremony over the record's digest, which the SDK
   * cannot obtain later on its own, and `Tzun.init()` refuses `'blockchain'`
   * or `'anchor'`: the retry never obtains an anchor.
   *
   * A component may be in `require` or `deferrable`, not both. In a
   * production mode (`local`, `cloud`, `self-hosted`) on a local store, when
   * `require` is unset the timestamp is added here if it is not already
   * listed, and when `require` is set the timestamp must be in one of the two
   * lists or `Tzun.init()` refuses the config.
   */
  deferrable?: RetryObtainableComponent[];
  /**
   * When 'pending' records are retried without being asked. Each scheduled
   * pass is one `Tzun.retryPendingAttestations({ limit: batchSize })`, and a
   * pass never overlaps another, scheduled or called by hand. `Tzun.close()`
   * stops the schedule and waits for a pass in flight.
   */
  retry?: {
    /**
     * Wait between scheduled passes, in milliseconds. Default: 60 000 in a
     * production mode on a local store with a deferrable component, and no
     * schedule otherwise. `0` means no schedule: passes run only when
     * `retryPendingAttestations()` is called. The first scheduled pass runs one
     * interval after `init()`. Refused on the cloud transport, which cannot
     * list pending records; the platform's worker attests cloud records.
     */
    intervalMs?: number;
    /**
     * `false` leaves a configured schedule unstarted: passes run only when
     * `retryPendingAttestations()` is called. Default: `true`.
     */
    autoStart?: boolean;
    /** Most records a scheduled pass requests attestation for. Default: 100. */
    batchSize?: number;
    /**
     * Ceiling on the wait between scheduled passes while passes obtain
     * nothing. The wait doubles after each pass that attempted records and
     * obtained no artifact for any of them (every authority failing), or that
     * failed outright, and returns to `intervalMs` after a pass that obtains
     * something. Default: 15 minutes, or `intervalMs` when that is longer.
     */
    maxBackoffMs?: number;
  };
}

/**
 * The transaction an {@link AnchorTransactionSigner} is asked to sign: an
 * EIP-1559 transaction with every field set. A signer signs it exactly as
 * given; the SDK parses what comes back and refuses a transaction that
 * differs in any field, that another address signed, or that breaks a rule
 * of tzun-anchor/1 §10.4 item 2 other than a high `s`.
 */
export interface AnchorTransactionRequest {
  type: 2;
  chainId: bigint;
  nonce: number;
  /** `0x` and 40 hex. */
  to: string;
  value: bigint;
  /** Calldata, `0x` hex. */
  data: string;
  gasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

/**
 * Signs the publisher's transactions for the SDK without handing it the key:
 * a customer may keep its publisher key in its own tool or KMS, and Tzun
 * never takes it. An ethers `Signer`
 * satisfies it: a `Wallet`, or a KMS or HSM signer built on `AbstractSigner`.
 * It must sign offline (`signTransaction`); the SDK broadcasts the signed
 * bytes itself, after it has stored them.
 */
export interface AnchorTransactionSigner {
  /** The publisher's address, `0x` and 40 hex. Read once, when the scheduler is created. */
  getAddress(): Promise<string>;
  /**
   * The signed transaction, `0x` hex: `0x02 ‖ rlp(fields ‖ signature)`. A
   * signature whose `s` is above (n − 1) / 2, as some KMS and HSM signers
   * return, is accepted: the SDK replaces `s` with n − s and flips `yParity`,
   * the same key's signature over the same hash, and stores and broadcasts
   * that transaction, whose id differs from the one returned (tzun-anchor/1
   * §7.2 rule 3).
   */
  signTransaction(transaction: AnchorTransactionRequest): Promise<string>;
}

/**
 * The EVM publisher of `evm-calldata/1` (tzun-anchor/1 §7.2), with its key
 * given in exactly one of two ways: `privateKey`, which the SDK holds in
 * memory, or `signer`, which holds it elsewhere. The SDK never reads either
 * from the environment and never logs either.
 */
export type EvmPublisherConfig = {
  /** JSON-RPC endpoint the scheduler reads the chain from and broadcasts to. Not a secret. */
  rpcUrl: string;
  /** CAIP-2 chain, `eip155:<id>`. The node's chain id must match it. */
  chain: string;
  /**
   * How long the SDK waits for the signer's `getAddress()` and for each
   * `signTransaction()`, in milliseconds. A call that has not settled by then
   * (a KMS, an HSM or an approval tool that never replies) fails the pass
   * with `AnchorSignerUnavailableError` and the `anchor_signer_unavailable`
   * alarm, and nothing is stored or sent; a signature that arrives later is
   * dropped. Default 60,000.
   */
  signTimeoutMs?: number;
} & (
  | {
      /** The dedicated publisher's private key, `0x` and 64 hex, passed in by the caller. */
      privateKey: string;
      signer?: never;
    }
  | {
      /** A signer that holds the dedicated publisher's key: the SDK sees only its address and signatures. */
      signer: AnchorTransactionSigner;
      privateKey?: never;
    }
);

/**
 * A sink the database owner cannot rewrite.
 * Reserved: the mirror arrives with the `rfc3161/1` publisher (Anchor §7.3, §10.6).
 */
export interface WriteOnceSink {
  put(key: string, value: string): Promise<void>;
}

/** When epochs are cut. Configuration, never wire format. */
export interface AnchorCadence {
  /** Publish when the oldest waiting leaf that is not an `anchor_fill` revision leaf is this old. Default 1 h. */
  targetIntervalMs: number;
  /** Never publish more often, except by `anchorNow({ force: true })`. Default 10 min. */
  minIntervalMs: number;
  /** Publish early (no sooner than `minIntervalMs`) when this many leaves wait. Default 10,000. */
  sizeTrigger: number;
  /** T_max: publish regardless of the soft fee maximum, within the hard cap. Default 24 h. */
  maxStalenessMs: number;
}

/** What publishing may cost. */
export interface AnchorBudget {
  /** The runway the governor spreads the balance over. Default 180 days. */
  runwayDays: number;
  /** Above this the governor defers publication until T_max. Default 20 gwei. */
  softMaxFeeGwei: number;
  /** No attempt and no replacement ever exceeds it. Default 50 gwei. */
  hardFeeCapGwei: number;
  /** Forced publications per rolling 24 hours. Default 6. */
  forcePerDay: number;
}

/**
 * One publisher, as a verifier's own manifest lists it (tzun-anchor/1 §9). A
 * verifier learns publishers from its input, never from the artifact.
 */
export interface PublisherManifestEntry {
  /** The publisher wallet: `0x` + 40 hex. Compared case-insensitively. */
  address: string;
  /** CAIP-2 chain, `eip155:<decimal chain id>`. Entries in other namespaces are not EVM publishers and are skipped. */
  chain: string;
  namespace: 'production' | 'test';
  /** RFC 3339. The entry counts for blocks at or after this instant. Absent: no lower bound. */
  validFrom?: string | null;
  /** RFC 3339. The entry counts for blocks at or before this instant. Absent: no upper bound. */
  validUntil?: string | null;
}

/**
 * The minimal publisher manifest a verifier reads: each anchor origin mapped
 * to the entries allowed to publish for it.
 */
export interface PublisherManifest {
  publishers: Record<string, PublisherManifestEntry[]>;
}

/**
 * Anchoring: the store's records are anchored by an anchor
 * scheduler that cuts epochs of the store's logs and publishes one value P per
 * epoch (tzun-anchor/1 §6). `Tzun.init()` runs one on a SQLite or Postgres
 * store and refuses it on the memory adapter and the cloud transport.
 *
 * Every writer of an anchored store must expect the same timestamp (the same
 * `'timestamp'` in `attestation.require` or `attestation.deferrable`, or none
 * in either). A record does not say what its writer expected, so the anchor
 * fill recomputes every record's status with the lease holder's expectation;
 * an instance whose own differs from the one the latest fill used raises the
 * `anchor_expectation_mismatch` alarm.
 */
export interface AnchoringConfig {
  /**
   * How old the header follower's finalized block may be for capture to copy
   * it into a decider's `freshness` under `'auto'` (Record §6.6), in
   * milliseconds. Default 30 minutes. An older reference is not written
   * (`null`), and a capture that requires one is refused.
   */
  freshnessMaxAgeMs?: number;
  publishers: {
    evm?: EvmPublisherConfig;
    /** Publish P to the configured timestamp authorities (Anchor §7.3, §10.6). Not built yet: refused. */
    rfc3161?: boolean;
  };
  cadence?: Partial<AnchorCadence>;
  budget?: Partial<AnchorBudget>;
  /** Required when rfc3161 is the only publisher and detection of a database owner's rewrite is claimed. Not built yet: refused. */
  mirror?: { sink: WriteOnceSink };
  /**
   * The activation guard. A store whose namespace is not a
   * `test.` namespace publishes production anchors. The first of them with an
   * `rfc3161/1` publication, or an `evm-calldata/1` publication on a chain
   * that tzun-anchor/1 §9 names `mainnet`, freezes the anchor format
   * (Specs §2); one published only on a test network such as Sepolia, or on
   * a chain §9 does not name, freezes nothing. Anchoring is refused for such
   * a store unless this is `true`, and so is a publisher that
   * `publisherManifest` lists in the `production` namespace, whatever the
   * store's namespace. The guard reads the origin and the publisher, not the
   * chain: it refuses on a test network as on a mainnet.
   */
  production?: boolean;
  /**
   * The publisher manifest your verifiers use (tzun-anchor/1 §9), for the
   * activation guard: a publisher address it lists in the `production`
   * namespace, for any origin, is a production publisher, and anchoring with
   * it is refused without `production: true`. That keeps a production key off
   * a `test.` store, where its publications would use up the production
   * wallet's nonces. Without a manifest only the namespace half of the guard
   * runs.
   */
  publisherManifest?: PublisherManifest;
  /**
   * Where the scanner's publisher-nonce accounting check starts accounting each
   * publisher wallet `publisherManifest` lists for this store's anchor
   * origin, keyed by CAIP-10 account (`eip155:<chain id>:0x…`, the address in
   * any case), when `Tzun.init()` also runs the scanner
   * (`monitoring.scanner`). A listed wallet absent here is accounted from
   * nonce 0: give the nonce it was enrolled at when it had sent transactions
   * before. It is the scanner's own input rather than the store's
   * `nonce_base`, because the store is what the scanner checks.
   */
  nonceBases?: Record<string, number>;
  /**
   * The store's namespace. `Tzun.init()` reads it as it reads
   * `TzunConfig.logNamespace`: a new store is minted with it, and a store in
   * another namespace is refused (`LogNamespaceMismatchError`); given with
   * `logNamespace`, the two must be equal. `Tzun.init()` refuses `anchoring`
   * with neither, before it opens the store, since an anchored store needs
   * its namespace chosen (a `test.` one, or your own with `production:
   * true`), never the default `local.invalid`. To `createAnchorScheduler` it
   * is a check against the store's identity, which it never changes.
   */
  namespace?: string;
  /**
   * `Tzun.init()` only: `false` leaves the scheduler unstarted, so passes run
   * only when `anchorNow()` is called. Default: `true`, a pass every minute.
   */
  autoStart?: boolean;
}

/** Configuration for Tzun.init(). */
export interface TzunConfig {
  /** Explicit mode override. */
  mode?: Mode;
  /** API key for cloud or self-hosted modes. */
  apiKey?: string;
  /** Custom API URL for self-hosted mode. */
  apiUrl?: string;
  /**
   * Per-request deadline for cloud capture POSTs, in milliseconds
   * (default: 10_000). `capture()` is awaited inside the vendor intercept, so
   * this is the ceiling on how long a wedged backend can hold the caller's own
   * request open. `0` disables the deadline (not recommended).
   */
  apiTimeoutMs?: number;
  /** AI system identifier (default: 'default'). */
  aiSystemId?: string;
  /** Schema version to use (default: 'v1.0'). */
  schemaVersion?: string;
  /**
   * How many times `capture()` will build a record and try to append it
   * before giving up with a `chain_conflict` failure (default: 10; must be an
   * integer >= 1).
   *
   * A capture reserves the next sequence number and links to the head it
   * knows, and both are hashed into the record, so the append is a
   * compare-and-swap: if another writer — a second replica of your service on
   * the same `DATABASE_URL`, a second `Tzun` instance on the same SQLite file,
   * a second client on the same cloud chain — has appended in the meantime,
   * the store refuses the record. The SDK then adopts the head the store
   * reported, rebuilds the record at the next position (re-attesting it, since
   * the digest changed) and tries again. Every attempt after the first means
   * some other writer made progress, so under N concurrent writers the
   * unluckiest capture can need up to N attempts in the worst case; raise this
   * if you run many replicas that capture in tight loops. `1` disables the
   * retry and surfaces the first refusal.
   *
   * One refusal is never retried, whatever this bound: a capture whose
   * `attestationInputs.webauthnAssertion` was supplied by the caller. That
   * assertion signed a challenge derived from the record's digest, and a
   * record rebuilt at another position has another digest, so the SDK
   * surfaces the conflict as a `chain_conflict` failure with
   * `retryRefused: 'caller_attestation_is_digest_bound'` rather than store a
   * signature that verifies `challenge_mismatch` against its own record.
   * Re-run the ceremony against the current head and capture again.
   */
  chainConflictMaxAttempts?: number;
  /**
   * The chain this instance writes evidence into.
   *
   * One chain per INSTANCE, many chains per STORE. Two instances on one SQLite
   * file or one `dbUrl`, each with its own `chainId`, interleave correctly:
   * each chain has its own head, its own sequence numbering from 1, and its own
   * append lock. That is the Python SDK's `chain_id` (`Tzun.init(chain_id=…)`),
   * and the cloud transport sends the same `chainId` with each capture request.
   *
   * Absent, the chain is resolved from the store — the one active
   * `ChainIdentity` row, or `'default'` on a store that has never forked. That
   * resolution refuses to guess: a store whose every chain is sealed throws
   * `NoActiveChainError`, and a store with several chains open for appends
   * throws `AmbiguousActiveChainError`. Naming a chain here is the answer to
   * both — with a chain named, there is nothing to resolve and nothing to
   * refuse. A chain named here that the store records as SEALED is still
   * refused at init, because a sealed chain accepts no records.
   *
   * It is not a tenancy boundary the evidence itself carries: `chainId` is
   * outside `EvidencePayload` and outside the v1.0 hashed field set, so the
   * digest does not commit to it. Per-tenant chains under one store are
   * isolated by the chain's own head and numbering, not cryptographically.
   */
  chainId?: string;
  /** PostgreSQL connection string (overrides storage selection regardless of mode). */
  dbUrl?: string;
  /** SQLite database file path for local mode (default: './tzun.db'). */
  dbPath?: string;
  /**
   * The namespace (`ns`) of the store's log origins (tzun-anchor/1 §4.3.2):
   * a lowercase DNS-style name, `local.invalid` by default. It is fixed when
   * the store's identity is minted, so it takes effect on a new store; on a
   * store that has one, a different value is refused
   * (`LogNamespaceMismatchError`). A store that will make a production anchor
   * needs its namespace chosen before it is created (the demo's is
   * `demo.tzun.ai`). A namespace beginning `test.` makes every origin of the
   * store a test origin: its anchors are trials and freeze nothing, on any
   * network (tzun-anchor/1 §2, Specs §2). Refused on the cloud transport,
   * whose logs are the platform's.
   */
  logNamespace?: string;
  /**
   * Anchor the store's records. Refused on the memory
   * adapter and on the cloud transport. Setting it makes `anchor` an
   * expectation for new records: a record is `pending` until the scheduler
   * fills its anchor. See {@link AnchoringConfig}.
   */
  anchoring?: AnchoringConfig;
  /**
   * INTERNAL TEST API — opt back IN to the `process.env.DATABASE_URL` fallback
   * when running under Jest. Outside of test mode this option is a no-op; the
   * env-var fallback is always honored.
   *
   * In test mode (`JEST_WORKER_ID` set) the SDK ignores `process.env.DATABASE_URL`
   * by default. Without this guard, setting `DATABASE_URL=...` for an
   * integration suite causes every unrelated test that calls `Tzun.init()` to
   * silently open a Postgres pool too, which (a) exhausts Postgres
   * `max_connections` and (b) breaks tests that expect fresh in-memory state
   * (e.g. capture-race expecting `sequenceNumber === 1`).
   *
   * Tests that specifically exercise the env-var-fallback wiring set this to
   * `true` to bypass the test-mode guard. Production code paths and any test
   * that explicitly passes `dbUrl` are unaffected.
   */
  _readDatabaseUrlEnv?: boolean;
  /**
   * INTERNAL TEST API — inject a custom `fetch` implementation for the cloud
   * HTTP transport (selected when `apiKey` is present). Tests pass a fake so
   * the cloud capture path can be exercised without a network. Production code
   * leaves this undefined and the transport uses the global `fetch`.
   */
  _httpFetchFn?: (url: string, init?: RequestInit) => Promise<Response>;
  /**
   * INTERNAL TEST API — the anchor scheduler's chain client (the SDK's
   * `EvmChainClient`), in place of JSON-RPC on
   * `anchoring.publishers.evm.rpcUrl`, so the wired scheduler can be driven
   * against an in-memory chain. Production code leaves this undefined.
   */
  _anchorChainClient?: unknown;
  /**
   * INTERNAL API — the storage extensions (the SDK's `StorageExtension`
   * objects, `src/storage/extensions.ts`) the store's adapter installs, in
   * place of the SDK's default list. A feature uses it to test its tables end
   * to end before it is registered by default.
   */
  _storageExtensions?: readonly unknown[];
  /**
   * INTERNAL API — the SDK extension factories (the SDK's
   * `SdkExtensionFactory`, `src/sdk/extension-points.ts`) `Tzun.init()`
   * installs, in place of the SDK's default list.
   */
  _sdkExtensions?: readonly unknown[];
  /** Attestation configuration (passed to AttestationOrchestrator). */
  attestation?: AttestationConfig;
  /** Monitoring subsystem configuration. */
  monitoring?: MonitoringConfig;
  /**
   * Whether local reads are verified (default: `true` on a local adapter —
   * memory, SQLite, Postgres). The one switch for read verification.
   *
   * On, the store is wrapped in the verifying proxy, and every `get()` and
   * `list()` returns each record with a `RecordVerdict`: the payload's digest
   * recomputed against the stored one, and the record's custody ledger rows
   * checked against its `custodyChain` mirror. A record that fails is still
   * returned, with an `invalid` verdict — a read is never blocked. With
   * `monitoring.enabled`, a failed digest check is also reported on the
   * monitoring bus as `digest_mismatch`. The cost is one canonical
   * serialization and SHA-256 of the payload, and one indexed read of the
   * record's `custody_entries` rows, per record read.
   *
   * `false` removes the proxy: reads return the records with a verdict whose
   * every check is `unmeasured` (`read_verification_off`), and nothing is
   * reported on the bus. `exportEvidence()` and `verify()` check the record
   * either way.
   *
   * Not available on the cloud transport (`apiKey`), which has no read path:
   * unset means off there, and `true` is refused at init.
   */
  verifyReads?: boolean;
  /**
   * Optional structured-log sink. When provided, SDK events
   * (descriptor registrations, connector auto-registrations) are forwarded
   * to this callback instead of the default console.log JSON line.
   *
   * Security contract: the SDK never passes auth material, tokens, or
   * `reason`/`aiOutput` payload content to this sink.
   */
  onLog?: (event: string, fields: Record<string, unknown>) => void;
  /**
   * Arm the demo tamper hooks on this Tzun instance.
   *
   * When `true`, the storage adapter's `deleteEnvelopeForDemo` and
   * `overwriteModelDescriptorBytesForDemo` methods are enabled — but only if
   * the store is recognised as a demo environment: it already holds the
   * sentinel, OR it is empty AND the adapter can demonstrate it is loopback-
   * local. Anything else — a non-empty unsentineled store, or an empty one
   * whose location the adapter cannot vouch for — refuses arming for the
   * process lifetime (DemoTamperGuardError from every hook call) and logs a
   * structured error.
   *
   * "Empty" alone is not enough: every production database is empty on its
   * first boot; see src/storage/demo-tamper-guard.ts.
   *
   * NEVER set this in production. DEMO/TEST environments only.
   */
  demoTamperHooks?: boolean;
}

/** Result returned from tzun.capture(). */
export interface CaptureResult {
  /**
   * The evidence envelope as the SDK assembled and SUBMITTED it.
   *
   * On local adapters this is byte-identical to what was stored, EXCEPT on a
   * replay ({@link CaptureResult.replayed}), where it is the record the first
   * capture under the key stored — read back from the store, because that is
   * the record that exists. On the cloud transport it is not necessarily the
   * stored record either: the backend re-stamps `partial` captures onto its own
   * locked chain head, which changes `sequenceNumber` (a hashed field) and
   * therefore the canonical digest and chain link, and a cloud replay has no
   * read path to fetch the original with. Read
   * {@link CaptureResult.serverReceipt} for what was actually recorded.
   */
  envelope: import('./evidence').EvidenceEnvelope;
  /** Whether the envelope was successfully stored. */
  stored: boolean;
  /** Failure record if storage failed. */
  failure?: import('./failure').FailureRecord;
  /**
   * `true` when this capture was answered by an earlier capture under the same
   * `CaptureOptions.idempotencyKey`: nothing was stored, and the result
   * describes the record that already existed. Absent on a fresh capture, so
   * `stored: true` alone does not tell the two apart and this field does.
   *
   * Locally, `envelope` is the original record read back from the store. On the
   * cloud transport it is the envelope THIS attempt built — the platform strips
   * its own replay flag from the single-capture response and the transport has
   * no read path — so {@link CaptureResult.serverReceipt} names the record that
   * exists and `envelope` is only the submitted form.
   */
  replayed?: boolean;
  /**
   * The authoritative stamp returned by a remote store, when there is one.
   *
   * Present only on the cloud (HTTP) transport. Absent on local adapters,
   * where `envelope` is already the stored record.
   *
   * This exists because the cloud receipt could otherwise be untrue: the first
   * capture of a process against a chain that already has records is stored by
   * the server at `headSeq + 1` with a recomputed digest and a real chain
   * link, while the local `envelope` still says sequence 1 / no link. Callers
   * that persist a receipt MUST prefer these fields.
   */
  serverReceipt?: RemoteCaptureReceipt;
  /**
   * Where the stored record sits in its chain's evidence log: the log's origin
   * and the record's leaf, `sequenceNumber − 1` (Tree §5.2). The store
   * wrote that leaf in the transaction that stored the record, so this is the
   * position every later checkpoint of the log commits the record to. On a
   * replay it is the original record's position.
   *
   * Present when the record is stored on a store with evidence logs (memory,
   * SQLite, Postgres). Absent on a failed capture, on the cloud transport,
   * whose logs are the platform's, and when reading the leaf back after the
   * store fails: the record is stored, and the failure is logged
   * (`capture_log_position_unread`).
   */
  logPosition?: import('./verification').RecordLogPosition;
  /**
   * A `decider.commit: true` capture: the opening of the `cmt:` identifier
   * the record carries, `{ salt, id }` (Record §6.3). The store keeps
   * it too (`tzun.deciders.opening(evidenceId)`).
   */
  deciderOpening?: import('./decider').DeciderOpening;
  /** A capture under a mandate: the mandate, the slot the record claimed, and the running totals including it. */
  mandate?: CaptureMandateSlot;
}

/** `CaptureResult.mandate`: what a capture under a mandate claimed. */
export interface CaptureMandateSlot {
  mandateId: string;
  /** The slot the record holds, 1-based. */
  slot: number;
  /** The running totals including this record, one per cap; `null` when the mandate has no cap. */
  totals: Record<string, number> | null;
}

/**
 * What a remote (server-authoritative) store recorded for a capture.
 *
 * `sequence` and `canonicalDigest` are the server's, not the client's; they
 * differ from the submitted envelope whenever the server re-stamped it.
 */
export interface RemoteCaptureReceipt {
  /** Evidence ID — preserved from the client's envelope. */
  evidenceId: string;
  /** Chain the record was appended to. */
  chainId: string;
  /** Sequence number the server assigned. */
  sequence: number;
  /** Canonical digest of the record as the server stored it. */
  canonicalDigest: string;
  /** The chain head after this append (equals `canonicalDigest`). */
  headDigest: string;
}

/** Options for listing evidence records. */
export interface ListOptions {
  /** Filter by AI system ID. */
  aiSystemId?: string;
  /** Maximum number of records to return. */
  limit?: number;
  /** Offset for pagination. */
  offset?: number;
  /**
   * Sort order (default: 'desc').
   *
   * Every adapter produces the same total order: by the UTC instant of
   * `payload.capturedAt` compared at millisecond precision (sub-millisecond
   * digits truncated), ties broken by `payload.sequenceNumber`, then by
   * `evidenceId`. `'desc'` is the exact reverse of `'asc'`. A `capturedAt`
   * that does not parse as an instant sorts first under 'asc' and last under
   * 'desc', as a NULL key would in SQL; Postgres refuses to store one. See
   * `src/storage/list-order.ts` in the SDK for the one definition.
   */
  order?: 'asc' | 'desc';
  /** Filter by chain ID. */
  chainId?: string;
}
