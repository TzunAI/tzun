/**
 * Errors raised by the evidence core and by storage adapters implementing it.
 */

import type { ChainHead } from './types/storage-interface';
import type { ChainIdentity } from './types/recovery';

export type { ChainHead };

/**
 * A conditional append was refused because the chain head moved.
 *
 * `Tzun.capture()` reserves a sequence number and computes a chain link from
 * the head it read, then hashes both into the record — `sequenceNumber` is in
 * the v1.0 hashed field set, so it cannot be assigned after the digest exists.
 * That makes the append a compare-and-swap: if the head is no longer what it
 * was when the record was built, the record does not belong at that position
 * and MUST NOT be written. Writing it anyway is what produced two records at
 * the same sequence, both linking to the same predecessor, both reported
 * `stored: true` — after which every verifier reports chain breaks on evidence
 * nobody tampered with, and real tampering becomes indistinguishable from load.
 *
 * A refused append is a *transient* answer, not a broken store: the record was
 * built against a head that has since moved, and the same input rebuilt
 * against the head this error carries in `actual` will (absent further
 * contention) be accepted. That is what a compare-and-swap is for, and it is
 * why `retryable` is `true` — the same `{ code, retryable }` discriminator
 * shape the cloud transport's `TzunCaptureError` carries, so a caller can tell
 * "the head moved under me" from "the database is broken" by the same two
 * fields on either path. `Tzun.capture()` performs that rebuild-and-retry
 * itself (bounded by `TzunConfig.chainConflictMaxAttempts`) and only surfaces
 * this error once the bound is exhausted.
 */
export class ChainConflictError extends Error {
  /** Stable discriminator for callers that branch on the cause. */
  readonly code = 'chain_conflict' as const;
  /**
   * Always `true`: rebuilding the record against `actual` and appending again
   * is the correct response to a moved head. Compare `TzunCaptureError`, where
   * `retryable` describes a *same-request* retry and is therefore `false` for
   * a 409 — the two flags answer different questions, and this one answers
   * "is re-capturing this decision worth attempting?".
   */
  readonly retryable = true as const;
  /** The head the caller built its record against. */
  readonly expected: ChainHead;
  /** The head the store actually holds. */
  readonly actual: ChainHead;

  constructor(expected: ChainHead, actual: ChainHead) {
    super(
      'Chain conflict: the chain head moved between building this record and ' +
        `storing it. Expected head sequence ${expected.sequence} ` +
        `digest ${expected.digest ?? '(none)'}, but the store holds sequence ` +
        `${actual.sequence} digest ${actual.digest ?? '(none)'}. The record was ` +
        'NOT stored — its sequence number and chain link are baked into its ' +
        'digest and would duplicate or orphan an existing record.',
    );
    this.name = 'ChainConflictError';
    this.expected = expected;
    this.actual = actual;
    // Restore prototype chain for `instanceof` across the ts-jest/CJS boundary.
    Object.setPrototypeOf(this, ChainConflictError.prototype);
  }
}

/**
 * The store has chain identity rows and none of them is active.
 *
 * `StorageAdapter.getActiveChainId()` is the only place the SDK decides which
 * chain `Tzun.capture()` appends to. Answering this state with `'default'` —
 * the fallback for a store that has never registered a chain at all — would,
 * on a store whose every chain had been sealed, adopt the sealed `default`
 * chain: `Tzun.init()` would come up reporting it as active and the next
 * capture would be aimed at the id space of a chain that cannot accept
 * records.
 *
 * A store cannot reach this state through `recovery.fork()`, which seals the
 * old chain and registers the new one in the same operation and so always
 * leaves exactly one active row. It means a row was sealed or inserted
 * directly — `StorageAdapter.sealChain()` / `storeChain()` are public — or the
 * `chains` table was edited. The SDK does not pick a chain for the operator
 * in that state: it names the rows and refuses. `chains` carries every row so
 * the caller can decide which one should be live.
 */
export class NoActiveChainError extends Error {
  /** Stable discriminator for callers that branch on the cause. */
  readonly code = 'no_active_chain' as const;
  /** Every chain identity row in the store, in `listChains()` order. */
  readonly chains: ChainIdentity[];

  constructor(chains: ChainIdentity[]) {
    super(
      `No active chain: every chain row in this store is sealed (${describeChains(chains)}). ` +
        'A sealed chain cannot accept records, and this SDK does not pick a chain for you. ' +
        'recovery.fork() never produces this state (it seals the old chain and registers the ' +
        'new one together); a row was sealed or written directly through ' +
        'StorageAdapter.sealChain() / storeChain() or the chains table. Either name the chain ' +
        'this instance writes to with Tzun.init({ chainId }) — any chain the store does not ' +
        'record as sealed, including one it has no row for, which numbers its records from 1 — ' +
        'or make exactly one chain active and initialise again: storeChain() a new active ' +
        'identity for the chain that should continue, or re-open the row that should still be ' +
        'live. A seal cannot be lifted with a plain UPDATE — the chains trigger refuses it on ' +
        'SQLite and Postgres — so re-opening a row is a change made as the store\'s owner: on ' +
        'SQLite, drop the chains_enforce_immutable trigger, update the row and re-create the ' +
        'trigger in one transaction (the adapter also re-creates it on its next open); on ' +
        "Postgres, run the UPDATE under SET LOCAL session_replication_role = 'replica'.",
    );
    this.name = 'NoActiveChainError';
    this.chains = chains;
    Object.setPrototypeOf(this, NoActiveChainError.prototype);
  }
}

/**
 * The store has more than one active chain identity row.
 *
 * Nothing in the store enforces a single active chain: `storeChain()` inserts
 * whatever status it is given. Resolving this by recency — `ORDER BY
 * created_at DESC LIMIT 1` — would send every capture from the next
 * `Tzun.init()` on to whichever row had been created last, with no warning;
 * the first record on that chain would take the OTHER chain's next sequence
 * number and link from the other chain's head: born unverifiable, and with
 * monitoring on, raising a `sequence_gap` incident on evidence nobody had
 * touched.
 *
 * A store with several active chains is either one written per chain (each
 * instance names its chain with `Tzun.init({ chainId })`, so `init()` does not
 * have to discover one) or a mistake; either way the chain has to be chosen,
 * not discovered, so this refuses and names the rows.
 */
export class AmbiguousActiveChainError extends Error {
  /** Stable discriminator for callers that branch on the cause. */
  readonly code = 'ambiguous_active_chain' as const;
  /** Every chain identity row in the store, in `listChains()` order. */
  readonly chains: ChainIdentity[];
  /**
   * Chains that hold records but have no identity row — `'default'` before a
   * fork materialises it, or any id handed to `store()`. Open to appends
   * exactly like an active row, and counted here for that reason.
   */
  readonly implicitChainIds: string[];
  /**
   * Every chain that accepts appends — the active rows and the implicit
   * chains — the ones the caller must choose between.
   */
  readonly activeChainIds: string[];

  constructor(chains: ChainIdentity[], implicitChainIds: string[] = []) {
    const activeRows = chains.filter((c) => c.status === 'active').map((c) => c.chainId);
    const candidates = [
      ...activeRows.map((id) => `${id} (row: active)`),
      ...implicitChainIds.map((id) => `${id} (no identity row, holds records)`),
    ];
    super(
      `Ambiguous active chain: ${candidates.length} chains accept appends (${candidates.join(', ')}) ` +
        'and this SDK instance appends to exactly one chain' +
        (chains.length > 0 ? ` (identity rows: ${describeChains(chains)})` : '') +
        '. This SDK does not pick one for you. Name the chain this instance writes to — ' +
        'Tzun.init({ chainId }), one chain per instance and as many instances as chains, each ' +
        'chain with its own head and its own numbering from 1 — or leave exactly one chain ' +
        'open: seal the rows that should not take appends (StorageAdapter.sealChain()), and ' +
        'register-then-seal an identity for an implicit chain that is finished, then ' +
        'initialise again.',
    );
    this.name = 'AmbiguousActiveChainError';
    this.chains = chains;
    this.implicitChainIds = implicitChainIds;
    this.activeChainIds = [...activeRows, ...implicitChainIds];
    Object.setPrototypeOf(this, AmbiguousActiveChainError.prototype);
  }
}

/**
 * An append was refused because its chain is sealed.
 *
 * A fork seals the chain it was taken from; from then on that chain is the
 * read-only remainder of the fork and new records go to the chain the fork
 * created. `code` is the hosted service's code for the same refusal (its
 * `ChainSealedError`), so a local capture and a cloud capture refused for this
 * reason report the same code. `retryable` is `false`: the chain does not
 * reopen, so the same append will be refused every time.
 */
export class ChainSealedError extends Error {
  /** Stable discriminator for callers that branch on the cause. */
  readonly code = 'chain_sealed' as const;
  /** Always `false`: a sealed chain never accepts the append. */
  readonly retryable = false as const;
  /** The sealed chain the append was aimed at. */
  readonly chainId: string;
  /** When the chain was sealed, when the store records it. */
  readonly sealedAt: string | null;

  constructor(chainId: string, sealedAt: string | null = null, options?: { cause?: unknown }) {
    super(
      `Chain "${chainId}" is sealed and cannot accept new records. A sealed chain is ` +
        'the read-only remainder of a fork; append to the chain the fork created instead.',
    );
    this.name = 'ChainSealedError';
    this.chainId = chainId;
    this.sealedAt = sealedAt;
    if (options?.cause !== undefined) (this as { cause?: unknown }).cause = options.cause;
    Object.setPrototypeOf(this, ChainSealedError.prototype);
  }
}

/**
 * A keyed capture was refused because its idempotency key already names a
 * record that was captured from different input.
 *
 * `code` is the hosted service's code for the same refusal (it answers it
 * 422 `idempotency_conflict`), so a local capture and a cloud capture refused
 * for this reason report the same code. `retryable` is `false`: a key names one
 * record for the life of the store — the platform never expires a key and
 * neither do the local adapters — so resubmitting the same input under the same
 * key is refused every time. The caller either resubmits the original input
 * (which replays) or chooses a new key for the new decision.
 *
 * `conflictReason` says which of the platform's two cases this is:
 *
 *   - `fingerprint_mismatch`   the key is held, and the input behind it is not
 *                             this input.
 *   - `missing_replay_target`  the key is held and the fingerprint matches, but
 *                             the record it names is no longer in the store, so
 *                             there is nothing to replay. The platform refuses
 *                             this rather than capturing a second record under
 *                             a key that already answered once.
 */
export class IdempotencyConflictError extends Error {
  /** Stable discriminator for callers that branch on the cause. */
  readonly code = 'idempotency_conflict' as const;
  /** Always `false`: the key keeps naming the record it named. */
  readonly retryable = false as const;
  /** The key the capture was made under. */
  readonly idempotencyKey: string;
  /** Which of the two conflict cases this is. */
  readonly conflictReason: IdempotencyConflictReason;

  constructor(
    idempotencyKey: string,
    conflictReason: IdempotencyConflictReason = 'fingerprint_mismatch',
  ) {
    super(
      conflictReason === 'missing_replay_target'
        ? `Idempotency conflict: key "${idempotencyKey}" names a record the store no longer ` +
            'holds, so there is nothing to replay. Nothing was stored. Capture this decision ' +
            'under a new key.'
        : `Idempotency conflict: key "${idempotencyKey}" already names a record captured from ` +
            'different input. Nothing was stored. Resubmit the original input to replay the ' +
            'first capture, or capture this decision under a new key.',
    );
    this.name = 'IdempotencyConflictError';
    this.idempotencyKey = idempotencyKey;
    this.conflictReason = conflictReason;
    Object.setPrototypeOf(this, IdempotencyConflictError.prototype);
  }
}

/** Which of the two idempotency-conflict cases a refusal is. */
export type IdempotencyConflictReason = 'fingerprint_mismatch' | 'missing_replay_target';

function describeChains(chains: ChainIdentity[]): string {
  return chains
    .map((c) => `${c.chainId}: ${c.status}${c.sealedAt ? ` since ${c.sealedAt}` : ''}`)
    .join('; ');
}

/**
 * A pagination bound — `ListOptions.limit` or `ListOptions.offset`, or the
 * `limit` of `listByAttestationStatus` — that is not a safe non-negative
 * integer.
 *
 * The bound is part of the `StorageAdapter` contract, and every adapter
 * refuses the same values with this error: strings (including numeric-looking
 * ones), NaN, Infinity, negatives and fractions. `ListOptions.limit` is typed
 * `number`, but a JavaScript caller writing `list({ limit: req.query.limit })`
 * hands over a string, and a store that interpolates LIMIT would run it as SQL.
 * An HTTP layer maps it to a 400.
 */
export class InvalidPaginationError extends Error {
  /** Stable discriminator for callers that branch on the cause. */
  readonly code = 'invalid_pagination' as const;

  constructor(
    /** The bound that was refused: `'limit'` or `'offset'`. */
    public readonly field: string,
    /** The value the caller passed. */
    public readonly received: unknown,
  ) {
    super(
      `Invalid ${field}: expected a non-negative integer, received ` +
        `${typeof received === 'string' ? JSON.stringify(received) : String(received)}.`,
    );
    this.name = 'InvalidPaginationError';
  }
}

/**
 * The store holds records an earlier release captured under an earlier v1.0
 * hashed field set, and this release cannot verify them (Record §4.1).
 *
 * The v1.0 hashed field set was revised in place twice while v1.0 was a draft:
 * 0.7.0 added `signoffExpectation` (Record §9.1), and 0.8.0 renamed
 * `humanAction` and `humanReason`, added `decider`, `contributions` and
 * `links`, and moved `aiBom` into the contribution steps. A record captured
 * under an earlier set has a digest over that set, so every check this release
 * runs would report it tampered. Opening the store is refused instead, before
 * anything is captured into it: create a new store (a new `dbPath`, or a new
 * Postgres database) and capture into that. The old store is left as it was,
 * and the release that wrote it still verifies it.
 *
 * `Tzun.init()` recognises such a store by its first record, whose stored
 * digest recomputes under an earlier set (`recordFieldSetGeneration`). A
 * record that was altered recomputes under no set, so it is not mistaken for
 * an old one; the verifiers report it.
 */
export class StoreSchemaOutdatedError extends Error {
  /** Stable discriminator for callers that branch on the cause. */
  readonly code = 'store_schema_outdated' as const;
  /** Opening the same store again is refused again: the remedy is a new store. */
  readonly retryable = false as const;

  constructor(
    /** The record the store was recognised by. */
    public readonly evidenceId: string,
    /** The field set that record's digest recomputes under. */
    public readonly generation: '0.7' | 'before-0.7' = 'before-0.7',
  ) {
    super(
      `This store was written by a Tzun SDK release ${generation === '0.7' ? 'of the 0.7 line' : 'before 0.7.0'} ` +
        `(record ${evidenceId}), under an earlier v1.0 hashed field set, so every record in it would verify ` +
        'as tampered. Create a new store — a new dbPath, or a new Postgres database — and capture into that. ' +
        'The old store is unchanged, and the release that wrote it still verifies it.',
    );
    this.name = 'StoreSchemaOutdatedError';
  }
}
