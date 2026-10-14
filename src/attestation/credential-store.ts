/**
 * Registered WebAuthn credentials: the key material a verifier needs in order
 * to say anything at all about a signature.
 *
 * WHY AN INTERFACE. A credential directory held only in memory loses every
 * registered passkey when its process restarts. The evidence records signed by
 * the vanished keys stay in the chain; the keys that would let anyone check
 * those signatures do not. `verifyAttestation` then reports
 * `signatureValid: null` / `no_credential_store` — honest, but "cannot check"
 * for every record ever captured. So the directory is an interface, with
 * durable implementations beside the in-memory one.
 *
 * There are three separate jobs here, each its own interface:
 *
 *   1. `CredentialLookup` — resolve a credential id to key material and
 *      status. This is all a VERIFIER needs, it is synchronous, and it is the
 *      surface `verifyAttestation()` and `ScheduledScanner` consume.
 *   2. `CredentialStore` — lookup plus the three writes a WebAuthn ceremony
 *      performs (register, revoke, bump the counter). Synchronous, because
 *      `TzunWebAuthn` is synchronous.
 *   3. `AsyncCredentialStore` — the durable, authoritative directory. Async,
 *      because a real one is a database or somebody else's IdP. The SDK reads
 *      it from its own storage adapter; `docs/design/credential-store.md`
 *      describes how a customer's own passkey directory plugs in.
 *
 * A verification pass bridges (3) to (1) with `store.snapshot()`: a
 * point-in-time read of the directory that the pass then uses for every record
 * it checks. Point-in-time on purpose — a scan of 10,000 records that re-reads
 * the directory per record can report two different verdicts for two records
 * signed by the same key because somebody revoked it mid-scan.
 *
 * Credentials are never deleted, only revoked. The durable backends in
 * `src/storage/credential-stores.ts` go further: registration and revocation
 * are rows in an append-only event log, so "this key was registered at T and
 * revoked at T+n" is itself a record an auditor can read, not a mutable
 * status column that only ever shows the latest answer.
 */

/** COSE algorithms the SDK verifies assertions for. */
export type CredentialAlgorithm = 'Ed25519' | 'ES256';

/** Whether a credential may still be used to sign. */
export type CredentialStatus = 'active' | 'revoked';

/**
 * A stored WebAuthn credential with its public key and status.
 *
 * `status` is the credential's status NOW. It is deliberately NOT the answer
 * to "was this credential usable when it signed record R" — see
 * `credentialStatusAt()`, which is.
 */
export interface StoredCredential {
  credentialId: string;
  publicKey: string;
  userId: string;
  algorithm: CredentialAlgorithm;
  counter: number;
  status: CredentialStatus;
  /** ISO-8601 UTC instant the credential was registered. */
  registeredAt: string;
  /**
   * ISO-8601 UTC instant the credential was revoked. Absent while active.
   *
   * Present so that revocation can be applied AS OF a moment rather than
   * retroactively: a key revoked in March does not make a signature it
   * produced in January invalid, any more than a cancelled passport
   * invalidates the visa stamps it collected while it was valid.
   */
  revokedAt?: string;
  /** Free-text reason recorded with the revocation, if one was given. */
  revocationReason?: string;
  /**
   * ISO-8601 UTC instant at which this credential's signature counter was
   * observed to go BACKWARDS. In WebAuthn a counter that does not increase is
   * the authenticator-cloning signal; it is recorded rather than thrown away
   * so a verifier can surface it. Absent means never observed.
   */
  counterRegressedAt?: string;
}

/** Options for `revoke()`. */
export interface RevocationOptions {
  /**
   * When the revocation took effect, ISO-8601 UTC. Defaults to now.
   * Supplying it matters: a key reported stolen on the 3rd but processed on
   * the 9th was not trustworthy on the 4th.
   */
  revokedAt?: string;
  /** Why. Recorded verbatim in the event log. */
  reason?: string;
}

/**
 * One immutable fact about a credential.
 *
 * The durable backends store these and derive `StoredCredential` by folding
 * them; the fold is the only place credential state is computed, so all three
 * backends agree by construction.
 */
export interface CredentialEvent {
  /** Unique id for the event row. */
  eventId: string;
  credentialId: string;
  type: 'registered' | 'revoked' | 'counter_regressed';
  /** ISO-8601 UTC instant the fact is asserted to have happened. */
  occurredAt: string;
  /** ISO-8601 UTC instant this store wrote the row. */
  recordedAt: string;
  /** `registered` only. */
  userId?: string;
  /** `registered` only. */
  publicKey?: string;
  /** `registered` only. */
  algorithm?: CredentialAlgorithm;
  /** `revoked` only. */
  reason?: string;
}

/**
 * What a VERIFIER needs: resolve a credential id to key material and status.
 *
 * Named for the verifier rather than for the database because the verifier is
 * the consumer that matters — it is the reason any of this is stored.
 */
export interface CredentialLookup {
  /** The credential with this id, or `undefined` if it was never registered. */
  getByCredentialId(credentialId: string): StoredCredential | undefined;
  /** Every credential registered to this user, revoked ones included. */
  getByUserId(userId: string): StoredCredential[];
}

/**
 * The synchronous store contract: lookup plus the writes a WebAuthn ceremony
 * performs.
 *
 * `TzunWebAuthn`, `verifyAttestation()` and `ScheduledScanner` are all typed
 * against this, so any implementation — the in-memory one below, a snapshot of
 * a durable directory, or an integrator's own — drops in without a fork.
 */
export interface CredentialStore extends CredentialLookup {
  /** @throws if a credential with the same id is already registered. */
  register(credential: StoredCredential): void;
  /** @throws if the credential is not found. */
  revoke(credentialId: string, options?: RevocationOptions): void;
  /** @throws if the credential is not found. */
  updateCounter(credentialId: string, newCounter: number): void;
}

/**
 * The durable, authoritative credential directory.
 *
 * The SDK ships three implementations of it (memory, SQLite, Postgres) in
 * `src/storage/credential-stores.ts`, one per storage adapter, and reads the
 * one behind its own storage (`tzun.getCredentialStore()`). The package root
 * does not export this interface: a customer who already runs an IdP or a
 * passkey directory implements the synchronous `CredentialStore` over a
 * point-in-time read of it and passes that to `verify()`, `ScheduledScanner`
 * or `TzunWebAuthn` (see `docs/design/credential-store.md`).
 */
export interface AsyncCredentialStore {
  /** @throws {CredentialAlreadyRegisteredError} */
  register(credential: StoredCredential): Promise<void>;
  getByCredentialId(credentialId: string): Promise<StoredCredential | undefined>;
  getByUserId(userId: string): Promise<StoredCredential[]>;
  /** @throws {CredentialNotFoundError} */
  revoke(credentialId: string, options?: RevocationOptions): Promise<void>;
  /** @throws {CredentialNotFoundError} */
  updateCounter(credentialId: string, newCounter: number): Promise<void>;
  /** Every credential ever registered, revoked ones included, oldest first. */
  list(): Promise<StoredCredential[]>;
  /**
   * The append-only event log, oldest first. What an auditor reads, and what
   * an export bundle carries when it carries credentials at all.
   */
  history(credentialId?: string): Promise<CredentialEvent[]>;
  /**
   * A point-in-time synchronous view for one verification pass.
   *
   * Pass the credential ids the pass will ask about to read only those; pass
   * nothing to snapshot the whole directory.
   */
  snapshot(credentialIds?: readonly string[]): Promise<CredentialStore>;
}

/** A second `register()` for a credential id that already exists. */
export class CredentialAlreadyRegisteredError extends Error {
  readonly code = 'credential_already_registered' as const;

  constructor(public readonly credentialId: string, options?: { cause?: unknown }) {
    super(`Credential "${credentialId}" is already registered.`);
    this.name = 'CredentialAlreadyRegisteredError';
    if (options?.cause !== undefined) (this as { cause?: unknown }).cause = options.cause;
    Object.setPrototypeOf(this, CredentialAlreadyRegisteredError.prototype);
  }
}

/** A `revoke()` / `updateCounter()` naming a credential that is not there. */
export class CredentialNotFoundError extends Error {
  readonly code = 'credential_not_found' as const;

  constructor(public readonly credentialId: string, options?: { cause?: unknown }) {
    super(`Credential "${credentialId}" not found.`);
    this.name = 'CredentialNotFoundError';
    if (options?.cause !== undefined) (this as { cause?: unknown }).cause = options.cause;
    Object.setPrototypeOf(this, CredentialNotFoundError.prototype);
  }
}

/**
 * A registration or revocation carrying an instant nothing can parse.
 *
 * Refused on every backend, at the same point, with the same message. Postgres
 * would reject it anyway — `occurred_at` is TIMESTAMPTZ — while the memory and
 * SQLite backends would store the string happily, so without this guard a
 * store that worked in dev would throw in production: the backends would
 * disagree on one input, which is exactly what an adapter must never do.
 */
export class InvalidCredentialInstantError extends Error {
  readonly code = 'invalid_credential_instant' as const;

  constructor(
    public readonly field: string,
    public readonly value: string
  ) {
    super(
      `Credential ${field} "${value}" is not a parseable instant. ` +
        'Use an ISO-8601 UTC string, e.g. "2026-03-22T10:00:00.000Z".'
    );
    this.name = 'InvalidCredentialInstantError';
    Object.setPrototypeOf(this, InvalidCredentialInstantError.prototype);
  }
}

/**
 * Refuse an instant no backend could store consistently.
 *
 * @throws {InvalidCredentialInstantError}
 */
export function assertCredentialInstant(field: string, value: string): void {
  if (Number.isNaN(Date.parse(value))) {
    throw new InvalidCredentialInstantError(field, value);
  }
}

/** A write against a read-only verification snapshot. */
export class CredentialSnapshotReadOnlyError extends Error {
  readonly code = 'credential_snapshot_read_only' as const;

  constructor(operation: string) {
    super(
      `Cannot ${operation} on a credential snapshot. A snapshot is a ` +
        'point-in-time read for one verification pass; write to the durable ' +
        'credential store instead, then take a new snapshot.'
    );
    this.name = 'CredentialSnapshotReadOnlyError';
    Object.setPrototypeOf(this, CredentialSnapshotReadOnlyError.prototype);
  }
}

/**
 * Was this credential usable at instant `at`?
 *
 * This is the function a verifier wants and `StoredCredential.status` is not.
 * `status` answers "is this key usable NOW", which is the right question for a
 * login and the wrong one for evidence: evidence is checked years after it was
 * signed, by which time every key involved may well have been rotated out. A
 * verifier that consults `status` reports every record signed by a since-
 * revoked key as forged, which is a false accusation, and it reports them as
 * forged RETROACTIVELY — the verdict on a record changes because of something
 * that happened after it was captured.
 *
 * Returns `'not_yet_registered'` for an instant before the key existed, which
 * is the genuinely suspicious case: a signature that predates its own key.
 */
export function credentialStatusAt(
  credential: StoredCredential,
  at: string | number | Date
): CredentialStatus | 'not_yet_registered' {
  const t = instantMs(at);
  const registered = instantMs(credential.registeredAt);
  // An unparseable instant on either side cannot support a judgement. Fall
  // back to the credential's current status rather than inventing one.
  if (t === null || registered === null) return credential.status;
  if (t < registered) return 'not_yet_registered';
  if (credential.revokedAt !== undefined) {
    const revoked = instantMs(credential.revokedAt);
    if (revoked !== null && t >= revoked) return 'revoked';
    if (revoked === null) return credential.status;
    return 'active';
  }
  return credential.status === 'revoked' ? 'revoked' : 'active';
}

function instantMs(value: string | number | Date): number | null {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value.getTime();
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * Fold an append-only credential event log into current credential state.
 *
 * The ONE place credential state is computed. All three durable backends call
 * it on rows read in insertion order, so "what does the store say about this
 * credential" cannot diverge between memory, SQLite and Postgres — the kind
 * of divergence between storage adapters the conformance suite exists to stop.
 *
 * Rules, in the order they matter:
 *   - the FIRST `registered` event fixes identity. Key material is immutable;
 *     rotation is a NEW credential id, never a rewrite of this one.
 *   - the FIRST `revoked` event fixes `revokedAt`. Revoking twice does not
 *     move the effective date earlier or later.
 *   - `counter_regressed` records the clone signal; it never changes status.
 *   - an event naming a credential with no registration is ignored, because
 *     there is no key for it to be about.
 */
export function foldCredentialEvents(
  events: readonly CredentialEvent[],
  counters: ReadonlyMap<string, number> = new Map()
): StoredCredential[] {
  const byId = new Map<string, StoredCredential>();
  for (const ev of events) {
    if (ev.type === 'registered') {
      if (byId.has(ev.credentialId)) continue;
      byId.set(ev.credentialId, {
        credentialId: ev.credentialId,
        publicKey: ev.publicKey ?? '',
        userId: ev.userId ?? '',
        algorithm: (ev.algorithm ?? 'ES256') as CredentialAlgorithm,
        counter: 0,
        status: 'active',
        registeredAt: ev.occurredAt,
      });
      continue;
    }
    const cred = byId.get(ev.credentialId);
    if (!cred) continue;
    if (ev.type === 'revoked') {
      if (cred.revokedAt !== undefined) continue;
      cred.status = 'revoked';
      cred.revokedAt = ev.occurredAt;
      if (ev.reason !== undefined) cred.revocationReason = ev.reason;
    } else if (ev.type === 'counter_regressed') {
      cred.counterRegressedAt = ev.occurredAt;
    }
  }
  for (const cred of byId.values()) {
    const c = counters.get(cred.credentialId);
    if (c !== undefined) cred.counter = c;
  }
  return [...byId.values()];
}

/** Detach a credential from every reference the caller or the store holds. */
function clone(cred: StoredCredential): StoredCredential {
  return { ...cred };
}

/**
 * In-memory credential store.
 *
 * The reference implementation of `CredentialStore` and a faithful double for
 * the durable ones: same errors, same ordering, detached copies in and out.
 * Everything it holds is lost when the process exits — which is exactly the
 * failure this release is about, so do not use it as the production store.
 */
export class InMemoryCredentialStore implements CredentialStore {
  private credentials: Map<string, StoredCredential> = new Map();

  /**
   * Register a new credential.
   *
   * @throws {CredentialAlreadyRegisteredError} if the id is already registered
   */
  register(credential: StoredCredential): void {
    assertCredentialInstant('registeredAt', credential.registeredAt);
    if (this.credentials.has(credential.credentialId)) {
      throw new CredentialAlreadyRegisteredError(credential.credentialId);
    }
    this.credentials.set(credential.credentialId, clone(credential));
  }

  /** Retrieve a credential by its ID. */
  getByCredentialId(credentialId: string): StoredCredential | undefined {
    const cred = this.credentials.get(credentialId);
    return cred ? clone(cred) : undefined;
  }

  /** Retrieve all credentials for a user, in registration order. */
  getByUserId(userId: string): StoredCredential[] {
    const results: StoredCredential[] = [];
    for (const cred of this.credentials.values()) {
      if (cred.userId === userId) results.push(clone(cred));
    }
    return results;
  }

  /**
   * Revoke a credential. The credential remains in the store with status
   * 'revoked' — it is never deleted — and the instant of revocation is
   * recorded so `credentialStatusAt()` can answer as-of questions.
   *
   * @throws {CredentialNotFoundError} if the credential is not found
   */
  revoke(credentialId: string, options: RevocationOptions = {}): void {
    if (options.revokedAt !== undefined) assertCredentialInstant('revokedAt', options.revokedAt);
    const cred = this.credentials.get(credentialId);
    if (!cred) throw new CredentialNotFoundError(credentialId);
    if (cred.revokedAt !== undefined) return; // first revocation wins
    cred.status = 'revoked';
    cred.revokedAt = options.revokedAt ?? new Date().toISOString();
    if (options.reason !== undefined) cred.revocationReason = options.reason;
  }

  /**
   * Update the counter for replay-attack prevention.
   *
   * The counter is monotonic. A new value BELOW the stored one is the WebAuthn
   * authenticator-cloning signal. Assigning it would leave the store holding
   * the lower value, so the very next assertion from the genuine authenticator
   * would look like an increase and the signal would be gone by the time
   * anybody could look for it. The high-water mark is kept and the regression
   * is recorded on the credential instead.
   *
   * @throws {CredentialNotFoundError} if the credential is not found
   */
  updateCounter(credentialId: string, newCounter: number): void {
    const cred = this.credentials.get(credentialId);
    if (!cred) throw new CredentialNotFoundError(credentialId);
    if (newCounter < cred.counter) {
      cred.counterRegressedAt = new Date().toISOString();
      return;
    }
    cred.counter = newCounter;
  }
}

/**
 * A point-in-time read of a durable credential directory, for one
 * verification pass.
 *
 * Implements the full `CredentialStore` because that is what
 * `verifyAttestation()` and `ScheduledScanner` are typed against, but the
 * three writes throw: a verifier does not register keys, and a write that
 * lands in a detached copy and is then discarded is precisely the failure this
 * release exists to remove.
 */
export class CredentialSnapshot implements CredentialStore {
  private readonly credentials: Map<string, StoredCredential>;
  /** The instant the snapshot was taken, ISO-8601 UTC. */
  readonly takenAt: string;

  constructor(credentials: readonly StoredCredential[], takenAt: string = new Date().toISOString()) {
    this.credentials = new Map(credentials.map((c) => [c.credentialId, clone(c)]));
    this.takenAt = takenAt;
  }

  getByCredentialId(credentialId: string): StoredCredential | undefined {
    const cred = this.credentials.get(credentialId);
    return cred ? clone(cred) : undefined;
  }

  getByUserId(userId: string): StoredCredential[] {
    const out: StoredCredential[] = [];
    for (const cred of this.credentials.values()) {
      if (cred.userId === userId) out.push(clone(cred));
    }
    return out;
  }

  register(): never {
    throw new CredentialSnapshotReadOnlyError('register a credential');
  }

  revoke(): never {
    throw new CredentialSnapshotReadOnlyError('revoke a credential');
  }

  updateCounter(): never {
    throw new CredentialSnapshotReadOnlyError('update a credential counter');
  }
}

/**
 * Back-compat alias.
 *
 * `CredentialStore` denotes the interface in type position and this
 * constructor in value position, so `new CredentialStore()` builds an
 * in-memory store (as `TzunWebAuthn` does by default). New code should say
 * `InMemoryCredentialStore` when it means the in-memory one, and
 * `CredentialStore` when it means "any store".
 *
 * @deprecated Use `InMemoryCredentialStore` for the constructor.
 */
export const CredentialStore = InMemoryCredentialStore;
