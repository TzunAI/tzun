// src/storage/chain-head-guard.ts
//
// The one place that decides whether a conditional chain append may proceed.
//
// Every adapter must apply this INSIDE whatever makes its write atomic — the
// memory adapter's synchronous section, SQLite's IMMEDIATE transaction, the
// Postgres transaction holding the chain advisory lock. Checking outside that
// boundary reintroduces exactly the read-modify-write race it exists to close.
import { ChainConflictError, ChainSealedError, type ChainHead } from '@tzun/engine';

/**
 * Throw {@link ChainConflictError} unless the live head is the one the caller
 * built its record against.
 *
 * A no-op when `expected` is undefined: `store()` stays usable as a low-level
 * primitive for writes that are not chain appends.
 *
 * `''` is normalised to `null` because the SQL adapters keep `last_digest` as a
 * `NOT NULL` column and use the empty string for "no head yet".
 */
export function assertChainHead(
  expected: ChainHead | undefined,
  actual: ChainHead,
): void {
  if (!expected) return;

  const actualDigest = actual.digest === '' ? null : actual.digest;
  const expectedDigest = expected.digest === '' ? null : expected.digest;

  if (expected.sequence !== actual.sequence || expectedDigest !== actualDigest) {
    throw new ChainConflictError(
      { sequence: expected.sequence, digest: expectedDigest },
      { sequence: actual.sequence, digest: actualDigest },
    );
  }
}

/**
 * Throw {@link ChainSealedError} unless the target chain is open for appends.
 *
 * Without this check on the write path, `sealChain()` would be a label and
 * nothing more: after `recovery.fork()` an insider — or a stale client still
 * holding the old chain id — could keep appending to the chain the operator
 * had just been told was closed, and those records would be invisible to
 * anyone reading the fork record, which reports the chain as sealed at a fixed
 * length.
 *
 * A chain with no identity row is deliberately NOT rejected. Chain identities
 * are created lazily — the shipped default path has none until the first fork —
 * so refusing writes to an unknown chain would break every store that has never
 * forked. Only an explicit `'sealed'` status closes the door.
 *
 * Like {@link assertChainHead}, this must be applied inside whatever makes the
 * adapter's write atomic, so a seal that lands mid-write cannot be stepped over.
 *
 * The status it reads is guarded where it is stored: on SQLite and Postgres
 * the `chains` triggers refuse to lift or re-date a seal and refuse to delete
 * a chain row, so the column cannot be flipped back to open behind this check.
 *
 * The refusal is the engine's typed {@link ChainSealedError} (`code:
 * 'chain_sealed'`), carrying the chain id and the `sealedAt` the store
 * records, so a caller branches on the code, never on the message.
 */
export function assertChainNotSealed(
  chainId: string,
  status: string | undefined | null,
  sealedAt?: string | null,
): void {
  if (status === 'sealed') {
    throw new ChainSealedError(chainId, sealedAt ?? null);
  }
}

/**
 * `resetChainState(chainId)` refused: the chain's evidence log holds leaves.
 * The log is dense and written once, so a chain whose log has a leaf keeps its
 * sequence state; clearing it would let the next record take a position whose
 * leaf is already held. The SQL adapters refuse it with a trigger on
 * `chain_state` as well, so a direct `DELETE` or a lowering `UPDATE` is refused
 * too.
 */
export class ChainStateResetRefusedError extends Error {
  readonly code = 'chain_state_reset_refused' as const;
  readonly retryable = false as const;

  constructor(public readonly chainId: string, options?: { cause?: unknown }) {
    super(
      `The state of chain ${JSON.stringify(chainId)} cannot be reset: its evidence log holds leaves, ` +
        `and a chain whose log has a leaf keeps its sequence state.`,
    );
    this.name = 'ChainStateResetRefusedError';
    if (options?.cause !== undefined) (this as { cause?: unknown }).cause = options.cause;
    Object.setPrototypeOf(this, ChainStateResetRefusedError.prototype);
  }
}

/** The tag the `chain_state` triggers put in their refusal. */
export const CHAIN_STATE_LOGGED_TAG = '[tzun:chain_state_logged]';

/** Turn a `chain_state` trigger refusal into {@link ChainStateResetRefusedError}; return any other error unchanged. */
export function translateChainStateError(err: unknown, chainId: string): unknown {
  const message = (err as { message?: unknown } | null)?.message;
  if (typeof message === 'string' && message.includes(CHAIN_STATE_LOGGED_TAG)) {
    return new ChainStateResetRefusedError(chainId, { cause: err });
  }
  return err;
}
