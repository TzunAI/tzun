/**
 * The one rule for "which chain is active", shared by every StorageAdapter.
 *
 * The chain `getActiveChainId()` names is the chain `Tzun.capture()` writes
 * evidence into, so the answer cannot be a guess. A per-adapter query such as
 * `SELECT chain_id FROM chains WHERE status = 'active' ORDER BY created_at
 * DESC LIMIT 1`, falling back to `'default'`, gives two wrong answers: a store
 * whose every chain is sealed comes back as `'default'` (the sealed chain, on
 * a forked store), and a store with two chains taking appends comes back as
 * the newer row, with nothing said either way.
 *
 * A chain accepts appends in exactly two shapes, and both count here:
 *   - an identity row with `status: 'active'`; and
 *   - records under a chain id that has NO identity row. `'default'` is
 *     implicit until a fork materialises it, `store(envelope, chainId)`
 *     accepts any id, and every adapter's sealed-chain guard only refuses a
 *     chain whose ROW says sealed — so a chain with records and no row is as
 *     open as an active one. Three records on the implicit default chain,
 *     then one active `tenant-globex` row, is the case a row-only query gets
 *     wrong: it names `tenant-globex` — the second chain, adopted silently,
 *     born with the default chain's next sequence number and a link from the
 *     default chain's head.
 *
 * The rule, over `listChains()` and `listRecordChainIds()`:
 *   - no candidates and no rows → `'default'` (a store nothing has written
 *     to yet; the next record lands on the implicit default chain);
 *   - exactly one candidate → that chain;
 *   - no candidates, but rows → `NoActiveChainError` (every chain sealed);
 *   - more than one candidate → `AmbiguousActiveChainError`.
 * Both errors name every row and every implicit chain so the caller can
 * decide which one should be live.
 *
 * Pure over the two lists so an adapter — in this repo or a consumer's own —
 * can hand it its reads and be conformant by construction.
 */
import type { ChainIdentity } from './types/recovery';
import { AmbiguousActiveChainError, NoActiveChainError } from './errors';

/** The id of the chain every record belongs to until a fork registers one. */
export const DEFAULT_CHAIN_ID = 'default';

/**
 * Chain ids that hold records but have no identity row — open to appends
 * without any row saying so.
 */
export function implicitChainIds(chains: ChainIdentity[], recordChainIds: string[]): string[] {
  const named = new Set(chains.map((c) => c.chainId));
  return recordChainIds.filter((id) => !named.has(id));
}

export function resolveActiveChainId(chains: ChainIdentity[], recordChainIds: string[]): string {
  const implicit = implicitChainIds(chains, recordChainIds);
  const candidates = [
    ...chains.filter((c) => c.status === 'active').map((c) => c.chainId),
    ...implicit,
  ];
  if (candidates.length === 1) return candidates[0];
  if (candidates.length === 0) {
    if (chains.length === 0) return DEFAULT_CHAIN_ID;
    throw new NoActiveChainError(chains);
  }
  throw new AmbiguousActiveChainError(chains, implicit);
}
