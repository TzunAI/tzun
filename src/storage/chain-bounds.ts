import { ChainIdentity, StorageAdapter } from '@tzun/engine';
import { AmbiguousActiveChainError, NoActiveChainError, resolveActiveChainId } from '@tzun/engine';

/**
 * One chain to verify, and the highest sequence number it is known to have
 * reached.
 *
 * Sequence numbers are unique only WITHIN a chain: `recovery.fork()` seals the
 * old chain and restarts the new one at 1. Every verifier that walks records in
 * sequence order — chain completeness, `verifyRange`, both scanner phases —
 * therefore has to walk one chain at a time. Walking the union would report
 * fabricated `duplicate_sequence` and `chain_break` incidents on stores where
 * nothing had been tampered with.
 */
export interface ChainScope {
  /** The chain to scope storage reads to. */
  chainId: string;
  /**
   * Inclusive upper bound for the sequence walk, or undefined when the chain's
   * high-water mark is not recorded anywhere — which, chain state being per
   * chain, means a chain that has never held a record. Supplying it is what
   * makes a deleted TAIL detectable, and a chain whose every record was deleted
   * distinguishable from one that was always empty: without it the verifier has
   * nothing to compare the last surviving record against.
   */
  upperBound: number | undefined;
}

/**
 * Highest sequence number `chainId` is known to have reached.
 *
 * Chain state is per chain, so `getLastSequence(chainId)` IS
 * this chain's high-water mark — live or sealed, active or not. It is what the
 * chain's own appends wrote and it does not fall when a record is deleted,
 * which is the whole point: with no survivor after the missing records, the
 * bound is the only thing left to compare against.
 *
 * A single global counter, answering about whichever chain the SDK believed
 * was active, would hand a chain that had never held a record ANOTHER chain's
 * bound, so that every position in it read as missing, and would leave a
 * sealed chain's bound to be recovered from the fork record once the fork that
 * sealed it had cleared the counter. Attribution per chain removes both.
 *
 * THE FORK-RECORD FALLBACK, for a chain whose state row is absent although the
 * chain held records — `resetChainState(chainId)` is public, and a store can be
 * edited. The seal captured the head at seal time (`sealedOldChainHead`).
 *
 * `sealedOldChainLength` is deliberately NOT the bound. It is a row count, and
 * a row count equals the head only while the chain has no gaps. On a sealed
 * chain with one gap it is short by one, so the chain's last record would sit
 * outside every range `relink()`, `verifyChainCompleteness()` and the scanner
 * walk, and deleting that record would be undetectable: the bound would be
 * taken from the wrong counter.
 *
 * FORK ROWS WITH NO RECORDED HEAD. `sealedOldChainHead` is optional, so a fork
 * record can reach the store without one and the column reads back NULL. That
 * is the defensive fallback below, not a dead path: reading the row count as
 * if it were the head is the bug above, so the bound is recomputed instead as
 * the larger of two numbers, each of which is a lower bound on the true head
 * and neither of which can overstate it:
 *   - the highest sequence number still present in the chain — a record at
 *     sequence S proves the chain reached S; and
 *   - the recorded row count — sequence numbers are distinct positive
 *     integers starting at 1, so a chain that held N rows reached at least N.
 * The present maximum is what puts the tail of a gapped head-less chain back
 * inside the range; the count is what keeps a deleted tail detectable on a
 * head-less chain WITHOUT gaps, where count == head exactly. What no
 * recomputation can recover is a tail deleted from a gapped head-less chain:
 * nothing recorded that head, and this function does not manufacture one.
 * (A chain holding duplicate sequence numbers can push the count past the
 * head; the verifier reports the duplicates on such a chain anyway, and the
 * extra "missing" sequence it may then report at the tail is an error in the
 * alarming direction, not the reassuring one.)
 */
export async function chainUpperBound(
  storage: StorageAdapter,
  chainId: string,
): Promise<number | undefined> {
  const recorded = await storage.getLastSequence(chainId);
  if (recorded > 0) return recorded;
  const seals = (await storage.listForksForChain(chainId)).filter((f) => f.oldChainId === chainId);
  if (seals.length === 0) return undefined;

  let bound = 0;
  let headless = false;
  for (const fork of seals) {
    if (typeof fork.sealedOldChainHead === 'number') {
      bound = Math.max(bound, fork.sealedOldChainHead);
    } else {
      // No head on this row: the count is a lower bound on the head, never
      // the head itself.
      headless = true;
      bound = Math.max(bound, fork.sealedOldChainLength);
    }
  }
  if (headless) {
    const present = await storage.listBySequence(undefined, undefined, chainId);
    bound = present.reduce((max, e) => Math.max(max, e.payload.sequenceNumber), bound);
  }
  return bound > 0 ? bound : undefined;
}

/**
 * Every chain in the store, each with its own sequence upper bound.
 *
 * A store that has never forked has no ChainIdentity rows at all — 'default' is
 * implicit until something materialises it — so the active chain is always
 * included even when `listChains()` comes back empty. Sealed chains are
 * included deliberately: a sealed chain is the read-only remainder of a fork
 * and is precisely where an insider would tamper, so dropping it from the scan
 * would be an error in the reassuring direction.
 */
export async function resolveChainScopes(storage: StorageAdapter): Promise<ChainScope[]> {
  // The two lists are read once, and both decisions are made from them:
  // which chain takes appends, and which chains exist. A conformant adapter's
  // getActiveChainId() IS the engine rule over these two reads (the contract
  // in storage-interface.ts), so resolving it here is the same answer without
  // a second pair of covering-index scans per pass, and the union below is
  // taken over the lists the active-chain decision was made from rather than
  // a later read. An adapter that cannot enumerate throws out of the first
  // read, as it threw out of getActiveChainId() before, and the scanner's
  // single-scope fallback catches it.
  //
  // A store whose chains are all sealed, or with two active rows, has no
  // answer to "which chain takes appends" — the rule refuses rather than
  // guess. Verification is not an append: every chain in the
  // store is still walked, and since chain state is per chain
  // every chain keeps its own upper bound whether or not anything is active.
  // A verifier that stopped scanning because the store could not say where the
  // NEXT record goes would be silence bought in the reassuring direction.
  const chains = await storage.listChains();
  const recordChainIds = await storage.listRecordChainIds();
  let activeChainId: string | null;
  try {
    activeChainId = resolveActiveChainId(chains, recordChainIds);
  } catch (err) {
    if (err instanceof NoActiveChainError || err instanceof AmbiguousActiveChainError) {
      activeChainId = null;
    } else {
      throw err;
    }
  }
  const chainIds = await listStoreChainIds(storage, activeChainId, { chains, recordChainIds });

  const scopes: ChainScope[] = [];
  for (const chainId of chainIds) {
    scopes.push({ chainId, upperBound: await chainUpperBound(storage, chainId) });
  }
  return scopes;
}

/**
 * Every chain in the store — the set a whole-store verifier must walk.
 *
 * Three sources, unioned, because no one of them is complete:
 *   - `listChains()`: every chain with an identity row, in `createdAt` order.
 *     A store that has never forked has NO rows; a fork registers both sides.
 *   - `listRecordChainIds()`: every chain at least one record belongs to.
 *     `'default'` is implicit until a fork materialises it, and `store()`
 *     accepts any chain id, so records can sit on a chain no row names.
 *   - the active chain, when the caller has one: an empty store still has a
 *     chain that the next capture will land on.
 *
 * Taking the identity rows alone, and falling back to the active chain only
 * when there are NO rows, would not do: one non-default row — the only thing
 * the public `storeChain()` lets an integrator do towards per-tenant chains —
 * would drop the implicit default chain from the walk. An empty chain is
 * vacuously valid, so on a store with three records on `default`, one empty
 * `tenant-b` row and a rewritten chain link on default's record 3, the
 * whole-store verifier would answer `valid: true` with `totalRecords: 0`.
 * Every record in the store belongs to a chain this function returns, which is
 * what makes a walk over its result structurally unable to leave a record
 * unread.
 *
 * Identity rows first (in `listChains()` order), then record-only chains
 * (sorted), then the active chain if it is still missing — stable on every
 * adapter.
 *
 * A caller that has already read the two lists (to decide the active chain
 * from them, as `resolveChainScopes()` does) passes them in `lists`, so the
 * union is over the same reads and the store is not scanned twice.
 */
export async function listStoreChainIds(
  storage: StorageAdapter,
  activeChainId: string | null,
  lists?: { chains: ChainIdentity[]; recordChainIds: string[] },
): Promise<string[]> {
  const chains = lists?.chains ?? (await storage.listChains());
  const recordChainIds = lists?.recordChainIds ?? (await storage.listRecordChainIds());
  const chainIds: string[] = [];
  const add = (id: string): void => {
    if (!chainIds.includes(id)) chainIds.push(id);
  };
  for (const chain of chains) add(chain.chainId);
  for (const id of recordChainIds) add(id);
  if (activeChainId !== null) add(activeChainId);
  return chainIds;
}
