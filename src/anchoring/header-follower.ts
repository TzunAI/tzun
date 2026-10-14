/**
 * The header follower: the finalized block of the store's anchoring chain,
 * read every minute and kept in memory, so a capture can write a decider's
 * `freshness` reference (Record §6.6) without calling a chain.
 *
 * Capture never waits on the follower: it takes the reference the follower
 * last read, and writes `null` under `freshness: 'auto'` when there is none or
 * the block is older than `maxAgeMs` (by the block's own timestamp, so a
 * finality stall ages the reference even while the node answers).
 *
 * A follower that shares a Postgres store with other capturing processes
 * also writes what it read to the store's `anchor_freshness` row
 * (`FreshnessRowStore`), which only the store's owner role may write; a
 * process with anchoring configured and no reading of its own takes the row
 * instead, under the same age rule, and only for its configured chain and
 * never below a block it already used.
 *
 * Every `recheckEvery` refreshes, the follower re-checks the references the
 * newest records carry against its own chain client: a reference that does
 * not name the canonical block at its height is reported
 * (`freshness_reference_invalid`).
 */
import { formatFreshnessReference, parseFreshnessReference } from '@tzun/engine';
import type { EvidenceEnvelope, FreshnessReferenceInvalidEvent } from '@tzun/engine';
import type { EvmChainClient } from './evm-chain';

/** The default greatest age of a reference capture writes: 30 minutes. */
export const DEFAULT_FRESHNESS_MAX_AGE_MS = 30 * 60_000;
/** How often the follower reads the finalized block. */
export const HEADER_FOLLOWER_INTERVAL_MS = 60_000;
/** How many of the newest records the re-check reads. */
export const FRESHNESS_RECHECK_WINDOW = 64;

/** A finalized block as the follower read it. */
export interface FinalizedHeader {
  /** CAIP-2, e.g. `eip155:1`. */
  chain: string;
  number: number;
  /** `0x` and 64 lowercase hex. */
  hash: string;
  /** The block's timestamp, in milliseconds. */
  timeMs: number;
}

/** The `anchor_freshness` row of a Postgres store, as the adapter reads and writes it. */
export interface FreshnessRowStore {
  writeAnchorFreshness(header: FinalizedHeader): Promise<void>;
  readAnchorFreshness(chain: string): Promise<FinalizedHeader | null>;
}

/** Whether a store has the `anchor_freshness` row. */
export function freshnessRowStoreFor(storage: unknown): FreshnessRowStore | undefined {
  const s = storage as Partial<FreshnessRowStore> | null;
  return s && typeof s.writeAnchorFreshness === 'function' && typeof s.readAnchorFreshness === 'function'
    ? (s as FreshnessRowStore)
    : undefined;
}

/** What the follower reads its records from, for the re-check. */
export interface FreshnessRecheckSource {
  /** The newest records, newest first, at most `limit`. */
  newest(limit: number): Promise<EvidenceEnvelope[]>;
}

export interface HeaderFollowerOptions {
  /** The anchoring chain, CAIP-2. */
  chain: string;
  /** The greatest age, by block timestamp, of a reference capture writes. Default 30 minutes. */
  maxAgeMs?: number;
  intervalMs?: number;
  clock?: () => number;
  /** Where to share what the follower reads (the store's `anchor_freshness` row), when the store has one. */
  row?: FreshnessRowStore;
  /** The records whose references the follower re-checks, and how it reports a bad one. */
  recheck?: { source: FreshnessRecheckSource; report(event: FreshnessReferenceInvalidEvent): void; every?: number };
  onError?(error: unknown): void;
}

/**
 * Reads the finalized block of one chain on a schedule, and answers the
 * reference a capture writes now.
 */
export class HeaderFollower {
  private latestRead: FinalizedHeader | null = null;
  /** The highest block a reference this process wrote named: a row below it is never taken. */
  private highestUsed = -1;
  private timer: NodeJS.Timeout | null = null;
  private refreshes = 0;
  private readonly maxAgeMs: number;
  private readonly intervalMs: number;
  private readonly clock: () => number;

  constructor(
    private readonly client: Pick<EvmChainClient, 'finalizedBlockNumber' | 'canonicalBlock'> | null,
    private readonly options: HeaderFollowerOptions,
  ) {
    this.maxAgeMs = options.maxAgeMs ?? DEFAULT_FRESHNESS_MAX_AGE_MS;
    this.intervalMs = options.intervalMs ?? HEADER_FOLLOWER_INTERVAL_MS;
    this.clock = options.clock ?? Date.now;
    if (!(Number.isFinite(this.maxAgeMs) && this.maxAgeMs > 0)) {
      throw new RangeError('freshnessMaxAgeMs must be a positive number of milliseconds.');
    }
  }

  /** The chain this follower reads. */
  get chain(): string {
    return this.options.chain;
  }

  /** The greatest age of a reference capture writes. */
  get maxAge(): number {
    return this.maxAgeMs;
  }

  /** The block the follower last read, or `null`. */
  latest(): FinalizedHeader | null {
    return this.latestRead === null ? null : { ...this.latestRead };
  }

  /**
   * Read the finalized block now. Shares it through the row when the store
   * has one, and every `recheck.every` refreshes re-checks the newest
   * records' references. A failed read leaves the last reading in place.
   */
  async refresh(): Promise<FinalizedHeader | null> {
    if (this.client === null) return this.latestRead;
    const number = await this.client.finalizedBlockNumber();
    const block = await this.client.canonicalBlock(number);
    if (block === null) return this.latestRead;
    const header: FinalizedHeader = {
      chain: this.options.chain,
      number,
      hash: block.hash.toLowerCase(),
      timeMs: block.timestamp * 1000,
    };
    if (this.latestRead === null || header.number >= this.latestRead.number) this.latestRead = header;
    if (this.options.row) await this.options.row.writeAnchorFreshness(header);
    this.refreshes += 1;
    const every = this.options.recheck?.every ?? 1;
    if (this.options.recheck && this.refreshes % every === 0) await this.recheck();
    return this.latestRead;
  }

  /** Start reading on the schedule: one read now, then every interval. The timer does not hold the process open. */
  start(): void {
    if (this.timer !== null) return;
    const tick = (): void => {
      this.refresh().catch((error) => this.options.onError?.(error));
    };
    tick();
    this.timer = setInterval(tick, this.intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer !== null) clearInterval(this.timer);
    this.timer = null;
  }

  /**
   * The reference a capture writes now under `freshness: 'auto'`: this
   * process's reading, else the store's row (for this chain, not below a
   * block this process already used); `null` when neither is younger than
   * the greatest age.
   */
  async reference(): Promise<string | null> {
    const now = this.clock();
    let header = this.latestRead;
    if (header === null || now - header.timeMs > this.maxAgeMs) {
      header = null;
      if (this.options.row) {
        const row = await this.options.row.readAnchorFreshness(this.options.chain).catch(() => null);
        if (row && row.chain === this.options.chain && row.number >= this.highestUsed && now - row.timeMs <= this.maxAgeMs) {
          header = row;
        }
      }
    }
    if (header === null) return null;
    this.highestUsed = Math.max(this.highestUsed, header.number);
    return formatFreshnessReference(header.chain, header.number, header.hash);
  }

  /**
   * Check every distinct freshness reference among the newest records
   * against the chain: one that does not name the canonical block at its
   * height is reported. A reference of another chain, or one the node cannot
   * answer for yet, is skipped.
   */
  async recheck(): Promise<void> {
    const recheck = this.options.recheck;
    if (!recheck || this.client === null) return;
    const records = await recheck.source.newest(FRESHNESS_RECHECK_WINDOW);
    const seen = new Map<string, boolean>();
    for (const record of records) {
      const reference = (record.payload?.decider as { freshness?: unknown } | null | undefined)?.freshness;
      if (typeof reference !== 'string') continue;
      let valid = seen.get(reference);
      if (valid === undefined) {
        const parsed = parseFreshnessReference(reference);
        if (parsed === null || parsed.chain !== this.options.chain) {
          seen.set(reference, true);
          continue;
        }
        const block = await this.client.canonicalBlock(parsed.blockNumber);
        valid = block === null ? true : block.hash.toLowerCase() === parsed.blockHash;
        seen.set(reference, valid);
      }
      if (!valid) {
        recheck.report({ type: 'freshness_reference_invalid', evidenceId: record.payload.evidenceId, reference });
      }
    }
  }
}
