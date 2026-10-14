/**
 * The cadence and the gas governor. Pure functions of what the scheduler
 * read: no I/O, no clock of their own.
 *
 * The governor spreads the wallet's balance over `runwayDays`:
 *
 *     allowance/day = balance / runwayDays
 *     interval      = clamp( max(targetInterval, 1 day / (allowance/day / cost(price))), <= T_max )
 *
 * where cost(price) is one publication's gas at the current price. Batch size
 * is not a gas input: the calldata is always 32 bytes.
 */
import type { AnchorBudget, AnchorCadence } from './config';

/**
 * The gas one `evm-calldata/1` publication costs at most: a zero-value
 * self-transaction with 32 bytes of calldata, 22,280 gas at the EIP-7623
 * calldata floor whatever the epoch's size (measured on Sepolia and on
 * anvil). After Glamsterdam (EIP-2780, EIP-7976) the same transaction costs
 * 14,048 gas whatever bytes P has, so this stays an upper bound on every
 * Ethereum network. It is the governor's estimate; accounting uses each
 * receipt's `gasUsed × effectiveGasPrice`.
 */
export const ANCHOR_PUBLICATION_GAS = 22_280n;

/** The gas limit a publication is signed with: above 22,280 with room for a node's estimate (22,615 measured before Glamsterdam). */
export const ANCHOR_PUBLICATION_GAS_LIMIT = 30_000n;

export const DAY_MS = 24 * 60 * 60_000;

/** The balance the scheduler refuses to submit below: 3 × one publication at the hard cap. */
export const MINIMUM_BALANCE_MULTIPLE = 3n;

/** Runway alarms. */
export const RUNWAY_WARNING_DAYS = 30;
export const RUNWAY_CRITICAL_DAYS = 7;

/** gwei, possibly fractional, to wei. */
export function gweiToWei(gwei: number): bigint {
  return BigInt(Math.round(gwei * 1e9));
}

/** What the governor concludes from the balance and the price. */
export interface GovernorView {
  /** One publication at `priceWei`. */
  costWei: bigint;
  /** balance / runwayDays. */
  allowancePerDayWei: bigint;
  /** The computed interval, between `targetIntervalMs` and T_max. */
  intervalMs: number;
  /** True when the budget alone would space publications further apart than T_max. */
  overBudget: boolean;
  /** How many days the balance lasts publishing every `intervalMs` at this price. */
  runwayDays: number;
  /** 3 × one publication at the hard cap: below it the scheduler refuses to submit. */
  minimumBalanceWei: bigint;
}

/**
 * The interval and runway at `priceWei` (the expected effective gas
 * price: base fee plus tip) with `balanceWei` in the wallet.
 */
export function governorView(input: {
  balanceWei: bigint;
  priceWei: bigint;
  cadence: AnchorCadence;
  budget: AnchorBudget;
}): GovernorView {
  const { balanceWei, priceWei, cadence, budget } = input;
  const costWei = ANCHOR_PUBLICATION_GAS * (priceWei > 0n ? priceWei : 0n);
  // runwayDays may be fractional: scale by 1e6 to stay in integers.
  const allowancePerDayWei = (balanceWei * 1_000_000n) / BigInt(Math.round(budget.runwayDays * 1_000_000));
  let budgetIntervalMs: number;
  if (costWei === 0n) budgetIntervalMs = 0;
  else if (allowancePerDayWei === 0n) budgetIntervalMs = Number.POSITIVE_INFINITY;
  else budgetIntervalMs = Number((BigInt(DAY_MS) * costWei) / allowancePerDayWei);
  const overBudget = budgetIntervalMs > cadence.maxStalenessMs;
  const intervalMs = Math.min(Math.max(cadence.targetIntervalMs, budgetIntervalMs), cadence.maxStalenessMs);
  const spendPerDayWei = costWei === 0n ? 0n : (costWei * BigInt(DAY_MS)) / BigInt(intervalMs);
  const runwayDays =
    spendPerDayWei === 0n ? Number.POSITIVE_INFINITY : Number((balanceWei * 1_000_000n) / spendPerDayWei) / 1_000_000;
  const minimumBalanceWei = MINIMUM_BALANCE_MULTIPLE * ANCHOR_PUBLICATION_GAS * gweiToWei(budget.hardFeeCapGwei);
  return { costWei, allowancePerDayWei, intervalMs, overBudget, runwayDays, minimumBalanceWei };
}

/** Whether a publication may be sent at `priceWei`. */
export type FeeDecision =
  | { ok: true }
  | { ok: false; reason: 'fee_above_soft_max' | 'fee_above_hard_cap' };

/**
 * Above the hard cap nothing is sent, even at T_max. Above the soft maximum
 * the governor defers, unless a leaf has waited T_max (`stale`).
 */
export function feeDecision(priceWei: bigint, budget: AnchorBudget, stale: boolean): FeeDecision {
  if (priceWei > gweiToWei(budget.hardFeeCapGwei)) return { ok: false, reason: 'fee_above_hard_cap' };
  if (priceWei > gweiToWei(budget.softMaxFeeGwei) && !stale) return { ok: false, reason: 'fee_above_soft_max' };
  return { ok: true };
}

/**
 * The least tip a publication is signed with, by CAIP-2 chain, in gwei: on
 * Ethereum mainnet a node's `eth_maxPriorityFeePerGas` can answer 0 (it
 * answered 0 and 0.0000065 gwei on 2026-10-01, when blocks paid a median tip
 * of 0.05 gwei and a 90th percentile of 0.118), and a replacement that bumps
 * nothing by 12.5% is still nothing. A chain not listed has no floor. The
 * scheduler's `minPriorityFeeGwei` option overrides this table.
 */
export const DEFAULT_MIN_PRIORITY_FEE_GWEI: Readonly<Record<string, number>> = Object.freeze({
  'eip155:1': 0.1,
});

/**
 * The tip floor for `chain`, in wei: `override` (gwei) when it is given,
 * otherwise {@link DEFAULT_MIN_PRIORITY_FEE_GWEI}'s entry, otherwise 0.
 */
export function minPriorityFeeWei(chain: string, override?: number): bigint {
  const gwei = override ?? (Object.prototype.hasOwnProperty.call(DEFAULT_MIN_PRIORITY_FEE_GWEI, chain) ? DEFAULT_MIN_PRIORITY_FEE_GWEI[chain] : 0);
  return gweiToWei(gwei);
}

/** `fees` with its tip raised to at least `floorWei`. */
export function withPriorityFeeFloor<T extends { maxPriorityFeePerGas: bigint }>(fees: T, floorWei: bigint): T {
  return fees.maxPriorityFeePerGas >= floorWei ? fees : { ...fees, maxPriorityFeePerGas: floorWei };
}

/**
 * The fees a publication is signed with: the tip, and a fee cap of twice the
 * base fee plus the tip, clamped to the hard cap. `null` when even the clamped
 * cap is below the base fee plus the tip, which the fee decision refuses first.
 * The scheduler passes a tip already raised to the chain's floor
 * ({@link withPriorityFeeFloor}).
 */
export function publicationFees(
  baseFeePerGas: bigint,
  maxPriorityFeePerGas: bigint,
  budget: AnchorBudget,
): { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint } | null {
  const hardCap = gweiToWei(budget.hardFeeCapGwei);
  const tip = maxPriorityFeePerGas < hardCap ? maxPriorityFeePerGas : hardCap;
  let maxFee = 2n * baseFeePerGas + tip;
  if (maxFee > hardCap) maxFee = hardCap;
  if (maxFee < baseFeePerGas + tip) return null;
  return { maxFeePerGas: maxFee, maxPriorityFeePerGas: tip };
}

/** A replacement raises both fees by 12.5% (geth needs at least 10%), clamped to the hard cap. */
export const REPLACEMENT_BUMP_PERMILLE = 125n;
/** The least bump a node accepts for a replacement. */
export const NODE_MINIMUM_BUMP_PERMILLE = 100n;
/** At most this many replacements, then `anchor_tx_stuck`. */
export const MAX_REPLACEMENTS = 5;

const bumped = (value: bigint, permille: bigint): bigint => (value * (1000n + permille) + 999n) / 1000n;

/**
 * The fees of the next replacement, or `null` when the clamp to the hard cap
 * leaves less than the node's 10% minimum bump on either fee.
 */
export function replacementFees(
  previous: { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint },
  budget: AnchorBudget,
): { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint } | null {
  const hardCap = gweiToWei(budget.hardFeeCapGwei);
  const clamp = (v: bigint): bigint => (v > hardCap ? hardCap : v);
  const maxFeePerGas = clamp(bumped(previous.maxFeePerGas, REPLACEMENT_BUMP_PERMILLE));
  const maxPriorityFeePerGas = clamp(bumped(previous.maxPriorityFeePerGas, REPLACEMENT_BUMP_PERMILLE));
  if (maxFeePerGas < bumped(previous.maxFeePerGas, NODE_MINIMUM_BUMP_PERMILLE)) return null;
  if (maxPriorityFeePerGas < bumped(previous.maxPriorityFeePerGas, NODE_MINIMUM_BUMP_PERMILLE)) return null;
  if (maxPriorityFeePerGas > maxFeePerGas) return null;
  return { maxFeePerGas, maxPriorityFeePerGas };
}

/** What the cadence reads. Times are epoch milliseconds. */
export interface CadenceInput {
  now: number;
  /** When the last epoch was cut, or null before the first. */
  lastEpochAt: number | null;
  /** The oldest waiting leaf that starts an epoch: every leaf but an `anchor_fill` revision leaf. */
  oldestTriggeringLeafAt: number | null;
  /** The oldest waiting `anchor_fill` revision leaf: it rides along, and starts an epoch only at T_max. */
  oldestRideAlongLeafAt: number | null;
  /** How many triggering leaves wait. */
  waitingLeaves: number;
  /** The governor's interval. */
  intervalMs: number;
  cadence: AnchorCadence;
  /** `anchorNow({ force: true })`: bypasses the cadence, minInterval included. */
  force: boolean;
}

export type CadenceDecision =
  | { due: true; why: 'interval' | 'size' | 'max_staleness' | 'forced'; stale: boolean }
  | { due: false; why: 'nothing_waiting' | 'min_interval' | 'waiting'; dueAt: number | null; stale: boolean };

/**
 * Whether an epoch is due. There are no empty epochs: with nothing waiting,
 * nothing is due. Freshness is the age of the oldest waiting leaf.
 */
export function cadenceDecision(input: CadenceInput): CadenceDecision {
  const { now, lastEpochAt, oldestTriggeringLeafAt, oldestRideAlongLeafAt, waitingLeaves, intervalMs, cadence } = input;
  const ages = [oldestTriggeringLeafAt, oldestRideAlongLeafAt].filter((t): t is number => t !== null).map((t) => now - t);
  if (ages.length === 0) return { due: false, why: 'nothing_waiting', dueAt: null, stale: false };
  const stale = Math.max(...ages) >= cadence.maxStalenessMs;
  if (input.force) return { due: true, why: 'forced', stale };
  if (lastEpochAt !== null && now - lastEpochAt < cadence.minIntervalMs) {
    return { due: false, why: 'min_interval', dueAt: lastEpochAt + cadence.minIntervalMs, stale };
  }
  if (oldestTriggeringLeafAt !== null && now - oldestTriggeringLeafAt >= intervalMs) return { due: true, why: 'interval', stale };
  if (oldestTriggeringLeafAt !== null && waitingLeaves >= cadence.sizeTrigger) return { due: true, why: 'size', stale };
  if (stale) return { due: true, why: 'max_staleness', stale };
  const candidates: number[] = [];
  if (oldestTriggeringLeafAt !== null) candidates.push(oldestTriggeringLeafAt + intervalMs);
  if (oldestRideAlongLeafAt !== null) candidates.push(oldestRideAlongLeafAt + cadence.maxStalenessMs);
  return { due: false, why: 'waiting', dueAt: Math.min(...candidates), stale };
}
