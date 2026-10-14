/**
 * The cadence, the gas governor and the anchoring configuration. Pure
 * functions: the fee and the balance are inputs.
 */
import {
  ANCHOR_PUBLICATION_GAS,
  AnchoringConfigError,
  DEFAULT_ANCHOR_BUDGET,
  DEFAULT_ANCHOR_CADENCE,
  cadenceDecision,
  feeDecision,
  governorView,
  gweiToWei,
  publicationFees,
  replacementFees,
  resolveAnchoringConfig,
  type AnchorBudget,
  type AnchorCadence,
} from '../../src/anchoring';

const ETH = 10n ** 18n;
const HOUR = 60 * 60_000;
const MIN = 60_000;
const cadence: AnchorCadence = { ...DEFAULT_ANCHOR_CADENCE };
const budget = (runwayDays = 180): AnchorBudget => ({ ...DEFAULT_ANCHOR_BUDGET, runwayDays });
const balance = (150n * ETH) / 1000n; // 0.150 ETH, a demo wallet's balance

describe('the governor reproduces the fee table on 0.150 ETH', () => {
  // [gwei, cost per anchor (ETH), anchors on 0.150 ETH, interval at 180 d, interval at 365 d]
  const rows: Array<[number, number, number, number, number]> = [
    [1.1, 2.45e-5, 6120, 60 * MIN, 86 * MIN],
    [5, 1.11e-4, 1346, 3.2 * HOUR, 6.5 * HOUR],
    [20, 4.46e-4, 336, 12.8 * HOUR, 24 * HOUR],
    [50, 1.11e-3, 134, 24 * HOUR, 24 * HOUR],
  ];

  it.each(rows)('%s gwei', (gwei, costEth, anchors, at180, at365) => {
    const v180 = governorView({ balanceWei: balance, priceWei: gweiToWei(gwei), cadence, budget: budget(180) });
    const v365 = governorView({ balanceWei: balance, priceWei: gweiToWei(gwei), cadence, budget: budget(365) });
    expect(v180.costWei).toBe(ANCHOR_PUBLICATION_GAS * gweiToWei(gwei));
    expect(Number(v180.costWei) / 1e18).toBeCloseTo(costEth, costEth < 1e-4 ? 6 : 5);
    expect(Math.floor(Number(balance) / Number(v180.costWei))).toBeGreaterThanOrEqual(anchors);
    expect(Math.floor(Number(balance) / Number(v180.costWei))).toBeLessThanOrEqual(anchors + 3);
    // The table rounds its intervals; within 2% of it, and never past T_max.
    expect(Math.abs(v180.intervalMs - at180) / at180).toBeLessThan(0.02);
    expect(Math.abs(v365.intervalMs - at365) / at365).toBeLessThan(0.02);
    expect(v180.intervalMs).toBeLessThanOrEqual(cadence.maxStalenessMs);
  });

  it('1.1 gwei is held at the 1 h target, with a runway of about 255 days', () => {
    const v = governorView({ balanceWei: balance, priceWei: gweiToWei(1.1), cadence, budget: budget(180) });
    expect(v.intervalMs).toBe(cadence.targetIntervalMs);
    expect(v.overBudget).toBe(false);
    expect(Math.round(v.runwayDays)).toBe(255);
  });

  it('50 gwei hits T_max, over budget, with a runway of 134 days', () => {
    const v = governorView({ balanceWei: balance, priceWei: gweiToWei(50), cadence, budget: budget(180) });
    expect(v.intervalMs).toBe(cadence.maxStalenessMs);
    expect(v.overBudget).toBe(true);
    expect(Math.floor(v.runwayDays)).toBe(134);
  });

  it('20 gwei on a 365-day runway is over budget at T_max', () => {
    const v = governorView({ balanceWei: balance, priceWei: gweiToWei(20), cadence, budget: budget(365) });
    expect(v.intervalMs).toBe(cadence.maxStalenessMs);
    expect(v.overBudget).toBe(true);
  });

  it('refuses to submit under 3x the cost at the hard cap', () => {
    const v = governorView({ balanceWei: balance, priceWei: gweiToWei(1), cadence, budget: budget() });
    expect(v.minimumBalanceWei).toBe(3n * ANCHOR_PUBLICATION_GAS * gweiToWei(50));
  });

  it('projects a runway under 30 and under 7 days for small balances', () => {
    const at = (wei: bigint) => governorView({ balanceWei: wei, priceWei: gweiToWei(1.1), cadence, budget: budget() }).runwayDays;
    // 0.001 ETH at 1.1 gwei: the budget stretches the interval to T_max, one anchor a day.
    expect(at(ETH / 1000n)).toBeGreaterThan(30);
    expect(at(ETH / 2000n)).toBeLessThan(30);
    expect(at(ETH / 10_000n)).toBeLessThan(7);
  });
});

describe('fees', () => {
  it('the soft maximum defers until T_max; the hard cap holds even then', () => {
    const b = budget();
    expect(feeDecision(gweiToWei(19), b, false)).toEqual({ ok: true });
    expect(feeDecision(gweiToWei(21), b, false)).toEqual({ ok: false, reason: 'fee_above_soft_max' });
    expect(feeDecision(gweiToWei(21), b, true)).toEqual({ ok: true });
    expect(feeDecision(gweiToWei(51), b, true)).toEqual({ ok: false, reason: 'fee_above_hard_cap' });
  });

  it('signs with twice the base fee plus the tip, clamped to the hard cap', () => {
    const b = budget();
    expect(publicationFees(gweiToWei(1), gweiToWei(0.1), b)).toEqual({ maxFeePerGas: gweiToWei(2.1), maxPriorityFeePerGas: gweiToWei(0.1) });
    expect(publicationFees(gweiToWei(30), gweiToWei(1), b)).toEqual({ maxFeePerGas: gweiToWei(50), maxPriorityFeePerGas: gweiToWei(1) });
    expect(publicationFees(gweiToWei(50), gweiToWei(1), b)).toBeNull();
  });

  it('a replacement raises both fees by 12.5%, clamped to the hard cap, and stops when the clamp leaves under 10%', () => {
    const b = budget();
    const first = { maxFeePerGas: gweiToWei(2), maxPriorityFeePerGas: gweiToWei(1) };
    const second = replacementFees(first, b)!;
    expect(second).toEqual({ maxFeePerGas: gweiToWei(2.25), maxPriorityFeePerGas: gweiToWei(1.125) });
    // Near the cap: 48 → 50 is a 4% bump, which a node refuses.
    expect(replacementFees({ maxFeePerGas: gweiToWei(48), maxPriorityFeePerGas: gweiToWei(1) }, b)).toBeNull();
    // 45 → 50 is 11%: clamped, but still a valid replacement.
    expect(replacementFees({ maxFeePerGas: gweiToWei(45), maxPriorityFeePerGas: gweiToWei(1) }, b)?.maxFeePerGas).toBe(gweiToWei(50));
  });
});

describe('the cadence', () => {
  const base = { cadence, intervalMs: HOUR, waitingLeaves: 1, force: false, oldestRideAlongLeafAt: null };
  const now = 10 * 24 * HOUR;

  it('has no empty epochs', () => {
    expect(cadenceDecision({ ...base, now, lastEpochAt: null, oldestTriggeringLeafAt: null, waitingLeaves: 0 })).toMatchObject({
      due: false,
      why: 'nothing_waiting',
    });
    expect(cadenceDecision({ ...base, now, lastEpochAt: null, oldestTriggeringLeafAt: null, waitingLeaves: 0, force: true }).due).toBe(false);
  });

  it('is due when the oldest waiting leaf is an interval old, and never inside minInterval', () => {
    expect(cadenceDecision({ ...base, now, lastEpochAt: null, oldestTriggeringLeafAt: now - HOUR + 1 })).toMatchObject({ due: false, why: 'waiting', dueAt: now + 1 });
    expect(cadenceDecision({ ...base, now, lastEpochAt: null, oldestTriggeringLeafAt: now - HOUR })).toMatchObject({ due: true, why: 'interval' });
    expect(cadenceDecision({ ...base, now, lastEpochAt: now - 5 * MIN, oldestTriggeringLeafAt: now - 2 * HOUR })).toMatchObject({ due: false, why: 'min_interval' });
  });

  it('publishes early on the size trigger, still no sooner than minInterval', () => {
    const many = { ...base, waitingLeaves: cadence.sizeTrigger, oldestTriggeringLeafAt: now - MIN };
    expect(cadenceDecision({ ...many, now, lastEpochAt: now - 11 * MIN })).toMatchObject({ due: true, why: 'size' });
    expect(cadenceDecision({ ...many, now, lastEpochAt: now - 9 * MIN })).toMatchObject({ due: false, why: 'min_interval' });
  });

  it('force bypasses the interval and minInterval, and says whether T_max passed', () => {
    expect(cadenceDecision({ ...base, force: true, now, lastEpochAt: now - MIN, oldestTriggeringLeafAt: now - MIN })).toEqual({ due: true, why: 'forced', stale: false });
  });

  it('anchor_fill leaves ride along: they never start an epoch before T_max', () => {
    const ride = { ...base, oldestTriggeringLeafAt: null, waitingLeaves: 0 };
    expect(cadenceDecision({ ...ride, now, lastEpochAt: now - 2 * HOUR, oldestRideAlongLeafAt: now - 23 * HOUR })).toMatchObject({
      due: false,
      why: 'waiting',
    });
    expect(cadenceDecision({ ...ride, now, lastEpochAt: now - 24 * HOUR, oldestRideAlongLeafAt: now - 24 * HOUR })).toMatchObject({
      due: true,
      why: 'max_staleness',
      stale: true,
    });
  });

  it('a capture burst followed by more than T_max idle costs exactly two epochs', () => {
    // Simulate a day and a half in one-minute ticks. The burst's leaves are
    // captured at t = 0; its fill, after its epoch is final (~15 min), writes
    // one anchor_fill revision leaf per record. Those ride along. Nothing else
    // is captured.
    const finality = 15 * MIN;
    let triggering: number | null = 0;
    let rideAlong: number | null = null;
    let lastEpochAt: number | null = null;
    const epochs: number[] = [];
    let pendingFillAt: number | null = null;
    for (let t = 0; t <= 36 * HOUR; t += MIN) {
      if (pendingFillAt !== null && t >= pendingFillAt) {
        // The fill of an epoch with evidence leaves writes revision leaves.
        rideAlong = t;
        pendingFillAt = null;
      }
      const decision = cadenceDecision({
        cadence,
        intervalMs: HOUR,
        now: t,
        lastEpochAt,
        oldestTriggeringLeafAt: triggering,
        oldestRideAlongLeafAt: rideAlong,
        waitingLeaves: triggering === null ? 0 : 50,
        force: false,
      });
      if (!decision.due) continue;
      epochs.push(t);
      lastEpochAt = t;
      // An epoch with evidence leaves has records to fill; one with only
      // revision leaves fills nothing and writes no new revision rows.
      if (triggering !== null) pendingFillAt = t + finality;
      triggering = null;
      rideAlong = null;
    }
    expect(epochs).toEqual([HOUR, HOUR + finality + 24 * HOUR]);
  });
});

describe('the anchoring configuration', () => {
  const evm = { rpcUrl: 'http://127.0.0.1:8545', privateKey: '0x' + '11'.repeat(32), chain: 'eip155:31337' };

  it('applies the default cadence and budget', () => {
    const resolved = resolveAnchoringConfig({ publishers: { evm } });
    expect(resolved.cadence).toEqual({ targetIntervalMs: HOUR, minIntervalMs: 10 * MIN, sizeTrigger: 10_000, maxStalenessMs: 24 * HOUR });
    expect(resolved.budget).toEqual({ runwayDays: 180, softMaxFeeGwei: 20, hardFeeCapGwei: 50, forcePerDay: 6 });
    expect(resolved.production).toBe(false);
  });

  it('takes caps and cadence per deployment', () => {
    const resolved = resolveAnchoringConfig({ publishers: { evm }, budget: { hardFeeCapGwei: 5, softMaxFeeGwei: 2 }, cadence: { targetIntervalMs: 15 * MIN } });
    expect(resolved.budget.hardFeeCapGwei).toBe(5);
    expect(resolved.cadence.targetIntervalMs).toBe(15 * MIN);
  });

  it.each([
    [{ publishers: {} }, /publishers.evm is required/],
    [{ publishers: { evm, rfc3161: true } }, /rfc3161\/1 publication is not built yet/],
    [{ publishers: { evm }, mirror: { sink: { put: async () => undefined } } }, /mirror/],
    [{ publishers: { evm: { ...evm, chain: 'ethereum-sepolia' } } }, /CAIP-2/],
    [{ publishers: { evm: { ...evm, rpcUrl: 'ws://x' } } }, /rpcUrl/],
    [{ publishers: { evm }, budget: { softMaxFeeGwei: 60 } }, /softMaxFeeGwei must not exceed/],
    [{ publishers: { evm }, cadence: { minIntervalMs: 2 * HOUR } }, /minIntervalMs <= targetIntervalMs/],
    [{ publishers: { evm }, namespace: 'Test.Upper' }, /namespace/],
  ])('refuses %j', (config, message) => {
    expect(() => resolveAnchoringConfig(config as never)).toThrow(AnchoringConfigError);
    expect(() => resolveAnchoringConfig(config as never)).toThrow(message);
  });

  it('never echoes the private key in a refusal', () => {
    const secret = '0x' + 'ab'.repeat(31) + 'zz';
    let message = '';
    try {
      resolveAnchoringConfig({ publishers: { evm: { ...evm, privateKey: secret } } });
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).toMatch(/privateKey/);
    expect(message).not.toContain('abab');
  });
});
