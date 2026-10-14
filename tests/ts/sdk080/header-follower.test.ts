/**
 * The header follower (src/anchoring/header-follower.ts):
 * the finalized block capture writes into a decider's freshness, its age
 * rule, the shared `anchor_freshness` row, and the re-check of the newest
 * records' references.
 */
import { createHash } from 'node:crypto';
import type { EvidenceEnvelope, FreshnessReferenceInvalidEvent } from '@tzun/engine';
import { HeaderFollower, freshnessRowStoreFor, type FinalizedHeader, type FreshnessRowStore } from '../../../src/anchoring/header-follower';

const hash = (label: string): string => `0x${createHash('sha256').update(label).digest('hex')}`;
const CHAIN = 'eip155:560048';
const BLOCK_TIME_S = 1_790_000_000;

/** A chain whose finalized height and canonical blocks the test sets. */
function chain(start: number) {
  const state = { finalized: start, blocks: new Map<number, { hash: string; timestamp: number }>() };
  for (let n = 0; n <= start + 10; n++) state.blocks.set(n, { hash: hash(`block ${n}`), timestamp: BLOCK_TIME_S + n * 12 });
  return {
    state,
    client: {
      async finalizedBlockNumber() {
        return state.finalized;
      },
      async canonicalBlock(n: number) {
        return state.blocks.get(n) ?? null;
      },
    },
  };
}

function record(id: string, freshness: string | null): EvidenceEnvelope {
  return { payload: { evidenceId: id, decider: { kind: 'human', id: 'acct:u-1', agent: null, credential: null, freshness } } } as unknown as EvidenceEnvelope;
}

describe('HeaderFollower', () => {
  it('answers the finalized block it last read while it is younger than the greatest age, by the block time', async () => {
    const { client } = chain(100);
    let now = (BLOCK_TIME_S + 100 * 12) * 1000 + 5_000;
    const follower = new HeaderFollower(client, { chain: CHAIN, maxAgeMs: 60_000, clock: () => now });
    expect(await follower.reference()).toBeNull();
    await follower.refresh();
    expect(await follower.reference()).toBe(`${CHAIN}@100:${hash('block 100')}`);
    now += 60_000;
    // A finality stall: the node answers, the block ages.
    expect(await follower.reference()).toBeNull();
  });

  it('shares what it reads through the row, and a process with no reading of its own takes the row under the same rules', async () => {
    const rows = new Map<string, FinalizedHeader>();
    const row: FreshnessRowStore = {
      async writeAnchorFreshness(h) {
        rows.set(h.chain, { ...h });
      },
      async readAnchorFreshness(c) {
        return rows.get(c) ?? null;
      },
    };
    const { client, state } = chain(100);
    const now = (BLOCK_TIME_S + 105 * 12) * 1000;
    const writer = new HeaderFollower(client, { chain: CHAIN, maxAgeMs: 600_000, clock: () => now, row });
    state.finalized = 105;
    await writer.refresh();
    expect(rows.get(CHAIN)?.number).toBe(105);

    const reader = new HeaderFollower(null, { chain: CHAIN, maxAgeMs: 600_000, clock: () => now, row });
    expect(await reader.reference()).toBe(`${CHAIN}@105:${hash('block 105')}`);
    // Another chain's row is never taken, nor one below a block already used.
    const other = new HeaderFollower(null, { chain: 'eip155:1', maxAgeMs: 600_000, clock: () => now, row });
    expect(await other.reference()).toBeNull();
    rows.set(CHAIN, { chain: CHAIN, number: 101, hash: hash('block 101'), timeMs: now - 1000 });
    expect(await reader.reference()).toBeNull();
  });

  it('re-checks the newest records and reports a reference that names no canonical block', async () => {
    const { client } = chain(100);
    const reported: FreshnessReferenceInvalidEvent[] = [];
    const planted = `${CHAIN}@99:${hash('not the block')}`;
    const follower = new HeaderFollower(client, {
      chain: CHAIN,
      recheck: {
        source: {
          async newest() {
            return [
              record('r-1', `${CHAIN}@99:${hash('block 99')}`),
              record('r-2', planted),
              record('r-3', planted),
              record('r-4', null),
              record('r-5', `eip155:1@5:${hash('another chain')}`),
            ];
          },
        },
        report: (event) => reported.push(event),
      },
    });
    await follower.refresh();
    expect(reported).toEqual([
      { type: 'freshness_reference_invalid', evidenceId: 'r-2', reference: planted },
      { type: 'freshness_reference_invalid', evidenceId: 'r-3', reference: planted },
    ]);
  });

  it('refuses a greatest age that is not a positive number', () => {
    expect(() => new HeaderFollower(null, { chain: CHAIN, maxAgeMs: 0 })).toThrow(RangeError);
  });

  it('freshnessRowStoreFor finds the row only on a store that has it', () => {
    expect(freshnessRowStoreFor({})).toBeUndefined();
    expect(freshnessRowStoreFor({ writeAnchorFreshness: async () => {}, readAnchorFreshness: async () => null })).toBeDefined();
  });
});
