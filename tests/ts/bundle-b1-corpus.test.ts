/**
 * The b1 bundle corpus (vectors/bundle-b1/; Bundle §13, Specs §6 item 2),
 * replayed by the TypeScript SDK: for every case, `verifyBundle()` over `bundle.json` with
 * the auditor's inputs of `inputs.json` must produce exactly
 * `expected-report.json` (compared in DEO canonical form, without
 * `checkedAt`), and `bundleExitCode()` under the case's regime must be
 * `expected-exit`.
 *
 * The expected reports were stated from the spec by
 * scripts/generate-bundle-b1-corpus.ts, not recorded from this verifier. When
 * this suite and a case disagree, the spec decides, and a change to an
 * expected report cites the section that moved it.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalSerialize } from '@tzun/engine';
import { bundleExitCode, verifyBundle, type BundleExitOptions, type EvmHeaderSource, type VerifyBundleOptions } from '../../src/sdk/index';

const DIR = join(__dirname, '..', '..', 'vectors', 'bundle-b1');
const FILES = ['bundle.json', 'inputs.json', 'expected-report.json', 'expected-exit'];

interface HeaderSourceSpec {
  chainId: number;
  finality: 'finalized';
  finalizedBlockNumber: number;
  blocks: Array<{ number: number; hash: string; timestamp: number }>;
}

interface Inputs {
  publisherManifest: VerifyBundleOptions['publisherManifest'] | null;
  headerSources: Record<string, HeaderSourceSpec>;
  trustAnchorsPem: string[];
  regime: Required<BundleExitOptions>;
}

/** The static header source an inputs file describes: its chain id, finality, finalized height and the canonical blocks it knows. */
function headerSource(spec: HeaderSourceSpec): EvmHeaderSource {
  return {
    finality: spec.finality,
    chainId: async () => BigInt(spec.chainId),
    finalizedBlockNumber: async () => spec.finalizedBlockNumber,
    canonicalBlock: async (n) => {
      const block = spec.blocks.find((b) => b.number === n);
      return block ? { hash: block.hash, timestamp: block.timestamp } : null;
    },
  };
}

const read = (name: string, file: string) => readFileSync(join(DIR, name, file), 'utf8');
const canonical = (value: Record<string, unknown>) => canonicalSerialize(value, Object.keys(value));

const index = JSON.parse(readFileSync(join(DIR, 'index.json'), 'utf8')) as { cases: Array<{ name: string; exit: number; description: string }> };

describe('vectors/bundle-b1 (Bundle §13)', () => {
  const saved = { anchors: process.env.TZUN_TSA_TRUST_ANCHORS, authorities: process.env.TZUN_TSA_AUTHORITIES };
  beforeAll(() => {
    // Trust comes only from each case's inputs.
    delete process.env.TZUN_TSA_TRUST_ANCHORS;
    delete process.env.TZUN_TSA_AUTHORITIES;
  });
  afterAll(() => {
    if (saved.anchors !== undefined) process.env.TZUN_TSA_TRUST_ANCHORS = saved.anchors;
    if (saved.authorities !== undefined) process.env.TZUN_TSA_AUTHORITIES = saved.authorities;
  });

  it('lists every case directory, and every case holds its four files', () => {
    const dirs = readdirSync(DIR).filter((e) => statSync(join(DIR, e)).isDirectory()).sort();
    expect(index.cases.map((c) => c.name).sort()).toEqual(dirs);
    for (const name of dirs) {
      expect(readdirSync(join(DIR, name)).sort()).toEqual([...FILES].sort());
      expect(read(name, 'expected-exit')).toMatch(/^[0-4]\n$/);
    }
    // Every exit code of Verification §6.6 is exercised.
    expect(new Set(index.cases.map((c) => c.exit))).toEqual(new Set([0, 1, 2, 3, 4]));
  });

  it.each(index.cases.map((c) => [c.name, c] as const))('%s', async (name, meta) => {
    const bundle = JSON.parse(read(name, 'bundle.json')) as unknown;
    const inputs = JSON.parse(read(name, 'inputs.json')) as Inputs;
    const expected = JSON.parse(read(name, 'expected-report.json')) as Record<string, unknown>;
    const exit = Number(read(name, 'expected-exit').trim());
    expect(exit).toBe(meta.exit);

    const report = await verifyBundle(bundle, {
      ...(inputs.publisherManifest !== null && { publisherManifest: inputs.publisherManifest }),
      evmHeaderSources: Object.fromEntries(Object.entries(inputs.headerSources).map(([chain, spec]) => [chain, headerSource(spec)])),
      ...(inputs.trustAnchorsPem.length > 0 && { trustAnchorsPem: inputs.trustAnchorsPem }),
    });
    const { checkedAt, ...actual } = report;
    expect(Date.parse(checkedAt)).not.toBeNaN();
    expect(actual).toEqual(expected);
    expect(canonical(actual as unknown as Record<string, unknown>)).toBe(canonical(expected));
    expect(bundleExitCode(report, inputs.regime)).toBe(exit);
  });
});
