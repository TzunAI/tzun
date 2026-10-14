/**
 * `b1` proof bundles against a real EVM node (anvil, one container for the
 * suite; Bundle §3, §4; Verification §3.1): records anchored by
 * `Tzun.init({ anchoring })`'s scheduler, exported with `exportBundle()`, and
 * verified with `verifyBundle()` and nothing else, the auditor's header
 * source reading the node over JSON-RPC (`RpcEvmHeaderSource`), with and
 * without its own transaction lookup.
 *
 * vectors/bundle-b1/ is generated from the same kind of run
 * (scripts/generate-bundle-b1-corpus.ts); this suite keeps the exporter and
 * the verifier exercised against a node in CI.
 *
 * Skipped, loudly, where Docker cannot run containers, when
 * TZUN_SKIP_ANVIL=1, and under CI unless TZUN_ANVIL=1 (harness.ts).
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { TzunConfig } from '@tzun/engine';
import { Tzun, verifyBundle, bundleExitCode, RpcEvmHeaderSource, type EvmHeaderSource } from '../../src/sdk';
import { ANVIL_CHAIN_ID, ANVIL_IMAGE, anvilAvailability, startAnvil, type AnvilNode } from './harness';

const CHAIN = `eip155:${ANVIL_CHAIN_ID}`;
const NS = 'test.bundle.anvil.tzun';

const availability = anvilAvailability();
if (!availability.ok) {
  const bar = '!'.repeat(78);
  // eslint-disable-next-line no-console
  console.warn(
    `\n${bar}\n  ANVIL SUITE SKIPPED: ${availability.reason}.\n` +
      `  The proof-bundle export and verification run on anvil (${ANVIL_IMAGE}).\n` +
      `  Run tests/anvil/ where Docker works before calling bundles verified against a node.\n${bar}\n`,
  );
}
const suite = availability.ok ? describe : describe.skip;

suite('b1 proof bundles on anvil', () => {
  jest.setTimeout(300_000);
  let node: AnvilNode;
  let dir: string;
  let tzun: Tzun;

  beforeAll(async () => {
    node = await startAnvil();
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-anvil-bundle-'));
    const publisher = node.devAccount(5);
    tzun = await Tzun.init({
      mode: 'dev',
      dbPath: join(dir, 'store.db'),
      logNamespace: NS,
      anchoring: { publishers: { evm: { rpcUrl: node.rpcUrl, chain: CHAIN, privateKey: publisher.privateKey } }, autoStart: false },
    } as TzunConfig);
  }, 300_000);

  afterAll(async () => {
    await tzun?.close();
    await node?.stop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  async function settle(): Promise<void> {
    for (let i = 0; i < 20; i++) {
      await node.mine(3);
      await tzun.anchorNow();
      const state = (await tzun.getAnchorState())!;
      if (state.lastFinalized && state.inFlight.length === 0 && state.fillBacklog === 0) return;
    }
    throw new Error('the publications did not settle');
  }

  const capture = async (i: number): Promise<string> =>
    (await tzun.capture({ decider: { kind: 'human', id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: `anvil bundle ${i}` })).envelope.payload.evidenceId;

  it('exports an anchored record whose log grew after it, and it verifies end to end against the node (exit 0), and not without it (exit 4)', async () => {
    const first = await capture(1);
    await tzun.anchorNow({ force: true });
    await settle();
    await capture(2);
    await tzun.anchorNow({ force: true });
    await settle();
    const pending = await capture(3);

    const bundle = JSON.parse(JSON.stringify(await tzun.exportBundle(first)));
    const anchorOrigin = (await tzun.getAnchorState())!.anchorOrigin;
    const publisher = node.devAccount(5).address.toLowerCase();
    const manifest = { publishers: { [anchorOrigin]: [{ address: publisher, chain: CHAIN, namespace: 'test' as const }] } };
    const rpc = new RpcEvmHeaderSource(node.provider);
    // The same node with no transaction lookup: the trie proof alone places the transaction.
    const headersOnly: EvmHeaderSource = {
      finality: rpc.finality,
      chainId: () => rpc.chainId(),
      finalizedBlockNumber: () => rpc.finalizedBlockNumber(),
      canonicalBlock: (n) => rpc.canonicalBlock(n),
    };

    for (const source of [rpc, headersOnly]) {
      const report = await verifyBundle(bundle, { publisherManifest: manifest, evmHeaderSources: { [CHAIN]: source } });
      expect(report.checks.filter((c) => c.outcome === 'checked-wrong')).toEqual([]);
      for (const id of ['anchor', 'anchor.evm.tx[0]', 'anchor.evm.canonical[0]', 'anchor.newer']) {
        expect(report.checks.find((c) => c.id === id)).toMatchObject({ outcome: 'checked-correct' });
      }
      expect(report.checks.find((c) => c.id === 'anchor.evm.canonical[0]')?.facts).toMatchObject({ inclusion: 'tx_proof', finality: 'finalized' });
      expect(report.checks.filter((c) => c.id.startsWith('anchor.consistency['))).toEqual([
        expect.objectContaining({ outcome: 'checked-correct' }),
        expect.objectContaining({ outcome: 'checked-correct' }),
      ]);
      expect(report.summary).toMatchObject({ anchorOriginAuthenticated: true, anchorNamespace: 'test', existedBy: { source: 'evm-calldata', check: 'anchor' } });
      expect(bundleExitCode(report)).toBe(0);
    }

    const offline = await verifyBundle(bundle);
    expect(offline.checks.find((c) => c.id === 'anchor')).toMatchObject({ outcome: 'not-checked', reason: 'publication_not_checked' });
    expect(bundleExitCode(offline)).toBe(4);

    const unanchored = await verifyBundle(await tzun.exportBundle(pending), { publisherManifest: manifest, evmHeaderSources: { [CHAIN]: rpc } });
    expect(unanchored.checks.find((c) => c.id === 'anchor.pending')).toEqual({ id: 'anchor.pending', outcome: 'not-checked', reason: 'not_yet_published' });
    expect(bundleExitCode(unanchored)).toBe(4);
  });
});
