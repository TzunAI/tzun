/**
 * The anchor scheduler against a real EVM node (anvil, one container for the
 * suite): one transaction per epoch, crash recovery, confirmation, forced
 * passes, heavy material and wallet accounting (Anchor §5, §6, §7.2, §11), the
 * history check, and the end-to-end check that the SDK's own `verifyAnchor`
 * accepts a record captured by `Tzun.capture()`, anchored and filled by the
 * scheduler.
 *
 * Skipped, loudly, where Docker cannot run containers, when
 * TZUN_SKIP_ANVIL=1, and under CI unless TZUN_ANVIL=1 (harness.ts,
 * `anvilAvailability`). See harness.ts for what anvil's `finalized` tag is
 * and is not.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { Transaction, type Wallet } from 'ethers';
import type { EvidenceEnvelope } from '@tzun/engine';
import { Tzun, verifyAnchor, RpcEvmHeaderSource, verifyEvmPublication } from '../../src/sdk';
import { ClosureSigner } from '../ts/helpers/closure-signer';
import { highSSigner } from '../ts/helpers/signer-faults';
import { readEvmTransaction } from '../../src/attestation/blockchain';
import { withLowS } from '../../src/anchoring/evm-chain';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { anchorStoreFor, type AnchorPublication } from '../../src/storage/log-store';
import { AnchorForceRateLimitedError, createAnchorScheduler, type AnchorScheduler, type AnchorSchedulerOptions } from '../../src/anchoring';
import { ANVIL_CHAIN_ID, ANVIL_IMAGE, anvilAvailability, removeStaleAnvils, startAnvil, type AnvilNode } from './harness';

const CHAIN = `eip155:${ANVIL_CHAIN_ID}`;
const NS = 'test.anvil.tzun';
const HOUR = 60 * 60_000;
const MIN = 60_000;
const GWEI = 1_000_000_000n;
const REPO = join(__dirname, '..', '..');

/** How the publisher's key is given: the SDK holds it, or an external signer does. */
type KeyKind = 'privateKey' | 'signer';
const KEY_KINDS: KeyKind[] = ['privateKey', 'signer'];

const availability = anvilAvailability();
if (!availability.ok) {
  const bar = '!'.repeat(78);
  // eslint-disable-next-line no-console
  console.warn(
    `\n${bar}\n  ANVIL SUITE SKIPPED: ${availability.reason}.\n` +
      `  The scheduler's chain tests and the end-to-end verifyAnchor check run on anvil (${ANVIL_IMAGE}).\n` +
      `  Run tests/anvil/ where Docker works before calling the anchor scheduler tested.\n${bar}\n`,
  );
}
const suite = availability.ok ? describe : describe.skip;

suite('the anvil harness', () => {
  jest.setTimeout(300_000);
  const run = (owner: string): string => {
    const r = spawnSync(
      'docker',
      ['run', '-d', '--label', 'tzun-anvil-suite=1', '--label', `tzun-anvil-owner=${owner}`, '--entrypoint', 'sleep', ANVIL_IMAGE, '300'],
      { encoding: 'utf8', timeout: 300_000 },
    );
    if (r.status !== 0) throw new Error(`docker run failed: ${r.stderr}`);
    return r.stdout.trim();
  };
  const exists = (id: string): boolean =>
    spawnSync('docker', ['ps', '-aq', '--no-trunc', '--filter', `id=${id}`], { encoding: 'utf8' }).stdout.trim() !== '';

  it('removes a container whose owner on this host has exited, and leaves a live owner\'s alone (review: killed jest runs)', () => {
    const dead = spawnSync(process.execPath, ['-e', '0']).pid;
    const orphan = run(`${hostname()}:${dead}`);
    const mine = run(`${hostname()}:${process.pid}`);
    try {
      const removed = removeStaleAnvils();
      expect(removed.some((id) => orphan.startsWith(id) || id.startsWith(orphan.slice(0, 12)))).toBe(true);
      expect(exists(orphan)).toBe(false);
      expect(exists(mine)).toBe(true);
    } finally {
      spawnSync('docker', ['rm', '-fv', orphan, mine], { encoding: 'utf8' });
    }
  });
});

suite('the anchor scheduler on anvil', () => {
  jest.setTimeout(300_000);
  let node: AnvilNode;
  let dir: string;
  let offset = 0;
  const clock = (): number => Date.now() + offset;
  const open: Array<{ close(): Promise<void> }> = [];
  const schedulers: AnchorScheduler[] = [];

  beforeAll(async () => {
    node = await startAnvil();
  }, 300_000);

  afterAll(async () => {
    await node?.stop();
  });

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-anvil-'));
    offset = 0;
  });

  afterEach(async () => {
    for (const s of schedulers.splice(0)) await s.close().catch(() => undefined);
    for (const o of open.splice(0)) await o.close().catch(() => undefined);
    await node.setAutomine(true);
    await node.setNextBaseFee(GWEI);
    await node.mine(1);
    rmSync(dir, { recursive: true, force: true });
  });

  /** A store minted in the test namespace, with `n` records on each chain captured through Tzun.capture(). */
  async function storeWith(chains: Record<string, number>): Promise<string> {
    const file = join(dir, `store-${Object.keys(chains).join('-')}-${Date.now()}.db`);
    await new SqliteStorageAdapter(file, { logNamespace: NS }).close();
    await capture(file, chains);
    return file;
  }

  async function capture(file: string, chains: Record<string, number>): Promise<void> {
    for (const [chainId, n] of Object.entries(chains)) {
      const tzun = await Tzun.init({ mode: 'dev', dbPath: file, chainId });
      for (let i = 0; i < n; i++) {
        await tzun.capture({ decider: { kind: 'human', id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { chainId, i, at: Date.now() }, action: 'approved', reason: 'reviewed', aiSystemId: 'anvil-suite' });
      }
      await tzun.close();
    }
  }

  async function scheduler(
    file: string,
    publisher: { privateKey: string },
    extra: Partial<AnchorSchedulerOptions> = {},
    kind: KeyKind = 'privateKey',
  ): Promise<{ s: AnchorScheduler; adapter: SqliteStorageAdapter }> {
    const adapter = new SqliteStorageAdapter(file);
    open.push(adapter);
    const evm =
      kind === 'signer'
        ? { rpcUrl: node.rpcUrl, signer: new ClosureSigner(publisher.privateKey), chain: CHAIN }
        : { rpcUrl: node.rpcUrl, privateKey: publisher.privateKey, chain: CHAIN };
    const s = await createAnchorScheduler({
      storage: adapter,
      clock,
      // Tzun.capture() here runs with no attestation configured.
      expectation: {},
      ...extra,
      config: { ...(extra.config ?? {}), publishers: { evm } },
    });
    schedulers.push(s);
    return { s, adapter };
  }

  const publications = async (adapter: SqliteStorageAdapter): Promise<AnchorPublication[]> =>
    anchorStoreFor(adapter)!.listAnchorPublications({ kind: 'evm-calldata/1' });

  async function settle(s: AnchorScheduler, adapter: SqliteStorageAdapter): Promise<void> {
    for (let i = 0; i < 10; i++) {
      await node.mine(3);
      await s.runPass();
      const pubs = await publications(adapter);
      if (pubs.length > 0 && pubs.every((p) => p.state === 'finalized' || p.state === 'superseded') && (await s.getAnchorState()).fillBacklog === 0) return;
    }
    throw new Error('the publications did not settle');
  }

  const nonceOf = async (address: string): Promise<number> => Number(BigInt(await node.rpc<string>('eth_getTransactionCount', [address, 'latest'])));

  it('3 chains x 50 captures: one transaction whose calldata is P; filled records verify end to end (Anchor §5, §6, §7.2, §11)', async () => {
    const file = await storeWith({ alpha: 50, beta: 50, gamma: 50 });
    const publisher = await node.fundedWallet();
    const { s, adapter } = await scheduler(file, publisher);
    offset = HOUR;
    const report = await s.runPass();
    expect(report.epoch).toMatchObject({ members: 3, anchorSize: 3 });
    expect(await nonceOf(publisher.address)).toBe(1);

    const [pub] = await publications(adapter);
    const tx = Transaction.from(pub.attempts[0].rawTx);
    expect(tx).toMatchObject({ type: 2, chainId: ANVIL_CHAIN_ID, value: 0n, data: `0x${pub.p}` });
    expect(tx.to?.toLowerCase()).toBe(publisher.address.toLowerCase());
    expect(tx.from?.toLowerCase()).toBe(publisher.address.toLowerCase());
    const onChain = await node.rpc<{ input: string; from: string }>('eth_getTransactionByHash', [pub.attempts[0].txHash]);
    expect(onChain.input).toBe(`0x${pub.p}`);

    await settle(s, adapter);
    expect(await nonceOf(publisher.address)).toBe(1);
    const [done] = await publications(adapter);
    // EIP-7623: 32 bytes of calldata cost the floor, 21,000 + 10 per token,
    // a zero byte one token and any other four: 22,280 when P has no zero
    // byte, 30 less for each one it has.
    const tokens = Buffer.from(done.p, 'hex').reduce((n, b) => n + (b === 0 ? 1 : 4), 0);
    expect(done).toMatchObject({ state: 'finalized', gasUsed: String(21_000 + 10 * tokens) });
    expect(done.blockHeader).toMatch(/^0x/);
    expect(done.txTrieProof!.length).toBeGreaterThan(0);

    const state = await s.getAnchorState();
    const records = await adapter.list({ chainId: 'beta' });
    expect(records).toHaveLength(50);
    const env = records[17] as EvidenceEnvelope;
    const headerSource = new RpcEvmHeaderSource(node.provider as never, { finality: 'finalized' });
    const manifest = { publishers: { [state.anchorOrigin]: [{ address: publisher.address, chain: CHAIN, namespace: 'test' as const }] } };
    const common = {
      sequenceNumber: env.payload.sequenceNumber,
      chainId: 'beta',
      publisherManifest: manifest,
      evmHeaderSources: { [CHAIN]: headerSource },
      evmNetworks: { [CHAIN]: 'testnet' as const },
    };
    // The envelope alone carries no signed transaction: the publication is
    // not checked, and nothing is false.
    const bare = await verifyAnchor(env.nonRepudiation, env.integrity.canonicalDigest, common);
    expect(bare).toMatchObject({ anchorValid: null, merkleProofValid: true, anchorReason: 'publication_not_checked' });

    // With the raw transaction: the header source places it.
    const withRaw = await verifyAnchor(env.nonRepudiation, env.integrity.canonicalDigest, {
      ...common,
      publicationMaterial: [{ kind: 'evm-calldata/1', rawTransaction: done.attempts[0].rawTx, blockNumber: done.blockNumber, blockHash: done.blockHash }],
    });
    expect(withRaw).toMatchObject({ anchorValid: true, merkleProofValid: true, anchorOriginAuthenticated: true, anchorPublication: 'evm-calldata', anchorNamespace: 'test', anchorNetwork: 'testnet' });
    expect(withRaw.anchorPosition).toMatchObject({ leafIndex: env.payload.sequenceNumber - 1, treeSize: 50, anchorSize: 3, chainChecked: true, leafIndexChecked: true });
    expect(withRaw.publications[0].evm?.inclusion).toBe('header_source');

    // With the stored heavy material: the trie proof places it.
    const material = {
      kind: 'evm-calldata/1' as const,
      rawTransaction: done.attempts[0].rawTx,
      blockNumber: done.blockNumber!,
      blockHash: done.blockHash!,
      blockHeader: done.blockHeader!,
      txIndex: done.txIndex!,
      txProof: done.txTrieProof!,
    };
    const bundled = await verifyAnchor(env.nonRepudiation, env.integrity.canonicalDigest, { ...common, publicationMaterial: [material] });
    expect(bundled.anchorValid).toBe(true);
    expect(bundled.publications[0].evm?.inclusion).toBe('tx_proof');

    // Offline, from the bundle alone: the transaction facts hold; canonicality is not claimed.
    const offline = await verifyEvmPublication({ publication: { ...material, transactionId: done.minedTxHash! }, p: done.p, anchorOrigin: state.anchorOrigin, manifest });
    expect(offline.checks.tx.outcome).toBe('checked-correct');
    expect(offline.valid).toBeNull();

    // A record from each chain carries its own chain's log.
    for (const chainId of ['alpha', 'gamma']) {
      const [first] = await adapter.list({ chainId });
      const v = await verifyAnchor((first as EvidenceEnvelope).nonRepudiation, (first as EvidenceEnvelope).integrity.canonicalDigest, {
        ...common,
        chainId,
        sequenceNumber: (first as EvidenceEnvelope).payload.sequenceNumber,
        publicationMaterial: [material],
      });
      expect(v.anchorValid).toBe(true);
    }
  });

  it.each(KEY_KINDS)('Tzun.init({ logNamespace, anchoring }) anchors its own captures; get() and verify() follow them (Anchor §10.9; key: %s)', async (kind) => {
    const publisher = await node.fundedWallet();
    const evm =
      kind === 'signer'
        ? { rpcUrl: node.rpcUrl, chain: CHAIN, signer: new ClosureSigner(publisher.privateKey) }
        : { rpcUrl: node.rpcUrl, chain: CHAIN, privateKey: publisher.privateKey };
    const tzun = await Tzun.init({
      mode: 'dev',
      dbPath: join(dir, `wired-${kind}.db`),
      chainId: 'wired',
      logNamespace: NS,
      anchoring: { publishers: { evm }, autoStart: false },
    });
    open.push(tzun);
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) ids.push((await tzun.capture({ decider: { kind: 'human', id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: 'wired', aiSystemId: 'anvil-suite' })).envelope.payload.evidenceId);
    const waiting = (await tzun.get(ids[1]))!;
    expect(waiting.envelope.attestationStatus).toBe('pending');
    expect(waiting.anchorState).toMatchObject({ state: 'awaiting_epoch', anchorReason: 'anchor_not_yet_published' });
    expect(typeof waiting.anchorState!.dueBy).toBe('string');

    const report = await tzun.anchorNow({ force: true });
    expect(report.epoch).toMatchObject({ members: 1, forced: true });
    for (let i = 0; i < 10; i++) {
      await node.mine(3);
      await tzun.anchorNow();
      const state = (await tzun.getAnchorState())!;
      if (state.lastFinalized && state.inFlight.length === 0 && state.fillBacklog === 0) break;
    }
    const state = (await tzun.getAnchorState())!;
    expect(state).toMatchObject({ namespace: 'test', publisher: publisher.address.toLowerCase(), wallet: { enrolled: true, nonceBase: 0 } });
    expect(BigInt(state.spentWei)).toBeGreaterThan(0n);
    expect(await nonceOf(publisher.address)).toBe(1);

    const anchored = (await tzun.get(ids[1]))!;
    expect(anchored.anchorState).toMatchObject({ state: 'anchored' });
    expect(anchored.envelope.attestationStatus).toBe('partial');
    const manifest = { publishers: { [state.anchorOrigin]: [{ address: publisher.address, chain: CHAIN, namespace: 'test' as const }] } };
    const verified = await tzun.verify(ids[1], undefined, {
      anchor: { publisherManifest: manifest, evmHeaderSources: { [CHAIN]: new RpcEvmHeaderSource(node.provider as never, { finality: 'finalized' }) } },
    });
    expect(verified).toMatchObject({
      verified: true,
      anchorValid: true,
      anchorNamespace: 'test',
      anchorFinality: 'finalized',
      existedBy: { source: 'evm-calldata' },
    });
    expect(verified).not.toHaveProperty('anchorReason');
  });

  it('an external signer that returns a high s: the transaction mined is its signature with n - s, which every rule of tzun-anchor/1 §10.4 item 2 reads, and the anchor verifies', async () => {
    const publisher = await node.fundedWallet();
    const signer = highSSigner(new ClosureSigner(publisher.privateKey));
    const tzun = await Tzun.init({
      mode: 'dev',
      dbPath: join(dir, 'high-s.db'),
      chainId: 'high-s',
      logNamespace: NS,
      anchoring: { publishers: { evm: { rpcUrl: node.rpcUrl, chain: CHAIN, signer } }, autoStart: false },
    });
    open.push(tzun);
    const id = (await tzun.capture({ decider: { kind: 'human', id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { highS: true }, action: 'approved', reason: 'high s', aiSystemId: 'anvil-suite' })).envelope.payload.evidenceId;
    await tzun.anchorNow({ force: true });
    for (let i = 0; i < 10; i++) {
      await node.mine(3);
      await tzun.anchorNow();
      const state = (await tzun.getAnchorState())!;
      if (state.lastFinalized && state.inFlight.length === 0 && state.fillBacklog === 0) break;
    }
    const state = (await tzun.getAnchorState())!;
    expect(state.alarms).toEqual([]);
    expect(signer.returned).toHaveLength(1);
    // What the signer returned, a verifier refuses; what was mined, it reads, with the publisher as sender.
    expect(readEvmTransaction(signer.returned[0])).toEqual({ ok: false, rule: 'signature-values' });
    const [publication] = await anchorStoreFor(tzun.getStorage())!.listAnchorPublications({ kind: 'evm-calldata/1' });
    expect(publication.state).toBe('finalized');
    const mined = await node.rpc<string>('eth_getRawTransactionByHash', [publication.minedTxHash]);
    expect(mined.toLowerCase()).toBe(withLowS(signer.returned[0]));
    const reading = readEvmTransaction(mined);
    expect(reading.ok && reading.transaction.sender).toBe(publisher.address.toLowerCase());

    const manifest = { publishers: { [state.anchorOrigin]: [{ address: publisher.address, chain: CHAIN, namespace: 'test' as const }] } };
    expect(
      await tzun.verify(id, undefined, {
        anchor: { publisherManifest: manifest, evmHeaderSources: { [CHAIN]: new RpcEvmHeaderSource(node.provider as never, { finality: 'finalized' }) } },
      }),
    ).toMatchObject({ verified: true, anchorValid: true });
  });

  it.each(KEY_KINDS)('a process killed right after broadcast restarts to finalize the same transaction, never a second (key: %s)', async (kind) => {
    const file = await storeWith({ alpha: 5 });
    const devIndex = kind === 'signer' ? 8 : 7;
    const publisher = node.devAccount(devIndex);
    const before = await nonceOf(publisher.address);
    await node.setAutomine(false);
    const child = spawnSync(join(REPO, 'node_modules', '.bin', 'tsx'), [join(REPO, 'tests', 'anvil', 'crash-child.ts'), file, node.rpcUrl, String(devIndex), kind], {
      cwd: REPO,
      encoding: 'utf8',
      timeout: 120_000,
    });
    expect(child.stdout).toContain('broadcast');
    expect(child.stdout).not.toContain('without the hook');
    expect(child.signal === 'SIGKILL' || child.status === 137).toBe(true);

    await new Promise((r) => setTimeout(r, 1_200)); // the dead process's 1 s lease expires
    const { s, adapter } = await scheduler(file, publisher, { holderId: 'restarted' }, kind);
    const [persisted] = await publications(adapter);
    expect(persisted).toMatchObject({ state: 'submitted', nonce: before });
    expect(persisted.attempts).toHaveLength(1);
    expect(persisted.attempts[0].broadcast).toBe('unknown');

    // The node still holds it: the rebroadcast of the identical bytes is "already known".
    const report = await s.runPass();
    expect(report.broadcasts).toEqual([expect.objectContaining({ txHash: persisted.attempts[0].txHash, outcome: 'accepted' })]);
    await node.setAutomine(true);
    await settle(s, adapter);
    const [done] = await publications(adapter);
    expect(done.state).toBe('finalized');
    expect(done.minedTxHash).toBe(persisted.attempts[0].txHash);
    expect(done.attempts).toHaveLength(1);
    expect(await nonceOf(publisher.address)).toBe(before + 1);
  });

  describe('confirmation', () => {
    async function submittedOn(
      extra: Partial<AnchorSchedulerOptions> = {},
      kind: KeyKind = 'privateKey',
    ): Promise<{ s: AnchorScheduler; adapter: SqliteStorageAdapter; publisher: Wallet; pub: AnchorPublication }> {
      const file = await storeWith({ alpha: 3 });
      const publisher = await node.fundedWallet();
      await node.setAutomine(false);
      const { s, adapter } = await scheduler(file, publisher, { tuning: { stuckAfterMs: MIN }, ...extra }, kind);
      offset = HOUR;
      await s.runPass();
      const [pub] = await publications(adapter);
      expect(pub.state).toBe('submitted');
      return { s, adapter, publisher, pub };
    }

    it('an evicted transaction comes back unchanged', async () => {
      const { s, adapter, pub } = await submittedOn();
      await node.rpc('anvil_dropTransaction', [pub.attempts[0].txHash]);
      expect(await node.rpc('eth_getTransactionByHash', [pub.attempts[0].txHash])).toBeNull();
      const report = await s.runPass();
      expect(report.broadcasts).toEqual([expect.objectContaining({ txHash: pub.attempts[0].txHash, outcome: 'accepted', reason: 'ok' })]);
      await node.setAutomine(true);
      await settle(s, adapter);
      expect((await publications(adapter))[0]).toMatchObject({ state: 'finalized', minedTxHash: pub.attempts[0].txHash });
    });

    it.each(KEY_KINDS)('a stuck transaction is replaced: same nonce, same calldata, +12.5% each time, at most 5, then anchor_tx_stuck (key: %s)', async (kind) => {
      const { s, adapter, pub } = await submittedOn({}, kind);
      // The next block's base fee jumps far above what the attempt pays: it stays unmined.
      await node.setNextBaseFee(40n * GWEI);
      await node.mine(1);
      const alarms: string[] = [];
      for (let i = 0; i < 7; i++) {
        offset += 2 * MIN;
        alarms.push(...(await s.runPass()).alarms.map((a) => a.code));
      }
      const [stuck] = await publications(adapter);
      expect(stuck.attempts).toHaveLength(6);
      const txs = stuck.attempts.map((a) => Transaction.from(a.rawTx));
      expect(new Set(txs.map((t) => t.nonce))).toEqual(new Set([pub.nonce]));
      expect(new Set(txs.map((t) => t.data))).toEqual(new Set([`0x${pub.p}`]));
      for (let i = 1; i < txs.length; i++) {
        expect(txs[i].maxFeePerGas).toBe((txs[i - 1].maxFeePerGas! * 1125n + 999n) / 1000n);
        expect(txs[i].maxPriorityFeePerGas).toBe((txs[i - 1].maxPriorityFeePerGas! * 1125n + 999n) / 1000n);
      }
      expect(alarms).toContain('anchor_tx_stuck');

      // The fee falls back: one of the attempts mines, and nothing else from the wallet does.
      await node.setNextBaseFee(GWEI / 10n);
      await node.setAutomine(true);
      await settle(s, adapter);
      const [done] = await publications(adapter);
      expect(done.state).toBe('finalized');
      expect(stuck.attempts.map((a) => a.txHash)).toContain(done.minedTxHash);
    });

    it('replacements are clamped to the hard cap, and stop when the clamp leaves under 10%', async () => {
      // Base fee 1 gwei and a 1 gwei tip: the first attempt pays 3 gwei; 3.375
      // and 3.797 follow; 4.271 is clamped to the 4 gwei cap, a 5% bump a node
      // refuses, so the third replacement is never signed.
      const { s, adapter } = await submittedOn({ config: { publishers: {}, budget: { hardFeeCapGwei: 4, softMaxFeeGwei: 2.5 } } as never });
      await node.setNextBaseFee(40n * GWEI);
      await node.mine(1);
      const alarms: string[] = [];
      for (let i = 0; i < 6; i++) {
        offset += 2 * MIN;
        alarms.push(...(await s.runPass()).alarms.map((a) => a.code));
      }
      const [stuck] = await publications(adapter);
      expect(stuck.attempts).toHaveLength(3);
      for (const a of stuck.attempts) expect(BigInt(a.maxFeePerGas)).toBeLessThanOrEqual(4n * GWEI);
      expect(alarms).toContain('anchor_tx_stuck');
    });

    it('a reorg returns an included transaction to submitted; it is rebroadcast and finalized in the new chain', async () => {
      const file = await storeWith({ alpha: 3 });
      const publisher = await node.fundedWallet();
      await node.setAutomine(false);
      const snapshot = await node.rpc<string>('evm_snapshot');
      const { s, adapter } = await scheduler(file, publisher);
      offset = HOUR;
      await s.runPass();
      await node.mine(1);
      await s.runPass();
      const [included] = await publications(adapter);
      expect(included.state).toBe('included');
      await node.rpc('evm_revert', [snapshot]);
      const report = await s.runPass();
      expect(report.transitions).toContainEqual({ publicationId: included.id, from: 'included', to: 'submitted' });
      expect(report.broadcasts[0]).toMatchObject({ txHash: included.attempts[0].txHash, outcome: 'accepted' });
      await node.setAutomine(true);
      await node.mine(1);
      await settle(s, adapter);
      const [done] = await publications(adapter);
      expect(done.state).toBe('finalized');
      expect(done.minedTxHash).toBe(included.minedTxHash);
    });

    it('a transaction from the wallet that is not the store\'s raises anchor_nonce_consumed_externally', async () => {
      const { s, publisher, pub } = await submittedOn();
      await node.rpc('anvil_dropTransaction', [pub.attempts[0].txHash]);
      const foreign = await publisher.connect(node.provider).sendTransaction({ to: publisher.address, value: 0n, data: '0xdead', nonce: pub.nonce! });
      await node.mine(1);
      expect((await node.rpc<{ blockHash: string | null }>('eth_getTransactionByHash', [foreign.hash])).blockHash).not.toBeNull();
      const report = await s.runPass();
      expect(report.alarms.map((a) => a.code)).toContain('anchor_nonce_consumed_externally');
      expect(report.halted).toBe(true);
    });
  });

  it('a "finalized" block that anvil reverts is caught by the history check: anchor_history_mismatch', async () => {
    const file = await storeWith({ alpha: 3 });
    const publisher = await node.fundedWallet();
    const snapshot = await node.rpc<string>('evm_snapshot');
    const { s, adapter } = await scheduler(file, publisher);
    offset = HOUR;
    await s.runPass();
    await settle(s, adapter);
    const [pub] = await publications(adapter);
    expect(await node.finalized()).toBeGreaterThanOrEqual(pub.blockNumber!);
    // anvil can revert below its finalized tag; a real chain cannot.
    await node.rpc('evm_revert', [snapshot]);
    await node.mine(6);
    await capture(file, { alpha: 1 });
    offset += 2 * HOUR;
    const report = await s.runPass();
    expect(report.halted).toBe(true);
    expect(report.alarms.map((a) => a.code)).toContain('anchor_history_mismatch');
  });

  it('anchorNow({ force: true }) is limited to 6 per rolling 24 hours', async () => {
    const file = await storeWith({ alpha: 1 });
    const publisher = await node.fundedWallet();
    const { s, adapter } = await scheduler(file, publisher);
    for (let i = 0; i < 6; i++) {
      if (i > 0) await capture(file, { alpha: 1 });
      const report = await s.anchorNow({ force: true });
      expect(report.epoch).toMatchObject({ forced: true });
    }
    await capture(file, { alpha: 1 });
    await expect(s.anchorNow({ force: true })).rejects.toBeInstanceOf(AnchorForceRateLimitedError);
    expect((await s.getAnchorState()).force).toEqual({ usedInLast24h: 6, limit: 6 });
    expect(await nonceOf(publisher.address)).toBe(6);
    await settle(s, adapter);
  });

  it.each(KEY_KINDS)('a wallet with 3 earlier transactions enrols at nonce 3; accounting stays clean through an anchor and a sweep (Anchor §7.2; key: %s)', async (kind) => {
    const file = await storeWith({ alpha: 2 });
    const publisher = await node.fundedWallet();
    const signer = publisher.connect(node.provider);
    for (let i = 0; i < 3; i++) await (await signer.sendTransaction({ to: publisher.address, value: 0n, nonce: i })).wait();
    const { s, adapter } = await scheduler(file, publisher, {}, kind);
    offset = HOUR;
    await s.runPass();
    await settle(s, adapter);
    expect((await s.getAnchorState()).wallet.nonceBase).toBe(3);
    expect(await s.accountNonces()).toMatchObject({ nonceBase: 3, transactionCount: 4, unaccounted: [] });

    const treasury = node.devAccount(9).address;
    const treasuryBefore = BigInt(await node.rpc<string>('eth_getBalance', [treasury, 'latest']));
    const swept = await s.sweep(treasury);
    expect(swept.tx).toMatchObject({ kind: 'sweep', nonce: 4 });
    await node.mine(1);
    const accounting = await s.accountNonces();
    expect(accounting.unaccounted).toEqual([]);
    expect(accounting.accounted.map((a) => [a.nonce, a.kind])).toEqual([
      [3, 'publication'],
      [4, 'sweep'],
    ]);
    expect(BigInt(await node.rpc<string>('eth_getBalance', [treasury, 'latest']))).toBeGreaterThan(treasuryBefore);
  });
});
