/**
 * Cross-SDK harness: a store anchored on anvil, for
 * tests/cross-sdk/test_anchor_anvil_store.py.
 *
 * Starts one anvil container (tests/anvil/harness.ts), makes a SQLite store
 * with `Tzun.init({ logNamespace, anchoring })` on three chains, anchors it in
 * two epochs whose publications share their blocks with other transactions,
 * captures one record after the last epoch, and verifies every record with the
 * TypeScript SDK: from the envelope and the bundle alone, and with an
 * `RpcEvmHeaderSource` reading the node. Then it writes one JSON line:
 *
 *   { rpcUrl, chain, anchorOrigin, manifest,
 *     records: [{ evidenceId, chainId, envelope, material, bundleOnly, withNode }] }
 *
 * `material` is the covering publication's bundle entry (tzun-anchor/1 §9), or
 * null for the record captured after the last epoch. The node stays up until
 * stdin closes, so the Python SDK can ask it the same questions; then the
 * container is removed.
 *
 * Nothing here is a real key: the publisher is anvil's development account 5.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { JsonRpcProvider, Network } from 'ethers';
import type { CaptureInput, EvidenceEnvelope } from '@tzun/engine';
import { Tzun, verifyAnchor } from '../../../src/sdk';
import { RpcEvmHeaderSource } from '../../../src/attestation/blockchain';
import { anchorStoreFor, type AnchorPublication } from '../../../src/storage/log-store';
import { ANVIL_CHAIN_ID, startAnvil, type AnvilNode } from '../../anvil/harness';

const CHAIN = `eip155:${ANVIL_CHAIN_ID}`;
const NS = 'test.cross-sdk.anvil';
const PUBLISHER_ACCOUNT = 5;
const TRAFFIC_ACCOUNT = 6;

const decision = (chainId: string, i: number): CaptureInput => ({
  aiOutput: { recommendation: 'approve', chain: chainId, i },
  action: 'approved',
  reason: `cross-SDK anvil store: ${chainId} #${i}`,
  decider: { kind: 'human', id: 'acct:u-cross-sdk' },
  aiSystemId: 'cross-sdk-anvil-store',
});

async function settle(node: AnvilNode, tzun: Tzun): Promise<void> {
  for (let i = 0; i < 20; i++) {
    await node.mine(3);
    await tzun.anchorNow();
    const state = (await tzun.getAnchorState())!;
    if (state.halted) throw new Error(`anchoring stopped: ${state.halted.code}`);
    if (state.lastFinalized && state.inFlight.length === 0 && state.fillBacklog === 0) return;
  }
  throw new Error('the publications did not settle');
}

/** Publish an epoch in a block it shares with `before` and `after` other transactions. */
async function epochAmongTraffic(node: AnvilNode, tzun: Tzun, before: number, after: number): Promise<void> {
  const traffic = node.devAccount(TRAFFIC_ACCOUNT).connect(node.provider);
  let nonce = Number(BigInt(await node.rpc<string>('eth_getTransactionCount', [traffic.address, 'pending'])));
  const send = async (n: number): Promise<void> => {
    for (let i = 0; i < n; i++) await traffic.sendTransaction({ to: traffic.address, value: 0n, nonce: nonce++ });
  };
  await node.setAutomine(false);
  try {
    await send(before);
    if (!(await tzun.anchorNow({ force: true })).epoch) throw new Error('no epoch was cut');
    await send(after);
    await node.mine(1);
  } finally {
    await node.setAutomine(true);
  }
}

function waitForStdinToClose(): Promise<void> {
  return new Promise((resolve) => {
    process.stdin.on('data', () => undefined);
    process.stdin.on('end', resolve);
    process.stdin.on('close', resolve);
  });
}

async function main(): Promise<void> {
  // stdout carries the answer: anything the SDK logs goes to stderr.
  console.log = (...args: unknown[]) => process.stderr.write(`${args.map(String).join(' ')}\n`);
  const node = await startAnvil();
  const dir = mkdtempSync(join(tmpdir(), 'tzun-test-xsdk-anvil-'));
  const open: Tzun[] = [];
  const provider = new JsonRpcProvider(node.rpcUrl, Network.from(ANVIL_CHAIN_ID), { staticNetwork: true });
  try {
    const publisher = node.devAccount(PUBLISHER_ACCOUNT);
    const file = join(dir, 'store.db');
    const anchoring = { publishers: { evm: { rpcUrl: node.rpcUrl, chain: CHAIN, privateKey: publisher.privateKey } }, autoStart: false };
    const alpha = await Tzun.init({ mode: 'dev', dbPath: file, chainId: 'alpha', logNamespace: NS, anchoring });
    open.push(alpha);
    const on = async (chainId: string): Promise<Tzun> => {
      const t = await Tzun.init({ mode: 'dev', dbPath: file, chainId });
      open.push(t);
      return t;
    };
    const beta = await on('beta');
    const gamma = await on('gamma');
    const captured: Array<{ chainId: string; evidenceId: string }> = [];
    const capture = async (t: Tzun, chainId: string, n: number): Promise<void> => {
      for (let i = 0; i < n; i++) {
        const r = await t.capture(decision(chainId, captured.length + 1));
        captured.push({ chainId, evidenceId: r.envelope.payload.evidenceId });
      }
    };

    await capture(alpha, 'alpha', 3);
    await capture(beta, 'beta', 2);
    await epochAmongTraffic(node, alpha, 7, 5);
    await settle(node, alpha);
    await capture(alpha, 'alpha', 2);
    await capture(gamma, 'gamma', 2);
    await epochAmongTraffic(node, alpha, 3, 2);
    await settle(node, alpha);
    // Captured after the last epoch: never anchored.
    await capture(beta, 'beta', 1);

    const anchors = anchorStoreFor(alpha.getStorage())!;
    const publications = (await anchors.listAnchorPublications({ kind: 'evm-calldata/1', states: ['finalized'] })) as AnchorPublication[];
    const state = (await alpha.getAnchorState())!;
    const manifest = { publishers: { [state.anchorOrigin]: [{ address: publisher.address.toLowerCase(), chain: CHAIN, namespace: 'test' as const }] } };
    const materialFor = (anchorCheckpoint: string) => {
      const size = Number(anchorCheckpoint.split('\n')[1]);
      const pub = publications.find((p) => p.anchorSize === size);
      if (!pub) return null;
      const mined = pub.attempts.find((a) => a.txHash === pub.minedTxHash)!;
      return {
        kind: 'evm-calldata/1',
        chain: pub.chain,
        transactionId: pub.minedTxHash,
        blockNumber: pub.blockNumber,
        blockHash: pub.blockHash,
        publisher: pub.fromAddress,
        rawTransaction: mined.rawTx,
        blockHeader: pub.blockHeader,
        txIndex: pub.txIndex,
        txProof: pub.txTrieProof,
      };
    };

    const nodeSource = new RpcEvmHeaderSource(provider);
    const records = [];
    for (const c of captured) {
      const envelope = (await alpha.get(c.evidenceId))!.envelope as EvidenceEnvelope;
      const anchor = envelope.nonRepudiation.anchor;
      const material = anchor ? materialFor(anchor.anchorCheckpoint) : null;
      const inputs = {
        sequenceNumber: envelope.payload.sequenceNumber,
        chainId: c.chainId,
        publisherManifest: manifest,
        ...(material && { publicationMaterial: [material] }),
      };
      records.push({
        evidenceId: c.evidenceId,
        chainId: c.chainId,
        envelope,
        material,
        bundleOnly: await verifyAnchor(envelope.nonRepudiation, envelope.integrity.canonicalDigest, inputs),
        withNode: await verifyAnchor(envelope.nonRepudiation, envelope.integrity.canonicalDigest, {
          ...inputs,
          evmHeaderSources: { [CHAIN]: nodeSource },
        }),
      });
    }
    process.stdout.write(`${JSON.stringify({ rpcUrl: node.rpcUrl, chain: CHAIN, anchorOrigin: state.anchorOrigin, manifest, records })}\n`);
    await waitForStdinToClose();
  } finally {
    provider.destroy();
    for (const t of open) await t.close().catch(() => undefined);
    await node.stop();
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  process.stderr.write(`${(err as Error).stack ?? err}\n`);
  process.exitCode = 1;
});
