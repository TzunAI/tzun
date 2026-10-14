/**
 * Generate vectors/anchor-e2e-vectors.json (tzun-anchor/1 §13):
 * records anchored end to end on anvil, by `Tzun.init({ logNamespace,
 * anchoring })` and its anchor scheduler, with everything a verifier needs to
 * check them without the SDK: each record's envelope and its
 * `nonRepudiation.anchor`, each epoch's anchor checkpoint, P and the
 * consistency proofs between published sizes, and each epoch's publication
 * with its heavy material (the raw transaction, the block header's RLP, the
 * transaction's index and its transactions-trie proof, tzun-anchor/1 §7.2
 * rule 5), and the canonical block a header source reported.
 *
 *   pnpm exec tsx scripts/generate-anchor-e2e-vectors.ts > vectors/anchor-e2e-vectors.json
 *
 * It needs Docker: one anvil container (tests/anvil/harness.ts), removed when
 * it is done. The publisher is anvil's development account 5 (the well-known
 * test mnemonic), the store's namespace is a `test.` namespace, and nothing
 * here is a real key or freezes anything (tzun-anchor/1 §2).
 *
 * The file is one run's output, not a transcription: its values (store id,
 * digests, P, hashes, block times) change with every run. The expected
 * verdicts are stated from the spec, not taken from the SDK: every record is
 * anchored honestly, so with the manifest and a header source that confirms
 * its block it is `true`, and from the envelope and the bundle alone its EVM
 * publication is not checked. The script then runs the SDK's own verifier
 * over every case and stops if it disagrees. The Go gate
 * (tests/cross-impl/go) re-derives the Merkle half with transparency-dev and
 * the EVM half with go-ethereum, and tests/ts/anchor-e2e-vectors.test.ts
 * holds the SDK to the stated verdicts.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CaptureInput, EvidenceEnvelope } from '@tzun/engine';
import { Tzun, verifyAnchor, type EvmHeaderSource } from '../src/sdk';
import { ANCHOR_LOG_KIND, EVIDENCE_LOG_KIND, anchorStoreFor, logStoreFor, type AnchorPublication, type LogCheckpoint } from '../src/storage/log-store';
import { ANVIL_CHAIN_ID, ANVIL_IMAGE, startAnvil, type AnvilNode } from '../tests/anvil/harness';

const CHAIN = `eip155:${ANVIL_CHAIN_ID}`;
const NS = 'test.vectors.tzun';
const PUBLISHER_ACCOUNT = 5;
/** Another development account, whose transactions share the publication's block, so its trie proof is not a one-leaf trie. */
const TRAFFIC_ACCOUNT = 6;

/** A human's decision under an opaque account id, no freshness reference: the vectors pin anchors, not the decider. */
const decision = (chainId: string, i: number): CaptureInput => ({
  aiOutput: { recommendation: 'approve', chain: chainId, i },
  action: 'approved',
  reason: `anchor e2e vector: ${chainId} #${i}`,
  decider: { kind: 'human', id: 'acct:u-anchor-e2e', agent: null, credential: null, freshness: null },
  aiSystemId: 'anchor-e2e-vectors',
});

/** Mine and pass until every publication is final and filled. */
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

/**
 * Publish an epoch in a block it shares: automine off, `before` transfers
 * from another account, the forced epoch's broadcast, `after` more, then one
 * block holds them all.
 */
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

/** `<origin>\n<size>\n<base64 root>\n`, read by hand (tzun-anchor/1 §4.1). */
function bodyParts(body: string): { origin: string; size: number } {
  const [origin, size] = body.split('\n');
  return { origin, size: Number(size) };
}

async function main(): Promise<void> {
  const node = await startAnvil();
  const dir = mkdtempSync(join(tmpdir(), 'tzun-anchor-e2e-'));
  const open: Tzun[] = [];
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
    const captured: Array<{ chainId: string; evidenceId: string; epoch: number }> = [];
    const capture = async (t: Tzun, chainId: string, n: number, epoch: number): Promise<void> => {
      for (let i = 0; i < n; i++) {
        const r = await t.capture(decision(chainId, captured.length + 1));
        captured.push({ chainId, evidenceId: r.envelope.payload.evidenceId, epoch });
      }
    };

    // Epoch 1: two chains. Epoch 2: one of them grows, and a third chain starts.
    // The first block holds 20 other transactions, so the trie proof has
    // branch and extension nodes; the second holds 3.
    await capture(alpha, 'alpha', 3, 0);
    await capture(beta, 'beta', 2, 0);
    await epochAmongTraffic(node, alpha, 11, 9);
    await settle(node, alpha);
    await capture(alpha, 'alpha', 2, 1);
    await capture(gamma, 'gamma', 1, 1);
    await epochAmongTraffic(node, alpha, 2, 1);
    await settle(node, alpha);

    const storage = alpha.getStorage();
    const logs = logStoreFor(storage)!;
    const anchors = anchorStoreFor(storage)!;
    const state = (await alpha.getAnchorState())!;
    const anchorLog = (await logs.listLogs()).find((l) => l.kind === ANCHOR_LOG_KIND)!;
    const evidenceLogs = (await logs.listLogs()).filter((l) => l.kind === EVIDENCE_LOG_KIND);
    const checkpointsOf = new Map<number, LogCheckpoint[]>();
    for (const l of evidenceLogs) checkpointsOf.set(l.logId, await anchors.listLogCheckpoints(l.logId));
    const publications = (await anchors.listAnchorPublications({ kind: 'evm-calldata/1', states: ['finalized'] })).sort((a, b) => a.anchorSize - b.anchorSize);
    if (publications.length !== 2) throw new Error(`expected 2 finalized publications, found ${publications.length}`);

    const finalized = await node.finalized();
    const epochs = [];
    for (const pub of publications as AnchorPublication[]) {
      const cp = (await anchors.getLogCheckpoint(anchorLog.logId, pub.anchorSize))!;
      const block = await node.rpc<{ hash: string; timestamp: string }>('eth_getBlockByNumber', ['0x' + pub.blockNumber!.toString(16), false]);
      const mined = pub.attempts.find((a) => a.txHash === pub.minedTxHash)!;
      const prev = cp.prevAnchoredSize;
      const members = [];
      for (const [, cps] of checkpointsOf) {
        for (const m of cps) {
          if (m.anchorLeafIndex === null || m.anchorLeafIndex < (prev ?? 0) || m.anchorLeafIndex >= pub.anchorSize) continue;
          const previous = m.prevAnchoredSize === null ? null : cps.find((c) => c.treeSize === m.prevAnchoredSize)!;
          members.push({
            logCheckpoint: m.body,
            anchorLeafIndex: m.anchorLeafIndex,
            previousLogCheckpoint: previous ? previous.body : null,
            consistencyProof: m.consistencyProof ?? [],
          });
        }
      }
      members.sort((a, b) => a.anchorLeafIndex - b.anchorLeafIndex);
      epochs.push({
        anchorCheckpoint: cp.body,
        p: pub.p,
        previousAnchorSize: prev,
        anchorConsistencyProof: cp.consistencyProof ?? [],
        members,
        publication: {
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
        },
        canonicalBlock: { number: pub.blockNumber, hash: block.hash.toLowerCase(), timestamp: Number(BigInt(block.timestamp)) },
      });
    }

    const manifest = { publishers: { [state.anchorOrigin]: [{ address: publisher.address.toLowerCase(), chain: CHAIN, namespace: 'test' as const }] } };
    const records = [];
    for (const c of captured) {
      const read = (await alpha.get(c.evidenceId))!;
      const envelope = read.envelope as EvidenceEnvelope;
      const anchor = envelope.nonRepudiation.anchor!;
      const epoch = epochs[c.epoch];
      if (anchor.anchorCheckpoint !== epoch.anchorCheckpoint) throw new Error(`${c.evidenceId}: not anchored in epoch ${c.epoch + 1}`);
      const log = bodyParts(anchor.logCheckpoint);
      const anchorBody = bodyParts(anchor.anchorCheckpoint);
      const blockTime = new Date(epoch.canonicalBlock.timestamp * 1000).toISOString();
      records.push({
        case: `${c.chainId} #${envelope.payload.sequenceNumber}, epoch ${c.epoch + 1}`,
        chainId: c.chainId,
        epoch: c.epoch,
        envelope,
        expect: {
          // From the envelope and the bundle alone (§10.4): the transaction's
          // facts hold; nothing confirms the block, so the publication is not checked.
          bundleOnly: {
            anchorValid: null,
            anchorReason: 'publication_not_checked',
            merkleProofValid: true,
            evmTx: 'checked-correct',
            evmCanonical: 'input_not_supplied:evm_header_source',
          },
          // With the manifest and a header source that reports the block as
          // canonical and final: true (§10.4 item 14, §10.6).
          withHeaderSource: {
            anchorValid: true,
            merkleProofValid: true,
            anchorPublication: 'evm-calldata',
            anchorOriginAuthenticated: true,
            anchorNamespace: 'test',
            anchorNetwork: null,
            anchorFinality: 'finalized',
            existedBy: { at: blockTime, source: 'evm-calldata' },
            inclusion: 'tx_proof',
            anchorPosition: {
              origin: log.origin,
              leafIndex: envelope.payload.sequenceNumber - 1,
              treeSize: log.size,
              anchorOrigin: anchorBody.origin,
              anchorLeafIndex: anchor.anchorLeafIndex,
              anchorSize: anchorBody.size,
              leafIndexChecked: true,
              chainChecked: true,
              authenticated: true,
            },
          },
        },
      });
    }

    const out = {
      description:
        'Records anchored end to end on anvil (Anchor §6 to §10, §13): each record\'s envelope with its nonRepudiation.anchor, the epochs its anchors name (the anchor checkpoint, P, the consistency proofs between published sizes and between a source log\'s anchored checkpoints), and each epoch\'s evm-calldata/1 publication with its heavy material. A verifier must: parse every checkpoint body; place each record\'s canonicalDigest at leafIndex = sequenceNumber - 1 in its logCheckpoint (logPath) and SHA-256(logCheckpoint) at anchorLeafIndex in its anchorCheckpoint (anchorPath); check P = SHA-256(anchorCheckpoint); verify each consistency proof with both sizes and roots taken from the bodies; check keccak256(blockHeader) = blockHash and the header\'s number; walk txProof from the header\'s transactionsRoot at key rlp(txIndex) to rawTransaction; recover the sender from rawTransaction and find it in the manifest for the anchor origin, on the chain it signed; check its calldata is exactly 0x || P; and give every record the verdicts in expect: bundleOnly with the manifest and the publication\'s material, withHeaderSource with those and a header source that reports canonicalBlock and a finalized height of headerSource.finalizedBlockNumber.',
      source:
        `Generated by scripts/generate-anchor-e2e-vectors.ts from one run of @tzun/sdk's anchor scheduler, through Tzun.init({ logNamespace: '${NS}', anchoring }), on anvil (${ANVIL_IMAGE}, chain id ${ANVIL_CHAIN_ID}, --slots-in-an-epoch 1, so its finalized tag is the head minus 2). The publisher is anvil's development account ${PUBLISHER_ACCOUNT}. The values are that run's; the expected verdicts are stated from Anchor §10, and the script stopped unless the SDK's verifyAnchor agreed with every one. scripts/regenerate-vectors.ts does not rewrite this file.`,
      format: {
        records: 'envelope is the stored record; its nonRepudiation.anchor is tzun-anchor/1 §8.1. epoch indexes epochs.',
        epochs:
          'anchorCheckpoint is the anchor log at its published size; p = SHA-256(anchorCheckpoint), 64 lowercase hex, and the publication\'s calldata. previousAnchorSize is the previous published size (null for the first) and anchorConsistencyProof is PROOF(previousAnchorSize, size) (empty for the first). members are the source-log checkpoints this epoch appended, in anchor-leaf order: previousLogCheckpoint is that log\'s previous anchored checkpoint (null for its first) and consistencyProof is PROOF between the two (empty for the first). Hashes are bare lowercase hex, except the EVM values, which are 0x-prefixed.',
        publication:
          'The evm-calldata/1 entry as a record carries it (tzun-anchor/1 §8.2: kind, chain, transactionId, blockNumber, blockHash, publisher) joined with the export bundle\'s heavy material (rawTransaction, blockHeader: the header RLP, txIndex, txProof: the transactions-trie nodes from the root, each RLP).',
        canonicalBlock: 'What anvil reported for the publication\'s block number when the file was made: its hash and its timestamp (unix seconds).',
        headerSource: 'The header source a withHeaderSource verdict uses: chainId, the finalized height, and for each epoch\'s block the canonicalBlock; it looks no transaction up.',
      },
      chain: CHAIN,
      anchorOrigin: state.anchorOrigin,
      manifest,
      headerSource: { chainId: Number(ANVIL_CHAIN_ID), finalizedBlockNumber: finalized, finality: 'finalized' },
      epochs,
      records,
    };

    // The SDK's verifier must agree with every stated verdict.
    const source: EvmHeaderSource = {
      finality: 'finalized',
      chainId: async () => ANVIL_CHAIN_ID,
      finalizedBlockNumber: async () => finalized,
      canonicalBlock: async (n) => {
        const b = epochs.find((e) => e.canonicalBlock.number === n)?.canonicalBlock;
        return b ? { hash: b.hash, timestamp: b.timestamp } : null;
      },
    };
    for (const r of records) {
      const pub = epochs[r.epoch].publication;
      const inputs = { sequenceNumber: r.envelope.payload.sequenceNumber, chainId: r.chainId, publisherManifest: manifest, publicationMaterial: [pub] };
      const bare = await verifyAnchor(r.envelope.nonRepudiation, r.envelope.integrity.canonicalDigest, inputs);
      const full = await verifyAnchor(r.envelope.nonRepudiation, r.envelope.integrity.canonicalDigest, { ...inputs, evmHeaderSources: { [CHAIN]: source } });
      const b = r.expect.bundleOnly;
      const w = r.expect.withHeaderSource;
      const bareCheck = (id: string) => bare.checks.find((c) => c.id === id);
      const agrees =
        bare.anchorValid === b.anchorValid &&
        bare.anchorReason === b.anchorReason &&
        bareCheck('anchor.evm.tx[0]')?.outcome === b.evmTx &&
        bareCheck('anchor.evm.canonical[0]')?.reason === b.evmCanonical &&
        full.anchorValid === w.anchorValid &&
        full.anchorOriginAuthenticated === w.anchorOriginAuthenticated &&
        full.anchorNamespace === w.anchorNamespace &&
        full.anchorFinality === w.anchorFinality &&
        full.existedBy?.at === w.existedBy.at &&
        full.publications[0]?.evm?.inclusion === w.inclusion &&
        JSON.stringify(full.anchorPosition) === JSON.stringify(w.anchorPosition);
      if (!agrees) throw new Error(`self-check failed: ${r.case}: ${JSON.stringify({ bare, full })}`);
    }

    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
  } finally {
    for (const t of open) await t.close().catch(() => undefined);
    await node.stop();
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  process.stderr.write(`${(err as Error).stack ?? err}\n`);
  process.exit(1);
});
