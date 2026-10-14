/**
 * One anchoring epoch against a real chain, under a test origin only
 * (the Sepolia `test.` dry run), through the same path
 * an integrator uses: `Tzun.init({ logNamespace, anchoring })`.
 *
 *   pnpm exec tsx scripts/anchor-dry-run.ts \
 *     --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
 *     --key-file ~/.config/tzun/sepolia-test-publisher.key \
 *     --store ./dry-run.db [--chain eip155:11155111] [--namespace test.dryrun.tzun] \
 *     [--captures 3] [--wait]
 *
 * It opens (or creates) a SQLite store in a `test.` namespace, captures a few
 * sample records when asked, forces one epoch with `anchorNow({ force: true })`,
 * and prints the anchor origin, P and the transaction. With --wait it keeps
 * passing until the block is finalized and the records are filled (about 15
 * minutes on Sepolia), then verifies one filled record: with `Tzun.verify()`,
 * which joins the heavy material the store holds, and with `verifyAnchor`
 * for the full verdict.
 *
 * It refuses a namespace that is not a `test.` namespace, and `Tzun.init`
 * refuses an existing store minted in another namespace: a test origin
 * freezes nothing (tzun-anchor/1 §2, §4.3.4), and a production anchor is a
 * separate, deliberate step this script never takes. The key is read from
 * the file and never printed; only the publisher's address is.
 */
import { readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { Wallet, JsonRpcProvider, Network } from 'ethers';
import { Tzun, verifyAnchor, RpcEvmHeaderSource } from '../src/sdk';
import { anchorStoreFor } from '../src/storage/log-store';

interface Args {
  rpcUrl: string;
  keyFile: string;
  store: string;
  chain: string;
  namespace: string;
  captures: number;
  wait: boolean;
}

function usage(message: string): never {
  process.stderr.write(`${message}\n\nusage: tsx scripts/anchor-dry-run.ts --rpc-url <url> --key-file <path> --store <file.db> [--chain eip155:<id>] [--namespace test.<name>] [--captures <n>] [--wait]\n`);
  process.exit(2);
}

function parseArgs(argv: string[]): Args {
  const get = (flag: string): string | undefined => {
    const i = argv.indexOf(flag);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const rpcUrl = get('--rpc-url') ?? usage('--rpc-url is required');
  const keyFile = (get('--key-file') ?? usage('--key-file is required')).replace(/^~(?=\/)/, homedir());
  const store = get('--store') ?? usage('--store is required');
  const namespace = get('--namespace') ?? 'test.dryrun.tzun';
  if (!namespace.startsWith('test.')) usage(`--namespace must begin with "test." (got ${JSON.stringify(namespace)}): a dry run never makes a production anchor`);
  return {
    rpcUrl,
    keyFile,
    store,
    chain: get('--chain') ?? 'eip155:11155111',
    namespace,
    captures: Number(get('--captures') ?? 3),
    wait: argv.includes('--wait'),
  };
}

function readKey(path: string): string {
  const mode = statSync(path).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    process.stderr.write(`warning: ${path} is readable by other users (mode ${mode.toString(8)}); 0600 is expected\n`);
  }
  const key = readFileSync(path, 'utf8').trim();
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(key)) usage(`${path} does not hold one 32-byte hex private key`);
  return key.startsWith('0x') ? key : `0x${key}`;
}

const say = (line: string): void => {
  process.stdout.write(`${line}\n`);
};

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const privateKey = readKey(args.keyFile);
  const publisher = new Wallet(privateKey).address;

  const tzun = await Tzun.init({
    mode: 'dev',
    dbPath: args.store,
    chainId: 'dry-run',
    logNamespace: args.namespace,
    // The dry run passes by hand: no background schedule.
    anchoring: { publishers: { evm: { rpcUrl: args.rpcUrl, privateKey, chain: args.chain } }, autoStart: false },
    onLog: (event, fields) => say(`  ${event} ${JSON.stringify(fields)}`),
  });
  try {
    const state0 = (await tzun.getAnchorState())!;
    if (state0.namespace !== 'test') throw new Error(`The store's anchor origin ${state0.anchorOrigin} is not a test origin.`);
    say(`anchor origin  ${state0.anchorOrigin} (namespace ${state0.namespace})`);
    say(`publisher      ${publisher} on ${args.chain}`);

    const captured: string[] = [];
    for (let i = 0; i < args.captures; i++) {
      const result = await tzun.capture({ aiOutput: { dryRun: true, i, at: new Date().toISOString() }, action: 'approved', reason: 'anchoring dry run', decider: { kind: 'human', id: 'acct:anchor-dry-run' }, aiSystemId: 'anchor-dry-run' });
      captured.push(result.envelope.payload.evidenceId);
    }

    const report = await tzun.anchorNow({ force: true });
    if (report.epoch) {
      const pub = (await anchorStoreFor(tzun.getStorage())!.getAnchorPublication(report.epoch.publicationId))!;
      say(`epoch          ${report.epoch.epochId}: ${report.epoch.members} log(s), anchor size ${report.epoch.anchorSize}, forced ${report.epoch.forced}`);
      say(`P              0x${report.epoch.p}`);
      say(`transaction    ${pub.attempts[pub.attempts.length - 1]?.txHash ?? '(not signed)'} nonce ${pub.nonce}`);
    } else {
      say(`no epoch cut: ${report.deferred ?? 'nothing to do'}`);
    }
    for (const a of report.alarms) say(`ALARM ${a.severity} ${a.code}: ${a.message}`);

    if (!args.wait) return;
    const started = Date.now();
    for (;;) {
      const state = (await tzun.getAnchorState())!;
      if (state.halted) throw new Error(`anchoring stopped: ${state.halted.code}`);
      if (state.lastFinalized && state.inFlight.length === 0 && state.fillBacklog === 0) {
        say(`finalized      block ${state.lastFinalized.blockNumber} after ${Math.round((Date.now() - started) / 1000)} s; records filled`);
        break;
      }
      await new Promise((r) => setTimeout(r, 30_000));
      const pass = await tzun.anchorNow();
      say(`  pass: ${pass.transitions.map((t) => `${t.from}->${t.to}`).join(', ') || (pass.awaitingFinality ? 'awaiting finality' : pass.deferred ?? 'waiting')}`);
    }

    const id = captured[0] ?? (await tzun.list({ chainId: 'dry-run', limit: 1 }))[0]?.envelope.payload.evidenceId;
    const read = id ? await tzun.get(id) : null;
    if (read) {
      const state = (await tzun.getAnchorState())!;
      const chainId = BigInt(args.chain.split(':')[1]);
      const network = Network.from(chainId);
      const provider = new JsonRpcProvider(args.rpcUrl, network, { staticNetwork: network });
      const inputs = {
        publisherManifest: { publishers: { [state.anchorOrigin]: [{ address: publisher, chain: args.chain, namespace: 'test' as const }] } },
        evmHeaderSources: { [args.chain]: new RpcEvmHeaderSource(provider as never, { finality: 'finalized' }) },
      };
      const verified = await tzun.verify(read.envelope.payload.evidenceId, undefined, { anchor: inputs });
      say(`Tzun.verify    anchorValid ${verified.anchorValid}${verified.anchorReason ? `, ${verified.anchorReason}` : ''}; get() state ${read.anchorState?.state}`);
      const pub = (await anchorStoreFor(tzun.getStorage())!.listAnchorPublications({ states: ['finalized'] })).pop()!;
      const verdict = await verifyAnchor(read.envelope.nonRepudiation, read.envelope.integrity.canonicalDigest, {
        sequenceNumber: read.envelope.payload.sequenceNumber,
        chainId: 'dry-run',
        ...inputs,
        publicationMaterial: [
          { kind: 'evm-calldata/1', rawTransaction: pub.attempts.find((a) => a.txHash === pub.minedTxHash)?.rawTx, blockNumber: pub.blockNumber, blockHash: pub.blockHash, blockHeader: pub.blockHeader, txIndex: pub.txIndex, txProof: pub.txTrieProof },
        ],
      });
      provider.destroy();
      say(`verifyAnchor   anchorValid ${verdict.anchorValid}, origin authenticated ${verdict.anchorOriginAuthenticated}, namespace ${verdict.anchorNamespace}, network ${verdict.anchorNetwork}, finality ${JSON.stringify(verdict.anchorFinality)}, inclusion ${verdict.publications[0]?.evm?.inclusion ?? '-'}`);
    }
  } finally {
    await tzun.close();
  }
}

main().catch((err) => {
  process.stderr.write(`${(err as Error).message}\n`);
  process.exit(1);
});
