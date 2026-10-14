// Regenerates the Sepolia vectors. Run by hand, never by jest:
//   pnpm exec tsx tests/ts/fixtures/evm-sepolia-block.generate.ts tests/ts/fixtures/evm-sepolia-block.json
//   pnpm exec tsx tests/ts/fixtures/evm-sepolia-block.generate.ts tests/ts/fixtures/evm-sepolia-self-tx.json <tx hash>
// It fetches one finalized Sepolia block over public read-only JSON-RPC and
// emits a vector: the header RLP (checked against the block hash), and
// transactions with their trie proofs. Without a hash it picks one legacy and
// one EIP-1559 transaction from a recent block; with one, it takes that
// transaction and its block. The proofs come from src/anchoring/tx-trie.ts,
// whose root must equal the block's transactionsRoot over all of its
// transactions.
import { encodeRlp, keccak256, toBeHex, Transaction, type RlpStructuredData } from 'ethers';
import { writeFileSync } from 'fs';
import { buildTxTrie } from '../helpers/evm-fixtures';

const URL = 'https://ethereum-sepolia-rpc.publicnode.com';
async function rpc(method: string, params: unknown[]) {
  const r = await fetch(URL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const j: any = await r.json();
  if (j.error) throw new Error(JSON.stringify(j.error));
  return j.result;
}
const q = (h: string) => (BigInt(h) === 0n ? '0x' : toBeHex(BigInt(h)));

(async () => {
  const wanted = process.argv[3]?.toLowerCase();
  const fin = await rpc('eth_getBlockByNumber', ['finalized', false]);
  if (wanted) {
    const t = await rpc('eth_getTransactionByHash', [wanted]);
    fin.number = toBeHex(BigInt(t.blockNumber) + 5n);
  }
  // A few blocks below finalized, searching down for one with both types.
  let n = BigInt(fin.number) - 5n;
  for (let tries = 0; tries < 40; tries++, n--) {
    const b = await rpc('eth_getBlockByNumber', [toBeHex(n), false]);
    const txs: string[] = b.transactions;
    if (txs.length < 20) continue;
    const raws: string[] = [];
    const types: number[] = [];
    for (const h of txs) {
      const raw: string = await rpc('eth_getRawTransactionByHash', [h]);
      if (keccak256(raw) !== h) throw new Error('raw hash mismatch ' + h);
      raws.push(raw);
      types.push(Number(getType(raw)));
    }
    const idx0 = wanted ? txs.indexOf(wanted) : types.findIndex((t) => t === 0);
    const idx2 = wanted ? -1 : types.findIndex((t, i) => t === 2 && i > 16);
    if (idx0 < 0 || (!wanted && idx2 < 0)) { console.error('skip', n, types.join('')); continue; }
    const trie = buildTxTrie(raws);
    if (trie.root !== b.transactionsRoot) throw new Error(`trie root mismatch ${trie.root} vs ${b.transactionsRoot}`);
    const fields: RlpStructuredData[] = [
      b.parentHash, b.sha3Uncles, b.miner, b.stateRoot, b.transactionsRoot, b.receiptsRoot, b.logsBloom,
      q(b.difficulty), q(b.number), q(b.gasLimit), q(b.gasUsed), q(b.timestamp), b.extraData, b.mixHash, b.nonce,
    ];
    const opt: [string, boolean][] = [['baseFeePerGas', true], ['withdrawalsRoot', false], ['blobGasUsed', true], ['excessBlobGas', true], ['parentBeaconBlockRoot', false], ['requestsHash', false], ['blockAccessListHash', false], ['slotNumber', true]];
    for (const [k, isQ] of opt) if (b[k] !== undefined) fields.push(isQ ? q(b[k]) : b[k]);
    const known = new Set(['parentHash','sha3Uncles','miner','stateRoot','transactionsRoot','receiptsRoot','logsBloom','difficulty','number','gasLimit','gasUsed','timestamp','extraData','mixHash','nonce','baseFeePerGas','withdrawalsRoot','blobGasUsed','excessBlobGas','parentBeaconBlockRoot','requestsHash','blockAccessListHash','slotNumber','hash','size','totalDifficulty','transactions','uncles','withdrawals']);
    const extra = Object.keys(b).filter((k) => !known.has(k));
    const header = encodeRlp(fields);
    if (keccak256(header) !== b.hash) throw new Error(`header hash mismatch; extra keys: ${extra}`);
    const pick = (i: number) => ({ index: i, type: types[i], raw: raws[i], sender: Transaction.from(raws[i]).from, proof: trie.proof(i) });
    const out = {
      source: `Sepolia block ${BigInt(b.number)}, fetched ${new Date().toISOString().slice(0, 10)} from ${URL} (eth_getBlockByNumber, eth_getRawTransactionByHash)`,
      chainId: '11155111',
      blockNumber: Number(BigInt(b.number)),
      blockHash: b.hash,
      timestamp: Number(BigInt(b.timestamp)),
      transactionsRoot: b.transactionsRoot,
      transactionCount: raws.length,
      header,
      transactions: wanted ? [pick(idx0)] : [pick(idx0), pick(idx2)],
    };
    writeFileSync(process.argv[2], JSON.stringify(out, null, 2) + '\n');
    console.log('wrote block', out.blockNumber, 'txs', raws.length, 'picked', idx0, idx2, 'extra', extra);
    return;
  }
  throw new Error('no suitable block');
})().catch((e) => { console.error(e); process.exit(1); });

function getType(raw: string): number { const b = parseInt(raw.slice(2, 4), 16); return b >= 0xc0 ? 0 : b; }
