/**
 * Cross-SDK harness for RFC 6962 Merkle trees — Node side.
 *
 * Reads one JSON command from stdin, runs it against the in-repo
 * `@tzun/engine` build (never a published version), and writes one
 * JSON result to stdout. tests/cross-sdk/test_merkle_parity.py drives it and
 * compares every answer with `tzun_sdk.attestation.merkle`.
 *
 * Every command batches its work, so one Node start answers a whole suite.
 *
 *   { action: "generate", digests: string[] }
 *     → { roots: string[], inclusion: string[][][], consistency: string[][][],
 *         consistencyFromLargest: string[][][] }
 *     For every n in 1..digests.length, over the tree of digests[0:n]:
 *       roots[n-1]                        MTH(D[n])
 *       inclusion[n-1][i]                 PATH(i, D[n]) for 0 <= i < n
 *       consistency[n-1][m-1]             PROOF(m, D[n]) for 1 <= m <= n, from the tree of n leaves
 *       consistencyFromLargest[n-1][m-1]  the same proof, from the tree of all the digests
 *
 *   { action: "verify-inclusion", cases: [{ leaf, leafIndex, treeSize, proof, root }] }
 *     → { results: boolean[] }            verifyMerkleProof for each case
 *
 *   { action: "verify-consistency", cases: [{ first, second, proof, firstRoot, secondRoot }] }
 *     → { results: [{ valid, reason }] }  verifyConsistencyProof for each case
 */

import {
  buildMerkleTree,
  getConsistencyProof,
  getMerkleProof,
  getMerkleRoot,
  verifyConsistencyProof,
  verifyMerkleProof,
} from '@tzun/engine';

interface InclusionCase {
  leaf: string;
  leafIndex: number;
  treeSize: number;
  proof: string[];
  root: string;
}

interface ConsistencyCase {
  first: number;
  second: number;
  proof: string[];
  firstRoot: string;
  secondRoot: string;
}

type Command =
  | { action: 'generate'; digests: string[] }
  | { action: 'verify-inclusion'; cases: InclusionCase[] }
  | { action: 'verify-consistency'; cases: ConsistencyCase[] };

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
  });
}

function consistencyProof(tree: ReturnType<typeof buildMerkleTree>, first: number, second?: number): string[] {
  const result = getConsistencyProof(tree, first, second);
  if (!result.ok) throw new Error(`getConsistencyProof(${first}, ${second}) refused: ${result.reason}`);
  return result.proof;
}

function generate(digests: string[]): unknown {
  const largest = buildMerkleTree(digests);
  const roots: string[] = [];
  const inclusion: string[][][] = [];
  const consistency: string[][][] = [];
  const consistencyFromLargest: string[][][] = [];
  for (let n = 1; n <= digests.length; n++) {
    const tree = buildMerkleTree(digests.slice(0, n));
    roots.push(getMerkleRoot(tree));
    const paths: string[][] = [];
    for (let i = 0; i < n; i++) paths.push(getMerkleProof(tree, i));
    inclusion.push(paths);
    const own: string[][] = [];
    const fromLargest: string[][] = [];
    for (let m = 1; m <= n; m++) {
      own.push(consistencyProof(tree, m));
      fromLargest.push(consistencyProof(largest, m, n));
    }
    consistency.push(own);
    consistencyFromLargest.push(fromLargest);
  }
  return { roots, inclusion, consistency, consistencyFromLargest };
}

async function main(): Promise<void> {
  const cmd = JSON.parse(await readStdin()) as Command;
  let result: unknown;
  if (cmd.action === 'generate') {
    result = generate(cmd.digests);
  } else if (cmd.action === 'verify-inclusion') {
    result = {
      results: cmd.cases.map((c) => verifyMerkleProof(c.leaf, c.leafIndex, c.treeSize, c.proof, c.root)),
    };
  } else if (cmd.action === 'verify-consistency') {
    result = {
      results: cmd.cases.map((c) => verifyConsistencyProof(c.first, c.second, c.proof, c.firstRoot, c.secondRoot)),
    };
  } else {
    throw new Error(`Unknown action: ${(cmd as { action: unknown }).action}`);
  }
  process.stdout.write(JSON.stringify(result));
}

main().catch((err) => {
  process.stderr.write(String(err instanceof Error ? err.stack : err));
  process.exit(1);
});
