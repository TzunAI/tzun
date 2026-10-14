/**
 * Regenerate the vector files of the v1.0 record as revised in 0.8.0, or check
 * that they are current.
 *
 *   pnpm run regenerate:vectors                 write every file below
 *   pnpm run regenerate:vectors -- --check      regenerate in memory; exit 1
 *                                               naming each file that differs
 *   pnpm run regenerate:vectors -- --only decider,links
 *                                               only the files whose generator
 *                                               name holds one of the words
 *   pnpm run regenerate:vectors -- --anvil      the files an anvil run produces
 *                                               (Docker): anchor-e2e, the EVM
 *                                               anchor vectors copied from its
 *                                               epoch 0, then the bundle-b1
 *                                               corpus
 *
 * Each generator prints its file on stdout and stops, writing nothing, when the
 * engine disagrees with an answer it states from the specification. The
 * generators run in the order listed: the canonical vectors read W3 from the
 * worked examples, so a run regenerates those first.
 *
 * The anvil files are regenerated once per release, after the record revision
 * and the anchoring changes it travels with are both on the integration
 * branch: their values (store ids, digests, block times) change with every
 * run, so `--check` does not cover them. `--anvil` runs anchor-e2e first,
 * writing vectors/anchor-e2e-vectors.json, then the b1 corpus, which writes
 * vectors/bundle-b1/ itself, and then the suites that replay both.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(__dirname, '..');
const TSX = join(ROOT, 'node_modules', '.bin', 'tsx');

/** Generator script → the vector file it prints, in the order they run. */
const GENERATORS: Array<[string, string]> = [
  ['generate-v1.0-worked-example-vectors.ts', 'v1.0-worked-example-vectors.json'],
  ['generate-v1.0-canonical-vectors.ts', 'v1.0-canonical-vectors.json'],
  ['generate-v1.0-integrity-vectors.ts', 'v1.0-integrity-vectors.json'],
  ['generate-signoff-expectation-vectors.ts', 'signoff-expectation-vectors.json'],
  ['generate-store-generation-vectors.ts', 'store-generation-vectors.json'],
  ['generate-decider-vectors.ts', 'decider-vectors.json'],
  ['generate-contributions-vectors.ts', 'contributions-vectors.json'],
  ['generate-links-vectors.ts', 'links-vectors.json'],
  ['generate-mandate-vectors.ts', 'mandate-vectors.json'],
  ['generate-agent-descriptor-vectors.ts', 'agent-descriptor-vectors.json'],
  ['generate-cross-sdk-parity-vectors.ts', 'cross-sdk-parity-vectors.json'],
];

function run(command: string, args: string[], capture: boolean): { status: number; stdout: string } {
  const r = spawnSync(command, args, {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    stdio: capture ? ['ignore', 'pipe', 'inherit'] : 'inherit',
  });
  if (r.error) throw r.error;
  return { status: r.status ?? 1, stdout: r.stdout ?? '' };
}

function regenerate(check: boolean, only: string[] | null): number {
  let failures = 0;
  for (const [script, file] of GENERATORS) {
    if (only !== null && !only.some((word) => script.includes(word))) continue;
    const { status, stdout } = run(TSX, [join('scripts', script)], true);
    if (status !== 0) {
      process.stderr.write(`${script}: stopped (exit ${status}); vectors/${file} left as it was\n`);
      failures++;
      continue;
    }
    const path = join(ROOT, 'vectors', file);
    if (check) {
      let current = '';
      try {
        current = readFileSync(path, 'utf8');
      } catch {
        current = '';
      }
      if (current !== stdout) {
        process.stderr.write(`vectors/${file} is not what ${script} prints: run pnpm run regenerate:vectors\n`);
        failures++;
      } else {
        process.stdout.write(`vectors/${file}: current\n`);
      }
    } else {
      writeFileSync(path, stdout);
      process.stdout.write(`vectors/${file}: written\n`);
    }
  }
  return failures === 0 ? 0 : 1;
}

function regenerateAnvil(): number {
  if (run('docker', ['info', '--format', '{{.ServerVersion}}'], true).status !== 0) {
    process.stderr.write('--anvil needs a Docker daemon: the generators start one anvil container each (tests/anvil/harness.ts)\n');
    return 1;
  }
  const e2e = run(TSX, [join('scripts', 'generate-anchor-e2e-vectors.ts')], true);
  if (e2e.status !== 0) {
    process.stderr.write('generate-anchor-e2e-vectors.ts stopped; vectors/anchor-e2e-vectors.json left as it was\n');
    return 1;
  }
  writeFileSync(join(ROOT, 'vectors', 'anchor-e2e-vectors.json'), e2e.stdout);
  process.stdout.write('vectors/anchor-e2e-vectors.json: written\n');
  // evm-anchor-vectors.json carries epoch 0 of the file just written, byte for byte.
  const evm = run(TSX, [join('scripts', 'generate-evm-anchor-vectors.ts')], true);
  if (evm.status !== 0) {
    process.stderr.write('generate-evm-anchor-vectors.ts stopped; vectors/evm-anchor-vectors.json left as it was\n');
    return 1;
  }
  writeFileSync(join(ROOT, 'vectors', 'evm-anchor-vectors.json'), evm.stdout);
  process.stdout.write('vectors/evm-anchor-vectors.json: written\n');
  if (run(TSX, [join('scripts', 'generate-bundle-b1-corpus.ts')], false).status !== 0) {
    process.stderr.write('generate-bundle-b1-corpus.ts stopped; vectors/bundle-b1/ left as it was\n');
    return 1;
  }
  const jest = join(ROOT, 'node_modules', '.bin', 'jest');
  const replay = run(jest, ['tests/ts/anchor-e2e-vectors.test.ts', 'tests/ts/evm-anchor-vectors.test.ts', 'tests/ts/bundle-b1-corpus.test.ts'], false);
  if (replay.status !== 0) {
    process.stderr.write('the TS replays of the regenerated files failed\n');
    return 1;
  }
  process.stdout.write(
    'Regenerated. Next: python -m pytest tests/cross-sdk/test_anchor_e2e_vectors.py tests/cross-sdk/test_anchor_verify_parity.py tests/cross-sdk/test_evm_anchor_vectors.py, ' +
      'the Go gate (tests/cross-impl/go), and the vectors census in the spec.\n',
  );
  return 0;
}

const args = process.argv.slice(2);
const onlyAt = args.indexOf('--only');
const only = onlyAt >= 0 ? (args[onlyAt + 1] ?? '').split(',').filter((w) => w.length > 0) : null;
process.exit(args.includes('--anvil') ? regenerateAnvil() : regenerate(args.includes('--check'), only));
