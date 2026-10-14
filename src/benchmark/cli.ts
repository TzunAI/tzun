#!/usr/bin/env node

import { runBenchmark } from './runner';
import { formatReport } from './format';
import { BenchmarkSuiteName } from './types';

const VALID_SUITES: BenchmarkSuiteName[] = [
  'serialization', 'digest', 'capture', 'verification', 'scanner', 'storage',
];

function printUsage(): void {
  console.log(`
Usage: npx ts-node src/benchmark/cli.ts [options]

Options:
  --json                  Output raw JSON report (default: human-readable)
  --suites <suite,...>    Comma-separated list of suites to run
                          Available: ${VALID_SUITES.join(', ')}
                          Default: all suites
  --min-duration <ms>     Minimum duration per benchmark in milliseconds (default: 1000)
  --warmup <n>            Number of warmup iterations (default: 10)
  --workers <n,n,...>     Comma-separated worker counts for scanner benchmark (default: 1,2,4,8)
  --help                  Show this help message

Examples:
  npx ts-node src/benchmark/cli.ts
  npx ts-node src/benchmark/cli.ts --json
  npx ts-node src/benchmark/cli.ts --suites serialization,digest --min-duration 2000
  npx ts-node src/benchmark/cli.ts --suites scanner --workers 1,2,4,8,16
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes('--help')) {
    printUsage();
    return;
  }

  const jsonOutput = args.includes('--json');

  let suites: BenchmarkSuiteName[] | undefined;
  const suitesIdx = args.indexOf('--suites');
  if (suitesIdx >= 0 && args[suitesIdx + 1]) {
    suites = args[suitesIdx + 1].split(',').map(s => s.trim()) as BenchmarkSuiteName[];
    for (const suite of suites) {
      if (!VALID_SUITES.includes(suite)) {
        console.error(`Unknown suite: "${suite}". Valid suites: ${VALID_SUITES.join(', ')}`);
        process.exit(1);
      }
    }
  }

  let minDurationMs: number | undefined;
  const minDurationIdx = args.indexOf('--min-duration');
  if (minDurationIdx >= 0 && args[minDurationIdx + 1]) {
    minDurationMs = parseInt(args[minDurationIdx + 1], 10);
    if (isNaN(minDurationMs) || minDurationMs <= 0) {
      console.error('--min-duration must be a positive integer.');
      process.exit(1);
    }
  }

  let warmupIterations: number | undefined;
  const warmupIdx = args.indexOf('--warmup');
  if (warmupIdx >= 0 && args[warmupIdx + 1]) {
    warmupIterations = parseInt(args[warmupIdx + 1], 10);
    if (isNaN(warmupIterations) || warmupIterations < 0) {
      console.error('--warmup must be a non-negative integer.');
      process.exit(1);
    }
  }

  let scannerWorkerCounts: number[] | undefined;
  const workersIdx = args.indexOf('--workers');
  if (workersIdx >= 0 && args[workersIdx + 1]) {
    scannerWorkerCounts = args[workersIdx + 1].split(',').map(s => {
      const n = parseInt(s.trim(), 10);
      if (isNaN(n) || n <= 0) {
        console.error(`Invalid worker count: "${s.trim()}". Must be a positive integer.`);
        process.exit(1);
      }
      return n;
    });
  }

  if (!jsonOutput) {
    console.log('Running Tzun SDK benchmarks...\n');
  }

  const report = await runBenchmark({
    suites,
    minDurationMs,
    warmupIterations,
    scannerWorkerCounts,
  });

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(formatReport(report));
  }
}

main().catch((err) => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
