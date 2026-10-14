import { BenchmarkOptions, BenchmarkReport, BenchmarkSuiteName, ScanEstimate } from './types';
import { detectHardware } from './hardware';
import { getDefaultDigestComputer } from '@tzun/engine';
import {
  benchmarkSerialization,
  benchmarkDigest,
  benchmarkCapture,
  benchmarkVerification,
  benchmarkScanner,
  benchmarkStorage,
} from './suites';

/** Every suite name `runBenchmark` knows how to run. Exported so the REST and
 * CLI front ends validate against one list rather than each keeping its own. */
export const ALL_SUITES: BenchmarkSuiteName[] = [
  'serialization', 'digest', 'capture', 'verification', 'scanner', 'storage',
];

/**
 * Run benchmark suites and produce a structured report.
 *
 * If no suites are specified, all suites are run.
 */
export async function runBenchmark(
  options: BenchmarkOptions = {},
): Promise<BenchmarkReport> {
  const startedAt = new Date().toISOString();
  const startTime = Date.now();
  const suites = options.suites ?? ALL_SUITES;
  const hardware = detectHardware();
  const digestBackend = getDefaultDigestComputer().backend;

  const measurements = [];

  for (const suite of suites) {
    switch (suite) {
      case 'serialization':
        measurements.push(...await benchmarkSerialization(options));
        break;
      case 'digest':
        measurements.push(...await benchmarkDigest(options));
        break;
      case 'capture':
        measurements.push(...await benchmarkCapture(options));
        break;
      case 'verification':
        measurements.push(...await benchmarkVerification(options));
        break;
      case 'scanner':
        measurements.push(...await benchmarkScanner(options));
        break;
      case 'storage':
        measurements.push(...await benchmarkStorage(options));
        break;
    }
  }

  const completedAt = new Date().toISOString();
  const durationMs = Date.now() - startTime;

  // Compute scan time estimates based on digest throughput
  const digestMeasurement = measurements.find(
    m => m.suite === 'digest' && m.name.includes('single'),
  );
  const scanEstimates = computeScanEstimates(digestMeasurement?.opsPerSecond);

  return {
    startedAt,
    completedAt,
    durationMs,
    hardware,
    digestBackend,
    measurements,
    scanEstimates,
  };
}

function computeScanEstimates(
  digestOpsPerSecond: number | undefined,
): ScanEstimate[] {
  const targets = [100_000, 1_000_000, 10_000_000];

  if (!digestOpsPerSecond || digestOpsPerSecond <= 0) {
    return targets.map(records => ({
      records,
      estimatedTimeSeconds: -1,
    }));
  }

  return targets.map(records => ({
    records,
    estimatedTimeSeconds: Math.round((records / digestOpsPerSecond) * 100) / 100,
  }));
}
