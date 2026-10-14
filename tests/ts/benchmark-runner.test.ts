import { runBenchmark } from '../../src/benchmark/runner';
import { formatReport } from '../../src/benchmark/format';
import { BenchmarkReport } from '../../src/benchmark/types';

describe('runBenchmark', () => {
  it('produces a complete BenchmarkReport', async () => {
    const report = await runBenchmark({
      suites: ['serialization', 'digest'],
      minDurationMs: 100,
      warmupIterations: 2,
    });

    expect(report.startedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(report.completedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(report.durationMs).toBeGreaterThan(0);
    expect(report.hardware).toBeDefined();
    expect(report.hardware.cpu).toBeDefined();
    expect(report.hardware.cores).toBeGreaterThan(0);
    expect(report.digestBackend).toBe('cpu');
    expect(report.measurements.length).toBeGreaterThanOrEqual(4); // 3 serialization + 3 digest
    expect(report.scanEstimates.length).toBeGreaterThanOrEqual(3);
  }, 30000);

  it('runs only specified suites', async () => {
    const report = await runBenchmark({
      suites: ['digest'],
      minDurationMs: 100,
      warmupIterations: 2,
    });

    const suiteNames = new Set(report.measurements.map(m => m.suite));
    expect(suiteNames.has('digest')).toBe(true);
    expect(suiteNames.has('serialization')).toBe(false);
    expect(suiteNames.has('capture')).toBe(false);
  }, 30000);

  it('runs all suites when no specific suites are requested', async () => {
    const report = await runBenchmark({
      minDurationMs: 100,
      warmupIterations: 2,
      scannerWorkerCounts: [1, 2],
    });

    const suiteNames = new Set(report.measurements.map(m => m.suite));
    expect(suiteNames.has('serialization')).toBe(true);
    expect(suiteNames.has('digest')).toBe(true);
    expect(suiteNames.has('capture')).toBe(true);
    expect(suiteNames.has('verification')).toBe(true);
    expect(suiteNames.has('scanner')).toBe(true);
    expect(suiteNames.has('storage')).toBe(true);
  }, 60000);

  it('scan estimates are computed from digest throughput', async () => {
    const report = await runBenchmark({
      suites: ['digest'],
      minDurationMs: 100,
      warmupIterations: 2,
    });

    expect(report.scanEstimates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ records: 100000 }),
        expect.objectContaining({ records: 1000000 }),
        expect.objectContaining({ records: 10000000 }),
      ]),
    );

    for (const estimate of report.scanEstimates) {
      expect(estimate.estimatedTimeSeconds).toBeGreaterThan(0);
    }
  }, 30000);
});

describe('formatReport', () => {
  it('produces human-readable text output', async () => {
    const report = await runBenchmark({
      suites: ['serialization'],
      minDurationMs: 100,
      warmupIterations: 2,
    });

    const text = formatReport(report);

    expect(typeof text).toBe('string');
    expect(text.length).toBeGreaterThan(0);
    expect(text).toContain('Benchmark Report');
    expect(text).toContain('Hardware');
    expect(text).toContain('SERIALIZATION');
    expect(text).toContain('ops/sec');
    expect(text).toContain('Scan Time Estimates');
  }, 30000);
});
