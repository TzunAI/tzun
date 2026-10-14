import {
  benchmarkSerialization,
  benchmarkDigest,
  benchmarkCapture,
  benchmarkVerification,
  benchmarkScanner,
  benchmarkStorage,
} from '../../src/benchmark/suites';
import { BenchmarkMeasurement } from '../../src/benchmark/types';

const FAST_OPTIONS = { minDurationMs: 100, warmupIterations: 2 };

describe('Benchmark Suites', () => {
  describe('benchmarkSerialization', () => {
    it('produces measurements for small/medium/large payloads', async () => {
      const measurements = await benchmarkSerialization(FAST_OPTIONS);
      expect(measurements.length).toBeGreaterThanOrEqual(3);
      for (const m of measurements) {
        expect(m.suite).toBe('serialization');
        expect(m.opsPerSecond).toBeGreaterThan(0);
        expect(m.iterations).toBeGreaterThan(0);
        expect(m.avgTimeMs).toBeGreaterThan(0);
        expect(m.totalTimeMs).toBeGreaterThan(0);
      }
    });

    it('small payload has higher ops/sec than large payload', async () => {
      const measurements = await benchmarkSerialization(FAST_OPTIONS);
      const small = measurements.find(m => m.name.includes('small'));
      const large = measurements.find(m => m.name.includes('large'));
      expect(small).toBeDefined();
      expect(large).toBeDefined();
      // Small payloads should serialize faster than large ones
      expect(small!.opsPerSecond).toBeGreaterThan(large!.opsPerSecond);
    });
  });

  describe('benchmarkDigest', () => {
    it('produces measurement with correct suite name', async () => {
      const measurements = await benchmarkDigest(FAST_OPTIONS);
      expect(measurements.length).toBeGreaterThanOrEqual(1);
      for (const m of measurements) {
        expect(m.suite).toBe('digest');
        expect(m.opsPerSecond).toBeGreaterThan(0);
      }
    });

    it('includes batch measurement if computeBatch is available', async () => {
      const measurements = await benchmarkDigest(FAST_OPTIONS);
      const batchMeasurement = measurements.find(m => m.name.includes('batch'));
      expect(batchMeasurement).toBeDefined();
    });
  });

  describe('benchmarkCapture', () => {
    it('produces measurements for capture throughput', async () => {
      const measurements = await benchmarkCapture(FAST_OPTIONS);
      expect(measurements.length).toBeGreaterThanOrEqual(1);
      for (const m of measurements) {
        expect(m.suite).toBe('capture');
        expect(m.opsPerSecond).toBeGreaterThan(0);
      }
    });
  });

  describe('benchmarkVerification', () => {
    it('produces measurements for verification throughput', async () => {
      const measurements = await benchmarkVerification(FAST_OPTIONS);
      expect(measurements.length).toBeGreaterThanOrEqual(1);
      for (const m of measurements) {
        expect(m.suite).toBe('verification');
        expect(m.opsPerSecond).toBeGreaterThan(0);
      }
    });
  });

  describe('benchmarkScanner', () => {
    it('produces measurements for various worker counts', async () => {
      const measurements = await benchmarkScanner({
        ...FAST_OPTIONS,
        scannerWorkerCounts: [1, 2],
      });
      expect(measurements.length).toBeGreaterThanOrEqual(2);
      for (const m of measurements) {
        expect(m.suite).toBe('scanner');
        expect(m.opsPerSecond).toBeGreaterThan(0);
      }
    });
  });

  describe('benchmarkStorage', () => {
    it('produces measurements for read and write throughput', async () => {
      const measurements = await benchmarkStorage(FAST_OPTIONS);
      expect(measurements.length).toBeGreaterThanOrEqual(2);
      const suiteNames = measurements.map(m => m.name);
      expect(suiteNames.some(n => n.includes('write'))).toBe(true);
      expect(suiteNames.some(n => n.includes('read'))).toBe(true);
      for (const m of measurements) {
        expect(m.suite).toBe('storage');
        expect(m.opsPerSecond).toBeGreaterThan(0);
      }
    });
  });
});
