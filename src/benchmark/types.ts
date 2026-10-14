/**
 * Benchmark types for the Tzun performance profiling tool.
 */

/** Hardware information for benchmark reports. */
export interface HardwareInfo {
  cpu: string;
  cores: number;
  totalMemoryMB: number;
  platform: string;
  arch: string;
  nodeVersion: string;
  gpu: string | null;
}

/** A single benchmark measurement. */
export interface BenchmarkMeasurement {
  /** Name of the benchmark suite. */
  suite: string;
  /** Specific test within the suite. */
  name: string;
  /** Operations per second. */
  opsPerSecond: number;
  /** Average time per operation in milliseconds. */
  avgTimeMs: number;
  /** Minimum time per operation in milliseconds. */
  minTimeMs: number;
  /** Maximum time per operation in milliseconds. */
  maxTimeMs: number;
  /** Total number of iterations run. */
  iterations: number;
  /** Total elapsed time in milliseconds. */
  totalTimeMs: number;
}

/** Full scan time estimate at a given dataset size. */
export interface ScanEstimate {
  records: number;
  estimatedTimeSeconds: number;
}

/** Complete benchmark report. */
export interface BenchmarkReport {
  /** Timestamp when the benchmark started. */
  startedAt: string;
  /** Timestamp when the benchmark completed. */
  completedAt: string;
  /** Total duration in milliseconds. */
  durationMs: number;
  /** Hardware info at time of benchmark. */
  hardware: HardwareInfo;
  /** Digest computer backend used. */
  digestBackend: string;
  /** Individual benchmark measurements. */
  measurements: BenchmarkMeasurement[];
  /** Full scan time estimates at various dataset sizes. */
  scanEstimates: ScanEstimate[];
}

/** Options for running benchmarks. */
export interface BenchmarkOptions {
  /** Which suites to run. Default: all. */
  suites?: BenchmarkSuiteName[];
  /** Minimum duration per benchmark in milliseconds. Default: 1000. */
  minDurationMs?: number;
  /** Number of warmup iterations before measurement. Default: 10. */
  warmupIterations?: number;
  /** Worker counts to test for scanner benchmark. Default: [1, 2, 4, 8]. */
  scannerWorkerCounts?: number[];
}

/** Names of available benchmark suites. */
export type BenchmarkSuiteName =
  | 'serialization'
  | 'digest'
  | 'capture'
  | 'verification'
  | 'scanner'
  | 'storage';
