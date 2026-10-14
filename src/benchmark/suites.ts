import { performance } from 'perf_hooks';
import { BenchmarkMeasurement, BenchmarkOptions } from './types';
import { canonicalSerialize } from '@tzun/engine';
import { getDefaultDigestComputer } from '@tzun/engine';
import { assembleEnvelope } from '@tzun/engine';
import { verifyEnvelope } from '@tzun/engine';
import { SchemaRegistry } from '@tzun/engine';
import { MemoryStorageAdapter } from '../storage/memory';
import { ScheduledScanner } from '../monitoring/scheduled-scanner';
import { MonitoringEventBus } from '../monitoring/event-bus';
import type { Decider, EnvelopeInput } from '@tzun/engine';

/** The decider every benchmark record names. */
const BENCHMARK_DECIDER: Decider = { kind: 'human', id: 'acct:benchmark', agent: null, credential: null, freshness: null };

/** The v1.0 hashed field set a capture serializes, from the engine's registry. */
const HASHED_FIELDS = new SchemaRegistry().get('v1.0')!.hashedFieldSet;

interface TimingResult {
  iterations: number;
  totalTimeMs: number;
  avgTimeMs: number;
  minTimeMs: number;
  maxTimeMs: number;
  opsPerSecond: number;
}

function arrayMin(arr: number[]): number {
  let min = arr[0];
  for (let i = 1; i < arr.length; i++) {
    if (arr[i] < min) min = arr[i];
  }
  return min;
}

function arrayMax(arr: number[]): number {
  let max = arr[0];
  for (let i = 1; i < arr.length; i++) {
    if (arr[i] > max) max = arr[i];
  }
  return max;
}

function runTimed(
  fn: () => void,
  minDurationMs: number,
  warmupIterations: number,
): TimingResult {
  // Warmup
  for (let i = 0; i < warmupIterations; i++) {
    fn();
  }

  const times: number[] = [];
  const startTotal = performance.now();
  let elapsed = 0;

  while (elapsed < minDurationMs) {
    const start = performance.now();
    fn();
    const end = performance.now();
    times.push(end - start);
    elapsed = end - startTotal;
  }

  const totalTimeMs = performance.now() - startTotal;
  const iterations = times.length;
  const avgTimeMs = totalTimeMs / iterations;
  const minTimeMs = arrayMin(times);
  const maxTimeMs = arrayMax(times);
  const opsPerSecond = iterations / (totalTimeMs / 1000);

  return { iterations, totalTimeMs, avgTimeMs, minTimeMs, maxTimeMs, opsPerSecond };
}

function toMeasurement(
  suite: string,
  name: string,
  result: TimingResult,
): BenchmarkMeasurement {
  return {
    suite,
    name,
    opsPerSecond: result.opsPerSecond,
    avgTimeMs: result.avgTimeMs,
    minTimeMs: result.minTimeMs,
    maxTimeMs: result.maxTimeMs,
    iterations: result.iterations,
    totalTimeMs: result.totalTimeMs,
  };
}

// ── Payloads ──────────────────────────────────────────────────────────

function makeSmallPayload(): Record<string, unknown> {
  return {
    evidenceId: 'ev-001',
    aiSystemId: 'test',
    aiOutput: { recommendation: 'approve' },
    action: 'approved',
    reason: 'ok',
    decider: BENCHMARK_DECIDER,
    contributions: null,
    links: null,
    signoffExpectation: null,
    capturedAt: '2026-01-01T00:00:00Z',
    sequenceNumber: 1,
  };
}

function makeMediumPayload(): Record<string, unknown> {
  return {
    evidenceId: 'ev-002',
    aiSystemId: 'ml-pipeline-v3',
    aiOutput: {
      recommendation: 'approve',
      confidence: 0.94,
      factors: {
        creditScore: 780,
        dti: 0.28,
        employmentYears: 5,
        loanAmount: 250000,
        propertyValue: 350000,
        ltv: 0.714,
      },
      riskCategory: 'low',
      alternativeRecommendation: 'approve_with_conditions',
    },
    action: 'approved_with_conditions',
    reason: 'Applicant meets all criteria. Added PMI requirement due to LTV > 0.7.',
    decider: BENCHMARK_DECIDER,
    contributions: null,
    links: null,
    signoffExpectation: null,
    capturedAt: '2026-01-15T10:30:00.123Z',
    sequenceNumber: 42,
  };
}

function makeLargePayload(): Record<string, unknown> {
  const factors: Record<string, unknown> = {};
  for (let i = 0; i < 50; i++) {
    factors[`factor_${i}`] = {
      value: Math.random(),
      weight: Math.random(),
      category: `category_${i % 5}`,
      description: `This is factor number ${i} with a moderately long description for sizing purposes.`,
    };
  }
  return {
    evidenceId: 'ev-003',
    aiSystemId: 'enterprise-ai-v7',
    aiOutput: {
      recommendation: 'review',
      confidence: 0.72,
      factors,
      modelVersion: '7.2.1',
      processingTimeMs: 2345,
    },
    action: 'escalated',
    reason: 'Complex case with multiple risk factors. Escalating to senior reviewer for additional assessment. ' +
      'The model confidence is below our 0.8 threshold for auto-approval, and several factors show borderline values ' +
      'that warrant human review.',
    decider: BENCHMARK_DECIDER,
    contributions: null,
    links: null,
    signoffExpectation: null,
    capturedAt: '2026-02-20T14:45:30.789Z',
    sequenceNumber: 9999,
  };
}

// ── Suite Implementations ─────────────────────────────────────────────

export async function benchmarkSerialization(
  options: BenchmarkOptions = {},
): Promise<BenchmarkMeasurement[]> {
  const minDurationMs = options.minDurationMs ?? 1000;
  const warmup = options.warmupIterations ?? 10;

  const small = makeSmallPayload();
  const medium = makeMediumPayload();
  const large = makeLargePayload();

  return [
    toMeasurement('serialization', 'small payload',
      runTimed(() => canonicalSerialize(small, HASHED_FIELDS), minDurationMs, warmup)),
    toMeasurement('serialization', 'medium payload',
      runTimed(() => canonicalSerialize(medium, HASHED_FIELDS), minDurationMs, warmup)),
    toMeasurement('serialization', 'large payload',
      runTimed(() => canonicalSerialize(large, HASHED_FIELDS), minDurationMs, warmup)),
  ];
}

export async function benchmarkDigest(
  options: BenchmarkOptions = {},
): Promise<BenchmarkMeasurement[]> {
  const minDurationMs = options.minDurationMs ?? 1000;
  const warmup = options.warmupIterations ?? 10;
  const computer = getDefaultDigestComputer();

  const canonical = canonicalSerialize(makeMediumPayload(), HASHED_FIELDS);
  const measurements: BenchmarkMeasurement[] = [];

  // Single digest
  measurements.push(
    toMeasurement('digest', `single (${computer.backend})`,
      runTimed(() => computer.computeDigest(canonical), minDurationMs, warmup)),
  );

  // Batch digest (10 items per batch)
  const batchInput = Array.from({ length: 10 }, () => canonical);
  measurements.push(
    toMeasurement('digest', `batch x10 (${computer.backend})`,
      runTimed(() => computer.computeBatch(batchInput), minDurationMs, warmup)),
  );

  // Batch digest (100 items per batch)
  const largeBatchInput = Array.from({ length: 100 }, () => canonical);
  measurements.push(
    toMeasurement('digest', `batch x100 (${computer.backend})`,
      runTimed(() => computer.computeBatch(largeBatchInput), minDurationMs, warmup)),
  );

  return measurements;
}

export async function benchmarkCapture(
  options: BenchmarkOptions = {},
): Promise<BenchmarkMeasurement[]> {
  const minDurationMs = options.minDurationMs ?? 1000;
  const warmup = options.warmupIterations ?? 10;

  let seqNum = 0;
  let previousDigest: string | undefined;

  const input: EnvelopeInput = {
    aiSystemId: 'benchmark',
    aiOutput: { recommendation: 'approve', confidence: 0.94 },
    action: 'approved',
    reason: 'Benchmark test capture',
    decider: BENCHMARK_DECIDER,
  };

  const result = runTimed(() => {
    seqNum++;
    const envelope = assembleEnvelope(input, { previousDigest, sequenceNumber: seqNum });
    previousDigest = envelope.integrity.canonicalDigest;
  }, minDurationMs, warmup);

  return [toMeasurement('capture', 'envelope assembly', result)];
}

export async function benchmarkVerification(
  options: BenchmarkOptions = {},
): Promise<BenchmarkMeasurement[]> {
  const minDurationMs = options.minDurationMs ?? 1000;
  const warmup = options.warmupIterations ?? 10;
  const registry = new SchemaRegistry();

  const input: EnvelopeInput = {
    aiSystemId: 'benchmark',
    aiOutput: { recommendation: 'approve', confidence: 0.94 },
    action: 'approved',
    reason: 'Benchmark test verification',
    decider: BENCHMARK_DECIDER,
  };

  const envelope = assembleEnvelope(input, { previousDigest: undefined, sequenceNumber: 1 });

  const result = runTimed(
    () => verifyEnvelope(envelope, undefined, registry),
    minDurationMs,
    warmup,
  );

  return [toMeasurement('verification', 'single record verify', result)];
}

export async function benchmarkScanner(
  options: BenchmarkOptions = {},
): Promise<BenchmarkMeasurement[]> {
  const minDurationMs = options.minDurationMs ?? 1000;
  const warmup = options.warmupIterations ?? 2;
  const workerCounts = options.scannerWorkerCounts ?? [1, 2, 4, 8];

  const measurements: BenchmarkMeasurement[] = [];
  const registry = new SchemaRegistry();

  // Prepare a storage with records to scan
  const recordCount = 100;
  const storage = new MemoryStorageAdapter();
  let previousDigest: string | undefined;

  for (let i = 1; i <= recordCount; i++) {
    const input: EnvelopeInput = {
      aiSystemId: 'benchmark',
      aiOutput: { step: i },
      action: 'approved',
      reason: `Step ${i}`,
      decider: BENCHMARK_DECIDER,
    };
    const envelope = assembleEnvelope(input, { previousDigest: previousDigest, sequenceNumber: i });
    await storage.store(envelope);
    previousDigest = envelope.integrity.canonicalDigest;
  }

  for (const workers of workerCounts) {
    const bus = new MonitoringEventBus();
    const scanner = new ScheduledScanner(storage, bus, registry, {
      batchSize: Math.ceil(recordCount / workers),
      workers,
      mode: 'interval',
      intervalMs: 0,
      verifyAttestation: false,
      verifyChainCompleteness: true,
    });

    // Warmup
    for (let i = 0; i < warmup; i++) {
      await scanner.runFullPass();
    }

    const times: number[] = [];
    const startTotal = performance.now();
    let elapsed = 0;

    while (elapsed < minDurationMs) {
      const start = performance.now();
      await scanner.runFullPass();
      const end = performance.now();
      times.push(end - start);
      elapsed = end - startTotal;
    }

    const totalTimeMs = performance.now() - startTotal;
    const iterations = times.length;
    const avgTimeMs = totalTimeMs / iterations;
    // records per second = (records * iterations) / (total time in seconds)
    const recordsPerSecond = (recordCount * iterations) / (totalTimeMs / 1000);

    measurements.push({
      suite: 'scanner',
      name: `${workers} worker(s), ${recordCount} records`,
      opsPerSecond: recordsPerSecond,
      avgTimeMs,
      minTimeMs: arrayMin(times),
      maxTimeMs: arrayMax(times),
      iterations,
      totalTimeMs,
    });
  }

  return measurements;
}

export async function benchmarkStorage(
  options: BenchmarkOptions = {},
): Promise<BenchmarkMeasurement[]> {
  const minDurationMs = options.minDurationMs ?? 1000;
  const warmup = options.warmupIterations ?? 10;
  const registry = new SchemaRegistry();
  const measurements: BenchmarkMeasurement[] = [];

  // Write benchmark
  {
    let writeSeq = 0;
    let writePrevDigest: string | undefined;
    const writeStorage = new MemoryStorageAdapter();

    const writeResult = runTimed(() => {
      writeSeq++;
      const input: EnvelopeInput = {
        aiSystemId: 'benchmark',
        aiOutput: { step: writeSeq },
        action: 'approved',
        reason: `Step ${writeSeq}`,
        decider: BENCHMARK_DECIDER,
      };
      const envelope = assembleEnvelope(input, { previousDigest: writePrevDigest, sequenceNumber: writeSeq });
      // store is async but MemoryStorageAdapter.store is synchronous internally
      writeStorage.store(envelope);
      writePrevDigest = envelope.integrity.canonicalDigest;
    }, minDurationMs, warmup);

    measurements.push(toMeasurement('storage', 'memory write', writeResult));
  }

  // Read benchmark
  {
    const readStorage = new MemoryStorageAdapter();
    const ids: string[] = [];
    let readPrevDigest: string | undefined;

    for (let i = 1; i <= 100; i++) {
      const input: EnvelopeInput = {
        aiSystemId: 'benchmark',
        aiOutput: { step: i },
        action: 'approved',
        reason: `Step ${i}`,
        decider: BENCHMARK_DECIDER,
      };
      const envelope = assembleEnvelope(input, { previousDigest: readPrevDigest, sequenceNumber: i });
      await readStorage.store(envelope);
      ids.push(envelope.payload.evidenceId);
      readPrevDigest = envelope.integrity.canonicalDigest;
    }

    let readIdx = 0;
    const readResult = runTimed(() => {
      readStorage.retrieve(ids[readIdx % ids.length]);
      readIdx++;
    }, minDurationMs, warmup);

    measurements.push(toMeasurement('storage', 'memory read', readResult));
  }

  return measurements;
}
