import { BenchmarkReport, BenchmarkMeasurement } from './types';

/**
 * Format a BenchmarkReport as a human-readable text summary.
 */
export function formatReport(report: BenchmarkReport): string {
  const lines: string[] = [];

  lines.push('');
  lines.push('='.repeat(70));
  lines.push('  Tzun SDK Benchmark Report');
  lines.push('='.repeat(70));
  lines.push('');

  // Hardware
  lines.push('Hardware:');
  lines.push(`  CPU:      ${report.hardware.cpu}`);
  lines.push(`  Cores:    ${report.hardware.cores}`);
  lines.push(`  Memory:   ${report.hardware.totalMemoryMB} MB`);
  lines.push(`  Platform: ${report.hardware.platform} ${report.hardware.arch}`);
  lines.push(`  Node.js:  ${report.hardware.nodeVersion}`);
  if (report.hardware.gpu) {
    lines.push(`  GPU:      ${report.hardware.gpu}`);
  }
  lines.push(`  Digest:   ${report.digestBackend}`);
  lines.push('');

  // Group measurements by suite
  const suites = new Map<string, BenchmarkMeasurement[]>();
  for (const m of report.measurements) {
    if (!suites.has(m.suite)) {
      suites.set(m.suite, []);
    }
    suites.get(m.suite)!.push(m);
  }

  for (const [suite, measurements] of suites) {
    lines.push('-'.repeat(70));
    lines.push(`  ${suite.toUpperCase()}`);
    lines.push('-'.repeat(70));

    for (const m of measurements) {
      const ops = formatNumber(m.opsPerSecond);
      const avg = m.avgTimeMs < 1 ? `${(m.avgTimeMs * 1000).toFixed(1)} us` : `${m.avgTimeMs.toFixed(2)} ms`;
      lines.push(`  ${m.name.padEnd(40)} ${ops.padStart(12)} ops/sec  avg: ${avg}`);
    }
    lines.push('');
  }

  // Scan estimates
  if (report.scanEstimates.length > 0) {
    lines.push('-'.repeat(70));
    lines.push('  Scan Time Estimates');
    lines.push('-'.repeat(70));

    for (const est of report.scanEstimates) {
      const records = formatNumber(est.records);
      const time = est.estimatedTimeSeconds < 0
        ? 'N/A'
        : formatDuration(est.estimatedTimeSeconds);
      lines.push(`  ${records.padStart(15)} records:  ${time}`);
    }
    lines.push('');
  }

  // Footer
  lines.push('='.repeat(70));
  lines.push(`  Duration: ${(report.durationMs / 1000).toFixed(1)}s`);
  lines.push(`  Started:  ${report.startedAt}`);
  lines.push(`  Finished: ${report.completedAt}`);
  lines.push('='.repeat(70));
  lines.push('');

  return lines.join('\n');
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) {
    return (n / 1_000_000).toFixed(2) + 'M';
  }
  if (n >= 1_000) {
    return (n / 1_000).toFixed(1) + 'K';
  }
  return n.toFixed(0);
}

function formatDuration(seconds: number): string {
  if (seconds < 1) {
    return `${(seconds * 1000).toFixed(0)} ms`;
  }
  if (seconds < 60) {
    return `${seconds.toFixed(1)} s`;
  }
  const minutes = seconds / 60;
  if (minutes < 60) {
    return `${minutes.toFixed(1)} min`;
  }
  const hours = minutes / 60;
  return `${hours.toFixed(1)} h`;
}
