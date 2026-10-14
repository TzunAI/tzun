import { Router, Request, Response } from 'express';
import { runBenchmark } from './runner';
import { BenchmarkSuiteName } from './types';
import { ALL_SUITES } from './runner';

const BENCHMARK_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Tzun SDK Benchmark</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 900px; margin: 0 auto; padding: 24px; background: #fafafa; color: #1a1a1a; }
  h1 { font-size: 1.5rem; margin-bottom: 8px; }
  p.subtitle { color: #666; margin-bottom: 24px; font-size: 0.9rem; }
  .controls { display: flex; gap: 12px; align-items: center; margin-bottom: 24px; flex-wrap: wrap; }
  .controls label { font-size: 0.85rem; color: #444; }
  .controls select, .controls input { padding: 6px 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 0.85rem; }
  button { padding: 8px 20px; background: #2563eb; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9rem; font-weight: 500; }
  button:hover { background: #1d4ed8; }
  button:disabled { background: #94a3b8; cursor: not-allowed; }
  #progress { display: none; margin-bottom: 16px; padding: 12px; background: #e0f2fe; border-radius: 4px; font-size: 0.85rem; }
  #results { display: none; }
  .hardware { background: #fff; border: 1px solid #e5e7eb; border-radius: 6px; padding: 16px; margin-bottom: 16px; font-size: 0.85rem; }
  .hardware dt { font-weight: 600; display: inline; }
  .hardware dd { display: inline; margin-right: 16px; }
  table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e5e7eb; border-radius: 6px; overflow: hidden; margin-bottom: 16px; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #f0f0f0; font-size: 0.85rem; }
  th { background: #f8fafc; font-weight: 600; color: #374151; }
  td.number { text-align: right; font-variant-numeric: tabular-nums; }
  .suite-header { background: #f1f5f9; font-weight: 600; }
  .estimates { background: #fff; border: 1px solid #e5e7eb; border-radius: 6px; padding: 16px; font-size: 0.85rem; }
  .estimates h3 { margin-bottom: 8px; }
  .footer { margin-top: 16px; font-size: 0.8rem; color: #888; }
</style>
</head>
<body>
<h1>Tzun SDK Benchmark</h1>
<p class="subtitle">Performance profiling for the evidence capture pipeline</p>

<div class="controls">
  <label>Suites:
    <select id="suites" multiple size="3">
      <option value="serialization" selected>Serialization</option>
      <option value="digest" selected>Digest</option>
      <option value="capture" selected>Capture</option>
      <option value="verification" selected>Verification</option>
      <option value="scanner">Scanner</option>
      <option value="storage" selected>Storage</option>
    </select>
  </label>
  <label>Min Duration (ms):
    <input id="minDuration" type="number" value="1000" min="100" step="100">
  </label>
  <button id="runBtn" onclick="runBenchmark()">Run Benchmark</button>
</div>

<div id="progress">Running benchmarks... This may take a minute.</div>
<div id="results"></div>

<script>
async function runBenchmark() {
  var btn = document.getElementById('runBtn');
  var progress = document.getElementById('progress');
  var results = document.getElementById('results');

  btn.disabled = true;
  progress.style.display = 'block';
  results.style.display = 'none';

  var suitesSelect = document.getElementById('suites');
  var suites = Array.from(suitesSelect.selectedOptions).map(function(o) { return o.value; });
  var minDurationMs = parseInt(document.getElementById('minDuration').value, 10) || 1000;

  try {
    var res = await fetch('/v1/benchmark/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ suites: suites, minDurationMs: minDurationMs, warmupIterations: 10 }),
    });
    var report = await res.json();
    renderReport(report);
  } catch (err) {
    results.innerHTML = '<p style="color:red">Benchmark failed: ' + err.message + '</p>';
    results.style.display = 'block';
  } finally {
    btn.disabled = false;
    progress.style.display = 'none';
  }
}

function renderReport(report) {
  var results = document.getElementById('results');
  var html = '';

  // Hardware
  html += '<div class="hardware"><dl>';
  html += '<dt>CPU:</dt><dd>' + report.hardware.cpu + '</dd>';
  html += '<dt>Cores:</dt><dd>' + report.hardware.cores + '</dd>';
  html += '<dt>Memory:</dt><dd>' + report.hardware.totalMemoryMB + ' MB</dd>';
  html += '<dt>Platform:</dt><dd>' + report.hardware.platform + ' ' + report.hardware.arch + '</dd>';
  html += '<dt>Node:</dt><dd>' + report.hardware.nodeVersion + '</dd>';
  html += '<dt>Digest:</dt><dd>' + report.digestBackend + '</dd>';
  html += '</dl></div>';

  // Measurements table
  html += '<table><thead><tr><th>Suite</th><th>Benchmark</th><th class="number">ops/sec</th><th class="number">avg</th><th class="number">min</th><th class="number">max</th><th class="number">iterations</th></tr></thead><tbody>';

  for (var i = 0; i < report.measurements.length; i++) {
    var m = report.measurements[i];
    html += '<tr>';
    html += '<td>' + m.suite + '</td>';
    html += '<td>' + m.name + '</td>';
    html += '<td class="number">' + fmtNum(m.opsPerSecond) + '</td>';
    html += '<td class="number">' + fmtTime(m.avgTimeMs) + '</td>';
    html += '<td class="number">' + fmtTime(m.minTimeMs) + '</td>';
    html += '<td class="number">' + fmtTime(m.maxTimeMs) + '</td>';
    html += '<td class="number">' + m.iterations.toLocaleString() + '</td>';
    html += '</tr>';
  }
  html += '</tbody></table>';

  // Scan estimates
  if (report.scanEstimates && report.scanEstimates.length > 0) {
    html += '<div class="estimates"><h3>Scan Time Estimates</h3><table><thead><tr><th class="number">Records</th><th class="number">Estimated Time</th></tr></thead><tbody>';
    for (var j = 0; j < report.scanEstimates.length; j++) {
      var est = report.scanEstimates[j];
      html += '<tr><td class="number">' + est.records.toLocaleString() + '</td><td class="number">' + fmtDuration(est.estimatedTimeSeconds) + '</td></tr>';
    }
    html += '</tbody></table></div>';
  }

  html += '<p class="footer">Duration: ' + (report.durationMs / 1000).toFixed(1) + 's | ' + report.startedAt + '</p>';

  results.innerHTML = html;
  results.style.display = 'block';
}

function fmtNum(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return n.toFixed(0);
}

function fmtTime(ms) {
  if (ms < 0.001) return (ms * 1e6).toFixed(0) + ' ns';
  if (ms < 1) return (ms * 1000).toFixed(1) + ' us';
  return ms.toFixed(2) + ' ms';
}

function fmtDuration(s) {
  if (s < 0) return 'N/A';
  if (s < 1) return (s * 1000).toFixed(0) + ' ms';
  if (s < 60) return s.toFixed(1) + ' s';
  if (s < 3600) return (s / 60).toFixed(1) + ' min';
  return (s / 3600).toFixed(1) + ' h';
}
</script>
</body>
</html>`;

/** Hard ceilings on the request-driven benchmark knobs. */
const MAX_MIN_DURATION_MS = 10_000;
const MAX_WARMUP_ITERATIONS = 100;
const MAX_SCANNER_WORKERS = 16;
const MAX_SCANNER_WORKER_COUNTS = 8;

/**
 * Validate the POST body before any of it reaches `runBenchmark`.
 *
 * The suites are synchronous busy loops (`while (elapsed < minDurationMs)
 * { fn(); }`), several of them run three times per suite, and a body-less POST
 * runs all six. With the caller choosing `minDurationMs` there was no upper
 * bound at all on how long one request could block the event loop, and
 * `scannerWorkerCounts: [0]` reached a segment loop that never advanced.
 *
 * Returns an error string, or null when the body is acceptable.
 */
function validateBenchmarkBody(body: unknown): string | null {
  const b = (body ?? {}) as Record<string, unknown>;

  if (b.suites !== undefined) {
    if (!Array.isArray(b.suites) || b.suites.length === 0) {
      return 'suites must be a non-empty array';
    }
    for (const s of b.suites) {
      if (typeof s !== 'string' || !ALL_SUITES.includes(s as BenchmarkSuiteName)) {
        return `unknown suite "${String(s)}" — expected one of ${ALL_SUITES.join(', ')}`;
      }
    }
  }

  if (b.minDurationMs !== undefined) {
    if (
      typeof b.minDurationMs !== 'number' ||
      !Number.isInteger(b.minDurationMs) ||
      b.minDurationMs < 100 ||
      b.minDurationMs > MAX_MIN_DURATION_MS
    ) {
      return `minDurationMs must be an integer between 100 and ${MAX_MIN_DURATION_MS}`;
    }
  }

  if (b.warmupIterations !== undefined) {
    if (
      typeof b.warmupIterations !== 'number' ||
      !Number.isInteger(b.warmupIterations) ||
      b.warmupIterations < 0 ||
      b.warmupIterations > MAX_WARMUP_ITERATIONS
    ) {
      return `warmupIterations must be an integer between 0 and ${MAX_WARMUP_ITERATIONS}`;
    }
  }

  if (b.scannerWorkerCounts !== undefined) {
    if (
      !Array.isArray(b.scannerWorkerCounts) ||
      b.scannerWorkerCounts.length === 0 ||
      b.scannerWorkerCounts.length > MAX_SCANNER_WORKER_COUNTS
    ) {
      return `scannerWorkerCounts must be an array of 1..${MAX_SCANNER_WORKER_COUNTS} entries`;
    }
    for (const w of b.scannerWorkerCounts) {
      if (typeof w !== 'number' || !Number.isInteger(w) || w < 1 || w > MAX_SCANNER_WORKERS) {
        return `scannerWorkerCounts entries must be integers between 1 and ${MAX_SCANNER_WORKERS} (received ${String(w)})`;
      }
    }
  }

  return null;
}

export function createBenchmarkRouter(): Router {
  const router = Router();

  router.get('/v1/benchmark', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/html');
    res.status(200).send(BENCHMARK_HTML);
  });

  router.post('/v1/benchmark/run', async (req: Request, res: Response) => {
    const invalid = validateBenchmarkBody(req.body);
    if (invalid !== null) {
      res.status(400).json({ error: 'invalid_request', message: invalid });
      return;
    }

    try {
      const suites = req.body?.suites as BenchmarkSuiteName[] | undefined;
      const minDurationMs = req.body?.minDurationMs as number | undefined;
      const warmupIterations = req.body?.warmupIterations as number | undefined;
      const scannerWorkerCounts = req.body?.scannerWorkerCounts as number[] | undefined;

      const report = await runBenchmark({
        suites,
        minDurationMs,
        warmupIterations,
        scannerWorkerCounts,
      });

      res.status(200).json(report);
    } catch (error) {
      res.status(500).json({
        error: 'Benchmark failed',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  });

  return router;
}
