import { execSync } from 'child_process';
import * as path from 'path';

// Each case spawns ts-node, which compiles the CLI before it runs; under a
// full parallel suite that compile alone can take tens of seconds.
const CLI_TIMEOUT_MS = 120_000;

describe('Benchmark CLI', () => {
  const cliPath = path.resolve(__dirname, '../../src/benchmark/cli.ts');

  it('CLI invocation completes and produces JSON output', () => {
    const output = execSync(
      `npx ts-node ${cliPath} --json --suites serialization --min-duration 100 --warmup 2`,
      {
        encoding: 'utf-8',
        timeout: CLI_TIMEOUT_MS,
        cwd: path.resolve(__dirname, '../..'),
      },
    );

    // The output should contain valid JSON
    const jsonStart = output.indexOf('{');
    expect(jsonStart).toBeGreaterThanOrEqual(0);

    const jsonStr = output.slice(jsonStart);
    const report = JSON.parse(jsonStr);

    expect(report).toHaveProperty('startedAt');
    expect(report).toHaveProperty('completedAt');
    expect(report).toHaveProperty('hardware');
    expect(report).toHaveProperty('measurements');
    expect(report.measurements.length).toBeGreaterThan(0);
  }, CLI_TIMEOUT_MS);

  it('CLI produces human-readable output by default', () => {
    const output = execSync(
      `npx ts-node ${cliPath} --suites digest --min-duration 100 --warmup 2`,
      {
        encoding: 'utf-8',
        timeout: CLI_TIMEOUT_MS,
        cwd: path.resolve(__dirname, '../..'),
      },
    );

    expect(output).toContain('Benchmark Report');
    expect(output).toContain('Hardware');
    expect(output).toContain('ops/sec');
  }, CLI_TIMEOUT_MS);

  it('CLI --help shows usage information', () => {
    const output = execSync(
      `npx ts-node ${cliPath} --help`,
      {
        encoding: 'utf-8',
        timeout: CLI_TIMEOUT_MS,
        cwd: path.resolve(__dirname, '../..'),
      },
    );

    expect(output).toContain('Usage');
    expect(output).toContain('--json');
    expect(output).toContain('--suites');
  }, CLI_TIMEOUT_MS);
});
