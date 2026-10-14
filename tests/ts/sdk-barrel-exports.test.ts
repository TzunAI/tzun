// tests/ts/sdk-barrel-exports.test.ts
// The hosted service imports the scanner pipeline from @tzun/sdk; these
// classes must be exported from the package barrel.
import { MonitoringEventBus, TamperDetector, ScheduledScanner, RFC3161Client } from '../../src/sdk/index';
// CaptureOptions must be exported so callers can type idempotencyKey params.
// Type-only import — absence breaks tsc (compile-time gate, no runtime value needed).
import type { CaptureOptions } from '../../src/sdk/index';
// Wrapper surface + named per-vendor aliases from the barrel.
import {
  SUPPORTED_VENDORS, TZUN_CAPTURE_KWARG,
  wrapOpenAI, wrapAnthropic, wrapAwsBedrock, wrapGcpVertex, wrapAzureAI, wrapNvidiaNim, wrapHFInference,
} from '../../src/sdk/index';
import type { DecisionInput, AttachOptions, SupportedVendor } from '../../src/sdk/index';

// Compile-time assertion: ensure CaptureOptions is a usable type. If the export
// disappears, this assignment errors at tsc.
const _captureOptionsTypeCheck: CaptureOptions = {};
void _captureOptionsTypeCheck;

describe('sdk barrel exports', () => {
  it('exports the monitoring pipeline classes', () => {
    expect(typeof MonitoringEventBus).toBe('function');
    expect(typeof TamperDetector).toBe('function');
    expect(typeof ScheduledScanner).toBe('function');
    expect(typeof RFC3161Client).toBe('function');
  });
});

it('re-exports the wrapper types + constants from the barrel', () => {
  expect(Array.isArray(SUPPORTED_VENDORS)).toBe(true);
  expect(TZUN_CAPTURE_KWARG).toBe('tzun_capture');
  expect(typeof wrapOpenAI).toBe('function');
  expect(typeof wrapAnthropic).toBe('function');
  expect(typeof wrapAwsBedrock).toBe('function');
  expect(typeof wrapGcpVertex).toBe('function');
  expect(typeof wrapAzureAI).toBe('function');
  expect(typeof wrapNvidiaNim).toBe('function');
  expect(typeof wrapHFInference).toBe('function');
  const _t: { d?: DecisionInput; a?: AttachOptions; v?: SupportedVendor } = {};
  expect(_t).toBeDefined();
});
