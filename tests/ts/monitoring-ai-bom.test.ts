/**
 * AI-BOM tamper-incident type tests.
 *
 * The four new incident types live alongside the existing monitoring types:
 *   - `descriptor_resolution_failure`         (warning)
 *   - `descriptor_digest_mismatch`            (critical)
 *   - `parent_descriptor_resolution_failure`  (warning)
 *   - `parent_descriptor_digest_mismatch`     (critical)
 */

import {
  MonitoringEventType,
  TamperIncident,
  TamperSeverity,
  AI_BOM_TAMPER_INCIDENT_SEVERITY,
} from '@tzun/engine';

describe('monitoring: AI-BOM tamper incident types', () => {
  it('TamperIncidentType (MonitoringEventType) union contains the 4 new types', () => {
    // TypeScript compile-time: each of the 4 strings must be a valid MonitoringEventType.
    const a: MonitoringEventType = 'descriptor_resolution_failure';
    const b: MonitoringEventType = 'descriptor_digest_mismatch';
    const c: MonitoringEventType = 'parent_descriptor_resolution_failure';
    const d: MonitoringEventType = 'parent_descriptor_digest_mismatch';
    expect([a, b, c, d]).toEqual([
      'descriptor_resolution_failure',
      'descriptor_digest_mismatch',
      'parent_descriptor_resolution_failure',
      'parent_descriptor_digest_mismatch',
    ]);
  });

  it('severity mapping for the 4 new types matches the spec table', () => {
    expect(AI_BOM_TAMPER_INCIDENT_SEVERITY.descriptor_resolution_failure).toBe('warning');
    expect(AI_BOM_TAMPER_INCIDENT_SEVERITY.descriptor_digest_mismatch).toBe('critical');
    expect(AI_BOM_TAMPER_INCIDENT_SEVERITY.parent_descriptor_resolution_failure).toBe('warning');
    expect(AI_BOM_TAMPER_INCIDENT_SEVERITY.parent_descriptor_digest_mismatch).toBe('critical');
  });

  it('severity values are valid TamperSeverity values', () => {
    const all = Object.values(AI_BOM_TAMPER_INCIDENT_SEVERITY);
    for (const sev of all) {
      const s: TamperSeverity = sev; // compile-time assertion
      expect(['critical', 'warning', 'info']).toContain(s);
    }
  });

  it('the 4 new types flow through TamperIncident interface as concrete values', () => {
    // Construct one TamperIncident of each new type and assert no TS errors at
    // compile time, plus runtime structural sanity.
    const a: TamperIncident = {
      id: 'a',
      detectedAt: '2026-05-25T00:00:00Z',
      severity: AI_BOM_TAMPER_INCIDENT_SEVERITY.descriptor_resolution_failure,
      type: 'descriptor_resolution_failure',
      affectedRecords: ['e1'],
      details: 'descriptor missing',
      status: 'open',
    };
    const b: TamperIncident = {
      id: 'b',
      detectedAt: '2026-05-25T00:00:00Z',
      severity: AI_BOM_TAMPER_INCIDENT_SEVERITY.descriptor_digest_mismatch,
      type: 'descriptor_digest_mismatch',
      affectedRecords: ['e2'],
      details: 'digest mismatch',
      status: 'open',
    };
    const c: TamperIncident = {
      id: 'c',
      detectedAt: '2026-05-25T00:00:00Z',
      severity: AI_BOM_TAMPER_INCIDENT_SEVERITY.parent_descriptor_resolution_failure,
      type: 'parent_descriptor_resolution_failure',
      affectedRecords: ['e3'],
      details: 'parent missing',
      status: 'open',
    };
    const d: TamperIncident = {
      id: 'd',
      detectedAt: '2026-05-25T00:00:00Z',
      severity: AI_BOM_TAMPER_INCIDENT_SEVERITY.parent_descriptor_digest_mismatch,
      type: 'parent_descriptor_digest_mismatch',
      affectedRecords: ['e4'],
      details: 'parent digest mismatch',
      status: 'open',
    };

    expect([a, b, c, d].map((i) => i.type)).toEqual([
      'descriptor_resolution_failure',
      'descriptor_digest_mismatch',
      'parent_descriptor_resolution_failure',
      'parent_descriptor_digest_mismatch',
    ]);
  });
});
