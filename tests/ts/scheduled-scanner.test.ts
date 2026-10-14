import { storeAtTakenPosition } from './helpers/store-owner';
import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { ScheduledScanner } from '../../src/monitoring/scheduled-scanner';
import { TamperDetector } from '../../src/monitoring/tamper-detector';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
// These cases tamper by rewriting the stored row itself, through
// `rewriteStoredEnvelope`, which works on every backend. The memory adapter
// clones on read and write, as the SQL adapters do, so mutating an object a
// read returned would change nothing in the store and leave the detection
// under test with nothing to detect.
import { SchemaRegistry } from '@tzun/engine';
import { assembleEnvelope } from '@tzun/engine';
import { EvidenceEnvelope } from '@tzun/engine';
import { MonitoringEvent, ScannerConfig } from '@tzun/engine';
import { signedTimestampToken } from './rfc3161-fixture';
import { UnreadableTrustAnchorError } from '../../src/attestation/rfc3161-token';
import { createHash } from 'crypto';
import { Tzun } from '../../src/sdk/index';
import { TamperIncident, ScanSummary } from '@tzun/engine';
import { readFileSync } from 'fs';
import { join } from 'path';
// tzun-anchor/1 artifacts (`nonRepudiation.anchor`) over the records' own
// digests: genuine RFC 6962 paths in a genuine evidence log and anchor log.
import { anchoredRecord } from './helpers/anchor-fixtures';

// ---------------------------------------------------------------------------
// Default config shared across all tests
// ---------------------------------------------------------------------------
const defaultConfig: ScannerConfig = {
  batchSize: 100,
  workers: 2,
  mode: 'interval',
  intervalMs: 0,
  verifyAttestation: false,
  verifyChainCompleteness: true,
};

// ---------------------------------------------------------------------------
// captureN helper — creates N properly-chained envelopes via assembleEnvelope
// ---------------------------------------------------------------------------
async function captureN(
  storage: MemoryStorageAdapter,
  n: number,
): Promise<EvidenceEnvelope[]> {
  const registry = new SchemaRegistry();
  const envelopes: EvidenceEnvelope[] = [];
  let previousDigest: string | undefined;

  for (let i = 1; i <= n; i++) {
    const envelope = assembleEnvelope({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiSystemId: 'test-system',
        aiOutput: { recommendation: `rec-${i}` },
        action: 'approved',
        reason: `reason-${i}`,
      }, { previousDigest: previousDigest, sequenceNumber: i });
    await storage.store(envelope);
    previousDigest = envelope.integrity.canonicalDigest;
    envelopes.push(envelope);
  }

  return envelopes;
}

describe('ScheduledScanner', () => {
  let bus: MonitoringEventBus;
  let storage: MemoryStorageAdapter;
  let registry: SchemaRegistry;

  beforeEach(() => {
    bus = new MonitoringEventBus();
    storage = new MemoryStorageAdapter();
    registry = new SchemaRegistry();
  });

  // ---------------------------------------------------------------------------
  // Test 1: Full pass verifies every record exactly once
  // ---------------------------------------------------------------------------
  it('full pass verifies every record exactly once (10 records)', async () => {
    await captureN(storage, 10);

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    const verifiedIds: string[] = [];
    bus.subscribe((event) => {
      if (event.type === 'record_verified') {
        verifiedIds.push(event.evidenceId);
      }
    });

    await scanner.runFullPass();

    expect(verifiedIds).toHaveLength(10);
    // Each ID should appear exactly once
    const unique = new Set(verifiedIds);
    expect(unique.size).toBe(10);
  });

  // ---------------------------------------------------------------------------
  // Test 2: scan_completed event fires with correct counts
  // ---------------------------------------------------------------------------
  it('scan_completed event fires with correct recordsChecked and issuesFound', async () => {
    await captureN(storage, 5);

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    const completedEvents: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'scan_completed') {
        completedEvents.push(event);
      }
    });

    await scanner.runFullPass();

    expect(completedEvents).toHaveLength(1);
    const completed = completedEvents[0];
    expect(completed.type).toBe('scan_completed');
    if (completed.type === 'scan_completed') {
      expect(completed.recordsChecked).toBe(5);
      expect(completed.issuesFound).toBe(0);
    }
  });

  // ---------------------------------------------------------------------------
  // Test 3: Digest mismatch detected (tamper record 3's payload)
  // ---------------------------------------------------------------------------
  it('detects digest mismatch when record payload is tampered', async () => {
    const envelopes = await captureN(storage, 5);

    // Tamper record 3 in the stored row
    await rewriteStoredEnvelope(storage, envelopes[2].payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED'; });

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    const mismatches: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'digest_mismatch') {
        mismatches.push(event);
      }
    });

    await scanner.runFullPass();

    expect(mismatches).toHaveLength(1);
    if (mismatches[0].type === 'digest_mismatch') {
      expect(mismatches[0].evidenceId).toBe(envelopes[2].payload.evidenceId);
    }
  });

  // ---------------------------------------------------------------------------
  // Test 4: Chain break detected (tamper record 3's chainLink)
  // ---------------------------------------------------------------------------
  it('detects chain break when chainLink is tampered', async () => {
    const envelopes = await captureN(storage, 5);

    // Tamper record 3's chainLink
    await rewriteStoredEnvelope(storage, envelopes[2].payload.evidenceId, (e) => { e.integrity.chainLink = 'deadbeef'; });

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    const breaks: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'chain_break') {
        breaks.push(event);
      }
    });

    await scanner.runFullPass();

    expect(breaks).toHaveLength(1);
    if (breaks[0].type === 'chain_break') {
      expect(breaks[0].evidenceId).toBe(envelopes[2].payload.evidenceId);
      expect(breaks[0].sequenceNumber).toBe(3);
    }
  });

  // ---------------------------------------------------------------------------
  // Test 5: Sequence gap detected (delete record 3 from storage)
  // ---------------------------------------------------------------------------
  it('detects sequence gap when a record is missing', async () => {
    const envelopes = await captureN(storage, 5);

    // Delete record 3 by directly removing from the internal map.
    // MemoryStorageAdapter uses a private `envelopes` Map — access via cast.
    const internalMap = (storage as unknown as { envelopes: Map<string, EvidenceEnvelope> }).envelopes;
    internalMap.delete(envelopes[2].payload.evidenceId);

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    const gaps: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'sequence_gap') {
        gaps.push(event);
      }
    });

    await scanner.runFullPass();

    expect(gaps).toHaveLength(1);
    if (gaps[0].type === 'sequence_gap') {
      expect(gaps[0].expectedSequence).toBe(3);
      expect(gaps[0].foundSequence).toBe(4);
    }
  });

  // ---------------------------------------------------------------------------
  // Test 6: Parallel workers verify all records
  // ---------------------------------------------------------------------------
  it('parallel workers with 4 workers, batchSize 5 still verify all 20 records', async () => {
    await captureN(storage, 20);

    const config: ScannerConfig = {
      ...defaultConfig,
      batchSize: 5,
      workers: 4,
    };

    const scanner = new ScheduledScanner(storage, bus, registry, config);

    const verifiedIds: string[] = [];
    bus.subscribe((event) => {
      if (event.type === 'record_verified') {
        verifiedIds.push(event.evidenceId);
      }
    });

    await scanner.runFullPass();

    expect(verifiedIds).toHaveLength(20);
    const unique = new Set(verifiedIds);
    expect(unique.size).toBe(20);
  });

  // ---------------------------------------------------------------------------
  // Test 7: Scanner state tracks progress
  // ---------------------------------------------------------------------------
  it('tracks totalPasses, lastCompletedPassAt, and highWaterMark', async () => {
    await captureN(storage, 5);

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    const stateBefore = scanner.getState();
    expect(stateBefore.totalPasses).toBe(0);
    expect(stateBefore.lastCompletedPassAt).toBeNull();
    expect(stateBefore.highWaterMark).toBe(0);

    await scanner.runFullPass();

    const stateAfter = scanner.getState();
    expect(stateAfter.totalPasses).toBe(1);
    expect(stateAfter.lastCompletedPassAt).not.toBeNull();
    expect(stateAfter.highWaterMark).toBe(5);

    // Second pass
    await scanner.runFullPass();
    const stateAfter2 = scanner.getState();
    expect(stateAfter2.totalPasses).toBe(2);
  });

  // ---------------------------------------------------------------------------
  // Test 8: Empty storage — 0 records checked
  // ---------------------------------------------------------------------------
  it('handles empty storage: 0 records checked', async () => {
    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    const completedEvents: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'scan_completed') {
        completedEvents.push(event);
      }
    });

    await scanner.runFullPass();

    expect(completedEvents).toHaveLength(1);
    if (completedEvents[0].type === 'scan_completed') {
      expect(completedEvents[0].recordsChecked).toBe(0);
      expect(completedEvents[0].issuesFound).toBe(0);
    }

    const state = scanner.getState();
    expect(state.totalPasses).toBe(1);
  });

  // ---------------------------------------------------------------------------
  // Test 9: verifyAttestation detects missing artifacts on 'complete' status
  // ---------------------------------------------------------------------------
  it('detects missing attestation artifacts when verifyAttestation is enabled', async () => {
    const envelopes = await captureN(storage, 3);

    // Mark record 2 as 'complete' attestation but leave nonRepudiation empty
    await rewriteStoredEnvelope(storage, envelopes[1].payload.evidenceId, (e) => {
      e.attestationStatus = 'complete';
      e.nonRepudiation = {}; // no artifacts
    });

    const config: ScannerConfig = {
      ...defaultConfig,
      verifyAttestation: true,
    };

    const scanner = new ScheduledScanner(storage, bus, registry, config);

    const attestationEvents: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') {
        attestationEvents.push(event);
      }
    });

    await scanner.runFullPass();

    // Should detect 3 missing components (timestamp, signature, anchor)
    expect(attestationEvents).toHaveLength(3);
    const components = attestationEvents.map(
      (e) => (e as { component: string }).component,
    );
    expect(components).toContain('timestamp');
    expect(components).toContain('signature');
    expect(components).toContain('anchor');
  });

  // ---------------------------------------------------------------------------
  // Test 10: verifyAttestation: false skips attestation checking
  // ---------------------------------------------------------------------------
  it('does not check attestation when verifyAttestation is false', async () => {
    const envelopes = await captureN(storage, 3);

    // Mark record 2 as 'complete' with no artifacts
    await rewriteStoredEnvelope(storage, envelopes[1].payload.evidenceId, (e) => {
      e.attestationStatus = 'complete';
      e.nonRepudiation = {};
    });

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    const attestationEvents: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') {
        attestationEvents.push(event);
      }
    });

    await scanner.runFullPass();

    // No attestation events since verifyAttestation is false
    expect(attestationEvents).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // Test 11: partial attestation whose only artifact is a real token passes
  //
  // A partial record with a usable artifact is not an incident. The artifact
  // here is a genuine timestamp token bound to the record's digest. A
  // non-empty string in the same field is not a timestamp, and the next test
  // (Test 11b, a non-empty string) pins that it is reported.
  // ---------------------------------------------------------------------------
  it('partial attestation with one VERIFIABLE artifact present does not emit events', async () => {
    const envelopes = await captureN(storage, 2);

    const token = await signedTimestampToken(envelopes[0].integrity.canonicalDigest);
    await rewriteStoredEnvelope(storage, envelopes[0].payload.evidenceId, (e) => {
      e.attestationStatus = 'partial';
      e.nonRepudiation = {
        rfc3161Token: token,
      };
    });

    const config: ScannerConfig = {
      ...defaultConfig,
      verifyAttestation: true,
    };

    const scanner = new ScheduledScanner(storage, bus, registry, config);

    const attestationEvents: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') {
        attestationEvents.push(event);
      }
    });

    await scanner.runFullPass();

    // partial with one genuine, record-bound artifact => no issue
    expect(attestationEvents).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // Test 11b: a non-empty string is not a timestamp
  //
  // The 'partial' requirement is met by a token that parses, not by any truthy
  // rfc3161Token. A presence-only check would accept a simulated placeholder
  // and, in production, whatever HTML a captive portal or CDN served on an
  // HTTP 200.
  // ---------------------------------------------------------------------------
  it('emits attestation_invalid when the rfc3161Token is not a parseable token', async () => {
    const envelopes = await captureN(storage, 2);

    await rewriteStoredEnvelope(storage, envelopes[0].payload.evidenceId, (e) => {
      e.attestationStatus = 'partial';
      e.nonRepudiation = { rfc3161Token: 'some-token' };
    });

    const scanner = new ScheduledScanner(storage, bus, registry, {
      ...defaultConfig,
      verifyAttestation: true,
    });

    const attestationEvents: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') attestationEvents.push(event);
    });

    await scanner.runFullPass();

    expect(attestationEvents).toHaveLength(1);
    expect(attestationEvents[0]).toMatchObject({
      component: 'timestamp',
      reason: 'unparseable_token',
      evidenceId: envelopes[0].payload.evidenceId,
    });
  });

  // ---------------------------------------------------------------------------
  // Test 11b: a 'pending' record's artifacts are verified as they arrive
  // ---------------------------------------------------------------------------
  //
  // 'pending' means a component the writer obtains for every record has not
  // arrived yet (determineAttestationStatus) — typically a timestamp
  // in hand and an anchor still to come. Skipping the whole record would leave
  // the timestamp it DOES carry unverified until the anchor lands, and
  // anchors wait on Merkle batches.
  describe('a pending record', () => {
    async function scanPending(nonRepudiation: EvidenceEnvelope['nonRepudiation']) {
      const envelopes = await captureN(storage, 2);
      await rewriteStoredEnvelope(storage, envelopes[0].payload.evidenceId, (e) => {
        e.attestationStatus = 'pending';
        e.nonRepudiation = nonRepudiation;
      });
      const events: MonitoringEvent[] = [];
      bus.subscribe((event) => {
        if (
          event.type === 'attestation_invalid' ||
          event.type === 'attestation_unverifiable' ||
          event.type === 'scan_completed'
        ) {
          events.push(event);
        }
      });
      await new ScheduledScanner(storage, bus, registry, {
        ...defaultConfig,
        verifyAttestation: true,
      }).runFullPass();
      const completed = events.find((e) => e.type === 'scan_completed');
      if (completed?.type !== 'scan_completed') throw new Error('no scan_completed');
      return {
        envelopes,
        findings: events.filter((e) => e.type !== 'scan_completed'),
        completed,
      };
    }

    it('has the timestamp it already carries verified, and a bad one raised', async () => {
      // A genuine token, but issued over some other record's digest.
      const other = assembleEnvelope({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiSystemId: 'test-system', aiOutput: { recommendation: 'other' }, action: 'approved', reason: 'x' });
      const { envelopes, findings, completed } = await scanPending({
        rfc3161Token: await signedTimestampToken(other.integrity.canonicalDigest),
      });

      // Exactly the bad timestamp: nothing for the anchor or the signature
      // the record does not carry yet.
      expect(findings).toEqual([
        {
          type: 'attestation_invalid',
          evidenceId: envelopes[0].payload.evidenceId,
          component: 'timestamp',
          reason: 'imprint_mismatch',
        },
      ]);
      expect(completed.attestationFailures).toBe(1);
    });

    it('raises nothing for the components it is still waiting for', async () => {
      const { findings, completed } = await scanPending({});
      expect(findings).toEqual([]);
      expect(completed.attestationFailures).toBe(0);
    });

    it('counts a timestamp it carries that verifies as valid', async () => {
      const envelopes = await captureN(storage, 1);
      const token = await signedTimestampToken(envelopes[0].integrity.canonicalDigest);
      await rewriteStoredEnvelope(storage, envelopes[0].payload.evidenceId, (e) => {
        e.attestationStatus = 'pending';
        e.nonRepudiation = { rfc3161Token: token };
      });
      const findings: MonitoringEvent[] = [];
      bus.subscribe((event) => {
        if (event.type === 'attestation_invalid' || event.type === 'attestation_unverifiable') {
          findings.push(event);
        }
      });
      const scanner = new ScheduledScanner(storage, bus, registry, {
        ...defaultConfig,
        verifyAttestation: true,
      });
      await scanner.runFullPass();

      expect(findings).toEqual([]);
      const summary = scanner.getState().lastCompletedPass!;
      expect(summary.attestationFailures).toBe(0);
      expect(summary.attestationValid?.timestamp).toBe(1);
    });
  });

  // ---------------------------------------------------------------------------
  // Test 11c: the production shape — a TSA that answered 200 with an HTML page
  // ---------------------------------------------------------------------------
  it('emits attestation_invalid for an HTML maintenance page stored as a token', async () => {
    const envelopes = await captureN(storage, 2);

    await rewriteStoredEnvelope(storage, envelopes[0].payload.evidenceId, (e) => {
      e.attestationStatus = 'partial';
      // This is what the RFC 3161 client stores when the TSA (or a proxy in front
      // of it) answers HTTP 200 with a maintenance page: the body, base64'd.
      e.nonRepudiation = {
        rfc3161Token: Buffer.from(
          '<html><head><title>503 Service Unavailable</title></head><body>maintenance</body></html>',
          'utf8',
        ).toString('base64'),
      };
    });

    const scanner = new ScheduledScanner(storage, bus, registry, {
      ...defaultConfig,
      verifyAttestation: true,
    });

    const attestationEvents: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') attestationEvents.push(event);
    });

    const completed: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'scan_completed') completed.push(event);
    });

    await scanner.runFullPass();

    expect(attestationEvents).toHaveLength(1);
    expect(attestationEvents[0]).toMatchObject({
      component: 'timestamp',
      reason: 'unparseable_token',
    });
    // The counter the public event type calls "attestation verification
    // failures" must actually count it.
    expect((completed[0] as { attestationFailures: number }).attestationFailures).toBe(1);
  });

  // ---------------------------------------------------------------------------
  // Test 11d: a genuine token, but stamped over some other record
  // ---------------------------------------------------------------------------
  it('emits attestation_invalid when a real token is not bound to this record', async () => {
    const envelopes = await captureN(storage, 2);

    const otherRecord = await storage.retrieve(envelopes[1].payload.evidenceId);
    const token = await signedTimestampToken(otherRecord!.integrity.canonicalDigest);
    await rewriteStoredEnvelope(storage, envelopes[0].payload.evidenceId, (e) => {
      e.attestationStatus = 'partial';
      // A genuine TSA response — for the NEXT record's digest.
      e.nonRepudiation = {
        rfc3161Token: token,
      };
    });

    const scanner = new ScheduledScanner(storage, bus, registry, {
      ...defaultConfig,
      verifyAttestation: true,
    });

    const attestationEvents: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') attestationEvents.push(event);
    });

    await scanner.runFullPass();

    expect(attestationEvents).toHaveLength(1);
    expect(attestationEvents[0]).toMatchObject({
      component: 'timestamp',
      reason: 'imprint_mismatch',
    });
  });

  // ---------------------------------------------------------------------------
  // Test 12: partial attestation with no artifacts emits event
  // ---------------------------------------------------------------------------
  it('partial attestation with no artifacts emits attestation_invalid', async () => {
    const envelopes = await captureN(storage, 2);

    await rewriteStoredEnvelope(storage, envelopes[0].payload.evidenceId, (e) => {
      e.attestationStatus = 'partial';
      e.nonRepudiation = {};
    });

    const config: ScannerConfig = {
      ...defaultConfig,
      verifyAttestation: true,
    };

    const scanner = new ScheduledScanner(storage, bus, registry, config);

    const attestationEvents: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') {
        attestationEvents.push(event);
      }
    });

    await scanner.runFullPass();

    expect(attestationEvents).toHaveLength(1);
  });

  // ---------------------------------------------------------------------------
  // Test 13: scan_completed event includes per-category breakdown
  // ---------------------------------------------------------------------------
  it('scan_completed event reports digestMismatches: 1 when record is tampered', async () => {
    const envelopes = await captureN(storage, 5);

    // Tamper record 3's payload so digest recomputation fails
    await rewriteStoredEnvelope(storage, envelopes[2].payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED'; });

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    const completedEvents: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'scan_completed') {
        completedEvents.push(event);
      }
    });

    await scanner.runFullPass();

    expect(completedEvents).toHaveLength(1);
    const completed = completedEvents[0];
    expect(completed.type).toBe('scan_completed');
    if (completed.type === 'scan_completed') {
      expect(completed.digestMismatches).toBe(1);
      expect(completed.chainBreaks).toBe(0);
      expect(completed.sequenceGaps).toBe(0);
      expect(completed.attestationFailures).toBe(0);
      expect(completed.issuesFound).toBe(1);
      expect(completed.durationMs).toBeGreaterThanOrEqual(0);
    }
  });

  // ---------------------------------------------------------------------------
  // Test 14: Clean chain — zero issues
  // ---------------------------------------------------------------------------
  it('clean 15-record chain: zero issues', async () => {
    await captureN(storage, 15);

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    const issues: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (
        event.type === 'digest_mismatch' ||
        event.type === 'chain_break' ||
        event.type === 'sequence_gap'
      ) {
        issues.push(event);
      }
    });

    const completedEvents: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'scan_completed') {
        completedEvents.push(event);
      }
    });

    await scanner.runFullPass();

    expect(issues).toHaveLength(0);
    expect(completedEvents).toHaveLength(1);
    if (completedEvents[0].type === 'scan_completed') {
      expect(completedEvents[0].recordsChecked).toBe(15);
      expect(completedEvents[0].issuesFound).toBe(0);
    }
  });

  // ---------------------------------------------------------------------------
  // Test 15: Mid-chain insertion — a forged record reusing a sequence number
  // ---------------------------------------------------------------------------
  it('detects a forged record appended under an already-used sequence number', async () => {
    const envelopes = await captureN(storage, 3);

    // The forgery is a genuine, self-consistent envelope: its canonicalDigest
    // really is the digest of its payload, and its chainLink really is
    // SHA-256(head digest + own digest). It just claims a sequence number the
    // chain already has. `chainLink` is not in the hashed field set, so no
    // honest record is touched and every attestation on them still verifies.
    const forged = assembleEnvelope({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiSystemId: 'test-system',
        aiOutput: { recommendation: 'forged' },
        action: 'approved',
        reason: 'inserted by a store-write attacker',
      }, { previousDigest: envelopes[2].integrity.canonicalDigest, sequenceNumber: 3 });
    await storeAtTakenPosition(storage, forged);

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    const seen: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (
        event.type === 'digest_mismatch' ||
        event.type === 'chain_break' ||
        event.type === 'sequence_gap' ||
        event.type === 'duplicate_sequence'
      ) {
        seen.push(event);
      }
    });

    const completed: MonitoringEvent[] = [];
    const logged: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'scan_completed') completed.push(event);
      if (event.type === 'digest_differs_from_logged_leaf') logged.push(event);
    });

    await scanner.runFullPass();

    // The repeated sequence number is reported as duplicate_sequence. The
    // digest, chain-link and gap checks are blind to this attack by
    // construction (a gap fires only when a sequence number is AHEAD of the
    // baseline) — hence the assertions below that they stay silent.
    expect(seen.map((e) => e.type)).toEqual(['duplicate_sequence']);
    const dup = seen[0];
    if (dup.type === 'duplicate_sequence') {
      expect(dup.sequenceNumber).toBe(3);
      expect(dup.previousSequence).toBe(3);
      expect(dup.evidenceId).toBe(forged.payload.evidenceId);
    }

    // The store's evidence log holds the honest record's digest at that
    // position, so the forged one is also not the record that was logged: the
    // one other finding.
    expect(logged.map((e) => e.type === 'digest_differs_from_logged_leaf' && [e.evidenceId, e.sequenceNumber])).toEqual([
      [forged.payload.evidenceId, 3],
    ]);
    expect(completed).toHaveLength(1);
    if (completed[0].type === 'scan_completed') {
      expect(completed[0].issuesFound).toBe(2);
      expect(completed[0].logFindings).toBe(1);
      expect(completed[0].duplicateSequences).toBe(1);
      expect(completed[0].sequenceGaps).toBe(0);
      expect(completed[0].chainBreaks).toBe(0);
      expect(completed[0].digestMismatches).toBe(0);
    }
  });

  // ---------------------------------------------------------------------------
  // Test 16: a duplicate must not fabricate gaps behind it
  // ---------------------------------------------------------------------------
  it('a duplicate does not drag the gap baseline backwards', async () => {
    const envelopes = await captureN(storage, 5);

    const forged = assembleEnvelope({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiSystemId: 'test-system',
        aiOutput: { recommendation: 'forged' },
        action: 'approved',
        reason: 'inserted mid-chain',
      }, { previousDigest: envelopes[1].integrity.canonicalDigest, sequenceNumber: 2 });
    await storeAtTakenPosition(storage, forged);

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);
    const gaps: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'sequence_gap') gaps.push(event);
    });

    const phase2 = await scanner.runPhase2(1, 5);

    expect(phase2.duplicateSequences).toBe(1);
    expect(gaps).toHaveLength(0);
    expect(phase2.sequenceGaps).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // Test 17: Tail truncation — the scanner's only continuity blind spot
  // ---------------------------------------------------------------------------
  //
  // Mirrors chain-completeness.test.ts's 'detects deletion of the TAIL of the
  // chain', which pins the same property for Tzun.verifyChainCompleteness().
  // The scanner is the component that runs unattended every 15 minutes and
  // drives incidents and alerts, so it must reach the same answer; keeping
  // both tests is what stops the two verification paths drifting apart.
  it('detects deletion of the TAIL of the chain', async () => {
    const envelopes = await captureN(storage, 5);

    // Delete the newest two records — the decisions most likely to be under
    // dispute. getLastSequence() still reports 5: the chain-state counter is a
    // separate row that survives DELETEs, which is what makes the loss
    // detectable at all.
    (storage as any).envelopes.delete(envelopes[3].payload.evidenceId);
    (storage as any).envelopes.delete(envelopes[4].payload.evidenceId);
    expect(await storage.getLastSequence()).toBe(5);

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    const gaps: MonitoringEvent[] = [];
    const completed: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'sequence_gap') gaps.push(event);
      if (event.type === 'scan_completed') completed.push(event);
    });

    await scanner.runFullPass();

    // Every check in the loop compares a record to its neighbours, so with no
    // survivor after sequence 3 none of them can see the loss. The pass must
    // still report one gap from 4 up to the chain counter, not a clean scan
    // of three records.
    expect(gaps).toHaveLength(1);
    if (gaps[0].type === 'sequence_gap') {
      expect(gaps[0].expectedSequence).toBe(4);
      expect(gaps[0].foundSequence).toBe(6);
    }
    expect(completed).toHaveLength(1);
    if (completed[0].type === 'scan_completed') {
      expect(completed[0].recordsChecked).toBe(3);
      expect(completed[0].sequenceGaps).toBe(1);
      expect(completed[0].issuesFound).toBeGreaterThan(0);
    }
  });

  // ---------------------------------------------------------------------------
  // Test 18: the whole chain deleted
  // ---------------------------------------------------------------------------
  it('detects deletion of EVERY record while the chain counter still stands', async () => {
    const envelopes = await captureN(storage, 5);
    for (const e of envelopes) {
      (storage as any).envelopes.delete(e.payload.evidenceId);
    }
    expect(await storage.getLastSequence()).toBe(5);

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);
    const gaps: MonitoringEvent[] = [];
    const completed: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'sequence_gap') gaps.push(event);
      if (event.type === 'scan_completed') completed.push(event);
    });

    await scanner.runFullPass();

    // Both phases run over an empty result set. The chain counter still says
    // five records were written, so a pass that checked nothing must report
    // the gap rather than a clean scan.
    expect(gaps).toHaveLength(1);
    if (gaps[0].type === 'sequence_gap') {
      expect(gaps[0].expectedSequence).toBe(1);
      expect(gaps[0].foundSequence).toBe(6);
    }
    if (completed[0].type === 'scan_completed') {
      expect(completed[0].recordsChecked).toBe(0);
      expect(completed[0].issuesFound).toBeGreaterThan(0);
    }
  });

  // ---------------------------------------------------------------------------
  // Test 19: tail truncation is still caught with Phase 2 switched off
  // ---------------------------------------------------------------------------
  it('flags missing records even when verifyChainCompleteness is false', async () => {
    const envelopes = await captureN(storage, 5);
    (storage as any).envelopes.delete(envelopes[3].payload.evidenceId);
    (storage as any).envelopes.delete(envelopes[4].payload.evidenceId);

    const scanner = new ScheduledScanner(storage, bus, registry, {
      ...defaultConfig,
      verifyChainCompleteness: false,
    });

    const gaps: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'sequence_gap') gaps.push(event);
    });

    await scanner.runFullPass();

    // The trailing gap check does not depend on Phase 2: with it switched off,
    // three surviving rows out of five must still raise a gap, not a clean
    // pass.
    expect(gaps).toHaveLength(1);
    if (gaps[0].type === 'sequence_gap') {
      expect(gaps[0].expectedSequence).toBe(4);
      expect(gaps[0].foundSequence).toBe(6);
    }
  });

  // ---------------------------------------------------------------------------
  // Test 20: head truncation must still be caught, and exactly once
  // ---------------------------------------------------------------------------
  it('still detects HEAD truncation without double-reporting it', async () => {
    const envelopes = await captureN(storage, 5);
    (storage as any).envelopes.delete(envelopes[0].payload.evidenceId);
    (storage as any).envelopes.delete(envelopes[1].payload.evidenceId);

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);
    const gaps: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'sequence_gap') gaps.push(event);
    });

    await scanner.runFullPass();

    // The in-loop check catches this one; the trailing check must not fire a
    // second time for the same chain.
    expect(gaps).toHaveLength(1);
    if (gaps[0].type === 'sequence_gap') {
      expect(gaps[0].expectedSequence).toBe(1);
      expect(gaps[0].foundSequence).toBe(3);
    }
  });

  // ---------------------------------------------------------------------------
  // Unknown schemaVersion is tampering, not an excuse to abandon the pass
  // ---------------------------------------------------------------------------
  it('reports an unknown schemaVersion as a digest_mismatch and finishes the pass', async () => {
    const envelopes = await captureN(storage, 5);

    // schemaVersion is NOT in v1.0's hashedFieldSet, so an attacker with UPDATE
    // on the evidence table can change it without disturbing canonicalDigest.
    // The scanner reports the unknown value as a digest_mismatch and carries
    // on. A throw here would escape verifyDigestsInRange -> Promise.all ->
    // runPhase1 -> runFullPass and kill the whole pass: no digest_mismatch for
    // the doctored row, no scan_completed, no Phase 2, and scanner state
    // stranded mid-pass. One row would switch monitoring off for the entire
    // chain.
    await rewriteStoredEnvelope(storage, envelopes[2].payload.evidenceId, (e) => {
      e.payload.reason = 'TAMPERED';
      e.payload.schemaVersion = 'v9.9';
    });

    const seen: MonitoringEvent[] = [];
    bus.subscribe((event) => seen.push(event));

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);
    await expect(scanner.runFullPass()).resolves.toBeUndefined();

    const mismatches = seen.filter((e) => e.type === 'digest_mismatch');
    expect(mismatches).toHaveLength(1);
    if (mismatches[0].type === 'digest_mismatch') {
      expect(mismatches[0].evidenceId).toBe(envelopes[2].payload.evidenceId);
      expect(mismatches[0].recomputed).toBe('');
    }

    // The pass must complete: every other record still verified, and
    // scan_completed still fired with the doctored row counted.
    expect(seen.filter((e) => e.type === 'record_verified')).toHaveLength(4);
    const completed = seen.filter((e) => e.type === 'scan_completed');
    expect(completed).toHaveLength(1);
    if (completed[0].type === 'scan_completed') {
      expect(completed[0].recordsChecked).toBe(5);
      expect(completed[0].digestMismatches).toBe(1);
    }

    // ...and the scanner must not be left looking mid-pass.
    expect(scanner.getState().currentPassStartedAt).toBeNull();
    expect(scanner.getState().segmentsInProgress).toEqual([]);
    expect(scanner.getState().totalPasses).toBe(1);
  });

  it('clears mid-pass state when a pass throws', async () => {
    await captureN(storage, 3);
    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    // A storage failure part-way through a pass must not strand
    // currentPassStartedAt / segmentsInProgress: computeIntegrityStatus reads
    // those to decide `scannerRunning`, so the dashboard would report a scan
    // in progress forever.
    jest
      .spyOn(storage, 'listBySequence')
      .mockRejectedValueOnce(new Error('storage exploded'));

    await expect(scanner.runFullPass()).rejects.toThrow('storage exploded');
    expect(scanner.getState().currentPassStartedAt).toBeNull();
    expect(scanner.getState().segmentsInProgress).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// TSA trust anchors the verifiers cannot read (Verification §3.1).
//
// `verifyAttestation` and `verifyAnchor` refuse them by throwing
// `UnreadableTrustAnchorError`. A pass that caught that per record and fell
// through to the presence rules would finish clean with no timestamp,
// signature or anchor verdict at all, so a typo in the environment would turn
// the tamper monitor off in silence. The pass fails instead.
// ---------------------------------------------------------------------------
describe('ScheduledScanner with TSA trust anchors it cannot read', () => {
  const NAMES = ['TZUN_TSA_TRUST_ANCHORS', 'TZUN_TSA_AUTHORITIES'] as const;
  const saved: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const name of NAMES) saved[name] = process.env[name];
  });
  afterEach(() => {
    for (const name of NAMES) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    }
  });

  /** A store whose first record carries a genuine token over the second record's digest. */
  async function storeWithMisboundToken(): Promise<{ storage: MemoryStorageAdapter; envelopes: EvidenceEnvelope[] }> {
    const storage = new MemoryStorageAdapter();
    const envelopes = await captureN(storage, 2);
    const token = await signedTimestampToken(envelopes[1].integrity.canonicalDigest);
    await rewriteStoredEnvelope(storage, envelopes[0].payload.evidenceId, (e) => {
      e.attestationStatus = 'partial';
      e.nonRepudiation = { rfc3161Token: token };
    });
    return { storage, envelopes };
  }

  const unreadable: Array<[string, Record<string, string>]> = [
    ['a TZUN_TSA_TRUST_ANCHORS file that does not exist', { TZUN_TSA_TRUST_ANCHORS: '/nonexistent/tzun-review-root.pem' }],
    ['a TZUN_TSA_AUTHORITIES name the registry does not know', { TZUN_TSA_AUTHORITIES: 'no-such-authority' }],
  ];

  it.each(unreadable)('fails the pass, never finishing it clean, for %s', async (_what, env) => {
    const { storage } = await storeWithMisboundToken();
    Object.assign(process.env, env);
    const bus = new MonitoringEventBus();
    const events: MonitoringEvent[] = [];
    bus.subscribe((event) => events.push(event));
    const scanner = new ScheduledScanner(storage, bus, new SchemaRegistry(), { ...defaultConfig, verifyAttestation: true });

    await expect(scanner.runFullPass()).rejects.toThrow(UnreadableTrustAnchorError);
    expect(events.filter((e) => e.type === 'scan_completed')).toEqual([]);
    expect(scanner.getState().totalPasses).toBe(0);
    expect(scanner.getState().currentPassStartedAt).toBeNull();
  });

  it.each(unreadable)('rethrows it from the record check itself, for %s', async (_what, env) => {
    const { storage, envelopes } = await storeWithMisboundToken();
    Object.assign(process.env, env);
    const scanner = new ScheduledScanner(storage, new MonitoringEventBus(), new SchemaRegistry(), { ...defaultConfig, verifyAttestation: true });
    const stored = await storage.listBySequence(1, envelopes.length);
    await expect(scanner.runAttestationCheckOnRecords(stored)).rejects.toThrow(UnreadableTrustAnchorError);
  });

  it('reads them only when the pass verifies attestations', async () => {
    const { storage } = await storeWithMisboundToken();
    process.env.TZUN_TSA_AUTHORITIES = 'no-such-authority';
    const scanner = new ScheduledScanner(storage, new MonitoringEventBus(), new SchemaRegistry(), defaultConfig);
    await expect(scanner.runFullPass()).resolves.toBeUndefined();
    expect(scanner.getState().totalPasses).toBe(1);
  });

  it('with them unset, still reports the token over another record', async () => {
    const { storage } = await storeWithMisboundToken();
    for (const name of NAMES) delete process.env[name];
    const bus = new MonitoringEventBus();
    const invalid: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') invalid.push(event);
    });
    await new ScheduledScanner(storage, bus, new SchemaRegistry(), { ...defaultConfig, verifyAttestation: true }).runFullPass();
    expect(invalid).toEqual([expect.objectContaining({ component: 'timestamp', reason: 'imprint_mismatch' })]);
  });
});

// ---------------------------------------------------------------------------
// A non-advancing worker count must be refused, loudly, at construction.
//
// `runPhase1` walks its segments with
// `for (let i = 0; i < segments.length; i += this.config.workers)`. With
// `workers` at 0 or negative the cursor would never move and
// `await Promise.all([])` only yields to the microtask queue — the process
// would pin a core forever, timers and I/O would starve, and even its SIGTERM
// handler could not run, so it would have to be SIGKILLed. The count can come
// from a request body: on a server with the benchmark mounted,
// `POST /v1/benchmark/run {"scannerWorkerCounts":[0]}` reaches it.
// ---------------------------------------------------------------------------
describe('ScheduledScanner config validation', () => {
  const deps = () =>
    [new MemoryStorageAdapter(), new MonitoringEventBus(), new SchemaRegistry()] as const;

  it('refuses workers: 0 at construction rather than looping forever', () => {
    const [storage, bus, registry] = deps();
    expect(
      () =>
        new ScheduledScanner(storage, bus, registry, {
          ...defaultConfig,
          workers: 0,
        }),
    ).toThrow(RangeError);
  });

  it('refuses a negative worker count', () => {
    const [storage, bus, registry] = deps();
    expect(
      () =>
        new ScheduledScanner(storage, bus, registry, {
          ...defaultConfig,
          workers: -4,
        }),
    ).toThrow(/workers/);
  });

  it('refuses a non-finite worker count', () => {
    const [storage, bus, registry] = deps();
    expect(
      () =>
        new ScheduledScanner(storage, bus, registry, {
          ...defaultConfig,
          workers: Number.NaN,
        }),
    ).toThrow(RangeError);
  });

  it('refuses a batchSize of 0', () => {
    const [storage, bus, registry] = deps();
    expect(
      () =>
        new ScheduledScanner(storage, bus, registry, {
          ...defaultConfig,
          batchSize: 0,
        }),
    ).toThrow(/batchSize/);
  });

  it('still accepts a valid config', () => {
    const [storage, bus, registry] = deps();
    expect(
      () => new ScheduledScanner(storage, bus, registry, { ...defaultConfig, workers: 1 }),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Post-fork scanning through the real SDK
//
// The scanner suite above drives ScheduledScanner directly against a store
// that has exactly one chain, which is every store that has never been
// forked. `recovery.fork()` is the one operation that gives a store two. These
// cases scan after a fork, through the real SDK, and pin that a pass reads the
// sealed chain (1..N) and the live chain that replaced it (restarting at 1) as
// two chains, not one.
// ---------------------------------------------------------------------------
describe('ScheduledScanner after an authorized fork (via Tzun)', () => {
  const scannerConfig: ScannerConfig = {
    batchSize: 100,
    workers: 2,
    mode: 'interval',
    intervalMs: 0,
    verifyAttestation: false,
    verifyChainCompleteness: true,
  };

  async function bootWithMonitoring() {
    const tzun = await Tzun.init({
      monitoring: { enabled: true, scanner: scannerConfig },
    });
    const incidents: TamperIncident[] = [];
    const summaries: ScanSummary[] = [];
    tzun.on('tamper', (i) => incidents.push(i));
    tzun.on('scan.completed', (s) => summaries.push(s));
    return { tzun, incidents, summaries };
  }

  async function captureVia(tzun: Tzun, n: number, tag: string) {
    for (let i = 1; i <= n; i++) {
      await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { recommendation: `${tag}-${i}` },
        action: 'approved',
        reason: `${tag} reason ${i}`,
      });
    }
  }

  it('reports a clean pass on an untampered store one fork old', async () => {
    const { tzun, incidents, summaries } = await bootWithMonitoring();
    try {
      await captureVia(tzun, 3, 'pre');
      await tzun.runScan();
      await new Promise((r) => setTimeout(r, 50));

      // Non-vacuity: the first pass really did look at all three records.
      expect(summaries).toHaveLength(1);
      expect(summaries[0].recordsChecked).toBe(3);
      expect(incidents).toHaveLength(0);

      const forkResult = await tzun.recovery.fork('inc-fork-1', {
        authorizedBy: 'admin@acme.example',
        reason: 'Key compromise; rotating the chain',
        forkAfterSequence: 3,
      });
      expect(forkResult.fork.oldChainId).toBe('default');

      // Two records on the new chain, which restarts numbering at 1 — so the
      // store now holds sequence 1 and 2 twice.
      await captureVia(tzun, 2, 'post');

      await tzun.runScan();
      await new Promise((r) => setTimeout(r, 50));

      // A store nobody touched raises no incident: the reused 1 and 2 are not
      // duplicate_sequence findings, and the boundary between the two chains
      // is not a chain_break.
      expect(incidents.map((i) => i.type)).toEqual([]);
      expect(summaries).toHaveLength(2);
      expect(summaries[1].issuesFound).toBe(0);
      expect(summaries[1].duplicateSequences).toBe(0);
      expect(summaries[1].chainBreaks).toBe(0);
      expect(summaries[1].sequenceGaps).toBe(0);

      // FIVE, not two: the pass walks each chain separately, bounded by its
      // own high-water mark — 3 sealed + 2 live. Scoping the scanner to the
      // ACTIVE chain alone would also avoid false incidents, but it buys
      // silence by not looking at the sealed chain, and the sealed chain is
      // the read-only remainder of a fork, so it is the first place an insider
      // would edit. If this reads 2, the sealed chain has fallen out of the
      // rotation.
      expect(summaries[1].recordsChecked).toBe(5);
    } finally {
      await tzun.close();
    }
  }, 30_000);

  it('an explicitly scoped scanner walks ONLY that chain', async () => {
    // Scoping a scanner to one chain is an explicit opt-in, for a caller that
    // owns one scanner per chain and does not want each of them redoing all N.
    // Exercised directly, because nothing in the SDK sets a scope — an API no
    // caller and no test drives is indistinguishable from one that does
    // nothing.
    const { tzun, incidents, summaries } = await bootWithMonitoring();
    try {
      await captureVia(tzun, 3, 'pre');
      const sealedChainId = await tzun.getActiveChainId();
      await tzun.recovery.fork('inc-fork-3', {
        authorizedBy: 'admin@acme.example',
        reason: 'Key compromise',
        forkAfterSequence: 3,
      });
      await captureVia(tzun, 2, 'post');
      const activeChainId = await tzun.getActiveChainId();
      expect(activeChainId).not.toBe(sealedChainId);

      const scanner = (tzun as unknown as { scanner: ScheduledScanner }).scanner;

      scanner.setChainScope(activeChainId);
      expect(scanner.getChainScope()).toBe(activeChainId);
      await tzun.runScan();
      await new Promise((r) => setTimeout(r, 50));
      // Two live records only — the scope really did exclude the sealed chain.
      expect(summaries[0].recordsChecked).toBe(2);

      scanner.setChainScope(sealedChainId);
      await tzun.runScan();
      await new Promise((r) => setTimeout(r, 50));
      // ...and pointing it the other way reaches the three sealed records,
      // bounded by the fork record's sealedOldChainLength rather than by the
      // live counter the fork reset to 2.
      expect(summaries[1].recordsChecked).toBe(3);

      scanner.setChainScope(undefined);
      await tzun.runScan();
      await new Promise((r) => setTimeout(r, 50));
      expect(summaries[2].recordsChecked).toBe(5);

      expect(incidents).toHaveLength(0);
    } finally {
      await tzun.close();
    }
  }, 30_000);

  it('still detects real tampering on the chain it followed across the fork', async () => {
    // The scope must narrow WHICH chain is scanned, not how hard it is scanned.
    const { tzun, incidents } = await bootWithMonitoring();
    try {
      await captureVia(tzun, 3, 'pre');
      await tzun.recovery.fork('inc-fork-2', {
        authorizedBy: 'admin@acme.example',
        reason: 'Key compromise',
        forkAfterSequence: 3,
      });
      await captureVia(tzun, 3, 'post');

      // Tamper with a record on the NEW chain, in the store itself.
      const inner = tzun.getStorage();
      const live = await inner.listBySequence(
        1,
        3,
        await tzun.getActiveChainId(),
      );
      expect(live).toHaveLength(3);
      await rewriteStoredEnvelope(inner, live[1].payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED'; });

      await tzun.runScan();
      await new Promise((r) => setTimeout(r, 50));

      expect(incidents.map((i) => i.type)).toContain('digest_mismatch');
    } finally {
      await tzun.close();
    }
  }, 30_000);

  it('scans an un-forked store as one default chain: every record checked, no incident', async () => {
    const { tzun, incidents, summaries } = await bootWithMonitoring();
    try {
      await captureVia(tzun, 4, 'only');
      await tzun.runScan();
      await new Promise((r) => setTimeout(r, 50));
      expect(summaries[0].recordsChecked).toBe(4);
      expect(incidents).toHaveLength(0);
      expect(await tzun.getActiveChainId()).toBe('default');
    } finally {
      await tzun.close();
    }
  }, 30_000);
});

// ---------------------------------------------------------------------------
// The scanner keeps what its last completed pass measured.
//
// `GET /v1/integrity/status` reaches the scanner only through
// `Tzun.getScannerState()`, so everything it reports about the last pass —
// duration, what was found, attestation presence — has to ride on
// `ScannerState` as `lastCompletedPass`. Without it the endpoint would have
// no duration and no attestation coverage to report.
// ---------------------------------------------------------------------------
describe('ScheduledScanner retains what its last completed pass measured', () => {
  let bus: MonitoringEventBus;
  let storage: MemoryStorageAdapter;
  let registry: SchemaRegistry;

  beforeEach(() => {
    bus = new MonitoringEventBus();
    storage = new MemoryStorageAdapter();
    registry = new SchemaRegistry();
  });

  it('lastCompletedPass is null before any pass and the pass summary after one', async () => {
    await captureN(storage, 3);
    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    expect(scanner.getState().lastCompletedPass).toBeNull();

    await scanner.runFullPass();

    const state = scanner.getState();
    expect(state.lastCompletedPass).not.toBeNull();
    const pass = state.lastCompletedPass!;
    expect(pass.passNumber).toBe(1);
    expect(pass.recordsChecked).toBe(3);
    expect(pass.issuesFound).toBe(0);
    expect(pass.completedAt).toBe(state.lastCompletedPassAt);
    expect(Date.parse(pass.startedAt)).toBeLessThanOrEqual(Date.parse(pass.completedAt));
    expect(typeof pass.durationMs).toBe('number');
    expect(pass.durationMs).toBeGreaterThanOrEqual(0);

    await scanner.runFullPass();
    expect(scanner.getState().lastCompletedPass!.passNumber).toBe(2);
  });

  it('counts attestation-artifact presence for every record, with attestation verification off', async () => {
    const envelopes = await captureN(storage, 4);
    // Presence is what is counted, not validity: these artifacts would never
    // verify, and with verifyAttestation: false nothing tries.
    await storage.updateAttestation(envelopes[0].payload.evidenceId, { rfc3161Token: 'not-a-real-token' }, 'partial');
    await storage.updateAttestation(envelopes[1].payload.evidenceId, { rfc3161Token: 'not-a-real-token' }, 'partial');
    await storage.updateAttestation(
      envelopes[2].payload.evidenceId,
      {
        // Well-formed, and about some other record: presence is what this
        // test counts, whatever the anchor would verify to.
        anchor: anchoredRecord().anchor,
      },
      'partial',
    );

    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);
    const emitted: Array<ScanSummary['attestationPresence']> = [];
    bus.subscribe((event) => {
      if (event.type === 'scan_completed') emitted.push(event.attestationPresence);
    });

    await scanner.runFullPass();

    const expected = { timestamp: 2, signature: 0, anchor: 1 };
    expect(scanner.getState().lastCompletedPass!.attestationPresence).toEqual(expected);
    expect(scanner.getState().lastCompletedPass!.attestationFailures).toBe(0);
    expect(emitted).toEqual([expected]);
  });

  it('a scan_completed subscriber reading getState() sees the pass that just completed', async () => {
    await captureN(storage, 2);
    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);
    let seen: ScanSummary | null | undefined;
    bus.subscribe((event) => {
      if (event.type === 'scan_completed') seen = scanner.getState().lastCompletedPass;
    });

    await scanner.runFullPass();

    expect(seen).toBeDefined();
    expect(seen!.passNumber).toBe(1);
    expect(seen!.recordsChecked).toBe(2);
  });

  it('does not retain a pass that threw', async () => {
    await captureN(storage, 3);
    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);
    jest
      .spyOn(storage, 'listBySequence')
      .mockRejectedValueOnce(new Error('storage exploded'));

    await expect(scanner.runFullPass()).rejects.toThrow('storage exploded');

    expect(scanner.getState().lastCompletedPass).toBeNull();
    expect(scanner.getState().lastCompletedPassAt).toBeNull();
  });

  it('getState() hands out a copy of the summary, not the live object', async () => {
    await captureN(storage, 1);
    const scanner = new ScheduledScanner(storage, bus, registry, { ...defaultConfig, verifyAttestation: true });
    await scanner.runFullPass();

    const a = scanner.getState().lastCompletedPass!;
    a.recordsChecked = 999;
    a.attestationPresence!.timestamp = 999;
    a.attestationValid!.timestamp = 999;

    const b = scanner.getState().lastCompletedPass!;
    expect(b.recordsChecked).toBe(1);
    expect(b.attestationPresence!.timestamp).toBe(0);
    expect(b.attestationValid!.timestamp).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// What the pass VERIFIED is reported separately from what is merely
// PRESENT. `attestationPresence` counts records that carry an
// artifact; `attestationValid` counts records whose artifact the verifier
// reported `true` for, and is null for a component the scanner is not
// equipped to verify. `GET /v1/integrity/status` derives `attestationCoverage`
// — "percentage with VALID timestamps" — from the latter only.
// ---------------------------------------------------------------------------
describe('ScheduledScanner reports what it verified separately from what is present', () => {
  let bus: MonitoringEventBus;
  let storage: MemoryStorageAdapter;
  let registry: SchemaRegistry;

  beforeEach(() => {
    bus = new MonitoringEventBus();
    storage = new MemoryStorageAdapter();
    registry = new SchemaRegistry();
  });

  /**
   * Leave a record the way updateAttestation would: artifacts + a claimed
   * status. The row itself is rewritten (every read is a detached copy,
   * so assigning to what `retrieve()` returns changes nothing on any backend).
   */
  async function seed(
    envelope: EvidenceEnvelope,
    nonRepudiation: EvidenceEnvelope['nonRepudiation'],
    status: EvidenceEnvelope['attestationStatus'] = 'partial',
  ): Promise<void> {
    await rewriteStoredEnvelope(storage, envelope.payload.evidenceId, (record) => {
      record.attestationStatus = status;
      record.nonRepudiation = nonRepudiation;
    });
  }

  /**
   * `nonRepudiation.anchor` for `envelopes[index]`: an evidence log of the
   * records' own digests, in capture order, with the record at `index`. Both
   * proofs hold; there is no publication, so the anchor is never valid.
   */
  function anchorOf(envelopes: EvidenceEnvelope[], index: number) {
    return anchoredRecord({ digests: envelopes.map((e) => e.integrity.canonicalDigest), leafIndex: index }).anchor;
  }

  async function seedTwoTokensAndAnAnchor(): Promise<EvidenceEnvelope[]> {
    const envelopes = await captureN(storage, 4);
    // A genuine token over THIS record's digest.
    await seed(envelopes[0], {
      rfc3161Token: await signedTimestampToken(envelopes[0].integrity.canonicalDigest),
    });
    // A genuine token over ANOTHER record's digest — a real TSA response
    // replayed from elsewhere. Present; not evidence about this record.
    await seed(envelopes[1], {
      rfc3161Token: await signedTimestampToken(envelopes[3].integrity.canonicalDigest),
    });
    // An anchor whose proofs hold. Present; with no publication checked,
    // never valid — the roots live inside the artifact.
    await seed(envelopes[2], { anchor: anchorOf(envelopes, 2) });
    return envelopes;
  }

  it('counts verified-valid artifacts per component, null for what it is not equipped to verify', async () => {
    await seedTwoTokensAndAnAnchor();
    const scanner = new ScheduledScanner(storage, bus, registry, { ...defaultConfig, verifyAttestation: true });
    const emitted: Array<ScanSummary['attestationValid']> = [];
    bus.subscribe((event) => {
      if (event.type === 'scan_completed') emitted.push(event.attestationValid);
    });

    await scanner.runFullPass();

    const pass = scanner.getState().lastCompletedPass!;
    expect(pass.attestationPresence).toEqual({ timestamp: 2, signature: 0, anchor: 1 });
    // One of the two tokens verified. Signatures need a credential store and
    // a per-record challenge; an anchor needs a checked publication, which
    // the scanner does not check: not measured.
    expect(pass.attestationValid).toEqual({ timestamp: 1, signature: null, anchor: null });
    // The replayed token is the one failure; the undecided anchor is not one.
    expect(pass.attestationFailures).toBe(1);
    expect(emitted).toEqual([{ timestamp: 1, signature: null, anchor: null }]);
  });

  it('reports validity as null for every component when verification is off, whatever is present', async () => {
    await seedTwoTokensAndAnAnchor();
    const scanner = new ScheduledScanner(storage, bus, registry, defaultConfig);

    await scanner.runFullPass();

    const pass = scanner.getState().lastCompletedPass!;
    expect(pass.attestationPresence).toEqual({ timestamp: 2, signature: 0, anchor: 1 });
    // Not 0: nothing was looked at, so nothing is known to be invalid either.
    expect(pass.attestationValid).toEqual({ timestamp: null, signature: null, anchor: null });
    expect(pass.attestationFailures).toBe(0);
  });

  it('checks an anchor\'s proofs, and never counts it valid: its publications are not checked', async () => {
    const envelopes = await captureN(storage, 3);
    // Both proofs hold: undecided, not valid and not a failure.
    await seed(envelopes[0], { anchor: anchorOf(envelopes, 0) });
    // An evidence log this record is not in, at the record's own position:
    // the inclusion proof fails.
    await seed(envelopes[1], { anchor: anchoredRecord({ leafIndex: 1 }).anchor });
    const scanner = new ScheduledScanner(storage, bus, registry, { ...defaultConfig, verifyAttestation: true });
    const invalid: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') invalid.push(event);
    });

    await scanner.runFullPass();

    expect(invalid).toEqual([
      { type: 'attestation_invalid', evidenceId: envelopes[1].payload.evidenceId, component: 'anchor', reason: 'merkle_proof_invalid' },
    ]);
    const pass = scanner.getState().lastCompletedPass!;
    expect(pass.attestationPresence).toEqual({ timestamp: 0, signature: 0, anchor: 2 });
    // Timestamps ARE verified under this configuration — none present, so 0,
    // not null. Anchors are not measured.
    expect(pass.attestationValid).toEqual({ timestamp: 0, signature: null, anchor: null });
    expect(pass.attestationFailures).toBe(1);
  });

  // -------------------------------------------------------------------------
  // Under RFC 6962 the side of every audit step is DERIVED from the leaf
  // index and the tree size, so both are load-bearing inputs — and the
  // scanner is the unattended component whose verdicts drive incidents. The
  // tree math itself is pinned by the vectors; what is under test here is
  // only that the scanner hands the whole artifact through unaltered.
  // -------------------------------------------------------------------------
  it('carries the record\'s position, leafIndex and the audit path through to the verifier', async () => {
    const envelopes = await captureN(storage, 4);
    // Record 2, in a real four-record evidence log: a non-empty path and a
    // seat that is actually its own.
    await seed(envelopes[2], { anchor: anchorOf(envelopes, 2) });
    // Record 3: the same log, its OWN correct audit path — and a leafIndex
    // belonging to someone else. Every hash in the path is genuine; only the
    // claimed position is wrong. The scanner hands the verifier the record's
    // hashed sequence number, so the position is refused before any hashing
    // (tzun-anchor/1 §10.3 step 3), and a verifier that ignored leafIndex
    // would still not pass it.
    await seed(envelopes[3], { anchor: { ...anchorOf(envelopes, 3), leafIndex: 1 } });

    const scanner = new ScheduledScanner(storage, bus, registry, { ...defaultConfig, verifyAttestation: true });
    const invalid: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') invalid.push(event);
    });

    await scanner.runFullPass();

    expect(invalid).toHaveLength(1);
    expect(invalid[0]).toMatchObject({
      component: 'anchor',
      reason: 'leaf_index_mismatch',
      evidenceId: envelopes[3].payload.evidenceId,
    });

    const pass = scanner.getState().lastCompletedPass!;
    expect(pass.attestationPresence).toEqual({ timestamp: 0, signature: 0, anchor: 2 });
    expect(pass.attestationValid).toEqual({ timestamp: 0, signature: null, anchor: null });
    expect(pass.attestationFailures).toBe(1);
  });

  // -------------------------------------------------------------------------
  // capturedAt is minted from the CAPTURING MACHINE's clock. It is in the
  // hashed field set, so the RFC 3161 token commits to it, and the scanner
  // compares the two: unchecked, the token would notarise whatever the clock
  // said.
  //
  // capturedAt more than the platform's 5-minute skew LATER than the genTime
  // that stamped it means the capturing clock ran well ahead: the token is over
  // a digest committing to capturedAt, so capturedAt existed first.
  // -------------------------------------------------------------------------
  it('flags a record whose capturedAt is later than the TSA genTime that notarised it', async () => {
    const envelopes = await captureN(storage, 1);
    const digest = envelopes[0].integrity.canonicalDigest;

    // Stamp an hour BEFORE the record claims to have been captured.
    const genTime = new Date(Date.parse(envelopes[0].payload.capturedAt) - 60 * 60 * 1000);
    await seed(envelopes[0], {
      rfc3161Token: await signedTimestampToken(digest, genTime),
    });

    const invalid: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') invalid.push(event);
    });

    const scanner = new ScheduledScanner(
      storage, bus, registry,
      { ...defaultConfig, verifyAttestation: true },
      {},
    );
    await scanner.runFullPass();

    expect(invalid).toContainEqual(
      expect.objectContaining({
        component: 'timestamp',
        reason: 'captured_after_timestamp',
        evidenceId: envelopes[0].payload.evidenceId,
      }),
    );
  });

  it('puts the skew on that event, and the incident names the reason and the skew', async () => {
    // An incident that read only "timestamp failed verification", naming
    // neither the reason nor the skew, would leave an operator unable to tell
    // a clock that ran ahead from a token issued over some other record.
    const envelopes = await captureN(storage, 1);
    const digest = envelopes[0].integrity.canonicalDigest;
    const genTime = new Date(Date.parse(envelopes[0].payload.capturedAt) - 60 * 60 * 1000);
    await seed(envelopes[0], {
      rfc3161Token: await signedTimestampToken(digest, genTime),
    });

    const incidents: TamperIncident[] = [];
    const detector = new TamperDetector(bus, storage);
    detector.onIncident((i) => incidents.push(i));
    const invalid: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') invalid.push(event);
    });

    await new ScheduledScanner(
      storage, bus, registry,
      { ...defaultConfig, verifyAttestation: true },
      {},
    ).runFullPass();
    await detector.settle();

    const evidenceId = envelopes[0].payload.evidenceId;
    const skewed = invalid.filter(
      (e) => e.type === 'attestation_invalid' && e.reason === 'captured_after_timestamp',
    );
    expect(skewed).toEqual([
      {
        type: 'attestation_invalid',
        evidenceId,
        component: 'timestamp',
        reason: 'captured_after_timestamp',
        capturedAtSkewMs: -3_600_000,
      },
    ]);

    const incident = incidents.find(
      (i) => i.type === 'attestation_invalid' && i.details.includes('captured_after_timestamp'),
    );
    expect(incident?.affectedRecords).toEqual([evidenceId]);
    expect(incident?.details).toContain('capturedAt is 3600 s later than the genTime');
    expect(incident?.details).toContain('capturedAtSkewMs -3600000');
  });

  it('does not flag the normal shape, where the TSA stamps just after capture', async () => {
    const envelopes = await captureN(storage, 1);
    const digest = envelopes[0].integrity.canonicalDigest;
    const genTime = new Date(Date.parse(envelopes[0].payload.capturedAt) + 400);
    await seed(envelopes[0], {
      rfc3161Token: await signedTimestampToken(digest, genTime),
    });

    const invalid: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') invalid.push(event);
    });

    const scanner = new ScheduledScanner(
      storage, bus, registry,
      { ...defaultConfig, verifyAttestation: true },
      {},
    );
    await scanner.runFullPass();

    expect(invalid.filter((e) => (e as { reason?: string }).reason === 'captured_after_timestamp')).toHaveLength(0);
  });

  it.each([
    [
      'a blockchainAnchor, which tzun-anchor/1 does not read',
      () => ({
        blockchainAnchor: {
          chain: 'test',
          transactionId: '0xlegacy',
          batchMerkleRoot: 'ab'.repeat(32),
          merklePath: [`left:${'ab'.repeat(32)}`],
        },
      }),
      'legacy_blockchain_anchor',
    ],
    ['an anchor under an unknown anchorSpec', () => ({ anchor: { ...anchoredRecord().anchor, anchorSpec: 'tzun-anchor/2' } }), 'unsupported_anchor_spec'],
    ['an anchor under an unknown merkleSpec', () => ({ anchor: { ...anchoredRecord().anchor, merkleSpec: 'sha256-v0' } }), 'unsupported_merkle_spec'],
  ])('raises %s as attestation_invalid (tzun-anchor/1 §10.10)', async (_label, artifacts, reason) => {
    const envelopes = await captureN(storage, 2);
    await seed(envelopes[0], artifacts() as unknown as EvidenceEnvelope['nonRepudiation']);

    const scanner = new ScheduledScanner(storage, bus, registry, { ...defaultConfig, verifyAttestation: true });
    const invalid: MonitoringEvent[] = [];
    const unverifiable: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid') invalid.push(event);
      if (event.type === 'attestation_unverifiable') unverifiable.push(event);
    });

    await scanner.runFullPass();

    // The verifier abstains; the scanner does not. Stored evidence whose whole
    // anchor has become unverifiable is a finding, and silence would let a
    // rewritten tag turn a failing anchor into a pass.
    expect(invalid).toEqual([
      { type: 'attestation_invalid', evidenceId: envelopes[0].payload.evidenceId, component: 'anchor', reason },
    ]);
    expect(unverifiable).toEqual([]);

    const pass = scanner.getState().lastCompletedPass!;
    // Present, and not counted valid.
    expect(pass.attestationPresence).toEqual({ timestamp: 0, signature: 0, anchor: 1 });
    expect(pass.attestationValid).toEqual({ timestamp: 0, signature: null, anchor: null });
    expect(pass.attestationFailures).toBe(1);
    expect(pass.attestationUnverifiable).toBe(0);
  });

  it('reports an anchor whose publications are of kinds this build does not implement as unverifiable', async () => {
    const envelopes = await captureN(storage, 2);
    const anchor = { ...anchorOf(envelopes, 0), publications: [{ kind: 'witness/1', cosignature: 'AAAA' }] };
    await seed(envelopes[0], { anchor } as unknown as EvidenceEnvelope['nonRepudiation']);

    const scanner = new ScheduledScanner(storage, bus, registry, { ...defaultConfig, verifyAttestation: true });
    const seen: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid' || event.type === 'attestation_unverifiable') seen.push(event);
    });
    await scanner.runFullPass();

    expect(seen).toEqual([
      { type: 'attestation_unverifiable', evidenceId: envelopes[0].payload.evidenceId, component: 'anchor', reason: 'unsupported_publication_kind' },
    ]);
    expect(scanner.getState().lastCompletedPass!.attestationUnverifiable).toBe(1);
  });

  it('never escalates publication_not_checked: an anchor whose publication it has no chain for raises nothing', async () => {
    const envelopes = await captureN(storage, 2);
    const anchor = {
      ...anchorOf(envelopes, 1),
      publications: [
        { kind: 'evm-calldata/1', chain: 'eip155:11155111', transactionId: `0x${'ab'.repeat(32)}`, blockNumber: 7, blockHash: `0x${'cd'.repeat(32)}`, publisher: `0x${'ef'.repeat(20)}` },
      ],
    };
    await seed(envelopes[1], { anchor } as unknown as EvidenceEnvelope['nonRepudiation']);

    const scanner = new ScheduledScanner(storage, bus, registry, { ...defaultConfig, verifyAttestation: true });
    const seen: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid' || event.type === 'attestation_unverifiable') seen.push(event);
    });
    await scanner.runFullPass();

    expect(seen).toEqual([]);
    expect(scanner.getState().lastCompletedPass).toMatchObject({ attestationFailures: 0, attestationUnverifiable: 0 });
  });

  it('an unknown kind before a publication it could not check is publication_not_checked, which raises nothing (tzun-anchor/1 §10.6 precedence)', async () => {
    const envelopes = await captureN(storage, 2);
    const anchor = {
      ...anchorOf(envelopes, 1),
      publications: [
        { kind: 'witness/1', cosignature: 'AAAA' },
        { kind: 'evm-calldata/1', chain: 'eip155:11155111', transactionId: `0x${'ab'.repeat(32)}`, blockNumber: 7, blockHash: `0x${'cd'.repeat(32)}`, publisher: `0x${'ef'.repeat(20)}` },
      ],
    };
    await seed(envelopes[1], { anchor } as unknown as EvidenceEnvelope['nonRepudiation']);

    const scanner = new ScheduledScanner(storage, bus, registry, { ...defaultConfig, verifyAttestation: true });
    const seen: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'attestation_invalid' || event.type === 'attestation_unverifiable') seen.push(event);
    });
    await scanner.runFullPass();

    // The first null publication's reason would be unsupported_publication_kind, an unverifiable anchor.
    expect(seen).toEqual([]);
    expect(scanner.getState().lastCompletedPass).toMatchObject({ attestationFailures: 0, attestationUnverifiable: 0 });
  });
});
