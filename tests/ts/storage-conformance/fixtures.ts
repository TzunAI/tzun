/**
 * Fixture builders shared by every leg of the storage conformance suite.
 *
 * Every builder returns a FRESH object graph on each call. That is load-bearing:
 * the suite's reference-vs-copy cases mutate what a builder returned and
 * then assert the store did not change, which only means something if the
 * builder did not hand the same object to two callers.
 */
import { createHash } from 'node:crypto';
import {
  AnnotationRecord,
  ChainIdentity,
  EvidenceEnvelope,
  ForkRecord,
  ModelDescriptor,
  ModelDescriptorAnnotationRow,
  RelinkRecord,
  TamperIncident,
} from '@tzun/engine';

export interface EnvelopeOverrides {
  evidenceId?: string;
  aiSystemId?: string;
  capturedAt?: string;
  digest?: string;
  sequenceNumber?: number;
  chainLink?: string | null;
  reason?: string;
  aiOutput?: Record<string, unknown>;
  attestationStatus?: EvidenceEnvelope['attestationStatus'];
}

let envelopeCounter = 0;

export function makeEnvelope(overrides: EnvelopeOverrides = {}): EvidenceEnvelope {
  envelopeCounter += 1;
  const id = overrides.evidenceId ?? `ev-${envelopeCounter.toString().padStart(4, '0')}`;
  return {
    envelopeVersion: 'e1',
    payload: {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      links: null,
      evidenceId: id,
      schemaVersion: 'v1.0',
      aiSystemId: overrides.aiSystemId ?? 'conformance-system',
      aiOutput: overrides.aiOutput ?? { recommendation: 'approve', confidence: 0.94 },
      action: 'approved',
      reason: overrides.reason ?? 'All criteria met',
      capturedAt: overrides.capturedAt ?? '2026-03-22T10:00:00.000Z',
      sequenceNumber: overrides.sequenceNumber ?? 1,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: {
      // 64 lowercase hex, the shape of a real digest and of an evidence-log
      // leaf, and unique per id so chain_state residues are distinguishable.
      canonicalDigest: overrides.digest ?? createHash('sha256').update(id).digest('hex'),
      chainLink: overrides.chainLink ?? null,
    },
    nonRepudiation: {},
    custodyChain: [
      {
        timestamp: '2026-03-22T10:00:00.000Z',
        actor: 'jane@acme.example',
        action: 'decision_captured',
        systemId: overrides.aiSystemId ?? 'conformance-system',
      },
    ],
    attestationStatus: overrides.attestationStatus ?? 'none',
  };
}

export function makeIncident(overrides: Partial<TamperIncident> = {}): TamperIncident {
  return {
    id: overrides.id ?? 'inc-001',
    detectedAt: overrides.detectedAt ?? '2026-04-04T10:00:00.000Z',
    severity: overrides.severity ?? 'critical',
    type: overrides.type ?? 'digest_mismatch',
    affectedRecords: overrides.affectedRecords ?? ['ev-001'],
    affectedSequenceRange: overrides.affectedSequenceRange,
    details: overrides.details ?? 'Digest mismatch detected on ev-001',
    status: overrides.status ?? 'open',
    resolvedAt: overrides.resolvedAt,
    resolvedBy: overrides.resolvedBy,
    resolutionNotes: overrides.resolutionNotes,
  };
}

export function makeChain(overrides: Partial<ChainIdentity> = {}): ChainIdentity {
  return {
    chainId: overrides.chainId ?? 'chain-001',
    status: overrides.status ?? 'active',
    createdAt: overrides.createdAt ?? '2026-04-04T10:00:00.000Z',
    ...(overrides.parentChainId !== undefined ? { parentChainId: overrides.parentChainId } : {}),
    ...(overrides.forkPoint !== undefined ? { forkPoint: overrides.forkPoint } : {}),
    ...(overrides.sealedAt !== undefined ? { sealedAt: overrides.sealedAt } : {}),
  };
}

export function makeAnnotation(overrides: Partial<AnnotationRecord> = {}): AnnotationRecord {
  return {
    id: overrides.id ?? 'ann-001',
    incidentId: overrides.incidentId ?? 'inc-001',
    affectedRecords: overrides.affectedRecords ?? ['ev-001'],
    annotatedAt: overrides.annotatedAt ?? '2026-04-04T11:00:00.000Z',
    annotatedBy: overrides.annotatedBy ?? 'alice',
    notes: overrides.notes ?? 'reviewed',
    originalDigests: overrides.originalDigests ?? { 'ev-001': 'sha256:abc' },
  };
}

export function makeRelink(overrides: Partial<RelinkRecord> = {}): RelinkRecord {
  return {
    id: overrides.id ?? 'rlk-001',
    incidentId: overrides.incidentId ?? 'inc-001',
    relinkedAt: overrides.relinkedAt ?? '2026-04-04T11:00:00.000Z',
    relinkedBy: overrides.relinkedBy ?? 'alice',
    fromSequence: overrides.fromSequence ?? 1,
    toSequence: overrides.toSequence ?? 2,
    modifiedLinks: overrides.modifiedLinks ?? [
      { evidenceId: 'ev-002', sequenceNumber: 2, previousChainLink: 'old', newChainLink: 'new' },
    ],
  };
}

export function makeFork(overrides: Partial<ForkRecord> = {}): ForkRecord {
  return {
    id: overrides.id ?? 'frk-001',
    incidentId: overrides.incidentId ?? 'inc-001',
    forkedAt: overrides.forkedAt ?? '2026-04-04T11:00:00.000Z',
    forkedBy: overrides.forkedBy ?? 'alice',
    reason: overrides.reason ?? 'tamper',
    oldChainId: overrides.oldChainId ?? 'chain-001',
    newChainId: overrides.newChainId ?? 'chain-002',
    forkAfterSequence: overrides.forkAfterSequence ?? 2,
    sealedOldChainLength: overrides.sealedOldChainLength ?? 2,
  };
}

export function makeDescriptor(overrides: Partial<ModelDescriptor> = {}): ModelDescriptor {
  return {
    descriptorVersion: 'd1',
    vendor: 'anthropic',
    modelName: 'claude-opus-4-7',
    modelVersion: '2026-01-15',
    modelType: null,
    integrityTier: 'vendor-asserted',
    modelDigest: null,
    parentModelDescriptorDigest: null,
    derivation: null,
    trainedBy: null,
    license: null,
    modelCardUrl: null,
    training: { trainingDataDigest: null, trainingDataRef: null, lastTrainingDate: null, evaluations: [] },
    regulatoryMarkings: [],
    externalIdentifiers: [],
    ...overrides,
  };
}

export function makeDescriptorAnnotation(
  digest: string,
  overrides: Partial<ModelDescriptorAnnotationRow> = {},
): ModelDescriptorAnnotationRow {
  return {
    annotationId: overrides.annotationId ?? 'mda-001',
    modelDescriptorDigest: digest,
    annotatedAt: overrides.annotatedAt ?? '2026-05-01T00:00:00.000Z',
    annotatedBy: overrides.annotatedBy ?? 'admin',
    annotationType: overrides.annotationType ?? 'freeform-note',
    valueJson: overrides.valueJson ?? '{"text":"looks right"}',
    retractsAnnotationId: overrides.retractsAnnotationId ?? null,
    signature: overrides.signature ?? null,
    note: overrides.note ?? null,
  };
}
