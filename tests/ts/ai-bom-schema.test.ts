import { modelOf } from './helpers/step-model';
import {
  ModelDescriptor, AiBom, Evaluation, RegulatoryMarking, ExternalIdentifier,
  ModelDescriptorRow, ModelDescriptorAnnotationRow, ModelDescriptorAliasRow,
} from '@tzun/engine';
import { EvidencePayload } from '@tzun/engine';
import { CaptureInput } from '@tzun/engine';

describe('AI-BOM schema (v1)', () => {
  it('MVD descriptor has 3 populated fields + all others nullable', () => {
    const mvd: ModelDescriptor = {
      descriptorVersion: 'd1',
      vendor: 'anthropic', modelName: 'claude-opus-4-7', modelVersion: '2026-01-15',
      modelType: null, integrityTier: 'vendor-asserted',
      modelDigest: null, parentModelDescriptorDigest: null, derivation: null,
      trainedBy: null, license: null, modelCardUrl: null,
      training: { trainingDataDigest: null, trainingDataRef: null, lastTrainingDate: null, evaluations: [] },
      regulatoryMarkings: [], externalIdentifiers: [],
    };
    expect(mvd.vendor).toBe('anthropic');
  });

  it('weight-attested descriptor has non-null modelDigest', () => {
    const w: ModelDescriptor = {
      descriptorVersion: 'd1', vendor: 'self-hosted', modelName: 'llama-3.1-70b', modelVersion: '2024.07',
      modelType: 'llm', integrityTier: 'weight-attested', modelDigest: 'sha256:abc',
      parentModelDescriptorDigest: null, derivation: 'base', trainedBy: 'Meta',
      license: 'llama-3.1-community', modelCardUrl: null,
      training: { trainingDataDigest: null, trainingDataRef: null, lastTrainingDate: null, evaluations: [] },
      regulatoryMarkings: [], externalIdentifiers: [],
    };
    expect(w.modelDigest).toMatch(/^sha256:/);
  });

  it('AiBom requires modelDescriptorDigest', () => {
    const bom: AiBom = {
      modelDescriptorDigest: 'sha256:def',
      vendorFingerprint: null, promptTemplate: null,
      inferenceParameters: null, infrastructure: null,
    };
    expect(bom.modelDescriptorDigest).toBe('sha256:def');
  });

  it('EvidencePayload accepts aiBom null', () => {
    const p: EvidencePayload = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      links: null,
      evidenceId: 'e', schemaVersion: 'v1.0', aiSystemId: 's', aiOutput: {},
      action: 'a', reason: 'r', capturedAt: '2026-05-25T00:00:00Z',
      sequenceNumber: 1, contributions: null, signoffExpectation: null,
    };
    expect(modelOf(p)).toBeNull();
  });

  it('a CaptureInput need record no model: contributions are optional', () => {
    const ci: CaptureInput = { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: {}, action: 'a', reason: 'r' };
    expect(modelOf(ci)).toBeNull();
  });
});
