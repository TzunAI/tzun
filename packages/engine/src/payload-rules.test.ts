import { aiBomViolation, fillAiBomNulls } from './ai-bom';
import {
  PAYLOAD_MEMBERS,
  actionViolation,
  aiOutputViolation,
  aiSystemIdViolation,
  captureTimeViolation,
  evidenceIdViolation,
  movedFieldViolation,
  payloadSizeViolation,
  reasonViolation,
  renamedFieldViolation,
  sequenceNumberViolation,
  unhashedPayloadMembers,
} from './payload-rules';
import {
  agentDescriptorDigest,
  agentDescriptorViolation,
  agentKindMismatch,
  canonicalSerializeAgentDescriptor,
} from './agent';
import { V1_0_HASHED_FIELDS } from './schema-registry';
import type { AgentDescriptor } from './types/agent';

const exactBom = {
  modelDescriptorDigest: 'sha256:' + '0a'.repeat(32),
  vendorFingerprint: null,
  promptTemplate: null,
  inferenceParameters: null,
  infrastructure: null,
};

describe('aiBom exact keys', () => {
  it('fills absent nullable members, then accepts the exact shape', () => {
    const filled = fillAiBomNulls({
      modelDescriptorDigest: exactBom.modelDescriptorDigest,
      inferenceParameters: { temperature: 0.2 },
      infrastructure: { provider: 'acme' },
      promptTemplate: { templateId: 't' },
    });
    expect(filled).toEqual({
      modelDescriptorDigest: exactBom.modelDescriptorDigest,
      vendorFingerprint: null,
      promptTemplate: { templateId: 't', templateDigest: null },
      inferenceParameters: { temperature: 0.2, topP: null, maxTokens: null, seed: null, stopSequences: null },
      infrastructure: { provider: 'acme', region: null, apiVersion: null, endpoint: null },
    });
    expect(aiBomViolation(filled)).toBeNull();
    expect(aiBomViolation(exactBom)).toBeNull();
  });

  it.each([
    ['a missing key', { ...exactBom, vendorFingerprint: undefined }, 'aiBom'],
    ['an extra key', { ...exactBom, model: 'x' }, 'aiBom'],
    ['an uppercase digest', { ...exactBom, modelDescriptorDigest: 'sha256:' + '0A'.repeat(32) }, 'aiBom.modelDescriptorDigest'],
    ['a nested missing key', { ...exactBom, promptTemplate: { templateId: null } }, 'aiBom.promptTemplate'],
    ['a string maxTokens', { ...exactBom, inferenceParameters: { temperature: null, topP: null, maxTokens: '3', seed: null, stopSequences: null } }, 'aiBom.inferenceParameters.maxTokens'],
    ['17 stop sequences', { ...exactBom, inferenceParameters: { temperature: null, topP: null, maxTokens: null, seed: null, stopSequences: Array(17).fill('x') } }, 'aiBom.inferenceParameters.stopSequences'],
    ['a long infrastructure string', { ...exactBom, infrastructure: { provider: 'p'.repeat(257), region: null, apiVersion: null, endpoint: null } }, 'aiBom.infrastructure.provider'],
  ])('refuses %s', (_name, value, field) => {
    const v = { ...value } as Record<string, unknown>;
    if (v.vendorFingerprint === undefined && 'vendorFingerprint' in v) delete v.vendorFingerprint;
    expect(aiBomViolation(v)?.field).toBe(field);
  });
});

describe('payload rules', () => {
  it('checks action', () => {
    expect(actionViolation('approve')).toBeNull();
    expect(actionViolation('a'.repeat(128))).toBeNull();
    for (const bad of ['', ' approve', 'approve ', 'a'.repeat(129), 'approve\n', 'appröve', 3]) {
      expect(actionViolation(bad)?.code).toBe('invalid_action');
    }
  });

  it('checks reason in UTF-16 code units', () => {
    expect(reasonViolation('😀'.repeat(8192))).toBeNull();
    expect(reasonViolation('😀'.repeat(8192) + 'x')?.code).toBe('invalid_reason');
    expect(reasonViolation('\ud800')?.code).toBe('invalid_reason');
    expect(reasonViolation('')?.code).toBe('invalid_reason');
  });

  it('reserves the tzun: prefix for system records', () => {
    expect(aiSystemIdViolation(undefined)).toBeNull();
    expect(aiSystemIdViolation('tzun:mandate')?.code).toBe('reserved_ai_system_id');
    expect(aiSystemIdViolation('tzun:link')?.code).toBe('reserved_ai_system_id');
    expect(aiSystemIdViolation('tzun:mandate', { systemRecord: 'mandate' })).toBeNull();
    expect(aiSystemIdViolation('tzun:link', { systemRecord: 'link' })).toBeNull();
    expect(aiSystemIdViolation('tzun:mandate', { systemRecord: 'link' })?.code).toBe('reserved_ai_system_id');
    expect(aiSystemIdViolation('tzun:link', { systemRecord: 'mandate' })?.code).toBe('reserved_ai_system_id');
    expect(aiSystemIdViolation('tzun:mandate', { systemRecord: 'toString' as never })?.code).toBe('reserved_ai_system_id');
    expect(aiSystemIdViolation('claims-triage', { systemRecord: 'link' })).toBeNull();
    // A system record admits only the system ids, never another tzun: name.
    expect(aiSystemIdViolation('tzun:other', { systemRecord: 'link' })?.code).toBe('reserved_ai_system_id');
    expect(aiSystemIdViolation('')?.code).toBe('invalid_ai_system_id');
  });

  it('refuses a non-object aiOutput, the renamed 0.7 fields and the moved ones', () => {
    expect(aiOutputViolation([1])?.code).toBe('invalid_ai_output');
    expect(renamedFieldViolation({ humanAction: 'x' })).toMatchObject({ code: 'renamed_field', field: 'humanAction', renamedTo: 'action' });
    expect(renamedFieldViolation({ humanReason: 'x' })).toMatchObject({ renamedTo: 'reason' });
    expect(renamedFieldViolation({ reviewer: 'x' })).toMatchObject({ renamedTo: 'decider' });
    expect(renamedFieldViolation({ action: 'x' })).toBeNull();
    expect(movedFieldViolation({ aiBom: null })).toMatchObject({ code: 'moved_field', field: 'aiBom', movedTo: 'contributions.steps[].aiBom' });
    expect(movedFieldViolation({ lineage: null })).toMatchObject({ code: 'moved_field', field: 'lineage', movedTo: 'links' });
    expect(movedFieldViolation({ links: null })).toBeNull();
  });

  it('names the twelve payload members, and reports any other in byte order', () => {
    expect(PAYLOAD_MEMBERS).toEqual([
      'action', 'aiOutput', 'aiSystemId', 'capturedAt', 'contributions', 'decider', 'evidenceId', 'links', 'reason',
      'schemaVersion', 'sequenceNumber', 'signoffExpectation',
    ]);
    const payload = Object.fromEntries(PAYLOAD_MEMBERS.map((k) => [k, null]));
    expect(unhashedPayloadMembers(payload)).toEqual([]);
    expect(unhashedPayloadMembers({ ...payload, humanReason: 'x', aiBom: null, Zeta: 1 })).toEqual(['Zeta', 'aiBom', 'humanReason']);
    expect(unhashedPayloadMembers(null)).toEqual([]);
  });

  it('caps the hashed object at 256 KiB of canonical bytes', () => {
    const small = { action: 'a', aiOutput: { blob: 'x'.repeat(1000) } };
    expect(payloadSizeViolation(small, V1_0_HASHED_FIELDS)).toBeNull();
    const big = { action: 'a', aiOutput: { blob: 'x'.repeat(256 * 1024) } };
    expect(payloadSizeViolation(big, V1_0_HASHED_FIELDS)?.code).toBe('payload_too_large');
  });
});

describe('record identity members', () => {
  it.each([[1], [41], [3.0], [Number.MAX_SAFE_INTEGER]])('accepts the sequence number %p', (n) => {
    expect(sequenceNumberViolation(n)).toBeNull();
  });

  it.each([[0], [-1], [1.5], ['3'], [true], [null], [Number.MAX_SAFE_INTEGER + 1]])('refuses the sequence number %p', (n) => {
    expect(sequenceNumberViolation(n)?.code).toBe('invalid_sequence_number');
  });

  it('accepts a v4 UUID record id and an ISO-8601 capture time, and refuses others', () => {
    expect(evidenceIdViolation('5f0c1f0e-2222-4b2b-9b2b-000000000041')).toBeNull();
    expect(evidenceIdViolation('record-41')?.code).toBe('invalid_evidence_id');
    expect(evidenceIdViolation(41)?.code).toBe('invalid_evidence_id');
    expect(captureTimeViolation('2026-10-05T15:04:05.000Z')).toBeNull();
    // A payload rule, not the capture path's skew rule: a far-future time is well formed.
    expect(captureTimeViolation('2099-01-01T00:00:00Z')).toBeNull();
    expect(captureTimeViolation('2026-10-05')?.code).toBe('invalid_captured_at');
    expect(captureTimeViolation('2026-13-45T25:61:61Z')?.code).toBe('invalid_captured_at');
  });
});

describe('agent descriptor', () => {
  const x12: AgentDescriptor = JSON.parse(
    '{"derivation":"base","identities":["spiffe://claims.example/agent/triage"],"instructions":"sha256:be6682dd9f0ba8bbbb060e759803b0b71b69342105824467a8d918a191b391e0","keys":[{"alg":"EdDSA","attestation":null,"custody":"software","kid":"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"}],"models":["sha256:6c9556bc8e35e7701b44ecee10c605a4db9fdf082e6856681db7d7dd1ca3a947"],"name":"claims-triage-agent","operator":{"organization":"Example Insurer","owner":"399bad81f76ef3e1a781d4edcf6eee0b54ce4cfc3304ca56b50d7457910c13b9"},"parent":null,"policy":"sha256:16c9ce7658ad1a8dd72bc047ce935212fc29b829818bac33e61546c3f9c57589","runtime":null,"tools":"sha256:d2269b9f0ab7e0a1ab7bf010b7f60ff9ab2fea2e6f728b666f0bc5e5ebf51ca9","v":"tzun-agent/1"}',
  );

  it('reproduces the example agent descriptor: 729 bytes and its digest', () => {
    expect(agentDescriptorViolation(x12)).toBeNull();
    expect(Buffer.byteLength(canonicalSerializeAgentDescriptor(x12))).toBe(729);
    expect(agentDescriptorDigest(x12)).toBe('sha256:eed92bfa7577d6f66e26fed38c35ebbec3b663a25fd6cc4c6af7d8c7475a250f');
  });

  it('sorts set members before hashing, runtime measurements included', () => {
    const withRuntime = { ...x12, runtime: { format: 'sev-snp', measurements: ['b', 'a'] }, identities: ['spiffe://z.example/b', 'spiffe://a.example/a'] };
    const sorted = { ...withRuntime, runtime: { format: 'sev-snp', measurements: ['a', 'b'] }, identities: ['spiffe://a.example/a', 'spiffe://z.example/b'] };
    expect(agentDescriptorDigest(withRuntime)).toBe(agentDescriptorDigest(sorted));
  });

  it('refuses a missing member, a repeated identity, a repeated kid and a bad key', () => {
    const { tools: _t, ...missing } = x12;
    expect(agentDescriptorViolation(missing)).toMatch(/exactly the members/);
    expect(agentDescriptorViolation({ ...x12, identities: ['spiffe://a/b', 'spiffe://a/b'] })).toMatch(/identities/);
    expect(agentDescriptorViolation({ ...x12, keys: [{ ...x12.keys[0], kid: 'short' }] })).toMatch(/keys/);
    expect(agentDescriptorViolation({ ...x12, keys: [x12.keys[0], { ...x12.keys[0], alg: 'ES256' }] })).toMatch(/keys/);
  });

  it('applies the writer limits at register, and not when re-reading what is stored', () => {
    const many = Array.from({ length: 65 }, (_, i) => `spiffe://e.example/${String(i).padStart(3, '0')}`);
    expect(agentDescriptorViolation({ ...x12, identities: many })).toMatch(/at most 64/);
    expect(agentDescriptorViolation({ ...x12, identities: many }, { limits: false })).toBeNull();
    expect(agentDescriptorViolation({ ...x12, name: 'n'.repeat(257) })).toMatch(/name is at most 256/);
    expect(agentDescriptorViolation({ ...x12, name: 'n'.repeat(256) })).toBeNull();
    const longAttestation = { ...x12, keys: [{ ...x12.keys[0], attestation: 'a'.repeat(8193) }] };
    expect(agentDescriptorViolation(longAttestation)).toMatch(/attestation is at most 8192/);
    expect(agentDescriptorViolation({ ...x12, name: 'bad\ud800' })).toMatch(/lone surrogate/);
    const big = { ...x12, identities: Array.from({ length: 64 }, (_, i) => `spiffe://e.example/${'p'.repeat(230)}${String(i).padStart(2, '0')}`) };
    expect(agentDescriptorViolation(big)).toMatch(/16384/);
  });

  it('sorts sets by UTF-8 bytes, a non-ASCII member included', () => {
    const a = { ...x12, identities: ['spiffe://e.example/\u00e9', 'spiffe://e.example/z'] };
    const b = { ...x12, identities: ['spiffe://e.example/z', 'spiffe://e.example/\u00e9'] };
    expect(agentDescriptorDigest(a)).toBe(agentDescriptorDigest(b));
    expect(canonicalSerializeAgentDescriptor(a)).toContain('["spiffe://e.example/z","spiffe://e.example/\u00e9"]');
  });

  it('a policy engine names no model', () => {
    expect(agentKindMismatch('policy-engine', x12)).toBe(true);
    expect(agentKindMismatch('policy-engine', { ...x12, models: [] })).toBe(false);
    expect(agentKindMismatch('agent', x12)).toBe(false);
  });
});
