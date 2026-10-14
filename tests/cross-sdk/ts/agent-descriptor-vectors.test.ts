/**
 * vectors/agent-descriptor-vectors.json (Record §6.9): the engine gives
 * every answer the file states. The Python half is
 * tests/cross-sdk/test_agent_descriptor_vectors.py.
 */
import { agentDescriptorDigest, agentDescriptorViolation, agentKindMismatch, canonicalSerializeAgentDescriptor } from '@tzun/engine';
import { materialize, vectorFile } from './vectors';

type Case = Record<string, any>;
const v = vectorFile<Record<string, Case[]>>('agent-descriptor-vectors.json');

describe('agent descriptor vectors', () => {
  it.each(v.digests)('digest: $case', (c) => {
    expect(canonicalSerializeAgentDescriptor(c.descriptor)).toBe(c.canonical);
    expect(Buffer.byteLength(c.canonical)).toBe(c.byteLength);
    expect(agentDescriptorDigest(c.descriptor)).toBe(c.digest);
  });
  it.each(v.violations)('violation: $case', (c) => {
    const d = materialize(c.descriptor);
    expect(agentDescriptorViolation(d, { limits: false }) === null).toBe(c.grammar);
    expect(agentDescriptorViolation(d) === null).toBe(c.writer);
  });
  it.each(v.kinds)('kind: $case', (c) => expect(agentKindMismatch(c.kind, c.descriptor)).toBe(c.mismatch));
});
