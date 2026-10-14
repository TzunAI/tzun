/**
 * Generate vectors/agent-descriptor-vectors.json: the agent descriptor
 * `tzun-agent/1` (Record §6.9).
 *
 *   - digests     a descriptor, its canonical bytes with every set sorted by
 *                 UTF-8 bytes, and its digest: the example descriptor of
 *                 Record §6.9, its sets supplied out of order,
 *                 `runtime.measurements`, and a set whose order by UTF-8
 *                 bytes differs from its order by UTF-16 code units;
 *   - violations  a descriptor, whether its grammar holds, and whether a
 *                 writer's limits hold (`register` refuses past them; a
 *                 store-level verifier re-hashes whatever is stored): a
 *                 repeated kid and every other grammar rule, and each writer
 *                 limit;
 *   - kinds       a decider kind and a descriptor, and whether the kind
 *                 contradicts it (`agent_kind_mismatch`: a policy engine whose
 *                 descriptor names a model).
 *
 *   pnpm exec tsx scripts/generate-agent-descriptor-vectors.ts > vectors/agent-descriptor-vectors.json
 *
 * Every expected answer is written here from the specification, and the script
 * stops if the engine disagrees. The TS replay is
 * tests/cross-sdk/ts/agent-descriptor-vectors.test.ts; the Python
 * recomputation is tests/cross-sdk/test_agent_descriptor_vectors.py.
 */
import {
  agentDescriptorDigest,
  agentDescriptorViolation,
  agentKindMismatch,
  canonicalSerializeAgentDescriptor,
  canonicalSerializeValue,
  type AgentDescriptor,
} from '@tzun/engine';
import { AGENT, LONE_SURROGATE, MODEL, checker, emit, prefixed, sha256Hex } from './generate-vectors-shared';

const { agree } = checker('generate-agent-descriptor-vectors');

const EXAMPLE_TEXT =
  '{"derivation":"base","identities":["spiffe://claims.example/agent/triage"],"instructions":"sha256:be6682dd9f0ba8bbbb060e759803b0b71b69342105824467a8d918a191b391e0","keys":[{"alg":"EdDSA","attestation":null,"custody":"software","kid":"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"}],"models":["sha256:6c9556bc8e35e7701b44ecee10c605a4db9fdf082e6856681db7d7dd1ca3a947"],"name":"claims-triage-agent","operator":{"organization":"Example Insurer","owner":"399bad81f76ef3e1a781d4edcf6eee0b54ce4cfc3304ca56b50d7457910c13b9"},"parent":null,"policy":"sha256:16c9ce7658ad1a8dd72bc047ce935212fc29b829818bac33e61546c3f9c57589","runtime":null,"tools":"sha256:d2269b9f0ab7e0a1ab7bf010b7f60ff9ab2fea2e6f728b666f0bc5e5ebf51ca9","v":"tzun-agent/1"}';
const EXAMPLE = JSON.parse(EXAMPLE_TEXT) as AgentDescriptor;
const KID_A = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const KID = EXAMPLE.keys[0].kid;
const d = (edit: Partial<Record<keyof AgentDescriptor, unknown>>): AgentDescriptor => ({ ...EXAMPLE, ...edit }) as AgentDescriptor;
const byUtf8 = (a: string, b: string) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));

/** The descriptor with its sets sorted by UTF-8 bytes, written here rather than by the engine. */
function sortedByRule(x: AgentDescriptor): AgentDescriptor {
  return {
    ...x,
    identities: [...x.identities].sort(byUtf8),
    keys: [...x.keys].sort((a, b) => byUtf8(a.kid, b.kid)),
    models: [...x.models].sort(byUtf8),
    runtime: x.runtime && { ...x.runtime, measurements: [...x.runtime.measurements].sort(byUtf8) },
  };
}

const digestCases: Array<[string, AgentDescriptor]> = [
  ['the example descriptor of Record §6.9', EXAMPLE],
  ['its sets supplied out of order: identities, keys by kid, models', d({
    identities: ['spiffe://claims.example/agent/triage', 'spiffe://alpha.example/agent/triage'],
    keys: [EXAMPLE.keys[0], { kid: KID_A, alg: 'ES256', custody: 'hsm', attestation: 'tpm-quote' }],
    models: ['sha256:' + 'ff'.repeat(32), MODEL],
  })],
  ['runtime.measurements supplied out of order', d({ runtime: { format: 'sev-snp', measurements: ['zz', 'aa', 'mm'] } })],
  [
    'a set whose order by UTF-8 bytes (U+FF01 first) is not its order by UTF-16 code units (U+1F600 first)',
    d({ identities: ['spiffe://claims.example/agent/\u{1F600}', 'spiffe://claims.example/agent/！'] }),
  ],
  ['a non-ASCII member beside an ASCII one', d({ identities: ['spiffe://claims.example/agent/é', 'spiffe://claims.example/agent/z'] })],
  ['a policy engine: models empty, no instructions or tools', d({ name: 'refund-rules', models: [], instructions: null, tools: null, derivation: null })],
  ['a revision of the example, naming it as parent', d({ parent: AGENT, derivation: 'revision' })],
];
const digests = digestCases.map(([label, descriptor]) => {
  const canonical = canonicalSerializeValue(sortedByRule(descriptor));
  return { case: label, descriptor, canonical, byteLength: Buffer.byteLength(canonical), digest: 'sha256:' + sha256Hex(canonical) };
});
agree('the example\'s bytes', digests[0].canonical, EXAMPLE_TEXT);
agree('the example\'s length', digests[0].byteLength, 729);
agree('the example\'s digest', digests[0].digest, AGENT);
agree('UTF-8 order', JSON.parse(digests[3].canonical).identities, ['spiffe://claims.example/agent/！', 'spiffe://claims.example/agent/\u{1F600}']);
for (const c of digests) {
  agree(`digests "${c.case}" bytes`, canonicalSerializeAgentDescriptor(c.descriptor), c.canonical);
  agree(`digests "${c.case}" digest`, agentDescriptorDigest(c.descriptor), c.digest);
  agree(`digests "${c.case}" valid`, agentDescriptorViolation(c.descriptor), null);
}

const violations: Array<{ case: string; descriptor: unknown; grammar: boolean; writer: boolean }> = [];
const bad = (c: string, descriptor: unknown) => violations.push({ case: c, descriptor, grammar: false, writer: false });
const limit = (c: string, descriptor: unknown) => violations.push({ case: c, descriptor, grammar: true, writer: false });
const fine = (c: string, descriptor: unknown) => violations.push({ case: c, descriptor, grammar: true, writer: true });

bad('a repeated kid (a duplicate is refused, never removed)', d({ keys: [EXAMPLE.keys[0], { ...EXAMPLE.keys[0], alg: 'ES256' }] }));
bad('a repeated identity', d({ identities: [EXAMPLE.identities[0], EXAMPLE.identities[0]] }));
bad('a repeated model', d({ models: [MODEL, MODEL] }));
bad('a repeated measurement', d({ runtime: { format: 'sev-snp', measurements: ['aa', 'aa'] } }));
bad('a member outside the twelve', { ...EXAMPLE, note: 'x' });
bad('a member missing (every member is written, null where it does not apply)', (() => {
  const { parent: _parent, ...rest } = EXAMPLE;
  return rest;
})());
bad('the version tag of another document', d({ v: 'tzun-agent/2' }));
bad('an empty name', d({ name: '' }));
bad('an operator without owner', d({ operator: { organization: 'Example Insurer' } }));
bad('a prefixed operator owner', d({ operator: { organization: 'Example Insurer', owner: `sha256:${'39'.repeat(32)}` } }));
bad('an empty organization', d({ operator: { organization: '', owner: null } }));
bad('a kid of 42 characters', d({ keys: [{ ...EXAMPLE.keys[0], kid: KID.slice(1) }] }));
bad('a key algorithm outside the three (RS256)', d({ keys: [{ ...EXAMPLE.keys[0], alg: 'RS256' }] }));
bad('a key custody outside the four', d({ keys: [{ ...EXAMPLE.keys[0], custody: 'cloud' }] }));
bad('an empty attestation (write null)', d({ keys: [{ ...EXAMPLE.keys[0], attestation: '' }] }));
bad('a key with a member outside the four', d({ keys: [{ ...EXAMPLE.keys[0], use: 'sig' }] }));
bad('a bare model digest', d({ models: [MODEL.slice(7)] }));
bad('a bare instructions digest', d({ instructions: EXAMPLE.instructions!.slice(7) }));
bad('runtime with a member outside format and measurements', d({ runtime: { format: 'sev-snp', measurements: [], vendor: 'amd' } }));
bad('an empty measurement', d({ runtime: { format: 'sev-snp', measurements: [''] } }));
bad('a derivation outside the four', d({ derivation: 'copy' }));
bad('an empty identity', d({ identities: [''] }));
fine('a set at its limit: 64 identities', d({ identities: Array.from({ length: 64 }, (_, i) => `spiffe://claims.example/agent/${String(i).padStart(2, '0')}`) }));
limit('65 identities', d({ identities: Array.from({ length: 65 }, (_, i) => `spiffe://claims.example/agent/${String(i).padStart(2, '0')}`) }));
limit('65 models', d({ models: Array.from({ length: 65 }, (_, i) => prefixed(`model ${i}`)).sort() }));
fine('a name of 256 UTF-16 code units', d({ name: 'n'.repeat(256) }));
limit('a name of 257 UTF-16 code units', d({ name: 'n'.repeat(257) }));
limit('a name of 129 astral characters (258 UTF-16 code units)', d({ name: '\u{1F916}'.repeat(129) }));
limit('an organization of 257 characters', d({ operator: { organization: 'o'.repeat(257), owner: null } }));
limit('a runtime format of 257 characters', d({ runtime: { format: 'f'.repeat(257), measurements: [] } }));
fine('an attestation of 8,192 characters', d({ keys: [{ ...EXAMPLE.keys[0], attestation: 'a'.repeat(8192) }] }));
limit('an attestation of 8,193 characters', d({ keys: [{ ...EXAMPLE.keys[0], attestation: 'a'.repeat(8193) }] }));
limit('over 16 KiB of canonical bytes, every string within its own limit', d({
  keys: [{ ...EXAMPLE.keys[0], attestation: 'q'.repeat(8192) }, { kid: KID_A, alg: 'ES256', custody: 'hsm', attestation: 'q'.repeat(8192) }],
}));
limit('a lone surrogate in the name (sentinel LONE_SURROGATE_D800)', d({ name: `agent ${LONE_SURROGATE}` }));
const materialize = (v: unknown): unknown => {
  if (typeof v === 'string') return v.replace(/LONE_SURROGATE_D800/g, '\uD800');
  if (Array.isArray(v)) return v.map(materialize);
  if (v !== null && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, e]) => [k, materialize(e)]));
  return v;
};
for (const v of violations) {
  const descriptor = materialize(v.descriptor);
  agree(`violations "${v.case}" grammar`, agentDescriptorViolation(descriptor, { limits: false }) === null, v.grammar);
  agree(`violations "${v.case}" writer`, agentDescriptorViolation(descriptor) === null, v.writer);
}

const kinds = [
  { case: 'a policy engine whose descriptor names a model', kind: 'policy-engine', descriptor: EXAMPLE, mismatch: true },
  { case: 'a policy engine whose descriptor names none', kind: 'policy-engine', descriptor: d({ models: [] }), mismatch: false },
  { case: 'an agent whose descriptor names a model', kind: 'agent', descriptor: EXAMPLE, mismatch: false },
  { case: 'an agent whose descriptor names none', kind: 'agent', descriptor: d({ models: [] }), mismatch: false },
  { case: 'agent-mandated', kind: 'agent-mandated', descriptor: EXAMPLE, mismatch: false },
];
for (const k of kinds) agree(`kinds "${k.case}"`, agentKindMismatch(k.kind, k.descriptor), k.mismatch);

emit({
  description:
    'The agent descriptor tzun-agent/1 (Record §6.9): its canonical bytes and digest with every set sorted by UTF-8 bytes, its ' +
    'grammar and the limits a writer applies when it registers one, and the decider kind it contradicts (Record §6.4).',
  source:
    'Generated by scripts/generate-agent-descriptor-vectors.ts. Every expected answer is written in the script from the specification, and the ' +
    'script stops if the engine disagrees with one. A violations case with grammar true and writer false is a descriptor a store-level ' +
    'verifier re-hashes as stored and a writer refuses to register. LONE_SURROGATE_D800 stands for an unpaired U+D800; a harness ' +
    'substitutes it before it checks.',
  digests,
  violations,
  kinds,
});
