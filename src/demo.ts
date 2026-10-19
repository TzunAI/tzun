import { canonicalSerialize } from '@tzun/engine';
import { computeDigest } from '@tzun/engine';
import { SchemaRegistry } from '@tzun/engine';
import { EvidenceChain } from '@tzun/engine';
import { assembleEnvelope } from '@tzun/engine';
import { verifyEnvelope } from '@tzun/engine';
import type { Decider, EnvelopeInput, EvidenceEnvelope } from '@tzun/engine';

/** A human decider by an opaque account id (never an email address or a name). */
function human(account: string): Decider {
  return { kind: 'human', id: `acct:${account}`, agent: null, credential: null, freshness: null };
}

function separator() {
  console.log('─'.repeat(60));
}

function main() {
  console.log();
  console.log('  TZUN EVIDENCE ENGINE — Interactive Demo');
  console.log('  Tamper-Evident Records for AI Decisions');
  separator();

  // ── 1. Capture a decision ─────────────────────────────────────
  console.log();
  console.log('1. CAPTURING DECISION');
  console.log();

  const input: EnvelopeInput = {
    aiSystemId: 'openai-gpt4',
    aiOutput: {
      recommendation: 'approve',
      confidence: 0.94,
      riskFactors: ['credit_score_borderline'],
    },
    action: 'approved',
    reason: 'Applicant has strong employment history despite borderline credit score',
    decider: human('u-4821'),
  };

  console.log('   AI System:      ', input.aiSystemId);
  console.log('   AI recommended: ', (input.aiOutput as any).recommendation,
    `(confidence: ${(input.aiOutput as any).confidence})`);
  console.log('   Decision:       ', input.action);
  console.log('   Reason:         ', input.reason);
  console.log('   Decided by:     ', input.decider.id);

  const envelope = assembleEnvelope(input);

  console.log();
  console.log('   Evidence envelope created:');
  console.log('   Evidence ID:    ', envelope.payload.evidenceId);
  console.log('   Schema:         ', envelope.payload.schemaVersion);
  console.log('   Digest:         ', envelope.integrity.canonicalDigest);
  console.log('   Chain link:     ', envelope.integrity.chainLink ?? '(first record)');
  console.log('   Attestation:    ', envelope.attestationStatus, '(dev mode — no external services)');
  console.log('   Custody entry:  ', envelope.custodyChain[0].action,
    'by', envelope.custodyChain[0].actor);

  // ── 2. Verify integrity ───────────────────────────────────────
  separator();
  console.log();
  console.log('2. VERIFYING INTEGRITY');
  console.log();

  const verifyResult = verifyEnvelope(envelope);
  console.log('   Stored digest:     ', verifyResult.storedDigest);
  console.log('   Recomputed digest: ', verifyResult.recomputedDigest);
  console.log('   Digest match:      ', verifyResult.storedDigest === verifyResult.recomputedDigest ? 'YES' : 'NO');
  console.log('   Schema valid:      ', verifyResult.schemaValid ? 'YES' : 'NO');
  console.log('   Result:            ', verifyResult.verified ? 'VERIFIED' : 'FAILED');

  // ── 3. Simulate tampering ─────────────────────────────────────
  separator();
  console.log();
  console.log('3. SIMULATING TAMPER ATTACK');
  console.log();
  console.log('   Attacker changes the reason to hide the real rationale...');
  console.log();

  // Clone the envelope and tamper with it
  const tampered: EvidenceEnvelope = JSON.parse(JSON.stringify(envelope));
  tampered.payload.reason = 'Auto-approved by system';

  console.log('   Original reason: ', envelope.payload.reason);
  console.log('   Tampered reason: ', tampered.payload.reason);
  console.log();

  const tamperResult = verifyEnvelope(tampered);
  console.log('   Re-verifying tampered record...');
  console.log('   Stored digest:     ', tamperResult.storedDigest);
  console.log('   Recomputed digest: ', tamperResult.recomputedDigest);
  console.log('   Digest match:      ', tamperResult.storedDigest === tamperResult.recomputedDigest ? 'YES' : 'NO');
  console.log('   Result:            ', tamperResult.verified ? 'VERIFIED' : 'TAMPER DETECTED');

  // ── 4. Evidence chain ─────────────────────────────────────────
  separator();
  console.log();
  console.log('4. BUILDING EVIDENCE CHAIN (3 records)');
  console.log();

  const decisions: EnvelopeInput[] = [
    {
      aiSystemId: 'openai-gpt4',
      aiOutput: { recommendation: 'approve', confidence: 0.91 },
      action: 'approved',
      reason: 'Standard approval',
      decider: human('u-4821'),
    },
    {
      aiSystemId: 'openai-gpt4',
      aiOutput: { recommendation: 'deny', confidence: 0.87 },
      action: 'escalated',
      reason: 'Needs senior review — model confidence below threshold',
      decider: human('u-4821'),
    },
    {
      aiSystemId: 'openai-gpt4',
      aiOutput: { recommendation: 'approve', confidence: 0.96 },
      action: 'approved',
      reason: 'Clear approval',
      decider: human('u-7702'),
    },
  ];

  const chain: EvidenceEnvelope[] = [];
  let previousDigest: string | undefined;

  for (let i = 0; i < decisions.length; i++) {
    const env = assembleEnvelope(decisions[i], { previousDigest, sequenceNumber: i + 1 });
    chain.push(env);
    previousDigest = env.integrity.canonicalDigest;
    console.log(`   Record ${i + 1}:`);
    console.log(`     ID:         ${env.payload.evidenceId.slice(0, 8)}...`);
    console.log(`     Action:     ${env.payload.action}`);
    console.log(`     Digest:     ${env.integrity.canonicalDigest.slice(0, 16)}...`);
    console.log(`     Chain link:  ${env.integrity.chainLink?.slice(0, 16) ?? '(genesis)'}...`);
    console.log();
  }

  // Verify the full chain
  console.log('   Verifying chain integrity...');
  let chainValid = true;
  for (let i = 0; i < chain.length; i++) {
    const prev = i > 0 ? chain[i - 1].integrity.canonicalDigest : undefined;
    const result = verifyEnvelope(chain[i], prev);
    const status = result.verified ? 'OK' : 'BROKEN';
    console.log(`     Record ${i + 1}: ${status}`);
    if (!result.verified) chainValid = false;
  }
  console.log(`   Chain status: ${chainValid ? 'INTACT' : 'COMPROMISED'}`);

  // ── 5. Tamper with chain ──────────────────────────────────────
  separator();
  console.log();
  console.log('5. TAMPERING WITH CHAIN HISTORY');
  console.log();
  console.log('   Attacker modifies Record 1 and recomputes its digest...');
  console.log();

  // Clone chain and tamper with record 1
  const tamperedChain: EvidenceEnvelope[] = JSON.parse(JSON.stringify(chain));
  tamperedChain[0].payload.reason = 'FORGED: Auto-approved';
  // Attacker recomputes the digest to try to cover their tracks
  const registry = new SchemaRegistry();
  const schema = registry.get('v1.0')!;
  const newCanonical = canonicalSerialize(
    tamperedChain[0].payload as unknown as Record<string, unknown>,
    schema.hashedFieldSet
  );
  tamperedChain[0].integrity.canonicalDigest = computeDigest(newCanonical);

  console.log('   Attacker updated Record 1 digest to match new content.');
  console.log('   But Record 2 chain link still references the ORIGINAL Record 1 digest...');
  console.log();

  console.log('   Re-verifying tampered chain...');
  let tamperedChainValid = true;
  for (let i = 0; i < tamperedChain.length; i++) {
    const prev = i > 0 ? tamperedChain[i - 1].integrity.canonicalDigest : undefined;
    const result = verifyEnvelope(tamperedChain[i], prev);
    const status = result.verified ? 'OK' : 'BROKEN';
    const detail = !result.verified && result.chainLinkValid === false
      ? ' (chain link mismatch — tampering detected)'
      : '';
    console.log(`     Record ${i + 1}: ${status}${detail}`);
    if (!result.verified) tamperedChainValid = false;
  }
  console.log(`   Chain status: ${tamperedChainValid ? 'INTACT' : 'COMPROMISED — TAMPERING DETECTED'}`);

  // ── 6. Canonical serialization demo ───────────────────────────
  separator();
  console.log();
  console.log('6. CANONICAL SERIALIZATION');
  console.log();

  const demoFields = {
    evidenceId: 'demo-123',
    aiSystemId: 'gpt4',
    aiOutput: { z_score: 0.94, approval: true, factors: ['income', 'history'] },
    action: 'approved',
    reason: 'Met criteria',
    decider: human('u-4821'),
    capturedAt: '2026-03-22T15:30:00Z',
  };

  console.log('   Input (keys in random order):');
  console.log('   ', JSON.stringify(demoFields, null, 2).split('\n').join('\n    '));
  console.log();

  const canonical = canonicalSerialize(
    demoFields as unknown as Record<string, unknown>,
    schema.hashedFieldSet
  );
  console.log('   Canonical output (keys sorted, no whitespace):');
  console.log('   ', canonical);
  console.log();
  console.log('   SHA-256 digest:');
  console.log('   ', computeDigest(canonical));
  console.log();
  console.log('   This output is byte-identical across any conforming implementation');
  console.log('   in any programming language — TypeScript, Python, Rust, Go, C#.');

  // ── Done ──────────────────────────────────────────────────────
  separator();
  console.log();
  console.log('  Demo complete. The Evidence Engine is working.');
  console.log();
  console.log('  What you just saw:');
  console.log('    1. Decision captured as a cryptographic evidence envelope');
  console.log('    2. Integrity verified by recomputing the digest');
  console.log('    3. Tamper attack detected via digest mismatch');
  console.log('    4. Evidence chain built with sequential hash linking');
  console.log('    5. Chain tampering detected even when attacker recomputes digest');
  console.log('    6. Canonical serialization produces deterministic output');
  console.log();
  console.log('  Next: Attestation Services (FIDO2 signatures, RFC 3161 timestamps,');
  console.log('  anchoring to a public ledger) will add non-repudiation and temporal proof.');
  console.log();
}

main();
