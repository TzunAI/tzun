/**
 * Minimal end-to-end example: capture an evidence envelope, verify it,
 * print the result.
 *
 * Run:
 *   pnpm install
 *   pnpm dev           # ts-node / tsx
 *   # or
 *   pnpm build && pnpm start
 *
 * This example uses the in-memory storage backend so it has no external
 * dependencies (no Postgres, no FreeTSA). For production configuration
 * (PostgreSQL or SQLite storage, RFC 3161 timestamps, WebAuthn sign-off) see
 * the Modes, Timestamp authorities and Signing a decision sections of the
 * repository README and docs/integration/. The record format itself is
 * specified at https://spec.tzun.ai.
 */

import { Tzun } from '@tzun/sdk';

async function main(): Promise<void> {
  // 1. Construct the client. Mode 'dev' keeps everything in-memory; no
  //    network, no DB, no attestation. Perfect for an SDK smoke test.
  //    Construction is async (storage + chain-state restore), so use the
  //    static `Tzun.init` factory rather than `new Tzun(...)`.
  const tzun = await Tzun.init({
    mode: 'dev',
  });

  // 2. Capture a decision. Tzun assembles the canonical bytes, computes
  //    the SHA-256 digest, and (in dev mode) returns the envelope without
  //    further attestation.
  const captureResult = await tzun.capture({
    aiSystemId: 'tzun.example.v1',
    aiOutput: {
      recommendation: 'approve',
      confidence: 0.94,
    },
    action: 'approved',
    reason: 'Example payload for the ts-example skeleton.',
    // Who decided, by an opaque account id (never an email address or a name).
    decider: { kind: 'human', id: 'acct:u-example' },
  });

  const { envelope } = captureResult;

  console.log('Captured envelope:');
  console.log(`  id:     ${envelope.payload.evidenceId}`);
  console.log(`  digest: ${envelope.integrity.canonicalDigest}`);
  console.log(`  status: ${envelope.attestationStatus}`);

  // 3. Verify the envelope by its evidence id. Re-canonicalizes,
  //    re-hashes, compares the digest, and (in higher modes) re-validates
  //    the timestamp and the WebAuthn signature.
  const verification = await tzun.verify(envelope.payload.evidenceId);

  console.log('Verification:');
  console.log(`  verified: ${verification.verified}`);
  if (!verification.verified) {
    console.log(`  storedDigest:     ${verification.storedDigest}`);
    console.log(`  recomputedDigest: ${verification.recomputedDigest}`);
  }
}

main().catch((err: unknown) => {
  console.error('ts-example failed:', err);
  process.exit(1);
});
