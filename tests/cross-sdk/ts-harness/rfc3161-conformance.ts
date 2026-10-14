/**
 * Cross-SDK harness for the RFC 3161 client's capture check (tzun-anchor/1
 * §10.5 steps 1 to 3): the Node side.
 * tests/cross-sdk/test_rfc3161_conformance_parity.py drives it and compares
 * every answer with tzun_sdk.attestation.rfc3161.
 *
 * Reads one JSON command from stdin, runs it against the in-repo TypeScript
 * (never a published version), writes one JSON result to stdout.
 *
 *   { action: "corpus", digest, nonce, genTime }
 *     → { cases: [{ name, token }] }: a token over `digest`, echoing `nonce`,
 *     from a throwaway authority (tests/ts/rfc3161-fixture.ts) for each
 *     `TokenFaults` shape and for none, and the unsigned token of the mock
 *     authority (tests/ts/helpers/mock-tsa.ts).
 *
 *   { action: "conformance", cases: [{ token, digest }] }
 *     → { results: [TimestampConformance] }: `timestampConformance`, the answer
 *     `RFC3161Client` returns for each token it keeps.
 *
 *   { action: "flips", token, digest, mask }
 *     → { results: [TimestampConformance] }: the same, for the token with
 *     byte i XORed with `mask`, for every i in order.
 *
 *   { action: "capture", url, cases: [{ token, digest, nonce }] }
 *     → { results: [{ stored, events }] }: a capture's attestation through
 *     `AttestationOrchestrator` and a real `RFC3161Client` whose one authority
 *     at `url` answers with `token`, and whose request nonce is `nonce`.
 *     `stored` is whether the artifacts carry the token; `events` are the
 *     `attestation_timestamp_nonconformant` events on `onLog`.
 *
 *   { action: "authority", subjects: [hex] }
 *     → { results: [string] }: `authorityOf` over each subject Name's DER, the
 *     trust check's `authority` fact (tzun-anchor/1 §10.5 step 4).
 *
 *   { action: "steps-authority", cases: [{ token, digest }] }
 *     → { results: [{ token, authority }] }: `verifyRfc3161Steps` with no
 *     root, its steps 1 to 3 verdict and the signer's `authority`.
 *
 *   { action: "trust-anchors", cases: [[pem]] }
 *     → { results: [{ count } | { error }] }: `trustAnchorsFromPem` over each
 *     list of the auditor's PEM entries: how many certificates it read, or
 *     the message of the `UnreadableTrustAnchorError` it threw.
 */
import { AttestationOrchestrator } from '../../../src/attestation/orchestrator';
import { RFC3161Client, timestampConformance } from '../../../src/attestation/rfc3161';
import { authorityOf, trustAnchorsFromPem, UnreadableTrustAnchorError, verifyRfc3161Steps } from '../../../src/attestation/rfc3161-token';
import { makeSigningTsa, type TokenFaults } from '../../ts/rfc3161-fixture';
import { buildTimestampResponse, makeResponse } from '../../ts/helpers/mock-tsa';

/**
 * The module object `src/attestation/rfc3161.ts` reads `randomBytes` from when
 * it draws a request nonce, so the "capture" command can set the nonce.
 */
// eslint-disable-next-line @typescript-eslint/no-require-imports
const nodeCrypto: { randomBytes: (size: number) => Buffer } = require('crypto');

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
  });
}

/** Every shape of `TokenFaults`, one rule of §10.5 broken (or its edge tested) at a time. */
const FAULTS: Array<[string, TokenFaults]> = [
  ['conforming', {}],
  ['ber-tst-info', { berTstInfo: true }],
  ['non-der-gen-time', { nonDerGenTime: true }],
  ['without-signer-certificate', { withoutSignerCertificate: true }],
  ['digest-algorithms-bare-oid', { digestAlgorithms: 'bare-oid' }],
  ['signer-key-bad', { signerKey: 'bad-key' }],
  ['signer-key-unknown-algorithm', { signerKey: 'unknown-key-algorithm' }],
  ['issuer-copy-bad-key', { issuerCopy: 'bad-key' }],
  ['issuer-copy-unknown-key-algorithm', { issuerCopy: 'unknown-key-algorithm' }],
  ['signer-key-unassigned-curve', { signerKey: 'unassigned-curve' }],
  ['issuer-copy-unassigned-curve', { issuerCopy: 'unassigned-curve' }],
  ['unneeded-certificate-unassigned-curve', { unneededCertificate: 'unassigned-curve' }],
  ['signer-issuer-intermediate-unassigned-curve', { signerIssuer: 'intermediate-unassigned-curve' }],
  ['content-type-data', { contentType: 'data' }],
  ['message-digest-other', { messageDigest: 'other' }],
  ['signer-issuer-name-utf8', { signerIssuerName: 'utf8' }],
  ['signing-certificate-v1', { signingCertificate: 'v1' }],
  ['signing-certificate-none', { signingCertificate: 'none' }],
  ['signing-certificate-other', { signingCertificate: 'other-certificate' }],
  ['signer-eku-none', { signerEku: 'none' }],
  ['signer-eku-non-critical', { signerEku: 'non-critical' }],
  ['signer-eku-tls-server', { signerEku: 'tls-server' }],
  ['signer-eku-second-purpose', { signerEku: 'second-purpose' }],
];

async function corpus(digest: string, nonce: string, genTime: string): Promise<Json> {
  const tsa = await makeSigningTsa();
  const at = new Date(genTime);
  const cases: Json[] = [];
  for (const [name, faults] of FAULTS) {
    const der = await tsa.issue(digest, Buffer.from(nonce, 'hex'), at, faults);
    cases.push({ name, token: der.toString('base64') });
  }
  cases.push({ name: 'mock-authority', token: buildTimestampResponse(digest, Buffer.from(nonce, 'hex'), { genTime: at }) });
  return { cases };
}

function flips(token: string, digest: string, mask: number): Json {
  const der = Buffer.from(token, 'base64');
  const results: Json[] = [];
  for (let i = 0; i < der.length; i++) {
    const flipped = Buffer.from(der);
    flipped[i] ^= mask;
    results.push(timestampConformance(flipped.toString('base64'), digest) as unknown as Json);
  }
  return { results };
}

async function capture(url: string, cases: Array<{ token: string; digest: string; nonce: string }>): Promise<Json> {
  const results: Json[] = [];
  const randomBytes = nodeCrypto.randomBytes;
  try {
    for (const c of cases) {
      // The client draws its request nonce with crypto.randomBytes(8); this is the nonce `token` echoes.
      nodeCrypto.randomBytes = () => Buffer.from(c.nonce, 'hex');
      const events: Json[] = [];
      const client = new RFC3161Client({
        tsaUrl: url,
        fetchFn: (async () => makeResponse(Buffer.from(c.token, 'base64'), 'application/timestamp-reply')) as unknown as typeof fetch,
      });
      const orchestrator = new AttestationOrchestrator({
        timestampClient: client,
        onLog: (event, fields) => {
          if (event === 'attestation_timestamp_nonconformant') events.push({ event, ...fields } as Json);
        },
      });
      const artifacts = await orchestrator.attest(c.digest);
      results.push({ stored: artifacts.rfc3161Token === c.token, events });
    }
  } finally {
    nodeCrypto.randomBytes = randomBytes;
  }
  return { results };
}

async function main(): Promise<void> {
  const cmd = JSON.parse(await readStdin());
  let out: Json;
  switch (cmd.action) {
    case 'corpus':
      out = await corpus(cmd.digest, cmd.nonce, cmd.genTime);
      break;
    case 'conformance':
      out = {
        results: (cmd.cases as Array<{ token: string; digest: string }>).map(
          (c) => timestampConformance(c.token, c.digest) as unknown as Json,
        ),
      };
      break;
    case 'flips':
      out = flips(cmd.token, cmd.digest, cmd.mask);
      break;
    case 'capture':
      out = await capture(cmd.url, cmd.cases);
      break;
    case 'authority':
      out = { results: (cmd.subjects as string[]).map((hex) => authorityOf({ subject: Buffer.from(hex, 'hex') })) };
      break;
    case 'steps-authority':
      out = {
        results: (cmd.cases as Array<{ token: string; digest: string }>).map((c) => {
          const v = verifyRfc3161Steps(c.token, c.digest, []);
          return { token: v.token, authority: v.authority ?? null };
        }),
      };
      break;
    case 'trust-anchors':
      out = {
        results: (cmd.cases as unknown[][]).map((pems) => {
          try {
            return { count: trustAnchorsFromPem(pems).length };
          } catch (err) {
            if (err instanceof UnreadableTrustAnchorError) return { error: err.message };
            throw err;
          }
        }),
      };
      break;
    default:
      throw new Error(`unknown action ${cmd.action}`);
  }
  process.stdout.write(JSON.stringify(out));
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(1);
});
