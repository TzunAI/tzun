/**
 * Cross-SDK test harness — Node side.
 *
 * Reads one JSON command from stdin, executes against the in-repo TS SDK,
 * writes a JSON result on stdout. Used by tests/cross-sdk/*.py to shuttle
 * envelopes between languages and verify byte-identical wire format.
 *
 * Command shapes:
 *   { action: "canonical", input: <any>, hashedFields: string[]? }
 *     → { canonical: "...", digest: "<bare-hex>" }
 *
 *   { action: "canonical-descriptor", input: <ModelDescriptor> }
 *     → { canonical: "...", digest: "sha256:..." }
 *
 *   { action: "capture", aiOutput: {...}, decision: { action: "...", reason: "...", decider?: {...} } }
 *     → { envelope: <EvidenceEnvelope JSON> }
 *     A genesis v1.0 record: the decision's `action` and
 *     `reason`, its `decider` (a human under acct:u-cross-sdk unless given),
 *     no contributions, links or expectation. `decision` is a member of its
 *     own because the command's `action` names the command.
 *
 *   { action: "verify", envelope: <EvidenceEnvelope JSON> }
 *     → { valid: boolean, canonicalDigest: "<bare-hex>" }
 *
 *   { action: "verify", envelopes: <EvidenceEnvelope JSON[]> }
 *     → { valid: boolean, canonicalDigest: "<bare-hex>", reason?: string }
 *     Re-checks each envelope's canonicalDigest, then verifies chainLink for
 *     every pair of consecutive envelopes (Verification §4.3).
 *
 *   { action: "chain-link", previousDigest: string|null, currentDigest: string }
 *     → { chainLink: string|null }
 *
 *   { action: "build-capture-request", envelope: <EvidenceEnvelope JSON>,
 *     completeness?: "raw"|"partial"|"sealed", chainId?: string }
 *     → { requestBody: { completeness, chainId?, envelope } }
 *     Mirrors the body HttpTransport.capture() POSTs to /v1/evidence.
 *
 *   { action: "webauthn-challenge", digests: string[] }
 *     → { challenges: string[] }
 *     `webauthnChallengeForDigest` for each digest; the Python
 *     twin is `tzun_sdk.attestation.webauthn_challenge_for_digest`.
 *
 *   { action: "assertion-provenance", cases: [{ assertion, options?, digest? }] }
 *     → { results: [{ provenance, binds }] }
 *     `assertionProvenance(assertion, options)` and, when `digest` is given,
 *     `assertionBindsDigest(assertion, digest)` (else `binds: null`) for each
 *     case; the Python twins are
 *     `tzun_sdk.attestation.assertion_provenance` and `assertion_binds_digest`.
 *
 *   { action: "custody-entry-hash", preimage: <CustodyEntryPreimage> }
 *     → { entryHash: "<bare-hex>", preimage: "<the length-prefixed concatenation>" }
 *     The engine's ONE custody-hash rule;
 *     test_custody_hash_parity.py holds it and the Python port to the
 *     platform-computed vectors.
 *
 *   { action: "parse-model-ids", items: [{ vendor, modelId, apiMetadata? }] }
 *     → { results: [{ vendor, modelId, modelName, modelVersion }] }
 *     Runs each item through the real `parseModelId` (src/models/import-vendor.ts)
 *     in one process; test_model_id_parity.py compares against the Python port.
 *
 *   { action: "anchor-envelope", envelope: <EvidenceEnvelope JSON>, chainId: string }
 *     → { envelope: <the same envelope carrying nonRepudiation.anchor> }
 *     Builds a tzun-anchor/1 artifact over the record: an evidence log of
 *     `chainId` whose leaf `sequenceNumber − 1` is the record's digest, an
 *     anchor log holding that log's checkpoint digest, both paths, and one
 *     publication entry of each kind (Anchor §8).
 *
 *   { action: "verify-anchor", envelope: <EvidenceEnvelope JSON>, chainId: string }
 *     → { anchorPresent, anchorValid, anchorReason, merkleProofValid, anchorPosition, checks, publications }
 *     `verifyAnchor` (tzun-anchor/1 §10.3) on the envelope's `nonRepudiation`,
 *     with its sequence number and `chainId`.
 *
 *   { action: "scheduler-fill", chainId: string, count: number }
 *     → { envelopes: <EvidenceEnvelope JSON[]>, causes: string[][] }
 *     Stores `count` records on `chainId` in a SQLite store minted in a
 *     `test.` namespace (the first `pending`, the rest `none`), runs the anchor
 *     scheduler against the in-memory chain until its publication is final
 *     and filled, and returns the records as the store holds them and each
 *     one's revision causes (Anchor §8.4, §11).
 *
 * This harness MUST use the in-repo build, never the published
 * @tzun/sdk version.
 */

import {
  assertionBindsDigest,
  assertionProvenance,
  canonicalSerialize,
  canonicalSerializeDescriptor,
  computeCustodyEntryHash,
  custodyEntryPreimage,
  EvidenceChain,
  SchemaRegistry,
  verifyCustodyTrail,
} from '@tzun/engine';
import type {
  AssertionProvenanceOptions,
  AttestationArtifacts,
  CustodyEntryPreimage,
  EvidenceEnvelope,
  ModelDescriptor,
} from '@tzun/engine';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Wallet } from 'ethers';
import { createAnchorScheduler, createEvmPublisher } from '../../../src/anchoring';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';
import { FakeEvmChain } from '../../ts/helpers/anchoring-fake-chain';
import { HttpTransport } from '../../../src/sdk/http-transport';
import { getConnector } from '../../../src/sdk/connectors/index';
import { loadKnownModels } from '../../../src/models/known-models';
import { parseModelId, type SupportedVendor } from '../../../src/models/import-vendor';
import { webauthnChallengeForDigest } from '../../../src/attestation/verify-attestation';
import { verifyAnchor } from '../../../src/attestation/anchor-verify';
import { anchorLogOrigin, checkpointDigest, evidenceLogOrigin, formatCheckpoint } from '../../../src/attestation/checkpoint';
import { buildMerkleTree, getMerkleProof, getMerkleRoot } from '../../../src/attestation/merkle';

/** The v1.0 hashed field set, from the engine's registry rather than a copy. */
const V1_0_HASHED_FIELDS = new SchemaRegistry().get('v1.0')!.hashedFieldSet;
/** The decider of a record the harness builds when the command names none: a human, under an opaque account id. */
const CROSS_SDK_DECIDER = { kind: 'human', id: 'acct:u-cross-sdk', agent: null, credential: null, freshness: null };

interface Command {
  action:
    | 'canonical'
    | 'canonical-descriptor'
    | 'capture'
    | 'verify'
    | 'chain-link'
    | 'build-capture-request'
    | 'connector'
    | 'parse-model-ids'
    | 'custody-entry-hash'
    | 'webauthn-challenge'
    | 'assertion-provenance'
    | 'anchor-envelope'
    | 'verify-anchor'
    | 'scheduler-fill';
  input?: Record<string, unknown>;
  // custody-entry-hash action field
  preimage?: CustodyEntryPreimage;
  hashedFields?: string[];
  envelope?: Record<string, unknown>;
  envelopes?: Record<string, unknown>[];
  aiOutput?: Record<string, unknown>;
  // capture action field: the decision's action, reason and decider
  decision?: { action?: string; reason?: string; decider?: Record<string, unknown> };
  previousDigest?: string | null;
  currentDigest?: string;
  completeness?: 'raw' | 'partial' | 'sealed';
  chainId?: string;
  // scheduler-fill action field
  count?: number;
  // connector action fields
  vendor?: string;
  request?: Record<string, unknown>;
  response?: Record<string, unknown>;
  knownModels?: Record<string, unknown>; // optional known-models override for tests
  // webauthn-challenge action field
  digests?: string[];
  // assertion-provenance action field
  cases?: Array<{
    assertion: NonNullable<AttestationArtifacts['webauthnAssertion']>;
    options?: AssertionProvenanceOptions;
    digest?: string;
  }>;
  // parse-model-ids action fields
  items?: Array<{
    vendor: string;
    modelId: string;
    apiMetadata?: { modelName?: string; modelVersion?: string };
  }>;
}

function linkFrom(previousDigest: string, digest: string): string | null {
  const chain = new EvidenceChain();
  chain.restore(previousDigest);
  return chain.computeLink(digest);
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
  });
}

async function main(): Promise<void> {
  const raw = await readStdin();
  const cmd = JSON.parse(raw) as Command;
  if (cmd.action === 'canonical') {
    if (!cmd.input) throw new Error('canonical: input required');
    const fields = cmd.hashedFields ?? Object.keys(cmd.input).sort();
    const bytes = canonicalSerialize(cmd.input, fields);
    const digest = createHash('sha256').update(bytes).digest('hex');
    process.stdout.write(JSON.stringify({ canonical: bytes, digest }));
    return;
  }
  if (cmd.action === 'canonical-descriptor') {
    if (!cmd.input) throw new Error('canonical-descriptor: input required');
    const bytes = canonicalSerializeDescriptor(cmd.input as ModelDescriptor);
    const digest = 'sha256:' + createHash('sha256').update(bytes).digest('hex');
    process.stdout.write(JSON.stringify({ canonical: bytes, digest }));
    return;
  }
  if (cmd.action === 'capture') {
    // Build a minimal v1.0 envelope structurally compatible with the Python
    // SDK output. Used for TS→Py roundtrip.
    const payload = {
      evidenceId: 'cross-sdk-' + Math.random().toString(16).slice(2, 10),
      schemaVersion: 'v1.0',
      aiSystemId: 'cross-sdk-ts',
      aiOutput: cmd.aiOutput ?? {},
      action: cmd.decision?.action ?? '',
      reason: cmd.decision?.reason ?? '',
      capturedAt: new Date().toISOString().replace(/\.\d{3}/, '.000'),
      sequenceNumber: 1,
      decider: cmd.decision?.decider ?? CROSS_SDK_DECIDER,
      contributions: null,
      links: null,
      signoffExpectation: null,
    };
    const hashed = V1_0_HASHED_FIELDS;
    const canonical = canonicalSerialize(payload, hashed);
    const digest = createHash('sha256').update(canonical).digest('hex');
    const envelope = {
      envelopeVersion: 'e1',
      payload,
      integrity: { canonicalDigest: digest, chainLink: null },
      nonRepudiation: {},
      custodyChain: [],
      attestationStatus: 'none',
    };
    process.stdout.write(JSON.stringify({ envelope }));
    return;
  }
  if (cmd.action === 'verify') {
    if (!cmd.envelope && !cmd.envelopes) throw new Error('verify: envelope or envelopes required');
    const hashed = V1_0_HASHED_FIELDS;

    // ── Single-envelope (backward-compat) path ────────────────────────────────
    // Digest-only verification, exactly as before the chainLink widening.
    // Chain-structure checks (genesis-null + link chain) do NOT apply here.
    if (cmd.envelope && !cmd.envelopes) {
      const payload = (cmd.envelope.payload as Record<string, unknown>) ?? {};
      const integrity = (cmd.envelope.integrity as Record<string, unknown>) ?? {};
      const canonical = canonicalSerialize(payload, hashed);
      const actual = createHash('sha256').update(canonical).digest('hex');
      const expected = integrity.canonicalDigest as string;
      if (actual !== expected) {
        process.stdout.write(JSON.stringify({ valid: false, canonicalDigest: actual, reason: 'canonicalDigest mismatch at index 0' }));
        return;
      }
      // the offline custody-trail verdict rides alongside the
      // digest answer (it never changes `valid`, exactly as in verifyEnvelope).
      const custody = verifyCustodyTrail(cmd.envelope as unknown as EvidenceEnvelope);
      process.stdout.write(JSON.stringify({
        valid: true,
        canonicalDigest: actual,
        custodyTrailValid: custody.valid,
        custodyTrailFailures: custody.failures,
      }));
      return;
    }

    // ── Multi-envelope path ───────────────────────────────────────────────────
    // An explicit guard against an empty array.
    const envelopes = cmd.envelopes as Record<string, unknown>[];
    if (envelopes.length === 0) {
      process.stdout.write(JSON.stringify({ valid: false, reason: 'envelopes array is empty' }));
      return;
    }

    // Step 1: re-check every envelope's canonicalDigest.
    const computedDigests: string[] = [];
    for (let i = 0; i < envelopes.length; i++) {
      const payload = (envelopes[i].payload as Record<string, unknown>) ?? {};
      const integrity = (envelopes[i].integrity as Record<string, unknown>) ?? {};
      const canonical = canonicalSerialize(payload, hashed);
      const actual = createHash('sha256').update(canonical).digest('hex');
      const expected = integrity.canonicalDigest as string;
      if (actual !== expected) {
        process.stdout.write(
          JSON.stringify({ valid: false, canonicalDigest: actual, reason: `canonicalDigest mismatch at index ${i}` }),
        );
        return;
      }
      computedDigests.push(actual);
    }

    // Step 2: re-check chainLink for every consecutive pair (Verification §4.3).
    // Genesis record's chainLink must be null.
    // For i >= 1: use EvidenceChain.computeLink() — definitionally identical to
    // the engine (chain-completeness.ts:97-105).
    const firstIntegrity = (envelopes[0].integrity as Record<string, unknown>) ?? {};
    if (firstIntegrity.chainLink !== null && firstIntegrity.chainLink !== undefined) {
      process.stdout.write(
        JSON.stringify({ valid: false, canonicalDigest: computedDigests[0], reason: 'chainLink mismatch at index 0: expected null for genesis record' }),
      );
      return;
    }
    for (let i = 1; i < envelopes.length; i++) {
      const prev = computedDigests[i - 1];
      const cur = computedDigests[i];
      // Delegate to the engine primitive instead of an inline SHA-256.
      const ch = new EvidenceChain();
      ch.restore(prev);
      const expectedLink = ch.computeLink(cur);
      const integrity = (envelopes[i].integrity as Record<string, unknown>) ?? {};
      if (integrity.chainLink !== expectedLink) {
        // The reason says how the expected link is computed.
        process.stdout.write(
          JSON.stringify({ valid: false, canonicalDigest: computedDigests[i], reason: `chainLink mismatch at index ${i}: expected SHA-256(prevDigest+curDigest)` }),
        );
        return;
      }
    }

    // All checks passed.
    process.stdout.write(
      JSON.stringify({ valid: true, canonicalDigest: computedDigests[computedDigests.length - 1] }),
    );
    return;
  }
  if (cmd.action === 'webauthn-challenge') {
    // the challenge that binds a WebAuthn assertion to one
    // evidence record. Python has the verifier half only (it is a
    // relying-party server), so the two derivations must agree
    // byte-for-byte or a TS-signed assertion fails Python verification for
    // reasons that look like tampering.
    if (!cmd.digests) throw new Error('webauthn-challenge: digests required');
    process.stdout.write(
      JSON.stringify({ challenges: cmd.digests.map((d) => webauthnChallengeForDigest(d)) }),
    );
    return;
  }
  if (cmd.action === 'assertion-provenance') {
    // what an assertion states about where the ceremony ran and
    // what kind of key signed, and the checks on it. Both SDKs read the same
    // bytes out of the same artifact, or they answer differently about one
    // record.
    if (!cmd.cases) throw new Error('assertion-provenance: cases required');
    process.stdout.write(
      JSON.stringify({
        results: cmd.cases.map((c) => ({
          provenance: assertionProvenance(c.assertion, c.options ?? {}),
          binds: c.digest === undefined ? null : assertionBindsDigest(c.assertion, c.digest),
        })),
      }),
    );
    return;
  }
  if (cmd.action === 'custody-entry-hash') {
    if (!cmd.preimage) throw new Error('custody-entry-hash: preimage required');
    process.stdout.write(JSON.stringify({
      entryHash: computeCustodyEntryHash(cmd.preimage),
      preimage: custodyEntryPreimage(cmd.preimage),
    }));
    return;
  }
  if (cmd.action === 'chain-link') {
    if (cmd.currentDigest == null) throw new Error('chain-link: currentDigest required');
    const chain = new EvidenceChain();
    if (cmd.previousDigest != null) chain.restore(cmd.previousDigest);
    const chainLink = chain.computeLink(cmd.currentDigest);
    process.stdout.write(JSON.stringify({ chainLink }));
    return;
  }
  if (cmd.action === 'build-capture-request') {
    // Routes through the REAL HttpTransport.capture() with an injected fetchFn
    // that captures the outgoing request body instead of making a network call.
    // This ensures future changes to HttpTransport.capture() (field renames,
    // body restructuring) will break this test rather than silently diverging.
    if (!cmd.envelope) throw new Error('build-capture-request: envelope required');
    let capturedBody: unknown;
    const transport = new HttpTransport({
      apiKey: 'test',
      apiUrl: 'https://api.tzun.ai',
      fetchFn: async (_url: string, init?: RequestInit) => {
        capturedBody = JSON.parse(init?.body as string);
        return new Response(
          JSON.stringify({
            evidenceId: 'x',
            chainId: cmd.chainId ?? 'default',
            sequence: 0,
            canonicalDigest: '',
            headDigest: '',
          }),
          { status: 202, headers: { 'Content-Type': 'application/json' } },
        );
      },
    });
    await transport.capture({
      completeness: cmd.completeness ?? 'partial',
      envelope: cmd.envelope as EvidenceEnvelope,
      chainId: cmd.chainId,
    });
    process.stdout.write(JSON.stringify({ requestBody: capturedBody }));
    return;
  }
  if (cmd.action === 'parse-model-ids') {
    if (!Array.isArray(cmd.items)) throw new Error('parse-model-ids: items required');
    const results = cmd.items.map((item) => {
      const parsed = parseModelId(item.vendor as SupportedVendor, item.modelId, item.apiMetadata);
      return {
        vendor: item.vendor,
        modelId: item.modelId,
        modelName: parsed.modelName,
        modelVersion: parsed.modelVersion,
      };
    });
    process.stdout.write(JSON.stringify({ results }));
    return;
  }
  if (cmd.action === 'connector') {
    // Run a request/response pair through the named TS connector and return the
    // AiBomSkeleton as JSON. Used by test_connector_parity.py.
    if (!cmd.vendor) throw new Error('connector: vendor required');
    if (!cmd.request) throw new Error('connector: request required');
    if (!cmd.response) throw new Error('connector: response required');
    const connector = getConnector(cmd.vendor);
    if (!connector) {
      process.stdout.write(JSON.stringify({ skeleton: null, error: `unknown vendor: ${cmd.vendor}` }));
      return;
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const knownModels = cmd.knownModels ? (cmd.knownModels as any) : await loadKnownModels();
    const skeleton = connector.buildAiBom(
      cmd.request as Record<string, unknown>,
      cmd.response as Record<string, unknown>,
      knownModels,
    );
    if (!skeleton) {
      process.stdout.write(JSON.stringify({ skeleton: null }));
      return;
    }
    // Serialize the skeleton fields to JSON-safe form
    process.stdout.write(JSON.stringify({
      skeleton: {
        modelDescriptor: skeleton.modelDescriptor,
        vendorFingerprint: skeleton.vendorFingerprint ?? null,
        promptTemplate: skeleton.promptTemplate ?? null,
        inferenceParameters: skeleton.inferenceParameters ?? null,
        infrastructure: skeleton.infrastructure ?? null,
      },
    }));
    return;
  }
  if (cmd.action === 'anchor-envelope') {
    if (!cmd.envelope || !cmd.chainId) throw new Error('anchor-envelope: envelope and chainId required');
    const envelope = cmd.envelope as unknown as EvidenceEnvelope;
    const leafIndex = envelope.payload.sequenceNumber - 1;
    const sha = (text: string) => createHash('sha256').update(text).digest('hex');
    const prefix = `local.invalid/${sha('cross-sdk-store').slice(0, 32)}`;
    const leaves = Array.from({ length: leafIndex + 2 }, (_, i) => (i === leafIndex ? envelope.integrity.canonicalDigest : sha(`leaf ${i}`)));
    const logTree = buildMerkleTree(leaves);
    const logCheckpoint = formatCheckpoint(evidenceLogOrigin(prefix, cmd.chainId), leaves.length, getMerkleRoot(logTree));
    const anchorLeaves = [sha('an earlier checkpoint'), checkpointDigest(logCheckpoint), sha('another log')];
    const anchorTree = buildMerkleTree(anchorLeaves);
    const anchorCheckpoint = formatCheckpoint(anchorLogOrigin(prefix), anchorLeaves.length, getMerkleRoot(anchorTree));
    const anchored = {
      ...envelope,
      nonRepudiation: {
        ...envelope.nonRepudiation,
        anchor: {
          anchorSpec: 'tzun-anchor/1',
          merkleSpec: 'rfc6962',
          leafIndex,
          logCheckpoint,
          logPath: getMerkleProof(logTree, leafIndex),
          anchorLeafIndex: 1,
          anchorCheckpoint,
          anchorPath: getMerkleProof(anchorTree, 1),
          publications: [
            {
              kind: 'evm-calldata/1',
              chain: 'eip155:11155111',
              transactionId: '0x' + sha('tx'),
              blockNumber: 11781565,
              blockHash: '0x' + sha('block'),
              publisher: '0x' + sha('publisher').slice(0, 40),
            },
            { kind: 'rfc3161/1', token: Buffer.from('not a real token').toString('base64') },
          ],
        },
      },
    };
    process.stdout.write(JSON.stringify({ envelope: anchored }));
    return;
  }
  if (cmd.action === 'verify-anchor') {
    if (!cmd.envelope || !cmd.chainId) throw new Error('verify-anchor: envelope and chainId required');
    const envelope = cmd.envelope as unknown as EvidenceEnvelope;
    const v = await verifyAnchor(envelope.nonRepudiation, envelope.integrity.canonicalDigest, {
      sequenceNumber: envelope.payload.sequenceNumber,
      chainId: cmd.chainId,
    });
    process.stdout.write(
      JSON.stringify({
        anchorPresent: v.anchorPresent,
        anchorValid: v.anchorValid,
        anchorReason: v.anchorReason ?? null,
        merkleProofValid: v.merkleProofValid,
        anchorPosition: v.anchorPosition,
        checks: v.checks,
        publications: v.publications.map((p) => ({ index: p.index, kind: p.kind, valid: p.valid, reason: p.reason ?? null })),
      }),
    );
    return;
  }
  if (cmd.action === 'scheduler-fill') {
    if (!cmd.chainId || !cmd.count) throw new Error('scheduler-fill: chainId and count required');
    // stdout carries the answer: anything the SDK logs goes to stderr.
    console.log = (...args: unknown[]) => process.stderr.write(`${args.map(String).join(' ')}\n`);
    const dir = mkdtempSync(join(tmpdir(), 'tzun-test-xsdk-fill-'));
    const adapter = new SqliteStorageAdapter(join(dir, 'store.db'), { logNamespace: 'test.cross-sdk' });
    try {
      const hashed = V1_0_HASHED_FIELDS;
      let previous: string | null = null;
      const ids: string[] = [];
      for (let i = 1; i <= cmd.count; i++) {
        const payload = {
          evidenceId: `cross-sdk-fill-${i}`,
          schemaVersion: 'v1.0',
          aiSystemId: 'cross-sdk-ts',
          aiOutput: { i },
          action: 'approved',
          reason: 'reviewed',
          capturedAt: '2026-09-25T12:00:00.000Z',
          sequenceNumber: i,
          decider: CROSS_SDK_DECIDER,
          contributions: null,
          links: null,
          signoffExpectation: null,
        };
        const digest = createHash('sha256').update(canonicalSerialize(payload, hashed)).digest('hex');
        const envelope = {
          envelopeVersion: 'e1',
          payload,
          integrity: { canonicalDigest: digest, chainLink: previous === null ? null : linkFrom(previous, digest) },
          nonRepudiation: {},
          custodyChain: [],
          attestationStatus: i === 1 ? 'pending' : 'none',
        } as unknown as EvidenceEnvelope;
        previous = digest;
        await adapter.store(envelope, cmd.chainId);
        ids.push(payload.evidenceId);
      }
      const node = new FakeEvmChain();
      const key = Wallet.createRandom();
      node.fund(key.address, 10n ** 18n);
      let now = Date.now();
      const scheduler = await createAnchorScheduler({
        storage: adapter,
        expectation: {},
        config: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', privateKey: key.privateKey, chain: 'eip155:31337' } } },
        publisher: createEvmPublisher({ privateKey: key.privateKey, chain: 'eip155:31337', client: node }),
        clock: () => now,
      });
      await scheduler.anchorNow({ force: true });
      for (let i = 0; i < 4 && (await scheduler.getAnchorState()).lastFinalized === null; i++) {
        node.mine(node.finalizedDepth + 1);
        now += 60_000;
        await scheduler.runPass();
      }
      await scheduler.stop();
      const envelopes = [];
      const causes = [];
      for (const id of ids) {
        envelopes.push(await adapter.retrieve(id));
        causes.push((await adapter.listEnvelopeRevisions(id)).map((r) => r.cause));
      }
      process.stdout.write(JSON.stringify({ envelopes, causes }));
    } finally {
      await adapter.close();
      rmSync(dir, { recursive: true, force: true });
    }
    return;
  }
  throw new Error(`Unknown action: ${cmd.action}`);
}

main().catch((err) => {
  process.stderr.write(String(err));
  process.exit(1);
});
