/**
 * Generate vectors/bundle-b1/, the b1 conformance corpus (Bundle §13): `b1`
 * proof bundles exported from a store anchored end to end on anvil, each with
 * the auditor's inputs and the report and exit code a verifier must produce
 * for them.
 *
 *   pnpm exec tsx scripts/generate-bundle-b1-corpus.ts
 *
 * It needs Docker: one anvil container (tests/anvil/harness.ts), removed when
 * it is done. The store runs `Tzun.init({ mode: 'local', logNamespace,
 * anchoring, attestation })` with its anchor scheduler publishing from anvil's
 * development account 5, and a local RFC 3161 authority (a throwaway CA, the
 * one tests/ts/rfc3161-fixture.ts builds) timestamping every record. Its
 * tokens meet every rule of tzun-anchor/1 §10.5, as a real public
 * authority's do: a DER TimeStampResp and TSTInfo, a signingCertificateV2
 * over the signer certificate, and a signer whose only extendedKeyUsage,
 * marked critical, is id-kp-timeStamping. The `record-token-*` cases carry a
 * token that breaks or tests one of those rules: a key on a curve no
 * verifier implements (the OID 1.2.840.10045.3.1.99, assigned to no curve)
 * where a step needs it and where none does, and the signer subjects that
 * shape the `authority` fact among them. The `anchor-token-*` cases add to the
 * record's anchor an `rfc3161/1` publication of its P from a second throwaway
 * authority under a root of its own (tzun-anchor/1 §10.5). The namespace is a `test.`
 * namespace: nothing here is a real key or freezes anything (tzun-anchor/1 §2).
 *
 * anvil's clock is set an hour behind the wall clock before anything is
 * captured, so every block time precedes every timestamp's genTime. Which
 * proof `summary.existedBy` names (Verification §6.4: the record's
 * timestamp, its anchor, or the newer anchor) is then fixed by what each case
 * proves, not by when the run's blocks happened to land; and the script
 * stops, writing nothing, unless each of the three is named by some case.
 *
 * Each case is a directory holding:
 *
 *   bundle.json           the bundle, as `Tzun.exportBundle()` wrote it, or
 *                         with the one change the case names;
 *   inputs.json           the auditor's inputs: the publisher manifest, a
 *                         static header source (its chain id, finality, finalized
 *                         height and the canonical blocks it knows), the RFC 3161
 *                         roots, and the regime (`require`, `requireRung`,
 *                         `allowUnchecked`);
 *   expected-report.json  the report (Verification §6) without `checkedAt`;
 *   expected-exit         the exit code under the regime, and a newline.
 *
 * Records are of the v1.0 format as revised in 0.8.0 (Record §4.1): every
 * report carries the record-rule rows (`decider`, `decider.freshness`,
 * `contributions`, `contributions.binding`, `links`, and a `links[<i>]` and
 * `links[<i>].edge` row per link) between `signoff.key` and the anchor, and
 * the `contributions-*`, `links-*` and `decider-*` cases pin them.
 *
 * THE EXPECTED REPORTS ARE STATED, NOT RECORDED. Every check row below is
 * written from Verification, Bundle and tzun-anchor/1 §10 for the case's inputs;
 * the values in them (digests, origins, transaction ids, block times, the
 * timestamp's genTime) are the run's own, read from the store, the chain and
 * the token. Only then does the script run `verifyBundle()` over every case,
 * and it stops, writing nothing, if the SDK disagrees with any row. The run's
 * values change with every run; the rows do not.
 */
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, X509Certificate } from 'node:crypto';
import { decodeRlp, encodeRlp, keccak256, toBeHex } from 'ethers';
import {
  assembleEnvelope,
  canonicalSerialize,
  computeDigest,
  determineAttestationStatus,
  EvidenceChain,
  SchemaRegistry,
  outputDigest,
  signoffStatementChallenge,
  signoffStatementDigest,
} from '@tzun/engine';
import type { AgentDescriptor, CaptureInput, TzunConfig } from '@tzun/engine';
import { Tzun, verifyBundle, bundleExitCode, type BundleExitOptions, type EvmHeaderSource, type ProofBundle } from '../src/sdk';
import { formatCheckpoint, parseCheckpoint } from '../src/attestation/checkpoint';
import { buildMerkleTree, getConsistencyProof, getMerkleProof, getMerkleRoot } from '../src/attestation/merkle';
import { extractTSTInfo, parseTimestampResponse } from '../src/attestation/rfc3161-verify';
import { requestTimestamp } from '../src/attestation/rfc3161';
import { buildTxTrie } from '../src/anchoring/tx-trie';
import { JsonRpcEvmChain } from '../src/anchoring/evm-chain';
import { ANCHOR_LOG_KIND, anchorStoreFor, logStoreFor } from '../src/storage/log-store';
import { bundleAnchoring } from '../src/export/bundle';
import { ANVIL_CHAIN_ID, ANVIL_IMAGE, startAnvil, type AnvilNode } from '../tests/anvil/harness';
import { makeSigningTsa, type SigningTsa } from '../tests/ts/rfc3161-fixture';
import { makeGenuineAssertion } from '../tests/ts/attestation-assertion-helpers';
import { parseTimestampQuery } from '../tests/ts/helpers/mock-tsa';

const OUT = join(__dirname, '..', 'vectors', 'bundle-b1');
const CHAIN = `eip155:${ANVIL_CHAIN_ID}`;
const NS = 'test.bundle-b1.tzun';
const PUBLISHER_ACCOUNT = 5;
const TRAFFIC_ACCOUNT = 6;

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
const json = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
/** The first hex digit of a hash, flipped. */
const flip = (h: string) => `${h[0] === '0' ? '1' : '0'}${h.slice(1)}`;

/** A subject Name: RDNs in order, each a list of [type OID, string tag, value], the attributes of each RDN in DER order. */
type Rdn = Array<[string, number, string]>;
function nameDer(rdns: Rdn[]): Buffer {
  const tlv = (tag: number, body: Buffer): Buffer => {
    const len = body.length < 0x80 ? Buffer.from([body.length]) : Buffer.from([0x81, body.length]);
    return Buffer.concat([Buffer.from([tag]), len, body]);
  };
  const oidDer = (dotted: string): Buffer => {
    const p = dotted.split('.').map(Number);
    const out = [p[0] * 40 + p[1]];
    for (const n of p.slice(2)) {
      const chunk = [n & 0x7f];
      for (let v = Math.floor(n / 128); v > 0; v = Math.floor(v / 128)) chunk.unshift(0x80 | (v & 0x7f));
      out.push(...chunk);
    }
    return tlv(0x06, Buffer.from(out));
  };
  // A BMPString is UTF-16BE, a TeletexString is read as ISO 8859-1, and the others are UTF-8 here.
  const value = (tag: number, text: string): Buffer =>
    tag === 30 ? Buffer.from(text, 'utf16le').swap16() : tag === 20 ? Buffer.from(text, 'latin1') : Buffer.from(text, 'utf8');
  const atv = ([oid, tag, text]: Rdn[number]) => tlv(0x30, Buffer.concat([oidDer(oid), tlv(tag, value(tag, text))]));
  return tlv(0x30, Buffer.concat(rdns.map((rdn) => tlv(0x31, Buffer.concat(rdn.map(atv).sort(Buffer.compare))))));
}

/**
 * The decider of every corpus record but those a case names another for: a
 * human under an opaque account id, no freshness reference (the store
 * anchors, and would otherwise fill one from its header follower, which a
 * verifier with no header source cannot check).
 */
const CORPUS_DECIDER = { kind: 'human' as const, id: 'acct:u-bundle-corpus', agent: null, credential: null, freshness: null };
/** The model the corpus's model-bearing records name, inline: capture registers its descriptor and writes its digest. */
const CORPUS_MODEL_BOM = {
  modelDescriptor: {
    descriptorVersion: 'd1', vendor: 'tzun-corpus', modelName: 'corpus-model', modelVersion: '1', modelType: null, integrityTier: 'vendor-asserted',
    modelDigest: null, parentModelDescriptorDigest: null, derivation: null, trainedBy: null, license: null, modelCardUrl: null,
    training: { trainingDataDigest: null, trainingDataRef: null, lastTrainingDate: null, evaluations: [] },
    regulatoryMarkings: [], externalIdentifiers: [],
  },
  vendorFingerprint: null,
  promptTemplate: null,
  inferenceParameters: null,
  infrastructure: null,
};
/** The agent the corpus's agent decision names: a descriptor with no model, key or identity, registered before capture. */
const CORPUS_AGENT_DESCRIPTOR = {
  v: 'tzun-agent/1', name: 'bundle-corpus-agent', operator: { organization: 'Tzun Corpus', owner: null }, identities: [], keys: [], models: [],
  instructions: null, tools: null, runtime: null, policy: null, parent: null, derivation: null,
};
const decision = (chainId: string, i: number): CaptureInput => ({
  aiOutput: { recommendation: 'approve', chain: chainId, i },
  action: 'approved',
  reason: `bundle corpus: ${chainId} #${i}`,
  decider: CORPUS_DECIDER,
  aiSystemId: 'bundle-b1-corpus',
});

// ---- The run ---------------------------------------------------------------------

/** A local RFC 3161 authority over HTTP, issuing genuine tokens from a throwaway CA. */
async function startTsa(): Promise<{ url: string; caPem: string; signerCN: string; issue: SigningTsa['issue']; close(): void }> {
  const tsa = await makeSigningTsa({ signerCN: 'Tzun Corpus Timestamping Authority', caCN: 'Tzun Corpus Test Root CA' });
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const { digest, nonce } = parseTimestampQuery(Buffer.concat(chunks));
      tsa.issue(digest, nonce).then(
        (der) => {
          res.writeHead(200, { 'content-type': 'application/timestamp-reply' });
          res.end(der);
        },
        () => {
          res.writeHead(500);
          res.end();
        },
      );
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}/tsr`, caPem: tsa.caPem, signerCN: tsa.signerCN, issue: tsa.issue, close: () => server.close() };
}

/** Mine and pass until every publication is final and filled. */
async function settle(node: AnvilNode, tzun: Tzun): Promise<void> {
  for (let i = 0; i < 20; i++) {
    await node.mine(3);
    await tzun.anchorNow();
    const state = (await tzun.getAnchorState())!;
    if (state.halted) throw new Error(`anchoring stopped: ${state.halted.code}`);
    if (state.lastFinalized && state.inFlight.length === 0 && state.fillBacklog === 0) return;
  }
  throw new Error('the publications did not settle');
}

/** A forced epoch published in a block it shares with other transactions, so its trie proof has branch nodes. */
async function epochAmongTraffic(node: AnvilNode, tzun: Tzun, before: number, after: number): Promise<void> {
  const traffic = node.devAccount(TRAFFIC_ACCOUNT).connect(node.provider);
  let nonce = Number(BigInt(await node.rpc<string>('eth_getTransactionCount', [traffic.address, 'pending'])));
  const send = async (n: number): Promise<void> => {
    for (let i = 0; i < n; i++) await traffic.sendTransaction({ to: traffic.address, value: 0n, nonce: nonce++ });
  };
  await node.setAutomine(false);
  try {
    await send(before);
    if (!(await tzun.anchorNow({ force: true })).epoch) throw new Error('no epoch was cut');
    await send(after);
    await node.mine(1);
  } finally {
    await node.setAutomine(true);
  }
}

interface Block {
  number: number;
  hash: string;
  timestamp: number;
}

/** The inputs file: what the auditor holds, as data a replay can rebuild. */
interface Inputs {
  publisherManifest: unknown | null;
  headerSources: Record<string, { chainId: number; finality: 'finalized'; finalizedBlockNumber: number; blocks: Block[] }>;
  trustAnchorsPem: string[];
  regime: { require: string[]; requireRung: string[]; allowUnchecked: boolean | string[] };
}

/** The static header source an inputs file describes. */
function headerSourceOf(spec: Inputs['headerSources'][string]): EvmHeaderSource {
  return {
    finality: spec.finality,
    chainId: async () => BigInt(spec.chainId),
    finalizedBlockNumber: async () => spec.finalizedBlockNumber,
    canonicalBlock: async (n) => {
      const b = spec.blocks.find((x) => x.number === n);
      return b ? { hash: b.hash, timestamp: b.timestamp } : null;
    },
  };
}

// ---- Stating the expected rows ----------------------------------------------------

type Row = { id: string; outcome: 'checked-correct' | 'checked-wrong' | 'not-checked' | 'abstain'; reason?: string; facts?: Record<string, unknown> };
const ok = (id: string, facts?: Record<string, unknown>): Row => ({ id, outcome: 'checked-correct', ...(facts && { facts }) });
const nc = (id: string, reason: string, facts?: Record<string, unknown>): Row => ({ id, outcome: 'not-checked', reason, ...(facts && { facts }) });
const wrong = (id: string, reason: string, facts?: Record<string, unknown>): Row => ({ id, outcome: 'checked-wrong', reason, ...(facts && { facts }) });
const abstain = (id: string, reason: string): Row => ({ id, outcome: 'abstain', reason });

const STEPS = ['anchor.spec', 'anchor.checkpoint', 'anchor.origin', 'anchor.leafIndex', 'anchor.inclusion', 'anchor.anchorInclusion'];

/** What a run knows about one epoch's publication. */
interface Epoch {
  transactionId: string;
  block: Block;
  blockTime: string;
}

interface Ctx {
  anchorOrigin: string;
  alphaOrigin: string;
  publisher: string;
  manifest: unknown;
  manifestDigest: string;
  caPem: string;
  caFingerprint: string;
  signerCN: string;
  epochs: Epoch[];
  finalized: number;
}

/** Which inputs a case gives the verifier. */
interface Given {
  manifest: boolean;
  headerSource: boolean;
  trust: boolean;
  /** The header source's finalized height is below every publication's block. */
  notFinal?: boolean;
  /** Roots supplied beside the corpus authority's, with `trust`. */
  moreRoots?: string[];
}

/** The EVM rows of one publication of `epoch` under `given`, and whether the publication is `true` (tzun-anchor/1 §10.4). */
function evmRows(ctx: Ctx, epoch: Epoch, given: Given): { rows: Row[]; valid: boolean } {
  const txFacts = { transactionId: epoch.transactionId, txType: 2, sender: ctx.publisher, signedChainId: String(ANVIL_CHAIN_ID) };
  if (!given.manifest) {
    return { rows: [ok('anchor.publication[0]'), nc('anchor.evm.tx[0]', 'no_expectation:publisher', txFacts), nc('anchor.evm.canonical[0]', 'blocked_by:anchor.evm.tx[0]')], valid: false };
  }
  if (!given.headerSource) {
    return { rows: [ok('anchor.publication[0]'), ok('anchor.evm.tx[0]', txFacts), nc('anchor.evm.canonical[0]', 'input_not_supplied:evm_header_source')], valid: false };
  }
  if (given.notFinal) {
    return {
      rows: [ok('anchor.publication[0]'), ok('anchor.evm.tx[0]', txFacts), nc('anchor.evm.canonical[0]', 'evm_block_not_finalized', { finality: 'finalized' })],
      valid: false,
    };
  }
  return {
    rows: [
      ok('anchor.publication[0]'),
      ok('anchor.evm.tx[0]', txFacts),
      ok('anchor.evm.canonical[0]', { chain: CHAIN, namespace: 'test', network: null, blockTime: epoch.blockTime, inclusion: 'tx_proof', finality: 'finalized' }),
    ],
    valid: true,
  };
}

/** The sign-off rows of a record: `signoff.expectation`, then `signoff.key`. */
interface SignoffRows {
  expectation: Row;
  key: Row;
}

/**
 * The record-rule rows of a record (Verification §4.9 to §4.11),
 * between `signoff.key` and the anchor: `decider`, `decider.freshness`,
 * `contributions`, `contributions.binding` and `links`, then a
 * `links[<i>]` and `links[<i>].edge` row for each link. A corpus record's
 * decider is a human under acct with no freshness reference, and it records
 * no contributions and no links, unless `rows` says otherwise.
 */
interface RecordRuleRows {
  decider?: Row;
  freshness?: Row;
  contributions?: Row[];
  links?: Row[];
}
const HUMAN_DECIDER = ok('decider', { kind: 'human', scheme: 'acct', level: 'human-asserted' });
function recordRuleRows(rows: RecordRuleRows = {}): Row[] {
  return [
    rows.decider ?? HUMAN_DECIDER,
    rows.freshness ?? nc('decider.freshness', 'absent'),
    ...(rows.contributions ?? [nc('contributions', 'absent'), nc('contributions.binding', 'absent')]),
    ...(rows.links ?? [nc('links', 'absent')]),
  ];
}
/** The record-rule rows of a record whose digest does not hold: each blocked by it. */
const RECORD_RULE_ROWS_BLOCKED: Row[] = ['decider', 'decider.freshness', 'contributions', 'contributions.binding', 'links'].map((id) =>
  nc(id, 'blocked_by:record.digest'),
);

/** The record rows before the anchor, for a genuine timestamped record with no custody rows, no sign-off and no assertion unless `rows` says otherwise. */
function recordRows(
  given: Given,
  genTime: string,
  ctx: Ctx,
  rows: { custody?: Row; signoff?: SignoffRows; record?: RecordRuleRows } = {},
): Row[] {
  return [
    ok('bundle'),
    ok('subject'),
    ok('record.digest'),
    ok('record.chainLink'),
    rows.custody ?? nc('custody.ledger', 'not_applicable'),
    ok('ts.record.token'),
    given.trust ? ok('ts.record.trust', { genTime, authority: ctx.signerCN }) : nc('ts.record.trust', 'no_matching_trust_anchor'),
    rows.signoff?.expectation ?? ok('signoff.expectation'),
    rows.signoff?.key ?? nc('signoff.key', 'absent'),
    ...recordRuleRows(rows.record),
  ];
}

/** The anchor rows of a genuine anchor of `epoch`: steps 1 to 5 hold, then its publication. */
function genuineAnchorRows(ctx: Ctx, epoch: Epoch, given: Given): { rows: Row[]; valid: boolean } {
  const pub = evmRows(ctx, epoch, given);
  return {
    rows: [
      pub.valid ? ok('anchor') : nc('anchor', 'publication_not_checked'),
      ok('anchor.spec'),
      ok('anchor.checkpoint'),
      ok('anchor.origin', { originAuthenticated: pub.valid, namespace: 'test', chainChecked: true }),
      ok('anchor.leafIndex', { leafIndexChecked: true }),
      ok('anchor.inclusion'),
      ok('anchor.anchorInclusion'),
      ...pub.rows,
    ],
    valid: pub.valid,
  };
}

interface Expected {
  rows: Row[];
  /** Candidates for `existedBy`, stated with the check that proves each. */
  proven: Array<{ at: string; source: 'evm-calldata' | 'rfc3161' | 'record-timestamp'; check: 'anchor' | 'anchor.newer' | 'ts.record.trust' }>;
  namespace: 'test' | null;
  authenticated: boolean;
}

function summary(e: Expected): Record<string, unknown> {
  const outcomes = { 'checked-correct': 0, 'checked-wrong': 0, 'not-checked': 0, abstain: 0 };
  for (const r of e.rows) outcomes[r.outcome] += 1;
  const earliest = [...e.proven].sort((a, b) => Date.parse(a.at) - Date.parse(b.at))[0] ?? null;
  return {
    mode: null,
    coverage: null,
    manifestEnforced: null,
    rungs: [],
    keyKind: null,
    keyAssurance: null,
    uv: null,
    actorBound: null,
    existedBy: earliest,
    anchorNetwork: null,
    anchorNamespace: e.namespace,
    anchorOriginAuthenticated: e.authenticated,
    outcomes,
  };
}

/** SHA-256 of a root's DER, lowercase hex: the fingerprint a report's inputs list. */
const fingerprintOf = (pem: string) => new X509Certificate(pem).fingerprint256.replace(/:/g, '').toLowerCase();

function reportInputs(ctx: Ctx, given: Given): Record<string, unknown> {
  return {
    trustAnchors: given.trust ? [...new Set([ctx.caFingerprint, ...(given.moreRoots ?? []).map(fingerprintOf)])].sort() : [],
    evmHeaderSources: given.headerSource ? [{ chain: CHAIN, finality: 'finalized' }] : [],
    publisherManifest: given.manifest ? ctx.manifestDigest : null,
    frameOrigins: null,
    vkeys: null,
    mdsRoots: null,
  };
}

function inputsFile(ctx: Ctx, given: Given, regime: Partial<Inputs['regime']> = {}, manifest?: unknown): Inputs {
  const blocks = ctx.epochs.map((e) => e.block);
  return {
    publisherManifest: given.manifest ? (manifest ?? ctx.manifest) : null,
    headerSources: given.headerSource
      ? {
          [CHAIN]: {
            chainId: Number(ANVIL_CHAIN_ID),
            finality: 'finalized',
            finalizedBlockNumber: given.notFinal ? Math.min(...blocks.map((b) => b.number)) - 1 : ctx.finalized,
            blocks,
          },
        }
      : {},
    trustAnchorsPem: given.trust ? [ctx.caPem, ...(given.moreRoots ?? [])] : [],
    regime: { require: [], requireRung: [], allowUnchecked: false, ...regime },
  };
}

interface Case {
  name: string;
  /** What the case pins, and the sections it pins it from. */
  description: string;
  bundle: unknown;
  inputs: Inputs;
  report: Record<string, unknown>;
  exit: number;
}

// ---- Main --------------------------------------------------------------------------

/** How far anvil's clock runs behind the wall clock: every block time precedes every genTime. */
const CHAIN_CLOCK_LAG_S = 3600;

async function main(): Promise<void> {
  const node = await startAnvil();
  await node.rpc('evm_setTime', [Math.floor(Date.now() / 1000) - CHAIN_CLOCK_LAG_S]);
  const tsa = await startTsa();
  const dir = mkdtempSync(join(tmpdir(), 'tzun-test-bundle-b1-'));
  const open: Tzun[] = [];
  try {
    const publisher = node.devAccount(PUBLISHER_ACCOUNT);
    const file = join(dir, 'store.db');
    const attestation = { timestamp: { rfc3161Url: tsa.url }, retry: { autoStart: false } };
    const anchoring = {
      publishers: { evm: { rpcUrl: node.rpcUrl, chain: CHAIN, privateKey: publisher.privateKey } },
      autoStart: false,
      budget: { forcePerDay: 100 },
    };
    const alpha = await Tzun.init({ mode: 'local', dbPath: file, chainId: 'alpha', logNamespace: NS, anchoring, attestation } as TzunConfig);
    open.push(alpha);
    const beta = await Tzun.init({ mode: 'local', dbPath: file, chainId: 'beta', attestation } as TzunConfig);
    open.push(beta);
    let n = 0;
    const capture = async (t: Tzun, chainId: string): Promise<string> => {
      const r = await t.capture(decision(chainId, ++n));
      if (!r.stored || !r.envelope.nonRepudiation.rfc3161Token) throw new Error(`capture ${n} was not stored with a timestamp`);
      return r.envelope.payload.evidenceId;
    };

    // Epoch 1: alpha (a1, a2) and beta (b1), in a block with 20 other
    // transactions. Epoch 2: alpha grows (a3). Then a4 awaits its epoch, and
    // after a third epoch is sent and mined, its finality.
    const a1 = await capture(alpha, 'alpha');
    const a2 = await capture(alpha, 'alpha');
    const b1 = await capture(beta, 'beta');
    // A record signed at capture: a WebAuthn assertion over its own digest's
    // challenge, from a throwaway P-256 key no slot of the bundle carries.
    const signedInput = decision('beta', ++n);
    const prepared = await beta.prepareAssertionChallenge(signedInput);
    const { assertion } = makeGenuineAssertion({ challenge: prepared.challenge, credentialId: 'bundle-corpus-credential' });
    const signedResult = await beta.capture({ ...signedInput, attestationInputs: { webauthnAssertion: assertion } }, { prepared });
    if (!signedResult.stored || !signedResult.envelope.nonRepudiation.webauthnAssertion || !signedResult.envelope.nonRepudiation.rfc3161Token) {
      throw new Error('the signed capture was not stored with its assertion and a timestamp');
    }
    const b2 = signedResult.envelope.payload.evidenceId;
    // A record whose hashed payload.signoffExpectation owes a signature under a
    // sign-off policy (Record §9.1), signed at capture the same way.
    // Its case carries the bundle with the assertion removed.
    const owedInput = decision('beta', ++n);
    const owedPrepared = await beta.prepareAssertionChallenge(owedInput, {
      signoffExpectation: { policyDigest: sha256('bundle-corpus sign-off policy') },
    });
    const { assertion: owedAssertion } = makeGenuineAssertion({ challenge: owedPrepared.challenge, credentialId: 'bundle-corpus-credential' });
    const owedResult = await beta.capture({ ...owedInput, attestationInputs: { webauthnAssertion: owedAssertion } }, { prepared: owedPrepared });
    if (!owedResult.stored || !owedResult.envelope.nonRepudiation.webauthnAssertion || owedResult.envelope.payload.signoffExpectation === null) {
      throw new Error('the capture that owes a signature was not stored with its expectation and assertion');
    }
    const b3 = owedResult.envelope.payload.evidenceId;
    // A session record (Record §9.1, §9.3): the capture that claimed
    // slot 1 of a sign-off session builds the record with { statementDigest,
    // sessionSeq } inside its digest, and writes the session's signoff block
    // and assertion in the same write. Neither SDK opens sessions yet, so it
    // is written as a server that runs them writes it: assembled by the
    // engine, timestamped by the corpus authority, and stored through the
    // adapter at beta's next position.
    const sessionStatement = {
      v: 'tzun-signoff/1',
      mode: 'session',
      sessionId: '5b0f3e1c-9a7d-4c2b-8e6f-1d2c3b4a5e6f',
      signer: 'bundle-corpus-signer',
      signerName: 'QnVuZGxlIENvcnB1cw',
      meaning: 'approval',
      policyDigest: sha256('bundle-corpus sign-off policy'),
      notBefore: 'none',
      openedAt: new Date().toISOString(),
      maxAgeMs: 1_800_000,
      maxRecords: 50,
    };
    const statementDigest = signoffStatementDigest(sessionStatement);
    if (statementDigest === null) throw new Error('the session statement has no digest');
    const betaStorage = beta.getStorage();
    const sessionPrevious = await betaStorage.getLastDigest('beta');
    const sessionPosition = (await betaStorage.getLastSequence('beta')) + 1;
    const sessionDecision = decision('beta', ++n);
    const sessionEnvelope = assembleEnvelope({
      aiSystemId: sessionDecision.aiSystemId,
      aiOutput: sessionDecision.aiOutput,
      action: sessionDecision.action,
      reason: sessionDecision.reason,
      decider: CORPUS_DECIDER,
    }, {
      previousDigest: sessionPrevious ?? undefined,
      sequenceNumber: sessionPosition,
      signoffExpectation: { statementDigest, sessionSeq: 1 },
    });
    const { assertion: sessionAssertion } = makeGenuineAssertion({ challenge: signoffStatementChallenge(statementDigest), credentialId: 'bundle-corpus-credential' });
    const sessionToken = await requestTimestamp(sessionEnvelope.integrity.canonicalDigest, { tsaUrl: tsa.url });
    sessionEnvelope.nonRepudiation = {
      ...sessionEnvelope.nonRepudiation,
      webauthnAssertion: sessionAssertion,
      signoff: { statement: sessionStatement, sessionSeq: 1 },
      rfc3161Token: sessionToken.token,
      ...(sessionToken.metadata && { rfc3161Metadata: sessionToken.metadata }),
    };
    sessionEnvelope.attestationStatus = determineAttestationStatus(sessionEnvelope.nonRepudiation, sessionEnvelope.integrity.canonicalDigest);
    await betaStorage.store(sessionEnvelope, 'beta', { expectChainHead: { sequence: sessionPosition - 1, digest: sessionPrevious } });
    const s1 = sessionEnvelope.payload.evidenceId;
    // Records of the revised v1.0 format's members (Record §6 to §8): a
    // decision on one model call (a contributions list of one); the same with
    // its proposal's output not the record's aiOutput, which capture accepts
    // and the binding row reports; a decision deriving from b1 in the same
    // store (a derivedFrom link and the root link the builder adds); and an
    // agent's own decision under a registered descriptor.
    const modelStep = (output?: string) => ({
      steps: [{ role: 'propose', actor: null, aiBom: { ...CORPUS_MODEL_BOM }, inputs: [], ...(output !== undefined && { output }) }],
    });
    const capturedWith = async (edit: Partial<CaptureInput>): Promise<{ id: string; envelope: { payload: Record<string, unknown> } }> => {
      const r = await beta.capture({ ...decision('beta', ++n), ...edit } as CaptureInput);
      if (!r.stored || !r.envelope.nonRepudiation.rfc3161Token) throw new Error(`capture ${n} was not stored with a timestamp`);
      return { id: r.envelope.payload.evidenceId, envelope: r.envelope as unknown as { payload: Record<string, unknown> } };
    };
    const m1 = await capturedWith({ contributions: modelStep() as CaptureInput['contributions'] });
    const m2 = await capturedWith({ contributions: modelStep(outputDigest({ recommendation: 'approve', amount: 45000 })) as CaptureInput['contributions'] });
    const l1 = await capturedWith({ links: [{ rel: 'derivedFrom', target: { evidenceId: b1 } }] });
    const { digest: agentDigest } = await beta.agents.register(CORPUS_AGENT_DESCRIPTOR as AgentDescriptor);
    const g1 = await capturedWith({ decider: { kind: 'agent', agent: agentDigest, freshness: null } as CaptureInput['decider'] });
    await epochAmongTraffic(node, alpha, 11, 9);
    await settle(node, alpha);
    const a3 = await capture(alpha, 'alpha');
    await epochAmongTraffic(node, alpha, 2, 1);
    await settle(node, alpha);

    const bundleA1 = json(await alpha.exportBundle(a1));
    const bundleA2 = json(await alpha.exportBundle(a2));
    const bundleA3 = json(await alpha.exportBundle(a3));
    const bundleB1 = json(await alpha.exportBundle(b1));
    const bundleB2 = json(await alpha.exportBundle(b2));
    const bundleB3 = json(await alpha.exportBundle(b3));
    const bundleS1 = json(await alpha.exportBundle(s1));
    if (!bundleS1.envelope.nonRepudiation.anchor || !bundleS1.envelope.nonRepudiation.signoff) throw new Error('the session record was not anchored with its sign-off');
    const bundleM1 = json(await alpha.exportBundle(m1.id));
    const bundleM2 = json(await alpha.exportBundle(m2.id));
    const bundleL1 = json(await alpha.exportBundle(l1.id));
    const bundleG1 = json(await alpha.exportBundle(g1.id));
    // a1 as the exporter writes it for an envelope the fill has not reached:
    // the same store, the record's stored envelope without its artifact.
    const unfilledEnvelope = json(bundleA1.envelope);
    delete (unfilledEnvelope.nonRepudiation as { anchor?: unknown }).anchor;
    const unfilled = await bundleAnchoring(unfilledEnvelope, logStoreFor(alpha.getStorage()), anchorStoreFor(alpha.getStorage()));
    const bundleA1Unfilled: ProofBundle = { ...json(bundleA1), envelope: unfilledEnvelope, anchoring: unfilled.anchoring, anchorPending: unfilled.anchorPending };
    // a2 once an operator has recorded a custody action on it.
    await (alpha.getStorage() as unknown as { appendCustodyEntry(id: string, entry: unknown): Promise<void> }).appendCustodyEntry(a2, {
      timestamp: new Date().toISOString(),
      actor: 'ops@example.com',
      action: 'reviewed',
      systemId: 'tzun-recovery',
      metadata: { incidentId: 'corpus-1' },
    });
    const bundleA2Custody = json(await alpha.exportBundle(a2));
    if (!bundleA2Custody.custody.entries || bundleA2Custody.custody.entries.length !== 1) throw new Error('a2 has no custody row');
    const a4 = await capture(alpha, 'alpha');
    const bundleA4Epoch = json(await alpha.exportBundle(a4));
    if (!(await alpha.anchorNow({ force: true })).epoch) throw new Error('no third epoch');
    await node.mine(1);
    await alpha.anchorNow();
    const bundleA4Finality = json(await alpha.exportBundle(a4));
    if (!bundleA4Epoch.anchorPending || !bundleA4Finality.anchorPending) throw new Error('a4 is not pending');

    const state = (await alpha.getAnchorState())!;
    const anchorOrigin = state.anchorOrigin;
    const alphaOrigin = bundleA4Epoch.anchorPending.origin;
    const anchorEntries = bundleA1.anchoring[anchorOrigin].checkpoints;
    const epochOf = async (entry: (typeof anchorEntries)[number]): Promise<Epoch> => {
      const pub = entry.publications![0] as { transactionId: string; blockNumber: number };
      const b = await node.rpc<{ hash: string; timestamp: string }>('eth_getBlockByNumber', [toBeHex(pub.blockNumber), false]);
      const block = { number: pub.blockNumber, hash: b.hash.toLowerCase(), timestamp: Number(BigInt(b.timestamp)) };
      return { transactionId: pub.transactionId, block, blockTime: new Date(block.timestamp * 1000).toISOString() };
    };
    const epochs = [await epochOf(anchorEntries[0]), await epochOf(anchorEntries[1])];

    // The split view: a second history of alpha at size 2 with a1 at leaf 0,
    // taken into a second history of the anchor log that extends the first
    // epoch's, and published with the store's own key.
    const anchorLog = (await logStoreFor(alpha.getStorage())!.listLogs()).find((l) => l.kind === ANCHOR_LOG_KIND)!;
    const epochOneLeaves = (await logStoreFor(alpha.getStorage())!.listLogLeaves(anchorLog.logId, 0, 2)).map((l) => l.leafDigest);
    const forgedLogTree = buildMerkleTree([bundleA1.subject.canonicalDigest, sha256('a second history of alpha')]);
    const forgedLog = formatCheckpoint(alphaOrigin, 2, getMerkleRoot(forgedLogTree));
    const forgedAnchorTree = buildMerkleTree([...epochOneLeaves, sha256(forgedLog)]);
    const forgedAnchor = formatCheckpoint(anchorOrigin, 3, getMerkleRoot(forgedAnchorTree));
    const forgedTx = await publisher.connect(node.provider).sendTransaction({ to: publisher.address, value: 0n, data: `0x${sha256(forgedAnchor)}` });
    await node.mine(4);
    const rpc = new JsonRpcEvmChain(node.rpcUrl, ANVIL_CHAIN_ID);
    const forgedReceipt = (await rpc.receipt(forgedTx.hash))!;
    const forgedMaterial = await rpc.blockMaterial(forgedReceipt.blockNumber);
    const forgedEpoch: Epoch = {
      transactionId: forgedTx.hash.toLowerCase(),
      block: { number: forgedMaterial.number, hash: forgedMaterial.hash.toLowerCase(), timestamp: forgedMaterial.timestamp },
      blockTime: new Date(forgedMaterial.timestamp * 1000).toISOString(),
    };

    const manifest = { publishers: { [anchorOrigin]: [{ address: publisher.address.toLowerCase(), chain: CHAIN, namespace: 'test' }] } };
    const ctx: Ctx = {
      anchorOrigin,
      alphaOrigin,
      publisher: publisher.address.toLowerCase(),
      manifest,
      manifestDigest: sha256(canonicalSerialize(manifest as unknown as Record<string, unknown>, Object.keys(manifest))),
      caPem: tsa.caPem,
      caFingerprint: fingerprintOf(tsa.caPem),
      signerCN: tsa.signerCN,
      epochs: [...epochs, forgedEpoch],
      finalized: await node.finalized(),
    };
    const genTimeOf = (b: ProofBundle) => extractTSTInfo(parseTimestampResponse(b.envelope.nonRepudiation.rfc3161Token!)).genTime.toISOString();
    const full: Given = { manifest: true, headerSource: true, trust: true };
    const consistencyIds = [`anchor.consistency[${anchorOrigin}]`, `anchor.consistency[${alphaOrigin}]`];
    const consistencyOk = [ok(consistencyIds[0], { fromSize: 2, toSize: 3 }), ok(consistencyIds[1], { fromSize: 2, toSize: 3 })];

    const cases: Case[] = [];
    const add = (name: string, description: string, bundle: unknown, given: Given, e: Expected, exit: number, regime: Partial<Inputs['regime']> = {}, manifestOverride?: unknown) => {
      // Verification §6.1: the bundle's bundleVersion and subject as they stand.
      const b = bundle !== null && typeof bundle === 'object' && !Array.isArray(bundle) ? (bundle as Record<string, unknown>) : {};
      const restated = (member: string) => (member in b ? b[member] : null);
      cases.push({
        name,
        description,
        bundle,
        inputs: inputsFile(ctx, given, regime, manifestOverride),
        report: {
          reportVersion: 'tzun-verify-report/1',
          bundleVersion: restated('bundleVersion'),
          subject: restated('subject'),
          inputs: reportInputs(ctx, given),
          checks: e.rows,
          summary: summary(e),
        },
        exit,
      });
    };

    // ---- A genuine anchored record, whose log and anchor log grew after it ----
    const a1Time = genTimeOf(bundleA1);
    const genuineA1 = (given: Given): Expected => {
      const anchor = genuineAnchorRows(ctx, epochs[0], given);
      const newer = evmRows(ctx, epochs[1], given).valid;
      return {
        rows: [
          ...recordRows(given, a1Time, ctx),
          ...anchor.rows,
          newer ? ok('anchor.newer', { treeSize: 3, anchorSize: 3 }) : nc('anchor.newer', 'publication_not_checked'),
          ...(anchor.valid && newer ? consistencyOk : consistencyIds.map((id) => nc(id, 'blocked_by:anchor'))),
        ],
        proven: [
          ...(given.trust ? [{ at: a1Time, source: 'record-timestamp' as const, check: 'ts.record.trust' as const }] : []),
          ...(anchor.valid ? [{ at: epochs[0].blockTime, source: 'evm-calldata' as const, check: 'anchor' as const }] : []),
          ...(newer ? [{ at: epochs[1].blockTime, source: 'evm-calldata' as const, check: 'anchor.newer' as const }] : []),
        ],
        namespace: 'test',
        authenticated: anchor.valid || newer,
      };
    };
    add('anchored-with-newer', 'A record anchored in epoch 1 whose log and anchor log grew in epoch 2: its own anchor, the newer anchor and both consistency proofs hold with the manifest, a header source and the TSA root (Bundle §7.5, §7.6; Anchor §10.8). Exit 0.', bundleA1, full, genuineA1(full), 0);
    const none: Given = { manifest: false, headerSource: false, trust: false };
    add('anchored-offline', 'The same bundle verified with no trust inputs: every publication, the timestamp\'s trust and both consistency checks are not checked. Exit 4 (Verification §6.6).', bundleA1, none, genuineA1(none), 4);
    add('anchored-offline-allow-unchecked', 'The same, with --allow-unchecked: exit 0, every NOT CHECKED line still in the report (Verification §6.6).', bundleA1, none, genuineA1(none), 0, { allowUnchecked: true });
    const noSource: Given = { manifest: true, headerSource: false, trust: true };
    add('anchored-no-header-source', 'The manifest and the TSA root, no header source: the transaction\'s offline facts hold and never make the publication true (tzun-anchor/1 §10.4). Exit 4.', bundleA1, noSource, genuineA1(noSource), 4);
    const notFinal: Given = { ...full, notFinal: true };
    add('anchored-not-final', 'A header source whose finalized height is below both publications\' blocks: evm_block_not_finalized, with the finality it judged by (tzun-anchor/1 §10.4 items 10 and 14). Exit 4.', bundleA1, notFinal, genuineA1(notFinal), 4);
    const untrusted: Given = { manifest: true, headerSource: true, trust: false };
    add('timestamp-untrusted', 'The record\'s RFC 3161 token verifies, and chains to no root the auditor supplied: ts.record.trust not checked, no_matching_trust_anchor (tzun-anchor/1 §10.5 step 4). Exit 4.', bundleA1, untrusted, genuineA1(untrusted), 4);

    // ---- The record's own timestamp, held to tzun-anchor/1 §10.5 --------------
    // The record's token re-issued by the corpus authority, over the same
    // digest and at the same genTime, with one rule of §10.5 broken. The
    // digest does not cover nonRepudiation, so only the timestamp checks can
    // show it (Verification §4.4).
    const withRecordToken = async (faults: Parameters<SigningTsa['issue']>[3]): Promise<ProofBundle> => {
      const b = json(bundleA1);
      b.envelope.nonRepudiation.rfc3161Token = (await tsa.issue(b.subject.canonicalDigest, null, new Date(a1Time), faults)).toString('base64');
      return b;
    };
    const recordTokenFails = (reason: 'malformed_token' | 'verification_failed'): Expected => {
      const e = genuineA1(full);
      return {
        ...e,
        rows: e.rows.map((r) =>
          r.id === 'ts.record.token' ? wrong(r.id, reason) : r.id === 'ts.record.trust' ? nc(r.id, 'blocked_by:ts.record.token') : r,
        ),
        proven: e.proven.filter((p) => p.check !== 'ts.record.trust'),
      };
    };
    add('record-token-not-der', 'The record\'s RFC 3161 token with its TSTInfo in a constructed (BER) OCTET STRING, which decodes to the same bytes and is not DER: ts.record.token checked-wrong, malformed_token, and ts.record.trust blocked by it (tzun-anchor/1 §10.5 step 1). Exit 1.',
      await withRecordToken({ berTstInfo: true }), full, recordTokenFails('malformed_token'), 1);
    add('record-token-no-signing-certificate', 'The record\'s RFC 3161 token, validly signed, whose signed attributes carry neither a signingCertificate nor a signingCertificateV2, so nothing binds its signer certificate: ts.record.token checked-wrong, verification_failed (tzun-anchor/1 §10.5 step 3). Exit 1.',
      await withRecordToken({ signingCertificate: 'none' }), full, recordTokenFails('verification_failed'), 1);
    add('record-token-no-timestamping-eku', 'The record\'s RFC 3161 token signed by a certificate of the same name under the root the auditor supplied, with no extendedKeyUsage: not a timestamping certificate, so ts.record.token checked-wrong, verification_failed, whatever root it chains to (tzun-anchor/1 §10.5 step 3). Exit 1.',
      await withRecordToken({ signerEku: 'none' }), full, recordTokenFails('verification_failed'), 1);
    add('record-token-digest-algorithms-malformed', 'The record\'s RFC 3161 token, validly signed, whose SignedData.digestAlgorithms holds a bare OBJECT IDENTIFIER where a SET OF AlgorithmIdentifier belongs. The set is not signed, so anyone can change it: ts.record.token checked-wrong, malformed_token (tzun-anchor/1 §10.5 step 1). Exit 1.',
      await withRecordToken({ digestAlgorithms: 'bare-oid' }), full, recordTokenFails('malformed_token'), 1);
    add('record-token-unreadable-certificate', 'The record\'s genuine RFC 3161 token with one certificate added to its unsigned certificates set: a CA certificate of the root\'s name whose public key is not a point on its curve. A certificate whose key does not decode is not a certificate, so ts.record.token checked-wrong, malformed_token, and every other check is still reported (tzun-anchor/1 §10.5 step 1; Verification §4.4). Exit 1.',
      await withRecordToken({ issuerCopy: 'bad-key' }), full, recordTokenFails('malformed_token'), 1);
    // A key whose curve this verifier does not implement is read with the key
    // left unread (tzun-anchor/1 §10.5 step 1); a step that needs it is not
    // checked, missing_dependency (step 5). The curve here is the OID
    // 1.2.840.10045.3.1.99, assigned to no curve, so every verifier lacks it
    // and the cases are the same for all of them.
    add('record-token-signer-off-curve', 'The record\'s RFC 3161 token signed by a certificate whose P-256 point is not on the curve: a curve every verifier implements, so the certificate is not one: ts.record.token checked-wrong, malformed_token (tzun-anchor/1 §10.5 step 1). Exit 1.',
      await withRecordToken({ signerKey: 'bad-key' }), full, recordTokenFails('malformed_token'), 1);
    {
      const e = genuineA1(full);
      add('record-token-signer-unassigned-curve', 'The record\'s RFC 3161 token whose signer certificate names the curve OID 1.2.840.10045.3.1.99, assigned to no curve: its key is left unread, not a decoding failure, and step 3 needs it: ts.record.token not checked, missing_dependency, and ts.record.trust blocked by it (tzun-anchor/1 §10.5 steps 1 and 5). Exit 4.',
        await withRecordToken({ signerKey: 'unassigned-curve' }), full, {
          ...e,
          rows: e.rows.map((r) => (r.id === 'ts.record.token' ? nc(r.id, 'missing_dependency') : r.id === 'ts.record.trust' ? nc(r.id, 'blocked_by:ts.record.token') : r)),
          proven: e.proven.filter((p) => p.check !== 'ts.record.trust'),
        }, 4);
      add('record-token-intermediate-unassigned-curve', 'The record\'s RFC 3161 token signed by a certificate that an intermediate CA issued, the intermediate carried in the token with its key renamed to the curve OID 1.2.840.10045.3.1.99 and signed again by the supplied root: every rule of the path holds but the intermediate\'s signature over the signer, which no verifier can check. ts.record.token checked-correct, ts.record.trust not checked, missing_dependency (tzun-anchor/1 §10.5 step 5). Exit 4.',
        await withRecordToken({ signerIssuer: 'intermediate-unassigned-curve' }), full, {
          ...e,
          rows: e.rows.map((r) => (r.id === 'ts.record.trust' ? nc(r.id, 'missing_dependency') : r)),
          proven: e.proven.filter((p) => p.check !== 'ts.record.trust'),
        }, 4);
    }
    add('record-token-unneeded-certificate-unassigned-curve', 'The record\'s genuine RFC 3161 token with a certificate added that no path names, whose key names the curve OID 1.2.840.10045.3.1.99: no step needs its key, so it is not examined past step 1, and every check holds (tzun-anchor/1 §10.5 steps 1 and 5). Exit 0.',
      await withRecordToken({ unneededCertificate: 'unassigned-curve' }), full, genuineA1(full), 0);

    // The authority fact: the value of the signer subject's first commonName,
    // RDNs and their attributes in encoded order, as its string type holds it,
    // with no escaping, no trimming and no normalization; the empty string with
    // no commonName (tzun-anchor/1 §10.5 step 4, §10.7).
    {
      const CN = '2.5.4.3';
      const shapes: Array<[string, string, Rdn[], string]> = [
        ['first-cn', 'two commonName RDNs after a country: the first', [[['2.5.4.6', 19, 'US']], [[CN, 12, 'First CN']], [[CN, 12, 'Second CN']]], 'First CN'],
        ['multi-valued-rdn', 'a commonName inside a multi-valued RDN with an organization: its value alone', [[['2.5.4.10', 12, 'Corpus Org'], [CN, 12, 'Multi CN']]], 'Multi CN'],
        ['specials', 'a commonName with RFC 4514 specials and a space at each end: as encoded, with no escaping and no trimming', [[[CN, 12, ' Acme, Inc. + "TSA" = #1 \\ <x>; ']]], ' Acme, Inc. + "TSA" = #1 \\ <x>; '],
        ['line-feed', 'a commonName holding a line feed', [[[CN, 12, 'Line1\nLine2']]], 'Line1\nLine2'],
        ['utf8-string', 'a UTF8String commonName outside ASCII', [[[CN, 12, 'Zeitstempel Zürich Ω 時']]], 'Zeitstempel Zürich Ω 時'],
        ['bmp-string', 'a BMPString commonName, read as UTF-16', [[[CN, 30, 'Zürich BMP']]], 'Zürich BMP'],
        ['teletex-string', 'a TeletexString commonName with the byte 0xFC, read as ISO 8859-1', [[[CN, 20, 'Zürich T61']]], 'Zürich T61'],
        ['empty-cn', 'an empty commonName after an organization: the empty string', [[['2.5.4.10', 12, 'Corpus Org']], [[CN, 12, '']]], ''],
        ['no-cn', 'a subject with no commonName: the empty string', [[['2.5.4.6', 19, 'US']], [['2.5.4.8', 12, 'California']], [['2.5.4.10', 12, 'Corpus Org']], [['2.5.4.11', 12, 'Unit A']], [['2.5.4.11', 12, 'Unit B']]], ''],
        ['empty-subject', 'a subject with no RDN: the empty string', [], ''],
      ];
      for (const [shape, what, rdns, authority] of shapes) {
        const e = genuineA1(full);
        add(`record-token-authority-${shape}`, `The record's RFC 3161 token signed by a certificate whose subject is ${what}: ts.record.trust checked-correct with authority ${JSON.stringify(authority)} (tzun-anchor/1 §10.5 step 4, §10.7). Exit 0.`,
          await withRecordToken({ signerSubject: nameDer(rdns) }), full, {
            ...e,
            rows: e.rows.map((r) => (r.id === 'ts.record.trust' ? ok(r.id, { genTime: a1Time, authority }) : r)),
          }, 0);
      }
    }
    {
      const e = genuineA1(full);
      add('record-token-issuer-name-reencoded', 'The record\'s RFC 3161 token signed by a certificate the supplied root did issue, whose issuer name writes the root\'s CN as a UTF8String where the root\'s subject writes a PrintableString. Names match byte for byte, so no path reaches the root: ts.record.token checked-correct, ts.record.trust not checked, no_matching_trust_anchor (tzun-anchor/1 §10.5 step 4). Exit 4.',
        await withRecordToken({ signerIssuerName: 'utf8' }), full, {
          ...e,
          rows: e.rows.map((r) => (r.id === 'ts.record.trust' ? nc(r.id, 'no_matching_trust_anchor') : r)),
          proven: e.proven.filter((p) => p.check !== 'ts.record.trust'),
        }, 4);
    }

    // ---- An rfc3161/1 publication of the record's P (tzun-anchor/1 §10.5) ------------
    // A second authority, under a root of its own, timestamps P, the SHA-256 of
    // the record's anchor checkpoint body (Anchor §6), at the record token's
    // genTime. Its token joins the envelope's artifact at index 1, and the
    // anchor-log checkpoint entry that carries the record's P (Bundle §7.4).
    // The artifact sits outside the record's digest, so only the anchor rows
    // show it; anchor.newer, whose checkpoint keeps its own publications, does
    // not. Steps 1 to 3 need no root; step 4 needs the authority's.
    {
      const anchorTsa = await makeSigningTsa({ signerCN: 'Tzun Corpus Anchor Timestamping Authority', caCN: 'Tzun Corpus Anchor Test Root CA' });
      const ownCheckpoint = bundleA1.envelope.nonRepudiation.anchor!.anchorCheckpoint;
      const anchorP = sha256(ownCheckpoint);
      const withAnchorToken = async (digestHex: string, faults?: Parameters<SigningTsa['issue']>[3]): Promise<ProofBundle> => {
        const publication = { kind: 'rfc3161/1' as const, token: (await anchorTsa.issue(digestHex, null, new Date(a1Time), faults)).toString('base64') };
        const b = json(bundleA1);
        b.envelope.nonRepudiation.anchor!.publications.push(publication);
        const entry = b.anchoring[anchorOrigin].checkpoints.find((c) => c.body === ownCheckpoint)!;
        entry.publications = [...(entry.publications ?? []), publication as never];
        return b;
      };
      const both: Given = { ...full, moreRoots: [anchorTsa.caPem] };
      const withTokenRows = (e: Expected, token: Row, trust: Row): Expected => {
        const at = e.rows.findIndex((r) => r.id === 'anchor.evm.canonical[0]') + 1;
        return { ...e, rows: [...e.rows.slice(0, at), ok('anchor.publication[1]'), token, trust, ...e.rows.slice(at)] };
      };
      // A token refused at steps 1 to 3 makes the publication, and so the record's
      // anchor, false: one false publication shows the artifact untrue, and it
      // yields no fact (Anchor §10.6). The EVM publication keeps its own rows,
      // anchor.newer holds, and the carried bodies only the record's anchor would
      // authenticate wait for it.
      const anchorFails = (reason: 'imprint_mismatch' | 'malformed_publication'): Expected => {
        const e = genuineA1(both);
        return withTokenRows(
          {
            ...e,
            rows: e.rows.map((r) =>
              r.id === 'anchor'
                ? wrong('anchor', reason)
                : r.id === 'anchor.origin'
                  ? ok(r.id, { originAuthenticated: false, namespace: 'test', chainChecked: true })
                  : consistencyIds.includes(r.id)
                    ? nc(r.id, 'blocked_by:anchor')
                    : r,
            ),
            proven: e.proven.filter((p) => p.check !== 'anchor'),
          },
          wrong('anchor.tsa.token[1]', reason),
          nc('anchor.tsa.trust[1]', 'blocked_by:anchor.tsa.token[1]'),
        );
      };
      const genuineToken = await withAnchorToken(anchorP);
      add('anchor-token-trusted', 'The record\'s anchor with a second publication: an rfc3161/1 token over its P from a second authority, whose root the auditor supplies beside the record authority\'s. Steps 1 to 3 hold on anchor.tsa.token[1], and step 4 on anchor.tsa.trust[1], with genTime and authority. The EVM block time is earlier, so existedBy stays the EVM publication\'s (tzun-anchor/1 §10.5, §10.6). Exit 0.',
        genuineToken, both, withTokenRows(genuineA1(both), ok('anchor.tsa.token[1]'), ok('anchor.tsa.trust[1]', { genTime: a1Time, authority: anchorTsa.signerCN })), 0);
      add('anchor-token-no-roots', 'The same bundle with no RFC 3161 root supplied: steps 1 to 3 need none, so anchor.tsa.token[1] holds; no path reaches a supplied root, so anchor.tsa.trust[1] is not checked, no_matching_trust_anchor, and the publication is null. The anchor holds by its EVM publication (tzun-anchor/1 §10.5). Exit 4.',
        genuineToken, untrusted, withTokenRows(genuineA1(untrusted), ok('anchor.tsa.token[1]'), nc('anchor.tsa.trust[1]', 'no_matching_trust_anchor')), 4);
      add('anchor-token-other-value', 'The second authority\'s token over the record\'s digest instead of the anchor\'s P, its root supplied: anchor.tsa.token[1] checked-wrong, imprint_mismatch, anchor.tsa.trust[1] blocked by it, whatever root the token chains to. One false publication makes the record\'s anchor false, with no fact from it; anchor.newer holds (tzun-anchor/1 §10.5 step 2, §10.6). Exit 1.',
        await withAnchorToken(bundleA1.subject.canonicalDigest), both, anchorFails('imprint_mismatch'), 1);
      add('anchor-token-not-der', 'The second authority\'s token over the anchor\'s P with its TSTInfo in a constructed (BER) OCTET STRING, which is not DER: anchor.tsa.token[1] checked-wrong, malformed_publication, anchor.tsa.trust[1] blocked by it, and the record\'s anchor false (tzun-anchor/1 §10.5 step 1, §10.6). Exit 1.',
        await withAnchorToken(anchorP, { berTstInfo: true }), both, anchorFails('malformed_publication'), 1);
    }

    // ---- A record anchored in the newest epoch --------------------------------
    const a3Time = genTimeOf(bundleA3);
    const a3Anchor = genuineAnchorRows(ctx, epochs[1], full);
    add('anchored-latest-epoch', 'A record anchored in the newest epoch: one checkpoint per log, no newer anchor and no consistency check (Bundle §7.3). Exit 0.', bundleA3, full, {
      rows: [...recordRows(full, a3Time, ctx), ...a3Anchor.rows],
      proven: [
        { at: a3Time, source: 'record-timestamp', check: 'ts.record.trust' },
        { at: epochs[1].blockTime, source: 'evm-calldata', check: 'anchor' },
      ],
      namespace: 'test',
      authenticated: true,
    }, 0);

    // ---- Unanchored ---------------------------------------------------------------
    const a4Time = genTimeOf(bundleA4Epoch);
    const pending = (): Expected => ({
      rows: [...recordRows(full, a4Time, ctx), nc('anchor', 'absent'), ...STEPS.map((id) => nc(id, 'absent')), nc('anchor.pending', 'not_yet_published')],
      proven: [{ at: a4Time, source: 'record-timestamp', check: 'ts.record.trust' }],
      namespace: null,
      authenticated: false,
    });
    add('unanchored-awaiting-epoch', 'A record no epoch has taken yet: anchorPending, never a marker in nonRepudiation; anchor absent and anchor.pending not checked, not_yet_published (Bundle §7.7). Exit 4.', bundleA4Epoch, full, pending(), 4);
    add('unanchored-allow-unchecked', 'The same, with --allow-unchecked: exit 0 (Bundle §7.7).', bundleA4Epoch, full, pending(), 0, { allowUnchecked: true });
    add('unanchored-awaiting-finality', 'The same record exported after its epoch\'s transaction was mined and before it was final: still pending (Bundle §2, §7.7). Exit 4.', bundleA4Finality, full, pending(), 4);

    // ---- Tampered and forged ---------------------------------------------------------
    const edited = json(bundleA1);
    edited.envelope.payload.reason = 'edited after capture';
    add('tampered-payload', 'A payload edited under its stored digest: record.digest checked-wrong once, and everything that takes the digest as input blocked by it (Verification §2.2, §4.3). Exit 1.', edited, full, {
      rows: [
        ok('bundle'),
        ok('subject'),
        wrong('record.digest', 'digest_mismatch'),
        ok('record.chainLink'),
        nc('custody.ledger', 'not_applicable'),
        nc('ts.record.token', 'blocked_by:record.digest'),
        nc('ts.record.trust', 'blocked_by:record.digest'),
        nc('signoff.expectation', 'blocked_by:record.digest'),
        nc('signoff.key', 'absent'),
        ...RECORD_RULE_ROWS_BLOCKED,
        nc('anchor', 'blocked_by:record.digest'),
        ...STEPS.map((id) => nc(id, 'blocked_by:record.digest')),
        nc('anchor.newer', 'blocked_by:record.digest'),
        ...consistencyIds.map((id) => nc(id, 'blocked_by:anchor')),
      ],
      proven: [],
      namespace: null,
      authenticated: false,
    }, 1);

    // Record §3.1, §3.6: a name holding a lone surrogate is kept as read and
    // refused by the canonical serialization, never replaced by U+FFFD, so a
    // digest computed over U+FFFD in its place is not the record's.
    const fffd = json(bundleA1);
    {
      const payload = fffd.envelope.payload as unknown as Record<string, unknown>;
      const schema = new SchemaRegistry().get(payload.schemaVersion as string)!;
      const replaced = { ...payload, aiOutput: { ...(payload.aiOutput as Record<string, unknown>), '\ufffd': 1 } };
      const digest = computeDigest(canonicalSerialize(replaced, schema.hashedFieldSet));
      payload.aiOutput = { ...(payload.aiOutput as Record<string, unknown>), '\ud800': 1 };
      fffd.envelope.integrity.canonicalDigest = digest;
      fffd.subject.canonicalDigest = digest;
    }
    add('payload-name-lone-surrogate-fffd-digest', 'A payload whose hashed aiOutput holds a member named "\\ud800", a lone surrogate, under a stored digest computed with U+FFFD in its place: the canonical serialization refuses the name, never normalises it, so record.digest is checked-wrong, payload_unserializable, and everything that takes the digest as input is blocked by it (Record §3.6, Verification §4.3). Exit 1.', fffd, full, {
      rows: [
        ok('bundle'),
        ok('subject'),
        wrong('record.digest', 'payload_unserializable'),
        ok('record.chainLink'),
        nc('custody.ledger', 'not_applicable'),
        nc('ts.record.token', 'blocked_by:record.digest'),
        nc('ts.record.trust', 'blocked_by:record.digest'),
        nc('signoff.expectation', 'blocked_by:record.digest'),
        nc('signoff.key', 'absent'),
        ...RECORD_RULE_ROWS_BLOCKED,
        nc('anchor', 'blocked_by:record.digest'),
        ...STEPS.map((id) => nc(id, 'blocked_by:record.digest')),
        nc('anchor.newer', 'blocked_by:record.digest'),
        ...consistencyIds.map((id) => nc(id, 'blocked_by:anchor')),
      ],
      proven: [],
      namespace: null,
      authenticated: false,
    }, 1);

    const retagged = json(bundleA1);
    (retagged.envelope as { envelopeVersion: unknown }).envelopeVersion = 'e2';
    add('envelope-version-unknown', 'An envelope tagged e2, a version this verifier does not read: record.digest abstains, unsupported_envelope_version, and everything that takes the digest as input is blocked by it (Verification §2.2: an unknown tag abstains on its section). Exit 4, never a pass.', retagged, full, {
      rows: [
        ok('bundle'),
        ok('subject'),
        abstain('record.digest', 'unsupported_envelope_version'),
        ok('record.chainLink'),
        nc('custody.ledger', 'not_applicable'),
        nc('ts.record.token', 'blocked_by:record.digest'),
        nc('ts.record.trust', 'blocked_by:record.digest'),
        nc('signoff.expectation', 'blocked_by:record.digest'),
        nc('signoff.key', 'absent'),
        ...RECORD_RULE_ROWS_BLOCKED,
        nc('anchor', 'blocked_by:record.digest'),
        ...STEPS.map((id) => nc(id, 'blocked_by:record.digest')),
        nc('anchor.newer', 'blocked_by:record.digest'),
        ...consistencyIds.map((id) => nc(id, 'blocked_by:anchor')),
      ],
      proven: [],
      namespace: null,
      authenticated: false,
    }, 4);

    const reseated = json(bundleA2);
    reseated.envelope.payload.reason = 'rewritten and reseated';
    {
      const schema = new SchemaRegistry().get(reseated.envelope.payload.schemaVersion)!;
      const digest = computeDigest(canonicalSerialize(reseated.envelope.payload as unknown as Record<string, unknown>, schema.hashedFieldSet));
      const link = new EvidenceChain();
      link.restore(reseated.chain.predecessor!.canonicalDigest);
      reseated.envelope.integrity.canonicalDigest = digest;
      reseated.envelope.integrity.chainLink = link.computeLink(digest);
      reseated.subject.canonicalDigest = digest;
    }
    add('rewrite-and-reseat', 'A payload rewritten with its digest and chain link recomputed: the record reads intact, and its RFC 3161 token and both anchors are over another digest (imprint_mismatch, merkle_proof_invalid). Exit 1.', reseated, full, {
      rows: [
        ok('bundle'),
        ok('subject'),
        ok('record.digest'),
        ok('record.chainLink'),
        nc('custody.ledger', 'not_applicable'),
        wrong('ts.record.token', 'imprint_mismatch'),
        nc('ts.record.trust', 'blocked_by:ts.record.token'),
        ok('signoff.expectation'),
        nc('signoff.key', 'absent'),
        ...recordRuleRows(),
        wrong('anchor', 'merkle_proof_invalid'),
        ok('anchor.spec'),
        ok('anchor.checkpoint'),
        ok('anchor.origin', { originAuthenticated: false, namespace: 'test', chainChecked: true }),
        ok('anchor.leafIndex', { leafIndexChecked: true }),
        wrong('anchor.inclusion', 'merkle_proof_invalid'),
        nc('anchor.anchorInclusion', 'blocked_by:anchor.inclusion'),
        wrong('anchor.newer', 'merkle_proof_invalid'),
        ...consistencyIds.map((id) => nc(id, 'blocked_by:anchor')),
      ],
      proven: [],
      namespace: 'test',
      authenticated: false,
    }, 1);

    /** A case whose own anchor fails at `failAt` with `reason`, while the store's newer anchor holds. */
    const ownAnchorFails = (failAt: string, reason: string): Expected => {
      const at = STEPS.indexOf(failAt);
      const facts = (id: string) =>
        id === 'anchor.origin' ? { originAuthenticated: false, namespace: 'test', chainChecked: true } : id === 'anchor.leafIndex' ? { leafIndexChecked: true } : undefined;
      // tzun-anchor/1 §10.7: anchor.origin states its facts when it holds;
      // anchor.leafIndex states leafIndexChecked whatever its outcome.
      const failedFacts = (id: string) => (id === 'anchor.leafIndex' ? facts(id) : undefined);
      return {
        rows: [
          ...recordRows(full, a1Time, ctx),
          wrong('anchor', reason),
          ...STEPS.map((id, i) => (i < at ? ok(id, facts(id)) : i === at ? wrong(id, reason, failedFacts(id)) : nc(id, `blocked_by:${failAt}`))),
          ok('anchor.newer', { treeSize: 3, anchorSize: 3 }),
          ...consistencyIds.map((id) => nc(id, 'blocked_by:anchor')),
        ],
        proven: [
          { at: a1Time, source: 'record-timestamp', check: 'ts.record.trust' },
          { at: epochs[1].blockTime, source: 'evm-calldata', check: 'anchor.newer' },
        ],
        namespace: 'test',
        authenticated: true,
      };
    };
    const leafTransplant = json(bundleA1);
    leafTransplant.envelope.nonRepudiation.anchor = json(bundleA2.envelope.nonRepudiation.anchor);
    add('transplanted-leaf', 'Another record\'s artifact, from the same chain, on this record: leaf_index_mismatch; the store\'s material still anchors the record (anchor.newer). Exit 1.', leafTransplant, full, ownAnchorFails('anchor.leafIndex', 'leaf_index_mismatch'), 1);
    const chainTransplant = json(bundleA1);
    chainTransplant.envelope.nonRepudiation.anchor = json(bundleB1.envelope.nonRepudiation.anchor);
    add('transplanted-chain', 'An artifact from a record on another chain of the store: chain_id_mismatch (tzun-anchor/1 §10.3 step 2b). Exit 1.', chainTransplant, full, ownAnchorFails('anchor.origin', 'chain_id_mismatch'), 1);
    const logPath = json(bundleA1);
    logPath.envelope.nonRepudiation.anchor!.logPath[0] = flip(logPath.envelope.nonRepudiation.anchor!.logPath[0]);
    add('tampered-log-path', 'One hash of the record\'s path in its log flipped: merkle_proof_invalid. Exit 1.', logPath, full, ownAnchorFails('anchor.inclusion', 'merkle_proof_invalid'), 1);
    const anchorPath = json(bundleA1);
    anchorPath.envelope.nonRepudiation.anchor!.anchorPath[0] = flip(anchorPath.envelope.nonRepudiation.anchor!.anchorPath[0]);
    add('tampered-anchor-path', 'One hash of the log checkpoint\'s path in the anchor log flipped: anchor_proof_invalid. Exit 1.', anchorPath, full, ownAnchorFails('anchor.anchorInclusion', 'anchor_proof_invalid'), 1);

    const fabricated = json(bundleA1);
    {
      const entry = fabricated.anchoring[anchorOrigin].checkpoints[0].publications![0] as { blockHeader: string; blockHash: string };
      const fields = decodeRlp(entry.blockHeader) as string[];
      fields[11] = toBeHex(BigInt(fields[11]) - 86_400n);
      entry.blockHeader = encodeRlp(fields);
      entry.blockHash = keccak256(entry.blockHeader).toLowerCase();
      (fabricated.envelope.nonRepudiation.anchor!.publications[0] as { blockHash: string }).blockHash = entry.blockHash;
    }
    const txFacts = { transactionId: epochs[0].transactionId, txType: 2, sender: ctx.publisher, signedChainId: String(ANVIL_CHAIN_ID) };
    const fabricatedRows = (given: Given): Expected => {
      const withSource = given.headerSource;
      return {
        rows: [
          ...recordRows(given, a1Time, ctx),
          withSource ? wrong('anchor', 'anchor_not_found_on_chain') : nc('anchor', 'publication_not_checked'),
          ok('anchor.spec'),
          ok('anchor.checkpoint'),
          ok('anchor.origin', { originAuthenticated: false, namespace: 'test', chainChecked: true }),
          ok('anchor.leafIndex', { leafIndexChecked: true }),
          ok('anchor.inclusion'),
          ok('anchor.anchorInclusion'),
          ok('anchor.publication[0]'),
          ok('anchor.evm.tx[0]', txFacts),
          withSource
            ? wrong('anchor.evm.canonical[0]', 'anchor_not_found_on_chain', { finality: 'finalized' })
            : nc('anchor.evm.canonical[0]', 'input_not_supplied:evm_header_source'),
          withSource ? ok('anchor.newer', { treeSize: 3, anchorSize: 3 }) : nc('anchor.newer', 'publication_not_checked'),
          ...consistencyIds.map((id) => nc(id, 'blocked_by:anchor')),
        ],
        proven: [
          { at: a1Time, source: 'record-timestamp', check: 'ts.record.trust' },
          ...(withSource ? [{ at: epochs[1].blockTime, source: 'evm-calldata' as const, check: 'anchor.newer' as const }] : []),
        ],
        namespace: 'test',
        authenticated: withSource,
      };
    };
    add('fabricated-header-offline', 'A validly signed transaction under a self-consistent, back-dated header (its hash written into the envelope and the bundle), with no header source: anchor.evm.tx holds, anchor.evm.canonical is not checked, the publication is null, and no existedBy comes from it (Anchor §10.4, §10.6). Exit 4.', fabricated, noSource, fabricatedRows(noSource), 4);
    add('fabricated-header-with-source', 'The same bundle against the auditor\'s header source: the block at that height has another hash, anchor_not_found_on_chain. Exit 1.', fabricated, full, fabricatedRows(full), 1);

    const publicationFails = (reason: string): Expected => ({
      rows: [
        ...recordRows(full, a1Time, ctx),
        wrong('anchor', reason),
        ok('anchor.spec'),
        ok('anchor.checkpoint'),
        ok('anchor.origin', { originAuthenticated: false, namespace: 'test', chainChecked: true }),
        ok('anchor.leafIndex', { leafIndexChecked: true }),
        ok('anchor.inclusion'),
        ok('anchor.anchorInclusion'),
        ok('anchor.publication[0]'),
        wrong('anchor.evm.tx[0]', reason, txFacts),
        nc('anchor.evm.canonical[0]', 'blocked_by:anchor.evm.tx[0]'),
        wrong('anchor.newer', reason),
        ...consistencyIds.map((id) => nc(id, 'blocked_by:anchor')),
      ],
      proven: [{ at: a1Time, source: 'record-timestamp', check: 'ts.record.trust' }],
      namespace: 'test',
      authenticated: false,
    });
    const otherChain = { publishers: { [anchorOrigin]: [{ ...manifest.publishers[anchorOrigin][0], chain: 'eip155:1' }] } };
    add('manifest-chain-mismatch', 'The manifest names the publisher on another chain than the one the transaction signed: evm_chain_mismatch (Anchor §10.4). Exit 1.', bundleA1, full, publicationFails('evm_chain_mismatch'), 1, {}, otherChain);
    const otherSender = { publishers: { [anchorOrigin]: [{ ...manifest.publishers[anchorOrigin][0], address: node.devAccount(7).address.toLowerCase() }] } };
    add('sender-not-publisher', 'The manifest names another address for the anchor origin: evm_sender_mismatch. Exit 1.', bundleA1, full, publicationFails('evm_sender_mismatch'), 1, {}, otherSender);
    // A validFrom is compared at full precision (tzun-anchor/1 §9): half a
    // millisecond past the second of the newer publication's block opens the
    // window after both publications' blocks, and half a millisecond into the
    // second before the record's publication's block opens it before both.
    // A reader that keeps milliseconds admits the newer publication's block
    // in the late case. When both blocks share a second it admits the
    // record's too, and exits 0 where the late case states 1; when the newer
    // block is later, the exit codes agree and the report's anchor.newer row
    // tells that reader apart.
    const sameSecond = epochs[0].block.timestamp === epochs[1].block.timestamp;
    const withValidFrom = (validFrom: string) => ({ publishers: { [anchorOrigin]: [{ ...manifest.publishers[anchorOrigin][0], validFrom }] } });
    const halfMsInto = (unixSeconds: number) => `${new Date(unixSeconds * 1000).toISOString().slice(0, 19)}.0005Z`;
    const fromLate = withValidFrom(halfMsInto(epochs[1].block.timestamp));
    const fromEarly = withValidFrom(halfMsInto(epochs[0].block.timestamp - 1));
    add('manifest-valid-from-fraction-late', `The manifest's entry for the publisher has a validFrom half a millisecond past the second of the newer publication's block. Compared at full precision (Anchor §9), the window opens after both publications' blocks: evm_sender_mismatch. A reader that keeps milliseconds reads .0005 as .000 and admits ${sameSecond ? 'them' : 'the newer one'}. Exit 1.`, bundleA1, full, publicationFails('evm_sender_mismatch'), 1, {}, fromLate);
    add('manifest-valid-from-fraction-early', 'The same entry with a validFrom half a millisecond into the second before the record\'s publication\'s block: the window opens before both blocks, and the bundle verifies as anchored-with-newer does (tzun-anchor/1 §9). Exit 0.', bundleA1, full, genuineA1(full), 0, {}, fromEarly);
    // The manifests change the inputs' digest.
    for (const [name, m] of [
      ['manifest-chain-mismatch', otherChain],
      ['sender-not-publisher', otherSender],
      ['manifest-valid-from-fraction-late', fromLate],
      ['manifest-valid-from-fraction-early', fromEarly],
    ] as const) {
      const c = cases.find((x) => x.name === name)!;
      (c.report.inputs as Record<string, unknown>).publisherManifest = sha256(canonicalSerialize(m as unknown as Record<string, unknown>, Object.keys(m)));
    }

    const futureSpec = json(bundleA1);
    (futureSpec.envelope.nonRepudiation.anchor as unknown as { anchorSpec: string }).anchorSpec = 'tzun-anchor/2';
    add('forged-future-anchor-spec', 'The record\'s artifact relabelled tzun-anchor/2: the verifier abstains on that section, which is never a pass. Exit 4 (Verification §6.6).', futureSpec, full, {
      rows: [
        ...recordRows(full, a1Time, ctx),
        abstain('anchor', 'unsupported_anchor_spec'),
        abstain('anchor.spec', 'unsupported_anchor_spec'),
        ...STEPS.slice(1).map((id) => nc(id, 'blocked_by:anchor.spec')),
        ok('anchor.newer', { treeSize: 3, anchorSize: 3 }),
        ...consistencyIds.map((id) => nc(id, 'blocked_by:anchor')),
      ],
      proven: [
        { at: a1Time, source: 'record-timestamp', check: 'ts.record.trust' },
        { at: epochs[1].blockTime, source: 'evm-calldata', check: 'anchor.newer' },
      ],
      namespace: 'test',
      authenticated: true,
    }, 4);

    const withGenuine = (patch: (rows: Row[]) => Row[]): Expected => {
      const e = genuineA1(full);
      return { ...e, rows: patch(e.rows) };
    };
    const brokenProof = json(bundleA1);
    brokenProof.anchoring[anchorOrigin].consistency[0].path[0] = flip(brokenProof.anchoring[anchorOrigin].consistency[0].path[0]);
    add('consistency-proof-tampered', 'One hash of the anchor log\'s consistency proof flipped, between two authenticated checkpoints: log_inconsistent_with_anchor (tzun-anchor/1 §10.8). Exit 1.', brokenProof, full,
      withGenuine((rows) => rows.map((r) => (r.id === consistencyIds[0] ? wrong(r.id, 'log_inconsistent_with_anchor') : r))), 1);
    const noProof = json(bundleA1);
    noProof.anchoring[alphaOrigin].consistency = [];
    add('consistency-proof-missing', 'The evidence log\'s consistency proof left out: not_in_bundle:consistency_proof. Exit 4.', noProof, full,
      withGenuine((rows) => rows.map((r) => (r.id === consistencyIds[1] ? nc(r.id, 'not_in_bundle:consistency_proof') : r))), 4);
    const newerPath = json(bundleA1);
    newerPath.anchoring[alphaOrigin].checkpoints[1].anchorPath![0] = flip(newerPath.anchoring[alphaOrigin].checkpoints[1].anchorPath![0]);
    add('newer-anchor-tampered', 'One hash of the newer checkpoint\'s path in the newest anchor checkpoint flipped: anchor.newer anchor_proof_invalid, and the consistency it would authenticate blocked by it. Exit 1.', newerPath, full, {
      ...genuineA1(full),
      rows: genuineA1(full).rows.map((r) =>
        r.id === 'anchor.newer' ? wrong(r.id, 'anchor_proof_invalid') : consistencyIds.includes(r.id) ? nc(r.id, 'blocked_by:anchor.newer') : r,
      ),
      proven: genuineA1(full).proven.filter((p) => p.check !== 'anchor.newer'),
    }, 1);

    const split = json(bundleA1);
    {
      const ownLogEntry = split.anchoring[alphaOrigin].checkpoints[0];
      const ownAnchorEntry = split.anchoring[anchorOrigin].checkpoints[0];
      const consistency = getConsistencyProof(forgedAnchorTree, 2, 3);
      if (!consistency.ok) throw new Error('no forged consistency proof');
      split.anchoring[alphaOrigin] = {
        checkpoints: [
          ownLogEntry,
          { body: forgedLog, signatures: [], logPath: getMerkleProof(forgedLogTree, 0), anchorLeafIndex: 2, anchorSize: 3, anchorPath: getMerkleProof(forgedAnchorTree, 2) },
        ],
        consistency: [],
      };
      split.anchoring[anchorOrigin] = {
        checkpoints: [
          ownAnchorEntry,
          {
            body: forgedAnchor,
            signatures: [],
            publications: [
              {
                kind: 'evm-calldata/1',
                chain: CHAIN,
                transactionId: forgedEpoch.transactionId,
                blockNumber: forgedEpoch.block.number,
                blockHash: forgedEpoch.block.hash,
                publisher: ctx.publisher,
                rawTransaction: forgedMaterial.rawTransactions[forgedReceipt.transactionIndex],
                blockHeader: forgedMaterial.headerRlp,
                txIndex: forgedReceipt.transactionIndex,
                txProof: buildTxTrie(forgedMaterial.rawTransactions).proof(forgedReceipt.transactionIndex),
              },
            ],
          },
        ],
        consistency: [{ fromSize: 2, toSize: 3, path: consistency.proof }],
      };
    }
    add('split-view', 'A second history of the record\'s log at the same size, taken into an extension of the anchor log and published with the store\'s own key: every anchor holds, and the two authenticated bodies of one size differ: split_view (tzun-anchor/1 §10.8). Exit 1.', split, full, {
      ...genuineA1(full),
      rows: genuineA1(full).rows.map((r) =>
        r.id === 'anchor.newer'
          ? ok(r.id, { treeSize: 2, anchorSize: 3 })
          : r.id === consistencyIds[0]
            ? ok(r.id, { fromSize: 2, toSize: 3 })
            : r.id === consistencyIds[1]
              ? wrong(r.id, 'split_view')
              : r,
      ),
      proven: genuineA1(full).proven.map((p) => (p.check === 'anchor.newer' ? { ...p, at: forgedEpoch.blockTime } : p)),
    }, 1);

    const subject = json(bundleA1);
    subject.subject.canonicalDigest = sha256('another record');
    add('subject-mismatch', 'A subject that does not name the envelope\'s digest (Bundle §5.1). Exit 1.', subject, full,
      withGenuine((rows) => rows.map((r) => (r.id === 'subject' ? wrong('subject', 'subject_mismatch') : r))), 1);

    const witness = json(bundleA1) as unknown as { extensions: Record<string, unknown> };
    witness.extensions['witness/1'] = { cosignature: 'reserved' };
    add('witness-extension', 'A value in the reserved witness/1 extension: this verifier abstains on that key only (Bundle §9). Exit 4.', witness, full,
      withGenuine((rows) => [...rows, abstain('extension[witness/1]', 'unsupported_extension')]), 4);

    // ---- A record whose log did not grow while the anchor log did ---------------------
    const bodyOf = (body: string) => {
      const r = parseCheckpoint(body);
      if (!r.ok) throw new Error(`a checkpoint body does not parse: ${r.reason}`);
      return r.checkpoint;
    };
    const betaOrigin = bodyOf(bundleB1.envelope.nonRepudiation.anchor!.logCheckpoint).origin;
    const betaSize = bodyOf(bundleB1.envelope.nonRepudiation.anchor!.logCheckpoint).size;
    const logUnchanged = (b: ProofBundle, signoff?: SignoffRows, record?: RecordRuleRows): Expected => {
      const time = genTimeOf(b);
      return {
        rows: [
          ...recordRows(full, time, ctx, { ...(signoff && { signoff }), ...(record && { record }) }),
          ...genuineAnchorRows(ctx, epochs[0], full).rows,
          ok('anchor.newer', { treeSize: betaSize, anchorSize: 3 }),
          ok(`anchor.consistency[${anchorOrigin}]`, { fromSize: 2, toSize: 3 }),
        ],
        proven: [
          { at: time, source: 'record-timestamp', check: 'ts.record.trust' },
          { at: epochs[0].blockTime, source: 'evm-calldata', check: 'anchor' },
          { at: epochs[1].blockTime, source: 'evm-calldata', check: 'anchor.newer' },
        ],
        namespace: 'test',
        authenticated: true,
      };
    };
    if (Object.keys(bundleB1.anchoring).sort().join() !== [anchorOrigin, betaOrigin].sort().join() || bundleB1.anchoring[betaOrigin].checkpoints.length !== 1) {
      throw new Error('b1 does not carry one checkpoint of its log');
    }
    add('anchored-log-unchanged', 'A record on another chain of the store, anchored in epoch 1, whose log did not grow while the anchor log did: one checkpoint of its log, carrying its anchor into the newest anchor checkpoint, and the anchor log\'s two checkpoints with their proof (Bundle §7.5; Anchor §10.8). Exit 0.', bundleB1, full, logUnchanged(bundleB1), 0);
    add('signed-record', 'A record signed at capture: its expectation is null and it carries no sign-off block, so signoff.expectation holds; its WebAuthn assertion needs a credential no slot of b1 carries, signoff.key not_in_bundle:credential (Verification §4.5, §5). Exit 4.', bundleB2, full,
      logUnchanged(bundleB2, { expectation: ok('signoff.expectation'), key: nc('signoff.key', 'not_in_bundle:credential') }, {
        decider: ok('decider', { kind: 'human', scheme: 'acct', level: 'human-asserted', levelUndetermined: 'human-proven' }),
      }), 4);
    const signatureStripped = json(bundleB3);
    delete (signatureStripped.envelope.nonRepudiation as { webauthnAssertion?: unknown }).webauthnAssertion;
    add('signature-stripped', 'A record whose hashed payload.signoffExpectation owes a signature under a sign-off policy ({ policyDigest }), signed at capture, with its WebAuthn assertion removed: a bundle cannot tell a stripped signature from one still to come, so signoff.expectation and signoff.key are not checked, signature_missing, and never absent (Verification §5). Exit 4.', signatureStripped, full,
      logUnchanged(signatureStripped, { expectation: nc('signoff.expectation', 'signature_missing'), key: nc('signoff.key', 'signature_missing') }), 4);
    // The session record, and three sign-offs that are not the record's own:
    // each decided from the one record's bundle, with no key (21 CFR 11.70;
    // Verification §5).
    const blockedKey = nc('signoff.key', 'blocked_by:signoff.expectation');
    const withSignoff = (b: ProofBundle, signoff: unknown, assertion: unknown): ProofBundle => {
      const out = json(b);
      Object.assign(out.envelope.nonRepudiation, { signoff: json(signoff), webauthnAssertion: json(assertion) });
      return out;
    };
    add('session-record', 'A record captured into slot 1 of a sign-off session: { statementDigest, sessionSeq } inside its digest, written with its signoff block and an assertion that presented the session statement\'s challenge. signoff.expectation holds with no key; signoff.key needs a credential no slot of b1 carries (Record §9.1, Verification §5). Exit 4.', bundleS1, full,
      logUnchanged(bundleS1, { expectation: ok('signoff.expectation'), key: nc('signoff.key', 'not_in_bundle:credential') }), 4);
    const sessionStripped = json(bundleS1);
    delete (sessionStripped.envelope.nonRepudiation as { signoff?: unknown }).signoff;
    delete (sessionStripped.envelope.nonRepudiation as { webauthnAssertion?: unknown }).webauthnAssertion;
    add('session-signoff-stripped', 'The session record with its signoff block and assertion removed: a session record is written with its sign-off (Record §9.1), so the record alone shows the removal, signoff.expectation checked-wrong, signoff_stripped, and signoff.key blocked by it (21 CFR 11.70). Exit 1, with or without --allow-unchecked.', sessionStripped, full,
      logUnchanged(sessionStripped, { expectation: wrong('signoff.expectation', 'signoff_stripped'), key: blockedKey }), 1);
    const sessionTransplanted = withSignoff(bundleB1, bundleS1.envelope.nonRepudiation.signoff, bundleS1.envelope.nonRepudiation.webauthnAssertion);
    add('session-signoff-transplanted', 'The session record\'s signoff block and assertion moved onto a record whose hashed expectation is null: signoff.expectation checked-wrong, session_signoff_not_expected (21 CFR 11.70). The digest does not cover nonRepudiation, so only the expectation shows it. Exit 1.', sessionTransplanted, full,
      logUnchanged(sessionTransplanted, { expectation: wrong('signoff.expectation', 'session_signoff_not_expected'), key: blockedKey }), 1);
    // A session sign-off is the signoff block alone (Record §9.3): a record that
    // names no session and carries the session record's block, with no
    // assertion, reads session_signoff_not_expected before any rule looks at
    // an assertion.
    const sessionBlockOnly = (b: ProofBundle): ProofBundle => {
      const out = json(b);
      delete (out.envelope.nonRepudiation as { webauthnAssertion?: unknown }).webauthnAssertion;
      out.envelope.nonRepudiation.signoff = json(bundleS1.envelope.nonRepudiation.signoff);
      return out;
    };
    const nullSessionBlock = sessionBlockOnly(bundleB1);
    add('session-signoff-without-assertion', 'A record whose hashed expectation is null, carrying the session record\'s signoff block and no assertion: a session sign-off is the block alone, so signoff.expectation is checked-wrong, session_signoff_not_expected, and signoff.key blocked by it (Record §9.3, Verification §5). Exit 1.', nullSessionBlock, full,
      logUnchanged(nullSessionBlock, { expectation: wrong('signoff.expectation', 'session_signoff_not_expected'), key: blockedKey }), 1);
    const policySessionBlock = sessionBlockOnly(bundleB3);
    add('policy-session-signoff-without-assertion', 'A record whose hashed expectation is { policyDigest }, its assertion removed, carrying the session record\'s signoff block: the session rule comes before the one that reads a missing assertion as signature_missing, so signoff.expectation is checked-wrong, session_signoff_not_expected, and signoff.key blocked by it (Verification §5). Exit 1.', policySessionBlock, full,
      logUnchanged(policySessionBlock, { expectation: wrong('signoff.expectation', 'session_signoff_not_expected'), key: blockedKey }), 1);
    const junkBatch = withSignoff(bundleB2, { statement: { mode: 'batch' } }, bundleB2.envelope.nonRepudiation.webauthnAssertion);
    add('junk-batch-signoff', 'The signed record with a batch signoff block beside its per-record assertion, whose statement has no digest, no root and no inclusion proof: a sign-off block that does not bind by the checks that need no key is never a signature carried, signoff.expectation checked-wrong, signoff_unbound (Record §9.5, Verification §5). Exit 1.', junkBatch, full,
      logUnchanged(junkBatch, { expectation: wrong('signoff.expectation', 'signoff_unbound'), key: blockedKey }), 1);

    // ---- The revised v1.0 record's members (Verification §4.9 to §4.11) ---------------
    const stepModel = (e: { payload: Record<string, unknown> }) =>
      ((e.payload.contributions as { steps: Array<{ aiBom: { modelDescriptorDigest: string } }> }).steps[0].aiBom.modelDescriptorDigest);
    const bindingFacts = { approvals: [], staleApprovals: [], uncoveredReviews: [], proposals: [0], decisionBinding: 'checked' };
    add('contributions-single-model', 'A human\'s decision on one model call: a contributions list of one, its step\'s actor null and its output the record\'s aiOutput. contributions and contributions.binding hold (Record §7.3, §7.5). Exit 0.', bundleM1, full,
      logUnchanged(bundleM1, undefined, {
        contributions: [ok('contributions', { steps: 1, models: [stepModel(m1.envelope)], decidingStep: 'record' }), ok('contributions.binding', bindingFacts)],
      }), 0);
    const m2Output = (m2.envelope.payload.contributions as { steps: Array<{ output: string }> }).steps[0].output;
    add('contributions-decided-output-differs', 'A decision whose aiOutput is not the output its one proposal recorded: capture accepts a flawed process, and contributions.binding reports it from the record alone, decided_output_differs (Record §7.5, Verification §4.10). Exit 1.', bundleM2, full,
      logUnchanged(bundleM2, undefined, {
        contributions: [
          ok('contributions', { steps: 1, models: [stepModel(m2.envelope)], decidingStep: 'record' }),
          wrong('contributions.binding', 'decided_output_differs', { ...bindingFacts, failedStep: 0, failedDigest: m2Output }),
        ],
      }), 1);
    const linkRows = (): RecordRuleRows => ({
      links: [
        ok('links', { count: 2, relations: ['derivedFrom', 'root'], extensions: 0 }),
        ok('links[0]', { targetHeld: false }),
        abstain('links[0].edge', 'unsupported_link_edge'),
        ok('links[1]', { targetHeld: false }),
        abstain('links[1].edge', 'unsupported_link_edge'),
      ],
    });
    add('links-derived-from', 'A decision deriving from b1 in the same store: a derivedFrom link and the root link the builder adds, both naming b1 with its locator. A bundle holds no target, and no edge is proven in this version, so each edge row abstains, unsupported_link_edge (Record §8.8, Verification §4.11). Exit 4.', bundleL1, full,
      logUnchanged(bundleL1, undefined, linkRows()), 4);
    add('links-derived-from-allow-unchecked', 'The same under --allow-unchecked: exit 0, every abstaining row still in the report.', bundleL1, full,
      logUnchanged(bundleL1, undefined, linkRows()), 0, { allowUnchecked: true });
    add('links-derived-from-allow-unchecked-scoped', 'The same under the scoped allowance --allow-unchecked unsupported_link_edge (regime allowUnchecked ["unsupported_link_edge"]): only rows abstaining for that reason stop counting toward 4, and here they are the only ones. Exit 0.', bundleL1, full,
      logUnchanged(bundleL1, undefined, linkRows()), 0, { allowUnchecked: ['unsupported_link_edge'] });
    add('decider-agent', 'An agent\'s own decision, its decider named by the digest of a descriptor registered in the store\'s catalog: decider holds, agent-asserted (Record §6, Verification §4.9). Exit 0.', bundleG1, full,
      logUnchanged(bundleG1, undefined, { decider: ok('decider', { kind: 'agent', scheme: 'desc', level: 'agent-asserted' }) }), 0);

    // ---- Custody ---------------------------------------------------------------------------
    const a2Time = genTimeOf(bundleA2Custody);
    const genuineA2 = (custody: Row): Expected => {
      const e = genuineA1(full);
      return {
        ...e,
        rows: [...recordRows(full, a2Time, ctx, { custody }), ...e.rows.slice(recordRows(full, a1Time, ctx).length)],
        proven: e.proven.map((p) => (p.check === 'ts.record.trust' ? { ...p, at: a2Time } : p)),
      };
    };
    // This version verifies no custody material (Verification §4.3, Bundle §6):
    // custody.ledger is never checked-correct. Its one finding is a slot that
    // holds no row beside a mirror entry in the envelope.
    add('custody-ledger', 'A record with a custody row an operator recorded after capture, and the envelope\'s hashed mirror of it: this version verifies no custody material, so custody.ledger abstains, unsupported_artifact, and never vouches for the row (Verification §4.3, Bundle §6). Exit 4.', bundleA2Custody, full, genuineA2(abstain('custody.ledger', 'unsupported_artifact')), 4);
    const rowRemoved = json(bundleA2Custody);
    rowRemoved.custody.entries = [];
    add('custody-row-removed', 'The same bundle with its custody row left out: the envelope\'s hashed mirror names a row the ledger does not hold, mirror_entry_unexpected. Exit 1.', rowRemoved, full, genuineA2(wrong('custody.ledger', 'mirror_entry_unexpected')), 1);
    const rowAndMirrorRemoved = json(rowRemoved);
    rowAndMirrorRemoved.envelope.custodyChain = rowAndMirrorRemoved.envelope.custodyChain.filter((e) => !(e as { entryHash?: unknown }).entryHash);
    add('custody-row-and-mirror-removed', 'The row and its hashed mirror entry both left out: the slot holds no row and the envelope names none, so custody.ledger is not_applicable. Nothing in the bundle commits to the ledger, so a row removed with its mirror entry leaves no trace (Verification §4.3). Exit 0.', rowAndMirrorRemoved, full, genuineA2(nc('custody.ledger', 'not_applicable')), 0);

    // ---- The envelope's artifact, and the carried checkpoints ------------------------------
    const noArtifact = (b: ProofBundle, consistency: Row[]): Expected => ({
      rows: [
        ...recordRows(full, genTimeOf(b), ctx),
        nc('anchor', 'absent'),
        ...STEPS.map((id) => nc(id, 'absent')),
        ok('anchor.newer', { treeSize: 3, anchorSize: 3 }),
        ...consistency,
      ],
      proven: [
        { at: genTimeOf(b), source: 'record-timestamp', check: 'ts.record.trust' },
        { at: epochs[1].blockTime, source: 'evm-calldata', check: 'anchor.newer' },
      ],
      namespace: 'test',
      authenticated: true,
    });
    add('artifact-not-filled', 'An anchored record whose envelope the fill has not reached, as the exporter writes it: no artifact names the record\'s own checkpoints, so only the newest of each log is carried, with the record\'s anchor into it; anchor absent, anchor.newer holds (Bundle §7.3, §7.5). Exit 0.', bundleA1Unfilled, full, noArtifact(bundleA1Unfilled, []), 0);
    const stripped = json(bundleA1);
    delete (stripped.envelope.nonRepudiation as { anchor?: unknown }).anchor;
    add('artifact-stripped', 'The first bundle with the envelope\'s artifact removed: the record\'s own checkpoints are still carried, and nothing authenticates them, so neither consistency check can run (tzun-anchor/1 §10.8). Exit 4.', stripped, full,
      noArtifact(stripped, consistencyIds.map((id) => nc(id, 'blocked_by:anchor'))), 4);
    const strippedEdited = json(stripped);
    strippedEdited.envelope.payload.reason = 'edited after capture';
    add('tampered-payload-artifact-stripped', 'The artifact-stripped bundle with its payload edited: record.digest checked-wrong, and with no artifact to wait for the digest the anchor rows are absent, not blocked; anchor.newer, whose composed artifact takes the digest, is blocked by it (Verification §4.3, §4.6; Bundle §7.4). Exit 1.', strippedEdited, full, {
      rows: [
        ok('bundle'),
        ok('subject'),
        wrong('record.digest', 'digest_mismatch'),
        ok('record.chainLink'),
        nc('custody.ledger', 'not_applicable'),
        nc('ts.record.token', 'blocked_by:record.digest'),
        nc('ts.record.trust', 'blocked_by:record.digest'),
        nc('signoff.expectation', 'blocked_by:record.digest'),
        nc('signoff.key', 'absent'),
        ...RECORD_RULE_ROWS_BLOCKED,
        nc('anchor', 'absent'),
        ...STEPS.map((id) => nc(id, 'absent')),
        nc('anchor.newer', 'blocked_by:record.digest'),
        ...consistencyIds.map((id) => nc(id, 'blocked_by:anchor')),
      ],
      proven: [],
      namespace: null,
      authenticated: false,
    }, 1);
    const contradicted = json(bundleA3);
    for (const key of [alphaOrigin, anchorOrigin]) {
      const entry = contradicted.anchoring[key].checkpoints[0];
      const body = bodyOf(entry.body);
      entry.body = formatCheckpoint(body.origin, body.size, sha256(`another history of ${key}`));
    }
    add('carried-checkpoints-contradict', 'A record anchored in the newest epoch whose carried checkpoints are replaced by bodies of the same logs and sizes with other roots: nothing authenticates them, with one checkpoint per log as with two, so the consistency checks are not checked, blocked_by:anchor.newer (tzun-anchor/1 §10.8). Exit 4.', contradicted, full, {
      rows: [...recordRows(full, a3Time, ctx), ...a3Anchor.rows, ...consistencyIds.map((id) => nc(id, 'blocked_by:anchor.newer'))],
      proven: [
        { at: a3Time, source: 'record-timestamp', check: 'ts.record.trust' },
        { at: epochs[1].blockTime, source: 'evm-calldata', check: 'anchor' },
      ],
      namespace: 'test',
      authenticated: true,
    }, 4);
    const twoLogs = json(bundleA1);
    twoLogs.anchoring[alphaOrigin] = {
      checkpoints: [
        { body: bundleA1.envelope.nonRepudiation.anchor!.logCheckpoint, signatures: [] },
        { body: bundleA1.envelope.nonRepudiation.anchor!.anchorCheckpoint, signatures: [] },
      ],
      consistency: [],
    };
    add('checkpoints-of-two-logs-under-one-key', 'The artifact\'s evidence-log and anchor-log checkpoints carried together under the evidence log\'s key: a checkpoint sits under the key of its own origin, so the bundle cannot be read, and two logs are never compared as one (Bundle §7.1). Exit 2.', twoLogs, full, { rows: [wrong('bundle', 'malformed_bundle')], proven: [], namespace: null, authenticated: false }, 2);

    // ---- Frozen slots and members this verifier does not read ------------------------------
    const related = json(bundleA1) as unknown as Record<string, unknown>;
    related.relatedRecords = { '00000000-0000-4000-8000-000000000000': { role: 'credential-revocation', envelope: {} } };
    add('related-records-filled', 'The reserved relatedRecords slot filled: this verifier does not read it yet, so it abstains on it, which is never a pass (Bundle §8). Exit 4.', related, full,
      withGenuine((rows) => [...rows, abstain('relatedRecords', 'unsupported_slot')]), 4);
    const policy = json(bundleA1) as unknown as Record<string, unknown>;
    policy.policy = { leaves: [{ modes: ['record'] }], checkpoint: 'reserved' };
    add('policy-filled', 'The reserved policy slot filled: abstain on it, unsupported_slot (Bundle §8). Exit 4.', policy, full,
      withGenuine((rows) => [...rows, abstain('policy', 'unsupported_slot')]), 4);
    const member = json(bundleA1) as unknown as Record<string, unknown>;
    member.futureSlot = { reserved: true };
    add('unknown-member', 'A top-level member a b1 record bundle does not have: abstain on it, unsupported_member, since what it carries is not examined (Bundle §3.3). Exit 4.', member, full,
      withGenuine((rows) => [...rows, abstain('member[futureSlot]', 'unsupported_member')]), 4);
    const unread = json(bundleA1);
    Object.assign(unread.envelope.nonRepudiation, {
      futureArtifact: { reserved: true },
      assertionTimestamp: { token: 'reserved' },
      blockchainAnchor: { chain: 'ethereum-sepolia', transactionId: `0x${'00'.repeat(32)}` },
    });
    add('nonrepudiation-unread-members', 'Members of nonRepudiation no check reads: an assertionTimestamp (ts.assertion.token), a legacy blockchainAnchor beside the anchor (nonRepudiation.blockchainAnchor, legacy_blockchain_anchor) and an unknown member (nonRepudiation.futureArtifact), each abstained on, in byte order of its name, never passed over in silence (Verification §4.7). Exit 4.', unread, full,
      withGenuine((rows) => [
        ...rows,
        abstain('ts.assertion.token', 'unsupported_artifact'),
        abstain('nonRepudiation.blockchainAnchor', 'legacy_blockchain_anchor'),
        abstain('nonRepudiation.futureArtifact', 'unsupported_artifact'),
      ]), 4);
    const remark = json(bundleA1) as unknown as { subject: Record<string, unknown> };
    remark.subject.note = 'a member the subject check does not read';
    add('subject-extra-member', 'A subject with a member beside evidenceId and canonicalDigest: the subject check reads those two and holds, and the report restates the bundle\'s subject as it stands, the extra member included (Verification §4.2, §6.1). Exit 0.', remark, full, genuineA1(full), 0);

    // ---- The pending slot left out ----------------------------------------------------------
    const pendingStripped = json(bundleA4Epoch);
    pendingStripped.anchorPending = null;
    const noAnchor = (): Expected => ({
      rows: [...recordRows(full, a4Time, ctx), nc('anchor', 'absent'), ...STEPS.map((id) => nc(id, 'absent'))],
      proven: [{ at: a4Time, source: 'record-timestamp', check: 'ts.record.trust' }],
      namespace: null,
      authenticated: false,
    });
    add('unanchored-pending-stripped', 'An unanchored record\'s bundle with anchorPending set to null: it reads as a record of a store that does not anchor, since an absent anchor is not an unchecked artifact (Verification §6.6, Bundle §7.8). Exit 0.', pendingStripped, full, noAnchor(), 0);
    add('unanchored-pending-stripped-require-anchor', 'The same under a regime that requires the anchor: exit 3. An auditor who needs the record anchored requires anchor (Verification §6.6).', pendingStripped, full, noAnchor(), 3, { require: ['anchor'] });

    // ---- Bundles that are abstained on or unreadable ----------------------------------
    const bundleOnly = (row: Row): Expected => ({ rows: [row], proven: [], namespace: null, authenticated: false });
    add('bundle-version-unknown', 'bundleVersion b2: the verifier abstains on the whole bundle (Bundle §4). Exit 2.', { ...json(bundleA1), bundleVersion: 'b2' }, none, bundleOnly(abstain('bundle', 'unsupported_bundle_version')), 2);
    const noVersion = json(bundleA1) as unknown as Record<string, unknown>;
    delete noVersion.bundleVersion;
    add('bundle-version-absent', 'No bundleVersion: read as unknown, abstained on (Bundle §4). Exit 2.', noVersion, none, bundleOnly(abstain('bundle', 'unsupported_bundle_version')), 2);
    add('bundle-chain-profile', 'The chain profile, which this verifier does not implement: abstain on the whole bundle. Exit 2.', { ...json(bundleA1), profile: 'chain' }, none, bundleOnly(abstain('bundle', 'unsupported_bundle_profile')), 2);
    const noEnvelope = json(bundleA1) as unknown as Record<string, unknown>;
    delete noEnvelope.envelope;
    add('bundle-unreadable', 'A bundle with no envelope: it cannot be read. Exit 2.', noEnvelope, none, bundleOnly(wrong('bundle', 'malformed_bundle')), 2);
    // Bundle §4 step 9: a member name a row id carries never holds a lone surrogate,
    // since a report that holds one cannot be written.
    const withName = (edit: (b: Record<string, Record<string, unknown>>) => void): unknown => {
      const b = json(bundleA1) as unknown as Record<string, Record<string, unknown>>;
      edit(b);
      return b;
    };
    add('member-name-lone-surrogate', 'A top-level member named "\\ud800", a lone UTF-16 surrogate, a name a member[…] row id would carry: malformed_bundle, the only row (Bundle §4 step 9). Exit 2.',
      withName((b) => (b['\ud800'] = { reserved: true })), full, bundleOnly(wrong('bundle', 'malformed_bundle')), 2);
    add('extension-name-lone-surrogate', 'An extensions member named "\\ud800", a name an extension[…] row id would carry: malformed_bundle, the only row (Bundle §4 step 9). Exit 2.',
      withName((b) => (b.extensions['\ud800'] = { a: 1 })), full, bundleOnly(wrong('bundle', 'malformed_bundle')), 2);
    add('nonrepudiation-name-lone-surrogate', 'An envelope.nonRepudiation member named "\\ud800", a name a nonRepudiation.… row id would carry: malformed_bundle, the only row (Bundle §4 step 9). Exit 2.',
      withName((b) => ((b.envelope.nonRepudiation as Record<string, unknown>)['\ud800'] = { a: 1 })), full, bundleOnly(wrong('bundle', 'malformed_bundle')), 2);

    // ---- The SDK must agree with every row ---------------------------------------------
    const disagreements: string[] = [];
    for (const c of cases) {
      const options = {
        ...(c.inputs.publisherManifest !== null && { publisherManifest: c.inputs.publisherManifest as never }),
        evmHeaderSources: Object.fromEntries(Object.entries(c.inputs.headerSources).map(([k, v]) => [k, headerSourceOf(v)])),
        ...(c.inputs.trustAnchorsPem.length > 0 && { trustAnchorsPem: c.inputs.trustAnchorsPem }),
      };
      const { checkedAt: _t, ...actual } = await verifyBundle(json(c.bundle), options);
      const exit = bundleExitCode(actual as never, c.inputs.regime as BundleExitOptions);
      // Compared in DEO canonical form: key order is not part of a report (Verification §6.5).
      const canonical = (v: Record<string, unknown>) => canonicalSerialize(v, Object.keys(v));
      const a = canonical(actual as unknown as Record<string, unknown>);
      const e = canonical(c.report);
      if (a !== e || exit !== c.exit) {
        disagreements.push(`${c.name}: exit ${exit} (expected ${c.exit})\n  actual:   ${a}\n  expected: ${e}`);
      }
    }
    if (disagreements.length > 0) throw new Error(`verifyBundle() disagrees with the stated reports:\n${disagreements.join('\n')}`);

    // Each proof existedBy can name (Verification §6.4) is named by some case.
    const named = new Set(cases.map((c) => (c.report.summary as { existedBy: { check: string } | null }).existedBy?.check));
    const unnamed = ['ts.record.trust', 'anchor', 'anchor.newer'].filter((check) => !named.has(check));
    if (unnamed.length > 0) throw new Error(`no case's existedBy comes from ${unnamed.join(', ')}: the run's block times and genTimes are not in the order CHAIN_CLOCK_LAG_S sets`);

    // Every case is rewritten; README.md, which states the formats, is kept.
    mkdirSync(OUT, { recursive: true });
    for (const entry of readdirSync(OUT)) if (entry !== 'README.md') rmSync(join(OUT, entry), { recursive: true, force: true });
    const pretty = (v: unknown) => `${JSON.stringify(v, null, 2)}\n`;
    for (const c of cases) {
      const d = join(OUT, c.name);
      mkdirSync(d);
      writeFileSync(join(d, 'bundle.json'), pretty(c.bundle));
      writeFileSync(join(d, 'inputs.json'), pretty(c.inputs));
      writeFileSync(join(d, 'expected-report.json'), pretty(c.report));
      writeFileSync(join(d, 'expected-exit'), `${c.exit}\n`);
    }
    writeFileSync(
      join(OUT, 'index.json'),
      pretty({
        description:
          'The b1 proof-bundle corpus (Bundle §13): one directory per case, each with bundle.json, inputs.json, expected-report.json and expected-exit. README.md states the formats and how to replay a case.',
        source: `Generated by scripts/generate-bundle-b1-corpus.ts from one run of @tzun/sdk: Tzun.init({ mode: 'local', logNamespace: '${NS}', anchoring, attestation }) on anvil (${ANVIL_IMAGE}, chain id ${ANVIL_CHAIN_ID}, finalized = head - 2), publishing from anvil's development account ${PUBLISHER_ACCOUNT}, its clock ${CHAIN_CLOCK_LAG_S} s behind the wall clock, with a local RFC 3161 authority under a throwaway CA whose tokens meet Anchor §10.5 (DER, a signingCertificateV2, a critical timestamping-only extendedKeyUsage). The expected reports are stated from Verification, Bundle and Anchor §10; the script stopped unless verifyBundle() agreed with every one.`,
        cases: cases.map((c) => ({ name: c.name, exit: c.exit, description: c.description })),
      }),
    );
    process.stdout.write(`wrote ${cases.length} cases to ${OUT}\n`);
  } finally {
    for (const t of open) await t.close().catch(() => undefined);
    tsa.close();
    await node.stop();
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  process.stderr.write(`${(err as Error).stack ?? err}\n`);
  process.exit(1);
});
