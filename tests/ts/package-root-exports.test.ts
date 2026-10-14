/**
 * The anchoring API is reachable from the package root the way a consumer
 * reaches it: `require('@tzun/sdk')` resolved through
 * package.json's `main` and `types`, against the compiled package, with no
 * deep import into `dist/`.
 *
 * The suite compiles the SDK with the repository's tsconfig into a scratch
 * `node_modules/@tzun/sdk` beside a consumer, copies package.json and the
 * runtime assets `pnpm run build` copies, and links the dependencies. The
 * consumer then:
 *
 *   - type-checks a file that imports every anchoring type from '@tzun/sdk'
 *     (a missing export fails tsc), including an ethers `Wallet` and an
 *     `AbstractSigner` given as the publisher's external signer, and the
 *     proof bundle's (`exportBundle`, `verifyBundle` and its report and exit
 *     code), and
 *   - runs a script that requires '@tzun/sdk', reports the kind of every
 *     anchoring value, and uses the API: a checkpoint vector parsed, an
 *     origin written and bound, a sub-floor confirmation depth refused, a
 *     record's anchor verified to its stated verdict, and the storage seam a
 *     store kept outside the SDK implements (the publication rules, the epoch
 *     fence, the fill merge, the wallet-transaction check and the
 *     conformance kit).
 *
 * Nothing is written inside the repository.
 */
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const ROOT = resolve(__dirname, '..', '..');
const TSC = require.resolve('typescript/bin/tsc');

/** Every anchoring value the package root exports, with its kind. */
const VALUES: Record<string, 'function' | 'string' | 'number' | 'object'> = {
  verifyAnchor: 'function',
  ANCHOR_SPEC: 'string',
  parseCheckpoint: 'function',
  formatCheckpoint: 'function',
  checkpointDigest: 'function',
  isOriginText: 'function',
  parseOrigin: 'function',
  chainIdRefusal: 'function',
  chainSegment: 'function',
  chainIdFromSegment: 'function',
  anchorLogOrigin: 'function',
  evidenceLogOrigin: 'function',
  sourceLogOrigin: 'function',
  isTestNamespace: 'function',
  checkOriginBinding: 'function',
  ANCHOR_LOG_KIND: 'string',
  EVIDENCE_LOG_KIND: 'string',
  TEST_NAMESPACE_PREFIX: 'string',
  PLATFORM_NAMESPACE: 'string',
  MERKLE_SPEC: 'string',
  merkleLeafHash: 'function',
  verifyMerkleProof: 'function',
  verifyConsistencyProof: 'function',
  verifyEvmPublication: 'function',
  verifyEvmTransactionProof: 'function',
  parseEvmBlockHeader: 'function',
  RpcEvmHeaderSource: 'function',
  EthereumAnchorVerifier: 'function',
  EvmPublicationNotCheckedError: 'function',
  DEFAULT_EVM_NETWORKS: 'object',
  DEFAULT_EVM_TIMEOUT_MS: 'number',
  EVM_MIN_FINAL_CONFIRMATIONS: 'number',
  verifyAttestation: 'function',
  createAnchorScheduler: 'function',
  AnchoringConfigError: 'function',
  AnchorActivationError: 'function',
  AnchorForceRateLimitedError: 'function',
  AnchorNotLeaderError: 'function',
  AnchorSignerError: 'function',
  AnchorSignerUnavailableError: 'function',
  AnchorWalletError: 'function',
  DEFAULT_ANCHOR_CADENCE: 'object',
  DEFAULT_ANCHOR_BUDGET: 'object',
  ScheduledScanner: 'function',
  runAnchorScanPass: 'function',
  JsonRpcEvmChain: 'function',
  EvmRpcError: 'function',
  verifyBundle: 'function',
  bundleExitCode: 'function',
  comparableReport: 'function',
  UnreadableTrustAnchorError: 'function',
  BUNDLE_VERSION: 'string',
  BUNDLE_REPORT_VERSION: 'string',
  isPlatformNamespace: 'function',
  AnchorEpochFenceError: 'function',
  ANCHOR_PUBLICATION_KINDS: 'object',
  ANCHOR_PUBLICATION_STATES: 'object',
  ANCHOR_PUBLICATION_STATES_BY_KIND: 'object',
  ANCHOR_PUBLICATION_TRANSITIONS: 'object',
  isAllowedPublicationTransition: 'function',
  ANCHOR_BROADCAST_OUTCOMES: 'object',
  ANCHOR_WALLET_TX_KINDS: 'object',
  ANCHOR_FILL_CAUSE: 'string',
  REVISION_ACTOR_ANCHOR: 'string',
  filledEnvelope: 'function',
  fillStatus: 'function',
  assertAnchorWalletTx: 'function',
  readRecordLog: 'function',
  recordLogPosition: 'function',
  anchorStoreConformanceCases: 'function',
  runAnchorStoreConformance: 'function',
};

/** Every anchoring type the package root exports. */
const TYPES = [
  'AnchorArtifact',
  'AnchorPublication',
  'Rfc3161AnchorPublication',
  'AnchorVerifyOptions',
  'AnchorVerification',
  'AnchorCheckId',
  'AnchorPublicationCheckId',
  'AnchorNotCheckedReason',
  'AnchorCheckResult',
  'AnchorPublicationVerdict',
  'AnchorPosition',
  'AnchorExistedBy',
  'ChainIdRefusalReason',
  'Checkpoint',
  'CheckpointMalformedReason',
  'CheckpointParseResult',
  'TzunOrigin',
  'OriginBinding',
  'OriginBindingReason',
  'ConsistencyProofReason',
  'ConsistencyVerification',
  'EthereumAnchorVerifierConfig',
  'EthereumAnchorVerification',
  'AnchorTransaction',
  'AnchorTransactionProvider',
  'EvmPublicationReason',
  'EvmNotCheckedReason',
  'EvmCheckOutcome',
  'EvmCheckResult',
  'PublisherManifest',
  'PublisherManifestEntry',
  'EvmCalldataPublication',
  'EvmHeaderSource',
  'EvmSourceTransaction',
  'EvmPublicationInput',
  'EvmPublicationFacts',
  'EvmPublicationVerdict',
  'EvmNetwork',
  'EvmFinality',
  'EvmBlockHeader',
  'AttestationAnchorReason',
  'AnchoringConfig',
  'AnchorCadence',
  'AnchorBudget',
  'AnchorTransactionRequest',
  'AnchorTransactionSigner',
  'EvmPublisherConfig',
  'WriteOnceSink',
  'AnchorScheduler',
  'AnchorSchedulerOptions',
  'AnchorState',
  'AnchorPassReport',
  'AnchorPublicationSummary',
  'AnchorAlarm',
  'AnchorAlarmCode',
  'AnchorAlarmSeverity',
  'AccountedTransactionResult',
  'NonceAccounting',
  'VerifyAnchorOptions',
  'ScannerAttestationDeps',
  'ScannerAnchoringDeps',
  'ScannerEvmChain',
  'ScannerEvmTransaction',
  'ScannerLogScope',
  'AnchorScanCache',
  'AnchorScanCarry',
  'EvmChainClient',
  'ProofBundle',
  'BundleCheckpoint',
  'BundleLogMaterial',
  'BundlePublication',
  'BundleAnchorPending',
  'BundleVerificationReport',
  'BundleCheck',
  'BundleReportSummary',
  'VerifyBundleOptions',
  'BundleExitOptions',
  'BundleExitCode',
  'LogStore',
  'AnchorStore',
  'LogStoreProvider',
  'AnchorStoreProvider',
  'StoreIdentity',
  'LogRecord',
  'LogLeaf',
  'LogLeafSource',
  'NewLogLeaf',
  'LogPosition',
  'LogSize',
  'LeafIndexRange',
  'EvidenceLogCoverage',
  'LogCheckpoint',
  'NewLogCheckpoint',
  'LeafAnchorProgress',
  'LeafAnchorPublication',
  'AnchorPublicationKind',
  'AnchorPublicationState',
  'AnchorBroadcastOutcome',
  'AnchorPublicationAttempt',
  'StoredAnchorPublication',
  'NewAnchorPublication',
  'AnchorPublicationPatch',
  'EpochWrite',
  'EpochGuard',
  'AnchorEpochFenceReason',
  'AnchorLease',
  'AnchorWallet',
  'AnchorWalletTxKind',
  'AnchorWalletTx',
  'NewAnchorWalletTx',
  'AnchorFill',
  'AnchorFillChunk',
  'AnchorFillResult',
  'RecordLogRead',
  'AnchorStoreConformanceHarness',
  'AnchorStoreConformanceStore',
  'AnchorStoreConformanceCase',
  'AnchorStoreConformanceReport',
];

const CONSUMER_TS = `import type { ${TYPES.join(', ')} } from '@tzun/sdk';
import { EthereumAnchorVerifier, EVM_MIN_FINAL_CONFIRMATIONS, JsonRpcEvmChain, Tzun, verifyBundle, bundleExitCode, runAnchorScanPass } from '@tzun/sdk';
import { AnchorEpochFenceError, anchorStoreConformanceCases, createAnchorScheduler, readRecordLog } from '@tzun/sdk';
import { AbstractSigner, Wallet } from 'ethers';

// The publisher's key given as an external signer: an ethers Wallet, and
// any AbstractSigner (the base of KMS and HSM signers), are one.
declare const kms: AbstractSigner;
const bySigner: AnchoringConfig = { publishers: { evm: { rpcUrl: 'https://rpc.example', chain: 'eip155:11155111', signer: kms } } };
const byWallet: EvmPublisherConfig = { rpcUrl: 'https://rpc.example', chain: 'eip155:11155111', signer: Wallet.createRandom() };
const byKey: EvmPublisherConfig = { rpcUrl: 'https://rpc.example', chain: 'eip155:11155111', privateKey: '0x' };
// @ts-expect-error: a key and a signer are one or the other.
const both: EvmPublisherConfig = { rpcUrl: 'https://rpc.example', chain: 'eip155:11155111', privateKey: '0x', signer: kms };
export { bySigner, byWallet, byKey, both };

// The instance's anchoring surface.
export async function anchoring(t: Tzun): Promise<[AnchorState | null, AnchorPassReport]> {
  const options: VerifyAnchorOptions = { evmTimeoutMs: 1_000 };
  await t.verify('id', undefined, { anchor: options });
  return [await t.getAnchorState(), await t.anchorNow({ force: true })];
}

export type Surface = [${TYPES.join(', ')}];

// A proof bundle written by an instance, and verified with the auditor's own inputs.
export async function bundled(t: Tzun, options: VerifyBundleOptions): Promise<[ProofBundle, BundleVerificationReport, BundleExitCode]> {
  const bundle = await t.exportBundle('id', { exportedBy: 'auditor' });
  const report = await verifyBundle(bundle, options);
  const regime: BundleExitOptions = { allowUnchecked: true };
  return [bundle, report, bundleExitCode(report, regime)];
}

// The finality forms, and the verifier's result naming the one it judged by.
const finalities: EvmFinality[] = ['finalized', { confirmations: EVM_MIN_FINAL_CONFIRMATIONS }, { confirmations: 2, acceptNonFinal: true }];
export async function judged(v: EthereumAnchorVerifier): Promise<EvmFinality> {
  const r: EthereumAnchorVerification = await v.verifyAnchor({ chain: 'ethereum-sepolia', transactionId: '0x', p: '' });
  const reason: EvmPublicationReason | undefined = r.reason;
  void reason;
  return r.finality;
}
export { finalities };

// A server-side scanner's anchoring inputs, from the package root: the SDK's
// JSON-RPC client is a chain reader.
const reader: ScannerEvmChain = new JsonRpcEvmChain('https://rpc.example', 11155111n);
const client: EvmChainClient = new JsonRpcEvmChain('https://rpc.example', 11155111n);
const scannerDeps: ScannerAttestationDeps = { anchoring: { evmChains: { 'eip155:11155111': reader }, nonceBases: {} } };
// A deployment's pass: a scan per chain and one domain scan, sharing the pass's cache.
const carry: AnchorScanCarry = { minedTransactions: new Map() };
const scopes: ScannerLogScope[] = ['sourceLogs', 'domain'];
export const passDeps: Promise<ScannerAnchoringDeps[]> = runAnchorScanPass(
  (pass: AnchorScanCache) => scopes.map((scope) => ({ ...scannerDeps.anchoring, scope, sharedCache: pass })),
  carry,
);
// @ts-expect-error: only runAnchorScanPass makes a pass's cache.
export const madeUp: AnchorScanCache = {};
const anchoringDeps: ScannerAnchoringDeps | undefined = scannerDeps.anchoring;
export { client, anchoringDeps };

// A store kept outside the SDK: the interfaces the scheduler takes, the
// refusal its epoch guard throws, the record read over it, and the kit it is
// held to, all from the package root.
export function scheduledOver(logStore: LogStore, anchorStore: AnchorStore, options: Omit<AnchorSchedulerOptions, 'logStore' | 'anchorStore'>): Promise<AnchorScheduler> {
  const seam: Pick<AnchorSchedulerOptions, 'logStore' | 'anchorStore'> = { logStore, anchorStore };
  return createAnchorScheduler({ ...options, ...seam });
}
export function deferred(err: unknown): AnchorEpochFenceReason | null {
  return err instanceof AnchorEpochFenceError ? err.reason : null;
}
export async function stateOf(anchors: AnchorStore, logs: LogStore, envelope: Parameters<typeof readRecordLog>[0]): Promise<RecordLogRead | null> {
  const position: LogPosition | null = await logs.getEvidenceLogPosition(envelope.payload.evidenceId);
  return position ? readRecordLog(envelope, position, anchors) : null;
}
const harness: AnchorStoreConformanceHarness = {
  open: async (): Promise<AnchorStoreConformanceStore> => { throw new Error('a store of its own'); },
  without: { records: 'no capture path here' },
  fillStatusFromChunk: false,
};
export const kit: AnchorStoreConformanceCase[] = anchorStoreConformanceCases(harness);
`;

const CONSUMER_JS = `const sdk = require('@tzun/sdk');
const vectors = require(${JSON.stringify(join(ROOT, 'vectors', 'checkpoint-vectors.json'))});
const kinds = {};
for (const name of ${JSON.stringify(Object.keys(VALUES))}) kinds[name] = typeof sdk[name];

const body = vectors.bodies.valid[0];
const parsed = sdk.parseCheckpoint(body.body);
const prefix = vectors.anchorLog.domainPrefix;
const origin = sdk.evidenceLogOrigin(prefix, 'default');
const binding = sdk.checkOriginBinding(sdk.anchorLogOrigin(prefix), origin, 'default');

let floor = null;
try {
  new sdk.EthereumAnchorVerifier({
    rpcUrls: {},
    publishers: [{ address: '0x' + '11'.repeat(20), chain: 'eip155:11155111', namespace: 'test' }],
    finality: { confirmations: 2 },
  });
} catch (err) {
  floor = err.message;
}
const source = new sdk.RpcEvmHeaderSource({}, { finality: { confirmations: 2, acceptNonFinal: true } });

// The storage seam, used from the root: the constants, the fence error, the
// pure fill merge, the wallet-transaction check and the conformance kit.
const fence = new sdk.AnchorEpochFenceError('lease_not_held', 'another holder');
let walletTx = null;
try {
  sdk.assertAnchorWalletTx({ address: '0x' + '11'.repeat(20), chain: 'eip155:11155111', nonce: 0, txHash: '0x', kind: 'sweep', rawTx: '0x1234' });
} catch (err) {
  walletTx = err.message;
}
const plain = { payload: { evidenceId: 'e' }, integrity: { canonicalDigest: 'd' }, nonRepudiation: {}, attestationStatus: 'none' };
const merged = sdk.filledEnvelope(plain, { anchor: { anchorSpec: 'tzun-anchor/1' } }, { statusOf: () => 'partial' });
const seam = {
  platform: [sdk.isPlatformNamespace('log.tzun.ai'), sdk.isPlatformNamespace('test.log.tzun.ai'), sdk.isPlatformNamespace('test.log.tzun.ai.example')],
  fence: { isError: fence instanceof Error, code: fence.code, reason: fence.reason },
  transitions: [sdk.isAllowedPublicationTransition('included', 'submitted'), sdk.isAllowedPublicationTransition('finalized', 'submitted')],
  kinds: Object.keys(sdk.ANCHOR_PUBLICATION_STATES_BY_KIND),
  walletTx,
  merged: { anchor: merged.nonRepudiation.anchor, status: merged.attestationStatus, again: sdk.filledEnvelope(merged, { anchor: {} }, { statusOf: () => 'none' }) },
  cases: sdk.anchorStoreConformanceCases({ open: async () => { throw new Error('unused'); } }).length,
};

(async () => {
  const c = vectors.artifacts[0];
  const verdict = await sdk.verifyAnchor(c.artifacts, c.digest, { sequenceNumber: c.sequenceNumber, chainId: c.chainId });
  process.stdout.write(JSON.stringify({
    kinds,
    parsed: parsed.ok ? { origin: parsed.checkpoint.origin, size: parsed.checkpoint.size, root: parsed.checkpoint.root } : parsed,
    origin,
    binding,
    floor,
    sourceFinality: source.finality,
    verdict: { anchorValid: verdict.anchorValid, reason: verdict.anchorReason, p: verdict.p },
    expect: c.expect,
    body: { origin: body.origin, size: body.size, root: body.root },
    seam,
  }));
})().catch((err) => {
  process.stderr.write(String(err && err.stack || err));
  process.exit(1);
});
`;

describe('the anchoring API from the package root, as a consumer imports it', () => {
  let dir: string;
  let out: {
    kinds: Record<string, string>;
    parsed: unknown;
    origin: string;
    binding: unknown;
    floor: string | null;
    sourceFinality: unknown;
    verdict: { anchorValid: unknown; reason: unknown; p: unknown };
    expect: { anchorValid: unknown; reason: unknown; p: unknown };
    body: unknown;
    seam: {
      platform: boolean[];
      fence: { isError: boolean; code: string; reason: string };
      transitions: boolean[];
      kinds: string[];
      walletTx: string | null;
      merged: { anchor: unknown; status: string; again: unknown };
      cases: number;
    };
  };

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-package-root-'));
    const pkg = join(dir, 'node_modules', '@tzun', 'sdk');
    mkdirSync(pkg, { recursive: true });
    execFileSync(process.execPath, [TSC, '-p', join(ROOT, 'tsconfig.json'), '--outDir', join(pkg, 'dist')], { stdio: 'pipe' });
    cpSync(join(ROOT, 'src', 'attestation', 'certs'), join(pkg, 'dist', 'src', 'attestation', 'certs'), { recursive: true });
    cpSync(join(ROOT, 'package.json'), join(pkg, 'package.json'));
    symlinkSync(join(ROOT, 'node_modules'), join(pkg, 'node_modules'), 'dir');
    // The consumer's own ethers, as an integrator that builds a signer has.
    symlinkSync(join(ROOT, 'node_modules', 'ethers'), join(dir, 'node_modules', 'ethers'), 'dir');

    writeFileSync(join(dir, 'consumer.ts'), CONSUMER_TS);
    execFileSync(
      process.execPath,
      [TSC, '--noEmit', '--strict', '--skipLibCheck', '--esModuleInterop', '--module', 'commonjs', '--moduleResolution', 'node', '--target', 'es2020', 'consumer.ts'],
      { cwd: dir, stdio: 'pipe' },
    );

    writeFileSync(join(dir, 'consumer.js'), CONSUMER_JS);
    out = JSON.parse(execFileSync(process.execPath, ['consumer.js'], { cwd: dir, encoding: 'utf8' }));
  }, 180_000);

  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("resolves '@tzun/sdk' through package.json's main and types", () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
    expect(pkg.main).toBe('dist/src/sdk/index.js');
    expect(pkg.types).toBe('dist/src/sdk/index.d.ts');
    // The consumer's tsc run in beforeAll resolved every type in TYPES there.
    expect(TYPES.length).toBeGreaterThan(40);
  });

  it.each(Object.entries(VALUES))('exports %s (a %s)', (name, kind) => {
    expect(out.kinds[name]).toBe(kind);
  });

  it('parses a checkpoint vector and writes and binds an origin', () => {
    expect(out.parsed).toEqual(out.body);
    expect(out.origin.endsWith('/evidence/64656661756c74')).toBe(true);
    expect(out.binding).toEqual({ ok: true, namespace: 'local.invalid', chainChecked: true });
  });

  it('refuses a sub-floor confirmation depth, and states an accepted one', () => {
    expect(out.floor).toMatch(/acceptNonFinal/);
    expect(out.sourceFinality).toEqual({ confirmations: 2, acceptNonFinal: true });
  });

  it('uses the storage seam a store kept outside the SDK implements: its rules, its refusal, its fill merge and its kit', () => {
    expect(out.seam).toEqual({
      platform: [true, true, false],
      fence: { isError: true, code: 'anchor_epoch_fenced', reason: 'lease_not_held' },
      transitions: [true, false],
      kinds: ['evm-calldata/1', 'rfc3161/1'],
      walletTx: expect.stringMatching(/rawTx is not a signed transaction/),
      merged: { anchor: { anchorSpec: 'tzun-anchor/1' }, status: 'partial', again: null },
      cases: expect.any(Number),
    });
    expect(out.seam.cases).toBeGreaterThan(40);
  });

  it("verifies a record's anchor to the vector's stated verdict", () => {
    expect(out.verdict).toEqual({ anchorValid: out.expect.anchorValid, reason: out.expect.reason, p: out.expect.p });
  });
});
