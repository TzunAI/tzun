/**
 * `verifyBundle()` and `bundleExitCode()` (Verification §2, §6; Bundle §3,
 * §5 to §8; tzun-anchor/1 §10): a `b1` bundle verified with nothing but the
 * bundle and the auditor's own inputs, each check one of the four outcomes,
 * reported in the shape of Verification §6.1, and the exit codes 0 to 4 with
 * their precedence (Verification §6.6).
 *
 * The bundles come from a store anchored by the real scheduler on the
 * in-memory EVM chain (tests/ts/helpers/bundle-fixtures.ts); the header source
 * is that chain, as an auditor's own node would be.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Wallet, decodeRlp, encodeRlp, keccak256, toBeHex } from 'ethers';
import {
  bundleExitCode,
  comparableReport,
  verifyBundle,
  BUNDLE_REPORT_VERSION,
  UnreadableTrustAnchorError,
  type BundleVerificationReport,
  type ProofBundle,
} from '../../src/sdk/index';
import {
  canonicalSerialize,
  computeDigest,
  EvidenceChain,
  SchemaRegistry,
  signoffStatementChallenge,
  signoffStatementDigest,
} from '@tzun/engine';
import { formatCheckpoint, parseCheckpoint } from '../../src/attestation/checkpoint';
import { buildMerkleTree, getConsistencyProof, getMerkleProof, getMerkleRoot } from '../../src/attestation/merkle';
import { buildTxTrie } from '../../src/anchoring/tx-trie';
import { makeTsaFixture, withUnreadableKey } from './rfc3161-fixture';
import { makeGenuineAssertion } from './attestation-assertion-helpers';
import { anchoredStore, BUNDLE_CHAIN, fakeHeaderSource, sqliteBundleBackend, type AnchoredStore } from './helpers/bundle-fixtures';

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
// A bundle as a verifier receives it: parsed from its file.
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const rows = (r: BundleVerificationReport) => r.checks.map((c) => [c.id, c.outcome, c.reason ?? null]);
const find = (r: BundleVerificationReport, id: string) => r.checks.find((c) => c.id === id);

function parsed(body: string) {
  const r = parseCheckpoint(body);
  if (!r.ok) throw new Error(r.reason);
  return r.checkpoint;
}

/** The payload's digest under v1.0, and the link to `previous`. */
function reseal(bundle: ProofBundle, previous: string | null): void {
  const schema = new SchemaRegistry().get(bundle.envelope.payload.schemaVersion)!;
  const digest = computeDigest(canonicalSerialize(bundle.envelope.payload as unknown as Record<string, unknown>, schema.hashedFieldSet));
  bundle.envelope.integrity.canonicalDigest = digest;
  if (previous !== null) {
    const chain = new EvidenceChain();
    chain.restore(previous);
    bundle.envelope.integrity.chainLink = chain.computeLink(digest);
  }
  bundle.subject.canonicalDigest = digest;
}

describe('verifyBundle()', () => {
  jest.setTimeout(120_000);
  const backend = sqliteBundleBackend();
  let store: AnchoredStore;
  let r1: string;
  let r2: string;
  let r3: string;
  let rOther: string;
  let r4: string;
  let logOrigin: string;
  let anchorOrigin: string;
  let good: ProofBundle;
  const auditor = () => ({ publisherManifest: manifest, evmHeaderSources: { [BUNDLE_CHAIN]: fakeHeaderSource(store.chain) } });
  let manifest: Awaited<ReturnType<AnchoredStore['manifest']>>;

  beforeAll(async () => {
    store = await anchoredStore(await backend.fresh());
    [r1, r2] = await store.capture(2);
    await store.epoch();
    [r3] = await store.capture(1);
    const other = await store.on('other');
    [rOther] = await store.capture(1, other, 'other');
    await store.epoch();
    [r4] = await store.capture(1);
    manifest = await store.manifest();
    anchorOrigin = await store.anchorOrigin();
    good = await store.tzun.exportBundle(r1);
    logOrigin = parsed(good.envelope.nonRepudiation.anchor!.logCheckpoint).origin;
  });

  afterAll(async () => {
    await store.close();
    backend.dispose();
  });

  it('holds a genuine anchored bundle with the manifest and a header source: every check correct, exit 0', async () => {
    expect(Object.keys(good.anchoring).sort()).toEqual([anchorOrigin, logOrigin].sort());
    const report = await verifyBundle(good, auditor());
    expect(rows(report)).toEqual([
      ['bundle', 'checked-correct', null],
      ['subject', 'checked-correct', null],
      ['record.digest', 'checked-correct', null],
      ['record.chainLink', 'checked-correct', null],
      ['custody.ledger', 'not-checked', 'not_applicable'],
      ['ts.record.token', 'not-checked', 'absent'],
      ['ts.record.trust', 'not-checked', 'absent'],
      ['signoff.expectation', 'checked-correct', null],
      ['signoff.key', 'not-checked', 'absent'],
      ['decider', 'checked-correct', null],
      ['decider.freshness', 'not-checked', 'absent'],
      ['contributions', 'not-checked', 'absent'],
      ['contributions.binding', 'not-checked', 'absent'],
      ['links', 'not-checked', 'absent'],
      ['anchor', 'checked-correct', null],
      ['anchor.spec', 'checked-correct', null],
      ['anchor.checkpoint', 'checked-correct', null],
      ['anchor.origin', 'checked-correct', null],
      ['anchor.leafIndex', 'checked-correct', null],
      ['anchor.inclusion', 'checked-correct', null],
      ['anchor.anchorInclusion', 'checked-correct', null],
      ['anchor.publication[0]', 'checked-correct', null],
      ['anchor.evm.tx[0]', 'checked-correct', null],
      ['anchor.evm.canonical[0]', 'checked-correct', null],
      ['anchor.newer', 'checked-correct', null],
      [`anchor.consistency[${anchorOrigin}]`, 'checked-correct', null],
      [`anchor.consistency[${logOrigin}]`, 'checked-correct', null],
    ]);
    expect(bundleExitCode(report)).toBe(0);
    expect(report.reportVersion).toBe(BUNDLE_REPORT_VERSION);
    expect(report.bundleVersion).toBe('b1');
    expect(report.subject).toEqual(good.subject);

    // Facts, re-derived.
    expect(find(report, 'anchor.origin')?.facts).toEqual({ originAuthenticated: true, namespace: 'test', chainChecked: true });
    expect(find(report, 'anchor.leafIndex')?.facts).toEqual({ leafIndexChecked: true });
    const pub = good.anchoring[anchorOrigin].checkpoints[0].publications![0] as { transactionId: string };
    expect(find(report, 'anchor.evm.tx[0]')?.facts).toEqual({
      transactionId: pub.transactionId,
      txType: 2,
      sender: store.publisher.address.toLowerCase(),
      signedChainId: '31337',
    });
    expect(find(report, 'anchor.evm.canonical[0]')?.facts).toMatchObject({
      chain: BUNDLE_CHAIN,
      namespace: 'test',
      network: null,
      inclusion: 'tx_proof',
      finality: 'finalized',
      blockTime: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
    });
    expect(find(report, 'anchor.newer')?.facts).toEqual({ treeSize: 3, anchorSize: 3 });
    expect(find(report, `anchor.consistency[${logOrigin}]`)?.facts).toEqual({ fromSize: 2, toSize: 3 });
    expect(find(report, `anchor.consistency[${anchorOrigin}]`)?.facts).toEqual({ fromSize: 1, toSize: 3 });

    // The summary is derived: the earliest proven bound is the record's own anchor.
    expect(report.summary).toMatchObject({
      mode: null,
      rungs: [],
      actorBound: null,
      anchorNetwork: null,
      anchorNamespace: 'test',
      anchorOriginAuthenticated: true,
      existedBy: { source: 'evm-calldata', check: 'anchor', at: find(report, 'anchor.evm.canonical[0]')!.facts!.blockTime },
      // The record-rule rows: the decider holds; its freshness, contributions,
      // the binding and links are absent.
      outcomes: { 'checked-correct': 19, 'checked-wrong': 0, 'not-checked': 8, abstain: 0 },
    });
    // The inputs, as fingerprints and digests.
    expect(report.inputs).toEqual({
      trustAnchors: [],
      evmHeaderSources: [{ chain: BUNDLE_CHAIN, finality: 'finalized' }],
      publisherManifest: sha256(canonicalSerialize(manifest as unknown as Record<string, unknown>, Object.keys(manifest))),
      frameOrigins: null,
      vkeys: null,
      mdsRoots: null,
    });
  });

  it('reports the same bundle offline as not checked, exit 4, and 0 with allowUnchecked (Verification §6.6)', async () => {
    const report = await verifyBundle(good);
    expect(find(report, 'anchor')).toEqual({ id: 'anchor', outcome: 'not-checked', reason: 'publication_not_checked' });
    expect(find(report, 'anchor.evm.tx[0]')).toMatchObject({ outcome: 'not-checked', reason: 'no_expectation:publisher' });
    expect(find(report, 'anchor.newer')).toMatchObject({ outcome: 'not-checked', reason: 'publication_not_checked' });
    expect(find(report, `anchor.consistency[${logOrigin}]`)).toEqual({ id: `anchor.consistency[${logOrigin}]`, outcome: 'not-checked', reason: 'blocked_by:anchor' });
    expect(report.summary).toMatchObject({ existedBy: null, anchorOriginAuthenticated: false, anchorNamespace: 'test' });
    expect(bundleExitCode(report)).toBe(4);
    expect(bundleExitCode(report, { allowUnchecked: true })).toBe(0);

    // With the manifest and no header source: the transaction's facts hold,
    // and the publication is not checked (a fabricated header proves nothing).
    const withManifest = await verifyBundle(good, { publisherManifest: manifest });
    expect(find(withManifest, 'anchor.evm.tx[0]')).toMatchObject({ outcome: 'checked-correct' });
    expect(find(withManifest, 'anchor.evm.canonical[0]')).toMatchObject({ outcome: 'not-checked', reason: 'input_not_supplied:evm_header_source' });
    expect(bundleExitCode(withManifest)).toBe(4);
  });

  it('holds a record anchored in the newest epoch with one checkpoint per log', async () => {
    const r3Bundle = await store.tzun.exportBundle(r3);
    const report = await verifyBundle(r3Bundle, auditor());
    expect(report.checks.map((c) => c.id)).not.toContain('anchor.newer');
    expect(report.checks.some((c) => c.id.startsWith('anchor.consistency'))).toBe(false);
    expect(find(report, 'record.chainLink')).toMatchObject({ outcome: 'checked-correct' });
    expect(bundleExitCode(report)).toBe(0);
    // With one authenticated body per log there is nothing to compare, so a
    // regime that requires a consistency check is not met.
    expect(bundleExitCode(report, { require: [`anchor.consistency[${logOrigin}]`] })).toBe(3);
  });

  it('reports an unanchored record as anchor.pending not_yet_published, exit 4, 0 with allowUnchecked (Bundle §7.7)', async () => {
    const report = await verifyBundle(await store.tzun.exportBundle(r4), auditor());
    expect(find(report, 'anchor')).toEqual({ id: 'anchor', outcome: 'not-checked', reason: 'absent' });
    expect(find(report, 'anchor.pending')).toEqual({ id: 'anchor.pending', outcome: 'not-checked', reason: 'not_yet_published' });
    expect(bundleExitCode(report)).toBe(4);
    expect(bundleExitCode(report, { allowUnchecked: true })).toBe(0);
  });

  it('fails a payload edited under its digest at record.digest, once, and blocks the anchor on it', async () => {
    const b = clone(good);
    b.envelope.payload.reason = 'edited';
    const report = await verifyBundle(b, auditor());
    expect(find(report, 'record.digest')).toEqual({ id: 'record.digest', outcome: 'checked-wrong', reason: 'digest_mismatch' });
    expect(find(report, 'anchor')).toMatchObject({ outcome: 'not-checked', reason: 'blocked_by:record.digest' });
    expect(find(report, 'anchor.inclusion')).toMatchObject({ outcome: 'not-checked', reason: 'blocked_by:record.digest' });
    expect(find(report, 'anchor.newer')).toMatchObject({ outcome: 'not-checked', reason: 'blocked_by:record.digest' });
    expect(report.checks.filter((c) => c.outcome === 'checked-wrong')).toHaveLength(1);
    expect(bundleExitCode(report)).toBe(1);
  });

  // Verification §2.2: an unknown tag makes the verifier abstain on its
  // section. The envelope's tag says how its members are read, and this
  // verifier reads e1 alone, so another tag, null or none abstains at
  // record.digest, and everything that takes the digest as input is blocked
  // by it.
  it.each([
    ['another tag', (b: ProofBundle) => { (b.envelope as { envelopeVersion: unknown }).envelopeVersion = 'e2'; }],
    ['null', (b: ProofBundle) => { (b.envelope as { envelopeVersion: unknown }).envelopeVersion = null; }],
    ['no tag', (b: ProofBundle) => { delete (b.envelope as { envelopeVersion?: unknown }).envelopeVersion; }],
  ])('abstains on an envelope whose envelopeVersion is not e1 (%s): exit 4, never a pass', async (_what, edit) => {
    const b = clone(good);
    edit(b);
    const report = await verifyBundle(b, auditor());
    expect(find(report, 'record.digest')).toEqual({ id: 'record.digest', outcome: 'abstain', reason: 'unsupported_envelope_version' });
    for (const id of ['signoff.expectation', 'anchor', 'anchor.inclusion', 'anchor.newer']) {
      expect(find(report, id)).toMatchObject({ outcome: 'not-checked', reason: 'blocked_by:record.digest' });
    }
    expect(report.checks.some((c) => c.outcome === 'checked-wrong')).toBe(false);
    expect(report.summary.existedBy).toBeNull();
    expect(bundleExitCode(report)).toBe(4);
  });

  it('fails a rewrite-and-reseat (payload, digest and link recomputed) at the anchor inclusion', async () => {
    const b = clone(await store.tzun.exportBundle(r2));
    b.envelope.payload.reason = 'rewritten';
    reseal(b, b.chain.predecessor!.canonicalDigest);
    const report = await verifyBundle(b, auditor());
    expect(find(report, 'record.digest')).toMatchObject({ outcome: 'checked-correct' });
    expect(find(report, 'record.chainLink')).toMatchObject({ outcome: 'checked-correct' });
    expect(find(report, 'anchor')).toEqual({ id: 'anchor', outcome: 'checked-wrong', reason: 'merkle_proof_invalid' });
    expect(find(report, 'anchor.inclusion')).toEqual({ id: 'anchor.inclusion', outcome: 'checked-wrong', reason: 'merkle_proof_invalid' });
    expect(find(report, 'anchor.anchorInclusion')).toMatchObject({ reason: 'blocked_by:anchor.inclusion' });
    expect(bundleExitCode(report)).toBe(1);
  });

  it('fails an artifact transplanted from another leaf of the chain, and from another chain', async () => {
    const leaf = clone(good);
    leaf.envelope.nonRepudiation.anchor = clone((await store.tzun.exportBundle(r2)).envelope.nonRepudiation.anchor);
    const byLeaf = await verifyBundle(leaf, auditor());
    expect(find(byLeaf, 'anchor')).toMatchObject({ outcome: 'checked-wrong', reason: 'leaf_index_mismatch' });
    expect(find(byLeaf, 'anchor.leafIndex')).toMatchObject({ outcome: 'checked-wrong', reason: 'leaf_index_mismatch' });
    // The store's own material still anchors the subject: the composed anchor holds.
    expect(find(byLeaf, 'anchor.newer')).toMatchObject({ outcome: 'checked-correct' });
    expect(bundleExitCode(byLeaf)).toBe(1);

    const chain = clone(good);
    chain.envelope.nonRepudiation.anchor = clone((await store.tzun.exportBundle(rOther)).envelope.nonRepudiation.anchor);
    const byChain = await verifyBundle(chain, auditor());
    expect(find(byChain, 'anchor.origin')).toMatchObject({ outcome: 'checked-wrong', reason: 'chain_id_mismatch' });
    expect(bundleExitCode(byChain)).toBe(1);
  });

  it('fails a bundle whose raw transaction is not the envelope\'s, and one whose header was fabricated, once a header source reads the chain', async () => {
    const raw = clone(good);
    const entry = raw.anchoring[anchorOrigin].checkpoints[0].publications![0] as unknown as Record<string, unknown>;
    // Another transaction, joined by the bundle's own claim: keccak(raw) is not the envelope's id.
    entry.rawTransaction = (raw.anchoring[anchorOrigin].checkpoints[1].publications![0] as { rawTransaction: string }).rawTransaction;
    const rawReport = await verifyBundle(raw, auditor());
    // The join finds no material for the envelope's transaction id.
    expect(find(rawReport, 'anchor.evm.tx[0]')).toMatchObject({ outcome: 'not-checked', reason: 'not_in_bundle:raw_transaction' });
    expect(bundleExitCode(rawReport)).toBe(4);

    // A header whose timestamp was moved: offline, its hash is not the block's.
    const fabricated = clone(good);
    const fe = fabricated.anchoring[anchorOrigin].checkpoints[0].publications![0] as { blockHeader: string };
    fe.blockHeader = `${fe.blockHeader.slice(0, -2)}${fe.blockHeader.slice(-2) === '00' ? '01' : '00'}`;
    const fabReport = await verifyBundle(fabricated, { publisherManifest: manifest });
    expect(find(fabReport, 'anchor.evm.tx[0]')).toMatchObject({ outcome: 'checked-wrong', reason: 'evm_tx_proof_invalid' });
    expect(bundleExitCode(fabReport)).toBe(1);
  });

  it('never counts a self-consistent fabricated header offline, and fails it against the auditor\'s own header source', async () => {
    // A back-dated header whose hash the forger writes into both the envelope
    // and the bundle: the transaction's offline facts still hold (tzun-anchor/1
    // §10.4), so only the header source can tell.
    const b = clone(good);
    const entry = b.anchoring[anchorOrigin].checkpoints[0].publications![0] as { blockHeader: string; blockHash: string };
    const fields = decodeRlp(entry.blockHeader) as string[];
    fields[11] = toBeHex(BigInt(fields[11]) - 86_400n);
    entry.blockHeader = encodeRlp(fields);
    entry.blockHash = keccak256(entry.blockHeader).toLowerCase();
    (b.envelope.nonRepudiation.anchor!.publications[0] as { blockHash: string }).blockHash = entry.blockHash;

    const offline = await verifyBundle(b, { publisherManifest: manifest });
    expect(find(offline, 'anchor.evm.tx[0]')).toMatchObject({ outcome: 'checked-correct' });
    expect(find(offline, 'anchor.evm.canonical[0]')).toMatchObject({ outcome: 'not-checked', reason: 'input_not_supplied:evm_header_source' });
    expect(find(offline, 'anchor')).toMatchObject({ outcome: 'not-checked', reason: 'publication_not_checked' });
    expect(offline.summary.existedBy).toBeNull();
    expect(bundleExitCode(offline)).toBe(4);

    const checked = await verifyBundle(b, auditor());
    expect(find(checked, 'anchor.evm.canonical[0]')).toMatchObject({ outcome: 'checked-wrong', reason: 'anchor_not_found_on_chain' });
    expect(find(checked, 'anchor')).toMatchObject({ outcome: 'checked-wrong', reason: 'anchor_not_found_on_chain' });
    expect(checked.summary.existedBy).toMatchObject({ check: 'anchor.newer' });
    expect(bundleExitCode(checked)).toBe(1);
  });

  it('fails a publication whose chain or sender is not the manifest\'s, and does not check one the manifest does not name', async () => {
    const wrongChain = { publishers: { [anchorOrigin]: [{ ...manifest.publishers[anchorOrigin][0], chain: 'eip155:1' }] } };
    const byChain = await verifyBundle(good, { publisherManifest: wrongChain, evmHeaderSources: { [BUNDLE_CHAIN]: fakeHeaderSource(store.chain) } });
    expect(find(byChain, 'anchor.evm.tx[0]')).toMatchObject({ outcome: 'checked-wrong', reason: 'evm_chain_mismatch' });
    expect(bundleExitCode(byChain)).toBe(1);

    const stranger = Wallet.createRandom().address.toLowerCase();
    const wrongSender = { publishers: { [anchorOrigin]: [{ ...manifest.publishers[anchorOrigin][0], address: stranger }] } };
    const bySender = await verifyBundle(good, { ...auditor(), publisherManifest: wrongSender });
    expect(find(bySender, 'anchor.evm.tx[0]')).toMatchObject({ outcome: 'checked-wrong', reason: 'evm_sender_mismatch' });
    expect(bundleExitCode(bySender)).toBe(1);

    const unnamed = await verifyBundle(good, { evmHeaderSources: { [BUNDLE_CHAIN]: fakeHeaderSource(store.chain) } });
    expect(find(unnamed, 'anchor.evm.tx[0]')).toMatchObject({ outcome: 'not-checked', reason: 'no_expectation:publisher' });
    expect(bundleExitCode(unnamed)).toBe(4);
  });

  it('does not count a block above the header source\'s finalized height', async () => {
    const pub = good.envelope.nonRepudiation.anchor!.publications[0] as { blockNumber: number };
    const report = await verifyBundle(good, { publisherManifest: manifest, evmHeaderSources: { [BUNDLE_CHAIN]: fakeHeaderSource(store.chain, pub.blockNumber - 1) } });
    expect(find(report, 'anchor.evm.canonical[0]')).toMatchObject({ outcome: 'not-checked', reason: 'evm_block_not_finalized', facts: { finality: 'finalized' } });
    expect(find(report, 'anchor')).toMatchObject({ outcome: 'not-checked', reason: 'publication_not_checked' });
    expect(bundleExitCode(report)).toBe(4);
  });

  it('abstains on a forged future anchorSpec: exit 4, never a pass (Verification §6.6)', async () => {
    const b = clone(good);
    (b.envelope.nonRepudiation.anchor as unknown as { anchorSpec: string }).anchorSpec = 'tzun-anchor/2';
    const report = await verifyBundle(b, auditor());
    expect(find(report, 'anchor')).toEqual({ id: 'anchor', outcome: 'abstain', reason: 'unsupported_anchor_spec' });
    expect(find(report, 'anchor.spec')).toEqual({ id: 'anchor.spec', outcome: 'abstain', reason: 'unsupported_anchor_spec' });
    expect(bundleExitCode(report)).toBe(4);
    expect(bundleExitCode(report, { allowUnchecked: true })).toBe(0);
  });

  it('checks consistency only between authenticated bodies, and fails a broken proof', async () => {
    const broken = clone(good);
    const proof = broken.anchoring[anchorOrigin].consistency[0];
    proof.path[0] = proof.path[0].replace(/^./, (c) => (c === '0' ? '1' : '0'));
    const brokenReport = await verifyBundle(broken, auditor());
    expect(find(brokenReport, `anchor.consistency[${anchorOrigin}]`)).toEqual({
      id: `anchor.consistency[${anchorOrigin}]`,
      outcome: 'checked-wrong',
      reason: 'log_inconsistent_with_anchor',
    });
    expect(bundleExitCode(brokenReport)).toBe(1);

    const missing = clone(good);
    missing.anchoring[logOrigin].consistency = [];
    const missingReport = await verifyBundle(missing, auditor());
    expect(find(missingReport, `anchor.consistency[${logOrigin}]`)).toMatchObject({ outcome: 'not-checked', reason: 'not_in_bundle:consistency_proof' });
    expect(bundleExitCode(missingReport)).toBe(4);

    // A newer anchor path that does not verify: anchor.newer fails, and the
    // consistency it would have authenticated is blocked by it.
    const newer = clone(good);
    const entry = newer.anchoring[logOrigin].checkpoints[1];
    entry.anchorPath![0] = entry.anchorPath![0].replace(/^./, (c) => (c === '0' ? '1' : '0'));
    const newerReport = await verifyBundle(newer, auditor());
    expect(find(newerReport, 'anchor.newer')).toEqual({ id: 'anchor.newer', outcome: 'checked-wrong', reason: 'anchor_proof_invalid' });
    expect(find(newerReport, `anchor.consistency[${logOrigin}]`)).toMatchObject({ outcome: 'not-checked', reason: 'blocked_by:anchor.newer' });
    expect(bundleExitCode(newerReport)).toBe(1);
  });

  /**
   * A second history of the subject's log, `leaves` with the subject at leaf
   * 0, taken into a second history of the anchor log that extends the genuine
   * one at size 1, and published by the store's own key: the evidence-log
   * entry that carries the subject's anchor into it, and the anchor log's
   * material (the genuine checkpoint, the forged one with its publication, and
   * the proof between them). Every anchor over it holds.
   */
  async function forgedHistory(b: ProofBundle, leaves: string[]) {
    const ownLogBody = b.envelope.nonRepudiation.anchor!.logCheckpoint;
    const ownAnchorEntry = b.anchoring[anchorOrigin].checkpoints[0];
    expect(ownAnchorEntry.body).toBe(b.envelope.nonRepudiation.anchor!.anchorCheckpoint);
    expect(getMerkleRoot(buildMerkleTree([sha256(ownLogBody)]))).toBe(parsed(ownAnchorEntry.body).root);
    const forgedTree = buildMerkleTree(leaves);
    const forgedLog = formatCheckpoint(logOrigin, leaves.length, getMerkleRoot(forgedTree));
    const anchorTree = buildMerkleTree([sha256(ownLogBody), sha256(forgedLog)]);
    const forgedAnchor = formatCheckpoint(anchorOrigin, 2, getMerkleRoot(anchorTree));
    const txId = await store.chain.sendExternal(store.publisher, `0x${sha256(forgedAnchor)}`);
    store.chain.mine(4);
    const receipt = (await store.chain.receipt(txId))!;
    const material = await store.chain.blockMaterial(receipt.blockNumber);
    const consistency = getConsistencyProof(anchorTree, 1, 2);
    if (!consistency.ok) throw new Error('no proof');
    return {
      forgedTree,
      logEntry: {
        body: forgedLog,
        signatures: [] as string[],
        logPath: getMerkleProof(forgedTree, 0),
        anchorLeafIndex: 1,
        anchorSize: 2,
        anchorPath: getMerkleProof(anchorTree, 1),
      },
      anchorMaterial: {
        checkpoints: [
          ownAnchorEntry,
          {
            body: forgedAnchor,
            signatures: [] as string[],
            publications: [
              {
                kind: 'evm-calldata/1' as const,
                chain: BUNDLE_CHAIN,
                transactionId: txId.toLowerCase(),
                blockNumber: receipt.blockNumber,
                blockHash: receipt.blockHash,
                publisher: store.publisher.address.toLowerCase(),
                rawTransaction: material.rawTransactions[receipt.transactionIndex],
                blockHeader: material.headerRlp,
                txIndex: receipt.transactionIndex,
                txProof: buildTxTrie(material.rawTransactions).proof(receipt.transactionIndex),
              },
            ],
          },
        ],
        consistency: [{ fromSize: 1, toSize: 2, path: consistency.proof }],
      },
    };
  }

  it('reports a split view the publisher key signed: two authenticated bodies of one size with different roots', async () => {
    // A second history of the subject's log at size 2, with the subject at
    // leaf 0 and another leaf after it. The two bodies cannot both be the log.
    const b = clone(good);
    const forged = await forgedHistory(b, [b.subject.canonicalDigest, sha256('another history')]);
    b.anchoring[logOrigin] = { checkpoints: [b.anchoring[logOrigin].checkpoints[0], forged.logEntry], consistency: [] };
    b.anchoring[anchorOrigin] = forged.anchorMaterial;
    const report = await verifyBundle(b, auditor());
    expect(find(report, 'anchor')).toMatchObject({ outcome: 'checked-correct' });
    expect(find(report, 'anchor.newer')).toMatchObject({ outcome: 'checked-correct', facts: { treeSize: 2, anchorSize: 2 } });
    expect(find(report, `anchor.consistency[${anchorOrigin}]`)).toMatchObject({ outcome: 'checked-correct' });
    expect(find(report, `anchor.consistency[${logOrigin}]`)).toEqual({ id: `anchor.consistency[${logOrigin}]`, outcome: 'checked-wrong', reason: 'split_view' });
    expect(bundleExitCode(report)).toBe(1);
  });

  it('compares the bodies it authenticated whatever the bundle lists: a split view with the record\'s own checkpoint left out', async () => {
    // The envelope's anchor still names the record's own checkpoint, and
    // authenticates it; the composed anchor authenticates the forged one.
    const b = clone(good);
    const forged = await forgedHistory(b, [b.subject.canonicalDigest, sha256('another history, own left out')]);
    b.anchoring[logOrigin] = { checkpoints: [forged.logEntry], consistency: [] };
    b.anchoring[anchorOrigin] = forged.anchorMaterial;
    const report = await verifyBundle(b, auditor());
    expect(find(report, 'anchor')).toMatchObject({ outcome: 'checked-correct' });
    expect(find(report, 'anchor.newer')).toMatchObject({ outcome: 'checked-correct' });
    expect(find(report, `anchor.consistency[${logOrigin}]`)).toEqual({ id: `anchor.consistency[${logOrigin}]`, outcome: 'checked-wrong', reason: 'split_view' });
    expect(bundleExitCode(report)).toBe(1);
    expect(bundleExitCode(report, { require: ['anchor', 'anchor.newer'] })).toBe(1);
  });

  it('does not pass a rewrite after the record was anchored when the bundle leaves out the record\'s own checkpoint', async () => {
    // A larger history of the subject's log whose first two leaves are not
    // the ones the record's own checkpoint committed to.
    const b = clone(good);
    const forged = await forgedHistory(b, [b.subject.canonicalDigest, sha256('rewritten second leaf'), sha256('third leaf')]);
    b.anchoring[logOrigin] = { checkpoints: [forged.logEntry], consistency: [] };
    b.anchoring[anchorOrigin] = forged.anchorMaterial;
    const report = await verifyBundle(b, auditor());
    expect(find(report, 'anchor.newer')).toMatchObject({ outcome: 'checked-correct', facts: { treeSize: 3, anchorSize: 2 } });
    expect(find(report, `anchor.consistency[${logOrigin}]`)).toEqual({
      id: `anchor.consistency[${logOrigin}]`,
      outcome: 'not-checked',
      reason: 'not_in_bundle:consistency_proof',
    });
    expect(bundleExitCode(report)).toBe(4);
    expect(bundleExitCode(report, { require: ['anchor', 'anchor.newer'] })).toBe(4);

    // With a proof from the forged history's own prefix: it does not hold over the record's own root.
    const proof = getConsistencyProof(forged.forgedTree, 2, 3);
    if (!proof.ok) throw new Error('no proof');
    const proved = clone(b);
    proved.anchoring[logOrigin].consistency = [{ fromSize: 2, toSize: 3, path: proof.proof }];
    const provedReport = await verifyBundle(proved, auditor());
    expect(find(provedReport, `anchor.consistency[${logOrigin}]`)).toMatchObject({ outcome: 'checked-wrong', reason: 'log_inconsistent_with_anchor' });
    expect(bundleExitCode(provedReport)).toBe(1);
  });

  it('refuses anchoring keys that are not their bodies\' origins, a checkpoint carried twice, and the subject\'s anchor on an anchor-log checkpoint', async () => {
    const malformed = (r: BundleVerificationReport) => {
      expect(r.checks).toEqual([{ id: 'bundle', outcome: 'checked-wrong', reason: 'malformed_bundle' }]);
      expect(bundleExitCode(r, { require: ['anchor', 'anchor.newer', `anchor.consistency[${logOrigin}]`] })).toBe(2);
    };
    // The anchor log's pair under the evidence log's key, and a forged newer
    // evidence checkpoint under any other key.
    const b = clone(good);
    const forged = await forgedHistory(b, [b.subject.canonicalDigest, sha256('relabelled history')]);
    const relabelled = clone(b) as unknown as { anchoring: Record<string, unknown> };
    relabelled.anchoring = {
      [logOrigin]: clone(forged.anchorMaterial),
      [anchorOrigin]: clone(forged.anchorMaterial),
      'zz-anything': { checkpoints: [forged.logEntry], consistency: [] },
    };
    malformed(await verifyBundle(relabelled, auditor()));

    // Two logs' material swapped between their keys.
    const swapped = clone(good);
    [swapped.anchoring[logOrigin], swapped.anchoring[anchorOrigin]] = [swapped.anchoring[anchorOrigin], swapped.anchoring[logOrigin]];
    malformed(await verifyBundle(swapped, auditor()));

    // The same checkpoint twice in one log.
    const twice = clone(await store.tzun.exportBundle(r3));
    const r3Log = Object.keys(twice.anchoring).find((k) => k !== anchorOrigin)!;
    twice.anchoring[r3Log].checkpoints.push({ body: twice.anchoring[r3Log].checkpoints[0].body, signatures: [] });
    malformed(await verifyBundle(twice, auditor()));

    // The subject's anchor into the newest checkpoint stated on an anchor-log checkpoint.
    const onAnchorLog = clone(good);
    const composedEntry = onAnchorLog.anchoring[logOrigin].checkpoints[1];
    const { logPath, anchorLeafIndex, anchorSize, anchorPath } = composedEntry;
    for (const m of ['logPath', 'anchorLeafIndex', 'anchorSize', 'anchorPath'] as const) delete composedEntry[m];
    Object.assign(onAnchorLog.anchoring[anchorOrigin].checkpoints[1], { logPath, anchorLeafIndex, anchorSize, anchorPath });
    malformed(await verifyBundle(onAnchorLog, auditor()));

    // A checkpoint body that does not parse.
    const unparsed = clone(good);
    unparsed.anchoring[logOrigin].checkpoints[0].body = `${logOrigin}\n2\nnot base64\n`;
    malformed(await verifyBundle(unparsed, auditor()));
  });

  describe('custody.ledger: never checked-correct, since this version verifies no custody material (Verification §4.3, Bundle §6)', () => {
    type Loose = Record<string, unknown> & { custody: unknown; envelope: Record<string, unknown> };
    const MIRROR = { entryHash: 'ab'.repeat(32), action: 'relink' };
    const custodyRow = async (edit: (b: Loose) => void) => {
      const b = clone(good) as unknown as Loose;
      edit(b);
      const report = await verifyBundle(b, auditor());
      return { row: find(report, 'custody.ledger'), report };
    };

    it('a slot that holds no row, and no mirror entry in the envelope: not_applicable', async () => {
      for (const custody of [null, { entries: [] }, { hashPreimage: 'x', entries: [], trail: null }]) {
        const { row, report } = await custodyRow((b) => (b.custody = custody));
        expect(row).toEqual({ id: 'custody.ledger', outcome: 'not-checked', reason: 'not_applicable' });
        expect(bundleExitCode(report)).toBe(0);
      }
      // An entry that is not a mirror entry (no 64-hex entryHash) names no custody row.
      for (const entry of [{ action: 'relink' }, { entryHash: 'AB'.repeat(32) }, { entryHash: 'ab'.repeat(31) }, 'x', null]) {
        const { row } = await custodyRow((b) => {
          b.custody = null;
          b.envelope.custodyChain = [entry];
        });
        expect(row).toEqual({ id: 'custody.ledger', outcome: 'not-checked', reason: 'not_applicable' });
      }
    });

    it('a slot that holds no row beside a mirror entry: checked-wrong, mirror_entry_unexpected, exit 1', async () => {
      for (const custody of [null, { entries: [] }]) {
        const { row, report } = await custodyRow((b) => {
          b.custody = custody;
          b.envelope.custodyChain = [{ action: 'unhashed' }, MIRROR];
        });
        expect(row).toEqual({ id: 'custody.ledger', outcome: 'checked-wrong', reason: 'mirror_entry_unexpected' });
        expect(bundleExitCode(report)).toBe(1);
        // The finding is the row's alone: every other check is reported as before.
        expect(report.checks.map((c) => c.id)).toEqual((await verifyBundle(good, auditor())).checks.map((c) => c.id));
      }
    });

    it('any other slot abstains, unsupported_artifact, whatever it holds, mirror entry or not: exit 4', async () => {
      for (const custody of [{}, { entries: null }, { entries: 'rows' }, { entries: [1, 'x', null] }, { entries: [{ id: 1 }] }]) {
        for (const custodyChain of [[], [MIRROR]]) {
          const { row, report } = await custodyRow((b) => {
            b.custody = custody;
            b.envelope.custodyChain = custodyChain;
          });
          expect(row).toEqual({ id: 'custody.ledger', outcome: 'abstain', reason: 'unsupported_artifact' });
          expect(bundleExitCode(report)).toBe(4);
          expect(bundleExitCode(report, { allowUnchecked: true })).toBe(0);
        }
      }
    });

    it('a custody slot that is neither an object nor null is unreadable', async () => {
      for (const custody of [[], 'rows', 1, true]) {
        const b = clone(good) as unknown as Loose;
        b.custody = custody;
        const report = await verifyBundle(b, auditor());
        expect(report.checks).toEqual([{ id: 'bundle', outcome: 'checked-wrong', reason: 'malformed_bundle' }]);
        expect(bundleExitCode(report)).toBe(2);
      }
    });
  });

  it('reads a null chain, anchoring or extensions slot as one with nothing to carry (Bundle §3.1, §3.2)', async () => {
    const withSlot = (slot: 'chain' | 'anchoring' | 'extensions', value: unknown) => {
      const b = clone(good) as unknown as Record<string, unknown>;
      b[slot] = value;
      return b;
    };
    const comparable = async (b: unknown) => {
      const { checkedAt: _t, ...rest } = await verifyBundle(b, auditor());
      return rest;
    };
    expect(await comparable(withSlot('anchoring', null))).toEqual(await comparable(withSlot('anchoring', {})));
    expect(await comparable(withSlot('extensions', null))).toEqual(await comparable(withSlot('extensions', {})));
    // A null chain supplies no chain id and no predecessor: the chain is left unchecked.
    expect(await comparable(withSlot('chain', null))).toEqual(await comparable(withSlot('chain', { chainId: null, predecessor: null })));
    const unchained = await verifyBundle(withSlot('chain', null), auditor());
    expect(find(unchained, 'bundle')).toEqual({ id: 'bundle', outcome: 'checked-correct' });
    expect(find(unchained, 'anchor.origin')?.facts).toMatchObject({ chainChecked: false });
    // An array is neither an object nor null.
    for (const slot of ['chain', 'anchoring', 'extensions'] as const) {
      expect((await verifyBundle(withSlot(slot, []), auditor())).checks).toEqual([{ id: 'bundle', outcome: 'checked-wrong', reason: 'malformed_bundle' }]);
    }
  });

  it('requires every carried checkpoint to be one an anchor authenticated, with one checkpoint per log as with two', async () => {
    // A record anchored in the newest epoch: one checkpoint per log, each the
    // one its artifact names. Carried bodies of another root at the same size
    // and origin (a carried split view) are authenticated by nothing.
    const r3Bundle = await store.tzun.exportBundle(r3);
    const r3Log = parsed(r3Bundle.envelope.nonRepudiation.anchor!.logCheckpoint).origin;
    const reroot = (body: string, seed: string) => {
      const p = parsed(body);
      return formatCheckpoint(p.origin, p.size, sha256(seed));
    };
    const both = clone(r3Bundle);
    both.anchoring[r3Log].checkpoints[0].body = reroot(both.anchoring[r3Log].checkpoints[0].body, 'another history');
    both.anchoring[anchorOrigin].checkpoints[0].body = reroot(both.anchoring[anchorOrigin].checkpoints[0].body, 'another anchor history');
    const bothReport = await verifyBundle(both, auditor());
    expect(find(bothReport, 'anchor')).toMatchObject({ outcome: 'checked-correct' });
    expect(bothReport.checks.filter((c) => c.id.startsWith('anchor.consistency'))).toEqual(
      [anchorOrigin, r3Log].sort().map((o) => ({ id: `anchor.consistency[${o}]`, outcome: 'not-checked', reason: 'blocked_by:anchor.newer' })),
    );
    expect(bundleExitCode(bothReport)).toBe(4);

    const one = clone(r3Bundle);
    one.anchoring[r3Log].checkpoints[0].body = reroot(one.anchoring[r3Log].checkpoints[0].body, 'another history');
    const oneReport = await verifyBundle(one, auditor());
    expect(oneReport.checks.filter((c) => c.id.startsWith('anchor.consistency'))).toEqual([
      { id: `anchor.consistency[${r3Log}]`, outcome: 'not-checked', reason: 'blocked_by:anchor.newer' },
    ]);
    expect(bundleExitCode(oneReport)).toBe(4);

    // The envelope's artifact stripped: the record's own checkpoints are
    // carried and nothing authenticates them, with one per log or two.
    for (const [bundle, origins] of [
      [r3Bundle, [anchorOrigin, r3Log]],
      [good, [anchorOrigin, logOrigin]],
    ] as const) {
      const stripped = clone(bundle);
      delete (stripped.envelope.nonRepudiation as { anchor?: unknown }).anchor;
      const report = await verifyBundle(stripped, auditor());
      expect(find(report, 'anchor')).toEqual({ id: 'anchor', outcome: 'not-checked', reason: 'absent' });
      expect(report.checks.filter((c) => c.id.startsWith('anchor.consistency'))).toEqual(
        [...origins].sort().map((o) => ({ id: `anchor.consistency[${o}]`, outcome: 'not-checked', reason: 'blocked_by:anchor' })),
      );
      expect(bundleExitCode(report)).toBe(4);
    }
  });

  it('never compares bodies of two logs: two authenticated bodies of different origins under one key, or under a key of neither, are unreadable', async () => {
    // The envelope's anchor authenticates both of its bodies; they are of two
    // logs, and never a split view of one.
    const artifact = good.envelope.nonRepudiation.anchor!;
    const mixed = clone(good);
    mixed.anchoring[logOrigin] = { checkpoints: [{ body: artifact.logCheckpoint, signatures: [] }, { body: artifact.anchorCheckpoint, signatures: [] }], consistency: [] };
    const extra = clone(good) as unknown as { anchoring: Record<string, unknown> };
    extra.anchoring['totally.unrelated/origin'] = { checkpoints: [{ body: artifact.logCheckpoint, signatures: [] }, { body: artifact.anchorCheckpoint, signatures: [] }], consistency: [] };
    for (const b of [mixed, extra]) {
      const report = await verifyBundle(b, auditor());
      expect(report.checks).toEqual([{ id: 'bundle', outcome: 'checked-wrong', reason: 'malformed_bundle' }]);
      expect(bundleExitCode(report)).toBe(2);
    }
  });

  it('abstains on a filled frozen slot it does not read, and on a member a record bundle does not have (Bundle §3.3, §8)', async () => {
    const abstentions = (r: BundleVerificationReport) => r.checks.filter((c) => c.outcome === 'abstain');
    const related = clone(good) as unknown as Record<string, unknown>;
    related.relatedRecords = { 'some-id': { role: 'credential-revocation', envelope: {} } };
    const relatedReport = await verifyBundle(related, auditor());
    expect(abstentions(relatedReport)).toEqual([{ id: 'relatedRecords', outcome: 'abstain', reason: 'unsupported_slot' }]);
    expect(bundleExitCode(relatedReport)).toBe(4);

    const policy = clone(good) as unknown as Record<string, unknown>;
    policy.policy = { leaves: [{ modes: ['record'] }], checkpoint: 'x' };
    const policyReport = await verifyBundle(policy, auditor());
    expect(abstentions(policyReport)).toEqual([{ id: 'policy', outcome: 'abstain', reason: 'unsupported_slot' }]);
    expect(bundleExitCode(policyReport)).toBe(4);

    const credentials = clone(good) as unknown as Record<string, unknown>;
    credentials.credentials = { 'key-1': { coseKey: 'x', registration: null, revocations: [] } };
    const credentialsReport = await verifyBundle(credentials, auditor());
    expect(abstentions(credentialsReport)).toEqual([{ id: 'signoff.key', outcome: 'abstain', reason: 'unsupported_signoff' }]);
    expect(bundleExitCode(credentialsReport)).toBe(4);

    const future = clone(good) as unknown as Record<string, unknown>;
    future.futureSlot = { something: true };
    future.logLeaves = {};
    const futureReport = await verifyBundle(future, auditor());
    expect(abstentions(futureReport)).toEqual([
      { id: 'member[futureSlot]', outcome: 'abstain', reason: 'unsupported_member' },
      { id: 'member[logLeaves]', outcome: 'abstain', reason: 'unsupported_member' },
    ]);
    expect(bundleExitCode(futureReport)).toBe(4);

    // Null slots, and whatever `exporter` says, are not artifacts.
    const exporter = clone(good);
    (exporter.exporter as unknown as Record<string, unknown>).verdict = { anything: true };
    const exporterReport = await verifyBundle(exporter, auditor());
    expect(abstentions(exporterReport)).toEqual([]);
    expect(bundleExitCode(exporterReport)).toBe(0);
  });

  it('checks the record\'s sign-off material against its hashed signoffExpectation, with no key: signoff.expectation (Verification §5)', async () => {
    // v1.0, whose hashed set holds signoffExpectation (Record §9.1),
    // beside a schema whose set does not, and an unanchored record whose
    // pending slot is left out, so nothing else keeps the exit code from 0.
    const registry = new SchemaRegistry();
    const v10 = registry.get('v1.0')!;
    expect(v10.hashedFieldSet).toContain('signoffExpectation');
    registry.register({ ...v10, versionId: 'v1.0-unhashed', hashedFieldSet: v10.hashedFieldSet.filter((f) => f !== 'signoffExpectation') });
    const base = clone(await store.tzun.exportBundle(r4));
    base.anchorPending = null;
    const predecessor = base.chain.predecessor!.canonicalDigest;
    const owed = (expectation: unknown, schemaVersion = 'v1.0') => {
      const b = clone(base);
      Object.assign(b.envelope.payload, { schemaVersion, signoffExpectation: expectation });
      const fields = registry.get(schemaVersion)!.hashedFieldSet;
      const digest = computeDigest(canonicalSerialize(b.envelope.payload as unknown as Record<string, unknown>, fields));
      const chain = new EvidenceChain();
      chain.restore(predecessor);
      b.envelope.integrity.canonicalDigest = digest;
      b.envelope.integrity.chainLink = chain.computeLink(digest);
      b.subject.canonicalDigest = digest;
      return b;
    };
    const verify = (b: ProofBundle) => verifyBundle(b, { ...auditor(), registry });
    const artifacts = (b: ProofBundle) => b.envelope.nonRepudiation as unknown as Record<string, unknown>;
    const EXPECTATION = 'signoff.expectation';
    const expectation = (r: BundleVerificationReport) => find(r, EXPECTATION);
    const key = (r: BundleVerificationReport) => find(r, 'signoff.key');
    const POLICY = 'ab'.repeat(32);

    // A record that expects no signature and carries none holds.
    const baseline = await verify(owed(null));
    expect(find(baseline, 'record.digest')).toMatchObject({ outcome: 'checked-correct' });
    expect(expectation(baseline)).toEqual({ id: EXPECTATION, outcome: 'checked-correct' });
    expect(key(baseline)).toEqual({ id: 'signoff.key', outcome: 'not-checked', reason: 'absent' });
    expect(baseline.checks.map((c) => c.id).indexOf(EXPECTATION)).toBe(baseline.checks.map((c) => c.id).indexOf('signoff.key') - 1);
    expect(bundleExitCode(baseline)).toBe(0);

    // A policy record with no assertion: its signature is still to come, or
    // was stripped, and the bundle cannot tell which. Never absent.
    const awaiting = await verify(owed({ policyDigest: POLICY }));
    expect(expectation(awaiting)).toEqual({ id: EXPECTATION, outcome: 'not-checked', reason: 'signature_missing' });
    expect(key(awaiting)).toEqual({ id: 'signoff.key', outcome: 'not-checked', reason: 'signature_missing' });
    expect(bundleExitCode(awaiting)).toBe(4);
    expect(bundleExitCode(awaiting, { require: ['signoff.key'] })).toBe(3);
    // With a per-record assertion carried, the credential it needs is what is missing.
    const perRecord = owed({ policyDigest: POLICY });
    artifacts(perRecord).webauthnAssertion = { signature: 'AA', credentialId: 'x' };
    expect(key(await verify(perRecord))).toEqual({ id: 'signoff.key', outcome: 'not-checked', reason: 'not_in_bundle:credential' });

    // A session record, written with its sign-off: the statement its
    // expectation names, the slot, and an assertion that presented the
    // statement's challenge (Record §9.4, §9.5).
    const statement = {
      v: 'tzun-signoff/1', mode: 'session', sessionId: '6f1c1f0e-8d6a-4f0e-9d6b-1a2b3c4d5e6f', signer: 'u1',
      signerName: 'SmFuZQ', meaning: 'approval', policyDigest: POLICY, notBefore: 'none',
      openedAt: '2026-09-26T10:00:00.000Z', maxAgeMs: 1800000, maxRecords: 50,
    };
    const statementDigest = signoffStatementDigest(statement)!;
    const { assertion: sessionAssertion } = makeGenuineAssertion({ challenge: signoffStatementChallenge(statementDigest), credentialId: 'session-key' });
    const session = owed({ statementDigest, sessionSeq: 1 });
    Object.assign(artifacts(session), { webauthnAssertion: sessionAssertion, signoff: { statement, sessionSeq: 1 } });
    const honest = await verify(session);
    expect(expectation(honest)).toEqual({ id: EXPECTATION, outcome: 'checked-correct' });
    expect(key(honest)).toEqual({ id: 'signoff.key', outcome: 'not-checked', reason: 'not_in_bundle:credential' });
    expect(bundleExitCode(honest)).toBe(4);

    /** A finding the bundle decides: checked-wrong at signoff.expectation, signoff.key blocked by it, exit 1 whatever the regime. */
    const decided = async (b: ProofBundle, reason: string) => {
      const report = await verify(b);
      expect(find(report, 'record.digest')).toMatchObject({ outcome: 'checked-correct' });
      expect(expectation(report)).toEqual({ id: EXPECTATION, outcome: 'checked-wrong', reason });
      expect(key(report)).toEqual({ id: 'signoff.key', outcome: 'not-checked', reason: 'blocked_by:signoff.expectation' });
      expect(report.checks.filter((c) => c.outcome === 'checked-wrong')).toHaveLength(1);
      expect(bundleExitCode(report)).toBe(1);
      expect(bundleExitCode(report, { allowUnchecked: true })).toBe(1);
    };

    // The session sign-off stripped, whole or in part: a session record is
    // written with it, so this is a removal, never a record awaiting one.
    for (const removed of [['signoff', 'webauthnAssertion'], ['signoff'], ['webauthnAssertion']]) {
      const stripped = clone(session);
      for (const member of removed) delete artifacts(stripped)[member];
      await decided(stripped, 'signoff_stripped');
    }
    const nothingCarried = owed({ statementDigest, sessionSeq: 1 });
    await decided(nothingCarried, 'signoff_stripped');

    // Another slot, or another session's statement.
    const otherSlot = clone(session);
    (artifacts(otherSlot).signoff as Record<string, unknown>).sessionSeq = 2;
    await decided(otherSlot, 'session_seq_mismatch');
    const otherStatement = clone(session);
    (artifacts(otherStatement).signoff as { statement: Record<string, unknown> }).statement.maxRecords = 49;
    await decided(otherStatement, 'statement_digest_mismatch');
    // An assertion from another ceremony beside the session block.
    const otherCeremony = clone(session);
    artifacts(otherCeremony).webauthnAssertion = makeGenuineAssertion({ challenge: 'another-ceremony', credentialId: 'session-key' }).assertion;
    await decided(otherCeremony, 'signoff_unbound');

    // The session sign-off moved onto a record that expects none, and onto
    // one that expects a policy signature.
    for (const target of [owed(null), owed({ policyDigest: POLICY })]) {
      Object.assign(artifacts(target), { webauthnAssertion: sessionAssertion, signoff: { statement, sessionSeq: 1 } });
      await decided(target, 'session_signoff_not_expected');
    }

    // A junk batch block beside a per-record assertion, and a relabelled
    // statement: a sign-off block that does not bind is never a signature
    // carried.
    const junk = owed(null);
    Object.assign(artifacts(junk), { webauthnAssertion: { signature: 'AA', credentialId: 'x' }, signoff: { statement: { mode: 'batch' } } });
    await decided(junk, 'signoff_unbound');
    const relabelled = owed({ policyDigest: POLICY });
    Object.assign(artifacts(relabelled), { webauthnAssertion: sessionAssertion, signoff: { statement: { ...statement, mode: 'batch' } } });
    await decided(relabelled, 'signoff_unbound');

    // A value of neither form, under a digest that holds over it.
    await decided(owed({ policyDigest: 'AB'.repeat(32) }), 'malformed_signoff_expectation');

    // A value outside the hashed set is not the record's, and says nothing;
    // one under a digest that fails is reported once, at record.digest.
    const unhashedReport = await verify(owed({ policyDigest: POLICY }, 'v1.0-unhashed'));
    expect(find(unhashedReport, 'record.digest')).toMatchObject({ outcome: 'checked-correct' });
    expect(expectation(unhashedReport)).toEqual({ id: EXPECTATION, outcome: 'not-checked', reason: 'not_applicable' });
    expect(key(unhashedReport)).toEqual({ id: 'signoff.key', outcome: 'not-checked', reason: 'absent' });
    expect(bundleExitCode(unhashedReport)).toBe(0);
    const edited = clone(session);
    edited.envelope.payload.reason = 'edited';
    delete artifacts(edited).signoff;
    const editedReport = await verify(edited);
    expect(find(editedReport, 'record.digest')).toMatchObject({ outcome: 'checked-wrong', reason: 'digest_mismatch' });
    expect(expectation(editedReport)).toEqual({ id: EXPECTATION, outcome: 'not-checked', reason: 'blocked_by:record.digest' });
    expect(key(editedReport)).toEqual({ id: 'signoff.key', outcome: 'not-checked', reason: 'not_in_bundle:credential' });
    expect(editedReport.checks.filter((c) => c.outcome === 'checked-wrong')).toHaveLength(1);
  });

  it('reads an unanchored record with its pending slot left out as unanchored, exit 0: an auditor who needs an anchor requires one', async () => {
    // Verification §6.6: an absent artifact is not an unchecked one, and a
    // bundle with no anchor and no pending slot is what a store that does not
    // anchor exports. The regime is what turns a missing anchor into a finding.
    const b = clone(await store.tzun.exportBundle(r4));
    b.anchorPending = null;
    const report = await verifyBundle(b, auditor());
    expect(find(report, 'anchor')).toEqual({ id: 'anchor', outcome: 'not-checked', reason: 'absent' });
    expect(report.checks.map((c) => c.id)).not.toContain('anchor.pending');
    expect(bundleExitCode(report)).toBe(0);
    expect(bundleExitCode(report, { require: ['anchor'] })).toBe(3);
  });

  it('checks the record\'s own RFC 3161 token over its digest, and its path to a root only the caller supplies', async () => {
    const fixture = await makeTsaFixture({ digestHex: good.subject.canonicalDigest, withIntermediate: true });
    const b = clone(good);
    b.envelope.nonRepudiation.rfc3161Token = fixture.tokenBase64;

    const untrusted = await verifyBundle(b, auditor());
    expect(find(untrusted, 'ts.record.token')).toEqual({ id: 'ts.record.token', outcome: 'checked-correct' });
    expect(find(untrusted, 'ts.record.trust')).toEqual({ id: 'ts.record.trust', outcome: 'not-checked', reason: 'no_matching_trust_anchor' });
    expect(bundleExitCode(untrusted)).toBe(4);

    const trusted = await verifyBundle(b, { ...auditor(), trustAnchorsPem: [fixture.caPem] });
    expect(find(trusted, 'ts.record.trust')).toEqual({
      id: 'ts.record.trust',
      outcome: 'checked-correct',
      facts: { genTime: fixture.genTime.toISOString(), authority: fixture.signerCN },
    });
    // The token is earlier than the anchor's block, so it is the earliest proven bound.
    expect(trusted.summary.existedBy).toEqual({ at: fixture.genTime.toISOString(), source: 'record-timestamp', check: 'ts.record.trust' });
    expect(trusted.inputs.trustAnchors).toEqual([expect.stringMatching(/^[0-9a-f]{64}$/)]);
    expect(bundleExitCode(trusted)).toBe(0);

    const other = await makeTsaFixture({ digestHex: sha256('another record') });
    const wrong = clone(good);
    wrong.envelope.nonRepudiation.rfc3161Token = other.tokenBase64;
    const wrongReport = await verifyBundle(wrong, { ...auditor(), trustAnchorsPem: [other.caPem] });
    expect(find(wrongReport, 'ts.record.token')).toEqual({ id: 'ts.record.token', outcome: 'checked-wrong', reason: 'imprint_mismatch' });
    expect(find(wrongReport, 'ts.record.trust')).toEqual({ id: 'ts.record.trust', outcome: 'not-checked', reason: 'blocked_by:ts.record.token' });
    expect(bundleExitCode(wrongReport)).toBe(1);

    const garbage = clone(good);
    garbage.envelope.nonRepudiation.rfc3161Token = Buffer.from('not a token').toString('base64');
    expect(find(await verifyBundle(garbage, auditor()), 'ts.record.token')).toMatchObject({ outcome: 'checked-wrong', reason: 'malformed_token' });
  });

  it('holds the record\'s token to every rule of tzun-anchor/1 §10.5, step by step (Verification §4.4)', async () => {
    const digest = good.subject.canonicalDigest;
    const withToken = (token: string): ProofBundle => {
      const b = clone(good);
      b.envelope.nonRepudiation.rfc3161Token = token;
      return b;
    };
    const tokenRows = (r: BundleVerificationReport) => [find(r, 'ts.record.token'), find(r, 'ts.record.trust')];
    const blocked = { id: 'ts.record.trust', outcome: 'not-checked', reason: 'blocked_by:ts.record.token' };

    // Steps 1 and 3 need nothing from the auditor: the same answer with the root and without it.
    for (const [faults, reason] of [
      [{ berTstInfo: true }, 'malformed_token'],
      [{ withoutSignerCertificate: true }, 'malformed_token'],
      [{ signingCertificate: 'none' }, 'verification_failed'],
      [{ signingCertificate: 'other-certificate' }, 'verification_failed'],
      [{ signerEku: 'none' }, 'verification_failed'],
      [{ signerEku: 'tls-server' }, 'verification_failed'],
    ] as const) {
      const f = await makeTsaFixture({ digestHex: digest, faults });
      for (const inputs of [auditor(), { ...auditor(), trustAnchorsPem: [f.caPem] }]) {
        const report = await verifyBundle(withToken(f.tokenBase64), inputs);
        expect([faults, tokenRows(report)]).toEqual([faults, [{ id: 'ts.record.token', outcome: 'checked-wrong', reason }, blocked]]);
        expect(report.summary.existedBy?.check).not.toBe('ts.record.trust');
        expect(bundleExitCode(report)).toBe(1);
      }
    }

    // Step 4: a path that reaches the supplied root and holds on none is a finding, not an abstention.
    const notCa = await makeTsaFixture({ digestHex: digest, withIntermediate: true, intermediateNotCa: true });
    const impostor = await makeTsaFixture({ digestHex: digest });
    const sameNameRoot = (await makeTsaFixture()).caPem;
    for (const [token, root] of [
      [notCa.tokenBase64, notCa.caPem],
      [impostor.tokenBase64, sameNameRoot],
    ]) {
      const report = await verifyBundle(withToken(token), { ...auditor(), trustAnchorsPem: [root] });
      expect(tokenRows(report)).toEqual([
        { id: 'ts.record.token', outcome: 'checked-correct' },
        { id: 'ts.record.trust', outcome: 'checked-wrong', reason: 'verification_failed' },
      ]);
      expect(bundleExitCode(report)).toBe(1);
    }

    // Step 5: an algorithm this verifier does not implement is not checked, and blocks the trust check.
    const genuine = await makeTsaFixture({ digestHex: digest });
    const der = Buffer.from(genuine.tokenBase64, 'base64');
    const at = der.lastIndexOf(Buffer.from('06082a8648ce3d040302', 'hex'));
    der[at + 9] = 0x7f; // the SignerInfo's ecdsa-with-SHA256 becomes 1.2.840.10045.4.3.127
    const unsupported = await verifyBundle(withToken(der.toString('base64')), { ...auditor(), trustAnchorsPem: [genuine.caPem] });
    expect(tokenRows(unsupported)).toEqual([{ id: 'ts.record.token', outcome: 'not-checked', reason: 'missing_dependency' }, blocked]);
    expect(bundleExitCode(unsupported)).toBe(4);

    // A real authority's stored token meets steps 1 and 3, and it is over another digest.
    const tokens = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'tsa-tokens.json'), 'utf8')) as Record<string, { tokenBase64: string }>;
    const real = await verifyBundle(withToken(tokens.freetsa.tokenBase64), { ...auditor(), authorities: ['freetsa'] });
    expect(tokenRows(real)).toEqual([{ id: 'ts.record.token', outcome: 'checked-wrong', reason: 'imprint_mismatch' }, blocked]);
  });

  it('keeps every other check when the record\'s token is hostile, and never reports bundle_verifier_error for a change to the token alone (tzun-anchor/1 §10.1)', async () => {
    const digest = good.subject.canonicalDigest;
    const withToken = (token: string): ProofBundle => {
      const b = clone(good);
      b.envelope.nonRepudiation.rfc3161Token = token;
      return b;
    };
    const genuineRows = rows(await verifyBundle(good, auditor())).filter(([id]) => !String(id).startsWith('ts.record.'));

    // A genuine token that chains to the supplied root, with a certificate of
    // its intermediate's name added to its unsigned certificates set, whose key
    // does not decode. Nothing needs a key to add it, and the record's digest
    // does not cover nonRepudiation.
    const junk = await makeTsaFixture({ digestHex: digest, withIntermediate: true, faults: { issuerCopy: 'bad-key' } });
    const report = await verifyBundle(withToken(junk.tokenBase64), { ...auditor(), trustAnchorsPem: [junk.caPem] });
    expect(rows(report).filter(([id]) => String(id).startsWith('ts.record.'))).toEqual([
      ['ts.record.token', 'checked-wrong', 'malformed_token'],
      ['ts.record.trust', 'not-checked', 'blocked_by:ts.record.token'],
    ]);
    expect(rows(report).filter(([id]) => !String(id).startsWith('ts.record.'))).toEqual(genuineRows);
    expect(bundleExitCode(report)).toBe(1);

    // Every one-bit change of a conformant token gets a verdict on the token's
    // own checks, and every other check is still reported. The sweep runs on
    // the bundle with its anchor taken out, which the token's checks do not
    // read, so a thousand reports take seconds.
    const f = await makeTsaFixture({ digestHex: digest, withIntermediate: true, genTime: new Date('2026-06-01T12:00:00.25Z') });
    const der = Buffer.from(f.tokenBase64, 'base64');
    const inputs = { trustAnchorsPem: [f.caPem] };
    const unanchored = (token: string): ProofBundle => {
      const b = withToken(token);
      delete (b.envelope.nonRepudiation as { anchor?: unknown }).anchor;
      b.anchoring = {};
      return b;
    };
    const ids = (await verifyBundle(unanchored(f.tokenBase64), inputs)).checks.map((c) => c.id);
    expect(ids).toContain('ts.record.trust');
    for (let i = 0; i < der.length; i++) {
      const flipped = Buffer.from(der);
      flipped[i] ^= 0x01;
      const r = await verifyBundle(unanchored(flipped.toString('base64')), inputs);
      expect([i, r.checks.map((c) => c.id), r.checks.some((c) => c.reason === 'bundle_verifier_error')]).toEqual([i, ids, false]);
    }
  });

  it('does not check a WebAuthn assertion whose credential no slot carries, and abstains on an extension it does not implement', async () => {
    const signed = clone(good);
    (signed.envelope.nonRepudiation as Record<string, unknown>).webauthnAssertion = { signature: 'AA', credentialId: 'x' };
    const report = await verifyBundle(signed, auditor());
    expect(find(report, 'signoff.key')).toEqual({ id: 'signoff.key', outcome: 'not-checked', reason: 'not_in_bundle:credential' });
    expect(bundleExitCode(report)).toBe(4);

    const witnessed = clone(good) as unknown as { extensions: Record<string, unknown> };
    witnessed.extensions['witness/1'] = { cosignature: 'x' };
    witnessed.extensions['vendor/1'] = null;
    const extReport = await verifyBundle(witnessed, auditor());
    expect(extReport.checks.filter((c) => c.id.startsWith('extension['))).toEqual([
      { id: 'extension[witness/1]', outcome: 'abstain', reason: 'unsupported_extension' },
    ]);
    expect(bundleExitCode(extReport)).toBe(4);
  });

  it('fails a subject that does not name the envelope, and a genesis claim with a predecessor', async () => {
    const b = clone(good);
    b.subject.canonicalDigest = sha256('another');
    expect(find(await verifyBundle(b, auditor()), 'subject')).toEqual({ id: 'subject', outcome: 'checked-wrong', reason: 'subject_mismatch' });

    const withPredecessor = clone(good);
    withPredecessor.chain.predecessor = { evidenceId: r2, sequenceNumber: 0, canonicalDigest: sha256('x') };
    expect(find(await verifyBundle(withPredecessor, auditor()), 'record.chainLink')).toMatchObject({ outcome: 'checked-wrong', reason: 'predecessor_mismatch' });

    const later = clone(await store.tzun.exportBundle(r2));
    later.chain.predecessor = null;
    expect(find(await verifyBundle(later, auditor()), 'record.chainLink')).toMatchObject({ outcome: 'not-checked', reason: 'not_in_bundle:predecessor' });
    later.envelope.integrity.chainLink = null;
    // chainLink is outside the hashed fields: nulling it leaves the digest intact.
    expect(find(await verifyBundle(later, auditor()), 'record.chainLink')).toMatchObject({ outcome: 'checked-wrong', reason: 'chain_link_missing' });
  });

  it('abstains on an unknown or absent bundle version and on the chain profile, and refuses an unreadable bundle: exit 2, one check', async () => {
    for (const bundleVersion of ['b2', undefined]) {
      const b = clone(good) as unknown as Record<string, unknown>;
      if (bundleVersion === undefined) delete b.bundleVersion;
      else b.bundleVersion = bundleVersion;
      const report = await verifyBundle(b);
      expect(report.checks).toEqual([{ id: 'bundle', outcome: 'abstain', reason: 'unsupported_bundle_version' }]);
      expect(bundleExitCode(report)).toBe(2);
      expect(bundleExitCode(report, { allowUnchecked: true })).toBe(2);
    }
    const chainProfile = { ...clone(good), profile: 'chain' };
    expect((await verifyBundle(chainProfile)).checks).toEqual([{ id: 'bundle', outcome: 'abstain', reason: 'unsupported_bundle_profile' }]);

    const malformed: unknown[] = [
      null,
      'b1',
      [],
      { ...clone(good), envelope: undefined },
      { ...clone(good), anchorPending: { origin: 'x' } },
      (() => {
        const b = clone(good);
        const cps = b.anchoring[logOrigin].checkpoints;
        cps.push(cps[0]);
        return b;
      })(),
    ];
    for (const b of malformed) {
      const report = await verifyBundle(b);
      expect(report.checks).toEqual([{ id: 'bundle', outcome: 'checked-wrong', reason: 'malformed_bundle' }]);
      expect(bundleExitCode(report)).toBe(2);
    }
  });

  it('never throws on hostile input', async () => {
    const hostile: unknown[] = [
      undefined,
      42,
      { bundleVersion: 'b1', profile: 'record' },
      { ...clone(good), envelope: { payload: null, integrity: 7, nonRepudiation: { anchor: [] } } },
      { ...clone(good), anchoring: { x: { checkpoints: [{ body: 5, signatures: [] }], consistency: [] } } },
      { ...clone(good), chain: { chainId: 3, predecessor: null } },
    ];
    for (const b of hostile) await expect(verifyBundle(b, auditor())).resolves.toMatchObject({ reportVersion: BUNDLE_REPORT_VERSION });
    await expect(verifyBundle(good, null as never)).resolves.toMatchObject({ reportVersion: BUNDLE_REPORT_VERSION });
  });

  it('applies the auditor\'s regime: required checks and rungs give 3, after 1 and 2', async () => {
    const report = await verifyBundle(good, auditor());
    expect(bundleExitCode(report, { require: ['anchor', 'anchor.newer'] })).toBe(0);
    expect(bundleExitCode(report, { require: ['ts.record.trust'] })).toBe(3);
    expect(bundleExitCode(report, { requireRung: ['per_record'] })).toBe(3);
    const offline = await verifyBundle(good);
    // 3 before 4.
    expect(bundleExitCode(offline, { require: ['anchor'] })).toBe(3);
    const tampered = clone(good);
    tampered.envelope.payload.reason = 'x';
    // 1 before 3.
    expect(bundleExitCode(await verifyBundle(tampered), { require: ['anchor'] })).toBe(1);
  });

  describe('aligned with the verification spec', () => {
    const pemOf = (der: Buffer) => `-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----`;
    const derOf = (pem: string) => Buffer.from(pem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, ''), 'base64');
    const withRecordToken = (token: string): ProofBundle => {
      const b = clone(good);
      b.envelope.nonRepudiation.rfc3161Token = token;
      return b;
    };

    it('refuses a root it cannot read, or an authority it does not know, and makes no report (Verification §3.1, §6.6)', async () => {
      const f = await makeTsaFixture({ digestHex: good.subject.canonicalDigest });
      const b = withRecordToken(f.tokenBase64);
      const unreadable: unknown[] = [
        pemOf(withUnreadableKey(derOf(f.caPem), 'bad-key')),
        pemOf(withUnreadableKey(derOf(f.caPem), 'unknown-key-algorithm')),
        pemOf(withUnreadableKey(derOf(f.caPem), 'unassigned-curve')),
        'no certificate here',
        7,
      ];
      for (const root of unreadable) {
        for (const roots of [[root], [f.caPem, root]]) {
          await expect(verifyBundle(b, { ...auditor(), trustAnchorsPem: roots as string[] })).rejects.toThrow(UnreadableTrustAnchorError);
        }
      }
      await expect(verifyBundle(b, { ...auditor(), authorities: ['no-such-authority'] })).rejects.toThrow(UnreadableTrustAnchorError);
      // The bundle is never read first: an unreadable bundle with an unreadable root is refused the same way.
      await expect(verifyBundle(42, { trustAnchorsPem: ['no certificate here'] })).rejects.toThrow(UnreadableTrustAnchorError);
      // The genuine root alone still verifies.
      expect(find(await verifyBundle(b, { ...auditor(), trustAnchorsPem: [f.caPem] }), 'ts.record.trust')).toMatchObject({ outcome: 'checked-correct' });
    });

    it('reports a key on a curve it does not implement as missing_dependency on the check that needs it, and does not examine one no check needs (tzun-anchor/1 §10.5 steps 1 and 5)', async () => {
      const digest = good.subject.canonicalDigest;
      const signer = await makeTsaFixture({ digestHex: digest, faults: { signerKey: 'unassigned-curve' } });
      const signerReport = await verifyBundle(withRecordToken(signer.tokenBase64), { ...auditor(), trustAnchorsPem: [signer.caPem] });
      expect([find(signerReport, 'ts.record.token'), find(signerReport, 'ts.record.trust')]).toEqual([
        { id: 'ts.record.token', outcome: 'not-checked', reason: 'missing_dependency' },
        { id: 'ts.record.trust', outcome: 'not-checked', reason: 'blocked_by:ts.record.token' },
      ]);
      expect(bundleExitCode(signerReport)).toBe(4);

      const intermediate = await makeTsaFixture({ digestHex: digest, faults: { signerIssuer: 'intermediate-unassigned-curve' } });
      const intermediateReport = await verifyBundle(withRecordToken(intermediate.tokenBase64), { ...auditor(), trustAnchorsPem: [intermediate.caPem] });
      expect([find(intermediateReport, 'ts.record.token'), find(intermediateReport, 'ts.record.trust')]).toEqual([
        { id: 'ts.record.token', outcome: 'checked-correct' },
        { id: 'ts.record.trust', outcome: 'not-checked', reason: 'missing_dependency' },
      ]);
      expect(bundleExitCode(intermediateReport)).toBe(4);

      const unneeded = await makeTsaFixture({ digestHex: digest, faults: { unneededCertificate: 'unassigned-curve' } });
      const unneededReport = await verifyBundle(withRecordToken(unneeded.tokenBase64), { ...auditor(), trustAnchorsPem: [unneeded.caPem] });
      expect(find(unneededReport, 'ts.record.trust')).toMatchObject({ outcome: 'checked-correct' });
      expect(bundleExitCode(unneededReport)).toBe(0);

      const offCurve = await makeTsaFixture({ digestHex: digest, faults: { signerKey: 'bad-key' } });
      const offCurveReport = await verifyBundle(withRecordToken(offCurve.tokenBase64), { ...auditor(), trustAnchorsPem: [offCurve.caPem] });
      expect(find(offCurveReport, 'ts.record.token')).toEqual({ id: 'ts.record.token', outcome: 'checked-wrong', reason: 'malformed_token' });
      expect(bundleExitCode(offCurveReport)).toBe(1);
    });

    it('always states authority on a trust check that holds, the empty string for a subject with no CN (tzun-anchor/1 §10.5 step 4)', async () => {
      const digest = good.subject.canonicalDigest;
      for (const [subject, authority] of [
        ['3000', ''],
        ['3015311330110603550403130a4669727374204e616d65', 'First Name'],
        ['30123110300e060355040a0c0750726f6265204f', ''],
      ] as const) {
        const f = await makeTsaFixture({ digestHex: digest, faults: { signerSubject: Buffer.from(subject, 'hex') } });
        const report = await verifyBundle(withRecordToken(f.tokenBase64), { ...auditor(), trustAnchorsPem: [f.caPem] });
        expect(find(report, 'ts.record.trust')).toEqual({ id: 'ts.record.trust', outcome: 'checked-correct', facts: { genTime: f.genTime.toISOString(), authority } });
      }
    });

    it('refuses a lone surrogate in a member name a row id would carry: malformed_bundle, exit 2 (Bundle §4 step 9)', async () => {
      const cases: Array<(b: Record<string, any>) => void> = [
        (b) => (b['\ud800'] = { a: 1 }),
        (b) => (b['x\udc00y'] = { a: 1 }),
        (b) => (b.extensions['\ud800'] = { a: 1 }),
        (b) => (b.envelope.nonRepudiation['\ud800'] = { a: 1 }),
        (b) => (b.anchoring['\udfff'] = { checkpoints: [], consistency: [] }),
      ];
      for (const edit of cases) {
        const b = clone(good) as unknown as Record<string, any>;
        edit(b);
        const report = await verifyBundle(b, auditor());
        expect(rows(report)).toEqual([['bundle', 'checked-wrong', 'malformed_bundle']]);
        expect(bundleExitCode(report)).toBe(2);
        expect(() => comparableReport(report)).not.toThrow();
      }
      // A surrogate pair is a character like any other.
      const pair = clone(good) as unknown as Record<string, any>;
      pair['\ud83d\ude00'] = { a: 1 };
      const pairReport = await verifyBundle(pair, auditor());
      expect(find(pairReport, 'member[\ud83d\ude00]')).toEqual({ id: 'member[\ud83d\ude00]', outcome: 'abstain', reason: 'unsupported_member' });
      // A lone surrogate where no row id carries it is the reader's concern of that member, not the bundle's.
      const deep = clone(good) as unknown as Record<string, any>;
      deep.exporter['\ud800'] = 1;
      expect(find(await verifyBundle(deep, auditor()), 'bundle')).toEqual({ id: 'bundle', outcome: 'checked-correct' });
    });

    it('reports each member of nonRepudiation no check reads, in byte order of its name (Verification §4.7)', async () => {
      const b = clone(good) as unknown as Record<string, any>;
      Object.assign(b.envelope.nonRepudiation, {
        zeta: { v: 1 },
        assertionTimestamp: { token: 'x' },
        blockchainAnchor: { txHash: '0x00' },
        alpha: { v: 1 },
        nulled: null,
      });
      const report = await verifyBundle(b, auditor());
      expect(rows(report).slice(-4)).toEqual([
        ['nonRepudiation.alpha', 'abstain', 'unsupported_artifact'],
        ['ts.assertion.token', 'abstain', 'unsupported_artifact'],
        ['nonRepudiation.blockchainAnchor', 'abstain', 'legacy_blockchain_anchor'],
        ['nonRepudiation.zeta', 'abstain', 'unsupported_artifact'],
      ]);
      expect(find(report, 'anchor')).toEqual({ id: 'anchor', outcome: 'checked-correct' });
      expect(bundleExitCode(report)).toBe(4);
      // A blockchainAnchor alone is the anchor's own abstention, and has no row of its own.
      const legacy = clone(good) as unknown as Record<string, any>;
      delete legacy.envelope.nonRepudiation.anchor;
      legacy.envelope.nonRepudiation.blockchainAnchor = { txHash: '0x00' };
      const legacyReport = await verifyBundle(legacy, auditor());
      expect(find(legacyReport, 'anchor')).toEqual({ id: 'anchor', outcome: 'abstain', reason: 'legacy_blockchain_anchor' });
      expect(find(legacyReport, 'nonRepudiation.blockchainAnchor')).toBeUndefined();
    });

    it('reports the anchor rows absent, not blocked, when the record has no artifact and its digest fails (Verification §4.3, §4.6)', async () => {
      const b = clone(good);
      b.envelope.payload.reason = 'edited after capture';
      delete (b.envelope.nonRepudiation as { anchor?: unknown }).anchor;
      const report = await verifyBundle(b, auditor());
      expect(find(report, 'record.digest')).toMatchObject({ outcome: 'checked-wrong', reason: 'digest_mismatch' });
      for (const id of ['anchor', 'anchor.spec', 'anchor.checkpoint', 'anchor.origin', 'anchor.leafIndex', 'anchor.inclusion', 'anchor.anchorInclusion']) {
        expect(find(report, id)).toEqual({ id, outcome: 'not-checked', reason: 'absent' });
      }
      expect(find(report, 'anchor.newer')).toEqual({ id: 'anchor.newer', outcome: 'not-checked', reason: 'blocked_by:record.digest' });
      expect(bundleExitCode(report)).toBe(1);
      // A legacy blockchainAnchor is an artifact: it waits for the digest.
      (b.envelope.nonRepudiation as Record<string, unknown>).blockchainAnchor = { txHash: '0x00' };
      expect(find(await verifyBundle(b, auditor()), 'anchor')).toEqual({ id: 'anchor', outcome: 'not-checked', reason: 'blocked_by:record.digest' });
    });

    it('restates the bundle\'s subject and bundleVersion as they stand (Verification §6.1)', async () => {
      const extra = clone(good) as unknown as Record<string, any>;
      extra.subject.note = { kept: [1, 2] };
      const report = await verifyBundle(extra, auditor());
      expect(report.subject).toEqual({ ...good.subject, note: { kept: [1, 2] } });
      expect(find(report, 'subject')).toEqual({ id: 'subject', outcome: 'checked-correct' });
      for (const [bundle, bundleVersion, subject] of [
        [{ ...clone(good), bundleVersion: 2 }, 2, good.subject],
        [{ bundleVersion: 'b1', profile: 'record', subject: 'a string' }, 'b1', 'a string'],
        [{ bundleVersion: null }, null, null],
        [[1, 2], null, null],
      ] as const) {
        const r = await verifyBundle(bundle, auditor());
        expect([r.bundleVersion, r.subject]).toEqual([bundleVersion, subject]);
      }
      // A copy: editing the report leaves the caller's bundle as it was.
      (report.subject as Record<string, any>).evidenceId = 'edited';
      (report.subject as Record<string, any>).note.kept.push(3);
      expect(extra.subject).toEqual({ ...good.subject, note: { kept: [1, 2] } });
      const versioned = { ...clone(good), bundleVersion: { of: ['b1'] } };
      const r = await verifyBundle(versioned, auditor());
      (r.bundleVersion as { of: string[] }).of.push('b2');
      expect(versioned.bundleVersion).toEqual({ of: ['b1'] });
      // A lone surrogate survives the copy, so the report still cannot be written (Verification §6.5).
      const lone = clone(good) as unknown as Record<string, any>;
      lone.subject.evidenceId = 'x\ud800';
      expect(((await verifyBundle(lone, auditor())).subject as Record<string, string>).evidenceId).toBe('x\ud800');
      // A member named __proto__ stays a member, and the copy writes in canonical form.
      const proto = clone(good) as unknown as Record<string, any>;
      proto.subject = JSON.parse(`{"__proto__":{"a":1},"evidenceId":${JSON.stringify(good.subject.evidenceId)}}`);
      const protoReport = await verifyBundle(proto, auditor());
      expect(Object.keys(protoReport.subject as object)).toEqual(['__proto__', 'evidenceId']);
      expect(comparableReport(protoReport)).toContain('"__proto__":{"a":1}');
      // A value that is not JSON is restated as it is, and the report has no canonical form.
      const fn = () => 1;
      const odd = await verifyBundle({ ...clone(good), subject: { fn } }, auditor());
      expect((odd.subject as { fn: unknown }).fn).toBe(fn);
      expect(bundleExitCode(odd)).toBe(2);
    });

    it('exits 2 for a report that cannot be written in canonical form: a lone surrogate in the subject (Verification §6.5)', async () => {
      for (const edit of [(b: Record<string, any>) => (b.subject['\ud800'] = 1), (b: Record<string, any>) => (b.subject.evidenceId = 'x\ud800')]) {
        const b = clone(good) as unknown as Record<string, any>;
        edit(b);
        const report = await verifyBundle(b, auditor());
        expect(() => comparableReport(report)).toThrow();
        expect(bundleExitCode(report)).toBe(2);
      }
    });
  });

  it('compares reports without checkedAt, in DEO canonical form', async () => {
    const a = await verifyBundle(good, auditor());
    const b = await verifyBundle(good, auditor());
    b.checkedAt = '1999-01-01T00:00:00.000Z';
    expect(comparableReport(a)).toBe(comparableReport(b));
    expect(comparableReport(a)).not.toContain('checkedAt');
    expect(JSON.parse(comparableReport(a))).toEqual(JSON.parse(JSON.stringify({ ...a, checkedAt: undefined })));
  });
});

describe('bundleExitCode: the scoped allowance', () => {
  // A report as a verifier writes it for a record with one link: the bundle
  // and the record hold, the link's edge abstains, and an assertion's
  // material is not checked for want of its credential.
  const report = (extra: Array<{ id: string; outcome: string; reason?: string }> = []) =>
    ({
      checks: [
        { id: 'bundle', outcome: 'checked-correct' },
        { id: 'record.digest', outcome: 'checked-correct' },
        { id: 'links', outcome: 'checked-correct' },
        { id: 'links[0]', outcome: 'checked-correct' },
        { id: 'links[0].edge', outcome: 'abstain', reason: 'unsupported_link_edge' },
        { id: 'anchor', outcome: 'not-checked', reason: 'absent' },
        ...extra,
      ],
      summary: { rungs: [] },
    }) as unknown as BundleVerificationReport;

  it('a list naming the only unchecked reason exits 0; the blanket form too', () => {
    expect(bundleExitCode(report())).toBe(4);
    expect(bundleExitCode(report(), { allowUnchecked: ['unsupported_link_edge'] })).toBe(0);
    expect(bundleExitCode(report(), { allowUnchecked: true })).toBe(0);
  });

  it('a row whose reason the list does not name still exits 4', () => {
    const r = report([{ id: 'signoff.key', outcome: 'not-checked', reason: 'material_unverified' }]);
    expect(bundleExitCode(r, { allowUnchecked: ['unsupported_link_edge'] })).toBe(4);
    expect(bundleExitCode(r, { allowUnchecked: ['unsupported_link_edge', 'material_unverified'] })).toBe(0);
    expect(bundleExitCode(r, { allowUnchecked: true })).toBe(0);
  });

  it('an empty list, false, or a list of non-strings allows nothing', () => {
    expect(bundleExitCode(report(), { allowUnchecked: [] })).toBe(4);
    expect(bundleExitCode(report(), { allowUnchecked: false })).toBe(4);
    expect(bundleExitCode(report(), { allowUnchecked: [1, null] as unknown as string[] })).toBe(4);
  });

  it('the allowance never lowers a failure, a missing requirement or an unreadable bundle', () => {
    const wrong = report([{ id: 'links[1]', outcome: 'checked-wrong', reason: 'link_target_mismatch' }]);
    expect(bundleExitCode(wrong, { allowUnchecked: ['unsupported_link_edge', 'link_target_mismatch'] })).toBe(1);
    expect(bundleExitCode(report(), { allowUnchecked: ['unsupported_link_edge'], require: ['anchor'] })).toBe(3);
    const unread = report();
    unread.checks[0] = { id: 'bundle', outcome: 'abstain', reason: 'unsupported_link_edge' } as never;
    expect(bundleExitCode(unread, { allowUnchecked: ['unsupported_link_edge'] })).toBe(2);
  });
});
