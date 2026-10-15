/**
 * Anchor §10.3, §10.6: `verifyAnchor`, step 6 and the verdict
 * fields. Steps 1 to 5, reason by reason, are pinned by
 * vectors/checkpoint-vectors.json (tests/ts/checkpoint-vectors.test.ts).
 *
 * No mocks of ethers and no network. EVM publications are really signed by
 * throwaway keys into fabricated blocks, and the header source is a fake the
 * test controls. RFC 3161 publications are genuine tokens from a throwaway CA
 * (tests/ts/rfc3161-fixture.ts), trusted only when its root is supplied.
 */
import { Transaction, Wallet } from 'ethers';
import { verifyAnchor, type AnchorVerifyOptions } from '../../src/attestation/anchor-verify';
import { verifyAttestation } from '../../src/attestation/verify-attestation';
import * as rfc3161Verify from '../../src/attestation/rfc3161-verify';
import { MERKLE_SPEC, merkleLeafHash } from '../../src/attestation/merkle';
import type {
  EvmHeaderSource,
  EvmSourceTransaction,
  PublisherManifest,
  PublisherManifestEntry,
} from '../../src/attestation/blockchain';
import { makeTsaFixture, type TokenFaults } from './rfc3161-fixture';
import { SEPOLIA, fabricateBlock, publicationFrom, signAnchorTx, signLegacy, type FabricatedBlock } from './helpers/evm-fixtures';
import { PLATFORM_PREFIX, SDK_PREFIX, TEST_PREFIX, anchoredRecord, sha256, type AnchoredRecord } from './helpers/anchor-fixtures';

const SEPOLIA_CHAIN = 'eip155:11155111';

/** The auditor's own view of the chain. */
class FakeHeaderSource implements EvmHeaderSource {
  finalized: number;
  blocks = new Map<number, { hash: string; timestamp: number }>();
  txs = new Map<string, EvmSourceTransaction>();
  hang = false;

  constructor(block: FabricatedBlock, opts: { finalizedDepth?: number } = {}) {
    this.finalized = block.number + (opts.finalizedDepth ?? 64);
    this.blocks.set(block.number, { hash: block.hash, timestamp: block.timestamp });
    for (const raw of block.raws) {
      const t = Transaction.from(raw);
      this.txs.set(t.hash!, { from: t.from!, blockHash: block.hash, blockNumber: block.number, rawTransaction: raw });
    }
  }
  async chainId() {
    if (this.hang) await new Promise(() => undefined);
    return SEPOLIA;
  }
  async finalizedBlockNumber() {
    return this.finalized;
  }
  async canonicalBlock(n: number) {
    return this.blocks.get(n) ?? null;
  }
  async transaction(id: string) {
    return this.txs.get(id) ?? null;
  }
}

function manifestFor(origin: string, ...entries: PublisherManifestEntry[]): PublisherManifest {
  return { publishers: { [origin]: entries } };
}

function entry(wallet: { address: string }, namespace: 'production' | 'test' = 'production'): PublisherManifestEntry {
  return { address: wallet.address, chain: SEPOLIA_CHAIN, namespace };
}

interface EvmScenario {
  record: AnchoredRecord;
  publisher: ReturnType<typeof Wallet.createRandom>;
  block: FabricatedBlock;
  source: FakeHeaderSource;
  /** The bundle form (Bundle §7.4): every field, raw transaction, header and trie proof included. */
  full: ReturnType<typeof publicationFrom>;
  /** The envelope form (Anchor §8.2): no heavy material. */
  envelope: Record<string, unknown>;
  options: AnchorVerifyOptions;
}

/** The publisher's zero-value self-transaction carrying P, mined at index 1 of a fabricated block. */
async function evmScenario(
  opts: { record?: AnchoredRecord; signer?: ReturnType<typeof Wallet.createRandom>; data?: string; timestamp?: number } = {},
): Promise<EvmScenario> {
  const record = opts.record ?? anchoredRecord();
  const publisher = Wallet.createRandom();
  const signer = opts.signer ?? publisher;
  const raw = await signAnchorTx(signer, { data: opts.data ?? '0x' + record.p, to: signer === publisher ? undefined : publisher.address });
  const filler = await signAnchorTx(Wallet.createRandom(), { data: '0x' + sha256('filler') });
  const block = fabricateBlock([filler, raw], 7_123_456, opts.timestamp ?? 1_790_000_000);
  const source = new FakeHeaderSource(block);
  const full = publicationFrom(block, 1);
  const envelope = {
    kind: 'evm-calldata/1',
    chain: SEPOLIA_CHAIN,
    transactionId: full.transactionId,
    blockNumber: full.blockNumber,
    blockHash: full.blockHash,
    publisher: publisher.address,
  };
  return {
    record,
    publisher,
    block,
    source,
    full,
    envelope,
    options: {
      sequenceNumber: record.sequenceNumber,
      chainId: record.chainId,
      publisherManifest: manifestFor(record.anchorOrigin, entry(publisher)),
      evmHeaderSources: { [SEPOLIA_CHAIN]: source },
    },
  };
}

async function tsaPublication(p: string, genTime = new Date('2026-09-20T12:00:00Z')) {
  const tsa = await makeTsaFixture({ digestHex: p, genTime });
  return { publication: { kind: 'rfc3161/1' as const, token: tsa.tokenBase64 }, caPem: tsa.caPem, genTime };
}

const withPublications = (r: AnchoredRecord, publications: unknown[]) => ({ anchor: { ...r.anchor, publications } });

describe('verifyAnchor (Anchor §10.3, §10.6): an RFC 3161-only anchor', () => {
  it('under a production-looking origin → anchored, existed-by only, namespace null', async () => {
    const r = anchoredRecord({ domainPrefix: PLATFORM_PREFIX, logOrigin: `${PLATFORM_PREFIX}/${sha256('opaque').slice(0, 32)}` });
    const tsa = await tsaPublication(r.p);

    const v = await verifyAnchor(withPublications(r, [tsa.publication]), r.digest, {
      sequenceNumber: r.sequenceNumber,
      chainId: 'user-abc',
      trustAnchorsPem: [tsa.caPem],
    });

    expect(v.anchorValid).toBe(true);
    expect(v.anchorReason).toBeUndefined();
    expect(v.anchorPublication).toBe('rfc3161');
    // A TSA token authenticates the TSA, not who named the origin: anyone can
    // build a log under log.tzun.ai/… and get a token over its P.
    expect(v.anchorOriginAuthenticated).toBe(false);
    expect(v.anchorNamespace).toBeNull();
    expect(v.anchorNetwork).toBeNull();
    expect(v.existedBy).toEqual({ at: tsa.genTime.toISOString(), source: 'rfc3161' });
    expect(v.anchorPosition).toMatchObject({
      origin: r.logOrigin,
      leafIndexChecked: true,
      // Platform origins are opaque: the chain cannot be checked from them.
      chainChecked: false,
      authenticated: false,
    });
    expect(v.publications).toEqual([
      expect.objectContaining({
        index: 0,
        kind: 'rfc3161/1',
        valid: true,
        checks: [
          { id: 'anchor.publication[0]', outcome: 'checked-correct', value: true },
          { id: 'anchor.tsa.token[0]', outcome: 'checked-correct', value: true },
          {
            id: 'anchor.tsa.trust[0]',
            outcome: 'checked-correct',
            value: true,
            facts: { genTime: tsa.genTime.toISOString(), authority: 'Acme Timestamping Authority' },
          },
        ],
      }),
    ]);
  });

  it('under an SDK origin → namespace null too', async () => {
    const r = anchoredRecord();
    const tsa = await tsaPublication(r.p);
    const v = await verifyAnchor(withPublications(r, [tsa.publication]), r.digest, { trustAnchorsPem: [tsa.caPem] });
    expect(v).toMatchObject({ anchorValid: true, anchorOriginAuthenticated: false, anchorNamespace: null });
  });

  it('under a test. origin → namespace test, because labelling yourself test is never an escalation', async () => {
    const r = anchoredRecord({ domainPrefix: TEST_PREFIX });
    const tsa = await tsaPublication(r.p);
    const v = await verifyAnchor(withPublications(r, [tsa.publication]), r.digest, { trustAnchorsPem: [tsa.caPem] });
    expect(v).toMatchObject({ anchorValid: true, anchorOriginAuthenticated: false, anchorNamespace: 'test' });
  });
});

describe('rfc3161/1 publications', () => {
  // TZUN_TSA_* in the environment count as trust input, so each case starts without them.
  const TRUST_ENV = ['TZUN_TSA_TRUST_ANCHORS', 'TZUN_TSA_AUTHORITIES'] as const;
  const savedEnv: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const name of TRUST_ENV) {
      savedEnv[name] = process.env[name];
      delete process.env[name];
    }
  });
  afterEach(() => {
    for (const name of TRUST_ENV) {
      if (savedEnv[name] === undefined) delete process.env[name];
      else process.env[name] = savedEnv[name];
    }
  });

  it('no trust anchors supplied → null, publication_not_checked: the built-in default roots are not a trust input', async () => {
    const r = anchoredRecord();
    const tsa = await tsaPublication(r.p);
    // With no trust input, the token is not judged against the SDK's default
    // store (FreeTSA and Sectigo) either: Anchor §10.2 needs a root the caller supplied.
    const resolveSpy = jest.spyOn(rfc3161Verify, 'verifyTimestampToken');
    try {
      const v = await verifyAnchor(withPublications(r, [tsa.publication]), r.digest);
      expect(resolveSpy).not.toHaveBeenCalled();
      expect(v).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked', existedBy: null });
      expect(v.publications[0]).toMatchObject({
        valid: null,
        reason: 'publication_not_checked',
        rfc3161: { genTime: tsa.genTime.toISOString() },
      });
      expect(v.publications[0].checks).toEqual([
        { id: 'anchor.publication[0]', outcome: 'checked-correct', value: true },
        { id: 'anchor.tsa.token[0]', outcome: 'not-checked', value: null, reason: 'blocked_by:anchor.tsa.trust[0]' },
        { id: 'anchor.tsa.trust[0]', outcome: 'not-checked', value: null, reason: 'no_matching_trust_anchor' },
      ]);

      for (const empty of [{ trustAnchorsPem: [] }, { authorities: [] }]) {
        const w = await verifyAnchor(withPublications(r, [tsa.publication]), r.digest, empty);
        expect(w).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
      }
    } finally {
      resolveSpy.mockRestore();
    }
  });

  it('trust anchors from the environment count as supplied', async () => {
    const r = anchoredRecord();
    const tsa = await tsaPublication(r.p);
    process.env.TZUN_TSA_TRUST_ANCHORS = tsa.caPem;
    const v = await verifyAnchor(withPublications(r, [tsa.publication]), r.digest);
    expect(v).toMatchObject({ anchorValid: true, anchorPublication: 'rfc3161' });
  });

  it('a token that reaches none of the supplied roots → null, publication_not_checked, no_matching_trust_anchor on the trust check, never false (Anchor §10.1)', async () => {
    const r = anchoredRecord();
    const tsa = await tsaPublication(r.p);
    const other = await makeTsaFixture({ caCN: 'Another Test Root CA' });
    const v = await verifyAnchor(withPublications(r, [tsa.publication]), r.digest, { trustAnchorsPem: [other.caPem] });
    expect(v.anchorValid).toBeNull();
    expect(v.anchorReason).toBe('publication_not_checked');
    expect(v.publications[0]).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.existedBy).toBeNull();
    expect(v.publications[0].checks).toEqual([
      { id: 'anchor.publication[0]', outcome: 'checked-correct', value: true },
      { id: 'anchor.tsa.token[0]', outcome: 'not-checked', value: null, reason: 'blocked_by:anchor.tsa.trust[0]' },
      { id: 'anchor.tsa.trust[0]', outcome: 'not-checked', value: null, reason: 'no_matching_trust_anchor' },
    ]);
    // Undecided, so the position is still reported, unauthenticated.
    expect(v.anchorPosition).toMatchObject({ authenticated: false });
  });

  it('an untrusted token over the wrong imprint is still null: nothing trusted vouched for it', async () => {
    const r = anchoredRecord();
    const tsa = await tsaPublication(sha256('another P'));
    const other = await makeTsaFixture({ caCN: 'Another Test Root CA' });
    const v = await verifyAnchor(withPublications(r, [tsa.publication]), r.digest, { trustAnchorsPem: [other.caPem] });
    expect(v).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
    expect(v.publications[0].checks[2]).toMatchObject({ id: 'anchor.tsa.trust[0]', reason: 'no_matching_trust_anchor' });
  });

  // The two cases below reach a supplied root and then fail on it. D-13 reads
  // them as false; the chain result verifyTimestampToken returns does not say
  // which link failed, so they read as null, publication_not_checked, with
  // no_matching_trust_anchor on the trust check.
  it('a TSA certificate expired at genTime, under a supplied root → null, no_matching_trust_anchor on the trust check', async () => {
    const r = anchoredRecord();
    const genTime = new Date('2026-09-20T12:00:00Z');
    const expired = await makeTsaFixture({ digestHex: r.p, genTime, signerNotAfter: new Date('2025-01-01T00:00:00Z') });
    const direct = await rfc3161Verify.verifyTimestampToken(expired.tokenBase64, r.p, { trustAnchorsPem: [expired.caPem] });
    expect(direct).toMatchObject({ valid: false, reason: 'untrusted_chain', certificateChainValid: false });
    expect(direct.error).toMatch(/not valid at the timestamp's genTime/);

    const v = await verifyAnchor(
      withPublications(r, [{ kind: 'rfc3161/1', token: expired.tokenBase64 }]),
      r.digest,
      { trustAnchorsPem: [expired.caPem] },
    );
    expect(v).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked', existedBy: null });
    expect(v.publications[0].checks[2]).toMatchObject({ id: 'anchor.tsa.trust[0]', reason: 'no_matching_trust_anchor' });
  });

  it("a certificate naming a supplied root as issuer, signed by another key → null, no_matching_trust_anchor on the trust check", async () => {
    const r = anchoredRecord();
    const trusted = await makeTsaFixture();
    // The same CA name, a different key: the path finds the trusted root by
    // name, and the signature does not verify under it.
    const impostor = await makeTsaFixture({ digestHex: r.p, genTime: new Date('2026-09-20T12:00:00Z') });
    const direct = await rfc3161Verify.verifyTimestampToken(impostor.tokenBase64, r.p, { trustAnchorsPem: [trusted.caPem] });
    expect(direct.error).toMatch(/signature does not verify against the trusted CA public key/);

    const v = await verifyAnchor(
      withPublications(r, [{ kind: 'rfc3161/1', token: impostor.tokenBase64 }]),
      r.digest,
      { trustAnchorsPem: [trusted.caPem] },
    );
    expect(v).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
    expect(v.publications[0].checks[2]).toMatchObject({ id: 'anchor.tsa.trust[0]', reason: 'no_matching_trust_anchor' });
  });

  it('a trusted token over another value → false, rfc3161_imprint_mismatch, and nothing is reported as fact', async () => {
    const r = anchoredRecord();
    const tsa = await tsaPublication(sha256('another P'));
    const v = await verifyAnchor(withPublications(r, [tsa.publication]), r.digest, { trustAnchorsPem: [tsa.caPem] });
    expect(v.anchorValid).toBe(false);
    expect(v.anchorReason).toBe('rfc3161_imprint_mismatch');
    expect(v.merkleProofValid).toBe(true);
    expect(v.anchorPosition).toBeNull();
    expect(v.existedBy).toBeNull();
    expect(v.anchorPublication).toBeNull();
    expect(v.publications[0].checks).toEqual([
      { id: 'anchor.publication[0]', outcome: 'checked-correct', value: true },
      { id: 'anchor.tsa.token[0]', outcome: 'checked-wrong', value: false, reason: 'rfc3161_imprint_mismatch' },
      { id: 'anchor.tsa.trust[0]', outcome: 'checked-correct', value: true, facts: expect.objectContaining({ genTime: expect.any(String) }) },
    ]);
  });

  it("a trusted token over P's bytes under another hash algorithm's OID → false, rfc3161_imprint_mismatch", async () => {
    const r = anchoredRecord();
    const sha512Oid = '2.16.840.1.101.3.4.2.3';
    const tsa = await makeTsaFixture({ digestHex: r.p, genTime: new Date('2026-09-20T12:00:00Z'), imprintAlgorithmOid: sha512Oid });
    // The shared token verifier holds the imprint to SHA-256 (tzun-anchor/1 §10.5 step 2).
    const direct = await rfc3161Verify.verifyTimestampToken(tsa.tokenBase64, r.p, { trustAnchorsPem: [tsa.caPem] });
    expect(direct).toMatchObject({ valid: false, reason: 'verification_failed', digestMatch: false, signatureValid: true, certificateChainValid: true });

    const v = await verifyAnchor(withPublications(r, [{ kind: 'rfc3161/1', token: tsa.tokenBase64 }]), r.digest, {
      trustAnchorsPem: [tsa.caPem],
    });
    expect(v).toMatchObject({ anchorValid: false, anchorReason: 'rfc3161_imprint_mismatch', existedBy: null });
    expect(v.publications[0].checks[1]).toMatchObject({ id: 'anchor.tsa.token[0]', outcome: 'checked-wrong', reason: 'rfc3161_imprint_mismatch' });
  });

  it('a trusted token whose CMS signature fails → false, rfc3161_signature_invalid', async () => {
    const r = anchoredRecord();
    const tsa = await tsaPublication(r.p);
    const spy = jest.spyOn(rfc3161Verify, 'verifyTimestampToken').mockResolvedValueOnce({
      valid: false,
      reason: 'verification_failed',
      digestMatch: true,
      signatureValid: false,
      certificateChainValid: true,
      genTime: new Date('2026-09-20T12:00:00Z'),
    });
    try {
      const v = await verifyAnchor(withPublications(r, [tsa.publication]), r.digest, { trustAnchorsPem: [tsa.caPem] });
      expect(v).toMatchObject({ anchorValid: false, anchorReason: 'rfc3161_signature_invalid', existedBy: null });
    } finally {
      spy.mockRestore();
    }
  });

  it('a verifier that cannot run CMS → null, publication_not_checked', async () => {
    const r = anchoredRecord();
    const tsa = await tsaPublication(r.p);
    const spy = jest
      .spyOn(rfc3161Verify, 'verifyTimestampToken')
      .mockResolvedValueOnce({ valid: false, reason: 'missing_dependency' });
    try {
      const v = await verifyAnchor(withPublications(r, [tsa.publication]), r.digest, { trustAnchorsPem: [tsa.caPem] });
      expect(v).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
      expect(v.publications[0].checks[1]).toMatchObject({ id: 'anchor.tsa.token[0]', outcome: 'not-checked', reason: 'missing_dependency' });
      expect(v.publications[0].checks[2]).toMatchObject({ id: 'anchor.tsa.trust[0]', reason: 'blocked_by:anchor.tsa.token[0]' });
    } finally {
      spy.mockRestore();
    }
  });

  it('a key on a curve the verifier does not implement → missing_dependency on the check whose step needs it; one no step needs is not examined (tzun-anchor/1 §10.5 step 5)', async () => {
    const r = anchoredRecord();
    const genTime = new Date('2026-09-20T12:00:00Z');
    const verdictFor = async (faults: TokenFaults) => {
      const tsa = await makeTsaFixture({ digestHex: r.p, genTime, faults });
      return verifyAnchor(withPublications(r, [{ kind: 'rfc3161/1', token: tsa.tokenBase64 }]), r.digest, { trustAnchorsPem: [tsa.caPem] });
    };
    const signer = await verdictFor({ signerKey: 'unassigned-curve' });
    expect(signer).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
    expect(signer.publications[0].checks.slice(1)).toEqual([
      { id: 'anchor.tsa.token[0]', outcome: 'not-checked', value: null, reason: 'missing_dependency' },
      { id: 'anchor.tsa.trust[0]', outcome: 'not-checked', value: null, reason: 'blocked_by:anchor.tsa.token[0]' },
    ]);
    const intermediate = await verdictFor({ signerIssuer: 'intermediate-unassigned-curve' });
    expect(intermediate).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
    expect(intermediate.publications[0].checks.slice(1)).toEqual([
      { id: 'anchor.tsa.token[0]', outcome: 'checked-correct', value: true },
      { id: 'anchor.tsa.trust[0]', outcome: 'not-checked', value: null, reason: 'missing_dependency' },
    ]);
    const unneeded = await verdictFor({ unneededCertificate: 'unassigned-curve' });
    expect(unneeded).toMatchObject({ anchorValid: true, anchorPublication: 'rfc3161' });
  });

  it('states authority on every trust check that holds, the empty string for a signer with no CN (tzun-anchor/1 §10.5 step 4, §10.7)', async () => {
    const r = anchoredRecord();
    const tsa = await makeTsaFixture({ digestHex: r.p, genTime: new Date('2026-09-20T12:00:00Z'), faults: { signerSubject: Buffer.from('3000', 'hex') } });
    const v = await verifyAnchor(withPublications(r, [{ kind: 'rfc3161/1', token: tsa.tokenBase64 }]), r.digest, { trustAnchorsPem: [tsa.caPem] });
    expect(v.publications[0].checks[2]).toEqual({
      id: 'anchor.tsa.trust[0]',
      outcome: 'checked-correct',
      value: true,
      facts: { genTime: '2026-09-20T12:00:00.000Z', authority: '' },
    });
  });

  it.each([
    ['not base64 DER', 'not-a-token'],
    ['empty', ''],
    ['not a string', 42],
    ['missing', undefined],
  ])('an unreadable token (%s) → false, malformed_publication, with or without trust input', async (_name, token) => {
    const r = anchoredRecord();
    for (const options of [{}, { trustAnchorsPem: [(await makeTsaFixture()).caPem] }]) {
      const v = await verifyAnchor(withPublications(r, [{ kind: 'rfc3161/1', token }]), r.digest, options);
      expect(v).toMatchObject({ anchorValid: false, anchorReason: 'malformed_publication', merkleProofValid: true });
      expect(v.publications[0].checks).toEqual([
        { id: 'anchor.publication[0]', outcome: 'checked-correct', value: true },
        { id: 'anchor.tsa.token[0]', outcome: 'checked-wrong', value: false, reason: 'malformed_publication' },
        { id: 'anchor.tsa.trust[0]', outcome: 'not-checked', value: null, reason: 'blocked_by:anchor.tsa.token[0]' },
      ]);
    }
  });
});

describe('evm-calldata/1 publications', () => {
  it("the publisher's transaction, confirmed final by the verifier's own source → authenticated, testnet, dated", async () => {
    const s = await evmScenario();
    const v = await verifyAnchor(withPublications(s.record, [s.full]), s.record.digest, s.options);

    expect(v.anchorValid).toBe(true);
    expect(v.anchorPublication).toBe('evm-calldata');
    expect(v.anchorOriginAuthenticated).toBe(true);
    expect(v.anchorNetwork).toBe('testnet');
    expect(v.anchorNamespace).toBe('production');
    expect(v.existedBy).toEqual({ at: new Date(s.block.timestamp * 1000).toISOString(), source: 'evm-calldata' });
    expect(v.anchorPosition).toMatchObject({ leafIndexChecked: true, chainChecked: true, authenticated: true });
    expect(v.checks.find((c) => c.id === 'anchor.origin')).toEqual({
      id: 'anchor.origin',
      outcome: 'checked-correct',
      value: true,
      facts: { originAuthenticated: true, namespace: 'production', chainChecked: true },
    });
    expect(v.publications[0]).toMatchObject({
      kind: 'evm-calldata/1',
      valid: true,
      evm: { sender: s.publisher.address.toLowerCase(), inclusion: 'tx_proof', chain: SEPOLIA_CHAIN },
    });
    // Anchor §10.7: the EVM facts are on the checks, each suffixed with the publication's index.
    expect(v.publications[0].checks).toEqual([
      { id: 'anchor.publication[0]', outcome: 'checked-correct', value: true },
      {
        id: 'anchor.evm.tx[0]',
        outcome: 'checked-correct',
        value: true,
        facts: { transactionId: s.full.transactionId, txType: 2, sender: s.publisher.address.toLowerCase(), signedChainId: '11155111' },
      },
      {
        id: 'anchor.evm.canonical[0]',
        outcome: 'checked-correct',
        value: true,
        facts: {
          chain: SEPOLIA_CHAIN,
          namespace: 'production',
          network: 'testnet',
          blockTime: new Date(s.block.timestamp * 1000).toISOString(),
          inclusion: 'tx_proof',
        },
      },
    ]);
    expect(v.checks[0]).toEqual({ id: 'anchor', outcome: 'checked-correct', value: true });
  });

  it("a test. origin is 'test' whatever the manifest says; any other authenticated origin takes the manifest entry's namespace (Anchor §10.6)", async () => {
    const t = await evmScenario({ record: anchoredRecord({ domainPrefix: TEST_PREFIX }) });
    const underTest = await verifyAnchor(withPublications(t.record, [t.full]), t.record.digest, {
      ...t.options,
      publisherManifest: manifestFor(t.record.anchorOrigin, entry(t.publisher, 'test')),
    });
    expect(underTest).toMatchObject({ anchorValid: true, anchorOriginAuthenticated: true, anchorNamespace: 'test' });
    // A production entry cannot make a test origin production.
    const underProduction = await verifyAnchor(withPublications(t.record, [t.full]), t.record.digest, t.options);
    expect(underProduction).toMatchObject({ anchorValid: true, anchorOriginAuthenticated: true, anchorNamespace: 'test' });

    const s = await evmScenario();
    const prod = await verifyAnchor(withPublications(s.record, [s.full]), s.record.digest, s.options);
    expect(prod).toMatchObject({ anchorValid: true, anchorNamespace: 'production' });
    const testEntry = await verifyAnchor(withPublications(s.record, [s.full]), s.record.digest, {
      ...s.options,
      publisherManifest: manifestFor(s.record.anchorOrigin, entry(s.publisher, 'test')),
    });
    expect(testEntry.anchorNamespace).toBe('test');
  });

  it('anchorFinality is what the header source counted as final, only for a true EVM publication', async () => {
    const s = await evmScenario();
    const plain = await verifyAnchor(withPublications(s.record, [s.full]), s.record.digest, s.options);
    expect(plain).toMatchObject({ anchorValid: true, anchorFinality: null });

    const depth = Object.assign(s.source, { finality: { confirmations: 2, acceptNonFinal: true } });
    const early = await verifyAnchor(withPublications(s.record, [s.full]), s.record.digest, {
      ...s.options,
      evmHeaderSources: { [SEPOLIA_CHAIN]: depth },
    });
    expect(early).toMatchObject({ anchorValid: true, anchorFinality: { confirmations: 2, acceptNonFinal: true } });
    expect(early.publications[0].evm?.finality).toEqual({ confirmations: 2, acceptNonFinal: true });
    expect(early.publications[0].checks[2].facts).toMatchObject({ finality: { confirmations: 2, acceptNonFinal: true }, inclusion: 'tx_proof' });

    // verifyAttestation surfaces it beside the other Anchor §10.6 fields.
    const viaAttestation = await verifyAttestation({ anchor: withPublications(s.record, [s.full]).anchor } as never, s.record.digest, undefined, {
      sequenceNumber: s.record.sequenceNumber,
      chainId: s.record.chainId,
      publisherManifest: s.options.publisherManifest,
      evmHeaderSources: { [SEPOLIA_CHAIN]: depth },
    });
    expect(viaAttestation).toMatchObject({ anchorValid: true, anchorFinality: { confirmations: 2, acceptNonFinal: true } });

    // Not final under it: undecided, and no anchor-level finality is claimed.
    depth.finalized = s.block.number - 1;
    const pending = await verifyAnchor(withPublications(s.record, [s.full]), s.record.digest, {
      ...s.options,
      evmHeaderSources: { [SEPOLIA_CHAIN]: depth },
    });
    expect(pending).toMatchObject({ anchorValid: null, anchorFinality: null, anchorReason: 'publication_not_checked' });
    expect(pending.publications[0].evm?.finality).toEqual({ confirmations: 2, acceptNonFinal: true });
    // Anchor §10.4 item 14: finality is the one fact of anchor.evm.canonical[i]
    // reported before that check is decided, and the only one.
    expect(pending.publications[0].checks[2]).toEqual({
      id: 'anchor.evm.canonical[0]',
      outcome: 'not-checked',
      value: null,
      reason: 'evm_block_not_finalized',
      facts: { finality: { confirmations: 2, acceptNonFinal: true } },
    });
  });

  it("the envelope's form alone carries no raw transaction → null; the bundle's material completes it", async () => {
    const s = await evmScenario();
    const bare = await verifyAnchor(withPublications(s.record, [s.envelope]), s.record.digest, s.options);
    expect(bare.anchorValid).toBeNull();
    expect(bare.anchorReason).toBe('publication_not_checked');
    // Nothing parsed, so no fact; the canonical check is blocked by the suffixed id.
    expect(bare.publications[0].checks).toEqual([
      { id: 'anchor.publication[0]', outcome: 'checked-correct', value: true },
      { id: 'anchor.evm.tx[0]', outcome: 'not-checked', value: null, reason: 'not_in_bundle:raw_transaction' },
      { id: 'anchor.evm.canonical[0]', outcome: 'not-checked', value: null, reason: 'blocked_by:anchor.evm.tx[0]' },
    ]);

    const { transactionId: _dropped, ...bundleEntry } = s.full;
    const joined = await verifyAnchor(withPublications(s.record, [s.envelope]), s.record.digest, {
      ...s.options,
      publicationMaterial: [{ kind: 'rfc3161/1', token: 'x' }, bundleEntry],
    });
    expect(joined.anchorValid).toBe(true);
    expect(joined.publications[0].evm).toMatchObject({ transactionId: s.full.transactionId, inclusion: 'tx_proof' });

    // JSON from nullable columns writes an absent field as null; a null in the
    // envelope never blanks the bundle's value.
    const nulls = { ...s.envelope, rawTransaction: null, blockHeader: null, txIndex: null, txProof: null };
    const filled = await verifyAnchor(withPublications(s.record, [nulls]), s.record.digest, {
      ...s.options,
      publicationMaterial: [bundleEntry],
    });
    expect(filled.anchorValid).toBe(true);
  });

  it("material is joined by the envelope's transaction id: another transaction's bytes, in this block or another, are not", async () => {
    const s = await evmScenario();
    const other = await evmScenario();
    const elsewhere = await verifyAnchor(withPublications(s.record, [s.envelope]), s.record.digest, {
      ...s.options,
      publicationMaterial: [other.full],
    });
    expect(elsewhere).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
    expect(elsewhere.publications[0].checks[1]).toMatchObject({ id: 'anchor.evm.tx[0]', reason: 'not_in_bundle:raw_transaction' });

    // Same block hash, another transaction's bytes: not this publication's material.
    const sameBlock = await verifyAnchor(withPublications(s.record, [s.envelope]), s.record.digest, {
      ...s.options,
      publicationMaterial: [{ ...s.full, transactionId: undefined, rawTransaction: s.block.raws[0], txIndex: 0, txProof: s.block.trie.proof(0) }],
    });
    expect(sameBlock).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });

    // This transaction's bytes under another block hash: not joined either.
    const otherHash = await verifyAnchor(withPublications(s.record, [s.envelope]), s.record.digest, {
      ...s.options,
      publicationMaterial: [{ ...s.full, blockHash: other.full.blockHash }],
    });
    expect(otherHash).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
  });

  it("an envelope's __proto__ member is an ordinary key when material joins: nothing is inherited from it", async () => {
    const s = await evmScenario();
    const { transactionId: _dropped, blockHeader, txIndex, txProof, ...partial } = s.full;
    const moved = { blockHeader, txIndex, txProof };
    // JSON.parse keeps a "__proto__" member as an own property, as a bundle read from a file has it.
    const withProto = (proto: unknown): Record<string, unknown> =>
      JSON.parse(`${JSON.stringify(s.envelope).slice(0, -1)},"__proto__":${JSON.stringify(proto)}}`);
    const verify = (envelope: unknown, material: unknown[]) =>
      verifyAnchor(withPublications(s.record, [envelope]), s.record.digest, { ...s.options, publicationMaterial: material });

    const plain = await verify(s.envelope, [partial]);
    expect(plain).toMatchObject({ anchorValid: true });
    for (const proto of [{ blockHeader: '0x00' }, moved]) {
      expect(await verify(withProto(proto), [partial])).toEqual(plain);
    }
    // The material's own fields are kept whatever __proto__ holds.
    const full = await verify(s.envelope, [{ ...partial, ...moved }]);
    expect(await verify(withProto({ blockHeader: '0x00' }), [{ ...partial, ...moved }])).toEqual(full);
  });

  it("a publication that carries another transaction's raw bytes itself → false, evm_tx_proof_invalid", async () => {
    const s = await evmScenario();
    const v = await verifyAnchor(
      withPublications(s.record, [{ ...s.full, rawTransaction: s.block.raws[0], txIndex: 0, txProof: s.block.trie.proof(0) }]),
      s.record.digest,
      s.options,
    );
    expect(v).toMatchObject({ anchorValid: false, anchorReason: 'evm_tx_proof_invalid' });
  });

  it('two publications mined in one block: each envelope joins its own transaction, in any order', async () => {
    // A backlog of epochs published together: the publisher lands P1 and P2 in one block.
    const publisher = Wallet.createRandom();
    const first = anchoredRecord({ before: 1 });
    const second = anchoredRecord({ before: 4 });
    const raw1 = await signAnchorTx(publisher, { data: '0x' + first.p, nonce: 7 });
    const raw2 = await signAnchorTx(publisher, { data: '0x' + second.p, nonce: 8 });
    const block = fabricateBlock([raw1, raw2]);
    const source = new FakeHeaderSource(block);
    const material = [publicationFrom(block, 0), publicationFrom(block, 1)].map(({ transactionId: _id, ...rest }) => rest);
    const envelopeOf = (index: number) => {
      const full = publicationFrom(block, index);
      return { kind: 'evm-calldata/1', transactionId: full.transactionId, blockNumber: full.blockNumber, blockHash: full.blockHash };
    };

    for (const [record, index] of [[first, 0], [second, 1]] as const) {
      for (const order of [material, [...material].reverse()]) {
        const v = await verifyAnchor(withPublications(record, [envelopeOf(index)]), record.digest, {
          sequenceNumber: record.sequenceNumber,
          chainId: record.chainId,
          publisherManifest: manifestFor(record.anchorOrigin, entry(publisher)),
          evmHeaderSources: { [SEPOLIA_CHAIN]: source },
          publicationMaterial: order,
        });
        expect(v).toMatchObject({ anchorValid: true, anchorPublication: 'evm-calldata', anchorOriginAuthenticated: true });
        expect(v.publications[0].evm).toMatchObject({ inclusion: 'tx_proof' });
      }
    }

    // With no transaction id, a block that holds two entries is ambiguous: nothing is joined.
    const { transactionId: _dropped, ...noId } = envelopeOf(0);
    const ambiguous = await verifyAnchor(withPublications(first, [noId]), first.digest, {
      publisherManifest: manifestFor(first.anchorOrigin, entry(publisher)),
      evmHeaderSources: { [SEPOLIA_CHAIN]: source },
      publicationMaterial: material,
    });
    expect(ambiguous).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
    // With one entry in that block, it is joined.
    const single = await verifyAnchor(withPublications(first, [noId]), first.digest, {
      publisherManifest: manifestFor(first.anchorOrigin, entry(publisher)),
      evmHeaderSources: { [SEPOLIA_CHAIN]: source },
      publicationMaterial: [material[0]],
    });
    expect(single).toMatchObject({ anchorValid: true });
  });

  it('no header source, or no manifest → null, and it contributes nothing', async () => {
    const s = await evmScenario();
    const noSource = await verifyAnchor(withPublications(s.record, [s.full]), s.record.digest, {
      ...s.options,
      evmHeaderSources: undefined,
    });
    expect(noSource).toMatchObject({
      anchorValid: null,
      anchorReason: 'publication_not_checked',
      anchorOriginAuthenticated: false,
      anchorNetwork: null,
      existedBy: null,
    });
    expect(noSource.publications[0].checks[2]).toMatchObject({ id: 'anchor.evm.canonical[0]', reason: 'input_not_supplied:evm_header_source' });
    expect(noSource.publications[0].checks[2]).not.toHaveProperty('facts');
    // The transaction parsed, so its facts are reported although the publication is undecided.
    expect(noSource.publications[0].checks[1]).toMatchObject({
      id: 'anchor.evm.tx[0]',
      outcome: 'checked-correct',
      facts: { sender: s.publisher.address.toLowerCase(), signedChainId: '11155111' },
    });

    const noManifest = await verifyAnchor(withPublications(s.record, [s.full]), s.record.digest, {
      ...s.options,
      publisherManifest: undefined,
    });
    expect(noManifest).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
    expect(noManifest.publications[0].checks[1]).toMatchObject({ id: 'anchor.evm.tx[0]', reason: 'no_expectation:publisher' });

    const otherOrigin = await verifyAnchor(withPublications(s.record, [s.full]), s.record.digest, {
      ...s.options,
      publisherManifest: manifestFor(`${TEST_PREFIX}/anchors`, entry(s.publisher)),
    });
    expect(otherOrigin.publications[0].checks[1]).toMatchObject({ reason: 'no_expectation:publisher' });
  });

  it('a transaction from another sender carrying P → false, evm_sender_mismatch', async () => {
    const attacker = Wallet.createRandom();
    const s = await evmScenario({ signer: attacker });
    const v = await verifyAnchor(withPublications(s.record, [s.full]), s.record.digest, s.options);
    expect(v).toMatchObject({ anchorValid: false, anchorReason: 'evm_sender_mismatch', anchorOriginAuthenticated: false });
    expect(v.anchorPosition).toBeNull();
    // The failing check still reports whom the transaction came from.
    expect(v.publications[0].checks[1]).toMatchObject({
      id: 'anchor.evm.tx[0]',
      outcome: 'checked-wrong',
      reason: 'evm_sender_mismatch',
      facts: { sender: attacker.address.toLowerCase() },
    });
    expect(v.checks[0]).toEqual({ id: 'anchor', outcome: 'checked-wrong', value: false, reason: 'evm_sender_mismatch' });
  });

  it("the publisher's transaction carrying another anchor's P → false, evm_calldata_mismatch", async () => {
    const s = await evmScenario({ data: '0x' + anchoredRecord({ before: 5 }).p });
    const v = await verifyAnchor(withPublications(s.record, [s.full]), s.record.digest, s.options);
    expect(v).toMatchObject({ anchorValid: false, anchorReason: 'evm_calldata_mismatch' });
  });

  it('a header source that never answers → null within the deadline, evm_header_source_timeout', async () => {
    const s = await evmScenario();
    s.source.hang = true;
    const started = Date.now();
    const v = await verifyAnchor(withPublications(s.record, [s.full]), s.record.digest, { ...s.options, evmTimeoutMs: 50 });
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(v).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
    expect(v.publications[0].checks[2]).toMatchObject({ id: 'anchor.evm.canonical[0]', reason: 'evm_header_source_timeout' });
  });
});

describe('several publications', () => {
  it('EVM and RFC 3161 both true: the EVM rung, and the earlier of the two times', async () => {
    const s = await evmScenario({ timestamp: Date.parse('2026-09-20T12:30:00Z') / 1000 });
    const early = await tsaPublication(s.record.p, new Date('2026-09-20T12:00:00Z'));
    const v = await verifyAnchor(withPublications(s.record, [s.full, early.publication]), s.record.digest, {
      ...s.options,
      trustAnchorsPem: [early.caPem],
    });
    expect(v).toMatchObject({ anchorValid: true, anchorPublication: 'evm-calldata', anchorOriginAuthenticated: true });
    expect(v.existedBy).toEqual({ at: '2026-09-20T12:00:00.000Z', source: 'rfc3161' });

    const late = await tsaPublication(s.record.p, new Date('2026-09-20T13:00:00Z'));
    const w = await verifyAnchor(withPublications(s.record, [late.publication, s.full]), s.record.digest, {
      ...s.options,
      trustAnchorsPem: [late.caPem],
    });
    expect(w.existedBy).toEqual({ at: '2026-09-20T12:30:00.000Z', source: 'evm-calldata' });
  });

  it('an undecided EVM publication beside a true RFC 3161 one: anchored, existed-by only', async () => {
    const s = await evmScenario();
    const tsa = await tsaPublication(s.record.p);
    const v = await verifyAnchor(withPublications(s.record, [s.envelope, tsa.publication]), s.record.digest, {
      ...s.options,
      trustAnchorsPem: [tsa.caPem],
    });
    expect(v).toMatchObject({
      anchorValid: true,
      anchorPublication: 'rfc3161',
      anchorOriginAuthenticated: false,
      anchorNetwork: null,
    });
  });

  it('an artifact that lies about one publication is false, whatever the others say', async () => {
    const s = await evmScenario({ signer: Wallet.createRandom() });
    const tsa = await tsaPublication(s.record.p);
    const v = await verifyAnchor(withPublications(s.record, [tsa.publication, s.full]), s.record.digest, {
      ...s.options,
      trustAnchorsPem: [tsa.caPem],
    });
    expect(v.anchorValid).toBe(false);
    expect(v.anchorReason).toBe('evm_sender_mismatch');
    expect(v.publications.map((p) => p.valid)).toEqual([true, false]);
    expect(v).toMatchObject({
      anchorPublication: null,
      anchorOriginAuthenticated: false,
      anchorPosition: null,
      existedBy: null,
      anchorNamespace: null,
    });
  });

  it('a lie beside a true EVM publication authenticates nothing, in the origin check either', async () => {
    const s = await evmScenario();
    const v = await verifyAnchor(withPublications(s.record, [s.full, { kind: 'rfc3161/1', token: 'x' }]), s.record.digest, s.options);
    expect(v.publications.map((p) => p.valid)).toEqual([true, false]);
    expect(v).toMatchObject({ anchorValid: false, anchorReason: 'malformed_publication', anchorOriginAuthenticated: false, anchorNetwork: null });
    expect(v.checks.find((c) => c.id === 'anchor.origin')?.facts).toEqual({
      originAuthenticated: false,
      namespace: null,
      chainChecked: true,
    });
  });

  it('a kind this verifier does not implement is abstained on, and never hides a true one', async () => {
    const r = anchoredRecord();
    const witness = { kind: 'witness/1', cosignature: 'AA==' };
    const alone = await verifyAnchor(withPublications(r, [witness]), r.digest);
    expect(alone).toMatchObject({ anchorValid: null, anchorReason: 'unsupported_publication_kind' });
    expect(alone.publications[0]).toEqual({
      index: 0,
      kind: 'witness/1',
      valid: null,
      reason: 'unsupported_publication_kind',
      checks: [{ id: 'anchor.publication[0]', outcome: 'abstain', value: null, reason: 'unsupported_publication_kind' }],
    });
    expect(alone.checks[0]).toEqual({ id: 'anchor', outcome: 'abstain', value: null, reason: 'unsupported_publication_kind' });

    const tsa = await tsaPublication(r.p);
    const beside = await verifyAnchor(withPublications(r, [witness, tsa.publication]), r.digest, { trustAnchorsPem: [tsa.caPem] });
    expect(beside).toMatchObject({ anchorValid: true, anchorPublication: 'rfc3161' });
  });

  it('the first false publication, in the artifact\'s order, names the reason', async () => {
    const r = anchoredRecord();
    const v = await verifyAnchor(withPublications(r, [{ kind: 'rfc3161/1', token: 'x' }, 'junk']), r.digest);
    expect(v.anchorReason).toBe('malformed_publication');
    expect(v.publications).toHaveLength(2);
    expect(v.publications[1]).toEqual({
      index: 1,
      kind: null,
      valid: false,
      reason: 'malformed_publication',
      checks: [{ id: 'anchor.publication[1]', outcome: 'checked-wrong', value: false, reason: 'malformed_publication' }],
    });
  });
});

// tzun-anchor/1 §10.3 step 2: the members are exactly those of §8.1, with their
// types, and `publications` is a non-empty array (malformed_anchor); both
// bodies parse (malformed_checkpoint); both paths are arrays of hashes
// (malformed_merkle_path). Every one is false at `anchor.checkpoint`, blocks
// the steps after it, and reports no P and no publication.
describe('step 2: the shape of the artifact (tzun-anchor/1 §10.3)', () => {
  const edited = (edit: (a: Record<string, unknown>) => void) => {
    const r = anchoredRecord();
    const anchor = JSON.parse(JSON.stringify(r.anchor)) as Record<string, unknown>;
    edit(anchor);
    return { r, bag: { anchor } };
  };
  const refusedAtStep2 = async (edit: (a: Record<string, unknown>) => void, reason: string) => {
    const { r, bag } = edited(edit);
    const v = await verifyAnchor(bag, r.digest, { sequenceNumber: r.sequenceNumber, chainId: r.chainId });
    expect(v).toMatchObject({ anchorPresent: true, anchorValid: false, anchorReason: reason, merkleProofValid: null, p: null, anchorPosition: null });
    expect(v.checks.map((c) => [c.id, c.outcome, c.reason])).toEqual([
      ['anchor', 'checked-wrong', reason],
      ['anchor.spec', 'checked-correct', undefined],
      ['anchor.checkpoint', 'checked-wrong', reason],
      ['anchor.origin', 'not-checked', 'blocked_by:anchor.checkpoint'],
      ['anchor.leafIndex', 'not-checked', 'blocked_by:anchor.checkpoint'],
      ['anchor.inclusion', 'not-checked', 'blocked_by:anchor.checkpoint'],
      ['anchor.anchorInclusion', 'not-checked', 'blocked_by:anchor.checkpoint'],
    ]);
    expect(v.publications).toEqual([]);
  };

  it('an empty publications list → false, malformed_anchor (not an undecided anchor)', async () => {
    await refusedAtStep2((a) => {
      a.publications = [];
    }, 'malformed_anchor');
  });

  it.each<[string, unknown]>([
    ['an object', { kind: 'evm-calldata/1' }],
    ['a string', 'evm-calldata/1'],
    ['null', null],
  ])('publications that is %s → false, malformed_anchor at step 2', async (_label, publications) => {
    await refusedAtStep2((a) => {
      a.publications = publications;
    }, 'malformed_anchor');
  });

  it.each<[string, (a: Record<string, unknown>) => void]>([
    ['a member added', (a) => { a.blockchainAnchor = {}; }],
    ['a member missing', (a) => { delete a.anchorLeafIndex; }],
    ['leafIndex as a numeric string', (a) => { a.leafIndex = '2'; }],
    ['leafIndex negative', (a) => { a.leafIndex = -1; }],
    ['leafIndex fractional', (a) => { a.leafIndex = 2.5; }],
    ['anchorLeafIndex past 2^53 − 1', (a) => { a.anchorLeafIndex = 2 ** 53; }],
  ])('%s → false, malformed_anchor', async (_label, edit) => {
    await refusedAtStep2(edit, 'malformed_anchor');
  });

  it.each<[string, (a: Record<string, unknown>) => void]>([
    ['logPath a string', (a) => { a.logPath = (a.logPath as string[]).join(''); }],
    ['logPath null', (a) => { a.logPath = null; }],
    ['anchorPath an object', (a) => { a.anchorPath = { 0: (a.anchorPath as string[])[0] }; }],
    ['a logPath element with a 0x prefix', (a) => { (a.logPath as string[])[0] = '0x' + (a.logPath as string[])[0]; }],
    ['an anchorPath element of 63 digits', (a) => { (a.anchorPath as string[])[0] = (a.anchorPath as string[])[0].slice(1); }],
    ['a legacy "left:<hash>" element', (a) => { (a.logPath as string[])[0] = 'left:' + (a.logPath as string[])[0]; }],
  ])('%s → false, malformed_merkle_path (not merkle_proof_invalid)', async (_label, edit) => {
    await refusedAtStep2(edit, 'malformed_merkle_path');
  });

  it('a path element in uppercase hex is read (the encoding rule of [TREE] §4)', async () => {
    const { r, bag } = edited((a) => {
      a.logPath = (a.logPath as string[]).map((h) => h.toUpperCase());
    });
    const v = await verifyAnchor(bag, r.digest, { sequenceNumber: r.sequenceNumber, chainId: r.chainId });
    expect(v).toMatchObject({ merkleProofValid: true, anchorValid: null, anchorReason: 'publication_not_checked' });
  });

  it('the shape is checked before the bodies: a malformed body beside a missing member is malformed_anchor', async () => {
    await refusedAtStep2((a) => {
      a.logCheckpoint = 'not a body';
      delete a.anchorPath;
    }, 'malformed_anchor');
  });

  it('a log checkpoint that names the anchor origin fails step 2b, origin_not_in_domain', async () => {
    const { r, bag } = edited((a) => {
      a.logCheckpoint = a.anchorCheckpoint;
    });
    const v = await verifyAnchor(bag, r.digest, { sequenceNumber: r.sequenceNumber });
    expect(v).toMatchObject({ anchorValid: false, anchorReason: 'origin_not_in_domain', p: r.p });
    expect(v.checks[3]).toEqual({ id: 'anchor.origin', outcome: 'checked-wrong', value: false, reason: 'origin_not_in_domain' });
  });

  it('undecided: publication_not_checked when any publication was not checked, even after an abstention (Anchor §10.6)', async () => {
    const r = anchoredRecord();
    const abstainFirst = await verifyAnchor(withPublications(r, [{ kind: 'witness/1' }, r.anchor.publications[0]]), r.digest);
    expect(abstainFirst).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
    const abstainOnly = await verifyAnchor(withPublications(r, [{ kind: 'witness/1' }, { token: 'x' }]), r.digest);
    expect(abstainOnly).toMatchObject({ anchorValid: null, anchorReason: 'unsupported_publication_kind' });
  });
});

describe('the step checks', () => {
  it('report the whole catalogue in order (tzun-anchor/1 §10.7): anchor, every step with its facts, then each publication', async () => {
    const r = anchoredRecord();
    const v = await verifyAnchor({ anchor: r.anchor }, r.digest, { sequenceNumber: r.sequenceNumber, chainId: r.chainId });
    expect(v.checks).toEqual([
      { id: 'anchor', outcome: 'not-checked', value: null, reason: 'publication_not_checked' },
      { id: 'anchor.spec', outcome: 'checked-correct', value: true },
      { id: 'anchor.checkpoint', outcome: 'checked-correct', value: true },
      {
        id: 'anchor.origin',
        outcome: 'checked-correct',
        value: true,
        facts: { originAuthenticated: false, namespace: null, chainChecked: true },
      },
      { id: 'anchor.leafIndex', outcome: 'checked-correct', value: true, facts: { leafIndexChecked: true } },
      { id: 'anchor.inclusion', outcome: 'checked-correct', value: true },
      { id: 'anchor.anchorInclusion', outcome: 'checked-correct', value: true },
      { id: 'anchor.publication[0]', outcome: 'checked-correct', value: true },
      { id: 'anchor.evm.tx[0]', outcome: 'not-checked', value: null, reason: 'not_in_bundle:raw_transaction' },
      { id: 'anchor.evm.canonical[0]', outcome: 'not-checked', value: null, reason: 'blocked_by:anchor.evm.tx[0]' },
    ]);
    expect(v).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked', merkleProofValid: true, p: r.p });
    expect(v.publications[0].checks).toEqual(v.checks.slice(7));
  });

  it('a step that fails blocks the ones after it, is reported once, and no publication is dispatched', async () => {
    const r = anchoredRecord();
    const v = await verifyAnchor({ anchor: r.anchor }, r.digest, { sequenceNumber: r.sequenceNumber + 1 });
    expect(v.checks.map((c) => [c.id, c.outcome, c.reason])).toEqual([
      ['anchor', 'checked-wrong', 'leaf_index_mismatch'],
      ['anchor.spec', 'checked-correct', undefined],
      ['anchor.checkpoint', 'checked-correct', undefined],
      ['anchor.origin', 'checked-correct', undefined],
      ['anchor.leafIndex', 'checked-wrong', 'leaf_index_mismatch'],
      ['anchor.inclusion', 'not-checked', 'blocked_by:anchor.leafIndex'],
      ['anchor.anchorInclusion', 'not-checked', 'blocked_by:anchor.leafIndex'],
    ]);
    // The index was compared, so the fact is true on the failing check; the
    // origin held, so its facts are reported, with nothing authenticated.
    expect(v.checks[4].facts).toEqual({ leafIndexChecked: true });
    expect(v.checks[3].facts).toEqual({ originAuthenticated: false, namespace: null, chainChecked: false });
    expect(v.publications).toEqual([]);
  });

  it('a step that fails after the origin held, under a test origin, still reports the test namespace on the origin check', async () => {
    const r = anchoredRecord({ domainPrefix: TEST_PREFIX });
    const v = await verifyAnchor({ anchor: r.anchor }, sha256('another digest'), { chainId: r.chainId });
    expect(v).toMatchObject({ anchorValid: false, anchorReason: 'merkle_proof_invalid', anchorNamespace: 'test' });
    expect(v.checks.find((c) => c.id === 'anchor.origin')?.facts).toEqual({ originAuthenticated: false, namespace: 'test', chainChecked: true });
    expect(v.checks.find((c) => c.id === 'anchor.leafIndex')).toEqual({
      id: 'anchor.leafIndex',
      outcome: 'not-checked',
      value: null,
      reason: 'input_not_supplied:sequence_number',
      facts: { leafIndexChecked: false },
    });
  });

  it('a record placed in an SDK log of another kind fails step 2b, with its chain supplied or not', async () => {
    const r = anchoredRecord({ logOrigin: `${SDK_PREFIX}/custody` });
    const v = await verifyAnchor({ anchor: r.anchor }, r.digest, { sequenceNumber: r.sequenceNumber, chainId: 'default' });
    expect(v).toMatchObject({ anchorValid: false, anchorReason: 'chain_id_mismatch', anchorPosition: null });
    expect(v.checks[3]).toEqual({ id: 'anchor.origin', outcome: 'checked-wrong', value: false, reason: 'chain_id_mismatch' });

    // A store's log of another kind never holds a record, so no chain id is
    // needed to refuse it.
    const unchecked = await verifyAnchor({ anchor: r.anchor }, r.digest, { sequenceNumber: r.sequenceNumber });
    expect(unchecked).toMatchObject({ anchorValid: false, anchorReason: 'chain_id_mismatch', anchorPosition: null });
    expect(unchecked.checks[3]).toEqual({ id: 'anchor.origin', outcome: 'checked-wrong', value: false, reason: 'chain_id_mismatch' });
  });

  it('no sequence number: leafIndex not checked, the proofs still run', async () => {
    const r = anchoredRecord();
    const v = await verifyAnchor({ anchor: r.anchor }, r.digest);
    expect(v.checks[4]).toEqual({
      id: 'anchor.leafIndex',
      outcome: 'not-checked',
      value: null,
      reason: 'input_not_supplied:sequence_number',
      facts: { leafIndexChecked: false },
    });
    expect(v.merkleProofValid).toBe(true);
    expect(v.anchorPosition).toMatchObject({ leafIndexChecked: false, chainChecked: false });
  });

  it('nothing attached: absent, never pending or abstained', async () => {
    const v = await verifyAnchor({}, 'ab'.repeat(32));
    expect(v.anchorPresent).toBe(false);
    expect(v.anchorValid).toBeNull();
    expect(v.anchorReason).toBeUndefined();
    expect(v.checks.map((c) => c.id)).toEqual([
      'anchor',
      'anchor.spec',
      'anchor.checkpoint',
      'anchor.origin',
      'anchor.leafIndex',
      'anchor.inclusion',
      'anchor.anchorInclusion',
    ]);
    expect(v.checks.every((c) => c.outcome === 'not-checked' && c.reason === 'absent')).toBe(true);
  });

  it('a legacy blockchainAnchor alone: present, abstained on', async () => {
    const v = await verifyAnchor({ blockchainAnchor: { merkleSpec: MERKLE_SPEC } }, 'ab'.repeat(32));
    expect(v).toMatchObject({ anchorPresent: true, anchorValid: null, anchorReason: 'legacy_blockchain_anchor' });
    expect(v.checks[0]).toEqual({ id: 'anchor', outcome: 'abstain', value: null, reason: 'legacy_blockchain_anchor' });
    expect(v.checks[1]).toEqual({ id: 'anchor.spec', outcome: 'abstain', value: null, reason: 'legacy_blockchain_anchor' });
    expect(v.checks[2]).toMatchObject({ outcome: 'not-checked', reason: 'blocked_by:anchor.spec' });
  });
});

describe('the check catalogue (tzun-anchor/1 §10.7)', () => {
  it('each publication check carries its index, and a blocked_by names the suffixed id', async () => {
    const s = await evmScenario();
    const first = await tsaPublication(s.record.p, new Date('2026-09-20T12:00:00Z'));
    const second = await makeTsaFixture({ digestHex: s.record.p, genTime: new Date('2026-09-20T12:05:00Z'), signerCN: 'Second Timestamping Authority', caCN: 'Second Test Root CA' });
    const v = await verifyAnchor(
      withPublications(s.record, [s.envelope, first.publication, { kind: 'rfc3161/1', token: second.tokenBase64 }, 'junk']),
      s.record.digest,
      { ...s.options, trustAnchorsPem: [first.caPem] },
    );
    expect(v.checks.slice(7).map((c) => [c.id, c.outcome, c.reason])).toEqual([
      ['anchor.publication[0]', 'checked-correct', undefined],
      ['anchor.evm.tx[0]', 'not-checked', 'not_in_bundle:raw_transaction'],
      ['anchor.evm.canonical[0]', 'not-checked', 'blocked_by:anchor.evm.tx[0]'],
      ['anchor.publication[1]', 'checked-correct', undefined],
      ['anchor.tsa.token[1]', 'checked-correct', undefined],
      ['anchor.tsa.trust[1]', 'checked-correct', undefined],
      // Two tokens from two authorities are told apart by their index.
      ['anchor.publication[2]', 'checked-correct', undefined],
      ['anchor.tsa.token[2]', 'not-checked', 'blocked_by:anchor.tsa.trust[2]'],
      ['anchor.tsa.trust[2]', 'not-checked', 'no_matching_trust_anchor'],
      ['anchor.publication[3]', 'checked-wrong', 'malformed_publication'],
    ]);
    expect(v.checks[7 + 5].facts).toEqual({ genTime: '2026-09-20T12:00:00.000Z', authority: 'Acme Timestamping Authority' });
    expect(v.checks[0]).toEqual({ id: 'anchor', outcome: 'checked-wrong', value: false, reason: 'malformed_publication' });
    // Each publication's checks are its slice of the catalogue, in order.
    expect(v.publications.flatMap((p) => p.checks)).toEqual(v.checks.slice(7));
    // Every id is unique within one report.
    expect(new Set(v.checks.map((c) => c.id)).size).toBe(v.checks.length);
  });

  it.each<[string, Record<string, unknown>, Partial<AnchorVerifyOptions>, unknown]>([
    ['true', {}, {}, { outcome: 'checked-correct', value: true }],
    ['false', {}, { chainId: 'other' }, { outcome: 'checked-wrong', value: false, reason: 'chain_id_mismatch' }],
    ['undecided', { publications: 'envelope' }, {}, { outcome: 'not-checked', value: null, reason: 'publication_not_checked' }],
    ['an unknown anchorSpec', { anchorSpec: 'tzun-anchor/2' }, {}, { outcome: 'abstain', value: null, reason: 'unsupported_anchor_spec' }],
    ['an unknown merkleSpec', { merkleSpec: 'sha3' }, {}, { outcome: 'abstain', value: null, reason: 'unsupported_merkle_spec' }],
  ])('check anchor follows anchorValid and anchorReason: %s', async (_name, edit, extra, expected) => {
    const s = await evmScenario();
    const publications = edit.publications === 'envelope' ? [s.envelope] : [s.full];
    const { publications: _p, ...rest } = edit;
    const v = await verifyAnchor({ anchor: { ...s.record.anchor, publications, ...rest } }, s.record.digest, { ...s.options, ...extra });
    expect(v.checks[0]).toEqual({ id: 'anchor', ...(expected as object) });
    expect(v.checks[0].reason).toBe(v.anchorReason);
  });

  it.each([0, 1] as const)('a legacy publication signed before EIP-155 (v 27 + %i) reports signedChainId null', async (yParity) => {
    const record = anchoredRecord();
    const publisher = Wallet.createRandom();
    const raw = signLegacy(publisher.signingKey, { data: '0x' + record.p, eip155: false, yParity });
    const block = fabricateBlock([raw], 7_123_456, 1_790_000_000);
    const full = publicationFrom(block, 0);
    const v = await verifyAnchor(withPublications(record, [full]), record.digest, {
      sequenceNumber: record.sequenceNumber,
      chainId: record.chainId,
      publisherManifest: manifestFor(record.anchorOrigin, entry(publisher)),
      evmHeaderSources: { [SEPOLIA_CHAIN]: new FakeHeaderSource(block) },
    });
    // Item 2 reads it; it signs no chain id, so item 5 matches no entry.
    expect(v.publications[0]).toMatchObject({ valid: false, reason: 'evm_chain_mismatch' });
    expect(v.publications[0].checks[1]).toEqual({
      id: 'anchor.evm.tx[0]',
      outcome: 'checked-wrong',
      value: false,
      reason: 'evm_chain_mismatch',
      facts: { transactionId: full.transactionId, txType: 0, sender: publisher.address.toLowerCase(), signedChainId: null },
    });
  });
});

describe('verifyAnchor never throws', () => {
  const r = anchoredRecord();
  const junk: Array<[string, unknown, unknown, unknown]> = [
    ['null artifacts', null, r.digest, {}],
    ['a string for artifacts', 'anchor', r.digest, {}],
    ['an array for artifacts', [r.anchor], r.digest, {}],
    ['a number for the anchor', { anchor: 7 }, r.digest, {}],
    ['every field the wrong type', { anchor: { anchorSpec: 'tzun-anchor/1', merkleSpec: 'rfc6962', leafIndex: '2', logCheckpoint: 7, logPath: 'x', anchorLeafIndex: {}, anchorCheckpoint: [], anchorPath: null, publications: 5 } }, r.digest, {}],
    ['a digest that is not a string', { anchor: r.anchor }, 42, {}],
    ['options that are not an object', { anchor: r.anchor }, r.digest, 'options'],
    ['a sequence number that is not a number', { anchor: r.anchor }, r.digest, { sequenceNumber: '3' }],
    ['a chain id that is not a string', { anchor: r.anchor }, r.digest, { chainId: { id: 'default' } }],
    ['junk material', { anchor: { ...r.anchor, publications: [{ kind: 'evm-calldata/1', blockHash: 7 }] } }, r.digest, { publicationMaterial: [null, 'x', { kind: 'evm-calldata/1', blockHash: null }] }],
    ['junk header sources and manifest', { anchor: { ...r.anchor, publications: [{ kind: 'evm-calldata/1' }] } }, r.digest, { evmHeaderSources: 7, publisherManifest: 'x' }],
  ];
  it.each(junk)('%s', async (_name, artifacts, digest, options) => {
    await expect(verifyAnchor(artifacts, digest as string, options as AnchorVerifyOptions)).resolves.toBeDefined();
  });

  it('a getter that throws inside the artifact → null, anchor_verifier_error', async () => {
    const hostile = { ...r.anchor };
    Object.defineProperty(hostile, 'logCheckpoint', {
      get() {
        throw new Error('boom');
      },
    });
    const v = await verifyAnchor({ anchor: hostile }, r.digest);
    expect(v).toMatchObject({ anchorPresent: true, anchorValid: null, anchorReason: 'anchor_verifier_error' });
    expect(v.checks).toHaveLength(7);
    expect(v.checks.every((c) => c.outcome === 'not-checked' && c.reason === 'anchor_verifier_error')).toBe(true);
  });
});

describe('verifyAttestation reads nonRepudiation.anchor through verifyAnchor', () => {
  it('maps the verdict onto the anchor fields and counts it', async () => {
    const r = anchoredRecord();
    const tsa = await tsaPublication(r.p);
    const out = await verifyAttestation(withPublications(r, [tsa.publication]) as never, r.digest, undefined, {
      sequenceNumber: r.sequenceNumber,
      chainId: r.chainId,
      trustAnchorsPem: [tsa.caPem],
    });
    expect(out.anchorValid).toBe(true);
    expect(out.anchorReason).toBeUndefined();
    expect(out.merkleProofValid).toBe(true);
    expect(out.anchorPublication).toBe('rfc3161');
    expect(out.anchorOriginAuthenticated).toBe(false);
    expect(out.anchorNamespace).toBeNull();
    expect(out.anchorNetwork).toBeNull();
    expect(out.existedBy).toEqual({ at: tsa.genTime.toISOString(), source: 'rfc3161' });
    expect(out.anchorPosition).toMatchObject({ leafIndex: r.anchor.leafIndex, leafIndexChecked: true, chainChecked: true });
    expect(out.attestationVerdict).toBe('partial');
  });

  it('with no trust anchors supplied, an RFC 3161 publication is not judged against the default roots', async () => {
    const saved = { anchors: process.env.TZUN_TSA_TRUST_ANCHORS, authorities: process.env.TZUN_TSA_AUTHORITIES };
    delete process.env.TZUN_TSA_TRUST_ANCHORS;
    delete process.env.TZUN_TSA_AUTHORITIES;
    try {
      const r = anchoredRecord();
      const tsa = await tsaPublication(r.p);
      const out = await verifyAttestation(withPublications(r, [tsa.publication]) as never, r.digest, undefined, {
        sequenceNumber: r.sequenceNumber,
        chainId: r.chainId,
      });
      expect(out).toMatchObject({
        anchorValid: null,
        anchorReason: 'publication_not_checked',
        merkleProofValid: true,
        existedBy: null,
      });
    } finally {
      if (saved.anchors !== undefined) process.env.TZUN_TSA_TRUST_ANCHORS = saved.anchors;
      if (saved.authorities !== undefined) process.env.TZUN_TSA_AUTHORITIES = saved.authorities;
    }
  });

  it('passes the EVM inputs through', async () => {
    const s = await evmScenario();
    const out = await verifyAttestation(withPublications(s.record, [s.envelope]) as never, s.record.digest, undefined, {
      sequenceNumber: s.record.sequenceNumber,
      chainId: s.record.chainId,
      publisherManifest: s.options.publisherManifest,
      evmHeaderSources: s.options.evmHeaderSources,
      anchorPublicationMaterial: [s.full],
      evmTimeoutMs: 5_000,
    });
    expect(out).toMatchObject({
      anchorValid: true,
      anchorPublication: 'evm-calldata',
      anchorOriginAuthenticated: true,
      anchorNetwork: 'testnet',
      anchorNamespace: 'production',
    });
  });

  it('a failing step is false with its reason; an undecided anchor is present, so the record is not pending', async () => {
    const r = anchoredRecord();
    const wrongChain = await verifyAttestation({ anchor: r.anchor } as never, r.digest, undefined, { chainId: 'other' });
    expect(wrongChain).toMatchObject({ anchorValid: false, anchorReason: 'chain_id_mismatch', merkleProofValid: null });

    const undecided = await verifyAttestation({ anchor: r.anchor } as never, r.digest);
    expect(undecided).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked', attestationVerdict: 'none' });
  });

  // tzun-anchor/1 §10.3 step 1 and §8.4: `blockchainAnchor` is not part of the
  // spec. Alone it is abstained on; beside an `anchor` it is not read.
  describe('a legacy blockchainAnchor', () => {
    const legacyFor = (digest: string, root = merkleLeafHash(digest)) => ({
      chain: 'ethereum-sepolia',
      transactionId: '0x' + 'ab'.repeat(32),
      batchMerkleRoot: root,
      merklePath: [],
      leafIndex: 0,
      treeSize: 1,
      merkleSpec: MERKLE_SPEC,
    });

    it('alone: abstained on, never checked, and present, so the record is not pending', async () => {
      const digest = sha256('legacy');
      for (const legacy of [legacyFor(digest), legacyFor(digest, sha256('another root')), { merkleSpec: 'sha256-v0' }]) {
        const out = await verifyAttestation({ blockchainAnchor: legacy } as never, digest);
        expect(out).toMatchObject({
          anchorValid: null,
          anchorReason: 'legacy_blockchain_anchor',
          merkleProofValid: null,
          anchorPublication: null,
          anchorOriginAuthenticated: false,
          anchorPosition: null,
          existedBy: null,
          attestationVerdict: 'none',
        });
      }
    });

    it('beside a true anchor, the anchor decides and the legacy one is not read', async () => {
      const r = anchoredRecord();
      const tsa = await tsaPublication(r.p);
      const out = await verifyAttestation(
        { ...withPublications(r, [tsa.publication]), blockchainAnchor: legacyFor(r.digest, sha256('another root')) } as never,
        r.digest,
        undefined,
        { trustAnchorsPem: [tsa.caPem] },
      );
      expect(out).toMatchObject({ anchorValid: true, anchorPublication: 'rfc3161', merkleProofValid: true });
      expect(out.anchorReason).toBeUndefined();
    });

    it('beside an anchor that fails, the anchor\'s own reason is reported', async () => {
      const r = anchoredRecord();
      const out = await verifyAttestation(
        { anchor: r.anchor, blockchainAnchor: legacyFor(r.digest) } as never,
        r.digest,
        undefined,
        { chainId: 'other' },
      );
      expect(out).toMatchObject({ anchorValid: false, anchorReason: 'chain_id_mismatch' });
    });

    it('beside an anchor under a future anchorSpec, the record is an abstention, never true', async () => {
      const r = anchoredRecord();
      const out = await verifyAttestation(
        { anchor: { anchorSpec: 'tzun-anchor/2' }, blockchainAnchor: legacyFor(r.digest) } as never,
        r.digest,
      );
      expect(out).toMatchObject({ anchorValid: null, anchorReason: 'unsupported_anchor_spec', merkleProofValid: null });
    });

    it('verifyAttestation takes no chain verifier for it', async () => {
      const digest = sha256('legacy');
      const asked: string[] = [];
      const out = await verifyAttestation({ blockchainAnchor: legacyFor(digest) } as never, digest, undefined, {
        anchorChainVerifier: { verifyAnchor: async (a: { transactionId: string }) => (asked.push(a.transactionId), { confirmed: true }) },
      } as never);
      expect(asked).toEqual([]);
      expect(out.anchorValid).toBeNull();
    });
  });

  it('reports the renamed verdict fields only', async () => {
    const r = anchoredRecord();
    const out = await verifyAttestation({ anchor: r.anchor } as never, r.digest);
    expect(out).toHaveProperty('anchorValid');
    expect(out).not.toHaveProperty('blockchainAnchorValid');
    expect(out).not.toHaveProperty('blockchainAnchorReason');
  });
});
