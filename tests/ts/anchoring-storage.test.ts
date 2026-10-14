/**
 * The anchoring tables the scheduler adds to the anchor store's
 * (`log_checkpoints`, `anchor_publications`; Anchor §7.2, §8.4, §11):
 * `anchor_lease`, `anchor_wallets`,
 * `anchor_wallet_txs`, a publication's `forced` flag and transaction index,
 * and the fill write. On SQLite and, when its legs run, Postgres; never the
 * memory adapter, where anchoring is refused.
 */
import { createHash } from 'node:crypto';
import { Wallet, keccak256 } from 'ethers';
import type { AnchorArtifact, EvidenceEnvelope } from '@tzun/engine';
import { formatCheckpoint } from '../../src/attestation/checkpoint';
import { extendCompactRange } from '../../src/attestation/merkle';
import {
  ANCHOR_LEASE_HOLDER_PREFIX,
  ANCHOR_FILL_CAUSE,
  AnchorEpochFenceError,
  REVISION_ACTOR_ANCHOR,
  type AnchorPublication,
  type AnchorStore,
  type EpochWrite,
  type LogStore,
  anchorStoreFor,
  logStoreFor,
} from '../../src/storage/log-store';

/** Lease holders as a scheduler names them: `tzun-anchor/2:<holder id>`. */
const HOLDER_A = `${ANCHOR_LEASE_HOLDER_PREFIX}holder-a`;
const HOLDER_B = `${ANCHOR_LEASE_HOLDER_PREFIX}holder-b`;
import { makeEnvelope } from './storage-conformance/fixtures';
import { type LogBackend, type OpenedStore, type RawDb, logBackends, refusal } from './helpers/log-store-backends';

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');
const CHAIN = 'eip155:31337';

describe.each(logBackends('anchoring_storage').map((b) => [b.name, b] as const))('anchoring storage on %s', (_name, backend: LogBackend) => {
  jest.setTimeout(60_000);
  let store: OpenedStore<unknown>;
  let logs: LogStore;
  let anchors: AnchorStore;
  let raw: RawDb;
  let domain: string;
  const wallet = Wallet.createRandom();
  const address = wallet.address.toLowerCase();

  beforeEach(async () => {
    await backend.fresh();
    store = await backend.open();
    logs = logStoreFor(store.adapter)!;
    anchors = anchorStoreFor(store.adapter)!;
    raw = store.raw;
    const identity = await logs.getStoreIdentity();
    domain = `${identity.ns}/${identity.storeId}`;
  });

  afterEach(async () => {
    await store.close();
  });

  afterAll(async () => {
    await backend.dispose();
  });

  /** A publication at anchor size 1, over a one-leaf anchor log. */
  async function publication(forced = false): Promise<AnchorPublication> {
    const log = await anchors.ensureStoreLog('anchors');
    const { size } = await logs.getLogSize(log.logId);
    if (size === 0) await anchors.appendLogLeaves(log.logId, [{ leafIndex: 0, leafDigest: hex('leaf-0'), sourceRef: 'cp-0' }]);
    const root = hex('root');
    const body = `${log.origin}\n1\n${Buffer.from(root, 'hex').toString('base64')}\n`;
    const digest = createHash('sha256').update(body).digest('hex');
    if (!(await anchors.getLogCheckpoint(log.logId, 1))) {
      await anchors.insertLogCheckpoint({
        logId: log.logId,
        treeSize: 1,
        root,
        body,
        bodyDigest: digest,
        compactRange: [root],
        prevAnchoredSize: null,
        consistencyProof: null,
        anchorLeafIndex: null,
        epochId: 1,
      });
    }
    return anchors.insertAnchorPublication({ epochId: 1, anchorSize: 1, p: digest, kind: 'evm-calldata/1', chain: CHAIN, forced });
  }

  async function signed(nonce: number, signer = wallet, chainId = 31337n) {
    const rawTx = (
      await signer.signTransaction({ type: 2, chainId, nonce, to: signer.address, value: 0n, data: '0x', gasLimit: 21_000n, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n })
    ).toLowerCase();
    return { rawTx, txHash: keccak256(rawTx) };
  }

  describe('anchor_lease', () => {
    it('is held by one holder until it expires, renewed by that holder, and released', async () => {
      const a = await anchors.acquireAnchorLease(domain, HOLDER_A, 60_000);
      expect(a.holder).toBe(HOLDER_A);
      expect((await anchors.acquireAnchorLease(domain, HOLDER_B, 60_000)).holder).toBe(HOLDER_A);
      const renewed = await anchors.acquireAnchorLease(domain, HOLDER_A, 120_000);
      expect(renewed.holder).toBe(HOLDER_A);
      expect(Date.parse(renewed.expiresAt)).toBeGreaterThan(Date.parse(a.expiresAt));
      await anchors.releaseAnchorLease(domain, HOLDER_B);
      expect((await anchors.getAnchorLease(domain))?.holder).toBe(HOLDER_A);
      await anchors.releaseAnchorLease(domain, HOLDER_A);
      expect(await anchors.getAnchorLease(domain)).toBeNull();
      expect((await anchors.acquireAnchorLease(domain, HOLDER_B, 60_000)).holder).toBe(HOLDER_B);
    });

    it('passes to another holder once it has expired', async () => {
      await anchors.acquireAnchorLease(domain, HOLDER_A, 50);
      await new Promise((r) => setTimeout(r, 120));
      expect((await anchors.acquireAnchorLease(domain, HOLDER_B, 60_000)).holder).toBe(HOLDER_B);
      expect((await anchors.acquireAnchorLease(domain, HOLDER_A, 60_000)).holder).toBe(HOLDER_B);
    });

    it('names the store\'s own domain only', async () => {
      await refusal(anchors.acquireAnchorLease('local.invalid/' + '0'.repeat(32), HOLDER_A, 1000), /domain prefix/);
      await anchors.acquireAnchorLease(domain, HOLDER_A, 1000);
      await refusal(raw.run(`UPDATE anchor_lease SET domain = 'other/x' WHERE domain = ?`, [domain]), /domain is fixed/);
    });
  });

  describe('anchor_wallets', () => {
    it('enrols once with its nonce base, which never changes', async () => {
      const w = await anchors.enrolAnchorWallet({ address, chain: CHAIN, domain, nonceBase: 3 });
      expect(w).toMatchObject({ address, chain: CHAIN, domain, nonceBase: 3, retiredAt: null });
      const again = await anchors.enrolAnchorWallet({ address, chain: CHAIN, domain, nonceBase: 7 });
      expect(again.nonceBase).toBe(3);
      await refusal(raw.run('UPDATE anchor_wallets SET nonce_base = 0 WHERE address = ?', [address]), /enrolment is fixed/);
      await refusal(raw.run('DELETE FROM anchor_wallets WHERE address = ?', [address]), /never deleted/);
    });

    it('is retired once', async () => {
      await anchors.enrolAnchorWallet({ address, chain: CHAIN, domain, nonceBase: 0 });
      const retired = await anchors.retireAnchorWallet(address, CHAIN);
      expect(retired.retiredAt).not.toBeNull();
      await refusal(anchors.retireAnchorWallet(address, CHAIN), /retired_at is set, once/);
      await refusal(raw.run('UPDATE anchor_wallets SET retired_at = NULL WHERE address = ?', [address]), /retired_at is set, once/);
    });

    it('enrols for the store\'s own domain, with a lowercase address and a CAIP-2 chain', async () => {
      await refusal(anchors.enrolAnchorWallet({ address, chain: CHAIN, domain: 'local.invalid/' + 'f'.repeat(32), nonceBase: 0 }), /own domain prefix/);
      await refusal(anchors.enrolAnchorWallet({ address: wallet.address, chain: CHAIN, domain, nonceBase: 0 }));
      await refusal(anchors.enrolAnchorWallet({ address, chain: 'ethereum-sepolia', domain, nonceBase: 0 }));
    });

    it('refuses a second enrolment the table would refuse as a first, with the same error', async () => {
      const enrolled = await anchors.enrolAnchorWallet({ address, chain: CHAIN, domain, nonceBase: 3 });
      const fresh = Wallet.createRandom().address.toLowerCase();
      const other = 'local.invalid/' + 'f'.repeat(32);
      /** The message and driver code a call is refused with. */
      const refused = async (work: Promise<unknown>): Promise<{ message: unknown; code: unknown }> => {
        try {
          await work;
        } catch (err) {
          const { message, code } = err as { message?: unknown; code?: unknown };
          return { message, code };
        }
        throw new Error('expected a refusal, but it went through');
      };
      for (const args of [
        { domain: other, nonceBase: 3 },
        { domain: other, nonceBase: -1 },
        { domain, nonceBase: -1 },
        { domain, nonceBase: 1.5 },
      ]) {
        const first = await refused(anchors.enrolAnchorWallet({ address: fresh, chain: CHAIN, ...args }));
        const second = await refused(anchors.enrolAnchorWallet({ address, chain: CHAIN, ...args }));
        expect(second).toEqual(first);
      }
      expect(await anchors.getAnchorWallet(fresh, CHAIN)).toBeNull();
      expect(await anchors.getAnchorWallet(address, CHAIN)).toEqual(enrolled);
    });
  });

  describe('anchor_wallet_txs', () => {
    beforeEach(async () => {
      await anchors.enrolAnchorWallet({ address, chain: CHAIN, domain, nonceBase: 2 });
    });

    it('stores a sweep or a handover, insert-only, in nonce order', async () => {
      const h = await signed(3);
      const s = await signed(2);
      await anchors.insertAnchorWalletTx({ address, chain: CHAIN, nonce: 3, kind: 'handover', ...h });
      await anchors.insertAnchorWalletTx({ address, chain: CHAIN, nonce: 2, kind: 'sweep', ...s });
      expect((await anchors.listAnchorWalletTxs(address, CHAIN)).map((t) => [t.nonce, t.kind, t.txHash])).toEqual([
        [2, 'sweep', s.txHash],
        [3, 'handover', h.txHash],
      ]);
      await refusal(raw.run('UPDATE anchor_wallet_txs SET kind = ? WHERE nonce = 2', ['handover']), /insert-only/);
      await refusal(raw.run('DELETE FROM anchor_wallet_txs WHERE nonce = 2'), /insert-only/);
    });

    it('refuses a transaction that is not the row: hash, sender, nonce, chain', async () => {
      const s = await signed(2);
      await refusal(anchors.insertAnchorWalletTx({ address, chain: CHAIN, nonce: 2, kind: 'sweep', rawTx: s.rawTx, txHash: '0x' + '0'.repeat(64) }), /keccak256/);
      await refusal(anchors.insertAnchorWalletTx({ address, chain: CHAIN, nonce: 4, kind: 'sweep', ...s }), /sender, nonce or chain/);
      const other = await signed(2, Wallet.createRandom());
      await refusal(anchors.insertAnchorWalletTx({ address, chain: CHAIN, nonce: 2, kind: 'sweep', ...other }), /sender, nonce or chain/);
      const wrongChain = await signed(2, wallet, 1n);
      await refusal(anchors.insertAnchorWalletTx({ address, chain: CHAIN, nonce: 2, kind: 'sweep', ...wrongChain }), /sender, nonce or chain/);
    });

    it('refuses a nonce below the base, of an unenrolled or retired wallet, or held by a publication', async () => {
      const low = await signed(1);
      await refusal(anchors.insertAnchorWalletTx({ address, chain: CHAIN, nonce: 1, kind: 'sweep', ...low }), /not enrolled and unretired from at or below this nonce/);

      const pub = await publication();
      const attempt = await signed(2);
      await anchors.updateAnchorPublication(pub.id, {
        state: 'submitted',
        fromAddress: address,
        nonce: 2,
        attempts: [{ txHash: attempt.txHash, rawTx: attempt.rawTx, maxFeePerGas: '2', maxPriorityFeePerGas: '1', sentAt: new Date().toISOString(), broadcast: 'accepted' }],
      });
      await refusal(anchors.insertAnchorWalletTx({ address, chain: CHAIN, nonce: 2, kind: 'sweep', ...attempt }), /a publication holds the nonce/);

      await anchors.retireAnchorWallet(address, CHAIN);
      const later = await signed(3);
      await refusal(anchors.insertAnchorWalletTx({ address, chain: CHAIN, nonce: 3, kind: 'sweep', ...later }), /unretired/);
    });
  });

  describe('anchor_publications: forced and tx_index', () => {
    it('keeps forced from insert', async () => {
      const pub = await publication(true);
      expect(pub.forced).toBe(true);
      await refusal(raw.run(`UPDATE anchor_publications SET forced = ${backend.name === 'sqlite' ? 0 : 'false'} WHERE id = ?`, [pub.id]), /fixed/);
    });

    it('fixes tx_index once the publication is finalized', async () => {
      const pub = await publication();
      const a = await signed(0);
      const attempts = [{ txHash: a.txHash, rawTx: a.rawTx, maxFeePerGas: '2', maxPriorityFeePerGas: '1', sentAt: new Date().toISOString(), broadcast: 'accepted' as const }];
      await anchors.updateAnchorPublication(pub.id, { state: 'submitted', fromAddress: address, nonce: 0, attempts });
      const mined = { minedTxHash: a.txHash, blockNumber: 5, blockHash: '0x' + hex('b5'), txIndex: 1 };
      let p = await anchors.updateAnchorPublication(pub.id, { state: 'included', ...mined });
      // A reorg may move it before finality.
      p = await anchors.updateAnchorPublication(pub.id, { txIndex: 0 });
      p = await anchors.updateAnchorPublication(pub.id, { state: 'finalized', blockHeader: '0xf9', txTrieProof: ['0xc0'] });
      expect(p.txIndex).toBe(0);
      await refusal(anchors.updateAnchorPublication(pub.id, { txIndex: 3 }), /fixed/);
    });
  });

  describe('the fill (Anchor §8.4, §11)', () => {
    /** The records of the chain the fill writes, in sequence order: its evidence log's leaves. */
    let logged: EvidenceEnvelope[] = [];
    /**
     * Record `i`'s artifact: its leaf index, and the log checkpoint and path
     * that place its digest in the chain's evidence log, which the store
     * checks before it writes. The rest is a marker.
     */
    const artifact = (i: number) => {
      const ext = extendCompactRange({ size: 0, hashes: [] }, logged.map((e) => e.integrity.canonicalDigest));
      return {
        anchorSpec: 'tzun-anchor/1',
        merkleSpec: 'rfc6962',
        leafIndex: i,
        logCheckpoint: formatCheckpoint(`test.invalid/${'0'.repeat(32)}/evidence/64656661756c74`, logged.length, ext.root),
        logPath: ext.inclusionProofs[i],
        marker: `a${i}`,
      } as unknown as AnchorArtifact;
    };

    async function stored(n: number): Promise<EvidenceEnvelope[]> {
      const out: EvidenceEnvelope[] = [];
      for (let i = 1; i <= n; i++) {
        const e = makeEnvelope({ evidenceId: `fill-${i}`, sequenceNumber: i, attestationStatus: i === 1 ? 'complete' : 'partial' });
        await (store.adapter as { store(e: EvidenceEnvelope): Promise<void> }).store(e);
        out.push(e);
      }
      logged = out;
      return out;
    }

    it('fills only what is absent, writes one anchor_fill revision per record filled, and records progress in the same transaction', async () => {
      const envelopes = await stored(3);
      const pub = await publication();
      const statusOf = jest.fn(() => 'pending' as const);
      const first = await anchors.fillAnchorArtifacts({
        publicationId: pub.id,
        fills: envelopes.slice(0, 2).map((e, i) => ({ evidenceId: e.payload.evidenceId, anchor: artifact(i) })),
        statusOf,
        fillProgress: { step: 1 },
      });
      expect(first).toEqual({ filled: 2, alreadyAnchored: 0, missing: [], conflicts: [] });
      const adapter = store.adapter as {
        retrieve(id: string): Promise<EvidenceEnvelope | null>;
        listEnvelopeRevisions(id: string): Promise<Array<{ revisionNo: number; cause: string; actor: string; canonicalDigest: string }>>;
      };
      const one = (await adapter.retrieve('fill-1'))!;
      expect((one.nonRepudiation as Record<string, unknown>).anchor).toEqual(artifact(0));
      // A complete record stays complete; the others take the caller's rule.
      expect(one.attestationStatus).toBe('complete');
      expect((await adapter.retrieve('fill-2'))!.attestationStatus).toBe('pending');
      expect((await adapter.retrieve('fill-3'))!.nonRepudiation).toEqual({});
      const revisions = await adapter.listEnvelopeRevisions('fill-2');
      expect(revisions.map((r) => [r.revisionNo, r.cause, r.actor])).toEqual([
        [0, 'capture', 'jane@acme.example'],
        [1, ANCHOR_FILL_CAUSE, REVISION_ACTOR_ANCHOR],
      ]);
      expect(revisions[1].canonicalDigest).toBe(envelopes[1].integrity.canonicalDigest);
      expect((await anchors.getAnchorPublication(pub.id))!.fillProgress).toEqual({ step: 1 });

      // Again, with one more record and one that is gone: fill-only.
      const second = await anchors.fillAnchorArtifacts({
        publicationId: pub.id,
        fills: [
          ...envelopes.map((e, i) => ({ evidenceId: e.payload.evidenceId, anchor: { ...artifact(i), marker: 'second' } })),
          { evidenceId: 'no-such-record', anchor: artifact(9) },
        ],
        statusOf,
        fillProgress: { step: 2 },
      });
      expect(second).toEqual({ filled: 1, alreadyAnchored: 2, missing: ['no-such-record'], conflicts: [] });
      expect(((await adapter.retrieve('fill-1'))!.nonRepudiation as Record<string, unknown>).anchor).toEqual(artifact(0));
      expect((await adapter.listEnvelopeRevisions('fill-2')).length).toBe(2);
      expect((await adapter.listEnvelopeRevisions('fill-3')).map((r) => r.cause)).toEqual(['capture', ANCHOR_FILL_CAUSE]);
    });

    it('writes nothing when the chunk fails', async () => {
      const envelopes = await stored(1);
      await refusal(
        anchors.fillAnchorArtifacts({
          publicationId: 9999,
          fills: [{ evidenceId: envelopes[0].payload.evidenceId, anchor: artifact(0) }],
          statusOf: () => 'partial',
          fillProgress: {},
        }),
        /no publication 9999/,
      );
      const adapter = store.adapter as { retrieve(id: string): Promise<EvidenceEnvelope | null>; listEnvelopeRevisions(id: string): Promise<unknown[]> };
      expect((await adapter.retrieve('fill-1'))!.nonRepudiation).toEqual({});
      expect(await adapter.listEnvelopeRevisions('fill-1')).toHaveLength(1);
    });

    it('keeps a pending record that has no timestamp pending, whatever the caller\'s rule says', async () => {
      const put = (store.adapter as { store(e: EvidenceEnvelope): Promise<void> }).store.bind(store.adapter);
      const waiting = makeEnvelope({ evidenceId: 'waiting', sequenceNumber: 1, attestationStatus: 'pending' });
      const stamped = makeEnvelope({ evidenceId: 'stamped', sequenceNumber: 2, attestationStatus: 'pending' });
      stamped.nonRepudiation = { rfc3161Token: 'dG9rZW4=' };
      await put(waiting);
      await put(stamped);
      logged = [waiting, stamped];
      const pub = await publication();
      await anchors.fillAnchorArtifacts({
        publicationId: pub.id,
        fills: [waiting, stamped].map((e, i) => ({ evidenceId: e.payload.evidenceId, anchor: artifact(i) })),
        statusOf: () => 'partial',
        fillProgress: {},
      });
      const adapter = store.adapter as {
        retrieve(id: string): Promise<EvidenceEnvelope | null>;
        listByMissingObtainable(components: ['timestamp']): Promise<EvidenceEnvelope[]>;
      };
      expect((await adapter.retrieve('waiting'))!.attestationStatus).toBe('pending');
      expect((await adapter.retrieve('stamped'))!.attestationStatus).toBe('partial');
      expect((await adapter.listByMissingObtainable(['timestamp'])).map((e) => e.payload.evidenceId)).toEqual(['waiting']);
    });

    it('lets the caller\'s rule decide a pending record without a timestamp when its writers expect none (timestampExpected: false)', async () => {
      // A Tzun that anchors and obtains no timestamp stores every record
      // pending for its anchor alone; filled, nothing is missing any more.
      const put = (store.adapter as { store(e: EvidenceEnvelope): Promise<void> }).store.bind(store.adapter);
      const awaitingAnchor = makeEnvelope({ evidenceId: 'awaiting-anchor', sequenceNumber: 1, attestationStatus: 'pending' });
      await put(awaitingAnchor);
      logged = [awaitingAnchor];
      const pub = await publication();
      await anchors.fillAnchorArtifacts({
        publicationId: pub.id,
        fills: [{ evidenceId: 'awaiting-anchor', anchor: artifact(0) }],
        statusOf: () => 'partial',
        timestampExpected: false,
        fillProgress: {},
      });
      const adapter = store.adapter as { retrieve(id: string): Promise<EvidenceEnvelope | null> };
      expect((await adapter.retrieve('awaiting-anchor'))!.attestationStatus).toBe('partial');
    });
  });

  describe('persistEpoch under an EpochGuard', () => {
    /** An epoch that extends the anchor log to `size` with one leaf, its checkpoint, and a publication of it. */
    async function epoch(size: number): Promise<EpochWrite> {
      const log = await anchors.ensureStoreLog('anchors');
      const root = hex(`root-${size}`);
      const body = `${log.origin}\n${size}\n${Buffer.from(root, 'hex').toString('base64')}\n`;
      const digest = createHash('sha256').update(body).digest('hex');
      return {
        leaves: [{ logId: log.logId, leaves: [{ leafIndex: size - 1, leafDigest: hex(`leaf-${size}`), sourceRef: `cp-${size}` }] }],
        checkpoints: [
          { logId: log.logId, treeSize: size, root, body, bodyDigest: digest, compactRange: [root], prevAnchoredSize: null, consistencyProof: null, anchorLeafIndex: null, epochId: size },
        ],
        publications: [{ epochId: size, anchorSize: size, p: digest, kind: 'evm-calldata/1', chain: CHAIN }],
      };
    }

    async function fenced(write: EpochWrite): Promise<string> {
      try {
        await anchors.persistEpoch(write);
      } catch (err) {
        expect(err).toBeInstanceOf(AnchorEpochFenceError);
        return (err as AnchorEpochFenceError).reason;
      }
      throw new Error('the epoch was written');
    }

    async function send(pub: AnchorPublication, nonce: number, broadcast: 'accepted' | 'rejected'): Promise<AnchorPublication> {
      const a = await signed(nonce);
      return anchors.updateAnchorPublication(pub.id, {
        state: 'submitted',
        fromAddress: address,
        nonce,
        attempts: [{ txHash: a.txHash, rawTx: a.rawTx, maxFeePerGas: '2', maxPriorityFeePerGas: '1', sentAt: new Date().toISOString(), broadcast }],
      });
    }

    it('writes only for the unexpired lease holder, with nothing unmined and the published size it was planned on', async () => {
      const anchorLog = await anchors.ensureStoreLog('anchors');
      const written = async () => ({
        leaves: (await logs.getLogSize(anchorLog.logId)).size,
        publications: (await anchors.listAnchorPublications()).length,
      });
      await anchors.acquireAnchorLease(domain, HOLDER_A, 60_000);
      const one = await epoch(1);
      expect(await fenced({ ...one, guard: { domain, holder: HOLDER_B, publishedAnchorSize: null } })).toBe('lease_not_held');
      expect(await written()).toEqual({ leaves: 0, publications: 0 });

      const [first] = await anchors.persistEpoch({ ...one, guard: { domain, holder: HOLDER_A, publishedAnchorSize: null } });
      const two = await epoch(2);
      // The first epoch is unmined: a second is refused.
      expect(await fenced({ ...two, guard: { domain, holder: HOLDER_A, publishedAnchorSize: null } })).toBe('publication_unmined');
      const sent = await send(first, 0, 'accepted');
      expect(await fenced({ ...two, guard: { domain, holder: HOLDER_A, publishedAnchorSize: null } })).toBe('publication_unmined');
      await anchors.updateAnchorPublication(sent.id, { state: 'included', minedTxHash: sent.attempts[0].txHash, blockNumber: 5, blockHash: '0x' + hex('b5'), txIndex: 0 });
      // Mined: the next epoch may be cut, but only from the size that was published.
      expect(await fenced({ ...two, guard: { domain, holder: HOLDER_A, publishedAnchorSize: null } })).toBe('published_size_moved');
      expect(await written()).toEqual({ leaves: 1, publications: 1 });
      await anchors.persistEpoch({ ...two, guard: { domain, holder: HOLDER_A, publishedAnchorSize: 1 } });
      expect(await written()).toEqual({ leaves: 2, publications: 2 });

      // An expired lease is not held, even by its holder.
      await anchors.acquireAnchorLease(domain, HOLDER_A, 1);
      await new Promise((r) => setTimeout(r, 20));
      const pubs = await anchors.listAnchorPublications();
      await send(pubs[1], 1, 'accepted');
      await anchors.updateAnchorPublication(pubs[1].id, { state: 'included', minedTxHash: (await anchors.getAnchorPublication(pubs[1].id))!.attempts[0].txHash, blockNumber: 6, blockHash: '0x' + hex('b6'), txIndex: 0 });
      expect(await fenced({ ...(await epoch(3)), guard: { domain, holder: HOLDER_A, publishedAnchorSize: 2 } })).toBe('lease_not_held');
    });

    it('supersedes an all-rejected publication in the epoch\'s own transaction, and not at all when the epoch is refused', async () => {
      await anchors.acquireAnchorLease(domain, HOLDER_A, 60_000);
      const [first] = await anchors.persistEpoch({ ...(await epoch(1)), guard: { domain, holder: HOLDER_A, publishedAnchorSize: null } });
      const rejected = await send(first, 0, 'rejected');
      const two = await epoch(2);
      expect(await fenced({ ...two, guard: { domain, holder: HOLDER_A, publishedAnchorSize: 1, supersedes: rejected.id } })).toBe('published_size_moved');
      expect((await anchors.getAnchorPublication(rejected.id))!.state).toBe('submitted');
      const [second] = await anchors.persistEpoch({ ...two, guard: { domain, holder: HOLDER_A, publishedAnchorSize: null, supersedes: rejected.id } });
      expect((await anchors.getAnchorPublication(rejected.id))!.state).toBe('superseded');
      expect(second.anchorSize).toBe(2);
    });
  });

  describe('a publication\'s nonce against the wallet', () => {
    it('is refused when an accounted transaction holds it, or the wallet is retired', async () => {
      await anchors.enrolAnchorWallet({ address, chain: CHAIN, domain, nonceBase: 0 });
      const sweep = await signed(0);
      await anchors.insertAnchorWalletTx({ address, chain: CHAIN, nonce: 0, kind: 'sweep', ...sweep });
      const pub = await publication();
      const a = await signed(0);
      const attempt = { txHash: a.txHash, rawTx: a.rawTx, maxFeePerGas: '2', maxPriorityFeePerGas: '1', sentAt: new Date().toISOString(), broadcast: 'accepted' as const };
      await refusal(
        anchors.updateAnchorPublication(pub.id, { state: 'submitted', fromAddress: address, nonce: 0, attempts: [attempt] }),
        /accounted wallet transaction holds the nonce, or the wallet is retired/,
      );
      await anchors.retireAnchorWallet(address, CHAIN);
      const b = await signed(1);
      await refusal(
        anchors.updateAnchorPublication(pub.id, {
          state: 'submitted',
          fromAddress: address,
          nonce: 1,
          attempts: [{ ...attempt, txHash: b.txHash, rawTx: b.rawTx }],
        }),
        /accounted wallet transaction holds the nonce, or the wallet is retired/,
      );
      expect((await anchors.getAnchorPublication(pub.id))!.nonce).toBeNull();
    });
  });

  describe('checkpoint lookups by index', () => {
    it('finds a log\'s last checkpoint, its last anchored one, and checkpoints by anchor leaf', async () => {
      const put = (store.adapter as { store(e: EvidenceEnvelope, chainId?: string): Promise<void> }).store.bind(store.adapter);
      for (let i = 1; i <= 3; i++) await put(makeEnvelope({ evidenceId: `cp-${i}`, sequenceNumber: i }), 'alpha');
      const alpha = (await logs.getEvidenceLog('alpha'))!;
      const anchorLog = await anchors.ensureStoreLog('anchors');
      const checkpoint = (size: number, anchorLeafIndex: number | null) => {
        const root = hex(`alpha-${size}`);
        const body = `${alpha.origin}\n${size}\n${Buffer.from(root, 'hex').toString('base64')}\n`;
        return { logId: alpha.logId, treeSize: size, root, body, bodyDigest: createHash('sha256').update(body).digest('hex'), compactRange: [root], prevAnchoredSize: null, consistencyProof: null, anchorLeafIndex, epochId: null };
      };
      expect(await anchors.getLastLogCheckpoint(alpha.logId)).toBeNull();
      expect(await anchors.getLastAnchoredCheckpoint(alpha.logId)).toBeNull();
      const one = checkpoint(1, 0);
      const two = checkpoint(2, 1);
      await anchors.appendLogLeaves(anchorLog.logId, [
        { leafIndex: 0, leafDigest: one.bodyDigest, sourceRef: 'alpha-1' },
        { leafIndex: 1, leafDigest: two.bodyDigest, sourceRef: 'alpha-2' },
      ]);
      await anchors.insertLogCheckpoint(one);
      await anchors.insertLogCheckpoint(two);
      await anchors.insertLogCheckpoint(checkpoint(3, null));
      expect((await anchors.getLastLogCheckpoint(alpha.logId))!.treeSize).toBe(3);
      expect((await anchors.getLastAnchoredCheckpoint(alpha.logId))!.treeSize).toBe(2);
      expect((await anchors.listCheckpointsByAnchorLeaf(0, 2)).map((c) => [c.anchorLeafIndex, c.treeSize])).toEqual([[0, 1], [1, 2]]);
      expect((await anchors.listCheckpointsByAnchorLeaf(1, 5)).map((c) => c.treeSize)).toEqual([2]);
      expect(await anchors.listCheckpointsByAnchorLeaf(2, 2)).toEqual([]);
    });
  });
});
