/**
 * Anchoring trust, the database's part: what the SQL stores refuse to a
 * writer the triggers hold. Every row is written on the store's own database,
 * outside the adapter, with every trigger enabled; on SQLite and, when its
 * legs run, on Postgres.
 *
 * Before these refusals, every write below went through, and a phantom
 * capture leaf could be written on both dialects.
 */
import { createHash, randomBytes } from 'node:crypto';
import { Client } from 'pg';
import type { EvidenceEnvelope } from '@tzun/engine';
import { checkpointDigest, formatCheckpoint } from '../../src/attestation/checkpoint';
import {
  ANCHOR_LEASE_HOLDER_PREFIX,
  anchorStoreFor,
  logStoreFor,
  type AnchorStore,
  type LogRecord,
  type LogStore,
} from '../../src/storage/log-store';
import { makeEnvelope } from './storage-conformance/fixtures';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { type LogBackend, type OpenedStore, type RawDb, logBackends, refusal } from './helpers/log-store-backends';

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');
const SQLITE_NOW = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')";
const CHAIN = 'eip155:31337';
const HOLDER = `${ANCHOR_LEASE_HOLDER_PREFIX}holder-a`;

type Adapter = {
  store(e: EvidenceEnvelope, chainId?: string): Promise<void>;
};

describe.each(logBackends('anchoring_trust_storage').map((b) => [b.name, b] as const))('anchoring trust in the database, on %s', (_name, backend: LogBackend) => {
  jest.setTimeout(60_000);
  let store: OpenedStore<unknown>;
  let adapter: Adapter;
  let logs: LogStore;
  let anchors: AnchorStore;
  let raw: RawDb;
  const sqlite = backend.name === 'sqlite';
  /** The SQL a raw insert writes for an insert time: the statement's own on SQLite, a fixed one on Postgres. */
  const at = (iso: string): string => (sqlite ? SQLITE_NOW : `'${iso}'`);

  beforeEach(async () => {
    await backend.fresh();
    store = await backend.open();
    adapter = store.adapter as unknown as Adapter;
    logs = logStoreFor(store.adapter)!;
    anchors = anchorStoreFor(store.adapter)!;
    raw = store.raw;
  });
  afterEach(async () => {
    await store.close();
  });
  afterAll(async () => backend.dispose());

  /** A raw INSERT of an evidence leaf. */
  const leaf = (log: LogRecord, leafIndex: number, sourceRef: string, digest: string, source = 'capture') =>
    raw.run(
      `INSERT INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source, logged_at) VALUES (?, ?, ?, ?, ?, ${at('2026-09-30T00:00:00Z')})`,
      [log.logId, leafIndex, digest, sourceRef, source],
    );
  /** A raw INSERT of a record, which the capture trigger gives its leaf when it is enabled. */
  const envelopeRow = (e: EvidenceEnvelope, chainId = 'default') =>
    raw.run(
      `INSERT INTO envelopes (evidence_id, envelope, captured_at, ai_system_id, digest, chain_id) VALUES (?, ?, ?, ?, ?, ?)`,
      [e.payload.evidenceId, JSON.stringify(e), e.payload.capturedAt, e.payload.aiSystemId, e.integrity.canonicalDigest, chainId],
    );
  /** The capture trigger off and on again, as the store's owner can (a writer the triggers do not hold). */
  let captureTriggerSql = '';
  const captureTrigger = async (on: boolean): Promise<void> => {
    if (sqlite) {
      if (on) {
        await raw.run(captureTriggerSql);
      } else {
        [{ sql: captureTriggerSql }] = await raw.all<{ sql: string }>("SELECT sql FROM sqlite_schema WHERE name = 'envelopes_evidence_log_append'");
        await raw.run('DROP TRIGGER envelopes_evidence_log_append');
      }
    } else {
      await raw.run(`ALTER TABLE envelopes ${on ? 'ENABLE' : 'DISABLE'} TRIGGER evidence_log_append_trigger`);
    }
  };
  const leaves = async (chainId = 'default') => {
    const log = await logs.getEvidenceLog(chainId);
    return log ? (await logs.listLogLeaves(log.logId, 0, 100)).map((l) => [l.leafIndex, l.sourceRef, l.source]) : [];
  };

  describe('an evidence leaf is a copy of the record stored at its position', () => {
    const BOUND = /\[tzun:leaf_without_record\]/;

    it('refuses a capture leaf at the next index naming no stored record; the genuine record then takes its leaf', async () => {
      await adapter.store(makeEnvelope({ evidenceId: 'a-1', sequenceNumber: 1 }));
      const log = (await logs.getEvidenceLog('default'))!;
      await refusal(leaf(log, 1, 'phantom', hex('phantom')), BOUND);
      expect(await leaves()).toEqual([[0, 'a-1', 'capture']]);
      await adapter.store(makeEnvelope({ evidenceId: 'a-2', sequenceNumber: 2 }));
      expect(await leaves()).toEqual([[0, 'a-1', 'capture'], [1, 'a-2', 'capture']]);
      expect((await logs.getEvidenceLogPosition('a-2'))!.leafIndex).toBe(1);
    });

    it("refuses a stored record's id at another position, and another chain's record at this position", async () => {
      await adapter.store(makeEnvelope({ evidenceId: 'a-1', sequenceNumber: 1 }));
      for (const seq of [1, 2]) await adapter.store(makeEnvelope({ evidenceId: `b-${seq}`, sequenceNumber: seq }), 'other');
      const log = (await logs.getEvidenceLog('default'))!;
      await refusal(leaf(log, 1, 'a-1', hex('a-1')), /\[tzun:duplicate_leaf\]|\[tzun:leaf_without_record\]/);
      // b-2 is at sequence 2, as leaf 1 is, with its own digest: its chain is not this log's.
      await refusal(leaf(log, 1, 'b-2', hex('b-2')), BOUND);
      expect(await leaves()).toEqual([[0, 'a-1', 'capture']]);
      await adapter.store(makeEnvelope({ evidenceId: 'a-2', sequenceNumber: 2 }));
      expect((await logs.getEvidenceLogPosition('a-2'))!.leafIndex).toBe(1);
    });

    it('takes only the exact copy of a record stored without its leaf: another digest, or a backfill leaf, is refused', async () => {
      await adapter.store(makeEnvelope({ evidenceId: 'a-1', sequenceNumber: 1 }));
      const log = (await logs.getEvidenceLog('default'))!;
      // The owner stores a record with the capture trigger off: it has no leaf.
      await captureTrigger(false);
      const a2 = makeEnvelope({ evidenceId: 'a-2', sequenceNumber: 2 });
      await envelopeRow(a2);
      await captureTrigger(true);
      expect(await leaves()).toEqual([[0, 'a-1', 'capture']]);
      await refusal(leaf(log, 1, 'a-2', hex('another digest')), BOUND);
      await refusal(leaf(log, 1, 'a-2', a2.integrity.canonicalDigest, 'backfill'), BOUND);
      expect(await leaves()).toEqual([[0, 'a-1', 'capture']]);
      await leaf(log, 1, 'a-2', a2.integrity.canonicalDigest);
      expect(await leaves()).toEqual([[0, 'a-1', 'capture'], [1, 'a-2', 'capture']]);
    });

    it("refuses a record's own id and digest at an index that is not its position", async () => {
      await adapter.store(makeEnvelope({ evidenceId: 'a-1', sequenceNumber: 1 }));
      const log = (await logs.getEvidenceLog('default'))!;
      // The owner stores a record at sequence 5 with the capture trigger off: it has no leaf.
      await captureTrigger(false);
      const a5 = makeEnvelope({ evidenceId: 'a-5', sequenceNumber: 5 });
      await envelopeRow(a5);
      await captureTrigger(true);
      // Its id and its real digest, at the next index (1), which is not position 5.
      await refusal(leaf(log, 1, 'a-5', a5.integrity.canonicalDigest), BOUND);
      expect(await leaves()).toEqual([[0, 'a-1', 'capture']]);
    });

    // One record per chain position: a unique index on (chain_id,
    // payload.sequenceNumber), `envelopes_position`, and a `position_taken`
    // refusal in store(). A phantom record stored first at the next position
    // keeps that position; the genuine record stored there afterwards is
    // refused, and nothing of it is written.
    it("a genuine record at a position another record took is refused as position_taken", async () => {
      await adapter.store(makeEnvelope({ evidenceId: 'g-1', sequenceNumber: 1 }));
      await adapter.store(makeEnvelope({ evidenceId: 'g-2', sequenceNumber: 2 }));
      await adapter.store(makeEnvelope({ evidenceId: 'phantom-3', sequenceNumber: 3 }));
      await expect(adapter.store(makeEnvelope({ evidenceId: 'g-3', sequenceNumber: 3 }))).rejects.toMatchObject({
        code: 'evidence_log_refused',
        reason: 'position_taken',
        sequenceNumber: 3,
      });
      expect(await raw.all('SELECT evidence_id FROM envelopes WHERE evidence_id = ?', ['g-3'])).toEqual([]);
      expect(await leaves()).toEqual([[0, 'g-1', 'capture'], [1, 'g-2', 'capture'], [2, 'phantom-3', 'capture']]);
    });

    it('a raw INSERT at a position another record holds is refused by the index itself', async () => {
      await adapter.store(makeEnvelope({ evidenceId: 'r-1', sequenceNumber: 1 }));
      const phantom = makeEnvelope({ evidenceId: 'r-1b', sequenceNumber: 1 });
      await refusal(
        sqlite
          ? raw.run(
              'INSERT INTO envelopes (evidence_id, envelope, captured_at, captured_at_ms, ai_system_id, digest, chain_id) VALUES (?, ?, ?, 0, ?, ?, ?)',
              ['r-1b', JSON.stringify(phantom), phantom.payload.capturedAt, phantom.payload.aiSystemId, phantom.integrity.canonicalDigest, 'default'],
            )
          : raw.run(
              'INSERT INTO envelopes (evidence_id, envelope, captured_at, ai_system_id, digest, chain_id) VALUES (?, ?::jsonb, ?, ?, ?, ?)',
              ['r-1b', JSON.stringify(phantom), phantom.payload.capturedAt, phantom.payload.aiSystemId, phantom.integrity.canonicalDigest, 'default'],
            ),
        /envelopes_position|unique/i,
      );
      expect(await raw.all('SELECT evidence_id FROM envelopes WHERE evidence_id = ?', ['r-1b'])).toEqual([]);
    });
  });

  describe('the database assigns the times the scheduler reads, and the transitions it trusts', () => {
    it("a publication's created_at and a leaf's logged_at are the insert's own time: assigned on Postgres, refused otherwise on SQLite", async () => {
      const anchorLog = await anchors.ensureStoreLog('anchors');
      const insertLeaf = (when: string) =>
        raw.run(
          `INSERT INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source, logged_at) VALUES (?, 0, ?, 'cp-0', 'scheduler', ?)`,
          [anchorLog.logId, hex('leaf-0'), when],
        );
      if (sqlite) {
        await refusal(insertLeaf('2020-01-01T00:00:00.000Z'), /logged_at is the insert's own time/);
        await refusal(insertLeaf('2099-01-01T00:00:00.000Z'), /logged_at is the insert's own time/);
      }
      await raw.run(
        `INSERT INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source, logged_at) VALUES (?, 0, ?, 'cp-0', 'scheduler', ${at('2020-01-01T00:00:00Z')})`,
        [anchorLog.logId, hex('leaf-0')],
      );
      const [stored] = await logs.listLogLeaves(anchorLog.logId, 0, 1);
      expect(Math.abs(Date.parse(stored.loggedAt) - Date.now())).toBeLessThan(5 * 60_000);

      const root = hex('root-1');
      const body = formatCheckpoint(anchorLog.origin, 1, root);
      await anchors.insertLogCheckpoint({
        logId: anchorLog.logId, treeSize: 1, root, body, bodyDigest: checkpointDigest(body), compactRange: [root],
        prevAnchoredSize: null, consistencyProof: null, anchorLeafIndex: null, epochId: 1,
      });
      const insertPublication = (when: string) =>
        raw.run(
          `INSERT INTO anchor_publications (epoch_id, anchor_size, p, kind, state, chain, created_at, updated_at)
           VALUES (1, 1, ?, 'evm-calldata/1', 'prepared', ?, ${when}, ${when})`,
          [checkpointDigest(body), CHAIN],
        );
      if (sqlite) {
        await refusal(insertPublication("'2020-01-01T00:00:00.000Z'"), /created_at is the insert's own time/);
        await refusal(insertPublication("'2099-01-01T00:00:00.000Z'"), /created_at is the insert's own time/);
        await insertPublication(SQLITE_NOW);
      } else {
        await insertPublication("'2020-01-01T00:00:00Z'");
      }
      const [publication] = await anchors.listAnchorPublications();
      expect(Math.abs(Date.parse(publication.createdAt) - Date.now())).toBeLessThan(5 * 60_000);
    });

    (sqlite ? it.skip : it)("Postgres refuses a checkpoint whose body_digest is not its body's SHA-256", async () => {
      const anchorLog = await anchors.ensureStoreLog('anchors');
      await anchors.appendLogLeaves(anchorLog.logId, [{ leafIndex: 0, leafDigest: hex('leaf-0'), sourceRef: 'cp-0' }]);
      const root = hex('root-1');
      const body = formatCheckpoint(anchorLog.origin, 1, root);
      await refusal(
        raw.run(
          `INSERT INTO log_checkpoints (log_id, tree_size, root, body, body_digest, compact_range) VALUES (?, 1, ?, ?, ?, ?)`,
          [anchorLog.logId, root, body, hex('not the body'), JSON.stringify([root])],
        ),
        /body_digest is not the SHA-256 of the body/,
      );
      expect(await anchors.listLogCheckpoints(anchorLog.logId)).toEqual([]);
    });
  });

  describe('a scheduler of an earlier release cannot lead, and its triggers leave the new rules in place', () => {
    it('refuses a lease holder that is not a tzun-anchor/2: scheduler, to take or to renew', async () => {
      const identity = await logs.getStoreIdentity();
      const domain = `${identity.ns}/${identity.storeId}`;
      await refusal(anchors.acquireAnchorLease(domain, 'anchor-0123456789abcdef', 60_000), /not a tzun-anchor\/2: scheduler/);
      expect(await anchors.getAnchorLease(domain)).toBeNull();
      await anchors.acquireAnchorLease(domain, HOLDER, 60_000);
      await refusal(raw.run('UPDATE anchor_lease SET holder = ? WHERE domain = ?', ['anchor-0123456789abcdef', domain]), /not a tzun-anchor\/2: scheduler/);
      expect((await anchors.getAnchorLease(domain))!.holder).toBe(HOLDER);
    });

    it("an earlier release's reconcile, reinstalling its own trigger bodies, leaves the new refusals in place", async () => {
      await adapter.store(makeEnvelope({ evidenceId: 'a-1', sequenceNumber: 1 }));
      const identity = await logs.getStoreIdentity();
      const domain = `${identity.ns}/${identity.storeId}`;
      // Every trigger the earlier release knows, reinstalled from its stored
      // statement, the guard on publication updates with the earlier
      // transition table (a prepared publication could be superseded).
      const earlier = (sql: string) =>
        sql.replace("(OLD.state = 'prepared' AND NEW.state IN ('submitted', 'obtained'))", "(OLD.state = 'prepared' AND NEW.state IN ('submitted', 'obtained', 'superseded'))");
      if (sqlite) {
        const NEW_NAMES = /^(log_leaves_bind_record|anchor_publications_created_now|log_leaves_logged_now|anchor_publications_guard_transitions|anchor_lease_require_protocol(_update)?)$/;
        const triggers = await raw.all<{ name: string; sql: string }>("SELECT name, sql FROM sqlite_schema WHERE type = 'trigger'");
        for (const t of triggers.filter((x) => !NEW_NAMES.test(x.name))) {
          await raw.run(`DROP TRIGGER ${t.name}`);
          await raw.run(earlier(t.sql));
        }
      } else {
        const [fn] = await raw.all<{ def: string }>("SELECT pg_get_functiondef('anchor_publications_guard_update'::regproc) AS def");
        expect(earlier(fn.def)).not.toBe(fn.def);
        await raw.run(earlier(fn.def));
      }
      const log = (await logs.getEvidenceLog('default'))!;
      await refusal(leaf(log, 1, 'phantom', hex('phantom')), /\[tzun:leaf_without_record\]/);
      await refusal(anchors.acquireAnchorLease(domain, 'anchor-0123456789abcdef', 60_000), /not a tzun-anchor\/2: scheduler/);
      const anchorLog = await anchors.ensureStoreLog('anchors');
      await anchors.appendLogLeaves(anchorLog.logId, [{ leafIndex: 0, leafDigest: hex('leaf-0'), sourceRef: 'cp-0' }]);
      const root = hex('root-1');
      const body = formatCheckpoint(anchorLog.origin, 1, root);
      await anchors.insertLogCheckpoint({
        logId: anchorLog.logId, treeSize: 1, root, body, bodyDigest: checkpointDigest(body), compactRange: [root],
        prevAnchoredSize: null, consistencyProof: null, anchorLeafIndex: null, epochId: 1,
      });
      const prepared = await anchors.insertAnchorPublication({ epochId: 1, anchorSize: 1, p: checkpointDigest(body), kind: 'evm-calldata/1', chain: CHAIN });
      await refusal(anchors.updateAnchorPublication(prepared.id, { state: 'superseded' }), /only a publication with an attempt, every one rejected, may be superseded/);
    });
  });
});

/**
 * Postgres: every anchoring write needs the store's owner. A second role
 * that may read, insert and update every table is refused each one, still
 * captures, and cannot borrow the right through a SECURITY DEFINER function;
 * a member of the owner role passes.
 */
(PG_TESTS_ENABLED ? describe : describe.skip)("every anchoring write needs the store's owner (Postgres)", () => {
  jest.setTimeout(120_000);
  const schema = pgSuiteSchema('anchoring_owner_gate');
  const suffix = randomBytes(5).toString('hex');
  const role = `owner_gate_${suffix}`;
  const member = `owner_gate_member_${suffix}`;
  const password = randomBytes(16).toString('hex');
  const S = schema.name;
  const OWNER_REQUIRED = /\[tzun:anchoring_owner_required\]/;

  const admin = async (sql: string, params: unknown[] = []): Promise<Record<string, unknown>[]> => {
    const client = new Client({ connectionString: schema.url });
    await client.connect();
    try {
      return (await client.query(sql, params)).rows;
    } finally {
      await client.end();
    }
  };
  const as = async (who: string): Promise<Client> => {
    const url = new URL(schema.url);
    url.username = who;
    url.password = password;
    const client = new Client({ connectionString: url.toString() });
    await client.connect();
    return client;
  };

  /** A checkpoint of `log` at `treeSize`, as the tables accept it. */
  const anchorCheckpoint = (log: LogRecord, treeSize: number) => {
    const root = hex(`root-${treeSize}`);
    const body = formatCheckpoint(log.origin, treeSize, root);
    return {
      logId: log.logId, treeSize, root, body, bodyDigest: checkpointDigest(body), compactRange: [root],
      prevAnchoredSize: null, consistencyProof: null, anchorLeafIndex: null, epochId: treeSize,
    };
  };

  let owner = '';
  beforeAll(async () => {
    owner = (await admin('SELECT current_user AS u'))[0].u as string;
    await admin(`CREATE ROLE ${role} LOGIN PASSWORD '${password}'`);
    await admin(`CREATE ROLE ${member} LOGIN NOINHERIT PASSWORD '${password}'`);
    await admin(`GRANT ${owner} TO ${member}`);
  });
  afterAll(async () => {
    await admin(`DROP OWNED BY ${role}; DROP OWNED BY ${member}; DROP ROLE ${role}; DROP ROLE ${member}`);
  });

  /** A fresh store with a custody log, an anchor checkpoint, a prepared publication, a wallet and a lease; and the grants. */
  async function storeWithRows(): Promise<{ adapter: import('../../src/storage/postgres').PostgresStorageAdapter; anchors: AnchorStore; domain: string; anchorLog: LogRecord; custody: LogRecord; p: string }> {
    await schema.reset();
    const { PostgresStorageAdapter } = await import('../../src/storage/postgres');
    const adapter = new PostgresStorageAdapter(schema.url);
    await adapter.ensureTables();
    const anchors = anchorStoreFor(adapter)!;
    const identity = await logStoreFor(adapter)!.getStoreIdentity();
    const domain = `${identity.ns}/${identity.storeId}`;
    await adapter.store(makeEnvelope({ evidenceId: 'a-1', sequenceNumber: 1 }));
    const anchorLog = await anchors.ensureStoreLog('anchors');
    const custody = await anchors.ensureStoreLog('custody');
    // Three anchor leaves; checkpoints at 1 and 2; a publication at 1. The
    // second role's writes below are each valid but for who writes them.
    await anchors.appendLogLeaves(anchorLog.logId, [0, 1, 2].map((i) => ({ leafIndex: i, leafDigest: hex(`leaf-${i}`), sourceRef: `cp-${i}` })));
    for (const size of [1, 2]) await anchors.insertLogCheckpoint(anchorCheckpoint(anchorLog, size));
    await anchors.insertAnchorPublication({ epochId: 1, anchorSize: 1, p: anchorCheckpoint(anchorLog, 1).bodyDigest, kind: 'evm-calldata/1', chain: CHAIN });
    await anchors.enrolAnchorWallet({ address: `0x${'1'.repeat(40)}`, chain: CHAIN, domain, nonceBase: 0 });
    await anchors.acquireAnchorLease(domain, HOLDER, 60_000);
    for (const who of [role, member]) {
      await admin(
        `GRANT USAGE ON SCHEMA ${S} TO ${who};
         GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ${S} TO ${who};
         GRANT USAGE ON ALL SEQUENCES IN SCHEMA ${S} TO ${who}`,
      );
    }
    return { adapter, anchors, domain, anchorLog, custody, p: anchorCheckpoint(anchorLog, 2).bodyDigest };
  }

  it('refuses a second role each anchoring write, with SQLSTATE 42501, and leaves the store as it was', async () => {
    const { adapter, domain, anchorLog, custody, p } = await storeWithRows();
    const client = await as(role);
    try {
      const attacks: Array<[string, string, unknown[]]> = [
        ['a log of another kind', `INSERT INTO ${S}.logs (origin, kind, chain_id) VALUES ($1, 'audit', NULL)`, [`${domain}/audit`]],
        ['a leaf of a per-store log', `INSERT INTO ${S}.log_leaves (log_id, leaf_index, leaf_digest, source_ref, source) VALUES ($1, 0, $2, 'x', 'scheduler')`, [custody.logId, hex('forged')]],
        ['an anchor checkpoint', `INSERT INTO ${S}.log_checkpoints (log_id, tree_size, root, body, body_digest, compact_range) VALUES ($1, 3, $2, $3, $4, '[]')`,
          [anchorLog.logId, anchorCheckpoint(anchorLog, 3).root, anchorCheckpoint(anchorLog, 3).body, anchorCheckpoint(anchorLog, 3).bodyDigest]],
        ["a checkpoint's signatures", `UPDATE ${S}.log_checkpoints SET signatures = '["forged"]' WHERE log_id = $1 AND tree_size = 1`, [anchorLog.logId]],
        ['a prepared publication', `INSERT INTO ${S}.anchor_publications (epoch_id, anchor_size, p, kind, state, chain) VALUES (2, 2, $1, 'evm-calldata/1', 'prepared', $2)`, [p, CHAIN]],
        ["a publication's fill progress", `UPDATE ${S}.anchor_publications SET fill_progress = '{"done": true}'`, []],
        ['a wallet', `INSERT INTO ${S}.anchor_wallets (address, chain, domain, nonce_base) VALUES ($1, $2, $3, 0)`, [`0x${'2'.repeat(40)}`, CHAIN, domain]],
        ["a wallet's retirement", `UPDATE ${S}.anchor_wallets SET retired_at = now()`, []],
        ['the lease', `UPDATE ${S}.anchor_lease SET holder = $1`, [`${ANCHOR_LEASE_HOLDER_PREFIX}mallory`]],
        ['an accounted transaction', `INSERT INTO ${S}.anchor_wallet_txs (address, chain, nonce, tx_hash, kind, raw_tx) VALUES ($1, $2, 3, $3, 'sweep', '0xc0')`, [`0x${'1'.repeat(40)}`, CHAIN, `0x${hex('t')}`]],
        ["a record's anchor", `UPDATE ${S}.envelopes SET envelope = jsonb_set(envelope, '{nonRepudiation,anchor}', '{"forged": true}'::jsonb) WHERE evidence_id = 'a-1'`, []],
      ];
      const before = await admin(`SELECT (SELECT count(*) FROM ${S}.logs) AS logs, (SELECT count(*) FROM ${S}.log_leaves) AS leaves,
        (SELECT count(*) FROM ${S}.log_checkpoints) AS cps, (SELECT json_agg(fill_progress) FROM ${S}.anchor_publications) AS progress,
        (SELECT json_agg(holder) FROM ${S}.anchor_lease) AS lease, (SELECT envelope::text FROM ${S}.envelopes WHERE evidence_id = 'a-1') AS record`);
      for (const [what, sql, params] of attacks) {
        const err = await client.query(sql, params).then(() => null, (e: { message: string; code: string }) => e);
        expect([what, err?.message.match(OWNER_REQUIRED) !== null, err?.code]).toEqual([what, true, '42501']);
      }
      const after = await admin(`SELECT (SELECT count(*) FROM ${S}.logs) AS logs, (SELECT count(*) FROM ${S}.log_leaves) AS leaves,
        (SELECT count(*) FROM ${S}.log_checkpoints) AS cps, (SELECT json_agg(fill_progress) FROM ${S}.anchor_publications) AS progress,
        (SELECT json_agg(holder) FROM ${S}.anchor_lease) AS lease, (SELECT envelope::text FROM ${S}.envelopes WHERE evidence_id = 'a-1') AS record`);
      expect(after).toEqual(before);
    } finally {
      await client.end();
      await adapter.close();
    }
  });

  it("refuses the second role a change to a record's existing anchor, its removal, and a lease delete; a write that keeps the anchor passes", async () => {
    const { adapter } = await storeWithRows();
    await admin(`UPDATE ${S}.envelopes SET envelope = jsonb_set(envelope, '{nonRepudiation,anchor}', '{"anchorSpec":"genuine"}'::jsonb, true) WHERE evidence_id = 'a-1'`);
    await admin(`GRANT DELETE ON ${S}.anchor_lease TO ${role}`);
    const client = await as(role);
    try {
      const attacks: Array<[string, string]> = [
        ['strip the anchor', `UPDATE ${S}.envelopes SET envelope = envelope #- '{nonRepudiation,anchor}' WHERE evidence_id = 'a-1'`],
        ['replace the anchor', `UPDATE ${S}.envelopes SET envelope = jsonb_set(envelope, '{nonRepudiation,anchor}', '{"anchorSpec":"forged"}'::jsonb) WHERE evidence_id = 'a-1'`],
        ['delete the lease', `DELETE FROM ${S}.anchor_lease`],
      ];
      for (const [what, sql] of attacks) {
        const err = await client.query(sql).then(() => null, (e: { message: string; code: string }) => e);
        expect([what, err?.message.match(OWNER_REQUIRED) !== null, err?.code]).toEqual([what, true, '42501']);
      }
      // A write that leaves the anchor as it is (an attestation retry, a custody append) is not gated.
      await client.query(`UPDATE ${S}.envelopes SET envelope = jsonb_set(envelope, '{nonRepudiation,kept}', 'true'::jsonb, true) WHERE evidence_id = 'a-1'`);
      const [row] = await admin(`SELECT envelope->'nonRepudiation' AS nr FROM ${S}.envelopes WHERE evidence_id = 'a-1'`);
      expect(row.nr).toEqual({ anchor: { anchorSpec: 'genuine' }, kept: true });
      expect(await admin(`SELECT holder FROM ${S}.anchor_lease`)).toEqual([{ holder: HOLDER }]);
    } finally {
      await client.end();
      await adapter.close();
    }
  });

  it('from PostgreSQL 16, refuses a member of the owner role that can neither inherit it nor SET ROLE to it', async () => {
    const [{ v }] = await admin(`SELECT current_setting('server_version_num')::int AS v`);
    if ((v as number) < 160000) return;
    const { adapter, custody } = await storeWithRows();
    const inert = `owner_gate_inert_${suffix}`;
    await admin(`CREATE ROLE ${inert} LOGIN NOINHERIT PASSWORD '${password}'; GRANT ${owner} TO ${inert} WITH INHERIT FALSE, SET FALSE;
      GRANT USAGE ON SCHEMA ${S} TO ${inert}; GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ${S} TO ${inert}`);
    const client = await as(inert);
    try {
      const err = await client
        .query(`INSERT INTO ${S}.log_leaves (log_id, leaf_index, leaf_digest, source_ref, source) VALUES ($1, 0, $2, 'inert', 'scheduler')`, [custody.logId, hex('inert')])
        .then(() => null, (e: { message: string; code: string }) => e);
      expect([err?.message.match(OWNER_REQUIRED) !== null, err?.code]).toEqual([true, '42501']);
    } finally {
      await client.end();
      await adapter.close();
      await admin(`DROP OWNED BY ${inert}; DROP ROLE ${inert}`);
    }
  });

  it('the second role still captures: its record gets its evidence leaf', async () => {
    const { adapter } = await storeWithRows();
    const client = await as(role);
    try {
      const e = makeEnvelope({ evidenceId: 'a-2', sequenceNumber: 2 });
      await client.query(
        `INSERT INTO ${S}.envelopes (evidence_id, envelope, captured_at, ai_system_id, digest, chain_id) VALUES ($1, $2, $3, $4, $5, 'default')`,
        [e.payload.evidenceId, JSON.stringify(e), e.payload.capturedAt, e.payload.aiSystemId, e.integrity.canonicalDigest],
      );
      expect((await logStoreFor(adapter)!.getEvidenceLogPosition('a-2'))!.leafIndex).toBe(1);
    } finally {
      await client.end();
      await adapter.close();
    }
  });

  it("refuses the second role through a SECURITY DEFINER function of the owner's (session_user), and passes a member of the owner role", async () => {
    const { adapter, custody } = await storeWithRows();
    await admin(
      `CREATE FUNCTION ${S}.lend_checkpoint(log BIGINT) RETURNS void SECURITY DEFINER SET search_path = pg_catalog AS $$
         INSERT INTO ${S}.log_leaves (log_id, leaf_index, leaf_digest, source_ref, source) VALUES (log, 0, '${hex('lent')}', 'lent', 'scheduler')
       $$ LANGUAGE sql;
       GRANT EXECUTE ON FUNCTION ${S}.lend_checkpoint(BIGINT) TO ${role}`,
    );
    const lender = await as(role);
    try {
      await expect(lender.query(`SELECT ${S}.lend_checkpoint($1)`, [custody.logId])).rejects.toThrow(OWNER_REQUIRED);
    } finally {
      await lender.end();
    }
    const ownerMember = await as(member);
    try {
      await ownerMember.query(`INSERT INTO ${S}.log_leaves (log_id, leaf_index, leaf_digest, source_ref, source) VALUES ($1, 0, $2, 'member', 'scheduler')`, [custody.logId, hex('member')]);
    } finally {
      await ownerMember.end();
    }
    expect((await logStoreFor(adapter)!.listLogLeaves(custody.logId, 0, 1)).map((l) => l.sourceRef)).toEqual(['member']);
    await adapter.close();
  });
});
