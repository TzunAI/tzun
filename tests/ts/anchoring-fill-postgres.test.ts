/**
 * What a fill (Anchor §8.4, §11) costs on Postgres: its write amplification
 * and the per-record size, measured and recorded. Records are captured
 * through `Tzun.capture()`, so their
 * envelopes are the real shape; the epoch is published on the in-memory
 * chain, and the fill is the scheduler's.
 *
 * It prints one line of measurements, and asserts only what must hold: every
 * record gains an artifact and one revision row, and the artifact stays
 * small (two paths of about log2(n) hashes and one publication entry).
 * Runs only when the Postgres legs run.
 */
import { Client } from 'pg';
import { Wallet } from 'ethers';
import { Tzun } from '../../src/sdk';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { createAnchorScheduler, createEvmPublisher } from '../../src/anchoring';
import { FakeEvmChain } from './helpers/anchoring-fake-chain';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

const RECORDS = Number(process.env.TZUN_FILL_MEASURE_RECORDS ?? 1000);
const schema = pgSuiteSchema('anchoring_fill_measure');
const maybe = PG_TESTS_ENABLED ? describe : describe.skip;

maybe('the fill on Postgres: write amplification and per-record size (Anchor §8.4, §11)', () => {
  jest.setTimeout(600_000);

  it(`fills ${RECORDS} captured records and reports what it wrote`, async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbUrl: schema.url });
    for (let i = 0; i < RECORDS; i++) {
      await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { decision: 'approve', score: i / RECORDS, rationale: 'x'.repeat(200) }, action: 'approved', reason: 'reviewed', aiSystemId: 'measure' });
    }
    await tzun.close();

    const adapter = new PostgresStorageAdapter(schema.url);
    await adapter.ensureTables();
    const client = new Client({ connectionString: schema.url });
    await client.connect();
    try {
      const measure = async () =>
        (
          await client.query(`SELECT pg_total_relation_size('envelopes') AS envelopes,
                                     pg_total_relation_size('envelope_revisions') AS revisions,
                                     (SELECT avg(octet_length(envelope::text)) FROM envelopes) AS avg_envelope,
                                     (SELECT count(*) FROM envelope_revisions) AS revision_rows,
                                     pg_current_wal_lsn() AS lsn`)
        ).rows[0];
      const chain = new FakeEvmChain();
      const wallet = Wallet.createRandom();
      chain.fund(wallet.address, 10n ** 18n);
      // The store was minted `local.invalid`: a production namespace, so the
      // measurement runs with the activation guard set, on the in-memory chain.
      const scheduler = await createAnchorScheduler({
        storage: adapter,
        // The records were captured with no attestation configured.
        expectation: {},
        config: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', privateKey: wallet.privateKey, chain: 'eip155:31337' } }, production: true },
        publisher: createEvmPublisher({ privateKey: wallet.privateKey, chain: 'eip155:31337', client: chain }),
      });
      await scheduler.anchorNow({ force: true });
      chain.mine(3);
      const before = await measure();
      const started = Date.now();
      // One pass: the publication is finalized (one row), then its records are filled.
      const report = await scheduler.runPass();
      const fillMs = Date.now() - started;
      const after = await measure();
      await scheduler.stop();

      const artifact = (
        await client.query(`SELECT avg(octet_length((envelope->'nonRepudiation'->'anchor')::text)) AS avg,
                                   max(octet_length((envelope->'nonRepudiation'->'anchor')::text)) AS max
                              FROM envelopes`)
      ).rows[0];
      const wal = (await client.query('SELECT pg_wal_lsn_diff($1, $2) AS bytes', [after.lsn, before.lsn])).rows[0].bytes;
      const line = {
        records: RECORDS,
        filled: report.filled,
        fillMs,
        avgEnvelopeBytesBefore: Math.round(Number(before.avg_envelope)),
        avgEnvelopeBytesAfter: Math.round(Number(after.avg_envelope)),
        avgArtifactBytes: Math.round(Number(artifact.avg)),
        maxArtifactBytes: Number(artifact.max),
        envelopesTableBytesBefore: Number(before.envelopes),
        envelopesTableBytesAfter: Number(after.envelopes),
        revisionsTableBytesBefore: Number(before.revisions),
        revisionsTableBytesAfter: Number(after.revisions),
        revisionRowsAdded: Number(after.revision_rows) - Number(before.revision_rows),
        walBytes: Number(wal),
        walBytesPerRecord: Math.round(Number(wal) / RECORDS),
      };
      // eslint-disable-next-line no-console
      console.log(`anchor fill measurement ${JSON.stringify(line)}`);
      expect(report.filled).toBe(RECORDS);
      expect(line.revisionRowsAdded).toBe(RECORDS);
      // Two paths of ceil(log2(n)) hashes (about 67 bytes each as JSON) and one publication entry.
      expect(line.maxArtifactBytes).toBeLessThan(2 * Math.ceil(Math.log2(RECORDS)) * 70 + 1200);
    } finally {
      await client.end();
      await adapter.close();
    }
  });
});
