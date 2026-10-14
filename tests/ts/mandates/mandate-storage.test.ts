/**
 * The mandate tables as a storage extension, on the
 * memory, SQLite and Postgres adapters: the issue, the slot claim by
 * compare-and-swap, the state moves and their events, expiry, the listing,
 * the refusals and conflicts, and (SQLite, Postgres) the triggers that keep
 * the rows honest against a direct write.
 */
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type Database from 'better-sqlite3';
import { Client, Pool } from 'pg';
import {
  assertionDigest,
  buildMandateEventBody,
  buildMandateStatement,
  canonicalSerializeValue,
  InvalidPaginationError,
  mandateStatementChallenge,
  mandateStatementDigest,
} from '@tzun/engine';
import type { EvidenceEnvelope, MandateRow, StorageAdapter, StoreOptions } from '@tzun/engine';
import { MemoryStorageAdapter } from '../../../src/storage/memory';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../../src/storage/postgres';
import { decidersExtension } from '../../../src/storage/ddl/deciders';
import { mandatesExtension, memoryListMandates, postgresListMandates, sqliteListMandates } from '../../../src/storage/ddl/mandates';
import {
  MandateStoreConflictError,
  MandateStoreInputError,
  MandateStoreRefusalError,
  type MandateListFilter,
  type MandateListPage,
} from '../../../src/storage/mandate-sql';
import { mandateEventRow } from '../../../src/sdk/mandates/store';
import { PG_TESTS_ENABLED, pgSuiteSchema } from '../helpers/postgres-test-db';
import { assert, mandateDocument, person } from './fixtures';

const sha = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');
const HOUR = 3_600_000;
const iso = (offsetMs: number): string => new Date(Date.now() + offsetMs).toISOString();

function envelope(evidenceId: string, sequenceNumber: number, payload: Record<string, unknown>): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      evidenceId,
      schemaVersion: 'v1.0',
      aiSystemId: 'claims-triage',
      aiOutput: {},
      action: 'approve',
      reason: 'mandate storage suite',
      capturedAt: new Date().toISOString(),
      sequenceNumber,
      decider: { kind: 'agent-mandated', id: `desc:sha256:${sha('agent')}`, agent: `sha256:${sha('agent')}`, credential: null, freshness: null },
      contributions: null,
      links: null,
      signoffExpectation: null,
      ...payload,
    },
    integrity: { canonicalDigest: sha(`record ${evidenceId}`), chainLink: null },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  } as EvidenceEnvelope;
}

/** The principal every mandate of this suite is issued by. */
const principal = person('user-2c9d');

/** A mandate as a store issues it: the issuance record and the `mandateIssue` option it is stored with. */
function issuance(seq: number, opts: { maxRecords?: number | null; notBefore?: string | null; notAfter?: string | null; caps?: Record<string, number> | null } = {}) {
  const maxRecords = opts.maxRecords === undefined ? 3 : opts.maxRecords;
  const notBefore = opts.notBefore === undefined ? iso(-HOUR) : opts.notBefore;
  const notAfter = opts.notAfter === undefined ? iso(HOUR) : opts.notAfter;
  const caps = opts.caps === undefined ? { paid: 1000 } : opts.caps;
  const document = mandateDocument(principal.userId, {
    validity: { notBefore, notAfter },
    limits: {
      maxRecords,
      cumulative: caps === null ? null : Object.fromEntries(Object.entries(caps).map(([cap, max]) => [cap, { path: '/aiOutput/amountMinor', max }])),
    },
  });
  const mandateId = document.mandateId;
  const documentBytes = canonicalSerializeValue(document);
  const mandateDigest = sha(documentBytes);
  const statement = buildMandateStatement({ mandateDigest, signer: principal.userId, policyDigest: null, notBefore: null });
  const statementDigest = mandateStatementDigest(statement)!;
  const assertion = assert(principal, mandateStatementChallenge(statementDigest));
  const aDigest = assertionDigest(assertion)!;
  const env = envelope(randomUUID(), seq, {
    aiSystemId: 'tzun:mandate',
    action: 'issue-mandate',
    aiOutput: { assertionDigest: aDigest, mandateDigest, statementDigest },
    decider: { kind: 'human', id: 'acct:user-2c9d', agent: null, credential: null, freshness: null },
  });
  const record: MandateRow = {
    mandateId,
    mandateDigest,
    documentBytes,
    statementJson: canonicalSerializeValue(statement),
    statementDigest,
    assertionJson: canonicalSerializeValue(assertion),
    assertionDigest: aDigest,
    assertionTimestamp: null,
    state: 'open',
    used: 0,
    maxRecords,
    notBefore,
    notAfter,
    issuanceEvidenceId: env.payload.evidenceId,
    issuanceDigest: env.integrity.canonicalDigest,
    createdAt: env.payload.capturedAt,
  };
  const options: StoreOptions = {
    mandateIssue: {
      record,
      caps: Object.entries(caps ?? {}).map(([cap, max]) => ({ cap, max })),
      event: mandateEventRow(mandateId, buildMandateEventBody({ event: 'issued', mandateDigest, record: env.integrity.canonicalDigest })),
    },
  };
  return { mandateId, mandateDigest, assertionDigest: aDigest, envelope: env, options, record, document };
}

type Issued = ReturnType<typeof issuance>;

/** A record under `m` claiming slot `expectUsed + 1`, adding `amount` to `paid` (when the mandate has that cap). */
function claimed(m: Issued, seq: number, expectUsed: number, amount: number, expectTotal: number, overrides: { mandateSeq?: number; now?: string } = {}) {
  const hasCap = m.options.mandateIssue!.caps.length > 0;
  const env = envelope(randomUUID(), seq, {
    aiOutput: { amountMinor: amount },
    signoffExpectation: {
      mandateAssertion: m.assertionDigest,
      mandateSeq: overrides.mandateSeq ?? expectUsed + 1,
      totals: hasCap ? { paid: expectTotal + amount } : null,
      confirm: false,
    },
    links: [{ rel: 'mandate', target: { digest: m.envelope.integrity.canonicalDigest, evidenceId: m.envelope.payload.evidenceId, locator: null }, attrs: null }],
  });
  if (overrides.now !== undefined) env.payload.capturedAt = overrides.now;
  const options: StoreOptions = {
    mandateClaim: {
      mandateId: m.mandateId,
      expectUsed,
      caps: hasCap ? [{ cap: 'paid', expectTotal, newTotal: expectTotal + amount }] : [],
      now: env.payload.capturedAt,
    },
  };
  return { envelope: env, options };
}

/** A record that closes `m` (`revoked`, its revocation record) on the slots and totals given. */
function revocation(m: Issued, seq: number, used: number, totals: Record<string, number> | null) {
  const env = envelope(randomUUID(), seq, {
    aiSystemId: 'tzun:mandate',
    action: 'revoke-mandate',
    aiOutput: { mandateDigest: m.mandateDigest },
    decider: { kind: 'human', id: 'acct:user-2c9d', agent: null, credential: null, freshness: null },
  });
  const options: StoreOptions = {
    mandateRevoke: {
      mandateId: m.mandateId,
      expectState: 'open',
      newState: 'revoked',
      expectUsed: used,
      expectTotals: totals,
      event: mandateEventRow(
        m.mandateId,
        buildMandateEventBody({ event: 'revoked', mandateDigest: m.mandateDigest, record: env.integrity.canonicalDigest, used, totals }),
      ),
    },
  };
  return { envelope: env, options };
}

function expiry(m: Issued, used: number, totals: Record<string, number> | null) {
  return {
    mandateId: m.mandateId,
    expectState: 'open' as const,
    expectUsed: used,
    expectTotals: totals,
    event: mandateEventRow(
      m.mandateId,
      buildMandateEventBody({ event: 'expired', mandateDigest: m.mandateDigest, record: m.envelope.integrity.canonicalDigest, used, totals }),
    ),
  };
}

interface Leg {
  name: 'memory' | 'sqlite' | 'postgres';
  open(): Promise<StorageAdapter>;
  /** Run one statement directly against the store's database (SQL legs only), answering how many rows it changed. */
  sql?(statement: string, params?: unknown[]): Promise<number>;
  /** The adapter's listing of its mandates (the `listMandates` its dialect implements). */
  list(adapter: StorageAdapter, filter?: MandateListFilter): Promise<MandateListPage>;
}

/** The mandate state a memory adapter keeps for the extension. */
function memoryMandateState(adapter: StorageAdapter): { rows: ReadonlyMap<string, MandateRow> } {
  const held = (adapter as unknown as { extensions: Array<{ ext: { name: string }; state: unknown }> }).extensions;
  return held.find((e) => e.ext.name === 'mandates')!.state as { rows: ReadonlyMap<string, MandateRow> };
}

let dir: string;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'tzun-test-mandate-storage-'));
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

const pg = pgSuiteSchema('mandate_storage');
/** The SQLite adapter's own connection: a direct write on it is the write an insider with the file would make. */
let sqliteDb: Database.Database | null = null;
let n = 0;
const legs: Leg[] = [
  {
    name: 'memory',
    open: async () => new MemoryStorageAdapter({ extensions: [decidersExtension, mandatesExtension] }),
    list: async (adapter, filter) => memoryListMandates(memoryMandateState(adapter), filter),
  },
  {
    name: 'sqlite',
    open: async () => {
      const adapter = new SqliteStorageAdapter(join(dir, `mandates-${++n}.db`), { extensions: [decidersExtension, mandatesExtension] });
      sqliteDb = (adapter as unknown as { db: Database.Database }).db;
      return adapter;
    },
    async sql(statement, params = []) {
      return sqliteDb!.prepare(statement).run(...(params as unknown[])).changes;
    },
    list: async (_adapter, filter) => sqliteListMandates(sqliteDb!, filter),
  },
  ...(PG_TESTS_ENABLED
    ? [
        {
          name: 'postgres' as const,
          open: async () => {
            await pg.empty();
            const adapter = new PostgresStorageAdapter(pg.url, undefined, { extensions: [decidersExtension, mandatesExtension] });
            await adapter.ensureTables();
            return adapter;
          },
          async sql(statement: string, params: unknown[] = []) {
            const client = new Client({ connectionString: pg.url });
            await client.connect();
            try {
              const result = await client.query(statement.replace(/\?/g, (() => { let i = 0; return () => `$${++i}`; })()), params);
              return result.rowCount ?? 0;
            } finally {
              await client.end();
            }
          },
          async list(_adapter: StorageAdapter, filter?: MandateListFilter) {
            const pool = new Pool({ connectionString: pg.url, max: 1 });
            try {
              return await postgresListMandates(pool, filter);
            } finally {
              await pool.end();
            }
          },
        },
      ]
    : []),
];

describe.each(legs)('the mandate tables on $name', (leg) => {
  let adapter: StorageAdapter;
  let seq: number;
  const store = async (w: { envelope: EvidenceEnvelope; options: StoreOptions }): Promise<void> => {
    await adapter.store(w.envelope, 'default', w.options);
    seq += 1;
  };

  beforeEach(async () => {
    adapter = await leg.open();
    seq = 1;
  });
  afterEach(async () => {
    await adapter.close?.();
  });

  it('issues a mandate with its caps and its issued event, in the storing transaction', async () => {
    const m = issuance(seq);
    await store(m);
    expect(await adapter.getMandate!(m.mandateId)).toEqual(m.record);
    expect(await adapter.getMandate!(m.mandateDigest)).toEqual(m.record);
    expect(await adapter.getMandateTotals!(m.mandateId)).toEqual({ paid: 0 });
    const events = await adapter.listMandateEvents!(m.mandateId);
    expect(events).toEqual([m.options.mandateIssue!.event]);
    expect(await adapter.getMandate!(randomUUID())).toBeNull();
    expect(await adapter.getMandateTotals!(randomUUID())).toEqual({});
    expect(await adapter.listMandateEvents!(randomUUID())).toEqual([]);
  });

  it('refuses a second issue of one mandate, and writes nothing of the refused record', async () => {
    const m = issuance(seq);
    await store(m);
    const again = issuance(seq);
    again.options.mandateIssue!.record = { ...again.options.mandateIssue!.record, mandateId: m.mandateId };
    again.options.mandateIssue!.event = mandateEventRow(m.mandateId, again.options.mandateIssue!.event.body);
    await expect(adapter.store(again.envelope, 'default', again.options)).rejects.toMatchObject({ name: 'MandateStoreRefusalError', code: 'mandate_already_issued' });
    expect(await adapter.retrieve(again.envelope.payload.evidenceId)).toBeNull();
    expect(await adapter.getLastSequence()).toBe(1);
  });

  it('claims slots and totals by compare-and-swap: a stale claim conflicts and writes nothing', async () => {
    const m = issuance(seq);
    await store(m);
    await store(claimed(m, seq, 0, 300, 0));
    expect(await adapter.getMandate!(m.mandateId)).toMatchObject({ used: 1 });
    expect(await adapter.getMandateTotals!(m.mandateId)).toEqual({ paid: 300 });

    const stale = claimed(m, seq, 0, 100, 0);
    await expect(adapter.store(stale.envelope, 'default', stale.options)).rejects.toBeInstanceOf(MandateStoreConflictError);
    const staleTotal = claimed(m, seq, 1, 100, 0);
    await expect(adapter.store(staleTotal.envelope, 'default', staleTotal.options)).rejects.toMatchObject({ code: 'mandate_claim_conflict' });
    expect(await adapter.retrieve(stale.envelope.payload.evidenceId)).toBeNull();
    expect(await adapter.getMandate!(m.mandateId)).toMatchObject({ used: 1 });
    expect(await adapter.getMandateTotals!(m.mandateId)).toEqual({ paid: 300 });

    await store(claimed(m, seq, 1, 700, 300));
    expect(await adapter.getMandateTotals!(m.mandateId)).toEqual({ paid: 1000 });
  });

  it('refuses a full mandate, a cap exceeded, an instant outside the window, and a mandate not held', async () => {
    const m = issuance(seq, { maxRecords: 1, notBefore: iso(-HOUR), notAfter: iso(HOUR) });
    await store(m);
    const over = claimed(m, seq, 0, 1001, 0);
    await expect(adapter.store(over.envelope, 'default', over.options)).rejects.toMatchObject({ name: 'MandateStoreRefusalError', code: 'cap_exceeded' });
    const late = claimed(m, seq, 0, 1, 0, { now: iso(2 * HOUR) });
    await expect(adapter.store(late.envelope, 'default', late.options)).rejects.toMatchObject({ code: 'outside_validity' });
    const early = claimed(m, seq, 0, 1, 0, { now: iso(-2 * HOUR) });
    await expect(adapter.store(early.envelope, 'default', early.options)).rejects.toMatchObject({ code: 'outside_validity' });
    await store(claimed(m, seq, 0, 1, 0));
    const full = claimed(m, seq, 1, 1, 1);
    await expect(adapter.store(full.envelope, 'default', full.options)).rejects.toMatchObject({ code: 'mandate_full' });
    const other = claimed({ ...m, mandateId: randomUUID() }, seq, 0, 1, 0);
    await expect(adapter.store(other.envelope, 'default', other.options)).rejects.toMatchObject({ code: 'mandate_not_found' });
    expect(await adapter.getMandate!(m.mandateId)).toMatchObject({ state: 'open', used: 1 });
  });

  it('refuses a claim the record it is stored with does not carry', async () => {
    const m = issuance(seq);
    await store(m);
    const wrongSlot = claimed(m, seq, 0, 1, 0, { mandateSeq: 2 });
    await expect(adapter.store(wrongSlot.envelope, 'default', wrongSlot.options)).rejects.toBeInstanceOf(MandateStoreInputError);
    const noLink = claimed(m, seq, 0, 1, 0);
    noLink.envelope.payload.links = null;
    await expect(adapter.store(noLink.envelope, 'default', noLink.options)).rejects.toBeInstanceOf(MandateStoreInputError);
    const missingCap = claimed(m, seq, 0, 1, 0);
    missingCap.options.mandateClaim!.caps = [];
    await expect(adapter.store(missingCap.envelope, 'default', missingCap.options)).rejects.toBeInstanceOf(MandateStoreInputError);
    expect(await adapter.getMandate!(m.mandateId)).toMatchObject({ used: 0 });
  });

  it('a mandate without caps claims slots only', async () => {
    const m = issuance(seq, { caps: null, maxRecords: null, notBefore: null, notAfter: null });
    await store(m);
    for (let used = 0; used < 3; used++) await store(claimed(m, seq, used, 0, 0));
    expect(await adapter.getMandate!(m.mandateId)).toMatchObject({ used: 3, maxRecords: null });
    expect(await adapter.getMandateTotals!(m.mandateId)).toEqual({});
  });

  it('revokes on the slots and totals it read; a stale close conflicts; a closed mandate takes no claim', async () => {
    const m = issuance(seq);
    await store(m);
    await store(claimed(m, seq, 0, 250, 0));
    const stale = revocation(m, seq, 0, { paid: 0 });
    await expect(adapter.store(stale.envelope, 'default', stale.options)).rejects.toMatchObject({ name: 'MandateStoreConflictError', code: 'mandate_state_conflict' });
    const r = revocation(m, seq, 1, { paid: 250 });
    await store(r);
    expect(await adapter.getMandate!(m.mandateId)).toMatchObject({ state: 'revoked', used: 1 });
    expect((await adapter.listMandateEvents!(m.mandateId)).map((e) => e.body.event)).toEqual(['issued', 'revoked']);
    const after = claimed(m, seq, 1, 1, 250);
    await expect(adapter.store(after.envelope, 'default', after.options)).rejects.toMatchObject({ code: 'mandate_not_open' });
    const twice = revocation(m, seq, 1, { paid: 250 });
    await expect(adapter.store(twice.envelope, 'default', twice.options)).rejects.toMatchObject({ code: 'mandate_not_open' });
  });

  it('expires a mandate whose window has ended, on the slots and totals it read, and only then', async () => {
    const live = issuance(seq);
    await store(live);
    await expect(adapter.expireMandate!(expiry(live, 0, { paid: 0 }))).rejects.toMatchObject({ name: 'MandateStoreRefusalError', code: 'mandate_not_expired' });

    const ended = issuance(seq, { notBefore: iso(-3 * HOUR), notAfter: iso(-HOUR) });
    await store(ended);
    await expect(adapter.expireMandate!(expiry(ended, 1, { paid: 0 }))).rejects.toBeInstanceOf(MandateStoreConflictError);
    await adapter.expireMandate!(expiry(ended, 0, { paid: 0 }));
    expect(await adapter.getMandate!(ended.mandateId)).toMatchObject({ state: 'expired' });
    expect((await adapter.listMandateEvents!(ended.mandateId)).map((e) => e.body)).toContainEqual(expect.objectContaining({ event: 'expired', used: 0 }));
    await expect(adapter.expireMandate!(expiry(ended, 0, { paid: 0 }))).rejects.toMatchObject({ code: 'mandate_not_open' });
  });

  it('refuses an event row whose digest is not its bytes', async () => {
    const m = issuance(seq);
    m.options.mandateIssue!.event = { ...m.options.mandateIssue!.event, digest: sha('other') };
    await expect(adapter.store(m.envelope, 'default', m.options)).rejects.toBeInstanceOf(MandateStoreInputError);
    expect(await adapter.getMandate!(m.mandateId)).toBeNull();
  });

  it('takes a claim at either end of the window and refuses one a millisecond outside it', async () => {
    const notBefore = iso(-HOUR);
    const notAfter = iso(HOUR);
    const at = (base: string, offsetMs: number): string => new Date(Date.parse(base) + offsetMs).toISOString();
    const m = issuance(seq, { notBefore, notAfter });
    await store(m);
    const early = claimed(m, seq, 0, 1, 0, { now: at(notBefore, -1) });
    await expect(adapter.store(early.envelope, 'default', early.options)).rejects.toMatchObject({ code: 'outside_validity' });
    const late = claimed(m, seq, 0, 1, 0, { now: at(notAfter, 1) });
    await expect(adapter.store(late.envelope, 'default', late.options)).rejects.toMatchObject({ code: 'outside_validity' });
    await store(claimed(m, seq, 0, 1, 0, { now: notBefore }));
    await store(claimed(m, seq, 1, 1, 1, { now: notAfter }));
    expect(await adapter.getMandate!(m.mandateId)).toMatchObject({ used: 2 });
  });

  it("refuses a claim whose instant, totals or expectation are not the record's", async () => {
    const m = issuance(seq);
    await store(m);
    const otherInstant = claimed(m, seq, 0, 1, 0);
    otherInstant.options.mandateClaim!.now = new Date(Date.parse(otherInstant.envelope.payload.capturedAt) - 1000).toISOString();
    await expect(adapter.store(otherInstant.envelope, 'default', otherInstant.options)).rejects.toBeInstanceOf(MandateStoreInputError);
    const otherTotals = claimed(m, seq, 0, 1, 0);
    (otherTotals.envelope.payload.signoffExpectation as { totals: Record<string, number> }).totals = { paid: 2 };
    await expect(adapter.store(otherTotals.envelope, 'default', otherTotals.options)).rejects.toBeInstanceOf(MandateStoreInputError);
    const otherAssertion = claimed(m, seq, 0, 1, 0);
    (otherAssertion.envelope.payload.signoffExpectation as { mandateAssertion: string }).mandateAssertion = sha('another assertion');
    await expect(adapter.store(otherAssertion.envelope, 'default', otherAssertion.options)).rejects.toBeInstanceOf(MandateStoreInputError);
    expect(await adapter.getMandate!(m.mandateId)).toMatchObject({ used: 0 });
    expect(await adapter.getLastSequence()).toBe(1);
  });

  it('refuses a close whose event names another record, or that is not stored with a revocation record', async () => {
    const m = issuance(seq);
    await store(m);
    const otherRecord = revocation(m, seq, 0, { paid: 0 });
    otherRecord.options.mandateRevoke!.event = mandateEventRow(
      m.mandateId,
      buildMandateEventBody({ event: 'revoked', mandateDigest: m.mandateDigest, record: sha('another record'), used: 0, totals: { paid: 0 } }),
    );
    await expect(adapter.store(otherRecord.envelope, 'default', otherRecord.options)).rejects.toBeInstanceOf(MandateStoreInputError);
    const notSystem = revocation(m, seq, 0, { paid: 0 });
    notSystem.envelope.payload.aiSystemId = 'claims-triage';
    await expect(adapter.store(notSystem.envelope, 'default', notSystem.options)).rejects.toBeInstanceOf(MandateStoreInputError);
    const notRevocation = revocation(m, seq, 0, { paid: 0 });
    notRevocation.envelope.payload.action = 'issue-mandate';
    await expect(adapter.store(notRevocation.envelope, 'default', notRevocation.options)).rejects.toBeInstanceOf(MandateStoreInputError);
    expect(await adapter.getMandate!(m.mandateId)).toMatchObject({ state: 'open' });
    expect((await adapter.listMandateEvents!(m.mandateId)).map((e) => e.body.event)).toEqual(['issued']);
  });

  it('refuses a mandate row that disagrees with its own document, statement or assertion', async () => {
    const variants: Array<[string, (m: Issued) => void]> = [
      ['document bytes that do not hash to the digest', (m) => (m.record.documentBytes = canonicalSerializeValue({ ...m.document, review: { maxAgeMs: 1 } }))],
      ['document bytes that are not canonical', (m) => {
        m.record.documentBytes = JSON.stringify(m.document);
        m.record.mandateDigest = sha(m.record.documentBytes);
      }],
      ['a slot limit other than the document', (m) => (m.record.maxRecords = 7)],
      ['a window end other than the document', (m) => (m.record.notAfter = iso(2 * HOUR))],
      ['a window start other than the document', (m) => (m.record.notBefore = null)],
      ['a cap maximum other than the document', (m) => (m.options.mandateIssue!.caps = [{ cap: 'paid', max: 5000 }])],
      ['a cap the document does not have', (m) => (m.options.mandateIssue!.caps = [{ cap: 'paid', max: 1000 }, { cap: 'count', max: 3 }])],
      ['a statement of another mandate', (m) => {
        const statement = buildMandateStatement({ mandateDigest: sha('another mandate'), signer: principal.userId, policyDigest: null, notBefore: null });
        m.record.statementJson = canonicalSerializeValue(statement);
        m.record.statementDigest = mandateStatementDigest(statement)!;
      }],
      ['a statement digest that is not the statement', (m) => (m.record.statementDigest = sha('another statement'))],
      ['an assertion digest that is not the assertion', (m) => (m.record.assertionDigest = sha('another assertion'))],
    ];
    for (const [label, spoil] of variants) {
      const m = issuance(seq);
      spoil(m);
      // The issuance record names what the row names, so the row's own parts are what is refused.
      Object.assign(m.envelope.payload.aiOutput as Record<string, unknown>, {
        mandateDigest: m.record.mandateDigest,
        statementDigest: m.record.statementDigest,
        assertionDigest: m.record.assertionDigest,
      });
      m.options.mandateIssue!.event = mandateEventRow(
        m.mandateId,
        buildMandateEventBody({ event: 'issued', mandateDigest: m.record.mandateDigest, record: m.envelope.integrity.canonicalDigest }),
      );
      await expect(adapter.store(m.envelope, 'default', m.options)).rejects.toMatchObject({ name: 'MandateStoreInputError', message: expect.any(String) });
      expect([label, await adapter.getMandate!(m.mandateId)]).toEqual([label, null]);
    }
    expect(await adapter.getLastSequence()).toBe(0);
  });

  it('lists mandates by state and by the end of their window, a page at a time, in mandate id order', async () => {
    const ended = issuance(seq, { notBefore: iso(-3 * HOUR), notAfter: iso(-HOUR) });
    await store(ended);
    const live = issuance(seq);
    await store(live);
    const endless = issuance(seq, { notBefore: null, notAfter: null });
    await store(endless);
    const closed = issuance(seq, { notBefore: iso(-3 * HOUR), notAfter: iso(-2 * HOUR) });
    await store(closed);
    await store(revocation(closed, seq, 0, { paid: 0 }));
    const ids = [ended, live, endless, closed].map((m) => m.mandateId).sort();

    const all = await leg.list(adapter);
    expect(all.rows.map((r) => r.mandateId)).toEqual(ids);
    expect(all.cursor).toBeNull();
    expect(all.rows.find((r) => r.mandateId === live.mandateId)).toEqual(live.record);

    const pastWindow = await leg.list(adapter, { state: 'open', notAfterBefore: new Date().toISOString() });
    expect(pastWindow.rows.map((r) => r.mandateId)).toEqual([ended.mandateId]);
    expect((await leg.list(adapter, { state: 'revoked' })).rows.map((r) => r.mandateId)).toEqual([closed.mandateId]);
    expect((await leg.list(adapter, { notAfterBefore: iso(-90 * 60_000) })).rows.map((r) => r.mandateId)).toEqual([closed.mandateId]);

    const paged: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const page: MandateListPage = await leg.list(adapter, { limit: 1, cursor });
      paged.push(...page.rows.map((r) => r.mandateId));
      cursor = page.cursor;
      pages += 1;
    } while (cursor !== null);
    expect(paged).toEqual(ids);
    expect(pages).toBe(4);

    for (const bad of [{ limit: 0 }, { limit: 201 }, { limit: '5' }, { state: 'closed' }, { notAfterBefore: 'yesterday' }, { cursor: 5 }]) {
      await expect(leg.list(adapter, bad as unknown as MandateListFilter)).rejects.toBeInstanceOf(InvalidPaginationError);
    }
  });

  /**
   * The message a direct statement is refused with, or `null` when it went
   * through. Read off the error rather than matched with `toThrow`: the
   * native SQLite binding keeps the error class of the first test file that
   * loaded it in a jest worker, so its errors need not be instances of this
   * file's `Error`.
   */
  const refusal = async (statement: Promise<number>): Promise<string | null> => {
    try {
      await statement;
      return null;
    } catch (error) {
      return String((error as { message?: unknown }).message ?? error);
    }
  };

  const sqlLeg = leg.sql ? it : it.skip;
  sqlLeg('the triggers refuse a direct write that the rules forbid', async () => {
    const m = issuance(seq);
    await store(m);
    await store(claimed(m, seq, 0, 10, 0));
    const run = leg.sql!;
    // The rows the statements below aim at are there to be changed.
    expect(await run('UPDATE mandates SET used = used WHERE mandate_id = ?', [m.mandateId])).toBe(1);
    expect(await refusal(run("UPDATE mandates SET document_bytes = '{}' WHERE mandate_id = ?", [m.mandateId]))).toMatch(/only state and used change/);
    expect(await refusal(run('UPDATE mandates SET used = used + 2 WHERE mandate_id = ?', [m.mandateId]))).toMatch(/used changes only by \+1/);
    expect(await refusal(run('UPDATE mandates SET used = 0 WHERE mandate_id = ?', [m.mandateId]))).toMatch(/used changes only by \+1/);
    expect(await refusal(run('DELETE FROM mandates WHERE mandate_id = ?', [m.mandateId]))).toMatch(/never deleted/);
    expect(await refusal(run('UPDATE mandate_totals SET total = 0 WHERE mandate_id = ?', [m.mandateId]))).toMatch(/only upward/);
    expect(await refusal(run('UPDATE mandate_totals SET max = 5000 WHERE mandate_id = ?', [m.mandateId]))).toMatch(/only total changes/);
    expect(await refusal(run('UPDATE mandate_totals SET total = 1001 WHERE mandate_id = ?', [m.mandateId]))).toMatch(/CHECK|check/);
    expect(await refusal(run('DELETE FROM mandate_totals WHERE mandate_id = ?', [m.mandateId]))).toMatch(/never deleted/);
    expect(await refusal(run("UPDATE mandate_events SET canonical = '{}' WHERE mandate_id = ?", [m.mandateId]))).toMatch(/insert-only/);
    expect(await refusal(run('DELETE FROM mandate_events WHERE mandate_id = ?', [m.mandateId]))).toMatch(/insert-only/);
    expect(await run("UPDATE mandates SET state = 'revoked' WHERE mandate_id = ?", [m.mandateId])).toBe(1);
    expect(await refusal(run("UPDATE mandates SET state = 'open' WHERE mandate_id = ?", [m.mandateId]))).toMatch(/state moves only from open/);
    expect(await refusal(run('UPDATE mandates SET used = used + 1 WHERE mandate_id = ?', [m.mandateId]))).toMatch(/used changes only by \+1/);
    if (leg.name === 'postgres') {
      expect(await refusal(run('TRUNCATE mandate_events'))).toMatch(/insert-only/);
      expect(await refusal(run('TRUNCATE mandates'))).toMatch(/insert-only/);
    }
    expect(await adapter.getMandate!(m.mandateId)).toMatchObject({ state: 'revoked', used: 1 });
    expect(await adapter.getMandateTotals!(m.mandateId)).toEqual({ paid: 10 });
  });
});

describe('the mandate tables: errors', () => {
  it('the three errors carry their codes and names', () => {
    expect(new MandateStoreRefusalError('mandate_full', 'm', 'mandate', 'full')).toMatchObject({ name: 'MandateStoreRefusalError', code: 'mandate_full', field: 'mandate' });
    expect(new MandateStoreConflictError('mandate_claim_conflict', 'm', 'moved')).toMatchObject({ name: 'MandateStoreConflictError', code: 'mandate_claim_conflict' });
    expect(new MandateStoreInputError('bad')).toMatchObject({ name: 'MandateStoreInputError', code: 'mandate_store_input_invalid' });
  });
});
