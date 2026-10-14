/**
 * Mandates as the SDK installs them by default: the
 * registered extensions, `tzun.mandates.list` over the adapters'
 * `listMandates`, the scheduled expiry pass, and a revocation stored while a
 * claim on another chain of the store lands between its read and its write.
 */
import type { CaptureResult, MandateRow, StorageAdapter } from '@tzun/engine';
import type { Tzun } from '../../../src/sdk';
import { expireEndedMandates, type MandateListingStore } from '../../../src/sdk/mandates';
import { CLAIMS_AGENT_DESCRIPTOR, HOUR, assert, backends, claim, enrol, issue, mandateDocument, person } from './fixtures';

/** The default install: no extension list of the test's own. */
const DEFAULTS = { _sdkExtensions: undefined, _storageExtensions: undefined };

const ended = (principal: string) =>
  mandateDocument(principal, { validity: { notBefore: new Date(Date.now() - 3 * HOUR).toISOString(), notAfter: new Date(Date.now() - HOUR).toISOString() } });

/** The adapter's own mandate methods, as the scheduled pass reads them. */
function listingStore(storage: StorageAdapter): MandateListingStore {
  return {
    getMandate: (key) => storage.getMandate!(key),
    getMandateTotals: (id) => storage.getMandateTotals!(id),
    listMandateEvents: (id) => storage.listMandateEvents!(id),
    expireMandate: (expiry) => storage.expireMandate!(expiry),
    listMandates: (filter) => storage.listMandates!(filter),
  };
}

describe.each(backends('mandate_wiring'))('mandates installed by default, $name', (backend) => {
  let tzun: Tzun;
  const principal = person('user-2c9d');
  beforeEach(async () => {
    tzun = await backend.fresh(DEFAULTS);
    await enrol(tzun, principal);
    await tzun.agents.register(CLAIMS_AGENT_DESCRIPTOR);
  });
  afterEach(async () => {
    await tzun.close();
  });

  it('lists mandates a page at a time; a listed mandate whose window ended is reported expired', async () => {
    const live = mandateDocument(principal.userId);
    const later = mandateDocument(principal.userId);
    const old = ended(principal.userId);
    for (const d of [live, later, old]) await issue(tzun, d, principal);
    const ids = [live, later, old].map((d) => d.mandateId).sort();

    const all = await tzun.mandates.list();
    expect(all.rows.map((r) => r.mandateId)).toEqual(ids);
    expect(all.cursor).toBeNull();
    expect(all.rows.find((r) => r.mandateId === old.mandateId)).toMatchObject({ state: 'expired' });
    expect((await tzun.mandates.events(old.mandateId)).map((e) => e.body.event)).toEqual(['issued', 'expired']);

    expect((await tzun.mandates.list({ state: 'open' })).rows.map((r) => r.mandateId)).toEqual([live, later].map((d) => d.mandateId).sort());
    expect((await tzun.mandates.list({ state: 'expired' })).rows.map((r) => r.mandateId)).toEqual([old.mandateId]);

    const first = await tzun.mandates.list({ limit: 2 });
    expect(first.rows).toHaveLength(2);
    const second = await tzun.mandates.list({ limit: 2, cursor: first.cursor });
    expect([...first.rows, ...second.rows].map((r) => r.mandateId)).toEqual(ids);
    expect(second.cursor).toBeNull();

    await expect(tzun.mandates.list({ limit: 0 })).rejects.toMatchObject({ name: 'MandateError', code: 'invalid_pagination', field: 'limit' });
  });

  it("a successor's issuance record links its predecessor's (supersedes) and, with the link service installed, the root of that lineage", async () => {
    const first = mandateDocument(principal.userId);
    const issuedFirst = await issue(tzun, first, principal);
    const second = mandateDocument(principal.userId, { predecessor: issuedFirst.mandateDigest });
    const issuedSecond = await issue(tzun, second, principal);
    const predecessor = issuedFirst.issuance.envelope;
    const links = issuedSecond.issuance.envelope.payload.links ?? [];
    expect(links.map((l) => [l.rel, l.target.digest, l.target.evidenceId])).toEqual([
      ['root', predecessor.integrity.canonicalDigest, predecessor.payload.evidenceId],
      ['supersedes', predecessor.integrity.canonicalDigest, predecessor.payload.evidenceId],
    ]);
    expect((await tzun.verify(issuedSecond.issuance.envelope.payload.evidenceId)).links).toMatchObject({ outcome: 'checked-correct' });
  });

  it('the scheduled pass moves every open mandate past its window to expired, with its event, once', async () => {
    const old = ended(principal.userId);
    const issued = await issue(tzun, old, principal);
    const live = mandateDocument(principal.userId);
    await issue(tzun, live, principal);
    const storage = tzun.getStorage();
    expect(await storage.getMandate!(old.mandateId)).toMatchObject({ state: 'open' });

    const pass = await expireEndedMandates(listingStore(storage), new Date().toISOString(), 1);
    expect(pass).toEqual({ expired: [old.mandateId], failed: [] });
    expect(await storage.getMandate!(old.mandateId)).toMatchObject({ state: 'expired', used: 0 });
    expect(await storage.getMandate!(live.mandateId)).toMatchObject({ state: 'open' });
    const events = await storage.listMandateEvents!(old.mandateId);
    expect(events.map((e) => e.body)).toContainEqual({
      v: 'tzun-mandate-event/1',
      event: 'expired',
      mandateDigest: issued.mandateDigest,
      record: issued.issuance.envelope.integrity.canonicalDigest,
      successor: null,
      used: 0,
      totals: { paid: 0 },
    });
    expect(await expireEndedMandates(listingStore(storage), new Date().toISOString())).toEqual({ expired: [], failed: [] });
  });
});

const shared = backends('mandate_wiring_shared').filter((b) => b.name !== 'memory');

describe.each(shared)('a revocation beside a claim on another chain, $name', (backend) => {
  const open: Tzun[] = [];
  afterEach(async () => {
    while (open.length > 0) await open.pop()!.close();
  });

  it('a claim on another chain that lands between the revocation read and its write does not stop it', async () => {
    const principal = person('user-2c9d');
    const a = await backend.fresh({ ...DEFAULTS, chainId: 'chain-a' });
    open.push(a);
    const b = await backend.again({ ...DEFAULTS, chainId: 'chain-b' });
    open.push(b);
    await enrol(a, principal);
    await a.agents.register(CLAIMS_AGENT_DESCRIPTOR);
    const document = mandateDocument(principal.userId);
    await issue(a, document, principal);
    const prepared = await a.mandates.prepareRevocation({ mandateId: document.mandateId, reason: 'stop', revoker: principal.userId });

    // revoke() reads the mandate to check it is open (read 1), then the
    // revocation record's store options read it again (read 2): a claim on
    // chain-b commits right after read 2, before the revocation is stored.
    // The reads go through the storage the SDK's extensions are given.
    const storage = (a as unknown as { storage: { getMandate(key: string): Promise<MandateRow | null> } }).storage;
    const read = storage.getMandate.bind(storage);
    let reads = 0;
    let injected: CaptureResult | undefined;
    Object.defineProperty(storage, 'getMandate', {
      configurable: true,
      writable: true,
      value: async (key: string) => {
        const row = await read(key);
        reads += 1;
        if (reads === 2) injected = await b.capture(claim(5), { mandate: { mandateId: document.mandateId } });
        return row;
      },
    });

    const revoked = await a.mandates.revoke({ mandateId: document.mandateId, reason: 'stop' }, { prepared, assertion: assert(principal, prepared.challenge) });
    expect(injected?.mandate?.slot).toBe(1);
    expect(revoked.envelope.integrity.canonicalDigest).toBe(prepared.digest);
    expect(await read(document.mandateId)).toMatchObject({ state: 'revoked', used: 1 });
    const events = (await a.mandates.events(document.mandateId)).map((e) => e.body);
    expect(events.map((e) => e.event)).toEqual(['issued', 'revoked']);
    expect(events[1]).toMatchObject({ record: prepared.digest, used: 1, totals: { paid: 5 } });
  });
});
