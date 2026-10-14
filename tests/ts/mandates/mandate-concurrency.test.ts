/**
 * Two writers on one mandate, on the stores two
 * processes can share (SQLite, Postgres): a claim that lost its slot to
 * another writer is rebuilt at the next slot, and concurrent captures leave
 * the slots contiguous, every one held once, and the totals stepping by each
 * record's own value.
 */
import { checkMandateConsumption } from '@tzun/engine';
import type { EvidenceEnvelope } from '@tzun/engine';
import type { Tzun } from '../../../src/sdk';
import type { MandateCaptureClaim, SdkExtensionFactory } from '../../../src/sdk/extension-points';
import { mandatesExtension } from '../../../src/sdk/mandates';
import { backends, claim, enrol, issue, mandateDocument, person } from './fixtures';

/**
 * The mandate extension, with `race` run once: after the first plan of the
 * first capture under a mandate, before that capture stores.
 */
function racing(race: () => Promise<void>): SdkExtensionFactory {
  let raced = false;
  return (host) => {
    const ext = mandatesExtension(host);
    const { api, captureHook } = ext.mandates!;
    return {
      name: 'mandates',
      mandates: {
        api,
        captureHook: {
          async open(request, ctx) {
            const opened = await captureHook.open(request, ctx);
            if (!('plan' in opened)) return opened;
            const claim: MandateCaptureClaim = {
              async plan(payload) {
                const planned = await opened.plan(payload);
                if (!raced) {
                  raced = true;
                  await race();
                }
                return planned;
              },
              classifyStoreError: (error) => opened.classifyStoreError(error),
            };
            return claim;
          },
        },
      },
    };
  };
}

const shared = backends('mandate_concurrency').filter((b) => b.name !== 'memory');

describe.each(shared)('two writers on one mandate, $name', (backend) => {
  const open: Tzun[] = [];
  afterEach(async () => {
    while (open.length > 0) await open.pop()!.close();
  });

  it('a claim that lost its slot to another writer is rebuilt at the next slot', async () => {
    const principal = person('user-2c9d');
    const document = mandateDocument(principal.userId);
    let other!: Tzun;
    let otherResult: Awaited<ReturnType<Tzun['capture']>> | undefined;
    const a = await backend.fresh({
      chainId: 'claims-a',
      _sdkExtensions: [
        racing(async () => {
          otherResult = await other.capture(claim(300_000), { mandate: { mandateId: document.mandateId } });
        }),
      ],
    });
    open.push(a);
    other = await backend.again({ chainId: 'claims-b' });
    open.push(other);
    await enrol(a, principal);
    await issue(a, document, principal);

    const mine = await a.capture(claim(200_000), { mandate: { mandateId: document.mandateId } });
    expect(otherResult?.mandate).toEqual({ mandateId: document.mandateId, slot: 1, totals: { paid: 300_000 } });
    expect(mine.failure).toBeUndefined();
    expect(mine.mandate).toEqual({ mandateId: document.mandateId, slot: 2, totals: { paid: 500_000 } });
    expect(mine.envelope.payload.signoffExpectation).toMatchObject({ mandateSeq: 2, totals: { paid: 500_000 } });
    expect(await a.mandates.get(document.mandateId)).toMatchObject({ used: 2 });

    const records = [otherResult!.envelope, mine.envelope];
    const consumption = checkMandateConsumption(document, records);
    expect(consumption).toMatchObject({ duplicateSlots: [], gaps: [], unexplainedSteps: [], malformed: [], completeUpTo: 2 });
  });

  it('two writers issuing one mandate on two chains: one issues, the other is refused', async () => {
    const principal = person('user-2c9d');
    const document = mandateDocument(principal.userId);
    const a = await backend.fresh({ chainId: 'issuer-a' });
    open.push(a);
    const b = await backend.again({ chainId: 'issuer-b' });
    open.push(b);
    await enrol(a, principal);
    const outcomes = await Promise.allSettled([issue(a, document, principal), issue(b, document, principal)]);
    const issued = outcomes.filter((o) => o.status === 'fulfilled');
    const refused = outcomes.filter((o): o is PromiseRejectedResult => o.status === 'rejected');
    expect(issued).toHaveLength(1);
    expect(refused).toHaveLength(1);
    expect(refused[0].reason).toMatchObject({ name: 'MandateError', code: 'mandate_already_issued' });
    expect((await a.mandates.events(document.mandateId)).map((e) => e.body.event)).toEqual(['issued']);
  });

  it('concurrent captures from two writers on one chain take contiguous slots, each once', async () => {
    const principal = person('user-2c9d');
    const document = mandateDocument(principal.userId, {
      limits: { maxRecords: 12, cumulative: { paid: { path: '/aiOutput/amountMinor', max: 1_000_000 } } },
    });
    const a = await backend.fresh({ chainConflictMaxAttempts: 40 });
    open.push(a);
    const b = await backend.again({ chainConflictMaxAttempts: 40 });
    open.push(b);
    await enrol(a, principal);
    await issue(a, document, principal);
    // A fresh instance reads the head once, at init: resync b by one capture of its own first.
    await b.capture(claim(1, { kind: 'agent' }));

    const amounts = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    const results = await Promise.all(
      amounts.map((amount, i) => (i % 2 === 0 ? a : b).capture(claim(amount), { mandate: { mandateId: document.mandateId } })),
    );
    for (const r of results) expect(r.failure).toBeUndefined();
    const slots = results.map((r) => r.mandate!.slot).sort((x, y) => x - y);
    expect(slots).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(await a.mandates.get(document.mandateId)).toMatchObject({ used: 10 });
    expect(await a.getStorage().getMandateTotals!(document.mandateId)).toEqual({ paid: 550 });
    const envelopes: EvidenceEnvelope[] = results.map((r) => r.envelope);
    expect(checkMandateConsumption(document, envelopes)).toMatchObject({
      duplicateSlots: [],
      gaps: [],
      unexplainedSteps: [],
      malformed: [],
      completeUpTo: 10,
    });
  }, 60_000);
});
