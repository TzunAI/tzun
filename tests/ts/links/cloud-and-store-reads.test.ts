/**
 * The link service on stores that cannot do everything: on the cloud
 * transport capture resolves a target through the platform's evidence read
 * (scoped to the API key's tenant), refuses a target named by digest alone,
 * takes a supplied locator's origin as given, and `to` and the walk throw
 * `links_not_supported_by_store`; a held record that does not recompute to
 * its stored digest is never linked unless the caller named it external by
 * its stored digest; a list over the link limit reads nothing.
 */
import type { EvidenceEnvelope, HeldLinkTarget } from '@tzun/engine';
import { Tzun } from '../../../src/sdk';
import { LinksNotSupportedError, linksSdkExtension, resolveLinkTargets, type LinksService, type LinkStoreReads } from '../../../src/sdk/links';
import type { DecisionGraphService } from '../../../src/sdk/decision-graph';
import type { CaptureRefusal } from '../../../src/sdk/extension-points';
import { hex, captured, decision, refusalOf, openLinked } from './fixtures';

/**
 * A platform that keeps what it is sent and answers the evidence read for
 * the ids it holds. The request URL is parsed as `fetch` parses it, so a path
 * segment of `.` or `..` is resolved away: `…/evidence/.` reaches the list
 * route, which answers a page.
 */
function fakePlatform(): typeof fetch {
  const held = new Map<string, EvidenceEnvelope>();
  return (async (url: string, init: { method?: string; body?: string }) => {
    if ((init.method ?? 'GET') === 'GET') {
      const path = new URL(String(url)).pathname;
      if (/\/evidence\/?$/.test(path)) {
        return { ok: true, status: 200, headers: new Headers(), json: async () => ({ items: [] }) } as unknown as Response;
      }
      const id = decodeURIComponent(path.split('/').pop() ?? '');
      const envelope = held.get(id);
      return {
        ok: envelope !== undefined,
        status: envelope !== undefined ? 200 : 404,
        headers: new Headers(),
        async json() {
          return envelope !== undefined ? { envelope, verdict: { status: 'verified' } } : { error: 'not_found' };
        },
      } as unknown as Response;
    }
    const body = JSON.parse(String(init.body)) as { chainId?: string; envelope: EvidenceEnvelope };
    held.set(body.envelope.payload.evidenceId, body.envelope);
    return {
      ok: true,
      status: 202,
      headers: new Headers(),
      async json() {
        return {
          ok: true,
          state: 'captured',
          evidenceId: body.envelope.payload.evidenceId,
          chainId: body.chainId ?? 'default',
          sequence: body.envelope.payload.sequenceNumber,
          canonicalDigest: body.envelope.integrity.canonicalDigest,
          headDigest: body.envelope.integrity.canonicalDigest,
        };
      },
    } as unknown as Response;
  }) as unknown as typeof fetch;
}

describe('the link service on the cloud transport', () => {
  let tzun: Tzun;
  beforeEach(async () => {
    tzun = await Tzun.init({
      mode: 'dev',
      apiKey: 'tzk_test_links',
      apiUrl: 'https://example.test',
      attestation: { require: [] },
      _httpFetchFn: fakePlatform(),
      _sdkExtensions: [linksSdkExtension],
    } as Parameters<typeof Tzun.init>[0]);
  });
  afterEach(async () => {
    await tzun.close();
  });

  it('resolves a target by evidence id through the evidence read, with no locator to fill', async () => {
    const parent = await captured(tzun, decision('cloud parent'));
    const child = await captured(tzun, { ...decision('cloud child'), links: [{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId } }] });
    const target = { digest: parent.integrity.canonicalDigest, evidenceId: parent.payload.evidenceId, locator: null };
    expect(child.payload.links).toEqual([
      { rel: 'derivedFrom', target, attrs: null },
      { rel: 'root', target, attrs: null },
    ]);
    // An id the tenant does not hold is not found, as an id that exists nowhere.
    expect(refusalOf(await tzun.capture({ ...decision('x'), links: [{ rel: 'derivedFrom', target: { evidenceId: 'other-tenant-id' } }] }))).toMatchObject({
      code: 'link_target_not_found',
    });
  });

  it('refuses a same-store target named by digest alone: the store cannot look a digest up', async () => {
    expect(refusalOf(await tzun.capture({ ...decision('x'), links: [{ rel: 'derivedFrom', target: { digest: hex('somewhere') } }] }))).toMatchObject({
      code: 'links_not_supported_by_store',
      field: 'links[0].target',
    });
    // External is written as given.
    const ext = await captured(tzun, { ...decision('y'), links: [{ rel: 'derivedFrom', target: { digest: hex('somewhere'), external: true } }] });
    expect(ext.payload.links![0].target).toEqual({ digest: hex('somewhere'), evidenceId: null, locator: null });
  });

  it("writes a supplied locator of a same-tenant target when its seq is the record's, and refuses another seq", async () => {
    const parent = await captured(tzun, decision('cloud parent'));
    const locator = { origin: 'log.tzun.ai/dep-1/log-1', seq: parent.payload.sequenceNumber };
    const target = { digest: parent.integrity.canonicalDigest, evidenceId: parent.payload.evidenceId, locator };
    const child = await captured(tzun, { ...decision('cloud child'), links: [{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId, locator } }] });
    expect(child.payload.links![0]).toEqual({ rel: 'derivedFrom', target, attrs: null });
    // Every member given, marked external: a same-tenant target all the same.
    const ext = await captured(tzun, { ...decision('cloud ext'), links: [{ rel: 'appeals', target: { ...target, external: true } }] });
    expect(ext.payload.links![0]).toEqual({ rel: 'appeals', target, attrs: null });
    // A seq that is not the record's is refused.
    expect(
      refusalOf(
        await tzun.capture({ ...decision('wrong seq'), links: [{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId, locator: { ...locator, seq: locator.seq + 1 } } }] }),
      ),
    ).toMatchObject({ code: 'link_target_mismatch', field: 'links[0].target.locator' });
  });

  it('answers the evidence ids . and .. as ids the tenant does not hold', async () => {
    for (const evidenceId of ['.', '..']) {
      expect(refusalOf(await tzun.capture({ ...decision('dots'), links: [{ rel: 'derivedFrom', target: { evidenceId } }] }))).toMatchObject({
        code: 'link_target_not_found',
        field: 'links[0].target',
      });
    }
  });

  it('to and the walk need the link index; of reads the record through the evidence read', async () => {
    const parent = await captured(tzun, decision('cloud parent'));
    const child = await captured(tzun, { ...decision('cloud child'), links: [{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId } }] });
    const links = tzun.links as LinksService;
    await expect(links.to(parent.integrity.canonicalDigest)).rejects.toBeInstanceOf(LinksNotSupportedError);
    await expect(links.to(parent.integrity.canonicalDigest)).rejects.toMatchObject({ code: 'links_not_supported_by_store' });
    await expect((tzun.decisionGraph as DecisionGraphService).walk(child.payload.evidenceId)).rejects.toMatchObject({ code: 'links_not_supported_by_store' });
    const of = await links.of(child.payload.evidenceId);
    expect(of!.map((l) => [l.link.rel, l.held, l.check.outcome, l.check.reason])).toEqual([
      ['derivedFrom', false, 'checked-correct', undefined],
      ['root', false, 'checked-correct', undefined],
    ]);
  });
});

describe('resolveLinkTargets over a store that holds a tampered record', () => {
  it('refuses to link a held record whose payload does not recompute to its stored digest', async () => {
    const s = await openLinked({});
    let parent: EvidenceEnvelope;
    try {
      parent = await captured(s.tzun, decision('original'));
    } finally {
      await s.close();
    }
    const tampered: EvidenceEnvelope = { ...parent, payload: { ...parent.payload, reason: 'rewritten after capture' } };
    const reads: LinkStoreReads = {
      byId: async (id) => (id === tampered.payload.evidenceId ? tampered : null),
      byDigest: async (digest) => (digest === tampered.integrity.canonicalDigest ? tampered : null),
      linksTo: null,
      originOf: async () => null,
      confirmsOrigin: true,
      ownOriginPrefix: async () => null,
      atLocator: async () => ({ own: false, envelope: null }),
    };
    const stored = parent.integrity.canonicalDigest;
    for (const target of [
      { evidenceId: parent.payload.evidenceId },
      { digest: stored },
      { evidenceId: parent.payload.evidenceId, digest: stored },
      { evidenceId: parent.payload.evidenceId, digest: hex('another record'), external: true },
    ]) {
      const out = (await resolveLinkTargets(reads, [{ rel: 'derivedFrom', target }])) as CaptureRefusal;
      expect(out).toMatchObject({ failureType: 'validation_failure', code: 'link_target_mismatch', field: 'links[0].target.digest' });
      expect(out.message).not.toContain('rewritten');
    }
    // Named external by its stored digest: left unresolved, so it is written as given.
    for (const target of [
      { digest: stored, external: true },
      { digest: stored, evidenceId: parent.payload.evidenceId, external: true },
    ]) {
      expect(await resolveLinkTargets(reads, [{ rel: 'revokes', target }])).toEqual([null]);
    }
    // The untampered record resolves.
    const intact: LinkStoreReads = { ...reads, byId: async () => parent };
    const held = (await resolveLinkTargets(intact, [{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId } }])) as Array<HeldLinkTarget | null>;
    expect(held[0]).toMatchObject({ digest: parent.integrity.canonicalDigest, origin: null });
  });

  it('leaves a malformed input to buildLinks, which refuses it by its shape', async () => {
    const reads: LinkStoreReads = {
      byId: async () => null,
      byDigest: async () => null,
      linksTo: null,
      originOf: async () => null,
      confirmsOrigin: true,
      ownOriginPrefix: async () => null,
      atLocator: async () => ({ own: false, envelope: null }),
    };
    expect(await resolveLinkTargets(reads, [null as never, { rel: 'derivedFrom', target: 'x' as never }])).toEqual([null, null]);
  });
});

describe('resolveLinkTargets reads nothing for a list buildLinks refuses by its length', () => {
  it('refuses 257 inputs too_many_links before the first read; reads 256', async () => {
    let reads = 0;
    const counted: LinkStoreReads = {
      byId: async () => {
        reads++;
        return null;
      },
      byDigest: async () => {
        reads++;
        return null;
      },
      linksTo: null,
      originOf: async () => null,
      confirmsOrigin: true,
      ownOriginPrefix: async () => null,
      atLocator: async () => {
        reads++;
        return { own: false, envelope: null };
      },
    };
    const input = (i: number) => ({ rel: 'derivedFrom', target: { evidenceId: `id-${i}`, digest: hex(String(i)), external: true } });
    const refused = (await resolveLinkTargets(counted, Array.from({ length: 257 }, (_, i) => input(i)))) as CaptureRefusal;
    expect(refused).toMatchObject({ failureType: 'validation_failure', code: 'too_many_links', field: 'links' });
    expect(reads).toBe(0);
    expect(await resolveLinkTargets(counted, [])).toEqual([]);
    expect(await resolveLinkTargets(counted, 'not a list' as never)).toEqual([]);
    expect(reads).toBe(0);
    expect(await resolveLinkTargets(counted, Array.from({ length: 256 }, (_, i) => input(i)))).toHaveLength(256);
    expect(reads).toBe(512);
  });
});
