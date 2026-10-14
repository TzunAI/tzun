/**
 * One implementation of the origin grammar (tzun-anchor/1 §4.3).
 *
 * `src/attestation/checkpoint.ts` implements the grammar: the chain-id rule,
 * the chain segment, the three origin forms a domain writes, and the reader
 * (`parseOrigin`, `checkOriginBinding`). `src/storage/log-store.ts` keeps its
 * store-shaped signatures (`evidenceLogOrigin(ns, storeId, chainId)`,
 * `storeLogOrigin(ns, storeId, kind)`) as wrappers that build the store's
 * domain prefix and delegate.
 *
 * This file holds the wrappers to the functions they replaced, whose bodies
 * are copied below as the oracle, on the same inputs: every result and every
 * refusal (the error class and its message) is the same. It also holds every
 * origin a store mints, in TypeScript and in the SQL the triggers run on
 * memory, SQLite and Postgres, to the reader: each parses, and each source
 * log binds to its store's anchor origin (an evidence log with its chain
 * checked).
 */
import { createHash, randomBytes } from 'node:crypto';
import type { EvidenceEnvelope } from '@tzun/engine';
import * as checkpoint from '../../src/attestation/checkpoint';
import * as logStore from '../../src/storage/log-store';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { logBackends } from './helpers/log-store-backends';

// ── The oracle: the storage origin functions as they were before they delegated ──

const ORACLE_LOG_KIND = /^[a-z][a-z0-9]*$/;
const ORACLE_STORE_ID = /^[0-9a-f]{32}$/;
const ORACLE_LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

const oracle = {
  chainIdRefusal(chainId: unknown): 'empty_chain_id' | 'invalid_chain_id' | null {
    if (typeof chainId !== 'string') return 'invalid_chain_id';
    if (chainId === '') return 'empty_chain_id';
    if (ORACLE_LONE_SURROGATE.test(chainId) || chainId.includes('\u0000')) return 'invalid_chain_id';
    return null;
  },
  chainSegment(chainId: string): string {
    const refusal = oracle.chainIdRefusal(chainId);
    if (refusal === 'empty_chain_id') throw new TypeError('an evidence log needs a non-empty chain id');
    if (refusal !== null) {
      throw new TypeError(
        'a chain id is a string of Unicode scalar values other than U+0000; this one is not a string, or holds a lone UTF-16 surrogate or U+0000',
      );
    }
    return Buffer.from(chainId, 'utf8').toString('hex');
  },
  assertStoreId(storeId: string): string {
    if (!ORACLE_STORE_ID.test(storeId)) {
      throw new TypeError(`store id ${JSON.stringify(storeId)} is not 32 lowercase hex characters`);
    }
    return storeId;
  },
  domainPrefix(ns: string, storeId: string): string {
    return `${logStore.assertLogNamespace(ns)}/${oracle.assertStoreId(storeId)}`;
  },
  evidenceLogOrigin(ns: string, storeId: string, chainId: string): string {
    return `${oracle.domainPrefix(ns, storeId)}/evidence/${oracle.chainSegment(chainId)}`;
  },
  storeLogOrigin(ns: string, storeId: string, kind: string): string {
    if (!ORACLE_LOG_KIND.test(kind) || kind === 'evidence') {
      throw new TypeError(`log kind ${JSON.stringify(kind)} is not a per-store kind (lowercase letters and digits, not "evidence")`);
    }
    return `${oracle.domainPrefix(ns, storeId)}/${kind}`;
  },
  isTestNamespace(ns: string): boolean {
    return ns.startsWith('test.');
  },
};

// ── Inputs ────────────────────────────────────────────────────────────────

/** mulberry32: a seeded generator, so a failure reproduces from its seed. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SEED = 0x7a756e; // "zun"
const RUNS = 4000;

/** Code units a chain id is built from: the ones each rule treats specially, and ordinary ones. */
const CHAIN_UNITS = [
  'a', 'z', 'A', '0', '-', '_', '.', '/', '+', ' ', '\t', '\n', '%',
  '\u0000', '\u0001', '\u007f', '\u0080', '\u00e9', '\u00ff', '\u0301', '\u65e5', '\ufeff', '\uffff', '\ufffd',
  '\ud7ff', '\ue000', '\ud800', '\udbff', '\udc00', '\udfff', '\ud83d\udd12', '\ud83d\ude00',
];
const KIND_UNITS = ['a', 'k', 'z', '0', '2', '9', 'A', '-', '.', '/', ' ', '+', '\u00e9', '\u0000'];
const KINDS = ['anchors', 'evidence', 'custody', 'revisions', 'policy', 'k2', 'K2', '2k', '', 'a-b', 'a b', 'anchors2', 'evidences'];

function pick<T>(next: () => number, from: readonly T[]): T {
  return from[Math.floor(next() * from.length)];
}

function stringOf(next: () => number, units: readonly string[], maxLength: number): string {
  let s = '';
  const length = Math.floor(next() * (maxLength + 1));
  for (let i = 0; i < length; i++) s += pick(next, units);
  return s;
}

const VALID_NS = ['local.invalid', 'test.tzun.ai', 'localhost', 'x-1.b2-c.io', 'demo.tzun.ai', 'a'];
const INVALID_NS = ['', 'Local.invalid', 'a..b', '.a', 'a.', '-a', 'a-', 'a/b', 'a b', 'a+b', '\u00e9', 'x'.repeat(64), 'a'.repeat(254)];

function storeIdOf(next: () => number): string {
  const r = next();
  const hex = randomHexFrom(next, 32);
  if (r < 0.8) return hex;
  if (r < 0.85) return hex.toUpperCase();
  if (r < 0.9) return hex.slice(1);
  if (r < 0.95) return `${hex}0`;
  return `${hex.slice(0, 31)}g`;
}

function randomHexFrom(next: () => number, length: number): string {
  let s = '';
  for (let i = 0; i < length; i++) s += '0123456789abcdef'[Math.floor(next() * 16)];
  return s;
}

type Outcome = { value: unknown } | { threw: string; message: string };

function outcome(work: () => unknown): Outcome {
  try {
    return { value: work() };
  } catch (err) {
    return { threw: (err as Error).constructor.name, message: (err as Error).message };
  }
}

// ── The wrappers equal the functions they replaced ─────────────────────────

describe('the storage origin functions delegate to the one grammar and behave as before', () => {
  it('chainIdRefusal and chainSegment are the checkpoint module\'s own functions', () => {
    expect(logStore.chainIdRefusal).toBe(checkpoint.chainIdRefusal);
    expect(logStore.chainSegment).toBe(checkpoint.chainSegment);
    expect(logStore.isTestNamespace).toBe(checkpoint.isTestNamespace);
    expect(logStore.EVIDENCE_LOG_KIND).toBe(checkpoint.EVIDENCE_LOG_KIND);
    expect(logStore.ANCHOR_LOG_KIND).toBe(checkpoint.ANCHOR_LOG_KIND);
  });

  it(`gives the same result or the same refusal on ${RUNS} generated inputs (seed ${SEED})`, () => {
    const next = rng(SEED);
    const mismatches: string[] = [];
    const compare = (label: string, a: () => unknown, b: () => unknown) => {
      const [got, want] = [outcome(a), outcome(b)];
      if (JSON.stringify(got) !== JSON.stringify(want)) {
        mismatches.push(`${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
      }
    };
    for (let i = 0; i < RUNS; i++) {
      const chainId = stringOf(next, CHAIN_UNITS, 10);
      const ns = next() < 0.85 ? pick(next, VALID_NS) : pick(next, INVALID_NS);
      const storeId = storeIdOf(next);
      const kind = next() < 0.5 ? pick(next, KINDS) : stringOf(next, KIND_UNITS, 6);
      const at = `#${i} ${JSON.stringify({ chainId, ns, storeId, kind })}`;

      compare(`chainIdRefusal ${at}`, () => logStore.chainIdRefusal(chainId), () => oracle.chainIdRefusal(chainId));
      compare(`chainSegment ${at}`, () => logStore.chainSegment(chainId), () => oracle.chainSegment(chainId));
      compare(`domainPrefix ${at}`, () => logStore.domainPrefix(ns, storeId), () => oracle.domainPrefix(ns, storeId));
      compare(
        `evidenceLogOrigin ${at}`,
        () => logStore.evidenceLogOrigin(ns, storeId, chainId),
        () => oracle.evidenceLogOrigin(ns, storeId, chainId),
      );
      compare(`storeLogOrigin ${at}`, () => logStore.storeLogOrigin(ns, storeId, kind), () => oracle.storeLogOrigin(ns, storeId, kind));
      compare(`isTestNamespace ${at}`, () => logStore.isTestNamespace(ns), () => oracle.isTestNamespace(ns));
    }
    expect(mismatches.slice(0, 10)).toEqual([]);
  });

  it('refuses values that are not chain ids the same way', () => {
    for (const bad of [undefined, null, 7, {}, [], true] as unknown[]) {
      expect(outcome(() => logStore.chainSegment(bad as string))).toEqual(outcome(() => oracle.chainSegment(bad as string)));
      expect(logStore.chainIdRefusal(bad)).toBe(oracle.chainIdRefusal(bad));
    }
  });

  it('refuses in the same order when more than one input is wrong', () => {
    // The namespace is checked before the store id, and both before the chain id;
    // a per-store kind is checked before either.
    const cases: Array<[string, string, string]> = [
      ['a b', 'NOT-HEX', '\ud800'],
      ['local.invalid', 'NOT-HEX', ''],
      ['', '0'.repeat(32), '\u0000'],
    ];
    for (const [ns, storeId, chainId] of cases) {
      expect(outcome(() => logStore.evidenceLogOrigin(ns, storeId, chainId))).toEqual(
        outcome(() => oracle.evidenceLogOrigin(ns, storeId, chainId)),
      );
      expect(outcome(() => logStore.storeLogOrigin(ns, storeId, 'Bad'))).toEqual(outcome(() => oracle.storeLogOrigin(ns, storeId, 'Bad')));
      expect(outcome(() => logStore.storeLogOrigin(ns, storeId, 'custody'))).toEqual(
        outcome(() => oracle.storeLogOrigin(ns, storeId, 'custody')),
      );
    }
  });
});

// ── Every origin the storage mints reads back through the grammar ─────────

/** Chain ids a store accepts, generated from the same code units. */
function acceptedChainIds(seed: number, count: number): string[] {
  const next = rng(seed);
  const out = new Set<string>(['default', 'caf\u00e9', 'cafe\u0301', '\ufeffbom', '\ud83d\ude00', 'a b+c/d', 'Tenant-ACME']);
  while (out.size < count) {
    const chainId = stringOf(next, CHAIN_UNITS, 8);
    if (checkpoint.chainIdRefusal(chainId) === null) out.add(chainId);
  }
  return [...out];
}

function expectReadsBack(origin: string, anchorOrigin: string, chainId: string | null): void {
  const parsed = checkpoint.parseOrigin(origin);
  if (chainId === null) {
    expect(parsed).not.toBeNull();
    expect(parsed!.kind).not.toBe('evidence');
    expect(checkpoint.checkOriginBinding(anchorOrigin, origin)).toMatchObject({ ok: true, chainChecked: false });
    return;
  }
  expect(parsed).toMatchObject({ kind: 'evidence', chainId });
  expect(checkpoint.checkOriginBinding(anchorOrigin, origin, chainId)).toMatchObject({ ok: true, chainChecked: true });
  expect(checkpoint.checkOriginBinding(anchorOrigin, origin, `${chainId}x`)).toEqual({ ok: false, reason: 'chain_id_mismatch' });
}

describe('every origin the storage functions write parses and binds', () => {
  it.each(VALID_NS)('under %s', (ns) => {
    const storeId = randomBytes(16).toString('hex');
    const anchorOrigin = logStore.storeLogOrigin(ns, storeId, 'anchors');
    expect(checkpoint.parseOrigin(anchorOrigin)).toEqual({ kind: 'anchors', domainPrefix: `${ns}/${storeId}`, namespace: ns });
    expect(anchorOrigin).toBe(checkpoint.anchorLogOrigin(logStore.domainPrefix(ns, storeId)));
    for (const chainId of acceptedChainIds(SEED + ns.length, 300)) {
      const origin = logStore.evidenceLogOrigin(ns, storeId, chainId);
      expect(origin).toBe(checkpoint.evidenceLogOrigin(logStore.domainPrefix(ns, storeId), chainId));
      expectReadsBack(origin, anchorOrigin, chainId);
    }
    for (const kind of ['custody', 'revisions', 'policy', 'k2', 'a0']) {
      const origin = logStore.storeLogOrigin(ns, storeId, kind);
      expect(checkpoint.parseOrigin(origin)).toMatchObject({ kind: 'log', name: kind });
      expectReadsBack(origin, anchorOrigin, null);
    }
  });
});

function envelopeOn(evidenceId: string, sequenceNumber: number): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      links: null,
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId,
      schemaVersion: 'v1.0',
      aiSystemId: 'origin-grammar',
      aiOutput: { ok: true },
      action: 'approved',
      reason: 'origin grammar',
      capturedAt: '2026-09-25T10:00:00.000Z',
      sequenceNumber,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: { canonicalDigest: createHash('sha256').update(evidenceId).digest('hex'), chainLink: null },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  };
}

const STORE_CHAIN_IDS = acceptedChainIds(SEED ^ 0x5eed, 40);

describe('every origin a store mints parses and binds: memory', () => {
  it('each evidence log, under the store identity', async () => {
    const adapter = new MemoryStorageAdapter({ logNamespace: 'test.tzun.dev' });
    for (const [i, chainId] of STORE_CHAIN_IDS.entries()) await adapter.store(envelopeOn(`mem-${i}`, 1), chainId);
    const logs = adapter.logStore();
    const { ns, storeId } = await logs.getStoreIdentity();
    const anchorOrigin = checkpoint.anchorLogOrigin(`${ns}/${storeId}`);
    const listed = await logs.listLogs();
    expect(listed.map((l) => l.chainId).sort()).toEqual([...STORE_CHAIN_IDS].sort());
    for (const log of listed) {
      expect(log.origin).toBe(logStore.evidenceLogOrigin(ns, storeId, log.chainId!));
      expectReadsBack(log.origin, anchorOrigin, log.chainId);
    }
  });
});

for (const backend of logBackends('origin_grammar')) {
  describe(`every origin a store mints parses and binds: ${backend.name}`, () => {
    beforeAll(() => backend.fresh());
    afterAll(() => backend.dispose());

    it('each evidence log the trigger names, and each per-store log', async () => {
      const store = await backend.open({ logNamespace: 'test.tzun.dev' });
      try {
        for (const [i, chainId] of STORE_CHAIN_IDS.entries()) await store.adapter.store(envelopeOn(`${backend.name}-${i}`, 1), chainId);
        const anchors = store.adapter.anchorStore();
        const anchorLog = await anchors.ensureStoreLog('anchors');
        await anchors.ensureStoreLog('custody');
        const logs = store.adapter.logStore();
        const { ns, storeId } = await logs.getStoreIdentity();
        expect(anchorLog.origin).toBe(checkpoint.anchorLogOrigin(`${ns}/${storeId}`));
        expect(checkpoint.parseOrigin(anchorLog.origin)).toMatchObject({ kind: 'anchors', namespace: ns });

        const listed = await logs.listLogs();
        expect(listed).toHaveLength(STORE_CHAIN_IDS.length + 2);
        for (const log of listed) {
          if (log.kind === 'anchors') continue;
          if (log.kind === 'evidence') {
            expect(log.origin).toBe(logStore.evidenceLogOrigin(ns, storeId, log.chainId!));
            expectReadsBack(log.origin, anchorLog.origin, log.chainId);
          } else {
            expect(log.origin).toBe(logStore.storeLogOrigin(ns, storeId, log.kind));
            expectReadsBack(log.origin, anchorLog.origin, null);
          }
        }
      } finally {
        await store.close();
      }
    });
  });
}
