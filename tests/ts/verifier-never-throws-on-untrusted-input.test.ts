/**
 * A verifier must never throw on untrusted input.
 *
 * THE HAZARD. `verifyEnvelope()` runs `verifyCustodyTrail()`, which hashes a
 * hashed custody entry's `actor` / `timestamp` / `systemId` through
 * `lengthPrefix()` -> `codePointLength()` -> `for (const _ of s)`. If any of
 * those is not a string and nothing checks its type, the engine throws
 * `TypeError: s is not iterable` — from inside the engine, out of
 * `verifyEnvelope`, and out of whatever called it. On a server, `{"actor": 123}`
 * in a `custodyChain` entry would turn an evidence intake's 202 into a 500, and
 * do the same to a batch dry-run, because a TypeError is not a typed rejection
 * and such routes map anything else to `internal`.
 *
 * It is a CLASS, not one field. Every verification entry point reachable with
 * client-supplied JSON receives types JSON never guarantees, and a verifier
 * that throws on malformed input is a denial of service on every server that
 * verifies what a client sent. This file is the table for the whole class:
 * every case asserts NO THROW and the right verdict.
 *
 * WITHOUT THE TYPE CHECKS, these inputs throw out of the verifier instead of
 * returning a verdict (quoted again per describe block below):
 *
 *   verifyCustodyTrail actor/timestamp/systemId/action = number|boolean|object
 *     TypeError: s is not iterable
 *   verifyCustodyTrail prevEntryHash = number
 *     TypeError: s is not iterable
 *   verifyCustodyTrail metadata = {lone surrogate} / 100-deep
 *     Error: Canonical serialization error: lone surrogate U+D800 in string. ...
 *     Error: Canonical serialization error: maximum nesting depth exceeded ...
 *   verifyEnvelope, payload/integrity/envelope absent
 *     TypeError: Cannot read properties of undefined (reading 'schemaVersion')
 *     TypeError: Cannot read properties of undefined (reading 'canonicalDigest')
 *     TypeError: Cannot read properties of null (reading 'payload')
 *   verifyEnvelope / verifyChainCompleteness, lone surrogate in aiOutput
 *     Error: Canonical serialization error: lone surrogate U+D800 in string. ...
 *   verifyAttestation, an anchor audit path absent / = 5 / = [7]
 *     TypeError: merklePath is not iterable
 *     TypeError: entry.indexOf is not a function
 *   verifyAttestation authenticatorData = 123
 *     TypeError [ERR_INVALID_ARG_TYPE]: The first argument must be of type string ...
 *   verifyAttestation artifacts = null
 *     TypeError: Cannot read properties of null (reading 'webauthnAssertion')
 *
 * The anchor (`nonRepudiation.anchor`, tzun-anchor/1 §8) is client JSON too:
 * both audit paths are bare 64-hex with no position label, the side of each
 * step is derived from the leaf indices and the sizes in the checkpoint
 * bodies, and `anchorSpec` / `merkleSpec` tag the rules. The tables below
 * break one member at a time: a non-integer or out-of-range index (the
 * phantom-leaf shape), a non-hex path element, and a legacy `"left:<hash>"`
 * element, which is REFUSED rather than parsed: re-read under the current
 * rule it would fold against the wrong tree and answer confidently wrong. The
 * tags are checked FIRST, so an unknown one reports `unsupported_*` with
 * `merkleProofValid: null` — "I cannot check this", never "invalid".
 *
 * ADAPTERS. The pure-function tables need no store. The two tests that matter
 * most — a MALFORMED ENTRY THAT WENT THROUGH A REAL STORE, and a chain walk
 * over one — run on SQLite (`SqliteStorageAdapter`, a real file), because that
 * is the round trip a server's verification makes: the entry is JSON on the
 * wire, JSON in the column, and JSON again on the way back out. `actor: 123`
 * survives that round trip unchanged, which is the whole point.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  assembleEnvelope,
  assertionBindingFailure,
  computeCustodyEntryHash,
  determineAttestationStatus,
  SchemaRegistry,
  verifyChainCompleteness,
  verifyCustodyTrail,
  verifyEnvelope,
  webauthnChallengeForDigest,
} from '@tzun/engine';
import type {
  AttestationArtifacts,
  EnvelopeInput,
  CustodyTrailFailureReason,
  CustodyTrailVerdict,
  EvidenceEnvelope,
  VerificationResult,
} from '@tzun/engine';
import { verifyAttestation } from '../../src/attestation/verify-attestation';
import { verifyMerkleProof } from '../../src/attestation/merkle';
import { anchoredRecord } from './helpers/anchor-fixtures';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
import { verifyExported } from './helpers/verify-exported';

const registry = new SchemaRegistry();
const CHAIN = 'chain-untrusted';
const HEX64 = 'a'.repeat(64);

/**
 * One known-good RFC 6962 proof, from the conformance vectors (Tree §9) rather
 * than hand-built, so this file cannot be its own witness.
 *
 * A malformed-input table needs a passing baseline sitting next to it or every
 * "returns false" row is ambiguous: false because the hostile field was caught,
 * or false because the baseline was broken all along and the row proved
 * nothing. Tree size 4 / leaf index 2 is the smallest vector whose audit path
 * takes a step on each side, so a verifier that mis-orders a concatenation
 * fails the control instead of passing the table.
 */
interface MerkleVectorTree {
  treeSize: number;
  root: string;
  proofs: Array<{ leafIndex: number; leafDigest: string; auditPath: string[] }>;
}
const TREE4: MerkleVectorTree = (
  JSON.parse(
    fs.readFileSync(
      path.join(__dirname, '..', '..', 'vectors', 'merkle-rfc6962-vectors.json'),
      'utf-8',
    ),
  ) as { trees: MerkleVectorTree[] }
).trees.find((t) => t.treeSize === 4)!;

const GOOD = {
  leaf: TREE4.proofs[2].leafDigest,
  leafIndex: TREE4.proofs[2].leafIndex,
  treeSize: TREE4.treeSize,
  path: TREE4.proofs[2].auditPath,
  root: TREE4.root,
};

const input: EnvelopeInput = {
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiSystemId: 'test-system',
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'Test',
};

/**
 * Wrong-typed values a JSON body can carry in a field the wire type declares as
 * a string. `undefined` stands for the key being absent altogether, which is
 * the shape a Python round trip or a hand-written client produces.
 */
const WRONG_FOR_STRING: Array<{ label: string; value: unknown }> = [
  { label: 'a number', value: 123 },
  { label: 'true', value: true },
  { label: 'false', value: false },
  { label: 'null', value: null },
  { label: 'an object', value: { nested: 'x' } },
  // An ARRAY is the nastiest of the set and the reason a typeof check beats a
  // try/catch: arrays ARE iterable, so `["a","b"]` throws nothing — unchecked,
  // it would length-prefix silently as `2:a,b` and the entry would come back
  // as an ordinary `entry_hash_mismatch`, as though the real value had been
  // hashed.
  { label: 'an array', value: ['a', 'b'] },
  { label: 'absent', value: undefined },
];

/**
 * ONE base envelope for the whole custody table. It has to be one: an entry
 * hash commits to the record's `evidenceId` and `canonicalDigest`, so hashing
 * against a freshly assembled envelope and attaching the result to a different
 * one produces a mismatch that has nothing to do with what is under test.
 */
const baseEnvelope: EvidenceEnvelope = assembleEnvelope(input, { sequenceNumber: 1 });

function envelopeWithChain(chain: unknown[]): EvidenceEnvelope {
  return { ...baseEnvelope, custodyChain: chain as unknown as EvidenceEnvelope['custodyChain'] };
}

/** A correctly hashed `reviewed` entry for `envelope`, with `overrides` applied after hashing. */
function hashedEntry(
  envelope: EvidenceEnvelope,
  overrides: Record<string, unknown> = {},
  prevEntryHash: string | null = null,
): Record<string, unknown> {
  const base = {
    action: 'reviewed',
    actor: 'jane@acme.example',
    timestamp: '2026-09-12T10:00:00.000Z',
    systemId: 'tzun-test',
  };
  const entryHash = computeCustodyEntryHash({
    prevEntryHash,
    evidenceId: envelope.payload.evidenceId,
    canonicalDigest: envelope.integrity.canonicalDigest,
    ...base,
    metadata: null,
  });
  return { ...base, entryHash, prevEntryHash, ...overrides };
}

function reasons(failures: Array<{ reason: CustodyTrailFailureReason }> | undefined): string[] {
  return (failures ?? []).map((f) => f.reason);
}

// ── verifyCustodyTrail — every entry field, every wrong type ──

describe('verifyCustodyTrail: a wrong-typed entry field is a verdict, not a throw', () => {
  const envelope = baseEnvelope;

  it('verifies a well-formed hashed entry (control — the type checks must not reject it)', () => {
    const verdict = verifyCustodyTrail(envelopeWithChain([hashedEntry(envelope)]));
    expect(verdict.valid).toBe(true);
    expect(verdict.failures).toEqual([]);
    expect(verdict.hashedEntries).toBe(1);
  });

  // Without the type check, every non-null/non-array row throws:
  //   TypeError: s is not iterable
  //       at codePointLength (packages/engine/src/custody-hash.ts)
  //       at lengthPrefix   (packages/engine/src/custody-hash.ts)
  for (const field of ['action', 'actor', 'timestamp', 'systemId'] as const) {
    describe(`${field}`, () => {
      for (const { label, value } of WRONG_FOR_STRING) {
        it(`reports entry_field_type when it is ${label}`, () => {
          const chain = [hashedEntry(envelope, { [field]: value })];
          let verdict!: CustodyTrailVerdict;
          expect(() => {
            verdict = verifyCustodyTrail(envelopeWithChain(chain));
          }).not.toThrow();
          expect(verdict.valid).toBe(false);
          expect(reasons(verdict.failures)).toContain('entry_field_type');
          expect(verdict.hashedEntries).toBe(1);
        });
      }
    });
  }

  describe('metadata', () => {
    // Unchecked, metadata does not throw — it coerces, which is the same hazard
    // wearing a quieter hat: `Object.keys(5)` is `[]`, so a number would
    // canonicalize as `{}` and the entry would be reported as an ordinary hash
    // mismatch rather than a wrong-typed field.
    for (const { label, value } of [
      { label: 'a number', value: 7 },
      { label: 'a string', value: 'x' },
      { label: 'an array', value: [1] },
      { label: 'true', value: true },
    ]) {
      it(`reports entry_field_type when it is ${label}`, () => {
        const verdict = verifyCustodyTrail(
          envelopeWithChain([hashedEntry(envelope, { metadata: value })]),
        );
        expect(verdict.valid).toBe(false);
        expect(reasons(verdict.failures)).toEqual(['entry_field_type']);
      });
    }

    it('accepts null and an absent key (both are legal, and hash identically)', () => {
      const withNull = verifyCustodyTrail(
        envelopeWithChain([hashedEntry(envelope, { metadata: null })]),
      );
      expect(withNull.valid).toBe(true);
      const absent = verifyCustodyTrail(envelopeWithChain([hashedEntry(envelope)]));
      expect(absent.valid).toBe(true);
    });

    // Unguarded, canonicalization throws:
    //   Error: Canonical serialization error: lone surrogate U+D800 in string. ...
    it('reports entry_metadata_unserializable for a lone UTF-16 surrogate', () => {
      let verdict!: CustodyTrailVerdict;
      expect(() => {
        verdict = verifyCustodyTrail(
          envelopeWithChain([hashedEntry(envelope, { metadata: { note: '\uD800' } })]),
        );
      }).not.toThrow();
      expect(verdict.valid).toBe(false);
      expect(reasons(verdict.failures)).toEqual(['entry_metadata_unserializable']);
    });

    // Unguarded, canonicalization throws:
    //   Error: Canonical serialization error: maximum nesting depth exceeded (circular reference?).
    it('reports entry_metadata_unserializable for nesting past the depth limit', () => {
      const deep: Record<string, unknown> = {};
      let cursor = deep;
      for (let i = 0; i < 100; i++) {
        cursor.n = {};
        cursor = cursor.n as Record<string, unknown>;
      }
      let verdict!: CustodyTrailVerdict;
      expect(() => {
        verdict = verifyCustodyTrail(
          envelopeWithChain([hashedEntry(envelope, { metadata: deep })]),
        );
      }).not.toThrow();
      expect(verdict.valid).toBe(false);
      expect(reasons(verdict.failures)).toEqual(['entry_metadata_unserializable']);
    });
  });

  describe('prevEntryHash', () => {
    // Without the type check, these throw TypeError: s is not iterable
    for (const { label, value } of [
      { label: 'a number', value: 5 },
      { label: 'true', value: true },
      { label: 'an object', value: {} },
      { label: 'an array', value: [] },
    ]) {
      it(`reports entry_field_type when it is ${label}`, () => {
        let verdict!: CustodyTrailVerdict;
        expect(() => {
          verdict = verifyCustodyTrail(
            envelopeWithChain([hashedEntry(envelope, { prevEntryHash: value })]),
          );
        }).not.toThrow();
        expect(verdict.valid).toBe(false);
        expect(reasons(verdict.failures)).toContain('entry_field_type');
        // A wrong-typed prevEntryHash is reported ONLY as a field-type failure:
        // "5 is not the previous entryHash" is true but says less than "5 is
        // not a hash at all".
        expect(reasons(verdict.failures)).not.toContain('prev_entry_hash_mismatch');
      });
    }

    it('still reports a genuine chain break when the field IS a string', () => {
      const verdict = verifyCustodyTrail(
        envelopeWithChain([hashedEntry(envelope, { prevEntryHash: HEX64 }, HEX64)]),
      );
      expect(verdict.valid).toBe(false);
      expect(reasons(verdict.failures)).toContain('prev_entry_hash_mismatch');
    });
  });

  describe('the record-level fields every entry hash commits to', () => {
    // evidenceId and canonicalDigest are length-prefixed into EVERY entry's
    // preimage, so an ill-typed one makes no entry on the record recomputable.
    it('reports entry_field_type on every hashed entry when evidenceId is not a string', () => {
      const base = baseEnvelope;
      const chain = [hashedEntry(base), hashedEntry(base)];
      const malformed = {
        ...base,
        payload: { ...base.payload, evidenceId: 42 as unknown as string },
        custodyChain: chain as unknown as EvidenceEnvelope['custodyChain'],
      };
      let verdict!: CustodyTrailVerdict;
      expect(() => {
        verdict = verifyCustodyTrail(malformed);
      }).not.toThrow();
      expect(verdict.valid).toBe(false);
      expect(reasons(verdict.failures)).toContain('entry_field_type');
    });

    it('reports entry_field_type when integrity.canonicalDigest is not a string', () => {
      const base = baseEnvelope;
      const malformed = {
        ...base,
        integrity: { ...base.integrity, canonicalDigest: { hex: 'x' } as unknown as string },
        custodyChain: [hashedEntry(base)] as unknown as EvidenceEnvelope['custodyChain'],
      };
      expect(() => verifyCustodyTrail(malformed)).not.toThrow();
      expect(verifyCustodyTrail(malformed).valid).toBe(false);
    });
  });

  // Unguarded, this throws:
  //   TypeError: Cannot read properties of null (reading 'custodyChain')
  it('answers "unverified" rather than throwing on a null envelope', () => {
    let verdict!: CustodyTrailVerdict;
    expect(() => {
      verdict = verifyCustodyTrail(null as unknown as EvidenceEnvelope);
    }).not.toThrow();
    expect(verdict.valid).toBeNull();
    expect(verdict.hashedEntries).toBe(0);
  });

  it('treats a non-array custodyChain as no chain at all', () => {
    const base = envelopeWithChain([]);
    const verdict = verifyCustodyTrail({
      ...base,
      custodyChain: 'nope' as unknown as EvidenceEnvelope['custodyChain'],
    });
    expect(verdict.valid).toBeNull();
    expect(verdict.hashedEntries).toBe(0);
  });
});

// ── verifyEnvelope — the public entry point the platform actually calls ──

describe('verifyEnvelope: malformed input is a verdict, not a throw', () => {
  it('reports custodyTrailValid:false for a wrong-typed actor instead of throwing', () => {
    const envelope = baseEnvelope;
    const withBadEntry = envelopeWithChain([hashedEntry(envelope, { actor: 123 })]);
    let result!: VerificationResult;
    expect(() => {
      result = verifyEnvelope(withBadEntry);
    }).not.toThrow();
    expect(result.custodyTrailValid).toBe(false);
    expect(reasons(result.custodyTrailFailures)).toContain('entry_field_type');
    // custodyChain is outside the hashed field set, so the DECISION record is
    // still intact — that separation is the point of the two fields.
    expect(result.verified).toBe(true);
  });

  // Unguarded, canonicalization throws:
  //   Error: Canonical serialization error: lone surrogate U+D800 in string. ...
  //
  // Not an exotic input: an LLM completion truncated mid-emoji yields one, and
  // JSON.stringify preserves it as \ud800 through every adapter into the store.
  it('reports payloadSerializationError for a lone surrogate in aiOutput', () => {
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });
    const malformed = {
      ...envelope,
      payload: { ...envelope.payload, aiOutput: { text: '\uD800' } },
    };
    let result!: VerificationResult;
    expect(() => {
      result = verifyEnvelope(malformed);
    }).not.toThrow();
    expect(result.verified).toBe(false);
    expect(result.recomputedDigest).toBe('');
    expect(result.payloadSerializationError).toMatch(/lone surrogate U\+D800/);
  });

  it('reports payloadSerializationError for nesting past the depth limit', () => {
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });
    const deep: Record<string, unknown> = {};
    let cursor = deep;
    for (let i = 0; i < 100; i++) {
      cursor.n = {};
      cursor = cursor.n as Record<string, unknown>;
    }
    const result = verifyEnvelope({
      ...envelope,
      payload: { ...envelope.payload, aiOutput: deep },
    });
    expect(result.verified).toBe(false);
    expect(result.payloadSerializationError).toMatch(/maximum nesting depth exceeded/);
  });

  // Unguarded, these throw, one per row:
  //   TypeError: Cannot read properties of undefined (reading 'schemaVersion')
  //   TypeError: Cannot read properties of undefined (reading 'canonicalDigest')
  //   TypeError: Cannot read properties of null (reading 'payload')
  const structurallyMalformed: Array<{ label: string; envelope: unknown }> = [
    {
      label: 'no payload key',
      envelope: {
        envelopeVersion: 'e1',
        integrity: { canonicalDigest: HEX64, chainLink: null },
        nonRepudiation: {},
        custodyChain: [],
        attestationStatus: 'none',
      },
    },
    {
      label: 'no integrity key',
      envelope: {
        envelopeVersion: 'e1',
        payload: assembleEnvelope(input, { sequenceNumber: 1 }).payload,
        nonRepudiation: {},
        custodyChain: [],
        attestationStatus: 'none',
      },
    },
    { label: 'null', envelope: null },
    { label: 'an empty object', envelope: {} },
  ];

  for (const { label, envelope } of structurallyMalformed) {
    it(`reports verified:false for an envelope that is ${label}`, () => {
      let result!: VerificationResult;
      expect(() => {
        result = verifyEnvelope(envelope as EvidenceEnvelope);
      }).not.toThrow();
      expect(result.verified).toBe(false);
    });
  }

  it('never verifies an envelope whose payload AND digest are both unreadable', () => {
    // The '' === '' trap: a missing integrity block and an unserializable
    // payload must not agree with each other.
    const result = verifyEnvelope({} as EvidenceEnvelope);
    expect(result.verified).toBe(false);
    expect(result.storedDigest).toBe('');
  });
});

// ── the stored round trip: SQLite, JSON into a column and back out ──

describe('verifyEnvelope over a STORED envelope (adapter: SQLite, real file)', () => {
  let dbPath: string;
  let adapter: SqliteStorageAdapter;

  beforeEach(() => {
    dbPath = path.join(
      os.tmpdir(),
      `tzun-test-${Date.now()}-${Math.random().toString(36).slice(2)}.db`,
    );
    adapter = new SqliteStorageAdapter(dbPath);
  });

  afterEach(() => {
    adapter.close();
    for (const suffix of ['', '-wal', '-shm']) {
      try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
    }
  });

  /**
   * The regression sentinel: a malformed custody entry that
   * went through a REAL STORE and back, handed to `verifyEnvelope`. If the
   * type checks are ever removed, this test fails as the TypeError itself —
   * `TypeError: s is not iterable` — not as a changed expectation.
   */
  it('reports a wrong-typed actor on a round-tripped record instead of throwing', async () => {
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });
    await adapter.store(envelope, CHAIN);

    await rewriteStoredEnvelope(adapter, envelope.payload.evidenceId, (stored) => {
      stored.custodyChain = [
        hashedEntry(envelope, { actor: 123 }),
      ] as unknown as EvidenceEnvelope['custodyChain'];
    });

    const readBack = await adapter.retrieve(envelope.payload.evidenceId);
    expect(readBack).not.toBeNull();
    // The number survives JSON -> TEXT column -> JSON unchanged. That round
    // trip is the one a server makes when it verifies a stored record.
    expect((readBack!.custodyChain[0] as unknown as { actor: unknown }).actor).toBe(123);

    let result!: VerificationResult;
    expect(() => {
      result = verifyEnvelope(readBack!);
    }).not.toThrow();
    expect(result.custodyTrailValid).toBe(false);
    expect(reasons(result.custodyTrailFailures)).toContain('entry_field_type');
  });

  // Unguarded, canonicalization throws:
  //   Error: Canonical serialization error: lone surrogate U+D800 in string. ...
  //   — out of the WALK, so one malformed row would make every OTHER record in
  //   the chain unverifiable rather than making itself a finding.
  it('verifyChainCompleteness reports one unserializable row and keeps walking', async () => {
    const clean = assembleEnvelope(input, { sequenceNumber: 1 });
    await adapter.store(clean, CHAIN);
    const second = assembleEnvelope(input, { previousDigest: clean.integrity.canonicalDigest, sequenceNumber: 2 });
    await adapter.store(second, CHAIN);

    await rewriteStoredEnvelope(adapter, clean.payload.evidenceId, (stored) => {
      stored.payload.aiOutput = { text: '\uD800' };
    });

    let result!: Awaited<ReturnType<typeof verifyChainCompleteness>>;
    await expect(
      (async () => {
        result = await verifyChainCompleteness(adapter, registry, { chainId: CHAIN });
      })(),
    ).resolves.not.toThrow();

    expect(result.valid).toBe(false);
    expect(result.totalRecords).toBe(2);
    // The malformed record is a finding; the honest one is still checked and
    // still clean.
    expect(result.digestMismatches).toEqual([clean.payload.evidenceId]);
  });
});

// ── verifyAttestation — nonRepudiation is client-supplied JSON too ──

describe('verifyAttestation: malformed artifacts are a verdict, not a throw', () => {
  /**
   * A WELL-FORMED tzun-anchor/1 artifact over GOOD's four-leaf tree, as
   * `nonRepudiation.anchor`, with `overrides` applied last. Every row below
   * breaks exactly one member of it. Its leaf `GOOD.leafIndex` is `GOOD.leaf`,
   * so its inclusion proof holds; its one publication is an EVM entry in its
   * envelope form, which nothing here checks, so it is never `true`.
   */
  const RECORD = anchoredRecord({ digests: TREE4.proofs.map((p) => p.leafDigest), leafIndex: GOOD.leafIndex });
  const anchor = (overrides: Record<string, unknown> = {}): AttestationArtifacts =>
    ({ anchor: { ...RECORD.anchor, ...overrides } }) as unknown as AttestationArtifacts;

  /**
   * A rejected proof: `false`, and never a claim that it was checked and held.
   * A path that is present but not an array of hashes is `malformed_merkle_path`
   * and an absent one `malformed_anchor` (tzun-anchor/1 §10.3 step 2).
   */
  const REFUSED_PROOF = ['merkle_proof_invalid', 'anchor_proof_invalid', 'malformed_merkle_path', 'malformed_anchor'];

  async function verdictOf(artifacts: AttestationArtifacts, digest: unknown = GOOD.leaf) {
    let result!: Awaited<ReturnType<typeof verifyAttestation>>;
    await expect(
      (async () => {
        result = await verifyAttestation(artifacts, digest as string);
      })(),
    ).resolves.not.toThrow();
    return result;
  }

  it('verifies the untouched baseline (control — every row below must fail for its OWN reason)', async () => {
    expect(RECORD.anchor.logPath).toEqual(GOOD.path);
    const result = await verdictOf(anchor());
    expect(result.merkleProofValid).toBe(true);
    // Not `true`: no publication is checked, and the roots arrive inside the
    // very artifact under examination.
    expect(result.anchorValid).toBeNull();
  });

  // A path element is a BARE 64-hex hash, so "looks like a hash" is not close
  // enough: a short or non-hex element, and above all a legacy
  // `"<left|right>:<hash>"` element, must be refused outright. Accepting the
  // legacy element by stripping its label would be the worst available
  // outcome — a stale path folded against the wrong tree and reported as a
  // confident verdict.
  const badPaths: Array<{ label: string; value: unknown }> = [
    { label: 'absent', value: undefined },
    { label: 'a number', value: 5 },
    { label: 'a string', value: 'left:aa' },
    { label: 'an object', value: { 0: 'left:aa' } },
    { label: 'an array of numbers', value: [7] },
    { label: 'an array of objects', value: [{ position: 'left', hash: 'aa' }] },
    { label: 'an array with a null', value: [GOOD.path[0], null] },
    { label: 'an array with a non-hex element', value: ['z'.repeat(64)] },
    { label: 'an array with a too-short hex element', value: ['abcdef'] },
    { label: 'an array with a legacy "left:<hash>" element', value: [`left:${GOOD.path[0]}`] },
    { label: 'an array with a legacy "right:<hash>" element', value: [`right:${GOOD.path[0]}`] },
  ];

  for (const member of ['logPath', 'anchorPath']) {
    for (const { label, value } of badPaths) {
      it(`reports a refused proof when ${member} is ${label}`, async () => {
        const result = await verdictOf(anchor({ [member]: value }));
        expect(result.anchorValid).toBe(false);
        expect(REFUSED_PROOF).toContain(result.anchorReason);
        expect(result.merkleProofValid).not.toBe(true);
      });
    }
  }

  // The side of each step is DERIVED from the leaf index and the size in the
  // checkpoint body, so the indices are part of the proof and are
  // attacker-supplied JSON like everything else here.
  const badIndex: Array<{ label: string; value: unknown }> = [
    { label: 'absent', value: undefined },
    { label: 'null', value: null },
    { label: 'a numeric string', value: '2' },
    { label: 'fractional', value: 2.5 },
    { label: 'NaN', value: NaN },
    { label: 'Infinity', value: Infinity },
    { label: 'negative', value: -1 },
    { label: 'an object', value: {} },
    { label: 'true', value: true },
    // The phantom leaf: an index at or past the tree size.
    { label: 'equal to the tree size', value: GOOD.treeSize },
    { label: 'absurdly past the tree size', value: Number.MAX_SAFE_INTEGER },
  ];

  for (const member of ['leafIndex', 'anchorLeafIndex']) {
    for (const { label, value } of badIndex) {
      it(`reports a refused proof when ${member} is ${label}`, async () => {
        const result = await verdictOf(anchor({ [member]: value }));
        expect(result.anchorValid).toBe(false);
        expect(result.merkleProofValid).not.toBe(true);
      });
    }
  }

  // A verifier meeting a rule it does not implement must say "I cannot check
  // this" — an explicit unsupported reason and `merkleProofValid` NULL — and
  // must never fall back to another rule and answer "invalid".
  const unknownTags: Array<{ label: string; value: unknown }> = [
    { label: 'absent', value: undefined },
    { label: 'null', value: null },
    { label: 'a future tag', value: 'v2' },
    { label: 'the right tag in the wrong case', value: 'RFC6962' },
    { label: 'a number', value: 5 },
    { label: 'true', value: true },
    { label: 'an object', value: {} },
    { label: 'an array', value: ['rfc6962'] },
  ];
  for (const [member, reason] of [
    ['anchorSpec', 'unsupported_anchor_spec'],
    ['merkleSpec', 'unsupported_merkle_spec'],
  ] as const) {
    for (const { label, value } of unknownTags) {
      it(`reports ${reason} when ${member} is ${label}`, async () => {
        const result = await verdictOf(anchor({ [member]: value }));
        // NULL, not false: `false` would assert the anchor was adjudicated.
        expect(result.anchorValid).toBeNull();
        expect(result.merkleProofValid).toBeNull();
        expect(result.anchorReason).toBe(reason);
      });
    }
  }

  it('checks the tags FIRST: an untagged artifact with a legacy path is unsupported, not malformed', async () => {
    const result = await verdictOf(anchor({ merkleSpec: undefined, logPath: [`left:${GOOD.path[0]}`] }));
    expect(result.anchorReason).toBe('unsupported_merkle_spec');
    expect(result.merkleProofValid).toBeNull();
  });

  for (const { label, artifacts, reason } of [
    { label: 'anchor is a number', artifacts: { anchor: 5 }, reason: 'unsupported_anchor_spec' },
    { label: 'anchor is an array', artifacts: { anchor: [] }, reason: 'unsupported_anchor_spec' },
    { label: 'blockchainAnchor is a number', artifacts: { blockchainAnchor: 5 }, reason: 'legacy_blockchain_anchor' },
  ]) {
    it(`reports an abstention, not a throw, when ${label}`, async () => {
      const result = await verdictOf(artifacts as unknown as AttestationArtifacts, HEX64);
      expect(result.anchorValid).toBeNull();
      expect(result.anchorReason).toBe(reason);
      expect(result.merkleProofValid).toBeNull();
    });
  }

  it('reports malformed_anchor for a correctly tagged anchor that carries nothing else (tzun-anchor/1 §10.3 step 2)', async () => {
    const result = await verdictOf(
      { anchor: { anchorSpec: 'tzun-anchor/1', merkleSpec: 'rfc6962' } } as unknown as AttestationArtifacts,
      HEX64,
    );
    expect(result.anchorValid).toBe(false);
    expect(result.anchorReason).toBe('malformed_anchor');
  });

  it('treats a null anchor as nothing anchored, not as a failure', async () => {
    // Absent is not invalid. An unanchored record must not read as one whose
    // anchor was checked and rejected.
    for (const artifacts of [{ anchor: null }, { blockchainAnchor: null }]) {
      const result = await verdictOf(artifacts as unknown as AttestationArtifacts, HEX64);
      expect(result.anchorValid).toBeNull();
      expect(result.merkleProofValid).toBeNull();
      expect(result.anchorReason).toBeUndefined();
    }
  });

  // The anchor here is the baseline, whose proofs hold, so the digest's type
  // is the only thing wrong with this call — the row cannot pass by accident.
  it('reports a failed proof when the digest under test is not a string', async () => {
    const result = await verdictOf(anchor(), 5);
    expect(result.anchorValid).toBe(false);
    expect(result.merkleProofValid).toBe(false);
    expect(result.anchorReason).toBe('merkle_proof_invalid');
  });

  // Unguarded, this throws:
  //   TypeError: Cannot read properties of null (reading 'webauthnAssertion')
  for (const { label, value } of [
    { label: 'null', value: null },
    { label: 'a number', value: 5 },
    { label: 'an array', value: [] },
  ]) {
    it(`reports "nothing attested" when the artifacts bag is ${label}`, async () => {
      let result!: Awaited<ReturnType<typeof verifyAttestation>>;
      await expect(
        (async () => {
          result = await verifyAttestation(value as unknown as AttestationArtifacts, HEX64);
        })(),
      ).resolves.not.toThrow();
      expect(result.signatureValid).toBeNull();
      expect(result.timestampValid).toBeNull();
      expect(result.anchorValid).toBeNull();
      expect(result.attestationVerdict).toBe('none');
    });
  }

  // Unguarded, this throws:
  //   TypeError [ERR_INVALID_ARG_TYPE]: The first argument must be of type string
  //   ... Received type number (123)     — from Buffer.from(authenticatorData, 'base64')
  //
  // The array row. Unchecked, an ARRAY does not throw: `Buffer.from(['x'],
  // 'base64')` succeeds (an array is an Array-like of byte values) and the
  // resulting 1-byte buffer is shorter than the mandatory 37, so the verdict
  // would be `malformed_authenticator_data`. That is wrong for the same reason
  // the array row in WRONG_FOR_STRING is: the verifier would coerce a value it
  // should reject, then report a length finding about bytes the assertion
  // never contained. A non-string carries no signed message at all, which is
  // `unverifiable_assertion`.
  for (const { label, value } of [
    { label: 'a number', value: 123 },
    { label: 'an object', value: { a: 1 } },
    { label: 'an array', value: ['x'] },
  ]) {
    it(`reports unverifiable_assertion when authenticatorData is ${label}`, async () => {
      const clientDataJSON = Buffer.from(
        JSON.stringify({ type: 'webauthn.get', challenge: 'c', origin: 'https://x' }),
      ).toString('base64');
      const credentialStore = {
        getByCredentialId: () => ({
          credentialId: 'k',
          userId: 'jane@acme.example',
          publicKey: 'AAAA',
          algorithm: 'ES256' as const,
          status: 'active' as const,
        }),
      };
      let result!: Awaited<ReturnType<typeof verifyAttestation>>;
      await expect(
        (async () => {
          result = await verifyAttestation(
            {
              webauthnAssertion: {
                signature: 's',
                credentialKeyId: 'k',
                algorithm: 'ES256',
                authenticatorData: value,
                clientDataJSON,
              },
            } as unknown as AttestationArtifacts,
            HEX64,
            credentialStore as never,
          );
        })(),
      ).resolves.not.toThrow();
      expect(result.signatureValid).toBe(false);
      expect(result.signatureReason).toBe('unverifiable_assertion');
    });
  }
});

describe('clientDataJSON that decodes to JSON but not to an object is malformed, not a throw', () => {
  // A successful `JSON.parse` is not enough: `clientDataJSON` = base64("null")
  // parses, and reading its first field without an object check throws
  // `TypeError: Cannot read properties of null (reading 'type')` out of the
  // binding check — which `determineAttestationStatus` runs at every capture
  // and assemble — and out of `verifyAttestation`. The Python SDK answers
  // these inputs too, so a throw here would also split the two SDKs.
  const credentialStore = {
    getByCredentialId: () => ({
      credentialId: 'k',
      userId: 'jane@acme.example',
      publicKey: 'AAAA',
      algorithm: 'ES256' as const,
      status: 'active' as const,
    }),
  };
  for (const { label, json } of [
    { label: 'null', json: 'null' },
    { label: 'a number', json: '7' },
    { label: 'a string', json: '"webauthn.get"' },
    { label: 'an array', json: '[]' },
  ]) {
    const assertion = {
      signature: 's',
      credentialKeyId: 'k',
      algorithm: 'ES256' as const,
      authenticatorData: Buffer.alloc(37, 1).toString('base64'),
      clientDataJSON: Buffer.from(json).toString('base64'),
    };

    it(`assertionBindingFailure reports malformed_client_data for ${label}`, () => {
      expect(assertionBindingFailure(assertion, HEX64)).toBe('malformed_client_data');
      expect(determineAttestationStatus({ webauthnAssertion: assertion }, HEX64)).toBe('none');
    });

    it(`verifyAttestation answers for ${label}, with and without a credential store`, async () => {
      const options = { expectedChallenge: webauthnChallengeForDigest(HEX64) };
      const withStore = await verifyAttestation(
        { webauthnAssertion: assertion },
        HEX64,
        credentialStore as never,
        options,
      );
      expect(withStore.signatureValid).toBe(false);
      expect(withStore.signatureReason).toBe('malformed_client_data');

      const withoutStore = await verifyAttestation({ webauthnAssertion: assertion }, HEX64, undefined, options);
      expect(withoutStore.signatureValid).not.toBe(true);
    });
  }
});

describe('verifyMerkleProof: a non-string anywhere is a failed proof, not a throw', () => {
  /**
   *   verifyMerkleProof(leaf, leafIndex, treeSize, proof, expectedRoot)
   *
   * The index arguments are not bookkeeping. The side of each step is derived
   * from `(leafIndex, treeSize)` rather than carried on the step itself, which
   * is exactly what lets a stock CT verifier check these proofs — and which
   * puts two integers, straight off the wire, into the arithmetic. So this
   * table covers all five untrusted arguments, and the property is the same
   * for each: a `false`, never a throw, because this function runs inside a
   * request handler on input a client chose.
   */
  it('verifies the conformance vector (control — nothing below is vacuously false)', () => {
    expect(
      verifyMerkleProof(GOOD.leaf, GOOD.leafIndex, GOOD.treeSize, GOOD.path, GOOD.root),
    ).toBe(true);
  });

  // Unguarded, a number reaches Buffer.from and throws TypeError [ERR_INVALID_ARG_TYPE]
  it('returns false for a non-string leaf', () => {
    expect(
      verifyMerkleProof(
        5 as unknown as string, GOOD.leafIndex, GOOD.treeSize, GOOD.path, GOOD.root,
      ),
    ).toBe(false);
  });
  it('returns false for a non-string expectedRoot', () => {
    expect(
      verifyMerkleProof(
        GOOD.leaf, GOOD.leafIndex, GOOD.treeSize, GOOD.path, 5 as unknown as string,
      ),
    ).toBe(false);
  });
  it('returns false for a non-array proof', () => {
    expect(
      verifyMerkleProof(
        GOOD.leaf, GOOD.leafIndex, GOOD.treeSize, 5 as unknown as string[], GOOD.root,
      ),
    ).toBe(false);
  });

  // A leaf that is a string but not a digest. The leaf is hex-DECODED
  // (Tree §3), so an unparseable leaf must be refused up front rather than handed to `Buffer.from(x, 'hex')`,
  // which silently truncates at the first non-hex character instead of failing.
  for (const { label, value } of [
    { label: 'not hex', value: 'z'.repeat(64) },
    { label: 'too short', value: 'ab'.repeat(31) },
    { label: 'too long', value: 'ab'.repeat(33) },
    { label: 'empty', value: '' },
    { label: 'hex with a space', value: `${'a'.repeat(63)} ` },
  ]) {
    it(`returns false for a leaf that is ${label}`, () => {
      expect(
        verifyMerkleProof(value, GOOD.leafIndex, GOOD.treeSize, GOOD.path, GOOD.root),
      ).toBe(false);
    });
  }

  // The first two rows are the legacy `{hash, position}` proof step, a shape
  // the SDK has no type for. It is what a stored pre-RFC-6962 artifact still
  // contains, so it is untrusted JSON of exactly the kind this file is about,
  // and it must be refused rather than read.
  for (const { label, value } of [
    { label: 'a legacy {hash, position} object', value: [{ hash: 7, position: 'left' }] },
    { label: 'a legacy {hash, position} object with a real hash', value: [{ hash: 'a'.repeat(64), position: 'left' }] },
    { label: 'a number', value: [7] },
    { label: 'null', value: [null] },
    { label: 'undefined', value: [undefined] },
    { label: 'an array', value: [['a'.repeat(64)]] },
    { label: 'a non-hex string', value: ['z'.repeat(64)] },
    { label: 'a short hex string', value: ['abcdef'] },
  ]) {
    it(`returns false for a proof step that is ${label}`, () => {
      expect(
        verifyMerkleProof(
          GOOD.leaf, GOOD.leafIndex, GOOD.treeSize, value as unknown as string[], GOOD.root,
        ),
      ).toBe(false);
    });
  }

  // A legacy path element is the dangerous one: it is not garbage, it is a
  // CORRECT hash wearing a label the current rule does not carry. Stripping
  // the label to "recover" the hash would fold a stale path against the wrong
  // tree and return a confident `true`, so it must be refused (Tree §8) as
  // hard as `[7]` is.
  it('returns false for a legacy "left:<hash>" path element', () => {
    expect(
      verifyMerkleProof(
        GOOD.leaf,
        GOOD.leafIndex,
        GOOD.treeSize,
        GOOD.path.map((h, i) => (i === 0 ? `left:${h}` : h)),
        GOOD.root,
      ),
    ).toBe(false);
  });

  // THE INDEX ARGUMENTS, same rule. `leafIndex` and `treeSize` reach `%`, `>>` and a
  // loop bound, so a non-integer would propagate NaN through the fold and a
  // negative or out-of-range pair would describe a tree that cannot exist.
  // Both are a `false`: an unanswerable proof is not a verified one.
  for (const { label, leafIndex, treeSize } of [
    { label: 'leafIndex is a string', leafIndex: '2' as unknown as number, treeSize: 4 },
    { label: 'treeSize is a string', leafIndex: 2, treeSize: '4' as unknown as number },
    { label: 'leafIndex is fractional', leafIndex: 2.5, treeSize: 4 },
    { label: 'treeSize is fractional', leafIndex: 2, treeSize: 4.5 },
    { label: 'leafIndex is NaN', leafIndex: NaN, treeSize: 4 },
    { label: 'treeSize is NaN', leafIndex: 2, treeSize: NaN },
    { label: 'leafIndex is Infinity', leafIndex: Infinity, treeSize: 4 },
    { label: 'treeSize is Infinity', leafIndex: 2, treeSize: Infinity },
    { label: 'leafIndex is negative', leafIndex: -1, treeSize: 4 },
    { label: 'treeSize is zero', leafIndex: 0, treeSize: 0 },
    { label: 'treeSize is negative', leafIndex: 0, treeSize: -4 },
    { label: 'leafIndex is null', leafIndex: null as unknown as number, treeSize: 4 },
    { label: 'treeSize is undefined', leafIndex: 2, treeSize: undefined as unknown as number },
    { label: 'leafIndex is an object', leafIndex: {} as unknown as number, treeSize: 4 },
  ]) {
    it(`returns false when ${label}`, () => {
      expect(verifyMerkleProof(GOOD.leaf, leafIndex, treeSize, GOOD.path, GOOD.root)).toBe(false);
    });
  }

  // The phantom leaf at the function level (Tree §3.4's first line): an index
  // the tree does not contain is refused before the first hash, so no path can
  // make it fold into the root.
  for (const { label, leafIndex } of [
    { label: 'equal to treeSize', leafIndex: GOOD.treeSize },
    { label: 'past treeSize', leafIndex: GOOD.treeSize + 1 },
    { label: 'in range but not the leaf this path belongs to', leafIndex: GOOD.treeSize - 1 },
  ]) {
    it(`returns false for a leaf index ${label}`, () => {
      // The last row IS in range, so it is the control for the other two: it
      // fails on the FOLD (that path belongs to a different leaf), not on the
      // range check — which is how we know the range check is not swallowing
      // every index and making this whole block vacuous.
      expect(
        verifyMerkleProof(GOOD.leaf, leafIndex, GOOD.treeSize, GOOD.path, GOOD.root),
      ).toBe(false);
    });
  }

  // A truncated path must not fold to a smaller tree's root, and an over-long
  // one must not keep hashing: `sn === 0` at the end is load-bearing, not
  // incidental (Tree §3.4). A vast treeSize with a two-step path is the cheap
  // hostile version — the loop is bounded by the PATH, so it returns rather
  // than running for 2^53 rounds.
  it('returns false for a truncated path', () => {
    expect(
      verifyMerkleProof(GOOD.leaf, GOOD.leafIndex, GOOD.treeSize, GOOD.path.slice(0, 1), GOOD.root),
    ).toBe(false);
  });
  it('returns false for a path longer than the tree justifies', () => {
    expect(
      verifyMerkleProof(
        GOOD.leaf, GOOD.leafIndex, GOOD.treeSize, [...GOOD.path, GOOD.path[0]], GOOD.root,
      ),
    ).toBe(false);
  });
  it('returns false — promptly — for an absurd treeSize', () => {
    const started = Date.now();
    expect(
      verifyMerkleProof(
        GOOD.leaf, GOOD.leafIndex, Number.MAX_SAFE_INTEGER, GOOD.path, GOOD.root,
      ),
    ).toBe(false);
    expect(Date.now() - started).toBeLessThan(1000);
  });
});

// ── the export-bundle verifier: the most untrusted input in the system ──

describe('verifyExported: a malformed bundle is a list of errors, not a throw', () => {
  const bundleFor = (envelope: unknown, resolved: unknown = {}) =>
    ({
      envelope,
      resolvedModelDescriptors: resolved,
      exportedAt: '2026-09-12T10:00:00.000Z',
      exportedBy: 'tzun-sdk',
    }) as never;

  it('reports rather than throws when the payload cannot be canonicalized', async () => {
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });
    const malformed = {
      ...envelope,
      payload: { ...envelope.payload, reason: '\uDC00' },
    };
    let result!: Awaited<ReturnType<typeof verifyExported>>;
    await expect(
      (async () => {
        result = await verifyExported(bundleFor(malformed));
      })(),
    ).resolves.not.toThrow();
    expect(result.ok).toBe(false);
    expect((result as { errors: string[] }).errors.join('\n')).toMatch(
      /cannot be canonically serialized/,
    );
  });

  const malformedBundles: Array<{ label: string; bundle: unknown }> = [
    { label: 'no envelope key', bundle: { resolvedModelDescriptors: {} } },
    { label: 'a null envelope', bundle: bundleFor(null) },
    { label: 'resolvedModelDescriptors missing', bundle: { envelope: {} } },
    { label: 'resolvedModelDescriptors = 5', bundle: bundleFor({}, 5) },
    {
      label: 'a descriptor entry whose canonicalBytes is a number',
      bundle: bundleFor({}, { [`sha256:${HEX64}`]: { canonicalBytes: 7, enrichedView: null, annotations: [] } }),
    },
  ];

  for (const { label, bundle } of malformedBundles) {
    it(`reports errors for a bundle with ${label}`, async () => {
      let result!: Awaited<ReturnType<typeof verifyExported>>;
      await expect(
        (async () => {
          result = await verifyExported(bundle as never);
        })(),
      ).resolves.not.toThrow();
      expect(result.ok).toBe(false);
    });
  }

  it("reports a step's non-string aiBom.modelDescriptorDigest rather than walking on it", async () => {
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });
    const step = { role: 'propose', actor: null, aiBom: { modelDescriptorDigest: 42 }, inputs: [], output: 'sha256:' + '0'.repeat(64), verdict: null, reason: null, prev: null };
    const result = await verifyExported(
      bundleFor({
        ...envelope,
        payload: { ...envelope.payload, contributions: { pipeline: null, externals: [], steps: [step] } } as never,
      }),
    );
    expect(result.ok).toBe(false);
    expect((result as { errors: string[] }).errors.join('\n')).toMatch(
      /is not a descriptor digest string/,
    );
  });
});
