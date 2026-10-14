#!/usr/bin/env node
// Writes vectors/evidence-log-origin-vectors.json: the evidence-log origin
// each implementation must compute for a chain id (tzun-anchor/1 §4.3.2).
// The same file is run by TypeScript (src/storage/log-store.ts), SQLite SQL
// and Postgres SQL (the adapters' triggers,
// tests/ts/evidence-log-origin-vectors.test.ts) and Python
// (python/src/tzun_sdk/log_origin.py, tests/cross-sdk/).
//
// The rule, transcribed here from the spec and not imported from the SDK:
//
//   evidence log:  <ns>/<storeId>/evidence/<lowercase hex of the chain id's UTF-8 bytes>
//   per-store log: <ns>/<storeId>/<kind>
//
// The chain id is not normalised: two spellings of one character are two
// chain ids, two segments and two logs. A chain id is a non-empty string of
// Unicode scalar values other than U+0000 (tzun-anchor/1 §4.3.2); the others
// are refused, and `invalidChainIds` lists them with the reason a store gives.
//
// `ns` is a lowercase DNS-style name: labels of a-z and 0-9, with "-" inside a
// label but not at either end, joined by "."; a label is at most 63
// characters and the name at most 253. `namespaces` lists names each
// implementation must accept and names it must refuse.
//
// Run: node scripts/generate-evidence-log-origin-vectors.mjs
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'vectors', 'evidence-log-origin-vectors.json');

const NS = 'local.invalid';
const STORE_ID = '3f2a9c4e1b7d6058a1c3e5f7092b4d6e';

const utf8Hex = (text) =>
  Array.from(new TextEncoder().encode(text), (byte) => byte.toString(16).padStart(2, '0')).join('');

const CHAIN_IDS = [
  ['the default chain', 'default'],
  ['a lowercase ASCII id', 'chain-a'],
  ['uppercase ASCII: the bytes, then lowercase hex digits', 'Tenant-ACME'],
  ['a platform-style id', 'user-4f1e9c'],
  ['a space, a plus and a slash, none of which may appear in an origin', 'a b+c/d'],
  ['a tab', 'tab\there'],
  ['two-byte UTF-8, NFC (U+00E9)', 'café'],
  ['the same text in NFD (e + U+0301): a different chain', 'café'],
  ['U+00FF', 'ÿ'],
  ['a byte-order mark (U+FEFF)', '﻿bom'],
  ['three-byte UTF-8 (CJK)', '日本'],
  ['four-byte UTF-8 (a surrogate pair in UTF-16)', '\u{1F600}'],
  ['a long id is not truncated', 'x'.repeat(200)],
];

const STORE_LOG_KINDS = ['anchors', 'custody', 'revisions', 'policy'];

const INVALID_CHAIN_IDS = [
  ['empty', '', 'empty_chain_id'],
  ['a lone high surrogate at the end (a truncated emoji)', 'bad\uD800', 'invalid_chain_id'],
  ['a lone low surrogate', 'x\uDFFFy', 'invalid_chain_id'],
  ['a low surrogate before a high one (reversed pair)', '\uDE00\uD83D', 'invalid_chain_id'],
  ['U+0000 inside', 'a\u0000b', 'invalid_chain_id'],
  ['U+0000 alone', '\u0000', 'invalid_chain_id'],
];

const label = (n) => 'a'.repeat(n);
const VALID_NAMESPACES = [
  ['the default', 'local.invalid'],
  ['a test namespace', 'test.tzun.ai'],
  ['one label', 'localhost'],
  ['digits and interior hyphens', 'x-1.b2-c.io'],
  ['a label of 63 characters', `${label(63)}.example`],
  ['253 characters', [label(63), label(63), label(63), label(61)].join('.')],
];
const INVALID_NAMESPACES = [
  ['empty', ''],
  ['a path (a third origin segment)', 'test.tzun.ai/demo'],
  ['uppercase', 'Example.COM'],
  ['punctuation', 'a!b'],
  ['a plus', 'a+b'],
  ['a space', 'has space'],
  ['an underscore', 'a_b.com'],
  ['a leading dot', '.example'],
  ['a trailing dot', 'example.'],
  ['an empty label', 'a..b'],
  ['a label starting with a hyphen', '-a.b'],
  ['a label ending with a hyphen', 'a-.b'],
  ['a hyphen after a dot', 'a.-b'],
  ['non-ASCII', 'café.example'],
  ['a label of 64 characters', `${label(64)}.example`],
  ['254 characters', [label(63), label(63), label(63), label(62)].join('.')],
];

const doc = {
  description:
    'Evidence-log origins (Anchor §4.3.2). Every implementation computes `origin` from ' +
    '`ns`, `storeId` and `chainId`: TypeScript, SQLite SQL (lower(hex(chain_id))), Postgres SQL ' +
    "(encode(convert_to(chain_id, 'UTF8'), 'hex')) and Python.",
  generator: 'scripts/generate-evidence-log-origin-vectors.mjs',
  rule: {
    evidence: '<ns>/<storeId>/evidence/<lowercase hex of the UTF-8 bytes of chainId>',
    storeLog: '<ns>/<storeId>/<kind>',
  },
  ns: NS,
  storeId: STORE_ID,
  vectors: CHAIN_IDS.map(([name, chainId]) => ({
    name,
    chainId,
    chainSegment: utf8Hex(chainId),
    origin: `${NS}/${STORE_ID}/evidence/${utf8Hex(chainId)}`,
  })),
  storeLogs: STORE_LOG_KINDS.map((kind) => ({ kind, origin: `${NS}/${STORE_ID}/${kind}` })),
  invalidChainIds: INVALID_CHAIN_IDS.map(([name, chainId, reason]) => ({ name, chainId, reason })),
  namespaces: {
    valid: VALID_NAMESPACES.map(([name, ns]) => ({ name, ns })),
    invalid: INVALID_NAMESPACES.map(([name, ns]) => ({ name, ns })),
  },
};

writeFileSync(OUT, JSON.stringify(doc, null, 2) + '\n');
console.log(
  `wrote ${doc.vectors.length} chain ids, ${doc.invalidChainIds.length} refused chain ids, ` +
    `${doc.storeLogs.length} store logs and ${VALID_NAMESPACES.length + INVALID_NAMESPACES.length} namespaces to ${OUT}`,
);
