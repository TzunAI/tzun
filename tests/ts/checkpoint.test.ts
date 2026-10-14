/**
 * Anchor §4: checkpoint bodies and origins. The byte
 * rules are pinned by vectors/checkpoint-vectors.json; this suite pins the
 * reasons, the writers' refusals, and that no reader throws.
 */
import {
  anchorLogOrigin,
  chainIdFromSegment,
  chainIdRefusal,
  chainSegment,
  checkOriginBinding,
  checkpointDigest,
  evidenceLogOrigin,
  formatCheckpoint,
  isOriginText,
  isPlatformNamespace,
  isTestNamespace,
  parseCheckpoint,
  parseOrigin,
  PLATFORM_NAMESPACE,
  sourceLogOrigin,
} from '../../src/attestation/checkpoint';

const ROOT = 'ab'.repeat(32);
const ORIGIN = 'local.invalid/3f2a9c0e5b7d4e1f8a6c2b9d0e4f7a1c/anchors';
const BODY = formatCheckpoint(ORIGIN, 7, ROOT);

describe('parseCheckpoint', () => {
  it('reads the exact form', () => {
    expect(BODY).toBe(`${ORIGIN}\n7\n${Buffer.from(ROOT, 'hex').toString('base64')}\n`);
    expect(parseCheckpoint(BODY)).toEqual({ ok: true, checkpoint: { origin: ORIGIN, size: 7, root: ROOT, body: BODY } });
  });

  const lines = BODY.slice(0, -1).split('\n');
  it.each([
    ['not_a_string', undefined],
    ['not_a_string', Buffer.from(BODY)],
    ['carriage_return', BODY.replace(/\n/g, '\r\n')],
    ['carriage_return', `${lines[0]}\n7\r\n${lines[2]}\n`],
    ['missing_final_newline', BODY.slice(0, -1)],
    ['extension_lines', `${BODY}ext\n`],
    ['extension_lines', `${BODY}\n`],
    ['too_few_lines', `${lines[0]}\n7\n`],
    ['too_few_lines', '\n'],
    ['malformed_origin', `\n7\n${lines[2]}\n`],
    ['malformed_origin', `a b\n7\n${lines[2]}\n`],
    ['malformed_origin', `a+b\n7\n${lines[2]}\n`],
    ['malformed_origin', `café\n7\n${lines[2]}\n`],
    ['malformed_size', `${lines[0]}\n07\n${lines[2]}\n`],
    ['malformed_size', `${lines[0]}\n-7\n${lines[2]}\n`],
    ['malformed_size', `${lines[0]}\n7.0\n${lines[2]}\n`],
    ['malformed_size', `${lines[0]}\n\n${lines[2]}\n`],
    ['size_out_of_range', `${lines[0]}\n0\n${lines[2]}\n`],
    ['size_out_of_range', `${lines[0]}\n9007199254740992\n${lines[2]}\n`],
    ['size_out_of_range', `${lines[0]}\n${'9'.repeat(40)}\n${lines[2]}\n`],
    ['malformed_root', `${lines[0]}\n7\n${lines[2].slice(0, -1)}\n`],
    ['malformed_root', `${lines[0]}\n7\n${ROOT}\n`],
    ['malformed_root', `${lines[0]}\n7\n${Buffer.alloc(48).toString('base64')}\n`],
  ])('refuses with %s', (reason, body) => {
    expect(parseCheckpoint(body)).toEqual({ ok: false, reason });
  });

  it('accepts the largest safe size (one more is in the table above)', () => {
    expect(parseCheckpoint(`${lines[0]}\n9007199254740991\n${lines[2]}\n`).ok).toBe(true);
  });

  it('refuses a root whose last base64 digit carries unused bits', () => {
    // 32 bytes leave two unused bits in the 43rd digit; a lenient decoder
    // reads "…E=" and "…F=" as the same bytes.
    const canonical = lines[2];
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const last = alphabet.indexOf(canonical[42]);
    const sibling = canonical.slice(0, 42) + alphabet[last | 1] + '=';
    expect(Buffer.from(sibling, 'base64').equals(Buffer.from(canonical, 'base64'))).toBe(true);
    expect(parseCheckpoint(`${lines[0]}\n7\n${sibling}\n`)).toEqual({ ok: false, reason: 'malformed_root' });
  });
});

describe('formatCheckpoint and checkpointDigest', () => {
  it('lowercases the root it is given', () => {
    expect(formatCheckpoint(ORIGIN, 7, ROOT.toUpperCase())).toBe(BODY);
  });

  it.each([
    ['an empty origin', '', 7, ROOT],
    ['an origin with a space', 'a b', 7, ROOT],
    ['size 0', ORIGIN, 0, ROOT],
    ['a fractional size', ORIGIN, 1.5, ROOT],
    ['an unsafe size', ORIGIN, 2 ** 53, ROOT],
    ['a short root', ORIGIN, 7, 'ab'],
    ['a root with 0x', ORIGIN, 7, '0x' + ROOT.slice(2)],
  ])('refuses %s', (_name, origin, size, root) => {
    expect(() => formatCheckpoint(origin as string, size as number, root as string)).toThrow();
  });

  it('hashes exactly the body bytes', () => {
    const { createHash } = require('crypto');
    expect(checkpointDigest(BODY)).toBe(createHash('sha256').update(BODY).digest('hex'));
  });

  it('refuses to hash anything that is not a body', () => {
    expect(() => checkpointDigest(BODY.slice(0, -1))).toThrow(/missing_final_newline/);
    expect(() => checkpointDigest(42 as unknown as string)).toThrow(/not_a_string/);
  });
});

describe('origins', () => {
  const PREFIX = 'local.invalid/3f2a9c0e5b7d4e1f8a6c2b9d0e4f7a1c';

  it('writes the three SDK forms', () => {
    expect(anchorLogOrigin(PREFIX)).toBe(`${PREFIX}/anchors`);
    expect(evidenceLogOrigin(PREFIX, 'default')).toBe(`${PREFIX}/evidence/64656661756c74`);
    expect(parseOrigin(`${PREFIX}/anchors`)).toEqual({ kind: 'anchors', domainPrefix: PREFIX, namespace: 'local.invalid' });
    expect(parseOrigin(`${PREFIX}/evidence/64656661756c74`)).toEqual({
      kind: 'evidence',
      domainPrefix: PREFIX,
      namespace: 'local.invalid',
      chainId: 'default',
    });
    expect(parseOrigin(`${PREFIX}/k2`)).toEqual({ kind: 'log', domainPrefix: PREFIX, namespace: 'local.invalid', name: 'k2' });
  });

  it.each([
    ['one segment', 'local.invalid'],
    ['a two-segment prefix only', PREFIX],
    ['evidence with no chain', `${PREFIX}/evidence`],
    ['a trailing slash', `${PREFIX}/anchors/`],
    ['a non-evidence four-segment origin', `${PREFIX}/k2/64`],
    ['a non-canonical chain segment', `${PREFIX}/evidence/64656661756C74`],
    ['not a string', 7],
  ])('reads %s as no origin', (_name, origin) => {
    expect(parseOrigin(origin)).toBeNull();
  });

  it('refuses a malformed domain prefix when writing', () => {
    expect(() => anchorLogOrigin('local.invalid')).toThrow();
    expect(() => anchorLogOrigin(`${PREFIX}/x`)).toThrow();
    expect(() => evidenceLogOrigin('a b/c', 'default')).toThrow();
    expect(() => sourceLogOrigin('local.invalid', 'k2')).toThrow();
  });

  it('writes a source log named by one segment, and reads it back', () => {
    expect(sourceLogOrigin(PREFIX, 'custody')).toBe(`${PREFIX}/custody`);
    expect(parseOrigin(sourceLogOrigin(PREFIX, 'custody'))).toEqual({
      kind: 'log',
      domainPrefix: PREFIX,
      namespace: 'local.invalid',
      name: 'custody',
    });
    const platform = `${PLATFORM_NAMESPACE}/0f1e2d3c4b5a69788796a5b4c3d2e1f0`;
    expect(sourceLogOrigin(platform, 'a1b2c3d4e5f60718293a4b5c6d7e8f90')).toBe(`${platform}/a1b2c3d4e5f60718293a4b5c6d7e8f90`);
    for (const name of ['anchors', 'evidence', '', 'a/b', 'a b', 'a+b', '\u00e9', 7]) {
      expect(() => sourceLogOrigin(PREFIX, name as string)).toThrow(/one segment of origin text/);
    }
  });

  it('refuses a value that is not a chain id, with the reason a store gives', () => {
    expect(() => chainSegment('\ud800')).toThrow(TypeError);
    expect(() => chainSegment('\ud800')).toThrow(/lone UTF-16 surrogate/);
    expect(() => chainSegment('a\u0000b')).toThrow(/U\+0000/);
    expect(() => chainSegment('')).toThrow(/non-empty chain id/);
    expect(() => chainSegment(7 as unknown as string)).toThrow(TypeError);
    expect(chainIdRefusal('')).toBe('empty_chain_id');
    for (const bad of ['\ud800', 'a\udc00', '\ude00\ud83d', '\u0000', 'a\u0000b', 7, null, undefined]) {
      expect(chainIdRefusal(bad)).toBe('invalid_chain_id');
    }
    for (const good of ['default', '\ud83d\udd12', '\ufeffa', ' ', 'a/b+c']) expect(chainIdRefusal(good)).toBeNull();
  });

  it('reads no chain id from a segment with a 0x00 byte', () => {
    expect(chainIdFromSegment('00')).toBeNull();
    expect(chainIdFromSegment('610062')).toBeNull();
    expect(parseOrigin(`${PREFIX}/evidence/610062`)).toBeNull();
    expect(checkOriginBinding(`${PREFIX}/anchors`, `${PREFIX}/evidence/610062`)).toEqual({
      ok: false,
      reason: 'origin_not_in_domain',
    });
  });

  it('keeps a leading U+FEFF in the chain id', () => {
    expect(chainIdFromSegment('efbbbf61')).toBe('﻿a');
  });

  it('knows a test namespace by its prefix only', () => {
    expect(isTestNamespace('test.tzun.dev')).toBe(true);
    expect(isTestNamespace('test')).toBe(false);
    expect(isTestNamespace('local.invalid')).toBe(false);
    expect(isTestNamespace('log.tzun.ai')).toBe(false);
    expect(isTestNamespace(undefined)).toBe(false);
  });

  it("knows the platform's two namespaces exactly, and nothing that extends them", () => {
    expect(isPlatformNamespace(PLATFORM_NAMESPACE)).toBe(true);
    expect(isPlatformNamespace('log.tzun.ai')).toBe(true);
    expect(isPlatformNamespace('test.log.tzun.ai')).toBe(true);
    for (const other of ['test.log.tzun.ai.example', 'log.tzun.ai.example', 'x.log.tzun.ai', 'test.test.log.tzun.ai', 'LOG.TZUN.AI', 'local.invalid', 'test.tzun.dev', '', undefined, null, 7]) {
      expect(isPlatformNamespace(other)).toBe(false);
    }
  });

  it('origin text excludes space, "+" and anything outside printable ASCII', () => {
    expect(isOriginText('a/b.c-d_e~f')).toBe(true);
    for (const bad of ['', ' ', 'a+b', 'a\tb', '\u00e9', '\x7f']) expect(isOriginText(bad)).toBe(false);
  });

  it("with a chain id supplied, the log must be that chain's evidence log, except under the platform's opaque origins", () => {
    const anchors = `${PREFIX}/anchors`;
    // An SDK source log of another kind never holds a record's leaf.
    expect(checkOriginBinding(anchors, `${PREFIX}/custody`, 'default')).toEqual({ ok: false, reason: 'chain_id_mismatch' });
    expect(checkOriginBinding(anchors, `${PREFIX}/custody`, null)).toEqual({
      ok: true,
      namespace: 'local.invalid',
      chainChecked: false,
    });
    const test = 'test.tzun.dev/3f2a9c0e5b7d4e1f8a6c2b9d0e4f7a1c';
    expect(checkOriginBinding(`${test}/anchors`, `${test}/k2`, 'default')).toEqual({ ok: false, reason: 'chain_id_mismatch' });

    expect(PLATFORM_NAMESPACE).toBe('log.tzun.ai');
    const platform = `${PLATFORM_NAMESPACE}/0f1e2d3c4b5a69788796a5b4c3d2e1f0`;
    expect(checkOriginBinding(`${platform}/anchors`, `${platform}/a1b2c3d4e5f60718293a4b5c6d7e8f90`, 'user-abc')).toEqual({
      ok: true,
      namespace: PLATFORM_NAMESPACE,
      chainChecked: false,
    });
    // Only the platform namespace itself is opaque.
    const lookalike = 'log.tzun.ai.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0';
    expect(checkOriginBinding(`${lookalike}/anchors`, `${lookalike}/k2`, 'user-abc')).toEqual({
      ok: false,
      reason: 'chain_id_mismatch',
    });
  });

  it('treats the platform test namespace, test.log.tzun.ai, exactly as log.tzun.ai (tzun-anchor/1 §4.3.4)', () => {
    const platformTest = 'test.log.tzun.ai/0f1e2d3c4b5a69788796a5b4c3d2e1f0';
    const opaque = `${platformTest}/a1b2c3d4e5f60718293a4b5c6d7e8f90`;
    for (const chainId of ['user-abc', null, undefined]) {
      expect(checkOriginBinding(`${platformTest}/anchors`, opaque, chainId)).toEqual({
        ok: true,
        namespace: 'test.log.tzun.ai',
        chainChecked: false,
      });
    }
    // An evidence origin under it still names its chain, and the chain is compared.
    const evidence = evidenceLogOrigin(platformTest, 'default');
    expect(checkOriginBinding(`${platformTest}/anchors`, evidence, 'default')).toEqual({
      ok: true,
      namespace: 'test.log.tzun.ai',
      chainChecked: true,
    });
    expect(checkOriginBinding(`${platformTest}/anchors`, evidence, 'other')).toEqual({ ok: false, reason: 'chain_id_mismatch' });
    // Only those two namespaces are the platform's: a name that extends either,
    // or sits under the platform's name, is an SDK namespace.
    for (const ns of ['test.log.tzun.ai.example', 'staging.log.tzun.ai', 'test.staging.log.tzun.ai', 'test.test.log.tzun.ai']) {
      const prefix = `${ns}/0f1e2d3c4b5a69788796a5b4c3d2e1f0`;
      expect(checkOriginBinding(`${prefix}/anchors`, `${prefix}/k2`, 'user-abc')).toEqual({ ok: false, reason: 'chain_id_mismatch' });
    }
  });

  it('a supplied chain id that is not a string matches no evidence log', () => {
    const log = evidenceLogOrigin(PREFIX, 'default');
    expect(checkOriginBinding(`${PREFIX}/anchors`, log, 7)).toEqual({ ok: false, reason: 'chain_id_mismatch' });
    expect(checkOriginBinding(`${PREFIX}/anchors`, log, '')).toEqual({ ok: false, reason: 'chain_id_mismatch' });
    expect(checkOriginBinding(`${PREFIX}/anchors`, log, undefined)).toEqual({
      ok: true,
      namespace: 'local.invalid',
      chainChecked: false,
    });
  });
});

describe('no reader throws', () => {
  const junk: unknown[] = [
    undefined,
    null,
    0,
    NaN,
    '',
    '\n\n\n',
    [],
    {},
    Symbol('x'),
    () => 1,
    'x'.repeat(100_000),
    '\ud800\n1\nAA==\n',
  ];
  it.each(junk.map((j, i) => [i, j] as const))('junk #%i', (_i, j) => {
    expect(() => parseCheckpoint(j)).not.toThrow();
    expect(() => parseOrigin(j)).not.toThrow();
    expect(() => chainIdFromSegment(j)).not.toThrow();
    expect(() => checkOriginBinding(j, j, j)).not.toThrow();
    expect(() => isOriginText(j)).not.toThrow();
    expect(parseCheckpoint(j).ok).toBe(false);
  });
});
