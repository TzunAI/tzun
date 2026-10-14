import { createHash } from 'crypto';

/**
 * Checkpoint bodies and the origins they name: tzun-anchor/1 §4 (origins:
 * §4.3; the checkpoint digest: §4.4). Vectors: vectors/checkpoint-vectors.json,
 * written by scripts/generate-checkpoint-vectors.mjs, which imports nothing
 * from here.
 *
 * This module is the one implementation of the origin grammar
 * (tzun-anchor/1 §4.3): the chain-id rule, the chain segment, the three forms
 * a domain writes and the reader. src/storage/log-store.ts adds the store's
 * own rules (`ns`, store id, per-store kinds) and builds its origins with the
 * functions here.
 *
 * A checkpoint body is the note text of a C2SP `tlog-checkpoint`:
 *
 *     <origin>\n<tree size, ASCII decimal>\n<root, RFC 4648 §4 base64 with padding>\n
 *
 * C2SP defines a checkpoint as a signed note. Tzun checkpoints carry no
 * signature until a log key exists, so everything here is about the
 * body alone, and the word "checkpoint" in this module means the body.
 * Signatures are signed-note lines after the body and never change it.
 *
 * Tzun reads the body more strictly than C2SP requires. Anything but the exact
 * form above is refused: CR anywhere, a missing final newline, leading zeros
 * in the size, a size of 0, a size above 2^53 − 1, a root that is not
 * canonical base64 of exactly 32 bytes, and any extension line.
 *
 * Every parser here takes `unknown` and never throws: bodies and origins
 * arrive inside artifacts, and a malformed one is a reported verdict.
 */

/** Why a checkpoint body was refused. Every reason reads as `malformed_checkpoint` in a verdict. */
export type CheckpointMalformedReason =
  /** The body is not a string. */
  | 'not_a_string'
  /** A CR (0x0D) appears: line endings are LF only. */
  | 'carriage_return'
  /** The body does not end in LF. */
  | 'missing_final_newline'
  /** The body has more than three lines: C2SP extension lines are not accepted. */
  | 'extension_lines'
  /** The body has fewer than three lines. */
  | 'too_few_lines'
  /** The origin line is empty, or holds a byte outside 0x21–0x7E, or a `+`. */
  | 'malformed_origin'
  /** The size line is not ASCII decimal digits, or has a leading zero. */
  | 'malformed_size'
  /** The size is 0 (Tzun never cuts a checkpoint of an empty log) or above 2^53 − 1. */
  | 'size_out_of_range'
  /** The root line is not canonical padded base64, or does not decode to 32 bytes. */
  | 'malformed_root';

/** A checkpoint body that parsed. */
export interface Checkpoint {
  origin: string;
  /** The tree size, at least 1. */
  size: number;
  /** The root hash, 64 lowercase hex digits. */
  root: string;
  /** The body exactly as parsed. `checkpointDigest(body)` is its leaf in an anchor log. */
  body: string;
}

export type CheckpointParseResult =
  | { ok: true; checkpoint: Checkpoint }
  | { ok: false; reason: CheckpointMalformedReason };

/** Printable ASCII other than space and `+`: 0x21–0x2A and 0x2C–0x7E. */
const ORIGIN_TEXT = /^[\x21-\x2a\x2c-\x7e]+$/;
const SIZE_TEXT = /^(0|[1-9][0-9]*)$/;
/** 32 bytes of padded base64 is 43 characters and one `=`. */
const ROOT_TEXT = /^[A-Za-z0-9+/]{43}=$/;
const HEX_64 = /^[0-9a-f]{64}$/;

/**
 * Whether `origin` is text a Tzun origin may be made of: non-empty printable
 * ASCII with no space and no `+`. C2SP recommends the same set.
 */
export function isOriginText(origin: unknown): origin is string {
  return typeof origin === 'string' && ORIGIN_TEXT.test(origin);
}

/**
 * Parse a checkpoint body under the exact form. Never throws.
 */
export function parseCheckpoint(body: unknown): CheckpointParseResult {
  if (typeof body !== 'string') return { ok: false, reason: 'not_a_string' };
  if (body.includes('\r')) return { ok: false, reason: 'carriage_return' };
  if (!body.endsWith('\n')) return { ok: false, reason: 'missing_final_newline' };
  const lines = body.slice(0, -1).split('\n');
  if (lines.length > 3) return { ok: false, reason: 'extension_lines' };
  if (lines.length < 3) return { ok: false, reason: 'too_few_lines' };
  const [origin, sizeText, rootText] = lines;

  if (!isOriginText(origin)) return { ok: false, reason: 'malformed_origin' };

  if (!SIZE_TEXT.test(sizeText)) return { ok: false, reason: 'malformed_size' };
  // Digits only, so the only way past MAX_SAFE_INTEGER is by length or value.
  const size = sizeText.length > 16 ? Number.POSITIVE_INFINITY : Number(sizeText);
  if (!(size >= 1 && size <= Number.MAX_SAFE_INTEGER)) return { ok: false, reason: 'size_out_of_range' };

  if (!ROOT_TEXT.test(rootText)) return { ok: false, reason: 'malformed_root' };
  const rootBytes = Buffer.from(rootText, 'base64');
  // Node decodes base64 leniently. Re-encoding pins the one canonical spelling:
  // the last character before `=` must leave its two low bits clear.
  if (rootBytes.length !== 32 || rootBytes.toString('base64') !== rootText) {
    return { ok: false, reason: 'malformed_root' };
  }

  return { ok: true, checkpoint: { origin, size, root: rootBytes.toString('hex'), body } };
}

/**
 * The body of the checkpoint of `origin` at `size` with root `root` (64 hex
 * digits, either case).
 *
 * @throws when the origin is not origin text, the size is not a safe integer of
 *         at least 1, or the root is not 64 hex digits. A writer that cannot
 *         produce a valid body has a bug to surface, not a verdict to report.
 */
export function formatCheckpoint(origin: string, size: number, root: string): string {
  if (!isOriginText(origin)) {
    throw new Error('Checkpoint origin must be non-empty printable ASCII with no space and no "+".');
  }
  if (!Number.isSafeInteger(size) || size < 1) {
    throw new Error('Checkpoint size must be a safe integer of at least 1.');
  }
  const rootHex = typeof root === 'string' ? root.toLowerCase() : '';
  if (!HEX_64.test(rootHex)) {
    throw new Error('Checkpoint root must be 64 hex digits.');
  }
  return `${origin}\n${size}\n${Buffer.from(rootHex, 'hex').toString('base64')}\n`;
}

/**
 * `SHA-256(body)`, 64 lowercase hex digits (tzun-anchor/1 §4.4): a
 * checkpoint's leaf in the anchor log (tzun-anchor/1 §5), and, for the anchor
 * log's own checkpoint, the published value P (tzun-anchor/1 §6). Signatures
 * are never part of the body, so they never change it.
 *
 * @throws when `body` is not a valid checkpoint body, so no caller can hash a
 *         string that no verifier would accept as one.
 */
export function checkpointDigest(body: string): string {
  const parsed = parseCheckpoint(body);
  if (!parsed.ok) {
    throw new Error(`Not a checkpoint body (${parsed.reason}).`);
  }
  return createHash('sha256').update(body, 'utf8').digest('hex');
}

// ---- Origins -----------------------------------------------------------------

/** The last segment of every anchor-log origin. */
export const ANCHOR_LOG_KIND = 'anchors' as const;
/** The segment before the chain segment of every SDK evidence-log origin. */
export const EVIDENCE_LOG_KIND = 'evidence' as const;
/** A namespace beginning with this names a test origin (tzun-anchor/1 §4.3.4). */
export const TEST_NAMESPACE_PREFIX = 'test.' as const;
/**
 * The platform's namespace (tzun-anchor/1 §4.3.3):
 * `log.tzun.ai/<deploymentId>/…`. Its source-log origins are opaque, so no
 * chain can be read from them. A platform deployment that anchors in the test
 * namespace uses `test.log.tzun.ai` (tzun-anchor/1 §4.3.4), which step 2b of
 * tzun-anchor/1 §10.3 treats the same way.
 */
export const PLATFORM_NAMESPACE = 'log.tzun.ai' as const;

/** The platform's two namespaces: production, and test (tzun-anchor/1 §4.3.4). */
const PLATFORM_NAMESPACES: ReadonlySet<string> = new Set([PLATFORM_NAMESPACE, `${TEST_NAMESPACE_PREFIX}${PLATFORM_NAMESPACE}`]);

const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const CHAIN_SEGMENT = /^(?:[0-9a-f]{2})+$/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Why a value is not a chain id, and so names no evidence log. */
export type ChainIdRefusalReason = 'empty_chain_id' | 'invalid_chain_id';

/**
 * Why `chainId` is not a chain id, or `null` when it is one (tzun-anchor/1
 * §4.3.2): a chain id is a non-empty string of Unicode scalar values other
 * than U+0000. Never throws.
 *
 *   - `empty_chain_id`: the empty string;
 *   - `invalid_chain_id`: not a string, or a string holding a lone UTF-16
 *     surrogate or U+0000. A lone surrogate has no UTF-8 encoding, and
 *     drivers do not agree on what to write for one: better-sqlite3 writes
 *     its WTF-8 bytes, which no reader takes as a chain segment, and node-pg
 *     writes U+FFFD, which is another chain id's bytes. U+0000 cannot be
 *     stored in Postgres `text` while SQLite stores it, so the two dialects
 *     could not name one log for it (Anchor §4.3.2).
 *
 * A store refuses such a chain id with this reason (`EvidenceLogRefusalError`).
 */
export function chainIdRefusal(chainId: unknown): ChainIdRefusalReason | null {
  if (typeof chainId !== 'string') return 'invalid_chain_id';
  if (chainId === '') return 'empty_chain_id';
  if (LONE_SURROGATE.test(chainId) || chainId.includes('\u0000')) return 'invalid_chain_id';
  return null;
}

/**
 * The chain segment of an SDK evidence-log origin: the lowercase hex of the
 * chain id's UTF-8 bytes (`default` → `64656661756c74`). No normalisation: two
 * spellings of one character are two chains and two segments. One spelling
 * per chain id, computable in SQLite (`lower(hex(chain_id))`) and Postgres
 * (`encode(convert_to(chain_id, 'UTF8'), 'hex')`).
 *
 * @throws {TypeError} for a value `chainIdRefusal` refuses: not a string,
 *   empty, or holding a lone UTF-16 surrogate or U+0000.
 */
export function chainSegment(chainId: string): string {
  const refusal = chainIdRefusal(chainId);
  if (refusal === 'empty_chain_id') throw new TypeError('an evidence log needs a non-empty chain id');
  if (refusal !== null) {
    throw new TypeError(
      'a chain id is a string of Unicode scalar values other than U+0000; this one is not a string, or holds a lone UTF-16 surrogate or U+0000',
    );
  }
  return Buffer.from(chainId, 'utf8').toString('hex');
}

/**
 * The chain id a chain segment spells, or `null` when the segment is not the
 * one spelling `chainSegment` produces for a chain id (the reader's rule of
 * tzun-anchor/1 §4.3.2): empty, odd-length, uppercase, not hex, bytes that
 * are not strict UTF-8 (overlong forms, surrogates, a leading byte-order mark
 * that a lenient decoder would drop), or a 0x00 byte. Never throws.
 */
export function chainIdFromSegment(segment: unknown): string | null {
  if (typeof segment !== 'string' || !CHAIN_SEGMENT.test(segment)) return null;
  const bytes = Buffer.from(segment, 'hex');
  let chainId: string;
  try {
    chainId = UTF8_STRICT.decode(bytes);
  } catch {
    return null;
  }
  if (chainIdRefusal(chainId) !== null) return null;
  return Buffer.from(chainId, 'utf8').toString('hex') === segment ? chainId : null;
}

/** An origin read under the tzun-anchor/1 §4.3 scheme. */
export type TzunOrigin =
  | { kind: 'anchors'; domainPrefix: string; namespace: string }
  | { kind: 'evidence'; domainPrefix: string; namespace: string; chainId: string }
  | { kind: 'log'; domainPrefix: string; namespace: string; name: string };

/**
 * Read an origin under the tzun-anchor/1 §4.3 scheme, or `null` when it is
 * not one. Never throws.
 *
 * Every origin is `<domain prefix>/<rest>`. The domain prefix is two segments:
 * `<ns>/<storeId>` for an SDK store, `log.tzun.ai/<deploymentId>` for a
 * platform deployment. The rest is one of:
 *
 * - `anchors`: the domain's anchor log;
 * - `evidence/<chain segment>`: an SDK evidence log, one per chain;
 * - one other segment: an SDK source log named by its kind, or a platform log
 *   under an opaque id. `evidence` alone is not one, because an evidence log
 *   always names its chain.
 *
 * Every segment is non-empty origin text without `/`.
 */
export function parseOrigin(origin: unknown): TzunOrigin | null {
  if (!isOriginText(origin)) return null;
  const segments = origin.split('/');
  if (segments.some((s) => s.length === 0)) return null;
  if (segments.length < 3 || segments.length > 4) return null;
  const namespace = segments[0];
  const domainPrefix = `${segments[0]}/${segments[1]}`;
  const rest = segments.slice(2);

  if (rest.length === 2) {
    if (rest[0] !== EVIDENCE_LOG_KIND) return null;
    const chainId = chainIdFromSegment(rest[1]);
    return chainId === null ? null : { kind: 'evidence', domainPrefix, namespace, chainId };
  }
  if (rest[0] === ANCHOR_LOG_KIND) return { kind: 'anchors', domainPrefix, namespace };
  if (rest[0] === EVIDENCE_LOG_KIND) return null;
  return { kind: 'log', domainPrefix, namespace, name: rest[0] };
}

function assertDomainPrefix(domainPrefix: string): void {
  const segments = typeof domainPrefix === 'string' ? domainPrefix.split('/') : [];
  if (segments.length !== 2 || !segments.every(isOriginText)) {
    throw new Error('A domain prefix is two non-empty segments of origin text: "<ns>/<id>".');
  }
}

/** The anchor-log origin of a domain: `<domain prefix>/anchors`. @throws on a malformed prefix. */
export function anchorLogOrigin(domainPrefix: string): string {
  assertDomainPrefix(domainPrefix);
  return `${domainPrefix}/${ANCHOR_LOG_KIND}`;
}

/**
 * The SDK evidence-log origin of a chain: `<domain prefix>/evidence/<chain segment>`.
 * @throws on a malformed prefix or chain id.
 */
export function evidenceLogOrigin(domainPrefix: string, chainId: string): string {
  assertDomainPrefix(domainPrefix);
  return `${domainPrefix}/${EVIDENCE_LOG_KIND}/${chainSegment(chainId)}`;
}

/**
 * The origin of a source log named by one segment: `<domain prefix>/<name>`,
 * an SDK source log of kind `name` (tzun-anchor/1 §4.3.2) or a platform log
 * under an opaque id (tzun-anchor/1 §4.3.3).
 * @throws on a malformed prefix, or a name that is not one segment of origin
 *         text, or is `anchors` or `evidence`.
 */
export function sourceLogOrigin(domainPrefix: string, name: string): string {
  assertDomainPrefix(domainPrefix);
  if (!isOriginText(name) || name.includes('/') || name === ANCHOR_LOG_KIND || name === EVIDENCE_LOG_KIND) {
    throw new Error('A source-log name is one segment of origin text other than "anchors" and "evidence".');
  }
  return `${domainPrefix}/${name}`;
}

/** Whether a namespace names a test origin: it begins with `test.`. */
export function isTestNamespace(namespace: unknown): boolean {
  return typeof namespace === 'string' && namespace.startsWith(TEST_NAMESPACE_PREFIX);
}

/**
 * Whether a namespace is one of the platform's two (tzun-anchor/1 §4.3.3,
 * §4.3.4): exactly `log.tzun.ai`, or `test.log.tzun.ai` for a platform
 * deployment that anchors in the test namespace. A name that extends either
 * (`test.log.tzun.ai.example`) is not. A source log under either names its
 * log by an opaque id, so no chain can be read from its origin. Never throws.
 */
export function isPlatformNamespace(namespace: unknown): boolean {
  return typeof namespace === 'string' && PLATFORM_NAMESPACES.has(namespace);
}

/** Why an anchor origin and a log origin do not bind (tzun-anchor/1 §10.3 step 2b). */
export type OriginBindingReason =
  /**
   * The anchor origin is not `<ns>/<id>/anchors`, or the log origin is not a
   * source log that the same domain names: a different domain prefix, another
   * anchor log, or a string the tzun-anchor/1 §4.3 scheme does not produce
   * (an uppercase or otherwise non-canonical chain segment included).
   */
  | 'origin_not_in_domain'
  /**
   * A chain id was supplied, and the log is not that chain's evidence log: an
   * evidence log for another chain, or, outside the platform's namespaces
   * (`log.tzun.ai` and `test.log.tzun.ai`), a source log of another kind. On
   * an SDK store a record's leaf is only ever in its chain's evidence log.
   */
  | 'chain_id_mismatch';

export type OriginBinding =
  | {
      ok: true;
      /** The anchor origin's namespace, the first segment of its domain prefix. */
      namespace: string;
      /** `true` only when a chain id was supplied and the log is an evidence log naming it. */
      chainChecked: boolean;
    }
  | { ok: false; reason: OriginBindingReason };

/**
 * tzun-anchor/1 §10.3 step 2b (origin binding, §4.3.5): does the log origin
 * belong to the anchor origin's domain, and is it the evidence log of the
 * chain supplied? Never throws.
 *
 * - No chain id (`undefined` or `null`): the chain is unchecked.
 * - A chain id and an evidence log: its chain segment must spell that chain
 *   id, or `chain_id_mismatch`. A chain id that is not a non-empty string
 *   matches no evidence log.
 * - A chain id and a platform source log (`log.tzun.ai/<id>/<opaque id>`, or
 *   `test.log.tzun.ai/<id>/<opaque id>` for a platform test deployment): the
 *   origin is opaque, so the chain is unchecked. Only those two namespaces
 *   are the platform's; a name that extends either is not.
 * - A chain id and any other source log: `chain_id_mismatch`, because on an
 *   SDK store a record's leaf is only ever in its chain's evidence log.
 */
export function checkOriginBinding(anchorOrigin: unknown, logOrigin: unknown, chainId?: unknown): OriginBinding {
  const anchor = parseOrigin(anchorOrigin);
  const log = parseOrigin(logOrigin);
  if (!anchor || anchor.kind !== 'anchors' || !log || log.kind === 'anchors') {
    return { ok: false, reason: 'origin_not_in_domain' };
  }
  if (log.domainPrefix !== anchor.domainPrefix) return { ok: false, reason: 'origin_not_in_domain' };

  let chainChecked = false;
  if (chainId !== undefined && chainId !== null) {
    if (log.kind === 'evidence') {
      if (chainId !== log.chainId) return { ok: false, reason: 'chain_id_mismatch' };
      chainChecked = true;
    } else if (!isPlatformNamespace(log.namespace)) {
      return { ok: false, reason: 'chain_id_mismatch' };
    }
  }
  return { ok: true, namespace: anchor.namespace, chainChecked };
}
