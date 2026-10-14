// Generate vectors/checkpoint-vectors.json.
//
// INDEPENDENT PIN. This script imports nothing but node:crypto. Every rule it
// applies is transcribed here from the text that defines it, not from the SDK:
//
//   - the checkpoint body: C2SP tlog-checkpoint, read under the exact form of
//     tzun-anchor/1 §4.1 and §4.2:
//         <origin>\n<size, ASCII decimal>\n<root, RFC 4648 §4 base64, padded>\n
//     LF only, a final newline, no leading zeros, size ≥ 1 (and ≤ 2^53 − 1,
//     the largest size a JSON number carries exactly), canonical base64 of
//     32 bytes, no extension lines, origin of printable ASCII with no space
//     and no "+";
//   - base64: RFC 4648 §4, encoded and decoded by hand below;
//   - the chain segment: lowercase hex of the chain id's UTF-8 bytes, with
//     UTF-8 encoded and strictly decoded by hand under RFC 3629. A chain id
//     is a non-empty string of Unicode scalar values other than U+0000, and
//     a chain segment whose bytes include 0x00 is not a Tzun origin
//     (tzun-anchor/1 §4.3.2);
//   - the origin scheme and the domain rule: tzun-anchor/1 §4.3 and §10.3
//     step 2b, with the platform's two namespaces, log.tzun.ai and
//     test.log.tzun.ai (tzun-anchor/1 §4.3.3, §4.3.4);
//   - the trees: RFC 6962 §2.1 MTH and §2.1.1 PATH, written recursively;
//   - the anchor log: tzun-anchor/1 §4.4 and §5 (leaf = SHA-256(checkpoint
//     body); members of an epoch appended in ascending bytewise origin order)
//     and §6 (P = SHA-256(anchor checkpoint body));
//   - the record artifact (tzun-anchor/1 §8.1) and §10.3 steps 1 to 5, plus
//     the step 6 dispatch of each publication, the §10.6 reason, and the
//     §10.7 check catalogue each case reports (ids, outcomes, reasons and
//     facts, in report order);
//   - two readings of every invalid body, each its own transcription: C2SP
//     tlog-checkpoint with signed-note v1.0.0, and the stock Go parser
//     (transparency-dev/formats log.Checkpoint.Unmarshal at v0.1.1, with Go's
//     strconv.ParseUint and base64.StdEncoding).
//
// The SDK implementation these vectors pin (src/attestation/checkpoint.ts,
// src/attestation/anchor-verify.ts) uses Buffer's base64, TextDecoder and the
// engine's iterative Merkle code. Every expected outcome below is also
// re-derived by this script's own transcription of §10.3 before it is written,
// so a case whose stated outcome the transcription disagrees with stops the
// script, and the catalogue of one case of each shape is stated by hand and
// held to the transcription the same way.
//
// scripts/regenerate-vectors.ts does not and must not rewrite this file.
//
// Run: node scripts/generate-checkpoint-vectors.mjs > vectors/checkpoint-vectors.json
import { createHash } from 'node:crypto';

const sha256 = (buf) => createHash('sha256').update(buf).digest();
const sha256Text = (text) => sha256(Buffer.from(text, 'latin1'));
const hex = (b) => b.toString('hex');

// ---- RFC 4648 §4 base64 -------------------------------------------------------

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function base64Encode(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
    out += i + 1 < bytes.length ? B64[(n >> 6) & 63] : '=';
    out += i + 2 < bytes.length ? B64[n & 63] : '=';
  }
  return out;
}

/** Strict decode: alphabet, padding and length are exact, and unused bits are zero. Null otherwise. */
function base64DecodeStrict(text) {
  if (text.length === 0 || text.length % 4 !== 0) return null;
  const pad = text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0;
  const body = text.slice(0, text.length - pad);
  const bits = [];
  for (const c of body) {
    const v = B64.indexOf(c);
    if (v < 0) return null;
    bits.push(v);
  }
  const bytes = [];
  let acc = 0;
  let nbits = 0;
  for (const v of bits) {
    acc = (acc << 6) | v;
    nbits += 6;
    if (nbits >= 8) {
      nbits -= 8;
      bytes.push((acc >> nbits) & 0xff);
    }
  }
  // Leftover bits must be zero for the one canonical spelling.
  if (nbits > 0 && (acc & ((1 << nbits) - 1)) !== 0) return null;
  const decoded = Buffer.from(bytes);
  return base64Encode(decoded) === text ? decoded : null;
}

// ---- RFC 3629 UTF-8 -------------------------------------------------------------

function utf8Encode(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let cp = str.charCodeAt(i);
    if (cp >= 0xd800 && cp <= 0xdbff) {
      const lo = str.charCodeAt(i + 1);
      if (!(lo >= 0xdc00 && lo <= 0xdfff)) throw new Error('lone high surrogate');
      cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
      i++;
    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
      throw new Error('lone low surrogate');
    }
    if (cp < 0x80) out.push(cp);
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
  }
  return Buffer.from(out);
}

/** Strict RFC 3629 decode: no overlong forms, no surrogates, nothing above U+10FFFF. Null otherwise. */
function utf8DecodeStrict(bytes) {
  let out = '';
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i];
    let cp;
    let need;
    let min;
    if (b0 < 0x80) [cp, need, min] = [b0, 0, 0];
    else if (b0 >= 0xc2 && b0 <= 0xdf) [cp, need, min] = [b0 & 0x1f, 1, 0x80];
    else if (b0 >= 0xe0 && b0 <= 0xef) [cp, need, min] = [b0 & 0x0f, 2, 0x800];
    else if (b0 >= 0xf0 && b0 <= 0xf4) [cp, need, min] = [b0 & 0x07, 3, 0x10000];
    else return null;
    for (let k = 1; k <= need; k++) {
      const b = bytes[i + k];
      if (b === undefined || (b & 0xc0) !== 0x80) return null;
      cp = (cp << 6) | (b & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return null;
    out += String.fromCodePoint(cp);
    i += need + 1;
  }
  return out;
}

// ---- Checkpoint bodies ------------------------------------------------------------

const MAX_SIZE = 2 ** 53 - 1;

/** Printable ASCII 0x21–0x7E, excluding "+" (0x2B), and non-empty. */
function isOriginText(s) {
  if (typeof s !== 'string' || s.length === 0) return false;
  for (const c of s) {
    const code = c.charCodeAt(0);
    if (c.length !== 1 || code < 0x21 || code > 0x7e || code === 0x2b) return false;
  }
  return true;
}

function formatBody(origin, size, rootHex) {
  if (!isOriginText(origin) || !(Number.isSafeInteger(size) && size >= 1) || !/^[0-9a-f]{64}$/.test(rootHex)) {
    throw new Error(`cannot format a body for ${JSON.stringify({ origin, size, rootHex })}`);
  }
  return `${origin}\n${size}\n${base64Encode(Buffer.from(rootHex, 'hex'))}\n`;
}

/** The exact-form reader. Returns { origin, size, rootHex } or null. */
function parseBody(body) {
  if (typeof body !== 'string') return null;
  for (const c of body) if (c === '\r') return null;
  if (!body.endsWith('\n')) return null;
  const lines = body.slice(0, -1).split('\n');
  if (lines.length !== 3) return null;
  const [origin, sizeText, rootText] = lines;
  if (!isOriginText(origin)) return null;
  if (!/^[0-9]+$/.test(sizeText) || (sizeText.length > 1 && sizeText[0] === '0')) return null;
  if (sizeText.length > 16) return null;
  const size = Number(sizeText);
  if (size < 1 || size > MAX_SIZE) return null;
  const root = base64DecodeStrict(rootText);
  if (root === null || root.length !== 32) return null;
  return { origin, size, rootHex: hex(root) };
}

// ---- What C2SP and a stock parser make of a body -------------------------------------
//
// Two independent readings of each invalid body, recorded as flags so that a
// cross-implementation gate knows which refusals are Tzun's own.

/** SHA-256 of the empty string: the RFC 6962 root of the empty tree. */
const EMPTY_TREE_ROOT = hex(sha256(Buffer.alloc(0)));

/**
 * Whether `body` is a conforming checkpoint note text, reading C2SP
 * tlog-checkpoint ("Note text") and signed-note v1.0.0 literally:
 *   - signed-note: valid UTF-8, no character below U+0020 other than LF, and
 *     the text ends in LF;
 *   - tlog-checkpoint: at least three lines, none empty (the origin MUST be
 *     non-empty, extension lines MUST be non-empty); the size is the ASCII
 *     decimal representation with no leading zero ("0" for the empty tree);
 *     the root is the RFC 4648 §4 base64 encoding of the RFC 6962 root, which
 *     is 32 bytes (SHA-256), padded, with zero pad bits (RFC 4648 §3.5: a
 *     conforming encoder zeroes them, so the encoding of a root is unique);
 *     at size 0 the root is the empty tree's.
 * SHOULDs and NOT RECOMMENDEDs (spaces or "+" in the origin, extension lines)
 * do not count.
 */
function c2spConforming(body) {
  for (const c of body) {
    const cp = c.codePointAt(0);
    if ((cp >= 0xd800 && cp <= 0xdfff) || (cp < 0x20 && cp !== 0x0a)) return false;
  }
  if (!body.endsWith('\n')) return false;
  const lines = body.slice(0, -1).split('\n');
  if (lines.length < 3 || lines.some((l) => l.length === 0)) return false;
  const [, sizeText, rootText] = lines;
  if (!/^(0|[1-9][0-9]*)$/.test(sizeText)) return false;
  const root = base64DecodeStrict(rootText);
  if (root === null || root.length !== 32) return false;
  return sizeText !== '0' || hex(root) === EMPTY_TREE_ROOT;
}

/**
 * The stock parser the Go gate uses: github.com/transparency-dev/formats
 * `log.Checkpoint.Unmarshal` at v0.1.1, the version the Go gate pins.
 * Transcribed from that source and Go's standard library:
 *   - bytes.SplitN(data, "\n", 4) must give four parts, so at least three LFs;
 *     whatever follows the third LF is returned as extension data, not refused;
 *   - the origin line is non-empty, and nothing else is asked of it;
 *   - strconv.ParseUint(size, 10, 64): ASCII digits only, no sign, leading
 *     zeros allowed, at most 2^64 − 1;
 *   - base64.StdEncoding.DecodeString(root), not Strict(): CR and LF are
 *     skipped anywhere, the rest is whole 4-character quanta with padding
 *     only at the end, unused bits are ignored, and no length is required.
 */
function stockParserAccepts(body) {
  const parts = [];
  let rest = body;
  while (parts.length < 3) {
    const at = rest.indexOf('\n');
    if (at < 0) return false;
    parts.push(rest.slice(0, at));
    rest = rest.slice(at + 1);
  }
  const [origin, sizeText, rootText] = parts;
  if (origin.length === 0) return false;
  if (!/^[0-9]+$/.test(sizeText) || BigInt(sizeText) > 2n ** 64n - 1n) return false;
  const root = rootText.replace(/[\r\n]/g, '');
  return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(root);
}

// ---- Origins ------------------------------------------------------------------------

/** tzun-anchor/1 §4.3.2: a chain id is a non-empty string of Unicode scalar values other than U+0000. */
function chainSegment(chainId) {
  if (chainId.length === 0 || chainId.includes('\u0000')) throw new Error('not a chain id');
  return hex(utf8Encode(chainId));
}

/** The reader's rule (§4.3.2): lowercase hex pairs, no 0x00 byte, strict UTF-8, one spelling. */
function chainIdFromSegment(seg) {
  if (typeof seg !== 'string' || seg.length === 0 || seg.length % 2 !== 0 || !/^[0-9a-f]+$/.test(seg)) return null;
  const bytes = Buffer.from(seg, 'hex');
  if (bytes.includes(0x00)) return null;
  const s = utf8DecodeStrict(bytes);
  return s === null || chainSegment(s) !== seg ? null : s;
}

/** tzun-anchor/1 §4.3.2: <ns>/<id>/anchors, <ns>/<id>/evidence/<chain segment>, or <ns>/<id>/<one other segment>. */
function readOrigin(origin) {
  if (!isOriginText(origin)) return null;
  const segs = origin.split('/');
  if (segs.some((s) => s === '') || segs.length < 3 || segs.length > 4) return null;
  const prefix = `${segs[0]}/${segs[1]}`;
  if (segs.length === 4) {
    if (segs[2] !== 'evidence') return null;
    const chainId = chainIdFromSegment(segs[3]);
    return chainId === null ? null : { kind: 'evidence', prefix, ns: segs[0], chainId };
  }
  if (segs[2] === 'anchors') return { kind: 'anchors', prefix, ns: segs[0] };
  if (segs[2] === 'evidence') return null;
  return { kind: 'log', prefix, ns: segs[0] };
}

/**
 * The platform's namespaces: log.tzun.ai (§4.3.3), and test.log.tzun.ai for a
 * platform deployment that anchors in the test namespace (§4.3.4). Their
 * source-log origins are opaque.
 */
const PLATFORM_NAMESPACES = ['log.tzun.ai', 'test.log.tzun.ai'];

/**
 * §10.3 step 2b. With a chain id supplied, the log must be that chain's
 * evidence log, because an SDK record's leaf is only ever in its chain's
 * evidence log; under either platform namespace a source log is opaque, and
 * the chain is left unchecked (§4.3.4 gives test.log.tzun.ai the treatment of
 * log.tzun.ai).
 */
function bindOrigins(anchorOrigin, logOrigin, chainId) {
  const a = readOrigin(anchorOrigin);
  const l = readOrigin(logOrigin);
  if (!a || a.kind !== 'anchors' || !l || l.kind === 'anchors' || l.prefix !== a.prefix) {
    return { ok: false, reason: 'origin_not_in_domain' };
  }
  let chainChecked = false;
  if (chainId !== null && chainId !== undefined) {
    if (l.kind === 'evidence') {
      if (chainId !== l.chainId) return { ok: false, reason: 'chain_id_mismatch' };
      chainChecked = true;
    } else if (!PLATFORM_NAMESPACES.includes(l.ns)) {
      return { ok: false, reason: 'chain_id_mismatch' };
    }
  }
  return { ok: true, ns: a.ns, chainChecked };
}

// ---- RFC 6962 trees ------------------------------------------------------------------

const leafHash = (dHex) => sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(dHex, 'hex')]));
const nodeHash = (l, r) => sha256(Buffer.concat([Buffer.from([0x01]), l, r]));

function splitPoint(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function mth(ds) {
  if (ds.length === 1) return leafHash(ds[0]);
  const k = splitPoint(ds.length);
  return nodeHash(mth(ds.slice(0, k)), mth(ds.slice(k)));
}

function path(m, ds) {
  if (ds.length <= 1) return [];
  const k = splitPoint(ds.length);
  return m < k ? [...path(m, ds.slice(0, k)), mth(ds.slice(k))] : [...path(m - k, ds.slice(k)), mth(ds.slice(0, k))];
}

function subproof(m, ds, b) {
  if (m === ds.length) return b ? [] : [mth(ds)];
  const k = splitPoint(ds.length);
  return m <= k
    ? [...subproof(m, ds.slice(0, k), b), mth(ds.slice(k))]
    : [...subproof(m - k, ds.slice(k), false), mth(ds.slice(0, k))];
}

const parseHash = (v) => (typeof v === 'string' && /^[0-9a-fA-F]{64}$/.test(v) ? v.toLowerCase() : null);

/** RFC 9162 §2.1.3.2, over bare-hex paths, with the encoding rule of the Merkle vectors. */
function verifyInclusion(dIn, index, size, pathIn, rootIn) {
  const d = parseHash(dIn);
  const root = parseHash(rootIn);
  if (d === null || root === null || !Array.isArray(pathIn)) return false;
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size) return false;
  const steps = pathIn.map(parseHash);
  if (steps.includes(null)) return false;
  let fn = index;
  let sn = size - 1;
  let r = leafHash(d);
  for (const p of steps) {
    if (sn === 0) return false;
    const c = Buffer.from(p, 'hex');
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(c, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = nodeHash(r, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && hex(r) === root;
}

// ---- tzun-anchor/1 §10.3 steps 1 to 5, the step 6 dispatch, and the §10.6 reason ---------

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const present = (v) => v !== undefined && v !== null;

/** §8.1: the members of the artifact, and no others. */
const ANCHOR_MEMBERS = ['anchorSpec', 'merkleSpec', 'leafIndex', 'logCheckpoint', 'logPath', 'anchorLeafIndex', 'anchorCheckpoint', 'anchorPath', 'publications'];
/** A JSON integer in [0, 2^53 - 1] (the spec's notation). */
const isIndex = (v) => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 2 ** 53 - 1;

/** The checks of steps 1 to 5 (§10.7), in step order. */
const STEP_CHECKS = ['anchor.spec', 'anchor.checkpoint', 'anchor.origin', 'anchor.leafIndex', 'anchor.inclusion', 'anchor.anchorInclusion'];
/** The abstentions of §10.1: a construction or version the verifier does not implement. */
const ABSTENTIONS = ['unsupported_anchor_spec', 'unsupported_merkle_spec', 'legacy_blockchain_anchor', 'unsupported_publication_kind', 'unsupported_evm_tx_type'];

/** One entry of the check catalogue (§10.7), as a report carries it: { id, outcome, reason?, facts? }. */
const check = (id, outcome, reason, facts) => ({
  id,
  outcome,
  ...(reason !== undefined && { reason }),
  ...(facts !== undefined && { facts }),
});

/**
 * Check `anchor` (§10.7): the anchor as a whole. checked-correct when
 * anchorValid is true, checked-wrong when it is false, and otherwise abstain
 * or not-checked as anchorReason is or is not an abstention; its reason is
 * anchorReason. With no anchor attached it is not-checked, absent.
 */
function anchorCheck(anchorValid, reason, present) {
  if (anchorValid === true) return check('anchor', 'checked-correct');
  if (anchorValid === false) return check('anchor', 'checked-wrong', reason);
  if (!present) return check('anchor', 'not-checked', 'absent');
  return check('anchor', ABSTENTIONS.includes(reason) ? 'abstain' : 'not-checked', reason);
}

/**
 * Step 6 for the publication at index i, as far as this file decides it, with
 * its checks, each suffixed [i] (§10.3 step 6). The dispatch is check
 * anchor.publication[i]: an element that is not an object is false
 * (malformed_publication); an absent, non-string or unknown kind abstains
 * (unsupported_publication_kind); and in both cases no other check of the
 * element is reported. An evm-calldata/1 entry passes the dispatch, and
 * without a raw transaction it is not checked (§10.4 item 1:
 * not_in_bundle:raw_transaction), which blocks anchor.evm.canonical[i]. No
 * case carries a raw transaction or an rfc3161/1 token, so none is decided
 * beyond that.
 */
function publicationVerdict(pub, i) {
  const dispatch = `anchor.publication[${i}]`;
  if (!isObject(pub)) {
    return { valid: false, reason: 'malformed_publication', checks: [check(dispatch, 'checked-wrong', 'malformed_publication')] };
  }
  if (pub.kind === 'evm-calldata/1' && !present(pub.rawTransaction)) {
    return {
      valid: null,
      reason: 'publication_not_checked',
      notChecked: true,
      checks: [
        check(dispatch, 'checked-correct'),
        check(`anchor.evm.tx[${i}]`, 'not-checked', 'not_in_bundle:raw_transaction'),
        check(`anchor.evm.canonical[${i}]`, 'not-checked', `blocked_by:anchor.evm.tx[${i}]`),
      ],
    };
  }
  if (pub.kind === 'evm-calldata/1' || pub.kind === 'rfc3161/1') throw new Error('self-check: this file decides no evm-calldata/1 raw transaction and no rfc3161/1 token');
  return { valid: null, reason: 'unsupported_publication_kind', checks: [check(dispatch, 'abstain', 'unsupported_publication_kind')] };
}

/**
 * { anchorValid, reason?, merkleProofValid, p, anchorNamespace, anchorPosition?,
 * checks } for an artifact bag, under tzun-anchor/1 §10.3, §10.6 and §10.7.
 * anchorNamespace is 'test' whenever the anchor checkpoint parses and its
 * origin begins with test., whatever the verdict (labelling yourself test is
 * never an escalation), and null otherwise: no case authenticates an origin.
 *
 * checks is the §10.7 catalogue in report order: anchor, the six step checks,
 * then each publication's checks in array order. A step that fails is
 * reported once, at its check, and every step check after it is not-checked,
 * blocked_by that check. The publications are dispatched only once steps 1
 * to 5 hold, so no publication check is reported before that. Facts:
 * anchor.origin, whenever it is checked-correct, carries originAuthenticated
 * (false: nothing here authenticates an origin), namespace (the
 * anchorNamespace) and chainChecked; anchor.leafIndex carries
 * leafIndexChecked, true when the index was compared with a supplied sequence
 * number (whether it matched or not) and false when none was supplied.
 */
function stepsVerdict(bag, digest, sequenceNumber, chainId) {
  let anchorNamespace = null;
  const steps = [];
  const pubChecks = [];
  const out = (anchorValid, reason, merkleProofValid, p, extra = {}) => ({
    anchorValid,
    ...(reason !== undefined && { reason }),
    merkleProofValid,
    p,
    anchorNamespace,
    ...extra,
    checks: [anchorCheck(anchorValid, reason, present(bag.anchor) || present(bag.blockchainAnchor)), ...steps, ...pubChecks],
  });
  /** Step `id` decides the anchor with `outcome`; every step after it is blocked by it. */
  const stop = (id, outcome, reason, facts) => {
    steps.push(check(id, outcome, reason, facts));
    for (const later of STEP_CHECKS.slice(STEP_CHECKS.indexOf(id) + 1)) steps.push(check(later, 'not-checked', `blocked_by:${id}`));
  };
  if (!present(bag.anchor)) {
    if (present(bag.blockchainAnchor)) {
      stop('anchor.spec', 'abstain', 'legacy_blockchain_anchor');
      return out(null, 'legacy_blockchain_anchor', null, null);
    }
    for (const id of STEP_CHECKS) steps.push(check(id, 'not-checked', 'absent'));
    return out(null, undefined, null, null);
  }
  const a = isObject(bag.anchor) ? bag.anchor : {};
  if (a.anchorSpec !== 'tzun-anchor/1') {
    stop('anchor.spec', 'abstain', 'unsupported_anchor_spec');
    return out(null, 'unsupported_anchor_spec', null, null);
  }
  if (a.merkleSpec !== 'rfc6962') {
    stop('anchor.spec', 'abstain', 'unsupported_merkle_spec');
    return out(null, 'unsupported_merkle_spec', null, null);
  }
  steps.push(check('anchor.spec', 'checked-correct'));
  const fail = (id, reason, merkleProofValid, p, facts) => {
    stop(id, 'checked-wrong', reason, facts);
    return out(false, reason, merkleProofValid, p);
  };
  // Step 2: the members of §8.1 exactly, with their types, and a non-empty
  // publications array; then both bodies parse; then both paths are arrays of
  // hashes. Each fails with its own reason, and none reports P.
  const keys = Object.keys(a);
  const shaped =
    keys.length === ANCHOR_MEMBERS.length &&
    ANCHOR_MEMBERS.every((k) => keys.includes(k)) &&
    isIndex(a.leafIndex) &&
    isIndex(a.anchorLeafIndex) &&
    Array.isArray(a.publications) &&
    a.publications.length > 0;
  if (!shaped) return fail('anchor.checkpoint', 'malformed_anchor', null, null);
  const log = parseBody(a.logCheckpoint);
  const anc = parseBody(a.anchorCheckpoint);
  if (anc && anc.origin.startsWith('test.')) anchorNamespace = 'test';
  if (!log || !anc) return fail('anchor.checkpoint', 'malformed_checkpoint', null, null);
  const hashes = (v) => Array.isArray(v) && v.every((x) => parseHash(x) !== null);
  if (!hashes(a.logPath) || !hashes(a.anchorPath)) return fail('anchor.checkpoint', 'malformed_merkle_path', null, null);
  steps.push(check('anchor.checkpoint', 'checked-correct'));
  const p = hex(sha256Text(a.anchorCheckpoint));
  // Step 2b. A log origin equal to the anchor origin has `anchors` as its rest.
  const bound = bindOrigins(anc.origin, log.origin, chainId);
  if (!bound.ok) return fail('anchor.origin', bound.reason, null, p);
  // A store source log of another kind never holds a record, chain id or not;
  // a platform log's name is opaque, so its kind cannot be read.
  const logRead = readOrigin(log.origin);
  if (logRead.kind === 'log' && !PLATFORM_NAMESPACES.includes(logRead.ns)) return fail('anchor.origin', 'chain_id_mismatch', null, p);
  steps.push(check('anchor.origin', 'checked-correct', undefined, { originAuthenticated: false, namespace: anchorNamespace, chainChecked: bound.chainChecked }));
  // Step 3: compared only with a sequence number supplied; not checked blocks nothing.
  if (present(sequenceNumber)) {
    if (!(Number.isSafeInteger(sequenceNumber) && sequenceNumber >= 1 && a.leafIndex === sequenceNumber - 1)) {
      return fail('anchor.leafIndex', 'leaf_index_mismatch', null, p, { leafIndexChecked: true });
    }
    steps.push(check('anchor.leafIndex', 'checked-correct', undefined, { leafIndexChecked: true }));
  } else {
    steps.push(check('anchor.leafIndex', 'not-checked', 'input_not_supplied:sequence_number', { leafIndexChecked: false }));
  }
  if (!verifyInclusion(digest, a.leafIndex, log.size, a.logPath, log.rootHex)) return fail('anchor.inclusion', 'merkle_proof_invalid', false, p);
  steps.push(check('anchor.inclusion', 'checked-correct'));
  const logLeaf = hex(sha256Text(a.logCheckpoint));
  if (!verifyInclusion(logLeaf, a.anchorLeafIndex, anc.size, a.anchorPath, anc.rootHex)) {
    return fail('anchor.anchorInclusion', 'anchor_proof_invalid', false, p);
  }
  steps.push(check('anchor.anchorInclusion', 'checked-correct'));
  // Step 6, each publication on its own, then §10.6.
  const verdicts = a.publications.map(publicationVerdict);
  for (const v of verdicts) pubChecks.push(...v.checks);
  const firstFalse = verdicts.find((v) => v.valid === false);
  if (firstFalse) return out(false, firstFalse.reason, true, p);
  // Steps 1 to 5 hold and nothing is false: the position is reported, as far
  // as its flags say.
  const position = {
    origin: log.origin,
    leafIndex: a.leafIndex,
    treeSize: log.size,
    anchorOrigin: anc.origin,
    anchorLeafIndex: a.anchorLeafIndex,
    anchorSize: anc.size,
    leafIndexChecked: present(sequenceNumber),
    chainChecked: bound.chainChecked,
    authenticated: false,
  };
  // §10.6: publication_not_checked when any publication was not checked,
  // otherwise the first publication's abstention.
  const reason = verdicts.some((v) => v.notChecked) ? 'publication_not_checked' : verdicts[0].reason;
  return out(null, reason, true, p, { anchorPosition: position });
}

// ---- Bodies ---------------------------------------------------------------------------------

const D = (label) => hex(sha256(Buffer.from(`tzun-checkpoint-vector-${label}`, 'utf8')));
const STORE = D('store').slice(0, 32);
const TEST_STORE = D('test-store').slice(0, 32);
const DEPLOYMENT = D('deployment').slice(0, 32);
const TEST_DEPLOYMENT = D('test-deployment').slice(0, 32);
const OPAQUE = D('opaque-log').slice(0, 32);

const SDK_PREFIX = `local.invalid/${STORE}`;
const TEST_PREFIX = `test.tzun.dev/${TEST_STORE}`;
const PLATFORM_PREFIX = `log.tzun.ai/${DEPLOYMENT}`;
const PLATFORM_TEST_PREFIX = `test.log.tzun.ai/${TEST_DEPLOYMENT}`;

const validBodies = [];
const addBody = (name, origin, size, rootHex) => {
  const body = formatBody(origin, size, rootHex);
  const parsed = parseBody(body);
  if (!parsed || parsed.origin !== origin || parsed.size !== size || parsed.rootHex !== rootHex) {
    throw new Error(`self-check failed: valid body "${name}" does not read back`);
  }
  if (!c2spConforming(body) || !stockParserAccepts(body)) {
    throw new Error(`self-check failed: valid body "${name}" is not a C2SP body the stock parser reads`);
  }
  validBodies.push({ case: name, origin, size, root: rootHex, body, checkpointDigest: hex(sha256Text(body)) });
};
addBody('SDK evidence log, chain "default"', `${SDK_PREFIX}/evidence/${chainSegment('default')}`, 1024, D('root-1'));
addBody('SDK evidence log, non-ASCII chain id', `${SDK_PREFIX}/evidence/${chainSegment('café')}`, 3, D('root-2'));
addBody('SDK source log of another kind', `${SDK_PREFIX}/k2`, 17, D('root-3'));
addBody('SDK anchor log', `${SDK_PREFIX}/anchors`, 412, D('root-4'));
addBody('test namespace', `${TEST_PREFIX}/anchors`, 2, D('root-5'));
addBody('platform opaque log', `${PLATFORM_PREFIX}/${OPAQUE}`, 88, D('root-6'));
addBody('size 1', `${SDK_PREFIX}/evidence/${chainSegment('solo')}`, 1, D('root-7'));
addBody('size 2^53 - 1', `${SDK_PREFIX}/anchors`, MAX_SIZE, D('root-8'));
addBody('root of all zero bytes', `${SDK_PREFIX}/anchors`, 5, '00'.repeat(32));
addBody('root of all 0xff bytes (base64 uses "/")', `${SDK_PREFIX}/anchors`, 5, 'ff'.repeat(32));
addBody('root whose base64 uses "+"', `${SDK_PREFIX}/anchors`, 5, 'fb'.repeat(32));

const sampleRoot = base64Encode(Buffer.from(D('root-1'), 'hex'));
const sampleOrigin = `${SDK_PREFIX}/anchors`;
// A root whose last base64 digit before "=" carries non-zero unused bits.
const lastIdx = B64.indexOf(sampleRoot[42]);
const noncanonicalRoot = sampleRoot.slice(0, 42) + B64[(lastIdx & ~3) | 1] + '=';

const invalidBodies = [];
/**
 * Every invalid body carries both readings: `c2spConforming` (only a rule
 * Tzun adds refuses it) and `stockParserAccepts` (formats/log v0.1.1 reads it
 * without error). The two are independent: C2SP forbids what the stock parser
 * reads (a CR, a leading zero, a 48-byte root), and the stock parser refuses
 * what C2SP allows (a size above 2^64 − 1).
 */
const refuseBody = (name, body) => {
  if (parseBody(body) !== null) throw new Error(`self-check failed: invalid body "${name}" parses`);
  invalidBodies.push({ case: name, body, c2spConforming: c2spConforming(body), stockParserAccepts: stockParserAccepts(body) });
};
refuseBody('CRLF line endings', `${sampleOrigin}\r\n5\r\n${sampleRoot}\r\n`);
refuseBody('a CR inside the origin line', `${sampleOrigin}\r\n5\n${sampleRoot}\n`);
refuseBody('no final newline', `${sampleOrigin}\n5\n${sampleRoot}`);
refuseBody('a CR at the end of the root line', `${sampleOrigin}\n5\n${sampleRoot}\r\n`);
refuseBody('an extension line', `${sampleOrigin}\n5\n${sampleRoot}\nextension\n`);
refuseBody('an empty extension line (two final newlines)', `${sampleOrigin}\n5\n${sampleRoot}\n\n`);
refuseBody('two lines only', `${sampleOrigin}\n5\n`);
refuseBody('empty body', '');
refuseBody('leading zero in the size', `${sampleOrigin}\n05\n${sampleRoot}\n`);
refuseBody('size 0: the empty tree, with its root', `${sampleOrigin}\n0\n${base64Encode(Buffer.from(EMPTY_TREE_ROOT, 'hex'))}\n`);
refuseBody('size 0 with a root that is not the empty tree\'s', `${sampleOrigin}\n0\n${sampleRoot}\n`);
refuseBody('size 00', `${sampleOrigin}\n00\n${sampleRoot}\n`);
refuseBody('negative size', `${sampleOrigin}\n-5\n${sampleRoot}\n`);
refuseBody('size with a plus sign', `${sampleOrigin}\n+5\n${sampleRoot}\n`);
refuseBody('size with a space', `${sampleOrigin}\n 5\n${sampleRoot}\n`);
refuseBody('size in hex', `${sampleOrigin}\n0x5\n${sampleRoot}\n`);
refuseBody('size 2^53', `${sampleOrigin}\n${2 ** 53}\n${sampleRoot}\n`);
refuseBody('size 2^64 - 1', `${sampleOrigin}\n18446744073709551615\n${sampleRoot}\n`);
refuseBody('size 2^64', `${sampleOrigin}\n18446744073709551616\n${sampleRoot}\n`);
refuseBody('empty origin', `\n5\n${sampleRoot}\n`);
refuseBody('origin with a space', `local.invalid/${STORE}/my anchors\n5\n${sampleRoot}\n`);
refuseBody('origin with a "+"', `local.invalid/${STORE}/a+b\n5\n${sampleRoot}\n`);
refuseBody('origin with a tab', `local.invalid/${STORE}/a\tb\n5\n${sampleRoot}\n`);
refuseBody('origin with a non-ASCII character', `local.invalid/${STORE}/café\n5\n${sampleRoot}\n`);
refuseBody('non-canonical base64 (unused bits set)', `${sampleOrigin}\n5\n${noncanonicalRoot}\n`);
refuseBody('base64 without padding', `${sampleOrigin}\n5\n${sampleRoot.slice(0, -1)}\n`);
refuseBody('base64url alphabet', `${sampleOrigin}\n5\n${base64Encode(Buffer.from('fb'.repeat(32), 'hex')).replace(/\+/g, '-')}\n`);
refuseBody('root of 31 bytes', `${sampleOrigin}\n5\n${base64Encode(Buffer.alloc(31, 7))}\n`);
refuseBody('root of 33 bytes', `${sampleOrigin}\n5\n${base64Encode(Buffer.alloc(33, 7))}\n`);
refuseBody('root in hex', `${sampleOrigin}\n5\n${D('root-1')}\n`);

const nonStringBodies = [null, 42, ['a'], { body: sampleOrigin }];

// ---- Chain segments -----------------------------------------------------------------------------

const validSegments = [];
const addSegment = (chainId, note) => {
  const segment = chainSegment(chainId);
  if (chainIdFromSegment(segment) !== chainId) throw new Error(`self-check failed: segment for ${JSON.stringify(chainId)}`);
  validSegments.push({ case: note, chainId, segment });
};
addSegment('default', 'ASCII');
addSegment('user-abc', 'ASCII with a hyphen');
addSegment('a/b c+d', 'characters an origin may not hold: hex removes them');
addSegment('café', 'two-byte UTF-8');
addSegment('日本', 'three-byte UTF-8');
addSegment('🔒chain', 'four-byte UTF-8 (a surrogate pair in UTF-16)');
addSegment('﻿a', 'a leading U+FEFF is part of the chain id, never dropped as a byte-order mark');

const invalidSegments = [];
const refuseSegment = (note, segment) => {
  if (chainIdFromSegment(segment) !== null) throw new Error(`self-check failed: segment "${segment}" reads`);
  invalidSegments.push({ case: note, segment });
};
refuseSegment('uppercase hex', chainSegment('default').toUpperCase());
refuseSegment('mixed-case hex', '64656661756C74');
refuseSegment('odd length', '6465666');
refuseSegment('empty', '');
refuseSegment('not hex', 'zz');
refuseSegment('0x prefix', '0x64656661756c74');
refuseSegment('invalid UTF-8 byte', 'ff');
refuseSegment('overlong encoding of "/"', 'c0af');
refuseSegment('UTF-8 of a surrogate code point', 'eda080');
refuseSegment('above U+10FFFF', 'f4908080');
refuseSegment('truncated three-byte sequence', 'e282');
refuseSegment('stray continuation byte', '80');
refuseSegment('a 0x00 byte: U+0000 is not in a chain id', '00');
refuseSegment('a 0x00 byte inside', '610062');

const unencodableChainIds = [
  { case: 'lone high surrogate', chainId: '\ud800' },
  { case: 'lone low surrogate', chainId: 'a\udc00' },
  { case: 'empty', chainId: '' },
  { case: 'U+0000 alone', chainId: '\u0000' },
  { case: 'U+0000 inside', chainId: 'a\u0000b' },
];
for (const { case: name, chainId } of unencodableChainIds) {
  let encodes = true;
  try {
    chainSegment(chainId);
  } catch {
    encodes = false;
  }
  if (encodes) throw new Error(`self-check failed: chain id "${name}" encodes`);
}

// ---- Domain binding (tzun-anchor/1 §10.3 step 2b) -----------------------------------------------

const domain = [];
const bindCase = (name, anchorOrigin, logOrigin, chainId, expect) => {
  const got = bindOrigins(anchorOrigin, logOrigin, chainId);
  const gotExpect = got.ok ? 'ok' : got.reason;
  if (gotExpect !== expect.result || (got.ok && got.chainChecked !== expect.chainChecked)) {
    throw new Error(`self-check failed: domain case "${name}"`);
  }
  domain.push({
    case: name,
    anchorOrigin,
    logOrigin,
    chainId,
    expect: got.ok ? { result: 'ok', namespace: got.ns, chainChecked: got.chainChecked } : { result: got.reason },
  });
};
const SDK_ANCHORS = `${SDK_PREFIX}/anchors`;
const DEFAULT_LOG = `${SDK_PREFIX}/evidence/${chainSegment('default')}`;
bindCase('SDK evidence log, chain supplied', SDK_ANCHORS, DEFAULT_LOG, 'default', { result: 'ok', chainChecked: true });
bindCase('SDK evidence log, no chain supplied', SDK_ANCHORS, DEFAULT_LOG, null, { result: 'ok', chainChecked: false });
bindCase('SDK evidence log, non-ASCII chain', SDK_ANCHORS, `${SDK_PREFIX}/evidence/${chainSegment('日本')}`, '日本', {
  result: 'ok',
  chainChecked: true,
});
bindCase('SDK source log of another kind, no chain supplied', SDK_ANCHORS, `${SDK_PREFIX}/k2`, null, { result: 'ok', chainChecked: false });
bindCase('SDK source log of another kind, chain supplied: a record\'s log is its chain\'s evidence log', SDK_ANCHORS, `${SDK_PREFIX}/k2`, 'default', {
  result: 'chain_id_mismatch',
});
bindCase('test namespace, source log of another kind, chain supplied', `${TEST_PREFIX}/anchors`, `${TEST_PREFIX}/k2`, 'default', {
  result: 'chain_id_mismatch',
});
bindCase('platform opaque log: no chain to check', `${PLATFORM_PREFIX}/anchors`, `${PLATFORM_PREFIX}/${OPAQUE}`, 'user-abc', {
  result: 'ok',
  chainChecked: false,
});
bindCase('platform opaque log, no chain supplied', `${PLATFORM_PREFIX}/anchors`, `${PLATFORM_PREFIX}/${OPAQUE}`, null, {
  result: 'ok',
  chainChecked: false,
});
bindCase('a namespace that only extends the platform\'s is not the platform', 'log.tzun.ai.example/x/anchors', 'log.tzun.ai.example/x/k2', 'default', {
  result: 'chain_id_mismatch',
});
// §4.3.4: a platform deployment that anchors in the test namespace uses
// test.log.tzun.ai, and step 2b treats it exactly as log.tzun.ai.
bindCase('platform test opaque log: no chain to check', `${PLATFORM_TEST_PREFIX}/anchors`, `${PLATFORM_TEST_PREFIX}/${OPAQUE}`, 'user-abc', {
  result: 'ok',
  chainChecked: false,
});
bindCase('platform test opaque log, no chain supplied', `${PLATFORM_TEST_PREFIX}/anchors`, `${PLATFORM_TEST_PREFIX}/${OPAQUE}`, null, {
  result: 'ok',
  chainChecked: false,
});
bindCase('platform test namespace, evidence log of another chain: an evidence origin still names its chain', `${PLATFORM_TEST_PREFIX}/anchors`, `${PLATFORM_TEST_PREFIX}/evidence/${chainSegment('default')}`, 'other', {
  result: 'chain_id_mismatch',
});
bindCase('a namespace that only extends the platform test namespace is not the platform', 'test.log.tzun.ai.example/x/anchors', 'test.log.tzun.ai.example/x/k2', 'default', {
  result: 'chain_id_mismatch',
});
bindCase('a namespace under the platform\'s name is not the platform', 'staging.log.tzun.ai/x/anchors', 'staging.log.tzun.ai/x/k2', 'default', {
  result: 'chain_id_mismatch',
});
bindCase('test namespace', `${TEST_PREFIX}/anchors`, `${TEST_PREFIX}/evidence/${chainSegment('default')}`, null, {
  result: 'ok',
  chainChecked: false,
});
bindCase('another chain', SDK_ANCHORS, DEFAULT_LOG, 'other', { result: 'chain_id_mismatch' });
bindCase('chain ids compare as strings, not case-folded', SDK_ANCHORS, DEFAULT_LOG, 'Default', { result: 'chain_id_mismatch' });
bindCase('another store', SDK_ANCHORS, `local.invalid/${TEST_STORE}/evidence/${chainSegment('default')}`, 'default', {
  result: 'origin_not_in_domain',
});
bindCase('another namespace', SDK_ANCHORS, `example.invalid/${STORE}/evidence/${chainSegment('default')}`, null, {
  result: 'origin_not_in_domain',
});
bindCase('a store id that extends the anchor\'s', SDK_ANCHORS, `${SDK_PREFIX}0/k2`, null, { result: 'origin_not_in_domain' });
bindCase('anchor origin not ending in /anchors', `${SDK_PREFIX}/anchor`, DEFAULT_LOG, null, { result: 'origin_not_in_domain' });
bindCase('anchor origin with a one-segment prefix', 'local.invalid/anchors', 'local.invalid/k2', null, {
  result: 'origin_not_in_domain',
});
bindCase('anchor origin with a three-segment prefix', `${SDK_PREFIX}/x/anchors`, `${SDK_PREFIX}/x/k2`, null, {
  result: 'origin_not_in_domain',
});
bindCase('the log is an anchor log', SDK_ANCHORS, `${TEST_PREFIX}/anchors`, null, { result: 'origin_not_in_domain' });
bindCase('uppercase hex in the chain segment', SDK_ANCHORS, `${SDK_PREFIX}/evidence/${chainSegment('default').toUpperCase()}`, null, {
  result: 'origin_not_in_domain',
});
bindCase('invalid UTF-8 in the chain segment', SDK_ANCHORS, `${SDK_PREFIX}/evidence/c0af`, null, { result: 'origin_not_in_domain' });
bindCase('a 0x00 byte in the chain segment', SDK_ANCHORS, `${SDK_PREFIX}/evidence/610062`, null, { result: 'origin_not_in_domain' });
bindCase('an evidence log with no chain segment', SDK_ANCHORS, `${SDK_PREFIX}/evidence`, null, { result: 'origin_not_in_domain' });
bindCase('an empty segment', SDK_ANCHORS, `${SDK_PREFIX}//k2`, null, { result: 'origin_not_in_domain' });
bindCase('five segments', SDK_ANCHORS, `${DEFAULT_LOG}/extra`, null, { result: 'origin_not_in_domain' });
bindCase('four segments that are not an evidence log', SDK_ANCHORS, `${SDK_PREFIX}/k2/64`, null, { result: 'origin_not_in_domain' });

// ---- The anchor log over two epochs (tzun-anchor/1 §5, §6) -------------------------------------

/** One source log: its origin and its leaves, grown by `append`. */
function sourceLog(origin, labels) {
  return { origin, leaves: labels.map(D) };
}
const logs = {
  default: sourceLog(DEFAULT_LOG, Array.from({ length: 9 }, (_, i) => `default-${i + 1}`)),
  cafe: sourceLog(`${SDK_PREFIX}/evidence/${chainSegment('café')}`, ['café-1', 'café-2', 'café-3']),
  solo: sourceLog(`${SDK_PREFIX}/evidence/${chainSegment('solo')}`, ['solo-1']),
  k2: sourceLog(`${SDK_PREFIX}/k2`, ['k2-entry-1', 'k2-entry-2']),
};

const anchorLeaves = [];
const epochs = [];
/**
 * Cut an epoch: each member log's checkpoint at its new size, appended to the
 * anchor log in ascending bytewise origin order (all origins are ASCII, so a
 * code-unit sort is a byte sort), then the anchor checkpoint and P.
 */
function cutEpoch(name, members) {
  const cps = members
    .map(([key, size]) => {
      const leaves = logs[key].leaves.slice(0, size);
      const body = formatBody(logs[key].origin, size, hex(mth(leaves)));
      return { key, origin: logs[key].origin, size, root: hex(mth(leaves)), body, checkpointDigest: hex(sha256Text(body)) };
    })
    .sort((x, y) => (x.origin < y.origin ? -1 : x.origin > y.origin ? 1 : 0));
  for (const cp of cps) {
    cp.anchorLeafIndex = anchorLeaves.length;
    anchorLeaves.push(cp.checkpointDigest);
  }
  const anchorSize = anchorLeaves.length;
  const anchorRoot = hex(mth(anchorLeaves));
  const anchorBody = formatBody(SDK_ANCHORS, anchorSize, anchorRoot);
  const epoch = {
    epoch: name,
    members: cps.map(({ key, ...rest }) => rest),
    anchorOrigin: SDK_ANCHORS,
    anchorSize,
    anchorRoot,
    anchorCheckpoint: anchorBody,
    p: hex(sha256Text(anchorBody)),
  };
  epochs.push(epoch);
  return { epoch, cps, anchorLeavesAtCut: [...anchorLeaves] };
}
const e1 = cutEpoch('E1', [['default', 5], ['cafe', 3], ['solo', 1]]);
const e2 = cutEpoch('E2', [['default', 9], ['k2', 2]]);
const anchorConsistency = {
  first: e1.epoch.anchorSize,
  second: e2.epoch.anchorSize,
  firstRoot: e1.epoch.anchorRoot,
  secondRoot: e2.epoch.anchorRoot,
  proof: subproof(e1.epoch.anchorSize, anchorLeaves, true).map(hex),
};

// ---- Record artifacts and their §10.3 steps ---------------------------------------------------

/**
 * An `evm-calldata/1` entry as a record's envelope carries it (tzun-anchor/1
 * §8.2): every member, and no heavy material, so no verifier can check it
 * from the envelope alone (§10.4 item 1, not_in_bundle:raw_transaction).
 */
const envelopeEvmEntry = (label) => ({
  kind: 'evm-calldata/1',
  chain: 'eip155:11155111',
  transactionId: '0x' + D(`tx-${label}`),
  blockNumber: 7123456,
  blockHash: '0x' + D(`block-${label}`),
  publisher: '0x' + D('publisher').slice(0, 40),
});

/** The `nonRepudiation.anchor` of leaf `leafIndex` of `key`, anchored in epoch `cut`. */
function artifactFor(cut, key, leafIndex) {
  const cp = cut.cps.find((c) => c.key === key);
  const leaves = logs[key].leaves.slice(0, cp.size);
  return {
    anchorSpec: 'tzun-anchor/1',
    merkleSpec: 'rfc6962',
    leafIndex,
    logCheckpoint: cp.body,
    logPath: path(leafIndex, leaves).map(hex),
    anchorLeafIndex: cp.anchorLeafIndex,
    anchorCheckpoint: cut.epoch.anchorCheckpoint,
    anchorPath: path(cp.anchorLeafIndex, cut.anchorLeavesAtCut).map(hex),
    publications: [envelopeEvmEntry(`epoch-${cut.epoch.anchorSize}`)],
  };
}

const artifacts = [];
function artifactCase(name, { bag, digest, sequenceNumber = null, chainId = null, expect, position }) {
  const got = stepsVerdict(bag, digest, sequenceNumber, chainId);
  for (const k of ['anchorValid', 'reason', 'merkleProofValid']) {
    if (expect[k] !== undefined && got[k] !== expect[k]) {
      throw new Error(`self-check failed: artifact case "${name}": ${k} is ${got[k]}, stated ${expect[k]}`);
    }
  }
  if (expect.p !== undefined && got.p !== expect.p) throw new Error(`self-check failed: artifact case "${name}": p`);
  if (position && JSON.stringify(got.anchorPosition) !== JSON.stringify(position)) {
    throw new Error(`self-check failed: artifact case "${name}": anchorPosition`);
  }
  if (expect.anchorNamespace !== undefined && got.anchorNamespace !== expect.anchorNamespace) {
    throw new Error(`self-check failed: artifact case "${name}": anchorNamespace`);
  }
  if (expect.checks !== undefined && JSON.stringify(got.checks) !== JSON.stringify(expect.checks)) {
    throw new Error(`self-check failed: artifact case "${name}": checks are ${JSON.stringify(got.checks)}`);
  }
  artifacts.push({ case: name, digest, sequenceNumber, chainId, artifacts: bag, expect: got });
}

const base = (cut, key, leafIndex) => ({ anchor: artifactFor(cut, key, leafIndex) });
const clone = (v) => JSON.parse(JSON.stringify(v));
const holds = (cut, key, leafIndex, flags) => ({
  anchorValid: null,
  reason: 'publication_not_checked',
  merkleProofValid: true,
  p: cut.epoch.p,
  ...flags,
});
const positionOf = (cut, key, leafIndex, leafIndexChecked, chainChecked) => {
  const cp = cut.cps.find((c) => c.key === key);
  return {
    origin: cp.origin,
    leafIndex,
    treeSize: cp.size,
    anchorOrigin: cut.epoch.anchorOrigin,
    anchorLeafIndex: cp.anchorLeafIndex,
    anchorSize: cut.epoch.anchorSize,
    leafIndexChecked,
    chainChecked,
    authenticated: false,
  };
};
const leaf = (key, i) => logs[key].leaves[i];

// Steps 1 to 5 hold. The envelope's EVM entry carries no raw transaction, so
// the anchor is undecided, never valid.
for (const [name, cut, key, i, chainId] of [
  ['first record of "default", epoch E1', e1, 'default', 0, 'default'],
  ['last record of "default", epoch E1', e1, 'default', 4, 'default'],
  ['a record of "default" first anchored in E2', e2, 'default', 6, 'default'],
  ['a record of "default" from E1, re-proved at E2', e2, 'default', 2, 'default'],
  ['non-ASCII chain "café"', e1, 'cafe', 1, 'café'],
  ['a one-record log: empty log path', e1, 'solo', 0, 'solo'],
]) {
  artifactCase(name, {
    bag: base(cut, key, i),
    digest: leaf(key, i),
    sequenceNumber: i + 1,
    chainId,
    expect: holds(cut, key, i),
    position: positionOf(cut, key, i, true, true),
  });
}
artifactCase('no sequence number and no chain id: both unchecked', {
  bag: base(e1, 'default', 3),
  digest: leaf('default', 3),
  expect: holds(e1, 'default', 3),
  position: positionOf(e1, 'default', 3, false, false),
});

// Step 1.
artifactCase('no anchor attached', { bag: {}, digest: leaf('default', 0), expect: { anchorValid: null, merkleProofValid: null } });
artifactCase('a legacy blockchainAnchor alone', {
  bag: {
    blockchainAnchor: {
      chain: 'ethereum-sepolia',
      transactionId: '0x' + D('tx'),
      batchMerkleRoot: hex(leafHash(leaf('default', 0))),
      merklePath: [],
      leafIndex: 0,
      treeSize: 1,
      merkleSpec: 'rfc6962',
    },
  },
  digest: leaf('default', 0),
  expect: { anchorValid: null, reason: 'legacy_blockchain_anchor' },
});
{
  const bag = base(e1, 'default', 0);
  bag.anchor.anchorSpec = 'tzun-anchor/2';
  artifactCase('a future anchorSpec', { bag, digest: leaf('default', 0), sequenceNumber: 1, expect: { anchorValid: null, reason: 'unsupported_anchor_spec' } });
}
{
  const bag = base(e1, 'default', 0);
  delete bag.anchor.anchorSpec;
  artifactCase('no anchorSpec', { bag, digest: leaf('default', 0), expect: { anchorValid: null, reason: 'unsupported_anchor_spec' } });
}
artifactCase('an anchor that is not an object', {
  bag: { anchor: 'tzun-anchor/1' },
  digest: leaf('default', 0),
  expect: { anchorValid: null, reason: 'unsupported_anchor_spec' },
});
{
  const bag = base(e1, 'default', 0);
  bag.anchor.merkleSpec = 'sha256-duplicate-odd';
  artifactCase('an unknown merkleSpec', { bag, digest: leaf('default', 0), expect: { anchorValid: null, reason: 'unsupported_merkle_spec' } });
}

// Step 2.
const mutate = (name, cut, key, i, edit, expect, inputs = {}) => {
  const bag = clone(base(cut, key, i));
  edit(bag.anchor);
  artifactCase(name, { bag, digest: leaf(key, i), sequenceNumber: i + 1, chainId: logs[key] === logs.cafe ? 'café' : key, ...inputs, expect });
};
mutate('log checkpoint with CRLF endings', e1, 'default', 1, (a) => {
  a.logCheckpoint = a.logCheckpoint.replace(/\n/g, '\r\n');
}, { anchorValid: false, reason: 'malformed_checkpoint', p: null });
mutate('anchor checkpoint with an extension line', e1, 'default', 1, (a) => {
  a.anchorCheckpoint += 'extension\n';
}, { anchorValid: false, reason: 'malformed_checkpoint', p: null });
mutate('log checkpoint with no final newline', e1, 'default', 1, (a) => {
  a.logCheckpoint = a.logCheckpoint.slice(0, -1);
}, { anchorValid: false, reason: 'malformed_checkpoint' });
mutate('log checkpoint of size 0', e1, 'default', 1, (a) => {
  a.logCheckpoint = a.logCheckpoint.replace(/\n5\n/, '\n0\n');
}, { anchorValid: false, reason: 'malformed_checkpoint' });
mutate('log checkpoint whose root is not canonical base64', e1, 'default', 1, (a) => {
  const [o, s, r] = a.logCheckpoint.slice(0, -1).split('\n');
  const idx = B64.indexOf(r[42]);
  a.logCheckpoint = `${o}\n${s}\n${r.slice(0, 42)}${B64[(idx & ~3) | 2]}=\n`;
}, { anchorValid: false, reason: 'malformed_checkpoint' });
mutate('log checkpoint is not a string', e1, 'default', 1, (a) => {
  a.logCheckpoint = null;
}, { anchorValid: false, reason: 'malformed_checkpoint' });
// Step 2, the shape of §8.1: exactly the nine members, with their types.
mutate('a member added', e1, 'default', 1, (a) => {
  a.note = 'not a member';
}, { anchorValid: false, reason: 'malformed_anchor', merkleProofValid: null, p: null });
mutate('a member missing', e1, 'default', 1, (a) => {
  delete a.anchorPath;
}, { anchorValid: false, reason: 'malformed_anchor', merkleProofValid: null, p: null });
mutate('leafIndex is a numeric string', e1, 'default', 1, (a) => {
  a.leafIndex = '1';
}, { anchorValid: false, reason: 'malformed_anchor' });
mutate('anchorLeafIndex is 2^53', e1, 'default', 1, (a) => {
  a.anchorLeafIndex = 2 ** 53;
}, { anchorValid: false, reason: 'malformed_anchor' });
mutate('publications is empty', e1, 'default', 1, (a) => {
  a.publications = [];
}, { anchorValid: false, reason: 'malformed_anchor', merkleProofValid: null, p: null });
mutate('publications is not a list', e1, 'default', 1, (a) => {
  a.publications = { kind: 'rfc3161/1' };
}, { anchorValid: false, reason: 'malformed_anchor', merkleProofValid: null });
// Step 2, the paths: arrays of hashes.
mutate('log path is not a list', e1, 'default', 1, (a) => {
  a.logPath = a.logPath.join('');
}, { anchorValid: false, reason: 'malformed_merkle_path', merkleProofValid: null, p: null });
mutate('an anchor path element with a 0x prefix', e1, 'default', 1, (a) => {
  a.anchorPath[0] = '0x' + a.anchorPath[0];
}, { anchorValid: false, reason: 'malformed_merkle_path' });
mutate('a log path element of 63 digits', e1, 'default', 1, (a) => {
  a.logPath[0] = a.logPath[0].slice(1);
}, { anchorValid: false, reason: 'malformed_merkle_path' });

// Step 2b.
const reOrigin = (body, origin) => `${origin}\n${body.split('\n').slice(1).join('\n')}`;
mutate('log origin in another store', e1, 'default', 1, (a) => {
  a.logCheckpoint = reOrigin(a.logCheckpoint, `local.invalid/${TEST_STORE}/evidence/${chainSegment('default')}`);
}, { anchorValid: false, reason: 'origin_not_in_domain', p: e1.epoch.p });
mutate('anchor origin not ending in /anchors', e1, 'default', 1, (a) => {
  a.anchorCheckpoint = reOrigin(a.anchorCheckpoint, `${SDK_PREFIX}/anchor`);
}, { anchorValid: false, reason: 'origin_not_in_domain' });
mutate('the log checkpoint is the anchor checkpoint', e1, 'default', 1, (a) => {
  a.logCheckpoint = a.anchorCheckpoint;
}, { anchorValid: false, reason: 'origin_not_in_domain', p: e1.epoch.p });
mutate('uppercase hex in the log origin\'s chain segment', e1, 'default', 1, (a) => {
  a.logCheckpoint = reOrigin(a.logCheckpoint, `${SDK_PREFIX}/evidence/${chainSegment('default').toUpperCase()}`);
}, { anchorValid: false, reason: 'origin_not_in_domain' });
mutate('the record claims another chain', e1, 'default', 1, () => {}, { anchorValid: false, reason: 'chain_id_mismatch', p: e1.epoch.p }, { chainId: 'other' });
// A leaf of an SDK source log of another kind: its proofs hold, but a record's
// leaf is only ever in its chain's evidence log, so step 2b refuses it with a
// chain id and without one.
artifactCase('a leaf of an SDK log of another kind, with a chain id supplied', {
  bag: base(e2, 'k2', 1),
  digest: leaf('k2', 1),
  sequenceNumber: 2,
  chainId: 'default',
  expect: { anchorValid: false, reason: 'chain_id_mismatch', merkleProofValid: null, p: e2.epoch.p },
});
artifactCase('a leaf of an SDK log of another kind, with no chain id: refused all the same', {
  bag: base(e2, 'k2', 1),
  digest: leaf('k2', 1),
  sequenceNumber: 2,
  expect: { anchorValid: false, reason: 'chain_id_mismatch', merkleProofValid: null, p: e2.epoch.p },
});
artifactCase('a leaf of an SDK log of another kind, with neither a chain id nor a sequence number: refused all the same', {
  bag: base(e2, 'k2', 1),
  digest: leaf('k2', 1),
  expect: { anchorValid: false, reason: 'chain_id_mismatch', merkleProofValid: null, p: e2.epoch.p },
});

// Step 3.
mutate('sequence number does not match leafIndex', e1, 'default', 1, () => {}, { anchorValid: false, reason: 'leaf_index_mismatch' }, { sequenceNumber: 4 });
mutate('sequence number 0', e1, 'default', 0, () => {}, { anchorValid: false, reason: 'leaf_index_mismatch' }, { sequenceNumber: 0 });
mutate('a fractional sequence number', e1, 'default', 1, () => {}, { anchorValid: false, reason: 'leaf_index_mismatch' }, { sequenceNumber: 2.5 });
// An index that is not a JSON integer in [0, 2^53 - 1] fails the shape of
// step 2, before step 3 compares it.
mutate('leafIndex -1 beside sequence number 0', e1, 'default', 0, (a) => {
  a.leafIndex = -1;
}, { anchorValid: false, reason: 'malformed_anchor', p: null }, { sequenceNumber: 0 });
mutate('a fractional leafIndex', e1, 'default', 1, (a) => {
  a.leafIndex = 1.5;
}, { anchorValid: false, reason: 'malformed_anchor', p: null }, { sequenceNumber: 2.5 });
mutate('leafIndex moved with the sequence number moved alike', e1, 'default', 1, (a) => {
  a.leafIndex = 2;
}, { anchorValid: false, reason: 'merkle_proof_invalid', merkleProofValid: false }, { sequenceNumber: 3 });

// Step 4.
mutate('another record\'s digest', e1, 'default', 1, () => {}, { anchorValid: false, reason: 'merkle_proof_invalid' }, { digest: leaf('default', 2) });
mutate('log path element bit-flipped', e1, 'default', 1, (a) => {
  a.logPath[0] = (parseInt(a.logPath[0][0], 16) ^ 1).toString(16) + a.logPath[0].slice(1);
}, { anchorValid: false, reason: 'merkle_proof_invalid', merkleProofValid: false });
mutate('log path truncated', e1, 'default', 1, (a) => {
  a.logPath.pop();
}, { anchorValid: false, reason: 'merkle_proof_invalid' });
mutate('leafIndex moved, no sequence number supplied', e1, 'default', 1, (a) => {
  a.leafIndex = 3;
}, { anchorValid: false, reason: 'merkle_proof_invalid' }, { sequenceNumber: null });
mutate('log root replaced', e1, 'default', 1, (a) => {
  const [o, s] = a.logCheckpoint.split('\n');
  a.logCheckpoint = `${o}\n${s}\n${base64Encode(Buffer.from(D('another-root'), 'hex'))}\n`;
}, { anchorValid: false, reason: 'merkle_proof_invalid' });

// Step 5.
mutate('anchor path element bit-flipped', e1, 'default', 1, (a) => {
  a.anchorPath[0] = (parseInt(a.anchorPath[0][0], 16) ^ 1).toString(16) + a.anchorPath[0].slice(1);
}, { anchorValid: false, reason: 'anchor_proof_invalid', merkleProofValid: false });
mutate('anchorLeafIndex moved', e1, 'default', 1, (a) => {
  a.anchorLeafIndex = a.anchorLeafIndex === 0 ? 1 : 0;
}, { anchorValid: false, reason: 'anchor_proof_invalid' });
// F11: the log path alone does not pin the log size. Step 4 accepts leaf 1 of
// a 5-leaf log under a claimed size of 6 with the same root, but the claimed
// size is inside the log checkpoint's body, and its digest is the anchor
// log's leaf, so step 5 refuses it.
mutate('log size altered, root kept: step 4 alone would accept it', e1, 'default', 1, (a) => {
  a.logCheckpoint = a.logCheckpoint.replace(/\n5\n/, '\n6\n');
}, { anchorValid: false, reason: 'anchor_proof_invalid' });

// Step 6: the dispatch of each publication, and the §10.6 reason.
mutate('a publication that is not an object', e1, 'default', 1, (a) => {
  a.publications = ['rfc3161/1'];
}, { anchorValid: false, reason: 'malformed_publication', merkleProofValid: true });
mutate('a publication that is not an object, beside one that is not checked', e1, 'default', 1, (a) => {
  a.publications = [a.publications[0], null];
}, { anchorValid: false, reason: 'malformed_publication', merkleProofValid: true });
mutate('a publication of an unknown kind', e1, 'default', 1, (a) => {
  a.publications = [{ kind: 'witness/1', cosignature: 'AA==' }];
}, { anchorValid: null, reason: 'unsupported_publication_kind', merkleProofValid: true });
mutate('a publication with no kind', e1, 'default', 1, (a) => {
  a.publications = [{ token: 'AA==' }];
}, { anchorValid: null, reason: 'unsupported_publication_kind', merkleProofValid: true });
mutate('an unknown kind first, then one not checked: not checked is the reason', e1, 'default', 1, (a) => {
  a.publications = [{ kind: 'witness/1', cosignature: 'AA==' }, a.publications[0]];
}, { anchorValid: null, reason: 'publication_not_checked', merkleProofValid: true });

// The anchor size is inside P too. Under F11 the anchor path may still verify
// under a claimed anchor size with the same root; P then changes, and no
// publication of the real P matches it.
{
  const bag = clone(base(e1, 'default', 1));
  bag.anchor.anchorCheckpoint = bag.anchor.anchorCheckpoint.replace(/\n3\n/, '\n4\n');
  const got = stepsVerdict(bag, leaf('default', 1), 2, 'default');
  artifactCase('anchor size altered, root kept: P changes', {
    bag,
    digest: leaf('default', 1),
    sequenceNumber: 2,
    chainId: 'default',
    expect: { ...got },
  });
  if (got.p === e1.epoch.p) throw new Error('self-check failed: altering the anchor size must change P');
}

// A test origin and a platform origin, for the namespace rule and the opaque chain.
{
  const leaves = ['t-1', 't-2'].map(D);
  const logOrigin = `${TEST_PREFIX}/evidence/${chainSegment('default')}`;
  const logBody = formatBody(logOrigin, 2, hex(mth(leaves)));
  const aLeaves = [hex(sha256Text(logBody))];
  const anchorBody = formatBody(`${TEST_PREFIX}/anchors`, 1, hex(mth(aLeaves)));
  const anchor = {
    anchorSpec: 'tzun-anchor/1',
    merkleSpec: 'rfc6962',
    leafIndex: 1,
    logCheckpoint: logBody,
    logPath: path(1, leaves).map(hex),
    anchorLeafIndex: 0,
    anchorCheckpoint: anchorBody,
    anchorPath: [],
    publications: [envelopeEvmEntry('test-namespace')],
  };
  // §10.6: 'test' whatever the verdict. A test origin whose proof fails, or
  // whose publication is false, still labels itself test.
  artifactCase('a test namespace whose record proof fails: false, and still test', {
    bag: { anchor: { ...anchor, logPath: [D('not-the-sibling')] } },
    digest: leaves[1],
    sequenceNumber: 2,
    chainId: 'default',
    expect: { anchorValid: false, reason: 'merkle_proof_invalid', merkleProofValid: false, p: hex(sha256Text(anchorBody)), anchorNamespace: 'test' },
  });
  artifactCase('a test namespace with a publication that is not an object: false, and still test', {
    bag: { anchor: { ...anchor, publications: [null] } },
    digest: leaves[1],
    sequenceNumber: 2,
    chainId: 'default',
    expect: { anchorValid: false, reason: 'malformed_publication', merkleProofValid: true, p: hex(sha256Text(anchorBody)), anchorNamespace: 'test' },
  });
  artifactCase('a test namespace whose log checkpoint does not parse: false, and still test', {
    bag: { anchor: { ...anchor, logCheckpoint: 'not a checkpoint' } },
    digest: leaves[1],
    sequenceNumber: 2,
    chainId: 'default',
    expect: { anchorValid: false, reason: 'malformed_checkpoint', merkleProofValid: null, p: null, anchorNamespace: 'test' },
  });
  artifactCase('a test namespace: the origin labels itself test', {
    bag: { anchor },
    digest: leaves[1],
    sequenceNumber: 2,
    chainId: 'default',
    expect: {
      anchorValid: null,
      reason: 'publication_not_checked',
      merkleProofValid: true,
      p: hex(sha256Text(anchorBody)),
      anchorNamespace: 'test',
    },
    position: {
      origin: logOrigin,
      leafIndex: 1,
      treeSize: 2,
      anchorOrigin: `${TEST_PREFIX}/anchors`,
      anchorLeafIndex: 0,
      anchorSize: 1,
      leafIndexChecked: true,
      chainChecked: true,
      authenticated: false,
    },
  });
}
{
  const leaves = ['p-1', 'p-2', 'p-3'].map(D);
  const logOrigin = `${PLATFORM_PREFIX}/${OPAQUE}`;
  const logBody = formatBody(logOrigin, 3, hex(mth(leaves)));
  const aLeaves = [D('another-log-checkpoint'), hex(sha256Text(logBody))];
  const anchorBody = formatBody(`${PLATFORM_PREFIX}/anchors`, 2, hex(mth(aLeaves)));
  const anchor = {
    anchorSpec: 'tzun-anchor/1',
    merkleSpec: 'rfc6962',
    leafIndex: 2,
    logCheckpoint: logBody,
    logPath: path(2, leaves).map(hex),
    anchorLeafIndex: 1,
    anchorCheckpoint: anchorBody,
    anchorPath: path(1, aLeaves).map(hex),
    publications: [envelopeEvmEntry('platform')],
  };
  artifactCase('a platform origin with no chain id: opaque, so neither its kind nor its chain is checked', {
    bag: { anchor },
    digest: leaves[2],
    sequenceNumber: 3,
    expect: {
      anchorValid: null,
      reason: 'publication_not_checked',
      merkleProofValid: true,
      p: hex(sha256Text(anchorBody)),
      anchorNamespace: null,
    },
    position: {
      origin: logOrigin,
      leafIndex: 2,
      treeSize: 3,
      anchorOrigin: `${PLATFORM_PREFIX}/anchors`,
      anchorLeafIndex: 1,
      anchorSize: 2,
      leafIndexChecked: true,
      chainChecked: false,
      authenticated: false,
    },
  });
  artifactCase('a platform origin: opaque, so the chain is unchecked, and production-looking but unauthenticated', {
    bag: { anchor },
    digest: leaves[2],
    sequenceNumber: 3,
    chainId: 'user-abc',
    expect: {
      anchorValid: null,
      reason: 'publication_not_checked',
      merkleProofValid: true,
      p: hex(sha256Text(anchorBody)),
      anchorNamespace: null,
    },
    position: {
      origin: logOrigin,
      leafIndex: 2,
      treeSize: 3,
      anchorOrigin: `${PLATFORM_PREFIX}/anchors`,
      anchorLeafIndex: 1,
      anchorSize: 2,
      leafIndexChecked: true,
      chainChecked: false,
      authenticated: false,
    },
  });
}

// §4.3.4: a platform test deployment (test.log.tzun.ai) is opaque like the
// platform, and its origin labels itself test.
{
  const leaves = ['pt-1', 'pt-2'].map(D);
  const logOrigin = `${PLATFORM_TEST_PREFIX}/${OPAQUE}`;
  const logBody = formatBody(logOrigin, 2, hex(mth(leaves)));
  const aLeaves = [hex(sha256Text(logBody))];
  const anchorBody = formatBody(`${PLATFORM_TEST_PREFIX}/anchors`, 1, hex(mth(aLeaves)));
  const anchor = {
    anchorSpec: 'tzun-anchor/1',
    merkleSpec: 'rfc6962',
    leafIndex: 0,
    logCheckpoint: logBody,
    logPath: path(0, leaves).map(hex),
    anchorLeafIndex: 0,
    anchorCheckpoint: anchorBody,
    anchorPath: [],
    publications: [envelopeEvmEntry('platform-test')],
  };
  artifactCase('a platform test origin: opaque, so the chain is unchecked, and test', {
    bag: { anchor },
    digest: leaves[0],
    sequenceNumber: 1,
    chainId: 'user-abc',
    expect: {
      anchorValid: null,
      reason: 'publication_not_checked',
      merkleProofValid: true,
      p: hex(sha256Text(anchorBody)),
      anchorNamespace: 'test',
    },
    position: {
      origin: logOrigin,
      leafIndex: 0,
      treeSize: 2,
      anchorOrigin: `${PLATFORM_TEST_PREFIX}/anchors`,
      anchorLeafIndex: 0,
      anchorSize: 1,
      leafIndexChecked: true,
      chainChecked: false,
      authenticated: false,
    },
  });
  // §10.6: before the anchor checkpoint parses, the origin is unknown, so a
  // shape failure reports no namespace, even for an artifact whose anchor
  // checkpoint names a test origin.
  artifactCase('malformed_anchor under a test origin: the namespace is null before the checkpoint is read', {
    bag: { anchor: { ...anchor, note: 'not a member' } },
    digest: leaves[0],
    sequenceNumber: 1,
    chainId: 'user-abc',
    expect: { anchorValid: false, reason: 'malformed_anchor', merkleProofValid: null, p: null, anchorNamespace: null },
  });
}

// The catalogue of §10.7, stated by hand for one case of each shape, so the
// transcription above is checked against the text and not only against itself.
{
  const stated = (name, checks) => {
    const c = artifacts.find((a) => a.case === name);
    if (!c) throw new Error(`self-check failed: no artifact case "${name}"`);
    if (JSON.stringify(c.expect.checks) !== JSON.stringify(checks)) {
      throw new Error(`self-check failed: artifact case "${name}": checks are ${JSON.stringify(c.expect.checks)}`);
    }
  };
  const blocked = (by, ...ids) => ids.map((id) => ({ id, outcome: 'not-checked', reason: `blocked_by:${by}` }));
  const envelopeEvm = (i) => [
    { id: `anchor.publication[${i}]`, outcome: 'checked-correct' },
    { id: `anchor.evm.tx[${i}]`, outcome: 'not-checked', reason: 'not_in_bundle:raw_transaction' },
    { id: `anchor.evm.canonical[${i}]`, outcome: 'not-checked', reason: `blocked_by:anchor.evm.tx[${i}]` },
  ];
  stated('first record of "default", epoch E1', [
    { id: 'anchor', outcome: 'not-checked', reason: 'publication_not_checked' },
    { id: 'anchor.spec', outcome: 'checked-correct' },
    { id: 'anchor.checkpoint', outcome: 'checked-correct' },
    { id: 'anchor.origin', outcome: 'checked-correct', facts: { originAuthenticated: false, namespace: null, chainChecked: true } },
    { id: 'anchor.leafIndex', outcome: 'checked-correct', facts: { leafIndexChecked: true } },
    { id: 'anchor.inclusion', outcome: 'checked-correct' },
    { id: 'anchor.anchorInclusion', outcome: 'checked-correct' },
    ...envelopeEvm(0),
  ]);
  stated('no sequence number and no chain id: both unchecked', [
    { id: 'anchor', outcome: 'not-checked', reason: 'publication_not_checked' },
    { id: 'anchor.spec', outcome: 'checked-correct' },
    { id: 'anchor.checkpoint', outcome: 'checked-correct' },
    { id: 'anchor.origin', outcome: 'checked-correct', facts: { originAuthenticated: false, namespace: null, chainChecked: false } },
    { id: 'anchor.leafIndex', outcome: 'not-checked', reason: 'input_not_supplied:sequence_number', facts: { leafIndexChecked: false } },
    { id: 'anchor.inclusion', outcome: 'checked-correct' },
    { id: 'anchor.anchorInclusion', outcome: 'checked-correct' },
    ...envelopeEvm(0),
  ]);
  stated('no anchor attached', [
    { id: 'anchor', outcome: 'not-checked', reason: 'absent' },
    ...STEP_CHECKS.map((id) => ({ id, outcome: 'not-checked', reason: 'absent' })),
  ]);
  stated('a legacy blockchainAnchor alone', [
    { id: 'anchor', outcome: 'abstain', reason: 'legacy_blockchain_anchor' },
    { id: 'anchor.spec', outcome: 'abstain', reason: 'legacy_blockchain_anchor' },
    ...blocked('anchor.spec', 'anchor.checkpoint', 'anchor.origin', 'anchor.leafIndex', 'anchor.inclusion', 'anchor.anchorInclusion'),
  ]);
  stated('publications is empty', [
    { id: 'anchor', outcome: 'checked-wrong', reason: 'malformed_anchor' },
    { id: 'anchor.spec', outcome: 'checked-correct' },
    { id: 'anchor.checkpoint', outcome: 'checked-wrong', reason: 'malformed_anchor' },
    ...blocked('anchor.checkpoint', 'anchor.origin', 'anchor.leafIndex', 'anchor.inclusion', 'anchor.anchorInclusion'),
  ]);
  stated('sequence number does not match leafIndex', [
    { id: 'anchor', outcome: 'checked-wrong', reason: 'leaf_index_mismatch' },
    { id: 'anchor.spec', outcome: 'checked-correct' },
    { id: 'anchor.checkpoint', outcome: 'checked-correct' },
    { id: 'anchor.origin', outcome: 'checked-correct', facts: { originAuthenticated: false, namespace: null, chainChecked: true } },
    { id: 'anchor.leafIndex', outcome: 'checked-wrong', reason: 'leaf_index_mismatch', facts: { leafIndexChecked: true } },
    ...blocked('anchor.leafIndex', 'anchor.inclusion', 'anchor.anchorInclusion'),
  ]);
  stated('a publication that is not an object, beside one that is not checked', [
    { id: 'anchor', outcome: 'checked-wrong', reason: 'malformed_publication' },
    { id: 'anchor.spec', outcome: 'checked-correct' },
    { id: 'anchor.checkpoint', outcome: 'checked-correct' },
    { id: 'anchor.origin', outcome: 'checked-correct', facts: { originAuthenticated: false, namespace: null, chainChecked: true } },
    { id: 'anchor.leafIndex', outcome: 'checked-correct', facts: { leafIndexChecked: true } },
    { id: 'anchor.inclusion', outcome: 'checked-correct' },
    { id: 'anchor.anchorInclusion', outcome: 'checked-correct' },
    ...envelopeEvm(0),
    { id: 'anchor.publication[1]', outcome: 'checked-wrong', reason: 'malformed_publication' },
  ]);
  stated('an unknown kind first, then one not checked: not checked is the reason', [
    { id: 'anchor', outcome: 'not-checked', reason: 'publication_not_checked' },
    { id: 'anchor.spec', outcome: 'checked-correct' },
    { id: 'anchor.checkpoint', outcome: 'checked-correct' },
    { id: 'anchor.origin', outcome: 'checked-correct', facts: { originAuthenticated: false, namespace: null, chainChecked: true } },
    { id: 'anchor.leafIndex', outcome: 'checked-correct', facts: { leafIndexChecked: true } },
    { id: 'anchor.inclusion', outcome: 'checked-correct' },
    { id: 'anchor.anchorInclusion', outcome: 'checked-correct' },
    { id: 'anchor.publication[0]', outcome: 'abstain', reason: 'unsupported_publication_kind' },
    ...envelopeEvm(1),
  ]);
  stated('a publication of an unknown kind', [
    { id: 'anchor', outcome: 'abstain', reason: 'unsupported_publication_kind' },
    { id: 'anchor.spec', outcome: 'checked-correct' },
    { id: 'anchor.checkpoint', outcome: 'checked-correct' },
    { id: 'anchor.origin', outcome: 'checked-correct', facts: { originAuthenticated: false, namespace: null, chainChecked: true } },
    { id: 'anchor.leafIndex', outcome: 'checked-correct', facts: { leafIndexChecked: true } },
    { id: 'anchor.inclusion', outcome: 'checked-correct' },
    { id: 'anchor.anchorInclusion', outcome: 'checked-correct' },
    { id: 'anchor.publication[0]', outcome: 'abstain', reason: 'unsupported_publication_kind' },
  ]);
  stated('a test namespace whose record proof fails: false, and still test', [
    { id: 'anchor', outcome: 'checked-wrong', reason: 'merkle_proof_invalid' },
    { id: 'anchor.spec', outcome: 'checked-correct' },
    { id: 'anchor.checkpoint', outcome: 'checked-correct' },
    { id: 'anchor.origin', outcome: 'checked-correct', facts: { originAuthenticated: false, namespace: 'test', chainChecked: true } },
    { id: 'anchor.leafIndex', outcome: 'checked-correct', facts: { leafIndexChecked: true } },
    { id: 'anchor.inclusion', outcome: 'checked-wrong', reason: 'merkle_proof_invalid' },
    ...blocked('anchor.inclusion', 'anchor.anchorInclusion'),
  ]);
  stated('a platform test origin: opaque, so the chain is unchecked, and test', [
    { id: 'anchor', outcome: 'not-checked', reason: 'publication_not_checked' },
    { id: 'anchor.spec', outcome: 'checked-correct' },
    { id: 'anchor.checkpoint', outcome: 'checked-correct' },
    { id: 'anchor.origin', outcome: 'checked-correct', facts: { originAuthenticated: false, namespace: 'test', chainChecked: false } },
    { id: 'anchor.leafIndex', outcome: 'checked-correct', facts: { leafIndexChecked: true } },
    { id: 'anchor.inclusion', outcome: 'checked-correct' },
    { id: 'anchor.anchorInclusion', outcome: 'checked-correct' },
    ...envelopeEvm(0),
  ]);
}

// ---- Output ----------------------------------------------------------------------------------------

const out = {
  description:
    'Checkpoint bodies, origins, the anchor log and record anchor artifacts (Anchor §4 to §8, and §10.3 steps 1–6). A verifier must read every body in bodies.valid back to its origin, size and root and hash it to checkpointDigest; refuse every body in bodies.invalid and bodies.nonString (each invalid body also records what C2SP and the stock Go parser make of it: c2spConforming and stockParserAccepts); map every chainSegments entry both ways and refuse every invalid one; give every domain case its result; reproduce the anchor log of anchorLog; and give every artifact case the anchorValid, reason, merkleProofValid, p, anchorPosition and anchorNamespace in its expect, and report exactly the checks it lists (Anchor §10.7: ids, outcomes, reasons and facts, in order). No case carries an EVM raw transaction or an RFC 3161 token, so no publication can be true.',
  source:
    'Computed by scripts/generate-checkpoint-vectors.mjs, which imports nothing but node:crypto and transcribes C2SP tlog-checkpoint and signed-note v1.0.0, transparency-dev/formats log.Checkpoint.Unmarshal at v0.1.1 (with Go\'s strconv.ParseUint and base64.StdEncoding), RFC 4648 §4 base64, RFC 3629 UTF-8, RFC 6962 §2.1 MTH and §2.1.1 PATH (recursive), RFC 9162 §2.1.3.2 and Anchor §4, §5, §6, §8.1, §10.3, §10.6 and §10.7 by hand. Every valid case was read back, every invalid case refused, and every artifact case given its stated outcome and checks by the script\'s own transcription of §10.3, §10.6 and §10.7 before being written. The SDK implementation (src/attestation/checkpoint.ts, src/attestation/anchor-verify.ts) uses Buffer base64, TextDecoder and the engine\'s iterative Merkle code. scripts/regenerate-vectors.ts does not and must not rewrite this file.',
  format: {
    body: '<origin>\\n<size, ASCII decimal, no leading zero, 1 to 2^53 - 1>\\n<root: canonical padded RFC 4648 §4 base64 of 32 bytes>\\n. LF only, a final newline, no extension lines. The origin is printable ASCII (0x21-0x7E) with no "+".',
    checkpointDigest: 'SHA-256 of the body bytes, lowercase hex. An anchor-log leaf; for the anchor log\'s own checkpoint, P.',
    origins:
      '<ns>/<id>/anchors; <ns>/<id>/evidence/<lowercase hex of the chain id\'s UTF-8 bytes>; <ns>/<id>/<one other segment> (an SDK source-log kind, or a platform opaque id). No empty segment. "evidence" alone is not a log.',
    domainRule:
      'The anchor origin is <prefix>/anchors with a two-segment prefix; the log origin is a non-anchor origin under the same prefix. With a chain id supplied, the log must be that chain\'s evidence log: an evidence log\'s chain segment spells the chain id (string equality), and a source log of any other kind is chain_id_mismatch, except under the platform\'s namespaces, exactly "log.tzun.ai" and "test.log.tzun.ai" (tzun-anchor/1 §4.3.3 and §4.3.4: a platform deployment that anchors in the test namespace uses the prefix test.log.tzun.ai), whose source-log origins are opaque and leave the chain unchecked. A name that extends either is not the platform\'s. With no chain id, the chain is unchecked. A namespace beginning "test." is a test origin.',
    anchorLog:
      'Per epoch, every member checkpoint\'s digest is appended in ascending bytewise origin order; the anchor checkpoint is taken at the new size and P = SHA-256(anchor checkpoint body).',
    artifactExpect:
      'expect.reason uses the reasons of tzun-anchor/1 §10.1. Step 2 is the shape of §8.1 (exactly the nine members; leafIndex and anchorLeafIndex JSON integers in [0, 2^53 - 1]; publications a non-empty array: malformed_anchor), then both bodies (malformed_checkpoint), then both paths as arrays of 64-hex hashes (malformed_merkle_path). A log origin equal to the anchor origin fails step 2b (origin_not_in_domain). anchorPosition is present exactly when steps 1-5 hold and no publication is false. anchorNamespace is in every expect: \'test\' whenever the anchor checkpoint parses and its origin begins with test., whatever the verdict (§10.6: labelling yourself test is never an escalation), and otherwise null, since no case authenticates an origin. Step 6 dispatches each publication: an entry that is not an object is false (malformed_publication); an absent, non-string or unknown kind abstains (unsupported_publication_kind); an evm-calldata/1 entry in its envelope form carries no raw transaction and is not checked. Under §10.6 the reason for an undecided anchor is publication_not_checked when any publication was not checked, and otherwise the first publication\'s abstention. merkleProofValid is null when steps 4 and 5 did not run, and false when either failed. p is null until step 2 holds. expect.checks is the check catalogue of tzun-anchor/1 §10.7 as a report carries it ({ id, outcome, reason?, facts? }), in this order: anchor (the anchor as a whole: checked-correct when anchorValid is true, checked-wrong when false, otherwise abstain or not-checked as the reason is or is not an abstention of §10.1, with the anchor\'s reason; not-checked, absent, when nothing is attached); the six step checks anchor.spec, anchor.checkpoint, anchor.origin, anchor.leafIndex, anchor.inclusion, anchor.anchorInclusion (a step that fails is reported once, and each step after it is not-checked, blocked_by:<that step>; with nothing attached every step is not-checked, absent); then, once steps 1 to 5 hold, each publication in array order: anchor.publication[i] (the dispatch of §10.3 step 6), followed, only when it is checked-correct, by that kind\'s checks, each suffixed [i] (anchor.evm.tx[i] and anchor.evm.canonical[i]; a blocked_by names the suffixed id). Facts: anchor.origin, whenever it is checked-correct, carries originAuthenticated, namespace (the anchorNamespace) and chainChecked; anchor.leafIndex carries leafIndexChecked (true when a supplied sequence number was compared, whether or not it matched; false when none was supplied); no other check here carries facts.',
    c2spConforming:
      'On every invalid body. true when the body is a conforming note text under C2SP tlog-checkpoint ("Note text") and signed-note v1.0.0, read literally: valid UTF-8 with no character below U+0020 other than LF; a final LF; at least three lines, none empty (the origin and any extension line MUST be non-empty); the size in ASCII decimal with no leading zero ("0" for the empty tree); the root the RFC 4648 section 4 base64 encoding, padded and with zero pad bits (RFC 4648 section 3.5), of a 32-byte RFC 6962 SHA-256 root, which at size 0 is the empty tree\'s, SHA-256(""). SHOULDs and NOT RECOMMENDEDs (spaces or "+" in the origin, extension lines) do not count. true means only a rule that Anchor §4.1 and §4.2 add to C2SP refuses the body.',
    stockParserAccepts:
      'On every invalid body. true when github.com/transparency-dev/formats log.Checkpoint.Unmarshal at v0.1.1 returns no error for the body\'s UTF-8 bytes. It splits on LF into at most four parts and needs four (so at least three LFs); it requires a non-empty origin line and nothing else of it; it reads the size with strconv.ParseUint(size, 10, 64) (digits only, leading zeros allowed, at most 2^64 - 1) and the root with base64.StdEncoding.DecodeString (CR and LF skipped anywhere, padding required, unused bits ignored, no length check); anything after the third LF is returned as extension data. A gate running that parser must get exactly these flags, and must accept every body in bodies.valid with its origin, size and root.',
  },
  bodies: { valid: validBodies, invalid: invalidBodies, nonString: nonStringBodies },
  chainSegments: { valid: validSegments, invalid: invalidSegments, unencodable: unencodableChainIds },
  domain,
  anchorLog: {
    domainPrefix: SDK_PREFIX,
    sourceLogs: Object.fromEntries(Object.entries(logs).map(([k, v]) => [v.origin, { key: k, leaves: v.leaves }])),
    epochs,
    anchorLeaves,
    anchorConsistency,
  },
  artifacts,
};

// Non-ASCII is written as \u escapes, so every chain id is visible in review.
process.stdout.write(
  JSON.stringify(out, null, 2).replace(/[\u007f-￿]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')) + '\n',
);
