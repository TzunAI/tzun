/**
 * A registry of public RFC 3161 Timestamp Authorities and their trust anchors.
 *
 * WHAT WAS MISSING. The product has supported an arbitrary TSA for a long time
 * — `TzunConfig.attestation.timestamp.rfc3161Url` takes any URL, the backend's
 * `TZUN_TSA_URL` takes any URL, and `resolveTrustAnchors()` already accepts a
 * `trustAnchorsPem` option and a `TZUN_TSA_TRUST_ANCHORS` environment variable.
 * Every piece a customer needs in order to run on their own authority is
 * there. What was missing is the ONE fact they cannot supply themselves
 * without becoming a PKI archaeologist: *which certificate* is the right trust
 * anchor for a given authority.
 *
 * That is not a small ask. A token from `timestamp.digicert.com` embeds a
 * DigiCert Trusted Root G4 that is CROSS-SIGNED by DigiCert Assured ID Root
 * CA; a token from `timestamp.sectigo.com` embeds a Sectigo Public Time
 * Stamping Root R46 cross-signed by USERTrust. Pin the copy that came in the
 * token and you have pinned a certificate whose trust runs up into a
 * general-purpose public CA. Pin the wrong one of the three certificates that
 * share the Sectigo R46 subject and you silently widen your trust store to
 * everything under Comodo AAA. Every anchor in this file is the SELF-SIGNED
 * root that terminates the path at the timestamping hierarchy and nowhere
 * higher, fetched from the CA's own published AIA `caIssuers` URL, with its
 * SHA-256 recorded here and asserted by `tests/ts/tsa-registry.test.ts`.
 *
 * TZUN IS NOT IN THIS LIST AND WILL NOT BE. An RFC 3161 token is worth
 * something precisely because an INDEPENDENT third party attested that a
 * digest existed at time T. A timestamp Tzun issued over evidence Tzun's SDK
 * captured is circular, and is the first thing anyone disputing the evidence
 * would attack. Tzun stays TSA-neutral and pluggable.
 *
 * WHAT A TSA LEARNS ABOUT YOU. An RFC 3161 request carries a
 * `MessageImprint` — a hash algorithm OID and a digest — and nothing else
 * (RFC 3161 §2.4.1). The decision, the payload, the actor, the model, the
 * record: none of it leaves the process. A TSA cannot invert SHA-256, so
 * adding a second authority discloses *timing and volume* — that this
 * deployment asked for N timestamps at these moments — never content. That is
 * the whole privacy cost, and it is worth stating plainly because it is
 * usually assumed to be larger than it is.
 *
 * @see resolveTrustAnchors in ./rfc3161-verify for how a selection here
 *      becomes the verifier's trust store.
 */

import fs from 'fs';
import path from 'path';

/** One public Timestamp Authority, as verified by a live probe. */
export interface TimestampAuthority {
  /** Stable registry key. This is what an integrator names in config. */
  key: string;
  /** The RFC 3161 endpoint. */
  url: string;
  /** Human-readable operator name. */
  operator: string;
  /**
   * Whether this endpoint answers RFC 3161 over TLS.
   *
   * The request body is only a hash imprint, so plaintext HTTP does not leak
   * the record — but it does leak, to anyone on the path, that a timestamp was
   * requested and for which digest, and it lets an active attacker substitute
   * a valid-but-different token. The verifier catches the substitution (the
   * imprint would not match), so the practical cost of `tls: false` is
   * metadata exposure plus an availability nuisance, not forgery.
   */
  tls: boolean;
  /**
   * `free` means the 2026-09-12 probe obtained a token for an arbitrary
   * SHA-256 with no account, no API key, no payment and no registration.
   * Every authority in this registry is `free` in that sense — including
   * Sectigo and DigiCert, whose *certificate* businesses are commercial but
   * whose timestamping endpoints are open. `commercial` would mean the
   * endpoint refuses an unauthenticated request.
   */
  access: 'free' | 'commercial';
  /**
   * When set, this endpoint does not operate its own TSA: it forwards to the
   * named registry key, and the token comes back signed by THAT operator.
   *
   * This matters more than it looks. Pairing a relay with the authority it
   * fronts buys correlated failure (one outage takes out both) and an extra
   * organisation that sees every digest, while LOOKING like two independent
   * attesters. `independentAuthorities()` filters these out for exactly that
   * reason.
   */
  relayOf?: string;
  /** CN of the trust anchor a token from this endpoint must chain to. */
  anchorCommonName: string;
  /** Anchor file, relative to `src/attestation/certs/`. */
  anchorFile: string;
  /**
   * SHA-256 of the anchor, uppercase colon-separated hex — the same form
   * `openssl x509 -fingerprint -sha256` prints.
   *
   * Pinned here so that swapping the PEM on disk fails the suite. A trust
   * anchor is the one input to verification that nothing else checks: a
   * verifier handed a substituted root reports `timestampValid: true` and is
   * behaving exactly as designed while being completely wrong.
   */
  anchorFingerprintSha256: string;
  /** TSA policy OID observed in the probe's TSTInfo. */
  policyOid: string;
  /** Whether the anchor is in the mainstream public root programmes. */
  publiclyTrustedRoot: boolean;
  /** ISO date of the last live probe that confirmed every field above. */
  probedAt: string;
  /** The one line an integrator needs before choosing this authority. */
  note: string;
}

/**
 * Every authority verified by a live probe on 2026-09-12.
 *
 * Each entry was probed with `openssl ts -query -sha256 -cert` over a freshly
 * generated random payload and returned `Status: Granted` with the imprint and
 * the per-request nonce echoed. A token from each is pinned in
 * `tests/ts/fixtures/tsa-tokens.json` and verified against the anchor named
 * here by `tests/ts/tsa-registry.test.ts` — so "this anchor verifies this
 * authority" is an assertion the suite re-checks, not a claim in a comment.
 *
 * ROUND-TRIP TIMES from that probe, for context rather than as a promise:
 * Apple 59ms, FreeTSA 67ms, DigiCert 84ms, IdenTrust 84ms, SSL.com 232ms,
 * GlobalSign 433ms, Certum 442ms, Sectigo 514ms, MeSign 2068ms.
 *
 * Single samples, and at least one of them is misleading. Re-probed three more
 * times, Sectigo returned 524ms, 3401ms and 2675ms while FreeTSA returned
 * 108ms, 85ms and 68ms. Sectigo is the default fallback and it is not a fast
 * one. With the default budget (`RFC3161Config.timeoutMs` 10000,
 * `totalTimeoutMs` 20000) a FreeTSA that hangs is cut off at 10000ms and
 * Sectigo gets the remaining 10000ms; `tests/ts/rfc3161-failover.test.ts`
 * holds the default to Sectigo's slowest sample above.
 *
 * NONE OF THESE ENDPOINTS OFFERS AN SLA, and FreeTSA's operator asks users not
 * to abuse the service. A deployment with a real evidentiary or retention
 * requirement should put a CONTRACTED TSA — in the EU, a qualified eIDAS one —
 * at the head of its list and keep a free endpoint as the tail. Registering a
 * contracted authority takes one `addTimestampAuthority()` call; nothing here
 * is a closed set.
 */
const AUTHORITIES: readonly TimestampAuthority[] = Object.freeze([
  {
    key: 'freetsa',
    url: 'https://freetsa.org/tsr',
    operator: 'FreeTSA (Wuerzburg, DE)',
    tls: true,
    access: 'free',
    anchorCommonName: 'www.freetsa.org',
    anchorFile: 'freetsa-ca.pem',
    anchorFingerprintSha256:
      'A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC',
    // Read out of the TSTInfo DER, not out of openssl's pretty-printer, which
    // renders this OID as the string "tsa_policy1" from its own config table.
    policyOid: '1.2.3.4.1',
    publiclyTrustedRoot: false,
    probedAt: '2026-09-12',
    note:
      'Tzun\'s default primary. A free public TSA that exists for exactly this use, answers over ' +
      'HTTPS, and sits outside the commercial CA ecosystem. Its root is not in the public trust ' +
      'programmes, which is irrelevant here — the root is pinned, not discovered.',
  },
  {
    key: 'sectigo',
    url: 'https://timestamp.sectigo.com',
    operator: 'Sectigo Limited (GB)',
    tls: true,
    access: 'free',
    anchorCommonName: 'Sectigo Public Time Stamping Root R46',
    anchorFile: 'sectigo-public-time-stamping-root-r46.pem',
    anchorFingerprintSha256:
      '49:41:B0:01:B8:A9:7E:96:1B:78:17:C9:D9:E9:60:EC:4B:05:6B:FC:91:5A:8C:1A:AB:F6:EF:6B:3A:C0:46:A5',
    policyOid: '1.3.6.1.4.1.6449.2.1.1',
    publiclyTrustedRoot: true,
    probedAt: '2026-09-12',
    note:
      'Tzun\'s default fallback, contacted only when FreeTSA does not issue a token: a different ' +
      'operator, country and trust hierarchy, and the ONLY other probed endpoint that serves ' +
      'RFC 3161 over TLS. Sectigo sells certificates, but ' +
      'this timestamping endpoint is free and UNAUTHENTICATED — the probe got a granted token ' +
      'for an arbitrary hash with no account, key or payment of any kind. Slow and variable ' +
      'though: four samples ran 514ms, 524ms, 3401ms, 2675ms against FreeTSA\'s steady 67-108ms.',
  },
  {
    key: 'digicert',
    url: 'http://timestamp.digicert.com',
    operator: 'DigiCert, Inc. (US)',
    tls: false,
    access: 'free',
    anchorCommonName: 'DigiCert Trusted Root G4',
    anchorFile: 'digicert-trusted-root-g4.pem',
    anchorFingerprintSha256:
      '55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88',
    policyOid: '2.16.840.1.114412.7.1',
    publiclyTrustedRoot: true,
    probedAt: '2026-09-12',
    note:
      'Fast (84ms) and free, but PLAINTEXT ONLY — port 443 has no listener at all, so there is no ' +
      'https:// form of this URL that works.',
  },
  {
    key: 'sslcom',
    url: 'http://ts.ssl.com',
    operator: 'SSL Corp (Houston, US)',
    tls: false,
    access: 'free',
    anchorCommonName: 'SSL.com Root Certification Authority RSA',
    anchorFile: 'sslcom-root-certification-authority-rsa.pem',
    anchorFingerprintSha256:
      '85:66:6A:56:2E:E0:BE:5C:E9:25:C1:D8:89:0A:6F:76:A8:7E:C1:6D:4D:7D:5F:29:EA:74:19:CF:20:12:3B:69',
    policyOid: '1.3.6.1.4.1.38064.1.3.6.1',
    publiclyTrustedRoot: true,
    probedAt: '2026-09-12',
    note:
      'Free and public. Plaintext only in practice: :443 answers TLS but presents a certificate ' +
      'that does not cover ts.ssl.com, so https:// fails hostname verification.',
  },
  {
    key: 'globalsign',
    url: 'http://timestamp.globalsign.com/tsa/r6advanced1',
    operator: 'GlobalSign nv-sa (BE)',
    tls: false,
    access: 'free',
    anchorCommonName: 'GlobalSign Timestamping Root R45',
    anchorFile: 'globalsign-timestamping-root-r45.pem',
    anchorFingerprintSha256:
      '2B:CB:BF:D6:62:82:C6:80:49:1C:8C:D7:73:5F:DB:BA:B7:A8:07:9B:12:7B:EC:60:C5:35:97:68:34:39:9A:F7',
    policyOid: '1.3.6.1.4.1.4146.2.3.2.2',
    publiclyTrustedRoot: true,
    probedAt: '2026-09-12',
    note:
      'Free and public, EU-operated. Plaintext only — :443 does not answer. The anchor pinned ' +
      'here is the timestamping root, NOT GlobalSign Root CA - R6, which the token also carries ' +
      'and which would widen trust to GlobalSign\'s whole public hierarchy.',
  },
  {
    key: 'certum',
    url: 'http://time.certum.pl',
    operator: 'Asseco Data Systems S.A. / Certum (PL)',
    tls: false,
    access: 'free',
    anchorCommonName: 'Certum Trusted Network CA 2',
    anchorFile: 'certum-trusted-network-ca-2.pem',
    anchorFingerprintSha256:
      'B6:76:F2:ED:DA:E8:77:5C:D3:6C:B0:F6:3C:D1:D4:60:39:61:F4:9E:62:65:BA:01:3A:2F:03:07:B6:D0:B8:04',
    policyOid: '1.2.616.1.113527.2.5.1.11',
    publiclyTrustedRoot: true,
    probedAt: '2026-09-12',
    note:
      'Free and public, EU-operated (Poland) — the most useful second jurisdiction for a European ' +
      'deployment. Plaintext only. Certum also sells a QUALIFIED eIDAS timestamping service; this ' +
      'free endpoint is not that, and must not be represented as a qualified timestamp.',
  },
  {
    key: 'identrust',
    url: 'http://timestamp.identrust.com',
    operator: 'IdenTrust (US)',
    tls: false,
    access: 'free',
    anchorCommonName: 'IdenTrust Public Sector Root CA 1',
    anchorFile: 'identrust-public-sector-root-ca-1.pem',
    anchorFingerprintSha256:
      '30:D0:89:5A:9A:44:8A:26:20:91:63:55:22:D1:F5:20:10:B5:86:7A:CA:E1:2C:78:EF:95:8F:D4:F4:38:9F:2F',
    policyOid: '2.16.840.1.113839.0.6.13.3',
    publiclyTrustedRoot: true,
    probedAt: '2026-09-12',
    note:
      'Free, public and fast (84ms). Plaintext only — :443 hangs rather than refusing, which ' +
      'costs a full connect timeout if you try it. Its tokens carry NO root at all, so this ' +
      'bundled anchor is the only way one of them can terminate a path.',
  },
  {
    key: 'apple',
    url: 'http://timestamp.apple.com/ts01',
    operator: 'Apple Inc. (US)',
    tls: false,
    access: 'free',
    anchorCommonName: 'Apple Root CA',
    anchorFile: 'apple-root-ca.pem',
    anchorFingerprintSha256:
      'B0:B1:73:0E:CB:C7:FF:45:05:14:2C:49:F1:29:5E:6E:DA:6B:CA:ED:7E:2C:68:C5:BE:91:B5:A1:10:01:F0:24',
    policyOid: '1.2.3',
    publiclyTrustedRoot: true,
    probedAt: '2026-09-12',
    note:
      'The fastest endpoint probed (59ms) and it does issue tokens over arbitrary hashes, but ' +
      'TREAT IT AS A LAST RESORT: it exists to timestamp Apple platform code signatures, its ' +
      'TSTInfo policy OID is the placeholder 1.2.3 rather than a published timestamping policy, ' +
      'and Apple publishes no terms under which a third party may rely on it. Plaintext only.',
  },
  {
    key: 'mesign',
    url: 'http://tsa.mesign.com',
    operator: 'MeSince Technology Limited (CN)',
    tls: false,
    access: 'free',
    anchorCommonName: 'MeSince Identity CA',
    anchorFile: 'mesince-identity-ca.pem',
    anchorFingerprintSha256:
      '16:CB:A7:6D:5F:2F:89:8F:E0:D3:6C:E3:A3:21:FA:34:15:21:C1:6A:13:03:D0:8E:43:45:33:54:E6:D3:E5:F5',
    policyOid: '1.3.6.1.4.1.50775.3.4.3',
    publiclyTrustedRoot: false,
    probedAt: '2026-09-12',
    note:
      'Works, but the weakest entry here: slowest by an order of magnitude (2068ms), plaintext ' +
      'only (:443 answers 405), and its root is NOT in the public trust programmes, so a ' +
      'third-party verifier who does not use this registry has no way to validate its tokens. ' +
      'Listed for completeness and for deployments that need a PRC-jurisdiction attester.',
  },
  {
    key: 'entrust',
    url: 'http://timestamp.entrust.net/TSS/RFC3161sha2TS',
    operator: 'Entrust (endpoint) — tokens signed by Sectigo Limited',
    tls: false,
    access: 'free',
    relayOf: 'sectigo',
    anchorCommonName: 'Sectigo Public Time Stamping Root R46',
    anchorFile: 'sectigo-public-time-stamping-root-r46.pem',
    anchorFingerprintSha256:
      '49:41:B0:01:B8:A9:7E:96:1B:78:17:C9:D9:E9:60:EC:4B:05:6B:FC:91:5A:8C:1A:AB:F6:EF:6B:3A:C0:46:A5',
    policyOid: '1.3.6.1.4.1.6449.2.1.1',
    publiclyTrustedRoot: true,
    probedAt: '2026-09-12',
    note:
      'NOT AN INDEPENDENT AUTHORITY. Entrust\'s public timestamp endpoint returns tokens signed ' +
      'by "Sectigo Public Time Stamping Signer R37" under Sectigo\'s policy OID — verified by ' +
      'fixture. Pairing it with `sectigo` looks like two attesters and is one.',
  },
  {
    key: 'aimoda',
    url: 'http://rfc3161.ai.moda',
    operator: 'ai.moda (relay) — tokens signed by DigiCert, Inc.',
    tls: false,
    access: 'free',
    relayOf: 'digicert',
    anchorCommonName: 'DigiCert Trusted Root G4',
    anchorFile: 'digicert-trusted-root-g4.pem',
    anchorFingerprintSha256:
      '55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88',
    policyOid: '2.16.840.1.114412.7.1',
    publiclyTrustedRoot: true,
    probedAt: '2026-09-12',
    note:
      'NOT AN INDEPENDENT AUTHORITY. A load balancer that forwards to DigiCert, Sectigo and ' +
      'GlobalSign; the probe came back signed by DigiCert under DigiCert\'s policy OID. Using it ' +
      'adds a fourth party who sees every digest and gives no attester you did not already have.',
  },
]);

/** The registry, keyed. Mutated only through `addTimestampAuthority`. */
const REGISTRY = new Map<string, TimestampAuthority>(AUTHORITIES.map((a) => [a.key, a]));

/**
 * The authorities a deployment captures against, and trusts, when it
 * configures neither: FreeTSA, then Sectigo.
 *
 * This list is the one statement of the default for both halves.
 * `DEFAULT_TIMESTAMP_AUTHORITIES` in ./rfc3161 is these authorities' URLs in
 * this order, and `resolveTrustAnchors()` with nothing configured returns
 * these authorities' roots, so a token an unconfigured capture obtains always
 * chains to a root an unconfigured verifier accepts.
 *
 * Sectigo is contacted only when FreeTSA does not issue a valid token (a
 * transport error, an error status, a malformed or mismatched reply, a
 * timeout) or FreeTSA's circuit breaker is open. It is sent what FreeTSA is
 * sent: a TimeStampReq carrying the record's SHA-256 digest as a hash imprint
 * and a random nonce, and nothing from the record itself.
 *
 * WHY EXACTLY THESE TWO ROOTS. Every trusted root is a signing hierarchy whose
 * compromise (the root's key, or any TSA key it certifies) can mint a token
 * with whatever genTime it likes, a backdated one included, and this verifier
 * accepts it. So the default trusts the two roots it captures against and none
 * of the other bundled ones. A deployment that captures against other
 * authorities names them on both sides.
 *
 * WHAT THE NARROW STORE DOES NOT DO. It does not stop an attacker who can
 * rewrite a stored envelope. FreeTSA is a free public service, so that
 * attacker can get a genuine FreeTSA token over the rewritten digest, and it
 * verifies under any store that trusts FreeTSA. Two other checks expose the
 * rewrite. First, the fresh token's genTime is the day of the rewrite:
 * `checkCapturedAt` (./verify-attestation) re-derives genTime from the token
 * and compares it with the record's capturedAt. A token newer than its record
 * is reported as `capturedAtSkewMs` rather than failed, because a retried
 * pending attestation looks the same. Second, chain linkage: the next record's
 * chainLink was computed over the digest this record was captured with, and a
 * rewrite that reseats that link too is caught by the store's revision log
 * (`digestSuperseded`).
 */
export const DEFAULT_TRUST_ANCHOR_AUTHORITIES: readonly string[] = Object.freeze([
  'freetsa',
  'sectigo',
]);

/** Where the bundled anchors live. */
function certsDir(): string {
  return path.join(__dirname, 'certs');
}

/** Every registered authority, in registration order. */
export function listTimestampAuthorities(): TimestampAuthority[] {
  return [...REGISTRY.values()];
}

/**
 * Every registered authority that actually operates its own TSA.
 *
 * This is the list to build a failover set from: two entries that share a
 * signer are one point of failure wearing two URLs.
 */
export function independentAuthorities(): TimestampAuthority[] {
  return listTimestampAuthorities().filter((a) => a.relayOf === undefined);
}

/**
 * Look an authority up by registry key or by URL.
 *
 * URL lookup exists because the fact an integrator has to hand is usually the
 * URL already sitting in their config, not a key they have never seen.
 * Matching ignores a trailing slash and is case-insensitive on the scheme and
 * host, because `https://FreeTSA.org/tsr/` is the same endpoint as
 * `https://freetsa.org/tsr` and failing to find an anchor for it would send
 * the integrator hunting for a PEM they already have.
 */
export function getTimestampAuthority(selector: string): TimestampAuthority | undefined {
  const direct = REGISTRY.get(selector);
  if (direct) return direct;
  const wanted = normaliseUrl(selector);
  if (!wanted) return undefined;
  return listTimestampAuthorities().find((a) => normaliseUrl(a.url) === wanted);
}

/**
 * Lower-case scheme+host, path as given, trailing slash dropped: the form a
 * selector and a registered URL are compared in. `scripts/codegen-python.ts`
 * writes each registered URL in this form for the Python SDK.
 */
export function normaliseUrl(value: string): string | undefined {
  try {
    const u = new URL(value);
    const p = u.pathname.replace(/\/+$/, '');
    return `${u.protocol.toLowerCase()}//${u.host.toLowerCase()}${p}${u.search}`;
  } catch {
    return undefined;
  }
}

/**
 * Resolve a list of selectors to registry records.
 *
 * THROWS on an unknown selector rather than skipping it, and the message names
 * every valid key. A silently dropped selector is the worst outcome available
 * here: a typo in `TZUN_TSA_AUTHORITIES` would quietly shrink the trust store,
 * and a shrunken trust store does not fail at configuration time — it fails
 * months later, as `untrusted_chain` on evidence that is otherwise genuine.
 */
export function resolveTimestampAuthorities(selectors: readonly string[]): TimestampAuthority[] {
  return selectors.map((s) => {
    const found = getTimestampAuthority(s);
    if (!found) {
      throw new Error(
        `Unknown timestamp authority "${s}". Known keys: ` +
          `${listTimestampAuthorities()
            .map((a) => a.key)
            .join(', ')}. Pass a registry key, or a URL exactly as registered, or supply the ` +
          `anchor yourself with trustAnchorsPem / TZUN_TSA_TRUST_ANCHORS.`
      );
    }
    return found;
  });
}

/**
 * The endpoint URLs for a selection, in the order given, de-duplicated.
 *
 * This is what feeds `attestation.timestamp.rfc3161Urls` (the ordered failover
 * list). De-duplication is by URL rather than by key, so selecting an
 * authority and a relay that share an endpoint cannot produce the same URL
 * twice.
 */
export function timestampAuthorityUrls(selectors: readonly string[]): string[] {
  return [...new Set(resolveTimestampAuthorities(selectors).map((a) => a.url))];
}

/**
 * Absolute path to one authority's bundled anchor.
 *
 * Throws for an authority registered at runtime, which has no file. Returning
 * `certsDir()` itself — what `path.join(dir, '')` gives — would be a directory
 * path that `readFileSync` rejects with EISDIR, several frames from the
 * mistake. Use `readAuthorityAnchorPem`, which handles both kinds.
 */
export function timestampAuthorityAnchorPath(authority: TimestampAuthority): string {
  if (!authority.anchorFile) {
    throw new Error(
      `Timestamp authority "${authority.key}" was registered at runtime and has no bundled ` +
        `anchor file. Call readAuthorityAnchorPem() instead.`
    );
  }
  return path.join(certsDir(), authority.anchorFile);
}

/**
 * The PEM trust anchors for a selection, de-duplicated.
 *
 * De-duplicated by the anchor's FINGERPRINT, not by authority: `entrust` and
 * `sectigo` resolve to the same root, and handing the verifier the same anchor
 * twice would make `resolveTrustAnchors()` report a trust store larger than it
 * is.
 */
export function timestampAuthorityAnchorsPem(selectors: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const a of resolveTimestampAuthorities(selectors)) {
    // Keyed on the FINGERPRINT rather than on `anchorFile`, because an
    // authority registered at runtime has no file: every one of them would
    // collide on the empty string and only the first would survive.
    if (seen.has(a.anchorFingerprintSha256)) continue;
    seen.add(a.anchorFingerprintSha256);
    out.push(readAuthorityAnchorPem(a));
  }
  return out;
}

/**
 * Register an authority this registry does not ship — a contracted TSA, a
 * qualified eIDAS provider, an internal one.
 *
 * The anchor is given as PEM rather than as a filename, because a customer's
 * own root does not live in this package. It is written to no disk and held
 * only for the life of the process.
 *
 * Re-registering a key REPLACES it, which is how a deployment pins a different
 * root for an authority whose hierarchy has rotated without waiting for an SDK
 * release.
 */
export function addTimestampAuthority(
  authority: Omit<TimestampAuthority, 'anchorFile' | 'anchorFingerprintSha256'> & {
    anchorPem: string;
  }
): void {
  const { anchorPem, ...rest } = authority;
  const { X509Certificate } = require('crypto');
  const cert = new X509Certificate(anchorPem);
  const record: TimestampAuthority = {
    ...rest,
    anchorFile: '',
    anchorFingerprintSha256: cert.fingerprint256,
  };
  REGISTRY.set(record.key, record);
  CUSTOM_ANCHORS.set(record.key, anchorPem);
}

/** PEM for authorities registered at runtime, which have no bundled file. */
const CUSTOM_ANCHORS = new Map<string, string>();

/** Read one authority's anchor, whether bundled or registered at runtime. */
export function readAuthorityAnchorPem(authority: TimestampAuthority): string {
  const custom = CUSTOM_ANCHORS.get(authority.key);
  if (custom !== undefined) return custom;
  return fs.readFileSync(timestampAuthorityAnchorPath(authority), 'utf-8');
}
