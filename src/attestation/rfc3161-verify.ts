import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import * as fs from 'fs';
import * as path from 'path';
import {
  timestampAuthorityAnchorsPem,
  DEFAULT_TRUST_ANCHOR_AUTHORITIES,
} from './tsa-registry';
import {
  authorityOf,
  checkSignatureAndSigner,
  imprintHolds,
  readCertificatePem,
  readRfc3161Token,
  searchTrustPath,
  subjectCommonName,
  trustAnchorsFromPem,
  UnreadableTrustAnchorError,
  verifyRfc3161Steps,
  VERIFIER_FAILED,
  type Rfc3161Certificate,
  type Rfc3161Verdict,
} from './rfc3161-token';

export { authorityOf, subjectCommonName, trustAnchorsFromPem, UnreadableTrustAnchorError };

// Set up pkijs crypto engine with Node 20's built-in Web Crypto API
// No @peculiar/webcrypto needed — globalThis.crypto is sufficient in Node 20+
const cryptoEngine = new pkijs.CryptoEngine({
  name: 'node',
  crypto: globalThis.crypto,
});
pkijs.setEngine('node', cryptoEngine as any);

export interface TSTInfoParsed {
  messageImprint: {
    hashAlgorithm: string;
    hashedMessage: string; // hex
  };
  genTime: Date;
  serialNumber?: string;
  tsaName?: string;
  /**
   * The TSTInfo `nonce`, hex-encoded, or undefined when the token carries none.
   *
   * RFC 3161 §2.4.2: "If the nonce field is present in the TimeStampReq, then
   * it MUST be present in the TSTInfo and it MUST have the same value." The
   * client sends a fresh random nonce on every request and refuses a response
   * that does not echo it, which is what stops a cached or replayed
   * TimeStampResp from being accepted as a fresh timestamp.
   */
  nonce?: string;
}

export type TimestampVerificationReason =
  | 'unparseable_token'
  | 'verification_failed'
  | 'missing_dependency'
  /**
   * The token is internally consistent — its digest matches, its CMS signature
   * verifies, and it names its signer, a timestamping certificate — but no
   * valid path leads from that certificate to a trusted root. Distinguished
   * from `verification_failed` because it is the self-signed-token case, where
   * everything checks out except who vouched for it.
   */
  | 'untrusted_chain';

export interface TimestampVerificationResult {
  valid: boolean;
  reason?: TimestampVerificationReason;
  digestMatch?: boolean;
  signatureValid?: boolean;
  certificateChainValid?: boolean;
  genTime?: Date;
  /** The signer certificate's `authority` (tzun-anchor/1 §10.5 step 4): its first commonName as encoded, or `''`. */
  tsaSubject?: string;
  error?: string;
}

/**
 * Parse a base64-encoded RFC 3161 TimeStampResp into its ASN.1 structure.
 *
 * @param base64Token - Base64-encoded DER TimeStampResp
 * @returns The parsed ASN.1 structure
 * @throws Error if the input is not valid ASN.1
 */
/**
 * The bytes CMS treats as the encapsulated content.
 *
 * pkijs represents eContent differently depending on its tag: a universal
 * primitive OCTET STRING keeps its bytes in `valueBlock.valueHexView`, while a
 * constructed one has to be reassembled from its chunks via `getValue()`.
 */
function eContentBytes(eContent: asn1js.BaseBlock): Uint8Array {
  if (eContent.idBlock.tagClass === 1 && eContent.idBlock.tagNumber === 4) {
    const direct = (eContent.valueBlock as unknown as { valueHexView?: Uint8Array }).valueHexView;
    if (direct && direct.length > 0) return direct;
    return new Uint8Array((eContent as asn1js.OctetString).getValue());
  }
  return eContent.valueBlock.valueBeforeDecodeView;
}

export function parseTimestampResponse(base64Token: string): asn1js.Sequence {
  if (!base64Token || base64Token.length === 0) {
    throw new Error('Empty timestamp token');
  }

  const der = Buffer.from(base64Token, 'base64');
  const asn1 = asn1js.fromBER(der);

  if (asn1.offset === -1) {
    throw new Error('Failed to parse DER-encoded timestamp response: invalid ASN.1');
  }

  const result = asn1.result;
  if (!(result instanceof asn1js.Sequence)) {
    throw new Error('Timestamp response is not an ASN.1 SEQUENCE');
  }

  return result;
}

/**
 * Extract the TSTInfo from a parsed TimeStampResp.
 *
 * TimeStampResp ::= SEQUENCE {
 *   status  PKIStatusInfo,
 *   timeStampToken  TimeStampToken OPTIONAL
 * }
 *
 * TimeStampToken is a CMS ContentInfo containing SignedData,
 * which in turn contains TSTInfo as its encapsulated content.
 *
 * @param tsResp - Parsed ASN.1 SEQUENCE of the TimeStampResp
 * @returns Parsed TSTInfo with digest and timestamp
 */
export function extractTSTInfo(tsResp: asn1js.Sequence): TSTInfoParsed {
  // Extract status (first element)
  const statusSeq = tsResp.valueBlock.value[0];
  if (statusSeq instanceof asn1js.Sequence) {
    const statusInt = statusSeq.valueBlock.value[0];
    if (statusInt instanceof asn1js.Integer) {
      const statusValue = statusInt.valueBlock.valueDec;
      if (statusValue !== 0 && statusValue !== 1) {
        throw new Error(`TSA returned non-success status: ${statusValue}`);
      }
    }
  }

  // Extract timeStampToken (second element) — CMS ContentInfo
  if (tsResp.valueBlock.value.length < 2) {
    throw new Error('TimeStampResp does not contain a timeStampToken');
  }

  const contentInfo = tsResp.valueBlock.value[1] as asn1js.Sequence;
  if (!(contentInfo instanceof asn1js.Sequence)) {
    throw new Error('TimeStampToken is not a valid ContentInfo SEQUENCE');
  }

  // Parse as CMS ContentInfo -> SignedData -> encapContentInfo -> TSTInfo
  const cmsContentInfo = new pkijs.ContentInfo({ schema: contentInfo });
  const signedData = new pkijs.SignedData({ schema: cmsContentInfo.content });

  // The encapsulated content is TSTInfo (OID 1.2.840.113549.1.9.16.1.4)
  const encapContent = signedData.encapContentInfo;
  if (!encapContent || !encapContent.eContent) {
    throw new Error('SignedData does not contain encapsulated TSTInfo content');
  }

  // Parse TSTInfo ASN.1 structure.
  //
  // CMS eContent may be a primitive OCTET STRING (what a DER-encoding TSA
  // emits) or a constructed one carrying chunks (legal BER). `valueHexView` is
  // empty for the constructed form, so eContentBytes reads either. This reader
  // is lenient on purpose: it serves capture and metadata, and the
  // tzun-anchor/1 §10.5 verdict is readRfc3161Token's.
  const tstInfoDer = eContentBytes(encapContent.eContent);
  const tstInfoAsn1 = asn1js.fromBER(tstInfoDer);
  if (tstInfoAsn1.offset === -1) {
    throw new Error('Failed to parse TSTInfo ASN.1');
  }

  const tstInfoSeq = tstInfoAsn1.result as asn1js.Sequence;
  const tstInfoValues = tstInfoSeq.valueBlock.value;

  // TSTInfo ::= SEQUENCE {
  //   version INTEGER,
  //   policy  OBJECT IDENTIFIER,
  //   messageImprint MessageImprint,
  //   serialNumber INTEGER,
  //   genTime GeneralizedTime,
  //   ...
  // }

  // messageImprint is the 3rd element (index 2)
  const messageImprintSeq = tstInfoValues[2] as asn1js.Sequence;
  const algIdSeq = messageImprintSeq.valueBlock.value[0] as asn1js.Sequence;
  const algOid = (algIdSeq.valueBlock.value[0] as asn1js.ObjectIdentifier).valueBlock.toString();
  const hashedMessageOctet = messageImprintSeq.valueBlock.value[1] as asn1js.OctetString;
  const hashedMessageHex = Buffer.from(hashedMessageOctet.valueBlock.valueHexView).toString('hex');

  // Map OID to algorithm name
  const algName = algOid === '2.16.840.1.101.3.4.2.1' ? 'SHA-256' : algOid;

  // genTime is the 5th element (index 4)
  const genTimeEl = tstInfoValues[4] as asn1js.GeneralizedTime;
  const genTime = genTimeEl.toDate();

  // nonce is optional and follows genTime:
  //   TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber,
  //                          genTime, accuracy OPTIONAL, ordering DEFAULT FALSE,
  //                          nonce OPTIONAL, tsa [0] OPTIONAL, extensions [1] OPTIONAL }
  // accuracy is a SEQUENCE and ordering a BOOLEAN, so the first INTEGER after
  // genTime is unambiguously the nonce.
  let nonce: string | undefined;
  for (let i = 5; i < tstInfoValues.length; i++) {
    const el = tstInfoValues[i];
    if (el instanceof asn1js.Integer) {
      nonce = Buffer.from(el.valueBlock.valueHexView).toString('hex');
      break;
    }
  }

  return {
    messageImprint: {
      hashAlgorithm: algName,
      hashedMessage: hashedMessageHex,
    },
    genTime,
    nonce,
  };
}

/**
 * Compare two DER INTEGER contents as numbers, ignoring leading zero padding.
 *
 * A TSA is free to re-encode the nonce it echoes (dropping or adding the
 * leading 0x00 that keeps a high-bit-set value positive), so a raw hex string
 * comparison would reject genuine tokens.
 */
export function nonceMatches(a: string | undefined, b: string | undefined): boolean {
  if (a === undefined || b === undefined) return false;
  const strip = (h: string) => h.toLowerCase().replace(/^(00)+/, '') || '0';
  return strip(a) === strip(b);
}

/** Map PKIStatus integer to typed string. */
export function parsePKIStatus(
  statusValue: number
): 'granted' | 'grantedWithMods' | 'rejection' | 'waiting' {
  switch (statusValue) {
    case 0: return 'granted';
    case 1: return 'grantedWithMods';
    case 2: return 'rejection';
    case 3: return 'waiting';
    default: return 'rejection'; // Unknown status treated as rejection
  }
}

/**
 * Extract PKIStatus from a parsed TimeStampResp.
 *
 * @param tsResp - Parsed ASN.1 SEQUENCE of the TimeStampResp
 * @returns The PKIStatus integer value
 */
export function extractPKIStatus(tsResp: asn1js.Sequence): number {
  const statusSeq = tsResp.valueBlock.value[0];
  if (statusSeq instanceof asn1js.Sequence) {
    const statusInt = statusSeq.valueBlock.value[0];
    if (statusInt instanceof asn1js.Integer) {
      return statusInt.valueBlock.valueDec;
    }
  }
  throw new Error('Could not extract PKIStatus from TimeStampResp');
}

/**
 * Extract the policy OID from TSTInfo.
 *
 * TSTInfo ::= SEQUENCE {
 *   version INTEGER,
 *   policy  OBJECT IDENTIFIER,  <-- index 1
 *   ...
 * }
 */
export function extractPolicyOid(tstInfoSeq: asn1js.Sequence): string | undefined {
  try {
    const policyOid = tstInfoSeq.valueBlock.value[1];
    if (policyOid instanceof asn1js.ObjectIdentifier) {
      return policyOid.valueBlock.toString();
    }
  } catch {
    // Non-fatal
  }
  return undefined;
}

/**
 * Extract RFC 3161 metadata from a base64-encoded TimeStampResp.
 *
 * @param base64Token - Base64-encoded DER TimeStampResp
 * @returns Metadata object or null if parsing fails
 */
export function extractRFC3161Metadata(base64Token: string): {
  genTime: string;
  tsaName?: string;
  policyOid?: string;
  status: 'granted' | 'grantedWithMods' | 'rejection' | 'waiting';
} | null {
  try {
    const tsResp = parseTimestampResponse(base64Token);
    const statusValue = extractPKIStatus(tsResp);
    const status = parsePKIStatus(statusValue);

    // If status is rejection or waiting, return early with just the status
    if (status === 'rejection' || status === 'waiting') {
      return {
        genTime: new Date(0).toISOString(), // placeholder
        status,
      };
    }

    const tstInfo = extractTSTInfo(tsResp);

    // Extract policy OID from the raw TSTInfo ASN.1
    // Re-parse to get the raw sequence (extractTSTInfo already parsed it)
    const der = Buffer.from(base64Token, 'base64');
    const asn1Result = asn1js.fromBER(der);
    const tsRespSeq = asn1Result.result as asn1js.Sequence;
    const contentInfoSeq = tsRespSeq.valueBlock.value[1] as asn1js.Sequence;
    const cmsContentInfo = new pkijs.ContentInfo({ schema: contentInfoSeq });
    const signedData = new pkijs.SignedData({ schema: cmsContentInfo.content });
    const encapContent = signedData.encapContentInfo;

    let policyOid: string | undefined;
    let tsaName: string | undefined;

    if (encapContent?.eContent) {
      const tstInfoDer = encapContent.eContent.valueBlock.valueHexView;
      const tstInfoAsn1 = asn1js.fromBER(tstInfoDer);
      const tstInfoSeq = tstInfoAsn1.result as asn1js.Sequence;
      policyOid = extractPolicyOid(tstInfoSeq);
    }

    // Extract TSA name from the signer certificate subject
    if (signedData.certificates && signedData.certificates.length > 0) {
      try {
        const signerCert = signedData.certificates[0] as pkijs.Certificate;
        const subject = signerCert.subject;
        // Look for Common Name (OID 2.5.4.3) in the subject
        for (const rdn of subject.typesAndValues) {
          if (rdn.type === '2.5.4.3') {
            tsaName = rdn.value.valueBlock.value;
            break;
          }
        }
      } catch {
        // Non-fatal
      }
    }

    return {
      genTime: tstInfo.genTime.toISOString(),
      tsaName,
      policyOid,
      status,
    };
  } catch {
    return null;
  }
}

/** Split a PEM bundle into individual certificate blocks. */
function splitPemBundle(pem: string): string[] {
  return pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
}

/**
 * Where the verifier's trust anchors come from.
 *
 * The product supports any RFC 3161 TSA — `TzunConfig.attestation.timestamp.rfc3161Url`
 * and the backend's `TZUN_TSA_URL` both take an arbitrary URL — so a
 * deployment that captures against an authority outside the default pair has
 * to tell the verifier which root to trust for it. These options are how.
 */
export interface TrustAnchorOptions {
  /**
   * PEM-encoded trust anchors. When omitted, `TZUN_TSA_TRUST_ANCHORS` is
   * consulted (inline PEM, or one or more file paths separated by the platform
   * path delimiter), and failing that the default trust store is used: the
   * roots of `DEFAULT_TRUST_ANCHOR_AUTHORITIES` (FreeTSA and Sectigo).
   */
  trustAnchorsPem?: string[];
  /**
   * Timestamp authorities to trust, named by registry key (`'sectigo'`) or by
   * the URL already in the capture config (`'https://timestamp.sectigo.com'`).
   * Their roots are bundled; see `./tsa-registry`.
   *
   * This is the ergonomic half of a capability the verifier already had. An
   * integrator pointing capture at Sectigo could always make verification work
   * by finding Sectigo's *timestamping* root — not the cross-signed copy in
   * the token, not the USERTrust root above it — converting it to PEM and
   * passing it as `trustAnchorsPem`. That is three chances to pin the wrong
   * certificate and no feedback when you do, so in practice nobody did it and
   * the capability went unused. Naming the authority is the same decision with
   * the PKI archaeology already done, and the anchors are fingerprint-pinned in
   * the suite.
   *
   * An unknown name THROWS rather than being ignored, because a silently
   * dropped authority does not fail here — it fails months later as
   * `untrusted_chain` on evidence that is perfectly genuine.
   */
  authorities?: string[];
}

/**
 * Resolve the trust anchors to check a TSA signing certificate against.
 *
 * Precedence, highest first:
 *
 *  1. The explicit options — `trustAnchorsPem` and `authorities`, UNIONED. A
 *     caller who passes both means both: one names authorities this package
 *     ships roots for, the other supplies a root it does not.
 *  2. The environment — `TZUN_TSA_TRUST_ANCHORS` (inline PEM, or file paths
 *     separated by the platform path delimiter) and `TZUN_TSA_AUTHORITIES` (a
 *     comma-separated list of registry keys or URLs), also unioned, and
 *     consulted only when neither option was given. Either env var alone is a
 *     complete configuration.
 *  3. The roots of `DEFAULT_TRUST_ANCHOR_AUTHORITIES` — FreeTSA and Sectigo,
 *     the same two authorities an unconfigured capture obtains tokens from.
 *
 * The other bundled roots are not trusted unless named. Every anchor in the
 * store is a signing hierarchy whose signature makes a token verify, so the
 * default holds the roots the default capture list needs and no others. See
 * `DEFAULT_TRUST_ANCHOR_AUTHORITIES` for the trade-off in full.
 */
export function resolveTrustAnchors(opts?: TrustAnchorOptions): string[] {
  const fromOptions = [
    ...(opts?.trustAnchorsPem ?? []),
    ...(opts?.authorities && opts.authorities.length > 0
      ? timestampAuthorityAnchorsPem(opts.authorities)
      : []),
  ];
  if (fromOptions.length > 0) {
    return dedupePem(fromOptions.flatMap((p) => splitPemBundle(p)));
  }

  const fromEnv: string[] = [];
  const envPem = process.env.TZUN_TSA_TRUST_ANCHORS;
  if (envPem && envPem.trim().length > 0) {
    if (envPem.includes('-----BEGIN CERTIFICATE-----')) {
      fromEnv.push(...splitPemBundle(envPem));
    } else {
      fromEnv.push(
        ...envPem
          .split(path.delimiter)
          .map((p) => p.trim())
          .filter((p) => p.length > 0)
          .flatMap((p) => splitPemBundle(fs.readFileSync(p, 'utf-8'))),
      );
    }
  }
  const envAuthorities = process.env.TZUN_TSA_AUTHORITIES;
  if (envAuthorities && envAuthorities.trim().length > 0) {
    const selectors = envAuthorities
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    fromEnv.push(...timestampAuthorityAnchorsPem(selectors).flatMap((p) => splitPemBundle(p)));
  }
  if (fromEnv.length > 0) return dedupePem(fromEnv);

  // Derived from DEFAULT_TRUST_ANCHOR_AUTHORITIES rather than hardcoded, so the
  // default is stated in exactly one place — the same place the capture-side
  // default is derived from. Reading the PEM files directly here would leave a
  // second, silent definition of the default that the constant does not
  // control.
  return dedupePem(
    timestampAuthorityAnchorsPem(DEFAULT_TRUST_ANCHOR_AUTHORITIES).flatMap((p) =>
      splitPemBundle(p),
    ),
  );
}

/**
 * The trust anchors `resolveTrustAnchors(opts)` names, read: every one of them
 * a certificate with a key this verifier reads (`trustAnchorsFromPem`). Each
 * source is held to that as the auditor gave it, before any is merged or
 * deduplicated: every entry of `trustAnchorsPem`, or, when the options name
 * none, every inline PEM or file of `TZUN_TSA_TRUST_ANCHORS`, must hold a
 * certificate that reads. An entry with no certificate, an authority that is
 * not a string or that the registry does not know, a path that cannot be read
 * and a root that does not read are all refused the same way, since each is
 * an auditor input that cannot be read (Verification §3.1, §6.6). The Python
 * SDK's `check_trust_configuration` refuses the same inputs with the same
 * messages.
 *
 * @throws UnreadableTrustAnchorError
 */
export function readTrustAnchors(opts?: TrustAnchorOptions): Rfc3161Certificate[] {
  const pems: unknown = opts?.trustAnchorsPem;
  const authorities: unknown = opts?.authorities;
  if (pems !== undefined && !Array.isArray(pems)) throw new UnreadableTrustAnchorError('the trust anchors are not a list of PEM strings');
  if (authorities !== undefined && (!Array.isArray(authorities) || authorities.some((a) => typeof a !== 'string'))) {
    throw new UnreadableTrustAnchorError('the authorities are not a list of names');
  }
  if ((Array.isArray(pems) && pems.length > 0) || (Array.isArray(authorities) && authorities.length > 0)) {
    trustAnchorsFromPem((pems as unknown[] | undefined) ?? []);
  } else {
    const env = process.env.TZUN_TSA_TRUST_ANCHORS;
    if (env && env.trim().length > 0) {
      const sources = env.includes('-----BEGIN CERTIFICATE-----')
        ? [env]
        : env
            .split(path.delimiter)
            .map((p) => p.trim())
            .filter((p) => p.length > 0)
            .map((p) => {
              try {
                return fs.readFileSync(p, 'utf-8');
              } catch {
                // The same words on every platform and in both SDKs: the
                // path, not the operating system's reason.
                throw new UnreadableTrustAnchorError(`TZUN_TSA_TRUST_ANCHORS: ${p} cannot be read`);
              }
            });
      trustAnchorsFromPem(sources);
    }
  }
  let resolved: string[];
  try {
    resolved = resolveTrustAnchors(opts);
  } catch (err) {
    throw new UnreadableTrustAnchorError(`the trust anchors cannot be read: ${(err as Error)?.message ?? String(err)}`);
  }
  return trustAnchorsFromPem(resolved);
}

/**
 * Drop repeated certificates, keeping first appearance.
 *
 * Two sources can legitimately name the same root — `authorities: ['sectigo',
 * 'entrust']` is one root, and an integrator may pass a PEM that a selected
 * authority also ships. A duplicated anchor changes no trust decision, but it
 * makes `resolveTrustAnchors().length` report a trust store larger than it is,
 * which is exactly the number an operator would read when auditing what their
 * verifier trusts.
 */
function dedupePem(pems: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const pem of pems) {
    const key = pem.replace(/\s+/g, '');
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(pem);
  }
  return out;
}

export interface CertificatePathOptions extends TrustAnchorOptions {
  /**
   * Additional certificates that may sit between the signer and an anchor —
   * in practice, the other certificates carried in the CMS SignedData.
   *
   * Without these, only a certificate issued *directly* by an anchor could ever
   * validate. That is not how public TSAs are structured, and it means a
   * FreeTSA rotation to an intermediate-issued signing certificate would
   * silently invalidate every token ever issued.
   */
  intermediatesPem?: string[];
  /** The instant the certificate had to be valid at — normally TSTInfo.genTime. */
  atTime?: Date;
}

/**
 * Find a path from a signer certificate up to one of the configured trust
 * anchors (tzun-anchor/1 §10.5 step 4).
 *
 * Every path is considered in which each certificate's issuer name is the next
 * one's subject name, drawn from `intermediatesPem` and the anchors. A path is
 * valid when each issuer's signature over its subject verifies (the name match
 * alone proves nothing: every field it compares is attacker-choosable), every
 * certificate between the signer and the anchor is a CA (`basicConstraints`
 * `cA`, `keyCertSign` when `keyUsage` is present, within its
 * `pathLenConstraint`), and every certificate on it, the anchor included, was
 * valid at `atTime`.
 *
 * The signer's own extendedKeyUsage is not a path rule: `verifyTimestampToken`
 * checks it with the token's signer binding (tzun-anchor/1 §10.5 step 3). An
 * anchor or intermediate that does not read (`readTrustAnchors`) makes the
 * result `valid: false` with the reason, never a search without it.
 */
export function verifyCertificatePath(
  signerCertPem: string,
  opts: CertificatePathOptions = {},
): { valid: boolean; error?: string; anchorSubject?: string } {
  try {
    const signer = readCertificatePem(signerCertPem);
    if (signer === null) return { valid: false, error: 'The signer certificate does not parse' };
    const anchors = readTrustAnchors(opts);
    const intermediates = trustAnchorsFromPem(opts.intermediatesPem ?? []);
    const path = searchTrustPath(signer, intermediates, anchors, opts.atTime);
    if (path.outcome === 'valid') return { valid: true, anchorSubject: subjectCommonName(path.root!.x509) };
    return { valid: false, error: path.error };
  } catch (err: any) {
    return { valid: false, error: err.message };
  }
}

/**
 * Verify the TSA certificate chains to a trusted root.
 *
 * Kept for callers that have a single anchor and no intermediates. New code
 * should call `verifyCertificatePath`, which can build a real path and reports
 * which anchor it terminated at.
 *
 * @param signerCertPem - PEM-encoded TSA signing certificate
 * @param caCertOverride - Optional CA cert PEM override. Pass null to use the
 *        configured anchors (see `resolveTrustAnchors`).
 * @returns Validation result
 */
export function verifyCertificateChain(
  signerCertPem: string,
  caCertOverride: string | null,
  atTime?: Date,
): { valid: boolean; error?: string } {
  const { valid, error } = verifyCertificatePath(signerCertPem, {
    ...(caCertOverride ? { trustAnchorsPem: [caCertOverride] } : {}),
    ...(atTime ? { atTime } : {}),
  });
  return valid ? { valid: true } : { valid: false, error };
}

/**
 * Full RFC 3161 timestamp verification, by the rules of tzun-anchor/1 §10.5.
 *
 * - The token must be RFC 4648 base64 of a DER TimeStampResp, granted, whose
 *   CMS SignedData carries a DER TSTInfo, exactly one SignerInfo, and the
 *   certificate it names (tzun-anchor/1 §10.5 step 1). Otherwise
 *   `{ valid: false, reason: 'unparseable_token' }`.
 * - `digestMatch`: the imprint is SHA-256 over `expectedDigest` (step 2).
 * - `signatureValid`: the content-type and message-digest attributes, the CMS
 *   signature, a signingCertificate(V2) that names the signer certificate, and
 *   a critical extendedKeyUsage on it whose only purpose is timestamping
 *   (step 3). A certificate issued for any other purpose never yields a
 *   timestamp, whoever issued it.
 * - `certificateChainValid`: some path from the signer to a configured trust
 *   anchor is valid at genTime (step 4, `verifyCertificatePath`'s rules).
 *
 * `valid` is `true` only when all three hold. A failed imprint or signer check
 * is `verification_failed`; a token whose imprint and signer hold and whose
 * signer chains validly to no configured anchor is `untrusted_chain`; a token
 * over the expected value whose step 3 needs an algorithm this verifier does
 * not implement is `missing_dependency` (a token over another value is
 * `verification_failed` whatever algorithm it names), and so is one whose
 * steps 1 to 3 hold and whose only path to an anchor has a signature this
 * verifier cannot check (step 5; `signatureValid` is then `true`). Every field
 * is computed whatever the others say, so a caller can tell which failed. This
 * function never throws on the token, and never returns `valid: true` from an
 * error path.
 *
 * @param base64Token - Base64-encoded DER TimeStampResp
 * @param expectedDigest - 64-char hex SHA-256 digest
 * @returns Full verification result with reason on failure
 * @throws UnreadableTrustAnchorError when the trust anchors `opts` names
 *   cannot be read (`readTrustAnchors`): the verifier's own input, refused
 *   rather than dropped.
 */
export async function verifyTimestampToken(
  base64Token: string,
  expectedDigest: string,
  opts: TrustAnchorOptions = {},
): Promise<TimestampVerificationResult> {
  const roots = readTrustAnchors(opts);
  try {
    return timestampToken(base64Token, expectedDigest, roots);
  } catch (err) {
    // Nothing above is expected to throw on a token; should it, the verifier
    // failed, and that is reported as a missing dependency, never as valid.
    return { valid: false, reason: 'missing_dependency', error: `${VERIFIER_FAILED}: ${(err as Error)?.message ?? String(err)}` };
  }
}

function timestampToken(base64Token: string, expectedDigest: string, roots: Rfc3161Certificate[]): TimestampVerificationResult {
  const read = readRfc3161Token(base64Token);
  if (!read.ok) return { valid: false, reason: 'unparseable_token', error: read.error };
  const token = read.token;
  const genTime = token.tstInfo.genTime;
  const tsaSubject = authorityOf(token.signer);

  // The imprint is step 2 and runs first: a token over another value is
  // verification_failed (imprint_mismatch to verifyAttestation) whatever
  // algorithm its signature names.
  const digestMatch = imprintHolds(token, expectedDigest);
  const signer = checkSignatureAndSigner(token);
  if (digestMatch && !signer.ok && signer.reason === 'missing_dependency') {
    return { valid: false, reason: 'missing_dependency', digestMatch, genTime, tsaSubject, error: signer.error };
  }
  const signatureValid = signer.ok;

  // The trust anchor, not a nicety: the signature above is checked against the
  // certificate carried INSIDE the token, so on its own it proves only that the
  // token is internally consistent. A self-signed token passes it. A valid path
  // from that certificate to a pinned root is what makes the timestamp mean a
  // third party attested to it.
  const path = searchTrustPath(token.signer, token.certificates.filter((c) => c !== token.signer), roots, genTime);
  const certificateChainValid = path.outcome === 'valid';
  const chainError = path.error;

  if (!digestMatch || !signatureValid || !certificateChainValid) {
    const untrusted = !certificateChainValid && digestMatch && signatureValid;
    const error = untrusted
      ? chainError
      : !digestMatch
        ? 'the imprint is not SHA-256 over the expected value'
        : !signer.ok
          ? signer.error
          : undefined;
    return {
      valid: false,
      reason: untrusted ? (path.outcome === 'missing_dependency' ? 'missing_dependency' : 'untrusted_chain') : 'verification_failed',
      digestMatch,
      signatureValid,
      certificateChainValid,
      genTime,
      tsaSubject,
      ...(error !== undefined && { error }),
    };
  }

  return { valid: true, digestMatch, signatureValid, certificateChainValid, genTime, tsaSubject };
}

/**
 * tzun-anchor/1 §10.5 steps 1 to 4 over one token, in order, with only
 * `trustAnchorsPem` as roots: the first step that does not hold decides, and
 * step 4 runs only once steps 1 to 3 hold. With no roots, step 4 reaches none.
 * This is the verdict of a bundle's `ts.record.token` and `ts.record.trust`
 * (Verification §4.4), where only the roots the caller supplies count.
 *
 * @throws UnreadableTrustAnchorError when a root does not read (`trustAnchorsFromPem`).
 */
export function verifyTimestampSteps(base64Token: unknown, expectedDigest: string, trustAnchorsPem: string[]): Rfc3161Verdict {
  return verifyRfc3161Steps(base64Token, expectedDigest, trustAnchorsFromPem(trustAnchorsPem));
}
