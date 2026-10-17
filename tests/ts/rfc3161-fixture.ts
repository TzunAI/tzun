/**
 * An offline RFC 3161 TSA, built with pkijs.
 *
 * The verifier suite needs a positive fixture: a test that only feeds the
 * verifier garbage and asserts `valid: false` still passes when a change makes
 * the verifier reject *everything*. This produces a genuine
 * TimeStampResp — real certificates, a real CMS SignedData, a real ECDSA
 * signature over the signed attributes — issued by a CA that is emphatically
 * not FreeTSA, which is the only way to test that the trust store is
 * injectable.
 *
 * By default a token meets every rule of tzun-anchor/1 §10.5, as a real
 * public authority's does: the TimeStampResp and its TSTInfo are DER (the
 * TSTInfo in a primitive OCTET STRING, genTime with no trailing zero in its
 * fraction), the signed attributes carry a signingCertificateV2 (ESSCertIDv2)
 * over the signer certificate, the signer certificate has a critical
 * extendedKeyUsage whose only purpose is id-kp-timeStamping, and every CA
 * certificate has `cA` and `keyCertSign`. `TokenFaults` breaks one rule at a
 * time, for the negative cases.
 *
 * Not a suite: jest's testMatch is `**\/tests/**\/*.test.ts`.
 */
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { createHash } from 'crypto';

const cryptoEngine = new pkijs.CryptoEngine({ name: 'fixture', crypto: globalThis.crypto });
pkijs.setEngine('fixture', cryptoEngine as any);

const OID_CN = '2.5.4.3';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_SIGNING_CERTIFICATE = '1.2.840.113549.1.9.16.2.12';
const OID_SIGNING_CERTIFICATE_V2 = '1.2.840.113549.1.9.16.2.47';
const OID_ID_CT_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_DATA = '1.2.840.113549.1.7.1';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_TSA_POLICY = '1.3.6.1.4.1.99999.1.1';
const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_KEY_USAGE = '2.5.29.15';
const OID_EXT_KEY_USAGE = '2.5.29.37';
const OID_KP_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';
const OID_KP_SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
const OID_KP_CODE_SIGNING = '1.3.6.1.5.5.7.3.3';
const OID_SUBJECT_KEY_IDENTIFIER = '2.5.29.14';

/**
 * One way a token breaks tzun-anchor/1 §10.5, for the negative cases. A token
 * built with none of them meets every rule.
 */
export interface TokenFaults {
  /**
   * Step 1: the TSTInfo in a constructed (BER) OCTET STRING, which is what
   * pkijs writes unless told otherwise. It decodes to the same bytes, and it
   * is not DER.
   */
  berTstInfo?: boolean;
  /**
   * Step 1: genTime with its fraction's trailing zeros kept (`…00.500Z`), as
   * asn1js writes a Date; DER writes `…00.5Z`. Visible only when the
   * millisecond ends in zero.
   */
  nonDerGenTime?: boolean;
  /** Step 1: the token carries no certificate for its SignerInfo (a request sent without certReq). */
  withoutSignerCertificate?: boolean;
  /** Step 1: SignedData.digestAlgorithms holds a bare OBJECT IDENTIFIER, not an AlgorithmIdentifier. The set is unsigned. */
  digestAlgorithms?: 'bare-oid';
  /**
   * The signer certificate's public key made unreadable (`withUnreadableKey`),
   * the token otherwise genuine: `'bad-key'` breaks step 1 (not a
   * certificate), `'unknown-key-algorithm'` and `'unassigned-curve'` leave
   * step 3 to a verifier that implements the algorithm or the curve
   * (`missing_dependency`, §10.5 steps 1 and 5).
   */
  signerKey?: UnreadableKey;
  /**
   * The token also carries a CA certificate with the subject name of the
   * signer's issuer, issued by the root, whose key is unreadable
   * (`withUnreadableKey`). The certificates set is unsigned: anyone can add
   * one to a genuine token. `'bad-key'` breaks step 1; with
   * `'unknown-key-algorithm'` or `'unassigned-curve'` the certificate is
   * read with its key unread, it signs nothing a verifier can check, and the
   * genuine path still holds.
   */
  issuerCopy?: UnreadableKey;
  /**
   * The token also carries a certificate no path names (its subject is no
   * certificate's issuer), issued by the root, whose key names the curve OID
   * 1.2.840.10045.3.1.99, assigned to no curve. No step needs it, so it is
   * not examined past step 1, and every step holds (§10.5 step 5).
   */
  unneededCertificate?: 'unassigned-curve';
  /**
   * Step 4 (step 5): the signer is issued by an intermediate CA the token
   * carries, whose key names the curve OID 1.2.840.10045.3.1.99, assigned to
   * no curve; the intermediate is signed again by the root after its key was
   * renamed, so every rule of the path holds but for the intermediate's own
   * signature over the signer, which no verifier can check:
   * `missing_dependency` on the trust check.
   */
  signerIssuer?: 'intermediate-unassigned-curve';
  /**
   * Not a fault: the signer certificate's subject Name, as DER, in place of
   * one commonName. It shapes the trust check's `authority` fact (§10.5
   * step 4), and every step holds.
   */
  signerSubject?: Buffer;
  /** Step 3: the content-type attribute names id-data instead of id-ct-TSTInfo. */
  contentType?: 'data';
  /** Step 3: the message-digest attribute is the digest of other bytes than the TSTInfo. */
  messageDigest?: 'other';
  /**
   * Step 4: the signer certificate names its issuer with the CN as a
   * UTF8String, where the issuer's own subject writes it as a
   * PrintableString. The same distinguished name in another encoding is
   * another name, so no path reaches the root.
   */
  signerIssuerName?: 'utf8';
  /**
   * Step 3: the signer binding. Default `'v2'`, a signingCertificateV2
   * (ESSCertIDv2, SHA-256); `'v1'` a signingCertificate (ESSCertID, SHA-1);
   * `'none'` neither; `'other-certificate'` a signingCertificateV2 whose
   * certHash names the root instead of the signer. `'v2-unknown-hash'` an
   * ESSCertIDv2 whose hash algorithm is 2.16.840.1.101.3.4.2.127, which no
   * verifier implements, so its certHash cannot be checked: when every other
   * requirement of step 3 holds, `missing_dependency` (§10.5 step 5).
   * `'v2-unknown-hash-other-serial'` the same, its issuerSerial naming another
   * serial number: a requirement the verifier can check fails first,
   * `verification_failed`.
   */
  signingCertificate?: 'v2' | 'v1' | 'none' | 'other-certificate' | 'v2-unknown-hash' | 'v2-unknown-hash-other-serial';
  /**
   * The members after genTime (RFC 3161 §2.4.2), the nonce among them
   * wherever the shape puts it. `'all'` is not a fault: every optional
   * member, each as RFC 3161 has it (accuracy of seconds 1, millis 999 and
   * micros 1, ordering written out as FALSE, the nonce, tsa as a
   * directoryName, one extension), meets every rule of tzun-anchor/1 §10.5
   * step 1. Each other shape breaks one: `'member-after-extensions'` every
   * member, then a NULL; `'ordering-after-nonce'` ordering after the nonce;
   * `'millis-zero'` and `'micros-1000'` an accuracy outside 1 to 999;
   * `'tsa-empty'` a tsa holding no GeneralName; `'tsa-dns-name-constructed'`
   * a dNSName in the constructed form; `'extensions-empty'` extensions
   * holding none.
   */
  tstInfoTail?:
    | 'all'
    | 'member-after-extensions'
    | 'ordering-after-nonce'
    | 'millis-zero'
    | 'micros-1000'
    | 'tsa-empty'
    | 'tsa-dns-name-constructed'
    | 'extensions-empty';
  /**
   * Not a fault: the signed attributes in the reverse of DER SET OF order,
   * signed as carried. Step 1 does not require that order, and the signature
   * is verified over the attributes as the token carries them (tzun-anchor/1
   * §10.5 step 3, RFC 5652 §5.4), so every step holds.
   */
  signedAttrsOrder?: 'reversed';
  /**
   * Step 3: the signer certificate's extendedKeyUsage. Default
   * `'timestamping'` (critical, id-kp-timeStamping only); `'none'` no
   * extension (an unconstrained v3 certificate); `'non-critical'`
   * id-kp-timeStamping not marked critical; `'tls-server'` a TLS server
   * certificate; `'second-purpose'` id-kp-timeStamping and code signing.
   */
  signerEku?: 'timestamping' | 'none' | 'non-critical' | 'tls-server' | 'second-purpose';
}

/** How `withUnreadableKey` makes a certificate's key unreadable. */
export type UnreadableKey = 'bad-key' | 'unknown-key-algorithm' | 'unassigned-curve';

/** The OBJECT IDENTIFIER 1.2.840.10045.3.1.99, a named curve OID assigned to no curve. */
const UNASSIGNED_CURVE = '06082a8648ce3d030163';

function toPem(der: ArrayBuffer | Buffer): string {
  return (
    '-----BEGIN CERTIFICATE-----\n' +
    (Buffer.isBuffer(der) ? der : Buffer.from(der)).toString('base64').match(/.{1,64}/g)!.join('\n') +
    '\n-----END CERTIFICATE-----'
  );
}

function cnTypeAndValue(cn: string, utf8 = false): pkijs.AttributeTypeAndValue {
  return new pkijs.AttributeTypeAndValue({
    type: OID_CN,
    value: utf8 ? new asn1js.Utf8String({ value: cn }) : new asn1js.PrintableString({ value: cn }),
  });
}

async function generateKeyPair(): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  return (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as { privateKey: CryptoKey; publicKey: CryptoKey };
}

interface IssuedCert {
  cert: pkijs.Certificate;
  pem: string;
  /** The certificate's DER, exactly as signed. */
  der: Buffer;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

/** A DER KeyUsage BIT STRING: `bits` set, trailing zero bits dropped. */
function keyUsage(bits: number[]): ArrayBuffer {
  const last = Math.max(...bits);
  const bytes = new Uint8Array((last >> 3) + 1);
  for (const b of bits) bytes[b >> 3] |= 0x80 >> (b & 7);
  return new asn1js.BitString({ valueHex: bytes.buffer, unusedBits: 7 - (last & 7) }).toBER(false);
}

function extension(extnID: string, critical: boolean, extnValue: ArrayBuffer): pkijs.Extension {
  return new pkijs.Extension({ extnID, critical, extnValue });
}

function ekuExtension(fault: NonNullable<TokenFaults['signerEku']>): pkijs.Extension | undefined {
  const purposes = (keyPurposes: string[]) => new pkijs.ExtKeyUsage({ keyPurposes }).toSchema().toBER(false);
  switch (fault) {
    case 'timestamping':
      return extension(OID_EXT_KEY_USAGE, true, purposes([OID_KP_TIME_STAMPING]));
    case 'non-critical':
      return extension(OID_EXT_KEY_USAGE, false, purposes([OID_KP_TIME_STAMPING]));
    case 'tls-server':
      return extension(OID_EXT_KEY_USAGE, false, purposes([OID_KP_SERVER_AUTH]));
    case 'second-purpose':
      return extension(OID_EXT_KEY_USAGE, true, purposes([OID_KP_TIME_STAMPING, OID_KP_CODE_SIGNING]));
    case 'none':
      return undefined;
  }
}

async function issueCertificate(opts: {
  subjectCN: string;
  serial: number;
  notBefore: Date;
  notAfter: Date;
  /** A CA certificate (`cA`, `keyCertSign`), or `'not-a-ca'`: one issued as an end entity. */
  isCa: boolean | 'not-a-ca';
  issuer?: IssuedCert;
  /** The extendedKeyUsage of an end-entity certificate. */
  eku?: NonNullable<TokenFaults['signerEku']>;
  /** A subjectKeyIdentifier extension with these bytes. */
  subjectKeyIdentifier?: Buffer;
  /** Write the issuer's CN as a UTF8String; every subject writes it as a PrintableString. */
  issuerNameUtf8?: boolean;
}): Promise<IssuedCert> {
  const { privateKey, publicKey } = await generateKeyPair();
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: opts.serial });
  cert.subject.typesAndValues.push(cnTypeAndValue(opts.subjectCN));
  const issuerCN = opts.issuer
    ? (opts.issuer.cert.subject.typesAndValues[0].value.valueBlock as any).value
    : opts.subjectCN;
  cert.issuer.typesAndValues.push(cnTypeAndValue(issuerCN, opts.issuerNameUtf8));
  cert.notBefore.value = opts.notBefore;
  cert.notAfter.value = opts.notAfter;

  if (opts.isCa === true) {
    // keyCertSign (5) and cRLSign (6).
    cert.extensions = [
      extension(OID_BASIC_CONSTRAINTS, true, new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(false)),
      extension(OID_KEY_USAGE, true, keyUsage([5, 6])),
    ];
  } else {
    // digitalSignature (0).
    const eku = ekuExtension(opts.eku ?? 'timestamping');
    cert.extensions = [extension(OID_KEY_USAGE, true, keyUsage([0])), ...(eku ? [eku] : [])];
  }
  if (opts.subjectKeyIdentifier) {
    cert.extensions = [
      ...(cert.extensions ?? []),
      extension(OID_SUBJECT_KEY_IDENTIFIER, false, new asn1js.OctetString({ valueHex: opts.subjectKeyIdentifier }).toBER(false)),
    ];
  }

  await cert.subjectPublicKeyInfo.importKey(publicKey, cryptoEngine as any);
  await cert.sign(opts.issuer ? opts.issuer.privateKey : privateKey, 'SHA-256', cryptoEngine as any);

  const der = cert.toSchema().toBER(false);
  return { cert, pem: toPem(der), der: Buffer.from(der), privateKey, publicKey };
}

/** A GeneralizedTime in DER form: `YYYYMMDDHHMMSS`, a fraction only when non-zero and with no trailing zero, then `Z`. */
function derGeneralizedTime(date: Date): asn1js.GeneralizedTime {
  const iso = date.toISOString(); // YYYY-MM-DDTHH:MM:SS.sssZ
  const whole = iso.slice(0, 19).replace(/[-:T]/g, '');
  const fraction = iso.slice(20, 23).replace(/0+$/, '');
  return new asn1js.GeneralizedTime({ value: `${whole}${fraction ? `.${fraction}` : ''}Z` });
}

function buildTstInfo(opts: {
  digestHex: string;
  genTime: Date;
  serial: number;
  /** Echoed as TSTInfo.nonce, as RFC 3161 §2.4.2 requires when the request carried one. */
  nonce?: Buffer | null;
  /** The messageImprint's hash algorithm OID. Default SHA-256. */
  imprintAlgorithmOid?: string;
  faults?: TokenFaults;
}): ArrayBuffer {
  const value: asn1js.AsnType[] = [
    new asn1js.Integer({ value: 1 }), // version
    new asn1js.ObjectIdentifier({ value: OID_TSA_POLICY }),
    new asn1js.Sequence({
      // messageImprint
      value: [
        new asn1js.Sequence({
          value: [new asn1js.ObjectIdentifier({ value: opts.imprintAlgorithmOid ?? OID_SHA256 }), new asn1js.Null()],
        }),
        new asn1js.OctetString({ valueHex: Buffer.from(opts.digestHex, 'hex') }),
      ],
    }),
    new asn1js.Integer({ value: opts.serial }),
    opts.faults?.nonDerGenTime ? new asn1js.GeneralizedTime({ valueDate: opts.genTime }) : derGeneralizedTime(opts.genTime),
  ];
  const shape = opts.faults?.tstInfoTail;
  if (shape !== undefined) {
    const members = [...value.map((v) => Buffer.from(v.toBER(false))), ...tstInfoTail(shape, opts.nonce ?? null)];
    const der = derElement(0x30, Buffer.concat(members));
    return der.buffer.slice(der.byteOffset, der.byteOffset + der.length) as ArrayBuffer;
  }
  if (opts.nonce) {
    // TSTInfo ::= SEQUENCE { ..., genTime, accuracy?, ordering?, nonce?, ... }
    value.push(new asn1js.Integer({ valueHex: positiveDerInteger(opts.nonce) }));
  }
  return new asn1js.Sequence({ value }).toBER(false);
}

/** The DER of the members after genTime that `shape` names (`TokenFaults.tstInfoTail`), echoing `nonce`. */
function tstInfoTail(shape: NonNullable<TokenFaults['tstInfoTail']>, nonce: Buffer | null): Buffer[] {
  const hex = (h: string) => Buffer.from(h, 'hex');
  const echoed = nonce ? [derElement(0x02, positiveDerInteger(nonce))] : [];
  const nonceAnyway = echoed.length > 0 ? echoed : [hex('020401020304')];
  // Accuracy ::= SEQUENCE { seconds 1, millis [0] 999, micros [1] 1 }
  const accuracy = hex('300a020101800203e7810101');
  const ordering = hex('010100');
  const tsaName = new pkijs.RelativeDistinguishedNames({ typesAndValues: [cnTypeAndValue('Acme Timestamping Authority')] });
  // tsa [0] GeneralName: directoryName [4] EXPLICIT Name.
  const tsa = derElement(0xa0, derElement(0xa4, Buffer.from(tsaName.toSchema().toBER(false))));
  // extensions [1] IMPLICIT Extensions: one, SEQUENCE { OID 1.2.3.4, OCTET STRING { NULL } }.
  const extensions = derElement(0xa1, hex('300906032a0304040205' + '00'));
  switch (shape) {
    case 'all':
      return [accuracy, ordering, ...nonceAnyway, tsa, extensions];
    case 'member-after-extensions':
      return [accuracy, ordering, ...nonceAnyway, tsa, extensions, hex('0500')];
    case 'ordering-after-nonce':
      return [...nonceAnyway, ordering];
    case 'millis-zero':
      return [hex('3003800100'), ...echoed];
    case 'micros-1000':
      return [hex('3004810203e8'), ...echoed];
    case 'tsa-empty':
      return [...echoed, hex('a000')];
    case 'tsa-dns-name-constructed':
      return [...echoed, derElement(0xa0, derElement(0xa2, derElement(0x16, Buffer.from('tsa.example', 'latin1'))))];
    case 'extensions-empty':
      return [...echoed, hex('a100')];
  }
}

/** DER INTEGER content for an unsigned value: leading zeros trimmed, 0x00 prefixed when the top bit is set. */
function positiveDerInteger(raw: Buffer): Buffer {
  let i = 0;
  while (i < raw.length - 1 && raw[i] === 0x00) i++;
  const trimmed = raw.subarray(i);
  return (trimmed[0] & 0x80) !== 0 ? Buffer.concat([Buffer.from([0x00]), trimmed]) : trimmed;
}

/**
 * The signer-binding attribute (RFC 3161 §2.4.2, RFC 5816): a
 * SigningCertificateV2 whose one ESSCertIDv2 is SHA-256 over `named`'s DER,
 * with the default hash algorithm left out as DER requires, and an
 * issuerSerial naming the signer; or, for `'v1'`, a SigningCertificate whose
 * ESSCertID is SHA-1 over it. With `unknownHash`, the ESSCertIDv2 names the
 * hash algorithm 2.16.840.1.101.3.4.2.127 (its certHash still SHA-256); with
 * `otherSerial`, its issuerSerial names another serial number, the signer's
 * with its last bit flipped.
 */
function signingCertificateAttribute(
  signer: IssuedCert,
  named: IssuedCert,
  version: 'v1' | 'v2',
  unknownHash = false,
  otherSerial = false,
): pkijs.Attribute {
  const serial = Buffer.from(signer.cert.serialNumber.valueBlock.valueHexView);
  if (otherSerial) serial[serial.length - 1] ^= 0x01;
  const issuerSerial = new asn1js.Sequence({
    value: [
      new asn1js.Sequence({
        // GeneralNames: one directoryName, [4] EXPLICIT Name.
        value: [new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 4 }, value: [signer.cert.issuer.toSchema()] })],
      }),
      new asn1js.Integer({ valueHex: serial }),
    ],
  });
  const certHash = createHash(version === 'v1' ? 'sha1' : 'sha256').update(named.der).digest();
  const essCertId = new asn1js.Sequence({
    value: [
      ...(unknownHash ? [new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: '2.16.840.1.101.3.4.2.127' })] })] : []),
      new asn1js.OctetString({ valueHex: certHash }),
      issuerSerial,
    ],
  });
  return new pkijs.Attribute({
    type: version === 'v1' ? OID_SIGNING_CERTIFICATE : OID_SIGNING_CERTIFICATE_V2,
    values: [new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [essCertId] })] })],
  });
}

/** DER orders the members of a SET OF by their encodings. */
function derSorted<T extends { toSchema(): asn1js.AsnType }>(members: T[]): T[] {
  return [...members].sort((a, b) =>
    Buffer.compare(Buffer.from(a.toSchema().toBER(false)), Buffer.from(b.toSchema().toBER(false))),
  );
}

/** A granted TimeStampResp over `tstInfoDer`, signed by `signer`, carrying `certificates`. */
async function signTimeStampResp(
  signer: IssuedCert,
  certificates: IssuedCert[],
  tstInfoDer: ArrayBuffer,
  root: IssuedCert,
  faults: TokenFaults = {},
  /** Name the signer by its subjectKeyIdentifier instead of its issuer and serial number. */
  signerKeyIdentifier?: Buffer,
): Promise<Buffer> {
  const binding = faults.signingCertificate ?? 'v2';
  const attributes = [
    new pkijs.Attribute({
      type: OID_CONTENT_TYPE,
      values: [new asn1js.ObjectIdentifier({ value: faults.contentType === 'data' ? OID_DATA : OID_ID_CT_TST_INFO })],
    }),
    new pkijs.Attribute({
      type: OID_MESSAGE_DIGEST,
      values: [
        new asn1js.OctetString({
          valueHex: createHash('sha256')
            .update(faults.messageDigest === 'other' ? Buffer.from('not the TSTInfo') : Buffer.from(tstInfoDer))
            .digest(),
        }),
      ],
    }),
    ...(binding === 'none'
      ? []
      : [
          signingCertificateAttribute(
            signer,
            binding === 'other-certificate' ? root : signer,
            binding === 'v1' ? 'v1' : 'v2',
            binding === 'v2-unknown-hash' || binding === 'v2-unknown-hash-other-serial',
            binding === 'v2-unknown-hash-other-serial',
          ),
        ]),
  ];
  const signedData = new pkijs.SignedData({
    version: 3,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: OID_ID_CT_TST_INFO,
      eContent: new asn1js.OctetString({ valueHex: tstInfoDer }),
    }),
    certificates: derSorted(certificates.filter((c) => !(faults.withoutSignerCertificate && c === signer)).map((c) => c.cert)),
    signerInfos: [
      new pkijs.SignerInfo({
        version: signerKeyIdentifier ? 3 : 1,
        sid: signerKeyIdentifier
          ? new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 }, valueHex: signerKeyIdentifier })
          : new pkijs.IssuerAndSerialNumber({
              issuer: signer.cert.issuer,
              serialNumber: signer.cert.serialNumber,
            }),
        signedAttrs: new pkijs.SignedAndUnsignedAttributes({
          type: 0,
          attributes: faults.signedAttrsOrder === 'reversed' ? derSorted(attributes).reverse() : derSorted(attributes),
        }),
      }),
    ],
  });
  // pkijs splits eContent into a constructed OCTET STRING when it builds the
  // EncapsulatedContentInfo. DER needs the primitive form.
  if (!faults.berTstInfo) signedData.encapContentInfo.eContent = new asn1js.OctetString({ valueHex: tstInfoDer });

  await signedData.sign(signer.privateKey, 0, 'SHA-256', undefined, cryptoEngine as any);

  const signedDataSchema = signedData.toSchema(true) as asn1js.Sequence;
  if (faults.digestAlgorithms === 'bare-oid') {
    // SignedData ::= SEQUENCE { version, digestAlgorithms, ... }
    signedDataSchema.valueBlock.value[1] = new asn1js.Set({ value: [new asn1js.ObjectIdentifier({ value: OID_SHA256 })] });
  }
  const contentInfo = new pkijs.ContentInfo({
    contentType: OID_SIGNED_DATA,
    content: signedDataSchema,
  });

  const timeStampResp = new asn1js.Sequence({
    value: [
      new asn1js.Sequence({ value: [new asn1js.Integer({ value: 0 })] }), // PKIStatusInfo: granted
      contentInfo.toSchema(),
    ],
  });

  return Buffer.from(timeStampResp.toBER(false));
}

/**
 * A certificate's DER with its P-256 public key made unreadable, the rest of
 * it untouched, so it still parses as X.509: `'bad-key'` moves the point off
 * the curve (the last byte of its y flipped), `'unknown-key-algorithm'` names
 * a key algorithm no verifier implements (id-ecPublicKey, 1.2.840.10045.2.1,
 * becomes 1.2.840.10045.2.9), `'unassigned-curve'` names the curve OID
 * 1.2.840.10045.3.1.99, which no verifier implements since it is assigned to
 * no curve (P-256, 1.2.840.10045.3.1.7, renamed). The certificate's own
 * signature no longer verifies either way; nothing reads it before the key.
 */
export function withUnreadableKey(der: Buffer, how: UnreadableKey): Buffer {
  const out = Buffer.from(der);
  if (how === 'bad-key') {
    const at = out.indexOf(Buffer.from('034200', 'hex')); // BIT STRING, no unused bits, then 04 x y
    if (at < 0) throw new Error('the certificate carries no P-256 point');
    out[at + 3 + 64] ^= 0x01;
  } else if (how === 'unknown-key-algorithm') {
    const at = out.indexOf(Buffer.from('06072a8648ce3d0201', 'hex'));
    if (at < 0) throw new Error('the certificate carries no id-ecPublicKey');
    out[at + 8] = 0x09;
  } else {
    const at = out.indexOf(Buffer.from('06082a8648ce3d030107', 'hex'));
    if (at < 0) throw new Error('the certificate carries no P-256 curve OID');
    Buffer.from(UNASSIGNED_CURVE, 'hex').copy(out, at);
  }
  return out;
}

// ---- Certificates edited after issue, then signed again ----------------------------

/** A DER element's header length and total length at `pos`. */
function derSpan(buf: Buffer, pos: number): { header: number; end: number } {
  let length = buf[pos + 1];
  let header = 2;
  if (length & 0x80) {
    const n = length & 0x7f;
    length = buf.readUIntBE(pos + 2, n);
    header += n;
  }
  return { header, end: pos + header + length };
}

/** The elements of a constructed element's content, as their raw bytes. */
function derChildren(el: Buffer): Buffer[] {
  const { header, end } = derSpan(el, 0);
  const out: Buffer[] = [];
  for (let pos = header; pos < end; ) {
    const span = derSpan(el, pos);
    out.push(el.subarray(pos, span.end));
    pos = span.end;
  }
  return out;
}

function derLength(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derElement(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

/** An ECDSA signature as WebCrypto gives it (r ‖ s) in the DER form X.509 carries. */
function ecdsaDer(raw: Buffer): Buffer {
  const int = (b: Buffer) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const v = b.subarray(i);
    return derElement(0x02, v[0] & 0x80 ? Buffer.concat([Buffer.from([0]), v]) : v);
  };
  const half = raw.length / 2;
  return derElement(0x30, Buffer.concat([int(raw.subarray(0, half)), int(raw.subarray(half))]));
}

/**
 * `issued`, with its subject Name and its SubjectPublicKeyInfo replaced as
 * `edit` says, signed again by `issuerKey` (ECDSA with SHA-256, as every
 * certificate here is signed). The private key is `issued`'s own, whatever
 * its certificate now says the key is.
 */
async function resigned(
  issued: IssuedCert,
  issuerKey: CryptoKey,
  edit: { subject?: Buffer; spki?: (spki: Buffer) => Buffer },
): Promise<IssuedCert> {
  const [tbs, algorithm] = derChildren(issued.der);
  const fields = derChildren(tbs);
  const at = fields[0][0] === 0xa0 ? 1 : 0;
  if (edit.subject) fields[at + 4] = edit.subject;
  if (edit.spki) fields[at + 5] = edit.spki(fields[at + 5]);
  const newTbs = derElement(0x30, Buffer.concat(fields));
  const raw = Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, issuerKey, new Uint8Array(newTbs)));
  const der = derElement(0x30, Buffer.concat([newTbs, algorithm, derElement(0x03, Buffer.concat([Buffer.from([0]), ecdsaDer(raw)]))]));
  return { ...issued, cert: pkijs.Certificate.fromBER(new Uint8Array(der)), der, pem: toPem(der) };
}

/** A SubjectPublicKeyInfo on P-256 renamed to the unassigned curve 1.2.840.10045.3.1.99. */
function onUnassignedCurve(spki: Buffer): Buffer {
  const out = Buffer.from(spki);
  const at = out.indexOf(Buffer.from('06082a8648ce3d030107', 'hex'));
  if (at < 0) throw new Error('the key is not on P-256');
  Buffer.from(UNASSIGNED_CURVE, 'hex').copy(out, at);
  return out;
}

/**
 * The certificates a token's faults add around its signer: the intermediate
 * that issues the signer when `signerIssuer` asks for one (the certificate
 * the token carries, and the one whose private key signs), and the
 * certificate no path names when `unneededCertificate` asks for it.
 */
async function faultCertificates(
  root: IssuedCert,
  faults: TokenFaults,
  serial: number,
): Promise<{ issuing?: IssuedCert; carried: IssuedCert[] }> {
  const wide = { notBefore: new Date('2020-01-01T00:00:00Z'), notAfter: new Date('2040-01-01T00:00:00Z') };
  const carried: IssuedCert[] = [];
  let issuing: IssuedCert | undefined;
  if (faults.signerIssuer === 'intermediate-unassigned-curve') {
    issuing = await issueCertificate({ subjectCN: 'Acme Unassigned Curve Intermediate CA', serial, isCa: true, issuer: root, ...wide });
    carried.push(await resigned(issuing, root.privateKey, { spki: onUnassignedCurve }));
  }
  if (faults.unneededCertificate === 'unassigned-curve') {
    const unrelated = await issueCertificate({ subjectCN: 'Acme Unrelated Certificate', serial: serial + 1, isCa: false, issuer: root, ...wide });
    carried.push(unreadableKey(unrelated, 'unassigned-curve'));
  }
  return { ...(issuing && { issuing }), carried };
}

/** `issued` with its public key made unreadable (`withUnreadableKey`): the same private key, the certificate as the new bytes read. */
function unreadableKey(issued: IssuedCert, how: UnreadableKey): IssuedCert {
  const der = withUnreadableKey(issued.der, how);
  return { ...issued, cert: pkijs.Certificate.fromBER(new Uint8Array(der)), der, pem: toPem(der) };
}

export interface TsaFixture {
  /** Base64 DER TimeStampResp, ready for verifyTimestampToken. */
  tokenBase64: string;
  /** PEM of the root that issued the chain. NOT FreeTSA. */
  caPem: string;
  /** PEM of the intermediate, when the fixture was built with one. */
  intermediatePem?: string;
  /** PEM of the TSA signing certificate. */
  signerPem: string;
  /** The hex digest the token is a timestamp over. */
  digestHex: string;
  genTime: Date;
  /** CN of the signing certificate — what `tsaSubject` must report. */
  signerCN: string;
}

/**
 * Issue a genuine TimeStampResp from a throwaway CA.
 *
 * @param opts.withIntermediate  put an intermediate CA between signer and root,
 *        which is how every real public TSA is structured.
 * @param opts.intermediateNotCa issue that intermediate as an end entity, with
 *        no `cA` (tzun-anchor/1 §10.5 step 4).
 * @param opts.signerNotAfter    expire the signing certificate before `genTime`
 *        to exercise the validity-window branch.
 * @param opts.imprintAlgorithmOid  the messageImprint's hash algorithm OID,
 *        default SHA-256. The imprint's bytes are `digestHex` whatever it names.
 * @param opts.faults            one rule of §10.5 the token breaks.
 */
export async function makeTsaFixture(
  opts: {
    digestHex?: string;
    genTime?: Date;
    withIntermediate?: boolean;
    intermediateNotCa?: boolean;
    signerNotBefore?: Date;
    signerNotAfter?: Date;
    signerCN?: string;
    caCN?: string;
    imprintAlgorithmOid?: string;
    faults?: TokenFaults;
    /** Name the signer in the SignerInfo by a subjectKeyIdentifier (CMS SignerIdentifier [0]). */
    signerKeyIdentifier?: boolean;
  } = {},
): Promise<TsaFixture> {
  const digestHex =
    opts.digestHex ?? createHash('sha256').update('offline-tsa-fixture', 'utf8').digest('hex');
  const genTime = opts.genTime ?? new Date('2026-06-01T12:00:00.000Z');
  const signerCN = opts.signerCN ?? 'Acme Timestamping Authority';
  const caCN = opts.caCN ?? 'Acme Test Root CA';

  const wide = { notBefore: new Date('2020-01-01T00:00:00Z'), notAfter: new Date('2040-01-01T00:00:00Z') };

  const keyId = opts.signerKeyIdentifier ? createHash('sha1').update(signerCN).digest() : undefined;
  const root = await issueCertificate({ subjectCN: caCN, serial: 1, isCa: true, ...wide });
  const intermediate = opts.withIntermediate
    ? await issueCertificate({
        subjectCN: 'Acme Test Intermediate CA',
        serial: 2,
        isCa: opts.intermediateNotCa ? 'not-a-ca' : true,
        issuer: root,
        ...wide,
      })
    : undefined;
  const added = await faultCertificates(root, opts.faults ?? {}, 20);
  const issuer = added.issuing ?? intermediate ?? root;
  const plain = await issueCertificate({
    subjectCN: signerCN,
    serial: 3,
    isCa: false,
    issuer,
    notBefore: opts.signerNotBefore ?? wide.notBefore,
    notAfter: opts.signerNotAfter ?? wide.notAfter,
    eku: opts.faults?.signerEku ?? 'timestamping',
    ...(keyId && { subjectKeyIdentifier: keyId }),
    issuerNameUtf8: opts.faults?.signerIssuerName === 'utf8',
  });
  const subject = opts.faults?.signerSubject;
  const issued = subject ? await resigned(plain, issuer.privateKey, { subject }) : plain;
  const signerKey = opts.faults?.signerKey;
  const signer = signerKey ? unreadableKey(issued, signerKey) : issued;
  const issuerCopy = opts.faults?.issuerCopy;
  const copy = issuerCopy
    ? unreadableKey(
        await issueCertificate({ subjectCN: intermediate ? 'Acme Test Intermediate CA' : caCN, serial: 9, isCa: true, issuer: root, ...wide }),
        issuerCopy,
      )
    : undefined;

  const tstInfoDer = buildTstInfo({
    digestHex,
    genTime,
    serial: 42,
    ...(opts.imprintAlgorithmOid !== undefined && { imprintAlgorithmOid: opts.imprintAlgorithmOid }),
    ...(opts.faults && { faults: opts.faults }),
  });

  const tokenDer = await signTimeStampResp(
    signer,
    [signer, ...(intermediate ? [intermediate] : []), ...(copy ? [copy] : []), ...added.carried],
    tstInfoDer,
    root,
    opts.faults,
    keyId,
  );

  return {
    tokenBase64: tokenDer.toString('base64'),
    caPem: root.pem,
    ...(intermediate && { intermediatePem: intermediate.pem }),
    signerPem: signer.pem,
    digestHex,
    genTime,
    signerCN,
  };
}

/** An offline TSA that issues a genuine token for any digest it is asked about. */
export interface SigningTsa {
  /** PEM of the root the tokens chain to. NOT FreeTSA or Sectigo. */
  caPem: string;
  /** CN of the signing certificate. */
  signerCN: string;
  /**
   * A DER TimeStampResp over `digestHex`, echoing `nonce` — what an RFC 3161
   * client that sent that request expects back. `faults` breaks one rule of
   * tzun-anchor/1 §10.5; a token with a `signerEku`, `signerIssuerName`,
   * `signerKey`, `signerIssuer` or `signerSubject` fault is signed by another
   * signing certificate of that shape, under the same root and (but for
   * `signerSubject`) CN.
   */
  issue(digestHex: string, nonce: Buffer | null, genTime?: Date, faults?: TokenFaults): Promise<Buffer>;
}

/**
 * A throwaway CA and TSA signing certificate that sign a token per request,
 * so a real `RFC3161Client` (which requires its nonce echoed) can be pointed
 * at it and the token it stores verifies in trust-chain mode against `caPem`.
 */
export async function makeSigningTsa(
  opts: { signerCN?: string; caCN?: string } = {},
): Promise<SigningTsa> {
  const signerCN = opts.signerCN ?? 'Acme Timestamping Authority';
  const caCN = opts.caCN ?? 'Acme Test Root CA';
  const wide = { notBefore: new Date('2020-01-01T00:00:00Z'), notAfter: new Date('2040-01-01T00:00:00Z') };
  const root = await issueCertificate({ subjectCN: caCN, serial: 1, isCa: true, ...wide });
  // One signing certificate per shape the faults ask for, all under the same root and CN.
  const signers = new Map<string, Promise<{ signer: IssuedCert; carried: IssuedCert[] }>>();
  const signerFor = (faults: TokenFaults): Promise<{ signer: IssuedCert; carried: IssuedCert[] }> => {
    const eku = faults.signerEku ?? 'timestamping';
    const shape = [
      eku,
      faults.signerIssuerName ?? '',
      faults.signerKey ?? '',
      faults.signerIssuer ?? '',
      faults.unneededCertificate ?? '',
      faults.signerSubject?.toString('hex') ?? '',
    ].join('|');
    let signer = signers.get(shape);
    if (!signer) {
      // Every shape's certificates get serials of their own under the root: 3, then 1000 and up by ten.
      const serial = signers.size === 0 ? 3 : 1000 + 10 * signers.size;
      signer = (async () => {
        const added = await faultCertificates(root, faults, serial + 1);
        const issuer = added.issuing ?? root;
        const plain = await issueCertificate({
          subjectCN: signerCN,
          serial,
          isCa: false,
          issuer,
          eku,
          issuerNameUtf8: faults.signerIssuerName === 'utf8',
          ...wide,
        });
        const issued = faults.signerSubject ? await resigned(plain, issuer.privateKey, { subject: faults.signerSubject }) : plain;
        return { signer: faults.signerKey ? unreadableKey(issued, faults.signerKey) : issued, carried: added.carried };
      })();
      signers.set(shape, signer);
    }
    return signer;
  };
  const copies = new Map<string, Promise<IssuedCert>>();
  const copyFor = (how: NonNullable<TokenFaults['issuerCopy']>): Promise<IssuedCert> => {
    let copy = copies.get(how);
    if (!copy) {
      copy = issueCertificate({ subjectCN: caCN, serial: 90 + copies.size, isCa: true, issuer: root, ...wide }).then((c) => unreadableKey(c, how));
      copies.set(how, copy);
    }
    return copy;
  };
  let serial = 100;
  return {
    caPem: root.pem,
    signerCN,
    issue: async (digestHex, nonce, genTime = new Date(), faults = {}) => {
      const { signer, carried } = await signerFor(faults);
      const certificates = [signer, ...(faults.issuerCopy ? [await copyFor(faults.issuerCopy)] : []), ...carried];
      return signTimeStampResp(signer, certificates, buildTstInfo({ digestHex, genTime, serial: serial++, nonce, faults }), root, faults);
    },
  };
}

let shared: Promise<SigningTsa> | undefined;

/**
 * A genuine token over `digestHex` at `genTime` (default now), from one
 * throwaway authority shared by the whole test file: what a store's record
 * carries after a real capture, for a check that reads the token without
 * asking who issued it (`timestampVerification: 'structural'`).
 */
export async function signedTimestampToken(digestHex: string, genTime?: Date): Promise<string> {
  shared ??= makeSigningTsa();
  return (await (await shared).issue(digestHex, null, genTime)).toString('base64');
}

/**
 * A self-signed CA certificate that impersonates the root `rootPem`: its
 * subject and issuer are the root's subject Name, byte for byte, and its
 * subjectKeyIdentifier and authorityKeyIdentifier carry the root's key
 * identifier, so every field a metadata comparison reads is the root's. Its
 * key is a fresh RSA key (the signature algorithm an RSA root's subjects
 * carry), discarded, so no signature by the root's key is on it.
 */
export async function impersonatorOf(rootPem: string): Promise<string> {
  const root = pkijs.Certificate.fromBER(
    new Uint8Array(Buffer.from(rootPem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, ''), 'base64')),
  );
  const { privateKey, publicKey } = (await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as { privateKey: CryptoKey; publicKey: CryptoKey };
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 7 });
  cert.subject = root.subject;
  cert.issuer = root.subject;
  cert.notBefore.value = new Date('2020-01-01T00:00:00Z');
  cert.notAfter.value = new Date('2040-01-01T00:00:00Z');
  const ski = root.extensions?.find((e) => e.extnID === OID_SUBJECT_KEY_IDENTIFIER);
  const keyId = ski ? (asn1js.fromBER(ski.extnValue.valueBlock.valueHexView).result as asn1js.OctetString).valueBlock.valueHexView : undefined;
  cert.extensions = [
    extension(OID_BASIC_CONSTRAINTS, true, new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(false)),
    ...(keyId
      ? [
          extension(OID_SUBJECT_KEY_IDENTIFIER, false, new asn1js.OctetString({ valueHex: keyId }).toBER(false)),
          extension(
            '2.5.29.35',
            false,
            new pkijs.AuthorityKeyIdentifier({ keyIdentifier: new asn1js.OctetString({ valueHex: keyId }) }).toSchema().toBER(false),
          ),
        ]
      : []),
  ];
  await cert.subjectPublicKeyInfo.importKey(publicKey, cryptoEngine as any);
  await cert.sign(privateKey, 'SHA-256', cryptoEngine as any);
  return toPem(cert.toSchema().toBER(false));
}
