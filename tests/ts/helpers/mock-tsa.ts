/**
 * Mock RFC 3161 Timestamp Authority for tests.
 *
 * The SDK's TSA client fails closed: `doRequestTimestamp` parses the
 * TimeStampResp, checks PKIStatus, and requires the returned messageImprint
 * and nonce to match what was requested. A `fetch` mock that returns
 * arbitrary bytes is refused, so a mock has to behave like an actual TSA.
 *
 * `mockTsaFetch()` produces a `fetch` stand-in that reads the DER TimeStampReq
 * out of the request body and mints a structurally valid TimeStampResp echoing
 * that digest and nonce. The token is NOT cryptographically signed (there are
 * no signerInfos and no certificates): the client verifies structure, status,
 * imprint and nonce, not the CMS signature, so an unsigned token is exactly
 * what is needed to exercise the client's contract without shipping a private
 * key in the repo. Anything that needs signature/trust-anchor semantics belongs
 * in rfc3161-verify / attestation-trust-anchor tests instead.
 *
 * A verifier refuses these tokens at tzun-anchor/1 §10.5 step 1: a TimeStampToken
 * carries exactly one SignerInfo and the certificate it names. A test whose
 * record must carry a token a verifier reads takes one from
 * tests/ts/rfc3161-fixture.ts (`signedTimestampToken`).
 */
import * as asn1js from 'asn1js';

const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const ID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const ID_CT_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const DEFAULT_POLICY_OID = '1.3.6.1.4.1.13762.3';

export interface MockTsaOptions {
  /** PKIStatus to report. Default 0 (granted). */
  status?: number;
  /**
   * Force the messageImprint in the response to this hex digest instead of
   * echoing the requested one — the "proxy served a token for someone else's
   * digest" case.
   */
  overrideDigest?: string;
  /**
   * Force the TSTInfo nonce to this value instead of echoing the requested one.
   * `null` drops the nonce from the response entirely.
   */
  overrideNonce?: Buffer | null;
  /** genTime to embed. Default: now. */
  genTime?: Date;
  /** Content-Type header to report. Default `application/timestamp-reply`. */
  contentType?: string | null;
}

/** Parse `{ digest, nonce }` back out of a DER TimeStampReq. */
export function parseTimestampQuery(der: Buffer): { digest: string; nonce: Buffer | null } {
  const parsed = asn1js.fromBER(der);
  if (parsed.offset === -1) throw new Error('mock TSA: request is not valid DER');
  const seq = parsed.result as asn1js.Sequence;
  const values = seq.valueBlock.value;

  // TimeStampReq ::= SEQUENCE { version, messageImprint, reqPolicy?, nonce?, certReq?, ... }
  const imprint = values[1] as asn1js.Sequence;
  const hashed = imprint.valueBlock.value[1] as asn1js.OctetString;
  const digest = Buffer.from(hashed.valueBlock.valueHexView).toString('hex');

  let nonce: Buffer | null = null;
  for (let i = 2; i < values.length; i++) {
    if (values[i] instanceof asn1js.Integer) {
      nonce = Buffer.from((values[i] as asn1js.Integer).valueBlock.valueHexView);
      break;
    }
  }
  return { digest, nonce };
}

/**
 * Build a base64 DER TimeStampResp carrying the given imprint / nonce.
 */
export function buildTimestampResponse(
  digest: string,
  nonce: Buffer | null,
  options: MockTsaOptions = {},
): string {
  const status = options.status ?? 0;
  const genTime = options.genTime ?? new Date();

  const tstInfoValues: asn1js.AsnType[] = [
    new asn1js.Integer({ value: 1 }), // version
    new asn1js.ObjectIdentifier({ value: DEFAULT_POLICY_OID }), // policy
    new asn1js.Sequence({
      // messageImprint
      value: [
        new asn1js.Sequence({
          value: [new asn1js.ObjectIdentifier({ value: SHA256_OID }), new asn1js.Null()],
        }),
        new asn1js.OctetString({ valueHex: Buffer.from(digest, 'hex') }),
      ],
    }),
    new asn1js.Integer({ value: 42 }), // serialNumber
    new asn1js.GeneralizedTime({ valueDate: genTime }), // genTime
  ];
  if (nonce !== null) {
    // TSTInfo ::= SEQUENCE { ..., genTime, accuracy?, ordering?, nonce?, ... }
    tstInfoValues.push(new asn1js.Integer({ valueHex: toPositiveDerInteger(nonce) }));
  }

  const tstInfoDer = new asn1js.Sequence({ value: tstInfoValues }).toBER(false);

  // ContentInfo { contentType id-signedData, content [0] EXPLICIT SignedData }
  // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
  //                           certificates [0]?, signerInfos SET }
  const signedData = new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 3 }),
      new asn1js.Set({
        value: [
          new asn1js.Sequence({
            value: [new asn1js.ObjectIdentifier({ value: SHA256_OID }), new asn1js.Null()],
          }),
        ],
      }),
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: ID_CT_TST_INFO }),
          new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 0 },
            value: [new asn1js.OctetString({ valueHex: tstInfoDer })],
          }),
        ],
      }),
      new asn1js.Set({ value: [] }), // signerInfos — deliberately empty
    ],
  });

  const contentInfo = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: ID_SIGNED_DATA }),
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [signedData],
      }),
    ],
  });

  const tsResp = new asn1js.Sequence({
    value: [
      new asn1js.Sequence({ value: [new asn1js.Integer({ value: status }) ] }), // PKIStatusInfo
      contentInfo,
    ],
  });

  return Buffer.from(tsResp.toBER(false)).toString('base64');
}

/**
 * DER INTEGER content must be signed two's-complement; prefix 0x00 when the
 * top bit is set so a random 64-bit nonce never encodes as negative.
 */
function toPositiveDerInteger(raw: Buffer): Buffer {
  let i = 0;
  while (i < raw.length - 1 && raw[i] === 0x00) i++;
  const trimmed = raw.subarray(i);
  return (trimmed[0] & 0x80) !== 0 ? Buffer.concat([Buffer.from([0x00]), trimmed]) : trimmed;
}

/**
 * A `fetch` stand-in that answers a TimeStampReq like a real TSA would.
 */
export function mockTsaFetch(options: MockTsaOptions = {}): jest.Mock {
  return jest.fn(async (_url: string, init: RequestInit) => {
    const body = Buffer.from(init.body as unknown as Uint8Array);
    const { digest, nonce } = parseTimestampQuery(body);
    const responseDigest = options.overrideDigest ?? digest;
    const responseNonce =
      options.overrideNonce === undefined ? nonce : options.overrideNonce;
    const b64 = buildTimestampResponse(responseDigest, responseNonce, options);
    const bytes = Buffer.from(b64, 'base64');
    return makeResponse(bytes, options.contentType === undefined
      ? 'application/timestamp-reply'
      : options.contentType);
  }) as unknown as jest.Mock;
}

/** Wrap raw bytes in the minimal Response shape the client consumes. */
export function makeResponse(bytes: Buffer, contentType: string | null) {
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: {
      get: (name: string) =>
        name.toLowerCase() === 'content-type' ? contentType : null,
    },
    arrayBuffer: async () =>
      bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  };
}
