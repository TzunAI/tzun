// The RFC 3161 trust anchor: the certificate-chain check verifies the
// issuer's signature, not just its metadata.
//
// verifyTimestampToken checks the CMS signature against the certificate carried
// INSIDE the token, so on its own it proves only internal consistency — a token
// you sign yourself passes it. The certificate-chain check is the only thing
// that ties that certificate to a real TSA, so it must verify the issuer's
// signature cryptographically. checkIssued is not enough: Node's own docs
// describe it as comparing METADATA for pruning a candidate issuer list.
//
// The attack is a self-signed certificate carrying the FreeTSA root's
// subject/issuer DN and its Subject Key Identifier copied into both SKID and
// AKID. Every field checkIssued examines is attacker-chosen. `impersonatorOf`
// builds one whose names are the root's, byte for byte, which is what reaches
// the root under tzun-anchor/1 §10.5 step 4; the static FORGED_CA_IMPERSONATOR
// below writes the same DN with other string types, which names another CA.
import * as fs from 'fs';
import * as path from 'path';
import { verifyCertificateChain, verifyCertificatePath } from '../../src/attestation/rfc3161-verify';
import { impersonatorOf, makeTsaFixture } from './rfc3161-fixture';

const FREETSA_ROOT = fs.readFileSync(path.join(__dirname, '../../src/attestation/certs/freetsa-ca.pem'), 'utf-8');

/**
 * Self-signed, generated for this test. Impersonates the bundled FreeTSA root:
 *   subject = issuer = O=Free TSA, OU=Root CA, CN=www.freetsa.org, ...
 *     (UTF8Strings, where the real root writes PrintableStrings)
 *   SKID = AKID = FA:55:0D:8C:...:A4:97  (the real root's SKID)
 * It is signed by its own key, which is discarded — nothing here is secret.
 */
const FORGED_CA_IMPERSONATOR =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIID6TCCAtGgAwIBAgIUZdM96gS7KDI/IxcLXPiARlM4QnMwDQYJKoZIhvcNAQEL\n' +
  'BQAwgZUxETAPBgNVBAoMCEZyZWUgVFNBMRAwDgYDVQQLDAdSb290IENBMRgwFgYD\n' +
  'VQQDDA93d3cuZnJlZXRzYS5vcmcxIjAgBgkqhkiG9w0BCQEWE2J1c2lsZXphc0Bn\n' +
  'bWFpbC5jb20xEjAQBgNVBAcMCVd1ZXJ6YnVyZzEPMA0GA1UECAwGQmF5ZXJuMQsw\n' +
  'CQYDVQQGEwJERTAeFw0yNjA4MjkyMzE0MzRaFw0zNjA4MjYyMzE0MzRaMIGVMREw\n' +
  'DwYDVQQKDAhGcmVlIFRTQTEQMA4GA1UECwwHUm9vdCBDQTEYMBYGA1UEAwwPd3d3\n' +
  'LmZyZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29t\n' +
  'MRIwEAYDVQQHDAlXdWVyemJ1cmcxDzANBgNVBAgMBkJheWVybjELMAkGA1UEBhMC\n' +
  'REUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLUrT+pEmdKm/zZvjS\n' +
  '819sk6m16v/6w9HurHH28jeQJlHwq+oUGtAFMGoWzOz6iXbOrlV6GzKBVxubJeNS\n' +
  'f34A59WQgBhjxvjnZP9vkRl4SGBiHegCEkQuufgisY8WosNZPbGJkoL/o66U3eXa\n' +
  'j9rj7fEIfJeR0NWVFhHxfHJFODdfoXhc32LQWCOV70VFhuMoqmehLn193sEs24NS\n' +
  '9AsoaEbBTAMJxW5BMoV6phbFtH67poDdsHsvD7tlykfjdKz1uMa/VNU1Mvtm6Ub3\n' +
  'quMW9zqE6whl4Dbfx3/MsnJdF6nRtzLt6TOS+QmhH2TDyko+PpSjwYtmUQmg4URK\n' +
  'NUW3AgMBAAGjLzAtMB0GA1UdDgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzAMBgNV\n' +
  'HRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAfypkk/mtY/yQM90Ns4i303pCn\n' +
  'UcroczBrK6VyIuYjoHeUPcJCmPEIWhm7dZOk6JbP0qlXS7xj6a0rK3nDIriFOBqS\n' +
  'XBz2ma/rx//9bvLvKekZ+mb9hO1jlgpAdWskQgk2kb1hGTbwYNfX5eCQ8agEtAEZ\n' +
  '2gRD/F0AGhUUerEMvZyISIs/LQ+5B9gEI7RVQnv/COMliUK1+eZLZtKwKoGd9K93\n' +
  'CKmu7s3Z661enNXcqeUNcGyXI+FBTFc1MYNPOrah3E7uwXmdr9xOISxk6hccGDpT\n' +
  'W4OC6XkPETa5fT/LtJJsxKE3t1bzZxSzHFhYPqT3H3IVtQnP2Te/njs0+lOP\n' +
  '-----END CERTIFICATE-----\n';

describe('RFC 3161 certificate chain — trust anchor', () => {
  let impersonator: string;
  beforeAll(async () => {
    impersonator = await impersonatorOf(FREETSA_ROOT);
  });

  it('rejects a self-signed cert that impersonates the trusted root', () => {
    const result = verifyCertificateChain(impersonator, null);

    // checkIssued alone would accept it, because the DN and key identifiers all
    // match; the signature check is what refuses it.
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/signature does not verify/i);
  });

  it('rejects one that writes the root\'s DN with other string types: that names another CA, and reaches no root', () => {
    const result = verifyCertificateChain(FORGED_CA_IMPERSONATOR, null);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('TSA certificate was not issued by the trusted CA');
  });

  it('passes the metadata check it is designed to defeat', () => {
    // Pins WHY the signature check is needed rather than just that it works:
    // the forged certs satisfy checkIssued, so a metadata comparison alone
    // would accept them.
    const { X509Certificate } = require('crypto');
    const ca = new X509Certificate(FREETSA_ROOT);
    for (const pem of [impersonator, FORGED_CA_IMPERSONATOR]) {
      const forged = new X509Certificate(pem);
      expect(forged.checkIssued(ca)).toBe(true); // metadata: indistinguishable
      expect(forged.verify(ca.publicKey)).toBe(false); // cryptography: not the CA's key
    }
    // The byte-identical one is what step 4's name match reaches.
    expect(new X509Certificate(impersonator).issuer).toBe(ca.subject);
  });

  // Uses a certificate that genuinely chains to its anchor, so the validity
  // window is the only thing left that can reject it, and asserts the error
  // message so the test cannot pass because some other step refused it.
  it('rejects a certificate that was not valid at the timestamp genTime', async () => {
    const f = await makeTsaFixture({
      genTime: new Date('2026-06-01T12:00:00.000Z'),
      signerNotBefore: new Date('2020-01-01T00:00:00Z'),
      signerNotAfter: new Date('2021-01-01T00:00:00Z'),
    });

    // Inside its window: the chain itself is sound.
    const inWindow = verifyCertificatePath(f.signerPem, {
      trustAnchorsPem: [f.caPem],
      atTime: new Date('2020-06-01T00:00:00Z'),
    });
    expect(inWindow.valid).toBe(true);

    // Outside it: rejected, and rejected by the window check specifically.
    const outOfWindow = verifyCertificatePath(f.signerPem, {
      trustAnchorsPem: [f.caPem],
      atTime: f.genTime,
    });
    expect(outOfWindow.valid).toBe(false);
    expect(outOfWindow.error).toMatch(/not valid at the timestamp's genTime/);
  });

  // The forged-certificate case, asserting the step it actually fails at in
  // each situation. The path builder checks the certificate's own validity
  // window before it checks who signed it, so a forged cert with a year-2000
  // genTime is rejected by the window and never reaches the signature step;
  // without a genTime, the signature step is what refuses it.
  it('rejects the forged impersonator at the signature step when the window is not the issue', () => {
    // No atTime: the window cannot be the reason, so the signature must be.
    const result = verifyCertificateChain(impersonator, null);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/signature does not verify against the trusted CA public key/);
  });

  it('rejects the forged impersonator on the window when the genTime is outside it', () => {
    const longAgo = new Date('2000-01-01T00:00:00Z');
    const result = verifyCertificateChain(impersonator, null, longAgo);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/not valid at the timestamp's genTime/);
  });
});
