/**
 * The registry of public RFC 3161 Timestamp Authorities.
 *
 * WHAT THIS FILE IS DEFENDING. The verifier could always be pointed at another
 * TSA — through `trustAnchorsPem` or `TZUN_TSA_TRUST_ANCHORS` — but only if
 * the integrator could produce the right root, and "the right root" is not the certificate that arrives in the token.
 * Sectigo's token carries a Public Time Stamping Root R46 CROSS-SIGNED by
 * USERTrust; DigiCert's carries a Trusted Root G4 cross-signed by Assured ID.
 * Pin either of those and you have quietly widened your trust store to a
 * general-purpose public CA. There are three certificates in Sectigo's own
 * published p7c sharing that subject and only one of them is the self-signed
 * timestamping root.
 *
 * So the registry's promise is a narrow, checkable one: *for this authority,
 * this exact certificate terminates the path, and nothing above it is
 * trusted.* Every test below re-checks that promise against a REAL token
 * captured from the live endpoint on 2026-09-12 and pinned in
 * `fixtures/tsa-tokens.json` — no synthetic CA, no mock. A registry entry
 * whose anchor is wrong, or whose PEM is swapped, fails here.
 *
 * The suite makes no network calls: jest's `no-live-network` guard would
 * refuse them, and a registry test that needed a live TSA would go red on
 * somebody else's outage.
 */
import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { X509Certificate } from 'crypto';
import {
  listTimestampAuthorities,
  independentAuthorities,
  getTimestampAuthority,
  resolveTimestampAuthorities,
  timestampAuthorityUrls,
  timestampAuthorityAnchorsPem,
  timestampAuthorityAnchorPath,
  addTimestampAuthority,
  DEFAULT_TRUST_ANCHOR_AUTHORITIES,
  TimestampAuthority,
} from '../../src/attestation/tsa-registry';
import {
  resolveTrustAnchors,
  verifyTimestampToken,
  extractRFC3161Metadata,
} from '../../src/attestation/rfc3161-verify';
import { verifyAttestation } from '../../src/attestation/verify-attestation';

jest.setTimeout(60_000);

interface TokenFixture {
  url: string;
  probedAt: string;
  digestHex: string;
  tokenBase64: string;
  genTime: string;
  policyOid: string;
  signerCommonName: string;
}

const FIXTURES: Record<string, TokenFixture> = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'tsa-tokens.json'), 'utf-8'),
);

const CERTS_DIR = path.join(__dirname, '..', '..', 'src', 'attestation', 'certs');

function firstCert(pem: string): X509Certificate {
  const block = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  if (!block) throw new Error('no certificate in PEM');
  return new X509Certificate(block[0]);
}

describe('public timestamp authority registry', () => {
  const savedAnchors = process.env.TZUN_TSA_TRUST_ANCHORS;
  const savedAuthorities = process.env.TZUN_TSA_AUTHORITIES;
  beforeEach(() => {
    delete process.env.TZUN_TSA_TRUST_ANCHORS;
    delete process.env.TZUN_TSA_AUTHORITIES;
  });
  afterAll(() => {
    if (savedAnchors === undefined) delete process.env.TZUN_TSA_TRUST_ANCHORS;
    else process.env.TZUN_TSA_TRUST_ANCHORS = savedAnchors;
    if (savedAuthorities === undefined) delete process.env.TZUN_TSA_AUTHORITIES;
    else process.env.TZUN_TSA_AUTHORITIES = savedAuthorities;
  });

  const authorities = listTimestampAuthorities();

  it('registers every authority that was probed', () => {
    // Guards against an entry being dropped in a refactor and nobody noticing,
    // because every other test in this file iterates the registry: a registry
    // of one would pass all of them vacuously.
    expect(authorities.map((a) => a.key).sort()).toEqual(
      [
        'aimoda',
        'apple',
        'certum',
        'digicert',
        'entrust',
        'freetsa',
        'globalsign',
        'identrust',
        'mesign',
        'sectigo',
        'sslcom',
      ].sort(),
    );
  });

  describe.each(authorities.map((a): [string, TimestampAuthority] => [a.key, a]))(
    '%s',
    (key, authority) => {
      const fixture = FIXTURES[key];

      it('has a live-probe fixture', () => {
        // A registry entry with no fixture is an unverified claim, which is
        // precisely what this registry must never carry.
        expect(fixture).toBeDefined();
        expect(fixture.url).toBe(authority.url);
      });

      it('pins the anchor by SHA-256 fingerprint', () => {
        // The trust anchor is the ONE input to verification that nothing else
        // checks. A verifier handed a substituted root reports
        // `timestampValid: true` and is behaving exactly as designed while
        // being completely wrong, so the bytes get pinned here.
        const pem = fs.readFileSync(timestampAuthorityAnchorPath(authority), 'utf-8');
        const cert = firstCert(pem);
        expect(cert.fingerprint256).toBe(authority.anchorFingerprintSha256);
        expect(cert.subject).toContain(`CN=${authority.anchorCommonName}`);
      });

      it('pins a self-signed root, not a cross-signed copy', () => {
        // Pinning a cross-signed certificate still verifies tokens, so this
        // mistake is invisible at runtime — while having silently moved the
        // top of the trust path up into a general-purpose public CA.
        const cert = firstCert(
          fs.readFileSync(timestampAuthorityAnchorPath(authority), 'utf-8'),
        );
        expect(cert.subject).toBe(cert.issuer);
        expect(cert.verify(cert.publicKey)).toBe(true);
      });

      it('records the policy OID the live token actually carries', () => {
        // Hand-transcribed from a probe, which is how a digit goes missing.
        // The OID is also the only machine-readable statement of the terms the
        // authority issued under, so a wrong one is a wrong claim about what
        // the evidence means — and openssl prints FreeTSA's as the string
        // "tsa_policy1" from its own config table, not as an OID at all.
        const meta = extractRFC3161Metadata(fixture.tokenBase64);
        expect(meta?.status).toBe('granted');
        expect(meta?.policyOid).toBe(authority.policyOid);
      });

      it('verifies a real token from the live endpoint', async () => {
        const result = await verifyTimestampToken(fixture.tokenBase64, fixture.digestHex, {
          authorities: [key],
        });

        expect(result.error).toBeUndefined();
        expect(result.valid).toBe(true);
        expect(result.digestMatch).toBe(true);
        expect(result.signatureValid).toBe(true);
        expect(result.certificateChainValid).toBe(true);
        expect(result.tsaSubject).toBe(fixture.signerCommonName);
      });

      it('selecting it by URL resolves the same anchor as selecting it by key', () => {
        // The fact an integrator has to hand is the URL already in their
        // config, not a key they have never seen.
        expect(getTimestampAuthority(authority.url)).toBe(authority);
        expect(timestampAuthorityAnchorsPem([authority.url])).toEqual(
          timestampAuthorityAnchorsPem([key]),
        );
      });
    },
  );

  describe('the default trust store is the default capture pair', () => {
    it('trusts FreeTSA and Sectigo and nothing else when nothing is configured', () => {
      // Nine roots ship; two are trusted. Each trusted root is a signing
      // hierarchy that can make a token verify, so the default trusts exactly
      // the two roots the default capture list obtains tokens from.
      const anchors = resolveTrustAnchors();
      expect(anchors).toHaveLength(2);
      const subjects = anchors.map((a) => firstCert(a).subject);
      expect(subjects.some((s) => s.includes('CN=www.freetsa.org'))).toBe(true);
      expect(
        subjects.some((s) => s.includes('CN=Sectigo Public Time Stamping Root R46')),
      ).toBe(true);
      expect(DEFAULT_TRUST_ANCHOR_AUTHORITIES).toEqual(['freetsa', 'sectigo']);
    });

    it('derives that default from DEFAULT_TRUST_ANCHOR_AUTHORITIES', () => {
      // Not the same assertion as the one above. That one says what the
      // default IS; this one says the default is COMPUTED from the constant,
      // so the constant is the only place it is stated. A hardcoded second
      // read of the PEMs would pass the first test forever while the constant
      // quietly controlled nothing.
      const derived = timestampAuthorityAnchorsPem(DEFAULT_TRUST_ANCHOR_AUTHORITIES);
      const fingerprints = resolveTrustAnchors().map((a) => firstCert(a).fingerprint256);
      expect(fingerprints).toEqual(derived.map((a) => firstCert(a).fingerprint256));
    });

    const defaultFingerprints = new Set(
      resolveTimestampAuthorities(DEFAULT_TRUST_ANCHOR_AUTHORITIES).map(
        (a) => a.anchorFingerprintSha256,
      ),
    );

    it.each(
      listTimestampAuthorities()
        .filter((a) => defaultFingerprints.has(a.anchorFingerprintSha256))
        .map((a) => a.key),
    )('accepts a genuine %s token under the default anchors', async (key) => {
      // `entrust` is here too: it relays Sectigo, so its tokens are Sectigo's
      // tokens and chain to the same root.
      const fixture = FIXTURES[key];
      const result = await verifyTimestampToken(fixture.tokenBase64, fixture.digestHex);
      expect(result.error).toBeUndefined();
      expect(result.valid).toBe(true);
      expect(result.tsaSubject).toBe(fixture.signerCommonName);
    });

    it.each(
      listTimestampAuthorities()
        .filter((a) => !defaultFingerprints.has(a.anchorFingerprintSha256))
        .map((a) => a.key),
    )('rejects a genuine %s token under the default anchors', async (key) => {
      // Non-vacuity for every "verifies a real token" case above: those tokens
      // are not universally accepted, they are accepted BECAUSE the right
      // anchor was selected. A bundled root is not a trusted root.
      const fixture = FIXTURES[key];
      const result = await verifyTimestampToken(fixture.tokenBase64, fixture.digestHex);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('untrusted_chain');
      // Still names the real signer even on the failure path.
      expect(result.tsaSubject).toBe(fixture.signerCommonName);
    });
  });

  describe('relays are recorded as relays', () => {
    it('proves Entrust\'s public endpoint returns Sectigo-signed tokens', async () => {
      // Listed as an authority everywhere else on the internet. It is not one:
      // pairing it with `sectigo` for failover looks like two attesters and is
      // one, so the outage that takes out Sectigo takes out both.
      expect(FIXTURES.entrust.signerCommonName).toBe(FIXTURES.sectigo.signerCommonName);
      expect(FIXTURES.entrust.policyOid).toBe(FIXTURES.sectigo.policyOid);

      const result = await verifyTimestampToken(
        FIXTURES.entrust.tokenBase64,
        FIXTURES.entrust.digestHex,
        { authorities: ['sectigo'] },
      );
      expect(result.valid).toBe(true);
    });

    it('proves rfc3161.ai.moda returns DigiCert-signed tokens', async () => {
      expect(FIXTURES.aimoda.signerCommonName).toBe(FIXTURES.digicert.signerCommonName);
      expect(FIXTURES.aimoda.policyOid).toBe(FIXTURES.digicert.policyOid);

      const result = await verifyTimestampToken(
        FIXTURES.aimoda.tokenBase64,
        FIXTURES.aimoda.digestHex,
        { authorities: ['digicert'] },
      );
      expect(result.valid).toBe(true);
    });

    it('keeps relays out of the independent list', () => {
      const keys = independentAuthorities().map((a) => a.key);
      expect(keys).not.toContain('entrust');
      expect(keys).not.toContain('aimoda');
      expect(keys).toContain('sectigo');
      expect(keys).toContain('digicert');
    });
  });

  describe('selection', () => {
    it('unions an explicit PEM with an explicit authority selection', () => {
      // A caller who passes both means both: one names authorities this
      // package ships roots for, the other supplies a root it does not.
      const ownRoot = fs.readFileSync(path.join(CERTS_DIR, 'apple-root-ca.pem'), 'utf-8');
      const anchors = resolveTrustAnchors({
        trustAnchorsPem: [ownRoot],
        authorities: ['sectigo'],
      });
      const subjects = anchors.map((a) => firstCert(a).subject);
      expect(subjects.some((s) => s.includes('CN=Apple Root CA'))).toBe(true);
      expect(
        subjects.some((s) => s.includes('CN=Sectigo Public Time Stamping Root R46')),
      ).toBe(true);
      expect(anchors).toHaveLength(2);
    });

    it('collapses two selectors that share one root', () => {
      // `entrust` IS `sectigo`. A duplicated anchor changes no trust decision,
      // but it makes resolveTrustAnchors().length report a trust store larger
      // than it is — the exact number an operator reads when auditing what
      // their verifier trusts.
      expect(resolveTrustAnchors({ authorities: ['sectigo', 'entrust'] })).toHaveLength(1);
      expect(timestampAuthorityAnchorsPem(['sectigo', 'entrust'])).toHaveLength(1);
    });

    it('reads TZUN_TSA_AUTHORITIES from the environment', () => {
      process.env.TZUN_TSA_AUTHORITIES = 'freetsa, digicert';
      const anchors = resolveTrustAnchors();
      expect(anchors).toHaveLength(2);
      const subjects = anchors.map((a) => firstCert(a).subject);
      expect(subjects.some((s) => s.includes('CN=www.freetsa.org'))).toBe(true);
      expect(subjects.some((s) => s.includes('CN=DigiCert Trusted Root G4'))).toBe(true);
    });

    it('unions the two environment variables', () => {
      process.env.TZUN_TSA_AUTHORITIES = 'sectigo';
      process.env.TZUN_TSA_TRUST_ANCHORS = fs.readFileSync(
        path.join(CERTS_DIR, 'freetsa-ca.pem'),
        'utf-8',
      );
      expect(resolveTrustAnchors()).toHaveLength(2);
    });

    it('lets an explicit option override the environment entirely', () => {
      process.env.TZUN_TSA_AUTHORITIES = 'digicert';
      const anchors = resolveTrustAnchors({ authorities: ['sectigo'] });
      expect(anchors).toHaveLength(1);
      expect(firstCert(anchors[0]).subject).toContain('CN=Sectigo Public Time Stamping Root R46');
    });

    it('refuses to hand out a file path for a runtime-registered authority', () => {
      // path.join(certsDir(), '') is the certs DIRECTORY, which readFileSync
      // rejects with EISDIR several frames from the mistake.
      addTimestampAuthority({
        key: 'no-file',
        url: 'https://tsa.example.invalid/nofile',
        operator: 'Example',
        tls: true,
        access: 'commercial',
        anchorCommonName: 'Apple Root CA',
        policyOid: '1.2.3',
        publiclyTrustedRoot: false,
        probedAt: '2026-09-12',
        note: 'test',
        anchorPem: fs.readFileSync(path.join(CERTS_DIR, 'apple-root-ca.pem'), 'utf-8'),
      });
      const registered = getTimestampAuthority('no-file')!;
      expect(() => timestampAuthorityAnchorPath(registered)).toThrow(
        /registered at runtime and has no bundled anchor file/,
      );
      // ...and the supported route still works.
      expect(timestampAuthorityAnchorsPem(['no-file'])).toHaveLength(1);
    });

    it('throws on an unknown selector instead of quietly dropping it', () => {
      // A silently dropped selector does not fail at configuration time. It
      // fails months later as `untrusted_chain` on evidence that is genuine.
      expect(() => resolveTimestampAuthorities(['sectgio'])).toThrow(
        /Unknown timestamp authority "sectgio"/,
      );
      expect(() => resolveTimestampAuthorities(['sectgio'])).toThrow(/Known keys: /);
      expect(() => resolveTrustAnchors({ authorities: ['https://tsa.example/nope'] })).toThrow(
        /Unknown timestamp authority/,
      );
    });

    it('matches a URL that differs only by case or a trailing slash', () => {
      expect(getTimestampAuthority('https://FreeTSA.org/tsr/')?.key).toBe('freetsa');
      expect(getTimestampAuthority('HTTPS://timestamp.sectigo.com')?.key).toBe('sectigo');
    });
  });

  describe('feeding the capture-side authority list', () => {
    it('turns a selection into the ordered URL list', () => {
      // This is what goes into `attestation.timestamp.rfc3161Urls`. The same
      // selection feeds the verify side, which is the whole point: configuring
      // only one half is how a deployment ends up with captures that succeed
      // and records that read `untrusted_chain`.
      expect(timestampAuthorityUrls(DEFAULT_TRUST_ANCHOR_AUTHORITIES)).toEqual([
        'https://freetsa.org/tsr',
        'https://timestamp.sectigo.com',
      ]);
    });

    it('defaults to two independent authorities over TLS', () => {
      // Failover only helps if the fallback does not fail WITH the primary. A
      // relay of the primary, or a second endpoint of the same operator, is one
      // point of failure wearing two URLs.
      const pair = resolveTimestampAuthorities(DEFAULT_TRUST_ANCHOR_AUTHORITIES);
      expect(pair).toHaveLength(2);
      const [primary, fallback] = pair;

      expect(primary.relayOf).not.toBe(fallback.key);
      expect(fallback.relayOf).not.toBe(primary.key);
      expect(pair.every((a) => a.relayOf === undefined)).toBe(true);
      expect(primary.operator).not.toBe(fallback.operator);
      expect(primary.anchorFingerprintSha256).not.toBe(fallback.anchorFingerprintSha256);
      expect(pair.every((a) => a.tls)).toBe(true);

      // The live tokens agree: different signers under different policies.
      expect(FIXTURES[primary.key].signerCommonName).not.toBe(
        FIXTURES[fallback.key].signerCommonName,
      );
      expect(FIXTURES[primary.key].policyOid).not.toBe(FIXTURES[fallback.key].policyOid);
    });

    it('de-duplicates URLs so one endpoint is never contacted twice', () => {
      expect(timestampAuthorityUrls(['sectigo', 'https://timestamp.sectigo.com'])).toEqual([
        'https://timestamp.sectigo.com',
      ]);
    });
  });

  describe('verifyAttestation plumbing', () => {
    it('passes authorities down to the timestamp check', async () => {
      // TrustAnchorOptions is forwarded key by key at three call sites. An
      // option that is added, typed, plumbed and documented but dropped at one
      // of them fails exactly like a missing feature, silently. DigiCert is
      // bundled but not trusted by default (next test but one), so only the
      // option can pass it.
      const f = FIXTURES.digicert;
      const withAuthority = await verifyAttestation({ rfc3161Token: f.tokenBase64 }, f.digestHex, undefined, {
        authorities: ['digicert'],
      });
      expect(withAuthority.timestampValid).toBe(true);
    });

    it('verifies a Sectigo token with no trust options, as a failed-over capture needs', async () => {
      // A capture that fell over to Sectigo stores Sectigo's token. The
      // default verifier has to accept it with nothing configured, or the
      // failover produced a record that reads `untrusted_chain`.
      const f = FIXTURES.sectigo;
      const result = await verifyAttestation({ rfc3161Token: f.tokenBase64 }, f.digestHex);
      expect(result.timestampValid).toBe(true);
      expect(result.timestampReason).toBeUndefined();
    });

    it('still calls a bundled-but-not-default authority untrusted with no trust options', async () => {
      const f = FIXTURES.digicert;
      const result = await verifyAttestation({ rfc3161Token: f.tokenBase64 }, f.digestHex);
      expect(result.timestampValid).toBe(false);
      expect(result.timestampReason).toBe('untrusted_chain');
    });
  });

  describe('registering an authority the registry does not ship', () => {
    it('accepts a caller-supplied root and uses it as an anchor', async () => {
      // A contracted or qualified-eIDAS TSA's root does not live in this
      // package, and a customer must not have to wait for an SDK release to
      // pin one.
      const applePem = fs.readFileSync(path.join(CERTS_DIR, 'apple-root-ca.pem'), 'utf-8');
      addTimestampAuthority({
        key: 'contracted-test',
        url: 'https://tsa.example.invalid/rfc3161',
        operator: 'Example Contracted TSA',
        tls: true,
        access: 'commercial',
        anchorCommonName: 'Apple Root CA',
        policyOid: '1.2.3',
        publiclyTrustedRoot: true,
        probedAt: '2026-09-12',
        anchorPem: applePem,
        note: 'Registered at runtime by the test suite.',
      });

      const anchors = resolveTrustAnchors({ authorities: ['contracted-test'] });
      expect(anchors).toHaveLength(1);
      expect(firstCert(anchors[0]).subject).toContain('CN=Apple Root CA');

      // And it really verifies: the Apple fixture is a genuine token.
      const result = await verifyTimestampToken(
        FIXTURES.apple.tokenBase64,
        FIXTURES.apple.digestHex,
        { authorities: ['contracted-test'] },
      );
      expect(result.valid).toBe(true);
    });

    it('de-duplicates runtime-registered anchors by fingerprint, not by filename', () => {
      // Every runtime-registered authority has an empty `anchorFile`. Keying
      // de-duplication on that collapses all of them to one and drops the rest.
      const gsPem = fs.readFileSync(
        path.join(CERTS_DIR, 'globalsign-timestamping-root-r45.pem'),
        'utf-8',
      );
      const certumPem = fs.readFileSync(
        path.join(CERTS_DIR, 'certum-trusted-network-ca-2.pem'),
        'utf-8',
      );
      const base = {
        url: 'https://tsa.example.invalid/x',
        operator: 'Example',
        tls: true,
        access: 'commercial' as const,
        policyOid: '1.2.3',
        publiclyTrustedRoot: false,
        probedAt: '2026-09-12',
        note: 'test',
      };
      addTimestampAuthority({ ...base, key: 'rt-a', anchorCommonName: 'A', anchorPem: gsPem });
      addTimestampAuthority({ ...base, key: 'rt-b', anchorCommonName: 'B', anchorPem: certumPem });

      expect(timestampAuthorityAnchorsPem(['rt-a', 'rt-b'])).toHaveLength(2);
    });
  });

  it('keeps the trust anchors readable in a diff', () => {
    // `.gitattributes` marks `*.pem binary`, which is right for the general
    // case and wrong for exactly these files: `binary` suppresses the diff, so
    // adding a root CA reaches a reviewer as "Bin 0 -> 2521 bytes". These are
    // the one kind of file in this repo where "trust me, it is the right
    // certificate" IS the thing under review, and each carries its provenance,
    // fingerprint, serial and validity window in a header a suppressed diff
    // never shows. The narrower rule has to keep winning.
    const attrs = execFileSync(
      'git',
      ['check-attr', 'diff', 'text', '--', 'src/attestation/certs/freetsa-ca.pem'],
      { cwd: path.join(__dirname, '..', '..'), encoding: 'utf-8' },
    );
    expect(attrs).toMatch(/diff: set/);
    expect(attrs).toMatch(/text: set/);
  });

  it('ships no orphan certificate and references no missing one', () => {
    // Both directions. An orphan PEM is dead weight in a published package;
    // a missing one is a registry entry that throws ENOENT the first time a
    // customer selects it.
    const onDisk = fs
      .readdirSync(CERTS_DIR)
      .filter((f) => f.endsWith('.pem'))
      .sort();
    const referenced = [
      ...new Set(listTimestampAuthorities().map((a) => a.anchorFile).filter((f) => f !== '')),
    ].sort();
    expect(onDisk).toEqual(referenced);
  });
});
