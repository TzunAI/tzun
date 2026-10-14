/**
 * attestationStatus has one rule, in the engine, and both
 * capture() and retryPendingAttestations() use it.
 *
 * With a copy of the rule on each path, one set of artifacts could get a
 * different status depending on which path last wrote the record, and retry
 * eligibility (the 'pending' listing) would depend on it too. These tests pin
 * that the retry rates what it obtains as capture does, and that the SDK
 * decides no status itself.
 */
import * as fs from 'fs';
import * as path from 'path';
import { Tzun } from '../../src/sdk/index';
import {
  determineAttestationStatus,
  isRetryObtainableComponent,
  missingAttestationComponents,
  webauthnChallengeForDigest,
  type AttestationArtifacts,
  type CaptureInput,
} from '@tzun/engine';
import { mockTsaFetch } from './helpers/mock-tsa';
import { anchoredRecord } from './helpers/anchor-fixtures';

const DIGEST = 'a'.repeat(64);

/** An assertion whose clientDataJSON carries the challenge for `digest`. */
function assertionFor(digest: string): NonNullable<AttestationArtifacts['webauthnAssertion']> {
  const clientData = { type: 'webauthn.get', challenge: webauthnChallengeForDigest(digest) };
  return {
    signature: 'sig',
    credentialKeyId: 'cred',
    algorithm: 'ES256',
    clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64'),
  };
}

const TOKEN = { rfc3161Token: 'dG9rZW4=' };
const ANCHOR: Pick<AttestationArtifacts, 'anchor'> = { anchor: anchoredRecord().anchor };
/** `blockchainAnchor` is not part of the anchor format (tzun-anchor/1 §8.4): it holds no anchor. */
const LEGACY = {
  blockchainAnchor: {
    chain: 'ethereum-sepolia',
    transactionId: '0x' + '1'.repeat(64),
    batchMerkleRoot: DIGEST,
    merklePath: [],
    leafIndex: 0,
    treeSize: 1,
    merkleSpec: 'rfc6962',
  },
} as unknown as AttestationArtifacts;
const BOUND = { webauthnAssertion: assertionFor(DIGEST) };
const UNBOUND = { webauthnAssertion: assertionFor('b'.repeat(64)) };

const decision: CaptureInput = {
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'Meets all criteria',
};

/** A deferrable timestamp; the TSA is mocked and can be taken down. */
async function deferrableTimestamp(): Promise<Tzun> {
  return Tzun.init({
    mode: 'dev',
    attestation: {
      deferrable: ['timestamp'],
      timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
    },
  });
}

describe('the engine rule', () => {
  const both = { timestamp: true, anchor: true };
  const cases: Array<[string, AttestationArtifacts | undefined, object, string]> = [
    ['no artifacts, nothing expected', undefined, {}, 'none'],
    ['no artifacts, nothing expected (empty)', {}, {}, 'none'],
    ['no artifacts, timestamp expected', {}, { timestamp: true }, 'pending'],
    ['timestamp only, nothing expected', TOKEN, {}, 'partial'],
    ['timestamp only, timestamp expected', TOKEN, { timestamp: true }, 'partial'],
    ['timestamp only, both expected', TOKEN, both, 'pending'],
    ['anchor only, both expected', ANCHOR, both, 'pending'],
    ['timestamp and anchor, both expected', { ...TOKEN, ...ANCHOR }, both, 'partial'],
    ['bound signature only, nothing expected', BOUND, {}, 'partial'],
    ['bound signature only, timestamp expected', BOUND, { timestamp: true }, 'pending'],
    ['all three', { ...BOUND, ...TOKEN, ...ANCHOR }, both, 'complete'],
    ['all three, nothing expected', { ...BOUND, ...TOKEN, ...ANCHOR }, {}, 'complete'],
    ['unbound signature counts for nothing', UNBOUND, {}, 'none'],
    ['unbound signature with timestamp and anchor', { ...UNBOUND, ...TOKEN, ...ANCHOR }, both, 'partial'],
    ['a legacy blockchainAnchor, nothing expected', LEGACY, {}, 'none'],
    ['a legacy blockchainAnchor, anchor expected', LEGACY, { anchor: true }, 'pending'],
    ['a legacy blockchainAnchor beside a timestamp and a bound signature', { ...BOUND, ...TOKEN, ...LEGACY }, {}, 'partial'],
  ];

  it.each(cases)('%s', (_label, artifacts, expected, status) => {
    expect(determineAttestationStatus(artifacts, DIGEST, expected)).toBe(status);
  });

  it('expectation defaults to nothing', () => {
    expect(determineAttestationStatus({}, DIGEST)).toBe('none');
    expect(determineAttestationStatus(TOKEN, DIGEST)).toBe('partial');
  });

  it('names the expected components a record lacks', () => {
    expect(missingAttestationComponents({}, { timestamp: true, anchor: true })).toEqual(['timestamp', 'anchor']);
    expect(missingAttestationComponents(TOKEN, { timestamp: true, anchor: true })).toEqual(['anchor']);
    expect(missingAttestationComponents(LEGACY, { anchor: true })).toEqual(['anchor']);
    expect(missingAttestationComponents(ANCHOR, { anchor: true })).toEqual([]);
    expect(missingAttestationComponents(TOKEN, { timestamp: true })).toEqual([]);
    expect(missingAttestationComponents(undefined, {})).toEqual([]);
  });

  it('an absent, null or empty token is missing', () => {
    for (const rfc3161Token of [undefined, null, '']) {
      expect(
        missingAttestationComponents({ rfc3161Token } as unknown as AttestationArtifacts, { timestamp: true }),
      ).toEqual(['timestamp']);
    }
  });

  // The retry obtains the timestamp. The
  // anchor is filled for a batch by an anchor scheduler, and the retry never
  // lists or requests it.
  it('the timestamp is retry-obtainable; the anchor, a signature and anything else are not', () => {
    expect(isRetryObtainableComponent('timestamp')).toBe(true);
    for (const other of ['blockchain', 'anchor', 'webauthn', 'assertionTimestamp', '', undefined, null, 1]) {
      expect(isRetryObtainableComponent(other)).toBe(false);
    }
  });
});

describe('one attestationStatus rule for capture and retry', () => {
  let savedFetch: typeof globalThis.fetch;

  beforeEach(() => {
    savedFetch = globalThis.fetch;
    globalThis.fetch = jest.fn().mockImplementation(mockTsaFetch());
  });

  afterEach(() => {
    globalThis.fetch = savedFetch;
    jest.restoreAllMocks();
  });

  it('a missing configured timestamp is pending at capture, and the retry rates what it obtains as capture does', async () => {
    const tzun = await deferrableTimestamp();
    try {
      (globalThis.fetch as jest.Mock).mockRejectedValueOnce(new Error('TSA down'));
      const missed = await tzun.capture(decision);
      expect(missed.stored).toBe(true);
      expect(missed.envelope.nonRepudiation.rfc3161Token).toBeUndefined();
      expect(missed.envelope.attestationStatus).toBe('pending');

      await tzun.retryPendingAttestations();
      const retried = await tzun.getStorage().retrieve(missed.envelope.payload.evidenceId);
      expect(retried!.nonRepudiation.rfc3161Token).toBeDefined();

      // The same kinds of artifact at capture: the same status.
      const timestamped = await tzun.capture(decision);
      expect(timestamped.envelope.nonRepudiation.rfc3161Token).toBeDefined();
      expect(retried!.attestationStatus).toBe(timestamped.envelope.attestationStatus);
      expect(retried!.attestationStatus).toBe('partial');
    } finally {
      await tzun.close();
    }
  });

  it('a record with every configured component is partial at capture', async () => {
    const tzun = await deferrableTimestamp();
    try {
      const captured = await tzun.capture(decision);
      expect(captured.envelope.nonRepudiation.rfc3161Token).toBeDefined();
      // No bound signature, so not complete; nothing configured is missing.
      expect(captured.envelope.attestationStatus).toBe('partial');
    } finally {
      await tzun.close();
    }
  });

  it('the SDK decides no status itself: every status in src/sdk/index.ts comes from the engine', () => {
    const source = fs.readFileSync(path.join(__dirname, '../../src/sdk/index.ts'), 'utf8');
    expect(source).not.toMatch(/(=|return)\s*'(complete|partial|none)'/);
    expect(source).not.toMatch(/Status\s*=\s*'pending'/);
    expect(source).toMatch(/determineAttestationStatus\(/);
  });
});
