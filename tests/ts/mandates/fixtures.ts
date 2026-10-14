/**
 * Fixtures for the mandate suites: the three backends a
 * `Tzun` instance opens with the mandate extensions installed, people with
 * registered Ed25519 passkeys who sign WebAuthn assertions, a mandate
 * document, and the issue ceremony.
 *
 * Not a suite: jest's testMatch is `**\/tests/**\/*.test.ts`.
 */
import { createHash, generateKeyPairSync, randomUUID, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { agentDescriptorDigest, type AgentDescriptor, type MandateDocument, type TzunConfig, type WebauthnAssertion } from '@tzun/engine';
import { Tzun } from '../../../src/sdk';
import { mandatesExtension } from '../../../src/sdk/mandates';
import { decidersExtension } from '../../../src/storage/ddl/deciders';
import { mandatesExtension as mandatesStorage } from '../../../src/storage/ddl/mandates';
import { PG_TESTS_ENABLED, pgSuiteSchema } from '../helpers/postgres-test-db';

export const hex = (label: string): string => createHash('sha256').update(label).digest('hex');

/**
 * The claims agent's descriptor. An instance with the agent catalog installed
 * (the default) refuses a decision naming an agent it does not hold, so a
 * suite on the default install registers it first.
 */
export const CLAIMS_AGENT_DESCRIPTOR: AgentDescriptor = {
  v: 'tzun-agent/1',
  name: 'claims-agent',
  operator: { organization: 'Example Insurer', owner: null },
  identities: [],
  keys: [],
  models: [],
  instructions: null,
  tools: null,
  runtime: null,
  policy: null,
  parent: null,
  derivation: null,
};

/** The agent the documents authorise, and one they do not. */
export const AGENT = agentDescriptorDigest(CLAIMS_AGENT_DESCRIPTOR);
export const OTHER_AGENT = `sha256:${hex('another agent descriptor')}`;

export const RP_ID = 'demo.tzun.ai';
const ORIGIN = 'https://demo.tzun.ai';

/** A person with a passkey registered in a `Tzun` instance's credential store. */
export interface Person {
  userId: string;
  credentialId: string;
  privateKey: KeyObject;
  publicKeyBase64: string;
}

export function person(userId: string): Person {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    userId,
    credentialId: `cred-${userId}-${randomUUID().slice(0, 8)}`,
    privateKey,
    publicKeyBase64: (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64'),
  };
}

/** Register a person's passkey in the instance's credential store. */
export async function enrol(tzun: Tzun, p: Person): Promise<void> {
  await tzun.getCredentialStore()!.register({
    credentialId: p.credentialId,
    publicKey: p.publicKeyBase64,
    userId: p.userId,
    algorithm: 'Ed25519',
    counter: 0,
    status: 'active',
    registeredAt: '2026-01-01T00:00:00.000Z',
  });
}

/**
 * A WebAuthn assertion by `p` presenting `challenge`: an Ed25519 signature
 * over `authenticatorData ‖ SHA-256(clientDataJSON)`, the flags User Present
 * and (unless `uv: false`) User Verified.
 */
export function assert(p: Person, challenge: string, opts: { uv?: boolean } = {}): WebauthnAssertion {
  const authenticatorData = Buffer.concat([
    createHash('sha256').update(RP_ID, 'utf8').digest(),
    Buffer.from([opts.uv === false ? 0x01 : 0x05]),
    Buffer.from([0, 0, 0, 1]),
  ]);
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN, crossOrigin: false }));
  const signed = Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]);
  return {
    signature: cryptoSign(null, signed, p.privateKey).toString('base64url'),
    credentialKeyId: p.credentialId,
    algorithm: 'Ed25519',
    authenticatorData: authenticatorData.toString('base64url'),
    clientDataJSON: clientDataJSON.toString('base64url'),
  };
}

const iso = (offsetMs: number): string => new Date(Date.now() + offsetMs).toISOString();
export const HOUR = 3_600_000;

/**
 * A mandate document: the claims agent may approve or refer claims of
 * `claims-triage` up to 500,000 minor units each, 1,000,000 in all, at most
 * three records, with a confirmation owed when the fraud flag is set; valid
 * from an hour ago for a day.
 */
export function mandateDocument(principal: string, overrides: Partial<MandateDocument> = {}): MandateDocument {
  return {
    v: 'tzun-mandate/1',
    mandateId: randomUUID(),
    principal: { signer: principal, credential: null },
    agents: [`desc:${AGENT}`],
    schemaVersion: 'v1.0',
    scope: {
      aiSystemIds: ['claims-triage'],
      actions: ['approve', 'refer'],
      models: null,
      predicates: { cap: { path: '/aiOutput/amountMinor', op: 'le', value: 500000, quant: null } },
    },
    confirm: { fraud: { path: '/aiOutput/fraudFlag', op: 'eq', value: true, quant: null } },
    validity: { notBefore: iso(-HOUR), notAfter: iso(24 * HOUR) },
    limits: { maxRecords: 3, cumulative: { paid: { path: '/aiOutput/amountMinor', max: 1_000_000 } } },
    delegation: { allowed: false, maxDepth: 0, attenuation: 'subset' },
    review: null,
    policyDigest: null,
    predecessor: null,
    parent: null,
    ...overrides,
  };
}

/** Prepare, sign and issue `document` as `principal`. */
export async function issue(tzun: Tzun, document: MandateDocument, principal: Person) {
  const prepared = await tzun.mandates.prepare(document);
  return tzun.mandates.issue({ document, statement: prepared.statement, assertion: assert(principal, prepared.challenge) });
}

/** A decision of the claims agent under a mandate. */
export function claim(amountMinor: number, overrides: { fraudFlag?: boolean; action?: string; agent?: string; kind?: 'agent-mandated' | 'agent' } = {}) {
  return {
    aiSystemId: 'claims-triage',
    aiOutput: { amountMinor, fraudFlag: overrides.fraudFlag ?? false },
    action: overrides.action ?? 'approve',
    reason: 'Within the claims mandate',
    decider: { kind: overrides.kind ?? ('agent-mandated' as const), agent: overrides.agent ?? AGENT },
  };
}

/** The extensions a mandate-capable instance installs. */
export const MANDATE_EXTENSIONS: Pick<TzunConfig, '_sdkExtensions' | '_storageExtensions'> = {
  _sdkExtensions: [mandatesExtension],
  _storageExtensions: [decidersExtension, mandatesStorage],
};

/** One backend: how to open an instance on a fresh store, and a second instance on the same store. */
export interface Backend {
  name: 'memory' | 'sqlite' | 'postgres';
  /** A fresh store. */
  fresh(config?: Partial<TzunConfig>): Promise<Tzun>;
  /** Another instance on the store `fresh` opened last (not for memory). */
  again(config?: Partial<TzunConfig>): Promise<Tzun>;
}

/** The backends of this run: memory and SQLite always, Postgres when its legs run. Call at module scope. */
export function backends(label: string): Backend[] {
  let dir = '';
  let file = '';
  let n = 0;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), `tzun-${label}-`));
  });
  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });
  const pg = pgSuiteSchema(label);
  const base = (config: Partial<TzunConfig> = {}): TzunConfig => ({ mode: 'dev', ...MANDATE_EXTENSIONS, ...config }) as TzunConfig;
  const list: Backend[] = [
    {
      name: 'memory',
      fresh: (config) => Tzun.init(base(config)),
      again: () => Promise.reject(new Error('a memory store is not shared between instances')),
    },
    {
      name: 'sqlite',
      fresh: (config) => {
        file = join(dir, `mandates-${++n}.db`);
        return Tzun.init(base({ dbPath: file, ...config }));
      },
      again: (config) => Tzun.init(base({ dbPath: file, ...config })),
    },
  ];
  if (PG_TESTS_ENABLED) {
    list.push({
      name: 'postgres',
      fresh: async (config) => {
        await pg.empty();
        return Tzun.init(base({ dbUrl: pg.url, ...config }));
      },
      again: (config) => Tzun.init(base({ dbUrl: pg.url, ...config })),
    });
  }
  return list;
}
