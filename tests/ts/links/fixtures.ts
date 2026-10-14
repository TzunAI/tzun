/**
 * Shared fixtures of the link suites: a `Tzun` with
 * the link service and the link index installed, on the memory, SQLite and
 * (when the Postgres legs run) Postgres stores, and the decision inputs the
 * suites capture.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import type { CaptureResult, EvidenceEnvelope } from '@tzun/engine';
import { Tzun } from '../../../src/sdk';
import type { SdkExtensionFactory, SdkHost } from '../../../src/sdk/extension-points';
import { linksSdkExtension, type LinksService } from '../../../src/sdk/links';
import type { DecisionGraphService } from '../../../src/sdk/decision-graph';
import { decidersExtension } from '../../../src/storage/ddl/deciders';
import { linksStorageExtension } from '../../../src/storage/ddl/links';
import { PG_TESTS_ENABLED, type PgTestSchema } from '../helpers/postgres-test-db';

export const hex = (label: string): string => createHash('sha256').update(label).digest('hex');

export const human = (id = 'acct:u-4821') => ({ kind: 'human' as const, id });
export const decision = (label = 'decision', decider = human()) => ({
  aiOutput: { label },
  action: 'approve',
  reason: `reason for ${label}`,
  decider,
});

/** The storage extensions a linked store installs. */
export const LINK_STORAGE_EXTENSIONS = [decidersExtension, linksStorageExtension];

/** A `Tzun` whose link service and index are installed, with the host the link service was given. */
export interface LinkedTzun {
  tzun: Tzun;
  host: SdkHost;
  links: LinksService;
  graph: DecisionGraphService;
  close(): Promise<void>;
}

/** Capture `input`, failing the test with the refusal when it is refused. */
export async function captured(tzun: Tzun, input: Parameters<Tzun['capture']>[0], options?: Parameters<Tzun['capture']>[1]): Promise<EvidenceEnvelope> {
  const result = await tzun.capture(input, options);
  if (!result.stored) throw new Error(`capture refused: ${JSON.stringify(result.failure?.diagnosticMetadata)}`);
  return result.envelope;
}

/** The refusal's diagnostic metadata, failing the test when the capture was stored. */
export function refusalOf(result: CaptureResult): Record<string, unknown> {
  if (result.stored) throw new Error('expected a refusal, the capture was stored');
  return result.failure!.diagnosticMetadata as Record<string, unknown>;
}

/** One kind of store a linked `Tzun` opens on. */
export interface StoreLeg {
  name: 'memory' | 'sqlite' | 'postgres';
  /** Open a linked `Tzun` on a fresh store of this kind (`file` names a store to reopen, SQLite only). */
  open(options?: { extra?: SdkExtensionFactory[]; file?: string }): Promise<LinkedTzun>;
}

let dir: string | null = null;
let files = 0;

/** A fresh SQLite path in a directory the suite removes. */
export function sqlitePath(): string {
  dir ??= mkdtempSync(join(tmpdir(), 'tzun-test-links-'));
  return join(dir, `links-${++files}.db`);
}

/** Remove the suite's SQLite files. */
export function removeSqliteFiles(): void {
  if (dir !== null) rmSync(dir, { recursive: true, force: true });
  dir = null;
}

/** Open a linked `Tzun` with this config. */
export async function openLinked(config: Record<string, unknown>, extra: SdkExtensionFactory[] = []): Promise<LinkedTzun> {
  let host!: SdkHost;
  const grab: SdkExtensionFactory = (h) => {
    host = h;
    return linksSdkExtension(h);
  };
  const tzun = await Tzun.init({
    mode: 'dev',
    ...config,
    _sdkExtensions: [grab, ...extra],
    _storageExtensions: LINK_STORAGE_EXTENSIONS,
  });
  return {
    tzun,
    host,
    links: tzun.links as LinksService,
    graph: tzun.decisionGraph as DecisionGraphService,
    close: () => tzun.close(),
  };
}

/** The store legs: memory, SQLite, and Postgres when its legs run (`pg` is the suite's schema). */
export function storeLegs(pg: PgTestSchema): StoreLeg[] {
  return [
    { name: 'memory', open: (o) => openLinked({}, o?.extra) },
    { name: 'sqlite', open: (o) => openLinked({ dbPath: o?.file ?? sqlitePath() }, o?.extra) },
    ...(PG_TESTS_ENABLED
      ? [
          {
            name: 'postgres' as const,
            open: async (o?: { extra?: SdkExtensionFactory[] }) => {
              await pg.reset();
              return openLinked({ dbUrl: pg.url }, o?.extra);
            },
          },
        ]
      : []),
  ];
}
