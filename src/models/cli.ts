/**
 * `tzun models` CLI surface.
 *
 * Thin shell around `registerModel`, `computeModelDigest`, and the
 * annotation/alias runtime. Exposed as a programmatic `runCli(argv, deps)`
 * so tests can drive it without spawning a subprocess; a separate bin
 * entry would call `runCli(process.argv.slice(2), { storage, prompt: stdinPrompt })`.
 *
 * Subcommands:
 *   - register [--quick] [--from-file <path>] [--weights <path>]
 *              [--vendor <v>] [--model <m>] [--version <v>]
 *   - list [--vendor <v>] [--limit N] [--offset N]
 *   - show <digest>
 *   - compute-digest <weights-path>
 *   - annotate <digest> --type <t> --value <json> [--note <text>]
 *              [--reviewer <name>] [--signature <hex>] [--admin]
 *   - alias set <slug> <digest> [--set-by <name>]
 *   - alias resolve <slug>
 *
 * Admin gating (v1):
 *   The CLI accepts `--admin` as a stand-in for "this caller has admin
 *   privileges". This is the lowest-friction marker for CLI use; the REST
 *   surface tightens this by requiring a real admin token via the existing
 *   API-key + admin-token middleware. Library callers that skip the CLI
 *   pass `options.isAdmin: true` to `tzun.models.annotate()` directly.
 *
 * Exit codes:
 *   0 = success
 *   1 = usage error (bad flags, missing required fields)
 *   2 = runtime error (file not found, storage failure, auth refused, etc.)
 */
import { readFileSync } from 'fs';
import * as path from 'path';

import { StorageAdapter } from '@tzun/engine';
import { ModelDescriptor } from '@tzun/engine';
import { registerModel, RegisterOptions } from './register';
import { computeModelDigest } from './compute-model-digest';
import { annotateModelDescriptor, TYPED_ANNOTATION_TYPES } from './annotations';
import { loadKnownModels, type KnownModelsReference } from './known-models';
import { enrichPartialFromKnownModels } from './import-vendor';

export interface CliDependencies {
  storage: StorageAdapter;
  /** Asks the user a question and returns their answer. Injected for testability. */
  prompt: (question: string) => Promise<string>;
  /** Defaults to `console.log`. Lines are emitted without trailing newlines. */
  stdout?: (msg: string) => void;
  /**
   * Injectable fetcher for `--enable-known-models-fetch`.
   * When provided, this is forwarded to `loadKnownModels` as its `fetcher`
   * option; production code leaves this undefined and the default global
   * `fetch` is used when the flag is supplied. The reference it returns is
   * what `register` enriches the descriptor from.
   */
  knownModelsFetchFn?: (url: string) => Promise<KnownModelsReference>;
}

// ── argv parsing ────────────────────────────────────────────────────

interface ParsedArgs {
  /** Positional args (non-flag tokens, in order). */
  positional: string[];
  /** Boolean flags (presence-only, no value). */
  flags: Set<string>;
  /** Flags with string values (`--vendor x`). */
  values: Map<string, string>;
}

class UsageError extends Error {}

/**
 * Tiny single-purpose argv parser. Supports:
 *   - --flag             (boolean)
 *   - --flag value       (value flag)
 *   - --flag=value       (value flag, inline)
 *   - positional args
 *
 * Caller declares which flags expect a value via `valueFlags`. Anything
 * else is treated as a boolean. Unknown flags raise `UsageError`.
 */
function parseArgs(
  argv: string[],
  knownBooleanFlags: ReadonlySet<string>,
  knownValueFlags: ReadonlySet<string>,
): ParsedArgs {
  const positional: string[] = [];
  const flags = new Set<string>();
  const values = new Map<string, string>();

  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (!tok.startsWith('--')) {
      positional.push(tok);
      continue;
    }
    const eq = tok.indexOf('=');
    const name = eq >= 0 ? tok.slice(2, eq) : tok.slice(2);

    if (knownValueFlags.has(name)) {
      const v = eq >= 0 ? tok.slice(eq + 1) : argv[++i];
      if (v === undefined) {
        throw new UsageError(`flag --${name} requires a value`);
      }
      values.set(name, v);
    } else if (knownBooleanFlags.has(name)) {
      if (eq >= 0) {
        throw new UsageError(`flag --${name} does not take a value`);
      }
      flags.add(name);
    } else {
      throw new UsageError(`unknown flag --${name}`);
    }
  }

  return { positional, flags, values };
}

// ── runCli entry point ─────────────────────────────────────────────

export async function runCli(argv: string[], deps: CliDependencies): Promise<number> {
  const out = deps.stdout ?? ((m: string) => console.log(m));

  // Strip the two global known-models fetch flags BEFORE the subcommand's
  // own parseArgs() runs, so per-command parsers never see them as unknown
  // flags. Default = bundled-only, zero network. A fetch reads only the
  // HTTPS URL `--known-models-url` names (the threat model); there is no
  // default URL.
  let rest = [...argv];

  const fetchIdx = rest.indexOf('--enable-known-models-fetch');
  const enableFetch = fetchIdx >= 0;
  if (enableFetch) rest = [...rest.slice(0, fetchIdx), ...rest.slice(fetchIdx + 1)];

  let runtimeFetchUrl: string | undefined;
  const urlIdx = rest.indexOf('--known-models-url');
  if (urlIdx >= 0) {
    runtimeFetchUrl = rest[urlIdx + 1];
    rest = [...rest.slice(0, urlIdx), ...rest.slice(urlIdx + 2)];
    if (!runtimeFetchUrl || !runtimeFetchUrl.startsWith('https://')) {
      out('usage error: --known-models-url must be an https:// URL');
      return 1;
    }
  }

  /**
   * Load the known-models reference with the CLI-configured fetch options, and
   * TELL THE OPERATOR WHAT HAPPENED.
   *
   * `loadKnownModels` is best-effort: it swallows every fetch error and returns
   * the bundled copy. Someone who passed `--enable-known-models-fetch
   * --known-models-url https://…` therefore got byte-identical output whether
   * the fetch succeeded, timed out, 404'd or was never attempted. The outcome
   * line is the only way to tell those apart.
   */
  const loadReference = () => loadKnownModels({
    enableRuntimeFetch: enableFetch,
    ...(runtimeFetchUrl ? { runtimeFetchUrl } : {}),
    ...(deps.knownModelsFetchFn ? { fetcher: deps.knownModelsFetchFn } : {}),
    onOutcome: (o) => {
      if (o.source === 'fetched') {
        out(`known-models: fetched version ${o.version} from ${o.url}`);
      } else if (o.reason === 'fetch-failed') {
        out(
          `known-models: fetch failed (${o.error}); using bundled version ${o.version}`,
        );
      } else if (o.reason === 'url-not-https') {
        out(`known-models: refusing non-HTTPS URL; using bundled version ${o.version}`);
      } else if (o.reason === 'no-url') {
        out(`known-models: no --known-models-url given; using bundled version ${o.version}`);
      }
      // 'fetch-not-enabled' is the default and silent — the operator did not
      // ask for anything, so there is nothing to report.
    },
  });

  const [sub, ...subRest] = rest;

  try {
    switch (sub) {
      case 'register':
        return await registerCmd(subRest, deps, out, loadReference, enableFetch);
      case 'list':
        return await listCmd(subRest, deps, out);
      case 'show':
        return await showCmd(subRest, deps, out);
      case 'compute-digest':
        return await computeDigestCmd(subRest, deps, out);
      case 'annotate':
        return await annotateCmd(subRest, deps, out);
      case 'alias':
        return await aliasCmd(subRest, deps, out);
      case undefined:
      case '--help':
      case '-h':
      case 'help':
        printUsage(out);
        return sub === undefined ? 1 : 0;
      default:
        out(`unknown subcommand: ${sub}`);
        printUsage(out);
        return 1;
    }
  } catch (err) {
    if (err instanceof UsageError) {
      out(`usage error: ${err.message}`);
      return 1;
    }
    out(`error: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }
}

function printUsage(out: (m: string) => void): void {
  out('tzun models <subcommand> [global-options] [options]');
  out('');
  out('Global options (apply to all subcommands):');
  out('  --enable-known-models-fetch          Opt in to a runtime fetch of the known-models');
  out('                                       reference, and to enrichment from it. With the');
  out('                                       flag, `register` fills the descriptive');
  out('                                       fields it was not given (modelType, trainedBy,');
  out('                                       license, modelCardUrl, training, markings,');
  out('                                       external ids) from the fetched reference (the');
  out('                                       bundled copy if the fetch fails);');
  out('                                       supplied values always win, and the');
  out('                                       integrity fields are never taken from it.');
  out('                                       Without the flag (the default: no network),');
  out('                                       `register` writes exactly the descriptor it was');
  out('                                       given — the same row and digest that');
  out('                                       tzun.models.register() writes for that triple.');
  out('  --known-models-url <https://…>       The URL to fetch the reference from (must be');
  out('                                       HTTPS). There is no default: without it the');
  out('                                       bundled reference is used.');
  out('');
  out('Subcommands:');
  out('  register [--quick] [--from-file <path>] [--weights <path>]');
  out('           [--vendor <v>] [--model <m>] [--version <v>]');
  out('  list     [--vendor <v>] [--limit N] [--offset N]');
  out('  show     <digest>');
  out('  compute-digest <weights-path>');
  out('  annotate <digest> --type <t> --value <json> [--note <text>]');
  out('           [--reviewer <name>] [--signature <hex>] [--admin]');
  out('  alias set <slug> <digest> [--set-by <name>]');
  out('  alias resolve <slug>');
}

// ── register ───────────────────────────────────────────────────────

const REGISTER_BOOLEAN_FLAGS = new Set(['quick']);
const REGISTER_VALUE_FLAGS = new Set([
  'from-file',
  'weights',
  'vendor',
  'model',
  'version',
]);

async function registerCmd(
  argv: string[],
  deps: CliDependencies,
  out: (m: string) => void,
  loadReference?: () => Promise<KnownModelsReference>,
  fetchRequested = false,
): Promise<number> {
  const args = parseArgs(argv, REGISTER_BOOLEAN_FLAGS, REGISTER_VALUE_FLAGS);

  const weightsPath = args.values.get('weights');
  const fromFile = args.values.get('from-file');
  const quick = args.flags.has('quick');

  let descriptor: Partial<ModelDescriptor> = {};

  if (fromFile) {
    descriptor = await loadDescriptorFromFile(fromFile);
  } else if (quick) {
    descriptor = quickFromFlags(args.values);
  } else {
    // Full interactive: prompt for every field the MVD covers + the common
    // human-supplied ones. Weight-only registration without --quick is
    // treated as interactive too (the user can answer all questions).
    descriptor = await fullInteractive(deps.prompt);
  }

  // CLI flags always override file/interactive values when supplied. This
  // lets `--from-file foo.json --version 2026-02-rc1` patch the file's
  // version field, mirroring the HF importer's overlay rule.
  applyFlagOverrides(descriptor, args.values);

  const options: RegisterOptions = {};
  if (weightsPath) options.weightsPath = weightsPath;

  // Enrich from the known-models reference — ONLY when the operator passed
  // --enable-known-models-fetch. The reference fills the descriptive fields
  // the operator did not supply. Supplied values win, and the integrity
  // fields are never taken from a reference (`enrichPartialFromKnownModels`
  // applies the rule for which fields enrichment may touch).
  //
  // Why the gate. The descriptor is content-addressed, so enrichment moves
  // `modelDescriptorDigest`. Enriching on the default path too (bundled
  // reference, no flag) would move the digest of every flag-less
  // `tzun models register` that hit the reference and make the CLI diverge
  // from `tzun.models.register()` — the API it fronts, which registers what
  // it is given: three entry points, two digests for one triple. So without
  // the flag the CLI writes exactly the descriptor it was given — the same
  // row and digest the programmatic API writes. With it the CLI enriches and
  // lands on the row the connector path (`tzun.attach()`, `importFromVendor`)
  // writes for the same model, instead of a second, bare duplicate. The
  // programmatic path has no opt-in enrichment.
  if (loadReference && fetchRequested) {
    const reference = await loadReference();
    const identityComplete =
      [descriptor.vendor, descriptor.modelName, descriptor.modelVersion].every(
        (v) => typeof v === 'string' && v.length > 0,
      );
    if (identityComplete) {
      const { descriptor: enriched, entry, filled } = enrichPartialFromKnownModels(
        descriptor,
        reference,
      );
      descriptor = enriched;
      const id = `${descriptor.vendor}/${descriptor.modelName}@${descriptor.modelVersion}`;
      if (entry && filled.length > 0) {
        out(
          `known-models: enriched ${id} from reference ${reference.version} (${filled.join(', ')})`,
        );
      } else if (entry) {
        out(
          `known-models: entry for ${id} in reference ${reference.version} adds nothing (no absent field the entry could fill)`,
        );
      } else {
        // The operator asked for a fetch expecting enrichment; a miss must
        // not be silent.
        out(
          `known-models: no entry for ${id} in reference ${reference.version}; registering as supplied`,
        );
      }
    }
  }

  let result;
  try {
    result = await registerModel(deps.storage, descriptor, options);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('Minimum Viable Descriptor requires')) {
      out(`usage error: ${msg}`);
      return 1;
    }
    throw err;
  }

  printRegisterResult(result, out);
  return 0;
}

function quickFromFlags(values: Map<string, string>): Partial<ModelDescriptor> {
  return {
    vendor: values.get('vendor'),
    modelName: values.get('model'),
    modelVersion: values.get('version'),
  };
}

function applyFlagOverrides(d: Partial<ModelDescriptor>, values: Map<string, string>): void {
  if (values.has('vendor'))  d.vendor       = values.get('vendor');
  if (values.has('model'))   d.modelName    = values.get('model');
  if (values.has('version')) d.modelVersion = values.get('version');
}

async function fullInteractive(
  prompt: (q: string) => Promise<string>,
): Promise<Partial<ModelDescriptor>> {
  const ask = async (label: string): Promise<string | null> => {
    const v = (await prompt(label)).trim();
    return v.length === 0 ? null : v;
  };

  return {
    vendor:       (await ask('vendor: ')) ?? undefined,
    modelName:    (await ask('modelName: ')) ?? undefined,
    modelVersion: (await ask('modelVersion: ')) ?? undefined,
    modelType:    await ask('modelType (or blank): '),
    trainedBy:    await ask('trainedBy (or blank): '),
    license:      await ask('license (or blank): '),
    modelCardUrl: await ask('modelCardUrl (or blank): '),
  };
}

async function loadDescriptorFromFile(filePath: string): Promise<Partial<ModelDescriptor>> {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.yaml' || ext === '.yml') {
    // YAML descriptor files require a `yaml` dep we don't currently pull in.
    // Until then, JSON-only.
    throw new Error(
      'YAML descriptor files are not yet supported (no yaml dep). Convert to JSON.',
    );
  }
  // JSON path (also covers .json and bare paths).
  const raw = readFileSync(filePath, 'utf-8');
  const parsed = JSON.parse(raw) as Partial<ModelDescriptor>;
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`descriptor file must contain a JSON object, got: ${typeof parsed}`);
  }
  return parsed;
}

function printRegisterResult(
  result: { digest: string; descriptor: ModelDescriptor; alreadyExisted: boolean },
  out: (m: string) => void,
): void {
  out('Registered model descriptor:');
  out(`  digest:          ${result.digest}`);
  out(`  integrityTier:   ${result.descriptor.integrityTier}`);
  out(`  alreadyExisted:  ${result.alreadyExisted}`);
  out(`  vendor:          ${result.descriptor.vendor}`);
  out(`  modelName:       ${result.descriptor.modelName}`);
  out(`  modelVersion:    ${result.descriptor.modelVersion}`);
  if (result.descriptor.modelDigest) {
    out(`  modelDigest:     ${result.descriptor.modelDigest}`);
  }
  if (result.descriptor.modelType) {
    out(`  modelType:       ${result.descriptor.modelType}`);
  }
  if (result.descriptor.license) {
    out(`  license:         ${result.descriptor.license}`);
  }
}

// ── list ───────────────────────────────────────────────────────────

const LIST_BOOLEAN_FLAGS = new Set<string>();
const LIST_VALUE_FLAGS = new Set(['vendor', 'limit', 'offset']);

async function listCmd(
  argv: string[],
  deps: CliDependencies,
  out: (m: string) => void,
): Promise<number> {
  const args = parseArgs(argv, LIST_BOOLEAN_FLAGS, LIST_VALUE_FLAGS);

  if (!deps.storage.listModelDescriptors) {
    out('error: storage adapter does not support catalog listing');
    return 2;
  }

  const filter: Parameters<NonNullable<StorageAdapter['listModelDescriptors']>>[0] = {};
  if (args.values.has('vendor')) filter!.vendor = args.values.get('vendor');
  if (args.values.has('limit'))  filter!.limit  = parseIntStrict(args.values.get('limit')!, 'limit');
  if (args.values.has('offset')) filter!.offset = parseIntStrict(args.values.get('offset')!, 'offset');

  const rows = await deps.storage.listModelDescriptors(filter);
  if (rows.length === 0) {
    out('(no descriptors registered)');
    return 0;
  }
  for (const r of rows) {
    out(`${r.modelDescriptorDigest}  ${r.vendor}/${r.modelName}@${r.modelVersion}  (${r.descriptor.integrityTier})`);
  }
  return 0;
}

function parseIntStrict(s: string, name: string): number {
  const n = Number(s);
  if (!Number.isInteger(n) || n < 0) {
    throw new UsageError(`--${name} must be a non-negative integer, got: ${s}`);
  }
  return n;
}

// ── show ───────────────────────────────────────────────────────────

async function showCmd(
  argv: string[],
  deps: CliDependencies,
  out: (m: string) => void,
): Promise<number> {
  const args = parseArgs(argv, new Set(), new Set());
  if (args.positional.length !== 1) {
    throw new UsageError('show requires exactly one positional argument: <digest>');
  }
  const digest = args.positional[0];

  if (!deps.storage.getModelDescriptor) {
    out('error: storage adapter does not support catalog lookup');
    return 2;
  }

  const row = await deps.storage.getModelDescriptor(digest);
  if (!row) {
    out(`(no descriptor found for ${digest})`);
    return 0;
  }
  out(`digest:        ${row.modelDescriptorDigest}`);
  out(`vendor:        ${row.vendor}`);
  out(`modelName:     ${row.modelName}`);
  out(`modelVersion:  ${row.modelVersion}`);
  out(`integrityTier: ${row.descriptor.integrityTier}`);
  out(`modelDigest:   ${row.descriptor.modelDigest ?? '(null)'}`);
  out(`source:        ${row.source}`);
  out(`firstRegisteredAt: ${row.firstRegisteredAt}`);
  out(`firstRegisteredBy: ${row.firstRegisteredBy}`);
  out('descriptor:');
  out(JSON.stringify(row.descriptor, null, 2));
  return 0;
}

// ── compute-digest ─────────────────────────────────────────────────

async function computeDigestCmd(
  argv: string[],
  _deps: CliDependencies,
  out: (m: string) => void,
): Promise<number> {
  const args = parseArgs(argv, new Set(), new Set());
  if (args.positional.length !== 1) {
    throw new UsageError('compute-digest requires exactly one positional argument: <weights-path>');
  }
  const weightsPath = args.positional[0];
  const result = await computeModelDigest(weightsPath);
  out(`modelDigest: ${result.modelDigest}`);
  out(`files:       ${result.manifest.files.length}`);
  out(`durationMs:  ${result.durationMs}`);
  return 0;
}

// ── annotate ───────────────────────────────────────────────────────

const ANNOTATE_BOOLEAN_FLAGS = new Set(['admin', 'freeform']);
const ANNOTATE_VALUE_FLAGS = new Set([
  'type',
  'value',
  'note',
  'reviewer',
  'signature',
]);

async function annotateCmd(
  argv: string[],
  deps: CliDependencies,
  out: (m: string) => void,
): Promise<number> {
  const args = parseArgs(argv, ANNOTATE_BOOLEAN_FLAGS, ANNOTATE_VALUE_FLAGS);
  if (args.positional.length !== 1) {
    throw new UsageError('annotate requires exactly one positional argument: <digest>');
  }
  const digest = args.positional[0];

  // --freeform is shorthand for --type freeform-note.
  let annotationType = args.values.get('type');
  if (args.flags.has('freeform') && !annotationType) {
    annotationType = 'freeform-note';
  }
  if (!annotationType) {
    throw new UsageError('annotate requires --type <annotation-type> (or --freeform)');
  }

  // --value is required for typed annotations; freeform-note also takes a
  // value (its body) but accepts an empty object via --value '{}'.
  const rawValue = args.values.get('value');
  if (rawValue === undefined) {
    throw new UsageError("annotate requires --value '<json>'");
  }
  let value: Record<string, unknown>;
  try {
    value = JSON.parse(rawValue) as Record<string, unknown>;
  } catch (e) {
    throw new UsageError(`--value is not valid JSON: ${(e as Error).message}`);
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new UsageError('--value must parse to a JSON object');
  }

  const isAdmin = args.flags.has('admin');
  const annotatedBy = args.values.get('reviewer') ?? 'cli';
  const signature = args.values.get('signature');
  const note = args.values.get('note');

  // For visibility: surface the typed-vs-custom-vs-freeform classification.
  const isTyped = TYPED_ANNOTATION_TYPES.has(annotationType);
  const isFreeform = annotationType === 'freeform-note';
  const isCustom = !isTyped && !isFreeform;

  const row = await annotateModelDescriptor(
    deps.storage,
    digest,
    { annotationType, value },
    {
      isAdmin,
      annotatedBy,
      signature,
      note,
    },
  );

  out('Annotation appended:');
  out(`  annotationId:          ${row.annotationId}`);
  out(`  modelDescriptorDigest: ${row.modelDescriptorDigest}`);
  out(`  annotationType:        ${row.annotationType}${isTyped ? ' (typed)' : isCustom ? ' (custom)' : ' (freeform)'}`);
  out(`  annotatedAt:           ${row.annotatedAt}`);
  out(`  annotatedBy:           ${row.annotatedBy}`);
  if (row.retractsAnnotationId) {
    out(`  retractsAnnotationId:  ${row.retractsAnnotationId}`);
  }
  if (row.signature) {
    out(`  signature:             ${row.signature}`);
  }
  if (row.note) {
    out(`  note:                  ${row.note}`);
  }
  out(`  valueJson:             ${row.valueJson}`);
  return 0;
}

// ── alias ──────────────────────────────────────────────────────────

const ALIAS_BOOLEAN_FLAGS = new Set<string>();
const ALIAS_VALUE_FLAGS = new Set(['set-by']);

async function aliasCmd(
  argv: string[],
  deps: CliDependencies,
  out: (m: string) => void,
): Promise<number> {
  const [action, ...rest] = argv;
  switch (action) {
    case 'set':
      return await aliasSetCmd(rest, deps, out);
    case 'resolve':
      return await aliasResolveCmd(rest, deps, out);
    case undefined:
      throw new UsageError('alias requires an action: set | resolve');
    default:
      throw new UsageError(`unknown alias action: ${action} (expected: set | resolve)`);
  }
}

async function aliasSetCmd(
  argv: string[],
  deps: CliDependencies,
  out: (m: string) => void,
): Promise<number> {
  const args = parseArgs(argv, ALIAS_BOOLEAN_FLAGS, ALIAS_VALUE_FLAGS);
  if (args.positional.length !== 2) {
    throw new UsageError('alias set requires two positional arguments: <slug> <digest>');
  }
  const [slug, digest] = args.positional;
  const setBy = args.values.get('set-by') ?? 'cli';

  if (!deps.storage.setModelDescriptorAlias) {
    out('error: storage adapter does not support aliases');
    return 2;
  }

  await deps.storage.setModelDescriptorAlias(slug, digest, setBy);
  out(`Alias set: ${slug} -> ${digest} (by ${setBy})`);
  return 0;
}

async function aliasResolveCmd(
  argv: string[],
  deps: CliDependencies,
  out: (m: string) => void,
): Promise<number> {
  const args = parseArgs(argv, new Set(), new Set());
  if (args.positional.length !== 1) {
    throw new UsageError('alias resolve requires exactly one positional argument: <slug>');
  }
  const slug = args.positional[0];

  if (!deps.storage.resolveModelDescriptorAlias) {
    out('error: storage adapter does not support aliases');
    return 2;
  }

  const digest = await deps.storage.resolveModelDescriptorAlias(slug);
  if (digest === null) {
    out(`(unbound: no alias for ${slug})`);
    return 0;
  }
  out(digest);
  return 0;
}
