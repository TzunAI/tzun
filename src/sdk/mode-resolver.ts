import { Mode, TzunConfig, AttestationConfig, CaptureAttestation } from '@tzun/engine';
import { resolveAnchoringConfig, type ResolvedAnchoringConfig } from '../anchoring/config';
import { AnchorActivationError, AnchoringConfigError } from '../anchoring/errors';
import { assertLogNamespace } from '../storage/log-store';

/**
 * Resolve the deployment mode from config and environment.
 *
 * Priority:
 * 1. Explicit config.mode — always wins.
 * 2. TZUN_MODE environment variable.
 * 3. Inference from config.apiKey and config.apiUrl:
 *    - apiKey + apiUrl → self-hosted
 *    - apiKey only → cloud
 *    - neither → dev
 */
export function resolveMode(config: TzunConfig | undefined): Mode {
  // 1. Explicit mode in config
  if (config?.mode) {
    return config.mode;
  }

  // 2. Environment variable.
  // A set-but-unrecognised value is an operator typo, not a request for dev
  // mode. Silently downgrading `TZUN_MODE=prod` (or `Cloud`) to `dev` is how
  // a production service ends up writing evidence to RAM with no signal at
  // all, so reject it loudly. An empty string counts as unset.
  const envMode = process.env.TZUN_MODE;
  if (envMode) {
    if (!isValidMode(envMode)) {
      throw new Error(
        `[Tzun] TZUN_MODE="${envMode}" is not a recognised mode. ` +
        'Expected one of: dev, local, cloud, self-hosted.'
      );
    }
    return envMode;
  }

  // 3. Inference from credentials
  if (config?.apiKey && config?.apiUrl) {
    return 'self-hosted';
  }
  if (config?.apiKey) {
    return 'cloud';
  }

  return 'dev';
}

function isValidMode(value: string): value is Mode {
  return ['dev', 'local', 'cloud', 'self-hosted'].includes(value);
}

/** A component a capture may store without, and retry: `AttestationConfig.deferrable`. */
export type DeferrableAttestation = NonNullable<AttestationConfig['deferrable']>[number];

/** Attestation config with guaranteed require and deferrable arrays. */
export interface ValidatedAttestationConfig extends AttestationConfig {
  require: CaptureAttestation[];
  deferrable: DeferrableAttestation[];
}

const PROD_ATTESTATION_ERROR =
  'Production modes must obtain an RFC 3161 timestamp for every record, for legal defensibility. ' +
  "Name 'timestamp' in `attestation.deferrable` (a capture no timestamp authority answers is " +
  "stored 'pending' and timestamped by the retry) or in `attestation.require` (such a capture " +
  'is refused), or leave `require` unset for the deferrable default. ' +
  'Use dev mode for development without attestation.';

/**
 * Validate and normalize an attestation config for a given mode.
 *
 * Every mode refuses a contradiction: a component in both `require` and
 * `deferrable`, or `'webauthn'` in `deferrable` (a signature is a human
 * ceremony the SDK cannot obtain later).
 *
 * Every mode refuses an anchor here, each case with its own message: the `blockchain` key, and `'blockchain'` or `'anchor'` named
 * in `require` or `deferrable`. Capture never waits on a chain and the retry
 * never obtains an anchor; an anchor is published for a batch of records by
 * the anchor scheduler, which `TzunConfig.anchoring` configures (see
 * {@link anchoringConfigFor}).
 *
 * Dev mode: no minimum; defaults to require: [], deferrable: [].
 *
 * Production modes (local, cloud, self-hosted) obtain a timestamp for every
 * record, and choose only whether a capture may be stored without one:
 *   - `require` unset: the timestamp is deferrable, added to `deferrable` if
 *     it is not already there. A capture no authority answers is stored
 *     'pending' and retried.
 *   - `require: ['timestamp', ...]`: the capture is refused without one.
 *   - `require` set, and the timestamp in neither list: refused here, because
 *     no record would ever be timestamped.
 *
 * When `usesHttpTransport` is true (apiKey present), the production-mode timestamp
 * rule is bypassed for both undefined and explicitly-empty require configs.
 * Rationale: on the HTTP transport, the backend attestation worker stamps every
 * ingested envelope server-side. A default-on client-side TSA call would add
 * latency and a second TSA dependency without adding evidence value. An explicit
 * non-empty require config is still honored verbatim.
 */
export function validateAttestationConfig(
  mode: Mode,
  config: AttestationConfig | undefined,
  usesHttpTransport: boolean = false,
): ValidatedAttestationConfig {
  refuseAnchorInAttestationConfig(config);

  const base: ValidatedAttestationConfig = {
    ...config,
    require: config?.require ?? [],
    deferrable: config?.deferrable ?? [],
  };

  // Untyped callers can put anything in the list; the type already excludes it.
  if ((base.deferrable as CaptureAttestation[]).includes('webauthn')) {
    throw new Error(
      "[Tzun] `attestation.deferrable` cannot name 'webauthn'. A deferrable component is " +
        'obtained later by the retry, and a WebAuthn signature is a human ceremony over the ' +
        "record's digest that the SDK cannot obtain on its own. Put 'webauthn' in `require`, " +
        'or pass the assertion to capture() without listing it.',
    );
  }
  const both = base.require.filter((c) => (base.deferrable as CaptureAttestation[]).includes(c));
  if (both.length > 0) {
    throw new Error(
      `[Tzun] Attestation components in both \`require\` and \`deferrable\`: ${both.join(', ')}. ` +
        '`require` refuses a capture without the component; `deferrable` stores it pending ' +
        'and retries. Name each component in one list.',
    );
  }

  if (mode === 'dev') {
    return base;
  }

  // The HTTP transport bypasses the production rule for undefined or
  // explicitly-empty require configs. The backend worker provides server-side
  // attestation unconditionally, so client-side TSA I/O adds no value.
  if (usesHttpTransport && (config?.require === undefined || config.require.length === 0)) {
    return base;
  }

  // Production modes
  if (base.require.includes('timestamp') || base.deferrable.includes('timestamp')) {
    return base;
  }

  if (config?.require === undefined) {
    // No explicit require: the timestamp is deferrable.
    return { ...base, deferrable: ['timestamp', ...base.deferrable] };
  }

  throw new Error(PROD_ATTESTATION_ERROR);
}

/** The names an untyped config may use for an anchor in `require` or `deferrable`. */
const ANCHOR_COMPONENT_NAMES = ['blockchain', 'anchor'] as const;

/**
 * Refuse every way an attestation config asks for an anchor.
 * Checked before anything else in the config, so a config that asks for one
 * is refused for that, whatever else is wrong with it.
 */
function refuseAnchorInAttestationConfig(config: AttestationConfig | undefined): void {
  if (config === undefined || config === null) return;
  const untyped = config as Record<string, unknown>;

  if (untyped.blockchain !== undefined && untyped.blockchain !== null) {
    throw new Error(
      '[Tzun] `attestation.blockchain` is not supported: a capture does not anchor a ' +
        'record, and neither does the pending-attestation retry. Anchoring is the `anchoring` ' +
        'config, which publishes one transaction per batch of records rather than one per ' +
        'capture. Remove `attestation.blockchain`, and ' +
        "'blockchain' from `attestation.require` and `attestation.deferrable`.",
    );
  }

  const require = (Array.isArray(untyped.require) ? untyped.require : []) as unknown[];
  const inRequire = ANCHOR_COMPONENT_NAMES.find((name) => require.includes(name));
  if (inRequire) {
    throw new Error(
      `[Tzun] \`attestation.require\` cannot name '${inRequire}': a capture never waits on a ` +
        'chain. An anchor is published for a batch of records after they are stored, so no ' +
        `record holds one when capture() returns. Remove '${inRequire}' from ` +
        '`attestation.require`.',
    );
  }

  const deferrable = (Array.isArray(untyped.deferrable) ? untyped.deferrable : []) as unknown[];
  const inDeferrable = ANCHOR_COMPONENT_NAMES.find((name) => deferrable.includes(name));
  if (inDeferrable) {
    throw new Error(
      `[Tzun] \`attestation.deferrable\` cannot name '${inDeferrable}': the retry pass never ` +
        "obtains an anchor. It obtains a record's timestamp; an anchor is published for a " +
        'batch of records by the anchor scheduler, which the `anchoring` config runs. ' +
        `Remove '${inDeferrable}' from \`attestation.deferrable\`.`,
    );
  }
}

/** The store `Tzun.init()` resolved, as far as anchoring is concerned. */
export type AnchoringStoreKind = 'memory' | 'cloud' | 'sqlite' | 'postgres';

/**
 * `TzunConfig.anchoring`, checked for the store it was configured against, or `null` when it is absent. Called before the store is
 * opened, so a refused config creates no file and makes no connection.
 *
 * `undefined` and `null` are no anchoring. `false` is refused on every store
 * with one message: it is not a setting. Any other value is a request to
 * anchor: refused for good on the memory adapter and the cloud transport, and
 * checked on SQLite and Postgres by `resolveAnchoringConfig`
 * (`AnchoringConfigError`), including `anchoring.namespace` against
 * `logNamespace` when both are given. One of the two must be given: an
 * anchored store needs its namespace chosen, and a store opened without one
 * would be minted, for good, in the default `local.invalid`. The namespace
 * half of the activation guard therefore always runs here,
 * before the store is opened: a namespace outside `test.` without
 * `anchoring.production: true` is refused (`AnchorActivationError`). The
 * publisher half needs the publisher's address, and runs when the scheduler
 * is created, once the store is open.
 */
export function anchoringConfigFor(config: TzunConfig | undefined, store: AnchoringStoreKind): ResolvedAnchoringConfig | null {
  const anchoring = (config as Record<string, unknown> | undefined)?.anchoring;
  if (anchoring === undefined || anchoring === null) return null;

  if (anchoring === false) {
    throw new Error(
      '[Tzun] `anchoring: false` is not a setting: omit `anchoring` to not anchor. Nothing ' +
        'anchors without it, and capture() never waits on a chain.',
    );
  }

  switch (store) {
    case 'memory':
      throw new Error(
        '[Tzun] `anchoring` is refused on the memory adapter: an anchor commits to a log of ' +
          "the store's records, and this store is gone when the process exits, so nothing " +
          'anchored from it could ever be checked. Remove `anchoring`, or configure a ' +
          'persistent store (dbPath or dbUrl).',
      );
    case 'cloud':
      throw new Error(
        '[Tzun] `anchoring` is refused on the cloud transport (apiKey set): this process holds ' +
          'no log of the records it sends, so it has nothing to anchor. Anchoring cloud records ' +
          'belongs to the platform. Remove `anchoring`.',
      );
    case 'sqlite':
    case 'postgres': {
      const resolved = resolveAnchoringConfig(anchoring as TzunConfig['anchoring'] & object);
      const logNamespace = config?.logNamespace;
      if (resolved.namespace !== undefined && logNamespace !== undefined && resolved.namespace !== logNamespace) {
        throw new AnchoringConfigError(
          `anchoring.namespace (${JSON.stringify(resolved.namespace)}) and logNamespace (${JSON.stringify(logNamespace)}) ` +
            'name different namespaces; a store has one. Set logNamespace, which a new store is minted with.',
        );
      }
      const ns = logNamespace ?? resolved.namespace;
      if (ns === undefined) {
        throw new AnchoringConfigError(
          '`anchoring` needs the store\'s namespace: set logNamespace (a test. namespace such as test.<you>.dev to anchor ' +
            'on a testnet, or your own, such as demo.tzun.ai, with anchoring.production: true). A store is minted with its ' +
            'namespace and keeps it, so it is never left to the default local.invalid on a store that anchors.',
        );
      }
      if (!resolved.production && !ns.startsWith('test.')) {
        throw new AnchorActivationError(`${ns}/<store id>/anchors`, 'its namespace is not a test. namespace');
      }
      return resolved;
    }
  }
}

/**
 * `TzunConfig.logNamespace`, checked before the store is opened: refused on
 * the cloud transport, whose logs are the platform's, and held to the `ns`
 * grammar (`InvalidLogNamespaceError`). `undefined` when it is not set.
 */
export function logNamespaceFor(config: TzunConfig | undefined, store: AnchoringStoreKind): string | undefined {
  const ns = config?.logNamespace;
  if (ns === undefined) return undefined;
  if (store === 'cloud') {
    throw new Error(
      '[Tzun] `logNamespace` is refused on the cloud transport (apiKey set): the records it ' +
        'sends are logged by the platform, under the platform\'s origins. Remove `logNamespace`.',
    );
  }
  return assertLogNamespace(ns);
}
