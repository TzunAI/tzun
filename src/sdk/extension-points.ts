/**
 * The SDK's extension points: what the mandate service, the agent catalog
 * and the link service plug into, and what the `Tzun` instance gives them.
 *
 * `capture()` lives in `index.ts` and has one owner. A feature delivers an
 * {@link SdkExtensionFactory} from a module of its own (`src/sdk/mandates/`,
 * `src/sdk/agents/`, `src/sdk/links/`); `Tzun.init()` calls each factory
 * with the instance's {@link SdkHost} and installs what it returns:
 *
 *   - the feature's namespace (`tzun.mandates`, `tzun.agents`, `tzun.links`,
 *     `tzun.decisionGraph`);
 *   - its capture hook, which `capture()` calls at a fixed point:
 *       - {@link AgentCaptureHook.checkReferences}: once, before any
 *         sequence number is taken, with every agent reference the record
 *         names;
 *       - {@link LinkCaptureHook.resolveTargets}: once, before any sequence
 *         number is taken, with the caller's link inputs;
 *       - {@link MandateCaptureHook.open}: once, before any sequence number
 *         is taken, for `capture(…, { mandate })`; then the returned
 *         {@link MandateCaptureClaim}'s `plan` on every build attempt, and its
 *         `classifyStoreError` on every store refusal.
 *
 * Until a feature is installed its namespace throws
 * {@link ExtensionNotInstalledError} and its hook is the stub below, which
 * behaves as a store without the feature: agent references are accepted as
 * given, no same-store link target is held (a target without `external` is
 * refused `link_target_not_found`), and a capture under a mandate is refused
 * `mandate_not_supported_by_store`.
 *
 * `Tzun.init()` installs `DEFAULT_SDK_EXTENSIONS` (`extensions-registry.ts`),
 * or the list in the internal config member `_sdkExtensions`; the matching
 * storage extensions are `_storageExtensions` (`src/storage/extensions.ts`).
 */
import type {
  AgentDescriptor,
  AgentDescriptorRow,
  AttestationArtifacts,
  CaptureResult,
  DeciderInput,
  DeciderKind,
  EvidenceEnvelope,
  EvidenceLinkRow,
  EvidencePayload,
  HeldLinkTarget,
  Link,
  LinkInput,
  MandateBlock,
  MandateClaimStore,
  MandateDocument,
  MandateEventRow,
  MandateExpectation,
  MandateRow,
  MandateState,
  MandateStatement,
  StorageAdapter,
  StoreOptions,
  SystemRecordKind,
  WebauthnAssertion,
} from '@tzun/engine';
import type { AsyncCredentialStore } from '../attestation/credential-store';
import type { PreparedAssertionChallenge } from './index';

// ── What a hook answers when it refuses ────────────────────────────────────

/**
 * A capture an extension point refuses. `capture()` turns it into the
 * `FailureRecord` it returns (`stored: false`), with `diagnosticMetadata`
 * `{ field, reason: code, message, ...details }`, before any sequence number
 * is taken (or, from a mandate plan, before the store).
 */
export interface CaptureRefusal {
  /**
   * `validation_failure` for input the store cannot take (an unregistered
   * agent, a link target not found, a store without the feature);
   * `mandate_refused` for a mandate that cannot take this record (closed,
   * full, over a cap, outside its scope or validity).
   */
  failureType: 'validation_failure' | 'mandate_refused';
  /** The refusal's code, e.g. `agent_not_registered`, `link_target_not_found`, `mandate_full`. */
  code: string;
  /** The member it concerns: `decider.agent`, `contributions.steps[1].actor.agent`, `links[0].target`, `mandate`. */
  field: string;
  /** Names the field and the rule; never echoes a value. */
  message: string;
  /** Further facts for the failure record (a scope check's findings). Never a payload value. */
  details?: Record<string, unknown>;
}

/** Whether a hook's answer is a refusal. */
export function isCaptureRefusal(value: unknown): value is CaptureRefusal {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as CaptureRefusal).code === 'string' &&
    ((value as CaptureRefusal).failureType === 'validation_failure' ||
      (value as CaptureRefusal).failureType === 'mandate_refused')
  );
}

// ── What the Tzun instance gives an extension ──────────────────────────────

/**
 * A system record (`tzun:mandate` issuance and revocation records, `tzun:link`
 * link records), captured through the same pipeline as every record: the
 * capture mutex, the decider's resolution (freshness, `commit`), link
 * resolution, the compare-and-swap append loop, attestation, the
 * idempotency key.
 */
export interface SystemRecordCapture {
  /** `mandate` writes `aiSystemId "tzun:mandate"`; `link` writes `"tzun:link"`. */
  kind: SystemRecordKind;
  aiOutput: Record<string, unknown>;
  action: string;
  reason: string;
  /** Resolved as a capture's decider is (`id` default, `freshness: 'auto'`, `commit`). */
  decider: DeciderInput;
  /** In input form. Same-store targets are resolved through the link hook. */
  links?: LinkInput[] | null;
  /** The reserved relations this record may carry (`mandate`, `revokes`, `subject`). */
  allowReserved?: readonly ('mandate' | 'revokes' | 'subject')[];
  /** A link record: `buildLinks` adds no `root` link and applies each relation's rules with the subject in the child's place. */
  linkRecord?: boolean;
  /** Attestation the record carries beside what the SDK obtains itself. */
  attestation?: Pick<AttestationArtifacts, 'webauthnAssertion' | 'mandateIssuance'>;
  /**
   * Called on every build attempt, after the record is built and attested and
   * before it is stored: the store options the record is stored with
   * (`mandateIssue`, `mandateRevoke`), read fresh on each attempt. Return a
   * refusal to stop the capture.
   */
  storeOptions?(attempt: { envelope: EvidenceEnvelope }): Promise<Pick<StoreOptions, 'mandateIssue' | 'mandateRevoke'> | CaptureRefusal>;
  /**
   * A `store()` error: `'retry'` to rebuild at the next attempt (a
   * compare-and-swap of yours lost to another writer), a refusal to stop,
   * `null` when the error is not yours (the SDK then handles it as any
   * capture's).
   */
  classifyStoreError?(error: unknown): 'retry' | CaptureRefusal | null;
}

/** Options of {@link SdkHost.captureSystemRecord}. */
export interface SystemRecordCaptureOptions {
  /** As `CaptureOptions.idempotencyKey`. */
  idempotencyKey?: string;
  /** As `CaptureOptions.prepared`: the record a per-record signature was made over (`prepareSystemRecord`). */
  prepared?: PreparedAssertionChallenge;
}

/** What the `Tzun` instance gives an extension. */
export interface SdkHost {
  /**
   * The store capture writes to: a local adapter behind the verifying proxy,
   * or the cloud transport. A feature's optional methods (`getMandate`,
   * `putAgentDescriptor`, `listLinksTo`, …) are present exactly when the
   * store has the feature.
   */
  readonly storage: StorageAdapter;
  /** The chain `capture()` appends to. */
  activeChainId(): string;
  /** The evidence-log origin of a chain of this store, or `null` when the store has no evidence logs (the cloud transport). */
  evidenceLogOrigin(chainId: string): Promise<string | null>;
  /**
   * The finalized-block reference (Record §6.6) `capture()` would write now
   * under `freshness: 'auto'`, or `null` when there is none: a mandate
   * statement's `notBefore`.
   */
  freshnessReference(): Promise<string | null>;
  /** Whether anchoring is configured on this instance (a mandated capture then requires a freshness reference). */
  anchoringConfigured(): boolean;
  /**
   * An RFC 3161 token (base64 of the DER `TimeStampResp`) over a 64-hex
   * digest, from the instance's timestamp authorities; `null` when none is
   * configured or none answered. Never throws.
   */
  timestampDigest(digestHex: string): Promise<string | null>;
  /** The durable credential directory a WebAuthn assertion is verified against, when the store has one. */
  credentialStore(): AsyncCredentialStore | undefined;
  /** Capture a system record (see {@link SystemRecordCapture}). Never throws for a refusal: it returns `stored: false`. */
  captureSystemRecord(request: SystemRecordCapture, options?: SystemRecordCaptureOptions): Promise<CaptureResult>;
  /** The record `captureSystemRecord(request)` would build next, and the challenge a per-record signature over it signs. */
  prepareSystemRecord(request: SystemRecordCapture): Promise<PreparedAssertionChallenge>;
  /** A structured line on the instance's log sink. Never log a payload value. */
  log(event: string, fields: Record<string, unknown>): void;
}

// ── Capture hooks ──────────────────────────────────────────────────────────

/** What every capture hook is called with. */
export interface CaptureHookContext {
  readonly host: SdkHost;
  /** The capture's idempotency key, when it has one. */
  readonly idempotencyKey?: string;
}

/** An agent reference a record names. */
export interface AgentReference {
  /** Where it is: `decider.agent` or `contributions.steps[<i>].actor.agent`. */
  field: string;
  /** The decider's or actor's kind (`agent`, `agent-mandated`, `policy-engine`). */
  kind: DeciderKind;
  /** `sha256:` and 64 lowercase hex. */
  agent: string;
}

/** The agent catalog's capture hook (Record §6.9). */
export interface AgentCaptureHook {
  /**
   * Called once per capture, before any sequence number is taken, with every
   * agent reference the record names (the decider's and each step actor's,
   * in that order; empty when there is none). Answer `null` to accept, or a
   * refusal: `agent_not_registered` (a store with the catalog that does not
   * hold the digest), `agent_kind_mismatch` (a `policy-engine` reference whose
   * descriptor names a model).
   */
  checkReferences(refs: readonly AgentReference[], ctx: CaptureHookContext): Promise<CaptureRefusal | null>;
}

/** The link service's capture hook (Record §8.7). */
export interface LinkCaptureHook {
  /**
   * Called once per capture with links, before any sequence number is taken
   * and outside the chain-head transaction. For each input, in input order,
   * the same-store record its target names (by `evidenceId` when given,
   * otherwise by `digest`), as a {@link HeldLinkTarget} whose `origin` is its
   * chain's evidence-log origin; `null` when it names none in this store. A
   * target marked `external` that resolves here is returned resolved. The SDK
   * then runs the engine's `buildLinks` with these, which fills digests and
   * locators, refuses member mismatches and unresolved non-external targets,
   * adds the `root` link and applies the target rules. Answer a refusal to
   * stop the capture (a store that cannot resolve: `links_not_supported_by_store`).
   */
  resolveTargets(inputs: readonly LinkInput[], ctx: CaptureHookContext): Promise<ReadonlyArray<HeldLinkTarget | null> | CaptureRefusal>;
}

/** What a capture under a mandate writes, for one build attempt (Record §9.6). */
export interface MandateAttemptPlan {
  /** The mandate form of the expectation, hashed. */
  signoffExpectation: MandateExpectation;
  /** The payload's links with the `mandate` link added, sorted (the engine's `planMandateClaim().links`). */
  links: Link[];
  /** `nonRepudiation.mandate`. */
  block: MandateBlock;
  /**
   * The SDK-derived custody entries written after `decision_captured`, in
   * order: `captured_under_mandate`, then `confirmation_required` when a
   * confirmation is owed. The SDK stamps each with the record's `capturedAt`
   * and `aiSystemId`.
   */
  custody: Array<{ action: 'captured_under_mandate' | 'confirmation_required'; actor: string; metadata: Record<string, unknown> }>;
  /** `StoreOptions.mandateClaim`: the slot and totals compare-and-swap, in the storing transaction. */
  claim: MandateClaimStore;
  /** `CaptureResult.mandate` on success. */
  result: { mandateId: string; slot: number; totals: Record<string, number> | null };
}

/** One capture's claim on a mandate, from {@link MandateCaptureHook.open}. */
export interface MandateCaptureClaim {
  /**
   * Called on every build attempt with the payload built so far (its links
   * as `buildLinks` built them, its expectation `null`): re-read the mandate
   * row and totals, and plan the slot (the engine's `planMandateClaim`).
   * Answer a refusal to stop the capture; a mandate found past its validity
   * is moved to `expired` here, in a transaction of its own.
   */
  plan(payload: EvidencePayload): Promise<MandateAttemptPlan | CaptureRefusal>;
  /** A `store()` error: `'retry'` when the claim lost to another capture, a refusal when it is terminal, `null` when it is not the claim's. */
  classifyStoreError(error: unknown): 'retry' | CaptureRefusal | null;
}

/** The mandate service's capture hook. */
export interface MandateCaptureHook {
  /**
   * Called once for `capture(input, { mandate: { mandateId } })`, before any
   * sequence number is taken: read the mandate, refuse what does not depend
   * on the slot (`mandate_not_found`, `mandate_not_open`,
   * `mandate_not_supported_by_store`), and return the claim the attempts use.
   */
  open(request: { mandateId: string }, ctx: CaptureHookContext): Promise<MandateCaptureClaim | CaptureRefusal>;
}

// ── Namespaces ─────────────────────────────────────────────────────────────

/** `tzun.mandates` (Record §9.6). */
export interface MandatesApi {
  /** Check a document and return the statement and the challenge the principal signs. Persists nothing. */
  prepare(document: MandateDocument): Promise<{ statement: MandateStatement; statementDigest: string; challenge: string }>;
  /** Verify the principal's assertion and issue: the mandate row, its `issued` event and the issuance record, in one transaction. */
  issue(request: { document: MandateDocument; statement: MandateStatement; assertion: WebauthnAssertion }): Promise<MandateIssueResult>;
  /** Capture a revocation record and close the mandate. */
  revoke(
    request: { mandateId: string; effectiveAt?: string; reason: string },
    signature: { prepared: PreparedAssertionChallenge; assertion: WebauthnAssertion },
  ): Promise<CaptureResult>;
  /** The record `revoke()` would capture next, and the challenge its author signs. */
  prepareRevocation(request: { mandateId: string; effectiveAt?: string; reason: string; revoker: string }): Promise<PreparedAssertionChallenge>;
  /** Attach a human confirmation to a record whose expectation owes one. */
  confirm(evidenceId: string, assertion: WebauthnAssertion): Promise<void>;
  get(mandateId: string): Promise<MandateRow | null>;
  /** The mandate's events, oldest first. */
  events(mandateId: string): Promise<MandateEventRow[]>;
  /** A page of the store's mandates, in mandate id order, by state and by the end of their window (`StorageAdapter.listMandates`). */
  list(filter?: {
    state?: MandateState;
    notAfterBefore?: string;
    limit?: number;
    cursor?: string | null;
  }): Promise<{ rows: MandateRow[]; cursor: string | null }>;
}

/** What {@link MandatesApi.issue} returns. */
export interface MandateIssueResult {
  mandateId: string;
  /** 64 lowercase hex. */
  mandateDigest: string;
  /** The issuance record's capture. */
  issuance: CaptureResult;
}

/** `tzun.agents` (Record §6.9). */
export interface AgentsApi {
  /** Register a descriptor; idempotent on identical canonical bytes. */
  register(descriptor: AgentDescriptor): Promise<{ digest: string; alreadyExisted: boolean }>;
  get(digest: string): Promise<AgentDescriptorRow | null>;
  list(filter?: { name?: string; organization?: string; limit?: number; cursor?: string }): Promise<{ rows: AgentDescriptorRow[]; cursor: string | null }>;
}

/** `tzun.links`: link records (Record §8.6) and a record's links in this store. */
export interface LinksApi {
  /** Capture a link record (`aiSystemId "tzun:link"`) stating relations of `subject`. */
  relate(request: {
    subject: LinkInput['target'];
    relations: Array<{ rel: string; target: LinkInput['target']; attrs?: Link['attrs'] }>;
    reason: string;
    decider: DeciderInput;
  }): Promise<CaptureResult>;
  /** A record's links, each with its resolution in this store. */
  of(evidenceId: string): Promise<Array<{ index: number; link: Link; held: boolean }> | null>;
  /** The same-store records that link to `digest`, a page at a time (`limit` at most 200, default 100). */
  to(digest: string, options?: { rels?: string[]; limit?: number; cursor?: string }): Promise<{ rows: EvidenceLinkRow[]; cursor: string | null }>;
}

/** `tzun.decisionGraph`: a bounded walk over the links of this store's records. */
export interface DecisionGraphApi {
  walk(
    evidenceId: string,
    options?: { rels?: string[]; depth?: number; maxNodes?: number },
  ): Promise<DecisionGraphWalk>;
}

/** One edge of a decision-graph walk: who asserts it (the child itself, or a link record and its decider). */
export interface DecisionGraphEdge {
  from: string;
  to: string;
  rel: string;
  /** The record that carries the link. */
  assertedBy: string;
}

/** What {@link DecisionGraphApi.walk} returns. */
export interface DecisionGraphWalk {
  root: string;
  nodes: string[];
  edges: DecisionGraphEdge[];
  truncated: boolean;
}

/** `tzun.deciders`: the openings of `cmt:` deciders (Record §6.3). */
export interface DecidersApi {
  /** The opening of a record's `cmt:` decider, from the store's `decider_openings`, or `null`. */
  opening(evidenceId: string): Promise<{ salt: string; id: string } | null>;
}

// ── Modules ────────────────────────────────────────────────────────────────

/** What a feature's factory returns: its namespace and its capture hook. */
export interface SdkExtension {
  /** `'mandates'`, `'agents'` or `'links'`; one of each per instance. */
  readonly name: 'mandates' | 'agents' | 'links';
  readonly mandates?: { api: MandatesApi; captureHook: MandateCaptureHook };
  readonly agents?: { api: AgentsApi; captureHook: AgentCaptureHook };
  readonly links?: { api: LinksApi; captureHook: LinkCaptureHook; decisionGraph: DecisionGraphApi };
}

/** A feature's entry point: called once by `Tzun.init()`. */
export type SdkExtensionFactory = (host: SdkHost) => SdkExtension;

/** A namespace whose feature is not installed on this instance. */
export class ExtensionNotInstalledError extends Error {
  readonly code = 'extension_not_installed' as const;
  constructor(public readonly extension: string) {
    super(`tzun.${extension} is not available: the ${extension} extension is not installed on this instance.`);
    this.name = 'ExtensionNotInstalledError';
    Object.setPrototypeOf(this, ExtensionNotInstalledError.prototype);
  }
}

/** A namespace object whose every method (named in `methods`) rejects with {@link ExtensionNotInstalledError}. */
export function notInstalledApi<T extends object>(extension: string, methods: readonly (keyof T & string)[]): T {
  const api: Record<string, () => Promise<never>> = {};
  for (const name of methods) api[name] = () => Promise.reject(new ExtensionNotInstalledError(extension));
  return api as unknown as T;
}

/** The agent hook of a store without the catalog: every reference accepted as given. */
export const STUB_AGENT_CAPTURE_HOOK: AgentCaptureHook = {
  async checkReferences() {
    return null;
  },
};

/** The link hook of a store that resolves nothing: no target is held here. */
export const STUB_LINK_CAPTURE_HOOK: LinkCaptureHook = {
  async resolveTargets(inputs) {
    return inputs.map(() => null);
  },
};

/** The mandate hook of a store without mandates. */
export const STUB_MANDATE_CAPTURE_HOOK: MandateCaptureHook = {
  async open() {
    return {
      failureType: 'validation_failure',
      code: 'mandate_not_supported_by_store',
      field: 'mandate',
      message: 'this store does not hold mandates',
    };
  },
};

/** What `Tzun` holds once its extensions are installed: every namespace and hook, stubs where none is installed. */
export interface InstalledSdkExtensions {
  mandates: { api: MandatesApi; captureHook: MandateCaptureHook };
  agents: { api: AgentsApi; captureHook: AgentCaptureHook };
  links: { api: LinksApi; captureHook: LinkCaptureHook; decisionGraph: DecisionGraphApi };
}

/**
 * Call each factory with the host and collect what it returns over the
 * stubs. A name installed twice is refused.
 */
export function installSdkExtensions(host: SdkHost, factories: readonly SdkExtensionFactory[]): InstalledSdkExtensions {
  const installed: InstalledSdkExtensions = {
    mandates: {
      api: notInstalledApi<MandatesApi>('mandates', ['prepare', 'issue', 'revoke', 'prepareRevocation', 'confirm', 'get', 'events']),
      captureHook: STUB_MANDATE_CAPTURE_HOOK,
    },
    agents: { api: notInstalledApi<AgentsApi>('agents', ['register', 'get', 'list']), captureHook: STUB_AGENT_CAPTURE_HOOK },
    links: {
      api: notInstalledApi<LinksApi>('links', ['relate', 'of', 'to']),
      captureHook: STUB_LINK_CAPTURE_HOOK,
      decisionGraph: notInstalledApi<DecisionGraphApi>('decisionGraph', ['walk']),
    },
  };
  const seen = new Set<string>();
  for (const factory of factories) {
    const ext = factory(host);
    if (seen.has(ext.name)) throw new Error(`SDK extension "${ext.name}" is installed twice.`);
    seen.add(ext.name);
    if (ext.mandates) installed.mandates = ext.mandates;
    if (ext.agents) installed.agents = ext.agents;
    if (ext.links) installed.links = ext.links;
  }
  return installed;
}
