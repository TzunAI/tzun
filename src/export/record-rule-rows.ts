/**
 * The record-rule rows of a `b1` bundle report (Verification §4.1 items 6 to 9,
 * §4.9 to §4.12): what `verifyBundle()` reports between `signoff.key` and the
 * anchor, read from the record alone, plus the `payload.<name>` rows of the
 * material it does not read.
 *
 * In report order: `decider`, `decider.freshness`, `contributions`,
 * `contributions.binding`, `contributions.pipeline` (when the member names a
 * pipeline), `links`, then for each link `links[<i>]` and `links[<i>].edge`,
 * then `mandate.issuance`, `mandate.scope`, `mandate.limits`, `mandate.key`
 * and `mandate.assertionTimestamp` where Verification §4.12 reports them.
 *
 * The decider, contributions, links and mandate rows are the engine's
 * (`verifyEnvelope`), so a bundle verifier and `Tzun.verify()` cannot answer
 * differently. A bundle holds no link target, so each `links[<i>]` row is
 * the bundle verifier's: `targetHeld: false`, and every edge abstains,
 * `unsupported_link_edge`. When the record's digest does not hold, every row
 * that reads the payload is `blocked_by:record.digest`.
 */
import {
  parseFreshnessReference,
  signoffExpectationForm,
  unhashedPayloadMembers,
  verifyEnvelope,
  type EvidenceEnvelope,
  type SchemaRegistry,
  type VerificationResult,
} from '@tzun/engine';
import type { EvmHeaderSource } from '../attestation/blockchain';
import type { BundleCheck, BundleCheckOutcome } from './verify-bundle';

type Json = Record<string, unknown>;

const isRecord = (value: unknown): value is Json => value !== null && typeof value === 'object' && !Array.isArray(value);

function row(id: string, outcome: BundleCheckOutcome, reason?: string, facts?: Json): BundleCheck {
  return { id, outcome, ...(reason !== undefined && { reason }), ...(facts !== undefined && Object.keys(facts).length > 0 && { facts }) };
}

/** The members of `source` named in `keys` that are not `undefined`, in `keys` order. */
function pick(source: object, keys: readonly string[]): Json {
  const out: Json = {};
  for (const key of keys) {
    const value = (source as Json)[key];
    if (value !== undefined) out[key] = value;
  }
  return out;
}

const DECIDER_FACTS = ['kind', 'scheme', 'level', 'levelUndetermined', 'committed', 'kindContradiction'] as const;
const CONTRIBUTIONS_FACTS = ['steps', 'models', 'decidingStep', 'failedStep'] as const;
const BINDING_FACTS = ['approvals', 'staleApprovals', 'uncoveredReviews', 'proposals', 'decisionBinding', 'failedStep', 'failedDigest'] as const;
const LINK_FACTS = ['rule', 'member', 'targetHeld', 'missing', 'rootInconsistent'] as const;

/** The rows that read the payload, in report order, when its digest does not hold. */
const PAYLOAD_ROWS = ['decider', 'decider.freshness', 'contributions', 'contributions.binding', 'links'] as const;

/** A wait for a header source, as the anchor checks bound theirs. */
const DEFAULT_TIMEOUT_MS = 10_000;

export interface RecordRuleRowsInput {
  envelope: EvidenceEnvelope;
  /** The `record.digest` row. */
  digest: BundleCheck;
  registry: SchemaRegistry;
  /** Whether the bundle's `credentials` slot is filled (`mandate.key` abstains, as `signoff.key` does). */
  credentialsFilled: boolean;
  /** The auditor's header sources, by CAIP-2 chain: what `decider.freshness` reads. */
  evmHeaderSources?: Record<string, EvmHeaderSource>;
  evmTimeoutMs?: number;
}

/** The record-rule rows of Verification §4.9 to §4.12 for one record, in report order. Never throws. */
export async function recordRuleChecks(input: RecordRuleRowsInput): Promise<BundleCheck[]> {
  const { envelope, digest } = input;
  const env = isRecord(envelope) ? (envelope as unknown as Json) : {};
  const payload = isRecord(env.payload) ? env.payload : {};
  const nonRepudiation = isRecord(env.nonRepudiation) ? env.nonRepudiation : {};
  const mandateForm = signoffExpectationForm(payload.signoffExpectation) === 'mandate';
  const issuanceReported =
    (nonRepudiation.mandateIssuance !== undefined && nonRepudiation.mandateIssuance !== null) ||
    (payload.aiSystemId === 'tzun:mandate' && payload.action === 'issue-mandate');

  if (digest.outcome !== 'checked-correct') {
    const blocked = `blocked_by:${digest.id}`;
    const rows = PAYLOAD_ROWS.map((id) => row(id, 'not-checked', blocked));
    if (issuanceReported) rows.push(row('mandate.issuance', 'not-checked', blocked));
    if (mandateForm) rows.push(row('mandate.scope', 'not-checked', blocked), row('mandate.limits', 'not-checked', blocked), mandateKeyRow(input));
    rows.push(...mandateTimestampRow(nonRepudiation));
    return rows;
  }

  // The digest holds, so the engine's answers are the record's own.
  const result = verifyEnvelope(envelope, undefined, input.registry) as VerificationResult;
  const rows: BundleCheck[] = [];

  const decider = result.decider ?? { outcome: 'not-checked' as const, valid: null, reason: 'absent' };
  const deciderRow = row('decider', decider.outcome, decider.reason, pick(decider, DECIDER_FACTS));
  rows.push(deciderRow, await freshnessRow(payload, deciderRow, input));

  const contributions = result.contributions;
  if (contributions) {
    rows.push(row('contributions', contributions.outcome, contributions.reason, pick(contributions, CONTRIBUTIONS_FACTS)));
    const binding = contributions.binding;
    const bindingDecided = binding.outcome === 'checked-correct' || binding.outcome === 'checked-wrong';
    rows.push(row('contributions.binding', binding.outcome, binding.reason, bindingDecided ? pick(binding, BINDING_FACTS) : undefined));
    if (contributions.pipeline) rows.push(row('contributions.pipeline', contributions.pipeline.outcome, contributions.pipeline.reason));
  }

  const links = result.links;
  if (links) {
    const linkFacts =
      links.outcome === 'checked-correct'
        ? { count: links.count, relations: links.relationNames, extensions: links.extensions }
        : pick(links, ['rule', 'failedLink']);
    rows.push(row('links', links.outcome, links.reason, pick(linkFacts, ['count', 'relations', 'extensions', 'rule', 'failedLink'])));
    for (const relation of links.relations) {
      rows.push(row(`links[${relation.index}]`, relation.outcome, relation.reason, pick(relation, LINK_FACTS)));
      const edge = links.edges[relation.index];
      if (edge) rows.push(row(`links[${relation.index}].edge`, edge.outcome, edge.reason));
    }
  }

  const mandate = result.mandate;
  if (mandate?.issuance) rows.push(row('mandate.issuance', mandate.issuance.outcome, mandate.issuance.reason, pick(mandate.issuance, ['link'])));
  if (mandate?.scope) rows.push(row('mandate.scope', mandate.scope.outcome, mandate.scope.reason, pick(mandate.scope, ['failures', 'undeterminable'])));
  if (mandate?.limits) rows.push(row('mandate.limits', mandate.limits.outcome, mandate.limits.reason, pick(mandate.limits, ['slot', 'totals'])));
  if (mandateForm) rows.push(mandateKeyRow(input));
  rows.push(...mandateTimestampRow(nonRepudiation));
  return rows;
}

/**
 * `mandate.key`, for the mandate form: the principal's assertion needs its
 * credential, which this bundle version carries in no slot (as `signoff.key`).
 */
function mandateKeyRow(input: RecordRuleRowsInput): BundleCheck {
  return input.credentialsFilled
    ? row('mandate.key', 'abstain', 'unsupported_signoff')
    : row('mandate.key', 'not-checked', 'not_in_bundle:credential');
}

/** `mandate.assertionTimestamp`: a token over the principal's assertion digest, which this version does not read. */
function mandateTimestampRow(nonRepudiation: Json): BundleCheck[] {
  for (const name of ['mandate', 'mandateIssuance'] as const) {
    const block = nonRepudiation[name];
    if (isRecord(block) && block.assertionTimestamp !== undefined && block.assertionTimestamp !== null) {
      return [row('mandate.assertionTimestamp', 'abstain', 'unsupported_artifact')];
    }
  }
  return [];
}

/**
 * `decider.freshness` (Verification §4.9, Record §6.6): the finalized-block
 * reference the decider carries, against the auditor's header source for its
 * chain. A reference names a block by height and hash; the source must call
 * that height final and hold that hash there. Facts: `blockTime` (ISO 8601) and
 * `captureLag` (`capturedAt` − `blockTime`, in milliseconds; informative).
 */
async function freshnessRow(payload: Json, deciderRow: BundleCheck, input: RecordRuleRowsInput): Promise<BundleCheck> {
  const id = 'decider.freshness';
  const decider = payload.decider;
  if (!isRecord(decider) || decider.freshness === null || decider.freshness === undefined) return row(id, 'not-checked', 'absent');
  if (deciderRow.outcome !== 'checked-correct') return row(id, 'not-checked', 'blocked_by:decider');
  const reference = parseFreshnessReference(decider.freshness);
  // The decider grammar refuses a reference that does not parse, so the row above is not correct for one.
  if (reference === null) return row(id, 'not-checked', 'blocked_by:decider');
  if (reference.namespace !== 'eip155') return row(id, 'abstain', 'unsupported_freshness_chain');
  const sources = input.evmHeaderSources;
  const source = isRecord(sources) && Object.prototype.hasOwnProperty.call(sources, reference.chain) ? sources[reference.chain] : undefined;
  if (!source) return row(id, 'not-checked', 'input_not_supplied:evm_header_source');

  const requested = input.evmTimeoutMs;
  const timeoutMs = typeof requested === 'number' && Number.isFinite(requested) && requested > 0 ? requested : DEFAULT_TIMEOUT_MS;
  const deadline = Date.now() + timeoutMs;
  const notChecked = (reason: string) => row(id, 'not-checked', reason);
  try {
    const chainId = await withDeadline(() => source.chainId(), deadline);
    if (typeof chainId !== 'bigint') return notChecked('evm_header_source_unavailable');
    if (chainId !== BigInt(reference.reference)) return notChecked('evm_header_source_chain_mismatch');
    const finalized = await withDeadline(() => source.finalizedBlockNumber(), deadline);
    if (typeof finalized !== 'number' || !Number.isSafeInteger(finalized)) return notChecked('evm_header_source_unavailable');
    if (reference.blockNumber > finalized) return notChecked('evm_block_not_finalized');
    const block = await withDeadline(() => source.canonicalBlock(reference.blockNumber), deadline);
    // A source that calls this height final must have a block there.
    if (block === null) return notChecked('evm_header_source_inconsistent');
    if (!isRecord(block) || typeof block.hash !== 'string' || typeof block.timestamp !== 'number' || !Number.isSafeInteger(block.timestamp)) {
      return notChecked('evm_header_source_unavailable');
    }
    if (block.hash.toLowerCase() !== reference.blockHash.toLowerCase()) return row(id, 'checked-wrong', 'freshness_block_mismatch');
    const blockMs = block.timestamp * 1000;
    const capturedMs = typeof payload.capturedAt === 'string' ? Date.parse(payload.capturedAt) : Number.NaN;
    return row(id, 'checked-correct', undefined, {
      blockTime: new Date(blockMs).toISOString(),
      ...(Number.isFinite(capturedMs) && { captureLag: capturedMs - blockMs }),
    });
  } catch (err) {
    return notChecked(err instanceof DeadlineExceeded ? 'evm_header_source_timeout' : 'evm_header_source_unavailable');
  }
}

class DeadlineExceeded extends Error {}

function withDeadline<T>(work: () => Promise<T> | T, deadline: number): Promise<T> {
  const remaining = deadline - Date.now();
  if (remaining <= 0) return Promise.reject(new DeadlineExceeded());
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new DeadlineExceeded()), remaining);
    timer.unref?.();
    Promise.resolve()
      .then(work)
      .then(
        (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        (error) => {
          clearTimeout(timer);
          reject(error);
        },
      );
  });
}

/**
 * The `payload.<name>` rows (Verification §4.7, Record §2.2): one per payload
 * member outside the format's twelve names, in byte order of the name, each
 * `abstain`, `unsupported_member`. They are not hashed, so a reader never
 * passes one over in silence.
 */
export function unhashedPayloadRows(envelope: unknown): BundleCheck[] {
  const payload = isRecord(envelope) && isRecord((envelope as Json).payload) ? (envelope as Json).payload : null;
  if (payload === null) return [];
  return unhashedPayloadMembers(payload).map((name) => row(`payload.${name}`, 'abstain', 'unsupported_member'));
}
