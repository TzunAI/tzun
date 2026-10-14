/**
 * `tzun.mandates` (Record §9.6): prepare and issue a mandate, revoke it,
 * supersede it with a successor, confirm a mandated record, and read a
 * mandate and its events.
 *
 *   - `prepare(document)` checks the document (grammar, the restriction, a
 *     window that does not end before it begins, no sub-mandate, an open
 *     predecessor with the same principal) and forms the statement the
 *     principal signs, with the header follower's finalized block as
 *     `notBefore` (`none` when there is none). It persists nothing.
 *   - `issue({ document, statement, assertion })` verifies the principal's
 *     assertion (a user-verifying WebAuthn assertion presenting the statement
 *     challenge, by a credential registered to `principal.signer`), computes
 *     the assertion digest, asks the timestamp authority for a token over it
 *     (soft-fail), and captures the issuance record: `aiSystemId
 *     "tzun:mandate"`, action `issue-mandate`, the principal as decider, the
 *     issuance material in `nonRepudiation.mandateIssuance`. The mandate row,
 *     its caps and its `issued` event are written in the storing transaction.
 *     A successor (a document naming a `predecessor`) also links its
 *     predecessor's issuance record (`supersedes`) and, in the same
 *     transaction, moves the predecessor to `superseded` with its event. The
 *     `root` link Record §8.5 adds beside `supersedes` is written by the
 *     links extension, which resolves the predecessor's issuance record as a
 *     held target; a store without that extension writes `supersedes` alone.
 *   - `prepareRevocation` / `revoke` capture a revocation record, signed per
 *     record by its author through the prepared-record flow, and move the
 *     mandate to `revoked` with its event in the storing transaction. Any
 *     account with a verified, user-verifying assertion may revoke.
 *   - `confirm(evidenceId, assertion)` fills `nonRepudiation.confirmation` of
 *     a record whose mandate expectation owes one, once, and appends a
 *     `mandate_confirmed` custody entry naming who confirmed, in one
 *     transaction under the record's row lock (`confirmRecord`), so of two
 *     confirmations from any processes exactly one is filled and recorded.
 *   - `get`, `events` and `list` read mandates; a read that finds an open
 *     mandate whose window has ended moves it to `expired` with its event
 *     first, so no read reports such a mandate open.
 *
 * Every refusal throws a {@link MandateError}.
 */
import {
  ACCT_VALUE_RE,
  assertionDigest,
  buildMandateEventBody,
  buildMandateStatement,
  isMandateInstant,
  mandateConfirmationChallenge,
  mandateConfirmationViolation,
  mandateDigest,
  mandateDocumentViolation,
  mandateExpiredAt,
  mandateIssuanceInput,
  mandateRevocationInput,
  mandateStatementChallenge,
  mandateStatementDigest,
  mandateStatementViolation,
  predecessorPrincipalViolation,
  reasonViolation,
  revocationInstantViolation,
  webauthnChallengeForDigest,
} from '@tzun/engine';
import type {
  CaptureResult,
  LinkInput,
  LinkTarget,
  MandateBlock,
  MandateCapLimit,
  MandateDocument,
  MandateEventRow,
  MandateExpectation,
  MandateRevokeStore,
  MandateRow,
  MandateStatement,
  StoreOptions,
  WebauthnAssertion,
} from '@tzun/engine';
import type { MandateListFilter, MandateListPage } from '../../storage/mandate-sql';
import type { CaptureRefusal, MandateIssueResult, MandatesApi, SdkHost, SystemRecordCapture } from '../extension-points';
import type { PreparedAssertionChallenge } from '../index';
import { verifyCeremony } from './ceremony';
import { MandateError, mandateErrorOfFailure, type MandateSwapConflict } from './errors';
import { expireMandateIfEnded } from './expiry';
import {
  canonicalJson,
  issuanceTargetOf,
  mandateEventRow,
  mandatePartsOf,
  requireMandateStore,
  totalsOf,
  type MandateParts,
  type MandateStore,
} from './store';
import { classifyMandateStoreError } from './store-errors';

/** The `reason` of every issuance record. */
export const MANDATE_ISSUANCE_REASON = 'Mandate issued by its principal';

/** What `prepareRevocation` returns: the prepared record, and the request it was prepared for. */
export interface PreparedMandateRevocation extends PreparedAssertionChallenge {
  /** What `revoke()` reuses: the instant the revocation claims is fixed in the prepared record's `aiOutput`. */
  revocation: { mandateId: string; effectiveAt: string; reason: string; revoker: string };
}

function refused(code: string, field: string, message: string, details: Record<string, unknown> = {}): MandateError {
  return new MandateError(code, field, message, 'mandate_refused', details);
}

function invalid(code: string, field: string, message: string, details: Record<string, unknown> = {}): MandateError {
  return new MandateError(code, field, message, 'validation_failure', details);
}

/** `tzun.mandates.list`: a page of the store's mandates. */
export interface MandateListApi {
  /**
   * A page of the mandates `filter` selects (a state, a window that ended
   * before an instant), in mandate id order, and the cursor of the next page.
   * A store that does not list its mandates refuses `mandate_not_supported_by_store`.
   */
  list(filter?: MandateListFilter): Promise<MandateListPage>;
}

/**
 * How a system record's capture reads a store refusal of its own write: a
 * lost compare-and-swap is retried, a refusal is the capture's refusal. It
 * keeps the conflict it last saw, so a capture that ends on one reports its
 * code.
 */
function ownStoreErrors(): { classify(error: unknown): 'retry' | CaptureRefusal | null; lost(): MandateSwapConflict | null } {
  let lost: MandateSwapConflict | null = null;
  return {
    classify(error: unknown): 'retry' | CaptureRefusal | null {
      const kind = classifyMandateStoreError(error);
      if (kind === null || kind.kind === 'input') return null;
      if (kind.kind === 'conflict') {
        lost = kind.code;
        return 'retry';
      }
      return {
        failureType: kind.code === 'mandate_not_found' ? 'validation_failure' : 'mandate_refused',
        code: kind.code,
        field: kind.field,
        message: kind.message,
      };
    },
    lost: () => lost,
  };
}

/** A link input naming a same-store record whose digest, id and locator are known: resolved by the link hook when it holds it, written as given when not. */
function knownTarget(target: LinkTarget): LinkInput['target'] {
  return {
    digest: target.digest,
    ...(target.evidenceId !== null && { evidenceId: target.evidenceId }),
    ...(target.locator !== null && { locator: { ...target.locator } }),
    external: true,
  };
}

/** The mandate service over the host's store. */
export function mandatesApi(host: SdkHost): MandatesApi & MandateListApi {
  /** The mandate with this id (not a digest), open, or a refusal. */
  async function openMandate(store: MandateStore, mandateId: unknown, field = 'mandateId'): Promise<MandateRow> {
    const row = typeof mandateId === 'string' && mandateId.length > 0 ? await store.getMandate(mandateId) : null;
    if (row === null || row.mandateId !== mandateId) throw invalid('mandate_not_found', field, 'this store holds no mandate with that id');
    if (row.state !== 'open') throw refused('mandate_not_open', field, `the mandate is ${row.state}, not open`);
    return row;
  }

  /**
   * `row` as a read reports it: an open mandate whose window has ended is
   * first moved to `expired`, with its event, and read again. A move that
   * fails is logged and the row is reported as held.
   */
  async function observed(store: MandateStore, row: MandateRow): Promise<MandateRow> {
    const now = new Date().toISOString();
    if (row.state !== 'open' || !mandateExpiredAt(row.notAfter, now)) return row;
    const outcome = await expireMandateIfEnded(store, row.mandateId, now).catch((error: unknown) => {
      host.log('mandate_expiry_failed', { mandateId: row.mandateId, errorName: error instanceof Error ? error.name : typeof error });
      return null;
    });
    if (outcome === 'expired') host.log('mandate_expired', { mandateId: row.mandateId, used: row.used });
    return outcome === null ? row : ((await store.getMandate(row.mandateId)) ?? row);
  }

  /** A revocation's reason: what a record's `reason` may be (1 to 16,384 UTF-16 code units, no lone surrogate). */
  function checkReason(reason: unknown): asserts reason is string {
    const violation = reasonViolation(reason, 'reason');
    if (violation) throw invalid('invalid_reason', 'reason', violation.message);
  }

  /** The revocation record `revoke()` would capture next, or a {@link MandateError} naming why it cannot be prepared. */
  async function prepareRecord(request: SystemRecordCapture): Promise<PreparedAssertionChallenge> {
    try {
      return await host.prepareSystemRecord(request);
    } catch (error) {
      const text = error instanceof Error ? error.message : '';
      const parsed = /^\[Tzun\] \w+: ([^:]+): (.*)$/s.exec(text);
      throw invalid(
        'invalid_prepared',
        parsed?.[1] ?? 'revocation',
        `the revocation record cannot be prepared${parsed ? `: ${parsed[1]}: ${parsed[2]}` : ''}`,
      );
    }
  }

  /** The document's grammar and the rules `prepare` applies before a principal signs. */
  function checkDocument(document: unknown): asserts document is MandateDocument {
    const violation = mandateDocumentViolation(document);
    if (violation) throw invalid(violation.code, violation.field, violation.message);
  }

  /** A successor's predecessor: held, open, and of the same principal. */
  async function predecessorOf(store: MandateStore, document: MandateDocument): Promise<{ row: MandateRow; parts: MandateParts } | null> {
    if (document.predecessor === null) return null;
    const row = await store.getMandate(document.predecessor);
    if (row === null || row.mandateDigest !== document.predecessor) {
      throw invalid('mandate_not_found', 'document.predecessor', 'this store holds no mandate with the predecessor digest');
    }
    if (row.state !== 'open') throw refused('mandate_not_open', 'document.predecessor', `the predecessor is ${row.state}, not open`);
    const parts = mandatePartsOf(row);
    const mismatch = predecessorPrincipalViolation(document, parts.document);
    if (mismatch) throw refused(mismatch.code, mismatch.field, mismatch.message);
    return { row, parts };
  }

  /** The statement `prepare` formed for `document`, checked against it. */
  function checkStatement(statement: unknown, document: MandateDocument, digest: string): asserts statement is MandateStatement {
    const reason = mandateStatementViolation(statement);
    if (reason !== null) throw invalid('invalid_statement', 'statement', `the statement is not a mandate statement: ${reason}`);
    const s = statement as MandateStatement;
    if (s.mandateDigest !== digest || s.signer !== document.principal.signer || s.policyDigest !== (document.policyDigest ?? 'none')) {
      throw invalid('invalid_statement', 'statement', "the statement must name the document's digest, principal and policy, as prepare() forms it");
    }
  }

  /** The `superseded` close of a successor's predecessor, read fresh for one attempt. */
  async function supersedeOf(
    store: MandateStore,
    predecessor: { row: MandateRow; parts: MandateParts },
    successorDigest: string,
    record: string,
  ): Promise<MandateRevokeStore | CaptureRefusal> {
    const row = await store.getMandate(predecessor.row.mandateId);
    if (row === null || row.state !== 'open') {
      return { failureType: 'mandate_refused', code: 'mandate_not_open', field: 'document.predecessor', message: 'the predecessor is no longer open' };
    }
    const totals = await totalsOf(store, row, predecessor.parts.document);
    const body = buildMandateEventBody({ event: 'superseded', mandateDigest: row.mandateDigest, record, successor: successorDigest, used: row.used, totals });
    return {
      mandateId: row.mandateId,
      expectState: 'open',
      newState: 'superseded',
      expectUsed: row.used,
      expectTotals: totals,
      event: mandateEventRow(row.mandateId, body),
    };
  }

  /** The revocation record's capture request (Record §9.6). */
  async function revocationRequest(
    store: MandateStore,
    row: MandateRow,
    args: { effectiveAt: string; reason: string; revoker: string },
    assertion?: WebauthnAssertion,
    classifyStoreError: (error: unknown) => 'retry' | CaptureRefusal | null = ownStoreErrors().classify,
  ): Promise<SystemRecordCapture> {
    const issuance = await issuanceTargetOf(host, row);
    const input = mandateRevocationInput({
      mandateDigest: row.mandateDigest,
      statementDigest: row.statementDigest,
      claimedRevocationInstant: args.effectiveAt,
      reason: args.reason,
      revokerUserId: args.revoker,
      issuance,
    });
    const document = mandatePartsOf(row).document;
    return {
      kind: 'mandate',
      aiOutput: input.aiOutput,
      action: input.action,
      reason: input.reason,
      decider: { kind: 'human', id: `acct:${args.revoker}` },
      links: [{ rel: 'revokes', target: knownTarget(issuance) }],
      allowReserved: ['revokes'],
      ...(assertion !== undefined && { attestation: { webauthnAssertion: assertion } }),
      async storeOptions({ envelope }): Promise<Pick<StoreOptions, 'mandateRevoke'> | CaptureRefusal> {
        const current = await store.getMandate(row.mandateId);
        if (current === null || current.state !== 'open') {
          return { failureType: 'mandate_refused', code: 'mandate_not_open', field: 'mandateId', message: 'the mandate is no longer open' };
        }
        const totals = await totalsOf(store, current, document);
        const body = buildMandateEventBody({
          event: 'revoked',
          mandateDigest: current.mandateDigest,
          record: envelope.integrity.canonicalDigest,
          used: current.used,
          totals,
        });
        return {
          mandateRevoke: {
            mandateId: current.mandateId,
            expectState: 'open',
            newState: 'revoked',
            expectUsed: current.used,
            expectTotals: totals,
            event: mandateEventRow(current.mandateId, body),
          },
        };
      },
      classifyStoreError,
    };
  }

  function checkRevoker(revoker: unknown): asserts revoker is string {
    if (typeof revoker !== 'string' || !ACCT_VALUE_RE.test(revoker)) {
      throw invalid('invalid_identifier', 'revoker', 'revoker must be an opaque account id [A-Za-z0-9._-]{1,128}, never an email address or a name');
    }
  }

  return {
    async prepare(document) {
      const store = requireMandateStore(host);
      checkDocument(document);
      await predecessorOf(store, document);
      const digest = mandateDigest(document)!;
      const statement = buildMandateStatement({
        mandateDigest: digest,
        signer: document.principal.signer,
        policyDigest: document.policyDigest,
        notBefore: await host.freshnessReference(),
      });
      const statementDigest = mandateStatementDigest(statement)!;
      return { statement, statementDigest, challenge: mandateStatementChallenge(statementDigest) };
    },

    async issue({ document, statement, assertion }): Promise<MandateIssueResult> {
      const store = requireMandateStore(host);
      checkDocument(document);
      const digest = mandateDigest(document)!;
      checkStatement(statement, document, digest);
      if ((await store.getMandate(document.mandateId)) !== null || (await store.getMandate(digest)) !== null) {
        throw refused('mandate_already_issued', 'document.mandateId', 'a mandate with this id or this document is already issued');
      }
      const predecessor = await predecessorOf(store, document);
      const statementDigest = mandateStatementDigest(statement)!;
      const ceremony = await verifyCeremony(host, assertion, mandateStatementChallenge(statementDigest));
      if (!ceremony.ok) {
        throw invalid('assertion_not_verified', 'assertion', "the principal's assertion over the statement did not verify", { reason: ceremony.reason });
      }
      if (ceremony.userId !== document.principal.signer) {
        throw invalid('assertion_not_verified', 'assertion', 'the assertion was made by a credential not registered to the principal', {
          reason: 'credential_not_principal',
        });
      }
      const aDigest = assertionDigest(assertion);
      if (aDigest === null) {
        throw invalid('assertion_not_verified', 'assertion', 'the assertion has no assertion digest (its signature is not valid DER)', {
          reason: 'assertion_digest_refused',
        });
      }
      const assertionTimestamp = await host.timestampDigest(aDigest);
      const block: MandateBlock = { statement, assertion, assertionTimestamp, document };
      const input = mandateIssuanceInput({ document, statement, assertion, reason: MANDATE_ISSUANCE_REASON });
      const predecessorTarget = predecessor ? await issuanceTargetOf(host, predecessor.row) : null;
      const caps: MandateCapLimit[] = Object.entries(document.limits.cumulative ?? {})
        .map(([cap, c]) => ({ cap, max: c.max }))
        .sort((a, b) => (a.cap < b.cap ? -1 : a.cap > b.cap ? 1 : 0));
      const storeErrors = ownStoreErrors();
      const result = await host.captureSystemRecord({
        kind: 'mandate',
        aiOutput: input.aiOutput,
        action: input.action,
        reason: input.reason,
        decider: { kind: 'human', id: `acct:${document.principal.signer}`, credential: document.principal.credential },
        links: predecessorTarget ? [{ rel: 'supersedes', target: knownTarget(predecessorTarget) }] : null,
        attestation: { mandateIssuance: block },
        async storeOptions({ envelope }) {
          const record = envelope.integrity.canonicalDigest;
          const row: MandateRow = {
            mandateId: document.mandateId,
            mandateDigest: digest,
            documentBytes: canonicalJson(document),
            statementJson: canonicalJson(statement),
            statementDigest,
            assertionJson: canonicalJson(assertion),
            assertionDigest: aDigest,
            assertionTimestamp,
            state: 'open',
            used: 0,
            maxRecords: document.limits.maxRecords,
            notBefore: document.validity.notBefore,
            notAfter: document.validity.notAfter,
            issuanceEvidenceId: envelope.payload.evidenceId,
            issuanceDigest: record,
            createdAt: envelope.payload.capturedAt,
          };
          const event = mandateEventRow(document.mandateId, buildMandateEventBody({ event: 'issued', mandateDigest: digest, record }));
          if (predecessor === null) return { mandateIssue: { record: row, caps, event } };
          const supersede = await supersedeOf(store, predecessor, digest, record);
          if ('failureType' in supersede) return supersede;
          return { mandateIssue: { record: row, caps, event }, mandateRevoke: supersede };
        },
        classifyStoreError: storeErrors.classify,
      });
      if (!result.stored) throw mandateErrorOfFailure(result.failure, 'the issuance record', storeErrors.lost());
      host.log('mandate_issued', { mandateId: document.mandateId, evidenceId: result.envelope.payload.evidenceId, successor: predecessor !== null });
      return { mandateId: document.mandateId, mandateDigest: digest, issuance: result };
    },

    async prepareRevocation({ mandateId, effectiveAt, reason, revoker }): Promise<PreparedMandateRevocation> {
      const store = requireMandateStore(host);
      checkRevoker(revoker);
      checkReason(reason);
      const row = await openMandate(store, mandateId);
      const instant = effectiveAt ?? new Date().toISOString();
      if (!isMandateInstant(instant)) {
        throw invalid('invalid_revocation_instant', 'effectiveAt', 'effectiveAt must be an ISO 8601 UTC instant with milliseconds');
      }
      const prepared = await prepareRecord(await revocationRequest(store, row, { effectiveAt: instant, reason, revoker }));
      const late = revocationInstantViolation(instant, prepared.capturedAt);
      if (late) throw invalid(late.code, late.field, late.message);
      return { ...prepared, revocation: { mandateId, effectiveAt: instant, reason, revoker } };
    },

    async revoke({ mandateId, effectiveAt, reason }, { prepared, assertion }): Promise<CaptureResult> {
      const store = requireMandateStore(host);
      if (typeof prepared !== 'object' || prepared === null || typeof prepared.digest !== 'string' || typeof prepared.capturedAt !== 'string') {
        throw invalid('invalid_prepared', 'prepared', 'prepared must be the object prepareRevocation() returned');
      }
      checkReason(reason);
      const deciderId = typeof prepared.decider?.id === 'string' ? prepared.decider.id : '';
      const revoker = deciderId.startsWith('acct:') ? deciderId.slice('acct:'.length) : '';
      const revocation = (prepared as Partial<PreparedMandateRevocation>).revocation;
      if (
        revocation !== undefined &&
        (revocation.mandateId !== mandateId ||
          revocation.reason !== reason ||
          revocation.revoker !== revoker ||
          (effectiveAt !== undefined && effectiveAt !== revocation.effectiveAt))
      ) {
        throw invalid('invalid_prepared', 'prepared', 'prepared is the revocation prepareRevocation() formed for another mandate, reason, revoker or instant');
      }
      const instant = effectiveAt ?? revocation?.effectiveAt;
      if (instant === undefined) {
        throw invalid('invalid_revocation_instant', 'effectiveAt', 'pass the effectiveAt prepareRevocation() used, or the prepared revocation it returned');
      }
      checkRevoker(revoker);
      const row = await openMandate(store, mandateId);
      const late = revocationInstantViolation(instant, prepared.capturedAt);
      if (late) throw invalid(late.code, late.field, late.message);
      const ceremony = await verifyCeremony(host, assertion, webauthnChallengeForDigest(prepared.digest));
      if (!ceremony.ok) {
        throw invalid('assertion_not_verified', 'assertion', "the revoker's assertion over the revocation record did not verify", { reason: ceremony.reason });
      }
      if (ceremony.userId !== revoker) {
        throw invalid('assertion_not_verified', 'assertion', 'the assertion was made by a credential not registered to the revoker', {
          reason: 'credential_not_revoker',
        });
      }
      const storeErrors = ownStoreErrors();
      const request = await revocationRequest(store, row, { effectiveAt: instant, reason, revoker }, assertion, storeErrors.classify);
      const result = await host.captureSystemRecord(request, { prepared });
      if (!result.stored) throw mandateErrorOfFailure(result.failure, 'the revocation record', storeErrors.lost());
      host.log('mandate_revoked', { mandateId, evidenceId: result.envelope.payload.evidenceId });
      return result;
    },

    async confirm(evidenceId, assertion): Promise<void> {
      requireMandateStore(host);
      if (typeof host.storage.confirmRecord !== 'function') {
        throw new MandateError('mandate_not_supported_by_store', 'mandate', 'this store cannot confirm a record in one transaction');
      }
      if (typeof evidenceId !== 'string') throw invalid('record_not_found', 'evidenceId', 'this store holds no record with that id');
      const envelope = await host.storage.retrieve(evidenceId);
      if (envelope === null) throw invalid('record_not_found', 'evidenceId', 'this store holds no record with that id');
      const owed = mandateConfirmationViolation(envelope);
      if (owed) throw refused(owed.code, owed.field, owed.message);
      const digest = envelope.integrity.canonicalDigest;
      const ceremony = await verifyCeremony(host, assertion, mandateConfirmationChallenge(digest));
      if (!ceremony.ok) {
        throw invalid('assertion_not_verified', 'assertion', 'the confirming assertion over the record did not verify', { reason: ceremony.reason });
      }
      const expectation = envelope.payload.signoffExpectation as MandateExpectation;
      // Fill-only, with the custody entry, in one transaction under the
      // record's row lock: of two confirmations, from this process or
      // another, exactly one fills and is recorded.
      const { filled } = await host.storage.confirmRecord(evidenceId, assertion, {
        timestamp: new Date().toISOString(),
        actor: `acct:${ceremony.userId}`,
        action: 'mandate_confirmed',
        systemId: envelope.payload.aiSystemId,
        metadata: { mandateId: envelope.nonRepudiation.mandate?.document?.mandateId ?? null, slot: expectation.mandateSeq },
      });
      if (!filled) throw refused('already_confirmed', 'nonRepudiation.confirmation', 'the record is already confirmed');
      host.log('mandate_record_confirmed', { evidenceId, slot: expectation.mandateSeq });
    },

    async get(mandateId): Promise<MandateRow | null> {
      const store = requireMandateStore(host);
      const row = await store.getMandate(mandateId);
      return row === null ? null : observed(store, row);
    },

    async events(mandateId): Promise<MandateEventRow[]> {
      const store = requireMandateStore(host);
      const row = await store.getMandate(mandateId);
      if (row === null) return [];
      await observed(store, row);
      return store.listMandateEvents(row.mandateId);
    },

    async list(filter?: MandateListFilter): Promise<MandateListPage> {
      const store = requireMandateStore(host);
      if (typeof store.listMandates !== 'function') {
        throw new MandateError('mandate_not_supported_by_store', 'mandate', 'this store does not list its mandates');
      }
      let page: MandateListPage;
      try {
        page = await store.listMandates(filter);
      } catch (error) {
        const e = error as { name?: unknown; field?: unknown };
        if (e?.name === 'InvalidPaginationError') {
          const field = typeof e.field === 'string' ? e.field : 'filter';
          throw invalid('invalid_pagination', field, `${field} is not a usable value for the mandate listing`);
        }
        throw error;
      }
      const rows: MandateRow[] = [];
      for (const row of page.rows) {
        const seen = await observed(store, row);
        if (filter?.state === undefined || filter.state === null || seen.state === filter.state) rows.push(seen);
      }
      return { rows, cursor: page.cursor };
    },
  };
}
