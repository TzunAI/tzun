import { randomUUID } from 'crypto';
import { StorageAdapter } from '@tzun/engine';
import { EvidenceChain } from '@tzun/engine';
import { SchemaRegistry } from '@tzun/engine';
import { CustodyEntry, EvidenceEnvelope } from '@tzun/engine';
import { canonicalSerialize, computeDigest } from '@tzun/engine';
import {
  AnnotateOptions,
  AnnotationRecord,
  RelinkRecord,
  ForkRecord,
  ChainIdentity,
  RelinkOptions,
  ForkOptions,
  AnnotationResult,
  RelinkResult,
  ForkResult,
  ModifiedLink,
} from '@tzun/engine';

import { MonitoringEvent, RelinkCustodyAppend, TamperIncidentStatus } from '@tzun/engine';
import { chainUpperBound } from '../storage/chain-bounds';
import { AmbiguousActiveChainError, NoActiveChainError } from '@tzun/engine';

/**
 * Ordered field set hashed into a RelinkRecord's digest.
 *
 * Explicit and ordered so the digest is reproducible by an auditor (and by a
 * second implementation) rather than dependent on JS key-insertion order.
 */
export const RELINK_RECORD_HASHED_FIELDS = [
  'id',
  'incidentId',
  'relinkedAt',
  'relinkedBy',
  'fromSequence',
  'toSequence',
  'modifiedLinks',
] as const;

/**
 * Digest over a RelinkRecord, embedded in each 'relinked' custody entry.
 *
 * This is a NEW digest over a recovery record. It is not part of the evidence
 * envelope digest or the chain link, and nothing about `canonicalDigest` or
 * `chainLink` changes because of it.
 */
export function computeRelinkDigest(relink: RelinkRecord): string {
  return computeDigest(
    canonicalSerialize(
      relink as unknown as Record<string, unknown>,
      [...RELINK_RECORD_HASHED_FIELDS],
    ),
  );
}

/**
 * The status an incident has after a human review (annotate): an open
 * incident becomes acknowledged, and any other status is kept. A review never
 * moves an incident backwards — an incident with a recovery under way stays
 * 'in_progress' and a resolved one stays resolved.
 */
function statusAfterReview(status: TamperIncidentStatus): AnnotationResult['updatedIncidentStatus'] {
  return status === 'open' ? 'acknowledged' : status;
}

/**
 * Event bus interface for emitting recovery events.
 * Structurally compatible with the real MonitoringEventBus class.
 */
interface EventBus {
  emit(event: MonitoringEvent): void;
}

/**
 * RecoveryManager -- tiered response system for handling detected tampering.
 *
 * Three tiers:
 * - Tier 1: annotate() -- document the issue, chain stays broken (default)
 * - Tier 2: relink() -- recompute chain links forward over a range of one chain; no payload or digest is rewritten (admin)
 * - Tier 3: fork() -- seal old chain, create new chain (last resort)
 *
 * All operations require explicit human authorization. Not part of the automated pipeline.
 */
export class RecoveryManager {
  private storage: StorageAdapter;
  private registry: SchemaRegistry;
  private eventBus: EventBus | null;

  constructor(
    storage: StorageAdapter,
    registry: SchemaRegistry,
    eventBus?: EventBus,
  ) {
    this.storage = storage;
    this.registry = registry;
    this.eventBus = eventBus ?? null;
  }

  /**
   * Tier 1: Annotate a tamper incident.
   *
   * The tampered record stays in place. The chain stays broken. Nothing is modified
   * except incident status and custody chain entries.
   */
  async annotate(
    incidentId: string,
    options: AnnotateOptions,
  ): Promise<AnnotationResult> {
    const { authorizedBy, notes } = options;
    if (!authorizedBy) {
      throw new Error('authorizedBy is required -- recovery operations require explicit human authorization.');
    }
    if (!notes) {
      throw new Error('notes is required -- annotations must include an explanation.');
    }

    // Resolve affected records from the incident itself, never from the whole
    // store. Custody chains are part of the evidence envelope: a 'reviewed'
    // entry appended to every record would make a later export of an unrelated
    // record show it as "reviewed in connection with tamper incident X" — a
    // false review event written into the evidence itself.
    const incident = await this.storage.getIncident(incidentId);
    if (!incident) {
      throw new Error(
        `Tamper incident "${incidentId}" not found -- annotate() records a human review of a specific ` +
          'incident and cannot invent one.',
      );
    }

    let affectedRecords = [...incident.affectedRecords];
    if (affectedRecords.length === 0 && incident.affectedSequenceRange) {
      // Sequence-shaped incidents (gaps, missing records) name a range rather
      // than ids. Scope the range to one chain: sequence numbers restart at 1
      // per chain, so an unscoped range would pull in same-numbered records
      // from a different chain.
      //
      // Which chain cannot be guessed. `TamperIncident` carries no chain id and
      // a sequence_gap / missing_record incident carries no evidence ids
      // either, so the range is all there is — and the scanner raises those
      // incidents on SEALED chains too. Silently resolving against the active
      // chain would append a 'reviewed' custody entry, naming a real incident,
      // to active-chain records the incident was never about, while the
      // records it IS about get nothing. A custody entry is part of the
      // evidence envelope: that is a false review event written into evidence.
      //
      // On a single-chain store there is nothing to get wrong, so the default
      // stands. Once the store has forked, the caller has to say which chain.
      const chainId = options.chainId ?? (await this.resolveIncidentChain(incidentId));
      const range = await this.storage.getBySequenceRange(
        incident.affectedSequenceRange.from,
        incident.affectedSequenceRange.to,
        chainId,
      );
      affectedRecords = range.map((e) => e.payload.evidenceId);
    }

    const originalDigests: Record<string, string> = {};
    const existingRecords: string[] = [];
    for (const evidenceId of affectedRecords) {
      const envelope = await this.storage.retrieve(evidenceId);
      if (!envelope) continue;
      originalDigests[evidenceId] = envelope.integrity.canonicalDigest;
      existingRecords.push(evidenceId);
    }

    const now = new Date().toISOString();
    const annotation: AnnotationRecord = {
      id: randomUUID(),
      incidentId,
      affectedRecords,
      annotatedAt: now,
      annotatedBy: authorizedBy,
      notes,
      originalDigests,
    };

    // Store the annotation
    await this.storage.storeAnnotation(annotation);

    // Append 'reviewed' custody chain entry to each affected record
    const custodyEntry: CustodyEntry = {
      timestamp: now,
      actor: authorizedBy,
      action: 'reviewed',
      systemId: 'tzun-recovery',
      metadata: {
        incidentId,
        annotationId: annotation.id,
        recoveryTier: 'annotation',
      },
    };

    // Only records that still exist can carry a custody entry; a record named
    // by the incident but since deleted stays in `affectedRecords` (it IS
    // affected) without a write.
    for (const evidenceId of existingRecords) {
      await this.storage.appendCustodyEntry(evidenceId, custodyEntry, { recoveryId: annotation.id });
    }

    // Acknowledge the incident if it is open; an acknowledged or resolved
    // incident keeps its status (the hosted service's rule too).
    // A review never reopens an incident.
    //
    // The status is read again here rather than taken from the read at the
    // top, so a resolve that landed while the custody entries were being
    // written is respected. The storage interface has no conditional update,
    // so a resolve between this read and the write below can still be
    // overwritten.
    //
    // The re-read after the write confirms the store holds the status that
    // annotate() returns, so the result never reports a status the store does
    // not have.
    const beforeUpdate = await this.storage.getIncident(incidentId);
    const expectedStatus = statusAfterReview(beforeUpdate?.status ?? incident.status);
    if (beforeUpdate?.status !== expectedStatus) {
      await this.storage.updateIncidentStatus(incidentId, expectedStatus);
    }
    const updatedIncident = await this.storage.getIncident(incidentId);
    if (updatedIncident?.status !== expectedStatus) {
      throw new Error(
        `Failed to set tamper incident "${incidentId}" to "${expectedStatus}": stored status is ` +
          `"${updatedIncident?.status ?? 'missing'}" after the update.`,
      );
    }

    // Emit event through monitoring event bus
    if (this.eventBus) {
      this.eventBus.emit({
        type: 'incident_annotated' as const,
        incidentId,
        annotationId: annotation.id,
        authorizedBy,
        affectedRecords,
        timestamp: now,
      });
    }

    return {
      annotation,
      updatedIncidentStatus: expectedStatus,
    };
  }

  /**
   * The chain a sequence-shaped incident is about, when it can be known.
   *
   * There is exactly one case where it can: a store with a single chain. Any
   * other store makes the answer a guess, and a wrong guess here writes a
   * 'reviewed' custody entry into the wrong evidence records — so it refuses
   * and asks the operator to name the chain instead.
   */
  private async resolveIncidentChain(incidentId: string): Promise<string> {
    // A store that cannot say which chain takes appends — every chain sealed,
    // or more than one open — is not a single-chain store, so
    // the answer is the same as for a forked one: the caller names the chain.
    const activeChainId = await this.activeChainIdOrNull();
    if (activeChainId === null) {
      throw new Error(
        `Tamper incident "${incidentId}" names a sequence range but no evidence ids, and this store ` +
          'has no single active chain to resolve the range against. Pass options.chainId to say which ' +
          'chain the incident is about -- guessing would append a "reviewed" custody entry to the wrong evidence.',
      );
    }
    let chains: ChainIdentity[];
    try {
      chains = await this.storage.listChains();
    } catch {
      // Adapters that cannot enumerate chains (the HTTP transport refuses
      // listChains outright) cannot have forked through this SDK either, so
      // there is no second chain for the range to collide with.
      return activeChainId;
    }
    const others = chains.filter((c) => c.chainId !== activeChainId);
    if (others.length === 0) return activeChainId;
    throw new Error(
      `Tamper incident "${incidentId}" names a sequence range but no evidence ids, and this store has ` +
        `${chains.length} chains (active: "${activeChainId}"). Sequence numbers restart at 1 per chain, ` +
        'so the range does not identify records on its own. Pass options.chainId to say which chain the ' +
        'incident is about -- guessing would append a "reviewed" custody entry to the wrong evidence.',
    );
  }

  /**
   * The active chain, or null when the store cannot name one.
   *
   * `getActiveChainId()` refuses a store whose every chain is sealed or whose
   * chains include more than one open to appends. An operation
   * whose caller has already named the chain it works on does not need that
   * answer for anything but a bound, so the refusal is not fatal there; an
   * operation that would have to pick the chain itself lets it propagate.
   */
  private async activeChainIdOrNull(): Promise<string | null> {
    try {
      return await this.storage.getActiveChainId();
    } catch (err) {
      if (err instanceof NoActiveChainError || err instanceof AmbiguousActiveChainError) return null;
      throw err;
    }
  }

  /**
   * Highest sequence number `chainId` is known to have reached.
   *
   * Every chain keeps its own head, so this is the chain's own
   * recorded high-water mark, live or sealed. A chain whose state row is gone
   * falls back to the head the seal captured on the fork record
   * (`sealedOldChainHead` — the row count `sealedOldChainLength` is not a
   * sequence), and a chain with neither to the last record actually
   * present in it, the only honest bound left.
   *
   * What it never does is answer with another chain's number: one global
   * counter read for whichever chain is active would make relink() answer
   * questions about one chain with another chain's numbers.
   */
  private async chainHeadSequence(chainId: string): Promise<number> {
    const recorded = await chainUpperBound(this.storage, chainId);
    if (recorded !== undefined) return recorded;
    const present = await this.storage.listBySequence(undefined, undefined, chainId);
    return present.reduce((max, e) => Math.max(max, e.payload.sequenceNumber), 0);
  }

  /**
   * Tier 2: Supervised re-link of chain links.
   *
   * Recomputes `integrity.chainLink` from `fromSequence` forward. Does NOT
   * recompute digests — only chain links change. `correctedPayload` is not
   * implemented and is refused (see the check below).
   *
   * WHAT THE THREE GUARDS ESTABLISH.
   *
   * Three checks run before any link is rewritten, over the range AND the
   * record on either side of it:
   *
   *   1. Every record must hash to its stored `canonicalDigest`. Catches the
   *      cheap rewrite that leaves the digest stale.
   *   2. No record may have both its own link and its successor's
   *      inconsistent — that pattern means a digest was substituted rather
   *      than a link corrupted.
   *   3. No record's current digest may differ from the digest it was
   *      CAPTURED with, as recorded in the append-only revision log. This is
   *      the one that refuses a reseated digest, and it is the only one of the
   *      three that is not computed from the store's present state.
   *
   * Why guard 3 exists. Guards 1 and 2 are satisfiable by construction:
   * rewrite record N's payload, recompute its digest, and repair N's OWN link
   * to H(digest(N-1) ‖ digest'(N)). N then hashes to its stored digest (past
   * guard 1) and only N+1's link is inconsistent, never N's own (past guard
   * 2) — a single broken link, which is exactly what one honestly corrupted
   * link looks like and is the case relink() exists to repair. With guards 1
   * and 2 alone, relink() would rewrite N+1's link to agree with the forged
   * digest, return `chainVerified: true`, and append operator-signed
   * 'relinked' custody entries vouching for the repair: the altered decision
   * would become the record of truth with a signed audit trail saying it had
   * been correctly repaired.
   *
   * No check computed from the store's present state can tell those two cases
   * apart, because they leave the store in the same state. What distinguishes
   * them is history: an honest link corruption leaves the record's digest
   * equal to its capture digest, and a reseat does not. `store()` writes that
   * capture digest as revision 0 of the append-only revision log, and guard 3
   * reads it — so the discrimination the whole feature buys is that an honest
   * single-link corruption still relinks cleanly while the reseat is refused.
   *
   * WHAT IT STILL DOES NOT ESTABLISH. A record captured before 0.3.16 has no
   * revision 0, so guard 3 cannot speak for it — `getCaptureDigests()` leaves
   * it out and it is treated as unprovable, not clean. For those records
   * relink() must only be run after an OUT-OF-BAND determination that the
   * payloads in and adjacent to the range are intact
   * (attestation artifacts still verifying against the stored digests, a
   * pre-incident export or backup that matches, or an equivalent), because
   * "the scanner reports one broken link" is the exact signature the attack
   * produces. When payload integrity cannot be established, fork().
   */
  async relink(
    incidentId: string,
    options: RelinkOptions,
  ): Promise<RelinkResult> {
    if (!options.authorizedBy) {
      throw new Error('authorizedBy is required -- recovery operations require explicit human authorization.');
    }
    if (options.fromSequence < 1) {
      throw new Error('fromSequence must be >= 1.');
    }

    if (options.correctedPayload !== undefined) {
      // Not implemented. Ignoring the option would silently discard the
      // genuine text an operator supplied while the tampered record was
      // re-linked into the chain and the result reported chainVerified: true.
      // Failing loudly is the honest behaviour: relink() never rewrites a
      // payload, and restoring a corrected one is a new record plus an
      // annotation, or a fork.
      throw new Error(
        'correctedPayload is not implemented -- relink() cannot rewrite a payload. ' +
          'Use fork() to seal the compromised chain, or annotate() to document it.',
      );
    }

    const incident = await this.storage.getIncident(incidentId);
    if (!incident) {
      throw new Error(
        `Tamper incident "${incidentId}" not found -- relink() rewrites evidence chain links and ` +
          'must be tied to a real incident.',
      );
    }

    const now = new Date().toISOString();

    // Scope every read to one chain. Sequence numbers restart at 1 per chain,
    // so an unscoped read mixes same-numbered records from different chains:
    // after a fork, a relink meant for the active chain would rewrite a link in
    // the SEALED parent chain and leave the active chain unhealed.
    //
    // When the caller names the chain, the store's own answer is needed only
    // to decide whether the live counter bounds it — so a store that cannot
    // name an active chain does not stop a relink on a chain
    // the operator has named; the bound comes from the fork record or the
    // records present instead. Without options.chainId the store's refusal is
    // the answer: this method will not pick a chain to rewrite links in.
    const chainId = options.chainId ?? (await this.storage.getActiveChainId());

    // Determine the range from THIS chain's head, never another chain's.
    //
    // Defaulting `toSequence` from another chain's head makes relink() report
    // repairs it has not performed. On a store with a sealed six-record chain
    // and a four-record active chain, break at sealed sequence 5,
    // `relink('inc', { fromSequence: 5, chainId: sealed })` with the active
    // chain's head would get toSequence 4: the range 5..4 selects nothing, so
    // nothing is rewritten; the post-relink check walks 1..4 of the sealed
    // chain, which really is intact, and returns true. The operator would be
    // told the chain was repaired, a signed RelinkRecord claiming range 5..4
    // would go into the store, and the break would still be there.
    const chainHead = await this.chainHeadSequence(chainId);
    const toSequence = options.toSequence ?? chainHead;

    // An empty or inverted range cannot repair anything, so it must not be
    // able to report that it did. Failing loudly is the only honest answer
    // here: relink() is the tool an operator reaches for after a chain_break,
    // and "nothing to do, all clear" is precisely the wrong thing to hear.
    if (toSequence < options.fromSequence) {
      throw new Error(
        `Refusing to re-link an empty range: fromSequence ${options.fromSequence} is past the end of ` +
          `chain "${chainId}" (head sequence ${toSequence}). Sequence numbers restart at 1 per chain, ` +
          'so a sequence from one chain does not name a record in another. Pass the chain that owns ' +
          'the record (options.chainId) and a range inside it.',
      );
    }

    // Retrieve all records in the range, plus the record immediately before fromSequence
    // to get the previous digest for chain link computation.
    // Fetch one record beyond the range as well: the successor's chain link is
    // the signal that tells a corrupted link apart from a rewritten digest (see
    // the digest-substitution guard below).
    const startFetch = Math.max(1, options.fromSequence - 1);
    const records = await this.storage.getBySequenceRange(startFetch, toSequence + 1, chainId);

    if (records.length === 0) {
      throw new Error(`No records found in sequence range ${options.fromSequence} to ${toSequence}.`);
    }

    // Sort by sequence number
    records.sort((a, b) => a.payload.sequenceNumber - b.payload.sequenceNumber);

    // Refuse to re-link over a payload that does not hash to its stored digest.
    //
    // Every link below is computed FROM the digest currently stored on the
    // record, and the post-relink check compares links against those same
    // stored digests, so neither hashes a payload. An attacker who edits a
    // decision and recomputes integrity.canonicalDigest to match leaves exactly
    // one trace: the chain_break the scanner reports at that record and the
    // next. Without this check, an operator who then runs "re-link from N"
    // would have relink rewrite both links to agree with the attacker's
    // digest, return chainVerified: true, append 'relinked' custody entries
    // signed by the operator, and hand back a store that scans clean: the
    // altered decision would become the record of truth with an audit trail
    // saying it had been correctly repaired.
    //
    // Hashing the payload is what tells the two cases apart: an honest broken
    // link has intact digests, a laundering attempt does not.
    for (const record of records) {
      const recomputed = this.recomputeDigest(record);
      if (recomputed !== record.integrity.canonicalDigest) {
        throw new Error(
          `Refusing to re-link: evidence record "${record.payload.evidenceId}" at sequence ` +
            `${record.payload.sequenceNumber} does not hash to its stored digest ` +
            `(stored=${record.integrity.canonicalDigest}, recomputed=${recomputed || '<unknown schema>'}). ` +
            'Re-linking would launder a modified payload into a clean-scanning chain. Use fork().',
        );
      }
    }

    // Build the modified links list
    const modifiedLinks: ModifiedLink[] = [];

    // Find the previous digest (record before fromSequence)
    let previousDigest: string | null = null;
    const recordBeforeRange = records.find((r) => r.payload.sequenceNumber === options.fromSequence - 1);
    if (recordBeforeRange) {
      previousDigest = recordBeforeRange.integrity.canonicalDigest;
    }

    // Walk forward from fromSequence, recomputing chain links. The extra
    // look-ahead record fetched above is evidence only — never re-linked.
    const rangeRecords = records.filter(
      (r) =>
        r.payload.sequenceNumber >= options.fromSequence &&
        r.payload.sequenceNumber <= toSequence,
    );

    // Refuse when the break was caused by a SUBSTITUTED DIGEST rather than a
    // corrupted link.
    //
    // Someone with DB write edits a decision and recomputes
    // integrity.canonicalDigest to match, so the digest check above still
    // passes and the only trace is the chain_break the scanner reports.
    // Without this guard relink() would rewrite the links to agree with the
    // attacker's digest, return chainVerified: true, append 'relinked' custody
    // entries signed by the operator, and leave a store that scans clean — the
    // altered decision the record of truth, with an audit trail saying it had
    // been correctly repaired.
    //
    // The two cases are distinguishable, because a chain link is a pairwise
    // function of two digests:
    //   link(N) = H(digest(N-1) || digest(N))
    // Corrupt link(N) alone and link(N+1) — which is built from digest(N) —
    // still verifies. Change digest(N) and BOTH link(N) and link(N+1) break.
    // So "my link is wrong and my successor's link is wrong" means my digest is
    // not the one the chain was built on.
    //
    // Known limits (spelled out in the method comment): two independently
    // corrupted adjacent links are refused (use fork()); a substitution in the
    // chain's last record has no successor to contradict it; and a rewrite
    // that ALSO repairs its own link leaves only the successor's link
    // inconsistent, which this guard cannot tell from an honest single-link
    // corruption. The guard raises the cost of laundering from one UPDATE to
    // a computed one; it is not a proof of payload integrity, and relink()
    // must not be run without one obtained out of band.
    const linkIsValid = new Map<number, boolean>();
    for (let i = 1; i < records.length; i++) {
      const prev = records[i - 1];
      const curr = records[i];
      if (prev.payload.sequenceNumber + 1 !== curr.payload.sequenceNumber) continue;
      const chain = new EvidenceChain();
      chain.restore(prev.integrity.canonicalDigest);
      linkIsValid.set(
        curr.payload.sequenceNumber,
        curr.integrity.chainLink === chain.computeLink(curr.integrity.canonicalDigest),
      );
    }
    for (const record of rangeRecords) {
      const seq = record.payload.sequenceNumber;
      if (linkIsValid.get(seq) === false && linkIsValid.get(seq + 1) === false) {
        throw new Error(
          `Refusing to re-link: the chain link of evidence record "${record.payload.evidenceId}" at ` +
            `sequence ${seq} AND the link of its successor are both inconsistent, which means the ` +
            "record's canonical digest was substituted rather than its link corrupted. Re-linking " +
            'would make a modified decision the record of truth. Use fork().',
        );
      }
    }

    // Refuse to re-link over a record whose payload was REWRITTEN AND RESEATED.
    //
    // This is the attack the two guards above cannot see, because it satisfies
    // both by construction: the attacker rewrites record N's payload,
    // recomputes canonicalDigest so N still hashes to its stored digest, and
    // repairs N's OWN chainLink onto its untouched predecessor so that the
    // only inconsistent link in the chain is N+1's. One broken link and no
    // digest mismatch is precisely the signature of an honest link corruption
    // — the case this method exists to repair — so without this guard
    // relink() would repair it, return chainVerified: true, and append
    // operator-signed 'relinked' custody entries stating the chain had been
    // correctly repaired.
    //
    // The two cases leave the store in the SAME state, so nothing computed
    // from present state separates them. The revision log is the memory that
    // does: `store()` writes the capture digest as revision 0, and a record
    // whose current digest is not that one was rewritten after capture,
    // however consistent its links now look.
    //
    // It runs AFTER the link-pattern guard above, deliberately. A bare digest
    // substitution trips both, and the link-pattern guard's message names the
    // more specific finding; it is also the only one of the two that works on
    // a record captured before 0.3.16, which has no capture revision for this
    // one to read.
    //
    // The scope is the fetched window — [fromSequence-1, toSequence+1] — not
    // just the range being re-linked. A reseat at fromSequence-1 shows up as a
    // broken link at fromSequence, which is what the operator would be
    // relinking from; a reseat at toSequence+1 is the record the last new link
    // is computed against. Both are records this operation would vouch for,
    // so both have to be proven first.
    const captureDigests = await this.storage.getCaptureDigests(
      records.map((r) => r.payload.evidenceId),
    );
    for (const record of records) {
      const captured = captureDigests[record.payload.evidenceId];
      // An absent id has no capture revision (written before 0.3.16). That is
      // unprovable, not clean — the method doc says what an operator must
      // establish out of band for such a record — but it cannot be a refusal
      // here or a migrated store could never be repaired at all.
      if (captured === undefined || captured === record.integrity.canonicalDigest) continue;
      throw new Error(
        `Refusing to re-link: evidence record "${record.payload.evidenceId}" at sequence ` +
          `${record.payload.sequenceNumber} no longer hashes to the digest it was CAPTURED with ` +
          `(captured=${captured}, current=${record.integrity.canonicalDigest}). Its payload was ` +
          'rewritten and its own chain link reseated after capture, which leaves exactly one ' +
          'inconsistent link and is indistinguishable from an honest link corruption without this ' +
          'record. Re-linking would make the rewritten decision the record of truth and sign an ' +
          'operator custody entry vouching for it. Use fork().',
      );
    }

    for (const record of rangeRecords) {
      const currentDigest = record.integrity.canonicalDigest;
      const existingChainLink = record.integrity.chainLink;

      // Compute the correct chain link
      let expectedLink: string | null = null;
      if (previousDigest !== null) {
        const chain = new EvidenceChain();
        chain.restore(previousDigest);
        expectedLink = chain.computeLink(currentDigest);
      }

      // Only record as modified if the chain link actually changed.
      //
      // `previousChainLink`/`newChainLink` are written through as-is, including
      // null. Coercing null to the string "null" would turn "this record had no
      // link" into a four-character value in a stored recovery record -- a
      // misstatement of what the operation found, and the exact value an undo
      // built on `modifiedLinks` would write back into `integrity.chainLink`.
      // Nothing is written here. The link is only RECORDED as modified; the
      // write itself happens below, inside the one transaction that also
      // stores the relink record and the custody entries.
      if (existingChainLink !== expectedLink) {
        modifiedLinks.push({
          evidenceId: record.payload.evidenceId,
          sequenceNumber: record.payload.sequenceNumber,
          previousChainLink: existingChainLink,
          newChainLink: expectedLink,
        });
      }

      // Move forward in the chain
      previousDigest = currentDigest;
    }

    // Create the RelinkRecord
    const relinkRecord: RelinkRecord = {
      id: randomUUID(),
      incidentId,
      relinkedAt: now,
      relinkedBy: options.authorizedBy,
      fromSequence: options.fromSequence,
      toSequence,
      modifiedLinks,
    };

    // Bind every 'relinked' custody entry to the record that authorises it.
    //
    // Each entry names the relink id AND a digest over the relink record's
    // fields. With only the incident id and the range, nothing would tie a
    // rewritten link to the RelinkRecord that claims to describe the rewrite:
    // the RelinkRecord could be swapped or edited afterwards and no envelope
    // would disagree. With the digest, altering `modifiedLinks` after the fact
    // contradicts the custody chains of the very records it names.
    //
    // The digest is computed here, after the loop, because it has to cover the
    // finished record -- `modifiedLinks` is not known until the loop ends.
    const relinkDigest = computeRelinkDigest(relinkRecord);
    const custodyAppends: RelinkCustodyAppend[] = modifiedLinks.map((link) => ({
      evidenceId: link.evidenceId,
      entry: {
        timestamp: now,
        actor: options.authorizedBy,
        action: 'relinked',
        systemId: 'tzun-recovery',
        metadata: {
          incidentId,
          fromSequence: options.fromSequence,
          toSequence,
          recoveryTier: 'relink',
          relinkId: relinkRecord.id,
          relinkDigest,
        },
      } satisfies CustodyEntry,
    }));

    // ONE transaction: the link rewrites, the relink record and the
    // hashed custody entries commit together or not at all.
    //
    // As separate writes in sequence, a crash between the first and the last
    // would leave rewritten links with no record and no custody entry saying
    // who rewrote them. The adapter mints each entry's `entryHash` (chained to
    // the previous custody action on the same record and bound to the record's
    // digest) as part of the same transaction, so the trail can be verified
    // offline from the envelope alone (`verifyEnvelope().custodyTrailValid`),
    // and removing a `relinked` entry breaks the trail rather than leaving a
    // record that presents as never repaired.
    await this.storage.applyRelink(relinkRecord, custodyAppends);

    // Verify the chain after re-linking.
    //
    // Over the WHOLE chain, not just the re-linked range. `chainVerified` is
    // read as "the chain is sound again"; bounding it by `toSequence` would
    // make it an answer about the range the operator happened to name, so a
    // break one record past the end of that range would come back as
    // chainVerified: true.
    let chainVerified = true;
    const verifyTo = Math.max(chainHead, toSequence);
    const allRecords = await this.storage.getBySequenceRange(1, verifyTo, chainId);
    allRecords.sort((a, b) => a.payload.sequenceNumber - b.payload.sequenceNumber);
    for (let i = 1; i < allRecords.length; i++) {
      const prev = allRecords[i - 1];
      const curr = allRecords[i];
      const chain = new EvidenceChain();
      chain.restore(prev.integrity.canonicalDigest);
      const expectedLink = chain.computeLink(curr.integrity.canonicalDigest);
      if (curr.integrity.chainLink !== expectedLink) {
        chainVerified = false;
        break;
      }
    }

    // Emit event through monitoring event bus
    if (this.eventBus) {
      this.eventBus.emit({
        type: 'chain_relinked' as const,
        incidentId,
        relinkId: relinkRecord.id,
        fromSequence: options.fromSequence,
        toSequence,
        authorizedBy: options.authorizedBy,
        modifiedCount: modifiedLinks.length,
        timestamp: now,
      });
    }

    return {
      relink: relinkRecord,
      chainVerified,
    };
  }

  /**
   * Tier 3: Fork the chain.
   *
   * Seals the old chain and creates a new one starting with sequenceNumber 1.
   */
  async fork(
    incidentId: string,
    options: ForkOptions,
  ): Promise<ForkResult> {
    if (!options.authorizedBy) {
      throw new Error('authorizedBy is required -- recovery operations require explicit human authorization.');
    }
    if (!options.reason) {
      throw new Error('reason is required -- fork operations must include an explanation.');
    }
    if (options.forkAfterSequence < 0) {
      throw new Error('forkAfterSequence must be >= 0.');
    }

    const now = new Date().toISOString();

    // Determine the current active chain.
    //
    // The chain we seal has to be the one that OWNS the records. Every SDK
    // capture stores under `activeChainId`, which is 'default' until something
    // creates a chain identity, so in that case 'default' itself is sealed. It
    // is a real chain id — the one in `recordChainMap` / the `chain_id` column
    // on every one of those rows — so the sealed identity owns its records and
    // the sealed-chain append guard in each adapter's store() covers them.
    // Sealing a freshly minted id instead would seal an empty name: no record
    // is associated with it, so its length would be 0, every pre-fork record
    // would still report 'default', and nothing would stop further appends to
    // the chain the operator had been told was sealed.
    const oldChainId = await this.storage.getActiveChainId();

    // Materialise the identity if the chain has been implicit until now. This
    // is the 'default' case, and after it 'default' is a first-class chain.
    const existingOldChain = await this.storage.getChain(oldChainId);
    if (!existingOldChain) {
      await this.storage.storeChain({
        chainId: oldChainId,
        status: 'active',
        createdAt: now,
      });
    }

    // Generate new chain ID
    const newChainId = 'chain-' + randomUUID().split('-')[0];

    // Seal the old chain FIRST. Every number the fork record keeps about it
    // is read after this line, on purpose — see the head read below.
    await this.storage.sealChain(oldChainId, now);

    // Get the total length of the old chain. Scoped to the chain being sealed:
    // passing `undefined` would count every record in the store, so
    // `sealedOldChainLength` would be wrong as soon as a second chain exists.
    const oldChainLength = await this.storage.getChainLength(oldChainId);

    // Record the sealed chain's HEAD — its highest sequence number — as well.
    //
    // `oldChainLength` is a row count. Handed by `chainUpperBound()` to every
    // verifier as the sealed chain's sequence upper bound, it would be right
    // only while the chain has no gaps. A sealed chain with one gap — a
    // deleted record, as in any store that has already lost a record, i.e. the
    // store that gets forked — would have a bound one short of its real head,
    // so its last record would sit outside every range relink(),
    // verifyChainCompleteness() and the scanner walk, and deleting that record
    // would be undetectable.
    //
    // Read AFTER sealChain(). Every adapter's store() refuses an append to a
    // sealed chain from inside its own write transaction, so once the seal is
    // written nothing can land at head+1 and a read here is exact. Reading it
    // BEFORE the seal would leave a window in which the old chain was still
    // active and still taking appends from any other client of the store (a
    // second process, a stale one holding the old chain id); a capture that
    // landed there would sit one above the recorded head, outside every
    // sealed-chain range, and deleting it would be undetectable: the same
    // hole, for one record (tests/ts/sealed-chain-head-read-after-seal.test.ts).
    //
    // The counter is read FOR THIS CHAIN, and nothing resets it:
    // chain state is per chain, so the sealed chain keeps its own head for good
    // and forking never loosens what is checked — a tail deleted before the fork
    // stays missing after it. The highest sequence actually present is folded in
    // so a counter that has fallen behind the records cannot pull the bound
    // below a record that is demonstrably there. Neither number overstates the
    // head.
    const presentInOldChain = await this.storage.listBySequence(undefined, undefined, oldChainId);
    const oldChainHead = presentInOldChain.reduce(
      (max, e) => Math.max(max, e.payload.sequenceNumber),
      await this.storage.getLastSequence(oldChainId),
    );

    // The digest of the record at that head, which each 'chain_forked' custody
    // entry carries with the head so the seal bound is inside the hashed entry
    // and checkable offline from an export. It is the head record's own
    // canonicalDigest when the record is present. When it is not (a tail
    // deleted before the fork) it is the sealed chain's own last digest, read
    // here, at the same point as the head: that digest pairs with
    // getLastSequence(oldChainId) and belongs to this chain permanently. null
    // only when neither exists.
    const oldChainHeadDigest =
      presentInOldChain.find((e) => e.payload.sequenceNumber === oldChainHead)?.integrity.canonicalDigest ??
      (await this.storage.getLastDigest(oldChainId)) ??
      null;

    // Create the new chain identity
    const newChain: ChainIdentity = {
      chainId: newChainId,
      parentChainId: oldChainId,
      forkPoint: options.forkAfterSequence,
      status: 'active',
      createdAt: now,
    };
    await this.storage.storeChain(newChain);

    // Create the fork record
    const forkRecord: ForkRecord = {
      id: randomUUID(),
      incidentId,
      forkedAt: now,
      forkedBy: options.authorizedBy,
      reason: options.reason,
      oldChainId,
      newChainId,
      forkAfterSequence: options.forkAfterSequence,
      sealedOldChainLength: oldChainLength,
      sealedOldChainHead: oldChainHead,
    };
    await this.storage.storeFork(forkRecord);

    // Append 'chain_forked' custody entries to records after the fork point.
    //
    // Scoped to the chain being sealed. Sequence numbers restart at 1 per
    // chain, so an unscoped read on the SECOND fork of a store would also match
    // the same-numbered records of the chain the FIRST fork had already sealed:
    // with two four-record chains and forkAfterSequence 2, records 3 and 4 of
    // the first sealed chain would get a 'chain_forked' entry for the second
    // fork — `{oldChainId: chain-A, newChainId: chain-B, incidentId: inc-b}` —
    // naming a fork of a chain they were never part of. Custody entries are
    // part of the evidence envelope, so that would be a false custody event
    // written into evidence, the same defect class annotate() guards against
    // above.
    //
    // The sealed chain's own counter, for the reason it is right for the head
    // read above: the chain is sealed, so the counter cannot advance, and
    // per-chain state means nothing else resets it.
    const lastSequence = await this.storage.getLastSequence(oldChainId);
    if (options.forkAfterSequence < lastSequence) {
      const affectedRecords = await this.storage.getBySequenceRange(
        options.forkAfterSequence + 1,
        lastSequence,
        oldChainId,
      );

      const custodyEntry: CustodyEntry = {
        timestamp: now,
        actor: options.authorizedBy,
        action: 'chain_forked',
        systemId: 'tzun-recovery',
        metadata: {
          incidentId,
          forkId: forkRecord.id,
          oldChainId,
          newChainId,
          forkAfterSequence: options.forkAfterSequence,
          recoveryTier: 'fork',
          sealedOldChainHead: oldChainHead,
          sealedOldChainHeadDigest: oldChainHeadDigest,
        },
      };

      for (const record of affectedRecords) {
        await this.storage.appendCustodyEntry(record.payload.evidenceId, custodyEntry, {
          recoveryId: forkRecord.id,
        });
      }
    }

    // Emit event through monitoring event bus
    if (this.eventBus) {
      this.eventBus.emit({
        type: 'chain_forked' as const,
        incidentId,
        forkId: forkRecord.id,
        oldChainId,
        newChainId,
        forkPoint: options.forkAfterSequence,
        authorizedBy: options.authorizedBy,
        timestamp: now,
      });
    }

    // Retrieve the sealed old chain identity
    const oldChain = await this.storage.getChain(oldChainId);

    return {
      fork: forkRecord,
      oldChain: oldChain!,
      newChain,
    };
  }

  /**
   * Recompute a record's canonical digest from its payload.
   *
   * Returns '' when the schema version is not in the registry — itself a
   * mismatch, since the registry only ever contains the active versions.
   */
  private recomputeDigest(envelope: EvidenceEnvelope): string {
    const schema = this.registry.get(envelope.payload.schemaVersion);
    if (!schema) return '';
    // A payload the canonical serializer refuses (lone UTF-16 surrogate,
    // nesting past MAX_DEPTH, non-finite number) has no recomputable digest,
    // which is the same finding as an unknown schema version and gets the same
    // ''. The relink pre-check above then refuses to re-link
    // with its own typed, explanatory Error naming the record — instead of the
    // serializer's TypeError escaping `relink()` and telling an operator
    // nothing about which record stopped the repair.
    try {
      return computeDigest(
        canonicalSerialize(
          envelope.payload as unknown as Record<string, unknown>,
          schema.hashedFieldSet,
        ),
      );
    } catch {
      return '';
    }
  }
}
