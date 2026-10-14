import { canonicalSerialize } from './canonical';
import { computeDigest } from './digest';
import { EvidenceChain } from './evidence-chain';
import { verifyCustodyTrail } from './custody-hash';
import { toCustodyLedgerEntry, verifyCustodyLedger } from './custody-ledger';
import { SchemaRegistry } from './schema-registry';
import { StorageAdapter } from './types/storage-interface';
import { EvidenceEnvelope } from './types/evidence';

/**
 * Used when a caller passes no registry. The digest check is not optional, so
 * it cannot be conditional on the caller having supplied one.
 */
const defaultRegistry = new SchemaRegistry();

/** Result of a chain completeness verification. */
/** Backwards movement smaller than this is treated as clock jitter, not a regression. */
export const DEFAULT_CAPTURED_AT_TOLERANCE_MS = 1000;

export interface ChainCompletenessResult {
  /**
   * Whether the chain is fully valid: no gaps, no duplicate or backwards
   * sequence numbers, no broken links, every record still hashing to its own
   * stored digest, no record superseded since capture, and, when the walk was
   * given the chain's evidence log, every record still the leaf it was logged
   * as. All of them, ANDed.
   */
  valid: boolean;
  /** Total number of records inspected. */
  totalRecords: number;
  /** Sequence numbers that are missing (gaps where a record was deleted). */
  sequenceGaps: number[];
  /**
   * Sequence numbers that repeat, or move backwards from, the record listed
   * before them.
   *
   * A record here is an EXTRA record occupying a position the chain already
   * has — the mid-chain-insertion shape. `chainLink` is not part of the hashed
   * field set, so an attacker with store-write access can append a forged
   * envelope reusing an existing sequence number, link it to the honest record
   * it shadows, and leave every canonicalDigest, RFC 3161 token and Merkle
   * anchor on the real records intact.
   */
  duplicateSequences: number[];
  /** Evidence IDs of records whose chain link does not match the expected value. */
  brokenLinks: string[];
  /**
   * Evidence IDs of records that do not hash to their own stored
   * `integrity.canonicalDigest` — the payload was rewritten.
   *
   * This is the cheapest attack on an evidence store and it was the only one
   * the other three checks could not see. `sequenceGaps`, `duplicateSequences`
   * and `brokenLinks` are all computed over DIGESTS, and the naive rewrite
   * leaves every digest stale rather than recomputed: no sequence number
   * moves, every `chainLink` still equals SHA-256(prevDigest ‖ curDigest), and
   * the walk reported `valid: true` on a chain holding a forged record. The
   * other three attacks all require the attacker to add or remove a row; this
   * one requires neither.
   *
   * An unrecognised `payload.schemaVersion` lands here too. schemaVersion is
   * not in v1.0's hashed field set, so store-write access can set it to
   * anything for free — treating an unknown version as "unverifiable,
   * therefore silent" would sell the attacker the same silence back for one
   * extra UPDATE. `VerifyingStorageProxy.quickVerify` takes the same
   * position.
   */
  digestMismatches: string[];
  /**
   * Evidence IDs whose CURRENT `canonicalDigest` is not the one they were
   * CAPTURED with — the payload was rewritten and the digest recomputed to
   * match.
   *
   * This is the one finding that is not computed from the store's present
   * state alone: it compares each record against its `revisionNo: 0` row in
   * the append-only revision log. That matters because the rewrite-and-reseat
   * attack is invisible to every other check here by construction — the
   * rewritten record hashes to its stored digest (so it is not a
   * `digestMismatch`), its own link is repaired onto its predecessor (so it
   * is not a `brokenLink`), and only its SUCCESSOR's link is inconsistent,
   * which is indistinguishable from one honestly corrupted link. A record
   * listed here is superseded REGARDLESS of link consistency.
   *
   * Records captured by an SDK older than 0.3.16 have no capture revision and
   * can never appear here. Their absence is "unprovable", not "clean".
   *
   * ScheduledScanner reports each one as a `digest_superseded` event, at
   * critical severity, counted in the pass's `issuesFound`.
   *
   * `valid` ANDs this field in, so a chain holding a superseded record
   * reports `valid: false`. A client that explains a red `valid` by listing
   * sequenceGaps / duplicateSequences / brokenLinks / digestMismatches alone
   * will show an unexplained red until it reads this array.
   */
  digestSuperseded: string[];
  /**
   * Evidence IDs whose `capturedAt` predates the record before them in the
   * chain — the capturing clock moved backwards between two appends.
   *
   * This closes the half the RFC 3161 token structurally CANNOT. A token proves
   * an UPPER bound ("this digest existed no later than genTime"), which can
   * never contradict a claim of EARLIER creation — and backdating is the
   * direction with legal value. Chain order is the independent constraint:
   * records are appended in sequence, so a later record should not claim an
   * earlier instant. It also needs no TSA, so it still works in dev mode,
   * through a TSA outage, and on records with no attestation at all — which is
   * where the exposure is widest.
   *
   * DELIBERATELY NOT PART OF `valid`. A regression is suspicious, not proof: an
   * NTP correction produces one honestly. And `capturedAt` is in the hashed
   * field set, so a chain condemned for a clock blip could never be repaired —
   * nothing can restamp a record without breaking every digest over it.
   *
   * ScheduledScanner reports each one as a `captured_at_regression` event, at
   * warning severity, and does not count it in the pass's `issuesFound`.
   */
  timeRegressions: string[];
  /**
   * Evidence IDs whose custody trail failed verification: the
   * hashed entries recording who relinked, forked or reviewed the record,
   * checked from the envelope (`verifyCustodyTrail`) and against the store's
   * `custody_entries` ledger (`verifyCustodyLedger`), which is what catches
   * the deletion of the last entry. `custodyChain` is outside the hashed field
   * set, so no other check here can see an altered custody entry.
   *
   * NOT PART OF `valid`, for now. Whether an altered custody trail makes a
   * chain invalid is a decision for the consumers of `valid` — a `valid:
   * false` beside empty gap, link and digest lists would be a new shape for
   * them — so the finding is reported and the verdict left as it was.
   *
   * ScheduledScanner reports each one as a `custody_trail_invalid` event, at
   * critical severity, from its Phase 1.
   */
  custodyTrailInvalid: string[];
  /**
   * Evidence IDs whose `canonicalDigest` is not the leaf the chain's evidence
   * log holds at their position (`digest_differs_from_logged_leaf`). The
   * leaf is written once, inside the transaction that stored the record,
   * and the log is insert-only, so a
   * record that no longer matches it was rewritten after it was logged. That
   * includes the rewrite-and-reseat attack on a record whose capture revision
   * is gone, and a record deleted and stored again at its position.
   *
   * Present only when the walk was given the chain's evidence log
   * (`ChainCompletenessOptions.evidenceLog`); absent means not checked.
   * `valid` ANDs it in. A position the log has no leaf for is not a finding
   * here: the log is dense from 0, and a missing position is a gap.
   */
  digestDiffersFromLoggedLeaf?: string[];
  /**
   * Evidence IDs that carry no `nonRepudiation.anchor` although their
   * position lies in an epoch whose fill the store has finished
   * (`anchor_stripped`). The fill writes each record of the epoch
   * once and never revisits a finished range, so a record there without an
   * anchor had it removed.
   *
   * Present only when the walk was given the chain's evidence log. NOT PART
   * OF `valid`: the record's own content is intact, and what was removed is
   * an attestation of it, as with `custodyTrailInvalid`.
   */
  anchorStripped?: string[];
  /** Sequence number of the first record inspected, or null if empty. */
  firstRecord: number | null;
  /** Sequence number of the last record inspected, or null if empty. */
  lastRecord: number | null;
  /**
   * The chain these fields describe, or null when the walk was not scoped to a
   * chain.
   *
   * A store that has forked holds more than one chain, and `recovery.fork()`
   * restarts sequence numbering at 1 for the new chain. An unscoped walk
   * therefore interleaves two chains into one sequence order and reports the
   * collisions as `duplicateSequences` and the chain-boundary crossings as
   * `brokenLinks` — a false alarm on an untampered store. Every result
   * names the chain it is an answer about, so a caller can never mistake a
   * single-chain answer for a whole-store one.
   */
  chainId: string | null;
}

/**
 * Completeness across every chain in a store, for stores that have forked.
 *
 * `active` is the answer for the chain that is currently being appended to —
 * the same shape a single-chain store returns — and `chains` carries one entry
 * per chain, sealed ones included. `valid` is the AND over `chains`: a sealed
 * chain is the read-only remainder of a fork and is exactly where an insider
 * would tamper, so it must not drop out of the answer.
 */
export interface MultiChainCompletenessResult {
  /** True only when EVERY chain in the store verifies clean. */
  valid: boolean;
  /** The chain currently accepting appends. */
  activeChainId: string;
  /** Completeness of the active chain. */
  active: ChainCompletenessResult;
  /** One result per chain in the store, active and sealed alike. */
  chains: ChainCompletenessResult[];
}

/** One leaf of a chain's evidence log, as the walk reads it. */
export interface EvidenceLogLeaf {
  /** `sequenceNumber − 1` of the record the leaf was logged for. */
  leafIndex: number;
  /** The digest the record was logged with, 64 lowercase hex. */
  leafDigest: string;
}

/**
 * A chain's evidence log (Tree §5.2), as the walk reads it for checks 7 and 8,
 * the logged leaf and the anchor fill. The store provides it: the engine holds
 * no log.
 */
export interface ChainEvidenceLog {
  /** The leaves with `fromIndex <= leafIndex < toIndex`, in index order. */
  leaves(fromIndex: number, toIndex: number): Promise<EvidenceLogLeaf[]>;
  /**
   * Whether the store has finished filling `nonRepudiation.anchor` into the
   * records of the epoch that anchors leaf `leafIndex`. Asked only about
   * records that carry no anchor.
   */
  anchorFillDone(leafIndex: number): Promise<boolean>;
}

/** Options for scoping chain completeness verification to a range. */
export interface ChainCompletenessOptions {
  /**
   * The chain's evidence log. Given, the walk also reports
   * `digestDiffersFromLoggedLeaf` and `anchorStripped`; absent, it reports
   * neither. Requires `chainId`, because a log belongs to one chain.
   */
  evidenceLog?: ChainEvidenceLog;
  /**
   * How far `capturedAt` may move backwards between consecutive records before
   * it is reported in {@link ChainCompletenessResult.timeRegressions}.
   * Default: {@link DEFAULT_CAPTURED_AT_TOLERANCE_MS}.
   *
   * The allowance exists for ordinary clock jitter, not for a meaningful
   * backward jump. Raising it hides exactly the signal this check exists for.
   */
  capturedAtToleranceMs?: number;
  /** Start of the sequence range (inclusive). */
  fromSequence?: number;
  /** End of the sequence range (inclusive). */
  toSequence?: number;
  /**
   * Restrict the walk to a single chain.
   *
   * Required for any store that has forked: sequence numbers are unique only
   * WITHIN a chain, so an unscoped walk over a multi-chain store is not a
   * chain walk at all. See `ChainCompletenessResult.chainId`.
   */
  chainId?: string;
}

/**
 * Verify the completeness AND the content of the evidence chain.
 *
 * Retrieves records in sequence order and checks for:
 * 1. Sequence gaps — missing sequence numbers indicate deleted records.
 * 2. Duplicate or backwards sequence numbers — an extra record sitting at a
 *    position the chain already occupies indicates insertion.
 * 3. Broken chain links — a record whose chainLink does not match
 *    SHA-256(previousDigest + currentDigest) indicates tampering.
 * 4. Digest mismatches — a record that does not hash to its own stored
 *    `canonicalDigest` had its payload rewritten.
 *
 * Check 4 is not optional and has no opt-out, deliberately.
 *
 * Checks 1-3 are all computed over digests, so the naive payload rewrite —
 * change `reason`, leave `canonicalDigest` stale — is invisible to every
 * one of them, and this function answered `valid: true` for a chain holding a
 * forged record. It is also the cheapest of the four attacks: the other three
 * require the attacker to add or remove a row, this one needs a single UPDATE.
 * A flag that could switch check 4 off would put that answer back within reach
 * of a config file, and the caller who most needs the check is exactly the one
 * who would set the flag for latency. A caller who wants digests without the
 * chain walk already has `ScheduledScanner` with `verifyChainCompleteness:
 * false`: its Phase 1 recomputes every digest on its own, and its chain phase —
 * which is this function — is what that flag switches off. This function is
 * the one-call, one-answer surface and its answer has to be true.
 *
 * COST. Check 4 adds one `canonicalSerialize` + SHA-256 per record. Measured
 * on the SQLite adapter, mean of 5 runs: 3.1 ms at 250 records, 32.7 ms at
 * 2 000, 205 ms at 20 000 — linear, ~10-16 µs per record, dominated by the
 * canonical serialization rather than by the hash. That is roughly 2.4x the
 * cost of the walk without it, and it does not change the complexity class:
 * this function materialises every record in the chain, unpaged, which is the
 * dominant structural cost and is O(n) regardless. A caller who can afford to
 * load the chain can afford to hash it. `verifyEnvelope`, the per-record
 * public verifier, recomputes the digest too; a chain-level verifier weaker
 * per record than the record-level one would be a surprise.
 *
 * The custody check (`custodyTrailInvalid`) reads the ledger with one
 * `listCustodyEntries` call per record, because the storage interface has no
 * batch form of it. On a remote Postgres that is one round trip per record.
 *
 * Given the chain's evidence log (`options.evidenceLog`), the walk also
 * compares each record with the leaf logged at its position
 * (`digestDiffersFromLoggedLeaf`) and reports each record with no anchor in
 * an epoch whose fill has finished (`anchorStripped`).
 * That costs one read of the leaves over the walked range, one fill question
 * per record that carries no anchor, and one `retrieve()` of each such record
 * whose fill is done, which is reported only if it still has no anchor.
 *
 * @param storage - Storage adapter to retrieve records from.
 * @param registry - Schema registry supplying the hashed field set for check 4
 *   (defaults to the v1.0 registry).
 * @param options - Optional range to scope the verification.
 */
export async function verifyChainCompleteness(
  storage: StorageAdapter,
  registry?: SchemaRegistry,
  options?: ChainCompletenessOptions,
): Promise<ChainCompletenessResult> {
  const chainId = options?.chainId ?? null;

  const records = await storage.listBySequence(
    options?.fromSequence,
    options?.toSequence,
    options?.chainId,
  );

  // No early return for an empty range. With no `toSequence` an empty range is
  // an empty chain and every check below finds nothing. With one, the bound says
  // the chain reached that far, so the trailing-gap check at the end reports
  // every position in the range as missing — the chain whose every record was
  // deleted. Returning `valid: true, totalRecords: 0` here would let a wiped
  // chain read as a clean one.
  const sequenceGaps: number[] = [];
  const duplicateSequences: number[] = [];
  const brokenLinks: string[] = [];
  const digestMismatches: string[] = [];
  const digestSuperseded: string[] = [];
  const timeRegressions: string[] = [];
  const capturedAtTolerance = options?.capturedAtToleranceMs ?? DEFAULT_CAPTURED_AT_TOLERANCE_MS;
  let previousCapturedMs: number | null = null;
  const schemas = registry ?? defaultRegistry;

  // Determine the expected starting sequence number.
  // If fromSequence is specified, gaps before the first returned record are reported.
  // Otherwise the caller means "the whole chain", so the baseline is genesis (1) —
  // NOT the first surviving record. Baselining on records[0] made head truncation
  // undetectable: deleting records 1..N moved the baseline along with them, so no
  // gaps were emitted and the chain reported valid. The earliest records are the
  // ones establishing who configured the system and what the first decisions were,
  // so that is precisely the deletion this function must catch.
  let expectedSeq = options?.fromSequence ?? 1;
  let previousSeq: number | null = null;

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    // Defensive reads throughout this loop. A chain walk is a
    // verifier: it is handed whatever the store holds, and on a platform the
    // store holds what clients sent. A record with no `payload` key threw
    // `TypeError: Cannot read properties of undefined` and took the whole walk
    // down, so one malformed row made every other row in the chain
    // unverifiable rather than making itself a finding.
    const payload = (record?.payload ?? {}) as EvidenceEnvelope['payload'];
    const integrity = (record?.integrity ?? {}) as EvidenceEnvelope['integrity'];
    const currentSeq = payload.sequenceNumber;

    // Detect duplicates / backwards steps. Gap detection alone only ever fired
    // when currentSeq was AHEAD of the baseline, so a record whose sequence
    // number equalled or undercut its predecessor's was accepted in silence and
    // then moved the baseline backwards with it. That is what let a forged
    // envelope be appended under an already-used sequence number — reusing the
    // head's number needs no rewrites at all, and chain_state.last_sequence is
    // untouched because the upsert takes MAX().
    if (previousSeq !== null && currentSeq <= previousSeq) {
      duplicateSequences.push(currentSeq);
    } else {
      // Detect gaps: any expected sequence numbers before the current one are missing.
      while (expectedSeq < currentSeq) {
        sequenceGaps.push(expectedSeq);
        expectedSeq++;
      }
    }

    // Validate chain link.
    if (i === 0) {
      // For the first record in our range, if it is the genesis record
      // (sequenceNumber 1), chainLink must be null.
      // We perform this check when fromSequence is absent OR when it is
      // explicitly 1 — both mean "start from the beginning of the chain".
      // For paginated ranges that start after genesis (fromSequence > 1),
      // we cannot validate the first record's chain link without the preceding
      // record, so we skip it.
      const startingFromGenesis = options?.fromSequence == null || options.fromSequence === 1;
      if (currentSeq === 1 && startingFromGenesis) {
        if (integrity.chainLink !== null) {
          brokenLinks.push(payload.evidenceId);
        }
      }
    } else {
      // For subsequent records, verify chainLink = SHA-256(prevDigest + curDigest).
      const prevDigest = records[i - 1]?.integrity?.canonicalDigest;
      const chain = new EvidenceChain();
      chain.restore(typeof prevDigest === 'string' ? prevDigest : '');
      const expectedLink = chain.computeLink(
        typeof integrity.canonicalDigest === 'string' ? integrity.canonicalDigest : '',
      );

      if (integrity.chainLink !== expectedLink) {
        brokenLinks.push(payload.evidenceId);
      }
    }

    // Recompute the payload digest. Everything above this line reads digests;
    // nothing above it asks whether a digest is still true of the bytes it
    // claims to cover, which is why a rewritten payload walked through clean.
    const schema = schemas.get(payload.schemaVersion);
    if (!schema) {
      // No serialization rules, so nothing can be recomputed — and that is a
      // finding, not an exemption. The registry only ever holds v1.0 and
      // schemaVersion is outside the hashed field set, so any other value is
      // itself evidence of an edit.
      digestMismatches.push(payload.evidenceId);
    } else {
      // canonicalSerialize throws by design on a payload it cannot render
      // injectively (a lone UTF-16 surrogate — which JSON.stringify preserves
      // as \ud800 straight into the store — nesting past MAX_DEPTH, a
      // non-finite number). For a WRITER that is the right refusal; here it
      // aborted the walk over every OTHER record in the chain. A record that
      // cannot be canonicalized cannot hash to its stored digest, so it is a
      // digest mismatch, exactly like the unknown-schema case above.
      let recomputed: string | null = null;
      try {
        recomputed = computeDigest(
          canonicalSerialize(
            payload as unknown as Record<string, unknown>,
            schema.hashedFieldSet,
          ),
        );
      } catch {
        recomputed = null;
      }
      if (recomputed === null || recomputed !== integrity.canonicalDigest) {
        digestMismatches.push(payload.evidenceId);
      }
    }

    // Clock monotonicity along the chain. An unreadable capturedAt is NOT a
    // regression — it is a different defect, and digestMismatches owns a
    // payload that does not hash to its own digest. Skipping it here also
    // means one bad value cannot mask a real regression on the record after
    // it, because the comparison baseline only advances on a readable one.
    const capturedRaw = record.payload?.capturedAt;
    const capturedMs = typeof capturedRaw === 'string' ? Date.parse(capturedRaw) : NaN;
    if (!Number.isNaN(capturedMs)) {
      if (previousCapturedMs !== null && capturedMs < previousCapturedMs - capturedAtTolerance) {
        timeRegressions.push(record.payload.evidenceId);
      }
      previousCapturedMs = capturedMs;
    }

    previousSeq = currentSeq;
    // Never let the baseline move backwards: a duplicate or out-of-order record
    // would otherwise re-open sequence numbers that were already accounted for
    // and fabricate gaps for every record after it.
    if (currentSeq + 1 > expectedSeq) {
      expectedSeq = currentSeq + 1;
    }
  }

  // Check 5: is every record still the one that was CAPTURED?
  //
  // Checks 1-4 are all answers about the store's present state, and the
  // rewrite-and-reseat attack is built to satisfy all four: the rewritten
  // record hashes to its (recomputed) stored digest, and its own chainLink is
  // repaired onto its untouched predecessor, so only the SUCCESSOR's link is
  // off — one inconsistent link, which is exactly what one honestly corrupted
  // link looks like. No check computed from present state can tell those two
  // apart; that is why relink() laundered the attack and signed off on it.
  //
  // The revision log is the memory that makes them distinguishable. One
  // indexed batch read of the capture revisions, then an O(1) comparison per
  // record: the walk already materialises every record, so this adds one
  // query and no complexity class.
  const captureDigests =
    records.length > 0 && typeof storage.getCaptureDigests === 'function'
      ? await storage.getCaptureDigests(records.map((r) => r.payload.evidenceId))
      : {};
  for (const record of records) {
    const captured = captureDigests[record.payload.evidenceId];
    // An absent id is a record with no capture revision (written before
    // 0.3.16). Unprovable, not clean — and deliberately not reported as a
    // finding, or every record in a migrated store would be one.
    if (captured !== undefined && captured !== record.integrity.canonicalDigest) {
      digestSuperseded.push(record.payload.evidenceId);
    }
  }

  // Check 6: is every record's custody trail intact? From the
  // envelope, and against the ledger when the store keeps one. An adapter that
  // cannot read the ledger — the platform's chain-scoped scanner view stubs
  // `listCustodyEntries` to throw, and checks custody in its own chain-status
  // read — gets the envelope check alone, for the rest of the walk, rather
  // than a walk that throws.
  const custodyTrailInvalid: string[] = [];
  let ledgerReadable = typeof storage.listCustodyEntries === 'function';
  for (const record of records) {
    const evidenceId = record?.payload?.evidenceId;
    let invalid = verifyCustodyTrail(record).valid === false;
    if (ledgerReadable && typeof evidenceId === 'string') {
      try {
        const rows = await storage.listCustodyEntries(evidenceId);
        const ledger = verifyCustodyLedger(evidenceId, record, undefined, rows.map(toCustodyLedgerEntry));
        if (!ledger.valid) invalid = true;
      } catch {
        ledgerReadable = false;
      }
    }
    if (invalid) custodyTrailInvalid.push(evidenceId);
  }

  // Check trailing gaps if toSequence is specified.
  if (options?.toSequence != null) {
    while (expectedSeq <= options.toSequence) {
      sequenceGaps.push(expectedSeq);
      expectedSeq++;
    }
  }

  // Checks 7 and 8, the logged leaf and the anchor fill, against the chain's
  // evidence log when the caller supplies it.
  const logFindings =
    options?.evidenceLog && options.chainId !== undefined ? await checkEvidenceLog(storage, records, options.evidenceLog) : null;

  return {
    valid:
      sequenceGaps.length === 0 &&
      duplicateSequences.length === 0 &&
      brokenLinks.length === 0 &&
      digestMismatches.length === 0 &&
      digestSuperseded.length === 0 &&
      (logFindings?.digestDiffersFromLoggedLeaf.length ?? 0) === 0,
    totalRecords: records.length,
    sequenceGaps,
    duplicateSequences,
    brokenLinks,
    digestMismatches,
    digestSuperseded,
    timeRegressions,
    custodyTrailInvalid,
    ...(logFindings ?? {}),
    // a stored row whose payload is not an object must be a verdict, not
    // a TypeError out of the verifier, hence the optional chaining.
    firstRecord: records[0]?.payload?.sequenceNumber ?? null,
    lastRecord: records[records.length - 1]?.payload?.sequenceNumber ?? null,
    chainId,
  };
}

/**
 * Checks 7 and 8 over the records the walk read: each
 * record's digest against the leaf its chain's evidence log holds at its
 * position, and each record that carries no anchor against the fill.
 *
 * A record is judged at the position its hashed `sequenceNumber` names, so a
 * duplicate is judged against the same leaf as the record it shadows, and a
 * record whose sequence number is not a positive integer names no position.
 *
 * A record read without an anchor is read again once its epoch's fill is
 * known to be done, and reported only if it still has none. The fill writes
 * its last chunk and marks the epoch done in one transaction, so a record the
 * walk read just before that commit carries its anchor by the time the fill
 * reads as done.
 */
/** Whether a record carries `nonRepudiation.anchor`. */
function hasAnchor(record: EvidenceEnvelope): boolean {
  const anchor = (record?.nonRepudiation as { anchor?: unknown } | null | undefined)?.anchor;
  return anchor !== undefined && anchor !== null;
}

async function checkEvidenceLog(
  storage: StorageAdapter,
  records: EvidenceEnvelope[],
  log: ChainEvidenceLog,
): Promise<{ digestDiffersFromLoggedLeaf: string[]; anchorStripped: string[] }> {
  const digestDiffersFromLoggedLeaf: string[] = [];
  const anchorStripped: string[] = [];
  const positionOf = (record: EvidenceEnvelope): number | null => {
    const seq: unknown = record?.payload?.sequenceNumber;
    return typeof seq === 'number' && Number.isSafeInteger(seq) && seq >= 1 ? seq - 1 : null;
  };

  let from = Number.POSITIVE_INFINITY;
  let to = -1;
  for (const record of records) {
    const at = positionOf(record);
    if (at === null) continue;
    if (at < from) from = at;
    if (at > to) to = at;
  }
  if (to < 0) return { digestDiffersFromLoggedLeaf, anchorStripped };

  const logged = new Map<number, string>();
  for (const leaf of await log.leaves(from, to + 1)) logged.set(leaf.leafIndex, leaf.leafDigest);

  for (const record of records) {
    const at = positionOf(record);
    if (at === null) continue;
    const evidenceId = record.payload.evidenceId;
    const leaf = logged.get(at);
    if (leaf !== undefined && leaf !== record.integrity?.canonicalDigest) digestDiffersFromLoggedLeaf.push(evidenceId);
    if (hasAnchor(record) || !(await log.anchorFillDone(at))) continue;
    const current = await storage.retrieve(evidenceId);
    if (current && !hasAnchor(current)) anchorStripped.push(evidenceId);
  }
  return { digestDiffersFromLoggedLeaf, anchorStripped };
}
