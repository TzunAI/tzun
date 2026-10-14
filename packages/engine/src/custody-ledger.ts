/**
 * The custody ledger check: a record's `custody_entries` rows checked against
 * each other and against the envelope's `custodyChain` mirror.
 *
 * `verifyCustodyTrail` (custody-hash.ts) reads the envelope alone, so it cannot
 * see a hashed entry deleted from the end of the mirror, or every hashed entry
 * stripped from it — both leave a trail that is internally consistent. The
 * ledger rows are what catch those, and this is the check that reads them.
 *
 * It is the engine twin of the hosted service's `verifyCustodyTrailOf`: the
 * same rules, the same ten failure reasons, the same verdict shape. It reads
 * the rows in the form an export
 * bundle carries them (`CustodyLedgerEntry`), which is the form both the SDK's
 * bundle and the platform's `server.custody.entries` use, so it runs offline
 * over either bundle as well as over rows read from a local store.
 *
 * ONE implementation, used by every reader in this SDK that reports on custody:
 * the verdict a local read carries (`recordVerdict`, so every `tzun.get()` /
 * `tzun.list()` through the verifying proxy), `Tzun.exportEvidence()`, the chain
 * walk (`verifyChainCompleteness`'s `custodyTrailInvalid`), and
 * `ScheduledScanner`'s `custody_trail_invalid` incident. The audit's root-cause
 * pattern is a verification re-implemented per surface, each copy a fix behind;
 * do not add a second copy.
 *
 * WHAT IS NOT VERIFIED HERE. A `'relinked'` entry's `relinkDigest` against the
 * relink record it names: the rule that writes it lives in the SDK's
 * `RecoveryManager`, and the record it is checked against is in the store, not
 * in the envelope or a bundle. `ScheduledScanner` makes that check and reports
 * it as a `CustodyRelinkFailure` in the same event.
 *
 * WHAT IS VERIFIED, for one record:
 *
 *   rows     in id order. Each row's `entryHash` must recompute from its own
 *            fields and its `prevEntryHash` (`computeCustodyEntryHash`), and
 *            its `prevEntryHash` must be the previous row's `entryHash`. A row
 *            whose `canonicalDigest` is no longer the record's digest is
 *            reported too: the record's content moved after the action.
 *
 *   mirror   `envelope.custodyChain`. Entries without an `entryHash` are the
 *            client-attested or legacy unhashed form and are counted, not verified.
 *            Entries with one must (a) all sit after every unhashed entry,
 *            (b) correspond one to one, in order, with the rows, (c) carry the
 *            row's hash and prev hash, and (d) recompute to that hash from
 *            their OWN fields — so a field rewritten in the mirror alone, or in
 *            the row alone, is caught either way.
 *
 * Never throws. A bundle is a file someone hands a verifier, and JSON
 * guarantees no field type: a row or entry whose fields the hash rule cannot
 * consume is reported as a hash mismatch with a `detail`, not raised.
 */

import { computeCustodyEntryHash, isHashedCustodyEntry } from './custody-hash';
import type { EvidenceEnvelope } from './types/evidence';
import type { StoredCustodyEntry } from './types/storage-interface';
import type {
  CustodyLedgerEntry,
  CustodyLedgerFailure,
  CustodyLedgerVerdict,
} from './types/verification';

/**
 * The entry hash rule, stated in the form the hosted service's export ships it as
 * `server.custody.hashPreimage`. The same text, so a reader of either bundle
 * reads the same sentence.
 */
export const CUSTODY_ENTRY_HASH_PREIMAGE =
  'sha256(lp(prevEntryHash)||lp(evidenceId)||lp(canonicalDigest)||lp(action)||lp(actor)||lp(timestamp)||lp(systemId)||lp(canonicalMetadata)); lp = "<code points>:<value>" or "-:" for null; canonicalMetadata = engine canonical JSON of metadata';

/** A local store's ledger row, in the form an export bundle carries it. */
export function toCustodyLedgerEntry(row: StoredCustodyEntry): CustodyLedgerEntry {
  return {
    id: String(row.id),
    action: row.action,
    actor: row.actor,
    actorParty: null,
    timestamp: row.timestamp,
    systemId: row.systemId,
    metadata: row.metadata,
    canonicalDigest: row.canonicalDigest,
    prevEntryHash: row.prevEntryHash,
    entryHash: row.entryHash,
    recoveryId: row.recoveryId,
    recordedAt: null,
  };
}

interface HashFields {
  prevEntryHash: unknown;
  canonicalDigest: unknown;
  action: unknown;
  actor: unknown;
  timestamp: unknown;
  systemId: unknown;
  metadata: unknown;
}

/**
 * `computeCustodyEntryHash` over fields read from untrusted JSON, or null when
 * they are not the types the rule consumes (or the metadata cannot be
 * canonicalized). Null is reported by the caller; it is never a pass.
 */
function hashOf(evidenceId: unknown, f: HashFields): string | null {
  const strings = [evidenceId, f.canonicalDigest, f.action, f.actor, f.timestamp, f.systemId];
  if (!strings.every((s) => typeof s === 'string')) return null;
  if (f.prevEntryHash !== null && f.prevEntryHash !== undefined && typeof f.prevEntryHash !== 'string') {
    return null;
  }
  const metadata = f.metadata;
  if (
    metadata !== null &&
    metadata !== undefined &&
    (typeof metadata !== 'object' || Array.isArray(metadata))
  ) {
    return null;
  }
  try {
    return computeCustodyEntryHash({
      prevEntryHash: (f.prevEntryHash as string | null | undefined) ?? null,
      evidenceId: evidenceId as string,
      canonicalDigest: f.canonicalDigest as string,
      action: f.action as string,
      actor: f.actor as string,
      timestamp: f.timestamp as string,
      systemId: f.systemId as string,
      metadata: (metadata as Record<string, unknown> | null | undefined) ?? null,
    });
  } catch {
    return null;
  }
}

const UNHASHABLE = 'fields are not the types the entry hash rule consumes, or metadata cannot be canonicalized';

/**
 * Verify one record's custody ledger rows against each other and against the
 * envelope's mirror.
 *
 * @param evidenceId     The record the rows belong to.
 * @param envelope       The record, or null when it is not there.
 * @param currentDigest  The record's current digest. Defaults to the
 *                       envelope's `integrity.canonicalDigest`; the platform
 *                       passes its `canonical_digest` column.
 * @param entries        The record's ledger rows, in id order.
 */
export function verifyCustodyLedger(
  evidenceId: string,
  envelope: Pick<EvidenceEnvelope, 'payload' | 'integrity' | 'custodyChain'> | null,
  currentDigest: string | null | undefined,
  entries: readonly CustodyLedgerEntry[],
): CustodyLedgerVerdict {
  const failures: CustodyLedgerFailure[] = [];
  const rows: CustodyLedgerEntry[] = Array.isArray(entries)
    ? entries.filter((r) => r !== null && typeof r === 'object')
    : [];

  if (!envelope || typeof envelope !== 'object') {
    failures.push({
      reason: 'record_missing',
      detail: `${rows.length} custody row(s) for a record that is not there`,
    });
    return { evidenceId, valid: false, rows: rows.length, hashedEntries: 0, unhashedEntries: 0, failures };
  }

  const digest =
    currentDigest !== undefined
      ? currentDigest
      : typeof envelope.integrity?.canonicalDigest === 'string'
        ? envelope.integrity.canonicalDigest
        : null;

  // ── rows ─────────────────────────────────────────────────────────────────
  let prev: string | null = null;
  for (const row of rows) {
    const rowId = String(row.id);
    if ((row.prevEntryHash ?? null) !== prev) {
      failures.push({ reason: 'row_prev_mismatch', rowId });
    }
    const recomputed = hashOf(evidenceId, row);
    if (recomputed === null) {
      failures.push({ reason: 'row_hash_mismatch', rowId, detail: `row ${UNHASHABLE}` });
    } else if (recomputed !== row.entryHash) {
      failures.push({ reason: 'row_hash_mismatch', rowId });
    }
    if (digest !== null && row.canonicalDigest !== digest) {
      failures.push({
        reason: 'digest_moved_since_entry',
        rowId,
        detail: "the record's canonical digest is no longer the one this custody action was recorded against",
      });
    }
    // Continue from the STORED hash so one bad row is reported once, not
    // cascaded onto every later row (the platform makes the same choice).
    prev = typeof row.entryHash === 'string' ? row.entryHash : null;
  }

  // ── mirror ───────────────────────────────────────────────────────────────
  const chain: unknown[] = Array.isArray(envelope.custodyChain) ? envelope.custodyChain : [];
  const hashed: Array<{ index: number; entry: Record<string, unknown> }> = [];
  let unhashed = 0;
  let seenHashed = false;
  chain.forEach((e, index) => {
    if (isHashedCustodyEntry(e)) {
      seenHashed = true;
      hashed.push({ index, entry: e as unknown as Record<string, unknown> });
    } else {
      unhashed += 1;
      if (seenHashed) failures.push({ reason: 'unhashed_after_hashed', index });
    }
  });

  const mirrorEvidenceId: unknown = envelope.payload?.evidenceId ?? evidenceId;
  const n = Math.min(hashed.length, rows.length);
  for (let i = 0; i < n; i += 1) {
    const { index, entry } = hashed[i]!;
    const row = rows[i]!;
    const rowId = String(row.id);
    if (entry.entryHash !== row.entryHash) {
      failures.push({ reason: 'mirror_hash_mismatch', index, rowId });
    }
    if ((entry.prevEntryHash ?? null) !== (row.prevEntryHash ?? null)) {
      failures.push({ reason: 'mirror_prev_mismatch', index, rowId });
    }
    const fromMirror = hashOf(mirrorEvidenceId, {
      prevEntryHash: entry.prevEntryHash,
      canonicalDigest: row.canonicalDigest,
      action: entry.action,
      actor: entry.actor,
      timestamp: entry.timestamp,
      systemId: entry.systemId,
      metadata: entry.metadata,
    });
    if (fromMirror === null) {
      failures.push({ reason: 'mirror_fields_mismatch', index, rowId, detail: `mirror entry ${UNHASHABLE}` });
    } else if (fromMirror !== entry.entryHash) {
      failures.push({ reason: 'mirror_fields_mismatch', index, rowId });
    }
  }
  for (let i = n; i < rows.length; i += 1) {
    failures.push({ reason: 'mirror_entry_missing', rowId: String(rows[i]!.id) });
  }
  for (let i = n; i < hashed.length; i += 1) {
    failures.push({ reason: 'mirror_entry_unexpected', index: hashed[i]!.index });
  }

  return {
    evidenceId,
    valid: failures.length === 0,
    rows: rows.length,
    hashedEntries: hashed.length,
    unhashedEntries: unhashed,
    failures,
  };
}
