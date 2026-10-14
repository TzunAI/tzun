/**
 * The verdict a read carries: what the integrity checks found about one
 * stored record, computed from the record and whatever else the reader
 * fetched for it. Pure — the caller does the I/O and hands the results in,
 * including the errors, so a check whose input could not be read is reported
 * as unmeasured rather than thrown. A verdict never withholds the record.
 *
 * One implementation serves every reader: the SDK's verifying storage proxy
 * (every `get()` / `list()`), `Tzun.exportEvidence()`, and an offline
 * verifier recomputing the verdict from an export bundle.
 */

import { verifyCustodyLedger } from './custody-ledger';
import { SchemaRegistry } from './schema-registry';
import { checkSignoffExpectation } from './signoff-expectation';
import { verifyEnvelope } from './verify';
import type { EvidenceEnvelope } from './types/evidence';
import type {
  CustodyLedgerEntry,
  RecordChainLinkCheck,
  RecordCustodyCheck,
  RecordDigestCheck,
  RecordVerdict,
  VerificationResult,
} from './types/verification';

const defaultRegistry = new SchemaRegistry();

/** What `recordVerdict` is given besides the record. */
export interface RecordVerdictInput {
  /** Serialization rules for the digest check. Defaults to the engine's registry. */
  registry?: SchemaRegistry;
  /**
   * The record's id as the store keys it. Defaults to the envelope's
   * `payload.evidenceId`. A store whose identity lives in columns
   * (such as the hosted service's `evidence_id` column) passes its own, which
   * is what its custody rows are keyed by.
   */
  evidenceId?: string;
  /**
   * The digest the store holds for the record. The hosted service passes its frozen
   * `canonical_digest` column, the digest its INSERT
   * trigger bound the custody rows to. When it is a string:
   *
   *   - the digest check also compares it with the envelope's
   *     `integrity.canonicalDigest`, and reports a difference `invalid` /
   *     `stored_digest_mismatch`, so an envelope rewritten consistently
   *     (payload, `canonicalDigest` and `chainLink` all recomputed) does not
   *     read `valid` against a store that holds the original digest;
   *   - the custody rule checks each ledger row against it.
   *
   * `null` and absent are read alike: the store holds no digest of its own,
   * and the custody rule checks each row against the envelope's
   * `integrity.canonicalDigest`. A nullable column can be passed straight
   * through.
   */
  currentDigest?: string | null;
  /** The record's custody ledger rows in id order, or the error reading them failed with. */
  custody: { entries: readonly CustodyLedgerEntry[] } | { error: string };
  /**
   * The chain-link check's input: the digest of the record at the previous
   * sequence of the record's chain (`null` when the store holds none), or the
   * error reading it failed with. Omitted for a single-record read, which
   * reports the link `not_checked_on_read`.
   */
  predecessor?: { digest: string | null } | { error: string };
}

/**
 * Check one stored record.
 *
 *   - digest       the payload recomputed under its schema's rules against
 *                  `integrity.canonicalDigest`, and that against the digest
 *                  the store holds (`input.currentDigest`) when one is given.
 *   - custodyTrail the ledger rows against each other and against the
 *                  `custodyChain` mirror (`verifyCustodyLedger`).
 *   - chainLink    `integrity.chainLink` against the predecessor digest, when
 *                  one was looked up.
 *   - signoffExpectation
 *                  the record's sign-off material against its hashed
 *                  expectation (`checkSignoffExpectation`), read only when
 *                  the digest check is `valid` (otherwise `null`,
 *                  `digest_invalid`: the expectation is authenticated by
 *                  nothing else). Reported beside the three, not counted in
 *                  `status`.
 *
 * The digest and chain-link rules are `verifyEnvelope`'s; this adds the
 * reasons, the ledger and the store-digest comparison.
 *
 * `envelope` is `null` for a row the store holds no record for. Nothing can
 * recompute to the digest the store holds for it, so the digest check is
 * `invalid` / `record_missing`; the custody check runs, and reports its rows
 * `record_missing`; the chain link, which is a property of the record, is
 * `unmeasured` / `record_missing`. The verdict is never `valid`.
 */
export function recordVerdict(
  envelope: EvidenceEnvelope | null,
  input: RecordVerdictInput,
): RecordVerdict {
  const registry = input.registry ?? defaultRegistry;
  const rawId: unknown = envelope?.payload?.evidenceId;
  const evidenceId = input.evidenceId ?? (typeof rawId === 'string' ? rawId : '');
  // `null` reads as absent: the custody rule then falls back to the envelope
  // rather than skipping `digest_moved_since_entry`.
  const storeDigest = typeof input.currentDigest === 'string' ? input.currentDigest : undefined;

  let digest: RecordDigestCheck;
  let chainLink: RecordChainLinkCheck;
  if (envelope == null) {
    digest = {
      status: 'invalid',
      stored: storeDigest ?? '',
      recomputed: '',
      reason: 'record_missing',
    };
    chainLink = chainLinkCheck(null, input.predecessor, null);
  } else {
    const predecessorDigest =
      input.predecessor && 'digest' in input.predecessor ? input.predecessor.digest : null;
    // `?? undefined`: the engine reads an absent previousDigest as "no
    // predecessor", and a supplied one (even '') as "a predecessor exists".
    const base = verifyEnvelope(envelope, predecessorDigest ?? undefined, registry);
    digest = digestCheckOf(base);
    if (digest.status === 'valid' && storeDigest !== undefined && storeDigest !== base.storedDigest) {
      digest.status = 'invalid';
      digest.reason = 'stored_digest_mismatch';
    }
    chainLink = chainLinkCheck(envelope, input.predecessor, base.chainLinkValid);
  }
  const custodyTrail = custodyCheck(evidenceId, envelope, storeDigest, input.custody);

  const checks = [digest.status, custodyTrail.status, chainLink.status];
  return {
    status: checks.includes('invalid') ? 'invalid' : 'valid',
    digest,
    custodyTrail,
    chainLink,
    ...(envelope != null && {
      signoffExpectation:
        digest.status === 'valid'
          ? checkSignoffExpectation(envelope)
          : { valid: null, reason: 'digest_invalid' as const },
    }),
    checkedAt: new Date().toISOString(),
  };
}

/**
 * The digest check alone: the payload recomputed under its schema's rules
 * against `integrity.canonicalDigest`. What `recordVerdict` reports as
 * `digest`, for a reader that needs nothing else.
 */
export function recordDigestCheck(
  envelope: EvidenceEnvelope,
  registry: SchemaRegistry = defaultRegistry,
): RecordDigestCheck {
  return digestCheckOf(verifyEnvelope(envelope, undefined, registry));
}

function digestCheckOf(base: VerificationResult): RecordDigestCheck {
  const digest: RecordDigestCheck = {
    status: 'valid',
    stored: base.storedDigest,
    recomputed: base.recomputedDigest,
  };
  if (!base.schemaValid) {
    digest.status = 'invalid';
    digest.reason = 'unknown_schema_version';
  } else if (base.payloadSerializationError !== undefined) {
    digest.status = 'invalid';
    digest.reason = 'payload_unserializable';
  } else if (base.recomputedDigest !== base.storedDigest) {
    digest.status = 'invalid';
    digest.reason = 'digest_mismatch';
  }
  return digest;
}

/**
 * The verdict a read carries when read verification is switched off: every
 * check unmeasured, the stored digest reported as found, nothing recomputed.
 */
export function unmeasuredRecordVerdict(envelope: EvidenceEnvelope): RecordVerdict {
  const stored = envelope?.integrity?.canonicalDigest;
  return {
    status: 'unmeasured',
    digest: {
      status: 'unmeasured',
      stored: typeof stored === 'string' ? stored : '',
      recomputed: '',
      reason: 'read_verification_off',
    },
    custodyTrail: { status: 'unmeasured', reason: 'read_verification_off', ledger: null },
    chainLink: { status: 'unmeasured', reason: 'read_verification_off', predecessorDigest: null },
    checkedAt: new Date().toISOString(),
  };
}

function custodyCheck(
  evidenceId: string,
  envelope: EvidenceEnvelope | null,
  currentDigest: string | undefined,
  custody: RecordVerdictInput['custody'],
): RecordCustodyCheck {
  if ('error' in custody) {
    return {
      status: 'unmeasured',
      reason: 'custody_ledger_unreadable',
      ledger: null,
      detail: custody.error,
    };
  }
  const ledger = verifyCustodyLedger(evidenceId, envelope, currentDigest, custody.entries);
  if (!ledger.valid) {
    return { status: 'invalid', reason: ledger.failures[0]!.reason, ledger };
  }
  if (ledger.rows === 0 && ledger.hashedEntries === 0) {
    return { status: 'unmeasured', reason: 'nothing_to_measure', ledger };
  }
  return { status: 'valid', ledger };
}

function chainLinkCheck(
  envelope: EvidenceEnvelope | null,
  predecessor: RecordVerdictInput['predecessor'],
  chainLinkValid: boolean | null,
): RecordChainLinkCheck {
  if (predecessor === undefined) {
    return { status: 'unmeasured', reason: 'not_checked_on_read', predecessorDigest: null };
  }
  if ('error' in predecessor) {
    return {
      status: 'unmeasured',
      reason: 'predecessor_unreadable',
      predecessorDigest: null,
      detail: predecessor.error,
    };
  }
  const predecessorDigest = predecessor.digest;
  if (envelope == null) {
    return { status: 'unmeasured', reason: 'record_missing', predecessorDigest };
  }
  // `null` from the engine is a genesis record carrying no link and given no
  // predecessor: the link is exactly what the record's position requires.
  if (chainLinkValid !== false) {
    return { status: 'valid', predecessorDigest };
  }
  const link: unknown = envelope?.integrity?.chainLink;
  const reason: RecordChainLinkCheck['reason'] =
    link === null || link === undefined
      ? 'chain_link_missing'
      : predecessorDigest === null
        ? 'predecessor_missing'
        : 'chain_link_mismatch';
  return { status: 'invalid', reason, predecessorDigest };
}
