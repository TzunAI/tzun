import { modelOf } from './step-model';
/**
 * Offline verifier for an `ExportedEvidenceEnvelope`.
 *
 * Self-contained: this helper does NOT touch any storage. The bundle is
 * the entire ground truth; the verifier:
 *
 *   1. Re-canonicalizes the envelope payload using the v1.0 schema's
 *      hashed-field-set and recomputes the integrity digest. Reports a
 *      mismatch if `storedDigest !== recomputed`.
 *
 *   2. For each entry in `resolvedModelDescriptors`:
 *      - Reports `missing: true` entries as verification gaps.
 *      - Otherwise re-hashes `canonicalBytes` against the entry's key
 *        (the claimed digest). Mismatches are surfaced.
 *
 *   3. Walks the parent DAG entirely within the bundle:
 *      - Starting from `aiBom.modelDescriptorDigest`, follow the parent
 *        pointer READ OUT OF `canonicalBytes` (depth-limited, cycle-safe).
 *      - Every reachable digest MUST be present in the bundle.
 *      - The shipped `enrichedView`'s parent pointer must agree with the
 *        bytes; a disagreement is reported rather than followed.
 *
 *   4. Recomputes the chain link: `integrity.chainLink` must
 *      be SHA-256(predecessor digest ‖ envelope digest) over the bundled
 *      predecessor, which must sit at the previous sequence number. A record
 *      past genesis, or one carrying a link, with no predecessor in the
 *      bundle is reported: its link cannot be checked.
 *
 *   5. Checks the custody ledger: the bundled rows against
 *      each other and against the envelope's `custodyChain` mirror, with the
 *      engine's `verifyCustodyLedger`. Each failure is reported.
 *
 *   6. Recomputes the exporter's verdict from the bundle (`recordVerdict`)
 *      and reports a `verdict.status` that disagrees: the shipped verdict is
 *      the exporter's claim, not evidence.
 *
 *   7. Re-reads the recorded `assertionProvenance` from the
 *      envelope's WebAuthn assertion and reports a field that disagrees, and
 *      reports a check the bundle claims is `true`: an export verifies no
 *      signature.
 *
 * It reads the SDK's bundle (`Tzun.exportEvidence`) and the hosted service's
 * customer export (`GET /v1/app/evidence/:id/export`) alike: the custody
 * block is `custody` in the first and `server.custody` in the second, with
 * the same shape. The platform's bundle carries no descriptors and no
 * predecessor, and each of those gaps is reported the way it would be for an
 * SDK bundle missing them.
 *
 * Every digest is checked against the exact form ITS producer emits — bare
 * hex for the envelope digest, `sha256:`-prefixed for descriptor keys. See
 * the digest-form constants below.
 *
 * Returns `{ ok: true }` on success, `{ ok: false, errors: [...] }` otherwise.
 *
 * Lives in tests/helpers/ rather than src/ because it's a verification
 * tool used by integration tests, not a runtime API. A production-grade
 * offline verifier would surface roughly the same checks via a CLI.
 */

import { createHash } from 'crypto';
import { assertionProvenance, canonicalSerialize, recordVerdict, verifyCustodyLedger, verifyEnvelope } from '@tzun/engine';
import type { StorageAdapter } from '@tzun/engine';
import { exportedAgentCatalog, recordAgentReferences } from '../../../src/sdk/agents';
import { SchemaRegistry } from '@tzun/engine';
import {
  CustodyLedgerEntry,
  EvidenceEnvelope,
  ExportedChainPosition,
  ExportedCustody,
  ExportedDescriptorEntry,
  ExportedEvidenceEnvelope,
  ModelDescriptor,
  RecordVerdictInput,
} from '@tzun/engine';

/**
 * The hosted service's customer export (`GET /v1/app/evidence/:id/export`), as far
 * as this verifier reads it: the envelope, and the server sidecar whose
 * `custody` block has the SDK bundle's `custody` shape.
 */
export interface PlatformExportBundle {
  envelope: EvidenceEnvelope;
  server: {
    /** `null` when the remote store does not record it — the platform's own shape. */
    receivedAt: string | null;
    attestation: Record<string, unknown>;
    custody: ExportedCustody;
  };
}

const MAX_LINEAGE_DEPTH = 16;

/**
 * The two digest spellings this bundle actually carries — and they are NOT
 * the same one. Normalizing both to one spelling would hide that.
 *
 * `envelope.integrity.canonicalDigest` is BARE 64-char hex: `computeDigest`
 * returns `createHash(...).digest('hex')` (packages/engine/src/digest-computer.ts:30)
 * and the in-process verifier compares it bare (verify.ts:125).
 *
 * Descriptor catalog keys are PREFIXED: `hashCanonicalBytes` emits
 * `'sha256:' + hex` (verify.ts:357) and `MODEL_DIGEST_FORMAT`
 * (src/models/descriptor-invariants.ts:23) enforces `^sha256:[a-f0-9]{64}$`
 * on every registered descriptor.
 *
 * Each site is pinned to the form its producer emits. Accepting both
 * spellings at either site lets a bundle present a digest the producing SDK
 * could never have written, and makes the string comparison that is this
 * verifier's whole job depend on which spelling arrived.
 */
const ENVELOPE_DIGEST_FORM = /^[a-f0-9]{64}$/;
const DESCRIPTOR_DIGEST_FORM = /^sha256:[a-f0-9]{64}$/;

export type VerifyExportedResult =
  | { ok: true }
  | { ok: false; errors: string[] };

export async function verifyExported(
  bundle: ExportedEvidenceEnvelope | PlatformExportBundle,
): Promise<VerifyExportedResult> {
  const errors: string[] = [];

  // A bundle is the most untrusted input in the system: it is a file someone
  // hands you, and a verifier that throws on a malformed one cannot tell you
  // it was malformed. Everything below reads through defensive
  // accessors and every string the crypto touches is type-checked first.
  const envelope = ((bundle ?? {}) as ExportedEvidenceEnvelope).envelope;
  const server = (bundle as Partial<PlatformExportBundle> | null)?.server;
  const fromPlatform = server !== null && typeof server === 'object';
  const payload = (envelope?.payload ?? {}) as (typeof envelope)['payload'];
  const integrity = (envelope?.integrity ?? {}) as (typeof envelope)['integrity'];

  // ── 1. Re-canonicalize the envelope payload and recompute the digest. ──
  const registry = new SchemaRegistry();
  const schema = registry.get(payload.schemaVersion);
  if (!schema) {
    errors.push(
      `envelope: schemaVersion "${String(payload.schemaVersion)}" is not registered in the offline verifier`,
    );
  } else {
    // canonicalSerialize refuses payloads it cannot render injectively — a
    // lone UTF-16 surrogate, nesting past MAX_DEPTH, a non-finite number. A
    // bundle carrying one has no recomputable digest, which is a finding to
    // report, not an exception to raise at whoever opened the file.
    let recomputed: string | null = null;
    let serializationError: string | null = null;
    try {
      recomputed = sha256(
        canonicalSerialize(
          payload as unknown as Record<string, unknown>,
          schema.hashedFieldSet,
        ),
      );
    } catch (err) {
      serializationError = err instanceof Error ? err.message : String(err);
    }
    const stored = integrity.canonicalDigest;
    // Exact form required — see the digest-form note in the file header. A
    // prefixed digest here is a malformed bundle, not a dialect to normalize.
    if (typeof stored !== 'string' || !ENVELOPE_DIGEST_FORM.test(stored)) {
      errors.push(
        `envelope: integrity digest "${String(stored)}" is not in the required bare "<64 lowercase hex>" form`,
      );
    } else if (serializationError !== null) {
      errors.push(
        `envelope: payload cannot be canonically serialized, so its digest cannot be recomputed (${serializationError})`,
      );
    } else if (recomputed !== stored) {
      errors.push(
        `envelope: integrity digest mismatch (stored=${stored}, recomputed=${String(recomputed)})`,
      );
    }
  }

  // ── 2. Re-hash every bundled descriptor against its claimed digest. ──
  // The platform's export bundles no descriptors; its lineage gaps are
  // reported by pass 3, as they would be for an SDK bundle missing them.
  const shipped = (bundle as Partial<ExportedEvidenceEnvelope> | null)?.resolvedModelDescriptors;
  const resolved = shipped === undefined && fromPlatform ? {} : shipped;
  if (resolved === null || typeof resolved !== 'object' || Array.isArray(resolved)) {
    errors.push('bundle: resolvedModelDescriptors is not an object');
  }
  const descriptorEntries: Array<[string, ExportedDescriptorEntry]> =
    resolved !== null && typeof resolved === 'object' && !Array.isArray(resolved)
      ? Object.entries(resolved)
      : [];
  for (const [digest, entry] of descriptorEntries) {
    if (entry === null || typeof entry !== 'object') {
      errors.push(`descriptor "${digest}": entry is not an object`);
      continue;
    }
    if (entry.missing) {
      errors.push(
        `descriptor "${digest}": missing from bundle (catalog gap at export time)`,
      );
      continue;
    }
    if (!DESCRIPTOR_DIGEST_FORM.test(digest)) {
      errors.push(
        `descriptor "${digest}": key is not in the required "sha256:<64 lowercase hex>" form`,
      );
      continue;
    }
    // `createHash().update(5)` throws rather than hashing, so a non-string
    // canonicalBytes is a malformed entry, reported the same way a mismatch is.
    if (typeof entry.canonicalBytes !== 'string') {
      errors.push(`descriptor "${digest}": canonicalBytes is not a string`);
      continue;
    }
    const recomputed = 'sha256:' + sha256(entry.canonicalBytes);
    if (recomputed !== digest) {
      errors.push(
        `descriptor "${digest}": digest mismatch (claimed=${digest}, recomputed=${recomputed})`,
      );
    }
  }

  // ── 3. Walk the lineage entirely within the bundle. ──
  //
  // The walk advances on the parent pointer parsed out of `canonicalBytes`
  // — the ONLY part of an entry that its digest key commits to — and never on
  // `entry.enrichedView.parentModelDescriptorDigest`, which is the
  // annotation-applied view of the row's denormalized columns and is covered
  // by nothing. This is the export-side twin of the in-process rule in
  // packages/engine/src/verify.ts. A walk over the enriched view would return
  // `{ ok: true }` for a bundle that re-parents a descriptor at a different
  // base model, because every digest still re-hashes and the only thing that
  // moved is a pointer no digest covers. The exported lineage — the thing a
  // compliance report is built from — would then be a claim the evidence does
  // not make, carrying a green verification.
  //
  // No annotation type in src/models/enriched-view.ts writes
  // `parentModelDescriptorDigest`, so in an honest bundle the enriched
  // view's pointer always equals the bytes'. A disagreement is therefore
  // reported, not silently preferred either way.
  const aiBom = modelOf(payload);
  if (aiBom != null && typeof aiBom === 'object' && !Array.isArray(aiBom)) {
    const visited = new Set<string>();
    const leaf: unknown = (aiBom as { modelDescriptorDigest?: unknown }).modelDescriptorDigest;
    if (typeof leaf !== 'string') {
      errors.push(
        `lineage: aiBom.modelDescriptorDigest "${String(leaf)}" is not a descriptor digest string`,
      );
    }
    let current: string | null = typeof leaf === 'string' ? leaf : null;
    let depth = 0;

    while (current !== null && depth < MAX_LINEAGE_DEPTH) {
      const here: string = current;
      if (visited.has(here)) {
        errors.push(`lineage: cycle detected at "${here}"`);
        break;
      }
      visited.add(here);
      const entry: ExportedDescriptorEntry | undefined =
        (resolved as Record<string, ExportedDescriptorEntry>)?.[here];
      if (!entry || typeof entry !== 'object') {
        errors.push(
          `lineage: descriptor "${here}" referenced from envelope/parent chain but absent from bundle`,
        );
        break;
      }
      if (entry.missing === true) {
        // Already reported in pass (2). Stop the walk — we cannot follow
        // through a hole.
        break;
      }

      const descriptor = parseDescriptorBytes(entry.canonicalBytes);
      if (descriptor === null) {
        errors.push(
          `lineage: descriptor "${here}": canonicalBytes are not parseable as a ModelDescriptor`,
        );
        break;
      }

      const rawNext: unknown = descriptor.parentModelDescriptorDigest ?? null;
      if (rawNext !== null && typeof rawNext !== 'string') {
        errors.push(
          `lineage: descriptor "${here}": parentModelDescriptorDigest ` +
            `(${String(rawNext)}) is not a descriptor digest string`,
        );
        break;
      }
      const next: string | null = rawNext;

      // The enriched view rides along in the bundle and a consumer may read
      // it. It is not digest-covered, so it is checked against the bytes
      // rather than trusted. `?.` because `enrichedView: null` is the shape an
      // exporter writes for a missing row — reading through it threw.
      const viewParent: string | null =
        entry.enrichedView?.parentModelDescriptorDigest ?? null;
      if (viewParent !== next) {
        errors.push(
          `lineage: descriptor "${here}": enrichedView.parentModelDescriptorDigest ` +
            `(${String(viewParent)}) disagrees with the digest-covered canonicalBytes (${String(next)})`,
        );
      }

      current = next;
      depth += 1;
    }
  }

  // ── 3b. Resolve every agent reference against the bundled agent descriptors. ──
  // The store-level rule over the bundle alone: each
  // reference's row re-hashed, read as a descriptor, a policy engine's
  // models checked empty. An entry under a reference the record does not
  // name is reported. A bundle with no `resolvedAgentDescriptors` (one
  // assembled before 0.8.0, or the platform's) is not read here.
  const agentEntries = (bundle as Partial<ExportedEvidenceEnvelope> | null)?.resolvedAgentDescriptors;
  if (agentEntries !== undefined) {
    if (agentEntries === null || typeof agentEntries !== 'object' || Array.isArray(agentEntries)) {
      errors.push('bundle: resolvedAgentDescriptors is not an object');
    } else if (envelope !== null && typeof envelope === 'object') {
      const named = new Set(recordAgentReferences(envelope).map((r) => r.reference));
      for (const reference of Object.keys(agentEntries)) {
        if (!named.has(reference)) errors.push(`bundle: resolvedAgentDescriptors names ${reference}, which the record does not`);
      }
      const verdict = await verifyEnvelope(envelope, undefined, undefined, {
        storage: exportedAgentCatalog(agentEntries) as StorageAdapter,
      });
      for (const agent of verdict.agents ?? []) {
        if (!agent.resolved) errors.push(`agent "${agent.reference}" (${agent.field}): ${agent.reason}`);
      }
    }
  }

  // ── 4. Recompute the chain link from the bundled predecessor. ──
  const position = (bundle as Partial<ExportedEvidenceEnvelope> | null)?.chain;
  const predecessorDigest = checkChainLink(errors, position, payload, integrity);

  // ── 5. The custody ledger rows against each other and the mirror. ──
  const custody = fromPlatform
    ? (server as Partial<PlatformExportBundle['server']>).custody
    : (bundle as Partial<ExportedEvidenceEnvelope> | null)?.custody;
  const entries = custodyEntriesOf(custody);
  const evidenceId = typeof payload.evidenceId === 'string' ? payload.evidenceId : '';
  if (entries === null) {
    errors.push('custody: the bundle carries no custody ledger rows, so the custody trail cannot be checked');
  } else if (envelope !== null && typeof envelope === 'object') {
    for (const f of verifyCustodyLedger(evidenceId, envelope, undefined, entries).failures) {
      const where = [f.rowId !== undefined ? `row ${f.rowId}` : null, f.index !== undefined ? `custodyChain[${f.index}]` : null]
        .filter(Boolean)
        .join(', ');
      errors.push(`custody: ${f.reason}${where ? ` (${where})` : ''}${f.detail ? `: ${f.detail}` : ''}`);
    }
  }

  // ── 6. The exporter's verdict is a claim; recompute it from the bundle. ──
  const claimed = (bundle as Partial<ExportedEvidenceEnvelope> | null)?.verdict;
  if (!fromPlatform) {
    if (claimed === null || typeof claimed !== 'object') {
      errors.push('verdict: the bundle carries no verdict');
    } else if (envelope !== null && typeof envelope === 'object') {
      const custodyInput: RecordVerdictInput['custody'] =
        entries === null ? { error: 'not in the bundle' } : { entries };
      const recomputed = recordVerdict(envelope, {
        custody: custodyInput,
        predecessor: { digest: predecessorDigest },
      });
      if (claimed.status !== recomputed.status) {
        errors.push(
          `verdict: the bundle's verdict says "${String(claimed.status)}" but the bundle recomputes to "${recomputed.status}"`,
        );
      }
    }
  }

  // ── 7. The recorded provenance is a claim; re-read it from the assertion. ──
  checkAssertionProvenance(errors, bundle, envelope);

  if (errors.length > 0) {
    return { ok: false, errors };
  }
  return { ok: true };
}

/**
 * Pass 7. The bundle's `assertionProvenance` records what the envelope's
 * WebAuthn assertion states: origin, crossOrigin, topOrigin and the four
 * flags. Those are re-read from the assertion itself and a disagreement is
 * reported; the flags are compared one by one, so the order an exporter wrote
 * their keys in does not matter. The checks are not recomputed: they depend
 * on what the exporter asked for, which the bundle does not say. But an
 * export verifies no signature, and a check is `true` only under a verified
 * one, so a check the bundle claims is `true` is reported. A bundle without
 * the field (assembled before 0.4.7, or the platform's) is not held to it.
 */
function checkAssertionProvenance(
  errors: string[],
  bundle: ExportedEvidenceEnvelope | PlatformExportBundle,
  envelope: EvidenceEnvelope | undefined,
): void {
  const claimed = (bundle as Partial<ExportedEvidenceEnvelope> | null)?.assertionProvenance;
  if (claimed === undefined) return;
  const assertion = envelope?.nonRepudiation?.webauthnAssertion;
  if (!assertion) {
    if (claimed !== null) {
      errors.push('assertionProvenance: recorded for an envelope that carries no assertion');
    }
    return;
  }
  if (claimed === null || typeof claimed !== 'object') {
    errors.push('assertionProvenance: the envelope carries an assertion and the bundle records no provenance for it');
    return;
  }
  const reread = assertionProvenance(assertion);
  for (const field of ['origin', 'crossOrigin', 'topOrigin', 'flags'] as const) {
    if (!sameStatement(claimed[field], reread[field])) {
      errors.push(
        `assertionProvenance.${field}: the bundle records ${JSON.stringify(claimed[field])} ` +
          `but the assertion states ${JSON.stringify(reread[field])}`,
      );
    }
  }
  for (const check of ['originValid', 'topOriginValid', 'deviceBound'] as const) {
    if (claimed[check] === true) {
      errors.push(
        `assertionProvenance.${check}: the bundle claims true, but an export verifies no signature, ` +
          'and a check is true only under a verified one',
      );
    }
  }
}

/** A recorded field against the re-read one; the flags by value, key by key. */
function sameStatement(claimed: unknown, reread: unknown): boolean {
  if (reread !== null && typeof reread === 'object') {
    if (claimed === null || typeof claimed !== 'object' || Array.isArray(claimed)) return false;
    const a = claimed as Record<string, unknown>;
    const b = reread as Record<string, unknown>;
    const keys = Object.keys(b);
    return Object.keys(a).length === keys.length && keys.every((k) => Object.is(a[k], b[k]));
  }
  return Object.is(claimed, reread);
}

/**
 * Pass 4. Reports what is wrong with the record's chain link against the
 * bundled predecessor and returns the predecessor digest it checked against
 * (null when the bundle names none).
 */
function checkChainLink(
  errors: string[],
  position: ExportedChainPosition | undefined,
  payload: EvidenceEnvelope['payload'],
  integrity: EvidenceEnvelope['integrity'],
): string | null {
  const seq: unknown = payload.sequenceNumber;
  const link: unknown = integrity.chainLink;
  const needsPredecessor = link !== null || (typeof seq === 'number' && seq > 1);

  if (position === null || typeof position !== 'object') {
    if (needsPredecessor) {
      errors.push('chain: the bundle carries no predecessor, so integrity.chainLink cannot be checked');
    }
    return null;
  }
  const predecessor: unknown = position.predecessor;
  if (predecessor === null || predecessor === undefined) {
    if (link !== null) {
      errors.push('chain: integrity.chainLink is set but the bundle names no predecessor to check it against');
    } else if (typeof seq === 'number' && seq > 1) {
      errors.push(`chain: record ${seq} carries no chain link and the bundle names no predecessor`);
    }
    return null;
  }
  if (typeof predecessor !== 'object') {
    errors.push('chain: predecessor is not an object');
    return null;
  }
  const p = predecessor as Record<string, unknown>;
  const digest = p.canonicalDigest;
  if (typeof digest !== 'string' || !ENVELOPE_DIGEST_FORM.test(digest)) {
    errors.push(`chain: predecessor digest "${String(digest)}" is not in the required bare "<64 lowercase hex>" form`);
    return null;
  }
  if (typeof seq !== 'number' || p.sequenceNumber !== seq - 1) {
    errors.push(
      `chain: the bundled predecessor is at sequence ${String(p.sequenceNumber)}, not at the one before ${String(seq)}`,
    );
  }
  const stored = integrity.canonicalDigest;
  if (typeof stored === 'string') {
    const expected = sha256(digest + stored);
    if (link !== expected) {
      errors.push(
        `chain: integrity.chainLink (${String(link)}) does not recompute from the bundled predecessor digest (expected ${expected})`,
      );
    }
  }
  return digest;
}

/** The custody block's rows, or null when the bundle carries none. */
function custodyEntriesOf(custody: unknown): CustodyLedgerEntry[] | null {
  if (custody === null || typeof custody !== 'object') return null;
  const entries = (custody as Partial<ExportedCustody>).entries;
  return Array.isArray(entries) ? entries : null;
}

function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Parse the digest-covered descriptor out of an entry's `canonicalBytes`.
 *
 * Mirrors `parseDescriptorBytes` in packages/engine/src/verify.ts. These
 * bytes are the only part of a bundled entry that the digest key commits
 * to, so they are the only part the lineage walk may advance on. Returns
 * null when the bytes are not a JSON object, which the caller turns into a
 * reported error rather than a fall-back to the enriched view.
 */
function parseDescriptorBytes(canonicalBytes: string): ModelDescriptor | null {
  try {
    const parsed = JSON.parse(canonicalBytes) as unknown;
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null;
    }
    return parsed as ModelDescriptor;
  } catch {
    return null;
  }
}
