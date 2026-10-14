import { Router, Request, Response } from 'express';
import { Tzun } from '../sdk/index';
import { computeIntegrityStatus } from './integrity-status';
import { TamperIncidentStatus, TamperSeverity, VerificationResult } from '@tzun/engine';
import { respondInternalError } from './error-response';

export function createIntegrityRouter(tzun: Tzun): Router {
  const router = Router();

  router.get('/v1/integrity/status', async (_req: Request, res: Response) => {
    try {
      const storage = tzun.getStorage();
      const scannerState = tzun.getScannerState();
      const activeChainId = await tzun.getActiveChainId();
      const sealedCount = await tzun.getSealedChainCount();
      // totalRecords is left to computeIntegrityStatus, which counts every
      // chain. Reading storage.getLastSequence() here overrode that count with
      // the active chain's sequence counter — the value fork() resets — so the
      // published status under-reported a forked store by every sealed record
      // it held.

      let pendingAttestations = 0;
      try {
        const pending = await storage.listByAttestationStatus('pending');
        pendingAttestations = pending.length;
      } catch {
        // listByAttestationStatus may not be implemented in all adapters
      }

      const status = await computeIntegrityStatus({
        storage,
        scannerState,
        activeChainId,
        sealedChains: sealedCount,
        pendingAttestations,
      });

      res.status(200).json(status);
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  router.get('/v1/integrity/incidents', async (req: Request, res: Response) => {
    try {
      const storage = tzun.getStorage();
      const filter: {
        status?: TamperIncidentStatus;
        severity?: TamperSeverity;
      } = {};

      if (req.query.status) {
        filter.status = req.query.status as TamperIncidentStatus;
      }
      if (req.query.severity) {
        filter.severity = req.query.severity as TamperSeverity;
      }

      const incidents = await storage.listIncidents(
        Object.keys(filter).length > 0 ? filter : undefined,
      );
      res.status(200).json(incidents);
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  router.get('/v1/integrity/incidents/:id', async (req: Request, res: Response) => {
    try {
      const storage = tzun.getStorage();
      const incident = await storage.getIncident(req.params.id as string);

      if (!incident) {
        res.status(404).json({
          error: `Tamper incident "${req.params.id}" not found.`,
        });
        return;
      }

      res.status(200).json(incident);
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  // Contract — the body carries `digestMismatches: string[]`, the evidence IDs
  // of records that do not hash to their stored canonicalDigest, at the top
  // level and inside every `chains[]` entry. `valid` and `allChainsValid` go
  // false for a rewritten payload, although a payload rewrite that leaves the
  // digest stale disturbs nothing structural. A client that explains a red
  // `valid` by listing sequenceGaps/duplicateSequences/brokenLinks alone shows
  // an unexplained red unless it reads this array too.
  //
  // Contract — the body carries `digestSuperseded: string[]`,
  // evidence IDs whose current canonicalDigest is not the one they were
  // CAPTURED with, at the top level and inside every `chains[]` entry.
  // `valid` and `allChainsValid` AND it in. This is the finding that is not
  // an answer about the store's present state: the rewrite-and-reseat attack
  // leaves a record that hashes to its own (recomputed) digest with its own
  // link repaired, so it appears here and NOWHERE else — `brokenLinks` names
  // only its successor, which is indistinguishable from an honest link
  // corruption. A record captured before 0.3.16 has no capture revision and
  // can never appear; that absence means unprovable, not clean.
  //
  // Contract — which chain is answered about:
  //
  //   ?chainId=<id>  verify exactly that chain. 404 if the store has chain
  //                  identities and none of them match.
  //   (no query)     the ACTIVE chain at the top level, which for a store that
  //                  has never forked is the whole store, plus `chainId`
  //                  naming the chain answered about,
  //                  `chains[]` with one result per chain (sealed included),
  //                  and `allChainsValid`, the AND across `chains`.
  //
  // Top-level `valid` stays scoped to the chain the top-level counters
  // describe: reporting `valid: false` beside an empty `brokenLinks` would be
  // self-contradictory on its face. A caller that wants the whole store reads
  // `allChainsValid`. Walking every chain's records in one interleaved
  // sequence order instead would make any forked store answer `valid: false`
  // with fabricated duplicates and broken links.
  router.get('/v1/integrity/chain', async (req: Request, res: Response) => {
    try {
      const requested = req.query.chainId as string | undefined;

      if (requested) {
        const known = await tzun.getStorage().listChains();
        if (known.length > 0 && !known.some((c) => c.chainId === requested)) {
          res.status(404).json({ error: `Chain "${requested}" not found.` });
          return;
        }
        res.status(200).json(await tzun.verifyChainCompleteness(requested));
        return;
      }

      const report = await tzun.verifyAllChains();
      res.status(200).json({
        ...report.active,
        allChainsValid: report.valid,
        activeChainId: report.activeChainId,
        chains: report.chains,
      });
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  router.get('/v1/integrity/scanner', async (_req: Request, res: Response) => {
    try {
      const scannerState = tzun.getScannerState();

      if (!scannerState) {
        res.status(200).json({
          currentPassStartedAt: null,
          lastCompletedPassAt: null,
          lastCompletedPass: null,
          totalPasses: 0,
          highWaterMark: 0,
          segmentsInProgress: [],
        });
        return;
      }

      res.status(200).json(scannerState);
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  // NOTE: /range must be registered before /:evidenceId to avoid
  // Express matching "range" as a parameterized evidenceId.
  router.post('/v1/integrity/verify/range', async (req: Request, res: Response) => {
    try {
      const fromSequence = req.body?.fromSequence as number | undefined;
      const toSequence = req.body?.toSequence as number | undefined;

      if (fromSequence === undefined || fromSequence === null) {
        res.status(400).json({
          error: 'fromSequence is required in request body.',
        });
        return;
      }

      if (toSequence !== undefined && fromSequence > toSequence) {
        res.status(400).json({
          error: 'fromSequence must be less than or equal to toSequence.',
        });
        return;
      }

      const result = await tzun.verifyRange(fromSequence, toSequence);
      res.status(200).json(result);
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  router.post('/v1/integrity/verify/:evidenceId', async (req: Request, res: Response) => {
    try {
      const evidenceId = req.params.evidenceId as string;
      const clientPreviousDigest = req.body?.previousDigest as string | undefined;

      const result = await tzun.verify(evidenceId, clientPreviousDigest);

      // Monitoring events are emitted ONLY when the predecessor was resolved by
      // the server.
      //
      // `previousDigest` is an unauthenticated request-body field, and
      // Tzun.verify prefers the caller's value over the one it would resolve
      // itself. A caller who posts `{"previousDigest":"deadbeef"}` against any
      // real evidence id therefore drives chainLinkValid to false — on an
      // untouched record, and on a genesis record too. Fed to the incident
      // pipeline, that caller-induced false negative would become a persisted
      // CRITICAL chain_break incident for any record the caller names:
      // /v1/integrity/status would flip to 'compromised', and (subject to
      // NotificationRouter's one-hour per-record suppression) PagerDuty, Slack,
      // webhook and email would fire, with nothing touching the evidence.
      //
      // An ad-hoc check against a caller-supplied predecessor still returns its
      // result; it does not feed the incident pipeline.
      if (clientPreviousDigest === undefined && !result.verified) {
        await emitOnDemandVerificationFailure(tzun, evidenceId, result);
      }

      res.status(200).json(result);
    } catch (error) {
      if (error instanceof Error && error.message.includes('not found')) {
        res.status(404).json({ error: error.message });
        return;
      }
      respondInternalError(res, error);
    }
  });

  return router;
}

/**
 * Turn a failed server-resolved verification into the monitoring event that
 * actually describes it, with the record's real sequence number and
 * predecessor digest rather than the placeholder `0` / `''`.
 *
 * Only ever called when the server resolved the predecessor itself — a
 * caller-supplied `previousDigest` must never reach the incident pipeline.
 */
async function emitOnDemandVerificationFailure(
  tzun: Tzun,
  evidenceId: string,
  result: VerificationResult,
): Promise<void> {
  // An unknown schemaVersion leaves recomputedDigest === '' because there are
  // no serialization rules to hash with. The registry only ever contains v1.0,
  // so any other value is itself evidence of modification, and reporting it as
  // a digest problem (recomputed='') is deliberate, not a mislabel.
  if (result.storedDigest !== result.recomputedDigest) {
    tzun.emitMonitoringEvent({
      type: 'digest_mismatch',
      evidenceId,
      stored: result.storedDigest,
      recomputed: result.recomputedDigest,
    });
    return;
  }

  if (result.chainLinkValid === false) {
    const envelope = await tzun.getStorage().retrieve(evidenceId);
    const predecessorDigest = await tzun.getPredecessorDigest(evidenceId);
    tzun.emitMonitoringEvent({
      type: 'chain_break',
      evidenceId,
      sequenceNumber: envelope?.payload.sequenceNumber ?? 0,
      expectedPrevDigest: predecessorDigest ?? '',
    });
    return;
  }

  // Descriptor-catalog failures flip `verified` without touching the digest or
  // the chain link. Re-emit them so an on-demand verify of a tampered catalog
  // row reaches the incident pipeline instead of being silently dropped.
  for (const incident of result.tamperIncidents ?? []) {
    tzun.emitMonitoringEvent(incident);
  }
}
