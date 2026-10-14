/**
 * Evidence export pipeline.
 *
 * One route:
 *   GET /v1/evidence/:id/export?walkLineage=true|false
 *   GET /v1/evidence/:id/export?bundle=b1
 *
 * Returns an `ExportedEvidenceEnvelope`: the original envelope plus every
 * referenced `ModelDescriptor` (canonical bytes + enriched view + annotation
 * log), keyed by digest. With `walkLineage=true` (the default), the bundle
 * inlines the full ancestor DAG (depth-limited 16, cycle-safe).
 *
 * With `bundle=b1`, returns the record's `b1` proof bundle instead
 * (`tzun.exportBundle()`, Bundle §3): the record with its anchoring
 * material or its `anchorPending` slot, which `verifyBundle()` verifies with no
 * access to this store. `walkLineage` does not apply to it; any other `bundle`
 * value is a 400.
 *
 * Auth model:
 *   - Unauthenticated, matching the `/v1/evidence/*` and `/v1/models/*`
 *     convention. A reverse proxy / API gateway is the assumed bearer-token
 *     boundary in production deployments.
 *
 * Exporter identity:
 *   - The bundle's `exportedBy` is always `'rest-export'`. The route has no
 *     authenticated caller to name, so it names itself. A caller-supplied
 *     `?exportedBy=` is refused with 400: recording it would let any caller
 *     make a bundle name anyone as its exporter, and dropping it silently
 *     would let the caller believe it had been recorded. An in-process
 *     caller that knows who is exporting passes `exportedBy` to
 *     `tzun.exportEvidence()` directly.
 *
 * Response:
 *   - 200 with the JSON bundle and
 *     `Content-Disposition: attachment; filename="evidence-<id>.json"` so
 *     browsers offer a download.
 *   - 400 for an unsupported `format` or `bundle`, or any `exportedBy` parameter.
 *   - 404 when the evidence ID is unknown.
 */
import { Router, Request, Response } from 'express';
import { Tzun } from '../sdk/index';
import { respondInternalError } from './error-response';

/** The `exportedBy` every bundle from this route carries. */
const REST_EXPORTED_BY = 'rest-export';

export function createExportRouter(tzun: Tzun): Router {
  const router = Router();

  router.get('/v1/evidence/:id/export', async (req: Request, res: Response) => {
    try {
      // Parse `format` honestly. JSON is the only format the exporter
      // produces; anything else is a 400, not silence.
      const formatRaw = typeof req.query.format === 'string' ? req.query.format : undefined;
      if (formatRaw !== undefined && formatRaw.toLowerCase() !== 'json') {
        res.status(400).json({
          error: `unsupported export format "${formatRaw}"; supported: json`,
        });
        return;
      }

      // Parse ?walkLineage. Default true. Explicit "false" disables; anything
      // else (including absent) keeps the default.
      const walkLineageRaw = typeof req.query.walkLineage === 'string'
        ? req.query.walkLineage.toLowerCase()
        : undefined;
      const walkLineage = walkLineageRaw !== 'false';

      if (req.query.exportedBy !== undefined) {
        res.status(400).json({
          error:
            'exportedBy is not accepted: this route is unauthenticated, so it ' +
            `records "${REST_EXPORTED_BY}" as the exporter`,
        });
        return;
      }

      const bundleRaw = req.query.bundle;
      if (bundleRaw !== undefined && bundleRaw !== 'b1') {
        res.status(400).json({
          error: `unsupported bundle version "${String(bundleRaw)}"; supported: b1`,
        });
        return;
      }

      const evidenceId = req.params.id as string;

      const bundle =
        bundleRaw === 'b1'
          ? await tzun.exportBundle(evidenceId, { exportedBy: REST_EXPORTED_BY })
          : await tzun.exportEvidence(evidenceId, {
              walkLineage,
              exportedBy: REST_EXPORTED_BY,
            });

      res.setHeader(
        'Content-Disposition',
        `attachment; filename="evidence-${evidenceId}.json"`,
      );
      res.status(200).json(bundle);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      // Both exports throw "Evidence record … not found" for an unknown id;
      // map that to 404, otherwise 500.
      if (/not found/i.test(msg)) {
        res.status(404).json({ error: msg });
        return;
      }
      respondInternalError(res, error);
    }
  });

  return router;
}
