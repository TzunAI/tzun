/**
 * REST endpoints for the AI-BOM model catalog.
 *
 * Auth model:
 *   - All GETs are open on the v1 surface today (matching the pattern of
 *     `/v1/evidence` and `/v1/integrity/*`). A reverse proxy or API gateway
 *     is the assumed bearer-token boundary in production deployments.
 *   - Mutating POSTs require an admin token via `X-Tzun-Admin-Token` header,
 *     checked against the `TZUN_ADMIN_TOKEN` environment variable.
 *   - When `TZUN_ADMIN_TOKEN` is unset, admin-gated writes return 503 — the
 *     server refuses to let anyone become "admin by default."
 *
 * Weights-based registration is CLI-only. The route rejects `weightsPath`
 * over REST with 400; accepting arbitrary server-side paths without a
 * whitelist is a security risk.
 */
import { Router, Request, Response, NextFunction } from 'express';
import { Tzun } from '../sdk/index';
import { registerModel } from '../models/register';
import {
  annotateModelDescriptor,
  TYPED_ANNOTATION_TYPES,
} from '../models/annotations';
import type { ResolveActor } from './actor-resolver';
import { constantTimeEqual } from './constant-time';
import { walkLineageDetailed } from '../models/lineage';
import {
  ModelDescriptor,
  ModelDescriptorRow,
  ModelDescriptorSource,
} from '@tzun/engine';
import { respondInternalError } from './error-response';
import { parsePaginationParam, InvalidPaginationError } from '../storage/pagination-guard';

const ADMIN_HEADER = 'x-tzun-admin-token';
// MAX_LINEAGE_DEPTH is defined in src/models/lineage.ts — imported via walkLineage.

/**
 * Rows `GET /v1/models` returns when the caller gives no `limit`. The hosted
 * service's GET /v1/models takes no limit and always returns up to its own
 * maximum, so the default is that same number.
 */
export const DEFAULT_MODEL_LIST_LIMIT = 1000;

/**
 * Most rows one `GET /v1/models` returns: the platform's `MAX_MODEL_ROWS`. A
 * larger `limit` is clamped to this; callers page with `offset` for the rest.
 */
export const MAX_MODEL_LIST_LIMIT = 1000;

/**
 * Admin-token middleware. Requires `TZUN_ADMIN_TOKEN` to be set; otherwise
 * returns 503 so no caller can pose as admin by default.
 */
function requireAdminToken(req: Request, res: Response, next: NextFunction): void {
  const expected = process.env.TZUN_ADMIN_TOKEN;
  if (!expected) {
    res.status(503).json({
      error:
        'admin operations are disabled: server TZUN_ADMIN_TOKEN is not configured',
    });
    return;
  }
  const supplied = req.header(ADMIN_HEADER);
  if (!constantTimeEqual(supplied, expected)) {
    res.status(403).json({ error: 'admin token required' });
    return;
  }
  next();
}

/** Returns true iff the caller is admin-authenticated. */
function isAdminRequest(req: Request): boolean {
  const expected = process.env.TZUN_ADMIN_TOKEN;
  if (!expected) {
    return false;
  }
  return constantTimeEqual(req.header(ADMIN_HEADER), expected);
}

/** Strips `canonicalBytes` from a row for list responses. */
function stripCanonicalBytes(row: ModelDescriptorRow): Omit<ModelDescriptorRow, 'canonicalBytes'> {
  const { canonicalBytes: _unused, ...rest } = row;
  void _unused;
  return rest;
}


/** Options for `createModelsRouter`. */
export interface ModelsRouterOptions {
  /**
   * Pluggable actor resolver. When provided, freeform-note
   * annotations are accepted from authenticated actors in addition to the
   * admin path — the actor identity is server-assigned, not
   * asserted by the client.
   */
  resolveActor?: ResolveActor;
}

export function createModelsRouter(tzun: Tzun, options?: ModelsRouterOptions): Router {
  const router = Router();

  // ── GET /v1/models (list + filter + paginate) ────────────────────────
  router.get('/v1/models', async (req: Request, res: Response) => {
    try {
      const storage = tzun.getStorage();
      if (!storage.listModelDescriptors) {
        res.status(501).json({ error: 'catalog is not supported by this storage adapter' });
        return;
      }

      const filter: Parameters<NonNullable<typeof storage.listModelDescriptors>>[0] = {};
      if (typeof req.query.vendor === 'string') filter.vendor = req.query.vendor;
      if (typeof req.query.modelName === 'string') filter.modelName = req.query.modelName;
      if (typeof req.query.modelVersion === 'string') {
        filter.modelVersion = req.query.modelVersion;
      }
      if (typeof req.query.integrityTier === 'string') {
        filter.integrityTier = req.query.integrityTier as
          | 'weight-attested'
          | 'vendor-asserted';
      }
      if (typeof req.query.hasRegulatoryMarking === 'string') {
        filter.hasRegulatoryMarking = req.query.hasRegulatoryMarking === 'true';
      }
      // Strict parse: a malformed bound is a 400, never coerced. A
      // well-formed limit is never refused: absent means the default, and
      // anything above the ceiling is clamped to it.
      let limit: number | undefined;
      let offset: number | undefined;
      try {
        limit = parsePaginationParam(req.query.limit, 'limit');
        offset = parsePaginationParam(req.query.offset, 'offset');
      } catch (error) {
        if (error instanceof InvalidPaginationError) {
          res.status(400).json({ error: 'Bad request', message: error.message });
          return;
        }
        throw error;
      }
      filter.limit = Math.min(limit ?? DEFAULT_MODEL_LIST_LIMIT, MAX_MODEL_LIST_LIMIT);
      if (offset !== undefined) filter.offset = offset;

      const rows = await storage.listModelDescriptors(filter);
      res.status(200).json({
        models: rows.map(stripCanonicalBytes),
        total: rows.length,
      });
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  // ── GET /v1/models/by-alias/:slug (resolve slug → row) ───────────────
  // Note: declared before `/v1/models/:digest` so Express doesn't match the
  // literal "by-alias" segment as a digest parameter.
  router.get('/v1/models/by-alias/:slug', async (req: Request, res: Response) => {
    try {
      const storage = tzun.getStorage();
      if (!storage.resolveModelDescriptorAlias || !storage.getModelDescriptor) {
        res.status(501).json({ error: 'catalog is not supported by this storage adapter' });
        return;
      }
      const slug = req.params.slug as string;
      const digest = await storage.resolveModelDescriptorAlias(slug);
      if (!digest) {
        res.status(404).json({ error: `alias "${slug}" is not bound` });
        return;
      }
      const row = await storage.getModelDescriptor(digest);
      if (!row) {
        res.status(404).json({
          error: `alias "${slug}" points at digest "${digest}" but the descriptor is missing`,
        });
        return;
      }
      res.status(200).json(row);
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  // ── GET /v1/models/usage (admin telemetry) ──────────────────────────────
  // Must be declared BEFORE /v1/models/:digest so "usage" is not matched as
  // a descriptor digest (same ordering trick as /v1/models/by-alias/:slug).
  router.get('/v1/models/usage', requireAdminToken, (_req: Request, res: Response) => {
    res.status(200).json({ usage: tzun.getConnectorUsageStats() });
  });

  // ── GET /v1/models/:digest (canonical view) ──────────────────────────
  router.get('/v1/models/:digest', async (req: Request, res: Response) => {
    try {
      const storage = tzun.getStorage();
      if (!storage.getModelDescriptor) {
        res.status(501).json({ error: 'catalog is not supported by this storage adapter' });
        return;
      }
      const row = await storage.getModelDescriptor(req.params.digest as string);
      if (!row) {
        res.status(404).json({ error: `model descriptor "${req.params.digest}" not found` });
        return;
      }
      res.status(200).json(row);
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  // ── GET /v1/models/:digest/enriched (enriched view) ──────────────────
  router.get('/v1/models/:digest/enriched', async (req: Request, res: Response) => {
    try {
      const storage = tzun.getStorage();
      if (!storage.getEnrichedModelDescriptor) {
        res.status(501).json({ error: 'catalog is not supported by this storage adapter' });
        return;
      }
      const descriptor = await storage.getEnrichedModelDescriptor(
        req.params.digest as string,
      );
      if (!descriptor) {
        res.status(404).json({ error: `model descriptor "${req.params.digest}" not found` });
        return;
      }
      res.status(200).json(descriptor);
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  // ── GET /v1/models/:digest/annotations (annotation log) ──────────────
  router.get('/v1/models/:digest/annotations', async (req: Request, res: Response) => {
    try {
      const storage = tzun.getStorage();
      if (!storage.listModelDescriptorAnnotations || !storage.getModelDescriptor) {
        res.status(501).json({ error: 'catalog is not supported by this storage adapter' });
        return;
      }
      const digest = req.params.digest as string;
      const row = await storage.getModelDescriptor(digest);
      if (!row) {
        res.status(404).json({ error: `model descriptor "${digest}" not found` });
        return;
      }
      const annotations = await storage.listModelDescriptorAnnotations(digest);
      res.status(200).json({ annotations });
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  // ── GET /v1/models/:digest/lineage (parent-DAG walk) ─────────────────
  router.get('/v1/models/:digest/lineage', async (req: Request, res: Response) => {
    try {
      const walk = await walkLineageDetailed(tzun.getStorage(), req.params.digest as string);
      if (walk === null) {
        res.status(404).json({ error: `model descriptor "${req.params.digest}" not found` });
        return;
      }
      // `complete` / `terminal` / `missingParentDigest` sit beside `lineage`.
      // Without them a truncated walk is byte-identical to a
      // complete one, so a report can state "no parent model" about a
      // fine-tune whose parent simply was never registered.
      res.status(200).json({
        lineage: walk.entries,
        complete: walk.complete,
        terminal: walk.terminal,
        ...(walk.missingParentDigest !== undefined && {
          missingParentDigest: walk.missingParentDigest,
        }),
      });
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  // ── POST /v1/models (register; admin-gated) ──────────────────────────
  router.post('/v1/models', requireAdminToken, async (req: Request, res: Response) => {
    try {
      const body = req.body ?? {};
      if (body.weightsPath !== undefined && body.weightsPath !== null) {
        res.status(400).json({
          error:
            'weightsPath is not accepted over the REST API; use the CLI for weights-based registration',
        });
        return;
      }

      const descriptor = body.descriptor as Partial<ModelDescriptor> | undefined;
      if (!descriptor || typeof descriptor !== 'object') {
        res.status(400).json({ error: 'request body must include a "descriptor" object' });
        return;
      }

      const source = (body.source as ModelDescriptorSource | undefined) ?? 'manual';
      const registeredBy =
        typeof body.registeredBy === 'string' ? body.registeredBy : 'rest-admin';

      const result = await registerModel(tzun.getStorage(), descriptor, {
        source,
        registeredBy,
      });
      res.status(201).json(result);
    } catch (error) {
      // assembleDescriptor throws on missing MVD fields — surface as 400.
      const msg = error instanceof Error ? error.message : String(error);
      if (/Minimum Viable Descriptor/.test(msg)) {
        res.status(400).json({ error: msg });
        return;
      }
      respondInternalError(res, error);
    }
  });

  // ── POST /v1/models/:digest/annotations (append annotation) ──────────
  // Annotation policy:
  //   - Typed annotations (deprecation, retraction, provenance, …) remain
  //     ADMIN-ONLY — any non-admin attempt is 403.
  //   - Freeform-note:
  //       • Admin-token path: unchanged — admin can supply any annotatedBy.
  //       • Resolver path: when `options.resolveActor` is configured and
  //         resolves a principal, freeform-note is accepted; `annotatedBy`
  //         is server-assigned to the resolved actor — a client-
  //         supplied `annotatedBy` that disagrees with the principal → 400.
  //       • No-resolver-configured path: 403 (today's admin-only behavior).
  // Per-request size limits on `value` / `note` keep the append-only
  // catalog from being permanently inflated.
  const MAX_VALUE_JSON_BYTES = 4096;
  const MAX_NOTE_LENGTH = 1024;
  router.post(
    '/v1/models/:digest/annotations',
    async (req: Request, res: Response) => {
      try {
        const storage = tzun.getStorage();
        if (!storage.appendModelDescriptorAnnotation || !storage.getModelDescriptor) {
          res
            .status(501)
            .json({ error: 'annotations are not supported by this storage adapter' });
          return;
        }
        const digest = req.params.digest as string;
        const body = req.body ?? {};
        const annotationType = body.annotationType;
        const value = body.value;
        const annotatedBy = body.annotatedBy;
        const note = body.note;
        const signature = body.signature;

        if (typeof annotationType !== 'string' || annotationType.length === 0) {
          res.status(400).json({ error: 'annotationType is required' });
          return;
        }
        if (typeof value !== 'object' || value === null) {
          res.status(400).json({ error: 'value must be an object' });
          return;
        }

        // Size bounds — annotations are append-only, so an unbounded payload
        // would permanently inflate the catalog.
        const valueJsonBytes = Buffer.byteLength(JSON.stringify(value), 'utf8');
        if (valueJsonBytes > MAX_VALUE_JSON_BYTES) {
          res.status(413).json({
            error: `annotation value exceeds ${MAX_VALUE_JSON_BYTES} bytes (got ${valueJsonBytes})`,
          });
          return;
        }
        if (note !== undefined) {
          if (typeof note !== 'string') {
            res.status(400).json({ error: 'note must be a string' });
            return;
          }
          if (note.length > MAX_NOTE_LENGTH) {
            res.status(413).json({
              error: `annotation note exceeds ${MAX_NOTE_LENGTH} characters (got ${note.length})`,
            });
            return;
          }
        }

        // Verify the descriptor exists before checking auth — gives 404
        // for the unknown-digest case regardless of auth state.
        const row = await storage.getModelDescriptor(digest);
        if (!row) {
          res.status(404).json({ error: `model descriptor "${digest}" not found` });
          return;
        }

        // Auth gate: resolve admin + principal, then apply policy.
        const isAdmin = isAdminRequest(req);
        const isFreeform = annotationType === 'freeform-note';
        const principal = options?.resolveActor ? options.resolveActor(req) : null;

        if (!isAdmin && !(isFreeform && principal)) {
          res.status(403).json({
            error: 'annotation writes require admin auth (X-Tzun-Admin-Token)' +
              (options?.resolveActor ? ' or an authenticated actor (freeform-note only)' : ''),
          });
          return;
        }

        // Authenticated-non-admin attribution is SERVER-assigned.
        let effectiveAnnotatedBy: string;
        if (!isAdmin && isFreeform && principal) {
          // Resolver path: annotatedBy is derived from the principal.
          if (typeof annotatedBy === 'string' && annotatedBy !== principal.actor) {
            res.status(400).json({
              error: 'annotatedBy must match the authenticated actor (attribution is authenticated, not asserted)',
            });
            return;
          }
          effectiveAnnotatedBy = principal.actor;
        } else {
          // Admin path: client-supplied annotatedBy is accepted.
          if (typeof annotatedBy !== 'string' || annotatedBy.length === 0) {
            res.status(400).json({ error: 'annotatedBy is required' });
            return;
          }
          effectiveAnnotatedBy = annotatedBy;
        }

        // Reference the typed-annotation table so the underlying runtime check
        // stays consistent with this route's outer gate.
        void TYPED_ANNOTATION_TYPES;

        const annotation = await annotateModelDescriptor(
          storage,
          digest,
          { annotationType, value },
          {
            isAdmin,
            annotatedBy: effectiveAnnotatedBy,
            ...(typeof note === 'string' ? { note } : {}),
            ...(typeof signature === 'string' ? { signature } : {}),
          },
        );
        res.status(201).json(annotation);
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        if (/requires admin auth/.test(msg)) {
          res.status(403).json({ error: msg });
          return;
        }
        if (/requires value\.retractsAnnotationId/.test(msg)) {
          res.status(400).json({ error: msg });
          return;
        }
        respondInternalError(res, error);
      }
    },
  );

  // ── POST /v1/models/aliases (set alias; admin-gated) ─────────────────
  router.post(
    '/v1/models/aliases',
    requireAdminToken,
    async (req: Request, res: Response) => {
      try {
        const storage = tzun.getStorage();
        if (!storage.setModelDescriptorAlias || !storage.getModelDescriptor) {
          res
            .status(501)
            .json({ error: 'aliases are not supported by this storage adapter' });
          return;
        }
        const body = req.body ?? {};
        const slug = body.slug;
        const digest = body.digest;
        const setBy = typeof body.setBy === 'string' ? body.setBy : 'rest-admin';

        if (typeof slug !== 'string' || slug.length === 0) {
          res.status(400).json({ error: 'slug is required' });
          return;
        }
        if (typeof digest !== 'string' || digest.length === 0) {
          res.status(400).json({ error: 'digest is required' });
          return;
        }

        const row = await storage.getModelDescriptor(digest);
        if (!row) {
          res.status(404).json({ error: `model descriptor "${digest}" not found` });
          return;
        }

        await storage.setModelDescriptorAlias(slug, digest, setBy);
        const setAt = new Date().toISOString();
        res.status(201).json({
          slug,
          modelDescriptorDigest: digest,
          setBy,
          setAt,
        });
      } catch (error) {
        respondInternalError(res, error);
      }
    },
  );

  return router;
}
