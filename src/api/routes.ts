/**
 * Evidence routes: capture, read, verify and list.
 *
 *   POST /v1/evidence               capture a decision
 *   GET  /v1/evidence/:id           read one record: `{ envelope, verdict }`
 *   POST /v1/evidence/:id/verify    verify one envelope
 *   GET  /v1/evidence               list records, each `{ envelope, verdict }`
 *                                   (limit ≤ MAX_LIST_LIMIT)
 *
 * The reads are `tzun.get()` and `tzun.list()`, so every record they return
 * carries the read-time verdict on it, and a record that fails is returned
 * with an `invalid` verdict rather than withheld.
 *
 * Every route is authenticated as the host chose when it built the router
 * (see `rest-auth.ts`): with a `resolveActor`, a request without a recognised
 * credential is refused 401 before any body is read; with
 * `allowUnauthenticated: true`, anyone who can reach the router may capture,
 * read, verify and list. The check sits on each route rather than on the
 * router, so a host route mounted beside this router is not affected. Who
 * decided is the body's `decider`, as the caller asserted it; it is hashed
 * into the record, and the custody actor is its identifier. See `server.ts`
 * for how this layer is meant to be exposed.
 *
 * The POST routes parse their own JSON bodies, after the auth check, so the
 * router works on an app with no body parser of its own.
 */
import { Router, Request, Response } from 'express';
import { Tzun } from '../sdk/index';
import { parsePaginationParam, InvalidPaginationError } from '../storage/pagination-guard';
import { respondInternalError } from './error-response';
import { restAuthGate, type RestAuthOptions } from './rest-auth';
import { jsonBodyParser, respondBodyRefusal } from './json-body';

/**
 * Rows `GET /v1/evidence` returns when the caller gives no `limit`. Same value
 * as the hosted service's list reads.
 */
export const DEFAULT_LIST_LIMIT = 100;

/**
 * Most rows one `GET /v1/evidence` returns. A larger `limit` is clamped to
 * this, as the platform's list reads clamp to their `MAX_LIMIT`; callers page
 * with `offset` to reach the rest.
 */
export const MAX_LIST_LIMIT = 200;

/** Options for {@link createRouter}: the routes' authentication. */
export type EvidenceRouterOptions = RestAuthOptions;

/**
 * Build the evidence router. Throws unless `options` makes an explicit
 * authentication choice (see {@link RestAuthOptions}).
 */
export function createRouter(tzun: Tzun, options: EvidenceRouterOptions): Router {
  const requireAuth = restAuthGate(options, 'createRouter');
  const parseJson = jsonBodyParser();
  const router = Router();

  router.post(
    '/v1/evidence',
    requireAuth,
    parseJson,
    respondBodyRefusal,
    async (req: Request, res: Response) => {
      try {
        const result = await tzun.capture(req.body);

        if (!result.stored) {
          res.status(400).json(result);
          return;
        }

        res.status(201).json(result);
      } catch (error) {
        respondInternalError(res, error);
      }
    },
  );

  router.get('/v1/evidence/:id', requireAuth, async (req: Request, res: Response) => {
    try {
      const read = await tzun.get(req.params.id as string);

      if (!read) {
        res.status(404).json({ error: `Evidence record "${req.params.id}" not found.` });
        return;
      }

      res.status(200).json(read);
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  router.post(
    '/v1/evidence/:id/verify',
    requireAuth,
    parseJson,
    respondBodyRefusal,
    async (req: Request, res: Response) => {
      try {
        const previousDigest = req.body?.previousDigest as string | undefined;
        const result = await tzun.verify(req.params.id as string, previousDigest);
        res.status(200).json(result);
      } catch (error) {
        if (error instanceof Error && error.message.includes('not found')) {
          res.status(404).json({ error: error.message });
          return;
        }
        respondInternalError(res, error);
      }
    },
  );

  router.get('/v1/evidence', requireAuth, async (req: Request, res: Response) => {
    try {
      // parseInt('abc') is NaN and parseInt('9 OR 1=1') is 9 — neither is a
      // rejection. Validate and answer 400 rather than handing an unusable
      // bound to the storage layer, which would surface as an opaque 500.
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
      // A well-formed limit is never refused: absent means the default, and
      // anything above the ceiling is clamped to it.
      const boundedLimit = Math.min(limit ?? DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT);
      const options = {
        aiSystemId: req.query.aiSystemId as string | undefined,
        limit: boundedLimit,
        offset,
        order: (req.query.order as 'asc' | 'desc') ?? undefined,
      };
      res.status(200).json(await tzun.list(options));
    } catch (error) {
      respondInternalError(res, error);
    }
  });

  return router;
}
