/**
 * Supported surface — the SDK's thin Express REST layer is the supported
 * surface for self-hosted deployments and demos. Load-bearing consumers: the
 * demo application (createModelsRouter, createExportRouter), this
 * createServer (all five routers), the annotation policy + endpoint-parity
 * tests.
 *
 * Authentication — `createServer` refuses to build without an explicit choice
 * (see `rest-auth.ts`), and the choice governs every route it mounts: capture,
 * evidence read / verify / list, export, integrity, the catalog, and the
 * benchmark when it is on.
 *
 *   - `{ resolveActor }` — every request under `/v1` must carry a credential
 *     the resolver recognises, or it is answered 401 `{ error:
 *     'unauthenticated' }` before any body is read and before routing, so an
 *     unknown `/v1` path is a 401 too. The resolver is also handed to the
 *     models router, so a resolved actor can post freeform-note annotations,
 *     attributed to itself. Registering models, setting aliases, typed
 *     annotations and connector telemetry also need `TZUN_ADMIN_TOKEN`
 *     (`X-Tzun-Admin-Token`).
 *   - `{ allowUnauthenticated: true }` — every route answers any caller that
 *     can reach the server; the admin-token routes still need the admin token.
 *
 * Paths outside `/v1` are neither checked nor body-parsed, so a host that
 * mounts this app inside its own keeps its own routes as they were.
 * `createServer` returns an Express app and never calls `listen()`, so the
 * host decides where it is reachable.
 *
 * The standalone `createModelsRouter` and `createExportRouter` do not take
 * this choice: their reads answer any caller, and a host that mounts them
 * directly, as the demo application does, puts its own auth in front of them.
 */
import express, { Express } from 'express';
import { createRouter } from './routes';
import { createIntegrityRouter } from './integrity-routes';
import { createModelsRouter } from './models-routes';
import { createExportRouter } from './export-routes';
import { createBenchmarkRouter } from '../benchmark/web';
import { Tzun } from '../sdk/index';
import {
  assertRestAuthChoice,
  resolvingOnce,
  restAuthGate,
  type RestAuthOptions,
} from './rest-auth';
import { jsonBodyParser, respondBodyRefusal } from './json-body';

export { JSON_BODY_LIMIT } from './json-body';

/**
 * Options for {@link createServer}: the routes' authentication (required, see
 * {@link RestAuthOptions}) plus the optional benchmark.
 */
export type ServerOptions = RestAuthOptions & {
  /**
   * Mount `GET /v1/benchmark` + `POST /v1/benchmark/run` (default: false).
   *
   * OFF by default because the benchmark runs synchronous busy loops sized by
   * the caller: any client it admits can block the whole event loop for as
   * long as it likes, so every capture, verify and health request on the
   * process stalls behind it. It is a local profiling tool, not a production
   * route — turn it on only on a host you would already let a stranger wedge.
   */
  benchmark?: boolean;
};

/**
 * Build the REST app. Throws unless `options` makes an explicit
 * authentication choice.
 */
export function createServer(tzun: Tzun, options: ServerOptions): Express {
  const choice = assertRestAuthChoice(options, 'createServer');
  const auth: RestAuthOptions =
    choice.kind === 'resolver'
      ? { resolveActor: resolvingOnce(choice.resolveActor) }
      : { allowUnauthenticated: true };
  const app = express();

  // First, ahead of the body parser and every router: nothing under /v1 is
  // parsed or routed for a caller the choice does not admit. Neither the check
  // nor the parser touches a path outside /v1.
  app.use('/v1', restAuthGate(auth, 'createServer'));
  app.use('/v1', jsonBodyParser());
  app.use('/v1', respondBodyRefusal);
  // Export router must mount before `createRouter` so the more specific
  // `/v1/evidence/:id/export` matches before the generic `/v1/evidence/:id`
  // would (Express matches in mount order on overlapping paths).
  app.use(createExportRouter(tzun));
  app.use(createRouter(tzun, auth));
  app.use(createIntegrityRouter(tzun));
  app.use(
    createModelsRouter(tzun, auth.resolveActor ? { resolveActor: auth.resolveActor } : undefined),
  );
  if (options.benchmark === true) {
    app.use(createBenchmarkRouter());
  }

  return app;
}
