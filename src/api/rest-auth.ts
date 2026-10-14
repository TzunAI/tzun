/**
 * Authentication for the REST routes `createRouter` and `createServer` mount.
 *
 * On the platform nothing is reachable anonymously: capture needs an API key,
 * and reads, integrity and export need a session. This layer has no key store
 * of its own, so whoever builds it must say how callers are authenticated, and
 * saying nothing is an error when the router or server is built:
 *
 *   - `{ resolveActor }` — every request must carry a credential the resolver
 *     recognises (`apiKeyActorResolver` maps `X-Tzun-Api-Key` values to
 *     actors). Anything else is answered 401 before any body is read.
 *   - `{ allowUnauthenticated: true }` — any caller that can reach the server
 *     may read and write evidence. For a server bound to loopback, or behind a
 *     proxy that authenticates every request.
 *
 * As on the platform, the credential authorises the request and is not
 * written into the evidence: a captured record holds what the body says,
 * `decider` included. The platform uses the key to choose the tenant the
 * record is stored under and to meter usage; a `Tzun` instance has one store
 * and no meter. The one place a resolved actor is recorded is a freeform-note
 * annotation, whose `annotatedBy` the models router assigns from it.
 */
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { ResolveActor } from './actor-resolver';
import { respondInternalError } from './error-response';

/** The host's authentication choice for the REST routes: exactly one. */
export type RestAuthOptions =
  | { resolveActor: ResolveActor; allowUnauthenticated?: undefined }
  | { allowUnauthenticated: true; resolveActor?: undefined };

type RestAuthChoice =
  | { kind: 'resolver'; resolveActor: ResolveActor }
  | { kind: 'unauthenticated' };

/**
 * Read the host's choice out of `options`, or throw. `builder` names the
 * function the host called, so the error points at the call to fix.
 */
export function assertRestAuthChoice(options: unknown, builder: string): RestAuthChoice {
  const opts = (typeof options === 'object' && options !== null ? options : {}) as {
    resolveActor?: unknown;
    allowUnauthenticated?: unknown;
  };
  const optedOut = opts.allowUnauthenticated === true;

  if (opts.resolveActor !== undefined) {
    if (optedOut) {
      throw new Error(
        `${builder}: pass resolveActor or allowUnauthenticated: true, not both.`,
      );
    }
    if (typeof opts.resolveActor !== 'function') {
      throw new Error(
        `${builder}: resolveActor must be a function (req) => { actor } | null, ` +
          `such as apiKeyActorResolver({ '<key>': '<actor>' }).`,
      );
    }
    return { kind: 'resolver', resolveActor: opts.resolveActor as ResolveActor };
  }
  if (optedOut) return { kind: 'unauthenticated' };

  throw new Error(
    `${builder}: the /v1 routes need an explicit authentication choice. ` +
      `Pass { resolveActor } (for example apiKeyActorResolver({ '<key>': '<actor>' })) ` +
      `to require a recognised credential on every request, or ` +
      `{ allowUnauthenticated: true } to let any caller that can reach the server ` +
      `read and write evidence, which is only safe on loopback or behind a proxy ` +
      `that authenticates every request.`,
  );
}

/**
 * The middleware that admits or refuses a request. Mount it ahead of any body
 * parser, so an unauthenticated request is refused without its body being
 * read.
 */
export function restAuthGate(options: unknown, builder: string): RequestHandler {
  const choice = assertRestAuthChoice(options, builder);
  if (choice.kind === 'unauthenticated') {
    return (_req: Request, _res: Response, next: NextFunction) => next();
  }
  const { resolveActor } = choice;
  return (req: Request, res: Response, next: NextFunction) => {
    let principal: { actor: string } | null;
    try {
      principal = resolveActor(req);
    } catch (error) {
      respondInternalError(res, error);
      return;
    }
    if (!principal || typeof principal.actor !== 'string' || principal.actor === '') {
      res.status(401).json({ error: 'unauthenticated' });
      return;
    }
    next();
  };
}

/**
 * A resolver that answers each request once and repeats that answer to every
 * later caller. `createServer` checks a request at the app level, again in the
 * evidence router, and again when a freeform note is attributed; with this,
 * the host's resolver runs once per request however many of those it passes.
 * A resolver that throws is not remembered, so the next caller sees it throw
 * too.
 */
export function resolvingOnce(resolveActor: ResolveActor): ResolveActor {
  const answers = new WeakMap<Request, { actor: string } | null>();
  return (req: Request) => {
    if (answers.has(req)) return answers.get(req) ?? null;
    const answer = resolveActor(req);
    answers.set(req, answer);
    return answer;
  };
}
