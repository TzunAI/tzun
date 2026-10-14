/**
 * JSON request-body parsing for the REST layer, shared by `createServer` and
 * by the routes that parse their own bodies.
 */
import express, { NextFunction, Request, RequestHandler, Response } from 'express';

/**
 * Largest JSON request body the server parses: 1 MiB, the hosted service's
 * limit for `POST /v1/evidence`.
 */
export const JSON_BODY_LIMIT = '1mb';

/**
 * A JSON body parser with the hosted service's settings. `inflate: false` —
 * no Tzun client compresses request bodies, and inflating would let a few KB
 * of gzip expand to the full limit before the limit could see it.
 *
 * A request whose body an earlier parser already read passes through
 * untouched, so a host that mounts its own parser keeps its own settings.
 */
export function jsonBodyParser(): RequestHandler {
  return express.json({ limit: JSON_BODY_LIMIT, inflate: false });
}

/**
 * The JSON answer for each request-body refusal body-parser raises. Anything
 * else passes on to Express's own handling.
 */
const BODY_REFUSALS = new Map<string, { status: number; error: string }>([
  ['entity.too.large', { status: 413, error: `request body exceeds ${JSON_BODY_LIMIT}` }],
  ['entity.parse.failed', { status: 400, error: 'request body is not valid JSON' }],
  ['encoding.unsupported', { status: 415, error: 'compressed request bodies are not accepted' }],
  ['charset.unsupported', { status: 415, error: 'request body charset is not supported' }],
]);

/**
 * Answers a body-parser refusal as JSON instead of Express's default HTML
 * error page, which prints the parser's stack trace unless
 * NODE_ENV=production.
 */
export function respondBodyRefusal(
  err: Error & { type?: unknown },
  _req: Request,
  res: Response,
  next: NextFunction,
): void {
  const refusal = typeof err?.type === 'string' ? BODY_REFUSALS.get(err.type) : undefined;
  if (refusal === undefined || res.headersSent) {
    next(err);
    return;
  }
  res.status(refusal.status).json({ error: refusal.error });
}
