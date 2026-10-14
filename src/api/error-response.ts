import type { Response } from 'express';

/**
 * Uniform 500 responder for the SDK REST surface.
 *
 * A route handler that ended with
 *
 *   res.status(500).json({ error: 'Internal server error',
 *                          message: error instanceof Error ? error.message : String(error) });
 *
 * would hand the caller — unauthenticated, on the read routes — whatever the
 * storage adapter happened to say. On SQLite that is better-sqlite3's SQL text
 * (`near "NaN": syntax error`), on Postgres it is a pg message naming columns
 * and sometimes the connection target. That tells an anonymous prober which
 * backend is behind the deployment and what the query looks like.
 *
 * The detail is still produced — it goes to the server log, where the operator
 * can read it — but it does not travel back over the wire.
 *
 * The opt-in is fail-CLOSED on purpose: an unset NODE_ENV (the common case in
 * a bare `node dist/...` deployment) redacts. Only an explicit
 * `NODE_ENV=development` or `TZUN_VERBOSE_ERRORS=1` echoes.
 */
export function verboseApiErrorsEnabled(): boolean {
  return (
    process.env.TZUN_VERBOSE_ERRORS === '1' || process.env.NODE_ENV === 'development'
  );
}

export function respondInternalError(res: Response, error: unknown): void {
  const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
  // Server-side only. Nothing below puts `detail` in the response body.
  console.error('[tzun-api] request failed:', detail);

  const body: { error: string; message?: string } = { error: 'Internal server error' };
  if (verboseApiErrorsEnabled()) {
    body.message = error instanceof Error ? error.message : String(error);
  }
  res.status(500).json(body);
}
