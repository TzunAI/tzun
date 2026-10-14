/**
 * A batteries-included actor resolver for the SDK REST layer.
 *
 * Hosts may supply ANY `ResolveActor` implementation to `createModelsRouter`.
 * This module ships one ready-made resolver that maps a static api-key table.
 * Keys are compared with constant-time equality to mitigate timing attacks,
 * as the admin-token guard compares its token.
 */
import { constantTimeEqual } from './constant-time';
import type { Request } from 'express';

/** The HTTP request header that carries the API key on the client side. */
export const ACTOR_AUTH_HEADER = 'x-tzun-api-key';

/**
 * A function that resolves the authenticated actor from an incoming request.
 * Returns `{ actor: string }` on success, or `null` when the request carries
 * no recognisable credential for this resolver.
 *
 * The returned `actor` string becomes the `annotatedBy` value — it is
 * server-assigned, not asserted by the client.
 */
export type ResolveActor = (req: Request) => { actor: string } | null;

/**
 * Build a resolver that maps API keys to actor names.
 *
 * @param keys - A record of `{ apiKey: actorName }` entries. Keys and actor
 *   names are compared and stored in-process (no external lookup on every
 *   request); rotate by restarting the process with a new key table.
 *
 * @example
 * ```ts
 * const resolver = apiKeyActorResolver({ 'key-abc': 'dana', 'key-xyz': 'ops-bot' });
 * const router = createModelsRouter(tzun, { resolveActor: resolver });
 * ```
 */
export function apiKeyActorResolver(keys: Record<string, string>): ResolveActor {
  return (req: Request): { actor: string } | null => {
    const supplied = req.header(ACTOR_AUTH_HEADER);
    if (!supplied) return null;
    for (const [key, actor] of Object.entries(keys)) {
      if (constantTimeEqual(key, supplied)) {
        return { actor };
      }
    }
    return null;
  };
}
