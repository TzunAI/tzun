/**
 * One constant-time string comparison, shared by every credential guard in the
 * REST surface: the api-key comparison of `actor-resolver.ts` and the
 * admin-token guard, since TZUN_ADMIN_TOKEN gates catalog registration and
 * alias writes. Remote exploitability of V8 string-compare timing is low, but
 * both guards are documented as constant-time, and one shared function keeps
 * that claim true for each of them.
 */
import { timingSafeEqual } from 'crypto';

/**
 * True iff `a` and `b` are the same string, compared without leaking the
 * position of the first differing byte through timing.
 *
 * `timingSafeEqual` throws on length mismatch, so length is checked first —
 * that necessarily leaks the length of the expected value, which is the
 * standard and accepted trade-off for this primitive.
 */
export function constantTimeEqual(a: string | undefined, b: string | undefined): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aBuf = Buffer.from(a, 'utf8');
  const bBuf = Buffer.from(b, 'utf8');
  if (aBuf.length !== bBuf.length) return false;
  return timingSafeEqual(aBuf, bBuf);
}
