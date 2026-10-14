import { getDefaultDigestComputer } from './digest-computer';

/**
 * Compute a SHA-256 digest over a canonical byte string.
 *
 * Delegates to the current default DigestComputer, which can be swapped
 * at startup via setDefaultDigestComputer() for native/GPU backends.
 *
 * @param canonical - The output of canonicalSerialize()
 * @returns 64-character lowercase hex string
 */
export function computeDigest(canonical: string): string {
  return getDefaultDigestComputer().computeDigest(canonical);
}
