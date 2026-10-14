import { createHash } from 'crypto';

/**
 * Pluggable interface for all digest computation.
 *
 * The scanner, storage proxy, and all digest paths flow through this interface.
 * Future native/GPU backends implement this same interface:
 *   - CpuDigestComputer (this file) — Node.js crypto, ships by default
 *   - NapiRsDigestComputer (future) — Rust via napi-rs, ~5-10x throughput
 *   - CudaDigestComputer (future) — GPU-accelerated, bulk verification
 */
export interface DigestComputer {
  /** Compute a SHA-256 digest over a canonical byte string. Returns 64-char hex. */
  computeDigest(canonical: string): string;

  /** Optional batch API for GPU backends. Falls back to sequential if not implemented. */
  computeBatch(canonicals: string[]): string[];

  /** Backend identifier: 'cpu' | 'napi-rs' | 'cuda' */
  readonly backend: string;
}

/**
 * Default CPU implementation using Node.js built-in crypto.
 */
export class CpuDigestComputer implements DigestComputer {
  readonly backend = 'cpu';

  computeDigest(canonical: string): string {
    return createHash('sha256').update(canonical, 'utf8').digest('hex');
  }

  computeBatch(canonicals: string[]): string[] {
    return canonicals.map(c => this.computeDigest(c));
  }
}

// ── Global default ────────────────────────────────────────────────────

let defaultComputer: DigestComputer = new CpuDigestComputer();

/**
 * Get the current default DigestComputer.
 */
export function getDefaultDigestComputer(): DigestComputer {
  return defaultComputer;
}

/**
 * Replace the default DigestComputer.
 *
 * Call this at application startup to swap in a native or GPU backend:
 *   setDefaultDigestComputer(new NapiRsDigestComputer());
 */
export function setDefaultDigestComputer(computer: DigestComputer): void {
  defaultComputer = computer;
}
