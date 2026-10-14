import { createHash } from 'crypto';

/**
 * Sequential hash chain linking evidence records.
 *
 * Each record's chain link is SHA-256(previousDigest + currentDigest).
 * The first record in the chain has a null chain link.
 * Tampering with any historical record breaks the chain from that point.
 */
export class EvidenceChain {
  private lastDigest: string | null = null;

  /**
   * Compute the chain link for a new record without appending it.
   * Call append() after the record is successfully stored.
   */
  computeLink(currentDigest: string): string | null {
    if (this.lastDigest === null) {
      return null;
    }
    return createHash('sha256')
      .update(this.lastDigest + currentDigest, 'utf8')
      .digest('hex');
  }

  /**
   * Append a record's digest to the chain.
   * Must be called after the record is successfully stored.
   */
  append(digest: string): void {
    this.lastDigest = digest;
  }

  /**
   * Get the last digest in the chain (for persistence/recovery).
   */
  getLastDigest(): string | null {
    return this.lastDigest;
  }

  /**
   * Restore the chain state from a persisted last digest.
   */
  restore(lastDigest: string): void {
    this.lastDigest = lastDigest;
  }
}
