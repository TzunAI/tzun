/**
 * A version-4 UUID derived from a label: a record id a test can name the
 * same way every run. A writer refuses any evidenceId that is not a v4 UUID,
 * so a fixture names its records through this.
 */
import { createHash } from 'node:crypto';

export function testEvidenceId(label: string): string {
  const h = createHash('sha256').update(label, 'utf8').digest('hex');
  const variant = ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
