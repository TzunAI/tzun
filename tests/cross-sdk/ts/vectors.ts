/**
 * What the TypeScript replays of the record-revision vector files share:
 * reading a file, the sentinels JSON text cannot carry,
 * and the link-target resolver a links case describes.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { HeldLinkTarget, LinkTargetResolver } from '@tzun/engine';

export const ROOT = join(__dirname, '..', '..', '..');

/** A vector file, parsed. Read with readFileSync rather than imported, so ts-jest does not type the whole file. */
export function vectorFile<T = Record<string, unknown>>(name: string): T {
  return JSON.parse(readFileSync(join(ROOT, 'vectors', name), 'utf8')) as T;
}

/** The value with each sentinel replaced: LONE_SURROGATE_D800 by an unpaired U+D800, NAN_MARKER by NaN. */
export function materialize(value: unknown): unknown {
  if (typeof value === 'string') return value === 'NAN_MARKER' ? NaN : value.replace(/LONE_SURROGATE_D800/g, '\uD800');
  if (Array.isArray(value)) return value.map(materialize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, materialize(v)]));
  }
  return value;
}

/** What a links case says a store-level verifier holds. */
export interface ResolverSpec {
  held?: HeldLinkTarget[];
  ownOrigins?: string[];
  positions?: Array<{ origin: string; seq: number; digest: string }>;
  openings?: Record<string, string>;
}

/** The resolver a links case describes; `undefined` (a bundle verifier, holding nothing) when it describes none. */
export function resolverOf(spec: ResolverSpec | undefined): LinkTargetResolver | undefined {
  if (spec === undefined) return undefined;
  const r: LinkTargetResolver = {
    byDigest: (d) => spec.held?.find((h) => h.digest === d) ?? null,
    openCommitment: (id) => spec.openings?.[id] ?? null,
  };
  if (spec.ownOrigins !== undefined) {
    r.isOwnOrigin = (o) => spec.ownOrigins!.includes(o);
    r.digestAt = (o, seq) => spec.positions?.find((p) => p.origin === o && p.seq === seq)?.digest ?? null;
  }
  return r;
}

/** `{ code, field }` of a violation (and `step`, `rule` when it names one), or `null`. */
export function codeOf(v: { code: string; field: string; step?: number; rule?: string } | null | undefined): unknown {
  if (v === null || v === undefined) return null;
  return { code: v.code, field: v.field, ...(v.step !== undefined && { step: v.step }), ...(v.rule !== undefined && { rule: v.rule }) };
}
