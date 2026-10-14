/**
 * Known-models reachability.
 *
 * `data/known-models.json` is keyed on `(vendor, modelName, modelVersion)`, and
 * the only thing that ever produces that key at runtime is `parseModelId`
 * applied to the id the vendor's API actually returned. An entry whose key the
 * parser can never yield is dead weight that reports as a working feature: the
 * seed says "we know this model", the connector says "no match", and every
 * capture of it goes out with `license: null` / `trainedBy: null` /
 * `modelVersion: 'unknown'`.
 *
 * An entry goes dead in several ways: a parser that expects `-YYYY-MM-DD`
 * when Anthropic only publishes `-YYYYMMDD`; a seed keyed on a date that no id
 * carries; a Bedrock parser that keeps the whole id while the seed splits off
 * `-vN:M`; a version segment that never appears in `response.model`; or a
 * model id (such as `meta.llama-3.1-70b-instruct`) that the vendor does not
 * have. A test that hand-injects `apiMetadata.modelVersion`, or uses a
 * synthetic id no API returns, can force a hit on such an entry and stay
 * green while no real capture ever enriches.
 *
 * This file closes the loop from BOTH ends against one shared table of real
 * wire ids (`tests/fixtures/known-model-wire-ids.json`, also consumed by the
 * Python and cross-SDK suites):
 *
 *   1. every real wire id parses to a key that hits exactly one bundled entry;
 *   2. every bundled entry is hit by at least one real wire id.
 *
 * Adding a seed entry without a wire-id row (or vice versa) fails here.
 */

import { readFileSync } from 'fs';
import * as path from 'path';

import {
  importFromVendor,
  parseModelId,
  SupportedVendor,
} from '../../src/models/import-vendor';
import {
  loadKnownModels,
  lookupKnownModel,
  KnownModelsReference,
} from '../../src/models/known-models';

interface WireIdRow {
  vendor: SupportedVendor;
  wireId: string;
}

const FIXTURE = path.resolve(__dirname, '../fixtures/known-model-wire-ids.json');

function loadRows(): WireIdRow[] {
  const parsed = JSON.parse(readFileSync(FIXTURE, 'utf-8')) as { rows: WireIdRow[] };
  return parsed.rows;
}

function entryKey(e: { vendor?: string; modelName?: string; modelVersion?: string }): string {
  return `${e.vendor}/${e.modelName}@${e.modelVersion}`;
}

describe('known-models reachability', () => {
  let known: KnownModelsReference;
  let rows: WireIdRow[];

  beforeAll(async () => {
    known = await loadKnownModels();
    rows = loadRows();
  });

  it('the wire-id table and the bundled seed are the same size', () => {
    // Guard against the two lists drifting apart silently — a seed entry with
    // no wire id is exactly the defect this file exists to catch.
    expect(rows.length).toBe(known.entries.length);
  });

  it('every real vendor wire id parses to a key that hits a bundled entry', () => {
    const misses: string[] = [];
    for (const { vendor, wireId } of rows) {
      const parsed = parseModelId(vendor, wireId);
      const hit = lookupKnownModel(known, vendor, parsed.modelName, parsed.modelVersion);
      if (!hit) {
        // Closest seeded entry for the diagnostic: same vendor, the seed's
        // modelName is a prefix of the wire id (or vice versa).
        const nearest = known.entries.find(
          (e) =>
            e.vendor === vendor &&
            typeof e.modelName === 'string' &&
            (wireId.startsWith(e.modelName) || e.modelName.startsWith(parsed.modelName)),
        );
        misses.push(
          `MISS ${vendor.padEnd(12)} wireId=${wireId} parsed=(${parsed.modelName}, ${parsed.modelVersion})` +
            (nearest ? ` seeded=(${nearest.modelName}, ${nearest.modelVersion})` : ' seeded=<none>'),
        );
      }
    }
    expect(misses).toEqual([]);
  });

  it('every bundled entry is reachable from at least one real wire id', () => {
    const reached = new Set<string>();
    for (const { vendor, wireId } of rows) {
      const parsed = parseModelId(vendor, wireId);
      const hit = lookupKnownModel(known, vendor, parsed.modelName, parsed.modelVersion);
      if (hit) reached.add(entryKey(hit));
    }
    const unreachable = known.entries
      .filter((e) => !reached.has(entryKey(e)))
      .map((e) => `UNREACHABLE ${entryKey(e)}`);
    expect(unreachable).toEqual([]);
  });

  it('every wire id round-trips through importFromVendor as an enriched descriptor', () => {
    // The end-to-end path a connector takes: parse → lookup → overlay. Every
    // bundled entry carries at least `license`, so `enriched: true` must come
    // with a non-null license — the observable symptom of an unreachable entry
    // is `license: null` on every capture of that model.
    for (const { vendor, wireId } of rows) {
      const { descriptor, enriched } = importFromVendor({
        vendor,
        modelId: wireId,
        knownModels: known,
      });
      expect({ wireId, enriched }).toEqual({ wireId, enriched: true });
      expect({ wireId, license: descriptor.license }).not.toEqual({ wireId, license: null });
    }
  });

  it('each wire id hits exactly one entry (no duplicate keys in the seed)', () => {
    const keys = known.entries.map(entryKey);
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe('Anthropic id shapes', () => {
  // The snapshot ids and bare ids from the official model table, including the
  // three current-generation models with no snapshot suffix. `response.model`
  // for a snapshot-bearing model echoes the snapshot id whether the request
  // named the alias or the snapshot; models with no snapshot echo the bare id.
  const cases: Array<[string, string, string]> = [
    ['claude-3-5-sonnet-20241022', 'claude-3-5-sonnet', '20241022'],
    ['claude-3-5-sonnet-20240620', 'claude-3-5-sonnet', '20240620'],
    ['claude-sonnet-4-20250514', 'claude-sonnet-4', '20250514'],
    ['claude-opus-4-1-20250805', 'claude-opus-4-1', '20250805'],
    ['claude-3-7-sonnet-20250219', 'claude-3-7-sonnet', '20250219'],
    ['claude-haiku-4-5-20251001', 'claude-haiku-4-5', '20251001'],
    ['claude-sonnet-4-5-20250929', 'claude-sonnet-4-5', '20250929'],
    // No snapshot suffix: the whole id is the name, the version is unknown.
    ['claude-opus-4-7', 'claude-opus-4-7', 'unknown'],
    ['claude-sonnet-4-6', 'claude-sonnet-4-6', 'unknown'],
    ['claude-haiku-4-5', 'claude-haiku-4-5', 'unknown'],
  ];

  it.each(cases)('parses %s → (%s, %s)', (wireId, name, version) => {
    expect(parseModelId('anthropic', wireId)).toEqual({
      modelName: name,
      modelVersion: version,
    });
  });

  /**
   * Anthropic has never issued a dashed-date id, so splitting
   * `claude-3-5-sonnet-2024-10-22` into `('claude-3-5-sonnet', '2024-10-22')`
   * would only ever make an id that no API returns enrich. A dashed id stays
   * whole: it is not a snapshot the vendor served, and splitting it would
   * register a phantom `(name, dashed-date)` descriptor.
   */
  it('does NOT split the dashed OpenAI-style date that no Anthropic id uses', () => {
    expect(parseModelId('anthropic', 'claude-3-5-sonnet-2024-10-22')).toEqual({
      modelName: 'claude-3-5-sonnet-2024-10-22',
      modelVersion: 'unknown',
    });
  });

  it('the dashed rule still applies to OpenAI, whose ids really are dashed', () => {
    expect(parseModelId('openai', 'gpt-4o-2024-08-06')).toEqual({
      modelName: 'gpt-4o',
      modelVersion: '2024-08-06',
    });
    // …and OpenAI does not get the undashed rule.
    expect(parseModelId('openai', 'gpt-4o-20240806')).toEqual({
      modelName: 'gpt-4o-20240806',
      modelVersion: 'unknown',
    });
  });
});

describe('Bedrock id shapes', () => {
  const cases: Array<[string, string, string]> = [
    ['anthropic.claude-3-5-sonnet-20241022-v2:0', 'anthropic.claude-3-5-sonnet', '20241022-v2:0'],
    ['anthropic.claude-3-5-sonnet-20240620-v1:0', 'anthropic.claude-3-5-sonnet', '20240620-v1:0'],
    ['meta.llama3-1-70b-instruct-v1:0', 'meta.llama3-1-70b-instruct', 'v1:0'],
    ['meta.llama3-70b-instruct-v1:0', 'meta.llama3-70b-instruct', 'v1:0'],
    ['mistral.mistral-large-2402-v1:0', 'mistral.mistral-large', '2402-v1:0'],
    ['amazon.nova-pro-v1:0', 'amazon.nova-pro', 'v1:0'],
    // Cross-region inference profile: the prefix stays on the name.
    ['us.anthropic.claude-3-5-sonnet-20241022-v2:0', 'us.anthropic.claude-3-5-sonnet', '20241022-v2:0'],
    // No `:variant` — not the documented version shape; kept whole.
    ['cohere.command-text-v14', 'cohere.command-text-v14', 'unknown'],
    ['amazon.titan-text-express-v1', 'amazon.titan-text-express-v1', 'unknown'],
  ];

  it.each(cases)('parses %s → (%s, %s)', (wireId, name, version) => {
    expect(parseModelId('bedrock', wireId)).toEqual({
      modelName: name,
      modelVersion: version,
    });
  });

  it('falls back to apiMetadata.modelVersion only when the id encodes no version', () => {
    expect(
      parseModelId('bedrock', 'cohere.command-text-v14', { modelVersion: 'hint' }),
    ).toEqual({ modelName: 'cohere.command-text-v14', modelVersion: 'hint' });
    expect(
      parseModelId('bedrock', 'meta.llama3-1-70b-instruct-v1:0', { modelVersion: 'hint' }),
    ).toEqual({ modelName: 'meta.llama3-1-70b-instruct', modelVersion: 'v1:0' });
  });
});
