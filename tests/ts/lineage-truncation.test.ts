/**
 * A lineage walk reports why it stopped.
 *
 * A walk stops on four different conditions — real root, missing ancestor,
 * cycle guard, depth cap. `ModelLineageEntry` carries no
 * `parentModelDescriptorDigest`, so the bare entry list cannot tell them
 * apart: a fine-tune whose base model was never registered reads
 * byte-identical to a base model. The detailed walk therefore reports
 * `complete`, a `terminal` reason and, for a missing ancestor, its digest.
 * Without that, a compliance report pulling the lineage to name the model a
 * system derives from would state there is no parent.
 */
import { Tzun } from '../../src/sdk/index';
import { walkLineageDetailed, MAX_LINEAGE_DEPTH } from '../../src/models/lineage';
import type { StorageAdapter, ModelDescriptorRow } from '@tzun/engine';

const ABSENT_PARENT = 'sha256:' + 'a'.repeat(64);

describe('lineage walks report why they stopped', () => {
  it('a genuine root reports complete/root', async () => {
    const tzun = await Tzun.init();
    const root = await tzun.models.register({
      vendor: 'v', modelName: 'base', modelVersion: '1',
    });

    const walk = await tzun.models.getLineageDetailed(root.digest);
    expect(walk).not.toBeNull();
    expect(walk!.entries).toHaveLength(1);
    expect(walk!.complete).toBe(true);
    expect(walk!.terminal).toBe('root');
    expect(walk!.missingParentDigest).toBeUndefined();
  });

  it('an unregistered ancestor reports missing-parent and names the digest', async () => {
    const tzun = await Tzun.init();
    const orphan = await tzun.models.register({
      vendor: 'v', modelName: 'ft', modelVersion: '1',
      parentModelDescriptorDigest: ABSENT_PARENT,
    });

    const walk = await tzun.models.getLineageDetailed(orphan.digest);
    expect(walk).not.toBeNull();
    // The same single entry the bare entry list carries …
    expect(walk!.entries).toHaveLength(1);
    expect(walk!.entries[0].descriptorDigest).toBe(orphan.digest);
    // … but distinguishable from the root case above.
    expect(walk!.complete).toBe(false);
    expect(walk!.terminal).toBe('missing-parent');
    expect(walk!.missingParentDigest).toBe(ABSENT_PARENT);
  });

  it('the entries-only view of both cases is genuinely identical (why the flag is needed)', async () => {
    const tzun = await Tzun.init();
    const root = await tzun.models.register({
      vendor: 'v', modelName: 'base', modelVersion: '1',
    });
    const orphan = await tzun.models.register({
      vendor: 'v', modelName: 'ft', modelVersion: '1',
      parentModelDescriptorDigest: ABSENT_PARENT,
    });

    const a = await tzun.models.getLineage(root.digest);
    const b = await tzun.models.getLineage(orphan.digest);
    expect(a).toHaveLength(1);
    expect(b).toHaveLength(1);
    // Strip the digest (the only differing field) — the shape a consumer reads
    // for "is there a parent?" is the same, which is why the detailed walk
    // has to say how it stopped.
    const shape = (e: { integrityTier: unknown; derivation: unknown; trainedBy: unknown }) => ({
      integrityTier: e.integrityTier, derivation: e.derivation, trainedBy: e.trainedBy,
    });
    expect(shape(a![0])).toEqual(shape(b![0]));
  });

  it('hitting the depth cap reports depth-cap, not root', async () => {
    const tzun = await Tzun.init();
    let parent: string | null = null;
    let leaf = '';
    for (let i = 0; i <= MAX_LINEAGE_DEPTH; i++) {
      const reg = await tzun.models.register({
        vendor: 'v', modelName: `m${i}`, modelVersion: '1',
        ...(parent !== null && { parentModelDescriptorDigest: parent }),
      });
      parent = reg.digest;
      leaf = reg.digest;
    }

    const walk = await tzun.models.getLineageDetailed(leaf);
    expect(walk!.entries).toHaveLength(MAX_LINEAGE_DEPTH);
    expect(walk!.complete).toBe(false);
    expect(walk!.terminal).toBe('depth-cap');
  });

  it('the cycle guard reports cycle', async () => {
    // Content-addressing makes a real cycle impossible, so drive the branch
    // with a stub adapter rather than leaving it unexercised.
    const A = 'sha256:' + '1'.repeat(64);
    const B = 'sha256:' + '2'.repeat(64);
    const row = (digest: string, parent: string): ModelDescriptorRow =>
      ({
        modelDescriptorDigest: digest,
        parentModelDescriptorDigest: parent,
        descriptor: { integrityTier: 'vendor-asserted', derivation: null, trainedBy: null },
      }) as unknown as ModelDescriptorRow;
    const stub = {
      getModelDescriptor: async (d: string) =>
        d === A ? row(A, B) : d === B ? row(B, A) : null,
    } as unknown as StorageAdapter;

    const walk = await walkLineageDetailed(stub, A);
    expect(walk!.entries.map((e) => e.descriptorDigest)).toEqual([A, B]);
    expect(walk!.complete).toBe(false);
    expect(walk!.terminal).toBe('cycle');
  });

  it('an unknown leaf is still null', async () => {
    const tzun = await Tzun.init();
    expect(await tzun.models.getLineageDetailed('sha256:' + '0'.repeat(64))).toBeNull();
  });
});
