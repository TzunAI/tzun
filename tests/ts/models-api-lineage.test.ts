// tests/ts/models-api-lineage.test.ts — models.getAnnotations and models.getLineage.
import { Tzun } from '../../src/sdk/index';

describe('models.getAnnotations / getLineage', () => {
  it('getLineage walks leaf→root, partial on missing ancestor, null on unknown digest', async () => {
    const tzun = await Tzun.init();
    const root = await tzun.models.register({ vendor: 'v', modelName: 'base', modelVersion: '1' });
    const child = await tzun.models.register({
      vendor: 'v', modelName: 'ft', modelVersion: '1',
      parentModelDescriptorDigest: root.digest,
    });
    const lineage = await tzun.models.getLineage(child.digest);
    expect(lineage!.map((e) => e.descriptorDigest)).toEqual([child.digest, root.digest]);
    expect(await tzun.models.getLineage('sha256:' + '0'.repeat(64))).toBeNull();
  });

  it('getAnnotations returns exactly the rows the REST route returns', async () => {
    const tzun = await Tzun.init();
    const { digest } = await tzun.models.register({ vendor: 'v', modelName: 'm', modelVersion: '1' });
    await tzun.models.annotate(digest, { annotationType: 'freeform-note', value: { text: 'n' } },
      { annotatedBy: 'rev' });
    const rows = await tzun.models.getAnnotations(digest);
    expect(rows.length).toBe(1);
    expect(rows[0]).toMatchObject({ annotationType: 'freeform-note', annotatedBy: 'rev' });
  });
});
