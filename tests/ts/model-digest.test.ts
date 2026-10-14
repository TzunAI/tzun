import { computeModelDigest } from '../../src/models/compute-model-digest';

describe('tzun-model-manifest-v1', () => {
  const FIXTURE = 'tests/ts/fixtures/model-weights';

  it('walks the directory and includes only allowed files', async () => {
    const result = await computeModelDigest(FIXTURE);
    const paths = result.manifest.files.map((f) => f.path);
    expect(paths).toEqual([
      'config.json',
      'model-00001-of-00001.bin',
      'tokenizer.json',
    ]);
    expect(paths).not.toContain('.hidden-marker');
    expect(paths).not.toContain('__pycache__/junk.pyc');
  });

  it('produces a reproducible modelDigest', async () => {
    const a = await computeModelDigest(FIXTURE);
    const b = await computeModelDigest(FIXTURE);
    expect(a.modelDigest).toBe(b.modelDigest);
    expect(a.modelDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('manifest schema declares algorithm + hashAlgorithm', async () => {
    const r = await computeModelDigest(FIXTURE);
    expect(r.manifest.algorithm).toBe('tzun-model-manifest-v1');
    expect(r.manifest.hashAlgorithm).toBe('sha256');
  });

  it('each manifest file entry has path, size, sha256', async () => {
    const r = await computeModelDigest(FIXTURE);
    for (const f of r.manifest.files) {
      expect(typeof f.path).toBe('string');
      expect(typeof f.size).toBe('number');
      expect(f.sha256).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  it('files are sorted by path ascending (lexicographic byte-wise)', async () => {
    const r = await computeModelDigest(FIXTURE);
    const paths = r.manifest.files.map((f) => f.path);
    const sorted = [...paths].sort();
    expect(paths).toEqual(sorted);
  });

  it('returns durationMs as a non-negative number', async () => {
    const r = await computeModelDigest(FIXTURE);
    expect(typeof r.durationMs).toBe('number');
    expect(r.durationMs).toBeGreaterThanOrEqual(0);
  });
});
