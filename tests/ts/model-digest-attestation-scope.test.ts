/**
 * A weight-attested descriptor must actually cover the weights.
 *
 * Two ways a walk can produce an attestation bound to less than it claims,
 * and what these tests pin against each:
 *
 *   1. A zero-file manifest. A wrong-but-existing path, an unfinished
 *      download, or a directory holding only dotfiles/__pycache__ would hash
 *      to the constant empty-manifest digest
 *      sha256:6e0a550956d2f005a1d83e701d7f8e4af21d1a72c4eaefcca2e7aaf10486ce48
 *      and `registerModel` would stamp `weight-attested` on it. The walk
 *      refuses a directory with no eligible files, and so does registerModel.
 *   2. A symlink pointing at a directory. `Dirent.isDirectory()` is false for
 *      one, so a walk that trusts it treats the link as a file and drops it.
 *      A layout with `shards/ -> ../shared/models/...` is the normal shape of
 *      an HF cache snapshot or shared model storage, and must hash the files
 *      behind the link, not only the ones beside it. Cycles terminate and
 *      dangling links are skipped.
 */
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import * as path from 'path';

import { computeModelDigest } from '../../src/models/compute-model-digest';
import { registerModel } from '../../src/models/register';
import { MemoryStorageAdapter } from '../../src/storage/memory';

async function tempRoot(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), 'tzun-test-weights-'));
}

describe('computeModelDigest attestation scope', () => {
  const roots: string[] = [];

  afterAll(async () => {
    await Promise.all(roots.map((r) => rm(r, { recursive: true, force: true })));
  });

  it('refuses an empty weights directory instead of hashing nothing', async () => {
    const root = await tempRoot();
    roots.push(root);
    await expect(computeModelDigest(root)).rejects.toThrow(
      /no eligible files under/,
    );
  });

  it('refuses a directory whose only entries are excluded', async () => {
    const root = await tempRoot();
    roots.push(root);
    await writeFile(path.join(root, '.gitkeep'), '');
    await mkdir(path.join(root, '__pycache__'));
    await writeFile(path.join(root, '__pycache__', 'junk.pyc'), 'x');
    await expect(computeModelDigest(root)).rejects.toThrow(
      /no eligible files under/,
    );
  });

  it('registerModel --weights cannot mint a weight-attested descriptor from an empty directory', async () => {
    const root = await tempRoot();
    roots.push(root);
    const storage = new MemoryStorageAdapter();
    await expect(
      registerModel(
        storage,
        { vendor: 'meta', modelName: 'llama-3.1-8b', modelVersion: '2024-07' },
        { weightsPath: root },
      ),
    ).rejects.toThrow(/no eligible files under/);
  });

  it('descends into a symlinked subdirectory instead of silently dropping it', async () => {
    const root = await tempRoot();
    const store = await tempRoot();
    roots.push(root, store);

    await writeFile(path.join(root, 'config.json'), '{"a":1}');
    await writeFile(path.join(store, 'model-00001-of-00002.bin'), 'shard-one');
    await writeFile(path.join(store, 'model-00002-of-00002.bin'), 'shard-two');
    await symlink(store, path.join(root, 'shards'), 'dir');

    const result = await computeModelDigest(root);
    expect(result.manifest.files.map((f) => f.path)).toEqual([
      'config.json',
      'shards/model-00001-of-00002.bin',
      'shards/model-00002-of-00002.bin',
    ]);
  });

  it('a symlink cycle terminates instead of recursing forever', async () => {
    const root = await tempRoot();
    roots.push(root);
    await writeFile(path.join(root, 'config.json'), '{"a":1}');
    await mkdir(path.join(root, 'nested'));
    await writeFile(path.join(root, 'nested', 'weights.bin'), 'w');
    await symlink(root, path.join(root, 'nested', 'loop'), 'dir');

    const result = await computeModelDigest(root);
    expect(result.manifest.files.map((f) => f.path)).toEqual([
      'config.json',
      'nested/weights.bin',
    ]);
  });

  it('a dangling symlink is skipped, not fatal', async () => {
    const root = await tempRoot();
    roots.push(root);
    await writeFile(path.join(root, 'config.json'), '{"a":1}');
    await symlink(path.join(root, 'nope'), path.join(root, 'broken'));
    const result = await computeModelDigest(root);
    expect(result.manifest.files.map((f) => f.path)).toEqual(['config.json']);
  });
});
