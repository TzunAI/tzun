/**
 * The weight-attested tier must work on real weights.
 *
 * Node's `fs.promises.readFile` refuses anything above `kIoMaxLength`
 * (2 GiB - 1) with `File size (N) is greater than 2 GiB`, and every standard
 * safetensors shard for a 7B+ model is larger than that. `computeModelDigest`
 * streams each file instead, so `tzun models compute-digest`,
 * `tzun models register --weights`, `tzun.models.computeModelDigest` and
 * `importFromHuggingFace({ weightsPath })` work on exactly the inputs the
 * tier exists for. Small fixtures cannot show this; a shard over the cap can.
 *
 * The shard here is created with `ftruncate`, so it occupies no disk blocks;
 * only the hashing is real.
 */
import { createHash } from 'crypto';
import { closeSync, ftruncateSync, openSync, statSync } from 'fs';
import { mkdtemp, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import * as path from 'path';

import { computeModelDigest } from '../../src/models/compute-model-digest';

/** One byte past Node's single-read cap. */
const OVER_CAP = 2147483649;

/** sha256 of `OVER_CAP` zero bytes — computed independently of the SDK. */
const ZEROS_SHA256 =
  'b8030a8ab89280935633d8d991da3d9907c0f12e8b6fc3bfc515f4d440872b6e';

describe('computeModelDigest on production-size shards', () => {
  let root: string;
  let sparseSupported = true;

  beforeAll(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'tzun-test-big-shard-'));
    await writeFile(path.join(root, 'config.json'), '{"architectures":["Llama"]}');
    const shard = path.join(root, 'model-00001-of-00004.safetensors');
    const fd = openSync(shard, 'w');
    try {
      ftruncateSync(fd, OVER_CAP);
    } finally {
      closeSync(fd);
    }
    // A filesystem without sparse-file support would materialise 2 GiB here;
    // skip rather than fill a CI runner's disk.
    sparseSupported = statSync(shard).blocks * 512 < OVER_CAP / 2;
  }, 120_000);

  afterAll(async () => {
    if (root) await rm(root, { recursive: true, force: true });
  });

  it('hashes a shard larger than Node\'s 2 GiB single-read cap', async () => {
    if (!sparseSupported) {
      console.warn('sparse files unsupported here — skipping large-shard check');
      return;
    }
    const result = await computeModelDigest(root);

    const shard = result.manifest.files.find((f) =>
      f.path.endsWith('.safetensors'),
    );
    expect(shard).toBeDefined();
    expect(shard!.size).toBe(OVER_CAP);
    // Non-vacuity: the digest is the real content hash, not a placeholder or
    // a hash of a truncated prefix.
    expect(shard!.sha256).toBe(ZEROS_SHA256);
    expect(result.modelDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
  }, 300_000);

  it('streaming produces the same per-file hash a buffered read would', async () => {
    // Guards the streaming path against a chunking bug: for a file small
    // enough to buffer, the streamed hash must equal the one-shot hash.
    const small = await mkdtemp(path.join(tmpdir(), 'tzun-test-small-shard-'));
    try {
      const bytes = Buffer.from('weights-not-really', 'utf8');
      await writeFile(path.join(small, 'model.bin'), bytes);
      const result = await computeModelDigest(small);
      expect(result.manifest.files[0].sha256).toBe(
        createHash('sha256').update(bytes).digest('hex'),
      );
    } finally {
      await rm(small, { recursive: true, force: true });
    }
  });
});
