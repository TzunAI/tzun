/**
 * tzun-model-manifest-v1.
 *
 * Walks a model-weights directory, hashes each included file, and produces a
 * canonical, content-addressed `modelDigest`. The intermediate manifest is
 * returned alongside so an external verifier can independently confirm
 * (a) manifest matches the digest, and (b) on-disk files match the manifest.
 *
 * Exclusion rules:
 *   - any entry whose name starts with '.' (hidden dotfiles/dirs)
 *   - any directory named '__pycache__'
 *   - any file with extension '.pyc'
 *
 * Path encoding: POSIX-style relative paths, NFC-normalized.
 *
 * Symlinks: resolved to their target; the symlink's own relative path is what
 * appears in the manifest. A symlink that points at a DIRECTORY is descended
 * into — `Dirent.isDirectory()` is false for one, so deciding file-vs-directory
 * from the Dirent alone would silently drop whole shard trees (HF cache snapshots
 * and shared model storage routinely link `shards/` elsewhere). A visited-real-
 * path set stops a link cycle from recursing forever.
 *
 * Empty result: hashing zero files yields a constant digest that is bound to
 * nothing, so `computeModelDigest` throws rather than let `registerModel`
 * stamp `weight-attested` on it.
 */

import { createHash, Hash } from 'crypto';
import { createReadStream } from 'fs';
import { readdir, realpath, stat, readlink } from 'fs/promises';
import * as path from 'path';
import { pipeline } from 'stream/promises';
import { canonicalSerialize } from '@tzun/engine';

const EXCLUDE_DIRS = new Set(['__pycache__']);
const EXCLUDE_FILE_EXTS = new Set(['.pyc']);

export interface ModelManifestFile {
  /** POSIX-style relative path from the model root, NFC-normalized. */
  path: string;
  /** File size in bytes. */
  size: number;
  /** Lowercase hex SHA-256 of the file's bytes. No `sha256:` prefix on per-file entries. */
  sha256: string;
}

export interface ModelManifest {
  algorithm: 'tzun-model-manifest-v1';
  hashAlgorithm: 'sha256';
  files: ModelManifestFile[];
}

export interface ComputeModelDigestResult {
  /** `'sha256:' + hex(sha256(canonical manifest bytes))`. */
  modelDigest: string;
  manifest: ModelManifest;
  durationMs: number;
}

export async function computeModelDigest(rootPath: string): Promise<ComputeModelDigestResult> {
  const start = Date.now();
  const files: ModelManifestFile[] = [];
  await walk(rootPath, '', files, new Set<string>());

  // A zero-file manifest hashes to a constant
  // (sha256:6e0a550956d2f005a1d83e701d7f8e4af21d1a72c4eaefcca2e7aaf10486ce48)
  // that is identical for every empty directory on earth. Returning it let a
  // wrong-but-existing path, a checkout whose download had not finished, or a
  // directory holding only dotfiles/__pycache__ produce a `weight-attested`
  // descriptor bound to no weights at all — the strongest integrity claim the
  // product makes, backed by nothing. Fail instead.
  if (files.length === 0) {
    throw new Error(
      `computeModelDigest: no eligible files under ${rootPath}. ` +
        `Hidden entries, __pycache__ directories and .pyc files are excluded; ` +
        `a weight digest must be computed over real weight files.`,
    );
  }

  // Lexicographic byte-wise ascending order — NOT localeCompare, since paths
  // are filesystem bytes, not locale-aware text.
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const manifest: ModelManifest = {
    algorithm: 'tzun-model-manifest-v1',
    hashAlgorithm: 'sha256',
    files,
  };

  const canonicalBytes = canonicalSerialize(
    manifest as unknown as Record<string, unknown>,
    ['algorithm', 'files', 'hashAlgorithm'],
  );
  const modelDigest = 'sha256:' + createHash('sha256').update(canonicalBytes).digest('hex');

  return { modelDigest, manifest, durationMs: Date.now() - start };
}

async function walk(
  dir: string,
  rel: string,
  out: ModelManifestFile[],
  visitedDirs: Set<string>,
): Promise<void> {
  // Cycle guard: `a/link -> ..` is a legal layout and would otherwise recurse
  // until the stack blows. Keyed on the resolved path so two different links
  // to one directory are also only walked once.
  const realDir = await realpath(dir);
  if (visitedDirs.has(realDir)) return;
  visitedDirs.add(realDir);

  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;

    const full = path.join(dir, entry.name);
    const relPath = (rel ? rel + '/' : '') + entry.name;

    // Resolve symlinks BEFORE classifying. `Dirent.isDirectory()` reports the
    // link itself, so a symlinked directory would otherwise fall through to the
    // file branch, get skipped by `!st.isFile()`, and vanish from the manifest
    // without a word.
    let readPath = full;
    if (entry.isSymbolicLink()) {
      const target = await readlink(full);
      readPath = path.resolve(dir, target);
    }

    const st = await stat(readPath).catch(() => null);
    // A dangling symlink stats to nothing — skip it rather than failing the
    // whole walk.
    if (st === null) continue;

    if (st.isDirectory()) {
      if (EXCLUDE_DIRS.has(entry.name)) continue;
      await walk(readPath, relPath, out, visitedDirs);
      continue;
    }

    const ext = path.extname(entry.name);
    if (EXCLUDE_FILE_EXTS.has(ext)) continue;

    if (!st.isFile()) continue;

    out.push({
      path: relPath.normalize('NFC'),
      size: st.size,
      sha256: await sha256File(readPath),
    });
  }
}

/**
 * SHA-256 one file by streaming it.
 *
 * Deliberately NOT `fs.promises.readFile`: Node caps a single read at
 * `kIoMaxLength` (2 GiB - 1) and rejects with
 * `File size (N) is greater than 2 GiB` above it. Standard safetensors
 * shards for 7B+ models are ~5 GB, so buffering made the weight-attested
 * tier unusable for exactly the inputs it exists for — and even below the
 * cap it held a whole shard in heap. Streaming also matches the Python
 * port (`python/src/tzun_sdk/ai_bom/compute_model_digest.py`), which has
 * always chunked.
 *
 * The bytes fed to the hash are identical either way, so no manifest entry,
 * `modelDigest` or conformance vector changes.
 */
async function sha256File(filePath: string): Promise<string> {
  const hash: Hash = createHash('sha256');
  await pipeline(createReadStream(filePath), hash);
  return hash.digest('hex');
}
