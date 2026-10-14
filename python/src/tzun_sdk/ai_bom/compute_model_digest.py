"""``tzun-model-manifest-v1`` algorithm in Python.

Port of the TS ``src/models/compute-model-digest.ts``, which is the reference
implementation. Used by ``tzun models compute-digest`` (CLI).

The manifest DOCUMENT is part of the contract, not an implementation detail:
the digest is the hash of its canonical bytes, so any difference in shape
produces a different modelDigest for the same directory. Every step below
matches the TS exactly (the key set and key names, the per-file size, the
files excluded, and the sort by UTF-16 code unit rather than Unicode code
point), or the two SDKs compute different digests for identical weights.

Algorithm:
  1. Walk the directory recursively.
  2. Exclude dotfiles/dirs, ``__pycache__`` directories, and ``.pyc`` files.
  3. NFC-normalize POSIX-style relative paths.
  4. Sort by UTF-16 code-unit order (what TS's ``a.path < b.path`` does).
  5. sha256 each file; emit manifest entries ``{path, size, sha256}``.
  6. Canonicalize ``{algorithm, hashAlgorithm, files}``; sha256 those bytes.
"""

from __future__ import annotations

import hashlib
import os
import stat as stat_module
import unicodedata
from pathlib import Path
from typing import Any, NamedTuple

from tzun_sdk._generated.canonical import canonical_serialize

EXCLUDE_DIRS = frozenset({"__pycache__"})
EXCLUDE_FILE_EXTS = frozenset({".pyc"})


class ComputeModelDigestResult(NamedTuple):
    model_digest: str
    manifest: list[dict[str, Any]]


def compute_model_digest(root_path: str | Path) -> ComputeModelDigestResult:
    """Compute the tzun-model-manifest-v1 digest of a directory tree."""
    root = Path(root_path)
    if not root.is_dir():
        raise ValueError(f"compute_model_digest: not a directory: {root}")

    files: list[dict[str, Any]] = []
    _walk(root, "", files, set())

    # A zero-file manifest hashes to a constant
    # (sha256:6e0a550956d2f005a1d83e701d7f8e4af21d1a72c4eaefcca2e7aaf10486ce48)
    # that is identical for every empty directory on earth. Returning it lets a
    # wrong-but-existing path, a checkout whose download had not finished, or a
    # directory holding only dotfiles/__pycache__ produce a `weight-attested`
    # descriptor bound to no weights at all — the strongest integrity claim the
    # product makes, backed by nothing. Fail instead. Mirrors the TS reference
    # implementation.
    if not files:
        raise ValueError(
            f"compute_model_digest: no eligible files under {root}. "
            "Hidden entries, __pycache__ directories and .pyc files are "
            "excluded; a weight digest must be computed over real weight files."
        )

    # TS sorts with `a.path < b.path`, i.e. UTF-16 code-unit order. Python's
    # default str sort is code-point order and the two disagree above the BMP.
    files.sort(key=lambda f: f["path"].encode("utf-16-be"))

    manifest_doc = {
        "algorithm": "tzun-model-manifest-v1",
        "hashAlgorithm": "sha256",
        "files": files,
    }
    canonical = canonical_serialize(manifest_doc)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return ComputeModelDigestResult(
        model_digest=f"sha256:{digest}",
        manifest=files,
    )


def _walk(
    directory: Path,
    rel: str,
    out: list[dict[str, Any]],
    visited_dirs: set[str],
) -> None:
    """Recursive directory walk, symlink-following, matching the TS reference.

    ``Path.rglob`` does not descend into symlinked directories, so a layout
    with a symlinked ``shards/`` — the norm in HF cache snapshots and on shared
    storage — was hashed without those shards and still called weight-attested.
    Worse for a cross-language contract: TS *does* descend, so the two SDKs
    computed different modelDigests for the same directory.
    """
    # Cycle guard keyed on the resolved path, so `a/link -> ..` terminates and
    # two different links to one directory are walked once.
    real_dir = str(directory.resolve())
    if real_dir in visited_dirs:
        return
    visited_dirs.add(real_dir)

    try:
        entries = sorted(directory.iterdir(), key=lambda e: e.name)
    except OSError:
        return

    for entry in entries:
        if entry.name.startswith("."):
            continue

        rel_path = f"{rel}/{entry.name}" if rel else entry.name

        # Resolve the link BEFORE classifying: `is_dir()` on the link itself is
        # what made a symlinked directory fall through and vanish.
        read_path = entry
        if entry.is_symlink():
            read_path = Path(os.path.realpath(entry))

        try:
            st = read_path.stat()
        except OSError:
            # A dangling symlink stats to nothing — skip it rather than
            # failing the whole walk.
            continue

        if stat_module.S_ISDIR(st.st_mode):
            if entry.name in EXCLUDE_DIRS:
                continue
            _walk(read_path, rel_path, out, visited_dirs)
            continue

        if entry.suffix in EXCLUDE_FILE_EXTS:
            continue

        if not stat_module.S_ISREG(st.st_mode):
            continue

        data = read_path.read_bytes()
        out.append(
            {
                "path": unicodedata.normalize("NFC", rel_path),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )


__all__ = ("ComputeModelDigestResult", "compute_model_digest")
