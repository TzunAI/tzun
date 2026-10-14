"""The model-digest attestation scope, Python half.

The Python port holds the same two rules as the TS reference implementation:

  1. A manifest with no eligible files is refused, not hashed. Otherwise a
     wrong-but-existing path, an unfinished download, or a directory of only
     dotfiles would produce the constant sha256:6e0a5509…, which
     `tzun models register --weights` (cli/main.py) stamps
     `integrityTier: "weight-attested"` on: a provably-bound-to-nothing
     attestation that verifiers accept as strong.

  2. Symlinked subdirectories are descended into, which `Path.rglob` alone
     does not do, so a layout with a symlinked `shards/` (the norm in HF cache
     snapshots and on shared storage) is hashed with those shards. TS descends
     too; skipping them would give the two SDKs DIFFERENT modelDigests for the
     same directory, breaking the tzun-model-manifest-v1 cross-language
     contract. Symlink cycles terminate and dangling symlinks are skipped.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from tzun_sdk.ai_bom.compute_model_digest import compute_model_digest

# The digest of an empty manifest, identical for every empty directory on
# earth. Pinned so a regression is unmistakable.
EMPTY_MANIFEST_DIGEST = (
    "sha256:6e0a550956d2f005a1d83e701d7f8e4af21d1a72c4eaefcca2e7aaf10486ce48"
)


def test_empty_directory_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no eligible files"):
        compute_model_digest(tmp_path)


def test_excluded_only_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / ".gitkeep").write_text("")
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "x.pyc").write_bytes(b"\x00")

    with pytest.raises(ValueError, match="no eligible files"):
        compute_model_digest(tmp_path)


def test_the_empty_manifest_digest_is_never_returned(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text("{}")
    result = compute_model_digest(tmp_path)
    assert result.model_digest != EMPTY_MANIFEST_DIGEST


def test_symlinked_subdirectory_is_descended_into(tmp_path: Path) -> None:
    real_shards = tmp_path / "elsewhere"
    real_shards.mkdir()
    (real_shards / "shard-0.safetensors").write_bytes(b"weights-0")
    (real_shards / "shard-1.safetensors").write_bytes(b"weights-1")

    model = tmp_path / "model"
    model.mkdir()
    (model / "config.json").write_text("{}")
    os.symlink(real_shards, model / "shards")

    result = compute_model_digest(model)
    paths = [f["path"] for f in result.manifest]
    assert paths == [
        "config.json",
        "shards/shard-0.safetensors",
        "shards/shard-1.safetensors",
    ]
    # The shard bytes really were hashed, not merely listed.
    by_path = {f["path"]: f for f in result.manifest}
    assert (
        by_path["shards/shard-0.safetensors"]["sha256"]
        == hashlib.sha256(b"weights-0").hexdigest()
    )


def test_symlink_cycle_terminates(tmp_path: Path) -> None:
    model = tmp_path / "model"
    model.mkdir()
    (model / "config.json").write_text("{}")
    os.symlink(model, model / "self")

    result = compute_model_digest(model)
    assert [f["path"] for f in result.manifest] == ["config.json"]


def test_dangling_symlink_is_skipped_not_fatal(tmp_path: Path) -> None:
    model = tmp_path / "model"
    model.mkdir()
    (model / "config.json").write_text("{}")
    os.symlink(tmp_path / "does-not-exist", model / "broken")

    result = compute_model_digest(model)
    assert [f["path"] for f in result.manifest] == ["config.json"]
