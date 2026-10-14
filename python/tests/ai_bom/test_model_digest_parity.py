"""The model-manifest document is part of the contract.

`modelDigest` is the sha256 of the manifest's canonical bytes, so the manifest
SHAPE decides the digest. Both SDKs emit
`{algorithm, hashAlgorithm, files:[{path, size, sha256}]}`, exclude the same
files (`.pyc` included), and sort paths by UTF-16 code unit. A different key
set, algorithm field name, missing per-file size, extra file or sort order
would make the two SDKs compute different digests for identical weights.

The digest below is what the TypeScript `computeModelDigest` returns for the
checked-in fixture directory. Pinning it as a literal means a Python-side
regression fails here without needing the TS runtime.
"""

from __future__ import annotations

import pathlib

from tzun_sdk.ai_bom.compute_model_digest import compute_model_digest

FIXTURE = (
    pathlib.Path(__file__).parent.parent.parent.parent
    / "tests"
    / "ts"
    / "fixtures"
    / "model-weights"
)

TS_DIGEST = "sha256:992f518bc75314171c1bd68102733f8423a0a85fd8e1c847a13d3eeb74e09e2b"


def test_model_digest_matches_the_typescript_reference() -> None:
    result = compute_model_digest(FIXTURE)
    assert result.model_digest == TS_DIGEST


def test_manifest_entries_carry_path_size_and_sha256() -> None:
    result = compute_model_digest(FIXTURE)
    assert [f["path"] for f in result.manifest] == [
        "config.json",
        "model-00001-of-00001.bin",
        "tokenizer.json",
    ]
    for entry in result.manifest:
        assert set(entry) == {"path", "size", "sha256"}
        assert entry["size"] > 0
        assert len(entry["sha256"]) == 64


def test_dotfiles_pycache_and_pyc_are_excluded() -> None:
    """The fixture ships `.hidden-marker` and `__pycache__/junk.pyc` for this."""
    paths = [f["path"] for f in compute_model_digest(FIXTURE).manifest]
    assert not any(p.startswith(".") for p in paths)
    assert not any("__pycache__" in p for p in paths)
    assert not any(p.endswith(".pyc") for p in paths)


def test_pyc_files_outside_pycache_are_excluded_too(tmp_path) -> None:
    """Both SDKs exclude `.pyc` by EXTENSION, not only by directory."""
    (tmp_path / "weights.bin").write_bytes(b"w")
    (tmp_path / "compiled.pyc").write_bytes(b"c")
    paths = [f["path"] for f in compute_model_digest(tmp_path).manifest]
    assert paths == ["weights.bin"]


def test_registered_descriptor_digest_is_the_canonical_hash_not_the_weights_hash() -> None:
    """`register_descriptor` must not short-circuit on `descriptor.modelDigest`.

    That field is the WEIGHTS digest — a different value about a different
    thing. TS hashes the canonical descriptor bytes unconditionally; keying on
    the weights digest would file the same descriptor under two different keys
    in the two SDKs, and collide two descriptors that differ only in metadata
    whenever they share weights.
    """
    import hashlib

    import anyio

    from tests.storage.test_catalog_primitives import mvd
    from tzun_sdk._generated.canonical import canonical_serialize_descriptor
    from tzun_sdk.storage.memory import MemoryAdapter

    weights_digest = "sha256:" + "11" * 32
    descriptor = mvd("weighted", "1").model_copy(
        update={"modelDigest": weights_digest, "integrityTier": "weight-attested"}
    )

    async def _run() -> str:
        return await MemoryAdapter().register_descriptor(descriptor)

    digest = anyio.run(_run)

    canonical = canonical_serialize_descriptor(
        descriptor.model_dump(mode="json", exclude_none=False)
    )
    expected = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert digest == expected
    assert digest != weights_digest
