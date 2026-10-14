"""Every Merkle vector through the Python port (Merkle part).

``vectors/merkle-rfc6962-vectors.json`` (tree hash and inclusion proofs) and
``vectors/merkle-consistency-vectors.json`` (consistency proofs: valid, invalid
and encoding) were written by recursive JavaScript transcriptions of RFC 6962
(``scripts/generate-merkle-vectors.mjs``, ``scripts/generate-consistency-vectors.mjs``).
``tzun_sdk.attestation.merkle`` is held to them byte for byte: every root, every
leaf hash and every proof it generates, and the outcome of every verification.

This file needs no Node. ``test_merkle_parity.py`` puts the same module beside
the TypeScript engine.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any, get_args

import pytest

from tzun_sdk.attestation.merkle import (
    MERKLE_SPEC,
    ConsistencyProofReason,
    build_merkle_tree,
    get_consistency_proof,
    get_merkle_proof,
    get_merkle_root,
    merkle_leaf_hash,
    verify_consistency_proof,
    verify_merkle_proof,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
INCLUSION = json.loads(
    (REPO_ROOT / "vectors" / "merkle-rfc6962-vectors.json").read_text(encoding="utf-8")
)
CONSISTENCY = json.loads(
    (REPO_ROOT / "vectors" / "merkle-consistency-vectors.json").read_text(encoding="utf-8")
)
LEAVES: list[str] = CONSISTENCY["leafDigests"]
REASONS = set(get_args(ConsistencyProofReason))


def _verify(case: dict[str, Any]) -> tuple[bool, str | None]:
    verdict = verify_consistency_proof(
        case["first"], case["second"], case["proof"], case["firstRoot"], case["secondRoot"]
    )
    return verdict.valid, verdict.reason


def _case_id(case: dict[str, Any]) -> str:
    label = case.get("mutation") or case.get("case") or "honest"
    return f"{case['first']},{case['second']}:{label}"


# ---- The vector files themselves -------------------------------------------------


def test_the_vector_files_hold_what_this_suite_expects() -> None:
    """Guard: a truncated or moved file must fail here, not shrink the parametrisation."""
    assert [t["treeSize"] for t in INCLUSION["trees"]] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 16]
    assert len(LEAVES) == 64
    counts = {k: len(CONSISTENCY[k]) for k in ("valid", "invalid", "encoding")}
    assert counts == {"valid": 237, "invalid": 426, "encoding": 17}


def test_the_spec_tag_is_the_wire_literal() -> None:
    assert MERKLE_SPEC == "rfc6962"


def test_the_leaves_follow_the_stated_derivation() -> None:
    expected = [hashlib.sha256(f"tzun-merkle-vector-{i}".encode()).hexdigest() for i in range(64)]
    assert expected == LEAVES
    # Both files use the same leaves, so a tree of size n is LEAVES[0:n] in each.
    for tree in INCLUSION["trees"]:
        assert tree["leafDigests"] == LEAVES[: tree["treeSize"]]


def test_the_empty_tree_constant_is_sha256_of_nothing() -> None:
    """The one value every CT implementation agrees on; it pins the hash before any Tzun rule."""
    assert INCLUSION["emptyTreeRoot"]["root"] == hashlib.sha256(b"").hexdigest()


# ---- Inclusion: merkle-rfc6962-vectors.json --------------------------------------


@pytest.mark.parametrize("tree", INCLUSION["trees"], ids=lambda t: f"n={t['treeSize']}")
def test_every_inclusion_tree_is_reproduced(tree: dict[str, Any]) -> None:
    built = build_merkle_tree(tree["leafDigests"])
    assert built.leaf_count == tree["treeSize"]
    assert get_merkle_root(built) == tree["root"]
    assert [merkle_leaf_hash(d) for d in tree["leafDigests"]] == tree["leafHashes"]
    assert [p["leafIndex"] for p in tree["proofs"]] == list(range(tree["treeSize"]))
    for p in tree["proofs"]:
        assert p["leafDigest"] == tree["leafDigests"][p["leafIndex"]]
        assert get_merkle_proof(built, p["leafIndex"]) == p["auditPath"]
        assert (
            verify_merkle_proof(
                p["leafDigest"], p["leafIndex"], tree["treeSize"], p["auditPath"], tree["root"]
            )
            is True
        )


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _rfc6962_root(digests: list[str]) -> str:
    """MTH(D[n]) read straight off RFC 6962 §2.1, with no rule against a repeated digest."""

    def mth(leaves: list[bytes]) -> bytes:
        if len(leaves) == 1:
            return _sha(b"\x00" + leaves[0])
        k = 1 << ((len(leaves) - 1).bit_length() - 1)
        return _sha(b"\x01" + mth(leaves[:k]) + mth(leaves[k:]))

    return mth([bytes.fromhex(d) for d in digests]).hex()


def _duplicate_last_root(digests: list[str]) -> str:
    """The construction promotion replaced: an odd last node is paired with itself."""
    level = [_sha(b"\x00" + bytes.fromhex(d)) for d in digests]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_sha(b"\x01" + level[j] + level[j + 1]) for j in range(0, len(level), 2)]
    return level[0].hex()


@pytest.mark.parametrize("vector", INCLUSION["distinctnessVectors"], ids=lambda v: v["name"][:40])
def test_the_promoted_construction_separates_a_repeated_last_leaf(vector: dict[str, Any]) -> None:
    a: list[str] = vector["a"]["leafDigests"]
    b: list[str] = vector["b"]["leafDigests"]
    assert b == [*a, a[-1]]
    # Both roots are computed here. The builder refuses a repeated digest (Tree §5.4),
    # so b's root comes from RFC 6962 §2.1 directly, and a's from both.
    root_a = get_merkle_root(build_merkle_tree(a))
    assert root_a == _rfc6962_root(a)
    root_b = _rfc6962_root(b)
    assert root_a != root_b
    # Under the duplicate-last construction, a's root IS b's root: the collision
    # the vector exists to keep closed.
    assert _duplicate_last_root(a) == root_b
    # The vector file states the same two roots.
    assert (root_a, root_b) == (vector["a"]["root"], vector["b"]["root"])
    assert vector["rootsEqual"] is False
    with pytest.raises(ValueError, match="duplicate"):
        build_merkle_tree(b)


# ---- Consistency: merkle-consistency-vectors.json, valid ---------------------------

LARGEST = build_merkle_tree(LEAVES)


@pytest.mark.parametrize("case", CONSISTENCY["valid"], ids=_case_id)
def test_every_valid_consistency_proof_is_generated_byte_for_byte(case: dict[str, Any]) -> None:
    first, second = case["first"], case["second"]
    tree = build_merkle_tree(LEAVES[:second])
    assert get_merkle_root(tree) == case["secondRoot"]
    assert get_merkle_root(build_merkle_tree(LEAVES[:first])) == case["firstRoot"]

    exact = get_consistency_proof(tree, first)
    assert exact.ok is True and exact.reason is None
    assert list(exact.proof or ()) == case["proof"]

    # The same proof, read out of a longer log at an earlier size.
    earlier = get_consistency_proof(LARGEST, first, second)
    assert earlier.ok is True
    assert list(earlier.proof or ()) == case["proof"]


@pytest.mark.parametrize("case", CONSISTENCY["valid"], ids=_case_id)
def test_every_valid_consistency_proof_verifies(case: dict[str, Any]) -> None:
    assert _verify(case) == (True, None)


# ---- Consistency, invalid ---------------------------------------------------------

# Mutations whose reason follows from the sizes and lengths alone. Every other
# mutation is a hash or length change whose reason depends on where the fold
# first goes wrong; test_merkle_parity.py holds those reasons to the engine's.
FIXED_REASON = {
    "first = 0 with an empty proof": "size_out_of_range",
    "first = 0 with a non-empty proof": "size_out_of_range",
    "first = 0 and second = 0": "size_out_of_range",
    "first greater than second": "size_out_of_range",
    "equal sizes with a non-empty proof": "proof_length_mismatch",
    "equal sizes with different roots": "second_root_mismatch",
}


@pytest.mark.parametrize("case", CONSISTENCY["invalid"], ids=_case_id)
def test_every_invalid_consistency_proof_is_refused(case: dict[str, Any]) -> None:
    valid, reason = _verify(case)
    assert valid is False
    assert reason in REASONS
    if case["mutation"] in FIXED_REASON:
        assert reason == FIXED_REASON[case["mutation"]]


def test_the_invalid_set_covers_the_first_zero_edge_rule() -> None:
    """The five cases transparency-dev/merkle v0.0.2 accepts are all present, and refused."""
    first_zero_empty = [c for c in CONSISTENCY["invalid"] if c["first"] == 0 and c["proof"] == []]
    assert len(first_zero_empty) == 5
    assert all(_verify(c) == (False, "size_out_of_range") for c in first_zero_empty)


# ---- Consistency, encoding ----------------------------------------------------------


@pytest.mark.parametrize("case", CONSISTENCY["encoding"], ids=lambda c: c["case"])
def test_every_encoding_case_has_its_stated_outcome(case: dict[str, Any]) -> None:
    valid, reason = _verify(case)
    assert valid is case["verifies"]
    if case["verifies"]:
        assert reason is None
    elif case["case"].startswith("proof"):
        assert reason == "malformed_proof"
    else:
        assert case["case"].startswith(("firstRoot", "secondRoot"))
        assert reason == "malformed_root"


# ---- Size malleability (documentation in the vector file) ------------------------------


@pytest.mark.parametrize(
    "entry",
    CONSISTENCY["sizeMalleability"]["inclusion"],
    ids=lambda e: f"leaf {e['leafIndex']} of {e['treeSize']}",
)
def test_an_inclusion_proof_also_verifies_under_the_listed_sizes(entry: dict[str, Any]) -> None:
    for size in [entry["treeSize"], *entry["alsoVerifiesUnderTreeSize"]]:
        assert verify_merkle_proof(
            entry["leafDigest"], entry["leafIndex"], size, entry["auditPath"], entry["root"]
        ), size


@pytest.mark.parametrize(
    "entry",
    CONSISTENCY["sizeMalleability"]["consistency"],
    ids=lambda e: f"{e['first']},{e['second']}",
)
def test_a_consistency_proof_also_verifies_under_the_listed_sizes(entry: dict[str, Any]) -> None:
    for second in [entry["second"], *entry["alsoVerifiesUnderSecond"]]:
        verdict = verify_consistency_proof(
            entry["first"], second, entry["proof"], entry["firstRoot"], entry["secondRoot"]
        )
        assert (verdict.valid, verdict.reason) == (True, None), second
