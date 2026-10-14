"""``tzun_sdk.attestation.merkle``: the rules around the tree math.

The vectors (``tests/cross-sdk/test_merkle_vectors.py``) pin the bytes, and
``tests/cross-sdk/test_merkle_parity.py`` holds this module to the TS engine.
This file pins what those cannot show on their own, on every Python version CI
runs: the hex rule, the size rule, that neither verifier ever raises, that the
recursive generator and the RFC 9162 verifier agree on every tree up to 64, and
that each guard of the inclusion fold refuses what it is there to refuse.
"""

from __future__ import annotations

import hashlib
import itertools
from collections.abc import Iterator
from typing import Any, get_args

import pytest

from tzun_sdk.attestation.merkle import (
    ConsistencyProofReason,
    ConsistencyVerification,
    MerkleTree,
    build_merkle_tree,
    get_consistency_proof,
    get_merkle_proof,
    get_merkle_root,
    merkle_leaf_hash,
    verify_consistency_proof,
    verify_merkle_proof,
)

LEAVES = [hashlib.sha256(f"tzun-merkle-vector-{i}".encode()).hexdigest() for i in range(64)]
TREES = {n: build_merkle_tree(LEAVES[:n]) for n in range(1, 65)}
REASONS = set(get_args(ConsistencyProofReason))
MAX_SAFE_INTEGER = 2**53 - 1


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _flip(h: str) -> str:
    return h[:-1] + format(int(h[-1], 16) ^ 1, "x")


def _consistency(first: int, second: int) -> list[str]:
    result = get_consistency_proof(TREES[second], first)
    assert result.ok and result.proof is not None and result.reason is None
    return list(result.proof)


def _root(n: int) -> str:
    return get_merkle_root(TREES[n])


# ---- Hashing -----------------------------------------------------------------------


def test_a_leaf_hash_is_over_the_raw_digest_bytes_not_its_hex_text() -> None:
    d = LEAVES[0]
    assert merkle_leaf_hash(d) == _sha(b"\x00" + bytes.fromhex(d)).hex()
    assert merkle_leaf_hash(d) != _sha(b"\x00" + d.encode()).hex()


def test_a_two_leaf_root_is_one_internal_node() -> None:
    a, b = (bytes.fromhex(merkle_leaf_hash(d)) for d in LEAVES[:2])
    assert _root(2) == _sha(b"\x01" + a + b).hex()


def test_an_odd_last_leaf_is_promoted_not_duplicated() -> None:
    ab = bytes.fromhex(_root(2))
    c = bytes.fromhex(merkle_leaf_hash(LEAVES[2]))
    assert _root(3) == _sha(b"\x01" + ab + c).hex()
    assert _root(3) != _sha(b"\x01" + ab + _sha(b"\x01" + c + c)).hex()


def test_uppercase_digests_build_the_same_tree() -> None:
    upper = build_merkle_tree([d.upper() for d in LEAVES[:5]])
    assert get_merkle_root(upper) == _root(5)
    assert upper.digests == tuple(LEAVES[:5])
    assert merkle_leaf_hash(LEAVES[0].upper()) == merkle_leaf_hash(LEAVES[0])


# ---- The hex rule: re.fullmatch, never re.match with $ ------------------------------------

REFUSED_SPELLINGS = {
    "trailing newline": LEAVES[1] + "\n",
    "trailing CRLF": LEAVES[1] + "\r\n",
    "leading space": " " + LEAVES[1],
    "trailing space": LEAVES[1] + " ",
    "63 digits": LEAVES[1][:63],
    "65 digits": LEAVES[1] + "0",
    "0x prefix": "0x" + LEAVES[1],
    "0x prefix, 64 chars": "0x" + LEAVES[1][2:],
    "non-hex letter": "g" + LEAVES[1][1:],
    "fullwidth digit": chr(0xFF10) + LEAVES[1][1:],
    "empty": "",
}
NON_STRINGS: list[Any] = [None, 0, 1.5, True, b"\x00" * 32, bytes.fromhex(LEAVES[1]), [LEAVES[1]]]


@pytest.mark.parametrize("spelling", REFUSED_SPELLINGS.values(), ids=REFUSED_SPELLINGS.keys())
def test_each_refused_spelling_is_refused_everywhere(spelling: str) -> None:
    honest = get_merkle_proof(TREES[2], 1)
    assert verify_merkle_proof(LEAVES[1], 1, 2, honest, _root(2)) is True
    assert verify_merkle_proof(spelling, 1, 2, honest, _root(2)) is False
    assert verify_merkle_proof(LEAVES[1], 1, 2, honest, spelling) is False
    assert verify_merkle_proof(LEAVES[1], 1, 2, [spelling], _root(2)) is False

    proof = _consistency(3, 7)
    verdict = verify_consistency_proof(3, 7, [spelling, *proof[1:]], _root(3), _root(7))
    assert (verdict.valid, verdict.reason) == (False, "malformed_proof")
    verdict = verify_consistency_proof(3, 7, proof, spelling, _root(7))
    assert (verdict.valid, verdict.reason) == (False, "malformed_root")

    with pytest.raises(ValueError):
        merkle_leaf_hash(spelling)
    with pytest.raises(ValueError):
        build_merkle_tree([LEAVES[0], spelling])


@pytest.mark.parametrize("value", NON_STRINGS, ids=repr)
def test_a_non_string_hash_is_refused_everywhere(value: Any) -> None:
    honest = get_merkle_proof(TREES[2], 1)
    assert verify_merkle_proof(value, 1, 2, honest, _root(2)) is False
    assert verify_merkle_proof(LEAVES[1], 1, 2, honest, value) is False
    assert verify_merkle_proof(LEAVES[1], 1, 2, [value], _root(2)) is False
    proof = _consistency(3, 7)
    assert verify_consistency_proof(3, 7, [value, *proof[1:]], _root(3), _root(7)).reason == (
        "malformed_proof"
    )
    assert verify_consistency_proof(3, 7, proof, _root(3), value).reason == "malformed_root"


def test_uppercase_and_mixed_case_hashes_verify() -> None:
    proof = _consistency(3, 7)
    mixed = [h[:32].upper() + h[32:] for h in proof]
    assert verify_consistency_proof(3, 7, mixed, _root(3).upper(), _root(7)).valid is True
    path = get_merkle_proof(TREES[7], 4)
    assert verify_merkle_proof(LEAVES[4].upper(), 4, 7, [h.upper() for h in path], _root(7).upper())


# ---- The size rule: a JSON integer in the safe range ----------------------------------------


def test_a_bool_is_not_a_size() -> None:
    """``True == 1`` in Python; a size check that forgot bool would accept it as index 1."""
    path = get_merkle_proof(TREES[2], 1)
    assert verify_merkle_proof(LEAVES[1], 1, 2, path, _root(2)) is True
    assert verify_merkle_proof(LEAVES[1], True, 2, path, _root(2)) is False
    assert verify_consistency_proof(True, 7, [], _root(1), _root(7)).reason == "malformed_size"
    assert get_consistency_proof(TREES[7], True).reason == "malformed_size"
    with pytest.raises(ValueError):
        get_merkle_proof(TREES[2], True)


def test_an_integral_float_is_the_integer_it_spells() -> None:
    """JSON has one number type: ``3.0`` and ``3`` are the same value to a JSON reader."""
    path = get_merkle_proof(TREES[7], 3)
    assert verify_merkle_proof(LEAVES[3], 3.0, 7.0, path, _root(7)) is True
    assert verify_consistency_proof(3.0, 7.0, _consistency(3, 7), _root(3), _root(7)).valid
    assert verify_merkle_proof(LEAVES[3], 3.5, 7, path, _root(7)) is False
    assert verify_consistency_proof(3.5, 7, _consistency(3, 7), _root(3), _root(7)).reason == (
        "malformed_size"
    )


def test_a_size_past_the_safe_integer_range_is_refused() -> None:
    """A size above 2**53 - 1 is refused outright, as the engine's consistency verifier does.

    The crafted path below is exactly what an exact-arithmetic RFC 9162 fold accepts
    for leaf 0 of a tree of 2**60 leaves: 60 right siblings. The engine's inclusion
    verifier checks sizes with Number.isInteger and folds them as floats, so it
    refuses this path and accepts a 61-step one instead.
    """
    leaf = LEAVES[0]
    r = bytes.fromhex(merkle_leaf_hash(leaf))
    path = []
    for i in range(60):
        sibling = _sha(f"s{i}".encode())
        path.append(sibling.hex())
        r = _sha(b"\x01" + r + sibling)
    assert verify_merkle_proof(leaf, 0, 2**60, path, r.hex()) is False
    assert verify_merkle_proof(leaf, 0, float(2**60), path, r.hex()) is False
    past = verify_consistency_proof(1, 2**53, ["00" * 32], _root(1), _root(2))
    assert past.reason == "malformed_size"
    at_limit = verify_consistency_proof(1, MAX_SAFE_INTEGER, ["00" * 32], _root(1), _root(2))
    assert at_limit.reason == "proof_length_mismatch"


# ---- Neither verifier ever raises ------------------------------------------------------------

HOSTILE: list[Any] = [
    None,
    True,
    0,
    -1,
    1,
    2**64,
    1.5,
    float("inf"),
    float("nan"),
    "",
    "3",
    LEAVES[0],
    LEAVES[0] + "\n",
    [],
    [None],
    [LEAVES[0]],
    ["zz"] * 100,
    {},
    {"a": 1},
    (LEAVES[0],),
    b"",
    object(),
]
# Every combination of these, on top of each HOSTILE value in each position alone.
HOSTILE_CORE: list[Any] = [None, True, 1, 1.5, LEAVES[0], [LEAVES[0]], {}, object()]


def _hostile_argument_lists(honest: list[Any]) -> list[list[Any]]:
    lists = [list(args) for args in itertools.product(HOSTILE_CORE, repeat=len(honest))]
    for position, value in itertools.product(range(len(honest)), HOSTILE):
        lists.append([*honest[:position], value, *honest[position + 1 :]])
    return lists


def test_the_inclusion_verifier_never_raises() -> None:
    honest = [LEAVES[4], 4, 7, get_merkle_proof(TREES[7], 4), _root(7)]
    for args in _hostile_argument_lists(honest):
        assert verify_merkle_proof(*args) in (True, False)


def test_the_consistency_verifier_never_raises() -> None:
    honest = [3, 7, _consistency(3, 7), _root(3), _root(7)]
    for args in _hostile_argument_lists(honest):
        verdict = verify_consistency_proof(*args)
        assert isinstance(verdict, ConsistencyVerification)
        assert verdict.valid is False or verdict.reason is None
        assert verdict.reason is None or verdict.reason in REASONS


def test_the_consistency_generator_never_raises() -> None:
    for tree, first, second in itertools.product([TREES[7], None, {}, "tree"], HOSTILE, HOSTILE):
        result = get_consistency_proof(tree, first, second)
        assert result.ok is (result.reason is None)


# ---- Consistency: edge rules and reasons ------------------------------------------------------


def test_equal_sizes_verify_only_with_an_empty_proof_and_equal_roots() -> None:
    assert verify_consistency_proof(5, 5, [], _root(5), _root(5)).valid is True
    assert verify_consistency_proof(5, 5, [_root(5)], _root(5), _root(5)).reason == (
        "proof_length_mismatch"
    )
    assert verify_consistency_proof(5, 5, [], _root(5), _root(6)).reason == "second_root_mismatch"
    assert get_consistency_proof(TREES[5], 5).proof == ()


def test_first_zero_is_refused_even_with_an_empty_proof() -> None:
    for second in (0, 1, 5):
        verdict = verify_consistency_proof(0, second, [], _root(1), _root(max(second, 1)))
        assert (verdict.valid, verdict.reason) == (False, "size_out_of_range")
    assert get_consistency_proof(TREES[5], 0).reason == "size_out_of_range"


def test_an_empty_proof_between_different_sizes_is_refused() -> None:
    assert verify_consistency_proof(4, 8, [], _root(4), _root(8)).reason == "proof_length_mismatch"


def test_a_proof_longer_than_any_proof_between_the_sizes_is_refused_on_length() -> None:
    # PROOF(m, D[n]) holds at most ceil(log2 n) + 1 hashes; past that the elements are not read.
    assert verify_consistency_proof(3, 7, ["zz"] * 5, _root(3), _root(7)).reason == (
        "proof_length_mismatch"
    )
    assert verify_consistency_proof(3, 7, ["zz"] * 4, _root(3), _root(7)).reason == (
        "malformed_proof"
    )


def test_malformed_input_reports_the_first_fault_in_a_fixed_order() -> None:
    """size, then range, then roots, then proof shape, then length, then elements."""
    assert verify_consistency_proof("3", 7, None, None, None).reason == "malformed_size"
    assert verify_consistency_proof(8, 7, None, None, None).reason == "size_out_of_range"
    assert verify_consistency_proof(3, 7, None, _root(3), None).reason == "malformed_root"
    assert verify_consistency_proof(3, 7, None, _root(3), _root(7)).reason == "malformed_proof"


def test_a_generated_proof_names_a_malformed_request() -> None:
    assert get_consistency_proof({"layers": [], "leafCount": 1}, 1).reason == "malformed_tree"
    assert get_consistency_proof(TREES[5], "1").reason == "malformed_size"
    assert get_consistency_proof(TREES[5], 1, 2.5).reason == "malformed_size"
    assert get_consistency_proof(TREES[5], 3, 2).reason == "size_out_of_range"
    assert get_consistency_proof(TREES[5], 1, 6).reason == "size_out_of_range"
    assert get_consistency_proof(TREES[5], -1).reason == "size_out_of_range"


# ---- Generator and verifier agree on every tree up to 64 ---------------------------------


def test_every_generated_inclusion_proof_verifies_and_only_for_its_leaf() -> None:
    for n, tree in TREES.items():
        root = get_merkle_root(tree)
        for i in range(n):
            path = get_merkle_proof(tree, i)
            assert len(path) <= (n - 1).bit_length()
            assert verify_merkle_proof(LEAVES[i], i, n, path, root), (i, n)
            if n > 1:
                assert not verify_merkle_proof(LEAVES[(i + 1) % n], i, n, path, root)
                assert not verify_merkle_proof(LEAVES[i], (i + 1) % n, n, path, root)
            if path:
                assert not verify_merkle_proof(LEAVES[i], i, n, path[:-1], root)
                assert not verify_merkle_proof(LEAVES[i], i, n, [_flip(path[0]), *path[1:]], root)
            assert not verify_merkle_proof(LEAVES[i], i, n, [*path, root], root)


def test_every_generated_consistency_proof_verifies() -> None:
    for n in range(1, 65):
        for m in range(1, n + 1):
            proof = _consistency(m, n)
            assert verify_consistency_proof(m, n, proof, _root(m), _root(n)).valid, (m, n)
            if m < n:
                assert len(proof) <= (n - 1).bit_length() + 1
                assert not verify_consistency_proof(m, n, proof[:-1], _root(m), _root(n)).valid
                assert not verify_consistency_proof(
                    m, n, [_flip(proof[0]), *proof[1:]], _root(m), _root(n)
                ).valid


def test_no_consistency_proof_verifies_under_another_first_size() -> None:
    """The vector file's census: a wrong first size always changes a step of the fold."""
    for n in range(2, 33):
        for m in range(1, n):
            proof = _consistency(m, n)
            for other in range(1, n + 1):
                if other != m:
                    verdict = verify_consistency_proof(other, n, proof, _root(m), _root(n))
                    assert not verdict.valid, (m, other, n)


def test_a_proof_read_at_an_earlier_size_equals_the_proof_of_that_tree() -> None:
    for n in (1, 2, 3, 7, 8, 9, 31, 33, 63):
        for m in range(1, n + 1):
            assert get_consistency_proof(TREES[64], m, n).proof == tuple(_consistency(m, n))
    assert get_consistency_proof(TREES[64], 5).proof == tuple(_consistency(5, 64))


def test_a_single_leaf_tree_has_an_empty_path() -> None:
    assert get_merkle_proof(TREES[1], 0) == []
    assert _root(1) == merkle_leaf_hash(LEAVES[0])
    assert verify_merkle_proof(LEAVES[0], 0, 1, [], _root(1)) is True


# ---- Inclusion: each guard of the RFC 9162 §2.1.3.2 fold, on its own ------------------------
#
# The TS verifier follows the same steps, so the cross-SDK parity test cannot tell
# whether either transcription kept a guard. Each test below fails when the guard it
# names is removed from verify_merkle_proof, with the other guards left in place.

PATH_LENGTHS = {
    (n, i): len(get_merkle_proof(tree, i)) for n, tree in TREES.items() for i in range(n)
}


def _past_the_root(root: str, extra: int) -> tuple[list[str], str]:
    """``extra`` siblings, and the root a fold that ignored step 4a would reach with them.

    An honest path ends with ``fn = sn = 0``. From there, a fold that kept going
    would take the ``fn == sn`` branch for every further element:
    ``r = SHA-256(0x01 || p || r)``.
    """
    r = bytes.fromhex(root)
    siblings: list[str] = []
    for k in range(extra):
        p = _sha(f"past-the-root-{k}".encode())
        siblings.append(p.hex())
        r = _sha(b"\x01" + p + r)
    return siblings, r.hex()


def test_a_path_that_goes_on_past_the_root_is_refused() -> None:
    """Step 4a: once ``sn`` is 0, any further element fails the proof.

    Each forged root below is the value the fold reaches if it keeps going, so
    only the ``sn`` checks refuse these paths. Many of them are no longer than
    the length bound allows. Leaf 4 of 5, for example, has a one-element path
    and a bound of three, so its paths with one or two extra elements get past
    the bound, and the check inside the loop is the only guard. The paths that
    exceed the bound are there for a verifier missing both.
    """
    within_bound = 0
    for n, tree in TREES.items():
        root = get_merkle_root(tree)
        bound = (n - 1).bit_length()
        for i in range(n):
            path = get_merkle_proof(tree, i)
            for extra in range(1, bound - len(path) + 3):
                siblings, forged = _past_the_root(root, extra)
                longer = [*path, *siblings]
                assert not verify_merkle_proof(LEAVES[i], i, n, longer, forged), (i, n, extra)
                if len(path) + extra <= bound:
                    within_bound += 1
    assert within_bound > 0
    siblings, forged = _past_the_root(_root(5), 1)
    assert not verify_merkle_proof(
        LEAVES[4], 4, 5, [*get_merkle_proof(TREES[5], 4), *siblings], forged
    )


def test_a_path_is_refused_under_a_size_that_calls_for_another_length() -> None:
    """Step 5: the path must run out exactly when ``sn`` reaches 0.

    The fold under a claimed size takes as many steps as that size's own path
    for the leaf has elements, so a path of any other length is refused,
    whatever it folds to. A path that is too short often folds to the right
    root. The path of leaf 0 in the tree of 4 leaves reaches that tree's root
    under every claimed size from 5 up, with ``sn`` still above 0, and only the
    final ``sn == 0`` check refuses it.

    A path that verifies under a claimed size of the same path length is the
    size malleability that ``tzun_sdk.attestation.merkle`` documents, and is
    not tested here.
    """
    for n, tree in TREES.items():
        root = get_merkle_root(tree)
        for i in range(n):
            path = get_merkle_proof(tree, i)
            for size in range(i + 1, 65):
                if PATH_LENGTHS[size, i] != len(path):
                    assert not verify_merkle_proof(LEAVES[i], i, size, path, root), (i, n, size)
    four = get_merkle_proof(TREES[4], 0)
    assert verify_merkle_proof(LEAVES[0], 0, 4, four, _root(4)) is True
    for size in (5, 8, 9, 64, 2**40):
        assert verify_merkle_proof(LEAVES[0], 0, size, four, _root(4)) is False, size


class _ReadCountingProof(list[str]):
    """A proof that counts how many times the verifier iterates over its elements."""

    def __init__(self, items: list[str]) -> None:
        super().__init__(items)
        self.reads = 0

    def __iter__(self) -> Iterator[str]:
        self.reads += 1
        return super().__iter__()


def test_a_path_longer_than_the_bound_is_refused_before_any_element_is_read() -> None:
    """The length bound: more than ``(size - 1).bit_length()`` elements is refused on length.

    Every step of the fold shifts ``sn`` right at least once, so step 4a would
    refuse such a path anyway, and the verdict is the same with or without the
    bound. What the bound adds is cost: a client-supplied list of any length is
    refused after one ``len()``, without a regex match and a hex decode per
    element. That is what this test observes.
    """
    for n in (1, 2, 3, 5, 8, 9, 33, 64):
        root = _root(n)
        bound = (n - 1).bit_length()
        for i in sorted({0, n // 2, n - 1}):
            honest = _ReadCountingProof(get_merkle_proof(TREES[n], i))
            assert verify_merkle_proof(LEAVES[i], i, n, honest, root) is True
            assert honest.reads > 0  # the counter sees an honest path being read
            for length in (bound + 1, bound + 2, 10_000):
                over = _ReadCountingProof([root] * length)
                assert verify_merkle_proof(LEAVES[i], i, n, over, root) is False
                assert over.reads == 0, (i, n, length)


# ---- The builder ----------------------------------------------------------------------------


def test_the_builder_refuses_what_it_cannot_anchor() -> None:
    with pytest.raises(ValueError, match="at least one"):
        build_merkle_tree([])
    with pytest.raises(ValueError, match="entry 1"):
        build_merkle_tree([LEAVES[0], "nope"])
    with pytest.raises(ValueError, match="duplicate"):
        build_merkle_tree([LEAVES[0], LEAVES[1], LEAVES[0]])
    with pytest.raises(ValueError, match="duplicate"):
        build_merkle_tree([LEAVES[0], LEAVES[0].upper()])
    with pytest.raises(ValueError):
        build_merkle_tree(LEAVES[0])  # a string is not a list of digests


def test_an_inclusion_proof_needs_an_index_inside_the_tree() -> None:
    for bad in (-1, 5, 1.5, "0", None):
        with pytest.raises(ValueError):
            get_merkle_proof(TREES[5], bad)  # type: ignore[arg-type]


def test_a_tree_reports_its_size_and_digests() -> None:
    tree = TREES[9]
    assert isinstance(tree, MerkleTree)
    assert tree.leaf_count == 9
    assert tree.digests == tuple(LEAVES[:9])
    assert tree.root == _root(9)
