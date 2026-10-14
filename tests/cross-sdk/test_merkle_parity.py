"""TS engine and Python port agree on every Merkle answer.

- **Generators: two structurally independent implementations.**
  ``packages/engine/src/merkle.ts`` walks node indices over stored layers;
  ``tzun_sdk.attestation.merkle`` follows RFC 6962's recursive definitions over
  leaf ranges. For every tree of 1 to 64 leaves, the roots, every inclusion
  proof PATH(i, D[n]) and every consistency proof PROOF(m, D[n]) are
  byte-identical: 64 roots, 2,080 inclusion proofs, and 2,080 consistency
  proofs read two ways (from the tree of n leaves, and from the 64-leaf tree
  at an earlier size).
- **Verifiers: two transcriptions of the same steps.** Both follow the RFC 9162
  §2.1.3.2 and §2.1.4.2 step lists, as any conforming verifier must, so
  agreement here shows that the transcriptions match, not that the steps were
  read correctly. The vectors and ``python/tests/attestation/test_merkle.py``
  check the steps themselves. Every consistency vector, every hostile input
  below and a mutation family over every pair up to 32 get the same ``valid``
  and the same ``reason`` from both. The inclusion verifier returns a bare
  boolean in both SDKs, and those agree over the same kind of corpus.

One Node process per harness command: the corpus is batched, not one call per case.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
from collections.abc import Callable
from typing import Any

import pytest

from tzun_sdk.attestation.merkle import (
    build_merkle_tree,
    get_consistency_proof,
    get_merkle_proof,
    get_merkle_root,
    verify_consistency_proof,
    verify_merkle_proof,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
HARNESS = REPO_ROOT / "tests" / "cross-sdk" / "ts-harness" / "merkle.ts"
CONSISTENCY = json.loads(
    (REPO_ROOT / "vectors" / "merkle-consistency-vectors.json").read_text(encoding="utf-8")
)
LEAVES: list[str] = [
    hashlib.sha256(f"tzun-merkle-vector-{i}".encode()).hexdigest() for i in range(64)
]
TREES = {n: build_merkle_tree(LEAVES[:n]) for n in range(1, 65)}
MAX_SAFE_INTEGER = 2**53 - 1

Harness = Callable[[dict[str, Any]], dict[str, Any]]


@pytest.fixture(scope="module")
def ts_merkle() -> Harness:
    if shutil.which("node") is None:
        pytest.skip("Node not available — cross-SDK suite requires Node 22+")

    def run(cmd: dict[str, Any]) -> dict[str, Any]:
        proc = subprocess.run(
            ["npx", "tsx", str(HARNESS)],
            input=json.dumps(cmd, allow_nan=False),
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=180,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"merkle harness failed (exit {proc.returncode})\n{proc.stderr}")
        result: dict[str, Any] = json.loads(proc.stdout)
        return result

    return run


@pytest.fixture(scope="module")
def ts_generated(ts_merkle: Harness) -> dict[str, Any]:
    return ts_merkle({"action": "generate", "digests": LEAVES})


def _flip(h: str) -> str:
    """Flip the lowest bit of the last hex digit."""
    return h[:-1] + format(int(h[-1], 16) ^ 1, "x")


def _honest_consistency(first: int, second: int) -> dict[str, Any]:
    proof = get_consistency_proof(TREES[second], first)
    assert proof.ok and proof.proof is not None
    return {
        "first": first,
        "second": second,
        "proof": list(proof.proof),
        "firstRoot": get_merkle_root(TREES[first]),
        "secondRoot": get_merkle_root(TREES[second]),
    }


# ---- Generators ---------------------------------------------------------------------


def test_roots_agree_for_every_size_up_to_64(ts_generated: dict[str, Any]) -> None:
    assert ts_generated["roots"] == [get_merkle_root(TREES[n]) for n in range(1, 65)]


@pytest.mark.parametrize("n", range(1, 65))
def test_inclusion_proofs_agree_for_every_leaf(ts_generated: dict[str, Any], n: int) -> None:
    assert ts_generated["inclusion"][n - 1] == [get_merkle_proof(TREES[n], i) for i in range(n)]


@pytest.mark.parametrize("n", range(1, 65))
def test_consistency_proofs_agree_for_every_first_size(
    ts_generated: dict[str, Any], n: int
) -> None:
    ours = [list(get_consistency_proof(TREES[n], m).proof or ()) for m in range(1, n + 1)]
    from_largest = [
        list(get_consistency_proof(TREES[64], m, n).proof or ()) for m in range(1, n + 1)
    ]
    assert ts_generated["consistency"][n - 1] == ours
    assert ts_generated["consistencyFromLargest"][n - 1] == from_largest
    assert ours == from_largest


def test_the_generated_corpus_is_the_size_the_suite_claims(ts_generated: dict[str, Any]) -> None:
    """Guard: a harness that stopped early must fail here, not pass on less."""
    assert sum(len(p) for p in ts_generated["inclusion"]) == 2080
    assert sum(len(p) for p in ts_generated["consistency"]) == 2080


# ---- Consistency verifier: verdict and reason ---------------------------------------------

BASE = _honest_consistency(3, 7)
ROOT = BASE["secondRoot"]

BAD_SIZES: list[Any] = [
    "3",
    3.5,
    True,
    False,
    None,
    -1,
    0,
    3.0,
    -0.0,
    2**53,
    MAX_SAFE_INTEGER,
    1e300,
    [],
    {},
]
BAD_HASHES: list[Any] = [
    None,
    123,
    "",
    "g" * 64,
    ROOT + "\n",
    " " + ROOT,
    ROOT + " ",
    "0x" + ROOT[2:],
    "0x" + ROOT,
    ROOT[:63],
    ROOT + "0",
    ROOT.upper(),
    [ROOT],
    {"hash": ROOT},
]


def _hostile_consistency_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for bad in BAD_SIZES:
        cases.append({**BASE, "first": bad})
        cases.append({**BASE, "second": bad})
    for bad in BAD_HASHES:
        cases.append({**BASE, "firstRoot": bad})
        cases.append({**BASE, "secondRoot": bad})
        cases.append({**BASE, "proof": [bad, *BASE["proof"][1:]]})
        cases.append({**BASE, "proof": [*BASE["proof"], bad]})
    for bad_proof in [None, "string", {}, 5, [[]], [], BASE["proof"] * 2, ["zz"] * 100]:
        cases.append({**BASE, "proof": bad_proof})
    # Which fault is reported when there are several.
    cases += [
        {**BASE, "first": "3", "firstRoot": None, "proof": None},
        {**BASE, "first": 8, "firstRoot": None, "proof": None},
        {**BASE, "firstRoot": None, "proof": None},
        {**BASE, "secondRoot": 5, "proof": ["zz"]},
        {**BASE, "proof": ["zz"] * 5},
        {**BASE, "proof": ["zz"] * 4},
        {**BASE, "first": 7, "proof": ["zz"]},
        {**BASE, "first": 7, "firstRoot": ROOT},
        {**BASE, "first": 7, "firstRoot": ROOT.upper()},
        {**BASE, "first": 7, "firstRoot": _flip(ROOT)},
        {**BASE, "second": MAX_SAFE_INTEGER},
        {**BASE, "first": MAX_SAFE_INTEGER - 1, "second": MAX_SAFE_INTEGER},
    ]
    return cases


def _mutated_consistency_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for second in range(1, 33):
        for first in range(1, second + 1):
            honest = _honest_consistency(first, second)
            cases.append(honest)
            proof = honest["proof"]
            for i in range(len(proof)):
                cases.append({**honest, "proof": [*proof[:i], _flip(proof[i]), *proof[i + 1 :]]})
            if proof:
                cases.append({**honest, "proof": proof[1:]})
                cases.append({**honest, "proof": proof[:-1]})
                cases.append({**honest, "proof": [*proof, proof[-1]]})
            cases.append({**honest, "firstRoot": _flip(honest["firstRoot"])})
            cases.append({**honest, "secondRoot": _flip(honest["secondRoot"])})
            cases.append({**honest, "first": second, "second": first})
            cases.append({**honest, "second": second + 1})
            cases.append({**honest, "first": first + 1})
            cases.append({**honest, "first": first - 1})
    return cases


def test_the_consistency_verifiers_agree_on_valid_and_reason(ts_merkle: Harness) -> None:
    cases = [
        *CONSISTENCY["valid"],
        *CONSISTENCY["invalid"],
        *CONSISTENCY["encoding"],
        *_hostile_consistency_cases(),
        *_mutated_consistency_cases(),
    ]
    stripped = [
        {k: c[k] for k in ("first", "second", "proof", "firstRoot", "secondRoot")} for c in cases
    ]
    ts = ts_merkle({"action": "verify-consistency", "cases": stripped})["results"]
    assert len(ts) == len(cases)
    disagreements = []
    for case, theirs in zip(stripped, ts, strict=True):
        verdict = verify_consistency_proof(
            case["first"], case["second"], case["proof"], case["firstRoot"], case["secondRoot"]
        )
        ours = {"valid": verdict.valid, "reason": verdict.reason}
        if ours != theirs:
            disagreements.append((case, ours, theirs))
    assert disagreements == []
    # The corpus exercises every reason in the vocabulary except the generator's own.
    assert {r["reason"] for r in ts} == {
        None,
        "malformed_size",
        "size_out_of_range",
        "malformed_root",
        "malformed_proof",
        "proof_length_mismatch",
        "first_root_mismatch",
        "second_root_mismatch",
    }


# ---- Inclusion verifier -----------------------------------------------------------------


def _honest_inclusion(index: int, size: int) -> dict[str, Any]:
    return {
        "leaf": LEAVES[index],
        "leafIndex": index,
        "treeSize": size,
        "proof": get_merkle_proof(TREES[size], index),
        "root": get_merkle_root(TREES[size]),
    }


def _inclusion_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for size in range(1, 33):
        for index in range(size):
            honest = _honest_inclusion(index, size)
            cases.append(honest)
            proof = honest["proof"]
            for i in range(len(proof)):
                cases.append({**honest, "proof": [*proof[:i], _flip(proof[i]), *proof[i + 1 :]]})
            if proof:
                cases.append({**honest, "proof": proof[:-1]})
            cases.append({**honest, "proof": [*proof, honest["root"]]})
            cases.append({**honest, "leaf": _flip(honest["leaf"])})
            cases.append({**honest, "root": _flip(honest["root"])})
            cases.append({**honest, "leafIndex": (index + 1) % size})
            cases.append({**honest, "treeSize": size + 1})
            cases.append({**honest, "treeSize": size - 1})
    base = _honest_inclusion(1, 2)
    # Sizes past 2**53 - 1 appear only where both verifiers refuse them. The engine's
    # inclusion verifier folds such sizes in float arithmetic and accepts a crafted
    # path this port refuses; python/tests/attestation/test_merkle.py
    # pins the Python side.
    for bad in [True, False, "1", -1, 1.5, None, [], 1.0, 2**53, MAX_SAFE_INTEGER]:
        cases.append({**base, "leafIndex": bad})
        cases.append({**base, "treeSize": bad})
    cases.append({**base, "treeSize": 2.0})
    for bad in BAD_HASHES:
        cases.append({**base, "leaf": bad})
        cases.append({**base, "root": bad})
        cases.append({**base, "proof": [bad]})
    cases.append({**base, "leaf": LEAVES[1].upper(), "root": base["root"].upper()})
    for bad_proof in [None, "string", {}, 5, [[]], []]:
        cases.append({**base, "proof": bad_proof})
    return cases


def test_the_inclusion_verifiers_agree(ts_merkle: Harness) -> None:
    cases = _inclusion_cases()
    ts = ts_merkle({"action": "verify-inclusion", "cases": cases})["results"]
    assert len(ts) == len(cases)
    disagreements = [
        (case, theirs)
        for case, theirs in zip(cases, ts, strict=True)
        if verify_merkle_proof(
            case["leaf"], case["leafIndex"], case["treeSize"], case["proof"], case["root"]
        )
        is not theirs
    ]
    assert disagreements == []
    assert True in ts and False in ts
