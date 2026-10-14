"""Cross-SDK integrity-block parity test (Record §4.2, §5; Verification §4.3).

Verifies that TypeScript and Python produce byte-identical integrity blocks
(evidence digest form + chainLink) and that the cross-verify accept/reject
path works end-to-end.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from tzun_sdk._generated.canonical import canonical_serialize
from tzun_sdk._generated.chain import compute_chain_link

VECTORS = json.loads(
    (pathlib.Path(__file__).parents[2] / "vectors" / "v1.0-integrity-vectors.json").read_text(
        encoding="utf-8"
    )
)["vectors"]

# A "digest" vector comes in two kinds and they are not equally load-bearing:
#
#   literal      — carries a pre-canonicalized ``canonical`` string. It pins the
#                  digest FORM only. Neither canonicalizer ever runs, so it
#                  cannot see a serializer divergence.
#   object-input — carries an ``input`` object plus ``hashedFields``. Each
#                  language canonicalizes with its OWN serializer and must
#                  reproduce ``expectedCanonical`` byte-for-byte before hashing.
#
# A corpus of literal vectors alone would leave the whole integrity-parity gate
# green regardless of what either canonicalizer did.
OBJECT_INPUT_VECTORS = [v for v in VECTORS if v.get("kind") == "digest" and "input" in v]


@pytest.mark.parametrize("v", VECTORS, ids=lambda v: v["id"])
def test_integrity_parity(v, ts_invoke):  # type: ignore[no-untyped-def]
    """Record §4.2, §5: TS and Python produce identical integrity blocks."""
    if v["kind"] == "digest" and "input" in v:
        # Object-input: run each language's own canonicalizer and compare the
        # BYTES first, so a divergence is reported as the serializer difference
        # it is rather than as an opaque digest mismatch.
        hashed = v["hashedFields"]
        py_canonical = canonical_serialize(v["input"], hashed)
        assert py_canonical == v["expectedCanonical"], (
            f"Python canonical bytes mismatch for {v['id']}:\n"
            f"  Python:   {py_canonical!r}\n"
            f"  Expected: {v['expectedCanonical']!r}"
        )
        py = hashlib.sha256(py_canonical.encode()).hexdigest()
        assert py == v["expectedDigest"], (
            f"Python digest mismatch for {v['id']}:\n"
            f"  Python:   {py}\n"
            f"  Expected: {v['expectedDigest']}"
        )
        ts = ts_invoke({"action": "canonical", "input": v["input"], "hashedFields": hashed})
        assert ts["canonical"] == v["expectedCanonical"], (
            f"TS canonical bytes mismatch for {v['id']}:\n"
            f"  TS:       {ts['canonical']!r}\n"
            f"  Expected: {v['expectedCanonical']!r}"
        )
        assert ts["digest"] == v["expectedDigest"], (
            f"TS digest mismatch for {v['id']}:\n"
            f"  TS:       {ts['digest']}\n"
            f"  Expected: {v['expectedDigest']}"
        )
    elif v["kind"] == "digest":
        # Literal: digest form only. Deliberately does NOT reach a canonicalizer.
        py = hashlib.sha256(v["canonical"].encode()).hexdigest()
        assert py == v["expectedDigest"], (
            f"Python digest mismatch for {v['id']}:\n"
            f"  Python:   {py}\n"
            f"  Expected: {v['expectedDigest']}"
        )
        ts = ts_invoke({"action": "canonical", "input": json.loads(v["canonical"])})
        assert ts["digest"] == v["expectedDigest"], (
            f"TS digest mismatch for {v['id']}:\n"
            f"  TS:       {ts['digest']}\n"
            f"  Expected: {v['expectedDigest']}"
        )
    elif v["kind"] == "chain-link":
        py = compute_chain_link(v["previousDigest"], v["currentDigest"])
        assert py == v["expectedChainLink"], (
            f"Python chainLink mismatch for {v['id']}:\n"
            f"  Python:   {py}\n"
            f"  Expected: {v['expectedChainLink']}"
        )
        ts = ts_invoke(
            {
                "action": "chain-link",
                "previousDigest": v["previousDigest"],
                "currentDigest": v["currentDigest"],
            }
        )
        assert ts["chainLink"] == v["expectedChainLink"], (
            f"TS chainLink mismatch for {v['id']}:\n"
            f"  TS:       {ts['chainLink']}\n"
            f"  Expected: {v['expectedChainLink']}"
        )
    else:
        pytest.fail(f"Unknown vector kind: {v['kind']!r}")



def test_integrity_corpus_exercises_both_canonicalizers() -> None:
    """The integrity corpus must contain at least one OBJECT-INPUT digest vector.

    A literal digest vector carries pre-canonicalized bytes, so for it
    ``test_integrity_parity`` hashes a string literal and never invokes either
    SDK's serializer. A corpus of only those could not fail on a canonicalizer
    divergence no matter how large. If the object-input vectors are ever
    removed or renamed out of the dispatch, this fails loudly instead of the
    suite quietly running with zero canonicalizer coverage.
    """
    assert OBJECT_INPUT_VECTORS, (
        "vectors/v1.0-integrity-vectors.json has no digest vector with an `input` "
        "object. Without one, every digest vector is a pre-canonicalized literal "
        "and neither canonicalizer is exercised by the integrity-parity gate."
    )
    for v in OBJECT_INPUT_VECTORS:
        assert "hashedFields" in v, f"{v['id']}: object-input vector needs hashedFields"
        assert "expectedCanonical" in v, (
            f"{v['id']}: object-input vector needs expectedCanonical — without it the "
            "test compares only digests and the byte-level report is lost"
        )


def test_cross_verify_accept_and_reject(ts_invoke):  # type: ignore[no-untyped-def]
    """Verification §4.3: accept valid envelope; reject tampered envelope."""
    cap = ts_invoke({"action": "capture", "aiOutput": {"r": "approve"}, "decision": {"action": "a", "reason": "b"}})
    env = cap["envelope"]

    ok = ts_invoke({"action": "verify", "envelope": env})
    assert ok["valid"] is True, f"Expected valid=True for untampered envelope, got: {ok}"

    # Mutate the envelope in-place (Python dicts are mutable) and re-verify
    import copy
    env_tampered = copy.deepcopy(env)
    env_tampered["payload"]["reason"] = "tampered"
    bad = ts_invoke({"action": "verify", "envelope": env_tampered})
    assert bad["valid"] is False, f"Expected valid=False for tampered envelope, got: {bad}"


def _build_chain(ts_invoke, n: int = 3):  # type: ignore[no-untyped-def]
    """Build a chain of n envelopes with correct chainLinks via the harness."""
    envelopes = []
    for i in range(n):
        cap = ts_invoke({
            "action": "capture",
            "aiOutput": {"step": i},
            "decision": {"action": f"action-{i}", "reason": f"reason-{i}"},
        })
        env = cap["envelope"]
        if i == 0:
            # Genesis: chainLink must be null (capture harness always sets null).
            assert env["integrity"]["chainLink"] is None
        else:
            # Compute the correct link via the engine's chain-link action.
            prev_digest = envelopes[-1]["integrity"]["canonicalDigest"]
            cur_digest = env["integrity"]["canonicalDigest"]
            link_result = ts_invoke({
                "action": "chain-link",
                "previousDigest": prev_digest,
                "currentDigest": cur_digest,
            })
            env["integrity"]["chainLink"] = link_result["chainLink"]
        envelopes.append(env)
    return envelopes


def test_multi_envelope_verify_valid_chain(ts_invoke):  # type: ignore[no-untyped-def]
    """Verification §4.3 (multi): verify({envelopes}) returns valid=True for a correct chain."""
    envelopes = _build_chain(ts_invoke, n=3)
    result = ts_invoke({"action": "verify", "envelopes": envelopes})
    assert result["valid"] is True, f"Expected valid=True for correct 3-record chain, got: {result}"


def test_multi_envelope_verify_bad_chain_link(ts_invoke):  # type: ignore[no-untyped-def]
    """Verification §4.3 (multi): verify({envelopes}) returns valid=False when a chainLink is wrong."""
    import copy
    envelopes = _build_chain(ts_invoke, n=3)
    tampered = copy.deepcopy(envelopes)
    # Flip the chainLink of record #2 (index 1) to a garbage value.
    tampered[1]["integrity"]["chainLink"] = "deadbeef" * 8
    result = ts_invoke({"action": "verify", "envelopes": tampered})
    assert result["valid"] is False, f"Expected valid=False for tampered chainLink, got: {result}"
    assert "chainLink mismatch" in result.get("reason", ""), (
        f"Expected 'chainLink mismatch' in reason, got: {result.get('reason')}"
    )


def test_multi_envelope_verify_empty_array(ts_invoke):  # type: ignore[no-untyped-def]
    """verify({envelopes: []}) must not crash; returns valid=False with informative reason."""
    result = ts_invoke({"action": "verify", "envelopes": []})
    assert result["valid"] is False, f"Expected valid=False for empty envelopes, got: {result}"
    assert "empty" in result.get("reason", "").lower(), (
        f"Expected 'empty' in reason, got: {result.get('reason')}"
    )
