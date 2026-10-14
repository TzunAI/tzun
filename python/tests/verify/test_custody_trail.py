"""The custody entry hash and the offline trail verifier, Python side.

The expected values in ``vectors/custody-entry-hash-vectors.json`` were computed
with the hosted service's implementation of the rule (whose SQL twin its ledger's
INSERT trigger enforces), so agreement here is agreement with what the hosted
ledger accepts. The end-to-end tests read the trail verdict ``Tzun.verify()``
reports as ``custodyTrailValid``.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from tests._raw import RawView
from tzun_sdk import Tzun
from tzun_sdk.custody_hash import (
    canonical_custody_metadata,
    compute_custody_entry_hash,
    custody_entry_preimage,
    is_hashed_custody_entry,
    length_prefix,
    verify_custody_trail,
)
from tzun_sdk.models import CustodyEntry, EvidenceEnvelope
from tzun_sdk.storage import MemoryAdapter

VECTORS_PATH = (
    pathlib.Path(__file__).resolve().parents[3] / "vectors" / "custody-entry-hash-vectors.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["vectors"]

# The hosted service's own test fixture for its custody implementation, and the hash
# that implementation computes for it (vector 1 of the vectors file).
PLATFORM_FIXTURE_HASH = "5c7467b1eecfd9f3541d3cf51fa3a68c2eeba4388ccde8b240bf4ed4e882c193"


def _kwargs(v: dict) -> dict:
    return {
        "prev_entry_hash": v["prevEntryHash"],
        "evidence_id": v["evidenceId"],
        "canonical_digest": v["canonicalDigest"],
        "action": v["action"],
        "actor": v["actor"],
        "timestamp": v["timestamp"],
        "system_id": v["systemId"],
        "metadata": v.get("metadata"),
    }


def test_vectors_file_is_where_the_test_expects_it() -> None:
    assert VECTORS_PATH.is_file(), VECTORS_PATH
    assert len(VECTORS) >= 3


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"][:40] for v in VECTORS])
def test_reproduces_every_platform_computed_vector(vector: dict) -> None:
    assert custody_entry_preimage(**_kwargs(vector["input"])) == vector["preimage"]
    assert compute_custody_entry_hash(**_kwargs(vector["input"])) == vector["entryHash"]
    assert (
        hashlib.sha256(vector["preimage"].encode("utf-8")).hexdigest() == vector["entryHash"]
    )


def test_platform_fixture_hashes_to_the_platform_value() -> None:
    assert (
        compute_custody_entry_hash(
            prev_entry_hash=None,
            evidence_id="ev-1",
            canonical_digest="d" * 64,
            action="relinked",
            actor="ünï 😀",
            timestamp="2026-09-09T00:00:00.000Z",
            system_id="rec-1",
            metadata={"newChainId": "c2"},
        )
        == PLATFORM_FIXTURE_HASH
    )
    assert VECTORS[0]["entryHash"] == PLATFORM_FIXTURE_HASH


def test_length_prefix_counts_code_points() -> None:
    assert length_prefix("😀ab") == "3:😀ab"
    assert len("😀ab".encode("utf-16-be")) // 2 == 4  # UTF-16 units would give 4
    assert len("😀ab".encode()) == 6  # bytes would give 6
    assert length_prefix(None) == "-:"
    assert length_prefix("") == "0:"


def test_canonical_metadata_uses_engine_rules() -> None:
    assert canonical_custody_metadata({"b": 1, "a": {"d": [1, None], "c": "x"}}) == (
        '{"a":{"c":"x","d":[1,null]},"b":1}'
    )
    assert canonical_custody_metadata(None) is None


def test_hashed_entry_is_recognised_only_by_a_bare_hex_entry_hash() -> None:
    assert is_hashed_custody_entry({"action": "relinked", "entryHash": "a" * 64})
    assert not is_hashed_custody_entry({"action": "relinked"})
    assert not is_hashed_custody_entry({"action": "relinked", "entryHash": None})
    assert not is_hashed_custody_entry({"action": "relinked", "entryHash": "sha256:" + "a" * 64})
    assert not is_hashed_custody_entry(None)
    assert is_hashed_custody_entry(
        CustodyEntry(timestamp="t", actor="a", action="reviewed", systemId="s", entryHash="b" * 64)
    )


# the whole string must be 64 lowercase hex digits. Python's `$`
# also matches before a trailing newline, so the pattern is applied with
# fullmatch; the TS engine and the platform refuse every one of these as well.
@pytest.mark.parametrize(
    "entry_hash",
    [
        "a" * 64 + "\n",
        "a" * 64 + "\r\n",
        "a" * 64 + " ",
        " " + "a" * 64,
        "A" * 64,
        "a" * 63,
        "a" * 65,
        "0x" + "a" * 64,
        "0x" + "a" * 62,
    ],
    ids=repr,
)
def test_an_entry_hash_spelled_any_other_way_is_not_a_hashed_entry(entry_hash: str) -> None:
    assert not is_hashed_custody_entry({"action": "relinked", "entryHash": entry_hash})


def test_an_entry_hash_with_a_trailing_newline_leaves_the_entry_client_attested() -> None:
    chain = _trail("ev", "d" * 64, 1)
    chain[1]["entryHash"] += "\n"
    v = verify_custody_trail(chain, evidence_id="ev", canonical_digest="d" * 64)
    assert v.valid is None and v.hashedEntries == 0 and v.unhashedEntries == 2


def _trail(evidence_id: str, digest: str, n: int) -> list[dict]:
    chain: list[dict] = [
        {"timestamp": "t0", "actor": "jane", "action": "decision_captured", "systemId": "sys"}
    ]
    prev: str | None = None
    for i in range(n):
        entry = {
            "timestamp": f"2026-09-09T10:0{i}:00.000Z",
            "actor": "admin@acme.example",
            "action": "relinked" if i == 0 else "reviewed",
            "systemId": "tzun-recovery",
            "metadata": {"step": i},
        }
        h = compute_custody_entry_hash(
            prev_entry_hash=prev,
            evidence_id=evidence_id,
            canonical_digest=digest,
            action=entry["action"],
            actor=entry["actor"],
            timestamp=entry["timestamp"],
            system_id=entry["systemId"],
            metadata=entry["metadata"],
        )
        chain.append({**entry, "entryHash": h, "prevEntryHash": prev})
        prev = h
    return chain


def test_trail_with_no_hashed_entry_is_unverified_not_valid() -> None:
    v = verify_custody_trail(_trail("ev", "d" * 64, 0), evidence_id="ev", canonical_digest="d" * 64)
    assert v.valid is None and v.hashedEntries == 0 and v.unhashedEntries == 1


def test_correctly_chained_trail_is_valid() -> None:
    v = verify_custody_trail(_trail("ev", "d" * 64, 3), evidence_id="ev", canonical_digest="d" * 64)
    assert v.valid is True and v.hashedEntries == 3 and v.unhashedEntries == 1
    assert v.failures == []


def test_absent_prev_entry_hash_reads_as_none() -> None:
    chain = _trail("ev", "d" * 64, 2)
    del chain[1]["prevEntryHash"]
    assert verify_custody_trail(chain, evidence_id="ev", canonical_digest="d" * 64).valid is True


def test_rewritten_actor_fails_entry_hash_once() -> None:
    chain = _trail("ev", "d" * 64, 3)
    chain[2]["actor"] = "mallory"
    v = verify_custody_trail(chain, evidence_id="ev", canonical_digest="d" * 64)
    assert v.valid is False
    assert [(f.reason, f.index) for f in v.failures] == [("entry_hash_mismatch", 2)]


def test_removed_middle_entry_breaks_the_link() -> None:
    chain = _trail("ev", "d" * 64, 3)
    del chain[2]
    v = verify_custody_trail(chain, evidence_id="ev", canonical_digest="d" * 64)
    assert [(f.reason, f.index) for f in v.failures] == [("prev_entry_hash_mismatch", 2)]


def test_unhashed_entry_after_a_hashed_one_is_invalid() -> None:
    chain = _trail("ev", "d" * 64, 1)
    chain.append({"timestamp": "t", "actor": "mallory", "action": "reviewed", "systemId": "x"})
    v = verify_custody_trail(chain, evidence_id="ev", canonical_digest="d" * 64)
    assert [(f.reason, f.index) for f in v.failures] == [("unhashed_after_hashed", 2)]


def test_moved_digest_no_longer_recomputes() -> None:
    chain = _trail("ev", "d" * 64, 1)
    v = verify_custody_trail(chain, evidence_id="ev", canonical_digest="e" * 64)
    assert [(f.reason, f.index) for f in v.failures] == [("entry_hash_mismatch", 1)]


# ── Tzun.verify() reports it ────────────────────────────────────────────────


def _stored_row(tzun: Tzun, evidence_id: str) -> EvidenceEnvelope:
    """The envelope the memory adapter HOLDS — tamper behind the adapter's back."""
    return RawView(tzun._storage._envelopes[evidence_id])  # type: ignore[attr-defined,return-value]


async def test_verify_reports_none_for_a_fresh_capture() -> None:
    async with await Tzun.init(storage=MemoryAdapter()) as tzun:
        r = await tzun.capture(ai_output={"r": 1}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        res = await tzun.verify(r.evidenceId)
        assert res.valid is True
        assert res.custodyTrailValid is None


async def test_verify_reports_a_hashed_trail_and_its_tampering() -> None:
    async with await Tzun.init(storage=MemoryAdapter()) as tzun:
        r = await tzun.capture(ai_output={"r": 1}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        row = _stored_row(tzun, r.evidenceId)
        prev: str | None = None
        for i, action in enumerate(("relinked", "reviewed")):
            ts = f"2026-09-09T10:0{i}:00.000Z"
            h = compute_custody_entry_hash(
                prev_entry_hash=prev,
                evidence_id=row.payload.evidenceId,
                canonical_digest=row.integrity.canonicalDigest,
                action=action,
                actor="admin@acme.example",
                timestamp=ts,
                system_id="tzun-recovery",
                metadata={"step": i},
            )
            row.custodyChain.append(
                CustodyEntry(
                    timestamp=ts,
                    actor="admin@acme.example",
                    action=action,  # type: ignore[arg-type]
                    systemId="tzun-recovery",
                    metadata={"step": i},
                    entryHash=h,
                    prevEntryHash=prev,
                )
            )
            prev = h

        res = await tzun.verify(r.evidenceId)
        assert res.valid is True
        assert res.custodyTrailValid is True

        row.custodyChain[1].actor = "mallory@acme.example"
        res = await tzun.verify(r.evidenceId)
        assert res.custodyTrailValid is False
        # The decision record and its chain link are intact; that is what `valid` says.
        assert res.valid is True
        assert res.reasons == []


# ── a verifier must answer, not raise, on untrusted input ────────────────────
#
# A custody entry that came off a wire can hold any JSON type in any field. A
# wrong-typed string field, metadata object or `prevEntryHash` is reported as
# `entry_field_type`, and metadata that cannot be canonicalized (a lone
# surrogate, nesting too deep) as `entry_metadata_unserializable`. The verifier
# neither raises nor coerces: hashing `str(123)` as "123" would yield an
# ordinary `entry_hash_mismatch`, a verdict that claims the real value was read
# and compared.
#
# Both SDKs must reach the SAME verdict on the same bytes; the TypeScript engine
# reports the same two reasons.


def _one_hashed(overrides: dict | None = None) -> list[dict]:
    chain = _trail("ev", "d" * 64, 1)
    if overrides:
        chain[1].update(overrides)
    return chain


@pytest.mark.parametrize("field", ["action", "actor", "timestamp", "systemId"])
@pytest.mark.parametrize(
    "value", [123, True, False, None, {"nested": "x"}, ["a", "b"]], ids=repr
)
def test_wrong_typed_string_field_reports_entry_field_type(field: str, value: object) -> None:
    v = verify_custody_trail(
        _one_hashed({field: value}), evidence_id="ev", canonical_digest="d" * 64
    )
    assert v.valid is False
    assert [f.reason for f in v.failures] == ["entry_field_type"]


@pytest.mark.parametrize("value", [7, "x", [1], True], ids=repr)
def test_wrong_typed_metadata_reports_entry_field_type(value: object) -> None:
    v = verify_custody_trail(
        _one_hashed({"metadata": value}), evidence_id="ev", canonical_digest="d" * 64
    )
    assert [f.reason for f in v.failures] == ["entry_field_type"]


@pytest.mark.parametrize("value", [5, True, {}, []], ids=repr)
def test_wrong_typed_prev_entry_hash_reports_entry_field_type(value: object) -> None:
    v = verify_custody_trail(
        _one_hashed({"prevEntryHash": value}), evidence_id="ev", canonical_digest="d" * 64
    )
    assert [f.reason for f in v.failures] == ["entry_field_type"]


def test_unserializable_metadata_reports_its_own_reason() -> None:
    v = verify_custody_trail(
        _one_hashed({"metadata": {"note": "\ud800"}}),
        evidence_id="ev",
        canonical_digest="d" * 64,
    )
    assert [f.reason for f in v.failures] == ["entry_metadata_unserializable"]


def test_deeply_nested_metadata_reports_its_own_reason() -> None:
    deep: dict = {}
    cursor = deep
    for _ in range(100):
        cursor["n"] = {}
        cursor = cursor["n"]
    v = verify_custody_trail(
        _one_hashed({"metadata": deep}), evidence_id="ev", canonical_digest="d" * 64
    )
    assert [f.reason for f in v.failures] == ["entry_metadata_unserializable"]


@pytest.mark.parametrize("bad", [42, {"hex": "x"}, None], ids=repr)
def test_wrong_typed_record_fields_invalidate_every_hashed_entry(bad: object) -> None:
    chain = _trail("ev", "d" * 64, 2)
    v = verify_custody_trail(chain, evidence_id=bad, canonical_digest="d" * 64)  # type: ignore[arg-type]
    assert v.valid is False
    assert {f.reason for f in v.failures} == {"entry_field_type"}
    assert len(v.failures) == 2


def test_a_non_sequence_custody_chain_is_no_chain_at_all() -> None:
    for chain in (None, "nope", {"a": 1}):
        v = verify_custody_trail(chain, evidence_id="ev", canonical_digest="d" * 64)  # type: ignore[arg-type]
        assert v.valid is None and v.hashedEntries == 0


async def test_verify_reports_a_wrong_typed_actor_instead_of_raising() -> None:
    """End to end through ``Tzun.verify()`` (adapter: memory).

    An entry whose ``actor`` is an int, as an envelope off a wire can carry,
    makes ``verify()`` return ``custodyTrailValid is False`` rather than raise,
    and the record's own verdict stays valid because the custody chain is
    outside the hashed field set.
    """
    async with await Tzun.init(storage=MemoryAdapter()) as tzun:
        r = await tzun.capture(ai_output={"r": 1}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        row = _stored_row(tzun, r.evidenceId)
        h = compute_custody_entry_hash(
            prev_entry_hash=None,
            evidence_id=row.payload.evidenceId,
            canonical_digest=row.integrity.canonicalDigest,
            action="reviewed",
            actor="admin@acme.example",
            timestamp="2026-09-12T10:00:00.000Z",
            system_id="tzun-recovery",
            metadata=None,
        )
        entry = CustodyEntry(
            timestamp="2026-09-12T10:00:00.000Z",
            actor="admin@acme.example",
            action="reviewed",
            systemId="tzun-recovery",
            entryHash=h,
            prevEntryHash=None,
        )
        # Behind pydantic's back: this is what arrives when the envelope came
        # off a wire rather than out of this process.
        object.__setattr__(entry, "actor", 123)
        row.custodyChain.append(entry)

        res = await tzun.verify(r.evidenceId)
        assert res.custodyTrailValid is False
        # The decision record itself is untouched — custodyChain is outside the
        # hashed field set.
        assert res.valid is True


async def test_verify_reports_an_unserializable_payload_instead_of_raising() -> None:
    """A payload holding a lone surrogate (U+D800) cannot be canonicalized;
    ``Tzun.verify()`` reports it as ``payload_not_serializable`` and
    ``digest_mismatch`` instead of raising (adapter: memory)."""
    async with await Tzun.init(storage=MemoryAdapter()) as tzun:
        r = await tzun.capture(ai_output={"r": 1}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        row = _stored_row(tzun, r.evidenceId)
        row.payload.aiOutput = {"text": "\ud800"}

        res = await tzun.verify(r.evidenceId)
        assert res.valid is False
        assert "payload_not_serializable" in res.reasons
        assert "digest_mismatch" in res.reasons
