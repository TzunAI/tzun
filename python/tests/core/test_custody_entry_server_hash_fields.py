"""Server-minted ``entryHash`` / ``prevEntryHash`` on ``CustodyEntry``.

The platform's custody ledger hash-chains every relink/fork custody entry into
a ``custody_entries`` row and mirrors it into ``envelope.custodyChain[i]`` as
``{...entry, entryHash, prevEntryHash}``. Before this change the generated
model had neither field and, being ``extra="forbid"``, refused the mirrored
entry — so ``EvidenceEnvelope.model_validate(bundle["envelope"])`` raised on
every repaired record (red quoted from the pre-change model, pydantic 2.13):

    2 validation errors for CustodyEntry
    entryHash
      Extra inputs are not permitted [type=extra_forbidden, input_value='sha256:aaa…', input_type=str]
    prevEntryHash
      Extra inputs are not permitted [type=extra_forbidden, input_value=None, input_type=NoneType]

The other half is the wire. A Pydantic ``x: T | None = None`` serialises as
``"x": null``, and the platform's capture allowlist (an exact key set)
refuses unknown keys even when null — so the naive field addition alone
would have turned every Python cloud capture into ``400 invalid_request
unknown_field custodyChain[0].entryHash``. The generated model therefore
omits the two keys unless they were set (``@tzun-omit-when-unset`` in
codegen-python.ts); an explicit null — the first server-minted entry's
``prevEntryHash`` — still round-trips.
"""

from __future__ import annotations

import json

import pytest

from tzun_sdk import Tzun
from tzun_sdk.models import CustodyEntry, EvidenceEnvelope
from tzun_sdk.storage import MemoryAdapter

# envelope-schema.ts CUSTODY_ENTRY_KEYS — what the platform accepts from a client.
PLATFORM_CLIENT_CUSTODY_KEYS = {"timestamp", "actor", "action", "systemId", "metadata"}

LEGACY = {
    "timestamp": "2026-09-09T10:00:00.000Z",
    "actor": "admin@acme.example",
    "action": "relinked",
    "systemId": "hosted-platform",
}
ENTRY_HASH_1 = "sha256:" + "a" * 64
ENTRY_HASH_2 = "sha256:" + "b" * 64


def test_server_minted_entry_validates() -> None:
    entry = CustodyEntry.model_validate(
        {**LEGACY, "entryHash": ENTRY_HASH_1, "prevEntryHash": None}
    )
    assert entry.entryHash == ENTRY_HASH_1
    assert entry.prevEntryHash is None
    chained = CustodyEntry.model_validate(
        {**LEGACY, "action": "chain_forked", "entryHash": ENTRY_HASH_2, "prevEntryHash": ENTRY_HASH_1}
    )
    assert chained.prevEntryHash == ENTRY_HASH_1


def test_legacy_entry_still_validates_and_stays_legacy_on_the_wire() -> None:
    entry = CustodyEntry.model_validate(LEGACY)
    assert entry.entryHash is None
    assert entry.prevEntryHash is None
    # Red before the serializer: {"…", "entryHash": null, "prevEntryHash": null}.
    for dumped in (entry.model_dump(mode="json"), json.loads(entry.model_dump_json())):
        assert "entryHash" not in dumped
        assert "prevEntryHash" not in dumped
        assert set(dumped) <= PLATFORM_CLIENT_CUSTODY_KEYS
    # A copy is still "unset" — the omission survives model_copy.
    assert "entryHash" not in entry.model_copy().model_dump(mode="json")


def test_explicit_null_prev_entry_hash_round_trips() -> None:
    # The first server-minted entry on a record has `prevEntryHash: null` —
    # a real wire value, distinct from "not server-minted". It must survive.
    entry = CustodyEntry.model_validate({**LEGACY, "entryHash": ENTRY_HASH_1, "prevEntryHash": None})
    dumped = entry.model_dump(mode="json")
    assert dumped["entryHash"] == ENTRY_HASH_1
    assert "prevEntryHash" in dumped and dumped["prevEntryHash"] is None
    # And a constructed one behaves the same way as a validated one.
    built = CustodyEntry(**LEGACY, entryHash=ENTRY_HASH_1, prevEntryHash=None)  # type: ignore[arg-type]
    assert built.model_dump(mode="json") == dumped


@pytest.mark.asyncio
async def test_python_capture_puts_no_server_minted_keys_on_the_wire() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        r = await tzun.capture(ai_output={"r": "approve"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        wire = r.envelope.model_dump(mode="json")["custodyChain"]
        assert len(wire) == 1
        assert set(wire[0]) <= PLATFORM_CLIENT_CUSTODY_KEYS, wire[0]
        assert "entryHash" not in wire[0] and "prevEntryHash" not in wire[0]
    finally:
        await tzun.close()


@pytest.mark.asyncio
async def test_verify_passes_with_server_minted_entries_in_the_chain() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        await tzun.capture(ai_output={"r": "approve"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        r2 = await tzun.capture(ai_output={"r": "deny"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="c", reason="d")
        env2 = await tzun._storage.retrieve(r2.evidenceId)
        assert env2 is not None
        env2.custodyChain.append(
            CustodyEntry.model_validate({**LEGACY, "entryHash": ENTRY_HASH_1, "prevEntryHash": None})
        )
        env2.custodyChain.append(
            CustodyEntry.model_validate(
                {**LEGACY, "action": "chain_forked", "entryHash": ENTRY_HASH_2, "prevEntryHash": ENTRY_HASH_1}
            )
        )

        res = await tzun.verify(r2.evidenceId)
        assert res.valid is True
        assert res.chainLinkValid is True
        assert res.canonicalDigest == r2.canonicalDigest

        # The mirrored envelope round-trips through the wire model intact.
        wire = env2.model_dump(mode="json")
        assert wire["custodyChain"][1]["entryHash"] == ENTRY_HASH_1
        assert wire["custodyChain"][1]["prevEntryHash"] is None
        assert wire["custodyChain"][2]["prevEntryHash"] == ENTRY_HASH_1
        assert "entryHash" not in wire["custodyChain"][0]
        again = EvidenceEnvelope.model_validate(wire)
        assert again == env2
    finally:
        await tzun.close()
