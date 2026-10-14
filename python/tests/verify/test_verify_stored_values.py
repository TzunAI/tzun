"""``verify()`` reports what it finds in a stored record and never raises on it (Verification §4.10).

A step model that does not resolve, or whose catalog bytes no longer hash to
the digest the step names, is a reported failure. An integer literal past
2^53 - 1 in a stored record is read as ``JSON.parse`` reads it, so a record a
JavaScript writer hashed verifies here.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

import pytest

from tests.storage.test_catalog_primitives import mvd
from tzun_sdk import Tzun
from tzun_sdk._capture import payload_digest
from tzun_sdk._generated.chain import compute_chain_link
from tzun_sdk._record_rules import js_json_loads
from tzun_sdk.storage import MemoryAdapter, SqliteAdapter

HUMAN = {"kind": "human", "id": "acct:u-1"}


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        (5, "descriptor_resolution_failure"),
        ("sha256:" + "9" * 64, "descriptor_resolution_failure"),
        (None, "descriptor_resolution_failure"),
    ],
)
async def test_a_step_model_that_does_not_resolve_is_reported(value: Any, reason: str) -> None:
    store = MemoryAdapter()
    tzun = await Tzun.init(storage=store)
    try:
        model = await tzun.models.register(mvd())
        r = await tzun.capture(
            ai_output={"x": 1},
            action="approve",
            reason="r",
            decider=HUMAN,
            contributions={"steps": [{"role": "propose", "actor": None, "aiBom": {"modelDescriptorDigest": model}, "inputs": []}]},
        )
        assert (await tzun.verify(r.evidenceId)).descriptorResolved is True
        tzun._descriptor_cache.clear()
        bom = store._envelopes[r.evidenceId]["payload"]["contributions"]["steps"][0]["aiBom"]
        if value is None:
            del bom["modelDescriptorDigest"]
        else:
            bom["modelDescriptorDigest"] = value
        result = await tzun.verify(r.evidenceId)
        assert result.descriptorResolved is False and result.valid is False
        assert reason in result.reasons and "digest_mismatch" in result.reasons
    finally:
        await tzun.close()


async def test_a_catalog_descriptor_that_no_longer_hashes_to_its_digest_is_reported() -> None:
    store = MemoryAdapter()
    tzun = await Tzun.init(storage=store)
    try:
        model = await tzun.models.register(mvd())
        r = await tzun.capture(
            ai_output={"x": 1},
            action="approve",
            reason="r",
            decider=HUMAN,
            contributions={"steps": [{"role": "propose", "actor": None, "aiBom": {"modelDescriptorDigest": model}, "inputs": []}]},
        )
        tzun._descriptor_cache.clear()
        store._descriptors[model] = store._descriptors[model].model_copy(update={"modelVersion": "edited"})
        result = await tzun.verify(r.evidenceId)
        assert result.valid is False and result.descriptorResolved is False
        assert result.reasons == ["descriptor_digest_mismatch"]
    finally:
        await tzun.close()


def test_integer_literals_past_two_to_the_53_read_as_json_parse_reads_them() -> None:
    assert js_json_loads("9007199254740991") == 9007199254740991
    assert isinstance(js_json_loads("9007199254740991"), int)
    assert js_json_loads("9007199254740993") == 9007199254740992.0
    assert js_json_loads("1152921504606846976") == float(2**60)
    assert js_json_loads("100000000000000000000") == 1e20
    assert js_json_loads("1" + "0" * 400) == float("inf")


async def test_a_record_a_javascript_writer_hashed_over_large_integers_verifies(tmp_path: Any) -> None:
    path = str(tmp_path / "store.db")
    tzun = await Tzun.init(storage=SqliteAdapter(path, mode="async"))
    first = await tzun.capture(ai_output={"x": 1}, action="approve", reason="r", decider=HUMAN)
    await tzun.close()
    # The record a JavaScript writer stores: integer literals past 2^53 - 1,
    # hashed over the doubles its parser made of them.
    literals = {"nanos": 2**60 + 1, "big": 10**20, "edge": 2**53 + 1}
    payload: dict[str, Any] = {
        "evidenceId": "9b2f1d4e-4444-4a1a-8a1a-000000000004",
        "schemaVersion": "v1.0",
        "aiSystemId": "claims",
        "aiOutput": literals,
        "action": "approve",
        "reason": "r",
        "capturedAt": "2026-10-01T00:00:00.000Z",
        "sequenceNumber": 2,
        "decider": {**HUMAN, "agent": None, "credential": None, "freshness": None},
        "contributions": None,
        "links": None,
        "signoffExpectation": None,
    }
    digest = payload_digest({**payload, "aiOutput": {k: float(v) for k, v in literals.items()}})
    envelope = {
        "envelopeVersion": "e1",
        "payload": payload,
        "integrity": {"canonicalDigest": digest, "chainLink": compute_chain_link(first.canonicalDigest, digest)},
        "nonRepudiation": {},
        "custodyChain": [],
        "attestationStatus": "none",
    }
    text = json.dumps(envelope, separators=(",", ":"))
    assert str(2**60 + 1) in text
    con = sqlite3.connect(path)
    con.execute(
        "INSERT INTO evidence_envelopes (evidence_id, chain_id, sequence_number, envelope_json) VALUES (?, ?, ?, ?)",
        (payload["evidenceId"], "default", 2, text),
    )
    con.commit()
    con.close()
    tzun = await Tzun.init(storage=SqliteAdapter(path, mode="async"))
    try:
        result = await tzun.verify(payload["evidenceId"])
        assert result.valid is True and result.reasons == []
        assert result.canonicalDigest == digest
    finally:
        await tzun.close()
