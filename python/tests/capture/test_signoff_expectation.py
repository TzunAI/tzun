"""``payload.signoffExpectation`` on the Python capture path (Record §9.1).

Every capture writes it into the hashed payload, ``None`` by default; a capture
refuses a value of the wrong shape before a sequence number is taken (the
session and mandate forms included: only the capture that claimed the slot
writes them); verify() reports a record that does not carry the signature it
expects; and a store an earlier release wrote (0.7.x, or before 0.7.0) is
refused at init with a typed error naming the record's field-set generation
(Record §4.1). The TS twin is tests/ts/signoff-expectation-capture.test.ts.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid

import pytest

from tzun_sdk import Tzun
from tzun_sdk._generated.canonical import (
    V1_HASHED_FIELDS,
    V1_HASHED_FIELDS_0_7,
    V1_HASHED_FIELDS_BEFORE_0_7,
    canonical_serialize,
)
from tzun_sdk.errors import InvalidSignoffExpectationError, StoreSchemaOutdatedError
from tzun_sdk.models import (
    EvidenceEnvelope,
    SignatureRequiredExpectation,
)
from tzun_sdk.storage import MemoryAdapter
from tzun_sdk.storage.sqlite import SqliteAdapter

HEX = "c" * 64
BEFORE_0_7 = list(V1_HASHED_FIELDS_BEFORE_0_7)
FIELD_SET_0_7 = list(V1_HASHED_FIELDS_0_7)
DECIDER = {"kind": "human", "id": "acct:test-reviewer"}


def _digest(payload: dict, fields: list[str]) -> str:
    return hashlib.sha256(canonical_serialize(payload, fields).encode("utf-8")).hexdigest()


def _json_from_06(seq: int = 1) -> dict:
    """A record's JSON exactly as 0.6.x stored it: no signoffExpectation key, digest over the earlier set."""
    payload = {
        "evidenceId": str(uuid.uuid4()),
        "schemaVersion": "v1.0",
        "aiSystemId": "signoff-expectation",
        "aiOutput": {"r": "x"},
        "humanAction": "approved",
        "humanReason": "ok",
        "capturedAt": "2026-09-01T00:00:00.000Z",
        "sequenceNumber": seq,
        "aiBom": None,
    }
    return {
        "envelopeVersion": "e1",
        "payload": payload,
        "integrity": {"canonicalDigest": _digest(payload, BEFORE_0_7), "chainLink": None},
        "nonRepudiation": {},
        "custodyChain": [],
        "attestationStatus": "none",
    }


def _json_from_07(seq: int = 1) -> dict:
    """A record's JSON exactly as 0.7.x stored it: the nine-name field set, signoffExpectation written."""
    record = _json_from_06(seq)
    record["payload"]["signoffExpectation"] = None
    record["integrity"]["canonicalDigest"] = _digest(record["payload"], FIELD_SET_0_7)
    return record


def _altered(record: dict) -> dict:
    """``record`` changed after its digest was taken: it recomputes under neither field set."""
    record["payload"]["humanReason"] = "rewritten"
    return record


def _minimal_store(path: str) -> None:
    """A SQLite file holding only the envelopes table, as the earliest releases wrote it."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE evidence_envelopes (evidence_id TEXT PRIMARY KEY, chain_id TEXT NOT NULL, "
            "sequence_number INTEGER NOT NULL, envelope_json TEXT NOT NULL, "
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        conn.commit()
    finally:
        conn.close()


def _fingerprint(path: str) -> tuple[str, list]:
    """The file's bytes and its schema, read without writing to it."""
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        schema = conn.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").fetchall()
    finally:
        conn.close()
    return digest, schema


def _write_06_row(path: str, record: dict, chain_id: str = "default") -> None:
    """Write the row 0.6.x wrote. Storing through this SDK would add the key."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "INSERT INTO evidence_envelopes (evidence_id, chain_id, sequence_number, envelope_json) "
            "VALUES (?, ?, ?, ?)",
            (
                record["payload"]["evidenceId"],
                chain_id,
                record["payload"]["sequenceNumber"],
                json.dumps(record),
            ),
        )
        conn.commit()
    finally:
        conn.close()


async def test_capture_writes_null_by_default_and_it_is_hashed() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        result = await tzun.capture(ai_output={"r": "x"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok")
        dumped = result.envelope.payload.model_dump(mode="json")
        assert dumped["signoffExpectation"] is None
        assert result.canonicalDigest == _digest(dumped, list(V1_HASHED_FIELDS))
        assert '"signoffExpectation":null' in canonical_serialize(dumped, list(V1_HASHED_FIELDS))
        verdict = await tzun.verify(result.evidenceId)
        assert verdict.valid is True
        assert verdict.signoffExpectationValid is True
        assert verdict.signoffExpectationReason is None
    finally:
        await tzun.close()


@pytest.mark.parametrize(
    "value",
    [{"policyDigest": HEX}, SignatureRequiredExpectation(policyDigest=HEX)],
    ids=["dict", "model"],
)
async def test_policy_form_is_stored_hashed_and_reported_owed(value: object) -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        result = await tzun.capture(
            ai_output={"r": "x"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok", signoff_expectation=value
        )
        dumped = result.envelope.payload.model_dump(mode="json")
        assert dumped["signoffExpectation"] == {"policyDigest": HEX}
        assert result.canonicalDigest == _digest(dumped, list(V1_HASHED_FIELDS))
        verdict = await tzun.verify(result.evidenceId)
        assert verdict.valid is True
        assert verdict.signoffExpectationValid is None
        assert verdict.signoffExpectationReason == "signature_missing"
    finally:
        await tzun.close()


async def test_the_callers_dict_is_copied() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        expectation = {"policyDigest": HEX}
        result = await tzun.capture(
            ai_output={"r": "x"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok",
            signoff_expectation=expectation,
        )
        expectation["policyDigest"] = "d" * 64
        stored = await tzun._storage.retrieve(result.evidenceId)
        assert stored is not None
        assert stored.payload.model_dump(mode="json")["signoffExpectation"] == {"policyDigest": HEX}
    finally:
        await tzun.close()


@pytest.mark.parametrize(
    ("value", "violation"),
    [
        ("required", "not_an_object"),
        ({"policyDigest": HEX, "by": "x"}, "unknown_members"),
        ({"policyDigest": HEX.upper()}, "invalid_policy_digest"),
        ({"policyDigest": "abc"}, "invalid_policy_digest"),
        ({"statementDigest": HEX, "sessionSeq": 0}, "invalid_session_seq"),
        ({"statementDigest": HEX, "sessionSeq": True}, "invalid_session_seq"),
        ({"statementDigest": HEX, "sessionSeq": 1}, "session_form_not_writable"),
        (
            {"mandateAssertion": HEX, "mandateSeq": 1, "totals": None, "confirm": False},
            "mandate_form_not_writable",
        ),
        ({"mandateAssertion": HEX, "mandateSeq": 1, "totals": None, "confirm": 1}, "invalid_confirm"),
        ({"mandateAssertion": HEX, "mandateSeq": 0, "totals": None, "confirm": False}, "invalid_mandate_seq"),
    ],
)
async def test_a_bad_value_is_refused_before_a_sequence_is_taken(value: object, violation: str) -> None:
    storage = MemoryAdapter()
    tzun = await Tzun.init(storage=storage)
    try:
        with pytest.raises(InvalidSignoffExpectationError) as exc:
            await tzun.capture(
                ai_output={"r": "x"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok",
                signoff_expectation=value,
            )
        assert exc.value.violation == violation
        assert exc.value.field == "signoffExpectation"
        assert exc.value.code == "validation_failure"
        assert await storage.head(None) is None
        ok = await tzun.capture(ai_output={"r": "x"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok")
        assert ok.sequenceNumber == 1
    finally:
        await tzun.close()


async def test_verify_reports_a_transplanted_session_signoff() -> None:
    storage = MemoryAdapter()
    tzun = await Tzun.init(storage=storage)
    try:
        result = await tzun.capture(ai_output={"r": "x"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok")
        # A store writer attaches a session sign-off to a record whose hashed
        # expectation names no session.
        raw = json.loads(result.envelope.model_dump_json())
        raw["nonRepudiation"]["signoff"] = {
            "statement": {"v": "tzun-signoff/1", "mode": "session"},
            "sessionSeq": 1,
        }
        raw["nonRepudiation"]["webauthnAssertion"] = {
            "signature": "c2ln", "credentialKeyId": "c", "algorithm": "ES256",
        }
        storage._envelopes[result.evidenceId] = raw  # type: ignore[attr-defined]
        verdict = await tzun.verify(result.evidenceId)
        assert verdict.valid is True
        assert verdict.signoffExpectationValid is False
        assert verdict.signoffExpectationReason == "session_signoff_not_expected"
    finally:
        await tzun.close()


async def test_sqlite_store_from_before_0_7_is_refused_at_init(tmp_path) -> None:
    path = str(tmp_path / "old.db")
    old = SqliteAdapter(path)
    await old.ensure_tables()
    await old.close()
    record = _json_from_06(1)
    _write_06_row(path, record)
    _write_06_row(path, _json_from_06(2))
    before = _fingerprint(path)

    with pytest.raises(StoreSchemaOutdatedError) as exc:
        await Tzun.init(storage=SqliteAdapter(path))
    assert exc.value.code == "store_schema_outdated"
    assert exc.value.retryable is False
    # The first record names the store, and its generation.
    assert exc.value.evidence_id == record["payload"]["evidenceId"]
    assert exc.value.generation == "before-0.7"
    assert _fingerprint(path) == before


async def test_sqlite_store_0_7_wrote_is_refused_at_init(tmp_path) -> None:
    """0.8.0 revised the v1.0 field set in place: a 0.7.x store is refused, naming the generation."""
    path = str(tmp_path / "seven.db")
    _minimal_store(path)
    record = _json_from_07(1)
    _write_06_row(path, record)
    _write_06_row(path, _json_from_07(2))
    before = _fingerprint(path)
    with pytest.raises(StoreSchemaOutdatedError) as exc:
        await Tzun.init(storage=SqliteAdapter(path))
    assert exc.value.evidence_id == record["payload"]["evidenceId"]
    assert exc.value.generation == "0.7"
    assert "0.7.x" in str(exc.value)
    assert _fingerprint(path) == before


async def test_a_refused_sqlite_store_gains_no_table(tmp_path) -> None:
    """The check reads before ensure_tables(), so a refused store is not set up first."""
    path = str(tmp_path / "minimal.db")
    _minimal_store(path)
    _write_06_row(path, _json_from_06(1))
    before = _fingerprint(path)
    with pytest.raises(StoreSchemaOutdatedError):
        await Tzun.init(storage=SqliteAdapter(path))
    assert _fingerprint(path) == before


async def test_an_old_sqlite_store_whose_newest_record_was_altered_is_still_refused(tmp_path) -> None:
    path = str(tmp_path / "old-altered-head.db")
    _minimal_store(path)
    first = _json_from_06(1)
    _write_06_row(path, first)
    _write_06_row(path, _altered(_json_from_06(2)))
    with pytest.raises(StoreSchemaOutdatedError) as exc:
        await Tzun.init(storage=SqliteAdapter(path))
    assert exc.value.evidence_id == first["payload"]["evidenceId"]


async def test_an_old_sqlite_store_whose_first_record_was_altered_is_refused_by_its_newest(tmp_path) -> None:
    path = str(tmp_path / "old-altered-first.db")
    _minimal_store(path)
    newest = _json_from_06(2)
    _write_06_row(path, _altered(_json_from_06(1)))
    _write_06_row(path, newest)
    with pytest.raises(StoreSchemaOutdatedError) as exc:
        await Tzun.init(storage=SqliteAdapter(path))
    assert exc.value.evidence_id == newest["payload"]["evidenceId"]


async def test_a_current_store_opens_with_an_old_format_record_appended(tmp_path) -> None:
    """One forged old-format row appended to a current store does not refuse it; verify reports it."""
    path = str(tmp_path / "new-forged.db")
    a = await Tzun.init(storage=SqliteAdapter(path))
    for i in range(3):
        await a.capture(ai_output={"r": i}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok")
    await a.close()
    forged = _json_from_06(4)
    _write_06_row(path, forged)
    b = await Tzun.init(storage=SqliteAdapter(path))
    try:
        verdict = await b.verify(forged["payload"]["evidenceId"])
        assert verdict.valid is False
        # Its digest does not recompute, so its expectation is not read; the
        # fact names the earlier field set it recomputes under.
        assert verdict.signoffExpectationValid is None
        assert verdict.signoffExpectationReason == "digest_invalid"
        assert verdict.fieldSet == "before-0.7"
    finally:
        await b.close()


async def test_an_expectation_rewritten_to_null_is_not_read(tmp_path) -> None:
    """The rewrite-to-null tamper on SQLite: a record that owed a signature, stripped of
    it, with its ``{policyDigest}`` rewritten to null. Its digest no longer
    recomputes, so the rewritten value is not read: ``None``,
    ``digest_invalid``, never ``True`` (the TS engine's rule).
    """
    path = str(tmp_path / "rewritten.db")
    a = await Tzun.init(storage=SqliteAdapter(path))
    try:
        genesis = await a.capture(ai_output={"r": "x"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok")
        owed = await a.capture(
            ai_output={"r": "y"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
            signoff_expectation={"policyDigest": HEX},
        )
    finally:
        await a.close()
    conn = sqlite3.connect(path)
    try:
        raw = json.loads(
            conn.execute(
                "SELECT envelope_json FROM evidence_envelopes WHERE evidence_id = ?",
                (owed.evidenceId,),
            ).fetchone()[0]
        )
        raw["payload"]["signoffExpectation"] = None
        conn.execute(
            "UPDATE evidence_envelopes SET envelope_json = ? WHERE evidence_id = ?",
            (json.dumps(raw), owed.evidenceId),
        )
        conn.commit()
    finally:
        conn.close()
    b = await Tzun.init(storage=SqliteAdapter(path))
    try:
        verdict = await b.verify(owed.evidenceId)
        assert verdict.valid is False
        assert "digest_mismatch" in verdict.reasons
        assert verdict.signoffExpectationValid is None
        assert verdict.signoffExpectationReason == "digest_invalid"
        intact = await b.verify(genesis.evidenceId)
        assert intact.signoffExpectationValid is True
        # The export's verdict gives the same answer (the TS recordVerdict rule).
        exported = await b.export_evidence(owed.evidenceId)
        assert exported.verdict.digest.status == "invalid"
        assert exported.verdict.signoffExpectation is not None
        assert exported.verdict.signoffExpectation.valid is None
        assert exported.verdict.signoffExpectation.reason == "digest_invalid"
        exported_intact = await b.export_evidence(genesis.evidenceId)
        assert exported_intact.verdict.signoffExpectation is not None
        assert exported_intact.verdict.signoffExpectation.valid is True
    finally:
        await b.close()


async def test_a_path_with_no_file_yet_opens(tmp_path) -> None:
    tzun = await Tzun.init(storage=SqliteAdapter(str(tmp_path / "none-yet.db")))
    await tzun.close()


async def test_sqlite_store_this_release_wrote_opens_again(tmp_path) -> None:
    path = str(tmp_path / "new.db")
    a = await Tzun.init(storage=SqliteAdapter(path))
    await a.capture(ai_output={"r": "x"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok")
    await a.close()
    b = await Tzun.init(storage=SqliteAdapter(path))
    try:
        r = await b.capture(ai_output={"r": "y"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok")
        assert r.sequenceNumber == 2
    finally:
        await b.close()


async def test_an_empty_chain_is_judged_by_the_stores_first_record(tmp_path) -> None:
    path = str(tmp_path / "other-chain.db")
    old = SqliteAdapter(path)
    await old.ensure_tables()
    await old.close()
    _write_06_row(path, _json_from_06(1))
    with pytest.raises(StoreSchemaOutdatedError):
        await Tzun.init(storage=SqliteAdapter(path), chain_id="a-new-chain")


async def test_an_altered_old_record_is_not_taken_for_an_old_store() -> None:
    storage = MemoryAdapter()
    await storage.store(_altered(_json_from_06(1)), None)
    tzun = await Tzun.init(storage=storage)
    await tzun.close()


@pytest.mark.parametrize("make", [_json_from_06, _json_from_07], ids=["before-0.7", "0.7"])
async def test_a_memory_store_holding_an_old_record_is_refused(make) -> None:
    storage = MemoryAdapter()
    record = make(1)
    await storage.store(record, None)
    with pytest.raises(StoreSchemaOutdatedError) as exc:
        await Tzun.init(storage=storage)
    assert exc.value.evidence_id == record["payload"]["evidenceId"]


async def _never() -> object:
    raise AssertionError("the newest record is not needed here")


async def test_the_store_rule_the_first_record_decides() -> None:
    from tzun_sdk._store_schema_guard import refuse_outdated_store

    await refuse_outdated_store(None, _never)
    first = _json_from_06(1)
    with pytest.raises(StoreSchemaOutdatedError) as exc:
        await refuse_outdated_store(first, _never)
    assert exc.value.evidence_id == first["payload"]["evidenceId"]

    seven = _json_from_07(1)
    with pytest.raises(StoreSchemaOutdatedError) as exc:
        await refuse_outdated_store(seven, _never)
    assert exc.value.generation == "0.7"

    current = {
        "payload": {
            "evidenceId": str(uuid.uuid4()),
            "schemaVersion": "v1.0",
            "aiSystemId": "signoff-expectation",
            "aiOutput": {},
            "action": "approved",
            "reason": "ok",
            "capturedAt": "2026-10-01T00:00:00.000Z",
            "sequenceNumber": 1,
            "decider": {"kind": "human", "id": "acct:u-1", "agent": None, "credential": None, "freshness": None},
            "contributions": None,
            "links": None,
            "signoffExpectation": None,
        },
        "integrity": {"canonicalDigest": "", "chainLink": None},
    }
    current["integrity"]["canonicalDigest"] = _digest(current["payload"], list(V1_HASHED_FIELDS))
    await refuse_outdated_store(current, _never)
    altered_current = json.loads(json.dumps(current))
    altered_current["payload"]["reason"] = "rewritten"
    await refuse_outdated_store(altered_current, _never)

    newest = _json_from_06(2)

    async def _newest() -> object:
        return newest

    with pytest.raises(StoreSchemaOutdatedError) as exc:
        await refuse_outdated_store(_altered(_json_from_06(1)), _newest)
    assert exc.value.evidence_id == newest["payload"]["evidenceId"]

    async def _altered_newest() -> object:
        return _altered(_json_from_06(2))

    await refuse_outdated_store(_altered(_json_from_06(1)), _altered_newest)


async def test_a_cloud_backend_is_left_to_the_platform() -> None:
    """The platform checks its own store, as the TS SDK's cloud transport leaves it to it.

    A cloud user whose platform still holds records from before 0.7.0 is not
    told to create a new dbPath or Postgres database, the remedy for a local
    store.
    """
    import httpx

    from tzun_sdk.storage.http import HttpBackendAdapter

    old = _json_from_06(1)

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/v1/app/evidence":
            item = {
                "evidenceId": old["payload"]["evidenceId"],
                "sequenceNumber": old["payload"]["sequenceNumber"],
                "canonicalDigest": old["integrity"]["canonicalDigest"],
            }
            return httpx.Response(200, json={"evidence": [item]})
        return httpx.Response(200, json={})

    adapter = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="tzk_live_x")
    adapter._async_client = httpx.AsyncClient(
        base_url="https://api.tzun.ai", transport=httpx.MockTransport(_handler)
    )
    tzun = await Tzun.init(storage=adapter)
    await tzun.close()


def _session_record(signoff_seq: object, expected_seq: int) -> dict:
    """A record captured into slot ``expected_seq`` of a session, its signoff block naming ``signoff_seq``."""
    vectors = json.loads(
        (
            __import__("pathlib").Path(__file__).parents[3] / "vectors" / "signoff-expectation-vectors.json"
        ).read_text(encoding="utf-8")
    )
    base = next(c for c in vectors["checks"] if c["case"] == "session, its own sign-off")["envelope"]
    raw = json.loads(json.dumps(base))
    raw["payload"]["signoffExpectation"]["sessionSeq"] = expected_seq
    raw["integrity"]["canonicalDigest"] = _digest(raw["payload"], list(V1_HASHED_FIELDS))
    raw["nonRepudiation"]["signoff"]["sessionSeq"] = signoff_seq
    return raw


@pytest.mark.parametrize(
    ("signoff_seq", "expected_seq"),
    [("4", 4), (" 4", 4), (True, 1)],
    ids=["the string 4", "the string space-4", "true for slot 1"],
)
async def test_a_slot_the_model_would_coerce_is_a_mismatch_end_to_end(
    signoff_seq: object, expected_seq: int
) -> None:
    """Loading a record through the models does not turn a stored "4" or true into a slot.

    Stored through MemoryAdapter and read back by Tzun.verify(), as the TS
    engine reads the same JSON: ``session_seq_mismatch``. The block round-trips
    as it was stored.
    """
    raw = _session_record(signoff_seq, expected_seq)
    storage = MemoryAdapter()
    await storage.store(EvidenceEnvelope.model_validate_json(json.dumps(raw)), None)
    tzun = await Tzun.init(storage=storage)
    try:
        verdict = await tzun.verify(raw["payload"]["evidenceId"])
        assert verdict.valid is True
        assert verdict.signoffExpectationValid is False
        assert verdict.signoffExpectationReason == "session_seq_mismatch"
        stored = await storage.retrieve(raw["payload"]["evidenceId"])
        assert stored is not None
        dumped = json.loads(stored.model_dump_json(exclude_unset=True))
        assert dumped["nonRepudiation"]["signoff"]["sessionSeq"] == signoff_seq
    finally:
        await tzun.close()


async def test_a_junk_signature_in_place_of_a_stripped_one_is_a_finding() -> None:
    storage = MemoryAdapter()
    tzun = await Tzun.init(storage=storage)
    try:
        result = await tzun.capture(
            ai_output={"r": "x"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
            signoff_expectation={"policyDigest": HEX},
        )
        raw = json.loads(result.envelope.model_dump_json())
        raw["nonRepudiation"]["signoff"] = {"statement": {"mode": "batch"}}
        raw["nonRepudiation"]["webauthnAssertion"] = {
            "signature": "AA", "credentialKeyId": "x", "algorithm": "ES256", "clientDataJSON": "e30",
        }
        storage._envelopes[result.evidenceId] = raw  # type: ignore[attr-defined]
        verdict = await tzun.verify(result.evidenceId)
        assert verdict.valid is True
        assert verdict.signoffExpectationValid is False
        assert verdict.signoffExpectationReason == "signoff_unbound"
    finally:
        await tzun.close()


def test_an_empty_stored_digest_never_raises() -> None:
    from tzun_sdk.signoff_expectation import check_signoff_expectation

    envelope = {
        "payload": {"signoffExpectation": {"policyDigest": HEX}},
        "integrity": {"canonicalDigest": ""},
        "nonRepudiation": {
            "webauthnAssertion": {
                "clientDataJSON": __import__("base64").urlsafe_b64encode(
                    json.dumps({"type": "webauthn.get", "challenge": "x"}).encode()
                ).decode(),
            }
        },
    }
    assert check_signoff_expectation(envelope) == {"valid": None, "reason": "signature_missing"}


def _pg_test_dsn() -> str:
    """DATABASE_URL, when it names a throwaway ``*_test`` database; the leg is skipped otherwise."""
    dsn = os.environ.get("DATABASE_URL", "")
    name = dsn.rsplit("/", 1)[-1].split("?", 1)[0]
    if not name.endswith("_test"):
        pytest.skip("DATABASE_URL must name a throwaway *_test database to run this leg")
    return dsn


async def _pg_schema(dsn: str, *, minimal: bool) -> tuple[str, str]:
    """A schema of this leg's own, and the DSN whose connections use it.

    ``minimal`` creates only the envelopes table, as the earliest releases
    wrote it; otherwise the schema is set up as this release sets it up.
    """
    import asyncpg

    from tzun_sdk.storage.postgres import PostgresAdapter

    schema = f"signoff_expectation_{uuid.uuid4().hex[:12]}"
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute(f"CREATE SCHEMA {schema}")
    finally:
        await conn.close()
    scoped = f"{dsn}{'&' if '?' in dsn else '?'}search_path={schema}"
    if minimal:
        conn = await asyncpg.connect(scoped)
        try:
            await conn.execute(
                "CREATE TABLE evidence_envelopes (evidence_id TEXT PRIMARY KEY, chain_id TEXT NOT NULL, "
                "sequence_number BIGINT NOT NULL, envelope_json JSONB NOT NULL, "
                "created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
        finally:
            await conn.close()
    else:
        adapter = PostgresAdapter(scoped, mode="async")
        await adapter.ensure_tables()
        await adapter.close()
    return schema, scoped


async def _pg_drop(dsn: str, schema: str) -> None:
    import asyncpg

    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
    finally:
        await conn.close()


async def _pg_insert_06(scoped: str, record: dict, chain: str = "default") -> None:
    import asyncpg

    conn = await asyncpg.connect(scoped)
    try:
        await conn.execute(
            "INSERT INTO evidence_envelopes (evidence_id, chain_id, sequence_number, envelope_json) "
            "VALUES ($1, $2, $3, $4::jsonb)",
            record["payload"]["evidenceId"], chain, record["payload"]["sequenceNumber"], json.dumps(record),
        )
    finally:
        await conn.close()


async def _pg_tables(scoped: str, schema: str) -> list[str]:
    import asyncpg

    conn = await asyncpg.connect(scoped)
    try:
        rows = await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname = $1 ORDER BY tablename", schema
        )
    finally:
        await conn.close()
    return [r["tablename"] for r in rows]


def _libpq_scoped(dsn: str, schema: str) -> str:
    """``dsn`` with its connections on ``schema``, spelt for libpq (the sync adapter's psycopg)."""
    return f"{dsn}{'&' if '?' in dsn else '?'}options=-csearch_path%3D{schema}"


@pytest.mark.integration
@pytest.mark.parametrize("mode", ["async", "sync"])
async def test_postgres_store_from_before_0_7_is_refused_at_init(mode: str) -> None:
    from tzun_sdk.storage.postgres import PostgresAdapter

    dsn = _pg_test_dsn()
    schema, scoped = await _pg_schema(dsn, minimal=True)
    adapter_dsn = scoped if mode == "async" else _libpq_scoped(dsn, schema)
    try:
        first = _json_from_06(1)
        await _pg_insert_06(scoped, first)
        await _pg_insert_06(scoped, _json_from_06(2))
        with pytest.raises(StoreSchemaOutdatedError) as exc:
            await Tzun.init(storage=PostgresAdapter(adapter_dsn, mode=mode), chain_id="a-new-chain")
        assert exc.value.evidence_id == first["payload"]["evidenceId"]
        # Read before ensure_tables(): nothing was set up in the refused store.
        assert await _pg_tables(scoped, schema) == ["evidence_envelopes"]
    finally:
        await _pg_drop(dsn, schema)


@pytest.mark.integration
async def test_postgres_store_0_7_wrote_opens_with_an_old_format_record_appended() -> None:
    from tzun_sdk.storage.postgres import PostgresAdapter

    dsn = _pg_test_dsn()
    schema, scoped = await _pg_schema(dsn, minimal=False)
    try:
        a = await Tzun.init(storage=PostgresAdapter(scoped, mode="async"))
        for i in range(3):
            await a.capture(ai_output={"r": i}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok")
        await a.close()
        await _pg_insert_06(scoped, _json_from_06(4))
        b = await Tzun.init(storage=PostgresAdapter(scoped, mode="async"))
        await b.close()
    finally:
        await _pg_drop(dsn, schema)


@pytest.mark.integration
async def test_postgres_ensure_tables_indexes_the_order_the_store_check_reads() -> None:
    """``read_envelope_at_end`` sorts by ``(created_at, evidence_id)`` on every
    open; after the first open it reads through an index."""
    import asyncpg

    from tzun_sdk.storage.postgres import PostgresAdapter

    dsn = _pg_test_dsn()
    schema, scoped = await _pg_schema(dsn, minimal=False)
    try:
        a = await Tzun.init(storage=PostgresAdapter(scoped, mode="async"))
        await a.close()
        conn = await asyncpg.connect(scoped)
        try:
            rows = await conn.fetch(
                "SELECT indexdef FROM pg_indexes WHERE schemaname = $1 "
                "AND indexname = 'idx_evidence_envelopes_created_at'",
                schema,
            )
        finally:
            await conn.close()
        assert [r["indexdef"].replace(f"{schema}.", "") for r in rows] == [
            "CREATE INDEX idx_evidence_envelopes_created_at ON evidence_envelopes "
            "USING btree (created_at, evidence_id)"
        ]
    finally:
        await _pg_drop(dsn, schema)
