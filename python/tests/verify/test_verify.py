"""Verify path tests."""

from __future__ import annotations

import pytest

from tests._raw import RawView
from tzun_sdk import Tzun
from tzun_sdk.errors import VerificationError, WireFormatMismatch
from tzun_sdk.models import EvidenceEnvelope
from tzun_sdk.storage import MemoryAdapter


def stored_row(tzun: Tzun, evidence_id: str) -> EvidenceEnvelope:
    """The envelope the memory adapter HOLDS — not a copy of it.

    Tampering has to happen behind the adapter's back, the way an attacker
    with write access to the store would do it. Every adapter's reads return a
    detached copy, so assigning to what ``retrieve()`` returned leaves the
    store as it was; a tamper test rewrites the held row itself, which is what
    an attacker's write does on SQLite and Postgres too.
    """
    return RawView(tzun._storage._envelopes[evidence_id])  # type: ignore[attr-defined,return-value]


@pytest.mark.asyncio
async def test_verify_detects_broken_chain() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        await tzun.capture(ai_output={"r": "approve"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        r2 = await tzun.capture(ai_output={"r": "deny"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="c", reason="d")
        stored_row(tzun, r2.evidenceId).integrity.chainLink = "0" * 64
        res = await tzun.verify(r2.evidenceId)
        assert res.chainLinkValid is False
        assert res.valid is False
        assert "chain_link_mismatch" in res.reasons
    finally:
        await tzun.close()


@pytest.mark.asyncio
async def test_verify_genesis_chainlink_is_none() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        r1 = await tzun.capture(ai_output={"r": "approve"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        res = await tzun.verify(r1.evidenceId)
        assert res.chainLinkValid is None
        assert res.valid is True
    finally:
        await tzun.close()


async def test_capture_then_verify_roundtrip() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        result = await tzun.capture(
            ai_output={"r": "x"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )
        v = await tzun.verify(result.evidenceId)
        assert v.valid is True
        assert v.canonicalDigest == result.canonicalDigest
    finally:
        await tzun.close()


async def test_verify_missing_envelope_raises() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        with pytest.raises(VerificationError):
            await tzun.verify("00000000-0000-0000-0000-000000000000")
    finally:
        await tzun.close()


async def test_verify_tampered_digest_invalid() -> None:
    """A modified envelope's verify reports digest_mismatch."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        result = await tzun.capture(
            ai_output={"r": "x"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )
        # Tamper directly in the memory store.
        env = RawView(tzun._storage._envelopes[result.evidenceId])  # type: ignore[attr-defined]
        env.payload.reason = "TAMPERED"
        v = await tzun.verify(result.evidenceId)
        assert v.valid is False
        assert "digest_mismatch" in v.reasons
    finally:
        await tzun.close()


async def test_wire_format_mismatch_raised() -> None:
    """schemaVersion != v1.0 raises WireFormatMismatch."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        result = await tzun.capture(
            ai_output={"r": "x"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )
        env = RawView(tzun._storage._envelopes[result.evidenceId])  # type: ignore[attr-defined]
        # The stored row rewritten behind the adapter's back.
        env.payload.schemaVersion = "v2.0"
        with pytest.raises(WireFormatMismatch):
            await tzun.verify(result.evidenceId)
    finally:
        await tzun.close()


# ── a nulled chainLink must not verify ───────────────────────────────────────
#
# chainLink is NOT in V1_HASHED_FIELDS, so nulling it leaves the canonical
# digest intact. sequenceNumber IS hashed, so a record claiming sequence > 1 is
# committed to having had a predecessor. verify() must therefore treat a null
# link on a non-genesis record as a failure, matching the TS engine rule
# (packages/engine/src/verify.ts).


async def test_verify_rejects_nulled_chainlink_at_sequence_two() -> None:
    """A detached (chainLink=None) record at sequence 2 must fail verification."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        await tzun.capture(ai_output={"r": "approve"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        r2 = await tzun.capture(ai_output={"r": "deny"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="c", reason="d")
        env2 = stored_row(tzun, r2.evidenceId)
        assert env2.payload.sequenceNumber == 2
        # The attack: drop the link. The canonical digest is untouched because
        # chainLink is outside the hashed field set.
        env2.integrity.chainLink = None
        res = await tzun.verify(r2.evidenceId)
        assert res.chainLinkValid is False
        assert res.valid is False
        assert "chain_link_mismatch" in res.reasons
    finally:
        await tzun.close()


async def test_verify_range_rejects_rewritten_chain() -> None:
    """The full exploit: rewrite record 1 and its digest, null record 2's link."""
    import hashlib

    from tzun_sdk._generated.canonical import V1_HASHED_FIELDS, canonical_serialize

    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        r1 = await tzun.capture(
            ai_output={"r": "approve"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b"
        )
        r2 = await tzun.capture(
            ai_output={"r": "deny"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="c", reason="d"
        )
        env1 = stored_row(tzun, r1.evidenceId)
        env2 = stored_row(tzun, r2.evidenceId)
        # Rewrite record 1's payload and recompute its digest with the public
        # algorithm — record 1 alone still verifies clean.
        env1.payload.reason = "REWRITTEN"
        env1.integrity.canonicalDigest = hashlib.sha256(
            canonical_serialize(env1.payload.raw, list(V1_HASHED_FIELDS)).encode("utf-8")
        ).hexdigest()
        # Detach record 2 so the now-stale link is not checked.
        env2.integrity.chainLink = None

        results = await tzun.verify_range(1, 2)
        assert len(results) == 2
        assert any(r.valid is False for r in results), (
            "a rewritten chain must not verify clean end to end"
        )
    finally:
        await tzun.close()


async def test_verify_rejects_missing_predecessor() -> None:
    """Deleting the predecessor must not turn record 2 into a valid genesis."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        r1 = await tzun.capture(
            ai_output={"r": "approve"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b"
        )
        r2 = await tzun.capture(
            ai_output={"r": "deny"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="c", reason="d"
        )
        env2 = stored_row(tzun, r2.evidenceId)
        # Attacker deletes record 1 outright and nulls record 2's link.
        store = tzun._storage
        del store._envelopes[r1.evidenceId]  # type: ignore[attr-defined]
        store._chains["default"].remove(r1.evidenceId)  # type: ignore[attr-defined]
        env2.integrity.chainLink = None

        res = await tzun.verify(r2.evidenceId)
        assert res.chainLinkValid is False
        assert res.valid is False
        assert "chain_link_mismatch" in res.reasons
    finally:
        await tzun.close()


async def test_verify_honest_record_past_list_page_limit(tmp_path) -> None:
    """An honest record beyond storage.list()'s default page size still verifies.

    SqliteAdapter.list()/PostgresAdapter.list() default to limit=100 and are not
    chain-scoped. Record 105's predecessor, record 104, is past that page, so a
    predecessor lookup bounded by it would report honest record 105 as
    chain_link_mismatch.
    """
    from tzun_sdk.storage import SqliteAdapter

    adapter = SqliteAdapter(str(tmp_path / "chain.db"), mode="sync")
    tzun = await Tzun.init(storage=adapter)
    try:
        last = None
        for i in range(105):
            last = await tzun.capture(
                ai_output={"i": i}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok"
            )
        assert last is not None and last.sequenceNumber == 105
        res = await tzun.verify(last.evidenceId)
        assert res.chainLinkValid is True
        assert res.valid is True
        assert res.reasons == []

        # verify_range must not truncate at the page limit either.
        all_results = await tzun.verify_range(1, 105)
        assert len(all_results) == 105
        assert all(r.valid for r in all_results)
    finally:
        await tzun.close()


# --- the WebAuthn artifact at rest ----------------------------------------------
#
# Python cannot run a ceremony and holds no credential store, so it
# can never report a signature as verified — `attestationVerified` is None for
# every record Python itself captures. What it CAN do, with nothing in hand, is
# say whether the assertion a record carries is even about that record: the
# challenge is a pure function of the canonical digest. So a replayed assertion
# reads `False` with `assertion_not_bound_to_digest`, while an unattested record
# stays `None`.


def _bound_assertion(digest: str, *, challenge: str | None = None) -> dict[str, str]:
    import base64
    import json as _json

    from tzun_sdk.attestation import webauthn_challenge_for_digest

    client_data = _json.dumps(
        {
            "type": "webauthn.get",
            "challenge": challenge or webauthn_challenge_for_digest(digest),
            "origin": "https://app.example",
        }
    ).encode()
    return {
        "signature": "sig",
        "credentialKeyId": "cred-jane",
        "algorithm": "ES256",
        "authenticatorData": base64.b64encode(b"\x01" * 37).decode(),
        "clientDataJSON": base64.b64encode(client_data).decode(),
    }


@pytest.mark.asyncio
async def test_verify_reports_an_unbound_assertion_as_such() -> None:
    from tzun_sdk._generated.models import WebauthnAssertion

    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        r = await tzun.capture(ai_output={"r": "approve"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        row = stored_row(tzun, r.evidenceId)
        # A reviewer's login assertion, stapled on after the fact — the shape
        # every pre-0.3.16 record with a signature actually has.
        row.nonRepudiation.webauthnAssertion = WebauthnAssertion(
            **_bound_assertion(row.integrity.canonicalDigest, challenge="a-login-nonce")
        )

        res = await tzun.verify(r.evidenceId)
        assert res.attestationVerified is False
        assert "assertion_not_bound_to_digest" in res.reasons
        # The record itself is intact; `valid` means the decision record and
        # its chain link, and an assertion about something else says nothing
        # about either.
        assert res.valid is True
    finally:
        await tzun.close()


@pytest.mark.asyncio
async def test_verify_does_not_claim_a_bound_assertion_is_verified() -> None:
    """No credential store here, so the signature is unchecked — None, not True."""
    from tzun_sdk._generated.models import WebauthnAssertion

    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        r = await tzun.capture(ai_output={"r": "approve"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        row = stored_row(tzun, r.evidenceId)
        row.nonRepudiation.webauthnAssertion = WebauthnAssertion(
            **_bound_assertion(row.integrity.canonicalDigest)
        )

        res = await tzun.verify(r.evidenceId)
        assert res.attestationVerified is None
        assert "assertion_not_bound_to_digest" not in res.reasons
        assert res.valid is True
    finally:
        await tzun.close()


@pytest.mark.asyncio
async def test_verify_leaves_an_unattested_record_alone() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        r = await tzun.capture(ai_output={"r": "approve"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        res = await tzun.verify(r.evidenceId)
        assert res.attestationVerified is None
        assert res.reasons == []
    finally:
        await tzun.close()
