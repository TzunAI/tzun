"""``verify()`` and ``export_evidence()`` record the assertion's provenance.

The TypeScript SDK's ``verify()`` result and export bundle carry
``assertionProvenance``: where the ceremony ran and what kind of key signed.
Python's ``verify()`` reads the same assertion for the binding check, so it
records the same fields, and its export bundle carries the same block, or the
two SDKs' evidence would say different things about one record.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from tests.verify.test_verify import stored_row
from tzun_sdk import Tzun
from tzun_sdk._generated.models import WebauthnAssertion
from tzun_sdk.attestation import webauthn_challenge_for_digest
from tzun_sdk.storage import MemoryAdapter

PANEL = "https://panel.example"
EXTENSION = "chrome-extension://cjdhdebnabcamkngfcpipeapbpgdfjlg"
SYNCED = 0x01 | 0x04 | 0x08 | 0x10


def side_panel_assertion(digest: str, flags: int = SYNCED) -> WebauthnAssertion:
    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": webauthn_challenge_for_digest(digest),
            "origin": PANEL,
            "crossOrigin": True,
            "topOrigin": EXTENSION,
        },
        separators=(",", ":"),
    ).encode()
    auth = hashlib.sha256(b"tzun.ai").digest() + bytes([flags]) + b"\x00\x00\x00\x07"
    return WebauthnAssertion(
        signature="sig",
        credentialKeyId="cred-jane",
        algorithm="ES256",
        authenticatorData=base64.b64encode(auth).decode(),
        clientDataJSON=base64.urlsafe_b64encode(client_data).decode().rstrip("="),
    )


async def signed_record(tzun: Tzun) -> str:
    r = await tzun.capture(ai_output={"pr": 4471}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok")
    row = stored_row(tzun, r.evidenceId)
    row.nonRepudiation.webauthnAssertion = side_panel_assertion(row.integrity.canonicalDigest)
    return r.evidenceId


@pytest.mark.asyncio
async def test_verify_records_where_the_reviewer_signed() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        evidence_id = await signed_record(tzun)
        res = await tzun.verify(evidence_id)
        assert res.attestationVerified is None
        assert res.assertionProvenance is not None
        p = res.assertionProvenance
        assert (p.origin, p.crossOrigin, p.topOrigin) == (PANEL, True, EXTENSION)
        assert p.flags is not None and (p.flags.BE, p.flags.BS) == (True, True)
        assert (p.originValid, p.originReason) == (None, "origin_not_checked")
    finally:
        await tzun.close()


@pytest.mark.asyncio
async def test_verify_runs_the_checks_it_is_given_and_vouches_for_none() -> None:
    """Python holds no credential store, so a met requirement is never True."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        evidence_id = await signed_record(tzun)
        res = await tzun.verify(
            evidence_id,
            allowed_origins=[PANEL],
            allowed_top_origins=[EXTENSION],
            require_device_bound=True,
        )
        p = res.assertionProvenance
        assert p is not None
        assert (p.originValid, p.originReason) == (None, "no_verified_signature")
        assert (p.topOriginValid, p.topOriginReason) == (None, "no_verified_signature")
        assert (p.deviceBound, p.deviceBoundReason) == (False, "credential_synced")
        # A synced key is a lower rung: the record is intact.
        assert res.valid is True
    finally:
        await tzun.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("kwarg", ["allowed_origins", "allowed_top_origins"])
async def test_verify_refuses_a_bare_string_allowlist_even_for_an_unsigned_record(kwarg: str) -> None:
    """A bare string would be matched by substring; an unsigned record would hide the mistake."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        r = await tzun.capture(ai_output={"r": 1}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        with pytest.raises(TypeError, match=kwarg):
            await tzun.verify(r.evidenceId, **{kwarg: PANEL})  # type: ignore[arg-type]
    finally:
        await tzun.close()


@pytest.mark.asyncio
async def test_verify_records_nothing_for_an_unsigned_record() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        r = await tzun.capture(ai_output={"r": 1}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        assert (await tzun.verify(r.evidenceId)).assertionProvenance is None
    finally:
        await tzun.close()


@pytest.mark.asyncio
async def test_export_records_the_provenance_in_the_bundle() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        evidence_id = await signed_record(tzun)
        bundle = await tzun.export_evidence(evidence_id)
        assert bundle.assertionProvenance is not None
        assert bundle.assertionProvenance.topOrigin == EXTENSION
        assert bundle.assertionProvenance.flags is not None
        assert bundle.assertionProvenance.flags.BE is True

        r = await tzun.capture(ai_output={"r": 2}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        unsigned = await tzun.export_evidence(r.evidenceId)
        assert unsigned.assertionProvenance is None
    finally:
        await tzun.close()


def test_the_sync_client_passes_the_checks_through() -> None:
    from tzun_sdk import TzunSync

    tzun = TzunSync.init(storage=MemoryAdapter())
    try:
        r = tzun.capture(ai_output={"pr": 4471}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok")
        row = stored_row(tzun._inner, r.evidenceId)
        row.nonRepudiation.webauthnAssertion = side_panel_assertion(row.integrity.canonicalDigest)
        res = tzun.verify(r.evidenceId, require_device_bound=True)
        assert res.assertionProvenance is not None
        assert res.assertionProvenance.deviceBoundReason == "credential_synced"
    finally:
        tzun.close()
