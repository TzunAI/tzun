"""Where the human signed, and with what kind of key — Python side.

The twin of ``assertionProvenance`` in
``packages/engine/src/assertion-provenance.ts``; the two are pinned together
by ``tests/cross-sdk/test_assertion_provenance_parity.py``. These tests pin the
Python behaviour on its own, so a joint drift cannot hide.

The first fixture is reconstructed from the fields recorded for a run through
the Tzun-origin iframe inside the extension side panel: a cross-origin
ceremony framed by a ``chrome-extension://`` page, signed by an iCloud
Keychain passkey with UP, UV, BE and BS all set. The record keeps the parsed
``clientDataJSON`` members and the flags, not the bytes, so
``clientDataJSON`` is those members re-serialized and ``authenticatorData`` is
synthesized for the run's RP ID, ``localhost``. There is no signature.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from tzun_sdk._generated.models import AssertionProvenance, WebauthnAssertion
from tzun_sdk.attestation import assertion_provenance

UP, UV, BE, BS = 0x01, 0x04, 0x08, 0x10
PANEL_ORIGIN = "http://localhost:17893"
EXTENSION = "chrome-extension://cjdhdebnabcamkngfcpipeapbpgdfjlg"


def auth_data(flags: int) -> str:
    raw = hashlib.sha256(b"localhost").digest() + bytes([flags]) + b"\x00\x00\x00\x07"
    return base64.b64encode(raw).decode()


def client_data(fields: object, *, url_safe: bool = False) -> str:
    raw = json.dumps(fields, separators=(",", ":")).encode()
    if url_safe:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return base64.b64encode(raw).decode()


def assertion(**fields: object) -> WebauthnAssertion:
    return WebauthnAssertion(
        signature="c2lnbmF0dXJl", credentialKeyId="cred-1", algorithm="ES256", **fields  # type: ignore[arg-type]
    )


SIDE_PANEL_RUN = assertion(
    clientDataJSON=client_data(
        {
            "type": "webauthn.get",
            "challenge": "z6vWQ94pDixn-eZz7Ycgx8QKsSwjIncqUyTpmdSiDBw",
            "origin": PANEL_ORIGIN,
            "crossOrigin": True,
            "topOrigin": EXTENSION,
        },
        url_safe=True,
    ),
    authenticatorData=auth_data(UP | UV | BE | BS),
)

SECURITY_KEY_RUN = assertion(
    clientDataJSON=client_data(
        {"type": "webauthn.get", "challenge": "abc", "origin": PANEL_ORIGIN, "crossOrigin": False}
    ),
    authenticatorData=auth_data(UP | UV),
)


# ── what the assertion states ────────────────────────────────────────────────


def test_records_the_side_panel_run() -> None:
    p = assertion_provenance(SIDE_PANEL_RUN)
    assert isinstance(p, AssertionProvenance)
    assert p.origin == PANEL_ORIGIN
    assert p.crossOrigin is True
    assert p.topOrigin == EXTENSION
    assert p.flags is not None
    assert (p.flags.UP, p.flags.UV, p.flags.BE, p.flags.BS) == (True, True, True, True)


@pytest.mark.parametrize(("name", "bit"), [("UP", UP), ("UV", UV), ("BE", BE), ("BS", BS)])
def test_each_flag_is_its_own_bit(name: str, bit: int) -> None:
    flags = assertion_provenance(assertion(authenticatorData=auth_data(bit))).flags
    assert flags is not None
    assert flags.model_dump() == {"UP": False, "UV": False, "BE": False, "BS": False, name: True}


def test_rfu_at_and_ed_bits_set_none_of_the_four() -> None:
    flags = assertion_provenance(assertion(authenticatorData=auth_data(0x02 | 0x20 | 0x40 | 0x80))).flags
    assert flags is not None
    assert flags.model_dump() == {"UP": False, "UV": False, "BE": False, "BS": False}


def test_unpadded_base64url_client_data_reads_as_a_browser_returns_it() -> None:
    """Three lengths in four leave an unpadded base64url string Python's decoder refuses."""
    for origin in ("https://panel.example", "https://panel1.example", "https://panel12.example"):
        fields = {"type": "webauthn.get", "challenge": "x", "origin": origin}
        p = assertion_provenance(assertion(clientDataJSON=client_data(fields, url_safe=True)))
        assert p.origin == origin


def test_short_or_absent_authenticator_data_has_no_flags() -> None:
    short = base64.b64encode(b"\xff" * 36).decode()
    assert assertion_provenance(assertion(authenticatorData=short)).flags is None
    assert assertion_provenance(assertion()).flags is None


def test_fields_of_the_wrong_type_are_recorded_as_none() -> None:
    p = assertion_provenance(
        assertion(
            clientDataJSON=client_data(
                {"type": "webauthn.get", "origin": 42, "crossOrigin": "true", "topOrigin": ["x"]}
            )
        )
    )
    assert (p.origin, p.crossOrigin, p.topOrigin) == (None, None, None)


@pytest.mark.parametrize(
    "bad",
    [None, 7, "x", [], {"clientDataJSON": 5, "authenticatorData": {}}, {"clientDataJSON": "bm90IGpzb24="}],
)
def test_never_raises_on_artifacts_json_never_promised_the_shape_of(bad: object) -> None:
    p = assertion_provenance(bad)
    assert p.origin is None
    assert p.flags is None


def test_mappings_are_accepted_as_well_as_models() -> None:
    raw = SIDE_PANEL_RUN.model_dump(exclude_none=True)
    assert assertion_provenance(raw) == assertion_provenance(SIDE_PANEL_RUN)


# ── the checks ───────────────────────────────────────────────────────────────


def test_nothing_is_checked_unless_asked() -> None:
    p = assertion_provenance(SIDE_PANEL_RUN, signature_verified=True)
    assert (p.originValid, p.originReason) == (None, "origin_not_checked")
    assert (p.topOriginValid, p.topOriginReason) == (None, "top_origin_not_checked")
    assert (p.deviceBound, p.deviceBoundReason) == (None, "device_bound_not_required")


def test_met_requirements_are_true_only_under_a_verified_signature() -> None:
    kwargs = {
        "allowed_origins": [PANEL_ORIGIN],
        "allowed_top_origins": [EXTENSION],
    }
    verified = assertion_provenance(SIDE_PANEL_RUN, signature_verified=True, **kwargs)  # type: ignore[arg-type]
    assert (verified.originValid, verified.originReason) == (True, None)
    assert (verified.topOriginValid, verified.topOriginReason) == (True, None)

    unverified = assertion_provenance(SIDE_PANEL_RUN, **kwargs)  # type: ignore[arg-type]
    assert (unverified.originValid, unverified.originReason) == (None, "no_verified_signature")
    assert (unverified.topOriginValid, unverified.topOriginReason) == (None, "no_verified_signature")


def test_an_origin_off_the_list_is_a_mismatch_signature_or_not() -> None:
    for verified in (True, False):
        p = assertion_provenance(
            SIDE_PANEL_RUN, allowed_origins=["https://panel.example"], signature_verified=verified
        )
        assert (p.originValid, p.originReason) == (False, "origin_mismatch")


def test_a_hostile_framer_is_not_allowed() -> None:
    framed = assertion(
        clientDataJSON=client_data(
            {
                "type": "webauthn.get",
                "origin": PANEL_ORIGIN,
                "crossOrigin": True,
                "topOrigin": "https://evil.example",
            }
        )
    )
    p = assertion_provenance(framed, allowed_top_origins=[EXTENSION], signature_verified=True)
    assert (p.topOriginValid, p.topOriginReason) == (False, "top_origin_not_allowed")


def test_a_framed_ceremony_naming_no_framer_is_unknown() -> None:
    framed = assertion(
        clientDataJSON=client_data({"type": "webauthn.get", "origin": PANEL_ORIGIN, "crossOrigin": True})
    )
    p = assertion_provenance(framed, allowed_top_origins=[EXTENSION], signature_verified=True)
    assert (p.topOriginValid, p.topOriginReason) == (False, "top_origin_unknown")


def test_a_top_level_ceremony_is_its_own_top_level_page() -> None:
    """``crossOrigin: false``: same-origin with every ancestor, so ``origin`` is the top."""
    for verified in (True, False):
        p = assertion_provenance(
            SECURITY_KEY_RUN, allowed_top_origins=[EXTENSION], signature_verified=verified
        )
        assert (p.topOriginValid, p.topOriginReason) == (False, "top_origin_not_allowed")
    listed = [EXTENSION, PANEL_ORIGIN]
    p = assertion_provenance(SECURITY_KEY_RUN, allowed_top_origins=listed, signature_verified=True)
    assert (p.topOriginValid, p.topOriginReason) == (True, None)
    p = assertion_provenance(SECURITY_KEY_RUN, allowed_top_origins=listed)
    assert (p.topOriginValid, p.topOriginReason) == (None, "no_verified_signature")


def test_a_top_level_ceremony_stating_no_origin_is_unknown() -> None:
    originless = assertion(clientDataJSON=client_data({"type": "webauthn.get", "crossOrigin": False}))
    p = assertion_provenance(originless, allowed_top_origins=[EXTENSION], signature_verified=True)
    assert (p.topOriginValid, p.topOriginReason) == (False, "top_origin_unknown")


@pytest.mark.parametrize("kwarg", ["allowed_origins", "allowed_top_origins"])
@pytest.mark.parametrize("bare", [PANEL_ORIGIN, PANEL_ORIGIN.encode(), bytearray(b"x")])
def test_a_bare_string_allowlist_is_refused_not_matched_by_substring(kwarg: str, bare: object) -> None:
    """``"x" in "...x..."`` is a substring test: a bare string would fail open."""
    with pytest.raises(TypeError, match=kwarg):
        assertion_provenance(SIDE_PANEL_RUN, **{kwarg: bare}, signature_verified=True)  # type: ignore[arg-type]


# ── reading clientDataJSON the way Node reads it ─────────────────────────────


def _raw_client_data(text: bytes) -> WebauthnAssertion:
    return assertion(clientDataJSON=base64.b64encode(text).decode())


def test_invalid_utf8_is_replaced_as_node_replaces_it() -> None:
    """Node's ``toString('utf8')`` writes U+FFFD for each maximal invalid subpart."""
    p = assertion_provenance(
        _raw_client_data(b'{"type":"webauthn.get","origin":"https://panel.example\xff\xed\xa0\x80"}')
    )
    assert p.origin == "https://panel.example" + "\ufffd" * 4


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_json_constants_are_refused_as_json_parse_refuses_them(constant: str) -> None:
    text = f'{{"type":"webauthn.get","origin":"{PANEL_ORIGIN}","n":{constant}}}'.encode()
    assert assertion_provenance(_raw_client_data(text)).origin is None


def test_an_integer_past_pythons_digit_limit_reads_as_json_parse_reads_it() -> None:
    """JSON.parse reads every number as a double; int() refuses past 4300 digits."""
    text = f'{{"type":"webauthn.get","origin":"{PANEL_ORIGIN}","n":{"9" * 5000}}}'.encode()
    assert assertion_provenance(_raw_client_data(text)).origin == PANEL_ORIGIN


def test_a_lone_surrogate_is_recorded_as_replacement_and_the_result_dumps() -> None:
    text = (
        b'{"type":"webauthn.get","origin":"https://panel.example\\ud800","crossOrigin":true,'
        b'"topOrigin":"\\udc00chrome-extension://x\\ud83d\\ude00"}'
    )
    p = assertion_provenance(_raw_client_data(text))
    assert p.origin == "https://panel.example\ufffd"
    assert p.topOrigin == "\ufffdchrome-extension://x\U0001f600"
    assert json.loads(p.model_dump_json())["origin"] == "https://panel.example\ufffd"


def test_a_device_bound_key_under_a_verified_signature() -> None:
    p = assertion_provenance(SECURITY_KEY_RUN, require_device_bound=True, signature_verified=True)
    assert (p.deviceBound, p.deviceBoundReason) == (True, None)
    unverified = assertion_provenance(SECURITY_KEY_RUN, require_device_bound=True)
    assert (unverified.deviceBound, unverified.deviceBoundReason) == (None, "no_verified_signature")


@pytest.mark.parametrize(
    ("flags", "reason"),
    [
        (UP | UV | BE | BS, "credential_synced"),
        (UP | BE, "credential_backup_eligible"),
        (UP | BS, "invalid_backup_flags"),
    ],
)
def test_a_key_that_is_not_device_bound_is_a_lower_rung(flags: int, reason: str) -> None:
    p = assertion_provenance(
        assertion(authenticatorData=auth_data(flags)), require_device_bound=True, signature_verified=True
    )
    assert (p.deviceBound, p.deviceBoundReason) == (False, reason)


def test_no_flags_under_a_device_bound_requirement() -> None:
    p = assertion_provenance(assertion(), require_device_bound=True, signature_verified=True)
    assert (p.deviceBound, p.deviceBoundReason) == (False, "flags_unreadable")


def test_the_dump_omits_a_reason_when_the_check_passed() -> None:
    """The TS verdict omits a reason key on a pass; the dump must match it."""
    p = assertion_provenance(SECURITY_KEY_RUN, require_device_bound=True, signature_verified=True)
    dumped = p.model_dump(exclude_unset=True)
    assert dumped["deviceBound"] is True
    assert "deviceBoundReason" not in dumped
    assert dumped["originValid"] is None
    assert dumped["originReason"] == "origin_not_checked"
