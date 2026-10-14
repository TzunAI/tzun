"""Cross-SDK parity for what a WebAuthn assertion states.

Both SDKs read ``origin``, ``crossOrigin`` and ``topOrigin`` out of
``clientDataJSON`` and the UP, UV, BE and BS flags out of
``authenticatorData``, and check them against the same requirements. If the
two read different bytes out of one artifact, they answer differently about
one record: an unpadded base64url ``clientDataJSON`` that one SDK decodes and
the other refuses reads as bound in one and unbound in the other. So the corpus
runs the binding check too, and every case goes through both implementations.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest
from tzun_sdk.attestation import (
    assertion_binds_digest,
    assertion_provenance,
    webauthn_challenge_for_digest,
)

UP, UV, BE, BS = 0x01, 0x04, 0x08, 0x10
PANEL = "https://panel.example"
LOCAL_PANEL = "http://localhost:17893"
EXTENSION = "chrome-extension://cjdhdebnabcamkngfcpipeapbpgdfjlg"
DIGEST = hashlib.sha256(b"pr-4471-head-4f1c0a9e").hexdigest()
CHALLENGE = webauthn_challenge_for_digest(DIGEST)


def b64(raw: bytes, *, url_safe: bool = False) -> str:
    if url_safe:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return base64.b64encode(raw).decode()


def client_data(fields: Any, *, url_safe: bool = True) -> str:
    return b64(json.dumps(fields, separators=(",", ":")).encode(), url_safe=url_safe)


def auth_data(flags: int, length: int = 37, rp_id: bytes = b"tzun.ai") -> str:
    raw = hashlib.sha256(rp_id).digest() + bytes([flags]) + b"\x00\x00\x00\x07"
    return b64((raw + b"\x00" * length)[:length], url_safe=True)


def assertion(client: str | None, auth: str | None) -> dict[str, Any]:
    out: dict[str, Any] = {"signature": "c2ln", "credentialKeyId": "cred", "algorithm": "ES256"}
    if client is not None:
        out["clientDataJSON"] = client
    if auth is not None:
        out["authenticatorData"] = auth
    return out


def get(fields: dict[str, Any]) -> dict[str, Any]:
    return {"type": "webauthn.get", "challenge": CHALLENGE, **fields}


# Every shape of clientDataJSON the checks branch on, and the encodings a
# browser, a padded round trip and a hand-edited artifact produce.
CLIENT_DATA = [
    client_data(get({"origin": LOCAL_PANEL, "crossOrigin": True, "topOrigin": EXTENSION})),
    client_data(get({"origin": PANEL, "crossOrigin": True, "topOrigin": EXTENSION}), url_safe=False),
    client_data(get({"origin": PANEL + "i", "crossOrigin": True, "topOrigin": EXTENSION})),
    client_data(get({"origin": PANEL + "ii", "crossOrigin": False})),
    client_data(get({"origin": PANEL, "crossOrigin": True, "topOrigin": "https://evil.example"})),
    client_data(get({"origin": PANEL, "crossOrigin": True})),
    client_data(get({"origin": PANEL})),
    client_data(get({"origin": 42, "crossOrigin": "true", "topOrigin": ["x"]})),
    client_data({"type": "webauthn.create", "challenge": CHALLENGE, "origin": PANEL}),
    client_data(get({"origin": PANEL}))[:10] + " \n" + client_data(get({"origin": PANEL}))[10:],
    client_data(get({"origin": PANEL})) + "==garbage",
    client_data([]),
    b64(b"null"),
    b64(b"not json"),
    "",
    None,
    # Where Python's json.loads and bytes.decode differ from Node's
    # JSON.parse and Buffer#toString unless told to read as Node does.
    b64(b'{"type":"webauthn.get","origin":"https://panel.example\xff\xed\xa0\x80","crossOrigin":false}'),
    b64(f'{{"type":"webauthn.get","origin":"{PANEL}","crossOrigin":true,"n":NaN}}'.encode()),
    b64(f'{{"type":"webauthn.get","origin":"{PANEL}","n":-Infinity}}'.encode()),
    b64(f'{{"type":"webauthn.get","origin":"{PANEL}","n":{"9" * 5000}}}'.encode()),
    b64(
        b'{"type":"webauthn.get","origin":"https://panel.example\\ud800","crossOrigin":true,'
        b'"topOrigin":"\\udc00chrome-extension://x\\ud83d\\ude00"}'
    ),
    b64(b'{"type":"webauthn.get","origin":"\\ud83d","crossOrigin":false}'),
    client_data(get({"crossOrigin": False})),
]

AUTH_DATA = [
    auth_data(UP | UV | BE | BS),
    auth_data(UP | UV),
    auth_data(UP | BE),
    auth_data(UP | BS),
    auth_data(0x02 | 0x20 | 0x40 | 0x80),
    auth_data(0xFF),
    auth_data(UP, length=36),
    auth_data(UP | UV, length=64),
    None,
]

OPTIONS: list[dict[str, Any]] = [
    {},
    {"signatureVerified": True},
    {"allowedOrigins": [PANEL, LOCAL_PANEL]},
    {"allowedOrigins": [PANEL, LOCAL_PANEL], "signatureVerified": True},
    {"allowedTopOrigins": [EXTENSION]},
    {"allowedTopOrigins": [EXTENSION], "signatureVerified": True},
    # A top-level ceremony (crossOrigin: false) is its own top-level page.
    {"allowedTopOrigins": [EXTENSION, PANEL + "ii"], "signatureVerified": True},
    {"requireDeviceBound": True},
    {"requireDeviceBound": True, "signatureVerified": True},
    {
        "allowedOrigins": [PANEL],
        "allowedTopOrigins": [EXTENSION],
        "requireDeviceBound": True,
        "signatureVerified": True,
    },
]


def python_kwargs(options: dict[str, Any]) -> dict[str, Any]:
    names = {
        "allowedOrigins": "allowed_origins",
        "allowedTopOrigins": "allowed_top_origins",
        "requireDeviceBound": "require_device_bound",
        "signatureVerified": "signature_verified",
    }
    return {names[k]: v for k, v in options.items()}


def run_both(ts_invoke, cases: list[dict[str, Any]]) -> None:  # type: ignore[no-untyped-def]
    ts = ts_invoke({"action": "assertion-provenance", "cases": cases})["results"]
    assert len(ts) == len(cases)
    mismatches = []
    for case, ts_result in zip(cases, ts):
        py_provenance = assertion_provenance(
            case["assertion"], **python_kwargs(case.get("options", {}))
        ).model_dump(mode="json", exclude_unset=True)
        py_binds = (
            assertion_binds_digest(case["assertion"], case["digest"]) if "digest" in case else None
        )
        if ts_result["provenance"] != py_provenance or ts_result["binds"] != py_binds:
            mismatches.append(
                f"{json.dumps(case)}\n  TS: {json.dumps(ts_result)}\n"
                f"  Py: {json.dumps({'provenance': py_provenance, 'binds': py_binds})}"
            )
    assert not mismatches, "assertion provenance diverged between the SDKs:\n" + "\n".join(mismatches)


def test_every_statement_reads_the_same_in_both_sdks(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    cases = [
        {"assertion": assertion(c, a), "digest": DIGEST}
        for c in CLIENT_DATA
        for a in AUTH_DATA
    ]
    run_both(ts_invoke, cases)


def test_every_check_answers_the_same_in_both_sdks(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    cases = [
        {"assertion": assertion(c, a), "options": o}
        for c in CLIENT_DATA
        for a in AUTH_DATA[:6]
        for o in OPTIONS
    ]
    run_both(ts_invoke, cases)


def test_the_recorded_code_review_run_reads_as_recorded(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    """A code-review sign-off run of 2026-09-21, reconstructed from the fields its
    report recorded.

    Not the captured bytes: the report records the parsed ``clientDataJSON`` members
    and the four flags, so this re-serializes those members and synthesizes
    ``authenticatorData`` for the run's RP ID, ``localhost``. There is no
    signature. What it pins is how both SDKs read those fields.
    """
    dana = assertion(
        client_data(
            {
                "type": "webauthn.get",
                "challenge": "z6vWQ94pDixn-eZz7Ycgx8QKsSwjIncqUyTpmdSiDBw",
                "origin": LOCAL_PANEL,
                "crossOrigin": True,
                "topOrigin": "chrome-extension://cjdhdebnabcamkngfcpipeapbpgdfjlg",
            }
        ),
        auth_data(UP | UV | BE | BS, rp_id=b"localhost"),
    )
    options = {"allowedTopOrigins": [EXTENSION], "requireDeviceBound": True, "signatureVerified": True}
    ts = ts_invoke(
        {"action": "assertion-provenance", "cases": [{"assertion": dana, "options": options}]}
    )["results"][0]["provenance"]
    assert ts == {
        "origin": LOCAL_PANEL,
        "crossOrigin": True,
        "topOrigin": EXTENSION,
        "flags": {"UP": True, "UV": True, "BE": True, "BS": True},
        "originValid": None,
        "originReason": "origin_not_checked",
        "topOriginValid": True,
        "deviceBound": False,
        "deviceBoundReason": "credential_synced",
    }
    run_both(ts_invoke, [{"assertion": dana, "options": options}])


def test_non_object_assertions_read_as_nothing_in_both_sdks(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    run_both(ts_invoke, [{"assertion": bad} for bad in (None, 7, "x", [])])


def test_a_bare_string_allowlist_never_matches_by_substring_in_either_sdk(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    """A caller that passes one origin as a bare string, not a list of one.

    TypeScript's types refuse it, and at run time a non-array reads as "not
    checked". Python's ``Sequence[str]`` lets a ``str`` through its types, so
    it refuses one at run time. Neither answers from ``"https://panel.exam" in
    "https://panel.example"``, which is true.
    """
    truncated = assertion(
        client_data(get({"origin": "https://panel.exam", "crossOrigin": True, "topOrigin": "chrome-extension://abc"})),
        auth_data(UP | UV),
    )
    bare = {"allowedOrigins": PANEL, "allowedTopOrigins": "chrome-extension://abcdef", "signatureVerified": True}
    ts = ts_invoke(
        {"action": "assertion-provenance", "cases": [{"assertion": truncated, "options": bare}]}
    )["results"][0]["provenance"]
    assert (ts["originValid"], ts["originReason"]) == (None, "origin_not_checked")
    assert (ts["topOriginValid"], ts["topOriginReason"]) == (None, "top_origin_not_checked")
    for name in ("allowedOrigins", "allowedTopOrigins"):
        with pytest.raises(TypeError):
            assertion_provenance(truncated, **python_kwargs({name: bare[name]}))
