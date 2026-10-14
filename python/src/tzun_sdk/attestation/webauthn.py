"""WebAuthn at-rest verification backend.

Python is a relying-party server context. Browser-side signing ceremonies
are explicitly NOT supported — any attempt raises with a clear
message. Verification failure chains the underlying ``py-webauthn``
exception via ``raise ... from e``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from collections.abc import Sequence
from typing import Any

from tzun_sdk.errors import TzunError, WebAuthnVerificationError
from tzun_sdk.models import (
    AssertionProvenance,
    AttestationArtifacts,
    AuthenticatorFlags,
    EvidenceEnvelope,
)

LOG = logging.getLogger(__name__)

#: Domain separator for the decision-binding challenge. Part of the wire
#: contract: the TypeScript SDK's ``webauthnChallengeForDigest`` uses the same
#: literal, and a change on one side silently invalidates every assertion the
#: other side produced.
_CHALLENGE_DOMAIN = "tzun-decision-v1"


def webauthn_challenge_for_digest(digest: str) -> str:
    """Derive the WebAuthn challenge that binds an assertion to an evidence digest.

    ``base64url(SHA-256("tzun-decision-v1" || digest))``, unpadded — the exact
    twin of ``webauthnChallengeForDigest`` in
    ``src/attestation/verify-attestation.ts``. ``tests/cross-sdk/
    test_webauthn_challenge_parity.py`` pins the two together.

    The point of a WebAuthn signature on a decision record is that the reviewer
    signed THAT decision, and that only holds if the challenge is a function of
    the decision. A random login nonce produces a signature that verifies
    against every record equally, which is the same as verifying against none.

    Pass the result as ``expected_challenge`` to
    :meth:`WebAuthnBackend.verify_assertion` — encoded as bytes, which is what
    ``py_webauthn`` compares against ``clientDataJSON.challenge``:

    .. code-block:: python

        challenge = webauthn_challenge_for_digest(envelope.integrity.canonicalDigest)
        backend.verify_assertion(
            blob, public_key,
            expected_challenge=base64.urlsafe_b64decode(challenge + "=="),
            ...
        )

    Python is a relying-party server and cannot run the ceremony, so
    this is the verifier half only; the TypeScript SDK drives the ceremony via
    ``Tzun.prepareAssertionChallenge()`` → ``startAuthentication(id, {digest})``.
    """
    if not digest:
        raise ValueError(
            "webauthn_challenge_for_digest requires the record's canonicalDigest; "
            "an empty digest would bind every record to the same challenge."
        )
    raw = hashlib.sha256((_CHALLENGE_DOMAIN + digest).encode("utf-8")).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def assertion_binds_digest(assertion: Any, digest: str) -> bool:
    """Does this assertion's ceremony actually cover ``digest``?

    The twin of ``assertionBindsDigest`` in
    ``packages/engine/src/webauthn-binding.ts``. The one question about a
    WebAuthn artifact that needs no key material, no credential store and no
    network: ``clientDataJSON`` states, inside the bytes the authenticator
    signed over, which challenge was presented, and the challenge is a pure
    function of the digest. So a Python relying party holding no keys can still
    say "this assertion is not about this record".

    ``assertion`` is a ``WebauthnAssertion`` model or any object/mapping with a
    ``clientDataJSON`` attribute or key. An assertion with no
    ``clientDataJSON`` binds nothing by construction and returns ``False``:
    there is no signed statement of what was signed.

    NOT a signature check — that needs the registered public key and is
    :meth:`WebAuthnBackend.verify_assertion`'s job.
    """
    client_data = _client_data(_assertion_field(assertion, "clientDataJSON"))
    if not client_data:
        return False
    if client_data.get("type") != "webauthn.get":
        return False
    challenge = client_data.get("challenge")
    if not isinstance(challenge, str):
        return False
    return _challenge_matches(challenge, webauthn_challenge_for_digest(digest))


def assertion_presents_challenge(assertion: Any, challenge: str) -> bool:
    """Whether the assertion's ``clientDataJSON`` is a ``webauthn.get`` that presented ``challenge``.

    Read from the signed client data alone, as :func:`assertion_binds_digest`
    reads it: no key is needed and no signature is checked. ``False`` for an
    assertion with no readable ``clientDataJSON``. Never raises.
    """
    client_data = _client_data(_assertion_field(assertion, "clientDataJSON"))
    if not client_data or client_data.get("type") != "webauthn.get":
        return False
    presented = client_data.get("challenge")
    return isinstance(presented, str) and _challenge_matches(presented, challenge)


def _challenge_matches(actual: str, expected: str) -> bool:
    """Padding- and alphabet-insensitive comparison, as the TS twin does.

    Browsers emit the ``clientDataJSON`` challenge as unpadded base64url, while
    a challenge that made a round trip through a padded base64 encoder keeps
    its ``=``.
    """
    def norm(v: str) -> str:
        return v.replace("+", "-").replace("/", "_").rstrip("=")

    return actual == expected or norm(actual) == norm(expected)


_BASE64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_"
)
_URL_SAFE_TO_STANDARD = str.maketrans("-_", "+/")


def _decode_base64(value: str) -> bytes:
    """Decode base64 exactly as Node's ``Buffer.from(value, 'base64')`` does.

    The TypeScript verifier decodes with Node, so this is what keeps the two
    reading the same bytes out of the same artifact. Node accepts both the
    standard and the url-safe alphabet, needs no padding, stops at the first
    ``=``, skips every other character outside the alphabet, and drops a lone
    trailing character that carries no whole byte. A browser hands
    ``clientDataJSON`` back as unpadded base64url, which ``base64.b64decode``
    refuses for its padding three times in four.
    """
    head = value.split("=", 1)[0]
    chars = "".join(c for c in head if c in _BASE64_ALPHABET).translate(_URL_SAFE_TO_STANDARD)
    if len(chars) % 4 == 1:
        chars = chars[:-1]
    return base64.b64decode(chars + "=" * (-len(chars) % 4))


def _assertion_field(assertion: Any, name: str) -> Any:
    """``name`` off a ``WebauthnAssertion`` model or a mapping; ``None`` otherwise."""
    if isinstance(assertion, dict):
        return assertion.get(name)
    if assertion is None or isinstance(assertion, (str, bytes, int, float, list, tuple)):
        return None
    return getattr(assertion, name, None)


def _refuse_json_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _client_data(raw: Any) -> dict[str, Any]:
    """The decoded ``clientDataJSON`` object, or ``{}`` when there is none to read.

    Read the way the TypeScript verifier's ``JSON.parse(Buffer.from(raw,
    'base64').toString('utf8'))`` reads it, so both SDKs answer alike about
    one assertion: an invalid UTF-8 sequence becomes U+FFFD, as Node writes it;
    ``NaN``, ``Infinity`` and ``-Infinity`` are refused, as ``JSON.parse``
    refuses them; and a number is read as a double, so an integer past
    Python's digit limit for ``int()`` does not fail the whole parse.
    """
    if not isinstance(raw, str) or not raw:
        return {}
    try:
        parsed = json.loads(
            _decode_base64(raw).decode("utf-8", errors="replace"),
            parse_constant=_refuse_json_constant,
            parse_int=float,
        )
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


#: Any surrogate code point. ``json.loads`` joins an escaped pair into one code
#: point, so each one left in a decoded string is lone.
_SURROGATE = re.compile("[\ud800-\udfff]")


def _well_formed_string(value: Any) -> str | None:
    """A string field with each lone surrogate replaced by U+FFFD; ``None`` for any other type.

    The TypeScript twin replaces them the same way. A lone surrogate survives
    ``json.loads``, and pydantic's ``model_dump_json`` cannot write one.
    """
    return _SURROGATE.sub("\ufffd", value) if isinstance(value, str) else None


def refuse_bare_string_allowlist(name: str, value: Any) -> None:
    """Raise ``TypeError`` for an origin allowlist passed as a bare ``str`` or bytes.

    ``str`` satisfies ``Sequence[str]``, so a type checker lets one through,
    and ``origin in "https://panel.example"`` is then a substring test that
    passes a truncated origin.
    """
    if isinstance(value, (str, bytes, bytearray)):
        raise TypeError(
            f"{name} must be a list or tuple of origins, not a bare {type(value).__name__}"
        )


#: ``authenticatorData`` is a 32-byte rpIdHash, a flags byte and a 4-byte counter.
_AUTHENTICATOR_DATA_MIN_LENGTH = 37
_FLAGS_OFFSET = 32
_FLAG_UP = 0x01
_FLAG_UV = 0x04
_FLAG_BE = 0x08
_FLAG_BS = 0x10


def _authenticator_flags(raw: Any) -> AuthenticatorFlags | None:
    """The UP, UV, BE and BS bits (WebAuthn L3 §6.1), or ``None`` with no flags byte."""
    if not isinstance(raw, str):
        return None
    try:
        data = _decode_base64(raw)
    except Exception:
        return None
    if len(data) < _AUTHENTICATOR_DATA_MIN_LENGTH:
        return None
    byte = data[_FLAGS_OFFSET]
    return AuthenticatorFlags(
        UP=bool(byte & _FLAG_UP),
        UV=bool(byte & _FLAG_UV),
        BE=bool(byte & _FLAG_BE),
        BS=bool(byte & _FLAG_BS),
    )


def assertion_provenance(
    assertion: Any,
    *,
    allowed_origins: Sequence[str] | None = None,
    allowed_top_origins: Sequence[str] | None = None,
    require_device_bound: bool = False,
    signature_verified: bool = False,
) -> AssertionProvenance:
    """Where the ceremony ran and what kind of key signed, and the checks asked for.

    The twin of ``assertionProvenance`` in
    ``packages/engine/src/assertion-provenance.ts``, pinned to
    it by ``tests/cross-sdk/test_assertion_provenance_parity.py``.

    Records ``origin``, ``crossOrigin`` and ``topOrigin`` from
    ``clientDataJSON`` and the UP, UV, BE and BS flags from
    ``authenticatorData``, each ``None`` when the assertion does not state it
    or states it in the wrong type. Then checks, each only when asked:

    * ``allowed_origins`` → ``originValid`` (``origin_mismatch``);
    * ``allowed_top_origins`` → ``topOriginValid``, against the ceremony's
      top-level origin: ``topOrigin`` for a cross-origin ceremony, and its own
      ``origin`` for one that says it was not cross-origin (it ran directly in
      a tab). Off the list is ``top_origin_not_allowed``; a cross-origin
      ceremony that names no framer is ``top_origin_unknown``;
    * ``require_device_bound`` → ``deviceBound``: a synced
      (``credential_synced``) or backup-eligible
      (``credential_backup_eligible``) credential is a lower rung, never a
      failed signature. ``BS`` clear on a backup-eligible credential means
      "not backed up now", not device-bound.

    A requirement the assertion meets is ``True`` only when
    ``signature_verified`` says a verified signature over this record covers
    the bytes — :meth:`WebAuthnBackend.verify_assertion` returned for it —
    and ``None`` with ``no_verified_signature`` otherwise. A requirement it
    fails is ``False`` either way. An unchecked requirement is ``None`` with a
    reason saying it was not checked.

    ``assertion`` is a ``WebauthnAssertion`` model or a mapping. Nothing in it
    raises: the artifact is JSON a client supplied. A lone surrogate in
    ``origin`` or ``topOrigin`` is recorded as U+FFFD. ``allowed_origins`` or
    ``allowed_top_origins`` passed as a bare ``str`` or bytes raises
    ``TypeError``: membership in a string is a substring test.
    """
    refuse_bare_string_allowlist("allowed_origins", allowed_origins)
    refuse_bare_string_allowlist("allowed_top_origins", allowed_top_origins)
    client_data = _client_data(_assertion_field(assertion, "clientDataJSON"))
    origin = _well_formed_string(client_data.get("origin"))
    cross_origin = client_data.get("crossOrigin")
    cross_origin = cross_origin if isinstance(cross_origin, bool) else None
    top_origin = _well_formed_string(client_data.get("topOrigin"))
    flags = _authenticator_flags(_assertion_field(assertion, "authenticatorData"))

    def met(unverified: str) -> tuple[bool | None, str | None]:
        return (True, None) if signature_verified else (None, unverified)

    if allowed_origins is None:
        origin_check: tuple[bool | None, str | None] = (None, "origin_not_checked")
    elif origin is None or origin not in allowed_origins:
        origin_check = (False, "origin_mismatch")
    else:
        origin_check = met("no_verified_signature")

    # The top-level page the ceremony ran under: a browser names it in
    # topOrigin only for a ceremony that is not same-origin with its
    # ancestors, so one that says it was not cross-origin is its own top.
    top = top_origin if top_origin is not None else (origin if cross_origin is False else None)
    if allowed_top_origins is None:
        top_check: tuple[bool | None, str | None] = (None, "top_origin_not_checked")
    elif top is None:
        top_check = (False, "top_origin_unknown")
    elif top in allowed_top_origins:
        top_check = met("no_verified_signature")
    else:
        top_check = (False, "top_origin_not_allowed")

    if not require_device_bound:
        device_check: tuple[bool | None, str | None] = (None, "device_bound_not_required")
    elif flags is None:
        device_check = (False, "flags_unreadable")
    elif not flags.BE:
        device_check = (False, "invalid_backup_flags") if flags.BS else met("no_verified_signature")
    else:
        device_check = (False, "credential_synced" if flags.BS else "credential_backup_eligible")

    fields: dict[str, Any] = {
        "origin": origin,
        "crossOrigin": cross_origin,
        "topOrigin": top_origin,
        "flags": flags,
        "originValid": origin_check[0],
        "topOriginValid": top_check[0],
        "deviceBound": device_check[0],
    }
    # A reason is present only when its check did not pass, as on the TS
    # verdict, so ``model_dump(exclude_unset=True)`` is the TS JSON.
    for key, check in (
        ("originReason", origin_check),
        ("topOriginReason", top_check),
        ("deviceBoundReason", device_check),
    ):
        if check[1] is not None:
            fields[key] = check[1]
    return AssertionProvenance(**fields)


class WebAuthnBackend:
    """At-rest WebAuthn assertion verification."""

    def __init__(self) -> None:
        # The 'webauthn' package is in required deps; no extras
        # gate. Verification uses webauthn.verify_authentication_response.
        pass

    async def attest(
        self, envelope: EvidenceEnvelope
    ) -> AttestationArtifacts | None:
        """No-op for at-rest only: WebAuthn signing requires a browser."""
        return None

    def sign(self, *_args: Any, **_kwargs: Any) -> None:
        """Raise: Python is the relying-party server only."""
        raise TzunError(
            "WebAuthn signing ceremonies require a browser; "
            "Python is the relying-party server only."
        )

    #: Keys a caller must never be able to smuggle through the artifact.
    #: These are relying-party assertions; if the blob under verification
    #: supplies them, verification proves nothing.
    _EXPECTATION_KEYS = (
        "expected_challenge",
        "expected_origin",
        "expected_rp_id",
    )

    def verify_assertion(
        self,
        assertion_blob: dict[str, Any],
        public_key: bytes,
        *,
        expected_challenge: bytes,
        expected_origin: str | list[str],
        expected_rp_id: str,
        current_sign_count: int,
        require_user_verification: bool = False,
    ) -> Any:
        """Verify a recorded WebAuthn assertion at rest.

        The ``expected_*`` values are *relying-party* assertions and MUST
        come from the caller, never from the artifact under verification.
        ``expected_challenge`` in particular is what binds the assertion to
        one specific evidence record: derive it from that record's
        ``integrity.canonicalDigest``. Passing a challenge lifted from the
        assertion itself reduces the check to "this key signed something,
        once", which any replayed assertion satisfies.

        ``current_sign_count`` is the last signature counter the caller
        recorded for this credential; py_webauthn uses it for authenticator
        clone detection. Zero disables that detection, so it has no default.

        Returns the ``VerifiedAuthentication`` object — the caller needs its
        ``new_sign_count`` to persist for the next verification. Failures
        chain the underlying exception via ``raise ... from e``.
        """
        try:
            import webauthn
        except ImportError as exc:  # pragma: no cover - webauthn is required dep
            raise WebAuthnVerificationError(
                "WebAuthn library not importable"
            ) from exc

        # An artifact carrying its own expectations is the attack this
        # signature exists to stop; refuse it loudly rather than ignore it.
        smuggled = [k for k in self._EXPECTATION_KEYS if k in assertion_blob]
        if smuggled:
            raise WebAuthnVerificationError(
                "Assertion artifact carries relying-party expectations "
                f"({', '.join(smuggled)}); these MUST come from the caller."
            )
        # Empty expectations silently neuter the corresponding check inside
        # py_webauthn, so a default of `b""` would make every assertion verify.
        if not expected_challenge:
            raise WebAuthnVerificationError(
                "expected_challenge is required and must be non-empty; "
                "derive it from the evidence record's canonicalDigest."
            )
        if not expected_rp_id:
            raise WebAuthnVerificationError("expected_rp_id is required.")
        if not expected_origin:
            raise WebAuthnVerificationError("expected_origin is required.")

        try:
            return webauthn.verify_authentication_response(
                credential=assertion_blob,
                expected_challenge=expected_challenge,
                expected_origin=expected_origin,
                expected_rp_id=expected_rp_id,
                credential_public_key=public_key,
                credential_current_sign_count=current_sign_count,
                require_user_verification=require_user_verification,
            )
        except Exception as exc:
            raise WebAuthnVerificationError(
                "WebAuthn assertion verification failed"
            ) from exc


__all__ = (
    "WebAuthnBackend",
    "assertion_binds_digest",
    "assertion_provenance",
    "webauthn_challenge_for_digest",
)
