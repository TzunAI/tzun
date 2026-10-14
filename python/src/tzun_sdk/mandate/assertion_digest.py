"""The assertion digest (Record §9.6): one value per WebAuthn ceremony.

``assertionDigest = hex(SHA-256(UTF8("tzun-assertion-v1") ‖ SHA-256(authenticatorData)
‖ SHA-256(clientDataJSON) ‖ SHA-256(signature')))``

For ES256, ``signature'`` is the signature parsed as DER and re-encoded in
minimal DER with low S. A signature that is not DER is refused. For Ed25519
it is the signature as given. Each member is decoded from base64 or
base64url text, padded or not. The twin of
``packages/engine/src/mandate/assertion-digest.ts``.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

from tzun_sdk._record_rules import plain

#: The domain separator (17 bytes).
_ASSERTION_DOMAIN = b"tzun-assertion-v1"

#: The order of the P-256 group.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_HALF_ORDER = P256_ORDER >> 1

_STANDARD_RE = re.compile(r"[A-Za-z0-9+/]*", re.ASCII)
_URL_RE = re.compile(r"[A-Za-z0-9_-]*", re.ASCII)


def decode_base64_text(text: Any) -> bytes | None:
    """Decode base64 or base64url text, padded or not, or ``None`` when it is not such text.

    The two alphabets may not be mixed within one value.
    """
    if not isinstance(text, str) or text == "":
        return None
    body = text.rstrip("=")
    if len(text) - len(body) > 2:
        return None
    standard = _STANDARD_RE.fullmatch(body) is not None
    url = _URL_RE.fullmatch(body) is not None
    if not standard and not url:
        return None
    if len(body) % 4 == 1:
        return None
    if len(text) != len(body) and len(text) % 4 != 0:
        return None
    normal = body.replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(normal + "=" * (-len(normal) % 4))
    except ValueError:
        return None


def _read_length(data: bytes, pos: int) -> tuple[int, int] | None:
    if pos >= len(data):
        return None
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0 or count > 4:
        return None
    length = 0
    for _ in range(count):
        if pos >= len(data):
            return None
        length = length * 256 + data[pos]
        pos += 1
    return length, pos


def _read_integer(data: bytes, pos: int) -> tuple[int, int] | None:
    if pos >= len(data) or data[pos] != 0x02:
        return None
    read = _read_length(data, pos + 1)
    if read is None:
        return None
    length, pos = read
    if length == 0 or pos + length > len(data):
        return None
    content = data[pos : pos + length]
    if content[0] & 0x80:
        return None
    return int.from_bytes(content, "big"), pos + length


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    out = []
    n = length
    while n > 0:
        out.insert(0, n & 0xFF)
        n //= 256
    return bytes([0x80 | len(out), *out])


def _encode_integer(value: int) -> bytes:
    content = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if content[0] & 0x80:
        content = b"\x00" + content
    return b"\x02" + _encode_length(len(content)) + content


def normalise_es256_signature(der: bytes) -> bytes | None:
    """An ECDSA P-256 signature re-encoded in minimal DER with low S, or ``None`` when it is not DER."""
    if len(der) == 0 or der[0] != 0x30:
        return None
    read = _read_length(der, 1)
    if read is None:
        return None
    seq_len, pos = read
    if pos + seq_len != len(der):
        return None
    r_read = _read_integer(der, pos)
    if r_read is None:
        return None
    r_value, pos = r_read
    s_read = _read_integer(der, pos)
    if s_read is None:
        return None
    s_value, pos = s_read
    if pos != len(der):
        return None
    if not 0 < r_value < P256_ORDER or not 0 < s_value < P256_ORDER:
        return None
    low_s = P256_ORDER - s_value if s_value > _P256_HALF_ORDER else s_value
    body = _encode_integer(r_value) + _encode_integer(low_s)
    return b"\x30" + _encode_length(len(body)) + body


def assertion_digest_result(assertion: Any) -> dict[str, Any]:
    """``{"ok": True, "digest": ...}`` or ``{"ok": False, "reason": ...}``. Never raises."""
    a = plain(assertion)
    if not isinstance(a, dict):
        return {"ok": False, "reason": "not_an_object"}
    if a.get("algorithm") not in ("ES256", "Ed25519"):
        return {"ok": False, "reason": "unsupported_algorithm"}
    if a.get("authenticatorData") is None:
        return {"ok": False, "reason": "missing_authenticator_data"}
    if a.get("clientDataJSON") is None:
        return {"ok": False, "reason": "missing_client_data"}
    authenticator_data = decode_base64_text(a.get("authenticatorData"))
    client_data = decode_base64_text(a.get("clientDataJSON"))
    signature = decode_base64_text(a.get("signature"))
    if authenticator_data is None or client_data is None or signature is None:
        return {"ok": False, "reason": "invalid_encoding"}
    normalised = signature
    if a.get("algorithm") == "ES256":
        der = normalise_es256_signature(signature)
        if der is None:
            return {"ok": False, "reason": "signature_not_der"}
        normalised = der
    digest = hashlib.sha256(
        _ASSERTION_DOMAIN
        + hashlib.sha256(authenticator_data).digest()
        + hashlib.sha256(client_data).digest()
        + hashlib.sha256(normalised).digest()
    ).hexdigest()
    return {"ok": True, "digest": digest}


def assertion_digest(assertion: Any) -> str | None:
    """The assertion digest, 64 lowercase hex, or ``None`` when the assertion has none. Never raises."""
    result = assertion_digest_result(assertion)
    return result["digest"] if result["ok"] else None


__all__ = (
    "P256_ORDER",
    "assertion_digest",
    "assertion_digest_result",
    "decode_base64_text",
    "normalise_es256_signature",
)
