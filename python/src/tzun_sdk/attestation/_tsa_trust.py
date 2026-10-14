# HAND-MAINTAINED. NOT generated.
"""The RFC 3161 trust configuration the auditor supplies, refused when it cannot be read.

:func:`check_trust_configuration` refuses the inputs the TypeScript ``readTrustAnchors``
refuses, with the same messages (Verification §3.1, §6.6): trust anchors or authorities
that are not lists, a root that does not read (:func:`read_trust_anchors`), a
``TZUN_TSA_TRUST_ANCHORS`` file that cannot be read, and an authority, in the options or
in ``TZUN_TSA_AUTHORITIES``, that the TypeScript registry does not know. This SDK checks
no trust path, so it holds no registry roots: it knows the registry by its keys and its
URLs, which ``pnpm run codegen:python`` writes to ``_data/tsa-authorities.json``.

A selector names an authority by its key, or by a URL that reads, as the WHATWG URL
parser reads an ``http`` or ``https`` URL, as the registered URL does: the scheme and the
host in lower case, the default port dropped, the path with its dot segments resolved and
its trailing slashes dropped, and the query. :func:`normalised_url` is that reading for a
URL whose host maps to ASCII letters, digits, hyphens and dots; a host that maps to
anything else is not one any registered URL has.

Private to :mod:`tzun_sdk.attestation`.
"""

from __future__ import annotations

import json
import os
import re
import unicodedata
from functools import lru_cache
from importlib import resources
from typing import Final
from urllib.parse import unquote

from tzun_sdk.attestation._ecmascript import js_trim
from tzun_sdk.attestation._rfc3161_steps import UnreadableTrustAnchorError, read_trust_anchors

_PEM_BEGIN: Final = "-----BEGIN CERTIFICATE-----"


@lru_cache(maxsize=1)
def _registry() -> tuple[tuple[str, ...], frozenset[str]]:
    """The registry's keys in registration order, and its URLs in normalised form."""
    text = resources.files("tzun_sdk._data").joinpath("tsa-authorities.json").read_text("utf-8")
    authorities = json.loads(text)["authorities"]
    return tuple(a["key"] for a in authorities), frozenset(a["normalisedUrl"] for a in authorities)


def known_authority(selector: str) -> bool:
    """Whether ``selector`` names an authority of the TypeScript registry: by its key, or
    by a URL of the same normalised form (``getTimestampAuthority``)."""
    keys, urls = _registry()
    if selector in keys:
        return True
    wanted = normalised_url(selector)
    return wanted is not None and wanted in urls


# ---- The WHATWG reading of an http or https URL ---------------------------------------------

_C0_OR_SPACE: Final = "".join(chr(c) for c in range(0x21))
_SCHEME: Final = re.compile(r"[A-Za-z][A-Za-z0-9+\-.]*:")
_DEFAULT_PORTS: Final = {"http": 80, "https": 443}
_LONE_SURROGATE: Final = re.compile("[\ud800-\udfff]")
_PORT: Final = re.compile(r"[0-9]*")
#: Beyond the C0 controls and every code point past U+007E, what WHATWG percent-encodes.
_QUERY_SET: Final = frozenset(' "#<>')
_SPECIAL_QUERY_SET: Final = _QUERY_SET | {"'"}
_PATH_SET: Final = _QUERY_SET | frozenset("?`{}")
_DOUBLE_DOT: Final = frozenset({"..", ".%2e", "%2e.", "%2e%2e"})
_SINGLE_DOT: Final = frozenset({".", "%2e"})
#: The code points UTS #46 ignores in a domain name, and the few it maps to ASCII that NFKC
#: does not: the ideographic full stops, and U+1E9E to ``ss``.
_UTS46_IGNORED: Final = frozenset(
    [
        0x00AD,
        0x034F,
        0x180B,
        0x180C,
        0x180D,
        0x180F,
        0x200B,
        0x2060,
        0x2064,
        0xFEFF,
        *range(0xFE00, 0xFE10),
        *range(0x1BCA0, 0x1BCA4),
        *range(0xE0100, 0xE01F0),
    ]
)
_UTS46_TO_ASCII: Final = {0x3002: ".", 0xFF0E: ".", 0xFF61: ".", 0x1E9E: "ss"}
_HOST_LETTERS: Final = re.compile(r"[a-z0-9-]+")


def _percent_encode(text: str, extra: frozenset[str]) -> str:
    out: list[str] = []
    for ch in text:
        if ch in extra or ord(ch) < 0x20 or ord(ch) > 0x7E:
            out.append("".join(f"%{b:02X}" for b in ch.encode("utf-8")))
        else:
            out.append(ch)
    return "".join(out)


def _ascii_character(c: str) -> str | None:
    """What UTS #46 maps a code point outside ASCII to, when that is letters, digits,
    hyphens or a dot: ignored, one of :data:`_UTS46_TO_ASCII`, or its NFKC form in lower
    case. ``None`` otherwise: a code point it keeps, disallows, or maps to other ASCII,
    none of which a registered host holds."""
    code = ord(c)
    if code in _UTS46_IGNORED:
        return ""
    if code in _UTS46_TO_ASCII:
        return _UTS46_TO_ASCII[code]
    mapped = unicodedata.normalize("NFKC", c).lower()
    return mapped if _HOST_LETTERS.fullmatch(mapped) else None


def _ascii_host(host: str) -> str | None:
    """The host as WHATWG's domain-to-ASCII writes it, percent-decoded and in lower case,
    when every code point maps to ASCII (:func:`_ascii_character`). ``None`` for a host
    that is empty or does not map to ASCII."""
    domain = unquote(host, encoding="utf-8", errors="replace")
    if not domain.isascii():
        parts = [c if c.isascii() else _ascii_character(c) for c in domain]
        if any(p is None for p in parts):
            return None
        domain = "".join(p for p in parts if p is not None)
    domain = domain.lower()
    return domain or None


def normalised_url(value: str) -> str | None:
    """``normaliseUrl`` of the TypeScript registry, for an ``http`` or ``https`` URL:
    ``scheme://host`` in lower case with a port other than the scheme's default, the path
    without its trailing slashes, and the query. ``None`` for a string that is not such a
    URL, or whose host does not map to ASCII (the module docstring says how far this
    reading goes)."""
    text = _LONE_SURROGATE.sub("\ufffd", value).strip(_C0_OR_SPACE)
    text = re.sub(r"[\t\n\r]", "", text)
    scheme_match = _SCHEME.match(text)
    if scheme_match is None:
        return None
    scheme = scheme_match.group(0)[:-1].lower()
    default_port = _DEFAULT_PORTS.get(scheme)
    if default_port is None:
        return None
    rest = text[scheme_match.end() :].lstrip("/\\")
    end = next((i for i, ch in enumerate(rest) if ch in "/\\?#"), len(rest))
    authority, rest = rest[:end], rest[end:]
    host_port = authority.rpartition("@")[2]
    if host_port.startswith("["):
        return None
    host, colon, port = host_port.partition(":")
    port_suffix = ""
    if colon and port != "":
        if not _PORT.fullmatch(port) or int(port) > 65535:
            return None
        if int(port) != default_port:
            port_suffix = f":{int(port)}"
    ascii_host = _ascii_host(host)
    if ascii_host is None:
        return None

    rest = rest.partition("#")[0]
    path, _, query = rest.partition("?")
    raw_segments = re.split(r"[/\\]", path)[1:] if path else [""]
    segments: list[str] = []
    last = len(raw_segments) - 1
    for i, raw in enumerate(raw_segments):
        segment = _percent_encode(raw, _PATH_SET)
        if segment.lower() in _DOUBLE_DOT:
            if segments:
                segments.pop()
            if i == last:
                segments.append("")
        elif segment.lower() in _SINGLE_DOT:
            if i == last:
                segments.append("")
        else:
            segments.append(segment)
    pathname = "/" + "/".join(segments)
    search = f"?{_percent_encode(query, _SPECIAL_QUERY_SET)}" if query else ""
    return f"{scheme}://{ascii_host}{port_suffix}{pathname.rstrip('/')}{search}"


# ---- The configuration --------------------------------------------------------------------


def _unknown_authority(selector: str) -> UnreadableTrustAnchorError:
    keys, _ = _registry()
    return UnreadableTrustAnchorError(
        f'the trust anchors cannot be read: Unknown timestamp authority "{selector}". Known keys: '
        f"{', '.join(keys)}. Pass a registry key, or a URL exactly as registered, or supply the "
        "anchor yourself with trustAnchorsPem / TZUN_TSA_TRUST_ANCHORS."
    )


def check_trust_configuration(trust_anchors_pem: object = None, authorities: object = None) -> None:
    """Refuse RFC 3161 trust the auditor supplied that cannot be read, as the TypeScript
    ``readTrustAnchors`` refuses it and with its messages (Verification §3.1, §6.6). ``None``
    is an input not given.

    - ``trust_anchors_pem`` that is not a list, or ``authorities`` that is not a list of
      strings, is refused;
    - with either given and not empty, every entry of ``trust_anchors_pem`` must read
      (:func:`read_trust_anchors`), and every authority must be one the registry knows;
    - with neither, ``TZUN_TSA_TRUST_ANCHORS`` (inline PEM, or paths separated by
      ``os.pathsep``, each a file that can be read and whose roots read) and every name of
      ``TZUN_TSA_AUTHORITIES`` (comma-separated) are held to the same.

    :raises UnreadableTrustAnchorError: naming the input and why.
    """
    if trust_anchors_pem is not None and not isinstance(trust_anchors_pem, (list, tuple)):
        raise UnreadableTrustAnchorError("the trust anchors are not a list of PEM strings")
    if authorities is not None and (
        not isinstance(authorities, (list, tuple))
        or not all(isinstance(a, str) for a in authorities)
    ):
        raise UnreadableTrustAnchorError("the authorities are not a list of names")
    pems = list(trust_anchors_pem or ())
    names: list[str] = list(authorities or ())
    if pems or names:
        read_trust_anchors(pems)
        selectors = names
    else:
        env = os.environ.get("TZUN_TSA_TRUST_ANCHORS", "")
        if js_trim(env):
            if _PEM_BEGIN in env:
                sources = [env]
            else:
                sources = []
                for path in (js_trim(p) for p in env.split(os.pathsep)):
                    if not path:
                        continue
                    try:
                        with open(path, "rb") as f:
                            data = f.read()
                    except (OSError, ValueError):
                        # The same words on every platform and in both SDKs: the path, not
                        # the operating system's reason.
                        raise UnreadableTrustAnchorError(
                            f"TZUN_TSA_TRUST_ANCHORS: {path} cannot be read"
                        ) from None
                    sources.append(data.decode("utf-8", errors="replace"))
            read_trust_anchors(sources)
        env_names = os.environ.get("TZUN_TSA_AUTHORITIES", "")
        selectors = (
            [s for s in (js_trim(n) for n in env_names.split(",")) if s]
            if js_trim(env_names)
            else []
        )
    for selector in selectors:
        if not known_authority(selector):
            raise _unknown_authority(selector)


__all__ = ("check_trust_configuration", "known_authority", "normalised_url")
