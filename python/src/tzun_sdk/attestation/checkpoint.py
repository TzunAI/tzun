# HAND-MAINTAINED. NOT generated.
#
# The Python twin of src/attestation/checkpoint.ts: checkpoint bodies and the
# origin grammar of tzun-anchor/1 §4. The chain-id rule and the chain segment
# come from tzun_sdk.log_origin, the one Python implementation of them, as the
# TypeScript store rules come from checkpoint.ts.
#
# tests/cross-sdk/test_anchor_verify_parity.py runs the same inputs through both
# modules and requires the same answers; tests/cross-sdk/test_checkpoint_vectors.py
# holds this module to vectors/checkpoint-vectors.json. Edit both sides together.
"""Checkpoint bodies and the origins they name (tzun-anchor/1 §4).

A checkpoint body is the note text of a C2SP ``tlog-checkpoint``::

    <origin>\\n<tree size, ASCII decimal>\\n<root, RFC 4648 §4 base64 with padding>\\n

Tzun checkpoints carry no signature until a log key exists, so
"checkpoint" here means the body. Signatures are signed-note lines after the
body and never change it.

The body is read more strictly than C2SP requires. Anything but the exact form
above is refused: CR anywhere, a missing final newline, leading zeros in the
size, a size of 0, a size above 2^53 - 1, a root that is not canonical base64 of
exactly 32 bytes, and any extension line.

Every reader here takes any value and never raises: bodies and origins arrive
inside artifacts, and a malformed one is a reported verdict. The writers
(:func:`format_checkpoint`, :func:`checkpoint_digest` and the origin builders)
raise :class:`ValueError`, because a writer that cannot produce a valid value has
a bug to surface.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Final, Literal, TypeGuard

from tzun_sdk.log_origin import ANCHOR_LOG_KIND, EVIDENCE_LOG_KIND, chain_id_refusal, chain_segment

CheckpointMalformedReason = Literal[
    "not_a_string",
    "carriage_return",
    "missing_final_newline",
    "extension_lines",
    "too_few_lines",
    "malformed_origin",
    "malformed_size",
    "size_out_of_range",
    "malformed_root",
]
"""Why a checkpoint body was refused. Every reason reads as ``malformed_checkpoint`` in a verdict.

- ``not_a_string``: the body is not a ``str``.
- ``carriage_return``: a CR (0x0D) appears; line endings are LF only.
- ``missing_final_newline``: the body does not end in LF.
- ``extension_lines``: more than three lines; C2SP extension lines are not accepted.
- ``too_few_lines``: fewer than three lines.
- ``malformed_origin``: the origin line is empty, or holds a character outside
  0x21-0x7E, or a ``+``.
- ``malformed_size``: the size line is not ASCII decimal digits, or has a leading zero.
- ``size_out_of_range``: the size is 0 or above 2^53 - 1.
- ``malformed_root``: the root line is not canonical padded base64 of 32 bytes.
"""

# ANCHOR_LOG_KIND ("anchors", the last segment of every anchor-log origin) and
# EVIDENCE_LOG_KIND ("evidence") are tzun_sdk.log_origin's, re-exported here.

#: A namespace beginning with this names a test origin (Anchor §4.3.4).
TEST_NAMESPACE_PREFIX: Final = "test."
#: The platform's namespace (Anchor §4.3.3): ``log.tzun.ai/<deploymentId>/...``. Its
#: source-log origins are opaque, so no chain can be read from them. A platform
#: deployment that anchors in the test namespace uses ``test.log.tzun.ai``
#: (Anchor §4.3.4), which step 2b treats the same way.
PLATFORM_NAMESPACE: Final = "log.tzun.ai"
#: The platform's two namespaces: production, and test (tzun-anchor/1 §4.3.4).
_PLATFORM_NAMESPACES: Final = frozenset(
    {PLATFORM_NAMESPACE, TEST_NAMESPACE_PREFIX + PLATFORM_NAMESPACE}
)

_MAX_SAFE_INTEGER: Final = 2**53 - 1
# Printable ASCII other than space and "+": 0x21-0x2A and 0x2C-0x7E.
_ORIGIN_TEXT: Final = re.compile(r"[\x21-\x2a\x2c-\x7e]+")
_SIZE_TEXT: Final = re.compile(r"0|[1-9][0-9]*")
# 32 bytes of padded base64 is 43 characters and one "=".
_ROOT_TEXT: Final = re.compile(r"[A-Za-z0-9+/]{43}=")
_HEX_64: Final = re.compile(r"[0-9a-f]{64}")
_CHAIN_SEGMENT: Final = re.compile(r"(?:[0-9a-f]{2})+")


@dataclass(frozen=True)
class Checkpoint:
    """A checkpoint body that parsed."""

    origin: str
    #: The tree size, at least 1.
    size: int
    #: The root hash, 64 lowercase hex digits.
    root: str
    #: The body exactly as parsed. ``checkpoint_digest(body)`` is its leaf in an anchor log.
    body: str


@dataclass(frozen=True)
class CheckpointParseResult:
    """The result of :func:`parse_checkpoint`: a checkpoint, or why there is none."""

    ok: bool
    #: Set exactly when ``ok`` is true.
    checkpoint: Checkpoint | None = None
    #: Set exactly when ``ok`` is false.
    reason: CheckpointMalformedReason | None = None


def _refuse(reason: CheckpointMalformedReason) -> CheckpointParseResult:
    return CheckpointParseResult(ok=False, reason=reason)


def is_origin_text(origin: object) -> TypeGuard[str]:
    """Whether ``origin`` is text a Tzun origin may be made of: non-empty printable
    ASCII with no space and no ``+``. C2SP recommends the same set."""
    return isinstance(origin, str) and _ORIGIN_TEXT.fullmatch(origin) is not None


def parse_checkpoint(body: object) -> CheckpointParseResult:
    """Parse a checkpoint body under the exact form. Never raises."""
    if not isinstance(body, str):
        return _refuse("not_a_string")
    if "\r" in body:
        return _refuse("carriage_return")
    if not body.endswith("\n"):
        return _refuse("missing_final_newline")
    lines = body[:-1].split("\n")
    if len(lines) > 3:
        return _refuse("extension_lines")
    if len(lines) < 3:
        return _refuse("too_few_lines")
    origin, size_text, root_text = lines

    if not is_origin_text(origin):
        return _refuse("malformed_origin")

    if _SIZE_TEXT.fullmatch(size_text) is None:
        return _refuse("malformed_size")
    # Digits only, so the only way past 2^53 - 1 is by length or value.
    size = int(size_text) if len(size_text) <= 16 else _MAX_SAFE_INTEGER + 1
    if not 1 <= size <= _MAX_SAFE_INTEGER:
        return _refuse("size_out_of_range")

    if _ROOT_TEXT.fullmatch(root_text) is None:
        return _refuse("malformed_root")
    root_bytes = base64.b64decode(root_text)
    # The decoder ignores the two unused bits of the 43rd character. Re-encoding
    # pins the one canonical spelling: those bits must be clear.
    if len(root_bytes) != 32 or base64.b64encode(root_bytes).decode("ascii") != root_text:
        return _refuse("malformed_root")

    return CheckpointParseResult(
        ok=True, checkpoint=Checkpoint(origin=origin, size=size, root=root_bytes.hex(), body=body)
    )


def _safe_size(size: object) -> int | None:
    """``size`` as an ``int`` when it is a JSON integer in [1, 2^53 - 1], else ``None``."""
    if isinstance(size, bool):
        return None
    if isinstance(size, int):
        value = size
    elif isinstance(size, float) and size.is_integer():
        value = int(size)
    else:
        return None
    return value if 1 <= value <= _MAX_SAFE_INTEGER else None


def format_checkpoint(origin: str, size: int | float, root: str) -> str:
    """The body of the checkpoint of ``origin`` at ``size`` with root ``root`` (64 hex
    digits, either case).

    :raises ValueError: when the origin is not origin text, the size is not an
        integer in [1, 2^53 - 1], or the root is not 64 hex digits.
    """
    if not is_origin_text(origin):
        raise ValueError(
            'Checkpoint origin must be non-empty printable ASCII with no space and no "+".'
        )
    safe = _safe_size(size)
    if safe is None:
        raise ValueError("Checkpoint size must be a safe integer of at least 1.")
    root_hex = root.lower() if isinstance(root, str) else ""
    if _HEX_64.fullmatch(root_hex) is None:
        raise ValueError("Checkpoint root must be 64 hex digits.")
    root_b64 = base64.b64encode(bytes.fromhex(root_hex)).decode("ascii")
    return f"{origin}\n{safe}\n{root_b64}\n"


def checkpoint_digest(body: str) -> str:
    """``SHA-256(body)``, 64 lowercase hex digits: a checkpoint's leaf in the anchor
    log (Anchor §4.4), and, for the anchor log's own checkpoint, the published value P (Anchor §6).

    :raises ValueError: when ``body`` is not a valid checkpoint body, so no caller
        can hash a string that no verifier would accept as one.
    """
    parsed = parse_checkpoint(body)
    if not parsed.ok:
        raise ValueError(f"Not a checkpoint body ({parsed.reason}).")
    assert isinstance(body, str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


# ---- Origins -----------------------------------------------------------------------


def chain_id_from_segment(segment: object) -> str | None:
    """The chain id a chain segment spells, or ``None`` when the segment is not the
    one spelling :func:`chain_segment` produces for a chain id (tzun-anchor/1
    §4.3.2): empty, odd-length, uppercase, not hex, bytes that are not strict
    UTF-8 (overlong forms, surrogates, a truncated sequence), or a 0x00 byte. A
    leading byte-order mark is kept. Never raises."""
    if not isinstance(segment, str) or _CHAIN_SEGMENT.fullmatch(segment) is None:
        return None
    try:
        chain_id = bytes.fromhex(segment).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if chain_id_refusal(chain_id) is not None:
        return None
    return chain_id if chain_id.encode("utf-8").hex() == segment else None


OriginKind = Literal["anchors", "evidence", "log"]


@dataclass(frozen=True)
class TzunOrigin:
    """An origin read under the Anchor §4.3 scheme."""

    #: ``anchors``: the domain's anchor log; ``evidence``: an SDK evidence log;
    #: ``log``: an SDK source log named by its kind, or a platform log.
    kind: OriginKind
    #: The first two segments: ``<ns>/<storeId>`` or ``log.tzun.ai/<deploymentId>``.
    domain_prefix: str
    #: The first segment.
    namespace: str
    #: The chain an evidence log names; ``None`` for the other kinds.
    chain_id: str | None = None
    #: The segment naming a source log; ``None`` for the other kinds.
    name: str | None = None


def parse_origin(origin: object) -> TzunOrigin | None:
    """Read an origin under the Anchor §4.3 scheme, or ``None`` when it is not one. Never raises.

    Every origin is ``<domain prefix>/<rest>``, the domain prefix being two
    segments. The rest is ``anchors``, ``evidence/<chain segment>``, or one other
    segment (a source log). ``evidence`` alone is not an origin, because an
    evidence log always names its chain. Every segment is non-empty origin text
    without ``/``.
    """
    if not is_origin_text(origin):
        return None
    segments = origin.split("/")
    if any(s == "" for s in segments):
        return None
    if not 3 <= len(segments) <= 4:
        return None
    namespace = segments[0]
    domain_prefix = f"{segments[0]}/{segments[1]}"
    rest = segments[2:]

    if len(rest) == 2:
        if rest[0] != EVIDENCE_LOG_KIND:
            return None
        chain_id = chain_id_from_segment(rest[1])
        if chain_id is None:
            return None
        return TzunOrigin(
            kind="evidence", domain_prefix=domain_prefix, namespace=namespace, chain_id=chain_id
        )
    if rest[0] == ANCHOR_LOG_KIND:
        return TzunOrigin(kind="anchors", domain_prefix=domain_prefix, namespace=namespace)
    if rest[0] == EVIDENCE_LOG_KIND:
        return None
    return TzunOrigin(kind="log", domain_prefix=domain_prefix, namespace=namespace, name=rest[0])


def _assert_domain_prefix(domain_prefix: object) -> str:
    segments = domain_prefix.split("/") if isinstance(domain_prefix, str) else []
    if len(segments) != 2 or not all(is_origin_text(s) for s in segments):
        raise ValueError('A domain prefix is two non-empty segments of origin text: "<ns>/<id>".')
    assert isinstance(domain_prefix, str)
    return domain_prefix


def anchor_log_origin(domain_prefix: str) -> str:
    """The anchor-log origin of a domain: ``<domain prefix>/anchors``.

    :raises ValueError: on a malformed prefix.
    """
    return f"{_assert_domain_prefix(domain_prefix)}/{ANCHOR_LOG_KIND}"


def evidence_log_origin(domain_prefix: str, chain_id: str) -> str:
    """The SDK evidence-log origin of a chain: ``<domain prefix>/evidence/<chain segment>``.

    (:func:`tzun_sdk.log_origin.evidence_log_origin` builds the same origin from
    a store's ``ns`` and store id.)

    :raises ValueError: on a malformed prefix or chain id.
    """
    return f"{_assert_domain_prefix(domain_prefix)}/{EVIDENCE_LOG_KIND}/{chain_segment(chain_id)}"


def source_log_origin(domain_prefix: str, name: str) -> str:
    """The origin of a source log named by one segment: ``<domain prefix>/<name>``,
    an SDK source log of kind ``name`` (Anchor §4.3.2) or a platform log under an opaque
    id (§4.3.3).

    :raises ValueError: on a malformed prefix, or a name that is not one segment of
        origin text, or is ``anchors`` or ``evidence``.
    """
    prefix = _assert_domain_prefix(domain_prefix)
    if not is_origin_text(name) or "/" in name or name in (ANCHOR_LOG_KIND, EVIDENCE_LOG_KIND):
        raise ValueError(
            'A source-log name is one segment of origin text other than "anchors" and "evidence".'
        )
    return f"{prefix}/{name}"


def is_test_namespace(namespace: object) -> bool:
    """Whether a namespace (or an origin) names a test origin: it begins with ``test.``."""
    return isinstance(namespace, str) and namespace.startswith(TEST_NAMESPACE_PREFIX)


def is_platform_namespace(namespace: object) -> bool:
    """Whether a namespace is one of the platform's two (tzun-anchor/1 §4.3.3, §4.3.4).

    Exactly ``log.tzun.ai``, or ``test.log.tzun.ai`` for a platform deployment
    that anchors in the test namespace. A name that extends either
    (``test.log.tzun.ai.example``) is not. A source log under either names its
    log by an opaque id, so no chain can be read from its origin. Never raises.
    """
    return isinstance(namespace, str) and namespace in _PLATFORM_NAMESPACES


OriginBindingReason = Literal["origin_not_in_domain", "chain_id_mismatch"]
"""Why an anchor origin and a log origin do not bind (Anchor §10.3 step 2b).

- ``origin_not_in_domain``: the anchor origin is not ``<ns>/<id>/anchors``, or
  the log origin is not a source log the same domain names: another domain
  prefix, another anchor log, or a string the Anchor §4.3 scheme does not produce (an
  uppercase or otherwise non-canonical chain segment included).
- ``chain_id_mismatch``: a chain id was supplied, and the log is not that
  chain's evidence log: an evidence log for another chain, or, outside the
  platform's namespaces (``log.tzun.ai`` and ``test.log.tzun.ai``), a source log
  of another kind.
"""


@dataclass(frozen=True)
class OriginBinding:
    """The result of :func:`check_origin_binding`."""

    ok: bool
    #: The anchor origin's namespace when ``ok``.
    namespace: str | None = None
    #: ``True`` only when a chain id was supplied and the log is an evidence log naming it.
    chain_checked: bool = False
    #: Set exactly when ``ok`` is false.
    reason: OriginBindingReason | None = None


def check_origin_binding(
    anchor_origin: object, log_origin: object, chain_id: object = None
) -> OriginBinding:
    """Anchor §10.3 step 2b: does the log origin belong to the anchor origin's domain, and
    is it the evidence log of the chain supplied? Never raises.

    - No chain id (``None``): the chain is unchecked.
    - A chain id and an evidence log: its chain segment must spell that chain id,
      or ``chain_id_mismatch``. A chain id that is not a non-empty string matches
      no evidence log.
    - A chain id and a platform source log (``log.tzun.ai/<id>/<opaque id>``, or
      ``test.log.tzun.ai/<id>/<opaque id>`` for a platform test deployment): the
      origin is opaque, so the chain is unchecked. Only those two namespaces are
      the platform's; a name that extends either is not.
    - A chain id and any other source log: ``chain_id_mismatch``, because on an
      SDK store a record's leaf is only ever in its chain's evidence log.
    """
    anchor = parse_origin(anchor_origin)
    log = parse_origin(log_origin)
    if anchor is None or anchor.kind != "anchors" or log is None or log.kind == "anchors":
        return OriginBinding(ok=False, reason="origin_not_in_domain")
    if log.domain_prefix != anchor.domain_prefix:
        return OriginBinding(ok=False, reason="origin_not_in_domain")

    chain_checked = False
    if chain_id is not None:
        if log.kind == "evidence":
            if not (isinstance(chain_id, str) and chain_id == log.chain_id):
                return OriginBinding(ok=False, reason="chain_id_mismatch")
            chain_checked = True
        elif not is_platform_namespace(log.namespace):
            return OriginBinding(ok=False, reason="chain_id_mismatch")
    return OriginBinding(ok=True, namespace=anchor.namespace, chain_checked=chain_checked)


__all__ = (
    "ANCHOR_LOG_KIND",
    "EVIDENCE_LOG_KIND",
    "PLATFORM_NAMESPACE",
    "TEST_NAMESPACE_PREFIX",
    "Checkpoint",
    "CheckpointMalformedReason",
    "CheckpointParseResult",
    "OriginBinding",
    "OriginBindingReason",
    "OriginKind",
    "TzunOrigin",
    "anchor_log_origin",
    "chain_id_from_segment",
    "chain_id_refusal",
    "chain_segment",
    "check_origin_binding",
    "checkpoint_digest",
    "evidence_log_origin",
    "format_checkpoint",
    "is_origin_text",
    "is_platform_namespace",
    "is_test_namespace",
    "parse_checkpoint",
    "parse_origin",
    "source_log_origin",
)
