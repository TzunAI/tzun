# HAND-MAINTAINED Python port of the SDK store's origin rules: the chain-id rule and
# the chain segment of src/attestation/checkpoint.ts (the one TypeScript
# implementation of the origin grammar), and the ns, store-id and kind rules of
# src/storage/log-store.ts, whose origin functions wrap it. NOT generated.
#
# Parity is enforced by tests/cross-sdk/test_evidence_log_origin_parity.py, which
# runs vectors/evidence-log-origin-vectors.json through this module and through
# SQLite, and by tests/ts/evidence-log-origin-vectors.test.ts, which runs the same
# file through the TypeScript functions and the SQLite and Postgres triggers.
# Edit both sides together.
"""Evidence-log origins (tzun-anchor/1 §4.3.2).

Every log a store keeps is named by an origin under the store's domain prefix
``<ns>/<store_id>``::

    evidence log of a chain:  <ns>/<store_id>/evidence/<lowercase hex of the chain id's UTF-8 bytes>
    per-store log:            <ns>/<store_id>/<kind>

``store_id`` is 32 lowercase hex characters (128 random bits) minted once per
store; ``ns`` is a lowercase DNS-style name and defaults to ``local.invalid``.
A chain id is a non-empty string of Unicode scalar values other than U+0000,
and it is not normalised: two spellings of one character are two chain ids
and two logs.
"""

from __future__ import annotations

import re

DEFAULT_LOG_NAMESPACE = "local.invalid"
EVIDENCE_LOG_KIND = "evidence"
ANCHOR_LOG_KIND = "anchors"
LOG_NAMESPACE_MAX_LENGTH = 253
LOG_NAMESPACE_LABEL_MAX_LENGTH = 63

_STORE_ID = re.compile(r"[0-9a-f]{32}")
_LOG_KIND = re.compile(r"[a-z][a-z0-9]*")
_NS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_SURROGATE = re.compile("[\ud800-\udfff]")


def assert_log_namespace(ns: str) -> str:
    """Return ``ns`` if the origin rules accept it; raise ``ValueError`` otherwise.

    A lowercase DNS-style name (tzun-anchor/1 §4.3.2): one or more labels of
    ``a``-``z`` and ``0``-``9``, with ``-`` inside a label but not at either end,
    joined by ``.``. A label is at most 63 characters and the name at most 253.
    """
    if not isinstance(ns, str) or ns == "":
        raise ValueError("a log namespace is a non-empty string")
    if len(ns) > LOG_NAMESPACE_MAX_LENGTH:
        raise ValueError(f"a log namespace is at most {LOG_NAMESPACE_MAX_LENGTH} characters")
    for label in ns.split("."):
        if label == "":
            raise ValueError('a log namespace has no empty label (a leading, trailing or doubled ".")')
        if len(label) > LOG_NAMESPACE_LABEL_MAX_LENGTH:
            raise ValueError(f"a log namespace label is at most {LOG_NAMESPACE_LABEL_MAX_LENGTH} characters")
        if not _NS_LABEL.fullmatch(label):
            raise ValueError('a log namespace label is a-z and 0-9, with "-" only inside it')
    return ns


def chain_id_refusal(chain_id: object) -> str | None:
    """Why ``chain_id`` names no evidence log, or ``None`` when it does.

    ``"empty_chain_id"`` for an empty string; ``"invalid_chain_id"`` for a value
    that is not a string, or one holding a surrogate code point (a lone UTF-16
    surrogate in the TypeScript SDK, which has no UTF-8 encoding) or U+0000.
    """
    if not isinstance(chain_id, str):
        return "invalid_chain_id"
    if chain_id == "":
        return "empty_chain_id"
    if "\x00" in chain_id or _SURROGATE.search(chain_id):
        return "invalid_chain_id"
    return None


def chain_segment(chain_id: str) -> str:
    """The lowercase hex of ``chain_id``'s UTF-8 bytes.

    Raises ``ValueError`` for a chain id ``chain_id_refusal`` refuses: empty, or
    holding a surrogate or U+0000.
    """
    refusal = chain_id_refusal(chain_id)
    if refusal == "empty_chain_id":
        raise ValueError("an evidence log needs a non-empty chain id")
    if refusal is not None:
        raise ValueError("a chain id is a string of Unicode scalar values other than U+0000")
    return chain_id.encode("utf-8").hex()


def domain_prefix(ns: str, store_id: str) -> str:
    """``<ns>/<store_id>``: the prefix every origin of one store shares."""
    if not isinstance(store_id, str) or not _STORE_ID.fullmatch(store_id):
        raise ValueError("a store id is 32 lowercase hex characters")
    return f"{assert_log_namespace(ns)}/{store_id}"


def evidence_log_origin(ns: str, store_id: str, chain_id: str) -> str:
    """The origin of ``chain_id``'s evidence log."""
    return f"{domain_prefix(ns, store_id)}/{EVIDENCE_LOG_KIND}/{chain_segment(chain_id)}"


def store_log_origin(ns: str, store_id: str, kind: str) -> str:
    """The origin of a per-store log (``anchors``, ``custody``, ``revisions``, ``policy``)."""
    if not isinstance(kind, str) or not _LOG_KIND.fullmatch(kind) or kind == EVIDENCE_LOG_KIND:
        raise ValueError(f"log kind {kind!r} is not a per-store kind")
    return f"{domain_prefix(ns, store_id)}/{kind}"


__all__ = [
    "ANCHOR_LOG_KIND",
    "DEFAULT_LOG_NAMESPACE",
    "EVIDENCE_LOG_KIND",
    "LOG_NAMESPACE_LABEL_MAX_LENGTH",
    "LOG_NAMESPACE_MAX_LENGTH",
    "assert_log_namespace",
    "chain_id_refusal",
    "chain_segment",
    "domain_prefix",
    "evidence_log_origin",
    "store_log_origin",
]
