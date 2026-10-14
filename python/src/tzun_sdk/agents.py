"""The agent descriptor ``tzun-agent/1`` (Record §6.9): its grammar and its digest.

``agentDescriptorDigest = "sha256:" ‖ hex(SHA-256(C(d)))``, with the set
members (``identities``, ``keys`` by ``kid``, ``models``,
``runtime.measurements``) sorted by UTF-8 bytes before serialization, so the
order a set was assembled in does not change the digest. The twin of
``packages/engine/src/agent.ts``. The catalog API is the ``agents`` namespace
of :class:`tzun_sdk.Tzun`.
"""

from __future__ import annotations

import re
from typing import Any

from tzun_sdk._record_rules import (
    bytes_key,
    canonical_value,
    has_exact_keys,
    has_lone_surrogate,
    is_bare_digest,
    is_prefixed_digest,
    is_strictly_increasing,
    plain,
    sha256_hex,
    utf8_length,
    utf16_length,
)

AGENT_DESCRIPTOR_VERSION = "tzun-agent/1"

#: The most canonical bytes a descriptor a writer registers may have.
AGENT_DESCRIPTOR_MAX_BYTES = 16 * 1024
#: The most elements of each set.
AGENT_DESCRIPTOR_MAX_SET = 64
#: The longest ``name``, ``operator.organization``, ``runtime.format`` and set string, in UTF-16 code units.
AGENT_DESCRIPTOR_MAX_STRING = 256
#: The longest ``keys[].attestation``, in UTF-16 code units.
AGENT_DESCRIPTOR_MAX_ATTESTATION = 8192

_DESCRIPTOR_KEYS = (
    "v", "name", "operator", "identities", "keys", "models", "instructions", "tools", "runtime", "policy", "parent",
    "derivation",
)
_KEY_KEYS = ("kid", "alg", "custody", "attestation")
_JKT_RE = re.compile(r"[A-Za-z0-9_-]{43}", re.ASCII)
_ALGS = ("EdDSA", "ES256", "PS256")
_CUSTODY = ("hsm", "tee", "workload", "software")
_DERIVATIONS = ("base", "revision", "fork", "clone")


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and len(value) > 0


def sort_agent_descriptor_sets(descriptor: Any) -> dict[str, Any]:
    """The descriptor with its set members sorted, as it is hashed."""
    d = plain(descriptor)
    runtime = d["runtime"]
    return {
        **d,
        "operator": dict(d["operator"]),
        "identities": sorted(d["identities"], key=bytes_key),
        "keys": sorted((dict(k) for k in d["keys"]), key=lambda k: bytes_key(k["kid"])),
        "models": sorted(d["models"], key=bytes_key),
        "runtime": None
        if runtime is None
        else {**runtime, "measurements": sorted(runtime["measurements"], key=bytes_key)},
    }


def canonical_serialize_agent_descriptor(descriptor: Any) -> str:
    """The canonical bytes of an agent descriptor, its sets sorted."""
    return canonical_value(sort_agent_descriptor_sets(descriptor))


def agent_descriptor_digest(descriptor: Any) -> str:
    """``sha256:`` and the lowercase hex SHA-256 of the descriptor's canonical bytes."""
    return "sha256:" + sha256_hex(canonical_serialize_agent_descriptor(descriptor))


def _unique_sorted(values: list[str]) -> bool:
    return is_strictly_increasing(sorted(values, key=bytes_key))


def _grammar_violation(descriptor: Any) -> str | None:
    d = plain(descriptor)
    if not isinstance(d, dict):
        return "an agent descriptor must be an object"
    if not has_exact_keys(d, _DESCRIPTOR_KEYS):
        return "an agent descriptor has exactly the members " + ", ".join(_DESCRIPTOR_KEYS)
    if d["v"] != AGENT_DESCRIPTOR_VERSION:
        return f"v must be {AGENT_DESCRIPTOR_VERSION}"
    if not _non_empty_string(d["name"]):
        return "name must be a non-empty string"
    operator = d["operator"]
    if (
        not isinstance(operator, dict)
        or not has_exact_keys(operator, ("organization", "owner"))
        or not _non_empty_string(operator["organization"])
        or (operator["owner"] is not None and not is_bare_digest(operator["owner"]))
    ):
        return "operator has exactly organization (a non-empty string) and owner (64 lowercase hex or null)"
    identities = d["identities"]
    if not isinstance(identities, list) or not all(_non_empty_string(v) for v in identities) or not _unique_sorted(identities):
        return "identities must be a set of non-empty strings"
    keys = d["keys"]
    if (
        not isinstance(keys, list)
        or not all(
            isinstance(k, dict)
            and has_exact_keys(k, _KEY_KEYS)
            and isinstance(k["kid"], str)
            and _JKT_RE.fullmatch(k["kid"]) is not None
            and k["alg"] in _ALGS
            and k["custody"] in _CUSTODY
            and (k["attestation"] is None or _non_empty_string(k["attestation"]))
            for k in keys
        )
        or not _unique_sorted([k["kid"] for k in keys])
    ):
        return "keys must be a set, by kid, of { kid, alg, custody, attestation }"
    models = d["models"]
    if not isinstance(models, list) or not all(is_prefixed_digest(m) for m in models) or not _unique_sorted(models):
        return "models must be a set of model descriptor digests"
    for key in ("instructions", "tools", "policy", "parent"):
        if d[key] is not None and not is_prefixed_digest(d[key]):
            return f"{key} must be null or a prefixed digest"
    runtime = d["runtime"]
    if runtime is not None and (
        not isinstance(runtime, dict)
        or not has_exact_keys(runtime, ("format", "measurements"))
        or not _non_empty_string(runtime["format"])
        or not isinstance(runtime["measurements"], list)
        or not all(_non_empty_string(m) for m in runtime["measurements"])
        or not _unique_sorted(runtime["measurements"])
    ):
        return "runtime must be null or exactly format and a set of measurements"
    if d["derivation"] is not None and d["derivation"] not in _DERIVATIONS:
        return "derivation must be null or one of " + ", ".join(_DERIVATIONS)
    return None


def _limit_violation(d: dict[str, Any]) -> str | None:
    runtime = d["runtime"]
    sets = [
        ("identities", d["identities"]),
        ("keys", d["keys"]),
        ("models", d["models"]),
        ("runtime.measurements", runtime["measurements"] if runtime is not None else []),
    ]
    for name, values in sets:
        if len(values) > AGENT_DESCRIPTOR_MAX_SET:
            return f"{name} holds at most {AGENT_DESCRIPTOR_MAX_SET} elements"
    strings: list[tuple[str, str, int]] = [
        ("name", d["name"], AGENT_DESCRIPTOR_MAX_STRING),
        ("operator.organization", d["operator"]["organization"], AGENT_DESCRIPTOR_MAX_STRING),
        *(("identities", v, AGENT_DESCRIPTOR_MAX_STRING) for v in d["identities"]),
    ]
    if runtime is not None:
        strings.append(("runtime.format", runtime["format"], AGENT_DESCRIPTOR_MAX_STRING))
        strings.extend(("runtime.measurements", v, AGENT_DESCRIPTOR_MAX_STRING) for v in runtime["measurements"])
    strings.extend(
        ("keys[].attestation", k["attestation"], AGENT_DESCRIPTOR_MAX_ATTESTATION)
        for k in d["keys"]
        if k["attestation"] is not None
    )
    for name, value, maximum in strings:
        if utf16_length(value) > maximum:
            return f"{name} is at most {maximum} UTF-16 code units"
        if has_lone_surrogate(value):
            return f"{name} holds a lone surrogate"
    try:
        size = utf8_length(canonical_serialize_agent_descriptor(d))
    except Exception:
        return "an agent descriptor must be canonically serializable"
    if size > AGENT_DESCRIPTOR_MAX_BYTES:
        return f"an agent descriptor's canonical bytes are at most {AGENT_DESCRIPTOR_MAX_BYTES}"
    return None


def agent_descriptor_violation(descriptor: Any, *, limits: bool = True) -> str | None:
    """Why ``descriptor`` is not an agent descriptor, or ``None``. Never raises.

    With ``limits`` (the default; ``register`` applies them), also the writer
    limits of Record §6.9. Store-level verification passes ``limits=False``.
    """
    grammar = _grammar_violation(descriptor)
    if grammar is not None or not limits:
        return grammar
    return _limit_violation(plain(descriptor))


def agent_kind_mismatch(kind: Any, descriptor: Any) -> bool:
    """A ``policy-engine`` decider or actor whose descriptor names a model (``agent_kind_mismatch``)."""
    d = plain(descriptor)
    return kind == "policy-engine" and isinstance(d, dict) and len(d.get("models") or []) > 0


__all__ = (
    "AGENT_DESCRIPTOR_MAX_ATTESTATION",
    "AGENT_DESCRIPTOR_MAX_BYTES",
    "AGENT_DESCRIPTOR_MAX_SET",
    "AGENT_DESCRIPTOR_MAX_STRING",
    "AGENT_DESCRIPTOR_VERSION",
    "agent_descriptor_digest",
    "agent_descriptor_violation",
    "agent_kind_mismatch",
    "canonical_serialize_agent_descriptor",
    "sort_agent_descriptor_sets",
)
