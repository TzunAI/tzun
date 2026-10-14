"""Writer rules for a payload's members (Record §2.2, §7.4, §11).

The twin of ``packages/engine/src/payload-rules.ts``, ``ai-bom.ts`` and
``store-schema.ts``: ``evidenceId``, ``capturedAt``, ``sequenceNumber``,
``action``, ``reason``, ``aiSystemId``, ``aiOutput``, the renamed and moved
0.7 fields, the members outside the format, the step ``aiBom`` exact-keys
rule, the size cap on the hashed object, and the recognition of a record's
field-set generation. The one gate over a built payload is
:func:`tzun_sdk.record_rules.payload_record_rule_violation`.

A refusal names the field and the rule and never echoes the value.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any

from tzun_sdk._generated.canonical import (
    V1_HASHED_FIELDS,
    V1_HASHED_FIELDS_0_7,
    V1_HASHED_FIELDS_BEFORE_0_7,
    canonical_serialize,
)
from tzun_sdk._instant import is_capture_time, js_date_parse_ms
from tzun_sdk._record_rules import (
    bytes_key,
    has_exact_keys,
    has_lone_surrogate,
    is_finite_number,
    is_non_negative_safe_integer,
    is_positive_safe_integer,
    is_safe_integer,
    plain,
    utf8_length,
    utf16_length,
)

#: The schema version every 0.8.0 writer writes.
CURRENT_SCHEMA_VERSION = "v1.0"

#: Every member of a payload: ``schemaVersion`` and the eleven hashed names, in byte order.
PAYLOAD_MEMBERS: tuple[str, ...] = tuple(sorted(("schemaVersion", *V1_HASHED_FIELDS), key=bytes_key))

#: The most canonical bytes a hashed object may have (a writer limit).
PAYLOAD_MAX_CANONICAL_BYTES = 256 * 1024
#: The longest ``action``, in characters.
ACTION_MAX_LENGTH = 128
#: The longest ``reason`` (and step ``reason``), in UTF-16 code units.
REASON_MAX_LENGTH = 16384
#: The ``aiSystemId`` prefix reserved for system records.
RESERVED_AI_SYSTEM_ID_PREFIX = "tzun:"
#: The reserved ``aiSystemId`` each system record kind admits.
SYSTEM_RECORD_AI_SYSTEM_IDS: dict[str, str] = {"mandate": "tzun:mandate", "link": "tzun:link"}

#: A v4 UUID, case-insensitive (the engine's ``EVIDENCE_ID_RE``).
EVIDENCE_ID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", re.ASCII
)
_ACTION_RE = re.compile(r"[\x20-\x7e]+", re.ASCII)

#: The model descriptor digest format.
MODEL_DESCRIPTOR_DIGEST_RE = re.compile(r"sha256:[a-f0-9]{64}", re.ASCII)
#: The most stop sequences an ``aiBom`` carries.
AI_BOM_MAX_STOP_SEQUENCES = 16
#: The longest stop sequence, and the longest ``infrastructure`` string, in UTF-16 code units.
AI_BOM_MAX_STRING_LENGTH = 256

_AI_BOM_KEYS = ("modelDescriptorDigest", "vendorFingerprint", "promptTemplate", "inferenceParameters", "infrastructure")
_PROMPT_TEMPLATE_KEYS = ("templateId", "templateDigest")
_INFERENCE_PARAMETER_KEYS = ("temperature", "topP", "maxTokens", "seed", "stopSequences")
_INFRASTRUCTURE_KEYS = ("provider", "region", "apiVersion", "endpoint")

_RENAMED_FIELDS = {"humanAction": "action", "humanReason": "reason", "reviewer": "decider"}
_MOVED_FIELDS = {"aiBom": "contributions.steps[].aiBom", "lineage": "links"}


def is_evidence_id(value: Any) -> bool:
    return isinstance(value, str) and EVIDENCE_ID_RE.fullmatch(value) is not None


def evidence_id_violation(evidence_id: Any) -> dict[str, str] | None:
    if not is_evidence_id(evidence_id):
        return {"code": "invalid_evidence_id", "field": "evidenceId", "message": "evidenceId must be a v4 UUID"}
    return None


def capture_time_violation(captured_at: Any) -> dict[str, str] | None:
    if not is_capture_time(captured_at):
        return {
            "code": "invalid_captured_at",
            "field": "capturedAt",
            "message": "capturedAt must be an ISO-8601 timestamp",
        }
    return None


#: How far ahead of the current time a client-chosen capturedAt may be (the engine's ``CAPTURED_AT_MAX_SKEW_MS``).
CAPTURED_AT_MAX_SKEW_MS = 5 * 60 * 1000


def captured_at_claim_violation(claim: Any, now_ms: int | None = None) -> str | None:
    """Why a client-chosen capturedAt is refused, or ``None`` (the engine's ``capturedAtViolation``).

    ``"unparsable"``: not an ISO-8601 date-time with a zone that ``Date.parse``
    reads. ``"future_dated"``: more than five minutes ahead of ``now_ms``
    (the current time when omitted).
    """
    if not is_capture_time(claim):
        return "unparsable"
    at = js_date_parse_ms(claim)
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if at is not None and at > now + CAPTURED_AT_MAX_SKEW_MS:
        return "future_dated"
    return None


def sequence_number_violation(sequence_number: Any) -> dict[str, str] | None:
    if not is_positive_safe_integer(sequence_number):
        return {
            "code": "invalid_sequence_number",
            "field": "sequenceNumber",
            "message": "sequenceNumber must be a safe integer of at least 1",
        }
    return None


def action_violation(action: Any) -> dict[str, str] | None:
    """``action``: 1 to 128 printable ASCII characters (0x20-0x7E), no leading or trailing space."""
    if (
        not isinstance(action, str)
        or not 1 <= len(action) <= ACTION_MAX_LENGTH
        or _ACTION_RE.fullmatch(action) is None
        or action.startswith(" ")
        or action.endswith(" ")
    ):
        return {
            "code": "invalid_action",
            "field": "action",
            "message": f"action must be 1 to {ACTION_MAX_LENGTH} printable ASCII characters (0x20-0x7E) "
            "with no leading or trailing space",
        }
    return None


def reason_violation(reason: Any, field: str = "reason") -> dict[str, str] | None:
    """A reason: 1 to 16,384 UTF-16 code units with no lone surrogate."""
    if (
        not isinstance(reason, str)
        or not 1 <= utf16_length(reason) <= REASON_MAX_LENGTH
        or has_lone_surrogate(reason)
    ):
        return {
            "code": "invalid_reason",
            "field": field,
            "message": f"{field} must be a string of 1 to {REASON_MAX_LENGTH} UTF-16 code units with no lone "
            "surrogate",
        }
    return None


def ai_system_id_violation(ai_system_id: Any, *, system_record: str | None = None) -> dict[str, str] | None:
    """``aiSystemId``: a non-empty string that is not a reserved ``tzun:`` id.

    ``None`` is refused here, as the engine refuses a payload's ``null``; a
    capture whose caller passes no ``aiSystemId`` writes the default and
    never asks.
    """
    if not isinstance(ai_system_id, str) or ai_system_id == "":
        return {"code": "invalid_ai_system_id", "field": "aiSystemId", "message": "aiSystemId must be a non-empty string"}
    admitted = SYSTEM_RECORD_AI_SYSTEM_IDS.get(system_record) if system_record is not None else None
    if ai_system_id.startswith(RESERVED_AI_SYSTEM_ID_PREFIX) and ai_system_id != admitted:
        return {
            "code": "reserved_ai_system_id",
            "field": "aiSystemId",
            "message": f'aiSystemId may not begin with "{RESERVED_AI_SYSTEM_ID_PREFIX}", which system records use',
        }
    return None


def ai_output_violation(ai_output: Any) -> dict[str, str] | None:
    if not isinstance(ai_output, dict):
        return {"code": "invalid_ai_output", "field": "aiOutput", "message": "aiOutput must be a plain object"}
    return None


def renamed_field_violation(value: Any) -> dict[str, str] | None:
    """A capture input or payload naming a renamed 0.7 field (``humanAction``, ``humanReason``, ``reviewer``)."""
    if not isinstance(value, dict):
        return None
    for field, renamed_to in _RENAMED_FIELDS.items():
        if field in value:
            return {
                "code": "renamed_field",
                "field": field,
                "renamedTo": renamed_to,
                "message": f"{field} was renamed: pass {renamed_to}",
            }
    return None


def moved_field_violation(value: Any) -> dict[str, str] | None:
    """A capture input or payload naming a moved 0.7 field (a top-level ``aiBom`` or ``lineage``)."""
    if not isinstance(value, dict):
        return None
    for field, moved_to in _MOVED_FIELDS.items():
        if field in value:
            return {"code": "moved_field", "field": field, "movedTo": moved_to, "message": f"{field} moved: pass {moved_to}"}
    return None


def unhashed_payload_members(payload: Any) -> list[str]:
    """The payload members outside the format's twelve names, sorted by bytes (Record §2.2)."""
    payload = plain(payload)
    if not isinstance(payload, dict):
        return []
    return sorted((k for k in payload if k not in PAYLOAD_MEMBERS), key=bytes_key)


def payload_size_violation(payload: dict[str, Any], hashed_field_set: tuple[str, ...] | list[str] = V1_HASHED_FIELDS) -> dict[str, str] | None:
    """The canonical bytes of the hashed object exceed 256 KiB."""
    try:
        size = utf8_length(canonical_serialize(payload, list(hashed_field_set)))
    except Exception:
        return None
    if size > PAYLOAD_MAX_CANONICAL_BYTES:
        return {
            "code": "payload_too_large",
            "field": "payload",
            "message": f"the hashed object's canonical bytes exceed {PAYLOAD_MAX_CANONICAL_BYTES}",
        }
    return None


# ── The step aiBom exact-keys rule (Record §7.4) ────────────────────────


def _fill_object(value: Any, keys: tuple[str, ...]) -> Any:
    if not isinstance(value, dict):
        return value
    out = dict(value)
    for key in keys:
        if key not in out:
            out[key] = None
    return out


def fill_ai_bom_nulls(value: Any) -> Any:
    """A copy of ``value`` with every absent nullable member written as ``None``.

    At the top level and inside ``promptTemplate``, ``inferenceParameters``
    and ``infrastructure`` when they are objects. A member the shape does not
    have is kept, so :func:`ai_bom_violation` then refuses it.
    """
    value = plain(value)
    if not isinstance(value, dict):
        return value
    out = _fill_object(value, tuple(k for k in _AI_BOM_KEYS if k != "modelDescriptorDigest"))
    out["promptTemplate"] = _fill_object(out["promptTemplate"], _PROMPT_TEMPLATE_KEYS)
    out["inferenceParameters"] = _fill_object(out["inferenceParameters"], _INFERENCE_PARAMETER_KEYS)
    out["infrastructure"] = _fill_object(out["infrastructure"], _INFRASTRUCTURE_KEYS)
    return out


def _nullable_string(value: Any, max_length: int | None = None) -> bool:
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    return max_length is None or utf16_length(value) <= max_length


def ai_bom_violation(value: Any, prefix: str = "aiBom") -> dict[str, str] | None:
    """Why ``value`` is not an exact ``AiBom``, or ``None`` (the engine's ``aiBomViolation``)."""
    value = plain(value)
    if not isinstance(value, dict):
        return {"field": prefix, "message": f"{prefix} must be an object"}
    if not has_exact_keys(value, _AI_BOM_KEYS):
        return {
            "field": prefix,
            "message": f"{prefix} must have exactly the members {', '.join(_AI_BOM_KEYS)}, nullable ones written as null",
        }
    digest = value["modelDescriptorDigest"]
    if not isinstance(digest, str) or MODEL_DESCRIPTOR_DIGEST_RE.fullmatch(digest) is None:
        return {
            "field": f"{prefix}.modelDescriptorDigest",
            "message": f"{prefix}.modelDescriptorDigest must be sha256: followed by 64 lowercase hex characters",
        }
    if not _nullable_string(value["vendorFingerprint"]):
        return {"field": f"{prefix}.vendorFingerprint", "message": f"{prefix}.vendorFingerprint must be a string or null"}
    pt = value["promptTemplate"]
    if pt is not None:
        f = f"{prefix}.promptTemplate"
        if not isinstance(pt, dict) or not has_exact_keys(pt, _PROMPT_TEMPLATE_KEYS):
            return {"field": f, "message": f"{f} must be null or have exactly the members templateId and templateDigest"}
        for k in _PROMPT_TEMPLATE_KEYS:
            if not _nullable_string(pt[k]):
                return {"field": f"{f}.{k}", "message": f"{f}.{k} must be a string or null"}
    ip = value["inferenceParameters"]
    if ip is not None:
        f = f"{prefix}.inferenceParameters"
        if not isinstance(ip, dict) or not has_exact_keys(ip, _INFERENCE_PARAMETER_KEYS):
            return {
                "field": f,
                "message": f"{f} must be null or have exactly the members {', '.join(_INFERENCE_PARAMETER_KEYS)}",
            }
        for k in ("temperature", "topP"):
            if ip[k] is not None and not is_finite_number(ip[k]):
                return {"field": f"{f}.{k}", "message": f"{f}.{k} must be a finite number or null"}
        if ip["maxTokens"] is not None and not is_non_negative_safe_integer(ip["maxTokens"]):
            return {"field": f"{f}.maxTokens", "message": f"{f}.maxTokens must be a non-negative safe integer or null"}
        if ip["seed"] is not None and not is_safe_integer(ip["seed"]):
            return {"field": f"{f}.seed", "message": f"{f}.seed must be a safe integer or null"}
        stops = ip["stopSequences"]
        if stops is not None and (
            not isinstance(stops, list)
            or len(stops) > AI_BOM_MAX_STOP_SEQUENCES
            or not all(isinstance(s, str) and utf16_length(s) <= AI_BOM_MAX_STRING_LENGTH for s in stops)
        ):
            return {
                "field": f"{f}.stopSequences",
                "message": f"{f}.stopSequences must be null or at most {AI_BOM_MAX_STOP_SEQUENCES} strings of at most "
                f"{AI_BOM_MAX_STRING_LENGTH} characters",
            }
    inf = value["infrastructure"]
    if inf is not None:
        f = f"{prefix}.infrastructure"
        if not isinstance(inf, dict) or not has_exact_keys(inf, _INFRASTRUCTURE_KEYS):
            return {"field": f, "message": f"{f} must be null or have exactly the members {', '.join(_INFRASTRUCTURE_KEYS)}"}
        for k in _INFRASTRUCTURE_KEYS:
            if not _nullable_string(inf[k], AI_BOM_MAX_STRING_LENGTH):
                return {
                    "field": f"{f}.{k}",
                    "message": f"{f}.{k} must be null or a string of at most {AI_BOM_MAX_STRING_LENGTH} characters",
                }
    return None


# ── Store generation (store-schema.ts) ──────────────────────────────────

#: The v1.0 hashed field set of 0.7.x (detection only).
FIELD_SET_0_7: tuple[str, ...] = tuple(V1_HASHED_FIELDS_0_7)
#: The v1.0 hashed field set before 0.7.0 (detection only).
FIELD_SET_BEFORE_0_7: tuple[str, ...] = tuple(V1_HASHED_FIELDS_BEFORE_0_7)


def _recomputes_under(payload: dict[str, Any], digest: str, fields: tuple[str, ...]) -> bool:
    try:
        return hashlib.sha256(canonical_serialize(payload, list(fields)).encode("utf-8")).hexdigest() == digest
    except Exception:
        return False


def _stored_parts(envelope: Any) -> tuple[dict[str, Any], str] | None:
    envelope = plain(envelope)
    if not isinstance(envelope, dict):
        return None
    payload = envelope.get("payload")
    integrity = envelope.get("integrity")
    if not isinstance(payload, dict) or not isinstance(integrity, dict):
        return None
    digest = integrity.get("canonicalDigest")
    if not isinstance(digest, str):
        return None
    return payload, digest


def record_field_set_generation(envelope: Any) -> str | None:
    """``"0.8"``, ``"0.7"``, ``"before-0.7"`` (the set the stored digest recomputes under) or ``None``."""
    parts = _stored_parts(envelope)
    if parts is None:
        return None
    payload, digest = parts
    if _recomputes_under(payload, digest, tuple(V1_HASHED_FIELDS)):
        return "0.8"
    if _recomputes_under(payload, digest, FIELD_SET_0_7):
        return "0.7"
    if _recomputes_under(payload, digest, FIELD_SET_BEFORE_0_7):
        return "before-0.7"
    return None


def earlier_field_set(payload: Any, stored_digest: Any) -> str | None:
    """The fact ``fieldSet`` on a mismatch: ``"0.7"`` or ``"before-0.7"`` when an older set reproduces the digest."""
    payload = plain(payload)
    if not isinstance(payload, dict) or not isinstance(stored_digest, str):
        return None
    if _recomputes_under(payload, stored_digest, FIELD_SET_0_7):
        return "0.7"
    if _recomputes_under(payload, stored_digest, FIELD_SET_BEFORE_0_7):
        return "before-0.7"
    return None


__all__ = (
    "ACTION_MAX_LENGTH",
    "AI_BOM_MAX_STOP_SEQUENCES",
    "AI_BOM_MAX_STRING_LENGTH",
    "CAPTURED_AT_MAX_SKEW_MS",
    "CURRENT_SCHEMA_VERSION",
    "EVIDENCE_ID_RE",
    "FIELD_SET_0_7",
    "FIELD_SET_BEFORE_0_7",
    "PAYLOAD_MAX_CANONICAL_BYTES",
    "PAYLOAD_MEMBERS",
    "REASON_MAX_LENGTH",
    "RESERVED_AI_SYSTEM_ID_PREFIX",
    "SYSTEM_RECORD_AI_SYSTEM_IDS",
    "action_violation",
    "ai_bom_violation",
    "ai_output_violation",
    "ai_system_id_violation",
    "capture_time_violation",
    "captured_at_claim_violation",
    "earlier_field_set",
    "evidence_id_violation",
    "fill_ai_bom_nulls",
    "is_evidence_id",
    "moved_field_violation",
    "payload_size_violation",
    "reason_violation",
    "record_field_set_generation",
    "renamed_field_violation",
    "sequence_number_violation",
    "unhashed_payload_members",
)
