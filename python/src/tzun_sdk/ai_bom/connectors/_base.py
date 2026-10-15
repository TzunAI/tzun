"""Connector protocol — ``build_ai_bom(params, response) -> AiBomSkeleton | None``.

Each connector is a stateless callable. Vendor SDK imports are lazy
 so importing ``tzun_sdk`` does not pull in any vendor library.
Connectors accept BOTH typed responses and plain dicts via
duck-typing: attribute access first, dict fallback, None on miss.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

from tzun_sdk.models import (
    InferenceParameters,
    Infrastructure,
    ModelDescriptor,
    PromptTemplate,
)


class AiBomSkeleton:
    """Connector output before catalog registration of the descriptor.

    The hook layer registers the descriptor (via the LRU cache) and
    rewrites the ``modelDescriptor`` field into a ``modelDescriptorDigest``
    on the final ``AiBom``. The skeleton carries the un-digested
    ``ModelDescriptor`` directly.
    """

    def __init__(
        self,
        *,
        model_descriptor: ModelDescriptor,
        vendor_fingerprint: str | None = None,
        prompt_template: PromptTemplate | None = None,
        inference_parameters: InferenceParameters | None = None,
        infrastructure: Infrastructure | None = None,
    ) -> None:
        self.model_descriptor = model_descriptor
        self.vendor_fingerprint = vendor_fingerprint
        self.prompt_template = prompt_template
        self.inference_parameters = inference_parameters
        self.infrastructure = infrastructure


class Connector(Protocol):
    """Vendor connector protocol."""

    vendor: str

    def build_ai_bom(
        self,
        params: dict[str, Any],
        response: dict[str, Any] | Any,
    ) -> AiBomSkeleton | None:
        """Extract an ``AiBomSkeleton`` from a (request, response) pair.

        Returns ``None`` if the call shape carries no resolvable model
        identity (e.g. response.model missing). MUST NOT raise on unknown
        fields: extraction is graceful, with ``None`` fallbacks.
        """
        ...


# ── Duck-typing helpers ────────────────────────────────────


def get_attr_or_item(obj: Any, name: str) -> Any:
    """Attribute access first, dict fallback. Returns ``None`` on miss."""
    if obj is None:
        return None
    if hasattr(obj, name):
        val = getattr(obj, name)
        if val is not None:
            return val
    if isinstance(obj, dict):
        return obj.get(name)
    return None


def as_string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            f = float(value)
        except (TypeError, ValueError):
            return None
        import math

        if math.isnan(f) or math.isinf(f):
            return None
        return f
    return None


def normalize_stop_sequences(value: Any) -> list[str] | None:
    """Mirror of TS ``normalizeStopSequences`` (e.g. vertex.ts:52-59).

    A bare string becomes a one-element list; a list keeps only its string
    members and collapses to ``None`` when nothing survives; anything else is
    ``None``. Shared by every connector so the three vendors that expose stop
    sequences cannot drift apart.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        xs = [x for x in value if isinstance(x, str)]
        return xs or None
    return None


def as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


# ── Vendor model-id parsing (byte parity with TS parseModelId) ───────

SupportedVendor = str
"""One of: openai, anthropic, bedrock, vertex, azure-ai, nvidia-nim, hf-inference,
openrouter."""

# JS `.` excludes exactly these four line terminators; Python's excludes only
# `\n`. Spelled out so the two parsers agree on ids containing `\r` etc.
_ANY = r"[^\n\r\u2028\u2029]"

# Trailing `-YYYY-MM-DD` snapshot date — OpenAI (`gpt-4o-2024-08-06`).
_OPENAI_DATE_SUFFIX = re.compile(rf"({_ANY}*)-([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})")
# Trailing `-YYYYMMDD` snapshot date — Anthropic (`claude-3-5-sonnet-20241022`).
# Anthropic never dashes the date; the dashed OpenAI form is deliberately NOT
# accepted here, since it matches no real Anthropic id.
_ANTHROPIC_SNAPSHOT_SUFFIX = re.compile(rf"({_ANY}*)-([0-9]{{8}})")
# Trailing numeric segment (1+ digits) — Vertex (`gemini-1.5-pro-002`).
_VERTEX_NUMERIC_SUFFIX = re.compile(rf"({_ANY}*)-([0-9]+)")
# Trailing `-vN:M` version:variant, optionally preceded by a 4-8 digit
# date-like run — Bedrock (`anthropic.claude-3-5-sonnet-20241022-v2:0`). The
# head is lazy so the optional date run lands in the version, not the name.
# A context-length variant after the `:M` (`...-v1:0:28k`, `:200k`) does not
# match: such an id is kept whole with 'unknown', as in TS.
_BEDROCK_VERSION_SUFFIX = re.compile(rf"({_ANY}+?)-((?:[0-9]{{4,8}}-)?v[0-9]+:[0-9]+)")


def parse_model_id(
    vendor: SupportedVendor,
    model_id: str,
    api_metadata: dict[str, Any] | None = None,
) -> tuple[str, str]:
    r"""Split a vendor-native model id into ``(modelName, modelVersion)``.

    Byte-for-byte port of TS ``parseModelId`` (src/models/import-vendor.ts),
    which documents the per-vendor rules. The single rule behind them: split
    out exactly the version segment the vendor's own id encodes, verbatim, so
    the bundled known-models catalog can be keyed on what a real
    ``response.model`` / ``modelId`` parses to. Every pattern is anchored to
    the whole id (``fullmatch`` — a bare ``$`` would also accept a trailing
    newline, which the JS anchor does not) and matches ASCII digits only
    (``[0-9]`` — ``\d`` would also accept Unicode digits, which JS's does not).

    ``api_metadata["modelVersion"]`` is the fallback only when the id encodes
    no version; ``hf-inference`` defaults to ``'main'`` instead of
    ``'unknown'`` per the Hugging Face revision convention. An ``openrouter``
    id is a slug: the whole served id, variant suffix (``:free``) included, is
    the ``modelName``, and no date is split out of it.
    """
    hint = None
    if isinstance(api_metadata, dict):
        hint_value = api_metadata.get("modelVersion")
        hint = hint_value if isinstance(hint_value, str) else None

    if vendor == "openai":
        m = _OPENAI_DATE_SUFFIX.fullmatch(model_id)
        if m:
            return m.group(1), m.group(2)
        return model_id, hint if hint is not None else "unknown"
    if vendor == "anthropic":
        m = _ANTHROPIC_SNAPSHOT_SUFFIX.fullmatch(model_id)
        if m:
            return m.group(1), m.group(2)
        return model_id, hint if hint is not None else "unknown"
    if vendor == "bedrock":
        m = _BEDROCK_VERSION_SUFFIX.fullmatch(model_id)
        if m:
            return m.group(1), m.group(2)
        return model_id, hint if hint is not None else "unknown"
    if vendor == "vertex":
        m = _VERTEX_NUMERIC_SUFFIX.fullmatch(model_id)
        if m:
            return m.group(1), m.group(2)
        return model_id, hint if hint is not None else "unknown"
    if vendor == "hf-inference":
        return model_id, hint if hint is not None else "main"
    if vendor in ("azure-ai", "nvidia-nim", "openrouter"):
        return model_id, hint if hint is not None else "unknown"
    raise ValueError(f"unsupported vendor for parse_model_id: {vendor!r}")


# ── OpenRouter ids (byte parity with TS) ─────────────────────────────
#
# String operations only, no regular expressions, so both SDKs yield the same
# strings for every input: ``find``/``rfind`` and slicing here, ``indexOf``/
# ``lastIndexOf`` and ``slice`` in TS (src/models/import-vendor.ts).


def openrouter_author(model_id: str) -> str | None:
    """OpenRouter's author prefix of a served id: the maker as the gateway names it.

    Port of TS ``openRouterAuthor``. The prefix is kept verbatim (``openai``,
    ``meta-llama``, ``x-ai``, ...). One leading ``~`` is dropped:
    ``~anthropic/claude-opus-latest`` is an alias in the maker's own
    namespace. An id with no ``author/`` prefix gives ``None``, and so does
    ``openrouter/*``: those ids name OpenRouter's routers
    (``openrouter/auto``), not a model maker.
    """
    model = model_id[1:] if model_id.startswith("~") else model_id
    slash = model.find("/")
    if slash <= 0:
        return None
    author = model[:slash]
    return None if author == "openrouter" else author


def openrouter_variant_base(model_id: str) -> str | None:
    """The base id of an OpenRouter id with a variant suffix, else ``None``.

    Port of TS ``openRouterVariantBase``: ``author/slug:variant`` gives
    ``author/slug``; an id with no ``/``, no ``:`` after the ``/``, or nothing
    after the last ``:`` carries no variant.
    """
    slash = model_id.find("/")
    colon = model_id.rfind(":")
    if slash < 0 or colon <= slash or colon == len(model_id) - 1:
        return None
    return model_id[:colon]


# ── Known-models enrichment (byte parity with TS) ────────────────────


def lookup_known_model(
    reference: dict[str, Any],
    vendor: str,
    model_name: str,
    model_version: str,
) -> dict[str, Any] | None:
    """Exact-match lookup on ``(vendor, modelName, modelVersion)``.

    Byte-for-byte port of TS ``lookupKnownModel`` (src/models/known-models.ts):
    case-sensitive, first match wins, ``None`` on a miss.
    """
    for entry in reference.get("entries", []) or []:
        if not isinstance(entry, dict):
            continue
        if (
            entry.get("vendor") == vendor
            and entry.get("modelName") == model_name
            and entry.get("modelVersion") == model_version
        ):
            return entry
    return None


_ENRICHABLE_SCALARS = (
    "modelType",
    "integrityTier",
    "modelDigest",
    "parentModelDescriptorDigest",
    "derivation",
    "trainedBy",
    "license",
    "modelCardUrl",
)


def merge_mvd_with_enrichment(
    mvd: ModelDescriptor,
    enrichment: dict[str, Any] | None,
) -> ModelDescriptor:
    """Overlay non-null enrichment fields on an MVD.

    Port of TS ``mergeMvdWithEnrichment`` (src/models/import-vendor.ts). The
    identity triple ``(vendor, modelName, modelVersion)`` and
    ``descriptorVersion`` come from the parsed vendor id and are never
    overwritten, even when the catalog entry disagrees. ``training`` merges
    field by field so a partial entry does not clobber the always-present
    nested shape; arrays replace as a unit when present.
    """
    if not enrichment:
        return mvd

    data = mvd.model_dump(mode="json", exclude_none=False)

    for key in _ENRICHABLE_SCALARS:
        value = enrichment.get(key)
        if value is not None:
            data[key] = value

    enr_training = enrichment.get("training")
    if isinstance(enr_training, dict):
        training = dict(data.get("training") or {})
        for key in ("trainingDataDigest", "trainingDataRef", "lastTrainingDate"):
            value = enr_training.get(key)
            if value is not None:
                training[key] = value
        if isinstance(enr_training.get("evaluations"), list):
            training["evaluations"] = enr_training["evaluations"]
        data["training"] = training

    if isinstance(enrichment.get("regulatoryMarkings"), list):
        data["regulatoryMarkings"] = enrichment["regulatoryMarkings"]
    if isinstance(enrichment.get("externalIdentifiers"), list):
        data["externalIdentifiers"] = enrichment["externalIdentifiers"]

    return ModelDescriptor.model_validate(data)


def enrich_from_known_models(
    mvd: ModelDescriptor,
    known_models: dict[str, Any] | None = None,
) -> ModelDescriptor:
    """Apply the bundled known-models overlay to a connector's MVD.

    Every TS connector routes through ``importFromVendor``, which performs this
    lookup and overlay, and every Python connector calls this. Because the
    descriptor is content-addressed, a connector that built a bare MVD would
    make the two SDKs register different rows, and put different
    ``aiBom.modelDescriptorDigest`` values into the hashed field set, for an
    identical vendor call. Either language yields a byte-identical AiBom.

    A catalog that cannot be loaded is not an error: the MVD is returned
    unchanged, exactly as a lookup miss would.

    For the ``openrouter`` vendor only, a miss on an id with a variant suffix
    (``:free``, ``:batch``, ...) retries with the base id, as TS
    ``importFromVendor`` does: the variant is the base model offered with its
    own limits or pricing, so it enriches from the base entry while keeping
    its own ``modelName``.
    """
    if known_models is None:
        try:
            from tzun_sdk.ai_bom.known_models import load_known_models

            known_models = load_known_models()
        except Exception:
            return mvd
    entry = lookup_known_model(
        known_models, mvd.vendor, mvd.modelName, mvd.modelVersion
    )
    if entry is None and mvd.vendor == "openrouter":
        base = openrouter_variant_base(mvd.modelName)
        if base is not None:
            entry = lookup_known_model(known_models, mvd.vendor, base, mvd.modelVersion)
    return merge_mvd_with_enrichment(mvd, entry)


__all__ = (
    "AiBomSkeleton",
    "Connector",
    "SupportedVendor",
    "as_int",
    "as_number",
    "as_string",
    "enrich_from_known_models",
    "get_attr_or_item",
    "lookup_known_model",
    "merge_mvd_with_enrichment",
    "normalize_stop_sequences",
    "openrouter_author",
    "openrouter_variant_base",
    "parse_model_id",
)
