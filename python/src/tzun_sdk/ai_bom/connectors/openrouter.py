"""OpenRouter gateway connector.

Port of ``src/sdk/connectors/openrouter.ts``. OpenRouter (https://openrouter.ai)
serves models of many makers through one OpenAI-compatible chat-completions
API and routes each call to an upstream provider. A record of such a call
states four things, each as the gateway reported it, and nothing it did not
report:

- who served it: the descriptor's ``vendor`` is ``openrouter``, and
  ``infrastructure.endpoint`` is the gateway URL the client called;
- which model it served: ``modelName`` is ``response.model`` verbatim, variant
  suffix (``:free``, ``:batch``, ...) included, with ``modelVersion: 'unknown'``;
- who made it: ``trainedBy`` is the author prefix of that id (``nvidia``,
  ``meta-llama``, ``x-ai``, ...), or ``None`` for OpenRouter's own routers
  (``openrouter/*``);
- which upstream ran it: ``infrastructure.provider`` is ``response.provider``
  verbatim (``"Nvidia"``, ``"Google AI Studio"``, ...), OpenRouter's own name
  for the provider it routed the call to.

The integrity tier is ``vendor-asserted``, the asserting vendor being the
gateway: nothing here is attested by the maker.

Field mapping::

  response.model              → modelName (no AI-BOM without it; never
                                params["model"], which a fallback list or a
                                router may not have served)
  response.system_fingerprint → vendorFingerprint (never response.id, a
                                per-call generation id)
  response.provider           → infrastructure.provider (1..256 UTF-16 code
                                units, else None)
  params.openrouter_endpoint  → infrastructure.endpoint (a client hint, set by
                                attach() from the client's base URL or passed
                                to hook(); never assumed)
  params.temperature          → inferenceParameters.temperature
  params.top_p                → inferenceParameters.topP
  params.max_tokens           → inferenceParameters.maxTokens (non-negative
                                safe integer, else None)
  params.seed                 → inferenceParameters.seed (safe integer, else
                                None)
  params.stop                 → inferenceParameters.stopSequences
                                (str → [str]; None when there are more
                                than 16 or one is over 256 UTF-16 code
                                units)

``params["provider"]`` (OpenRouter's routing preferences), ``models``,
``route``, ``transforms``, ``reasoning`` and ``usage`` are request options, not
AI-BOM members, and are not read.

The URL helpers use string operations only: ``urllib.parse`` and JavaScript's
``URL`` disagree on host case, default ports and IDNA, which would make the two
SDKs record different strings for one client. They follow the TS helpers step
for step, and lengths are measured in UTF-16 code units, as JavaScript's
``String.length`` measures them. ``openrouter_endpoint`` lowercases the ASCII
letters of the host and drops the scheme's default port, as openai-python's
``httpx.URL`` base URL already does, so a client configured as
``https://OpenRouter.AI:443/api/v1`` records the same endpoint through either
SDK's ``attach()``. httpx also IDNA-encodes a non-ASCII host,
percent-encodes some path characters and reads a port written with leading
zeros (``:0443``) as a number; such a base URL may still be recorded
differently by the two ``attach()`` paths.

No I/O is performed. Same input → same output.
"""

from __future__ import annotations

from typing import Any

from tzun_sdk._record_rules import utf16_length
from tzun_sdk.ai_bom.connectors._base import (
    AiBomSkeleton,
    as_int,
    as_number,
    as_string,
    enrich_from_known_models,
    get_attr_or_item,
    normalize_stop_sequences,
    openrouter_author,
    parse_model_id,
)
from tzun_sdk.models import InferenceParameters, Infrastructure, ModelDescriptor
from tzun_sdk.payload_rules import AI_BOM_MAX_STOP_SEQUENCES, AI_BOM_MAX_STRING_LENGTH

#: ``Number.MAX_SAFE_INTEGER``: the largest integer both SDKs carry exactly.
_MAX_SAFE_INTEGER = 2**53 - 1


# ── Field-extraction helpers ──────────────────────────────────────


def _as_safe_integer(value: Any) -> int | None:
    """A safe integer, else ``None``: an AI-BOM ``seed`` that is anything else fails capture.

    TS ``Number.isSafeInteger``: ``as_int`` refuses a ``bool`` and accepts an
    integral float, and the bound refuses what JavaScript cannot hold exactly.
    """
    n = as_int(value)
    return n if n is not None and -_MAX_SAFE_INTEGER <= n <= _MAX_SAFE_INTEGER else None


def _as_non_negative_safe_integer(value: Any) -> int | None:
    """A non-negative safe integer, else ``None`` (the AI-BOM ``maxTokens`` rule)."""
    n = _as_safe_integer(value)
    return n if n is not None and n >= 0 else None


def _bounded_string(value: Any) -> str | None:
    """A string of 1..256 UTF-16 code units, else ``None`` (an ``infrastructure`` member's limit)."""
    if isinstance(value, str) and 0 < utf16_length(value) <= AI_BOM_MAX_STRING_LENGTH:
        return value
    return None


def _bounded_stops(value: Any) -> list[str] | None:
    """The stop sequences an AI-BOM can carry: at most 16, each at most 256 UTF-16 code units.

    Port of TS ``boundedStops``. Anything else is ``None`` as a whole, never
    truncated: a partial list would misstate the request, and an over-long one
    would turn the capture into a validation failure.
    """
    xs = normalize_stop_sequences(value)
    if xs is None or len(xs) > AI_BOM_MAX_STOP_SEQUENCES:
        return None
    return xs if all(utf16_length(x) <= AI_BOM_MAX_STRING_LENGTH for x in xs) else None


# ── Base-URL handling ─────────────────────────────────────────────


def _split_http_url(value: Any) -> tuple[str, str, str] | None:
    """Split an ``http(s)://`` URL into ``(scheme, authority, path)``.

    The authority is without userinfo and the path without query or fragment,
    by string operations only. ``None`` for a value that is not a string, has
    another scheme (the match is case-sensitive), or has an empty authority.
    """
    if not isinstance(value, str):
        return None
    if value.startswith("https://"):
        scheme = "https://"
    elif value.startswith("http://"):
        scheme = "http://"
    else:
        return None
    rest = value[len(scheme) :]
    # Drop the query and the fragment: cut at the first `?` or `#`.
    for i, ch in enumerate(rest):
        if ch in ("?", "#"):
            rest = rest[:i]
            break
    slash = rest.find("/")
    authority = rest if slash < 0 else rest[:slash]
    path = "" if slash < 0 else rest[slash:]
    # Drop the userinfo (`user:password@`).
    authority = authority[authority.rfind("@") + 1 :]
    if not authority:
        return None
    return scheme, authority, path


def _ascii_lower(value: str) -> str:
    """ASCII ``A``-``Z`` to ``a``-``z``, nothing else (Python and JS case-map other characters differently)."""
    return "".join(chr(ord(ch) + 0x20) if "A" <= ch <= "Z" else ch for ch in value)


def openrouter_endpoint(value: Any) -> str | None:
    """The gateway endpoint an ``infrastructure`` block records for a base URL.

    Port of TS ``openRouterEndpoint``: scheme, host and path, with userinfo,
    query, fragment and trailing ``/`` removed (openai-python's ``base_url``
    ends with ``/``, openai-node's ``baseURL`` does not; both record
    ``https://openrouter.ai/api/v1``). The host's ASCII letters are lowercased
    and the scheme's default port (``:443`` for https, ``:80`` for http) is
    dropped, as ``httpx.URL`` does, so ``https://OpenRouter.AI:443/api/v1/``
    records ``https://openrouter.ai/api/v1``. The path is kept as given.
    ``None`` when the value is not an ``http(s)://`` URL, the host is empty, or
    the result is longer than 256 UTF-16 code units.
    """
    parts = _split_http_url(value)
    if parts is None:
        return None
    scheme, authority, path = parts
    authority = _ascii_lower(authority)
    default_port = ":443" if scheme == "https://" else ":80"
    if authority.endswith(default_port):
        authority = authority[: -len(default_port)]
    if not authority:
        return None
    while path.endswith("/"):
        path = path[:-1]
    out = scheme + authority + path
    return out if utf16_length(out) <= AI_BOM_MAX_STRING_LENGTH else None


def is_openrouter_base_url(value: Any) -> bool:
    """Whether a client's base URL points at OpenRouter.

    Port of TS ``isOpenRouterBaseUrl``: the host, without the port and
    compared case-insensitively, is ``openrouter.ai``.
    """
    parts = _split_http_url(value)
    if parts is None:
        return False
    authority = parts[1]
    colon = authority.rfind(":")
    host = authority if colon < 0 else authority[:colon]
    return host.lower() == "openrouter.ai"


# ── Connector implementation ──────────────────────────────────────


class _OpenRouterConnector:
    vendor = "openrouter"

    def build_ai_bom(
        self,
        params: dict[str, Any],
        response: dict[str, Any] | Any,
        known_models: dict[str, Any] | None = None,
    ) -> AiBomSkeleton | None:
        """Build an AiBomSkeleton from an OpenRouter chat-completions call.

        Args:
            params: Request kwargs, plus the ``openrouter_endpoint`` hint when
                the caller or ``attach()`` supplies one.
            response: Response object (dict or typed response).
            known_models: Optional known-models reference dict. Defaults to
                the bundled catalog.
        """
        # The served id, as the gateway names it. Never params["model"]: with
        # a `models` fallback list or a router (`openrouter/auto`) the
        # requested id is not necessarily the one that served the call.
        served = as_string(get_attr_or_item(response, "model"))
        if not served:
            return None

        model_name, model_version = parse_model_id("openrouter", served)
        descriptor = ModelDescriptor(
            descriptorVersion="d1",
            vendor="openrouter",
            modelName=model_name,
            modelVersion=model_version,
            integrityTier="vendor-asserted",
            # The maker, as the gateway states it. Set before enrichment, so
            # an entry's own `trainedBy` would overlay it, as in TS; the
            # bundled OpenRouter entries carry none.
            trainedBy=openrouter_author(model_name),
        )
        descriptor = enrich_from_known_models(descriptor, known_models)

        inference = InferenceParameters(
            temperature=as_number(params.get("temperature")),
            topP=as_number(params.get("top_p")),
            maxTokens=_as_non_negative_safe_integer(params.get("max_tokens")),
            seed=_as_safe_integer(params.get("seed")),
            stopSequences=_bounded_stops(params.get("stop")),
        )
        infrastructure = Infrastructure(
            provider=_bounded_string(get_attr_or_item(response, "provider")),
            region=None,
            apiVersion=None,
            endpoint=openrouter_endpoint(params.get("openrouter_endpoint")),
        )
        return AiBomSkeleton(
            model_descriptor=descriptor,
            vendor_fingerprint=as_string(get_attr_or_item(response, "system_fingerprint")),
            inference_parameters=inference,
            infrastructure=infrastructure,
        )


openrouter_connector = _OpenRouterConnector()

__all__ = ("is_openrouter_base_url", "openrouter_connector", "openrouter_endpoint")
