"""Anthropic connector.

Field mapping mirrors ``src/sdk/connectors/anthropic.ts``:

  params.temperature      → inferenceParameters.temperature
  params.top_p            → inferenceParameters.topP
  params.max_tokens       → inferenceParameters.maxTokens
  params.stop_sequences   → inferenceParameters.stopSequences
  response.model          → modelName / modelVersion
"""

from __future__ import annotations

from typing import Any

from tzun_sdk.ai_bom.connectors._base import (
    AiBomSkeleton,
    as_int,
    as_number,
    as_string,
    enrich_from_known_models,
    get_attr_or_item,
    normalize_stop_sequences,
    parse_model_id,
)
from tzun_sdk.models import InferenceParameters, ModelDescriptor


class _AnthropicConnector:
    vendor = "anthropic"

    def build_ai_bom(
        self,
        params: dict[str, Any],
        response: dict[str, Any] | Any,
    ) -> AiBomSkeleton | None:
        response_model = as_string(get_attr_or_item(response, "model"))
        if not response_model:
            return None
        # Real Anthropic snapshot ids end in an undashed `-YYYYMMDD`
        # (`claude-3-5-sonnet-20240620`); the shared parser splits it off. A
        # dashed `-YYYY-MM-DD` rule would match no real id.
        name, version = parse_model_id("anthropic", response_model)
        descriptor = ModelDescriptor(
            descriptorVersion="d1",
            vendor="anthropic",
            modelName=name,
            modelVersion=version,
            integrityTier="vendor-asserted",
        )

        # TS routes every connector through importFromVendor, which
        # overlays the known-models entry on the MVD. Without this the two SDKs
        # produce different descriptor digests for the same vendor call.
        descriptor = enrich_from_known_models(descriptor)
        stops = normalize_stop_sequences(params.get("stop_sequences"))
        inference = InferenceParameters(
            temperature=as_number(params.get("temperature")),
            topP=as_number(params.get("top_p")),
            maxTokens=as_int(params.get("max_tokens")),
            stopSequences=stops,
        )
        return AiBomSkeleton(
            model_descriptor=descriptor,
            inference_parameters=inference,
        )


anthropic_connector = _AnthropicConnector()

__all__ = ("anthropic_connector",)
