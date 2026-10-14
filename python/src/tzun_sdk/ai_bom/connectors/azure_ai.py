"""Azure AI Inference (non-OpenAI Azure) connector."""

from __future__ import annotations

from typing import Any

from tzun_sdk.ai_bom.connectors._base import (
    AiBomSkeleton,
    as_int,
    as_number,
    as_string,
    enrich_from_known_models,
    get_attr_or_item,
    parse_model_id,
)
from tzun_sdk.models import InferenceParameters, Infrastructure, ModelDescriptor


class _AzureAiConnector:
    vendor = "azure_ai"

    def build_ai_bom(
        self,
        params: dict[str, Any],
        response: dict[str, Any] | Any,
    ) -> AiBomSkeleton | None:
        model_id = (
            as_string(get_attr_or_item(response, "model"))
            or as_string(params.get("model"))
        )
        if not model_id:
            return None
        # Deployment-name surface: the whole id is the name, nothing encodes a
        # version (shared parser, byte parity with TS parseModelId).
        model_name, model_version = parse_model_id("azure-ai", model_id)
        descriptor = ModelDescriptor(
            descriptorVersion="d1",
            vendor="azure-ai",
            modelName=model_name,
            modelVersion=model_version,
            integrityTier="vendor-asserted",
        )

        # TS routes every connector through importFromVendor, which
        # overlays the known-models entry on the MVD. Without this the two SDKs
        # produce different descriptor digests for the same vendor call.
        descriptor = enrich_from_known_models(descriptor)
        inference = InferenceParameters(
            temperature=as_number(params.get("temperature")),
            topP=as_number(params.get("top_p")),
            maxTokens=as_int(params.get("max_tokens")),
        )
        endpoint = as_string(params.get("endpoint"))
        infrastructure: Infrastructure | None = None
        if endpoint:
            infrastructure = Infrastructure(provider="azure-ai", endpoint=endpoint)
        return AiBomSkeleton(
            model_descriptor=descriptor,
            inference_parameters=inference,
            infrastructure=infrastructure,
        )


azure_ai_connector = _AzureAiConnector()

__all__ = ("azure_ai_connector",)
