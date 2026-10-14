"""OpenAI / Azure OpenAI connector.

Field mapping mirrors ``src/sdk/connectors/openai.ts``:

  params.temperature        → inferenceParameters.temperature
  params.top_p              → inferenceParameters.topP
  params.max_tokens         → inferenceParameters.maxTokens
  params.seed               → inferenceParameters.seed
  params.stop               → inferenceParameters.stopSequences
                              (str normalized to single-element list)
  response.system_fingerprint → vendorFingerprint
  response.model            → drives modelName/modelVersion resolution

Azure detection: ``params.__tzunIsAzure`` truthy OR ``azure_endpoint``
URL-shaped. On Azure, the deployment name in ``response.model`` is
reverse-looked-up against the known-models reference.
On a hit, the descriptor is rewritten to the underlying model. On a
miss, the deployment name passes through as the modelName (vendor-asserted).
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
    parse_model_id,
)
from tzun_sdk.models import InferenceParameters, Infrastructure, ModelDescriptor


def _normalize_stop(value: Any) -> list[str] | None:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        xs = [x for x in value if isinstance(x, str)]
        return xs if xs else None
    return None


def _is_azure(params: dict[str, Any]) -> bool:
    if params.get("__tzunIsAzure") is True:
        return True
    endpoint = as_string(params.get("azure_endpoint"))
    if endpoint and "openai.azure.com" in endpoint.lower():
        return True
    return False


def _vendor_asserted_descriptor(model_name: str, model_version: str) -> ModelDescriptor:
    return ModelDescriptor(
        descriptorVersion="d1",
        vendor="openai",
        modelName=model_name,
        modelVersion=model_version,
        integrityTier="vendor-asserted",
    )


def _resolve_azure_deployment(
    deployment_name: str, ref: dict[str, Any]
) -> dict[str, Any] | None:
    """Reverse-lookup a deployment name against the known-models reference.

    Matches entries with vendor=='openai' that carry an external identifier
    {scheme: 'azure-deployment-name', value: <deployment>}.
    Returns the matching entry dict or None (mirrors openai.ts:87-106).
    """
    for entry in ref.get("entries", []):
        # Support both dict and object-shaped entries
        vendor = entry.get("vendor") if isinstance(entry, dict) else getattr(entry, "vendor", None)
        if vendor != "openai":
            continue
        ext_ids = (
            entry.get("externalIdentifiers", [])
            if isinstance(entry, dict)
            else getattr(entry, "externalIdentifiers", []) or []
        )
        for ident in ext_ids:
            scheme = ident.get("scheme") if isinstance(ident, dict) else getattr(ident, "scheme", None)
            value = ident.get("value") if isinstance(ident, dict) else getattr(ident, "value", None)
            if scheme == "azure-deployment-name" and value == deployment_name:
                return entry if isinstance(entry, dict) else vars(entry)
    return None


class _OpenAiConnector:
    vendor = "openai"

    def build_ai_bom(
        self,
        params: dict[str, Any],
        response: dict[str, Any] | Any,
        known_models: dict[str, Any] | None = None,
    ) -> AiBomSkeleton | None:
        """Build an AiBomSkeleton from an OpenAI request/response pair.

        Args:
            params: Request kwargs.
            response: Response object (dict or typed response).
            known_models: Optional known-models reference dict. When provided
                and Azure is detected, the deployment name in response.model
                is reverse-looked-up. Defaults to the bundled catalog.
        """
        response_model = as_string(get_attr_or_item(response, "model"))
        if not response_model:
            return None

        is_azure = _is_azure(params)
        if is_azure and known_models is None:
            from tzun_sdk.ai_bom.known_models import load_known_models

            known_models = load_known_models()
        if is_azure:
            # Azure reverse-lookup. On hit: rewrite to underlying model.
            # On miss: deployment name passes through as vendor-asserted MVD.
            resolved = _resolve_azure_deployment(response_model, known_models)
            if (
                resolved
                and isinstance(resolved.get("modelName"), str)
                and isinstance(resolved.get("modelVersion"), str)
            ):
                # Synthesize the resolved underlying model id and split it.
                model_name = resolved["modelName"]
                model_version = resolved["modelVersion"]
                descriptor = _vendor_asserted_descriptor(model_name, model_version)
            else:
                # Pass-through: deployment name is the modelName; vendor-asserted.
                descriptor = _vendor_asserted_descriptor(response_model, "unknown")
        else:
            name, version = parse_model_id("openai", response_model)
            descriptor = _vendor_asserted_descriptor(name, version)

        # TS routes every connector through importFromVendor, which
        # overlays the known-models entry. Without this the two SDKs produce
        # different descriptor digests for the same vendor call.
        descriptor = enrich_from_known_models(descriptor, known_models)

        inference = InferenceParameters(
            temperature=as_number(params.get("temperature")),
            topP=as_number(params.get("top_p")),
            maxTokens=as_int(params.get("max_tokens")),
            seed=as_int(params.get("seed")),
            stopSequences=_normalize_stop(params.get("stop")),
        )

        infrastructure: Infrastructure | None = None
        if is_azure:
            infrastructure = Infrastructure(
                provider="azure",
                region=as_string(params.get("azure_region")),
                apiVersion=as_string(params.get("api_version")),
                endpoint=as_string(params.get("azure_endpoint")),
            )

        vendor_fingerprint = as_string(get_attr_or_item(response, "system_fingerprint"))
        return AiBomSkeleton(
            model_descriptor=descriptor,
            vendor_fingerprint=vendor_fingerprint,
            inference_parameters=inference,
            infrastructure=infrastructure,
        )


openai_connector = _OpenAiConnector()

__all__ = ("openai_connector",)
