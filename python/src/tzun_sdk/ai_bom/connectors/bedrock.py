"""AWS Bedrock connector.

Handles BOTH the ``Converse`` and ``InvokeModel`` boto3 client shapes.
Field mapping mirrors ``src/sdk/connectors/bedrock.ts``.
"""

from __future__ import annotations

import json
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
from tzun_sdk.models import InferenceParameters, Infrastructure, ModelDescriptor


def _params_from_converse(config: dict[str, Any]) -> InferenceParameters:
    """Mirror of TS ``paramsFromConverse`` in ``src/sdk/connectors/bedrock.ts``.

    Fields are read DIRECTLY from ``inferenceConfig``, never coalesced across
    Converse and InvokeModel spellings with ``pick("topP") or pick("top_p")``,
    which would drop a legitimate ``0``.
    """
    return InferenceParameters(
        temperature=as_number(config.get("temperature")),
        topP=as_number(config.get("topP")),
        maxTokens=as_int(config.get("maxTokens")),
        seed=None,
        stopSequences=normalize_stop_sequences(config.get("stopSequences")),
    )


def _params_from_invoke_model_body(body: str | bytes | bytearray) -> InferenceParameters:
    """Mirror of TS ``paramsFromInvokeModelBody`` in ``src/sdk/connectors/bedrock.ts``.

    The InvokeModel body carries VENDOR-NATIVE parameter names, so the
    spellings differ from Converse: ``top_p``, ``max_tokens``
    (Anthropic-on-Bedrock) or ``max_gen_len`` (Llama-on-Bedrock), and
    ``stop_sequences``. ``max_tokens`` wins when both are present, exactly as
    TS's ``??`` does, so a ``max_tokens`` of 0 still beats ``max_gen_len``.

    The body is ``str``, ``bytes`` or ``bytearray`` (boto3 hands over either),
    as TS reads a string or a ``Uint8Array``. A malformed or non-object body
    yields all-null parameters — the descriptor still rides on modelId.
    """
    try:
        parsed = json.loads(body)
    except Exception:
        return InferenceParameters()
    if not isinstance(parsed, dict):
        return InferenceParameters()
    max_tokens = as_int(parsed.get("max_tokens"))
    if max_tokens is None:
        max_tokens = as_int(parsed.get("max_gen_len"))
    return InferenceParameters(
        temperature=as_number(parsed.get("temperature")),
        topP=as_number(parsed.get("top_p")),
        maxTokens=max_tokens,
        seed=None,
        stopSequences=normalize_stop_sequences(parsed.get("stop_sequences")),
    )


class _BedrockConnector:
    vendor = "bedrock"

    def build_ai_bom(
        self,
        params: dict[str, Any],
        response: dict[str, Any] | Any,
    ) -> AiBomSkeleton | None:
        model_id = as_string(params.get("modelId")) or as_string(
            get_attr_or_item(response, "modelId")
        )
        if not model_id:
            return None
        # The shared parser splits `provider.model-date-vN:M` at `-vN:M`, the
        # split the bundled Bedrock entries are keyed on; the whole id as the
        # modelName with modelVersion 'unknown' would never match them.
        name, version = parse_model_id("bedrock", model_id)
        descriptor = ModelDescriptor(
            descriptorVersion="d1",
            vendor="bedrock",
            modelName=name,
            modelVersion=version,
            integrityTier="vendor-asserted",
        )

        # TS routes every connector through importFromVendor, which
        # overlays the known-models entry on the MVD. Without this the two SDKs
        # produce different descriptor digests for the same vendor call.
        descriptor = enrich_from_known_models(descriptor)
        # Surface dispatch, mirroring TS ``buildAiBom``: Converse beats
        # InvokeModel when both shapes are present. The two surfaces are NOT
        # merged — a Converse call reads inferenceConfig and nothing else, so
        # the vendor-native body spellings can never bleed into it.
        inference_config = params.get("inferenceConfig")
        inference_config = inference_config if isinstance(inference_config, dict) else None
        body = params.get("body")
        if inference_config is not None:
            inference = _params_from_converse(inference_config)
        elif isinstance(body, (str, bytes, bytearray)) and body:
            inference = _params_from_invoke_model_body(body)
        else:
            inference = InferenceParameters()
        region = as_string(params.get("region"))
        infrastructure: Infrastructure | None = None
        if region:
            infrastructure = Infrastructure(provider="aws-bedrock", region=region)
        return AiBomSkeleton(
            model_descriptor=descriptor,
            inference_parameters=inference,
            infrastructure=infrastructure,
        )


bedrock_connector = _BedrockConnector()

__all__ = ("bedrock_connector",)
