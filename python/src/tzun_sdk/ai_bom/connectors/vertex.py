"""Google Vertex AI connector.

Handles both ``generateContent`` and ``predict`` request shapes.
Field mapping mirrors ``src/sdk/connectors/vertex.ts``.
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
from tzun_sdk.models import InferenceParameters, Infrastructure, ModelDescriptor


def _params_from_vertex_config(config: dict[str, Any]) -> InferenceParameters:
    """Mirror of TS ``paramsFromVertexConfig`` (vertex.ts:82-90).

    Both Vertex surfaces carry the same field shape under different keys:
    ``generationConfig`` for generateContent, ``parameters`` for predict.

    Every field is read DIRECTLY, never coalesced with ``a or b``, which would
    silently turn a legitimate ``0`` — the standard setting for a
    deterministic decision — into ``None``.

    ``seed`` is hard-coded ``None`` to match TS, which does not extract a seed
    on either Vertex surface.
    """
    return InferenceParameters(
        temperature=as_number(config.get("temperature")),
        topP=as_number(config.get("topP")),
        maxTokens=as_int(config.get("maxOutputTokens")),
        seed=None,
        stopSequences=normalize_stop_sequences(config.get("stopSequences")),
    )


class _VertexConnector:
    vendor = "vertex"

    def build_ai_bom(
        self,
        params: dict[str, Any],
        response: dict[str, Any] | Any,
    ) -> AiBomSkeleton | None:
        # generateContent: model id from params.model (may be full resource path)
        # predict: model id from endpoint resource path, fallback to params.model
        # Mirrors TS vertex.ts dispatch (generateContent wins when both present).
        gen_config = params.get("generationConfig")
        instances = params.get("instances")
        endpoint = as_string(params.get("endpoint"))
        model_id: str | None = None
        if gen_config is not None or instances is None:
            # generateContent path: use params.model directly (full path or short id)
            model_id = as_string(params.get("model"))
        if model_id is None:
            # predict path: extract from endpoint resource path, fallback to params.model
            if endpoint:
                import re
                m = re.search(r"publishers/[^/]+/models/([^/]+)$", endpoint)
                model_id = m.group(1) if m else as_string(params.get("model"))
            else:
                model_id = as_string(params.get("model"))
        if not model_id:
            model_id = as_string(get_attr_or_item(response, "model"))
        if not model_id:
            return None
        # Trailing numeric suffix splits off as the version; otherwise the full
        # id is the name (shared parser, byte parity with TS parseModelId).
        model_name, model_version = parse_model_id("vertex", model_id)
        descriptor = ModelDescriptor(
            descriptorVersion="d1",
            vendor="vertex",
            modelName=model_name,
            modelVersion=model_version,
            integrityTier="vendor-asserted",
        )

        # TS routes every connector through importFromVendor, which
        # overlays the known-models entry on the MVD. Without this the two SDKs
        # produce different descriptor digests for the same vendor call.
        descriptor = enrich_from_known_models(descriptor)
        # Surface dispatch for inference parameters, mirroring TS
        # vertex.ts:100-135: generationConfig wins; otherwise the predict
        # surface reads params["parameters"]; otherwise all-null. Top-level
        # params.temperature etc. are NOT a fallback in either language.
        gen_config_rec = params.get("generationConfig")
        gen_config_rec = gen_config_rec if isinstance(gen_config_rec, dict) else None
        predict_params = params.get("parameters")
        predict_params = predict_params if isinstance(predict_params, dict) else None
        has_instances = isinstance(params.get("instances"), list)
        if gen_config_rec is not None:
            inference = _params_from_vertex_config(gen_config_rec)
        elif has_instances and predict_params is not None:
            inference = _params_from_vertex_config(predict_params)
        else:
            inference = InferenceParameters()
        location = as_string(params.get("location"))
        infrastructure: Infrastructure | None = None
        if location:
            infrastructure = Infrastructure(provider="gcp-vertex", region=location)
        return AiBomSkeleton(
            model_descriptor=descriptor,
            inference_parameters=inference,
            infrastructure=infrastructure,
        )


vertex_connector = _VertexConnector()

__all__ = ("vertex_connector",)
