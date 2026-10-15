"""Cross-SDK connector parity.

For each of the six Python connectors (openai, anthropic, bedrock, vertex,
azure_ai, openrouter), runs the shared fixture files through both the Python
connector and the TS connector via the ts-harness, then compares the extracted
model identity (vendor, modelName, modelVersion) and inference parameters.

The full ModelDescriptor is compared for equality, not only the identity
triple. The AiBom must be byte-identical from either language, and the
descriptor is content-addressed, so a Python descriptor without the
known-models enrichment the TS connector's ``importFromVendor`` applies would
put a different ``modelDescriptorDigest`` into the hashed field set for the
same vendor call. Both SDKs apply the same known-models overlay, and this gate
asserts it field by field.

Azure hit/miss cases are included to verify that the Azure connector's
decision tree agrees across languages.

For openrouter the whole ``infrastructure`` block is compared too, null members
included: it is the one connector that always writes it, and its ``provider``
and ``endpoint`` are what say the gateway served the call.
"""

from __future__ import annotations

import json
import pathlib

import pytest

FIXTURES_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent / "python" / "tests" / "ai_bom" / "connectors" / "fixtures"

# Map Python connector module name → TS registry key
VENDOR_MAP = {
    "openai": "openai",
    "anthropic": "anthropic",
    "bedrock": "bedrock",
    "vertex": "vertex",
    "azure_ai": "azure-ai",
    "openrouter": "openrouter",
}

# Three-case fixtures that exist for every vendor
BASE_CASES = ["happy", "optional_fields_populated", "optional_fields_absent"]

# Vendor-specific extra fixtures. The recorded corpus held
# no zero-valued inference parameter and no string-form `stop`, so a connector
# that dropped a falsy 0 (`params.temperature || undefined` on one side,
# `as_number(0) -> 0.0` on the other) or normalized the string form differently
# diverged with this gate still green. Named explicitly rather than globbed, so
# a fixture that goes missing fails the run instead of shrinking it.
EXTRA_CASES = {
    "openai": ["zero_valued", "stop_sequences"],
    "anthropic": ["zero_valued"],
    "openrouter": [
        "zero_valued",
        "stop_string",
        "stop_over_limits",
        "alias_id",
        "router_id",
        "endpoint_normalized",
        "overlong_strings",
        "non_integer_tokens",
    ],
}

ALL_CASES = [
    (v, c)
    for v in ["openai", "anthropic", "bedrock", "vertex", "azure_ai", "openrouter"]
    for c in BASE_CASES + EXTRA_CASES.get(v, [])
]


def _load_py_connector(vendor_module: str):
    if vendor_module == "openai":
        from tzun_sdk.ai_bom.connectors.openai import openai_connector
        return openai_connector
    elif vendor_module == "anthropic":
        from tzun_sdk.ai_bom.connectors.anthropic import anthropic_connector
        return anthropic_connector
    elif vendor_module == "bedrock":
        from tzun_sdk.ai_bom.connectors.bedrock import bedrock_connector
        return bedrock_connector
    elif vendor_module == "vertex":
        from tzun_sdk.ai_bom.connectors.vertex import vertex_connector
        return vertex_connector
    elif vendor_module == "azure_ai":
        from tzun_sdk.ai_bom.connectors.azure_ai import azure_ai_connector
        return azure_ai_connector
    elif vendor_module == "openrouter":
        from tzun_sdk.ai_bom.connectors.openrouter import openrouter_connector
        return openrouter_connector
    raise ValueError(f"Unknown vendor module: {vendor_module}")


def _identity(descriptor: dict) -> dict:
    """Extract the parity-compared identity fields from a ModelDescriptor."""
    return {
        "vendor": descriptor.get("vendor"),
        "modelName": descriptor.get("modelName"),
        "modelVersion": descriptor.get("modelVersion"),
    }


def _inf_params(skeleton: dict | None) -> dict:
    """Normalize inferenceParameters for comparison (None-safe).

    Both sides are reduced to "the keys that carry a value", so a field one SDK
    omits and the other emits as explicit null still compares equal — but a
    field one SDK drops as falsy (0) and the other keeps does NOT. That is the
    divergence class this normalizer exists to expose.
    """
    if not skeleton:
        return {}
    ip = skeleton.get("inferenceParameters") or {}
    if not ip:
        return {}
    # Compare only the fields both sides extract
    return {k: v for k, v in ip.items() if v is not None}


def _py_inf_params(py_skeleton) -> dict:  # type: ignore[no-untyped-def]
    """`_inf_params` over the Python skeleton, in the TS skeleton's shape."""
    ip = py_skeleton.inference_parameters
    if ip is None:
        return {}
    return _inf_params({"inferenceParameters": ip.model_dump(mode="json", exclude_none=False)})


def test_connector_parity_corpus_is_not_empty() -> None:
    """Guard: the parity corpus must be non-empty and every named fixture present.

    The case list is enumerated explicitly and checked here before anything
    runs, so deleting or renaming the fixture tree fails the gate instead of
    turning the whole cross-language connector gate into zero assertions that
    still report green.
    """
    assert ALL_CASES, "connector parity corpus is empty"
    missing = [
        f"{v}/{c}.json"
        for v, c in ALL_CASES
        if not (FIXTURES_ROOT / v / f"{c}.json").exists()
    ]
    assert not missing, (
        f"connector parity fixtures missing under {FIXTURES_ROOT}: {missing}. "
        "A missing fixture must fail the gate, never silently shrink it."
    )
    # Every vendor in VENDOR_MAP must actually be exercised.
    covered = {v for v, _ in ALL_CASES}
    assert covered == set(VENDOR_MAP), (
        f"vendors in VENDOR_MAP but not in the corpus: {set(VENDOR_MAP) - covered}"
    )


@pytest.mark.parametrize("vendor_module,case", ALL_CASES)
def test_identity_parity(vendor_module: str, case: str, ts_invoke) -> None:
    """Both sides extract the same identity, descriptor AND inference params."""
    fixture_path = FIXTURES_ROOT / vendor_module / f"{case}.json"
    assert fixture_path.exists(), (
        f"Fixture not found: {fixture_path}. A missing fixture fails rather than "
        "skips, so a renamed fixture tree cannot disable the gate silently."
    )
    fx = json.loads(fixture_path.read_text())
    req, resp = fx["request"], fx["response"]

    # Python side
    py_connector = _load_py_connector(vendor_module)
    py_skeleton = py_connector.build_ai_bom(req, resp)

    # TS side
    ts_vendor = VENDOR_MAP[vendor_module]
    ts_result = ts_invoke({
        "action": "connector",
        "vendor": ts_vendor,
        "request": req,
        "response": resp,
    })
    ts_skeleton = ts_result.get("skeleton")

    # A one-sided None IS the divergence, not a reason to stand down: a skip
    # here would let a connector that stops recognising a payload in exactly
    # one language pass this gate.
    assert (py_skeleton is None) == (ts_skeleton is None), (
        f"{vendor_module}/{case}: one connector recognised the payload and the "
        f"other did not — Python={'None' if py_skeleton is None else 'skeleton'}, "
        f"TS={'None' if ts_skeleton is None else 'skeleton'}. That is a parity "
        f"failure: the same vendor call would produce an AI-BOM in one SDK and "
        f"no aiBom (and therefore different canonical bytes) in the other."
    )
    assert py_skeleton is not None, (
        f"{vendor_module}/{case}: both connectors returned None. Every fixture in "
        f"the parity corpus is a recorded real call and must produce a skeleton."
    )

    # Compare model identity
    py_id = {
        "vendor": py_skeleton.model_descriptor.vendor,
        "modelName": py_skeleton.model_descriptor.modelName,
        "modelVersion": py_skeleton.model_descriptor.modelVersion,
    }
    ts_id = _identity(ts_skeleton.get("modelDescriptor", {}))
    assert py_id == ts_id, (
        f"{vendor_module}/{case} identity mismatch:\n"
        f"  Python: {py_id}\n"
        f"  TS:     {ts_id}"
    )

    # The whole descriptor, not just the identity triple. The
    # descriptor is content-addressed, so any field that differs changes
    # `aiBom.modelDescriptorDigest` — which IS inside the hashed field set.
    py_descriptor = py_skeleton.model_descriptor.model_dump(
        mode="json", exclude_none=False
    )
    ts_descriptor = ts_skeleton.get("modelDescriptor", {})
    assert py_descriptor == ts_descriptor, (
        f"{vendor_module}/{case} descriptor mismatch:\n"
        f"  Python: {py_descriptor}\n"
        f"  TS:     {ts_descriptor}"
    )

    # Inference parameters. `_inf_params` was defined here and never
    # called — the module docstring claimed this suite compared "the extracted
    # model identity ... and inference parameters" while comparing only the
    # former. temperature/topP/maxTokens/seed/stopSequences are all inside the
    # AI-BOM that goes into the hashed field set, so a divergence there moves
    # the evidence digest for the same vendor call.
    py_inf = _py_inf_params(py_skeleton)
    ts_inf = _inf_params(ts_skeleton)
    assert py_inf == ts_inf, (
        f"{vendor_module}/{case} inferenceParameters mismatch:\n"
        f"  Python: {py_inf}\n"
        f"  TS:     {ts_inf}"
    )

    # vendorFingerprint is likewise inside the AI-BOM and was never compared.
    py_fp = py_skeleton.vendor_fingerprint
    ts_fp = ts_skeleton.get("vendorFingerprint")
    assert py_fp == ts_fp, (
        f"{vendor_module}/{case} vendorFingerprint mismatch:\n"
        f"  Python: {py_fp!r}\n"
        f"  TS:     {ts_fp!r}"
    )

    if vendor_module == "openrouter":
        # The gateway's facts live here: the upstream provider OpenRouter
        # reported and the base URL the client called. Compared whole, null
        # members included, since this connector always writes the block.
        assert py_skeleton.infrastructure is not None
        py_infra = py_skeleton.infrastructure.model_dump(mode="json", exclude_none=False)
        ts_infra = ts_skeleton.get("infrastructure")
        assert py_infra == ts_infra, (
            f"{vendor_module}/{case} infrastructure mismatch:\n"
            f"  Python: {py_infra}\n"
            f"  TS:     {ts_infra}"
        )


@pytest.mark.parametrize("case", ["azure_hit", "azure_miss"])
def test_openai_azure_decision_parity(case: str, ts_invoke) -> None:
    """OpenAI Azure hit/miss decision tree agrees across Python and TS.

    For the azure_hit case, we inject a known-models reference with the matching
    azure-deployment-name entry into BOTH sides to verify the reverse-lookup
    decision tree agrees. The TS side receives it as a known_models override param;
    the Python side receives it directly. Both must produce the same resolved identity.
    """
    fixture_path = FIXTURES_ROOT / "openai" / f"{case}.json"
    if not fixture_path.exists():
        pytest.skip(f"Fixture not found: {fixture_path}")
    fx = json.loads(fixture_path.read_text())
    req, resp = fx["request"], fx["response"]
    deployment = resp["model"]

    from tzun_sdk.ai_bom.connectors.openai import openai_connector

    if case == "azure_hit":
        # Inject a known_models reference with the matching entry into both sides.
        custom_km = {
            "version": "tzun-known-models-v1",
            "entries": [
                {
                    "vendor": "openai",
                    "modelName": "gpt-4o",
                    "modelVersion": "2024-08-06",
                    "externalIdentifiers": [
                        {"scheme": "azure-deployment-name", "value": deployment}
                    ],
                }
            ],
        }
        py_skeleton = openai_connector.build_ai_bom(req, resp, custom_km)
        assert py_skeleton is not None

        # TS side: pass the known_models override in the harness command.
        ts_result = ts_invoke({
            "action": "connector",
            "vendor": "openai",
            "request": req,
            "response": resp,
            "knownModels": custom_km,
        })
        ts_skeleton = ts_result.get("skeleton")
        assert ts_skeleton is not None

        # Neither should be the raw deployment name.
        assert py_skeleton.model_descriptor.modelName != deployment, \
            "Python: Azure hit should resolve away from deployment name"
        assert ts_skeleton["modelDescriptor"]["modelName"] != deployment, \
            "TS: Azure hit should resolve away from deployment name"

        py_id = {"vendor": py_skeleton.model_descriptor.vendor, "modelName": py_skeleton.model_descriptor.modelName}
        ts_id = {"vendor": ts_skeleton["modelDescriptor"]["vendor"], "modelName": ts_skeleton["modelDescriptor"]["modelName"]}
        assert py_id == ts_id, f"Azure hit identity mismatch: py={py_id} ts={ts_id}"
    else:  # azure_miss
        py_skeleton = openai_connector.build_ai_bom(req, resp)
        assert py_skeleton is not None

        ts_result = ts_invoke({
            "action": "connector",
            "vendor": "openai",
            "request": req,
            "response": resp,
        })
        ts_skeleton = ts_result.get("skeleton")
        assert ts_skeleton is not None

        # Both should pass through the deployment name.
        assert py_skeleton.model_descriptor.modelName == deployment, \
            "Python: Azure miss should pass through deployment name"
        assert ts_skeleton["modelDescriptor"]["modelName"] == deployment, \
            "TS: Azure miss should pass through deployment name"
