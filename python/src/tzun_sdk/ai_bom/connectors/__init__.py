"""Vendor connectors for tzun-sdk AI-BOM.

Six connectors: openai, anthropic, bedrock, vertex, azure_ai, openrouter.
Registry maps the vendor string → connector instance. NIM and HF-Inference
connectors exist in the TypeScript SDK and are not implemented in Python.
"""

from __future__ import annotations

from tzun_sdk.ai_bom.connectors._base import Connector
from tzun_sdk.ai_bom.connectors.anthropic import anthropic_connector
from tzun_sdk.ai_bom.connectors.azure_ai import azure_ai_connector
from tzun_sdk.ai_bom.connectors.bedrock import bedrock_connector
from tzun_sdk.ai_bom.connectors.openai import openai_connector
from tzun_sdk.ai_bom.connectors.openrouter import openrouter_connector
from tzun_sdk.ai_bom.connectors.vertex import vertex_connector

#: Registry of supported vendor connectors.
CONNECTORS: dict[str, Connector] = {
    "openai": openai_connector,
    "anthropic": anthropic_connector,
    "bedrock": bedrock_connector,
    "vertex": vertex_connector,
    "azure_ai": azure_ai_connector,
    "openrouter": openrouter_connector,
}

#: The supported vendors enumerated, in registry order.
SUPPORTED_VENDORS: tuple[str, ...] = tuple(CONNECTORS.keys())


def get_connector(vendor: str) -> Connector | None:
    return CONNECTORS.get(vendor)


__all__ = (
    "CONNECTORS",
    "SUPPORTED_VENDORS",
    "Connector",
    "anthropic_connector",
    "azure_ai_connector",
    "bedrock_connector",
    "get_connector",
    "openai_connector",
    "openrouter_connector",
    "vertex_connector",
)
