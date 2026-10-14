"""AI-BOM surface for tzun-sdk.

Exports the primary :func:`tzun_sdk.hook` API, the optional
:func:`tzun_sdk.attach` sugar, the descriptor LRU cache
(:class:`DescriptorCache`), and the five vendor connectors.
"""

from __future__ import annotations

from tzun_sdk.ai_bom.attach import attach
from tzun_sdk.ai_bom.hook import hook
from tzun_sdk.ai_bom.registry import DescriptorCache

__all__ = ("DescriptorCache", "attach", "hook")
