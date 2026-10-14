"""``tzun_sdk.hook()`` — primary AI-BOM API.

Pure function: ``hook(vendor, request, response, *, tzun=None) -> AiBom``.

Resolves the active ``Tzun`` via:

1. The ``tzun=`` kwarg if explicitly passed.
2. The contextvar set by the most recent ``Tzun.init()`` call.
3. ``TzunError`` if neither is set.

Streaming works naturally because the application drives the stream and
calls ``hook()`` with whatever aggregated response shape it has.
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

from tzun_sdk.ai_bom.connectors import SUPPORTED_VENDORS, get_connector
from tzun_sdk.errors import ModelCatalogUnsupportedError, TzunError
from tzun_sdk.models import AiBom

if TYPE_CHECKING:
    from tzun_sdk.core import Tzun

LOG = logging.getLogger(__name__)

#: ContextVar set by ``Tzun.init()`` and cleared by ``Tzun.close()``.
#: ``hook()`` reads this when no explicit ``tzun=`` is passed.
active_tzun: ContextVar[Tzun | None] = ContextVar("active_tzun", default=None)


async def hook(
    vendor: str,
    request: dict[str, Any],
    response: dict[str, Any] | Any,
    *,
    tzun: Tzun | None = None,
) -> AiBom | None:
    """Primary AI-BOM API.

    Pure function. Dispatches to the registered connector for ``vendor``,
    registers the resolved descriptor in the active ``Tzun``'s catalog
    (deduplicated via the per-digest lock + LRU cache), and returns the
    wire ``AiBom`` shape (with ``modelDescriptorDigest`` instead of an
    inline descriptor).

    On a store with no model catalog (the HTTP backend against a platform
    that does not serve ``POST /v1/models``) the descriptor cannot be
    registered: ``hook()`` returns ``None`` and logs
    ``event=capture_model_not_recordable``, and a wrapped call captures the
    decision with ``contributions=None``.

    Raises:
        TzunError: Unknown vendor, or no Tzun resolvable.
    """
    # An unknown vendor is refused.
    if vendor not in SUPPORTED_VENDORS:
        raise TzunError(
            f"Unknown vendor {vendor!r}. Supported vendors: "
            f"{', '.join(SUPPORTED_VENDORS)}."
        )
    # The explicit ``tzun=``, else the active instance; neither is refused.
    resolved = tzun if tzun is not None else active_tzun.get()
    if resolved is None:
        raise TzunError(
            "hook() requires either tzun= kwarg or an initialized Tzun instance."
        )
    # Dispatch to the vendor's connector.
    connector = get_connector(vendor)
    assert connector is not None  # set membership above guarantees this
    skeleton = connector.build_ai_bom(request, response)
    if skeleton is None:
        return None

    # Cache-aware registration with per-digest dedup.
    cache = resolved.descriptor_cache_obj
    descriptor = skeleton.model_descriptor
    cache_key = (
        f"{connector.vendor}:{descriptor.modelName}:{descriptor.modelVersion}"
    )
    cached_digest = cache.get(cache_key)
    if cached_digest is None:
        async_lock = cache.async_lock_for(cache_key)
        async with async_lock:
            cached_digest = cache.get(cache_key)
            if cached_digest is None:
                try:
                    digest = await resolved._storage.register_descriptor(descriptor)
                except ModelCatalogUnsupportedError:
                    # The decision is still captured, without its model; this
                    # line is the signal that the model is not recorded.
                    LOG.warning(
                        "event=capture_model_not_recordable vendor=%s model_name=%s "
                        "reason=store_has_no_model_catalog",
                        connector.vendor,
                        descriptor.modelName,
                    )
                    return None
                cache.put(cache_key, digest)
                cached_digest = digest

    return AiBom(
        modelDescriptorDigest=cached_digest,
        vendorFingerprint=skeleton.vendor_fingerprint,
        promptTemplate=skeleton.prompt_template,
        inferenceParameters=skeleton.inference_parameters,
        infrastructure=skeleton.infrastructure,
    )


__all__ = ("active_tzun", "hook")
