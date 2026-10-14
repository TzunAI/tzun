"""Known-models reference loader (bundled).

Loads ``data/known-models.json`` (the seed catalog) via
``importlib.resources``. The JSON file is a tracked package data file at
``tzun_sdk/_data/known-models.json``, synced from the repo-root
``data/known-models.json`` by ``pnpm run codegen:python`` and drift-checked
in CI, so both the wheel and the sdist carry it.

Runtime fetch is disabled by default (matching the TS behavior).
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

from tzun_sdk.errors import TzunError


class KnownModelsNotBundledError(TzunError):
    """Raised when the bundled known-models catalog is missing.

    A missing catalog is a broken install, not an empty catalog. Answering
    with a warning and an empty ``{"entries": []}`` would make a packaging
    defect indistinguishable from "no model matched": every AI-BOM enrichment
    lookup would silently return nothing, and the resulting evidence would
    record an unenriched descriptor as if that were the truth.
    """


@lru_cache(maxsize=1)
def load_known_models() -> dict[str, Any]:
    """Return the bundled known-models catalog.

    Raises:
        KnownModelsNotBundledError: if the catalog is not present in the
            installed package. Run ``pnpm run codegen:python`` in a source
            checkout, or reinstall the package.
    """
    try:
        with resources.files("tzun_sdk._data").joinpath("known-models.json").open(
            "r", encoding="utf-8"
        ) as f:
            data: dict[str, Any] = json.load(f)
            return data
    except (FileNotFoundError, OSError, ModuleNotFoundError) as exc:
        raise KnownModelsNotBundledError(
            "known-models catalog is missing from this installation "
            "(tzun_sdk/_data/known-models.json). AI-BOM model enrichment "
            "cannot run. In a source checkout run 'pnpm run codegen:python'; "
            "otherwise reinstall tzun-sdk."
        ) from exc


__all__ = ("KnownModelsNotBundledError", "load_known_models")
