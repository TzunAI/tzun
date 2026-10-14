"""Known-models reference loader (REQ — bundled catalog).

The catalog is a tracked package data file at
``tzun_sdk/_data/known-models.json``, synced from the repo-root
``data/known-models.json`` by ``pnpm run codegen:python`` and drift-checked
in CI, so both the wheel and the sdist carry it.

A missing catalog raises instead of loading as an empty placeholder. An
empty placeholder would make a mis-packaged install indistinguishable from
"no model matched": every AI-BOM enrichment lookup would come back empty and
the evidence would record an unenriched descriptor as if that were the truth.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from tzun_sdk.ai_bom import known_models


def test_loader_returns_wellformed_structure() -> None:
    """The loader returns a dict with version + entries keys."""
    known_models.load_known_models.cache_clear()
    data = known_models.load_known_models()
    assert isinstance(data, dict)
    assert "version" in data
    assert "entries" in data
    assert isinstance(data["entries"], list)


def test_loader_is_cached() -> None:
    """REQ — the loader is lru_cache'd; repeated calls return the same object."""
    known_models.load_known_models.cache_clear()
    first = known_models.load_known_models()
    second = known_models.load_known_models()
    assert first is second


def test_catalog_is_bundled_and_non_empty() -> None:
    """The catalog ships with the package, with real entries in it."""
    known_models.load_known_models.cache_clear()
    data = known_models.load_known_models()
    source = pathlib.Path(__file__).parents[3] / "data" / "known-models.json"
    assert source.exists(), f"repo seed catalog missing at {source}"
    expected = json.loads(source.read_text(encoding="utf-8"))
    assert data["version"] == expected["version"]
    assert len(data["entries"]) == len(expected["entries"])
    assert len(data["entries"]) > 0


def test_loader_raises_when_catalog_is_not_bundled(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing catalog is a broken install, not an empty catalog.

    The loader raises ``KnownModelsNotBundledError`` rather than returning
    ``{"version": ..., "entries": []}``, so a package built without the data
    file fails loudly instead of degrading silently to "no known model
    matches anything".
    """

    class _MissingPath:
        def joinpath(self, *_args: str) -> _MissingPath:
            return self

        def open(self, *_args: object, **_kwargs: object) -> object:
            raise FileNotFoundError("known-models.json")

    monkeypatch.setattr(known_models.resources, "files", lambda _pkg: _MissingPath())
    known_models.load_known_models.cache_clear()
    try:
        with pytest.raises(known_models.KnownModelsNotBundledError):
            known_models.load_known_models()
    finally:
        known_models.load_known_models.cache_clear()
