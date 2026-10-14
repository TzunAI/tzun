"""Attribute access over a record's stored JSON, for tests that tamper with a store's row.

The adapters keep each record as the JSON the capture hashed. A test that
rewrites a row behind the adapter's back, as an attacker with write access to
the store would, edits that JSON; :class:`RawView` lets it say
``row.integrity.chainLink = ...`` for ``row["integrity"]["chainLink"] = ...``.
A model assigned in is stored as its JSON value.
"""

from __future__ import annotations

from typing import Any

from tzun_sdk._record_rules import json_value


def _wrap(value: Any) -> Any:
    if isinstance(value, dict):
        return RawView(value)
    if isinstance(value, list):
        return RawList(value)
    return value


class RawView:
    """A dict seen through attributes; writes go to the dict."""

    def __init__(self, data: dict[str, Any]) -> None:
        object.__setattr__(self, "_data", data)

    def __getattr__(self, name: str) -> Any:
        data = object.__getattribute__(self, "_data")
        if name not in data:
            raise AttributeError(name)
        return _wrap(data[name])

    def __setattr__(self, name: str, value: Any) -> None:
        object.__getattribute__(self, "_data")[name] = json_value(value)

    def __delattr__(self, name: str) -> None:
        del object.__getattribute__(self, "_data")[name]

    @property
    def raw(self) -> dict[str, Any]:
        data: dict[str, Any] = object.__getattribute__(self, "_data")
        return data


class RawList:
    """A list seen with its dict elements as :class:`RawView`."""

    def __init__(self, data: list[Any]) -> None:
        self._data = data

    def __getitem__(self, index: int) -> Any:
        return _wrap(self._data[index])

    def __setitem__(self, index: int, value: Any) -> None:
        self._data[index] = json_value(value)

    def __len__(self) -> int:
        return len(self._data)

    def append(self, value: Any) -> None:
        self._data.append(json_value(value))

    def pop(self, index: int = -1) -> Any:
        return self._data.pop(index)

    def clear(self) -> None:
        self._data.clear()
