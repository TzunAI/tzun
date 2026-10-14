"""StorageAdapter Protocol conformance."""

from __future__ import annotations

from tzun_sdk.storage import (
    HttpBackendAdapter,
    MemoryAdapter,
    PostgresAdapter,
    SqliteAdapter,
    StorageAdapter,
)


def test_memory_adapter_implements_protocol() -> None:
    inst = MemoryAdapter()
    assert isinstance(inst, StorageAdapter)


def test_sqlite_adapter_has_protocol_methods() -> None:
    inst = SqliteAdapter(":memory:", mode="sync")
    # Spot-check protocol method presence.
    for method in (
        "store",
        "retrieve",
        "list",
        "list_by_sequence",
        "head",
        "ensure_tables",
        "close",
        "register_descriptor",
        "get_descriptor",
        "store_attestation",
        "get_attestations",
        "store_annotation",
        "store_relink",
        "store_fork",
        "store_incident",
        "delete_envelope_for_demo",
    ):
        assert hasattr(inst, method), f"SqliteAdapter missing {method}"


def test_http_adapter_has_protocol_methods() -> None:
    inst = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="x")
    for method in (
        "store",
        "retrieve",
        "list",
        "list_by_sequence",
        "head",
        "register_descriptor",
        "get_descriptor",
    ):
        assert hasattr(inst, method), f"HttpBackendAdapter missing {method}"


def test_postgres_adapter_class_exists() -> None:
    """PostgresAdapter class is importable; constructor requires the extra."""
    assert PostgresAdapter is not None
