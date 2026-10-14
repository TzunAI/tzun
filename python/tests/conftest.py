"""pytest fixtures for the tzun-sdk test suite.

Centralizes:
  * ``RUN_INTEGRATION_TESTS`` gate. Tests requiring a live DB
    skip cleanly when the env var is unset.
  * ``PYTEST_CURRENT_TEST`` guard — refuses to touch a live DB outside
    pytest, an extra belt-and-suspenders layer on top of the env-var gate.
  * Common in-memory ``Tzun`` factory.
"""

from __future__ import annotations

import os

import pytest

INTEGRATION_FLAG = "RUN_INTEGRATION_TESTS"


@pytest.fixture(scope="session")
def integration_enabled() -> bool:
    """Integration-test gate.

    Returns True only when the test runner explicitly opts in by setting
    ``RUN_INTEGRATION_TESTS=true``. Otherwise tests that require live
    services skip with a clear message naming the env var.
    """
    return os.environ.get(INTEGRATION_FLAG, "").lower() == "true"


@pytest.fixture
def require_pytest_context() -> None:
    """Guard: refuse to touch live DBs outside pytest.

    Mirrors the TS suite's belt-and-suspenders pattern: integration
    fixtures double-check that
    ``PYTEST_CURRENT_TEST`` is set so a test helper accidentally imported
    by production code cannot reach the live DB.
    """
    if not os.environ.get("PYTEST_CURRENT_TEST"):
        pytest.fail("Integration fixtures cannot run outside pytest")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-skip integration-marked tests when the gate is off."""
    if os.environ.get(INTEGRATION_FLAG, "").lower() == "true":
        return
    skip_marker = pytest.mark.skip(
        reason="integration test — set RUN_INTEGRATION_TESTS=true to run"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_marker)
