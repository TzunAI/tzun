"""pytest configuration for the cross-SDK suite.

The cross-SDK tests spawn a Node subprocess running an in-repo TS harness
(never the published npm version) and shuttle envelope JSON over
stdin/stdout. This file pins the in-repo TS build path and exposes a
``ts_harness`` fixture to the tests.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
from typing import Any

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
TS_HARNESS = REPO_ROOT / "tests" / "cross-sdk" / "ts-harness" / "index.ts"


@pytest.fixture(scope="session")
def ts_harness_path() -> pathlib.Path:
    """The in-repo TS harness path."""
    return TS_HARNESS


@pytest.fixture(scope="session")
def has_node() -> bool:
    """Probe Node availability — cross-SDK suite skips when absent."""
    return shutil.which("node") is not None


@pytest.fixture
def ts_invoke(ts_harness_path: pathlib.Path, has_node: bool):
    """Fixture returning a function ``invoke(cmd: dict) -> dict`` that runs
    the TS harness via Node with the given JSON command on stdin.

    Skips when Node is not installed (e.g., minimal CI runner).
    """
    if not has_node:
        pytest.skip("Node not available — cross-SDK suite requires Node 22+")

    def _invoke(cmd: dict[str, Any]) -> dict[str, Any]:
        proc = subprocess.run(
            ["npx", "tsx", str(ts_harness_path)],
            input=json.dumps(cmd),
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"ts-harness failed (exit {proc.returncode})\nstderr: {proc.stderr}"
            )
        return json.loads(proc.stdout)

    return _invoke


# ---------------------------------------------------------------------------
# The record-revision vector files
#
# The Python half of each file recomputes, with hashlib and the Python SDK's
# canonical serializer, every value a file pins as bytes or a digest. Where a
# file states a rule's answer (a refusal code, a row's outcome), the Python
# SDK gives it through the rule module the design names (tzun_sdk.decider,
# tzun_sdk.contributions, tzun_sdk.links, tzun_sdk.mandate, tzun_sdk.agents),
# function for function with the engine; `sdk_rule` hands a test that
# function, and skips it, saying why, while the module or the function is not
# in the SDK. `projection` reduces an answer, whatever type the SDK returns it
# as, to the members the vectors compare.
# ---------------------------------------------------------------------------


@pytest.fixture
def sdk_rule():  # type: ignore[no-untyped-def]
    """``get(module, name)``: the Python SDK's twin of an engine rule, or a skip naming it."""

    def get(module: str, name: str):  # type: ignore[no-untyped-def]
        mod = pytest.importorskip(f"tzun_sdk.{module}", reason=f"tzun_sdk.{module} is not in the Python SDK yet")
        fn = getattr(mod, name, None)
        if fn is None:
            pytest.skip(f"tzun_sdk.{module}.{name} is not in the Python SDK yet")
        return fn

    return get


@pytest.fixture
def projection():  # type: ignore[no-untyped-def]
    """``project(value, keys)``: the named members of a dict, dataclass or model, read under their
    camelCase names whether the SDK spells them so or in snake_case; ``None`` stays ``None``."""

    def camel(name: str) -> str:
        head, *rest = name.split("_")
        return head + "".join(part[:1].upper() + part[1:] for part in rest)

    def project(value: Any, keys: tuple[str, ...]) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            return {"code": value} if "code" in keys else value
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="json")
        elif hasattr(value, "__dataclass_fields__"):
            import dataclasses

            value = dataclasses.asdict(value)
        elif not isinstance(value, dict):
            value = {k: getattr(value, k) for k in keys if hasattr(value, k)}
        value = {camel(k): v for k, v in value.items()}
        return {k: value[k] for k in keys if value.get(k) is not None}

    return project
