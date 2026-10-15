"""Packaging metadata tests."""

from __future__ import annotations

import ast
import pathlib
import re
import tomllib
from collections.abc import Iterator

import pytest

PYPROJECT = pathlib.Path(__file__).parent.parent / "pyproject.toml"


def _config() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def test_python_floor() -> None:
    """Python 3.11+ floor."""
    cfg = _config()
    assert cfg["project"]["requires-python"] == ">=3.11"


def test_distribution_and_import_names() -> None:
    """Dist name + import name."""
    cfg = _config()
    assert cfg["project"]["name"] == "tzun-sdk"


def test_build_backend() -> None:
    """Hatchling backend."""
    cfg = _config()
    assert cfg["build-system"]["build-backend"] == "hatchling.build"


def test_required_deps_no_vendor_sdks() -> None:
    """No vendor SDKs in required deps."""
    cfg = _config()
    deps = " ".join(cfg["project"]["dependencies"]).lower()
    for forbidden in ("openai", "anthropic", "boto3", "google-cloud", "azure-ai-inference"):
        assert forbidden not in deps, f"{forbidden!r} must not be a required dep"


def test_optional_extras_present() -> None:
    """Optional extras."""
    cfg = _config()
    extras = cfg["project"]["optional-dependencies"]
    for required in ("postgres", "sqlite", "rfc3161", "anchor", "all"):
        assert required in extras, f"missing optional extra: {required}"


def test_the_anchor_extra_carries_the_evm_verifier_dependencies() -> None:
    """tzun_sdk.attestation.evm_transaction imports coincurve (secp256k1 recovery) and
    Cryptodome.Hash.keccak (pycryptodomex, which does not claim the ``Crypto`` package a
    legacy pycrypto owns) from the ``anchor`` extra, and ``all`` holds it."""
    extras = _config()["project"]["optional-dependencies"]
    names = [re.split(r"[\s<>=!~\[;]", dep, maxsplit=1)[0].lower() for dep in extras["anchor"]]
    assert names == ["coincurve", "pycryptodomex"]
    assert "anchor" in extras["all"][0]


def test_no_module_imports_the_crypto_package() -> None:
    """``Crypto`` is the package a legacy pyCrypto owns. bandit's B413 blacklist refuses
    any import of it, and ``bandit -r src/ -ll`` gates publishing (python-publish.yml),
    so Keccak-256 comes from pycryptodomex as ``Cryptodome``."""
    src = PYPROJECT.parent / "src"
    importing = re.compile(r"^\s*(?:from|import)\s+Crypto(?:\.|\s|$)", re.MULTILINE)
    offenders = [
        str(path.relative_to(src))
        for path in src.rglob("*.py")
        if importing.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


#: What bandit's B608 takes for SQL (bandit/plugins/injection_sql.py).
_B608_SQL = re.compile(
    r"(select\s.*from\s|delete\s+from\s|insert\s+into\s.*values\s|update\s.*set\s)",
    re.IGNORECASE | re.DOTALL,
)


def _strings_built_at_run_time(tree: ast.AST) -> Iterator[tuple[int, str]]:
    """Each string built at run time, with each run-time part as ``?``: an f-string,
    ``%`` or ``+`` over string literals, and ``"...".format(...)``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            parts = (v.value if isinstance(v, ast.Constant) else "?" for v in node.values)
            yield node.lineno, "".join(str(part) for part in parts)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            literals = [
                n.value
                for n in ast.walk(node)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
            ]
            yield node.lineno, "?".join(literals)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant)
            and isinstance(node.func.value.value, str)
        ):
            yield node.lineno, node.func.value.value


def test_no_sql_is_built_at_run_time() -> None:
    """bandit's B608 refuses SQL built from an f-string, ``%``, ``+`` or ``.format``,
    whatever it interpolates, and ``bandit -r src/ -ll`` gates publishing
    (python-publish.yml), so a query that varies is chosen from literals."""
    src = PYPROJECT.parent / "src"
    offenders = [
        f"{path.relative_to(src)}:{line}"
        for path in sorted(src.rglob("*.py"))
        for line, text in _strings_built_at_run_time(ast.parse(path.read_text(encoding="utf-8")))
        if _B608_SQL.search(text + " ")
    ]
    assert offenders == []


def test_console_script_registered() -> None:
    """The ``tzun`` script targets ``tzun_sdk.cli.main:main``, not the typer app.

    ``main()``'s ``except (TzunError, AdminTokenRequiredError)`` wrapper is the
    only thing turning a storage failure into ``error: …`` + exit 2 instead of a
    raw traceback, and a script pointed at the typer app object would skip it.
    The target string is a mechanism; the outcome is that the registered
    callable actually runs that handler, so both are asserted.
    """
    cfg = _config()
    scripts = cfg["project"].get("scripts", {})
    assert scripts.get("tzun") == "tzun_sdk.cli.main:main"

    module_path, _, attr = scripts["tzun"].partition(":")
    module = __import__(module_path, fromlist=[attr])
    entry = getattr(module, attr)
    assert callable(entry)
    import inspect

    source = inspect.getsource(entry)
    assert "AdminTokenRequiredError" in source
    assert "sys.exit(2)" in source


def test_version_matches_the_npm_packages() -> None:
    """The Python package is versioned in lockstep with @tzun/sdk and @tzun/engine."""
    import json

    cfg = _config()
    root = pathlib.Path(__file__).parent.parent.parent
    if not (root / "package.json").exists():
        pytest.skip("outside the repository: no npm manifests to compare with")
    sdk = json.loads((root / "package.json").read_text())
    engine = json.loads((root / "packages" / "engine" / "package.json").read_text())
    assert cfg["project"]["version"] == sdk["version"] == engine["version"]
