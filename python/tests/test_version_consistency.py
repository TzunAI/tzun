"""The package version must agree with the version it declares to installers.

This file lives in ``python/tests``, which ``pytest`` run from ``python/``
collects (``testpaths = ["tests"]``), so every Python test run checks it. It
asserts ``tzun_sdk.__version__`` against the ``version`` field ``pip``/``uv``
read out of ``pyproject.toml``. When they disagree, an installed wheel reports
a version its own metadata contradicts, and every piece of evidence that
records the producing SDK version records the wrong one.
"""

from __future__ import annotations

import pathlib
import re
import tomllib

import tzun_sdk

PYPROJECT = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"


def _declared_version() -> str:
    with PYPROJECT.open("rb") as fh:
        return str(tomllib.load(fh)["project"]["version"])


def test_pyproject_exists() -> None:
    """Guard: a moved pyproject must fail here, not make the test below vacuous."""
    assert PYPROJECT.is_file(), f"pyproject.toml not found at {PYPROJECT}"


def test_dunder_version_matches_pyproject() -> None:
    """``tzun_sdk.__version__`` == the version declared to installers."""
    declared = _declared_version()
    assert tzun_sdk.__version__ == declared, (
        "tzun_sdk.__version__ disagrees with pyproject.toml:\n"
        f"  tzun_sdk.__version__ = {tzun_sdk.__version__!r}\n"
        f"  pyproject [project].version = {declared!r}\n"
        "Bump both, or an installed wheel reports a version its own metadata "
        "contradicts."
    )


def test_version_is_pep440_release_shaped() -> None:
    """The version is a real release identifier, not a placeholder."""
    assert re.fullmatch(
        r"\d+\.\d+\.\d+([abc]|rc|\.post|\.dev)?\d*", tzun_sdk.__version__
    ), f"not a PEP 440 release version: {tzun_sdk.__version__!r}"
