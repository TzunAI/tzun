"""The Python example's requirement on ``tzun-sdk`` admits the version this tree builds.

CI's ``clients/py-example smoke`` job builds the wheel from ``python/``, installs
it, then runs ``pip install -e clients/py-example``. ``pip`` keeps the installed
wheel only while the example's ``tzun-sdk`` requirement admits its version;
otherwise it looks for another release on the package index and the job fails
without running the example. A reader who follows the example's README installs
the SDK from ``python/`` the same way, so the requirement must name a version
this tree can satisfy.
"""

from __future__ import annotations

import pathlib
import tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

PYTHON_ROOT = pathlib.Path(__file__).resolve().parent.parent
SDK_PYPROJECT = PYTHON_ROOT / "pyproject.toml"
EXAMPLE_PYPROJECT = PYTHON_ROOT.parent / "clients" / "py-example" / "pyproject.toml"


def _load(path: pathlib.Path) -> dict:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def test_example_pyproject_exists() -> None:
    """Guard: a moved example must fail here, not make the test below vacuous."""
    assert EXAMPLE_PYPROJECT.is_file(), f"example pyproject.toml not found at {EXAMPLE_PYPROJECT}"


def test_example_requirement_admits_the_sdk_version() -> None:
    """The example declares ``tzun-sdk`` once, with a specifier this tree's version satisfies."""
    declared = str(_load(SDK_PYPROJECT)["project"]["version"])
    requirements = [Requirement(dep) for dep in _load(EXAMPLE_PYPROJECT)["project"]["dependencies"]]
    sdk = [req for req in requirements if canonicalize_name(req.name) == "tzun-sdk"]
    assert len(sdk) == 1, f"expected one tzun-sdk requirement in {EXAMPLE_PYPROJECT}, got {sdk}"
    # pip keeps an installed distribution the specifier admits even when its
    # version is a pre-release, so a pre-release built from this tree counts.
    assert sdk[0].specifier.contains(Version(declared), prereleases=True), (
        "clients/py-example/pyproject.toml requires a tzun-sdk version this tree does not build:\n"
        f"  clients/py-example requires {str(sdk[0])!r}\n"
        f"  python/pyproject.toml [project].version = {declared!r}\n"
        "Change the example's requirement, or pip installs tzun-sdk from the package "
        "index instead of this tree."
    )
