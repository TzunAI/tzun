"""The ``anchor`` extra in tests: skipped without it, except under CI.

A test that needs the extra skips where the extra is not installed, so a
contributor without it can run the suite. Under CI (``CI`` set, as GitHub Actions
sets it) it fails instead: a parity or EVM test that skips there is a test that
never runs, so the job must install the SDK with ``pip install -e '.[anchor]'``.
"""

from __future__ import annotations

import os

import pytest

from tzun_sdk.attestation.evm_transaction import anchor_extra_available

MISSING_IN_CI = (
    "The 'anchor' extra is not installed, and CI must run these tests: install the "
    "Python SDK with pip install -e '.[anchor]' in this job."
)


def in_ci() -> bool:
    return os.environ.get("CI", "").strip().lower() not in ("", "false", "0")


def require_anchor_extra() -> None:
    """Skip the module without the extra, or fail it under CI."""
    if anchor_extra_available():
        return
    if in_ci():
        pytest.fail(MISSING_IN_CI, pytrace=False)
    pytest.skip("the 'anchor' extra is not installed", allow_module_level=True)


#: Skips a test without the extra, except under CI, where the test then fails.
needs_anchor_extra = pytest.mark.skipif(
    not anchor_extra_available() and not in_ci(), reason="the 'anchor' extra is not installed"
)
