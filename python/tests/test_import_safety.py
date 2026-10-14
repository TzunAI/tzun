"""Import safety — ``import tzun_sdk`` must not pull in vendor SDKs."""

from __future__ import annotations

import subprocess
import sys


def test_import_tzun_sdk_does_not_import_vendor_sdks() -> None:
    """Vendor SDKs are late-imported.

    Confirms that after ``import tzun_sdk`` no vendor module appears in
    ``sys.modules``. The check is the production-safe variant of the
    full venv-isolation test described in the plan.
    """
    code = (
        "import sys; import tzun_sdk;\n"
        "vendor_modules = ['openai', 'anthropic', 'boto3', 'google.cloud.aiplatform']\n"
        "loaded = [m for m in vendor_modules if m in sys.modules]\n"
        "print('LOADED:', loaded)\n"
        "assert not loaded, f'Vendor SDKs leaked: {loaded}'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "LOADED: []" in result.stdout
