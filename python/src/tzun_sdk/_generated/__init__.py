"""Codegen output for tzun-sdk.

This package is populated by ``scripts/codegen-python.ts`` running against
``packages/engine/src/types/*.ts`` (the TypeScript types are the IDL).

The files in this directory are committed artifacts, not build-time artifacts.
CI runs ``npm run codegen:python`` and ``git diff --exit-code`` to enforce
that uncommitted regenerations fail the build.

No import-time codegen-drift check runs by default. Set
``TZUN_VERIFY_CODEGEN_AT_IMPORT=1`` in development to opt in.
"""

from __future__ import annotations

__all__: list[str] = []
