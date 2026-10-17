"""tzun-sdk — Python SDK for Tzun (forensic evidence for AI decisions).

Public API surface:

- Core: ``Tzun``, ``TzunSync``
- AI-BOM: ``hook``, ``attach``
- Storage adapters: ``storage.MemoryAdapter``, ``storage.SqliteAdapter``,
  ``storage.PostgresAdapter``, ``storage.HttpBackendAdapter``
- Pydantic models: ``models.EvidenceEnvelope``, ``models.EvidencePayload``,
  ``models.AiBom``, ``models.ModelDescriptor``, ``models.DecisionInput``,
  plus every other model emitted by the codegen pipeline.
- Errors: ``errors.TzunError`` (base), plus the typed subclasses listed in
  the errors module.

Major version tracks the TypeScript SDK major; both speak the same
canonical v1 wire format byte-for-byte.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):  # noqa: UP036 — runtime guard for sub-3.11 users
    raise RuntimeError(
        "tzun-sdk requires Python 3.11 or newer, "
        f"got {sys.version_info.major}.{sys.version_info.minor}"
    )

__version__ = "0.9.0"

# Public re-exports — these submodules are loaded eagerly so users can
# write `from tzun_sdk import Tzun, hook, attach, storage, models, errors`
# without further sub-imports. The submodules themselves are designed so
# importing `tzun_sdk` does not pull in any vendor SDK or any
# optional-extra dependency; those are loaded lazily
# at point of use.

from tzun_sdk import (
    errors,
    models,
    storage,
)
from tzun_sdk.ai_bom.attach import attach
from tzun_sdk.ai_bom.hook import hook
from tzun_sdk.core import Tzun, TzunSync

__all__ = (
    "Tzun",
    "TzunSync",
    "__version__",
    "attach",
    "errors",
    "hook",
    "models",
    "storage",
)
