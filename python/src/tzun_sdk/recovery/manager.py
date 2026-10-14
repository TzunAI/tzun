"""Three-tier recovery surface.

Tier 1: ``annotate`` — append an annotation record.
Tier 2: ``relink`` — rebind a chain forward.
Tier 3: ``fork`` — create a new chain.

All three are admin-gated via :meth:`Tzun._check_admin_token`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tzun_sdk.models import AnnotationRecord, ForkRecord, RelinkRecord

if TYPE_CHECKING:
    from tzun_sdk.core import Tzun


class RecoveryManager:
    """Standalone recovery surface; mirrors :class:`Tzun.recovery`."""

    def __init__(self, tzun: Tzun) -> None:
        self._tzun = tzun

    async def annotate(
        self, record: AnnotationRecord, *, admin_token: str | None = None
    ) -> None:
        self._tzun._check_admin_token(admin_token)
        await self._tzun._storage.store_annotation(record)

    async def relink(
        self, record: RelinkRecord, *, admin_token: str | None = None
    ) -> None:
        self._tzun._check_admin_token(admin_token)
        await self._tzun._storage.store_relink(record)

    async def fork(
        self, record: ForkRecord, *, admin_token: str | None = None
    ) -> None:
        self._tzun._check_admin_token(admin_token)
        await self._tzun._storage.store_fork(record)


__all__ = ("RecoveryManager",)
