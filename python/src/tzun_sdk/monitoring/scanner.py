"""Scheduled scanner — periodically verifies stored envelopes."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any

from tzun_sdk.models import TamperIncident
from tzun_sdk.monitoring.tamper_detector import TamperDetector, _incident

if TYPE_CHECKING:
    from tzun_sdk.core import Tzun

LOG = logging.getLogger(__name__)


class ScheduledScanner:
    """Runs the TamperDetector on every envelope, and the mandate checks, at a configurable interval."""

    def __init__(self, tzun: Tzun, interval_seconds: float = 60.0) -> None:
        self._tzun = tzun
        self._interval = interval_seconds
        self._detector = TamperDetector()
        self._task: asyncio.Task[None] | None = None

    async def _records(self) -> list[Any]:
        storage = self._tzun._storage
        reader = getattr(storage, "list_raw_by_sequence", None)
        if reader is not None:
            records: list[Any] = await reader(chain_id=self._tzun._chain_id)
            return records
        envelopes: list[Any] = await storage.list_by_sequence(chain_id=self._tzun._chain_id)
        return envelopes

    async def scan_once(self) -> list[TamperIncident]:
        """Scan the whole chain once; persist and return every incident found.

        Reads through the chain-scoped, unpaged sequence listing (the paged
        ``list()`` stopped the scan at its page). Each record is checked by
        :class:`TamperDetector` over its stored JSON, with the same-store link
        targets resolved. Then every open mandate past its window is moved to
        ``expired``, and the records of each mandate are checked for slots
        held twice (``mandate_slot_duplicate``), missing slots
        (``mandate_slot_gap``) and totals that do not step by each record's
        own value (``mandate_totals_unexplained``).
        """
        from tzun_sdk._verify_rows import store_link_resolver

        found: list[TamperIncident] = []
        storage = self._tzun._storage
        for record in await self._records():
            raw = record if isinstance(record, dict) else json.loads(record.model_dump_json(by_alias=True))
            resolver = await store_link_resolver(raw, storage)
            found.extend(await self._detector.detect(raw, resolver=resolver))
        # The record incidents are stored before the mandate checks run, so a
        # mandate check that fails cannot lose them.
        for inc in found:
            await self._store(inc)
        mandate_incidents = await self._scan_mandates()
        for inc in mandate_incidents:
            await self._store(inc)
        return [*found, *mandate_incidents]

    async def _store(self, inc: TamperIncident) -> None:
        await self._tzun._storage.store_incident(inc)
        LOG.info("tamper_incident incident_id=%s evidence_id=%s", inc.incidentId, inc.evidenceId)

    async def _scan_mandates(self) -> list[TamperIncident]:
        from tzun_sdk.mandate.scope import check_mandate_consumption

        storage = self._tzun._storage
        if not hasattr(storage, "list_mandates") or not hasattr(storage, "list_links_to"):
            return []
        await self._tzun.mandates.expire_due()
        incidents: list[TamperIncident] = []
        for row in await storage.list_mandates():
            envelopes: list[dict[str, Any]] = []
            cursor: str | None = None
            while True:
                page, cursor = await storage.list_links_to(row.issuanceDigest, rels=["mandate"], limit=200, cursor=cursor)
                for link_row in page:
                    raw = await storage.retrieve_raw(link_row.evidenceId)
                    if isinstance(raw, dict):
                        envelopes.append(raw)
                if cursor is None:
                    break
            events = await storage.list_mandate_events(row.mandateId)
            terminal = next(
                (e.body.model_dump(mode="json") for e in reversed(events) if e.body.event != "issued"), None
            )
            result = check_mandate_consumption(json.loads(row.documentBytes), envelopes, last_event=terminal)
            for slot in result["duplicateSlots"]:
                incidents.append(
                    _incident("mandate_slot_duplicate", None, {"mandateDigest": row.mandateDigest, "slot": slot})
                )
            for gap in result["gaps"]:
                incidents.append(
                    _incident("mandate_slot_gap", None, {"mandateDigest": row.mandateDigest, **gap})
                )
            for step in result["unexplainedSteps"]:
                incidents.append(
                    _incident("mandate_totals_unexplained", None, {"mandateDigest": row.mandateDigest, **step})
                )
        return incidents

    async def _loop(self) -> None:
        while True:
            try:
                await self.scan_once()
            except Exception as exc:
                LOG.warning("scanner_iteration_failed err=%s", exc)
            await asyncio.sleep(self._interval)

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None


__all__ = ("ScheduledScanner",)
