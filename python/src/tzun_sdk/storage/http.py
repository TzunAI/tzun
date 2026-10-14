"""HTTP backend storage adapter.

Calls the hosted service's REST API (the platform backend). Both async (``httpx.AsyncClient``)
and sync (``httpx.Client``) paths.

Security posture:

* Bearer auth — token sent in ``Authorization: Bearer <token>``.
* Bearer token NEVER logged — redacted as ``***`` in any structured
  log line; the exception path explicitly strips the Authorization header
  before re-raising.
* HTTPS-only for non-localhost URLs — constructor rejects plain
  HTTP unless the host is ``localhost``/``127.0.0.1``.

Retry policy:
* Idempotent ops (GET, HEAD) retry on 5xx + connection errors.
* Non-idempotent ops (POST, DELETE) do NOT auto-retry.
* Exponential backoff: 200ms → 400ms → 800ms, max 3 attempts.

Evidence reads use the routes the platform serves to an API key
(``app-reads-routes.ts``), scoped by the key to its account and env:
``GET /v1/app/evidence`` (newest first, at most 200 a page) and
``GET /v1/app/evidence/{id}``. ``retrieve`` and ``list`` unwrap the
``envelope`` of each answer.

The chain head: the platform holds the chain lock and stamps every capture, so
the adapter keeps the head the platform last reported for each chain (the
capture receipt's ``sequence`` and ``headDigest``, or a ``409 chain_conflict``
body's ``expectedPreviousDigest`` and ``expectedSequence``). Until it has one,
``head_raw`` takes the highest sequence on the platform's newest page as a
starting point. A wrong starting point costs a re-stamp or one refused
attempt, never a wrong record: the platform re-stamps a capture without a
chain link onto its head and refuses one whose link does not match it.

Catalogs (the SDK 0.8.0 cloud catalog contract): ``register_descriptor`` /
``get_descriptor`` call ``POST /v1/models`` / ``GET /v1/models/{digest}``, and
``put_agent_descriptor`` / ``get_agent_descriptor`` / ``list_agent_descriptors``
call ``POST /v1/agents`` / ``GET /v1/agents/{digest}`` / ``GET /v1/agents``. A
backend that does not serve a catalog's routes makes this a store without that
catalog for :data:`CATALOG_REPROBE_SECONDS`: ``register_descriptor`` raises
:class:`~tzun_sdk.errors.ModelCatalogUnsupportedError`, ``get_descriptor``
answers ``None``, and the agent methods raise
:class:`~tzun_sdk.errors.InvalidAgentDescriptorError` with the code
``agent_not_supported_by_store``, which ``tzun.agents`` reports and
verification and export read as ``catalog_absent``. Capture reads neither
catalog for an agent reference: the platform checks those itself.

"Not served" is a 405, a 501, or the catch-all's JSON ``404 {"error":
"not_found"}`` on a write. A 404 without a JSON error code (an edge's page
during a deploy) is raised as it came, and decides nothing. A JSON 404 on a
model lookup is always "not held". A 404 on an agent lookup is "not
registered" when it carries ``agent_not_registered``; a bare ``not_found`` is
"not registered" when the agent catalog has answered a 2xx within the window,
and is otherwise settled by asking for one row of the listing. Every row read
is re-hashed: one whose bytes do not hash to the digest asked for is refused
(:class:`~tzun_sdk.errors.TzunError`) and never kept.
"""

from __future__ import annotations

import asyncio
import builtins
import hashlib
import json
import logging
import time
from collections.abc import Sequence
from typing import Any, Literal, TypeGuard
from urllib.parse import quote, urlparse

import httpx

from tzun_sdk._record_rules import js_json_loads
from tzun_sdk.agents import (
    agent_descriptor_digest,
    agent_descriptor_violation,
    canonical_serialize_agent_descriptor,
)
from tzun_sdk.errors import (
    InvalidAgentDescriptorError,
    MandateRefusedError,
    ModelCatalogUnsupportedError,
    TzunCaptureError,
    TzunError,
)
from tzun_sdk.models import (
    AgentDescriptorRow,
    AnnotationRecord,
    AttestationArtifacts,
    EvidenceEnvelope,
    ForkRecord,
    ModelDescriptor,
    ModelDescriptorAnnotationRow,
    ModelDescriptorRow,
    RelinkRecord,
    StoreOptions,
    TamperIncident,
)
from tzun_sdk.storage._records import raw_envelope
from tzun_sdk.storage._revision_log import EnvelopeRevision

LOG = logging.getLogger(__name__)
REDACTED = "***"
IDEMPOTENT_METHODS = frozenset({"GET", "HEAD"})

#: How long a backend's "route not served" answer for a catalog stands before
#: the adapter asks again, in seconds: one probe per window, not one per
#: wrapped call, and a backend upgraded under a running client is used within
#: one window. The TS twin is ``CATALOG_REPROBE_MS``.
CATALOG_REPROBE_SECONDS = 5 * 60

#: Catalog rows each kind keeps in the adapter's cache (rows are immutable).
_CATALOG_ROW_CACHE_SIZE = 256

_CatalogKind = Literal["models", "agents", "agents.list"]


def _error_body(error: TzunError) -> dict[str, Any] | None:
    """The JSON object an HTTP error response carried, or ``None``."""
    cause = error.__cause__
    if not isinstance(cause, httpx.HTTPStatusError):
        return None
    try:
        body = cause.response.json()
    except Exception:
        return None
    return body if isinstance(body, dict) else None


def _wire_code(error: TzunCaptureError) -> str | None:
    """The ``error`` code of the JSON body an HTTP error carried, or ``None`` when the body was not one."""
    body = _error_body(error)
    code = body.get("error") if body is not None else None
    return code if isinstance(code, str) else None


def _route_not_served(error: TzunCaptureError) -> bool:
    """Whether an HTTP error says the backend does not serve the route.

    A 405, a 501, or the catch-all's JSON ``404 {"error": "not_found"}``: a
    catalog route that is served never answers ``not_found`` (its "not held"
    codes are ``descriptor_not_registered`` and ``agent_not_registered``). A
    404 without that body decides nothing.
    """
    if error.status == 404:
        return _wire_code(error) == "not_found"
    return error.status in (405, 501)


def _sha256_prefixed(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


#: The longest cursor a listing passes on (a platform's is a 71-character digest).
_CURSOR_MAX = 512


def _pagination_refusal(error: TzunCaptureError) -> TzunError | None:
    """The backend's refusal of a listing's ``limit`` or ``cursor``, as a local store words it; ``None`` otherwise."""
    if error.status != 400 or not isinstance(error.__cause__, httpx.HTTPStatusError):
        return None
    try:
        payload = error.__cause__.response.json()
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("error") != "invalid_request":
        return None
    field = payload.get("field")
    if field == "limit":
        return TzunError("limit must be 1 to 200")
    if field == "cursor" or payload.get("reason") == "invalid_pagination":
        return TzunError("cursor must be one a previous page returned")
    return None


def _agent_catalog_absent() -> InvalidAgentDescriptorError:
    return InvalidAgentDescriptorError(
        "agent_not_supported_by_store",
        "agents",
        "this store keeps no agent catalog; capture accepts agent references as given",
    )


def _is_http_404(error: TzunError) -> bool:
    """True only when ``error`` wraps a real HTTP 404.

    The reads that answer ``None`` for "not found" (``retrieve_raw``,
    ``resolve_model_descriptor_alias``, ``get_enriched_model_descriptor``)
    answer it only for this. Any other ``TzunError`` is raised: answering
    ``None`` for an expired API key, a revoked scope or a backend outage would
    make it indistinguishable from "no such alias", and a caller reading
    ``resolve_alias('prod')`` would treat production model routing as unset
    while the real cause was a credential rotation.

    ``_request_async`` raises :class:`TzunCaptureError` (a ``TzunError``)
    carrying ``status`` for an HTTP error response, and a plain ``TzunError``
    with no status for a connection failure, so both are checked.
    """
    status = getattr(error, "status", None)
    if status == 404:
        return True
    cause = error.__cause__
    return isinstance(cause, httpx.HTTPStatusError) and cause.response.status_code == 404


#: The evidence read route the platform serves to an API key.
EVIDENCE_READ_PATH = "/v1/app/evidence"

#: The platform's largest page of ``GET /v1/app/evidence`` (``MAX_LIMIT``); a
#: larger ``limit`` is answered with this many.
_PLATFORM_PAGE_LIMIT = 200

#: The platform's furthest ``offset`` (``MAX_OFFSET``); a larger one is
#: answered as this one, so a walk stops here instead of reading one page again.
_PLATFORM_MAX_OFFSET = 100_000

#: The chain the platform resolves when a capture names none.
_DEFAULT_CHAIN = "default"

#: A chain head as the platform reported it: ``(sequence, digest)``, the
#: sequence ``None`` when only the digest was reported; ``None`` for an empty chain.
_ChainPosition = tuple[int | None, str] | None


def _evidence_page(body: Any, *, with_envelope: bool) -> builtins.list[dict[str, Any]]:
    """The items of a ``GET /v1/app/evidence`` answer, ``{"evidence": [...]}``.

    Raises :class:`TzunError` for any other shape, and, when ``with_envelope``,
    for an item without its ``envelope``: a page the adapter cannot read is
    never answered as an empty one.
    """
    page = body.get("evidence") if isinstance(body, dict) else None
    if not isinstance(page, builtins.list) or not all(isinstance(item, dict) for item in page):
        raise TzunError(f"GET {EVIDENCE_READ_PATH} answered a body that is not a page of evidence")
    if with_envelope and not all(isinstance(item.get("envelope"), dict) for item in page):
        raise TzunError(f"GET {EVIDENCE_READ_PATH} answered an item without its envelope")
    return page


def _is_int(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


class HttpBackendAdapter:
    """REST-API-backed storage adapter."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        timeout: float = 30.0,
        max_attempts: int = 3,
        initial_backoff: float = 0.2,
        mode: str = "async",
    ) -> None:
        if mode not in ("async", "sync"):
            raise TzunError(f"HttpBackendAdapter: mode must be 'async' or 'sync', got {mode!r}")
        parsed = urlparse(base_url)
        # HTTPS-only for non-localhost.
        if parsed.scheme not in ("http", "https"):
            raise TzunError(
                f"HttpBackendAdapter: invalid scheme {parsed.scheme!r} (expected http or https)"
            )
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "http" and host not in ("localhost", "127.0.0.1", "::1"):
            raise TzunError(
                "HttpBackendAdapter requires HTTPS for non-localhost base URLs "
                ". Plain HTTP to non-localhost hosts is rejected."
            )
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._initial_backoff = initial_backoff
        self._mode = mode
        self._async_client: httpx.AsyncClient | None = None
        # Each chain's head as the platform last reported it; a chain with no
        # entry has not been read or captured to yet.
        self._server_heads: dict[str, _ChainPosition] = {}
        # Until when (``time.monotonic()``) each catalog is taken as not served.
        self._catalog_absent_until: dict[_CatalogKind, float] = {}
        # Until when (``time.monotonic()``) the agent catalog is taken as
        # served, after a 2xx from one of its routes: a backend rolled back to
        # a build without the routes is noticed within one window.
        self._agent_catalog_served_until = 0.0
        self._model_rows: dict[str, ModelDescriptor] = {}
        self._agent_rows: dict[str, AgentDescriptorRow] = {}

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Content-Type": "application/json",
        }

    async def _ensure_async_client(self) -> httpx.AsyncClient:
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                base_url=self._base_url, timeout=self._timeout
            )
        return self._async_client

    async def _request_async(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Send an async HTTP request, merging per-call ``headers`` over the
        default ``_headers()`` (Authorization + Content-Type).

        The ``headers`` parameter is intentionally keyword-only to avoid
        breaking existing positional call-sites.
        """
        client = await self._ensure_async_client()
        idempotent = method in IDEMPOTENT_METHODS
        # Merge: defaults first, per-call headers override.
        merged_headers = {**self._headers(), **(headers or {})}
        attempt = 0
        backoff = self._initial_backoff
        last_exc: Exception | None = None
        while True:
            attempt += 1
            try:
                resp = await client.request(
                    method, path, json=json, params=params, headers=merged_headers
                )
                if idempotent and 500 <= resp.status_code < 600 and attempt < self._max_attempts:
                    LOG.warning(
                        "http_retry method=%s path=%s status=%d attempt=%d/%d",
                        method,
                        path,
                        resp.status_code,
                        attempt,
                        self._max_attempts,
                    )
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                resp.raise_for_status()
                return resp
            except httpx.HTTPStatusError as e:
                # Strip the Authorization header before any reraise that
                # might log the request shape.
                if e.request is not None:
                    e.request.headers.pop("Authorization", None)
                # Attempt to extract the stable machine-readable error code
                # from the response body ({"ok": false, "error": "<code>"}).
                code: str = "internal"
                try:
                    payload = e.response.json()
                    if isinstance(payload, dict) and isinstance(payload.get("error"), str):
                        code = payload["error"]
                except Exception:
                    pass
                raise TzunCaptureError(
                    f"HttpBackendAdapter {method} {path} -> {e.response.status_code} ({code})",
                    code=code,
                    status=e.response.status_code,
                ) from e
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError) as e:
                last_exc = e
                if idempotent and attempt < self._max_attempts:
                    LOG.warning(
                        "http_retry method=%s path=%s err=%s attempt=%d/%d",
                        method,
                        path,
                        type(e).__name__,
                        attempt,
                        self._max_attempts,
                    )
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                raise TzunError(f"HttpBackendAdapter {method} {path} connection error") from e
        # Unreachable
        raise TzunError(f"HttpBackendAdapter {method} {path} exhausted retries") from last_exc

    # ── Public surface ─────────────────────────────────────────────

    async def store(
        self,
        envelope: EvidenceEnvelope | dict[str, Any],
        chain_id: str | None = None,
        options: StoreOptions | None = None,
        *,
        completeness: str = "partial",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Submit an evidence envelope to the cloud capture endpoint.

        Wire contract (P1):
        - Body: ``{"completeness": ..., "envelope": {...}, "chainId": ...}``
        - Headers: ``Authorization: Bearer <token>`` always; ``Idempotency-Key``
          when ``idempotency_key`` is given.
        - Success: ``202`` → returns the parsed response dict
          ``{ok, evidenceId, chainId, sequence, state, verification,
             canonicalDigest, headDigest}``.
        - Errors: raises :class:`~tzun_sdk.errors.TzunCaptureError` carrying the
          stable ``error`` code from the server body.
        """
        # `options` is the shared StoreOptions the local adapters use for their
        # compare-and-swap. Over HTTP the CAS is the SERVER's to run — it holds
        # the chain lock and answers 409 `chain_conflict` — so
        # `expectChainHead` is deliberately not resent here; only
        # `idempotencyKey` has a wire slot, and an explicit keyword argument
        # still wins over it.
        if options is not None and (
            options.mandateClaim is not None or options.mandateIssue is not None or options.mandateRevoke is not None
        ):
            # The hosted service keeps no mandates in this release.
            raise MandateRefusedError(
                "mandate_not_supported_by_store",
                "mandate",
                "The cloud store does not host mandates in this release; capture under a mandate "
                "into a local store.",
            )
        if options is not None and idempotency_key is None:
            idempotency_key = options.idempotencyKey
        body: dict[str, Any] = {
            "completeness": completeness,
            "envelope": raw_envelope(envelope),
        }
        if chain_id:
            body["chainId"] = chain_id
        extra_headers: dict[str, str] | None = None
        if idempotency_key:
            extra_headers = {"Idempotency-Key": idempotency_key}
        try:
            resp = await self._request_async(
                "POST", "/v1/evidence", json=body, headers=extra_headers
            )
        except TzunCaptureError as e:
            if e.code == "chain_conflict":
                self._adopt_conflict_head(chain_id, e)
            raise
        receipt = dict(resp.json())
        # `headDigest` is the committed record's digest and `sequence` its
        # position: what the next capture on this chain links from. A receipt
        # without them leaves the chain to be read again.
        key = chain_id or _DEFAULT_CHAIN
        sequence, head_digest = receipt.get("sequence"), receipt.get("headDigest")
        if _is_int(sequence) and isinstance(head_digest, str) and head_digest:
            self._server_heads[key] = (sequence, head_digest)
        else:
            self._server_heads.pop(key, None)
        return receipt

    def _adopt_conflict_head(self, chain_id: str | None, error: TzunCaptureError) -> None:
        """Keep the head a ``409 chain_conflict`` names for the chain the refused capture named.

        ``expectedPreviousDigest`` is the platform's head digest (``null`` for an
        empty chain) and ``expectedSequence``, when present, the position it
        would have assigned. A refusal that names no head leaves the chain to
        be read again.
        """
        key = chain_id or _DEFAULT_CHAIN
        body = _error_body(error)
        if body is None or "expectedPreviousDigest" not in body:
            self._server_heads.pop(key, None)
            return
        expected = body["expectedPreviousDigest"]
        if expected is None:
            self._server_heads[key] = None
            return
        if not isinstance(expected, str) or expected == "":
            self._server_heads.pop(key, None)
            return
        expected_sequence = body.get("expectedSequence")
        sequence = expected_sequence - 1 if _is_int(expected_sequence) and expected_sequence >= 1 else None
        self._server_heads[key] = (sequence, expected)

    async def retrieve(self, evidence_id: str) -> EvidenceEnvelope | None:
        raw = await self.retrieve_raw(evidence_id)
        return EvidenceEnvelope.model_validate(raw) if raw is not None else None

    async def retrieve_raw(self, evidence_id: str) -> dict[str, Any] | None:
        """The record's envelope as ``GET /v1/app/evidence/{id}`` returns it, unparsed, or ``None``.

        ``None`` when the key's scope holds no such record, which is the answer
        the platform gives for another account's id too. An id that would name
        another route once resolved as a path (``""``, ``"."``, ``".."``) is
        ``None`` without a request.
        """
        if not isinstance(evidence_id, str) or evidence_id in ("", ".", ".."):
            return None
        try:
            resp = await self._request_async("GET", f"{EVIDENCE_READ_PATH}/{quote(evidence_id, safe='')}")
        except TzunError as e:
            if _is_http_404(e):
                return None
            raise
        body = js_json_loads(resp.content)
        envelope = body.get("envelope") if isinstance(body, dict) else None
        if not isinstance(envelope, dict):
            raise TzunError(f"GET {EVIDENCE_READ_PATH}/{{id}} answered a body without the record's envelope")
        return envelope

    async def list(self, **options: Any) -> list[EvidenceEnvelope]:
        return [EvidenceEnvelope.model_validate(e) for e in await self.list_raw(**options)]

    async def list_raw(self, **options: Any) -> builtins.list[dict[str, Any]]:
        """A page of envelopes, newest first, as ``GET /v1/app/evidence?include=envelope`` returns them.

        ``limit`` (at most 200) and ``offset`` are the only filters the
        platform applies, so any other option is refused rather than answered
        with a page that ignored it.
        """
        unsupported = sorted(k for k, v in options.items() if k not in ("limit", "offset") and v is not None)
        if unsupported:
            raise TzunError(
                f"HttpBackendAdapter.list(): the platform's evidence list takes limit and offset only, "
                f"not {', '.join(unsupported)}"
            )
        params: dict[str, Any] = {"include": "envelope"}
        params.update({k: options[k] for k in ("limit", "offset") if options.get(k) is not None})
        resp = await self._request_async("GET", EVIDENCE_READ_PATH, params=params)
        page = _evidence_page(js_json_loads(resp.content), with_envelope=True)
        return [item["envelope"] for item in page]

    async def _newest_position(self, digest: str | None) -> tuple[int, str] | None:
        """A chain position read from the platform's newest page (no envelopes).

        With ``digest``, the position of the record holding it; without, the
        highest sequence on the page. ``None`` when the page has no such record.
        """
        resp = await self._request_async(
            "GET", EVIDENCE_READ_PATH, params={"limit": _PLATFORM_PAGE_LIMIT, "offset": 0}
        )
        best: tuple[int, str] | None = None
        for item in _evidence_page(js_json_loads(resp.content), with_envelope=False):
            sequence, item_digest = item.get("sequenceNumber"), item.get("canonicalDigest")
            if not _is_int(sequence) or not isinstance(item_digest, str):
                continue
            if digest is not None:
                if item_digest == digest:
                    return sequence, item_digest
            elif best is None or sequence > best[0]:
                best = (sequence, item_digest)
        return best

    async def head_raw(self, chain_id: str | None = None) -> dict[str, Any] | None:
        """The chain head's position, ``{"payload": {"sequenceNumber"}, "integrity": {"canonicalDigest"}}``, or ``None``.

        The head the platform last reported for ``chain_id`` (a capture
        receipt or a ``409 chain_conflict``). Before it reported one, the
        highest sequence on the platform's newest page: that page spans every
        chain of the key's scope and names none, so on an account with several
        chains it is a starting point the platform corrects (see the module
        docstring). A digest reported without its sequence is looked up on the
        same page, and taken at sequence 0 when the page does not hold it. A
        read that fails is logged and answers ``None`` (nothing known): the
        platform stamps the capture either way.
        """
        key = chain_id or _DEFAULT_CHAIN
        try:
            if key not in self._server_heads:
                self._server_heads[key] = await self._newest_position(None)
            position = self._server_heads[key]
            if position is None:
                return None
            sequence, digest = position
            if sequence is None:
                found = await self._newest_position(digest)
                sequence = found[0] if found is not None else 0
                self._server_heads[key] = (sequence, digest)
        except TzunError as e:
            LOG.warning(
                "cloud_head_read_failed path=%s status=%s code=%s",
                EVIDENCE_READ_PATH,
                getattr(e, "status", None),
                getattr(e, "code", None),
            )
            position = self._server_heads.get(key)
            if position is None:
                return None
            sequence = position[0] if position[0] is not None else 0
            digest = position[1]
        return {"payload": {"sequenceNumber": sequence}, "integrity": {"canonicalDigest": digest}}

    async def list_by_sequence(
        self,
        from_sequence: int | None = None,
        to_sequence: int | None = None,
        chain_id: str | None = None,
    ) -> builtins.list[EvidenceEnvelope]:
        """Sequence-range lookup over the platform's evidence list.

        The list has no sequence or chain filter, so this pages it (200 a page)
        and filters client-side.

        LIMITATION: ``chain_id`` cannot be honoured — the list carries no chain
        identifier — so the result is sequence-scoped only. An account with
        more than one chain must not be used for chain-link verification
        through this adapter. The platform pages no further than offset
        100000; a walk that would go further raises :class:`TzunError`.
        """
        lower = 1 if from_sequence is None else from_sequence
        collected: builtins.list[EvidenceEnvelope] = []
        offset = 0
        while True:
            if offset > _PLATFORM_MAX_OFFSET:
                raise TzunError(
                    f"HttpBackendAdapter.list_by_sequence(): the platform's evidence list pages no further "
                    f"than offset {_PLATFORM_MAX_OFFSET}"
                )
            batch = await self.list(limit=_PLATFORM_PAGE_LIMIT, offset=offset)
            if not batch:
                break
            for env in batch:
                seq = env.payload.sequenceNumber
                if seq >= lower and (to_sequence is None or seq <= to_sequence):
                    collected.append(env)
            if len(batch) < _PLATFORM_PAGE_LIMIT:
                break
            offset += _PLATFORM_PAGE_LIMIT
        collected.sort(key=lambda e: e.payload.sequenceNumber)
        return collected

    async def head(self, chain_id: str | None = None) -> EvidenceEnvelope | None:
        """The record with the highest sequence on the platform's newest page of whole records.

        The platform lists newest first, so the head of a chain that is
        captured to in order is on that page. LIMITATION, as for
        ``list_by_sequence``: the page spans every chain of the key's scope,
        so ``chain_id`` cannot be honoured.
        """
        first = await self.list(limit=_PLATFORM_PAGE_LIMIT, offset=0)
        return max(first, key=lambda e: e.payload.sequenceNumber) if first else None

    async def ensure_tables(self) -> None:
        # The HTTP backend manages its own schema; the adapter is a no-op.
        return None

    # ── Catalogs (the SDK 0.8.0 cloud catalog contract) ───────────────────

    def _catalog_absent(self, kind: _CatalogKind) -> bool:
        until = self._catalog_absent_until.get(kind)
        if until is None:
            return False
        if time.monotonic() < until:
            return True
        del self._catalog_absent_until[kind]
        return False

    def _mark_catalog_absent(self, kind: _CatalogKind) -> None:
        self._catalog_absent_until[kind] = time.monotonic() + CATALOG_REPROBE_SECONDS

    def _mark_agent_catalog_served(self) -> None:
        self._agent_catalog_served_until = time.monotonic() + CATALOG_REPROBE_SECONDS

    @staticmethod
    def _remember(cache: dict[str, Any], digest: str, row: Any) -> None:
        cache[digest] = row
        if len(cache) > _CATALOG_ROW_CACHE_SIZE:
            del cache[next(iter(cache))]

    async def register_descriptor(
        self,
        descriptor: ModelDescriptor,
        *,
        source: str = "connector-auto",
        registered_by: str = "python-sdk",
    ) -> str:
        """Register a model descriptor (``POST /v1/models``), idempotently on identical bytes.

        The digest is computed here over the canonical bytes, and a backend
        answer naming another digest is refused (:class:`TzunError`): a record
        never names a digest this SDK did not compute.

        Raises:
            ModelCatalogUnsupportedError: the backend does not serve the route.
        """
        from tzun_sdk.storage.memory import _compute_descriptor_digest

        digest = _compute_descriptor_digest(descriptor)
        if self._catalog_absent("models"):
            raise ModelCatalogUnsupportedError("this store keeps no model catalog")
        try:
            resp = await self._request_async(
                "POST",
                "/v1/models",
                json={
                    "descriptor": descriptor.model_dump(mode="json", exclude_none=False),
                    "source": source,
                    "registeredBy": registered_by,
                },
            )
        except TzunCaptureError as e:
            if _route_not_served(e):
                self._mark_catalog_absent("models")
                raise ModelCatalogUnsupportedError("this store keeps no model catalog") from e
            raise
        body = resp.json()
        answered = body.get("digest") if isinstance(body, dict) else None
        if not isinstance(answered, str) or answered == "":
            # The descriptor digest is the catalog's answer; the model's
            # weights digest is another kind of digest and is never taken for it.
            raise TzunError("POST /v1/models answered without the registered descriptor's digest")
        if answered != digest:
            raise TzunError(
                "POST /v1/models answered a digest other than the one computed over the descriptor sent"
            )
        return digest

    async def get_descriptor(self, digest: str) -> ModelDescriptor | None:
        """The descriptor the backend's catalog holds under ``digest`` (``GET /v1/models/{digest}``).

        Read from the row's ``canonicalBytes``, which must hash to ``digest``
        (a row that does not is refused with :class:`TzunError`). ``None``
        when the key's scope does not hold it (a JSON 404), the reference is
        not a descriptor digest, or the backend keeps no model catalog.
        """
        if not isinstance(digest, str) or not _is_prefixed_digest(digest):
            return None
        cached = self._model_rows.get(digest)
        if cached is not None:
            return cached.model_copy(deep=True)
        if self._catalog_absent("models"):
            return None
        try:
            resp = await self._request_async("GET", f"/v1/models/{quote(digest, safe='')}")
        except TzunCaptureError as e:
            # A JSON 404 is "not held"; a lookup never decides the catalog is absent.
            if (e.status == 404 and _wire_code(e) is not None) or e.status in (405, 501):
                return None
            raise
        body = resp.json()
        canonical = body.get("canonicalBytes") if isinstance(body, dict) else None
        if not isinstance(canonical, str):
            raise TzunError("GET /v1/models/{digest} answered without the row's canonicalBytes")
        if _sha256_prefixed(canonical) != digest:
            raise TzunError("GET /v1/models/{digest} answered a row whose bytes do not hash to the digest asked for")
        try:
            descriptor = ModelDescriptor.model_validate(json.loads(canonical))
        except Exception as exc:
            raise TzunError("GET /v1/models/{digest} answered canonicalBytes that are not a descriptor") from exc
        self._remember(self._model_rows, digest, descriptor)
        return descriptor.model_copy(deep=True)

    async def put_agent_descriptor(self, descriptor: Any) -> tuple[str, bool]:
        """Register an agent descriptor (``POST /v1/agents``); ``(digest, already_existed)``.

        The descriptor is checked here as every store checks it, and a backend
        answer naming another digest is refused (:class:`TzunError`).
        """
        reason = agent_descriptor_violation(descriptor)
        if reason is not None:
            raise InvalidAgentDescriptorError("invalid_agent_descriptor", "descriptor", reason)
        digest = agent_descriptor_digest(descriptor)
        if self._catalog_absent("agents"):
            raise _agent_catalog_absent()
        try:
            resp = await self._request_async("POST", "/v1/agents", json={"descriptor": descriptor})
        except TzunCaptureError as e:
            if _route_not_served(e):
                self._mark_catalog_absent("agents")
                raise _agent_catalog_absent() from e
            raise
        self._mark_agent_catalog_served()
        body = resp.json()
        answered = body.get("digest") if isinstance(body, dict) else None
        if answered != digest:
            raise TzunError("POST /v1/agents answered a digest other than the one computed over the descriptor sent")
        return digest, body.get("alreadyExisted") is True

    async def get_agent_descriptor(self, digest: str) -> AgentDescriptorRow | None:
        """The catalog row (``GET /v1/agents/{digest}``), or ``None`` when the key's scope does not hold it.

        A row whose bytes do not hash to ``digest`` is refused with
        :class:`TzunError`. Raises :class:`InvalidAgentDescriptorError`
        (``agent_not_supported_by_store``) when the backend does not serve
        the route.
        """
        if self._catalog_absent("agents"):
            raise _agent_catalog_absent()
        if not isinstance(digest, str) or not _is_prefixed_digest(digest):
            return None
        cached = self._agent_rows.get(digest)
        if cached is not None:
            return cached.model_copy(deep=True)
        try:
            resp = await self._request_async("GET", f"/v1/agents/{quote(digest, safe='')}")
        except TzunCaptureError as e:
            code = _wire_code(e) if e.status == 404 else None
            if code == "agent_not_registered":
                return None
            if code == "not_found" and await self._agent_catalog_is_served():
                return None
            if _route_not_served(e):
                self._mark_catalog_absent("agents")
                raise _agent_catalog_absent() from e
            raise
        self._mark_agent_catalog_served()
        row = _agent_row(resp.json())
        if row is None or row.digest != digest:
            raise TzunError("GET /v1/agents/{digest} answered a body that is not the catalog row")
        if _sha256_prefixed(row.canonicalBytes) != digest:
            raise TzunError("GET /v1/agents/{digest} answered a row whose bytes do not hash to the digest asked for")
        self._remember(self._agent_rows, digest, row)
        return row.model_copy(deep=True)

    async def _agent_catalog_is_served(self) -> bool:
        """Whether the backend serves the agent catalog: known from a 2xx within the window, or asked with one listing row."""
        if time.monotonic() < self._agent_catalog_served_until:
            return True
        try:
            await self._request_async("GET", "/v1/agents", params={"limit": 1})
        except TzunCaptureError as e:
            if _route_not_served(e):
                return False
            raise
        self._mark_agent_catalog_served()
        return True

    async def list_agent_descriptors(
        self,
        *,
        name: str | None = None,
        organization: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> tuple[builtins.list[AgentDescriptorRow], str | None]:
        """A page of the backend's agent catalog (``GET /v1/agents``).

        The cursor is the backend's own, handed back to it unread: any
        non-empty string of at most 512 printable ASCII characters is sent,
        and one the backend refuses (a 400 naming ``cursor`` or ``limit``, or
        reason ``invalid_pagination``) raises the :class:`TzunError` a local
        store raises for a cursor it did not hand out.

        Raises :class:`InvalidAgentDescriptorError` (``agent_not_supported_by_store``)
        when the backend does not serve the listing (it may serve register and
        get without it).
        """
        from tzun_sdk.storage._records import page_limit

        size = page_limit(limit)
        if cursor is not None and (
            not isinstance(cursor, str)
            or not 1 <= len(cursor) <= _CURSOR_MAX
            or not all("\x21" <= c <= "\x7e" for c in cursor)
        ):
            raise TzunError("cursor must be one a previous page returned")
        if self._catalog_absent("agents") or self._catalog_absent("agents.list"):
            raise _agent_catalog_absent()
        params: dict[str, Any] = {"limit": size}
        if name is not None:
            params["name"] = name
        if organization is not None:
            params["organization"] = organization
        if cursor is not None:
            params["cursor"] = cursor
        try:
            resp = await self._request_async("GET", "/v1/agents", params=params)
        except TzunCaptureError as e:
            if _route_not_served(e):
                self._mark_catalog_absent("agents.list")
                raise _agent_catalog_absent() from e
            refused = _pagination_refusal(e)
            if refused is not None:
                raise refused from e
            raise
        self._mark_agent_catalog_served()
        payload = resp.json()
        body = payload if isinstance(payload, dict) else {}
        # ``rows``/``cursor``, or the ``agents``/``nextCursor`` spelling of the same page.
        rows = body.get("rows", body.get("agents"))
        nxt = body["cursor"] if "cursor" in body else body.get("nextCursor")
        if not isinstance(rows, builtins.list) or (nxt is not None and not isinstance(nxt, str)):
            raise TzunError("GET /v1/agents answered a body that is not a page of the catalog")
        page: builtins.list[AgentDescriptorRow] = []
        for item in rows:
            row = _agent_row(item)
            if row is None:
                raise TzunError("GET /v1/agents answered a row that is not a catalog row")
            page.append(row)
        return page, nxt

    async def store_attestation(
        self, evidence_id: str, blob: AttestationArtifacts
    ) -> None:
        # POST /v1/evidence/:id/attestations is NOT served by the SDK REST surface.
        raise TzunError(
            "store_attestation() is not supported by this backend — "
            "POST /v1/evidence/:id/attestations has no SDK REST route."
        )

    async def get_attestations(
        self, evidence_id: str
    ) -> builtins.list[AttestationArtifacts]:
        # GET /v1/evidence/:id/attestations is NOT served by the SDK REST surface.
        raise TzunError(
            "get_attestations() is not supported by this backend — "
            "GET /v1/evidence/:id/attestations has no SDK REST route."
        )

    async def list_envelope_revisions(
        self, evidence_id: str
    ) -> builtins.list[EnvelopeRevision]:
        # The revision log lives server-side; there is no SDK
        # REST route for it. This RAISES rather than answering [] for the same
        # reason the reads above do: an empty answer would say "this record
        # was never rewritten" about evidence the SDK has not looked at, which
        # is the reassuring lie.
        raise TzunError(
            "list_envelope_revisions() is not supported by this backend — "
            "GET /v1/evidence/:id/revisions has no SDK REST route."
        )

    async def get_capture_digests(self, evidence_ids: Sequence[str]) -> dict[str, str]:
        # Same, and more sharply: an empty map here reads as "no record in the
        # store was ever superseded".
        raise TzunError(
            "get_capture_digests() is not supported by this backend — "
            "the revision log has no SDK REST route."
        )

    async def store_annotation(self, record: AnnotationRecord) -> None:
        # POST /v1/recovery/annotations is NOT served by the SDK REST surface.
        raise TzunError(
            "store_annotation() is not supported by this backend — "
            "POST /v1/recovery/annotations has no SDK REST route."
        )

    async def store_relink(self, record: RelinkRecord) -> None:
        # POST /v1/recovery/relinks is NOT served by the SDK REST surface.
        raise TzunError(
            "store_relink() is not supported by this backend — "
            "POST /v1/recovery/relinks has no SDK REST route."
        )

    async def store_fork(self, record: ForkRecord) -> None:
        # POST /v1/recovery/forks is NOT served by the SDK REST surface.
        raise TzunError(
            "store_fork() is not supported by this backend — "
            "POST /v1/recovery/forks has no SDK REST route."
        )

    async def store_incident(self, incident: TamperIncident) -> None:
        # POST /v1/incidents is NOT served by the SDK REST surface.
        raise TzunError(
            "store_incident() is not supported by this backend — "
            "POST /v1/incidents has no SDK REST route."
        )

    # ── Catalog primitives ────────────────────────────────────────────────

    async def list_model_descriptors(
        self,
        vendor: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> builtins.list[ModelDescriptorRow]:
        params: dict[str, Any] = {}
        if vendor is not None:
            params["vendor"] = vendor
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        resp = await self._request_async("GET", "/v1/models", params=params or None)
        # GET /v1/models strips canonicalBytes (models-routes.ts:64-69) — validate
        # with canonicalBytes absent (the generated field is required but the HTTP
        # route omits it; use model_validate with missing-field fallback).
        items = resp.json().get("models", resp.json().get("items", []))
        return [ModelDescriptorRow.model_validate(m) for m in items]

    async def list_model_descriptor_annotations(
        self, digest: str
    ) -> builtins.list[ModelDescriptorAnnotationRow]:
        resp = await self._request_async("GET", f"/v1/models/{digest}/annotations")
        items = resp.json() if isinstance(resp.json(), list) else resp.json().get("annotations", [])
        return [ModelDescriptorAnnotationRow.model_validate(a) for a in items]

    async def append_model_descriptor_annotation(
        self, row: ModelDescriptorAnnotationRow
    ) -> None:
        raise TzunError(
            "append_model_descriptor_annotation is not supported directly by the HTTP adapter; "
            "use POST /v1/models/{digest}/annotations via tzun.models.annotate"
        )

    async def set_model_descriptor_alias(
        self, slug: str, digest: str, set_by: str
    ) -> None:
        await self._request_async(
            "POST", "/v1/models/aliases",
            json={"slug": slug, "digest": digest, "setBy": set_by},
        )

    async def resolve_model_descriptor_alias(self, slug: str) -> str | None:
        try:
            resp = await self._request_async("GET", f"/v1/models/by-alias/{slug}")
        except TzunError as e:
            # Only a 404 means "no such alias". An expired key (401), a
            # revoked scope (403), a backend outage (5xx) or a connection
            # error must NOT be reported as "unset" — see _is_http_404.
            if _is_http_404(e):
                return None
            raise
        data = resp.json()
        return data.get("digest") or data.get("modelDescriptorDigest") or None

    async def get_enriched_model_descriptor(self, digest: str) -> ModelDescriptor | None:
        try:
            resp = await self._request_async("GET", f"/v1/models/{digest}/enriched")
        except TzunError as e:
            if _is_http_404(e):
                return None
            raise
        return ModelDescriptor.model_validate(resp.json())

    async def delete_envelope_for_demo(self, evidence_id: str) -> None:
        # DELETE /v1/evidence/:id is NOT served by the SDK REST surface.
        # The SDK REST layer has no DELETE route for evidence.
        raise TzunError(
            "delete_envelope_for_demo() is not supported by this backend — "
            "DELETE /v1/evidence/:id has no SDK REST route."
        )

    async def close(self) -> None:
        if self._async_client is not None:
            await self._async_client.aclose()
            self._async_client = None


def _is_prefixed_digest(value: str) -> bool:
    """``sha256:`` and 64 lowercase hex: the form of a descriptor digest."""
    return (
        len(value) == 71
        and value.startswith("sha256:")
        and all(c in "0123456789abcdef" for c in value[7:])
    )


def _agent_row(value: Any) -> AgentDescriptorRow | None:
    """An agent catalog row from a backend body, or ``None`` for any other shape.

    ``canonicalBytes`` are taken as sent; a body carrying the parsed
    ``descriptor`` in their place has them computed from it. Either way capture
    and verification re-hash the bytes against the reference.
    """
    if not isinstance(value, dict):
        return None
    fields = {k: value.get(k) for k in ("digest", "canonicalBytes", "name", "organization", "parent", "registeredAt")}
    descriptor = value.get("descriptor")
    if not isinstance(fields["canonicalBytes"], str):
        if not isinstance(descriptor, dict):
            return None
        try:
            fields["canonicalBytes"] = canonical_serialize_agent_descriptor(descriptor)
        except Exception:
            return None
    if "parent" not in value and isinstance(descriptor, dict):
        fields["parent"] = descriptor.get("parent")
    try:
        return AgentDescriptorRow.model_validate(fields)
    except Exception:
        return None


__all__ = ("CATALOG_REPROBE_SECONDS", "HttpBackendAdapter")
