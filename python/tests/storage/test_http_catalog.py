"""The HTTP backend's model and agent catalogs (SDK 0.8.0 cloud catalog contract).

``HttpBackendAdapter`` registers and reads descriptors through
``POST /v1/models`` / ``GET /v1/models/{digest}`` and ``POST /v1/agents`` /
``GET /v1/agents/{digest}`` / ``GET /v1/agents``, so a wrapped vendor call over
it records its model; against a backend that does not serve them it answers as
a store without the catalog. The TS twin is ``tests/ts/cloud-catalog.test.ts``.

NON-VACUITY: each fallback case is paired with the same call recording the
model, or resolving the reference, against a backend that serves the catalog.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

import httpx
import pytest

from tzun_sdk import Tzun, attach
from tzun_sdk._generated.canonical import canonical_serialize_descriptor
from tzun_sdk._verify_rows import resolve_agent_references
from tzun_sdk.agents import agent_descriptor_digest, canonical_serialize_agent_descriptor
from tzun_sdk.errors import (
    InvalidAgentDescriptorError,
    InvalidContributionsError,
    ModelCatalogUnsupportedError,
    TzunCaptureError,
    TzunError,
)
from tzun_sdk.models import DecisionInput, ModelDescriptor
from tzun_sdk.storage import http as http_module
from tzun_sdk.storage.http import CATALOG_REPROBE_SECONDS, HttpBackendAdapter
from tzun_sdk.storage.memory import _compute_descriptor_digest

DECIDER = {"kind": "human", "id": "acct:test-reviewer"}


def _descriptor(model_name: str = "claims-model") -> ModelDescriptor:
    return ModelDescriptor(
        descriptorVersion="d1",
        vendor="example-vendor",
        modelName=model_name,
        modelVersion="v1",
        integrityTier="vendor-asserted",
    )


def _agent(name: str = "rules", **over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "v": "tzun-agent/1",
        "derivation": "base",
        "identities": [],
        "instructions": None,
        "keys": [],
        "models": [],
        "name": name,
        "operator": {"organization": "Example Org", "owner": None},
        "parent": None,
        "policy": None,
        "runtime": None,
        "tools": None,
    }
    d.update(over)
    return d


class FakePlatform:
    """The backend's key-authenticated surface; ``catalog=False`` predates the catalog endpoints.

    With the catalog, ``POST /v1/evidence`` refuses an agent reference the
    catalog does not hold, or a ``policy-engine`` agent whose descriptor names
    a model, as the platform does (``400 invalid_request`` with ``reason``).
    """

    def __init__(self, *, catalog: bool = True, agent_list: bool = True, bare_404: bool = False) -> None:
        # ``bare_404``: what the hosted service's catalog routes answer. An
        # unregistered digest answers the
        # catch-all's ``not_found``, an agent row carries its parsed
        # ``descriptor`` in place of ``canonicalBytes`` and ``parent``, and a
        # listing is ``{agents, nextCursor}`` ordered by digest, whose cursor is
        # the last row's digest; a cursor that is not a digest is
        # ``400 {"error": "invalid_request", "field": "cursor"}``.
        self.catalog = catalog
        self.agent_list = agent_list
        self.bare_404 = bare_404
        self.requests: list[str] = []
        self.evidence: list[dict[str, Any]] = []
        self.model_posts: list[dict[str, Any]] = []
        self.models: dict[str, str] = {}
        self.agents: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _json(status: int, body: Any) -> httpx.Response:
        return httpx.Response(status, headers={"Content-Type": "application/json"}, content=json.dumps(body).encode())

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method
        self.requests.append(f"{method} {path}")
        body = json.loads(request.content.decode()) if request.content else None
        if method == "POST" and path == "/v1/evidence":
            refused = self._agent_refusal(body["envelope"]["payload"]) if self.catalog else None
            if refused is not None:
                return self._json(400, {"ok": False, "error": "invalid_request", **refused})
            envelope = body["envelope"]
            self.evidence.append(envelope)
            return self._json(
                202,
                {
                    "ok": True,
                    "evidenceId": envelope["payload"]["evidenceId"],
                    "sequence": envelope["payload"]["sequenceNumber"],
                    "headDigest": envelope["integrity"]["canonicalDigest"],
                },
            )
        if method == "GET" and path == "/v1/app/evidence":
            items = [
                {
                    "evidenceId": e["payload"]["evidenceId"],
                    "sequenceNumber": e["payload"]["sequenceNumber"],
                    "canonicalDigest": e["integrity"]["canonicalDigest"],
                }
                for e in reversed(self.evidence)
            ]
            return self._json(200, {"evidence": items})
        if not self.catalog:
            return self._json(404, {"ok": False, "error": "not_found"})
        if method == "POST" and path == "/v1/models":
            self.model_posts.append(body)
            canonical = canonical_serialize_descriptor(body["descriptor"])
            digest = _compute_descriptor_digest(ModelDescriptor.model_validate(body["descriptor"]))
            existed = digest in self.models
            self.models.setdefault(digest, canonical)
            return self._json(200 if existed else 201, {"ok": True, "digest": digest, "alreadyExisted": existed})
        if method == "GET" and path.startswith("/v1/models/sha256:"):
            digest = path.rsplit("/", 1)[1]
            if digest not in self.models:
                return self._json(404, {"ok": False, "error": "not_found" if self.bare_404 else "descriptor_not_registered"})
            return self._json(200, {"ok": True, "modelDescriptorDigest": digest, "canonicalBytes": self.models[digest]})
        if method == "POST" and path == "/v1/agents":
            d = body["descriptor"]
            digest = agent_descriptor_digest(d)
            existed = digest in self.agents
            self.agents.setdefault(
                digest,
                {
                    "digest": digest,
                    "canonicalBytes": canonical_serialize_agent_descriptor(d),
                    "name": d["name"],
                    "organization": d["operator"]["organization"],
                    "parent": d["parent"],
                    "registeredAt": "2026-10-07T12:00:00.000Z",
                },
            )
            return self._json(200 if existed else 201, {"ok": True, "digest": digest, "alreadyExisted": existed})
        if method == "GET" and path.startswith("/v1/agents/sha256:"):
            row = self.agents.get(path.rsplit("/", 1)[1])
            if row is None:
                return self._json(404, {"ok": False, "error": "not_found" if self.bare_404 else "agent_not_registered"})
            return self._json(200, self._agent_body(row))
        if method == "GET" and path == "/v1/agents" and self.agent_list:
            limit = int(request.url.params.get("limit", "100"))
            cursor = request.url.params.get("cursor")
            if self.bare_404:
                if cursor is not None and not (len(cursor) == 71 and cursor.startswith("sha256:")):
                    return self._json(400, {"ok": False, "error": "invalid_request", "field": "cursor"})
                ordered = [self.agents[d] for d in sorted(self.agents) if cursor is None or d > cursor]
                page = ordered[:limit]
                nxt = page[-1]["digest"] if len(ordered) > limit and page else None
                return self._json(200, {"agents": [self._agent_body(r) for r in page], "nextCursor": nxt})
            return self._json(200, {"ok": True, "rows": list(self.agents.values())[:limit], "cursor": None})
        return self._json(404, {"ok": False, "error": "not_found"})

    def _agent_refusal(self, payload: dict[str, Any]) -> dict[str, str] | None:
        refs: list[tuple[str, Any, str]] = []
        decider = payload.get("decider") or {}
        if isinstance(decider.get("agent"), str):
            refs.append(("payload.decider.agent", decider.get("kind"), decider["agent"]))
        for i, step in enumerate((payload.get("contributions") or {}).get("steps") or []):
            actor = step.get("actor") or {}
            if isinstance(actor.get("agent"), str):
                refs.append((f"payload.contributions.steps[{i}].actor.agent", actor.get("kind"), actor["agent"]))
        for field, kind, agent in refs:
            row = self.agents.get(agent)
            if row is None:
                return {"reason": "agent_not_registered", "field": field}
            if kind == "policy-engine" and json.loads(row["canonicalBytes"])["models"]:
                return {"reason": "agent_kind_mismatch", "field": field}
        return None

    def _agent_body(self, row: dict[str, Any]) -> dict[str, Any]:
        if not self.bare_404:
            return {"ok": True, **row}
        return {
            "digest": row["digest"],
            "descriptor": json.loads(row["canonicalBytes"]),
            "name": row["name"],
            "organization": row["organization"],
            "registeredAt": row["registeredAt"],
        }

    def adapter(self, handler: Any = None) -> HttpBackendAdapter:
        adapter = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="tzk_test_catalog", initial_backoff=0)
        adapter._async_client = httpx.AsyncClient(
            base_url="https://api.tzun.ai", transport=httpx.MockTransport(handler or self.handler)
        )
        return adapter


# ── The model catalog ────────────────────────────────────────────────────────


async def test_register_posts_the_contract_body_and_answers_the_computed_digest() -> None:
    platform = FakePlatform()
    adapter = platform.adapter()
    d = _descriptor()
    digest = await adapter.register_descriptor(d)
    assert digest == "sha256:" + hashlib.sha256(
        canonical_serialize_descriptor(d.model_dump(mode="json", exclude_none=False)).encode()
    ).hexdigest()
    assert platform.model_posts == [
        {"descriptor": d.model_dump(mode="json", exclude_none=False), "source": "connector-auto", "registeredBy": "python-sdk"}
    ]
    assert await adapter.register_descriptor(d) == digest
    await adapter.close()


async def test_get_reads_the_descriptor_from_canonical_bytes_and_keeps_it() -> None:
    platform = FakePlatform()
    adapter = platform.adapter()
    d = _descriptor()
    digest = await adapter.register_descriptor(d)
    got = await adapter.get_descriptor(digest)
    assert got is not None and got.modelName == "claims-model"
    assert _compute_descriptor_digest(got) == digest
    await adapter.get_descriptor(digest)
    assert [r for r in platform.requests if r.startswith("GET /v1/models/")] == [f"GET /v1/models/{digest}"]
    await adapter.close()


async def test_get_answers_none_for_a_digest_the_scope_does_not_hold_and_asks_again() -> None:
    platform = FakePlatform()
    adapter = platform.adapter()
    digest = _compute_descriptor_digest(_descriptor("never-registered"))
    assert await adapter.get_descriptor(digest) is None
    assert await adapter.get_descriptor(digest) is None
    assert platform.requests == [f"GET /v1/models/{digest}"] * 2
    assert await adapter.get_descriptor("sha256:XYZ") is None
    assert len(platform.requests) == 2
    await adapter.close()


async def test_a_backend_without_the_model_catalog_is_remembered_until_the_reprobe_window_ends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform = FakePlatform(catalog=False)
    adapter = platform.adapter()
    now = [1000.0]
    monkeypatch.setattr(http_module.time, "monotonic", lambda: now[0])
    with pytest.raises(ModelCatalogUnsupportedError) as raised:
        await adapter.register_descriptor(_descriptor())
    assert raised.value.code == "model_catalog_not_supported_by_store"
    with pytest.raises(ModelCatalogUnsupportedError):
        await adapter.register_descriptor(_descriptor())
    assert await adapter.get_descriptor(_compute_descriptor_digest(_descriptor())) is None
    assert platform.requests == ["POST /v1/models"]
    now[0] += CATALOG_REPROBE_SECONDS
    with pytest.raises(ModelCatalogUnsupportedError):
        await adapter.register_descriptor(_descriptor())
    assert platform.requests == ["POST /v1/models", "POST /v1/models"]
    await adapter.close()


async def test_a_registration_answer_naming_another_digest_is_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"ok": True, "digest": "sha256:" + "c" * 64, "alreadyExisted": False})

    adapter = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="tzk_test_catalog")
    adapter._async_client = httpx.AsyncClient(base_url="https://api.tzun.ai", transport=httpx.MockTransport(handler))
    with pytest.raises(TzunError, match="a digest other than the one computed"):
        await adapter.register_descriptor(_descriptor())
    await adapter.close()


# ── The agent catalog ────────────────────────────────────────────────────────


async def test_agents_register_get_and_list() -> None:
    platform = FakePlatform()
    adapter = platform.adapter()
    digest, existed = await adapter.put_agent_descriptor(_agent())
    assert (digest, existed) == (agent_descriptor_digest(_agent()), False)
    assert (await adapter.put_agent_descriptor(_agent()))[1] is True
    row = await adapter.get_agent_descriptor(digest)
    assert row is not None and row.name == "rules" and row.organization == "Example Org"
    assert await adapter.get_agent_descriptor("sha256:" + "0" * 64) is None
    rows, cursor = await adapter.list_agent_descriptors(limit=10)
    assert [r.digest for r in rows] == [digest] and cursor is None
    await adapter.close()


async def test_a_backend_without_the_agent_catalog_answers_agent_not_supported_by_store() -> None:
    platform = FakePlatform(catalog=False)
    adapter = platform.adapter()
    with pytest.raises(InvalidAgentDescriptorError) as raised:
        await adapter.get_agent_descriptor(agent_descriptor_digest(_agent()))
    assert raised.value.code == "agent_not_supported_by_store"
    with pytest.raises(InvalidAgentDescriptorError) as raised:
        await adapter.put_agent_descriptor(_agent())
    assert raised.value.code == "agent_not_supported_by_store"
    # The bare 404 was settled by asking for one listing row, which the backend does not serve either.
    assert platform.requests == [f"GET /v1/agents/{agent_descriptor_digest(_agent())}", "GET /v1/agents"]
    await adapter.close()


async def test_a_backend_answering_a_bare_404_for_an_unregistered_digest() -> None:
    platform = FakePlatform(bare_404=True)
    adapter = platform.adapter()
    assert await adapter.get_descriptor(_compute_descriptor_digest(_descriptor("never-registered"))) is None
    assert await adapter.register_descriptor(_descriptor()) == _compute_descriptor_digest(_descriptor())

    unregistered = "sha256:" + "2" * 64
    assert await adapter.get_agent_descriptor(unregistered) is None
    assert await adapter.get_agent_descriptor(unregistered) is None
    assert platform.requests.count("GET /v1/agents") == 1
    digest, _ = await adapter.put_agent_descriptor(_agent())
    row = await adapter.get_agent_descriptor(digest)
    assert row is not None and row.canonicalBytes == canonical_serialize_agent_descriptor(_agent()) and row.parent is None
    rows, cursor = await adapter.list_agent_descriptors()
    assert [r.digest for r in rows] == [digest] and cursor is None
    await adapter.close()


async def test_a_backend_without_the_listing_refuses_the_listing_only() -> None:
    platform = FakePlatform(agent_list=False)
    adapter = platform.adapter()
    digest, _ = await adapter.put_agent_descriptor(_agent())
    with pytest.raises(InvalidAgentDescriptorError) as raised:
        await adapter.list_agent_descriptors()
    assert raised.value.code == "agent_not_supported_by_store"
    assert (await adapter.get_agent_descriptor(digest)) is not None
    await adapter.close()


# ── Through Tzun ─────────────────────────────────────────────────────────────


class _FakeOpenAI:
    class _Chat:
        class _Completions:
            async def create(self, **kwargs: Any) -> dict[str, Any]:
                return {"model": "gpt-4o-2024-08-06", "choices": [{"text": "yes"}]}

        def __init__(self) -> None:
            self.completions = self._Completions()

    def __init__(self) -> None:
        self.chat = self._Chat()


async def _wrapped_call(tzun: Tzun) -> None:
    wrapped = attach(_FakeOpenAI(), tzun=tzun, vendor="openai")
    await wrapped.chat.completions.create(
        model="gpt-4o-2024-08-06",
        tzun_capture=DecisionInput(
            action="approved",
            decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
            reason="ok",
        ),
    )


async def test_a_wrapped_call_over_the_http_backend_records_its_model() -> None:
    platform = FakePlatform()
    tzun = await Tzun.init(storage=platform.adapter())
    try:
        await _wrapped_call(tzun)
        await _wrapped_call(tzun)
    finally:
        await tzun.close()
    assert len(platform.evidence) == 2
    assert len(platform.models) == 1
    (digest,) = platform.models
    for envelope in platform.evidence:
        steps = envelope["payload"]["contributions"]["steps"]
        assert len(steps) == 1 and steps[0]["aiBom"]["modelDescriptorDigest"] == digest
    assert platform.requests.count("POST /v1/models") == 1


async def test_a_wrapped_call_against_a_backend_without_the_catalog_is_captured_without_its_model(
    caplog: pytest.LogCaptureFixture,
) -> None:
    platform = FakePlatform(catalog=False)
    tzun = await Tzun.init(storage=platform.adapter())
    try:
        with caplog.at_level(logging.WARNING, logger="tzun_sdk.ai_bom.hook"):
            await _wrapped_call(tzun)
    finally:
        await tzun.close()
    assert len(platform.evidence) == 1
    assert platform.evidence[0]["payload"]["contributions"] is None
    lines = [r.getMessage() for r in caplog.records if "capture_model_not_recordable" in r.getMessage()]
    assert lines == [
        "event=capture_model_not_recordable vendor=openai model_name=gpt-4o reason=store_has_no_model_catalog"
    ]


async def test_an_inline_step_descriptor_is_registered_or_refused_as_the_backend_allows() -> None:
    step = {
        "role": "propose",
        "actor": None,
        "aiBom": {"modelDescriptor": _descriptor("inline").model_dump(mode="json"), "vendorFingerprint": None},
        "inputs": [],
        "outputOf": {"checked": True},
    }
    serving = FakePlatform()
    tzun = await Tzun.init(storage=serving.adapter())
    try:
        result = await tzun.capture(
            ai_output={"x": 1}, action="approved", reason="ok", decider=DECIDER, contributions={"steps": [step]}
        )
        assert result.envelope.payload.contributions.steps[0].aiBom.modelDescriptorDigest == _compute_descriptor_digest(
            _descriptor("inline")
        )
    finally:
        await tzun.close()

    older = FakePlatform(catalog=False)
    tzun = await Tzun.init(storage=older.adapter())
    try:
        with pytest.raises(InvalidContributionsError) as raised:
            await tzun.capture(
                ai_output={"x": 1}, action="approved", reason="ok", decider=DECIDER, contributions={"steps": [step]}
            )
        assert raised.value.code == "invalid_step_ai_bom"
    finally:
        await tzun.close()
    assert older.evidence == []


async def test_agent_references_are_left_to_a_serving_backend_and_taken_as_given_otherwise() -> None:
    serving = FakePlatform()
    tzun = await Tzun.init(storage=serving.adapter())
    try:
        registered = await tzun.agents.register(_agent())
        await tzun.capture(
            ai_output={"x": 1}, action="approve", reason="r", decider={"kind": "agent", "agent": registered["digest"]}
        )
        with pytest.raises(TzunCaptureError) as missing:
            await tzun.capture(
                ai_output={"x": 2}, action="approve", reason="r", decider={"kind": "agent", "agent": "sha256:" + "2" * 64}
            )
        assert (missing.value.code, missing.value.status) == ("invalid_request", 400)
    finally:
        await tzun.close()
    assert len(serving.evidence) == 1
    # Capture read no agent row: the reference check is the platform's.
    assert [r for r in serving.requests if r.startswith("GET /v1/agents")] == []

    older = FakePlatform(catalog=False)
    tzun = await Tzun.init(storage=older.adapter())
    try:
        await tzun.capture(
            ai_output={"x": 3}, action="approve", reason="r", decider={"kind": "agent", "agent": "sha256:" + "2" * 64}
        )
        with pytest.raises(InvalidAgentDescriptorError) as absent:
            await tzun.agents.register(_agent())
        assert absent.value.code == "agent_not_supported_by_store"
    finally:
        await tzun.close()
    assert len(older.evidence) == 1


# ── What the platform may answer that is not the contract ────────────────────


def _html_404_once(platform: FakePlatform, method: str, path: str) -> Any:
    sent = [False]

    def handler(request: httpx.Request) -> httpx.Response:
        if not sent[0] and request.method == method and request.url.path == path:
            sent[0] = True
            return httpx.Response(404, headers={"Content-Type": "text/html"}, content=b"<html>Application not found</html>")
        return platform.handler(request)

    return handler


def _answering(status: int, body: Any, calls: list[str] | None = None) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(f"{request.method} {request.url.path}")
        return httpx.Response(status, json=body)

    return handler


async def test_an_html_404_on_registration_is_raised_and_does_not_switch_model_recording_off() -> None:
    platform = FakePlatform()
    adapter = platform.adapter(_html_404_once(platform, "POST", "/v1/models"))
    with pytest.raises(TzunCaptureError) as raised:
        await adapter.register_descriptor(_descriptor())
    assert not isinstance(raised.value, ModelCatalogUnsupportedError) and raised.value.status == 404
    assert await adapter.register_descriptor(_descriptor()) == _compute_descriptor_digest(_descriptor())
    await adapter.close()


async def test_a_json_404_with_another_code_on_registration_decides_nothing() -> None:
    calls: list[str] = []
    adapter = FakePlatform().adapter(_answering(404, {"ok": False, "error": "descriptor_not_registered"}, calls))
    for _ in range(2):
        with pytest.raises(TzunCaptureError) as raised:
            await adapter.register_descriptor(_descriptor())
        assert not isinstance(raised.value, ModelCatalogUnsupportedError)
    assert calls == ["POST /v1/models", "POST /v1/models"]
    await adapter.close()


async def test_an_html_404_on_an_agent_lookup_is_raised_not_read_as_no_catalog() -> None:
    platform = FakePlatform()
    digest = agent_descriptor_digest(_agent())
    adapter = platform.adapter(_html_404_once(platform, "GET", f"/v1/agents/{digest}"))
    await adapter.put_agent_descriptor(_agent())
    with pytest.raises(TzunCaptureError) as raised:
        await adapter.get_agent_descriptor(digest)
    assert raised.value.status == 404
    assert (await adapter.get_agent_descriptor(digest)) is not None
    await adapter.close()


async def test_a_wrapped_call_whose_registration_fails_is_captured_without_its_model(
    caplog: pytest.LogCaptureFixture,
) -> None:
    platform = FakePlatform()
    failed = [False]

    def handler(request: httpx.Request) -> httpx.Response:
        if not failed[0] and request.method == "POST" and request.url.path == "/v1/models":
            failed[0] = True
            return httpx.Response(500, json={"ok": False, "error": "internal_error"})
        return platform.handler(request)

    tzun = await Tzun.init(storage=platform.adapter(handler))
    try:
        with caplog.at_level(logging.WARNING, logger="tzun_sdk.ai_bom.attach"):
            await _wrapped_call(tzun)
            await _wrapped_call(tzun)
    finally:
        await tzun.close()
    assert len(platform.evidence) == 2
    assert platform.evidence[0]["payload"]["contributions"] is None
    assert platform.evidence[1]["payload"]["contributions"] is not None
    lines = [r.getMessage() for r in caplog.records if "connector_hook_failure" in r.getMessage()]
    assert lines == ["event=connector_hook_failure vendor=openai error_name=TzunCaptureError"]


async def test_a_backend_rolled_back_without_the_agent_catalog_is_noticed_after_the_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [1000.0]
    monkeypatch.setattr(http_module.time, "monotonic", lambda: now[0])
    serving = FakePlatform(bare_404=True)
    older = FakePlatform(catalog=False)
    current = [serving]
    adapter = serving.adapter(lambda request: current[0].handler(request))
    await adapter.put_agent_descriptor(_agent())
    unregistered = "sha256:" + "2" * 64
    assert await adapter.get_agent_descriptor(unregistered) is None

    current[0] = older
    now[0] += CATALOG_REPROBE_SECONDS
    with pytest.raises(InvalidAgentDescriptorError) as raised:
        await adapter.get_agent_descriptor(unregistered)
    assert raised.value.code == "agent_not_supported_by_store"
    assert older.requests == [f"GET /v1/agents/{unregistered}", "GET /v1/agents"]
    await adapter.close()


async def test_the_listing_pages_with_the_digest_cursor_the_platform_hands_out() -> None:
    platform = FakePlatform(bare_404=True)
    adapter = platform.adapter()
    digests = sorted([(await adapter.put_agent_descriptor(_agent(f"agent-{i}")))[0] for i in range(3)])
    rows, cursor = await adapter.list_agent_descriptors(limit=2)
    assert [r.digest for r in rows] == digests[:2] and cursor == digests[1]
    rows, cursor = await adapter.list_agent_descriptors(limit=2, cursor=cursor)
    assert [r.digest for r in rows] == digests[2:] and cursor is None

    with pytest.raises(TzunError, match="cursor must be one a previous page returned"):
        await adapter.list_agent_descriptors(cursor="2")
    sent = len(platform.requests)
    for bad in ("", "has space"):
        with pytest.raises(TzunError, match="cursor must be one a previous page returned"):
            await adapter.list_agent_descriptors(cursor=bad)
    assert len(platform.requests) == sent
    await adapter.close()


async def test_a_row_without_a_parent_member_takes_it_from_the_descriptor() -> None:
    platform = FakePlatform(bare_404=True)
    adapter = platform.adapter()
    base, _ = await adapter.put_agent_descriptor(_agent("base"))
    child, _ = await adapter.put_agent_descriptor(_agent("child", parent=base, derivation="revision"))
    row = await adapter.get_agent_descriptor(child)
    assert row is not None and row.parent == base
    await adapter.close()


async def test_rows_that_do_not_hash_to_the_digest_asked_for_are_refused_and_not_kept() -> None:
    asked = _compute_descriptor_digest(_descriptor("asked-for"))
    calls: list[str] = []
    other_bytes = canonical_serialize_descriptor(_descriptor("another").model_dump(mode="json", exclude_none=False))
    adapter = FakePlatform().adapter(_answering(200, {"ok": True, "modelDescriptorDigest": asked, "canonicalBytes": other_bytes}, calls))
    for _ in range(2):
        with pytest.raises(TzunError, match="do not hash to the digest asked for"):
            await adapter.get_descriptor(asked)
    assert len(calls) == 2
    await adapter.close()

    a, b = _agent("a"), _agent("b")
    digest_a, digest_b = agent_descriptor_digest(a), agent_descriptor_digest(b)

    def row(digest: str, d: dict[str, Any]) -> dict[str, Any]:
        return {
            "ok": True,
            "digest": digest,
            "canonicalBytes": canonical_serialize_agent_descriptor(d),
            "name": d["name"],
            "organization": "Example Org",
            "parent": None,
            "registeredAt": "2026-10-07T12:00:00.000Z",
        }

    # B's row answered for A: refused by its digest member.
    adapter = FakePlatform().adapter(_answering(200, row(digest_b, b)))
    with pytest.raises(TzunError, match="not the catalog row"):
        await adapter.get_agent_descriptor(digest_a)
    await adapter.close()
    # A row naming A but holding B's bytes: refused by its bytes.
    adapter = FakePlatform().adapter(_answering(200, row(digest_a, b)))
    with pytest.raises(TzunError, match="do not hash to the digest asked for"):
        await adapter.get_agent_descriptor(digest_a)
    await adapter.close()


async def test_an_agent_registration_answered_with_another_digest_is_refused() -> None:
    adapter = FakePlatform().adapter(_answering(201, {"ok": True, "digest": "sha256:" + "c" * 64, "alreadyExisted": False}))
    with pytest.raises(TzunError, match="a digest other than the one computed"):
        await adapter.put_agent_descriptor(_agent())
    await adapter.close()


async def test_verification_reads_a_backend_without_the_agent_catalog_as_catalog_absent() -> None:
    adapter = FakePlatform(catalog=False).adapter()
    raw = {"payload": {"decider": {"kind": "agent", "agent": "sha256:" + "2" * 64}, "contributions": None}}
    assert await resolve_agent_references(raw, adapter) == [
        {"reference": "sha256:" + "2" * 64, "field": "decider", "resolved": False, "reason": "catalog_absent"}
    ]
    await adapter.close()
