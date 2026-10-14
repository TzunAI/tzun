"""The Python cloud path: `Tzun.init` and `capture()` over `HttpBackendAdapter`.

`Tzun.init` calls `self._storage.head(chain_id)` unconditionally and
`capture()` calls it on every append, so `HttpBackendAdapter.head()` must
answer for

    await Tzun.init(storage=HttpBackendAdapter("https://api.tzun.ai", "tzk_live_..."))

(the recipe in README.md and `storage/__init__`) to work at all. A `head()`
that raised would fail that recipe before a single network call, and no
Python user could capture to the cloud.

This drives init plus two captures end to end through an `httpx.MockTransport`
that serves the platform's capture and API-key read routes, and asserts the
SECOND capture links to the first — i.e. the head is not merely readable but
correct. The fake's capture answer names no head, so the adapter reads it
again (`GET /v1/app/evidence`) before the second capture.
"""

from __future__ import annotations

import json

import httpx
import pytest

from tzun_sdk import Tzun
from tzun_sdk._generated.chain import compute_chain_link
from tzun_sdk.storage.http import HttpBackendAdapter


def _cloud_adapter() -> tuple[HttpBackendAdapter, list[dict]]:
    """An adapter wired to a fake backend that stores what it is POSTed."""
    stored: list[dict] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == "/v1/evidence":
            body = json.loads(request.content.decode())
            stored.append(body.get("envelope", body))
            return httpx.Response(
                201,
                headers={"Content-Type": "application/json"},
                content=json.dumps({"ok": True}).encode(),
            )
        if request.method == "GET" and path == "/v1/app/evidence":
            whole = "envelope" in request.url.params.get("include", "")
            items = [
                {
                    "evidenceId": env["payload"]["evidenceId"],
                    "sequenceNumber": env["payload"]["sequenceNumber"],
                    "canonicalDigest": env["integrity"]["canonicalDigest"],
                    **({"envelope": env, "verdict": {}} if whole else {}),
                }
                for env in reversed(stored)
            ]
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=json.dumps({"evidence": items}).encode(),
            )
        return httpx.Response(
            200, headers={"Content-Type": "application/json"}, content=b"{}"
        )

    adapter = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="tzk_live_x")
    adapter._async_client = httpx.AsyncClient(
        base_url="https://api.tzun.ai", transport=httpx.MockTransport(_handler)
    )
    return adapter, stored


@pytest.mark.asyncio
async def test_init_and_two_captures_over_the_http_adapter() -> None:
    adapter, stored = _cloud_adapter()
    tzun = await Tzun.init(storage=adapter)
    try:
        await tzun.capture(
            ai_output={"n": 1}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok"
        )
        await tzun.capture(
            ai_output={"n": 2}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok"
        )
    finally:
        await tzun.close()

    assert len(stored) == 2, stored
    first, second = stored
    assert first["payload"]["sequenceNumber"] == 1
    assert second["payload"]["sequenceNumber"] == 2

    # Genesis has no predecessor; capture #2 must link to capture #1. A head()
    # that returned None (or the genesis record) for capture #2 would fail here.
    assert first["integrity"]["chainLink"] is None
    assert second["integrity"]["chainLink"] == compute_chain_link(
        first["integrity"]["canonicalDigest"], second["integrity"]["canonicalDigest"]
    )
