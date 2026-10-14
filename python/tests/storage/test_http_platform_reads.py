"""The Python cloud adapter against the platform's routes.

The platform serves an API key ``GET /v1/app/evidence`` and
``GET /v1/app/evidence/{id}``, not the SDK REST router's ``GET /v1/evidence``.
The adapter reads the chain head and records over the ``/v1/app/evidence``
routes and keeps the head the platform reports; reading ``GET /v1/evidence``
would fail Python cloud mode with ``404 (not_found)`` before the first
capture. The fake (tests/_platform_fake.py) serves those routes as the
platform does and answers ``GET /v1/evidence`` with the platform's catch-all
404, so an adapter that reads ``GET /v1/evidence`` fails here.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
import pytest

from tests._platform_fake import API, FakePlatform
from tzun_sdk import Tzun
from tzun_sdk._generated.chain import compute_chain_link
from tzun_sdk.errors import TzunError
from tzun_sdk.storage.http import HttpBackendAdapter


def _cap(tzun: Tzun, n: int) -> Any:
    return tzun.capture(
        ai_output={"n": n}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="ok"
    )


def _assert_linked(stored: list[dict[str, Any]]) -> None:
    assert [e["payload"]["sequenceNumber"] for e in stored] == list(range(1, len(stored) + 1))
    previous: str | None = None
    for env in stored:
        assert env["integrity"]["chainLink"] == compute_chain_link(previous, env["integrity"]["canonicalDigest"])
        previous = env["integrity"]["canonicalDigest"]


def _assert_result_is_stored(result: Any, fake: FakePlatform, chain: str = "default") -> None:
    stored = next(e for e in fake.chain(chain) if e["payload"]["evidenceId"] == result.evidenceId)
    assert (result.sequenceNumber, result.canonicalDigest) == (
        stored["payload"]["sequenceNumber"],
        stored["integrity"]["canonicalDigest"],
    )


async def test_init_and_captures_over_the_routes_the_platform_serves_to_an_api_key() -> None:
    fake = FakePlatform()
    tzun = await Tzun.init(storage=fake.adapter())
    try:
        results = [await _cap(tzun, n) for n in (1, 2, 3)]
        # One read at init; each capture then links from the receipt before it.
        assert fake.requests.count(("GET", "/v1/app/evidence")) == 1
        # verify() reads the record and its predecessor over the same routes.
        verified = await tzun.verify(results[2].evidenceId)
        assert verified.valid and verified.chainLinkValid
    finally:
        await tzun.close()

    _assert_linked(fake.chain())
    for result in results:
        _assert_result_is_stored(result, fake)
    assert fake.restamped == 0 and fake.chain_conflicts == 0
    assert ("GET", "/v1/evidence") not in fake.requests


async def test_a_new_client_on_a_chain_that_holds_records_captures_at_its_head() -> None:
    fake = FakePlatform()
    first = await Tzun.init(storage=fake.adapter())
    await _cap(first, 1)
    await _cap(first, 2)
    await first.close()

    second = await Tzun.init(storage=fake.adapter())
    try:
        result = await _cap(second, 3)
    finally:
        await second.close()
    assert result.sequenceNumber == 3
    _assert_result_is_stored(result, fake)
    _assert_linked(fake.chain())
    assert fake.restamped == 0 and fake.chain_conflicts == 0


async def test_a_client_whose_head_moved_rebuilds_on_the_head_the_conflict_names(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The link conflict names the head's digest only; its sequence is read from the newest page."""
    fake = FakePlatform()
    a = await Tzun.init(storage=fake.adapter())
    b = await Tzun.init(storage=fake.adapter())
    try:
        await _cap(a, 1)
        # b read an empty chain at init: its record carries no link, so the
        # platform re-stamps it onto a's, and the capture logs it.
        with caplog.at_level(logging.WARNING, logger="tzun_sdk.core"):
            await _cap(b, 2)
        assert fake.restamped == 1
        assert any("receipt_restamped" in r.getMessage() for r in caplog.records)
        # a's head is now b's: its link is refused, and it rebuilds on b's record.
        result = await _cap(a, 3)
    finally:
        await a.close()
        await b.close()
    assert fake.chain_conflicts == 1
    assert fake.restamped == 1
    _assert_result_is_stored(result, fake)
    _assert_linked(fake.chain())


async def test_another_chain_on_the_account_converges_on_its_own_head() -> None:
    """The newest page spans every chain; the platform's refusal names this chain's head (here: empty)."""
    fake = FakePlatform()
    default = await Tzun.init(storage=fake.adapter())
    await _cap(default, 1)
    await _cap(default, 2)
    await default.close()

    other = await Tzun.init(storage=fake.adapter(), chain_id="other")
    try:
        first = await _cap(other, 1)
        second = await _cap(other, 2)
    finally:
        await other.close()
    _assert_linked(fake.chain("other"))
    _assert_result_is_stored(first, fake, "other")
    _assert_result_is_stored(second, fake, "other")
    assert fake.restamped == 0


async def test_a_failed_head_read_is_logged_and_the_platform_stamps_the_capture(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakePlatform()
    seed = await Tzun.init(storage=fake.adapter())
    await _cap(seed, 1)
    await seed.close()

    fake.fail_reads = 503
    with caplog.at_level(logging.WARNING, logger="tzun_sdk.storage.http"):
        tzun = await Tzun.init(storage=fake.adapter())
    try:
        assert any("cloud_head_read_failed" in r.getMessage() for r in caplog.records)
        await _cap(tzun, 2)  # built at sequence 1 with no link: re-stamped onto the head
        assert fake.restamped == 1
        result = await _cap(tzun, 3)  # links from the receipt
    finally:
        await tzun.close()
    _assert_linked(fake.chain())
    _assert_result_is_stored(result, fake)


async def test_retrieve_reads_one_record_and_answers_none_for_one_the_scope_does_not_hold() -> None:
    fake = FakePlatform()
    tzun = await Tzun.init(storage=fake.adapter())
    try:
        result = await _cap(tzun, 1)
    finally:
        await tzun.close()

    adapter = fake.adapter()
    got = await adapter.retrieve(result.evidenceId)
    assert got is not None and got.integrity.canonicalDigest == result.canonicalDigest
    assert fake.requests[-1] == ("GET", f"/v1/app/evidence/{result.evidenceId}")
    assert await adapter.retrieve("ev-unknown") is None
    before = len(fake.requests)
    for unnameable in ("", ".", ".."):
        assert await adapter.retrieve(unnameable) is None
    assert len(fake.requests) == before


async def test_list_by_sequence_walks_the_platforms_200_a_page() -> None:
    fake = FakePlatform()
    tzun = await Tzun.init(storage=fake.adapter())
    try:
        for n in range(1, 251):
            await _cap(tzun, n)
    finally:
        await tzun.close()

    adapter = fake.adapter()
    assert len(await adapter.list_by_sequence()) == 250
    assert [e.payload.sequenceNumber for e in await adapter.list_by_sequence(17, 18)] == [17, 18]
    head = await adapter.head()
    assert head is not None and head.payload.sequenceNumber == 250


async def test_list_refuses_a_filter_the_platform_does_not_apply() -> None:
    adapter = FakePlatform().adapter()
    with pytest.raises(TzunError, match="limit and offset only"):
        await adapter.list(order="desc")
    assert await adapter.list(limit=5, offset=0) == []


@pytest.mark.parametrize("body", [[], {"items": []}, {"evidence": [{"evidenceId": "ev-1"}]}])
async def test_a_page_the_adapter_cannot_read_is_refused_not_answered_empty(body: Any) -> None:
    adapter = HttpBackendAdapter(base_url=API, api_token="t")
    adapter._async_client = httpx.AsyncClient(
        base_url=API, transport=httpx.MockTransport(lambda _r: httpx.Response(200, json=body))
    )
    with pytest.raises(TzunError):
        await adapter.list()


async def test_a_receipt_without_the_head_leaves_the_chain_to_be_read_again() -> None:
    """A capture answer that names no head does not leave the adapter on the head it had."""
    fake = FakePlatform()
    plain = fake.handler

    def _receipt_without_head(request: httpx.Request) -> httpx.Response:
        response = plain(request)
        if request.method == "POST" and response.status_code == 202:
            return httpx.Response(202, json={"ok": True})
        return response

    adapter = HttpBackendAdapter(base_url=API, api_token="t")
    adapter._async_client = httpx.AsyncClient(base_url=API, transport=httpx.MockTransport(_receipt_without_head))
    tzun = await Tzun.init(storage=adapter)
    try:
        await _cap(tzun, 1)
        await _cap(tzun, 2)
    finally:
        await tzun.close()
    _assert_linked(fake.chain())
    assert fake.restamped == 0
