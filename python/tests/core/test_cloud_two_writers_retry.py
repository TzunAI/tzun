"""Two Python cloud clients on one chain: the server's ``409 chain_conflict``
takes the same bounded rebuild-and-retry the local adapters' refusal does.

``capture()`` retries a refused compare-and-swap: adopt the head the store
reported, rebuild at the next position, append again, bounded by
``chain_conflict_max_attempts`` (test_two_writers_retry.py, on SQLite). On the
local adapters that refusal is ``ChainConflictError``. Over HTTP the CAS is
the SERVER's — it holds the chain lock and answers ``409 chain_conflict`` —
and :class:`~tzun_sdk.storage.http.HttpBackendAdapter` surfaces that as
``TzunCaptureError(code="chain_conflict", status=409)``, a different class.
The loop retries both, so a second Python client on one cloud chain does not
lose a contended capture on its first attempt: the cloud transport gets the
same retry as the local adapters.

The 409 is not a ``ChainConflictError`` with an ``.actual`` head: the adapter
keeps the head its body names (``expectedPreviousDigest``,
``expectedSequence``), the loop reads it back over the adapter and rebuilds
against it. Any other server answer — including
``409 evidence_id_conflict``, the wire twin of the local
``DuplicateEvidenceError`` — is not a moved head and surfaces once.

The server side is a fake with the backend's CAS rule (a record must sit at
``head + 1`` and link to the head digest); the two clients are real
``HttpBackendAdapter``s over ``httpx.MockTransport`` to that fake, and the
interleaving is the same wrapper test_two_writers_retry.py uses: the other
client appends between our head read and our store.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
import pytest

from tzun_sdk import Tzun
from tzun_sdk._generated.chain import compute_chain_link
from tzun_sdk.errors import DuplicateEvidenceError, TzunCaptureError
from tzun_sdk.models import CaptureResult
from tzun_sdk.storage.http import HttpBackendAdapter

LOGGER = "tzun_sdk.core"
API = "https://api.tzun.ai"

FIXED_ID = "0f1e2d3c-4b5a-4987-8796-a5b4c3d2e1f0"


def _cap(tzun: Tzun, label: str, **kw: Any) -> Any:
    return tzun.capture(
        ai_output={"label": label},
        decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
        reason=f"because {label}",
        **kw,
    )


def _log(caplog: pytest.LogCaptureFixture, needle: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if needle in r.getMessage()]


def _json(status: int, body: Any) -> httpx.Response:
    return httpx.Response(
        status, headers={"Content-Type": "application/json"}, content=json.dumps(body).encode()
    )


class _FakeCloud:
    """The capture endpoint as far as ``capture()`` can see it: an append-only
    list with the backend's chain rule and its two 409 answers."""

    def __init__(self) -> None:
        self.stored: list[dict[str, Any]] = []
        self.posts = 0
        self.chain_conflicts = 0

    def head_digest(self) -> str | None:
        return self.stored[-1]["integrity"]["canonicalDigest"] if self.stored else None

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == "/v1/evidence":
            self.posts += 1
            env = json.loads(request.content.decode())["envelope"]
            seq = env["payload"]["sequenceNumber"]
            expected_seq = len(self.stored) + 1
            expected_link = compute_chain_link(
                self.head_digest(), env["integrity"]["canonicalDigest"]
            )
            if any(e["payload"]["evidenceId"] == env["payload"]["evidenceId"] for e in self.stored):
                return _json(409, {"ok": False, "error": "evidence_id_conflict"})
            if seq != expected_seq or env["integrity"]["chainLink"] != expected_link:
                self.chain_conflicts += 1
                return _json(
                    409,
                    {
                        "ok": False,
                        "error": "chain_conflict",
                        "expectedPreviousDigest": self.head_digest(),
                        "expectedSequence": expected_seq,
                    },
                )
            self.stored.append(env)
            return _json(
                202,
                {
                    "ok": True,
                    "evidenceId": env["payload"]["evidenceId"],
                    "chainId": None,
                    "sequence": seq,
                    "state": "stored",
                    "verification": "ok",
                    "canonicalDigest": env["integrity"]["canonicalDigest"],
                    "headDigest": env["integrity"]["canonicalDigest"],
                },
            )
        if request.method == "GET" and path == "/v1/app/evidence":
            whole = "envelope" in request.url.params.get("include", "")
            return _json(
                200,
                {
                    "evidence": [
                        {
                            "evidenceId": env["payload"]["evidenceId"],
                            "sequenceNumber": env["payload"]["sequenceNumber"],
                            "canonicalDigest": env["integrity"]["canonicalDigest"],
                            **({"envelope": env, "verdict": {}} if whole else {}),
                        }
                        for env in reversed(self.stored)
                    ]
                },
            )
        return _json(404, {"ok": False, "error": "not_found"})

    def adapter(self) -> HttpBackendAdapter:
        adapter = HttpBackendAdapter(base_url=API, api_token="tzk_test_x")
        adapter._async_client = httpx.AsyncClient(
            base_url=API, transport=httpx.MockTransport(self.handler)
        )
        return adapter

    def assert_chain_clean(self, expected_len: int) -> None:
        assert [e["payload"]["sequenceNumber"] for e in self.stored] == list(
            range(1, expected_len + 1)
        )
        prev: str | None = None
        for env in self.stored:
            assert env["integrity"]["chainLink"] == compute_chain_link(
                prev, env["integrity"]["canonicalDigest"]
            )
            prev = env["integrity"]["canonicalDigest"]


class _ForeignAppendBeforeStore:
    """A REAL cloud adapter, with another client appending to the same server
    just before the first ``times`` calls to ``store()``."""

    def __init__(self, inner: Any, foreign: Tzun, times: int) -> None:
        self._inner = inner
        self._foreign = foreign
        self._remaining = times
        self.foreign_captures: list[CaptureResult] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def store(self, envelope: Any, chain_id: Any = None, options: Any = None) -> Any:
        if self._remaining > 0:
            self._remaining -= 1
            self.foreign_captures.append(
                await _cap(self._foreign, f"foreign-{len(self.foreign_captures) + 1}")
            )
        return await self._inner.store(envelope, chain_id, options)


async def test_cloud_refused_append_is_rebuilt_against_the_head_it_lost_to(
    caplog: pytest.LogCaptureFixture,
) -> None:
    server = _FakeCloud()
    foreign = await Tzun.init(storage=server.adapter())
    racing = _ForeignAppendBeforeStore(server.adapter(), foreign, times=1)
    ours = await Tzun.init(storage=racing)
    try:
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            result = await _cap(ours, "ours")
        # The first attempt's 409 was retried, not raised as
        #   TzunCaptureError: HttpBackendAdapter POST /v1/evidence -> 409 (chain_conflict)
        assert len(racing.foreign_captures) == 1
        assert racing.foreign_captures[0].sequenceNumber == 1
        assert result.sequenceNumber == 2
        assert server.chain_conflicts == 1
        assert server.posts == 3  # foreign, ours refused, ours rebuilt
        assert len(_log(caplog, "chain_conflict_retry")) == 1
        assert not _log(caplog, "store_refused")
        server.assert_chain_clean(2)
        # The rebuilt record links to the one that beat it.
        assert result.envelope.integrity.chainLink == compute_chain_link(
            racing.foreign_captures[0].canonicalDigest, result.canonicalDigest
        )
    finally:
        await ours.close()
        await foreign.close()


async def test_cloud_exhausted_retry_raises_the_typed_409_and_stores_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    server = _FakeCloud()
    foreign = await Tzun.init(storage=server.adapter())
    # Beaten to the head on every one of its two attempts.
    racing = _ForeignAppendBeforeStore(server.adapter(), foreign, times=2)
    ours = await Tzun.init(storage=racing, chain_conflict_max_attempts=2)
    try:
        with (
            caplog.at_level(logging.WARNING, logger=LOGGER),
            pytest.raises(TzunCaptureError) as exc,
        ):
            await _cap(ours, "ours")
        # The server's own answer surfaces, typed, once the bound is spent.
        assert exc.value.code == "chain_conflict"
        assert exc.value.status == 409
        # Both attempts ran, each beaten by a foreign capture, and the
        # exhaustion is logged.
        assert len(racing.foreign_captures) == 2
        assert server.chain_conflicts == 2
        assert len(_log(caplog, "chain_conflict_retry")) == 1
        assert len(_log(caplog, "chain_conflict_exhausted")) == 1
        assert not _log(caplog, "store_refused")
        # Nothing of ours landed; the chain is the two foreign records, clean.
        server.assert_chain_clean(2)
        assert ours._sequence_counter == 2
        # Exhaustion is not a wedge: the next capture links from the truth.
        assert (await _cap(ours, "ours-again")).sequenceNumber == 3
        server.assert_chain_clean(3)
    finally:
        await ours.close()
        await foreign.close()


async def test_cloud_evidence_id_conflict_is_refused_once_under_the_local_code(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A reused id is not a moved head on the cloud either. The server's
    ``409 evidence_id_conflict`` surfaces on the first attempt, is logged under
    its own code, and that code is the one the local adapters'
    ``DuplicateEvidenceError`` carries — one branch for one condition,
    whichever backend the caller is on."""
    server = _FakeCloud()
    tzun = await Tzun.init(storage=server.adapter(), chain_conflict_max_attempts=10)
    try:
        await _cap(tzun, "first", evidence_id=FIXED_ID)
        with (
            caplog.at_level(logging.WARNING, logger=LOGGER),
            pytest.raises(TzunCaptureError) as exc,
        ):
            await _cap(tzun, "replay", evidence_id=FIXED_ID)
        assert exc.value.status == 409
        assert exc.value.code == DuplicateEvidenceError.code == "evidence_id_conflict"
        assert server.posts == 2, "a duplicate id must be submitted once, not retried"
        assert server.chain_conflicts == 0
        refused = _log(caplog, "store_refused")
        assert len(refused) == 1, [r.getMessage() for r in caplog.records]
        assert "code=evidence_id_conflict" in refused[0].getMessage()
        assert not _log(caplog, "chain_conflict")
        server.assert_chain_clean(1)
    finally:
        await tzun.close()
