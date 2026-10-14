"""The hosted service's routes the Python cloud adapter calls, as the service serves them to an API key.

- ``POST /v1/evidence``: a ``partial`` capture under the platform's rules
  A record without a chain link is re-stamped onto
  the chain's head. A record with one must link to the head, or the answer is
  ``409 chain_conflict`` naming ``expectedPreviousDigest``; it is then
  re-stamped onto the next sequence, unless it carries an attestation, which
  is refused with ``expectedSequence`` too. The receipt names the stored
  ``sequence`` and ``headDigest``.
- ``GET /v1/app/evidence``: every chain of the key's scope, newest first,
  ``limit`` clamped to 200 and ``offset`` to 100000; ``include=envelope``
  adds ``envelope`` and ``verdict`` to each item.
- ``GET /v1/app/evidence/{id}``: ``{envelope, verdict, anchor}``, or
  ``404 not_found``.
- Anything else, ``GET /v1/evidence`` included: the catch-all
  ``404 {"ok": false, "error": "not_found"}``.

``fail_reads`` makes the two read routes answer that status instead.
"""

from __future__ import annotations

import copy
import json
from typing import Any
from urllib.parse import unquote

import httpx

from tzun_sdk._capture import payload_digest
from tzun_sdk._generated.chain import compute_chain_link
from tzun_sdk.storage.http import HttpBackendAdapter

API = "https://api.tzun.ai"


def _json(status: int, body: Any) -> httpx.Response:
    return httpx.Response(status, headers={"Content-Type": "application/json"}, content=json.dumps(body).encode())


class FakePlatform:
    def __init__(self) -> None:
        # (chain, envelope) in the order stored.
        self.rows: list[tuple[str, dict[str, Any]]] = []
        self.requests: list[tuple[str, str]] = []
        self.restamped = 0
        self.chain_conflicts = 0
        self.fail_reads: int | None = None

    def chain(self, chain: str = "default") -> list[dict[str, Any]]:
        return [env for c, env in self.rows if c == chain]

    def _head(self, chain: str) -> tuple[int, str | None]:
        stored = self.chain(chain)
        if not stored:
            return 0, None
        return stored[-1]["payload"]["sequenceNumber"], stored[-1]["integrity"]["canonicalDigest"]

    def _capture(self, body: dict[str, Any]) -> httpx.Response:
        chain = body.get("chainId") or "default"
        env = copy.deepcopy(body["envelope"])
        head_seq, head_digest = self._head(chain)
        link = env["integrity"]["chainLink"]
        if link is not None and (
            head_digest is None or link != compute_chain_link(head_digest, env["integrity"]["canonicalDigest"])
        ):
            self.chain_conflicts += 1
            return _json(409, {"ok": False, "error": "chain_conflict", "expectedPreviousDigest": head_digest})
        expected = head_seq + 1
        if env["payload"]["sequenceNumber"] != expected:
            if env.get("nonRepudiation"):
                self.chain_conflicts += 1
                return _json(
                    409,
                    {
                        "ok": False,
                        "error": "chain_conflict",
                        "reason": "attested_envelope_cannot_be_restamped",
                        "expectedSequence": expected,
                        "actualSequence": env["payload"]["sequenceNumber"],
                        "expectedPreviousDigest": head_digest,
                    },
                )
            self.restamped += 1
            env["payload"]["sequenceNumber"] = expected
            digest = payload_digest(env["payload"])
            env["integrity"] = {"canonicalDigest": digest, "chainLink": compute_chain_link(head_digest, digest)}
        elif link is None and head_digest is not None:
            self.restamped += 1
            digest = env["integrity"]["canonicalDigest"]
            env["integrity"]["chainLink"] = compute_chain_link(head_digest, digest)
        self.rows.append((chain, env))
        return _json(
            202,
            {
                "ok": True,
                "evidenceId": env["payload"]["evidenceId"],
                "chainId": chain,
                "sequence": expected,
                "state": "stored",
                "verification": "ok",
                "canonicalDigest": env["integrity"]["canonicalDigest"],
                "headDigest": env["integrity"]["canonicalDigest"],
            },
        )

    @staticmethod
    def _item(env: dict[str, Any], with_envelope: bool) -> dict[str, Any]:
        item: dict[str, Any] = {
            "evidenceId": env["payload"]["evidenceId"],
            "sequenceNumber": env["payload"]["sequenceNumber"],
            "capturedAt": env["payload"]["capturedAt"],
            "decider": None,
            "canonicalDigest": env["integrity"]["canonicalDigest"],
            "attestationStatus": "none",
            "attestationState": "none",
            "attestationStatusClaimed": None,
            "receivedAt": env["payload"]["capturedAt"],
            "anchor": {"stage": "not_anchored"},
        }
        if with_envelope:
            item["envelope"] = env
            item["verdict"] = {"evidenceId": env["payload"]["evidenceId"]}
        return item

    def handler(self, request: httpx.Request) -> httpx.Response:
        method, path = request.method, request.url.path
        self.requests.append((method, path))
        if method == "POST" and path == "/v1/evidence":
            return self._capture(json.loads(request.content.decode()))
        if method == "GET" and path == "/v1/app/evidence":
            if self.fail_reads is not None:
                return _json(self.fail_reads, {"ok": False, "error": "internal_error"})
            params = request.url.params
            limit = min(200, int(params.get("limit", 100)))
            offset = min(100_000, int(params.get("offset", 0)))
            with_envelope = "envelope" in params.get("include", "").split(",")
            newest_first = [env for _, env in reversed(self.rows)]
            page = newest_first[offset : offset + limit]
            return _json(200, {"evidence": [self._item(env, with_envelope) for env in page]})
        if method == "GET" and path.startswith("/v1/app/evidence/"):
            if self.fail_reads is not None:
                return _json(self.fail_reads, {"ok": False, "error": "internal_error"})
            evidence_id = unquote(path.removeprefix("/v1/app/evidence/"))
            for _, env in self.rows:
                if env["payload"]["evidenceId"] == evidence_id:
                    return _json(200, {"envelope": env, "verdict": {"evidenceId": evidence_id}, "anchor": None})
        return _json(404, {"ok": False, "error": "not_found"})

    def adapter(self) -> HttpBackendAdapter:
        adapter = HttpBackendAdapter(base_url=API, api_token="tzk_live_x")
        adapter._async_client = httpx.AsyncClient(base_url=API, transport=httpx.MockTransport(self.handler))
        return adapter
