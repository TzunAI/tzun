"""HTTP adapter endpoint-mapping parity.

Pins every HttpBackendAdapter method→route pair. The evidence reads go to
the hosted service's API-key read routes; the rest of the inventory is the
SDK REST surface (src/api/routers). Methods whose target route is served by
neither raise TzunError("not supported") rather than silently posting to a
phantom path.

Update SERVED_ROUTES + UNSERVED_METHODS when new routes land.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from tzun_sdk._generated.canonical import canonical_serialize_descriptor
from tzun_sdk.errors import TzunError
from tzun_sdk.models import (
    AttestationArtifacts,
    EvidenceEnvelope,
    IntegrityBlock,
    ModelDescriptor,
)
from tzun_sdk.storage.http import HttpBackendAdapter
from tzun_sdk.storage.memory import _compute_descriptor_digest

# ── Served-route inventory ────────────────────────────────────────────────────
# The platform's evidence routes the adapter calls, then the route registrations
# of the SDK REST surface (src/api/*.ts).
SERVED_ROUTES: frozenset[tuple[str, str]] = frozenset({
    ("POST", "/v1/evidence"),
    ("GET",  "/v1/app/evidence"),
    ("GET",  "/v1/app/evidence/:id"),
    ("GET",  "/v1/evidence"),
    ("GET",  "/v1/evidence/:id"),
    ("POST", "/v1/evidence/:id/verify"),
    ("GET",  "/v1/evidence/:id/export"),
    ("GET",  "/v1/models"),
    ("GET",  "/v1/models/by-alias/:slug"),
    ("GET",  "/v1/models/:digest"),
    ("GET",  "/v1/models/:digest/enriched"),
    ("GET",  "/v1/models/:digest/annotations"),
    ("GET",  "/v1/models/:digest/lineage"),
    ("POST", "/v1/models"),
    ("POST", "/v1/models/:digest/annotations"),
    ("POST", "/v1/models/aliases"),
    ("GET",  "/v1/integrity/status"),
    ("GET",  "/v1/integrity/incidents"),
    ("GET",  "/v1/integrity/incidents/:id"),
    ("GET",  "/v1/integrity/chain"),
    ("GET",  "/v1/integrity/scanner"),
    ("POST", "/v1/integrity/verify/range"),
    ("POST", "/v1/integrity/verify/:evidenceId"),
})

# ── Methods with no matching SDK REST route ───────────────────────────────────
# These must raise TzunError rather than silently hitting a 404.
UNSERVED_METHODS: frozenset[str] = frozenset({
    "store_attestation",                  # POST /v1/evidence/:id/attestations — no route
    "get_attestations",                   # GET /v1/evidence/:id/attestations — no route
    "store_annotation",                   # POST /v1/recovery/annotations — no route
    "store_relink",                       # POST /v1/recovery/relinks — no route
    "store_fork",                         # POST /v1/recovery/forks — no route
    "store_incident",                     # POST /v1/incidents — no route
    "delete_envelope_for_demo",           # DELETE /v1/evidence/:id — no route
    "append_model_descriptor_annotation", # intentionally unsupported; use POST via annotate
})


# ── Test helpers ──────────────────────────────────────────────────────────────

def _minimal_envelope() -> EvidenceEnvelope:
    return EvidenceEnvelope.model_validate({
        "envelopeVersion": "e1",
        "payload": {
            "evidenceId": "ev-test-1",
            "schemaVersion": "v1.0",
            "aiSystemId": "test",
            "aiOutput": {"d": 1},
            "action": "approved",
            "decider": {"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
            "reason": "ok",
            "capturedAt": "2026-06-10T00:00:00.000Z",
            "sequenceNumber": 1,
            "contributions": None,
            "links": None,
        },
        "integrity": IntegrityBlock(
            canonicalDigest="a" * 64,
            chainLink=None,
        ).model_dump(),
        "nonRepudiation": {},
        "custodyChain": [],
        "attestationStatus": "none",
    })


def _minimal_descriptor() -> ModelDescriptor:
    return ModelDescriptor(
        descriptorVersion="d1",
        vendor="openai",
        modelName="gpt-4o",
        modelVersion="2024-08-06",
        integrityTier="vendor-asserted",
    )


_ENVELOPE_JSON = {
    "envelopeVersion": "e1",
    "payload": {
        "evidenceId": "ev-1",
        "schemaVersion": "v1.0",
        "aiSystemId": "test",
        "aiOutput": {},
        "action": "approved",
        "decider": {"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
        "reason": "ok",
        "capturedAt": "2026-06-10T00:00:00.000Z",
        "sequenceNumber": 1,
    },
    "integrity": {"canonicalDigest": "a" * 64, "chainLink": None},
    "nonRepudiation": {},
    "custodyChain": [],
    "attestationStatus": "none",
}

_DESCRIPTOR_JSON = {
    "descriptorVersion": "d1",
    "vendor": "openai",
    "modelName": "gpt-4o",
    "modelVersion": "2024-08-06",
    "integrityTier": "vendor-asserted",
}


def _make_recording_adapter() -> tuple[HttpBackendAdapter, list[tuple[str, str]]]:
    """Return (adapter, calls) where calls records (method, path) for each request."""
    calls: list[tuple[str, str]] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append((request.method, path))

        # Return different shapes depending on which route was called so that
        # the adapters that parse the response body don't blow up on wrong fields.
        if path == "/v1/app/evidence":
            body = {"evidence": [{"envelope": _ENVELOPE_JSON, "verdict": {}}]}
        elif path.startswith("/v1/app/evidence/"):
            body = {"envelope": _ENVELOPE_JSON, "verdict": {}}
        elif path.startswith("/v1/evidence") and not path.endswith("/verify"):
            body = _ENVELOPE_JSON
        elif request.method == "POST" and path == "/v1/models":
            body = {"ok": True, "digest": _compute_descriptor_digest(_minimal_descriptor()), "alreadyExisted": False}
        elif request.method == "GET" and path.startswith("/v1/models/sha256:") and path.count("/") == 3:
            body = {
                "ok": True,
                "canonicalBytes": canonical_serialize_descriptor(
                    _minimal_descriptor().model_dump(mode="json", exclude_none=False)
                ),
            }
        elif path.startswith("/v1/models"):
            body = _DESCRIPTOR_JSON
        else:
            body = {"ok": True, "digest": "sha256:" + "a" * 64}

        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            content=json.dumps(body).encode(),
        )

    adapter = HttpBackendAdapter(
        base_url="https://api.tzun.ai",
        api_token="test-token",
    )
    # Inject mock transport directly.
    adapter._async_client = httpx.AsyncClient(
        base_url="https://api.tzun.ai",
        transport=httpx.MockTransport(_handler),
    )
    return adapter, calls


# ── Served-route table ────────────────────────────────────────────────────────
# Format: (method_name, expected_http_method, expected_path_prefix)
# path_prefix matches the beginning of the actual request path (handles IDs).

SERVED_TABLE: list[tuple[str, str, str]] = [
    ("store",                             "POST", "/v1/evidence"),
    ("retrieve",                          "GET",  "/v1/app/evidence/ev-test-1"),
    ("list",                              "GET",  "/v1/app/evidence"),
    ("list_by_sequence",                  "GET",  "/v1/app/evidence"),
    ("register_descriptor",               "POST", "/v1/models"),
    ("get_descriptor",                    "GET",  "/v1/models/sha256:"),
    ("list_model_descriptors",            "GET",  "/v1/models"),
    ("list_model_descriptor_annotations", "GET",  "/v1/models/sha256:"),
    ("set_model_descriptor_alias",        "POST", "/v1/models/aliases"),
    ("resolve_model_descriptor_alias",    "GET",  "/v1/models/by-alias/test-slug"),
    ("get_enriched_model_descriptor",     "GET",  "/v1/models/sha256:"),
]


@pytest.mark.parametrize("method_name,expected_method,expected_path_prefix", SERVED_TABLE)
def test_method_hits_served_route(
    method_name: str, expected_method: str, expected_path_prefix: str
) -> None:
    """Every listed method fires exactly the right HTTP method + path."""
    adapter, calls = _make_recording_adapter()
    digest = "sha256:" + "a" * 64
    envelope = _minimal_envelope()
    descriptor = _minimal_descriptor()

    async def run() -> None:
        if method_name == "store":
            await adapter.store(envelope)
        elif method_name == "retrieve":
            await adapter.retrieve("ev-test-1")
        elif method_name == "list":
            await adapter.list()
        elif method_name == "list_by_sequence":
            await adapter.list_by_sequence(1, 1)
        elif method_name == "register_descriptor":
            await adapter.register_descriptor(descriptor)
        elif method_name == "get_descriptor":
            # The row must hash to the digest asked for, or the adapter refuses it.
            await adapter.get_descriptor(_compute_descriptor_digest(descriptor))
        elif method_name == "list_model_descriptors":
            await adapter.list_model_descriptors()
        elif method_name == "list_model_descriptor_annotations":
            await adapter.list_model_descriptor_annotations(digest)
        elif method_name == "set_model_descriptor_alias":
            await adapter.set_model_descriptor_alias("prod", digest, "ops")
        elif method_name == "resolve_model_descriptor_alias":
            await adapter.resolve_model_descriptor_alias("test-slug")
        elif method_name == "get_enriched_model_descriptor":
            await adapter.get_enriched_model_descriptor(digest)
        else:
            raise ValueError(f"Unhandled served method in test: {method_name}")

    asyncio.run(run())

    assert calls, f"{method_name} made no HTTP call"
    actual_method, actual_path = calls[-1]
    assert actual_method == expected_method, (
        f"{method_name}: expected HTTP {expected_method} but got {actual_method}"
    )
    assert actual_path.startswith(expected_path_prefix), (
        f"{method_name}: path {actual_path!r} does not start with {expected_path_prefix!r}"
    )


def test_register_descriptor_returns_the_catalog_digest_and_refuses_an_answer_without_one() -> None:
    """The registered descriptor's digest is the one computed over its bytes, never the weights digest.

    An answer without a digest, or naming another digest, is refused.
    """
    computed = _compute_descriptor_digest(_minimal_descriptor())
    answers: list[dict[str, object]] = [
        {"digest": computed},
        {},
        {"digest": None},
        {"digest": "sha256:" + "c" * 64},
    ]

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=201,
            headers={"Content-Type": "application/json"},
            content=json.dumps(answers.pop(0)).encode(),
        )

    adapter = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="test-token")
    adapter._async_client = httpx.AsyncClient(base_url="https://api.tzun.ai", transport=httpx.MockTransport(_handler))
    descriptor = _minimal_descriptor()

    async def run() -> None:
        assert await adapter.register_descriptor(descriptor) == computed
        for _ in range(3):
            with pytest.raises(TzunError):
                await adapter.register_descriptor(descriptor)

    asyncio.run(run())


# ── Unserved-method table ─────────────────────────────────────────────────────

@pytest.mark.parametrize("method_name", sorted(UNSERVED_METHODS))
def test_unserved_methods_raise_tzun_error(method_name: str) -> None:
    """Methods whose target route is not in the SDK REST surface raise TzunError.

    They must raise — NOT silently hit a phantom path that would 404 in prod.
    """

    adapter, calls = _make_recording_adapter()

    async def run() -> None:
        if method_name == "store_attestation":
            fake = AttestationArtifacts(rfc3161Token="dGVzdA==", rfc3161Metadata=None)
            await adapter.store_attestation("ev-1", fake)
        elif method_name == "get_attestations":
            await adapter.get_attestations("ev-1")
        elif method_name == "store_annotation":
            await adapter.store_annotation(None)  # type: ignore[arg-type]
        elif method_name == "store_relink":
            await adapter.store_relink(None)  # type: ignore[arg-type]
        elif method_name == "store_fork":
            await adapter.store_fork(None)  # type: ignore[arg-type]
        elif method_name == "store_incident":
            await adapter.store_incident(None)  # type: ignore[arg-type]
        elif method_name == "delete_envelope_for_demo":
            await adapter.delete_envelope_for_demo("ev-1")
        elif method_name == "append_model_descriptor_annotation":
            await adapter.append_model_descriptor_annotation(None)  # type: ignore[arg-type]
        else:
            raise ValueError(f"Unhandled unserved method in test: {method_name}")

    with pytest.raises(TzunError):
        asyncio.run(run())

    # Crucially: no HTTP call must have been made (raised before hitting the wire).
    assert not calls, (
        f"{method_name} must raise before making any HTTP call, "
        f"but it made: {calls}"
    )


# ── head() is served ────────────────────────────────────────────────────
#
# head() answers over the platform's evidence list, GET /v1/app/evidence, and
# must not invent a path. It is not in UNSERVED_METHODS: an adapter whose
# `head()` raises makes the Python cloud path unreachable.

def test_head_answers_over_the_platforms_evidence_list() -> None:
    """head() takes the highest sequence on the newest page of GET /v1/app/evidence."""
    calls: list[tuple[str, str]] = []
    envelopes = []
    for seq in (1, 3, 2):
        env = dict(_ENVELOPE_JSON)
        env["payload"] = dict(_ENVELOPE_JSON["payload"], sequenceNumber=seq,
                              evidenceId=f"ev-{seq}")
        envelopes.append(env)

    def _handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        # Not in sequence order: head() must still return sequence 3.
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=json.dumps({"evidence": [{"envelope": e, "verdict": {}} for e in envelopes]}).encode(),
        )

    adapter = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="t")
    adapter._async_client = httpx.AsyncClient(
        base_url="https://api.tzun.ai", transport=httpx.MockTransport(_handler)
    )

    head = asyncio.run(adapter.head())
    assert head is not None
    assert head.payload.sequenceNumber == 3
    assert calls, "head() made no HTTP call"
    assert all(path == "/v1/app/evidence" for _, path in calls), calls


def test_head_returns_none_on_an_empty_chain() -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"Content-Type": "application/json"}, content=b'{"evidence": []}'
        )

    adapter = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="t")
    adapter._async_client = httpx.AsyncClient(
        base_url="https://api.tzun.ai", transport=httpx.MockTransport(_handler)
    )
    assert asyncio.run(adapter.head()) is None
