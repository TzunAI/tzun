"""``vectors/checkpoint-vectors.json`` through the Python SDK (tzun-anchor/1 §4 to §6,
§10.3 steps 1 to 5, and §13).

The vectors are an independent pin: ``scripts/generate-checkpoint-vectors.mjs``
imports nothing but node:crypto. ``tzun_sdk.attestation.checkpoint`` and
``tzun_sdk.attestation.anchor_verify`` must give every case its stated answer,
as ``tests/ts/checkpoint-vectors.test.ts`` requires of the TypeScript SDK.

This file needs no Node and no optional extra: no artifact case reaches an EVM
transaction.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import re
from typing import Any

import pytest
from tzun_sdk.attestation.anchor_verify import verify_anchor
from tzun_sdk.attestation.checkpoint import (
    Checkpoint,
    CheckpointParseResult,
    OriginBinding,
    chain_id_from_segment,
    chain_segment,
    check_origin_binding,
    checkpoint_digest,
    evidence_log_origin,
    format_checkpoint,
    is_platform_namespace,
    parse_checkpoint,
    parse_origin,
)
from tzun_sdk.attestation.merkle import (
    build_merkle_tree,
    get_consistency_proof,
    get_merkle_root,
    verify_consistency_proof,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
VECTORS: dict[str, Any] = json.loads(
    (REPO_ROOT / "vectors" / "checkpoint-vectors.json").read_text(encoding="utf-8")
)
BODIES = VECTORS["bodies"]
SEGMENTS = VECTORS["chainSegments"]
ANCHOR_LOG = VECTORS["anchorLog"]


@pytest.mark.parametrize("v", BODIES["valid"], ids=[v["case"] for v in BODIES["valid"]])
def test_reads_and_writes_every_valid_body(v: dict[str, Any]) -> None:
    assert parse_checkpoint(v["body"]) == CheckpointParseResult(
        ok=True,
        checkpoint=Checkpoint(origin=v["origin"], size=v["size"], root=v["root"], body=v["body"]),
    )
    assert format_checkpoint(v["origin"], v["size"], v["root"]) == v["body"]
    assert checkpoint_digest(v["body"]) == v["checkpointDigest"]


@pytest.mark.parametrize("v", BODIES["invalid"], ids=[v["case"] for v in BODIES["invalid"]])
def test_refuses_every_invalid_body(v: dict[str, Any]) -> None:
    assert parse_checkpoint(v["body"]).ok is False
    with pytest.raises(ValueError):
        checkpoint_digest(v["body"])


def test_refuses_every_body_that_is_not_a_string() -> None:
    for body in BODIES["nonString"]:
        assert parse_checkpoint(body) == CheckpointParseResult(ok=False, reason="not_a_string")


@pytest.mark.parametrize("v", SEGMENTS["valid"], ids=[v["case"] for v in SEGMENTS["valid"]])
def test_chain_segments_both_ways(v: dict[str, Any]) -> None:
    assert chain_segment(v["chainId"]) == v["segment"]
    assert chain_id_from_segment(v["segment"]) == v["chainId"]
    prefix = ANCHOR_LOG["domainPrefix"]
    assert evidence_log_origin(prefix, v["chainId"]) == f"{prefix}/evidence/{v['segment']}"


@pytest.mark.parametrize("v", SEGMENTS["invalid"], ids=[v["case"] for v in SEGMENTS["invalid"]])
def test_refuses_every_invalid_chain_segment(v: dict[str, Any]) -> None:
    assert chain_id_from_segment(v["segment"]) is None


@pytest.mark.parametrize(
    "v", SEGMENTS["unencodable"], ids=[v["case"] for v in SEGMENTS["unencodable"]]
)
def test_cannot_encode_what_is_not_a_chain_id(v: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        chain_segment(v["chainId"])


@pytest.mark.parametrize("v", VECTORS["domain"], ids=[v["case"] for v in VECTORS["domain"]])
def test_the_domain_rule(v: dict[str, Any]) -> None:
    got = check_origin_binding(v["anchorOrigin"], v["logOrigin"], v["chainId"])
    expect = v["expect"]
    if expect["result"] == "ok":
        assert got == OriginBinding(
            ok=True, namespace=expect["namespace"], chain_checked=expect["chainChecked"]
        )
    else:
        assert got == OriginBinding(ok=False, reason=expect["result"])


# With a chain id, a source log that is not an evidence log binds exactly when
# its namespace is the platform's: is_platform_namespace is that half of the rule.
OPAQUE = [
    v
    for v in VECTORS["domain"]
    if v["chainId"] is not None
    and v["expect"]["result"] != "origin_not_in_domain"
    and getattr(parse_origin(v["logOrigin"]), "kind", None) == "log"
]


def test_the_domain_vectors_hold_both_platform_outcomes() -> None:
    assert any(v["expect"]["result"] == "ok" for v in OPAQUE)
    assert any(v["expect"]["result"] == "chain_id_mismatch" for v in OPAQUE)


@pytest.mark.parametrize("v", OPAQUE, ids=[v["case"] for v in OPAQUE])
def test_the_platform_namespaces(v: dict[str, Any]) -> None:
    origin = parse_origin(v["logOrigin"])
    assert origin is not None
    assert is_platform_namespace(origin.namespace) == (v["expect"]["result"] == "ok")


@pytest.mark.parametrize("e", ANCHOR_LOG["epochs"], ids=[e["epoch"] for e in ANCHOR_LOG["epochs"]])
def test_each_epoch_of_the_anchor_log(e: dict[str, Any]) -> None:
    source_logs = ANCHOR_LOG["sourceLogs"]
    leaves = ANCHOR_LOG["anchorLeaves"]
    origins = [m["origin"] for m in e["members"]]
    # Members are appended in ascending bytewise origin order.
    assert origins == sorted(origins, key=lambda o: o.encode("utf-8"))
    for m in e["members"]:
        root = get_merkle_root(build_merkle_tree(source_logs[m["origin"]]["leaves"][: m["size"]]))
        assert root == m["root"]
        assert format_checkpoint(m["origin"], m["size"], root) == m["body"]
        assert checkpoint_digest(m["body"]) == m["checkpointDigest"]
        assert leaves[m["anchorLeafIndex"]] == m["checkpointDigest"]
    anchor_root = get_merkle_root(build_merkle_tree(leaves[: e["anchorSize"]]))
    assert anchor_root == e["anchorRoot"]
    assert (
        format_checkpoint(e["anchorOrigin"], e["anchorSize"], anchor_root) == e["anchorCheckpoint"]
    )
    assert checkpoint_digest(e["anchorCheckpoint"]) == e["p"]


def test_the_anchor_log_grows_append_only() -> None:
    c = ANCHOR_LOG["anchorConsistency"]
    generated = get_consistency_proof(
        build_merkle_tree(ANCHOR_LOG["anchorLeaves"]), c["first"], c["second"]
    )
    assert generated.ok and list(generated.proof or ()) == c["proof"]
    assert verify_consistency_proof(
        c["first"], c["second"], c["proof"], c["firstRoot"], c["secondRoot"]
    ).valid


@pytest.mark.parametrize("v", VECTORS["artifacts"], ids=[v["case"] for v in VECTORS["artifacts"]])
def test_verify_anchor_steps_1_to_5(v: dict[str, Any]) -> None:
    got = asyncio.run(
        verify_anchor(
            v["artifacts"], v["digest"], sequence_number=v["sequenceNumber"], chain_id=v["chainId"]
        )
    )
    expect = v["expect"]
    assert got["anchorValid"] is expect["anchorValid"]
    assert got.get("anchorReason") == expect.get("reason")
    assert got["merkleProofValid"] is expect["merkleProofValid"]
    assert got["p"] == expect["p"]
    # No case carries a publication that can be true.
    assert got["anchorPublication"] is None
    assert got["anchorOriginAuthenticated"] is False
    assert got["existedBy"] is None
    # §10.6: 'test' for a test origin whatever the verdict, so every case states it.
    assert got["anchorNamespace"] == expect["anchorNamespace"]
    assert got["anchorPosition"] == expect.get("anchorPosition")
    # The tzun-anchor/1 §10.7 catalogue, in report order, as the vector states it.
    assert [{k: c[k] for k in c if k != "value"} for c in got["checks"]] == expect["checks"]
    # Each publication's checks are its slice of the catalogue.
    assert [c for pub in got["publications"] for c in pub["checks"]] == [
        c for c in got["checks"] if re.search(r"\[\d+\]$", c["id"])
    ]
