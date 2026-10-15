"""The EVM anchor vectors through the Python SDK (tzun-anchor/1 §9, §10.4 item 2, §13).

``vectors/evm-anchor-vectors.json`` holds §9's validity-bound cases
(``scripts/generate-evm-anchor-vectors.ts``): a manifest entry for the real
publisher whose ``validFrom`` or ``validUntil`` sits at, just inside or just
outside the block time, compared at full precision, and dates
§9 refuses. ``verify_evm_publication`` must give every case its stated verdict
in each of the file's three modes. It also holds §10.4 item 2's transaction
cases: a transaction that breaks one of the rules item 2 states is false,
``malformed_publication``, refused for the very rule the file names, and the one
just inside each edge is read, with the sender and signed chain id the file
states (None for a legacy ``v`` of 27 or 28, which signs none). These need the
``anchor`` extra: without it they are skipped, except under CI, where they fail.

This file needs no Node. ``tests/ts/evm-anchor-vectors.test.ts`` holds the
TypeScript verifier to the same file, and ``test_anchor_verify_parity.py``
requires both SDKs to give every case the same whole verdict.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import re
from typing import Any

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
VECTORS: dict[str, Any] = json.loads(
    (REPO_ROOT / "vectors" / "evm-anchor-vectors.json").read_text(encoding="utf-8")
)
E2E: dict[str, Any] = json.loads(
    (REPO_ROOT / "vectors" / "anchor-e2e-vectors.json").read_text(encoding="utf-8")
)
CASES: list[dict[str, Any]] = VECTORS["validityBounds"]
MODES = ("header", "noHeader", "offline")
TX = VECTORS["transactionCases"]
TX_CASES: list[dict[str, Any]] = TX["cases"]


def _needs_anchor_extra() -> None:
    """Skip without the 'anchor' extra, except under CI, where the job must install it."""
    try:
        import coincurve  # noqa: F401
        from Cryptodome.Hash import keccak  # noqa: F401
    except ImportError:
        if os.environ.get("CI", "").strip().lower() not in ("", "false", "0"):
            pytest.fail(
                "The 'anchor' extra is not installed: install pip install -e '.[anchor]' in this CI job."
            )
        pytest.skip("the 'anchor' extra is not installed")


class StatedSource:
    """The header source the file states: its chain, finality, finalized height,
    the canonical blocks it lists and the transactions it looks up."""

    def __init__(self, spec: dict[str, Any]) -> None:
        self._spec = spec
        self.finality = spec["finality"]

    async def chain_id(self) -> int:
        return int(self._spec["chainId"])

    async def finalized_block_number(self) -> int:
        return int(self._spec["finalizedBlockNumber"])

    async def canonical_block(self, n: int) -> dict[str, Any] | None:
        for b in self._spec["blocks"]:
            if b["number"] == n:
                return {"hash": b["hash"], "timestamp": b["timestamp"]}
        return None

    async def transaction(self, transaction_id: str) -> dict[str, Any] | None:
        for t in self._spec["transactions"]:
            if t["transactionId"] == transaction_id:
                return {
                    "blockHash": t["blockHash"],
                    "blockNumber": t["blockNumber"],
                    "from": t["from"],
                }
        return None


def _input(case: dict[str, Any], mode: str) -> dict[str, Any]:
    publication = dict(VECTORS["publication"])
    if mode == "noHeader":
        for member in ("blockHeader", "txIndex", "txProof"):
            del publication[member]
    return {
        "publication": publication,
        "p": VECTORS["p"],
        "anchor_origin": VECTORS["anchorOrigin"],
        "manifest": {
            "publishers": {
                VECTORS["anchorOrigin"]: [{**VECTORS["manifestEntry"], **case["bounds"]}]
            }
        },
        "header_sources": None
        if mode == "offline"
        else {VECTORS["chain"]: StatedSource(VECTORS["headerSource"])},
    }


def _check(c: Any) -> dict[str, Any]:
    return {"outcome": c["outcome"], **({"reason": c["reason"]} if c.get("reason") else {})}


def test_the_publication_is_epoch_0_of_the_anvil_vectors() -> None:
    epoch = E2E["epochs"][0]
    assert VECTORS["publication"] == epoch["publication"]
    assert VECTORS["p"] == epoch["p"]
    assert VECTORS["chain"] == E2E["chain"]
    assert VECTORS["anchorOrigin"] == E2E["anchorOrigin"]
    assert VECTORS["blockTime"] == epoch["canonicalBlock"]["timestamp"]
    assert VECTORS["headerSource"]["blocks"] == [epoch["canonicalBlock"]]
    assert VECTORS["manifestEntry"] == E2E["manifest"]["publishers"][E2E["anchorOrigin"]][0]
    assert VECTORS["sender"] == VECTORS["manifestEntry"]["address"]
    hs = VECTORS["headerSource"]
    assert {k: hs[k] for k in E2E["headerSource"]} == E2E["headerSource"]
    assert hs["transactions"] == [
        {
            "transactionId": epoch["publication"]["transactionId"],
            "blockHash": epoch["publication"]["blockHash"],
            "blockNumber": epoch["publication"]["blockNumber"],
            "from": VECTORS["sender"],
        }
    ]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_every_case_gets_its_stated_verdict(case: dict[str, Any], mode: str) -> None:
    _needs_anchor_extra()
    from tzun_sdk.attestation.evm_publication import verify_evm_publication

    i = _input(case, mode)
    v = asyncio.run(
        verify_evm_publication(
            i["publication"],
            p=i["p"],
            anchor_origin=i["anchor_origin"],
            manifest=i["manifest"],
            header_sources=i["header_sources"],
        )
    )
    e = case["expect"][mode]
    actual = {
        "valid": v["valid"],
        "reason": v.get("reason"),
        "tx": _check(v["checks"]["tx"]),
        "canonical": _check(v["checks"]["canonical"]),
        "inclusion": v["facts"].get("inclusion") if v["valid"] is True else None,
    }
    assert actual == {
        "valid": e["valid"],
        "reason": e.get("reason"),
        "tx": e["tx"],
        "canonical": e["canonical"],
        "inclusion": e.get("inclusion"),
    }


def test_the_transaction_cases_break_each_rule_and_meet_each_at_its_edge() -> None:
    assert {c["rule"] for c in TX_CASES} == {
        "chain-id",
        "legacy-v",
        "signature-values",
        "fees",
        "recovery",
        "encoding",
        "field-sizes",
        None,
    }
    assert len({c["id"] for c in TX_CASES}) == len(TX_CASES)
    for c in TX_CASES:
        assert c["item2"] == ("reads" if c["rule"] is None else "refuses")


def test_the_transaction_cases_state_the_signed_chain_id() -> None:
    """Each read case states its signed chain id, null only for v 27 and 28 (tzun-anchor/1
    §10.7); each refused case states null."""
    read = [c for c in TX_CASES if c["rule"] is None]
    assert all(c["signedChainId"] is None for c in TX_CASES if c["rule"] is not None)
    assert sorted(c["id"] for c in read if c["signedChainId"] is None) == [
        "legacy-v-27",
        "legacy-v-28",
    ]
    assert all(
        c["signedChainId"] is None or re.fullmatch(r"[1-9][0-9]*", c["signedChainId"])
        for c in read
    )


@pytest.mark.parametrize("case", TX_CASES, ids=[c["id"] for c in TX_CASES])
def test_every_transaction_case_gets_its_stated_verdict(case: dict[str, Any]) -> None:
    _needs_anchor_extra()
    from tzun_sdk.attestation.evm_publication import verify_evm_publication

    publication = {
        "kind": "evm-calldata/1",
        "chain": TX["chain"],
        "transactionId": case["transactionId"],
        "rawTransaction": case["rawTransaction"],
        "blockNumber": TX["blockNumber"],
        "blockHash": TX["blockHash"],
    }
    manifest = {
        "publishers": {
            VECTORS["anchorOrigin"]: [
                {"address": case["publisher"], "chain": TX["chain"], "namespace": "test"}
            ]
        }
    }
    v = asyncio.run(
        verify_evm_publication(
            publication,
            p=VECTORS["p"],
            anchor_origin=VECTORS["anchorOrigin"],
            manifest=manifest,
            header_sources=None,
        )
    )
    e = case["expect"]
    assert {
        "valid": v["valid"],
        "reason": v.get("reason"),
        "tx": _check(v["checks"]["tx"]),
        "canonical": _check(v["checks"]["canonical"]),
        "sender": v["facts"].get("sender"),
    } == {
        "valid": e["valid"],
        "reason": e.get("reason"),
        "tx": e["tx"],
        "canonical": e["canonical"],
        "sender": case["sender"],
    }
    # tzun-anchor/1 §10.7: the signed chain id once the transaction decodes, None for v 27 or
    # 28; no facts at all when item 2 refuses it.
    if case["rule"] is None:
        assert "signedChainId" in v["facts"]
        assert v["facts"]["signedChainId"] == case["signedChainId"]
    else:
        assert "signedChainId" not in v["facts"]


@pytest.mark.parametrize("case", TX_CASES, ids=[c["id"] for c in TX_CASES])
def test_every_transaction_case_breaks_the_rule_it_states(case: dict[str, Any]) -> None:
    _needs_anchor_extra()
    from tzun_sdk.attestation.evm_transaction import (
        EvmTransactionError,
        decode_signed_transaction,
    )

    raw = bytes.fromhex(case["rawTransaction"][2:])
    if case["rule"] is None:
        assert decode_signed_transaction(raw).sender == case["sender"]
    else:
        with pytest.raises(EvmTransactionError) as refused:
            decode_signed_transaction(raw)
        assert refused.value.rule == case["rule"]
