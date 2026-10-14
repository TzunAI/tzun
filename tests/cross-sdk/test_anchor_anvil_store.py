"""Every record of a store anchored on anvil, verified by both SDKs (tzun-anchor/1 §10).

``ts-harness/anvil-store.ts`` starts one anvil node, makes a SQLite store with the
TypeScript SDK's ``Tzun.init({ logNamespace, anchoring })`` on three chains,
anchors it in two epochs (each publication in a block it shares with other
transactions), captures one record after the last epoch, and reports the
TypeScript verdict on every record: from the envelope and the bundle alone, and
with an ``RpcEvmHeaderSource`` reading the node. While the node is still up, the
Python SDK verifies the same records, the second time with its own
``RpcEvmHeaderSource`` reading the same node, and the verdicts must be equal,
every check and fact included.

Runs where the anvil suite runs (tests/anvil/harness.ts, ``anvilAvailability``):
never with ``TZUN_SKIP_ANVIL=1``, under CI only with ``TZUN_ANVIL=1``, and
otherwise wherever Docker runs containers. Needs Node and the ``anchor`` extra.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import shutil
import subprocess
from typing import Any

import pytest


def _anchor_extra_or_skip() -> None:
    """Skip without the 'anchor' extra, except under CI, where a skipped parity test
    is one that never runs: there the job must install ``pip install -e 'python[anchor]'``."""
    try:
        import coincurve  # noqa: F401
        from Cryptodome.Hash import keccak  # noqa: F401
    except ImportError:
        if os.environ.get("CI", "").strip().lower() not in ("", "false", "0"):
            pytest.fail(
                "The 'anchor' extra is not installed, and CI must run the anchor parity tests: "
                "install the Python SDK with pip install -e '.[anchor]' in this job.",
                pytrace=False,
            )
        pytest.skip("the 'anchor' extra is not installed", allow_module_level=True)


_anchor_extra_or_skip()

from tzun_sdk.attestation.anchor_verify import verify_anchor  # noqa: E402
from tzun_sdk.attestation.evm_publication import RpcEvmHeaderSource  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
HARNESS = REPO_ROOT / "tests" / "cross-sdk" / "ts-harness" / "anvil-store.ts"


def _anvil_unavailable() -> str | None:
    if os.environ.get("TZUN_SKIP_ANVIL") == "1":
        return "TZUN_SKIP_ANVIL=1"
    ci = os.environ.get("CI")
    if ci and ci != "false" and os.environ.get("TZUN_ANVIL") != "1":
        return "CI is set and TZUN_ANVIL=1 is not"
    if shutil.which("npx") is None:
        return "Node is not available"
    if shutil.which("docker") is None:
        return "Docker is not available"
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True
    )
    if probe.returncode != 0:
        return "Docker does not run containers here"
    return None


@pytest.fixture(scope="module")
def anvil_store() -> Any:
    reason = _anvil_unavailable()
    if reason:
        pytest.skip(reason)
    proc = subprocess.Popen(
        ["npx", "tsx", str(HARNESS)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.stdout is not None and proc.stdin is not None
    line = proc.stdout.readline()
    if not line:
        proc.wait(timeout=120)
        stderr = proc.stderr.read() if proc.stderr else ""
        raise RuntimeError(f"anvil-store harness failed (exit {proc.returncode})\nstderr: {stderr}")
    try:
        yield json.loads(line)
    finally:
        # Closing stdin tells the harness to remove the anvil container.
        proc.stdin.close()
        proc.wait(timeout=180)


def _verify(store: dict[str, Any], record: dict[str, Any], *, with_node: bool) -> Any:
    envelope = record["envelope"]
    material = record["material"]
    verdict = asyncio.run(
        verify_anchor(
            envelope["nonRepudiation"],
            envelope["integrity"]["canonicalDigest"],
            sequence_number=envelope["payload"]["sequenceNumber"],
            chain_id=record["chainId"],
            publisher_manifest=store["manifest"],
            publication_material=[material] if material else None,
            evm_header_sources={store["chain"]: RpcEvmHeaderSource(store["rpcUrl"])}
            if with_node
            else None,
        )
    )
    return json.loads(json.dumps(verdict))


def test_the_store_holds_anchored_records_on_three_chains_and_one_unanchored(
    anvil_store: Any,
) -> None:
    records = anvil_store["records"]
    assert {r["chainId"] for r in records} == {"alpha", "beta", "gamma"}
    anchored = [r for r in records if r["material"] is not None]
    assert len(anchored) == len(records) - 1
    assert all(r["withNode"]["anchorValid"] is True for r in anchored)
    assert all(r["withNode"]["publications"][0]["evm"]["inclusion"] == "tx_proof" for r in anchored)
    unanchored = [r for r in records if r["material"] is None]
    assert unanchored[0]["withNode"]["anchorPresent"] is False


def test_every_record_from_the_envelope_and_the_bundle_alone(anvil_store: Any) -> None:
    for record in anvil_store["records"]:
        assert _verify(anvil_store, record, with_node=False) == record["bundleOnly"], record[
            "evidenceId"
        ]


def test_every_record_with_each_sdk_reading_the_node(anvil_store: Any) -> None:
    for record in anvil_store["records"]:
        assert _verify(anvil_store, record, with_node=True) == record["withNode"], record[
            "evidenceId"
        ]
