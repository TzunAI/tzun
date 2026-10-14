"""What 0.8.0 changed about the EVM chains, checked in the Python SDK.

- The verifier's registry knows the Hoodi test network, ``eip155:560048``, beside
  mainnet and Sepolia: it is the TypeScript SDK's ``DEFAULT_EVM_NETWORKS``, read
  live through the anchor-verify harness.
- The verifier reads a Glamsterdam header, which carries EIP-7928's
  ``blockAccessListHash`` and EIP-7843's ``slotNumber`` after ``requestsHash``: the
  header of a real Platåberget block, as the TypeScript anchor writer rebuilds it
  (``tests/ts/fixtures/evm-glamsterdam-block.json``).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from tzun_sdk.attestation.evm_publication import (
    DEFAULT_EVM_NETWORKS,
    parse_evm_block_header,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS = REPO_ROOT / "tests" / "cross-sdk" / "ts-harness" / "anchor-verify.ts"
GLAMSTERDAM = json.loads(
    (REPO_ROOT / "tests" / "ts" / "fixtures" / "evm-glamsterdam-block.json").read_text(encoding="utf-8")
)


def _typescript_networks() -> dict[str, str]:
    if shutil.which("npx") is None:
        pytest.skip("Node not available: the cross-SDK suite needs Node 22+")
    proc = subprocess.run(
        ["npx", "tsx", str(HARNESS)],
        input=json.dumps({"action": "networks"}),
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=120,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        raise RuntimeError(f"anchor-verify harness failed (exit {proc.returncode})\nstderr: {proc.stderr}")
    networks: dict[str, str] = json.loads(proc.stdout)["networks"]
    return networks


def test_the_registry_is_the_typescript_sdks_and_names_mainnet_sepolia_and_hoodi() -> None:
    assert dict(DEFAULT_EVM_NETWORKS) == _typescript_networks()
    assert DEFAULT_EVM_NETWORKS["eip155:1"] == "mainnet"
    assert DEFAULT_EVM_NETWORKS["eip155:11155111"] == "testnet"
    assert DEFAULT_EVM_NETWORKS["eip155:560048"] == "testnet"


def test_a_glamsterdam_header_of_twenty_three_fields_is_read() -> None:
    header = parse_evm_block_header(GLAMSTERDAM["header"])
    assert header is not None
    assert header.hash == GLAMSTERDAM["blockHash"]
    assert header.number == GLAMSTERDAM["blockNumber"]
    assert header.timestamp == GLAMSTERDAM["timestamp"]
    assert header.transactions_root == GLAMSTERDAM["transactionsRoot"].lower()
