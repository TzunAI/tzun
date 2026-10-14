"""The anvil end-to-end anchor vectors through the Python SDK (tzun-anchor/1 §13).

``vectors/anchor-e2e-vectors.json`` holds records the TypeScript anchor scheduler
anchored on anvil (``scripts/generate-anchor-e2e-vectors.ts``). This checks, from
the file alone:

- every envelope parses in the Python wire models and serialises back unchanged;
- its canonical digest recomputes from its payload (``canonical_serialize``);
- ``leafIndex`` is ``sequenceNumber - 1``;
- both inclusion proofs verify with ``tzun_sdk.attestation.merkle``, under the size
  and root read from the checkpoint bodies (RFC 4648 base64);
- P is the SHA-256 of the anchor checkpoint body, and is the same P as the epoch's;
- the consistency proofs between published anchor sizes, and between a source
  log's anchored checkpoints, verify;
- ``tzun_sdk.attestation.anchor_verify.verify_anchor`` gives every record the
  verdicts the file states, from the envelope and the bundle alone and with the
  header source the file states, and refuses the same changes the TypeScript
  suite refuses. These need the ``anchor`` extra: without it they are skipped,
  except under CI, where they fail.

This file needs no Node. The Go gate checks the same file with transparency-dev and
go-ethereum, and ``tests/ts/anchor-e2e-vectors.test.ts`` holds the TypeScript
verifier to the same verdicts.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import pathlib
from typing import Any

import pytest

from tzun_sdk._generated.canonical import V1_HASHED_FIELDS, canonical_serialize
from tzun_sdk.attestation.merkle import verify_consistency_proof, verify_merkle_proof
from tzun_sdk.models import AnchorArtifact, EvidenceEnvelope

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
VECTORS = json.loads(
    (REPO_ROOT / "vectors" / "anchor-e2e-vectors.json").read_text(encoding="utf-8")
)


def _body(body: str) -> tuple[str, int, str]:
    """``<origin>\\n<size>\\n<base64 root>\\n`` → (origin, size, root as hex)."""
    origin, size, root, rest = body.split("\n")
    assert rest == ""
    return origin, int(size), base64.b64decode(root, validate=True).hex()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


RECORDS: list[dict[str, Any]] = VECTORS["records"]


def test_the_file_holds_two_epochs_and_their_records() -> None:
    assert len(VECTORS["epochs"]) == 2
    assert {r["epoch"] for r in RECORDS} == {0, 1}
    assert VECTORS["anchorOrigin"].startswith("test.")


@pytest.mark.parametrize("record", RECORDS, ids=[r["case"] for r in RECORDS])
def test_record(record: dict[str, Any]) -> None:
    envelope = record["envelope"]
    model = EvidenceEnvelope.model_validate(envelope)
    assert isinstance(model.nonRepudiation.anchor, AnchorArtifact)
    assert model.model_dump(mode="json", exclude_unset=True) == envelope

    canonical = canonical_serialize(model.payload.model_dump(mode="json"), list(V1_HASHED_FIELDS))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert digest == envelope["integrity"]["canonicalDigest"]

    anchor = envelope["nonRepudiation"]["anchor"]
    assert anchor["leafIndex"] == envelope["payload"]["sequenceNumber"] - 1

    log_origin, log_size, log_root = _body(anchor["logCheckpoint"])
    anchor_origin, anchor_size, anchor_root = _body(anchor["anchorCheckpoint"])
    assert anchor_origin == VECTORS["anchorOrigin"]
    assert log_origin.startswith(anchor_origin.removesuffix("/anchors") + "/evidence/")
    assert verify_merkle_proof(digest, anchor["leafIndex"], log_size, anchor["logPath"], log_root)
    assert verify_merkle_proof(
        _sha256(anchor["logCheckpoint"]),
        anchor["anchorLeafIndex"],
        anchor_size,
        anchor["anchorPath"],
        anchor_root,
    )
    epoch = VECTORS["epochs"][record["epoch"]]
    assert anchor["anchorCheckpoint"] == epoch["anchorCheckpoint"]
    assert _sha256(anchor["anchorCheckpoint"]) == epoch["p"]
    assert epoch["publication"]["rawTransaction"].startswith("0x02")
    # The envelope carries the publication entry of §8.2, and the epoch joins
    # the bundle's heavy material to the same transaction.
    (entry,) = anchor["publications"]
    for member in ("kind", "chain", "transactionId", "blockNumber", "blockHash", "publisher"):
        assert entry[member] == epoch["publication"][member]


@pytest.mark.parametrize("index", range(len(VECTORS["epochs"])))
def test_epoch_consistency(index: int) -> None:
    epoch = VECTORS["epochs"][index]
    _, size, root = _body(epoch["anchorCheckpoint"])
    if epoch["previousAnchorSize"] is None:
        assert index == 0 and epoch["anchorConsistencyProof"] == []
    else:
        previous = VECTORS["epochs"][index - 1]
        _, first, first_root = _body(previous["anchorCheckpoint"])
        assert first == epoch["previousAnchorSize"]
        assert verify_consistency_proof(first, size, epoch["anchorConsistencyProof"], first_root, root).valid
    for member in epoch["members"]:
        if member["previousLogCheckpoint"] is None:
            continue
        o1, m, r1 = _body(member["previousLogCheckpoint"])
        o2, n, r2 = _body(member["logCheckpoint"])
        assert o1 == o2
        assert verify_consistency_proof(m, n, member["consistencyProof"], r1, r2).valid


# ---- verify_anchor: the stated verdicts ---------------------------------------------------

EPOCHS: list[dict[str, Any]] = VECTORS["epochs"]
CHAIN: str = VECTORS["chain"]


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
    """The header source the file states: its chain, its finalized height, the
    canonical blocks it reported. It looks no transaction up."""

    finality = "finalized"

    def __init__(self, *, block_hash: str | None = None, finalized: int | None = None) -> None:
        self._hash = block_hash
        self._finalized = finalized

    async def chain_id(self) -> int:
        return int(VECTORS["headerSource"]["chainId"])

    async def finalized_block_number(self) -> int:
        return (
            self._finalized
            if self._finalized is not None
            else VECTORS["headerSource"]["finalizedBlockNumber"]
        )

    async def canonical_block(self, n: int) -> dict[str, Any] | None:
        for epoch in EPOCHS:
            block = epoch["canonicalBlock"]
            if block["number"] == n:
                return {"hash": self._hash or block["hash"], "timestamp": block["timestamp"]}
        return None


def _verify(record: dict[str, Any], digest: str | None = None, **overrides: Any) -> dict[str, Any]:
    from tzun_sdk.attestation.anchor_verify import verify_anchor

    envelope = record["envelope"]
    options: dict[str, Any] = {
        "sequence_number": envelope["payload"]["sequenceNumber"],
        "chain_id": record["chainId"],
        "publisher_manifest": VECTORS["manifest"],
        "publication_material": [EPOCHS[record["epoch"]]["publication"]],
    }
    options.update(overrides)
    digest = digest or envelope["integrity"]["canonicalDigest"]
    return dict(asyncio.run(verify_anchor(envelope["nonRepudiation"], digest, **options)))


@pytest.mark.parametrize("record", RECORDS, ids=[r["case"] for r in RECORDS])
def test_verify_anchor_from_the_envelope_and_the_bundle_alone(record: dict[str, Any]) -> None:
    _needs_anchor_extra()
    v = _verify(record)
    e = record["expect"]["bundleOnly"]
    assert (v["anchorValid"], v.get("anchorReason"), v["merkleProofValid"]) == (
        e["anchorValid"],
        e["anchorReason"],
        e["merkleProofValid"],
    )
    dispatch, *checks = v["publications"][0]["checks"]
    assert dispatch == {"id": "anchor.publication[0]", "outcome": "checked-correct", "value": True}
    assert [c["id"] for c in checks] == ["anchor.evm.tx[0]", "anchor.evm.canonical[0]"]
    assert [
        c["outcome"] if c["outcome"] == "checked-correct" else c.get("reason") for c in checks
    ] == [
        e["evmTx"],
        e["evmCanonical"],
    ]


@pytest.mark.parametrize("record", RECORDS, ids=[r["case"] for r in RECORDS])
def test_verify_anchor_with_the_stated_header_source(record: dict[str, Any]) -> None:
    _needs_anchor_extra()
    v = _verify(record, evm_header_sources={CHAIN: StatedSource()})
    expect = dict(record["expect"]["withHeaderSource"])
    inclusion = expect.pop("inclusion")
    for key, value in expect.items():
        assert v[key] == value, key
    assert "anchorReason" not in v
    assert v["p"] == EPOCHS[record["epoch"]]["p"]
    assert v["publications"][0]["evm"]["inclusion"] == inclusion


def _flip(text: str, at: int | None = None) -> str:
    at = len(text) - 1 if at is None else at
    return text[:at] + ("1" if text[at] == "0" else "0") + text[at + 1 :]


LAST = RECORDS[-1]
LAST_PUB = EPOCHS[LAST["epoch"]]["publication"]


def _changed(
    material: dict[str, Any], source: StatedSource | None = None, manifest: Any = None
) -> dict[str, Any]:
    return _verify(
        LAST,
        publication_material=[material],
        evm_header_sources={CHAIN: source or StatedSource()},
        publisher_manifest=manifest if manifest is not None else VECTORS["manifest"],
    )


def test_a_changed_trie_node_is_evm_tx_proof_invalid() -> None:
    _needs_anchor_extra()
    proof = list(LAST_PUB["txProof"])
    proof[1] = _flip(proof[1])
    v = _changed({**LAST_PUB, "txProof": proof})
    assert (v["anchorValid"], v["anchorReason"]) == (False, "evm_tx_proof_invalid")


def test_a_header_that_does_not_hash_to_the_block_hash_is_evm_tx_proof_invalid() -> None:
    _needs_anchor_extra()
    v = _changed({**LAST_PUB, "blockHeader": _flip(LAST_PUB["blockHeader"], 20)})
    assert (v["anchorValid"], v["anchorReason"]) == (False, "evm_tx_proof_invalid")


def test_another_block_at_that_height_is_anchor_not_found_on_chain() -> None:
    _needs_anchor_extra()
    v = _changed(LAST_PUB, StatedSource(block_hash=_flip(LAST_PUB["blockHash"])))
    assert (v["anchorValid"], v["anchorReason"]) == (False, "anchor_not_found_on_chain")


def test_a_finalized_height_below_the_block_is_not_checked() -> None:
    _needs_anchor_extra()
    v = _changed(LAST_PUB, StatedSource(finalized=LAST_PUB["blockNumber"] - 1))
    assert (v["anchorValid"], v["anchorReason"]) == (None, "publication_not_checked")
    assert v["publications"][0]["checks"][2]["reason"] == "evm_block_not_finalized"


def test_a_manifest_that_names_another_publisher_is_evm_sender_mismatch() -> None:
    _needs_anchor_extra()
    other = {
        "publishers": {
            VECTORS["anchorOrigin"]: [
                {"address": "0x" + "42" * 20, "chain": CHAIN, "namespace": "test"}
            ]
        }
    }
    v = _changed(LAST_PUB, manifest=other)
    assert (v["anchorValid"], v["anchorReason"]) == (False, "evm_sender_mismatch")


def test_another_records_digest_is_merkle_proof_invalid() -> None:
    v = _verify(LAST, digest=RECORDS[0]["envelope"]["integrity"]["canonicalDigest"])
    assert (v["anchorValid"], v["anchorReason"]) == (False, "merkle_proof_invalid")
