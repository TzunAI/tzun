"""The anchor verifier in both SDKs: the same inputs, the same answers (tzun-anchor/1
§4 and §10.1: "All three MUST produce the same outcome and reason for every check
on the same inputs").

``ts-harness/anchor-verify.ts`` runs the TypeScript SDK; this file runs
``tzun_sdk.attestation`` over the same JSON and requires equal results, down to
every check, reason and fact:

- the checkpoint and origin readers, over the vector files and mutations of them;
- the RLP decoder, the transaction decoder and sender recovery, over
  ethers-signed transactions of every type the verifier reads and mutations the
  TypeScript side makes of them (non-canonical encodings, high s, bad parity,
  out-of-range fields, bad access lists, legacy ``v`` values), and transactions
  at each edge of each rule of §10.4 item 2 (typed chain id 0, legacy ``v`` 35 to
  38, ``s`` at and above n/2, a tip at and above the fee cap, an ``r`` no key
  recovers from, integers and lengths written non-canonically, bytes after the
  list, a nonce or gasLimit at and above 2^64, amounts and chain ids at and
  above 2^256, a legacy ``v`` at and above its size); a refused transaction must
  be refused for the same rule in both;
- the block-header reader and the transactions-trie walk, over two real Sepolia
  blocks, the anvil vectors and tries the TypeScript trie builder makes;
- Node's base64 and asn1js's ``UTCTime`` and ``GeneralizedTime``, which decide
  whether an ``rfc3161/1`` token is readable;
- ``verifyEvmPublication``, over about 240 publications with scripted header
  sources (``ScriptedSource``: the JSON both sides build a source from), and
  over every validity case of ``evm-anchor-vectors.json`` in each of its modes,
  and its transaction cases;
- ``verifyAnchor``, over anchored records with EVM and RFC 3161 publications,
  the checkpoint and anvil vectors whole, and hostile artifacts.

Two differences are designed, and those cases are held to them, not to equality:

- with RFC 3161 trust anchors supplied, the TypeScript SDK checks the token's CMS
  signature and certificate path, and the Python SDK, which has no verifier for
  them, reports ``missing_dependency``;
- a token corrupted only inside its certificates or signer infos, which pkijs
  parses and the Python reader does not, is ``malformed_publication`` in
  TypeScript and ``publication_not_checked`` in Python; beside a true EVM
  publication, TypeScript's anchor is false and Python's true.

Skipped without Node. Without the ``anchor`` extra the module is skipped, except
under CI, where it fails: the job must install ``pip install -e '.[anchor]'``.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import dataclasses
import datetime
import json
import os
import pathlib
import random
import shutil
import subprocess
from collections.abc import Mapping
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

import anyio  # noqa: E402

from tzun_sdk.attestation._ecmascript import node_base64_decode  # noqa: E402
from tzun_sdk.attestation._rfc3161_steps import UnreadableTrustAnchorError  # noqa: E402
from tzun_sdk.attestation._rfc3161_token import (  # noqa: E402
    UnreadableToken,
    generalized_time_iso,
    pkijs_only_regions,
    utc_time_iso,
)
from tzun_sdk.attestation.anchor_verify import verify_anchor  # noqa: E402
from tzun_sdk.attestation.checkpoint import (  # noqa: E402
    chain_id_from_segment,
    check_origin_binding,
    format_checkpoint,
    parse_checkpoint,
    parse_origin,
)
from tzun_sdk.attestation.evm_publication import (  # noqa: E402
    parse_evm_block_header,
    verify_evm_publication,
    verify_evm_transaction_proof,
)
from tzun_sdk.attestation.evm_rlp import RlpItem, decode_rlp, encode_rlp  # noqa: E402
from tzun_sdk.attestation.evm_transaction import (  # noqa: E402
    ITEM_TWO_RULES,
    EvmTransactionError,
    decode_signed_transaction,
    keccak256,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
HARNESS = REPO_ROOT / "tests" / "cross-sdk" / "ts-harness" / "anchor-verify.ts"
VECTORS = REPO_ROOT / "vectors"
FIXTURES = REPO_ROOT / "tests" / "ts" / "fixtures"
MAX_RLP_DEPTH = 64


def _load(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


CHECKPOINTS = _load(VECTORS / "checkpoint-vectors.json")
E2E = _load(VECTORS / "anchor-e2e-vectors.json")
EVM_ANCHOR = _load(VECTORS / "evm-anchor-vectors.json")
LOG_ORIGINS = _load(VECTORS / "evidence-log-origin-vectors.json")
SEPOLIA_BLOCKS = [
    _load(FIXTURES / "evm-sepolia-block.json"),
    _load(FIXTURES / "evm-sepolia-self-tx.json"),
]


def harness(cmd: dict[str, Any]) -> Any:
    """Run one command through the TypeScript harness."""
    if shutil.which("npx") is None:
        pytest.skip("Node not available: the cross-SDK suite needs Node 22+")
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("TZUN_TSA_TRUST_ANCHORS", "TZUN_TSA_AUTHORITIES")
    }
    env["TZ"] = "UTC"
    proc = subprocess.run(
        ["npx", "tsx", str(HARNESS)],
        input=json.dumps(cmd),
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=600,
        env=env,
    )
    if proc.returncode != 0 or not proc.stdout:
        raise RuntimeError(
            f"anchor-verify harness failed (exit {proc.returncode})\nstderr: {proc.stderr}"
        )
    return json.loads(proc.stdout)


@pytest.fixture(autouse=True)
def _no_tsa_trust_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TZUN_TSA_TRUST_ANCHORS", raising=False)
    monkeypatch.delenv("TZUN_TSA_AUTHORITIES", raising=False)


def as_json(value: Any) -> Any:
    """The value as the TypeScript side's JSON would carry it."""
    return json.loads(json.dumps(value))


# ---- Scripted header sources (the twin of `scripted` in the harness) ----------------------


class ScriptedSource:
    """A header source the JSON describes; see ``SourceSpec`` in the harness."""

    def __init__(self, spec: Mapping[str, Any]) -> None:
        self._spec = spec
        if "finality" in spec:
            self.finality = spec["finality"]
        if spec.get("transactions") is not None:
            self.transaction = self._transaction

    async def _act(self, method: str, answer: Any) -> Any:
        failure = (self._spec.get("fail") or {}).get(method)
        if failure == "throw":
            raise RuntimeError(f"{method} failed")
        if failure == "hang":
            await anyio.sleep_forever()
        if self._spec.get("delayMs"):
            await anyio.sleep(self._spec["delayMs"] / 1000)
        return answer()

    async def chain_id(self) -> Any:
        spec = self._spec
        return await self._act(
            "chainId", lambda: spec["chainIdRaw"] if "chainIdRaw" in spec else int(spec["chainId"])
        )

    async def finalized_block_number(self) -> Any:
        return await self._act("finalizedBlockNumber", lambda: self._spec.get("finalized"))

    async def canonical_block(self, n: int) -> Any:
        blocks = self._spec.get("blocks") or {}
        return await self._act("canonicalBlock", lambda: blocks.get(str(n)))

    async def _transaction(self, transaction_id: str) -> Any:
        txs = self._spec["transactions"]
        return await self._act("transaction", lambda: txs.get(transaction_id))


def header_sources(sources: Any) -> Any:
    if isinstance(sources, Mapping):
        return {chain: ScriptedSource(spec) for chain, spec in sources.items()}
    return sources


def py_verify_evm(case: Mapping[str, Any]) -> Any:
    i = case["input"]
    return as_json(
        asyncio.run(
            verify_evm_publication(
                i.get("publication"),
                p=i.get("p"),
                anchor_origin=i.get("anchorOrigin"),
                manifest=i.get("manifest"),
                header_sources=header_sources(case.get("sources")),
                networks=i.get("networks"),
                timeout_ms=i.get("timeoutMs"),
            )
        )
    )


def py_verify_anchor(case: Mapping[str, Any]) -> Any:
    o = case.get("options") or {}
    return as_json(
        asyncio.run(
            verify_anchor(
                case.get("artifacts"),
                case.get("digest"),
                sequence_number=o.get("sequenceNumber"),
                chain_id=o.get("chainId"),
                publisher_manifest=o.get("publisherManifest"),
                evm_header_sources=header_sources(o.get("evmHeaderSources")),
                evm_networks=o.get("evmNetworks"),
                evm_timeout_ms=o.get("evmTimeoutMs"),
                publication_material=o.get("publicationMaterial"),
                trust_anchors_pem=o.get("trustAnchorsPem"),
                authorities=o.get("authorities"),
            )
        )
    )


# ---- The corpus: readers and decoders --------------------------------------------------------


def _hex_item(item: RlpItem) -> Any:
    return "0x" + item.hex() if isinstance(item, bytes) else [_hex_item(x) for x in item]


def _error_or(f: Any) -> Any:
    try:
        return f()
    except Exception:
        return {"error": True}


def _origin(o: Any) -> Any:
    if o is None:
        return None
    out = {"kind": o.kind, "domainPrefix": o.domain_prefix, "namespace": o.namespace}
    if o.kind == "evidence":
        out["chainId"] = o.chain_id
    if o.kind == "log":
        out["name"] = o.name
    return out


def _binding(b: Any) -> Any:
    if b.ok:
        return {"ok": True, "namespace": b.namespace, "chainChecked": b.chain_checked}
    return {"ok": False, "reason": b.reason}


def _parsed(r: Any) -> Any:
    if r.ok:
        return {"ok": True, "checkpoint": dataclasses.asdict(r.checkpoint)}
    return {"ok": False, "reason": r.reason}


def _transaction(raw: str) -> Any:
    try:
        tx = decode_signed_transaction(bytes.fromhex(raw[2:]))
    except EvmTransactionError as exc:
        return {"refused": exc.rule}
    return {
        "type": tx.type,
        "chainId": str(tx.chain_id),
        "data": "0x" + tx.data.hex(),
        "sender": tx.sender,
    }


def _header(h: Any) -> Any:
    header = parse_evm_block_header(h)
    if header is None:
        return None
    return {
        "hash": header.hash,
        "number": header.number,
        "timestamp": header.timestamp,
        "transactionsRoot": header.transactions_root,
    }


def _time(parse: Any, text: str) -> Any:
    try:
        return {"iso": parse(text)}
    except UnreadableToken:
        return {"error": True}


def python_corpus(c: Mapping[str, Any]) -> dict[str, list[Any]]:
    return {
        "bodies": [_parsed(parse_checkpoint(b)) for b in c.get("bodies", [])],
        "segments": [chain_id_from_segment(s) for s in c.get("segments", [])],
        "origins": [_origin(parse_origin(o)) for o in c.get("origins", [])],
        "bindings": [
            _binding(
                check_origin_binding(b.get("anchorOrigin"), b.get("logOrigin"), b.get("chainId"))
            )
            for b in c.get("bindings", [])
        ],
        "formats": [
            _error_or(lambda f=f: {"body": format_checkpoint(f["origin"], f["size"], f["root"])})
            for f in c.get("formats", [])
        ],
        "rlp": [
            _error_or(lambda h=h: {"value": _hex_item(decode_rlp(bytes.fromhex(h[2:])))})
            for h in c.get("rlp", [])
        ],
        "transactions": [_error_or(lambda r=r: _transaction(r)) for r in c.get("transactions", [])],
        "headers": [_header(h) for h in c.get("headers", [])],
        "proofs": [
            verify_evm_transaction_proof(p.get("root"), p.get("index"), p.get("proof"))
            for p in c.get("proofs", [])
        ],
        "base64": [node_base64_decode(s).hex() for s in c.get("base64", [])],
        "generalizedTimes": [_time(generalized_time_iso, s) for s in c.get("generalizedTimes", [])],
        "utcTimes": [_time(utc_time_iso, s) for s in c.get("utcTimes", [])],
    }


def assert_same(name: str, inputs: list[Any], ts: list[Any], py: list[Any]) -> None:
    assert len(ts) == len(py) == len(inputs), name
    diverged = [(inputs[i], ts[i], py[i]) for i in range(len(inputs)) if as_json(py[i]) != ts[i]]
    assert not diverged, f"{name}: {len(diverged)} of {len(inputs)} differ, first: {diverged[0]!r}"


def _mutations(text: str, rng: random.Random, n: int) -> list[str]:
    """Single-character substitutions, insertions and deletions of ``text``."""
    alphabet = "0123456789abcdefABCDEF+/=\n\r /.-_:ZTé"
    out: list[str] = []
    for _ in range(n):
        at = rng.randrange(len(text) + 1)
        op = rng.randrange(3)
        ch = rng.choice(alphabet)
        if op == 0 and at < len(text):
            out.append(text[:at] + ch + text[at + 1 :])
        elif op == 1:
            out.append(text[:at] + ch + text[at:])
        elif at < len(text):
            out.append(text[:at] + text[at + 1 :])
    return out


def _rlp_corpus(rng: random.Random) -> list[str]:
    fixed = [
        "00",
        "7f",
        "80",
        "8100",
        "8105",
        "817f",
        "8180",
        "83646f67",
        "b80161",
        "b9000161",
        "b838" + "61" * 56,
        "c0",
        "c180",
        "c28180",
        "c1" + "8161",
        "c2" + "80",
        "c3808080",
        "f80180",
        "f90000",
        "f83a" + "b838" + "61" * 56,
        "81",
        "b8",
        "b802" + "61",
        "c180" + "80",
        "ff",
        "bf" + "ff" * 8,
        "fb" + "00" * 4,
        "c7c0c1c0c3c0c1c0",
    ]
    out = ["0x" + h for h in fixed]

    def item(depth: int) -> RlpItem:
        if depth > 3 or rng.random() < 0.5:
            return bytes(
                rng.randrange(256) for _ in range(rng.choice([0, 1, 1, 2, 20, 32, 56, 70]))
            )
        return [item(depth + 1) for _ in range(rng.randrange(4))]

    for _ in range(60):
        encoded = encode_rlp(item(0))
        out.append("0x" + encoded.hex())
        cut = rng.randrange(1, len(encoded) + 1)
        out.append("0x" + encoded[:cut].hex())
        flipped = bytearray(encoded)
        at = rng.randrange(len(flipped))
        flipped[at] ^= 1 << rng.randrange(8)
        out.append("0x" + bytes(flipped).hex())
    return out


def _der(tag: int, content: bytes) -> bytes:
    """One DER element: ``tag``, the definite length of ``content``, and ``content``."""
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    length = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + content


def _rlp_list_of(items: list[bytes]) -> bytes:
    """An RLP list of items already encoded."""
    payload = b"".join(items)
    if len(payload) <= 55:
        return bytes([0xC0 + len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(length)]) + length + payload


def _nested_lists(depth: int) -> bytes:
    """``depth`` lists, each holding the next, the innermost empty."""
    encoded = encode_rlp([])
    for _ in range(depth - 1):
        encoded = _rlp_list_of([encoded])
    return encoded


#: Nesting depths around MAX_RLP_DEPTH and past where ethers' recursive decoder
#: runs out of stack in Node (about 3,000).
_DEPTHS = (MAX_RLP_DEPTH - 1, MAX_RLP_DEPTH, MAX_RLP_DEPTH + 1, 1_000, 3_000, 20_000)


def _deep_rlp_items() -> tuple[list[str], list[str], list[dict[str, Any]]]:
    """Items, headers and trie proofs with lists nested around and past MAX_RLP_DEPTH,
    in fields and trie slots neither verifier reads."""
    items = ["0x" + _nested_lists(d).hex() for d in _DEPTHS]
    fields = decode_rlp(bytes.fromhex(SEPOLIA_BLOCKS[0]["header"][2:]))
    assert isinstance(fields, list)
    rest = [encode_rlp(f) for f in fields[1:]]
    headers = ["0x" + _rlp_list_of([_nested_lists(d), *rest]).hex() for d in _DEPTHS]
    # A branch node whose slot 8 holds an embedded leaf for key rlp(0) = 0x80 and
    # whose slot 3 holds nested lists the walk never reads.
    leaf = encode_rlp([b"\x30", b"\xab\xcd"])
    proofs: list[dict[str, Any]] = []
    for d in _DEPTHS:
        slots = [encode_rlp(b"")] * 17
        slots[3] = _nested_lists(d)
        slots[8] = leaf
        node = _rlp_list_of(slots)
        proofs.append(
            {"root": "0x" + keccak256(node).hex(), "index": 0, "proof": ["0x" + node.hex()]}
        )
    return items, headers, proofs


#: Characters above U+00FF, which Node's base64 decoder reads by the low byte of
#: each UTF-16 code unit: U+0141 as 'A', U+4E2D as '-', U+013D and an emoji's high
#: surrogate as '=', U+FF21 as '!', and lone surrogates, which JSON can carry.
_WIDE_CHARACTERS = (
    "\u0100",
    "\u0141",
    "\u013d",
    "\u0161",
    "\u4e2d",
    "\u2028",
    "\ufeff",
    "\uff21",
    "\uff41",
    "\U0001f600",
    "\U0001f92f",
    "\U00010441",
    "\ud83d",
    "\ude00",
)


def _wide_base64_inputs(token: str, rng: random.Random) -> list[str]:
    out: list[str] = []
    for ch in _WIDE_CHARACTERS:
        out += [ch + "QUJD", "QU" + ch + "JD", token[:40] + ch + token[40:80]]
    for _ in range(100):
        text = list(token[:24])
        for _ in range(rng.randrange(1, 4)):
            ch = chr(rng.choice([rng.randrange(0x100, 0x800), rng.randrange(0x4E00, 0x9FFF)]))
            text.insert(rng.randrange(len(text) + 1), ch)
        out.append("".join(text))
    return out


def _log_origin_corpus() -> tuple[list[Any], list[Any], list[Any]]:
    """The origins, chain segments and bindings of evidence-log-origin-vectors.json."""
    anchors = next(s["origin"] for s in LOG_ORIGINS["storeLogs"] if s["kind"] == "anchors")
    origins = [v["origin"] for v in LOG_ORIGINS["vectors"]]
    origins += [s["origin"] for s in LOG_ORIGINS["storeLogs"]]
    segments = [v["chainSegment"] for v in LOG_ORIGINS["vectors"]]
    bindings: list[Any] = []
    for v in LOG_ORIGINS["vectors"]:
        for chain_id in (v["chainId"], None, "default", v["chainId"] + "x"):
            bindings.append(
                {"anchorOrigin": anchors, "logOrigin": v["origin"], "chainId": chain_id}
            )
    for store_log in LOG_ORIGINS["storeLogs"]:
        bindings.append(
            {"anchorOrigin": anchors, "logOrigin": store_log["origin"], "chainId": None}
        )
    return origins, segments, bindings


@pytest.fixture(scope="module")
def ts_transactions() -> list[dict[str, str]]:
    return harness({"action": "transactions"})["cases"]


@pytest.fixture(scope="module")
def ts_trie() -> dict[str, Any]:
    small = ["0x" + format(i + 1, "02x") for i in range(20)]
    return {
        "small": {**harness({"action": "trie", "values": small}), "values": small},
        "wide": {
            **harness(
                {
                    "action": "trie",
                    "values": ["0x" + format(i, "04x") + "cc" * 38 for i in range(300)],
                }
            ),
        },
    }


def test_the_corpus(ts_transactions: list[dict[str, str]], ts_trie: dict[str, Any]) -> None:
    rng = random.Random(20260926)
    valid = [v["body"] for v in CHECKPOINTS["bodies"]["valid"]]
    bodies: list[Any] = (
        valid
        + [v["body"] for v in CHECKPOINTS["bodies"]["invalid"]]
        + list(CHECKPOINTS["bodies"]["nonString"])
        + [m for body in valid for m in _mutations(body, rng, 25)]
        + [True, 1.5, [], {}]
    )
    segments: list[Any] = (
        [v["segment"] for v in CHECKPOINTS["chainSegments"]["valid"]]
        + [v["segment"] for v in CHECKPOINTS["chainSegments"]["invalid"]]
        + [
            "c0af",
            "eda080",
            "f4908080",
            "e282",
            "ff",
            "efbbbf61",
            "00",
            "610062",
            "f09f9492",
            "",
            "6",
            7,
            None,
        ]
        + [bytes(rng.randrange(256) for _ in range(rng.randrange(1, 6))).hex() for _ in range(200)]
    )
    log_origins, log_segments, log_bindings = _log_origin_corpus()
    segments += log_segments
    domain = CHECKPOINTS["domain"]
    origins: list[Any] = [d["anchorOrigin"] for d in domain] + [d["logOrigin"] for d in domain]
    origins += [m for o in origins[:10] for m in _mutations(o, rng, 10)] + [
        7,
        None,
        "",
        "a/b/c/d/e",
    ]
    bindings: list[Any] = [
        {"anchorOrigin": d["anchorOrigin"], "logOrigin": d["logOrigin"], "chainId": d["chainId"]}
        for d in domain
    ]
    bindings += [
        {"anchorOrigin": d["anchorOrigin"], "logOrigin": d["logOrigin"], "chainId": c}
        for d in domain[:8]
        for c in (None, "default", "", 7, "﻿a", "alpha")
    ]
    origins += log_origins
    bindings += log_bindings
    formats: list[Any] = [
        {"origin": v["origin"], "size": v["size"], "root": v["root"]}
        for v in CHECKPOINTS["bodies"]["valid"]
    ]
    formats += [
        {"origin": "a/b/anchors", "size": s, "root": r}
        for s in (1, 0, -1, 1.5, 2**53 - 1, 2**53, "7", True, None)
        for r in ("ab" * 32, "AB" * 32, "ab" * 31, "0x" + "ab" * 31, None, 7)
    ]
    formats += [
        {"origin": o, "size": 1, "root": "ab" * 32}
        for o in ("", "a b", "a+b", "café", None, 7, "a\nb")
    ]

    transactions = [c["raw"] for c in ts_transactions]
    transactions += [e["publication"]["rawTransaction"] for e in E2E["epochs"]]
    transactions += [t["raw"] for block in SEPOLIA_BLOCKS for t in block["transactions"]]

    headers: list[Any] = [block["header"] for block in SEPOLIA_BLOCKS] + [
        e["publication"]["blockHeader"] for e in E2E["epochs"]
    ]
    headers += [
        "0x",
        "0xdeadbeef",
        "0x" + encode_rlp([b"\x01"] * 15).hex(),
        "0x" + encode_rlp([[]] * 15).hex(),
        7,
        None,
        "zz",
    ]
    for h in list(headers[:4]):
        raw = bytes.fromhex(h[2:])
        for _ in range(8):
            flipped = bytearray(raw)
            flipped[rng.randrange(len(flipped))] ^= 1 << rng.randrange(8)
            headers.append("0x" + bytes(flipped).hex())

    proofs: list[Any] = []
    for block in SEPOLIA_BLOCKS:
        for t in block["transactions"]:
            proofs.append(
                {"root": block["transactionsRoot"], "index": t["index"], "proof": t["proof"]}
            )
            proofs.append(
                {"root": block["transactionsRoot"], "index": t["index"] + 1, "proof": t["proof"]}
            )
            proofs.append(
                {
                    "root": block["transactionsRoot"],
                    "index": t["index"],
                    "proof": [*t["proof"], t["proof"][0]],
                }
            )
            proofs.append(
                {
                    "root": block["transactionsRoot"].upper().replace("0X", "0x"),
                    "index": float(t["index"]),
                    "proof": t["proof"],
                }
            )
    for e in E2E["epochs"]:
        pub = e["publication"]
        header = parse_evm_block_header(pub["blockHeader"])
        assert header is not None
        proofs.append(
            {"root": header.transactions_root, "index": pub["txIndex"], "proof": pub["txProof"]}
        )
        proofs.append(
            {
                "root": header.transactions_root,
                "index": pub["txIndex"],
                "proof": pub["txProof"][::-1],
            }
        )
    small = ts_trie["small"]
    for i in range(len(small["values"])):
        for j in (i, (i + 1) % len(small["values"])):
            proofs.append({"root": small["root"], "index": j, "proof": small["proofs"][i]})
    wide = ts_trie["wide"]
    for i in (0, 1, 127, 128, 255, 256, 257, 299):
        for j in (i, 512, 257):
            proofs.append({"root": wide["root"], "index": j, "proof": wide["proofs"][i]})
    deep_items, deep_headers, deep_proofs = _deep_rlp_items()
    headers += deep_headers
    proofs += deep_proofs
    proofs += [
        {"root": "0x" + "00" * 32, "index": 0, "proof": []},
        {"root": 7, "index": 0, "proof": ["0x80"]},
        {"root": "0x" + "00" * 32, "index": -1, "proof": ["0x80"]},
        {"root": "0x" + "00" * 32, "index": 0, "proof": "0x80"},
    ]

    token = base64.b64encode(bytes(range(256)) * 3).decode()
    base64_inputs = [
        token,
        token.replace("+", "-").replace("/", "_"),
        "AQID",
        "AQI",
        "AQ",
        "A",
        "AQ==",
        "AQ=",
        "A Q I D",
        "AQ-_",
    ]
    base64_inputs += [
        "AQ==AQ==",
        "=AQ",
        "AQ=I",
        "@@AQID",
        "",
        "====",
        "é" + token[:40],
        "AQIDBA\n==\n",
    ]
    base64_inputs += _mutations(token[:80], rng, 80)
    base64_inputs += _wide_base64_inputs(token, rng)

    times = [
        "20260920120000Z",
        "20260920120000.123Z",
        "20260920120000.1Z",
        "20260920120000.9999Z",
        "202609201200Z",
        "2026092012Z",
    ]
    times += [
        "20260920Z",
        "20260920120000,5Z",
        "20260920120000.Z",
        "20260920120000.5e1Z",
        "2026092012.5Z",
        "202609201230.25Z",
    ]
    times += [
        "20260920120000",
        "20260920120000+0130",
        "20260920120000-0500",
        "20260920120000+01",
        "2026092012+01",
        "20260920+0100",
    ]
    times += [
        "20260920120000+1",
        "20260920120000+01a0",
        "0050010100000Z",
        "00500101000000Z",
        "00991231235959Z",
        "01000101000000Z",
    ]
    times += [
        "20261340256161Z",
        "20260931000000Z",
        "2026092012000Z",
        "abcdefghijklmnZ",
        "20260920120000z",
        "Z",
        "20260920120000 ",
    ]
    times += [
        "99991231235959.999Z",
        "20260920120000.0000001Z",
        "20260920 20000Z",
        "20260920120000+0100Z",
    ]
    utc_times = [
        "260920120000Z",
        "990101000000Z",
        "500101000000Z",
        "491231235959Z",
        "junk",
        "",
        "x260920120000Zx",
        "261340256161Z",
    ]

    corpus = {
        "bodies": bodies,
        "segments": segments,
        "origins": origins,
        "bindings": bindings,
        "formats": formats,
        "rlp": _rlp_corpus(rng) + transactions + deep_items,
        "transactions": transactions,
        "headers": headers,
        "proofs": proofs,
        "base64": base64_inputs,
        "generalizedTimes": times,
        "utcTimes": utc_times,
    }
    ts = harness({"action": "corpus", **corpus})
    py = python_corpus(corpus)
    for key, inputs in corpus.items():
        assert_same(key, inputs, ts[key], py[key])
    # The corpus reaches what it is for: senders recovered, trie proofs walked, bodies read.
    assert sum(1 for r in ts["transactions"] if "sender" in r) >= 20
    # And refusals for every rule of §10.4 item 2, and for bytes that are no transaction.
    refused = [r["refused"] for r in ts["transactions"] if "refused" in r]
    assert len(refused) >= 20
    assert set(refused) == {*ITEM_TWO_RULES, None}
    assert sum(1 for r in ts["proofs"] if r is not None) >= 30
    assert sum(1 for r in ts["bodies"] if r["ok"]) >= len(valid)
    # MAX_RLP_DEPTH lists decode and one more does not, in an item, a header's
    # unread field and a trie slot off the key's path.
    depth_limit = [d <= MAX_RLP_DEPTH for d in _DEPTHS]
    assert [("value" in r) for r in ts["rlp"][-len(_DEPTHS) :]] == depth_limit
    within = [d < MAX_RLP_DEPTH for d in _DEPTHS]
    assert [(r is not None) for r in ts["headers"][-len(_DEPTHS) :]] == within
    assert [r == "0xabcd" for r in ts["proofs"][-4 - len(_DEPTHS) : -4]] == within
    # Every log-origin vector binds to its own chain id.
    assert all(
        ts["bindings"][len(bindings) - len(log_bindings) + 4 * i]["ok"]
        for i in range(len(LOG_ORIGINS["vectors"]))
    )


# ---- verifyEvmPublication ------------------------------------------------------------------


@pytest.fixture(scope="module")
def evm_scenarios() -> list[dict[str, Any]]:
    return harness({"action": "evm-scenarios"})["cases"]


def test_every_evm_scenario_gets_the_same_verdict(evm_scenarios: list[dict[str, Any]]) -> None:
    diverged = []
    for case in evm_scenarios:
        py = py_verify_evm(case)
        if py != case["verdict"]:
            diverged.append((case["name"], case["verdict"], py))
    assert not diverged, f"{len(diverged)} of {len(evm_scenarios)} differ; first: {diverged[0]!r}"
    # Every outcome is reached.
    reasons = {(c["verdict"]["valid"], c["verdict"].get("reason")) for c in evm_scenarios}
    for expected in [
        (True, None),
        (False, "evm_sender_mismatch"),
        (False, "evm_chain_mismatch"),
        (False, "evm_calldata_mismatch"),
        (False, "evm_tx_proof_invalid"),
        (False, "anchor_not_found_on_chain"),
        (False, "malformed_publication"),
        (None, "publication_not_checked"),
        (None, "unsupported_publication_kind"),
        (None, "unsupported_evm_tx_type"),
    ]:
        assert expected in reasons
    details = {c["verdict"]["checks"]["canonical"].get("reason") for c in evm_scenarios}
    details |= {c["verdict"]["checks"]["tx"].get("reason") for c in evm_scenarios}
    for detail in [
        "input_not_supplied:evm_header_source",
        "input_not_supplied:publisher_manifest",
        "input_not_supplied:p",
        "no_expectation:publisher",
        "not_in_bundle:raw_transaction",
        "not_in_bundle:tx_proof",
        "not_in_bundle:block_header",
        "evm_header_source_chain_mismatch",
        "evm_header_source_unavailable",
        "evm_header_source_timeout",
        "evm_block_not_finalized",
        "evm_header_source_inconsistent",
    ]:
        assert detail in details, detail


def _mutated_publications(evm_scenarios: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Field-by-field mutations of the true publications, for both verifiers."""
    rng = random.Random(7)
    out: list[dict[str, Any]] = []
    trues = [c for c in evm_scenarios if c["verdict"]["valid"] is True][:12]
    for case in trues:
        pub = case["input"]["publication"]
        for key in list(pub):
            for value in (None, 0, -1, "", "0x", [], {}, True, "0x" + "00" * 32):
                mutated = copy.deepcopy(case)
                mutated["input"]["publication"][key] = value
                out.append(mutated)
            value = pub[key]
            if isinstance(value, str) and value.startswith("0x") and len(value) > 4:
                mutated = copy.deepcopy(case)
                at = rng.randrange(2, len(value))
                mutated["input"]["publication"][key] = (
                    value[:at] + ("1" if value[at] == "0" else "0") + value[at + 1 :]
                )
                out.append(mutated)
    return out


def test_mutated_publications_get_the_same_verdict(evm_scenarios: list[dict[str, Any]]) -> None:
    cases = _mutated_publications(evm_scenarios)
    ts = harness(
        {
            "action": "verify-evm",
            "cases": [{"input": c["input"], "sources": c["sources"]} for c in cases],
        }
    )["verdicts"]
    diverged = [
        (c["input"]["publication"], t, p)
        for c, t in zip(cases, ts, strict=True)
        if (p := py_verify_evm(c)) != t
    ]
    assert not diverged, f"{len(diverged)} of {len(cases)} differ; first: {diverged[0]!r}"


def _true_case(evm_scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    return copy.deepcopy(next(c for c in evm_scenarios if c["verdict"]["valid"] is True))


def _iso_second(seconds: int) -> str:
    return datetime.datetime.fromtimestamp(seconds, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S")


def test_manifest_bounds_below_the_millisecond_get_the_same_verdict(
    evm_scenarios: list[dict[str, Any]],
) -> None:
    """A bound is compared at full precision on both sides, however many digits
    its fraction has (tzun-anchor/1 §9): a validFrom any fraction
    past the block's second excludes the block, and a validUntil any fraction
    past it still admits the block."""
    base = _true_case(evm_scenarios)
    number = str(base["input"]["publication"]["blockNumber"])
    (spec,) = base["sources"].values()
    second = _iso_second(spec["blocks"][number]["timestamp"])
    earlier = _iso_second(spec["blocks"][number]["timestamp"] - 1)
    bounds = [
        ({"validFrom": f"{second}.000Z"}, True),
        ({"validFrom": f"{second}.0005Z"}, False),
        ({"validFrom": f"{second}.0001234567Z"}, False),
        ({"validFrom": f"{second}.0009999999999Z"}, False),
        ({"validFrom": f"{second}.0999999999Z"}, False),
        ({"validFrom": f"{second}.0019999999Z"}, False),
        ({"validFrom": f"{earlier}.0005Z"}, True),
        ({"validUntil": f"{earlier}.9999999999Z"}, False),
        ({"validUntil": f"{second}.0000000001Z"}, True),
        ({"validFrom": f"{earlier}.9999999999999999+00:00"}, True),
    ]
    cases = []
    for bound, _ in bounds:
        case = copy.deepcopy(base)
        entries = case["input"]["manifest"]["publishers"]
        for origin in entries:
            entries[origin] = [{**e, **bound} for e in entries[origin]]
        cases.append({"input": case["input"], "sources": case["sources"]})
    ts = harness({"action": "verify-evm", "cases": cases})["verdicts"]
    py = [py_verify_evm(c) for c in cases]
    assert py == ts
    assert [v["valid"] for v in ts] == [valid for _, valid in bounds]


def _evm_vector_cases() -> list[dict[str, Any]]:
    """Every validity case of evm-anchor-vectors.json in each of its modes, as
    verify-evm cases: header (the publication as given, with the file's header
    source), noHeader (without blockHeader, txIndex and txProof) and offline (no
    header source); then every transaction case of §10.4 item 2, offline."""
    spec = EVM_ANCHOR["headerSource"]
    source = {
        "chainId": str(spec["chainId"]),
        "finalized": spec["finalizedBlockNumber"],
        "finality": spec["finality"],
        "blocks": {
            str(b["number"]): {"hash": b["hash"], "timestamp": b["timestamp"]}
            for b in spec["blocks"]
        },
        "transactions": {
            t["transactionId"]: {
                "blockHash": t["blockHash"],
                "blockNumber": t["blockNumber"],
                "from": t["from"],
            }
            for t in spec["transactions"]
        },
    }
    publication = EVM_ANCHOR["publication"]
    bare = {k: v for k, v in publication.items() if k not in ("blockHeader", "txIndex", "txProof")}
    origin = EVM_ANCHOR["anchorOrigin"]
    cases: list[dict[str, Any]] = []
    for case in EVM_ANCHOR["validityBounds"]:
        manifest = {"publishers": {origin: [{**EVM_ANCHOR["manifestEntry"], **case["bounds"]}]}}
        for mode in ("header", "noHeader", "offline"):
            cases.append(
                {
                    "input": {
                        "publication": bare if mode == "noHeader" else publication,
                        "p": EVM_ANCHOR["p"],
                        "anchorOrigin": origin,
                        "manifest": manifest,
                    },
                    "sources": None if mode == "offline" else {EVM_ANCHOR["chain"]: source},
                }
            )
    tx = EVM_ANCHOR["transactionCases"]
    for case in tx["cases"]:
        cases.append(
            {
                "input": {
                    "publication": {
                        "kind": "evm-calldata/1",
                        "chain": tx["chain"],
                        "transactionId": case["transactionId"],
                        "rawTransaction": case["rawTransaction"],
                        "blockNumber": tx["blockNumber"],
                        "blockHash": tx["blockHash"],
                    },
                    "p": EVM_ANCHOR["p"],
                    "anchorOrigin": origin,
                    "manifest": {
                        "publishers": {
                            origin: [
                                {"address": case["publisher"], "chain": tx["chain"], "namespace": "test"}
                            ]
                        }
                    },
                },
                "sources": None,
            }
        )
    return cases


def test_the_evm_anchor_vectors_get_the_same_whole_verdicts() -> None:
    """Both SDKs give every validity case of evm-anchor-vectors.json, in each mode,
    and every transaction case the same verdict, every check and fact included. Each SDK's own suite holds it
    to the file's stated verdicts (tests/ts/evm-anchor-vectors.test.ts,
    test_evm_anchor_vectors.py)."""
    cases = _evm_vector_cases()
    ts = harness({"action": "verify-evm", "cases": cases})["verdicts"]
    diverged = [
        (c["input"]["manifest"], t, p)
        for c, t in zip(cases, ts, strict=True)
        if (p := py_verify_evm(c)) != t
    ]
    assert not diverged, f"{len(diverged)} of {len(cases)} differ; first: {diverged[0]!r}"
    assert {t["valid"] for t in ts} == {True, False, None}


def test_a_deadline_beyond_what_set_timeout_can_wait_gets_the_same_verdict(
    evm_scenarios: list[dict[str, Any]],
) -> None:
    """Node runs a setTimeout longer than 2^31 - 1 ms after 1 ms; the TypeScript
    deadline re-arms instead, so both sides wait for a source that answers late."""
    base = _true_case(evm_scenarios)
    for spec in base["sources"].values():
        spec["delayMs"] = 30
    cases = []
    for timeout_ms in (2**31 - 1, 2**31, 2**53 - 1, 1e308):
        case = copy.deepcopy(base)
        case["input"]["timeoutMs"] = timeout_ms
        cases.append({"input": case["input"], "sources": case["sources"]})
    ts = harness({"action": "verify-evm", "cases": cases})["verdicts"]
    py = [py_verify_evm(c) for c in cases]
    assert py == ts
    assert all(v["valid"] is True for v in ts)


# ---- verifyAnchor ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def anchor_scenarios() -> list[dict[str, Any]]:
    return harness({"action": "anchor-scenarios"})["cases"]


def _trust_supplied(case: Mapping[str, Any]) -> bool:
    o = case.get("options") or {}
    return bool(o.get("trustAnchorsPem") or o.get("authorities"))


def _in_pkijs_only_region(case: Mapping[str, Any], regions: list[tuple[int, int]]) -> bool:
    at = case.get("flipAt")
    return at is not None and any(start <= at < end for start, end in regions)


def test_every_anchor_scenario_gets_the_same_verdict(
    anchor_scenarios: list[dict[str, Any]],
) -> None:
    good = next(c for c in anchor_scenarios if c["name"] == "RFC 3161: no trust supplied")
    regions = pkijs_only_regions(good["artifacts"]["anchor"]["publications"][0]["token"])
    compared = [
        c
        for c in anchor_scenarios
        if not _trust_supplied(c) and not _in_pkijs_only_region(c, regions)
    ]
    diverged = [
        (c["name"], c["verdict"], p) for c in compared if (p := py_verify_anchor(c)) != c["verdict"]
    ]
    assert not diverged, f"{len(diverged)} of {len(compared)} differ; first: {diverged[0]!r}"
    outcomes = {(c["verdict"]["anchorValid"], c["verdict"].get("anchorReason")) for c in compared}
    assert (True, None) in outcomes
    assert (False, "malformed_publication") in outcomes
    assert (None, "publication_not_checked") in outcomes
    # The RFC 3161 corpus reaches both decisions: readable tokens and unreadable ones.
    tsa = [c for c in compared if c["name"].startswith("RFC 3161:")]
    readable = [c for c in tsa if c["verdict"]["publications"][0]["valid"] is None]
    assert len(readable) >= 5 and len(tsa) - len(readable) >= 20


def test_a_trust_anchor_that_cannot_be_read_is_refused_by_both(
    anchor_scenarios: list[dict[str, Any]],
) -> None:
    """Verification §3.1: a root the verifier cannot read is the auditor's input, refused in
    both SDKs with the same words, whatever the artifact holds."""
    good = next(c for c in anchor_scenarios if _trust_supplied(c))
    root = good["options"]["trustAnchorsPem"][0]
    cases = [
        {**good, "options": {**good["options"], "trustAnchorsPem": roots}}
        for roots in (["not a certificate"], [root, "not a certificate"], [7])
    ]
    cases.append({"artifacts": {}, "digest": "x", "options": {"trustAnchorsPem": ["not a certificate"]}})
    ts = harness({"action": "verify-anchor", "cases": cases})["verdicts"]
    for case, t in zip(cases, ts, strict=True):
        try:
            py_verify_anchor(case)
        except UnreadableTrustAnchorError as exc:
            py: Any = {"refused": str(exc)}
        else:
            py = "not refused"
        assert py == t
    assert [t["refused"] for t in ts] == [
        "trust anchor 1 holds no PEM CERTIFICATE block",
        "trust anchor 2 holds no PEM CERTIFICATE block",
        "trust anchor 1 is not a PEM string",
        "trust anchor 1 holds no PEM CERTIFICATE block",
    ]


_TSA_ENV = ("TZUN_TSA_TRUST_ANCHORS", "TZUN_TSA_AUTHORITIES")


def _py_verify_anchor_refusing(case: Mapping[str, Any]) -> Any:
    """``py_verify_anchor`` with the case's TSA trust environment, as the harness sets it
    (and, with none, as the harness runs: unset), and ``{"refused": message}`` for a
    configuration it refuses."""
    env = case.get("env") or {}
    saved = {name: os.environ.get(name) for name in _TSA_ENV}
    try:
        for name in _TSA_ENV:
            if isinstance(env.get(name), str):
                os.environ[name] = env[name]
            else:
                os.environ.pop(name, None)
        try:
            return py_verify_anchor(case)
        except UnreadableTrustAnchorError as exc:
            return {"refused": str(exc)}
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_the_trust_configuration_is_refused_by_both_in_the_same_words(tmp_path: pathlib.Path) -> None:
    """Verification §3.1: every source of RFC 3161 trust, the options and the environment,
    is read first and refused when it cannot be read, in both SDKs and in the same words
   : a ``TZUN_TSA_TRUST_ANCHORS`` file that cannot be read or whose root
    does not read, an authority the registry does not know, and inputs that are not
    lists. The options, when they name any trust, stand for the environment."""
    root = (REPO_ROOT / "src" / "attestation" / "certs" / "freetsa-ca.pem").read_text("utf-8")
    good = tmp_path / "root.pem"
    good.write_text(root, "utf-8")
    junk = tmp_path / "junk.pem"
    junk.write_text("not a certificate", "utf-8")
    missing = str(tmp_path / "missing.pem")
    bad_block = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"
    none: dict[str, Any] = {"artifacts": {}, "digest": "x", "options": {}}
    cases: list[dict[str, Any]] = [
        {**none, "env": {"TZUN_TSA_TRUST_ANCHORS": missing}},
        {**none, "env": {"TZUN_TSA_TRUST_ANCHORS": f"{good}{os.pathsep}{missing}"}},
        {**none, "env": {"TZUN_TSA_TRUST_ANCHORS": str(good)}},
        {**none, "env": {"TZUN_TSA_TRUST_ANCHORS": f" {good} {os.pathsep}{os.pathsep}"}},
        {**none, "env": {"TZUN_TSA_TRUST_ANCHORS": str(junk)}},
        {**none, "env": {"TZUN_TSA_TRUST_ANCHORS": f"{good}{os.pathsep}{junk}"}},
        {**none, "env": {"TZUN_TSA_TRUST_ANCHORS": root}},
        {**none, "env": {"TZUN_TSA_TRUST_ANCHORS": bad_block}},
        # White space alone is no configuration; ECMAScript's white space, not Python's.
        {**none, "env": {"TZUN_TSA_TRUST_ANCHORS": " \t\n"}},
        {**none, "env": {"TZUN_TSA_TRUST_ANCHORS": "\ufeff\u3000"}},
        {**none, "env": {"TZUN_TSA_TRUST_ANCHORS": "\x1c"}},
        {**none, "env": {"TZUN_TSA_AUTHORITIES": "no-such-authority"}},
        {**none, "env": {"TZUN_TSA_AUTHORITIES": " freetsa , https://FreeTSA.org/tsr/ ,, "}},
        {**none, "env": {"TZUN_TSA_TRUST_ANCHORS": str(good), "TZUN_TSA_AUTHORITIES": "sectigo,bogus"}},
        {**none, "options": {"trustAnchorsPem": [root]}, "env": {"TZUN_TSA_AUTHORITIES": "bogus", "TZUN_TSA_TRUST_ANCHORS": missing}},
        {**none, "options": {"trustAnchorsPem": [], "authorities": []}, "env": {"TZUN_TSA_AUTHORITIES": "bogus"}},
        {**none, "options": {"authorities": ["nope"]}},
        {**none, "options": {"authorities": "freetsa"}},
        {**none, "options": {"authorities": [42]}},
        {**none, "options": {"authorities": ["freetsa", "sectigo"]}},
        {**none, "options": {"trustAnchorsPem": "not a list"}},
        {**none, "options": {"trustAnchorsPem": [root], "authorities": ["nope"]}},
    ]
    ts = harness({"action": "verify-anchor", "cases": cases})["verdicts"]
    for i, (case, t) in enumerate(zip(cases, ts, strict=True)):
        assert (i, _py_verify_anchor_refusing(case)) == (i, t)
    unknown = (
        'the trust anchors cannot be read: Unknown timestamp authority "{}". Known keys: freetsa, sectigo, '
        "digicert, sslcom, globalsign, certum, identrust, apple, mesign, entrust, aimoda. Pass a registry "
        "key, or a URL exactly as registered, or supply the anchor yourself with trustAnchorsPem / "
        "TZUN_TSA_TRUST_ANCHORS."
    )
    assert [t.get("refused") for t in ts] == [
        f"TZUN_TSA_TRUST_ANCHORS: {missing} cannot be read",
        f"TZUN_TSA_TRUST_ANCHORS: {missing} cannot be read",
        None,
        None,
        "trust anchor 1 holds no PEM CERTIFICATE block",
        "trust anchor 2 holds no PEM CERTIFICATE block",
        None,
        "trust anchor 1 is not base64",
        None,
        None,
        "TZUN_TSA_TRUST_ANCHORS: \x1c cannot be read",
        unknown.format("no-such-authority"),
        None,
        unknown.format("bogus"),
        None,
        unknown.format("bogus"),
        unknown.format("nope"),
        "the authorities are not a list of names",
        "the authorities are not a list of names",
        None,
        "the trust anchors are not a list of PEM strings",
        unknown.format("nope"),
    ]


#: Authority selectors: each registry key and URL, and spellings of them the WHATWG URL
#: parser reads as the same URL or as another.
AUTHORITY_SELECTORS: list[str] = [
    "freetsa",
    "FREETSA",
    " freetsa",
    "",
    "https://freetsa.org/tsr",
    "https://freetsa.org/tsr/",
    "https://freetsa.org/tsr//",
    "HTTPS://FREETSA.ORG/tsr",
    "https://freetsa.org/TSR",
    "http://freetsa.org/tsr",
    "https://freetsa.org:443/tsr",
    "https://freetsa.org:0443/tsr",
    "https://freetsa.org:/tsr",
    "https://freetsa.org:8443/tsr",
    "https://freetsa.org:443x/tsr",
    "https://user:pw@" "freetsa.org/tsr",
    "https://@freetsa.org/tsr",
    "https:freetsa.org/tsr",
    "https:///freetsa.org/tsr",
    "https:\\\\freetsa.org\\tsr",
    "https://freetsa.org/./tsr",
    "https://freetsa.org/x/../tsr",
    "https://freetsa.org/x/%2E%2e/tsr",
    "https://freetsa.org/tsr/.",
    "https://freetsa.org/tsr?",
    "https://freetsa.org/tsr?x=1",
    "https://freetsa.org/tsr#frag",
    "https://fr%65etsa.org/tsr",
    "https://freetsa.org/ts%72",
    " \thttps://freetsa.org/tsr\n ",
    "https://free\ttsa.org/t\nsr",
    "https://\uff46\uff52\uff45\uff45\uff54\uff53\uff41.org/tsr",
    "https://freetsa\u3002org/tsr",
    "https://freetsa\uff0eorg/tsr",
    "https://free\u00adtsa.org/tsr",
    "https://free\u200btsa.org/tsr",
    "https://freetsa\u2024org/tsr",
    "https://freetsa.org./tsr",
    "https://[::1]/tsr",
    "https://freetsa.org\ud800/tsr",
    "freetsa.org/tsr",
    "https://timestamp.sectigo.com",
    "https://timestamp.sectigo.com/",
    "https://timestamp.sectigo.com/.",
    "https://timestamp.sectigo.com/a/..",
    "https://timestamp.sectigo.com?",
    "http://timestamp.digicert.com:80/",
    "http://timestamp.digicert.com:443/",
    "http://ts.ssl.com",
    "http://ts.\u1e9el.com",
    "http://TS.SSL.COM:80",
    "http://timestamp.globalsign.com/tsa/r6advanced1",
    "http://timestamp.globalsign.com/TSA/R6ADVANCED1",
    "http://time.certum.pl",
    "http://timestamp.identrust.com",
    "http://timestamp.apple.com/ts01",
    "http://timestamp.apple.com/ts01/../ts01",
    "http://tsa.mesign.com",
    "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
    "http://timestamp.entrust.net/tss/rfc3161sha2ts",
    "http://rfc3161.ai.moda",
    "http://rfc316\u2488ai.moda",
    "http://rfc3161\uff0eai.moda",
    "sectigo",
    "digicert",
    "sslcom",
    "globalsign",
    "certum",
    "identrust",
    "apple",
    "mesign",
    "entrust",
    "aimoda",
]


def test_an_authority_is_known_to_both_by_the_same_spellings() -> None:
    """An authority is named by its registry key or by its URL as the TypeScript registry
    compares one (``getTimestampAuthority``): the same spellings name one in both SDKs,
    and every other is refused in the same words."""
    cases = [{"artifacts": {}, "digest": "x", "options": {"authorities": [s]}} for s in AUTHORITY_SELECTORS]
    ts = harness({"action": "verify-anchor", "cases": cases})["verdicts"]
    for selector, case, t in zip(AUTHORITY_SELECTORS, cases, ts, strict=True):
        assert (selector, _py_verify_anchor_refusing(case)) == (selector, t)
    known = [s for s, t in zip(AUTHORITY_SELECTORS, ts, strict=True) if "refused" not in t]
    assert len(known) >= 50 and len(AUTHORITY_SELECTORS) - len(known) >= 15
    assert "https://\uff46\uff52\uff45\uff45\uff54\uff53\uff41.org/tsr" in known
    assert "http://ts.\u1e9el.com" in known
    assert "http://rfc316\u2488ai.moda" not in known


def test_inside_certificates_and_signer_infos_python_never_refuses_what_typescript_reads(
    anchor_scenarios: list[dict[str, Any]],
) -> None:
    """A corruption pkijs's X.509 or SignerInfo schema refuses is not refused by the
    Python reader (``_rfc3161_token``'s docstring). Either the verdicts are equal,
    or the TypeScript verdict is ``malformed_publication`` and the Python one
    ``publication_not_checked``; never the reverse."""
    good = next(c for c in anchor_scenarios if c["name"] == "RFC 3161: no trust supplied")
    regions = pkijs_only_regions(good["artifacts"]["anchor"]["publications"][0]["token"])
    cases = [c for c in anchor_scenarios if _in_pkijs_only_region(c, regions)]
    assert len(cases) > 100
    equal = 0
    for case in cases:
        py = py_verify_anchor(case)
        if py == case["verdict"]:
            equal += 1
            continue
        assert (case["verdict"]["anchorReason"], py["anchorReason"]) == (
            "malformed_publication",
            "publication_not_checked",
        ), case["name"]
        assert py["publications"][0]["checks"][2]["reason"] == "no_matching_trust_anchor", case[
            "name"
        ]
    assert equal > len(cases) // 2


def test_with_trust_anchors_supplied_python_reports_missing_dependency(
    anchor_scenarios: list[dict[str, Any]],
) -> None:
    cases = [c for c in anchor_scenarios if _trust_supplied(c)]
    assert cases
    for case in cases:
        py = py_verify_anchor(case)
        ts_pub = case["verdict"]["publications"][0]
        py_pub = py["publications"][0]
        if ts_pub.get("reason") == "malformed_publication":
            # An unreadable token is refused the same way on both sides.
            assert py == case["verdict"], case["name"]
            continue
        assert py["anchorValid"] is None and py["anchorReason"] == "publication_not_checked", case[
            "name"
        ]
        assert py_pub["checks"] == [
            {"id": "anchor.publication[0]", "outcome": "checked-correct", "value": True},
            {
                "id": "anchor.tsa.token[0]",
                "outcome": "not-checked",
                "value": None,
                "reason": "missing_dependency",
            },
            {
                "id": "anchor.tsa.trust[0]",
                "outcome": "not-checked",
                "value": None,
                "reason": "blocked_by:anchor.tsa.token[0]",
            },
        ], case["name"]
        # Steps 1 and 2 agree whatever the publication (checks[0] is `anchor`).
        assert py["checks"][1:3] == case["verdict"]["checks"][1:3]
        assert py["merkleProofValid"] == case["verdict"]["merkleProofValid"]


def _hostile_anchor_cases() -> list[dict[str, Any]]:
    record = E2E["records"][0]
    anchor = record["envelope"]["nonRepudiation"]["anchor"]
    digest = record["envelope"]["integrity"]["canonicalDigest"]
    options = {
        "sequenceNumber": record["envelope"]["payload"]["sequenceNumber"],
        "chainId": record["chainId"],
    }
    cases: list[dict[str, Any]] = []
    for artifacts in (
        None,
        "anchor",
        [anchor],
        7,
        True,
        {},
        {"anchor": None},
        {"anchor": []},
        {"anchor": 7},
    ):
        cases.append({"artifacts": artifacts, "digest": digest, "options": options})
    for key in list(anchor):
        for value in (
            None,
            0,
            -1,
            1.5,
            "",
            [],
            {},
            True,
            "x",
            [None],
            ["ab" * 32],
            2**53,
            "ab" * 32,
        ):
            mutated = dict(anchor)
            mutated[key] = value
            cases.append({"artifacts": {"anchor": mutated}, "digest": digest, "options": options})
        missing = {k: v for k, v in anchor.items() if k != key}
        cases.append({"artifacts": {"anchor": missing}, "digest": digest, "options": options})
    for digest_value in (None, 7, "", digest.upper(), "0x" + digest, digest[:-1]):
        cases.append({"artifacts": {"anchor": anchor}, "digest": digest_value, "options": options})
    for opts in (
        {},
        {"sequenceNumber": 0},
        {"sequenceNumber": True},
        {"sequenceNumber": 1.0},
        {"chainId": 7},
        {"chainId": ""},
    ):
        cases.append({"artifacts": {"anchor": anchor}, "digest": digest, "options": opts})
    return cases


def _with_status(token: str, status: bytes) -> str:
    """``token`` (a granted TimeStampResp, base64) with its PKIStatus INTEGER holding ``status``."""
    der = base64.b64decode(token)
    header = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
    body = der[header:]
    granted = bytes.fromhex("3003020100")
    assert body.startswith(granted)
    return base64.b64encode(
        _der(0x30, _der(0x30, _der(0x02, status)) + body[len(granted) :])
    ).decode()


def test_the_status_at_every_width_gets_the_same_verdict(
    anchor_scenarios: list[dict[str, Any]],
) -> None:
    """asn1js reads a PKIStatus INTEGER of four or more bytes as 0, so the TypeScript
    reader takes such a status, whatever its value, as granted. The
    Python reader reads it the same way."""
    good = next(c for c in anchor_scenarios if c["name"] == "RFC 3161: no trust supplied")
    token = good["artifacts"]["anchor"]["publications"][0]["token"]
    cases = []
    for width in range(1, 10):
        for value in (0, 1, 2, 3, 5, -1):
            case = copy.deepcopy(good)
            publication = case["artifacts"]["anchor"]["publications"][0]
            publication["token"] = _with_status(token, value.to_bytes(width, "big", signed=True))
            cases.append({"width": width, "value": value, **case})
    ts = harness({"action": "verify-anchor", "cases": cases})["verdicts"]
    py = [py_verify_anchor(c) for c in cases]
    diverged = [
        (c["width"], c["value"], t["anchorReason"], p["anchorReason"])
        for c, t, p in zip(cases, ts, py, strict=True)
        if p != t
    ]
    assert not diverged, f"{len(diverged)} of {len(cases)} differ; first: {diverged[0]!r}"
    readable = [
        (c["width"], c["value"])
        for c, t in zip(cases, ts, strict=True)
        if t["publications"][0]["valid"] is None
    ]
    assert readable == [
        (c["width"], c["value"]) for c in cases if c["width"] >= 4 or c["value"] in (0, 1)
    ]


def _proto_case(anchor_scenarios: list[dict[str, Any]], variant: str) -> dict[str, Any]:
    """'EVM: true' with an envelope publication that carries a ``__proto__`` member."""
    case = copy.deepcopy(next(c for c in anchor_scenarios if c["name"] == "EVM: true"))
    publication = case["artifacts"]["anchor"]["publications"][0]
    (material,) = case["options"]["publicationMaterial"]
    moved = {k: material.pop(k) for k in ("blockHeader", "txIndex", "txProof")}
    if variant == "joins, a false header in __proto__":
        publication["__proto__"] = {"blockHeader": "0x00"}
    elif variant == "joins, the real header and proof in __proto__":
        publication["__proto__"] = moved
    elif variant == "joins, nothing in __proto__ the material lacks":
        material.update(moved)
        publication["__proto__"] = {"blockHeader": "0x00"}
    else:
        assert variant == "no material joins"
        case["options"]["publicationMaterial"] = None
        publication["__proto__"] = {"rawTransaction": material["rawTransaction"], **moved}
    return case


@pytest.mark.parametrize(
    "variant",
    [
        "joins, a false header in __proto__",
        "joins, the real header and proof in __proto__",
        "joins, nothing in __proto__ the material lacks",
        "no material joins",
    ],
)
def test_a_proto_member_is_an_ordinary_key(
    anchor_scenarios: list[dict[str, Any]], variant: str
) -> None:
    case = _proto_case(anchor_scenarios, variant)
    (ts,) = harness({"action": "verify-anchor", "cases": [case]})["verdicts"]
    assert py_verify_anchor(case) == ts


def test_hostile_artifacts_get_the_same_verdict() -> None:
    cases = _hostile_anchor_cases()
    ts = harness({"action": "verify-anchor", "cases": cases})["verdicts"]
    diverged = [
        (c, t, p) for c, t in zip(cases, ts, strict=True) if (p := py_verify_anchor(c)) != t
    ]
    assert not diverged, f"{len(diverged)} of {len(cases)} differ; first: {diverged[0]!r}"


def test_the_vector_files_get_the_same_whole_verdicts() -> None:
    cases: list[dict[str, Any]] = [
        {
            "artifacts": v["artifacts"],
            "digest": v["digest"],
            "options": {
                **(
                    {"sequenceNumber": v["sequenceNumber"]}
                    if v["sequenceNumber"] is not None
                    else {}
                ),
                **({"chainId": v["chainId"]} if v["chainId"] is not None else {}),
            },
        }
        for v in CHECKPOINTS["artifacts"]
    ]
    source = {
        "chainId": str(E2E["headerSource"]["chainId"]),
        "finalized": E2E["headerSource"]["finalizedBlockNumber"],
        "finality": E2E["headerSource"]["finality"],
        "blocks": {
            str(e["canonicalBlock"]["number"]): {
                "hash": e["canonicalBlock"]["hash"],
                "timestamp": e["canonicalBlock"]["timestamp"],
            }
            for e in E2E["epochs"]
        },
    }
    for record in E2E["records"]:
        envelope = record["envelope"]
        base_options = {
            "sequenceNumber": envelope["payload"]["sequenceNumber"],
            "chainId": record["chainId"],
            "publisherManifest": E2E["manifest"],
            "publicationMaterial": [E2E["epochs"][record["epoch"]]["publication"]],
        }
        digest = envelope["integrity"]["canonicalDigest"]
        cases.append(
            {"artifacts": envelope["nonRepudiation"], "digest": digest, "options": base_options}
        )
        cases.append(
            {
                "artifacts": envelope["nonRepudiation"],
                "digest": digest,
                "options": {**base_options, "evmHeaderSources": {E2E["chain"]: source}},
            }
        )
    ts = harness({"action": "verify-anchor", "cases": cases})["verdicts"]
    diverged = [
        (c, t, p) for c, t in zip(cases, ts, strict=True) if (p := py_verify_anchor(c)) != t
    ]
    assert not diverged, f"{len(diverged)} of {len(cases)} differ; first: {diverged[0]!r}"
    assert sum(1 for t in ts if t["anchorValid"] is True) == len(E2E["records"])
