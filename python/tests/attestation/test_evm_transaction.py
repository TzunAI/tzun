"""Signed EVM transactions as the anchor verifier reads them (tzun-anchor/1 §10.4 item 2).

The decoder must accept and refuse what ethers v6 ``Transaction.from(raw)``
accepts and refuses, and recover the same sender, for the three types the
verifier reads: legacy (pre-EIP-155 and EIP-155), EIP-2930 and EIP-1559. Real
transactions pin it here: the EIP-155 specification's example, two Sepolia
blocks (``tests/ts/fixtures``) and the anvil vectors. Mutations signed by ethers
itself are compared across the SDKs in
``tests/cross-sdk/test_anchor_verify_parity.py``.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from ._anchor_extra import require_anchor_extra

require_anchor_extra()

from coincurve import PrivateKey  # noqa: E402

from tzun_sdk.attestation.evm_rlp import decode_rlp, encode_rlp  # noqa: E402
from tzun_sdk.attestation.evm_transaction import (  # noqa: E402
    SECP256K1_N,
    EvmTransactionError,
    SignedEvmTransaction,
    decode_signed_transaction,
    keccak256,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
FIXTURES = REPO_ROOT / "tests" / "ts" / "fixtures"


def _load(name: str) -> dict:  # type: ignore[type-arg]
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def h(text: str) -> bytes:
    return bytes.fromhex(text.removeprefix("0x"))


def ib(n: int) -> bytes:
    return b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")


KEY = PrivateKey(bytes.fromhex("46" * 32))
KEY_ADDRESS = "0x" + keccak256(KEY.public_key.format(compressed=False)[1:])[12:].hex()


def sign(unsigned: bytes) -> tuple[int, int, int]:
    """(yParity, r, s) of KEY over keccak256(unsigned)."""
    sig = KEY.sign_recoverable(keccak256(unsigned), hasher=None)
    return sig[64], int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")


P = bytes.fromhex("f8525911c336d6cf32369e465f18c8f92b8a911c7d44782079ee70cc6322b8db")
TO = bytes.fromhex("35" * 20)


def type2(
    *,
    chain_id: int = 11155111,
    fee: int = 3_000_000_000,
    tip: int = 1_000_000_000,
    access: list | None = None,  # type: ignore[type-arg]
    tamper: object = None,
) -> bytes:
    body: list = [ib(chain_id), ib(0), ib(tip), ib(fee), ib(30_000), TO, b"", P, access or []]  # type: ignore[type-arg]
    y, r, s = sign(b"\x02" + encode_rlp(body))
    signed = [*body, ib(y), ib(r), ib(s)]
    if callable(tamper):
        signed = tamper(signed)
    return b"\x02" + encode_rlp(signed)


def legacy(*, chain_id: int = 0, v_override: int | None = None) -> bytes:
    body: list = [ib(0), ib(2_000_000_000), ib(30_000), TO, b"", P]  # type: ignore[type-arg]
    unsigned = body + ([ib(chain_id), b"", b""] if chain_id else [])
    y, r, s = sign(encode_rlp(unsigned))
    v = (chain_id * 2 + 35 + y) if chain_id else 27 + y
    return encode_rlp([*body, ib(v_override if v_override is not None else v), ib(r), ib(s)])


class TestRealTransactions:
    def test_the_eip155_specification_example(self) -> None:
        raw = h(
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7640000"  # pragma: allowlist secret
            "8025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f"  # pragma: allowlist secret
            "761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"  # pragma: allowlist secret
        )
        tx = decode_signed_transaction(raw)
        assert tx == SignedEvmTransaction(
            type=0, chain_id=1, data=b"", sender="0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"
        )

    @pytest.mark.parametrize("fixture", ["evm-sepolia-block.json", "evm-sepolia-self-tx.json"])
    def test_sepolia_transactions(self, fixture: str) -> None:
        block = _load(fixture)
        for t in block["transactions"]:
            tx = decode_signed_transaction(h(t["raw"]))
            assert tx.type == t["type"]
            assert tx.chain_id == int(block["chainId"])
            assert tx.sender == t["sender"].lower()

    def test_the_anvil_vectors(self) -> None:
        vectors = json.loads(
            (REPO_ROOT / "vectors" / "anchor-e2e-vectors.json").read_text(encoding="utf-8")
        )
        for epoch in vectors["epochs"]:
            pub = epoch["publication"]
            tx = decode_signed_transaction(h(pub["rawTransaction"]))
            assert tx.sender == pub["publisher"]
            assert tx.chain_id == 31337
            assert tx.data == h(epoch["p"])
            assert "0x" + keccak256(h(pub["rawTransaction"])).hex() == pub["transactionId"]


class TestSignedHere:
    def test_eip1559(self) -> None:
        tx = decode_signed_transaction(type2())
        assert tx == SignedEvmTransaction(type=2, chain_id=11155111, data=P, sender=KEY_ADDRESS)

    def test_eip1559_with_an_access_list(self) -> None:
        tx = decode_signed_transaction(
            type2(access=[[TO, [b"\x01" * 32, b"\x02" * 32]], [b"\x07" * 20, []]])
        )
        assert tx.sender == KEY_ADDRESS

    def test_eip2930(self) -> None:
        body: list = [ib(1), ib(5), ib(2_000_000_000), ib(30_000), TO, b"", P, []]  # type: ignore[type-arg]
        y, r, s = sign(b"\x01" + encode_rlp(body))
        tx = decode_signed_transaction(b"\x01" + encode_rlp([*body, ib(y), ib(r), ib(s)]))
        assert tx == SignedEvmTransaction(type=1, chain_id=1, data=P, sender=KEY_ADDRESS)

    def test_legacy_pre_eip155_signs_chain_id_zero(self) -> None:
        tx = decode_signed_transaction(legacy())
        assert tx == SignedEvmTransaction(type=0, chain_id=0, data=P, sender=KEY_ADDRESS)

    def test_legacy_eip155(self) -> None:
        tx = decode_signed_transaction(legacy(chain_id=11155111))
        assert (tx.chain_id, tx.sender) == (11155111, KEY_ADDRESS)

    def test_a_high_s_signature_recovers_the_same_sender(self) -> None:
        def high_s(fields: list) -> list:  # type: ignore[type-arg]
            y = int.from_bytes(fields[9], "big")
            s = int.from_bytes(fields[11], "big")
            return [*fields[:9], ib(y ^ 1), fields[10], ib(SECP256K1_N - s)]

        assert decode_signed_transaction(type2(tamper=high_s)).sender == KEY_ADDRESS

    def test_a_non_canonical_field_is_read_by_value(self) -> None:
        # ethers reads a leading zero byte as the same number, and recovers the
        # sender over the canonical re-encoding, as the SDKs' reference does.
        def padded_nonce(fields: list) -> list:  # type: ignore[type-arg]
            return [fields[0], b"\x00", *fields[2:]]

        tx = decode_signed_transaction(type2(tamper=padded_nonce))
        assert tx.sender == KEY_ADDRESS


def _with(index: int, value: object):  # type: ignore[no-untyped-def]
    def tamper(fields: list) -> list:  # type: ignore[type-arg]
        out = list(fields)
        out[index] = value
        return out

    return tamper


@pytest.mark.parametrize(
    ("name", "raw"),
    [
        ("an empty typed payload", b"\x02"),
        ("a typed payload that is a string", b"\x02" + encode_rlp(b"abc")),
        ("unsigned (9 fields)", b"\x02" + encode_rlp(decode_rlp(type2()[1:])[:9])),  # type: ignore[index]
        ("10 fields", b"\x02" + encode_rlp(decode_rlp(type2()[1:])[:10])),  # type: ignore[index]
        ("yParity 2", type2(tamper=_with(9, b"\x02"))),
        ("yParity as a list", type2(tamper=_with(9, []))),
        ("r of 33 bytes", type2(tamper=_with(10, b"\x00" + b"\x01" * 32))),
        ("r = 0", type2(tamper=_with(10, b""))),
        ("r = n", type2(tamper=_with(10, SECP256K1_N.to_bytes(32, "big")))),
        ("s = n", type2(tamper=_with(11, SECP256K1_N.to_bytes(32, "big")))),
        ("s above n", type2(tamper=_with(11, b"\xff" * 32))),
        ("a tip above the fee cap", type2(fee=1, tip=2)),
        ("a nonce above 2^53 - 1", type2(tamper=_with(1, ib(2**53)))),
        ("a value above 2^256 - 1", type2(tamper=_with(6, b"\x01" + b"\x00" * 32))),
        ("a recipient of 19 bytes", type2(tamper=_with(5, b"\x35" * 19))),
        ("calldata as a list", type2(tamper=_with(7, []))),
        ("an access list that is a string", type2(tamper=_with(8, b"x"))),
        ("an access-list entry of three items", type2(tamper=_with(8, [[TO, [], b""]]))),
        ("an access-list address of 19 bytes", type2(tamper=_with(8, [[b"\x35" * 19, []]]))),
        ("an access-list key of 31 bytes", type2(tamper=_with(8, [[TO, [b"\x01" * 31]]]))),
        ("access-list keys as a string", type2(tamper=_with(8, [[TO, b"\x01" * 32]]))),
        ("legacy with 7 fields", encode_rlp(decode_rlp(legacy())[:7])),  # type: ignore[index]
        ("legacy unsigned (6 fields)", encode_rlp(decode_rlp(legacy())[:6])),  # type: ignore[index]
        ("legacy v = 0", legacy(v_override=0)),
        ("legacy v = 35", legacy(v_override=35)),
        ("legacy v = 36", legacy(v_override=36)),
        ("legacy r = s = 0", encode_rlp([*decode_rlp(legacy())[:7], b"", b""])),  # type: ignore[misc]
        ("type 3", b"\x03" + encode_rlp([])),
        ("trailing bytes", type2() + b"\x00"),
    ],
)
def test_refuses(name: str, raw: bytes) -> None:
    with pytest.raises(EvmTransactionError):
        decode_signed_transaction(raw)
