"""Signed EVM transactions as the anchor verifier reads them (tzun-anchor/1 §10.4 item 2).

The decoder must accept and refuse what the TypeScript SDK's
``decodeEvmTransaction`` accepts and refuses, and recover the same sender, for
the three types the verifier reads: legacy (pre-EIP-155 and EIP-155), EIP-2930
and EIP-1559. That is item 2's rules that no transaction a block holds can break
(``TestItemTwo``), then the fields' shapes as ethers v6 ``Transaction.from(raw)``
reads them. Real transactions pin it here: the EIP-155 specification's example,
two Sepolia blocks (``tests/ts/fixtures``) and the anvil vectors. Mutations
signed by ethers itself are compared across the SDKs in
``tests/cross-sdk/test_anchor_verify_parity.py``, and
``vectors/evm-anchor-vectors.json`` states a verdict for item 2's edges.
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


def legacy(
    *,
    chain_id: int = 0,
    v_override: int | None = None,
    nonce: int = 0,
    eip155: bool | None = None,
) -> bytes:
    """A legacy transaction KEY signs: EIP-155 for ``chain_id`` (when ``eip155``, which
    defaults to ``chain_id != 0``, so ``eip155=True`` with chain id 0 signs ``v`` 35
    or 36), unprotected otherwise."""
    protected = chain_id != 0 if eip155 is None else eip155
    body: list = [ib(nonce), ib(2_000_000_000), ib(30_000), TO, b"", P]  # type: ignore[type-arg]
    unsigned = body + ([ib(chain_id), b"", b""] if protected else [])
    y, r, s = sign(encode_rlp(unsigned))
    v = (chain_id * 2 + 35 + y) if protected else 27 + y
    return encode_rlp([*body, ib(v_override if v_override is not None else v), ib(r), ib(s)])


def legacy_v(raw: bytes) -> int:
    return int.from_bytes(decode_rlp(raw)[6], "big")  # type: ignore[index, arg-type]


def legacy_with_parity(y_parity: int, **kwargs: object) -> bytes:
    """``legacy(**kwargs)`` at the first nonce whose signature has this parity: v 27,
    or odd from 35, is parity 0; v 28, or even from 36, is parity 1."""
    for nonce in range(64):
        raw = legacy(nonce=nonce, **kwargs)  # type: ignore[arg-type]
        v = legacy_v(raw)
        if (v - 27 if v in (27, 28) else (v - 35) % 2) == y_parity:
            return raw
    raise AssertionError("no nonce below 64 gives this parity")


def type1(*, chain_id: int = 1) -> bytes:
    body: list = [ib(chain_id), ib(5), ib(2_000_000_000), ib(30_000), TO, b"", P, []]  # type: ignore[type-arg]
    y, r, s = sign(b"\x01" + encode_rlp(body))
    return b"\x01" + encode_rlp([*body, ib(y), ib(r), ib(s)])


# ---- Signatures at the edges of item 2 ---------------------------------------------

#: The field prime of secp256k1.
SECP256K1_P = 2**256 - 2**32 - 977
HALF_N = SECP256K1_N // 2


def is_x_coordinate(x: int) -> bool:
    """Whether some point of secp256k1 has this x: x^3 + 7 is a square mod p."""
    return pow((x**3 + 7) % SECP256K1_P, (SECP256K1_P - 1) // 2, SECP256K1_P) == 1


def address_recovered(digest: bytes, r: int, s: int, y_parity: int) -> str:
    """The address libsecp256k1 recovers from (r, s, yParity) over ``digest``."""
    from coincurve import PublicKey

    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([y_parity])
    point = PublicKey.from_signature_and_message(sig, digest, hasher=None)
    return "0x" + keccak256(point.format(compressed=False)[1:])[12:].hex()


def first_recoverable_r(digest: bytes, s: int, y_parity: int) -> tuple[int, str]:
    """The smallest r from which a public key recovers with this s and parity, and
    the address it recovers: a signature no key was asked to make, but a valid one."""
    r = next(x for x in range(1, 1_000) if is_x_coordinate(x))
    return r, address_recovered(digest, r, s, y_parity)


def type2_body() -> list:  # type: ignore[type-arg]
    """An EIP-1559 transaction's unsigned fields, on chain id 1."""
    return [ib(1), ib(0), ib(1), ib(2), ib(30_000), TO, b"", P, []]


def with_signature(body: list, y_parity: int, r: int, s: int) -> bytes:  # type: ignore[type-arg]
    """The EIP-1559 ``body`` carrying this signature, which no key need have made."""
    return b"\x02" + encode_rlp([*body, ib(y_parity), ib(r), ib(s)])


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

    def test_a_high_s_signature_is_refused(self) -> None:
        # n - s with the other parity names the same public key, and ethers
        # recovers it; tzun-anchor/1 §10.4 item 2 refuses s above n/2 (EIP-2).
        def high_s(fields: list) -> list:  # type: ignore[type-arg]
            y = int.from_bytes(fields[9], "big")
            s = int.from_bytes(fields[11], "big")
            return [*fields[:9], ib(y ^ 1), fields[10], ib(SECP256K1_N - s)]

        with pytest.raises(EvmTransactionError, match="above n/2"):
            decode_signed_transaction(type2(tamper=high_s))

    def test_a_non_canonical_field_is_read_by_value(self) -> None:
        # ethers reads a leading zero byte as the same number, and recovers the
        # sender over the canonical re-encoding, as the SDKs' reference does.
        def padded_nonce(fields: list) -> list:  # type: ignore[type-arg]
            return [fields[0], b"\x00", *fields[2:]]

        tx = decode_signed_transaction(type2(tamper=padded_nonce))
        assert tx.sender == KEY_ADDRESS


class TestItemTwo:
    """tzun-anchor/1 §10.4 item 2: what no transaction a block on any chain holds
    can carry is refused, whatever an Ethereum library would recover from it."""

    # A typed transaction signs a chain id of 1 or more.

    @pytest.mark.parametrize("chain_id", [0, 1])
    def test_a_typed_transaction_on_chain_id_0_is_refused_and_1_is_read(
        self, chain_id: int
    ) -> None:
        for raw in (type2(chain_id=chain_id), type1(chain_id=chain_id)):
            if chain_id == 0:
                with pytest.raises(EvmTransactionError, match="chain id 0"):
                    decode_signed_transaction(raw)
            else:
                tx = decode_signed_transaction(raw)
                assert (tx.chain_id, tx.sender) == (1, KEY_ADDRESS)

    # A legacy v is 27, 28, or chainId * 2 + 35 or + 36 for a chain id of 1 or more.

    @pytest.mark.parametrize("y_parity", [0, 1])
    def test_legacy_v_35_and_36_sign_chain_id_0_and_are_refused(self, y_parity: int) -> None:
        raw = legacy_with_parity(y_parity, chain_id=0, eip155=True)
        assert legacy_v(raw) == 35 + y_parity
        with pytest.raises(EvmTransactionError, match="legacy v"):
            decode_signed_transaction(raw)

    @pytest.mark.parametrize("y_parity", [0, 1])
    def test_legacy_v_37_and_38_sign_chain_id_1(self, y_parity: int) -> None:
        raw = legacy_with_parity(y_parity, chain_id=1)
        assert legacy_v(raw) == 37 + y_parity
        tx = decode_signed_transaction(raw)
        assert (tx.chain_id, tx.sender) == (1, KEY_ADDRESS)

    @pytest.mark.parametrize("y_parity", [0, 1])
    def test_legacy_v_27_and_28_are_read_with_chain_id_0(self, y_parity: int) -> None:
        raw = legacy_with_parity(y_parity)
        assert legacy_v(raw) == 27 + y_parity
        tx = decode_signed_transaction(raw)
        assert (tx.chain_id, tx.sender) == (0, KEY_ADDRESS)

    @pytest.mark.parametrize("v", [0, 1, 26, 29, 30, 34])
    def test_any_other_legacy_v_below_37_is_refused(self, v: int) -> None:
        with pytest.raises(EvmTransactionError):
            decode_signed_transaction(legacy(v_override=v))

    # r in [1, n - 1], s in [1, n/2], yParity 0 or 1.

    def test_s_exactly_n_over_2_is_read_and_one_more_is_refused(self) -> None:
        body = type2_body()
        digest = keccak256(b"\x02" + encode_rlp(body))
        r, sender = first_recoverable_r(digest, HALF_N, 0)
        tx = decode_signed_transaction(with_signature(body, 0, r, HALF_N))
        assert tx.sender == sender
        # n - (n/2 + 1) = n/2: with the other parity it names the same key, which
        # a library that reads a high s as n - s recovers.
        assert address_recovered(digest, r, HALF_N + 1, 1) == sender
        with pytest.raises(EvmTransactionError, match="above n/2"):
            decode_signed_transaction(with_signature(body, 1, r, HALF_N + 1))

    def test_s_of_1_is_read(self) -> None:
        body = type2_body()
        digest = keccak256(b"\x02" + encode_rlp(body))
        r, sender = first_recoverable_r(digest, 1, 0)
        assert decode_signed_transaction(with_signature(body, 0, r, 1)).sender == sender

    def test_a_legacy_high_s_is_refused(self) -> None:
        fields = decode_rlp(legacy(chain_id=1))
        assert isinstance(fields, list)
        v = int.from_bytes(fields[6], "big")  # type: ignore[arg-type]
        s = int.from_bytes(fields[8], "big")  # type: ignore[arg-type]
        high = encode_rlp([*fields[:6], ib(75 - v), fields[7], ib(SECP256K1_N - s)])
        with pytest.raises(EvmTransactionError, match="above n/2"):
            decode_signed_transaction(high)

    @pytest.mark.parametrize(
        ("r", "s"),
        [(0, 1), (1, 0), (SECP256K1_N, 1), (1, SECP256K1_N), (SECP256K1_N - 1, HALF_N + 1)],
        ids=["r = 0", "s = 0", "r = n", "s = n", "r = n - 1, s = n/2 + 1"],
    )
    def test_r_or_s_out_of_range_is_refused(self, r: int, s: int) -> None:
        with pytest.raises(EvmTransactionError, match="out of range"):
            decode_signed_transaction(with_signature(type2_body(), 0, r, s))

    @pytest.mark.parametrize("y_parity", [2, 27, 28])
    def test_a_typed_y_parity_other_than_0_or_1_is_refused(self, y_parity: int) -> None:
        with pytest.raises(EvmTransactionError, match="yParity"):
            decode_signed_transaction(type2(tamper=_with(9, ib(y_parity))))

    # An EIP-1559 tip is at most its fee cap.

    def test_a_tip_equal_to_the_fee_cap_is_read_and_one_wei_more_is_refused(self) -> None:
        assert decode_signed_transaction(type2(fee=7, tip=7)).sender == KEY_ADDRESS
        with pytest.raises(EvmTransactionError, match="priorityFee"):
            decode_signed_transaction(type2(fee=7, tip=8))

    # A public key recovers from the signature.

    def test_an_r_that_is_no_points_x_coordinate_is_refused(self) -> None:
        r = next(x for x in range(1, 1_000) if not is_x_coordinate(x))
        with pytest.raises(EvmTransactionError, match="no public key"):
            decode_signed_transaction(with_signature(type2_body(), 0, r, 1))

    def test_a_signature_that_recovers_the_point_at_infinity_is_refused(self) -> None:
        # With R = (z / s) G, r = x(R): r^-1 (s R - z G) is the point at infinity.
        body = type2_body()
        z = int.from_bytes(keccak256(b"\x02" + encode_rlp(body)), "big") % SECP256K1_N
        s = 1
        k = z * pow(s, -1, SECP256K1_N) % SECP256K1_N
        point = PrivateKey(k.to_bytes(32, "big")).public_key.format(compressed=False)
        r = int.from_bytes(point[1:33], "big")
        y_parity = point[64] & 1
        assert 1 <= r < SECP256K1_N
        with pytest.raises(EvmTransactionError, match="no public key"):
            decode_signed_transaction(with_signature(body, y_parity, r, s))


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
