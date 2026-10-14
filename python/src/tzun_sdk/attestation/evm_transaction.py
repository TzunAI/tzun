# HAND-MAINTAINED. NOT generated.
#
# The TypeScript verifier reads a raw transaction with `decodeEvmTransaction`
# (src/attestation/blockchain.ts): first the rules of tzun-anchor/1 §10.4 item 2
# that no transaction a block holds can break, read from the RLP fields, then
# ethers v6 `Transaction.from(raw)` for the fields' shapes and `tx.from` for the
# sender. This module accepts and refuses the same raw transactions and recovers
# the same sender, for the three types the verifier reads: the item 2 rules as
# that function states them, and each field-shape rule as ethers applies it.
# tests/cross-sdk/test_anchor_verify_parity.py runs ethers-signed transactions,
# their mutations and signatures at the edges of item 2 through both SDKs.
"""Signed EVM transactions: keccak-256, decoding and sender recovery.

Needs the ``anchor`` extra (``pip install 'tzun-sdk[anchor]'``):

- ``coincurve``, Python bindings to libsecp256k1, the secp256k1 library of
  Bitcoin Core that go-ethereum also uses, for public-key recovery;
- ``pycryptodomex``, for Keccak-256 (Ethereum's hash is the original Keccak
  padding, not NIST SHA3-256, so :mod:`hashlib` cannot compute it). It installs
  as ``Cryptodome``, so it does not clash with a legacy ``pycrypto`` that owns
  the ``Crypto`` package.

Without them, :func:`keccak256` and :func:`decode_signed_transaction` raise
:class:`~tzun_sdk.errors.MissingExtraError`, and the anchor verifier reports an
``evm-calldata/1`` publication ``missing_dependency``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from tzun_sdk.attestation.evm_rlp import RlpError, RlpItem, decode_rlp, encode_rlp
from tzun_sdk.errors import MissingExtraError

#: The order of the secp256k1 group.
SECP256K1_N: Final = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
#: floor(n / 2): the largest ``s`` EIP-2 allows.
_HALF_N: Final = SECP256K1_N // 2
_MAX_UINT256: Final = 2**256 - 1
_MAX_SAFE_INTEGER: Final = 2**53 - 1

ANCHOR_EXTRA_HINT: Final = "pip install 'tzun-sdk[anchor]'"


class EvmTransactionError(ValueError):
    """The bytes are not a signed transaction this verifier reads."""


def _extra() -> tuple[Any, Any]:
    """The ``anchor`` extra's modules: ``Cryptodome.Hash.keccak`` and ``coincurve``."""
    try:
        import coincurve
        from Cryptodome.Hash import keccak
    except ImportError as exc:
        raise MissingExtraError(
            "EVM anchor verification (evm-calldata/1) requires the 'anchor' extra: "
            f"{ANCHOR_EXTRA_HINT}"
        ) from exc
    return keccak, coincurve


def anchor_extra_available() -> bool:
    """Whether the ``anchor`` extra's dependencies import."""
    try:
        _extra()
    except MissingExtraError:
        return False
    return True


def keccak256(data: bytes) -> bytes:
    """Keccak-256 of ``data``, 32 bytes.

    :raises MissingExtraError: without the ``anchor`` extra.
    """
    keccak, _ = _extra()
    return bytes(keccak.new(digest_bits=256, data=bytes(data)).digest())


@dataclass(frozen=True)
class SignedEvmTransaction:
    """What the verifier reads from a signed transaction."""

    #: 0 (legacy), 1 (EIP-2930) or 2 (EIP-1559).
    type: int
    #: The chain id the sender signed; 0 for an unprotected legacy transaction (``v`` 27 or 28).
    chain_id: int
    #: The calldata.
    data: bytes
    #: The recovered sender, ``0x`` and 40 lowercase hex digits.
    sender: str


# ---- Fields, read as ethers reads them --------------------------------------------
#
# What tzun-anchor/1 §10.4 item 2 refuses beyond the fields' shapes, because no
# block on any chain a manifest can name holds such a transaction:
#
# - a typed transaction signing chain id 0 (``_eip2930``, ``_eip1559``);
# - a legacy ``v`` other than 27, 28 or ``chainId * 2 + 35`` or ``+ 36`` for a
#   chain id of 1 or more, so ``v`` 35 and 36 (chain id 0) (``_legacy``);
# - ``r`` outside [1, n - 1], ``s`` outside [1, n/2] (EIP-2) (``_recover_sender``),
#   or a typed ``yParity`` other than 0 or 1 (``_y_parity``);
# - an EIP-1559 tip above its fee cap (``_eip1559``);
# - a signature from which no public key recovers (``_recover_sender``).


def _string(item: RlpItem) -> bytes:
    if not isinstance(item, bytes):
        raise EvmTransactionError("a field that must be a byte string is a list")
    return item


def _uint(item: RlpItem) -> int:
    """ethers ``handleUint``: any byte length, leading zeros read by value, at most 2^256 - 1."""
    value = int.from_bytes(_string(item), "big")
    if value > _MAX_UINT256:
        raise EvmTransactionError("value exceeds uint size")
    return value


def _number(item: RlpItem) -> int:
    """ethers ``handleNumber``: at most 2^53 - 1."""
    value = int.from_bytes(_string(item), "big")
    if value > _MAX_SAFE_INTEGER:
        raise EvmTransactionError("value exceeds a safe integer")
    return value


def _address(item: RlpItem) -> bytes:
    """ethers ``handleAddress``: empty for contract creation, otherwise exactly 20 bytes."""
    value = _string(item)
    if len(value) not in (0, 20):
        raise EvmTransactionError("invalid address")
    return value


def _padded_scalar(item: RlpItem) -> int:
    """ethers ``zeroPadValue(field, 32)``: at most 32 bytes."""
    value = _string(item)
    if len(value) > 32:
        raise EvmTransactionError("a signature scalar is longer than 32 bytes")
    return int.from_bytes(value, "big")


def _access_list(item: RlpItem) -> list[RlpItem]:
    """ethers ``accessListify``: a list of ``[20-byte address, [32-byte keys]]``."""
    if not isinstance(item, list):
        raise EvmTransactionError("invalid access list")
    out: list[RlpItem] = []
    for entry in item:
        if not isinstance(entry, list) or len(entry) != 2:
            raise EvmTransactionError("invalid access-list entry")
        address, keys = entry
        if not isinstance(address, bytes) or len(address) != 20:
            raise EvmTransactionError("invalid access-list address")
        if not isinstance(keys, list) or not all(
            isinstance(k, bytes) and len(k) == 32 for k in keys
        ):
            raise EvmTransactionError("invalid access-list storage key")
        out.append([address, list(keys)])
    return out


def _typed_chain_id(item: RlpItem) -> int:
    """A typed transaction's chain id: 1 or more, read as ethers ``handleUint`` reads it."""
    chain_id = _uint(item)
    if chain_id == 0:
        raise EvmTransactionError("a typed transaction signs chain id 0")
    return chain_id


def _y_parity(item: RlpItem) -> int:
    try:
        y = _number(item)
    except EvmTransactionError as exc:
        raise EvmTransactionError("invalid yParity") from exc
    if y not in (0, 1):
        raise EvmTransactionError("invalid yParity")
    return y


def _int_bytes(value: int) -> bytes:
    """ethers ``toBeArray``: big-endian with no leading zero, and 0 as no bytes."""
    return b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


# ---- Sender recovery ---------------------------------------------------------------


def _recover_sender(unsigned: bytes, r: int, s: int, y_parity: int) -> str:
    keccak_mod, coincurve = _extra()
    # A high s is refused, not read as n - s with the other parity.
    if not 1 <= r < SECP256K1_N:
        raise EvmTransactionError("signature r out of range")
    if not 1 <= s <= _HALF_N:
        raise EvmTransactionError("signature s out of range, or above n/2 (EIP-2)")
    digest = bytes(keccak_mod.new(digest_bits=256, data=unsigned).digest())
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([y_parity])
    try:
        public_key = coincurve.PublicKey.from_signature_and_message(signature, digest, hasher=None)
    except Exception as exc:
        raise EvmTransactionError("no public key recovers from this signature") from exc
    point = public_key.format(compressed=False)[1:]
    return "0x" + bytes(keccak_mod.new(digest_bits=256, data=point).digest())[12:].hex()


# ---- The three types ----------------------------------------------------------------


def _legacy(raw: bytes) -> SignedEvmTransaction:
    fields = decode_rlp(raw)
    if not isinstance(fields, list) or len(fields) not in (6, 9):
        raise EvmTransactionError("invalid field count for legacy transaction")
    nonce = _number(fields[0])
    gas_price = _uint(fields[1])
    gas_limit = _uint(fields[2])
    to = _address(fields[3])
    value = _uint(fields[4])
    data = _string(fields[5])
    if len(fields) == 6:
        raise EvmTransactionError("the transaction is not signed")
    v = _uint(fields[6])
    r = _uint(fields[7])
    s = _uint(fields[8])
    if r == 0 and s == 0:
        raise EvmTransactionError("the transaction is not signed (EIP-155 unsigned form)")
    if v not in (27, 28) and v < 37:
        raise EvmTransactionError(
            "legacy v is not 27, 28, or chainId * 2 + 35 or + 36 for a chain id of 1 or more"
        )
    chain_id = (v - 35) // 2 if v >= 37 else 0
    r = _padded_scalar(fields[7])
    s = _padded_scalar(fields[8])
    # 27 and odd EIP-155 values are parity 0; 28 and even ones are parity 1.
    y_parity = 0 if v == 27 or (v >= 35 and v % 2 == 1) else 1
    unsigned_fields: list[RlpItem] = [
        _int_bytes(nonce),
        _int_bytes(gas_price),
        _int_bytes(gas_limit),
        to,
        _int_bytes(value),
        data,
    ]
    if chain_id != 0:
        unsigned_fields += [_int_bytes(chain_id), b"", b""]
    sender = _recover_sender(encode_rlp(unsigned_fields), r, s, y_parity)
    return SignedEvmTransaction(type=0, chain_id=chain_id, data=data, sender=sender)


def _eip2930(raw: bytes) -> SignedEvmTransaction:
    fields = decode_rlp(raw[1:])
    if not isinstance(fields, list) or len(fields) not in (8, 11):
        raise EvmTransactionError("invalid field count for transaction type: 1")
    chain_id = _typed_chain_id(fields[0])
    nonce = _number(fields[1])
    gas_price = _uint(fields[2])
    gas_limit = _uint(fields[3])
    to = _address(fields[4])
    value = _uint(fields[5])
    data = _string(fields[6])
    access_list = _access_list(fields[7])
    if len(fields) == 8:
        raise EvmTransactionError("the transaction is not signed")
    y_parity = _y_parity(fields[8])
    r = _padded_scalar(fields[9])
    s = _padded_scalar(fields[10])
    unsigned = b"\x01" + encode_rlp(
        [
            _int_bytes(chain_id),
            _int_bytes(nonce),
            _int_bytes(gas_price),
            _int_bytes(gas_limit),
            to,
            _int_bytes(value),
            data,
            access_list,
        ]
    )
    sender = _recover_sender(unsigned, r, s, y_parity)
    return SignedEvmTransaction(type=1, chain_id=chain_id, data=data, sender=sender)


def _eip1559(raw: bytes) -> SignedEvmTransaction:
    fields = decode_rlp(raw[1:])
    if not isinstance(fields, list) or len(fields) not in (9, 12):
        raise EvmTransactionError("invalid field count for transaction type: 2")
    chain_id = _typed_chain_id(fields[0])
    nonce = _number(fields[1])
    max_priority_fee = _uint(fields[2])
    max_fee = _uint(fields[3])
    gas_limit = _uint(fields[4])
    to = _address(fields[5])
    value = _uint(fields[6])
    data = _string(fields[7])
    access_list = _access_list(fields[8])
    if len(fields) == 9:
        raise EvmTransactionError("the transaction is not signed")
    y_parity = _y_parity(fields[9])
    r = _padded_scalar(fields[10])
    s = _padded_scalar(fields[11])
    if max_fee < max_priority_fee:
        raise EvmTransactionError("priorityFee cannot be more than maxFee")
    unsigned = b"\x02" + encode_rlp(
        [
            _int_bytes(chain_id),
            _int_bytes(nonce),
            _int_bytes(max_priority_fee),
            _int_bytes(max_fee),
            _int_bytes(gas_limit),
            to,
            _int_bytes(value),
            data,
            access_list,
        ]
    )
    sender = _recover_sender(unsigned, r, s, y_parity)
    return SignedEvmTransaction(type=2, chain_id=chain_id, data=data, sender=sender)


def decode_signed_transaction(raw: bytes) -> SignedEvmTransaction:
    """Decode a signed legacy, EIP-2930 or EIP-1559 transaction envelope and recover
    its sender.

    ``raw`` is the envelope: ``type || rlp(payload)`` for a typed transaction, or
    ``rlp(fields)`` for a legacy one (first byte ``0xc0`` or above). A field read
    as a number is read by value, so a leading zero byte does not refuse it, and
    the sender is recovered over the canonical encoding of the fields, as ethers
    does.

    :raises EvmTransactionError: for anything tzun-anchor/1 §10.4 item 2
        refuses: a wrong field count, an unsigned transaction, a field of the
        wrong shape or out of range (as ethers v6 ``Transaction.from`` reads
        them), a typed transaction on chain id 0, a legacy ``v`` of 35 or 36,
        ``r`` or ``s`` out of range or ``s`` above n/2, a tip above the fee cap,
        a signature no public key recovers from, and any type other than these
        three.
    :raises MissingExtraError: without the ``anchor`` extra.
    """
    _extra()
    data = bytes(raw)
    if not data:
        raise EvmTransactionError("empty transaction")
    try:
        if data[0] >= 0xC0:
            return _legacy(data)
        if data[0] == 1:
            return _eip2930(data)
        if data[0] == 2:
            return _eip1559(data)
    except RlpError as exc:
        raise EvmTransactionError(f"not RLP: {exc}") from exc
    raise EvmTransactionError("unsupported transaction type")


__all__ = (
    "ANCHOR_EXTRA_HINT",
    "SECP256K1_N",
    "EvmTransactionError",
    "SignedEvmTransaction",
    "anchor_extra_available",
    "decode_signed_transaction",
    "keccak256",
)
