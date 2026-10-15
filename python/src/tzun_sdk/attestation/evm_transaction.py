# HAND-MAINTAINED. NOT generated.
#
# The TypeScript verifier reads a raw transaction with `readEvmTransaction`
# (src/attestation/blockchain.ts): the rules of tzun-anchor/1 §10.4 item 2, on
# the bytes and then on the fields read as integers of any size, then the
# sender, recovered over a signing payload it builds from the fields. This
# module applies the same rules in the same order, reports the same rule for a
# refusal, and recovers the same sender. tests/cross-sdk/test_anchor_verify_parity.py
# runs ethers-signed transactions, their mutations and transactions at the
# edges of each rule through both SDKs.
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

from tzun_sdk.attestation.evm_rlp import RlpError, RlpItem, decode_rlp, encode_rlp, rlp_form
from tzun_sdk.errors import MissingExtraError

#: The order of the secp256k1 group.
SECP256K1_N: Final = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
#: floor(n / 2), which is (n - 1) / 2 because n is odd: the largest ``s`` EIP-2 allows.
_HALF_N: Final = SECP256K1_N // 2
_MAX_UINT256: Final = 2**256 - 1

ANCHOR_EXTRA_HINT: Final = "pip install 'tzun-sdk[anchor]'"


class EvmTransactionError(ValueError):
    """The bytes are not a signed transaction this verifier reads."""

    def __init__(self, message: str, *, rule: str | None = None) -> None:
        super().__init__(message)
        #: The rule of tzun-anchor/1 §10.4 item 2 the transaction breaks, one of
        #: :data:`ITEM_TWO_RULES`, or ``None`` when the bytes are not a signed
        #: transaction of type 0, 1 or 2 at all.
        self.rule = rule


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


# ---- The rules of item 2 -------------------------------------------------------------

#: The rules of tzun-anchor/1 §10.4 item 2, by the names ``vectors/evm-anchor-vectors.json``
#: gives them (the specification's **Chain id**, **Legacy v**, **Signature values**,
#: **Fees**, **Recovery**, **Encoding** and **Field sizes**).
ITEM_TWO_RULES: Final = (
    "chain-id",
    "legacy-v",
    "signature-values",
    "fees",
    "recovery",
    "encoding",
    "field-sizes",
)

_MAX_UINT64: Final = 2**64 - 1
#: The largest legacy ``v``: chainId * 2 + 36 for the largest chain id, 2^256 - 1.
_MAX_LEGACY_V: Final = _MAX_UINT256 * 2 + 36

#: Each type's signed fields, in order.
_SIGNED_FIELDS: Final[dict[int, tuple[str, ...]]] = {
    0: ("nonce", "gasPrice", "gasLimit", "to", "value", "data", "v", "r", "s"),
    1: (
        "chainId", "nonce", "gasPrice", "gasLimit", "to", "value", "data", "accessList",
        "yParity", "r", "s",
    ),
    2: (
        "chainId", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gasLimit", "to",
        "value", "data", "accessList", "yParity", "r", "s",
    ),
}  # fmt: skip

#: The fields that are integers, which **Encoding** writes with no leading zero byte.
_INTEGER_FIELDS: Final = frozenset(
    {
        "chainId", "nonce", "gasPrice", "maxPriorityFeePerGas", "maxFeePerGas", "gasLimit",
        "value", "v", "yParity", "r", "s",
    }
)  # fmt: skip

#: **Field sizes**: the largest value of each integer field it bounds (``r``, ``s``
#: and ``yParity`` are bounded by **Signature values**).
_FIELD_MAX: Final = (
    ("chainId", _MAX_UINT256),
    ("nonce", _MAX_UINT64),
    ("gasPrice", _MAX_UINT256),
    ("maxPriorityFeePerGas", _MAX_UINT256),
    ("maxFeePerGas", _MAX_UINT256),
    ("gasLimit", _MAX_UINT64),
    ("value", _MAX_UINT256),
    ("v", _MAX_LEGACY_V),
)


def _is_access_list(item: RlpItem) -> bool:
    """A list of ``[20-byte address, [32-byte storage keys]]``."""
    return isinstance(item, list) and all(
        isinstance(entry, list)
        and len(entry) == 2
        and isinstance(entry[0], bytes)
        and len(entry[0]) == 20
        and isinstance(entry[1], list)
        and all(isinstance(k, bytes) and len(k) == 32 for k in entry[1])
        for entry in item
    )


def _int_bytes(value: int) -> bytes:
    """An integer as RLP writes it: big-endian with no leading zero, and 0 as no bytes."""
    return b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


def _recover_sender(unsigned: bytes, r: int, s: int, y_parity: int) -> str:
    keccak_mod, coincurve = _extra()
    digest = bytes(keccak_mod.new(digest_bits=256, data=unsigned).digest())
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([y_parity])
    try:
        public_key = coincurve.PublicKey.from_signature_and_message(signature, digest, hasher=None)
    except Exception as exc:
        # r is no point's x-coordinate, or the point recovered is the point at infinity.
        raise EvmTransactionError(
            "no public key recovers from this signature", rule="recovery"
        ) from exc
    point = public_key.format(compressed=False)[1:]
    return "0x" + bytes(keccak_mod.new(digest_bits=256, data=point).digest())[12:].hex()


def _read(tx_type: int, payload: bytes) -> SignedEvmTransaction:
    """Item 2 on the payload of a transaction of type 0, 1 or 2 (see
    :func:`decode_signed_transaction`)."""
    form = rlp_form(payload)
    if form == "malformed":
        raise EvmTransactionError("not an RLP item")
    if form == "non-canonical":
        raise EvmTransactionError("not the canonical RLP encoding", rule="encoding")

    names = _SIGNED_FIELDS[tx_type]
    decoded = decode_rlp(payload)
    if not isinstance(decoded, list) or len(decoded) != len(names):
        raise EvmTransactionError(f"invalid field count for transaction type: {tx_type}")
    fields = dict(zip(names, decoded, strict=True))
    for name, item in fields.items():
        if not (_is_access_list(item) if name == "accessList" else isinstance(item, bytes)):
            raise EvmTransactionError(f"{name} is not of its shape")
    if len(fields["to"]) not in (0, 20):  # type: ignore[arg-type]
        raise EvmTransactionError("invalid address")

    n: dict[str, int] = {}
    for name in names:
        if name in _INTEGER_FIELDS:
            item = fields[name]
            assert isinstance(item, bytes)
            if item[:1] == b"\x00":
                raise EvmTransactionError(f"{name} has a leading zero byte", rule="encoding")
            n[name] = int.from_bytes(item, "big")
    for name, maximum in _FIELD_MAX:
        if name in n and n[name] > maximum:
            raise EvmTransactionError(f"{name} is above {maximum}", rule="field-sizes")
    if tx_type != 0 and n["chainId"] < 1:
        raise EvmTransactionError("a typed transaction signs chain id 0", rule="chain-id")
    v = n["v"] if tx_type == 0 else None
    if v is not None and v not in (27, 28) and v < 37:
        raise EvmTransactionError(
            "legacy v is not 27, 28, or chainId * 2 + 35 or + 36 for a chain id of 1 or more",
            rule="legacy-v",
        )
    r, s = n["r"], n["s"]
    if not (1 <= r < SECP256K1_N and 1 <= s <= _HALF_N):
        raise EvmTransactionError(
            "r outside [1, n - 1], or s outside [1, n/2] (EIP-2)", rule="signature-values"
        )
    if tx_type != 0 and n["yParity"] not in (0, 1):
        raise EvmTransactionError("invalid yParity", rule="signature-values")
    if tx_type == 2 and n["maxPriorityFeePerGas"] > n["maxFeePerGas"]:
        raise EvmTransactionError("priorityFee cannot be more than maxFee", rule="fees")

    # The signing payload, from the fields read as integers.
    unsigned: list[RlpItem] = [
        _int_bytes(n[name]) if name in _INTEGER_FIELDS else fields[name] for name in names[:-3]
    ]
    if v is None:
        chain_id, y_parity = n["chainId"], n["yParity"]
    elif v in (27, 28):
        chain_id, y_parity = 0, v - 27
    else:
        chain_id, y_parity = (v - 35) // 2, (v - 35) % 2
        unsigned += [_int_bytes(chain_id), b"", b""]
    body = encode_rlp(unsigned)
    sender = _recover_sender(body if tx_type == 0 else bytes([tx_type]) + body, r, s, y_parity)
    data = fields["data"]
    assert isinstance(data, bytes)
    return SignedEvmTransaction(type=tx_type, chain_id=chain_id, data=data, sender=sender)


def decode_signed_transaction(raw: bytes) -> SignedEvmTransaction:
    """Decode a signed legacy, EIP-2930 or EIP-1559 transaction envelope and recover
    its sender, as tzun-anchor/1 §10.4 item 2 reads it.

    ``raw`` is the envelope: ``type || rlp(fields)`` for a typed transaction, or
    ``rlp(fields)`` for a legacy one (first byte ``0xc0`` or above). Item 2's rules
    are applied in this order, on the bytes and then on the fields read as integers
    of any size, before any signature is recovered:

    1. **Encoding** (``encoding``): the bytes after the type are the canonical RLP of
       one list and nothing after it (:func:`~tzun_sdk.attestation.evm_rlp.rlp_form`),
       and no integer field has a leading zero byte (0 is the empty string);
    2. **Field sizes** (``field-sizes``): ``nonce`` and ``gasLimit`` at most
       2^64 - 1; the chain id, ``value``, ``gasPrice``, ``maxPriorityFeePerGas`` and
       ``maxFeePerGas`` at most 2^256 - 1; a legacy ``v`` at most 2 * (2^256 - 1) + 36;
    3. **Chain id** (``chain-id``): a typed transaction's chain id is 1 or more;
    4. **Legacy v** (``legacy-v``): 27 or 28 (unprotected: item 5 decides its
       chain), or ``chainId * 2 + 35`` or ``+ 36`` for a chain id of 1 or more;
    5. **Signature values** (``signature-values``): ``r`` in [1, n - 1], ``s`` in
       [1, (n - 1) / 2] (EIP-2), and a typed ``yParity`` of 0 or 1;
    6. **Fees** (``fees``): an EIP-1559 ``maxPriorityFeePerGas`` is at most its
       ``maxFeePerGas``;
    7. **Recovery** (``recovery``): a public key recovers from the signature over the
       signing payload built from the fields (EIP-2718 type byte and the unsigned
       fields; for legacy EIP-155, the chain id, 0 and 0).

    The field shapes (the signed form's field count, a ``to`` of 0 or 20 bytes, an
    access list of 20-byte addresses and 32-byte keys) are checked first among the
    fields. The TypeScript SDK's ``readEvmTransaction`` reads and refuses the same
    envelopes, for the same rule, and recovers the same sender.

    :raises EvmTransactionError: for anything item 2 refuses, with ``rule`` the
        name of the rule broken first, or ``None`` when the bytes are not a signed
        transaction of type 0, 1 or 2 at all (not one RLP item, another type, the
        wrong number of fields, or a field of the wrong shape).
    :raises MissingExtraError: without the ``anchor`` extra.
    """
    _extra()
    data = bytes(raw)
    if not data:
        raise EvmTransactionError("empty transaction")
    if data[0] >= 0xC0:
        tx_type, payload = 0, data
    elif data[0] in (1, 2):
        tx_type, payload = data[0], data[1:]
    else:
        raise EvmTransactionError("unsupported transaction type")
    try:
        return _read(tx_type, payload)
    except RlpError as exc:
        raise EvmTransactionError(f"not RLP: {exc}") from exc


__all__ = (
    "ANCHOR_EXTRA_HINT",
    "ITEM_TWO_RULES",
    "SECP256K1_N",
    "EvmTransactionError",
    "SignedEvmTransaction",
    "anchor_extra_available",
    "decode_signed_transaction",
    "keccak256",
)
