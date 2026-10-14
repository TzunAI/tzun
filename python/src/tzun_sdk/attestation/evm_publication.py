# HAND-MAINTAINED. NOT generated.
#
# The Python twin of the evm-calldata/1 half of src/attestation/blockchain.ts:
# `verifyEvmPublication`, `parseEvmBlockHeader`, `verifyEvmTransactionProof`,
# the publisher-manifest reader and `RpcEvmHeaderSource`. Every check runs in the
# same order and gives the same outcome and reason (tzun-anchor/1 §10.4).
# tests/cross-sdk/test_anchor_verify_parity.py runs ethers-signed publications,
# fabricated blocks and scripted header sources through both SDKs and requires
# identical verdicts, facts included. Edit both sides together.
"""The ``evm-calldata/1`` publication verifier (tzun-anchor/1 §10.4).

An ``evm-calldata/1`` publication is a transaction whose calldata is exactly
``0x || P``. It is a statement by the transaction's SIGNER, so the sender is
recovered from the raw signed transaction and checked against the publishers
the verifier's own manifest lists for the anchor origin. The recipient is not
read.

Offline, everything in a publication except the sender's signature comes from
the bundle: the raw transaction, the header, the trie proof, the block hash, the
block time and the chain. Those facts prove only that the publisher key signed a
transaction carrying P. A publication is ``True`` only once the verifier's own
header source confirms the block canonical at finalized depth; until then it is
``None``, ``publication_not_checked``.

Needs the ``anchor`` extra (:mod:`tzun_sdk.attestation.evm_transaction`). Without
it, a publication that reaches the transaction is ``None``,
``publication_not_checked``, with ``missing_dependency`` on ``anchor.evm.tx``.

A header source is the auditor's, never the artifact's: any object with the
methods of :class:`EvmHeaderSource`, each returning its answer or an awaitable
of it. A method that returns its answer directly runs on the event loop and
must not block: the verifier's deadline cannot interrupt it. Its blocks and
transactions are dicts (:class:`EvmCanonicalBlock`,
:data:`EvmSourceTransaction`). :class:`RpcEvmHeaderSource` reads one over JSON-RPC.
"""

from __future__ import annotations

import inspect
import math
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, NotRequired, Protocol, TypeAlias, TypedDict, TypeVar

import anyio
import httpx

from tzun_sdk.attestation._ecmascript import days_from_civil, iso_from_millis, js_falsy, js_safe_int
from tzun_sdk.attestation.evm_rlp import RlpItem, decode_rlp, encode_rlp
from tzun_sdk.attestation.evm_transaction import (
    EvmTransactionError,
    SignedEvmTransaction,
    decode_signed_transaction,
    keccak256,
)
from tzun_sdk.errors import MissingExtraError

EvmCheckOutcome = Literal["checked-correct", "checked-wrong", "not-checked", "abstain"]
"""The four outcomes of tzun-anchor/1 §10.1, per check."""

EvmPublicationReason = Literal[
    "evm_calldata_mismatch",
    "evm_sender_mismatch",
    "evm_chain_mismatch",
    "evm_tx_proof_invalid",
    "anchor_not_found_on_chain",
    "malformed_publication",
    "publication_not_checked",
    "unsupported_publication_kind",
    "unsupported_evm_tx_type",
]
"""Why an ``evm-calldata/1`` publication came out the way it did.

``False`` reasons: ``evm_calldata_mismatch`` (the calldata is not exactly
``0x || P``), ``evm_sender_mismatch`` (the recovered sender is not a publisher
the manifest lists for this origin, or was not one at the block time),
``evm_chain_mismatch`` (the signed chain id is not the manifest entry's),
``evm_tx_proof_invalid`` (``keccak(raw)`` is not the transaction id, the header
does not hash to the block hash or names another number, or the trie proof does
not place the transaction under the header's ``transactionsRoot``),
``anchor_not_found_on_chain`` (the header source says the block, or the
transaction's place in it, is not canonical) and ``malformed_publication`` (a
field is missing or mistyped, or §10.4 item 2 refuses the raw transaction: see
:func:`~tzun_sdk.attestation.evm_transaction.decode_signed_transaction`).

``None`` reasons: ``publication_not_checked`` (the checks name what was
missing), ``unsupported_publication_kind`` and ``unsupported_evm_tx_type``.
"""

EvmNotCheckedReason = Literal[
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
    "blocked_by:anchor.evm.tx",
    "evm_verifier_error",
    "missing_dependency",
]
"""Why a check was ``not-checked``: the detail under ``publication_not_checked``.

``missing_dependency`` is this SDK's own: the ``anchor`` extra is not installed.
"""

EvmNetwork = Literal["mainnet", "testnet"]


class EvmConfirmationDepthDict(TypedDict):
    confirmations: int
    acceptNonFinal: NotRequired[bool]


EvmFinalityValue: TypeAlias = "Literal['finalized'] | EvmConfirmationDepthDict"
"""What a header source counts as final: ``'finalized'`` (the chain's tag), or a
confirmation depth (``acceptNonFinal`` when the caller accepts a depth below
:data:`EVM_MIN_FINAL_CONFIRMATIONS`)."""


class EvmCheckResult(TypedDict):
    id: Literal["anchor.evm.tx", "anchor.evm.canonical"]
    outcome: EvmCheckOutcome
    #: ``True`` for checked-correct, ``False`` for checked-wrong, ``None`` otherwise.
    value: bool | None
    reason: NotRequired[str]


class EvmPublicationChecks(TypedDict):
    tx: EvmCheckResult
    canonical: EvmCheckResult


class EvmPublicationFacts(TypedDict, total=False):
    """What the verification established, under the TypeScript SDK's names."""

    #: ``keccak256(rawTransaction)``.
    transactionId: str
    txType: int
    #: Recovered from the signature. Reported whatever the verdict.
    sender: str
    #: The chain id the sender signed, in decimal; ``'0'`` for a pre-EIP-155 transaction.
    signedChainId: str
    #: As the publication claims it. Confirmed only when ``valid`` is true.
    blockNumber: int
    blockHash: str
    #: What placed the transaction in the block.
    inclusion: Literal["tx_proof", "header_source"]
    #: Set only when ``valid`` is true: the manifest entry's CAIP-2 chain.
    chain: str
    namespace: Literal["production", "test"] | None
    network: Any
    #: Set only when ``valid`` is true: the confirmed block time, ISO 8601.
    blockTime: str
    #: The header source's declared finality, once it has been asked for its finalized height.
    finality: EvmFinalityValue


class EvmPublicationVerdict(TypedDict):
    #: ``True``: decided and holds. ``False``: decided and fails. ``None``: not decided, or abstained.
    valid: bool | None
    reason: NotRequired[EvmPublicationReason]
    checks: EvmPublicationChecks
    facts: EvmPublicationFacts


class EvmCanonicalBlock(TypedDict):
    """A canonical block as a header source reports it."""

    hash: str
    #: Unix seconds.
    timestamp: int


EvmSourceTransaction = TypedDict(
    "EvmSourceTransaction",
    {
        "from": str,
        "blockHash": "str | None",
        "blockNumber": "int | None",
        "rawTransaction": NotRequired[str],
    },
)
"""A transaction as a header source's node reports it."""

_T = TypeVar("_T")
_Answer: TypeAlias = "_T | Awaitable[_T]"


class EvmHeaderSource(Protocol):
    """The verifier's own view of a chain. Supplied by the auditor, never by the artifact.

    Each method returns its answer or an awaitable of it. One that returns its
    answer directly runs on the event loop, so it must not block (wait on I/O or
    sleep): the deadline cannot interrupt it, and the verdict comes back only when
    it returns. Two members are optional:

    - ``finality``: what the source counts as final, reported with every verdict
      the source took part in (``'finalized'``, or ``{'confirmations': n}``);
    - ``transaction(transaction_id)``: the transaction as the source's node sees
      it (:data:`EvmSourceTransaction`), or ``None``; used to cross-check the
      sender and to place a transaction the bundle carries no trie proof for.
    """

    def chain_id(self) -> _Answer[int]:
        """The EIP-155 chain id of the network this source reads."""
        ...

    def finalized_block_number(self) -> _Answer[int]:
        """The height of the newest block this source considers final."""
        ...

    def canonical_block(self, block_number: int) -> _Answer[EvmCanonicalBlock | None]:
        """The canonical block at ``block_number``, or ``None`` when the source has none there."""
        ...


#: The verifier's registry from CAIP-2 chain to network (tzun-anchor/1 §9): Ethereum
#: mainnet, and the Sepolia and Hoodi test networks. Any other chain is ``None``
#: unless the caller's ``networks`` names it.
DEFAULT_EVM_NETWORKS: Final[Mapping[str, EvmNetwork]] = {
    "eip155:1": "mainnet",
    "eip155:11155111": "testnet",
    "eip155:560048": "testnet",
}
#: The default deadline for one verification's header-source calls, in milliseconds.
DEFAULT_EVM_TIMEOUT_MS: Final = 30_000
#: The fewest confirmations a confirmation depth may count as final without ``acceptNonFinal``.
EVM_MIN_FINAL_CONFIRMATIONS: Final = 64

_HEX32: Final = re.compile(r"0x[0-9a-fA-F]{64}")
_HEX: Final = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_ADDRESS: Final = re.compile(r"0x[0-9a-fA-F]{40}")
_EIP155: Final = re.compile(r"eip155:([1-9][0-9]{0,30})")
_RFC3339: Final = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(Z|[+-]([0-9]{2}):([0-9]{2}))"
)
_MAX_SAFE_INTEGER: Final = 2**53 - 1

TX_CHECK: Final = "anchor.evm.tx"
CANONICAL_CHECK: Final = "anchor.evm.canonical"


def _is_hex(value: object) -> bool:
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def _is_hex32(value: object) -> bool:
    return isinstance(value, str) and _HEX32.fullmatch(value) is not None


def _hex_bytes(value: str) -> bytes:
    return bytes.fromhex(value[2:])


def rfc3339_seconds(value: str) -> tuple[int, bool] | None:
    """A manifest's RFC 3339 timestamp (tzun-anchor/1 §9) at full precision, or ``None``.

    The result is ``(seconds, fractional)``: the instant is ``seconds``, in unix
    seconds, plus a fraction of a second that is non-zero exactly when
    ``fractional`` is true. An offset is whole minutes, so it never moves the
    fraction. Every field is range-checked, so an impossible date
    (``2026-09-31``, ``T24:00:00``, a second of 60) is refused rather than rolled
    over. The fraction's digits are only tested for zero, never converted to a
    number of milliseconds. The TypeScript SDK's ``rfc3339Seconds`` reads the
    same value.
    """
    m = _RFC3339.fullmatch(value)
    if m is None:
        return None
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    leap = (year % 4 == 0 and year % 100 != 0) or year % 400 == 0
    days_in = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if not 1 <= month <= 12 or not 1 <= day <= days_in[month - 1]:
        return None
    if hour > 23 or minute > 59 or second > 59:
        return None
    offset_seconds = 0
    if m.group(9) is not None:
        offset_hour, offset_minute = int(m.group(9)), int(m.group(10))
        if offset_hour > 23 or offset_minute > 59:
            return None
        sign = 1 if m.group(8)[0] == "+" else -1
        offset_seconds = sign * (offset_hour * 60 + offset_minute) * 60
    fractional = re.search("[1-9]", m.group(7) or "") is not None
    seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
    return seconds - offset_seconds, fractional


# ---- The block header and the transactions trie ------------------------------------------


@dataclass(frozen=True)
class EvmBlockHeader:
    """The fields of a block header the verifier reads."""

    #: ``keccak256`` of the header RLP, lowercase ``0x`` hex.
    hash: str
    number: int
    #: Unix seconds.
    timestamp: int
    #: Lowercase ``0x`` hex.
    transactions_root: str


def _rlp_safe_int(item: RlpItem) -> int | None:
    """An RLP scalar as a safe integer: empty is 0, and a leading zero byte is not canonical."""
    if not isinstance(item, bytes):
        return None
    if item == b"":
        return 0
    if item[0] == 0:
        return None
    value = int.from_bytes(item, "big")
    return value if value <= _MAX_SAFE_INTEGER else None


def parse_evm_block_header(rlp: object) -> EvmBlockHeader | None:
    """Read ``transactionsRoot`` (field 4), ``number`` (8) and ``timestamp`` (11) from a
    block header's RLP, ``0x`` hex.

    ``None`` for anything that is not an RLP list of at least the fifteen original
    header fields, or whose three read fields are not byte strings of the right
    form. Other fields are not read, whatever their shape. Never raises, except
    :class:`~tzun_sdk.errors.MissingExtraError` without the ``anchor`` extra.
    """
    if not _is_hex(rlp):
        return None
    assert isinstance(rlp, str)
    raw = _hex_bytes(rlp)
    header_hash = "0x" + keccak256(raw).hex()
    try:
        fields = decode_rlp(raw)
    except ValueError:
        return None
    if not isinstance(fields, list) or len(fields) < 15:
        return None
    root = fields[4]
    if not isinstance(root, bytes) or len(root) != 32:
        return None
    number = _rlp_safe_int(fields[8])
    timestamp = _rlp_safe_int(fields[11])
    if number is None or timestamp is None:
        return None
    return EvmBlockHeader(
        hash=header_hash, number=number, timestamp=timestamp, transactions_root="0x" + root.hex()
    )


def _nibbles(data: bytes) -> list[int]:
    out: list[int] = []
    for b in data:
        out += (b >> 4, b & 0x0F)
    return out


def _decode_hex_prefix(path: bytes) -> tuple[bool, list[int]] | None:
    """Hex-prefix decoding (Yellow Paper appendix C): (is a leaf, the nibbles)."""
    n = _nibbles(path)
    if not n or n[0] > 3:
        return None
    odd = (n[0] & 1) == 1
    if not odd and n[1] != 0:
        return None
    return n[0] >= 2, n[1:] if odd else n[2:]


def _tx_key(tx_index: int) -> list[int]:
    """The trie key of transaction ``tx_index``: the nibbles of ``rlp(tx_index)``."""
    scalar = b"" if tx_index == 0 else tx_index.to_bytes((tx_index.bit_length() + 7) // 8, "big")
    return _nibbles(encode_rlp(scalar))


def verify_evm_transaction_proof(
    transactions_root: object, tx_index: object, proof: object
) -> str | None:
    """Walk a Merkle-Patricia proof for transaction ``tx_index`` (key ``rlp(tx_index)``)
    from ``transactions_root``, and return the value it proves, ``0x`` hex: the
    transaction's signed envelope.

    ``None`` when the proof is broken, proves the key absent, or carries nodes it
    never uses. Never raises, except :class:`~tzun_sdk.errors.MissingExtraError`
    without the ``anchor`` extra.
    """
    index = js_safe_int(tx_index)
    if not _is_hex32(transactions_root) or index is None or index < 0:
        return None
    if (
        not isinstance(proof, (list, tuple))
        or len(proof) == 0
        or not all(_is_hex(n) for n in proof)
    ):
        return None
    assert isinstance(transactions_root, str)
    key = _tx_key(index)
    expected = _hex_bytes(transactions_root)
    pos = 0
    used = 0
    node: RlpItem | None = None
    try:
        while True:
            if node is None:
                if used >= len(proof):
                    return None
                encoded = _hex_bytes(proof[used])
                used += 1
                if keccak256(encoded) != expected:
                    return None
                node = decode_rlp(encoded)
            if not isinstance(node, list):
                return None

            nxt: RlpItem
            if len(node) == 17:
                if pos == len(key):
                    value = node[16]
                    if isinstance(value, bytes) and value != b"" and used == len(proof):
                        return "0x" + value.hex()
                    return None
                nxt = node[key[pos]]
                pos += 1
            elif len(node) == 2:
                if not isinstance(node[0], bytes):
                    return None
                decoded = _decode_hex_prefix(node[0])
                if decoded is None:
                    return None
                leaf, path = decoded
                if leaf:
                    if key[pos:] != path:
                        return None
                    value = node[1]
                    if isinstance(value, bytes) and used == len(proof):
                        return "0x" + value.hex()
                    return None
                if not path or key[pos : pos + len(path)] != path:
                    return None
                pos += len(path)
                nxt = node[1]
            else:
                return None

            if isinstance(nxt, list):
                node = nxt  # an embedded node, under 32 bytes, carried inside its parent
                continue
            if not isinstance(nxt, bytes) or len(nxt) != 32:
                return None
            expected = nxt
            node = None
    except MissingExtraError:
        raise
    except Exception:
        return None


# ---- The publisher manifest (Anchor §9) -----------------------------------------------------


@dataclass(frozen=True)
class _Entry:
    address: str
    chain_id: int
    chain: str
    namespace: Literal["production", "test"]
    #: The first whole unix second the entry is valid at: ``validFrom`` rounded up.
    #: ``None`` when unbounded.
    first_second: int | None
    #: The last whole unix second the entry is valid at: ``validUntil`` rounded down.
    #: ``None`` when unbounded.
    last_second: int | None


def _own_property(obj: object, key: str) -> tuple[bool, object]:
    """JavaScript ``hasOwnProperty`` and the value, for a JSON object or array."""
    if isinstance(obj, Mapping):
        return (True, obj[key]) if key in obj else (False, None)
    if isinstance(obj, (list, tuple)):
        if key == "length":
            return True, len(obj)
        if re.fullmatch(r"0|[1-9][0-9]*", key) and int(key) < len(obj):
            return True, obj[int(key)]
    return False, None


def _eip155_chain_id(caip2: object) -> int | None:
    if not isinstance(caip2, str):
        return None
    m = _EIP155.fullmatch(caip2)
    return int(m.group(1)) if m else None


def _entries_for(manifest: object, origin: object) -> list[_Entry] | None:
    """The EVM entries for one origin, normalised. ``None`` when an EVM entry is
    malformed; entries in other CAIP-2 namespaces are skipped."""
    if not isinstance(origin, str) or not isinstance(manifest, Mapping):
        return []
    publishers = manifest.get("publishers")
    if js_falsy(publishers) or not isinstance(publishers, (Mapping, list, tuple)):
        return []
    present, entries = _own_property(publishers, origin)
    if not present:
        return []
    if not isinstance(entries, (list, tuple)):
        return None

    out: list[_Entry] = []
    for e in entries:
        if not isinstance(e, Mapping):
            return None
        chain = e.get("chain")
        if not isinstance(chain, str):
            return None
        if not chain.startswith("eip155:"):
            continue
        chain_id = _eip155_chain_id(chain)
        if chain_id is None:
            return None
        address = e.get("address")
        if not isinstance(address, str) or _ADDRESS.fullmatch(address) is None:
            return None
        namespace = e.get("namespace")
        if namespace not in ("production", "test"):
            return None

        bounds: list[tuple[int, bool] | None] = []
        for name in ("validFrom", "validUntil"):
            bound = e.get(name)
            if bound is None:
                bounds.append(None)
                continue
            instant = rfc3339_seconds(bound) if isinstance(bound, str) else None
            if instant is None:
                return None
            bounds.append(instant)
        start, end = bounds
        # Both ends are inclusive and compared at full precision (Anchor §9). A block
        # time is a whole second, so that is validFrom rounded up and validUntil
        # rounded down to the whole second.
        out.append(
            _Entry(
                address=address.lower(),
                chain_id=chain_id,
                chain=f"eip155:{chain_id}",
                namespace=namespace,
                first_second=None if start is None else start[0] + (1 if start[1] else 0),
                last_second=None if end is None else end[0],
            )
        )
    return out


def _valid_at(entry: _Entry, unix_seconds: int) -> bool:
    return (entry.first_second is None or entry.first_second <= unix_seconds) and (
        entry.last_second is None or unix_seconds <= entry.last_second
    )


def _declared_finality(source: object) -> EvmFinalityValue | None:
    """A copy of the finality a header source declares, or ``None`` when it declares
    none or something that is not a finality. Never raises."""
    try:
        f: Any = getattr(source, "finality", None)
        if f is not None and hasattr(f, "model_dump"):
            f = f.model_dump(exclude_none=True)
        if f == "finalized" and isinstance(f, str):
            return "finalized"
        if isinstance(f, Mapping):
            n = js_safe_int(f.get("confirmations"))
            if n is not None and n >= 1:
                if f.get("acceptNonFinal") is True:
                    return {"confirmations": n, "acceptNonFinal": True}
                return {"confirmations": n}
    except Exception:
        # A getter that raises declares nothing.
        return None
    return None


# ---- The deadline ---------------------------------------------------------------------------


class _DeadlineExceeded(Exception):
    """The verification's deadline passed before a header-source call answered."""


async def _with_deadline(call: Callable[[], object], deadline: float) -> Any:
    """``call()``'s answer, awaited when it is awaitable, or :class:`_DeadlineExceeded`
    at ``deadline`` (``time.monotonic()`` seconds), whichever comes first.

    A synchronous ``call`` that blocks holds the event loop until it returns, and
    the deadline cannot interrupt it, so the verification returns late: header
    sources must not block (:class:`EvmHeaderSource`). The TypeScript verifier's
    ``withDeadline`` has the same limit."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _DeadlineExceeded
    answered = False
    result: object = None
    with anyio.move_on_after(remaining):
        result = call()
        if inspect.isawaitable(result):
            result = await result
        answered = True
    if not answered:
        raise _DeadlineExceeded
    return result


def _timeout_seconds(requested: object) -> float:
    if (
        isinstance(requested, (int, float))
        and not isinstance(requested, bool)
        and math.isfinite(requested)
        and requested > 0
    ):
        return float(requested) / 1000
    return DEFAULT_EVM_TIMEOUT_MS / 1000


# ---- The verifier -----------------------------------------------------------------------------


def _check(check_id: str, outcome: EvmCheckOutcome, reason: str | None = None) -> EvmCheckResult:
    value = True if outcome == "checked-correct" else False if outcome == "checked-wrong" else None
    result: EvmCheckResult = {"id": check_id, "outcome": outcome, "value": value}  # type: ignore[typeddict-item]
    if reason is not None:
        result["reason"] = reason
    return result


async def verify_evm_publication(
    publication: object,
    *,
    p: object,
    anchor_origin: object,
    manifest: object = None,
    header_sources: Mapping[str, object] | None = None,
    networks: Mapping[str, object] | None = None,
    timeout_ms: object = None,
) -> EvmPublicationVerdict:
    """Verify one ``evm-calldata/1`` publication against P (tzun-anchor/1 §10.4).

    ``True`` needs every offline fact (the transaction id, calldata ``0x || P``, a
    recovered sender the manifest lists for ``anchor_origin`` at the block time,
    the signed chain id equal to that entry's CAIP-2 chain, and, when the bundle
    carries them, the header hash and the trie proof) AND the header source for
    that chain confirming the block canonical at finalized depth, with the
    transaction placed in it by a verified trie proof or by the source's own
    lookup. Offline facts that fail give ``False``; anything short of the header
    source's confirmation gives ``None``, ``publication_not_checked``.

    :param publication: the publication entry joined with the bundle's material
        (untrusted; validated field by field). ``None`` reads as absent for every
        optional field.
    :param p: the 32 bytes the publication must carry, as hex with or without ``0x``.
    :param anchor_origin: the anchor origin whose manifest entries may publish P.
    :param manifest: the verifier's publisher manifest (Anchor §9): ``{"publishers":
        {<anchor origin>: [<entry>, ...]}}``.
    :param header_sources: header sources keyed by canonical CAIP-2 chain.
    :param networks: overrides or extends :data:`DEFAULT_EVM_NETWORKS`.
    :param timeout_ms: one deadline for every header-source call this
        verification makes; default :data:`DEFAULT_EVM_TIMEOUT_MS`. A call still
        pending at it makes the publication ``None``, ``evm_header_source_timeout``.

    Never raises.
    """
    deadline = time.monotonic() + _timeout_seconds(timeout_ms)
    facts: EvmPublicationFacts = {}
    blocked = _check(CANONICAL_CHECK, "not-checked", "blocked_by:anchor.evm.tx")

    def tx_failed(reason: EvmPublicationReason) -> EvmPublicationVerdict:
        return {
            "valid": False,
            "reason": reason,
            "checks": {"tx": _check(TX_CHECK, "checked-wrong", reason), "canonical": blocked},
            "facts": facts,
        }

    def tx_abstained(reason: EvmPublicationReason) -> EvmPublicationVerdict:
        return {
            "valid": None,
            "reason": reason,
            "checks": {"tx": _check(TX_CHECK, "abstain", reason), "canonical": blocked},
            "facts": facts,
        }

    def tx_not_checked(reason: EvmNotCheckedReason) -> EvmPublicationVerdict:
        return {
            "valid": None,
            "reason": "publication_not_checked",
            "checks": {"tx": _check(TX_CHECK, "not-checked", reason), "canonical": blocked},
            "facts": facts,
        }

    try:
        pub = publication
        if not isinstance(pub, Mapping):
            return tx_failed("malformed_publication")
        if not (isinstance(pub.get("kind"), str) and pub.get("kind") == "evm-calldata/1"):
            return tx_abstained("unsupported_publication_kind")

        # P is the caller's input, not the artifact's.
        p_hex = (p if p.startswith("0x") else "0x" + p) if isinstance(p, str) else ""
        if not _is_hex32(p_hex):
            return tx_not_checked("input_not_supplied:p")

        # JSON from nullable columns or other languages writes an absent field as
        # null, so None reads as absent for every optional member.
        raw = pub.get("rawTransaction")
        if raw is None:
            return tx_not_checked("not_in_bundle:raw_transaction")
        block_number_value = pub.get("blockNumber")
        block_hash = pub.get("blockHash")
        transaction_id = pub.get("transactionId")
        block_header = pub.get("blockHeader")
        tx_index_value = pub.get("txIndex")
        tx_proof = pub.get("txProof")
        if not _is_hex(raw) or raw == "0x":
            return tx_failed("malformed_publication")
        assert isinstance(raw, str)
        if transaction_id is not None and not _is_hex32(transaction_id):
            return tx_failed("malformed_publication")
        if not _is_hex32(block_hash):
            return tx_failed("malformed_publication")
        assert isinstance(block_hash, str)
        block_number = js_safe_int(block_number_value)
        if block_number is None or block_number < 0:
            return tx_failed("malformed_publication")
        if block_header is not None and not _is_hex(block_header):
            return tx_failed("malformed_publication")
        has_proof = tx_index_value is not None or tx_proof is not None
        tx_index: int | None = None
        if has_proof:
            tx_index = js_safe_int(tx_index_value)
            if tx_index is None or tx_index < 0:
                return tx_failed("malformed_publication")
            if (
                not isinstance(tx_proof, (list, tuple))
                or len(tx_proof) == 0
                or not all(_is_hex(n) for n in tx_proof)
            ):
                return tx_failed("malformed_publication")
        claimed_hash = block_hash.lower()
        facts["blockNumber"] = block_number
        facts["blockHash"] = claimed_hash

        # EIP-2718: a legacy transaction is an RLP list (first byte 0xc0 or
        # above); a typed one starts with its type, 0x00 to 0x7f. Only types
        # this verifier reads go on to be parsed, so an unknown type abstains
        # instead of failing to parse.
        first_byte = int(raw[2:4], 16)
        if first_byte < 0xC0:
            if first_byte >= 0x80:
                return tx_failed("malformed_publication")
            if first_byte not in (1, 2):
                facts["txType"] = first_byte
                return tx_abstained("unsupported_evm_tx_type")

        # Item 2: the transaction decodes and its signature yields a sender.
        raw_bytes = _hex_bytes(raw)
        try:
            tx: SignedEvmTransaction = decode_signed_transaction(raw_bytes)
        except MissingExtraError:
            return tx_not_checked("missing_dependency")
        except EvmTransactionError:
            return tx_failed("malformed_publication")
        sender = tx.sender

        computed_id = "0x" + keccak256(raw_bytes).hex()
        facts["transactionId"] = computed_id
        facts["txType"] = tx.type
        facts["sender"] = sender
        facts["signedChainId"] = str(tx.chain_id)

        if transaction_id is not None and str(transaction_id).lower() != computed_id:
            return tx_failed("evm_tx_proof_invalid")
        if "0x" + tx.data.hex() != p_hex.lower():
            return tx_failed("evm_calldata_mismatch")

        entries = _entries_for(manifest, anchor_origin)
        if entries is None:
            return tx_not_checked("input_not_supplied:publisher_manifest")
        if len(entries) == 0:
            return tx_not_checked("no_expectation:publisher")
        by_sender = [e for e in entries if e.address == sender]
        if not by_sender:
            return tx_failed("evm_sender_mismatch")
        # A pre-EIP-155 transaction signs chain id 0, which matches no entry.
        by_chain = [e for e in by_sender if e.chain_id == tx.chain_id]
        if not by_chain:
            return tx_failed("evm_chain_mismatch")

        # The header and the trie proof, when the bundle carries them.
        header_time: int | None = None
        proof_verified = False
        if block_header is not None:
            assert isinstance(block_header, str)
            if "0x" + keccak256(_hex_bytes(block_header)).hex() != claimed_hash:
                return tx_failed("evm_tx_proof_invalid")
            header = parse_evm_block_header(block_header)
            if header is None or header.number != block_number:
                return tx_failed("evm_tx_proof_invalid")
            header_time = header.timestamp
            if has_proof:
                proven = verify_evm_transaction_proof(header.transactions_root, tx_index, tx_proof)
                if proven is None or proven.lower() != raw.lower():
                    return tx_failed("evm_tx_proof_invalid")
                proof_verified = True

        # The bundle's block time decides the validity window offline. It is the
        # artifact's own claim, so it can make the publication fail but never pass.
        candidates = by_chain
        if header_time is not None:
            candidates = [e for e in by_chain if _valid_at(e, header_time)]
            if not candidates:
                return tx_failed("evm_sender_mismatch")
        # Without a header, a bounded window waits for the block time the header
        # source confirms, and the sender check is not complete until then.
        window_pending = header_time is None and any(
            e.first_second is not None or e.last_second is not None for e in by_chain
        )
        tx_check = (
            _check(TX_CHECK, "not-checked", "not_in_bundle:block_header")
            if window_pending
            else _check(TX_CHECK, "checked-correct")
        )
        chain = by_chain[0].chain
        no_inclusion: EvmNotCheckedReason = (
            "not_in_bundle:block_header"
            if has_proof and block_header is None
            else "not_in_bundle:tx_proof"
        )

        def not_canonical(reason: EvmNotCheckedReason) -> EvmPublicationVerdict:
            return {
                "valid": None,
                "reason": "publication_not_checked",
                "checks": {
                    "tx": tx_check,
                    "canonical": _check(CANONICAL_CHECK, "not-checked", reason),
                },
                "facts": facts,
            }

        def off_chain() -> EvmPublicationVerdict:
            return {
                "valid": False,
                "reason": "anchor_not_found_on_chain",
                "checks": {
                    "tx": tx_check,
                    "canonical": _check(
                        CANONICAL_CHECK, "checked-wrong", "anchor_not_found_on_chain"
                    ),
                },
                "facts": facts,
            }

        source: object = None
        if isinstance(header_sources, Mapping) and chain in header_sources:
            source = header_sources[chain]
        if js_falsy(source):
            return not_canonical("input_not_supplied:evm_header_source")

        async def ask(call: Callable[[], object]) -> Any:
            return await _with_deadline(call, deadline)

        def failed(err: BaseException) -> EvmPublicationVerdict:
            if isinstance(err, _DeadlineExceeded):
                return not_canonical("evm_header_source_timeout")
            return not_canonical("evm_header_source_unavailable")

        inclusion: Literal["tx_proof", "header_source"] | None = (
            "tx_proof" if proof_verified else None
        )
        try:
            source_chain_id = await ask(lambda: source.chain_id())  # type: ignore[attr-defined]
            if not isinstance(source_chain_id, int) or isinstance(source_chain_id, bool):
                return not_canonical("evm_header_source_unavailable")
            if source_chain_id != tx.chain_id:
                return not_canonical("evm_header_source_chain_mismatch")

            declared = _declared_finality(source)
            if declared is not None:
                facts["finality"] = declared
            finalized = js_safe_int(await ask(lambda: source.finalized_block_number()))  # type: ignore[attr-defined]
            if finalized is None:
                return not_canonical("evm_header_source_unavailable")
            if block_number > finalized:
                return not_canonical("evm_block_not_finalized")

            # A source that calls this height final must have a block there.
            block = await ask(lambda: source.canonical_block(block_number))  # type: ignore[attr-defined]
            if block is None:
                return not_canonical("evm_header_source_inconsistent")
            block_timestamp = (
                js_safe_int(block.get("timestamp")) if isinstance(block, Mapping) else None
            )
            if (
                not isinstance(block, Mapping)
                or not _is_hex32(block.get("hash"))
                or block_timestamp is None
            ):
                return not_canonical("evm_header_source_unavailable")
            if str(block["hash"]).lower() != claimed_hash:
                return off_chain()
            # The header hashed to this canonical block, so its timestamp is the
            # block's; a source that reports another one is not answering straight.
            if header_time is not None and block_timestamp != header_time:
                return not_canonical("evm_header_source_inconsistent")
            block_time = block_timestamp

            lookup = getattr(source, "transaction", None)
            if callable(lookup):
                # A lookup that fails, times out or knows nothing (an expired
                # lookup index, say) contradicts nothing when the trie proof
                # already placed the transaction in the confirmed block.
                seen: object = None
                try:
                    seen = await ask(lambda: lookup(computed_id))
                except Exception as err:
                    if not proof_verified:
                        return failed(err)
                if not js_falsy(seen):
                    seen_hash = seen.get("blockHash") if isinstance(seen, Mapping) else None
                    seen_from = seen.get("from") if isinstance(seen, Mapping) else None
                    if not isinstance(seen_hash, str) or not isinstance(seen_from, str):
                        return not_canonical("evm_header_source_inconsistent")
                    assert isinstance(seen, Mapping)
                    seen_hash = seen_hash.lower()
                    if seen_hash != claimed_hash:
                        # With a verified proof, the source has confirmed the very
                        # block that holds the transaction, so it is contradicting
                        # itself.
                        if proof_verified:
                            return not_canonical("evm_header_source_inconsistent")
                        # Without one, the lookup decides only if the source also
                        # calls the block it names canonical at that block's
                        # height. A stale lookup index, or a backend behind a load
                        # balancer that has not caught up, names a block it no
                        # longer calls canonical.
                        at = js_safe_int(seen.get("blockNumber"))
                        if at is None or at < 0:
                            return not_canonical("evm_header_source_inconsistent")
                        named = await ask(lambda: source.canonical_block(at))  # type: ignore[attr-defined]
                        if (
                            js_falsy(named)
                            or not isinstance(named, Mapping)
                            or not isinstance(named.get("hash"), str)
                            or named["hash"].lower() != seen_hash
                        ):
                            return not_canonical("evm_header_source_inconsistent")
                        return off_chain()
                    if seen_from.lower() != sender:
                        return not_canonical("evm_header_source_inconsistent")
                    inclusion = inclusion or "header_source"
        except Exception as err:
            return failed(err)
        if inclusion is None:
            return not_canonical(no_inclusion)
        facts["inclusion"] = inclusion

        # The validity window, at the block time the header source confirmed.
        valid = [e for e in candidates if _valid_at(e, block_time)]
        if not valid:
            return {
                "valid": False,
                "reason": "evm_sender_mismatch",
                "checks": {
                    "tx": _check(TX_CHECK, "checked-wrong", "evm_sender_mismatch"),
                    "canonical": blocked,
                },
                "facts": facts,
            }

        namespaces = {e.namespace for e in valid}
        registry: dict[Any, Any] = dict(DEFAULT_EVM_NETWORKS)
        if isinstance(networks, Mapping):
            registry.update(networks)
        facts["chain"] = chain
        facts["namespace"] = valid[0].namespace if len(namespaces) == 1 else None
        facts["network"] = registry.get(chain) if chain in registry else None
        facts["blockTime"] = iso_from_millis(block_time * 1000)
        return {
            "valid": True,
            "checks": {
                "tx": _check(TX_CHECK, "checked-correct"),
                "canonical": _check(CANONICAL_CHECK, "checked-correct"),
            },
            "facts": facts,
        }
    except Exception:
        # Every expected failure returns above. This keeps an unforeseen one
        # undecided rather than an exception or a verdict.
        return tx_not_checked("evm_verifier_error")


# ---- A header source over JSON-RPC ----------------------------------------------------------


def checked_finality(finality: object, who: str) -> EvmFinalityValue:
    """``finality`` checked and normalised.

    :raises ValueError: for anything but ``'finalized'`` or a positive-integer
        confirmation depth, and for a depth below
        :data:`EVM_MIN_FINAL_CONFIRMATIONS` without ``acceptNonFinal: True``.
    """
    if finality is None or finality == "finalized":
        return "finalized"
    if hasattr(finality, "model_dump"):
        finality = finality.model_dump(exclude_none=True)
    if not isinstance(finality, Mapping):
        raise ValueError(f"{who} `finality` must be 'finalized' or {{'confirmations': n}}.")
    n = js_safe_int(finality.get("confirmations"))
    if n is None or n < 1:
        raise ValueError(f"{who} `finality.confirmations` must be a positive integer.")
    if finality.get("acceptNonFinal") is True:
        return {"confirmations": n, "acceptNonFinal": True}
    if n < EVM_MIN_FINAL_CONFIRMATIONS:
        raise ValueError(
            f"{who} `finality.confirmations` of {n} is below {EVM_MIN_FINAL_CONFIRMATIONS}, so an anchor it "
            f"confirms may not be final. Use 'finalized' (the default), at least {EVM_MIN_FINAL_CONFIRMATIONS} "
            "confirmations, or set `acceptNonFinal: True` to accept anchors that may be reorganised away."
        )
    return {"confirmations": n}


class RpcEvmHeaderSource:
    """An :class:`EvmHeaderSource` backed by a JSON-RPC node the verifier chooses.

    :param rpc_url: the node's JSON-RPC endpoint.
    :param finality: ``'finalized'`` (the default: the node's ``finalized`` tag),
        or ``{'confirmations': n}`` with ``n`` at least
        :data:`EVM_MIN_FINAL_CONFIRMATIONS` unless ``acceptNonFinal`` is true.
    :param timeout: seconds per request.
    :param transport: an ``httpx`` transport, for tests.
    :raises ValueError: for a finality :func:`checked_finality` refuses.
    """

    def __init__(
        self,
        rpc_url: str,
        *,
        finality: object = "finalized",
        timeout: float = DEFAULT_EVM_TIMEOUT_MS / 1000,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.finality: EvmFinalityValue = checked_finality(finality, "RpcEvmHeaderSource")
        self._rpc_url = rpc_url
        self._timeout = timeout
        self._transport = transport
        self._next_id = 0

    async def _call(self, method: str, params: Sequence[object]) -> Any:
        self._next_id += 1
        body = {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": list(params)}
        async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
            response = await client.post(self._rpc_url, json=body)
        response.raise_for_status()
        answer = response.json()
        if not isinstance(answer, Mapping) or ("error" in answer and answer["error"] is not None):
            raise RuntimeError(
                f"{method} failed: {answer.get('error') if isinstance(answer, Mapping) else answer!r}"
            )
        return answer.get("result")

    async def chain_id(self) -> int:
        return int(await self._call("eth_chainId", []), 16)

    async def finalized_block_number(self) -> int:
        if self.finality == "finalized":
            block = await self._call("eth_getBlockByNumber", ["finalized", False])
            if not block:
                raise RuntimeError("The node reports no finalized block.")
            return int(block["number"], 16)
        assert isinstance(self.finality, Mapping)
        head = int(await self._call("eth_blockNumber", []), 16)
        return head - (self.finality["confirmations"] - 1)

    async def canonical_block(self, block_number: int) -> EvmCanonicalBlock | None:
        block = await self._call("eth_getBlockByNumber", [hex(block_number), False])
        if not block or not block.get("hash"):
            return None
        return {"hash": block["hash"], "timestamp": int(block["timestamp"], 16)}

    async def transaction(self, transaction_id: str) -> EvmSourceTransaction | None:
        tx = await self._call("eth_getTransactionByHash", [transaction_id])
        if not tx:
            return None
        number = tx.get("blockNumber")
        return {
            "from": tx["from"],
            "blockHash": tx.get("blockHash"),
            "blockNumber": int(number, 16) if isinstance(number, str) else None,
        }


__all__ = (
    "CANONICAL_CHECK",
    "DEFAULT_EVM_NETWORKS",
    "DEFAULT_EVM_TIMEOUT_MS",
    "EVM_MIN_FINAL_CONFIRMATIONS",
    "TX_CHECK",
    "EvmBlockHeader",
    "EvmCanonicalBlock",
    "EvmCheckOutcome",
    "EvmCheckResult",
    "EvmConfirmationDepthDict",
    "EvmFinalityValue",
    "EvmHeaderSource",
    "EvmNetwork",
    "EvmNotCheckedReason",
    "EvmPublicationChecks",
    "EvmPublicationFacts",
    "EvmPublicationReason",
    "EvmPublicationVerdict",
    "EvmSourceTransaction",
    "RpcEvmHeaderSource",
    "checked_finality",
    "parse_evm_block_header",
    "rfc3339_seconds",
    "verify_evm_publication",
    "verify_evm_transaction_proof",
)
