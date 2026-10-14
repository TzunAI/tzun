# HAND-MAINTAINED. NOT generated.
#
# The TypeScript verifier (src/attestation/blockchain.ts) decodes RLP with ethers
# v6 `decodeRlp` and encodes it with `encodeRlp`. This module accepts exactly the
# inputs that decoder accepts, so that an offline verdict on a block header, a
# transactions-trie node or a raw transaction never depends on which SDK read the
# bytes. tests/cross-sdk/test_anchor_verify_parity.py runs one corpus through
# both decoders and requires the same answers.
"""Recursive Length Prefix, as the ``evm-calldata/1`` verifier reads it.

The decoder is the one the Ethereum Yellow Paper (appendix B) defines, with the
acceptance of ethers v6: a string or list may use a longer prefix than it needs
(``0x81 0x05`` for the byte ``0x05``, the long form for a short length, a length
with leading zero bytes). Everything else is refused with :class:`RlpError`: a
string, list or length that runs past its data or its enclosing list, an empty
input, and bytes left over after the item.

An item nested more than :data:`MAX_RLP_DEPTH` lists deep is refused too. No
header, transactions-trie node or transaction the verifier reads comes near it,
and the TypeScript verifier refuses the same items before ethers' recursive
decoder meets them, so neither SDK's answer depends on how deep a host's stack
is. The decoder itself does not recurse.

A decoded item is ``bytes`` or a ``list`` of items. The encoder writes the one
canonical encoding of such a value.
"""

from __future__ import annotations

from typing import Final, TypeAlias

RlpItem: TypeAlias = "bytes | list[RlpItem]"

#: The most lists an item may sit inside, its own included: a top-level list is at
#: depth 1. ``MAX_RLP_DEPTH`` in src/attestation/blockchain.ts is the same number.
MAX_RLP_DEPTH: Final = 64


class RlpError(ValueError):
    """The bytes are not an RLP item."""


def decode_rlp(data: bytes) -> RlpItem:
    """Decode one RLP item that spans all of ``data``.

    :raises RlpError: when ``data`` is empty, is not an RLP item, nests lists more
        than :data:`MAX_RLP_DEPTH` deep, or has bytes after the item.
    """
    size = len(data)
    if size == 0:
        raise RlpError("data too short")

    def within(end: int) -> None:
        if end > size:
            raise RlpError("data short segment too short")

    # Open lists: the items read so far and the offset each list ends at.
    stack: list[tuple[list[RlpItem], int]] = []
    pos = 0
    while True:
        prefix = data[pos]
        item: RlpItem
        if prefix >= 0xC0:
            if prefix >= 0xF8:
                length_length = prefix - 0xF7
                within(pos + 1 + length_length)
                length = int.from_bytes(data[pos + 1 : pos + 1 + length_length], "big")
                start = pos + 1 + length_length
            else:
                length = prefix - 0xC0
                start = pos + 1
            end = start + length
            within(end)
            if len(stack) >= MAX_RLP_DEPTH:
                raise RlpError("lists nested too deep")
            if length > 0:
                stack.append(([], end))
                pos = start
                continue
            item = []
            pos = end
        elif prefix >= 0x80:
            if prefix >= 0xB8:
                length_length = prefix - 0xB7
                within(pos + 1 + length_length)
                length = int.from_bytes(data[pos + 1 : pos + 1 + length_length], "big")
                start = pos + 1 + length_length
            else:
                length = prefix - 0x80
                start = pos + 1
            within(start + length)
            item = data[start : start + length]
            pos = start + length
        else:
            item = data[pos : pos + 1]
            pos += 1

        # Hand the finished item to the list it is in, closing every list it ends.
        while stack:
            items, end = stack[-1]
            items.append(item)
            if pos > end:
                raise RlpError("child data too short")
            if pos < end:
                break
            stack.pop()
            item = items
        else:
            if pos != size:
                raise RlpError("unexpected junk after rlp payload")
            return item


def _length_prefix(offset: int, length: int) -> bytes:
    if length <= 55:
        return bytes([offset + length])
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(length_bytes)]) + length_bytes


def encode_rlp(value: RlpItem) -> bytes:
    """The canonical RLP encoding of ``value``: ``bytes`` or a list of such values.

    :raises TypeError: for anything else.
    """
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
        if len(data) == 1 and data[0] <= 0x7F:
            return data
        return _length_prefix(0x80, len(data)) + data
    if isinstance(value, list):
        payload = b"".join(encode_rlp(child) for child in value)
        return _length_prefix(0xC0, len(payload)) + payload
    raise TypeError(f"cannot RLP-encode a {type(value).__name__}")


__all__ = ("MAX_RLP_DEPTH", "RlpError", "RlpItem", "decode_rlp", "encode_rlp")
