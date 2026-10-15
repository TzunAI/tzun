"""RLP as the anchor verifier reads it (tzun_sdk.attestation.evm_rlp).

The TypeScript verifier decodes with ethers v6 ``decodeRlp``, which accepts
some non-canonical encodings (a single byte below 0x80 behind a prefix, a long
form for a short length, leading zeros in a length). The Python decoder accepts
exactly the same inputs, so an offline verdict never depends on which SDK read
the bytes. ``tests/cross-sdk/test_anchor_verify_parity.py`` runs a corpus
through both decoders. ``rlp_form`` tells a canonical encoding from the others,
for the Encoding rule of tzun-anchor/1 §10.4 item 2, as the TypeScript SDK's
``evmRlpForm`` does.
"""

from __future__ import annotations

import pytest

from tzun_sdk.attestation.evm_rlp import MAX_RLP_DEPTH, RlpError, decode_rlp, encode_rlp, rlp_form


def h(text: str) -> bytes:
    return bytes.fromhex(text)


@pytest.mark.parametrize(
    ("encoded", "value"),
    [
        ("00", b"\x00"),
        ("7f", b"\x7f"),
        ("80", b""),
        ("8180", b"\x80"),
        ("83646f67", b"dog"),
        ("c0", []),
        ("c88363617483646f67", [b"cat", b"dog"]),
        ("c7c0c1c0c3c0c1c0", [[], [[]], [[], [[]]]]),
        ("b838" + "61" * 56, b"a" * 56),
        ("f83a" + "b838" + "61" * 56, [b"a" * 56]),
    ],
)
def test_decodes_canonical_encodings(encoded: str, value: object) -> None:
    assert decode_rlp(h(encoded)) == value
    assert encode_rlp(value) == h(encoded)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("encoded", "value"),
    [
        # A byte below 0x80 behind a one-byte prefix.
        ("8105", b"\x05"),
        # The long string form for a short length, and a leading zero in the length.
        ("b80161", b"a"),
        ("b9000161", b"a"),
        # The long list form for a short list.
        ("f80180", [b""]),
    ],
)
def test_accepts_what_ethers_accepts(encoded: str, value: object) -> None:
    assert decode_rlp(h(encoded)) == value


@pytest.mark.parametrize(
    "encoded",
    [
        "",
        "81",  # the string runs past the data
        "b8",  # the length runs past the data
        "b802" + "61",
        "c2" + "80",  # the list runs past the data
        "c180" + "80",  # junk after the payload
        "c1" + "8161",  # the child claims more than the list holds
    ],
)
def test_refuses(encoded: str) -> None:
    with pytest.raises(RlpError):
        decode_rlp(h(encoded))


def nested_lists(depth: int) -> bytes:
    """``depth`` lists, each holding the next, the innermost empty."""
    encoded = encode_rlp([])
    for _ in range(depth - 1):
        encoded = encode_rlp_list_of(encoded)
    return encoded


def test_decodes_max_rlp_depth_lists_and_refuses_one_more_at_any_depth() -> None:
    # The TypeScript verifier refuses the same items (MAX_RLP_DEPTH in
    # src/attestation/blockchain.ts) before ethers' recursive decoder meets them.
    assert MAX_RLP_DEPTH == 64
    value = decode_rlp(nested_lists(MAX_RLP_DEPTH))
    for _ in range(MAX_RLP_DEPTH - 1):
        assert isinstance(value, list) and len(value) == 1
        value = value[0]
    assert value == []
    for depth in (MAX_RLP_DEPTH + 1, 1_000, 3_000, 20_000):
        with pytest.raises(RlpError, match="nested too deep"):
            decode_rlp(nested_lists(depth))


def test_the_depth_counts_lists_not_strings() -> None:
    # A string at the innermost list is not one more level.
    encoded = encode_rlp([b"x"])
    for _ in range(MAX_RLP_DEPTH - 1):
        encoded = encode_rlp_list_of(encoded)
    assert decode_rlp(encoded) is not None


def encode_rlp_list_of(child: bytes) -> bytes:
    """A list whose one item is the already-encoded ``child``."""
    if len(child) <= 55:
        return bytes([0xC0 + len(child)]) + child
    length = len(child).to_bytes((len(child).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(length)]) + length + child


def test_encodes_integers_as_ethers_does() -> None:
    assert encode_rlp(b"") == h("80")
    assert encode_rlp([b"", b"\x00", b"\x01" * 60]) == h("f840" + "80" + "00" + "b83c" + "01" * 60)


STR56 = "ab" * 56


@pytest.mark.parametrize(
    ("label", "encoded"),
    [
        ("a byte below 0x80 as itself", "05"),
        ("the empty string", "80"),
        ("a byte of 0x80 or more as a one-byte string", "8180"),
        ("55 bytes in the short form", "b7" + "ab" * 55),
        ("56 bytes in the long form", "b838" + STR56),
        ("an empty list", "c0"),
        ("nested lists", "c3c1c0c0"),
        ("a list of 56 bytes in the long form", "f838" + "c0" * 56),
    ],
)
def test_rlp_form_canonical(label: str, encoded: str) -> None:
    assert rlp_form(h(encoded)) == "canonical", label


@pytest.mark.parametrize(
    ("label", "encoded"),
    [
        ("a byte below 0x80 as a one-byte string", "8105"),
        ("zero as a one-byte string", "8100"),
        ("a short length in the long form (string)", "b80105"),
        ("a short length in the long form (list)", "f800"),
        ("a long length with a leading zero byte (string)", "b90038" + STR56),
        ("a long length with a leading zero byte (list)", "f90038" + "c0" * 56),
        ("55 bytes in the long form (string)", "b837" + "ab" * 55),
        ("a list of 55 bytes in the long form", "f837" + "c0" * 55),
        ("a byte after the item (decode_rlp refuses it too)", "0500"),
        ("a byte after a list (decode_rlp refuses it too)", "c000"),
        ("a non-canonical item inside a list", "c3c28105"),
    ],
)
def test_rlp_form_non_canonical(label: str, encoded: str) -> None:
    assert rlp_form(h(encoded)) == "non-canonical", label


@pytest.mark.parametrize(
    ("label", "encoded"),
    [
        ("nothing", ""),
        ("a string that runs past the data", "81"),
        ("a long length that runs past the data", "b9"),
        ("a list that runs past the data", "c280"),
        ("an item that runs past its list", "c18105"),
    ],
)
def test_rlp_form_malformed(label: str, encoded: str) -> None:
    assert rlp_form(h(encoded)) == "malformed", label
