"""Number rendering must be JavaScript's, not Python's.

Both languages produce the same shortest round-trip DIGITS; they disagree on
how those digits are rendered, and the disagreement changes canonical bytes —
which changes the digest, which makes genuine evidence captured in one SDK read
as tampered in the other.

The four renderings where the two disagree, all covered below:

  value                    Python repr                 JavaScript
  1e-5                     1e-05                       0.00001
  1e-7                     1e-07                       1e-7
  1e21                     1000000000000000000000      1e+21
  1.2345678901234568e20    123456789012345683968       123456789012345680000

Plus the case JSON cannot express and so cannot live in the vector corpus:
negative zero, which JavaScript renders as "0".
"""

from __future__ import annotations

import pytest

from tzun_sdk._generated.canonical import (
    MAX_SAFE_INTEGER,
    CanonicalSerializationError,
    _js_number_to_string,
)

# (python float, exactly what `String(x)` returns in Node)
JS_RENDERINGS = [
    (1e-5, "0.00001"),
    (1e-6, "0.000001"),
    (1e-7, "1e-7"),
    (1e-4, "0.0001"),
    (1e20, "100000000000000000000"),
    (1e21, "1e+21"),
    (1.7976931348623157e308, "1.7976931348623157e+308"),
    (5e-324, "5e-324"),
    (1.2345678901234568e20, "123456789012345680000"),
    (0.1 + 0.2, "0.30000000000000004"),
    (1e16, "10000000000000000"),
    (100.0, "100"),
    (1.5, "1.5"),
    (-2.25, "-2.25"),
    (2 / 3, "0.6666666666666666"),
    (6.02e23, "6.02e+23"),
    (1e-21, "1e-21"),
    (1e-323, "1e-323"),
    (1.2345678901234568e21, "1.2345678901234568e+21"),
]


@pytest.mark.parametrize("value,expected", JS_RENDERINGS)
def test_matches_javascript_number_to_string(value: float, expected: str) -> None:
    assert _js_number_to_string(value) == expected


def test_negative_zero_renders_as_zero() -> None:
    """`String(-0) === "0"` in JavaScript. JSON cannot carry -0, so this case
    cannot live in the vector corpus and is pinned here instead."""
    assert _js_number_to_string(-0.0) == "0"
    assert _js_number_to_string(0.0) == "0"


def test_integers_beyond_the_safe_range_are_refused() -> None:
    """A snowflake ID or nanosecond timestamp cannot round-trip through a double.

    Python holds it exactly; JavaScript has already rounded it by the time the
    reference canonicalizer sees it. Emitting the exact Python digits would
    write canonical bytes the other SDK can never reproduce, so the record would
    verify as tampered. Refusing is the same choice already made for NaN and
    Infinity.
    """
    from tzun_sdk._generated.canonical import canonical_serialize

    with pytest.raises(CanonicalSerializationError, match="safe range"):
        canonical_serialize({"snowflake": 1725000000000000123})
    with pytest.raises(CanonicalSerializationError, match="safe range"):
        canonical_serialize({"negative": -(2**53)})


def test_the_safe_boundary_itself_is_accepted() -> None:
    """Negative control: the guard must not reject values JS represents exactly."""
    from tzun_sdk._generated.canonical import canonical_serialize

    assert canonical_serialize({"n": MAX_SAFE_INTEGER}) == '{"n":9007199254740991}'
    assert canonical_serialize({"n": -MAX_SAFE_INTEGER}) == '{"n":-9007199254740991}'
    assert canonical_serialize({"n": 0}) == '{"n":0}'


def test_descriptor_set_fields_sort_by_utf16_code_unit() -> None:
    """U+1F600's first UTF-16 unit (0xD83D) is below U+FF21 (0xFF21).

    Python's default string sort compares code points and puts them the other
    way round. Sorted that way, a descriptor whose set-valued fields contain an
    emoji would serialise in a different order from the TS SDK, and hash
    differently.
    """
    from tzun_sdk._generated.canonical import canonical_serialize_descriptor

    emoji = chr(0x1F600)
    bmp = chr(0xFF21)
    out = canonical_serialize_descriptor(
        {
            "vendor": "v",
            "training": {"evaluations": []},
            "regulatoryMarkings": [],
            "externalIdentifiers": [
                {"scheme": bmp, "value": "a"},
                {"scheme": emoji, "value": "b"},
            ],
        }
    )
    # JS order: the emoji first. Python code-point order would be the reverse.
    assert out.index(f'"{emoji}"') < out.index(f'"{bmp}"')
    assert sorted([bmp, emoji]) == [bmp, emoji], "the naive Python order is the reverse"
