# HAND-MAINTAINED. NOT generated.
"""The ECMAScript and Node value rules the TypeScript anchor verifier's answers
depend on, so the Python verifier gives the same answer on the same JSON.

JSON has one number type (``7.0`` is ``7``); JavaScript truthiness; ``Date``'s
proleptic Gregorian calendar, its range and ``toISOString``; ``Date.UTC``; and
Node's lenient base64 decoder. Private to :mod:`tzun_sdk.attestation`.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Final

MAX_SAFE_INTEGER: Final = 2**53 - 1
#: The range of an ECMAScript Date, in milliseconds either side of the epoch.
MAX_DATE_MS: Final = 8_640_000_000_000_000
#: The ASCII characters ECMAScript counts as white space or a line terminator.
JS_ASCII_WHITESPACE: Final = " \t\n\v\f\r"
#: Every character ECMAScript counts as white space or a line terminator, which
#: ``String.prototype.trim`` strips: the ASCII ones, U+00A0, U+1680, U+2000 to U+200A,
#: U+2028, U+2029, U+202F, U+205F, U+3000 and U+FEFF. Python's ``str.strip()`` strips
#: U+001C to U+001F and U+0085 as well, and not U+FEFF.
JS_WHITESPACE: Final = (
    JS_ASCII_WHITESPACE
    + "\u00a0\u1680"
    + "".join(chr(c) for c in range(0x2000, 0x200B))
    + "\u2028\u2029\u202f\u205f\u3000\ufeff"
)


def js_trim(text: str) -> str:
    """``text.trim()``: ``text`` without the ECMAScript white space at either end."""
    return text.strip(JS_WHITESPACE)


def js_safe_int(value: object) -> int | None:
    """``value`` as an ``int`` when it is a JSON number that is a safe integer
    (``Number.isSafeInteger``), else ``None``. ``bool`` is not a number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER else None
    if isinstance(value, float) and value.is_integer() and abs(value) <= MAX_SAFE_INTEGER:
        return int(value)
    return None


def js_integral_number_string(value: float) -> str:
    """``String(value)`` for a non-negative integral ECMAScript number: its shortest
    round-trip digits, written out in full below 1e21 (so 2**64 is
    ``18446744073709552000``) and with an exponent from there; ``Infinity`` past the
    largest double."""
    if value == math.inf:
        return "Infinity"
    if value < 1e21:
        return format(Decimal(repr(float(value))).normalize(), "f")
    return repr(float(value))


def js_falsy(value: object) -> bool:
    """Whether JavaScript reads ``value`` as false: ``None``, ``False``, ``0``, NaN or ``''``."""
    if value is None or value is False:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value == 0 or value != value
    return isinstance(value, str) and value == ""


def days_from_civil(year: int, month: int, day: int) -> int:
    """Days from 1970-01-01 to a proleptic Gregorian date (``month`` 1-12)."""
    year -= month <= 2
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def civil_from_days(days: int) -> tuple[int, int, int]:
    """The proleptic Gregorian date ``days`` after 1970-01-01, ``month`` 1-12."""
    z = days + 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + 3 if mp < 10 else mp - 9
    return yoe + era * 400 + (month <= 2), month, day


def iso_from_millis(ms: int) -> str:
    """``new Date(ms).toISOString()``: ``YYYY-MM-DDTHH:mm:ss.sssZ``, with a signed
    six-digit year outside 0000-9999.

    :raises ValueError: outside the range of an ECMAScript Date.
    """
    if abs(ms) > MAX_DATE_MS:
        raise ValueError("Invalid time value")
    days, rem = divmod(ms, 86_400_000)
    year, month, day = civil_from_days(days)
    hour, rem = divmod(rem, 3_600_000)
    minute, rem = divmod(rem, 60_000)
    second, millis = divmod(rem, 1000)
    year_text = f"{year:04d}" if 0 <= year <= 9999 else f"{'+' if year > 0 else '-'}{abs(year):06d}"
    return f"{year_text}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}.{millis:03d}Z"


def millis_from_iso(text: str) -> int:
    """The inverse of :func:`iso_from_millis`, for a string it wrote."""
    sign = 1
    if text[0] in "+-":
        sign = -1 if text[0] == "-" else 1
        year, rest = int(text[1:7]) * sign, text[7:]
    else:
        year, rest = int(text[0:4]), text[4:]
    month, day = int(rest[1:3]), int(rest[4:6])
    hour, minute, second, millis = (
        int(rest[7:9]),
        int(rest[10:12]),
        int(rest[13:15]),
        int(rest[16:19]),
    )
    return (
        ((days_from_civil(year, month, day) * 24 + hour) * 60 + minute) * 60_000
        + second * 1000
        + millis
    )


def date_utc(
    year: float, month: float, day: float, hour: float, minute: float, second: float, ms: float
) -> float:
    """``Date.UTC`` (and, on a host whose zone is UTC, ``new Date(y, m, ...)``): the
    month counts from 0, years 0-99 are 1900-1999, every field may overflow into
    the next, and the result is NaN outside the Date range or for a NaN field."""
    fields = (year, month, day, hour, minute, second, ms)
    if any(isinstance(v, float) and not math.isfinite(v) for v in fields):
        return math.nan
    y, mo, d, h, mi, s, milli = (int(v) for v in fields)
    if 0 <= y <= 99:
        y += 1900
    y += mo // 12
    mo %= 12
    days = days_from_civil(y, mo + 1, 1) + d - 1
    total = days * 86_400_000 + h * 3_600_000 + mi * 60_000 + s * 1000 + milli
    return float(total) if abs(total) <= MAX_DATE_MS else math.nan


_BASE64_VALUES: Final = {
    c: i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
}
_BASE64_VALUES.update({"-": 62, "_": 63})


def node_base64_decode(text: str) -> bytes:
    """Base64 decoded as Node's ``Buffer.from(text, 'base64')`` decodes it: the
    URL-safe alphabet too, characters outside the alphabet skipped, decoding
    stopped at the first ``=``, and a final lone character dropped.

    Node reads the string's UTF-16 code units and looks each one up by its low
    byte, so a character above U+00FF counts as the ASCII character that byte
    is: U+0141 reads as ``A``, U+4E2D as ``-``, and U+013D, like the high
    surrogate of most emoji, as ``=``."""
    values: list[int] = []
    # The low byte of each UTF-16 code unit: every other byte of UTF-16LE. A lone
    # surrogate, which JSON can carry, is a code unit like any other.
    for low in text.encode("utf-16-le", "surrogatepass")[::2]:
        ch = chr(low)
        if ch == "=":
            break
        v = _BASE64_VALUES.get(ch)
        if v is not None:
            values.append(v)
    out = bytearray()
    whole = len(values) - len(values) % 4
    for i in range(0, whole, 4):
        n = (values[i] << 18) | (values[i + 1] << 12) | (values[i + 2] << 6) | values[i + 3]
        out += n.to_bytes(3, "big")
    rest = values[whole:]
    if len(rest) >= 2:
        n = (rest[0] << 18) | (rest[1] << 12) | ((rest[2] << 6) if len(rest) == 3 else 0)
        out += n.to_bytes(3, "big")[: len(rest) - 1]
    return bytes(out)
