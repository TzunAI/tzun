"""ISO 8601 instants read the way JavaScript's ``Date.parse`` reads them.

The record rules compare instants (a mandate's validity window, a revocation's
claimed instant) and check the form of a capture time. The engine uses
``Date.parse``, which V8 implements with rules ``datetime`` does not share: a
day of 29 to 31 is accepted in every month and rolls over (``2026-02-30`` is
2 March), ``24:00:00`` is midnight of the next day, and fraction digits past
the third are read and dropped. These helpers reproduce that for the one form
the rules accept, ``YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)``, so the two
SDKs accept, refuse and order the same strings.
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Any

#: An ISO-8601 date-time with seconds and a zone designator (the engine's ``ISO_8601_RE``).
ISO_8601_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})",
    re.ASCII,
)
_PARTS_RE = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?"
    r"(Z|([+-])([0-9]{2}):([0-9]{2}))",
    re.ASCII,
)
#: An ISO 8601 UTC instant with milliseconds (a mandate document's instants).
_MANDATE_INSTANT_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", re.ASCII
)


def _days_from_civil(y: int, m: int, d: int) -> int:
    """Days since 1970-01-01 of the proleptic Gregorian date (day may exceed the month)."""
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    mp = (m + 9) % 12
    doy = (153 * mp + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def js_date_parse_ms(text: Any) -> int | None:
    """Milliseconds since the epoch, as ``Date.parse`` gives them, or ``None`` for ``NaN``.

    Only the form of :data:`ISO_8601_RE` is read; any other string is ``None``.
    """
    if not isinstance(text, str):
        return None
    m = _PARTS_RE.fullmatch(text)
    if m is None:
        return None
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    fraction = m.group(7) or ""
    millis = int((fraction + "000")[:3])
    if not 1 <= month <= 12 or not 1 <= day <= 31:
        return None
    if minute > 59 or second > 59:
        return None
    if hour > 24 or (hour == 24 and (minute or second or millis or fraction.strip("0"))):
        return None
    offset = 0
    if m.group(8) != "Z":
        oh, om = int(m.group(10)), int(m.group(11))
        if oh > 23 or om > 59:
            return None
        offset = (oh * 60 + om) * 60_000
        if m.group(9) == "-":
            offset = -offset
    days = _days_from_civil(year, month, day)
    ms = ((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + millis
    return ms - offset


def iso_from_ms(ms: int) -> str:
    """``new Date(ms).toISOString()`` for a year 0001 to 9999."""
    instant = _dt.datetime(1970, 1, 1, tzinfo=_dt.UTC) + _dt.timedelta(milliseconds=ms)
    return instant.strftime("%Y-%m-%dT%H:%M:%S.") + f"{instant.microsecond // 1000:03d}Z"


def is_capture_time(value: Any) -> bool:
    """An ISO-8601 date-time with seconds and a zone that ``Date.parse`` reads."""
    return isinstance(value, str) and ISO_8601_RE.fullmatch(value) is not None and js_date_parse_ms(value) is not None


def is_mandate_instant(value: Any) -> bool:
    """An ISO 8601 UTC instant with milliseconds that names a real instant (the engine's ``isMandateInstant``)."""
    if not isinstance(value, str) or _MANDATE_INSTANT_RE.fullmatch(value) is None:
        return False
    ms = js_date_parse_ms(value)
    if ms is None:
        return False
    if value.startswith("0000"):
        # Year 0 is outside datetime's range; JavaScript round-trips its real dates.
        return _year_zero_round_trips(value)
    try:
        return iso_from_ms(ms) == value
    except (OverflowError, ValueError):
        return False


def _year_zero_round_trips(value: str) -> bool:
    month, day = int(value[5:7]), int(value[8:10])
    hour, minute, second = int(value[11:13]), int(value[14:16]), int(value[17:19])
    month_days = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)  # year 0 is a leap year
    return day <= month_days[month - 1] and hour <= 23 and minute <= 59 and second <= 59


__all__ = ("ISO_8601_RE", "is_capture_time", "is_mandate_instant", "iso_from_ms", "js_date_parse_ms")
