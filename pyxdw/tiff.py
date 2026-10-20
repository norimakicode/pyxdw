"""Minimal TIFF construction for verified XDW CCITT page data."""

from __future__ import annotations

import struct
from fractions import Fraction


_TYPE_SHORT = 3
_TYPE_LONG = 4
_TYPE_RATIONAL = 5


def _short(value: int) -> bytes:
    return struct.pack("<H", value) + b"\0\0"


def _long(value: int) -> bytes:
    return struct.pack("<I", value)


def _entry(tag: int, field_type: int, count: int, encoded_value: bytes) -> bytes:
    if len(encoded_value) != 4:
        raise ValueError("inline TIFF values must be exactly four bytes")
    return struct.pack("<HHI", tag, field_type, count) + encoded_value


def _rational(value: float) -> bytes:
    fraction = Fraction(value).limit_denominator(10000)
    return struct.pack("<II", fraction.numerator, fraction.denominator)


def _wrap_ccitt_tiff(
    compressed_data: bytes,
    width: int,
    height: int,
    dpi: tuple[float, float],
    *,
    compression: int,
    options_tag: int,
) -> bytes:
    if width <= 0 or height <= 0:
        raise ValueError("TIFF dimensions must be positive")
    if not compressed_data:
        raise ValueError("CCITT data must not be empty")
    if dpi[0] <= 0 or dpi[1] <= 0:
        raise ValueError("TIFF resolution must be positive")

    entry_count = 15
    ifd_offset = 8
    ifd_end = ifd_offset + 2 + entry_count * 12 + 4
    x_resolution_offset = ifd_end
    y_resolution_offset = x_resolution_offset + 8
    strip_offset = y_resolution_offset + 8

    entries = (
        _entry(256, _TYPE_LONG, 1, _long(width)),
        _entry(257, _TYPE_LONG, 1, _long(height)),
        _entry(258, _TYPE_SHORT, 1, _short(1)),
        _entry(259, _TYPE_SHORT, 1, _short(compression)),
        _entry(262, _TYPE_SHORT, 1, _short(0)),  # WhiteIsZero
        _entry(266, _TYPE_SHORT, 1, _short(1)),  # MSB-to-LSB
        _entry(273, _TYPE_LONG, 1, _long(strip_offset)),
        _entry(274, _TYPE_SHORT, 1, _short(1)),
        _entry(277, _TYPE_SHORT, 1, _short(1)),
        _entry(278, _TYPE_LONG, 1, _long(height)),
        _entry(279, _TYPE_LONG, 1, _long(len(compressed_data))),
        _entry(282, _TYPE_RATIONAL, 1, _long(x_resolution_offset)),
        _entry(283, _TYPE_RATIONAL, 1, _long(y_resolution_offset)),
        _entry(options_tag, _TYPE_LONG, 1, _long(0)),
        _entry(296, _TYPE_SHORT, 1, _short(2)),  # inches
    )
    header = b"II" + struct.pack("<HI", 42, ifd_offset)
    ifd = struct.pack("<H", entry_count) + b"".join(entries) + _long(0)
    return (
        header
        + ifd
        + _rational(dpi[0])
        + _rational(dpi[1])
        + compressed_data
    )


def wrap_ccitt_group3_tiff(
    compressed_data: bytes,
    width: int,
    height: int,
    dpi: tuple[float, float],
) -> bytes:
    """Wrap one MSB-first, 1-D Group 3 fax strip in a standard TIFF file."""

    return _wrap_ccitt_tiff(
        compressed_data,
        width,
        height,
        dpi,
        compression=3,
        options_tag=292,
    )


def wrap_ccitt_group4_tiff(
    compressed_data: bytes,
    width: int,
    height: int,
    dpi: tuple[float, float],
) -> bytes:
    """Wrap one MSB-first Group 4 fax strip in a standard TIFF file."""

    return _wrap_ccitt_tiff(
        compressed_data,
        width,
        height,
        dpi,
        compression=4,
        options_tag=293,
    )
