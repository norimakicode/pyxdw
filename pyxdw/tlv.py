"""BER-style definite-length TLV primitives observed in XDW files."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import XdwFormatError


@dataclass(frozen=True)
class TlvField:
    """One single-byte-tag, definite-length field."""

    offset: int
    tag: int
    header_size: int
    length: int

    @property
    def value_offset(self) -> int:
        return self.offset + self.header_size

    @property
    def end_offset(self) -> int:
        return self.value_offset + self.length


def decode_field(data: bytes, offset: int, limit: int | None = None) -> TlvField:
    """Decode one field, bounded by *limit*."""
    if limit is None:
        limit = len(data)
    if offset < 0 or offset + 2 > limit:
        raise XdwFormatError(f"0x{offset:X}: truncated TLV header")

    tag = data[offset]
    first_length = data[offset + 1]
    if first_length < 0x80:
        length = first_length
        header_size = 2
    else:
        length_octets = first_length & 0x7F
        if length_octets == 0:
            raise XdwFormatError(f"0x{offset:X}: indefinite length is unsupported")
        if length_octets > 4 or offset + 2 + length_octets > limit:
            raise XdwFormatError(
                f"0x{offset:X}: invalid length-of-length {length_octets}"
            )
        length = int.from_bytes(
            data[offset + 2:offset + 2 + length_octets], "big"
        )
        header_size = 2 + length_octets

    field = TlvField(offset, tag, header_size, length)
    if field.end_offset > limit:
        raise XdwFormatError(
            f"0x{offset:X}: field ends at 0x{field.end_offset:X}, "
            f"past limit 0x{limit:X}"
        )
    return field


def parse_sequence(data: bytes, start: int, end: int) -> tuple[TlvField, ...]:
    """Parse fields that must consume exactly ``[start, end)``."""
    fields = []
    cursor = start
    while cursor < end:
        field = decode_field(data, cursor, end)
        fields.append(field)
        cursor = field.end_offset
    if cursor != end:
        raise XdwFormatError(
            f"TLV sequence ended at 0x{cursor:X}, expected 0x{end:X}"
        )
    return tuple(fields)


def value(data: bytes, field: TlvField) -> bytes:
    return data[field.value_offset:field.end_offset]


def unsigned_be(data: bytes, field: TlvField) -> int:
    return int.from_bytes(value(data, field), "big")


def encode_length(length: int) -> bytes:
    """Encode a non-negative BER-style definite length."""
    if length < 0:
        raise ValueError("length must be non-negative")
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    if len(encoded) > 4:
        raise ValueError("lengths larger than 32 bits are unsupported")
    return bytes([0x80 | len(encoded)]) + encoded


def encode_field(tag: int, payload: bytes) -> bytes:
    """Encode one single-byte-tag field."""
    if not 0 <= tag <= 0xFF:
        raise ValueError("tag must fit in one byte")
    return bytes([tag]) + encode_length(len(payload)) + payload
