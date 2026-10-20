"""Small, read-only subset of the Windows Enhanced Metafile format.

Application pages observed in XDW decode to complete EMF byte streams.  This
module validates their record framing and extracts strings from the standard
text-output records; it is intentionally not an EMF renderer.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from statistics import median

from .errors import XdwFormatError


EMR_HEADER = 1
EMR_EOF = 14
EMR_EXTTEXTOUTA = 83
EMR_EXTTEXTOUTW = 84
EMR_POLYTEXTOUTA = 96
EMR_POLYTEXTOUTW = 97
EMR_SMALLTEXTOUT = 108

ETO_GLYPH_INDEX = 0x10
ETO_NO_RECT = 0x100
ETO_SMALL_CHARS = 0x200
ETO_PDY = 0x2000


@dataclass(frozen=True)
class EmfTextRecord:
    """Text and reference position recovered from one EMF drawing record."""

    text: str
    x: int
    y: int
    record_index: int
    record_type: int
    advances: tuple[int, ...] = ()

    @property
    def layout_text(self) -> str:
        """Return text with large EMF character advances exposed as tabs."""

        if len(self.advances) < len(self.text) or len(self.text) < 2:
            return self.text
        widths = [
            abs(width)
            for character, width in zip(self.text[:-1], self.advances[:-1])
            if width and not character.isspace()
        ]
        if not widths:
            return self.text
        typical = float(median(widths))
        # Observed spreadsheet EMFs use 2.5x–80x advances for cell gaps,
        # while ordinary mixed-width glyphs stay below roughly 2.1x.
        gap_threshold = max(typical * 2.25, typical + 32.0)
        parts: list[str] = []
        for index, character in enumerate(self.text):
            parts.append(character)
            if (
                index + 1 < len(self.text)
                and abs(self.advances[index]) > gap_threshold
                and not character.isspace()
            ):
                parts.append("\t")
        return "".join(parts)


def _decode_text(raw: bytes, wide: bool, small_chars: bool = False) -> str:
    if wide:
        return raw.decode("utf-16le", errors="replace")
    if small_chars:
        return raw.decode("latin-1")
    return raw.decode("cp932", errors="replace")


def _slice_string(
    record: bytes,
    offset: int,
    characters: int,
    *,
    wide: bool,
    small_chars: bool = False,
) -> str:
    width = 2 if wide else 1
    end = offset + characters * width
    if offset < 0 or end > len(record):
        raise XdwFormatError("EMF text string exceeds its record")
    return _decode_text(record[offset:end], wide, small_chars).rstrip("\x00")


def _text_advances(
    record: bytes,
    offset: int,
    characters: int,
    options: int,
) -> tuple[int, ...]:
    """Read the optional EMRTEXT character-position array."""

    if offset == 0 or characters == 0:
        return ()
    count = characters * (2 if options & ETO_PDY else 1)
    end = offset + count * 4
    if offset < 0 or end > len(record):
        raise XdwFormatError("EMF text advance array exceeds its record")
    values = struct.unpack_from(f"<{count}i", record, offset)
    if options & ETO_PDY:
        return tuple(values[::2])
    return tuple(values)


def _extended_text(
    record: bytes, record_index: int, record_type: int
) -> EmfTextRecord | None:
    if len(record) < 76:
        raise XdwFormatError("truncated EMR_EXTTEXTOUT record")
    x, y, characters, string_offset, options = struct.unpack_from(
        "<iiIII", record, 36
    )
    if options & ETO_GLYPH_INDEX:
        return None
    wide = record_type == EMR_EXTTEXTOUTW
    text = _slice_string(record, string_offset, characters, wide=wide)
    advances_offset = struct.unpack_from("<I", record, 72)[0]
    advances = _text_advances(record, advances_offset, characters, options)
    return (
        EmfTextRecord(text, x, y, record_index, record_type, advances)
        if text
        else None
    )


def _poly_text(
    record: bytes, record_index: int, record_type: int
) -> list[EmfTextRecord]:
    if len(record) < 40:
        raise XdwFormatError("truncated EMR_POLYTEXTOUT record")
    string_count = struct.unpack_from("<I", record, 36)[0]
    if string_count > (len(record) - 40) // 40:
        raise XdwFormatError("EMR_POLYTEXTOUT text array exceeds its record")
    wide = record_type == EMR_POLYTEXTOUTW
    results = []
    for index in range(string_count):
        base = 40 + index * 40
        x, y, characters, string_offset, options = struct.unpack_from(
            "<iiIII", record, base
        )
        if options & ETO_GLYPH_INDEX:
            continue
        text = _slice_string(record, string_offset, characters, wide=wide)
        advances_offset = struct.unpack_from("<I", record, base + 36)[0]
        advances = _text_advances(record, advances_offset, characters, options)
        if text:
            results.append(
                EmfTextRecord(
                    text, x, y, record_index, record_type, advances
                )
            )
    return results


def _small_text(record: bytes, record_index: int) -> EmfTextRecord | None:
    if len(record) < 36:
        raise XdwFormatError("truncated EMR_SMALLTEXTOUT record")
    x, y, characters, options = struct.unpack_from("<iiII", record, 8)
    if options & ETO_GLYPH_INDEX:
        return None
    string_offset = 36 if options & ETO_NO_RECT else 52
    small_chars = bool(options & ETO_SMALL_CHARS)
    text = _slice_string(
        record,
        string_offset,
        characters,
        wide=not small_chars,
        small_chars=small_chars,
    )
    return EmfTextRecord(text, x, y, record_index, EMR_SMALLTEXTOUT) if text else None


def emf_text_records(data: bytes) -> tuple[EmfTextRecord, ...]:
    """Validate an EMF stream and return text-output records in drawing order."""

    if len(data) < 88:
        raise XdwFormatError("truncated EMF header")
    record_type, header_size = struct.unpack_from("<II", data)
    signature = struct.unpack_from("<I", data, 40)[0]
    declared_size, declared_records = struct.unpack_from("<II", data, 48)
    if record_type != EMR_HEADER or header_size < 88 or header_size % 4:
        raise XdwFormatError("invalid EMF header record")
    if signature != 0x464D4520:
        raise XdwFormatError("missing EMF signature")
    if declared_size != len(data):
        raise XdwFormatError("EMF header size does not match decoded data")

    results: list[EmfTextRecord] = []
    offset = 0
    record_index = 0
    saw_eof = False
    while offset < len(data):
        if offset + 8 > len(data):
            raise XdwFormatError("truncated EMF record header")
        current_type, size = struct.unpack_from("<II", data, offset)
        if size < 8 or size % 4 or offset + size > len(data):
            raise XdwFormatError(f"invalid EMF record at 0x{offset:X}")
        record = data[offset:offset + size]

        if current_type in (EMR_EXTTEXTOUTA, EMR_EXTTEXTOUTW):
            text = _extended_text(record, record_index, current_type)
            if text is not None:
                results.append(text)
        elif current_type in (EMR_POLYTEXTOUTA, EMR_POLYTEXTOUTW):
            results.extend(_poly_text(record, record_index, current_type))
        elif current_type == EMR_SMALLTEXTOUT:
            text = _small_text(record, record_index)
            if text is not None:
                results.append(text)
        elif current_type == EMR_EOF:
            saw_eof = True

        offset += size
        record_index += 1

    if offset != len(data) or record_index != declared_records or not saw_eof:
        raise XdwFormatError("EMF record framing disagrees with its header")
    return tuple(results)


def extract_emf_text(data: bytes, extraction_mode: str = "plain") -> str:
    """Return basic EMF text in drawing-order or coordinate-layout mode."""

    records = emf_text_records(data)
    if extraction_mode == "plain":
        # The Windows text oracle used for the compatibility corpus emits the
        # drawing-order strings without synthetic separators. Keeping the same
        # rule makes the pure-Python result byte-for-byte comparable after
        # UTF-8 encoding, while ``layout`` remains available for readable rows.
        return "".join(record.text for record in records)
    if extraction_mode != "layout":
        raise ValueError("extraction_mode must be 'plain' or 'layout'")

    positioned = sorted(records, key=lambda record: (record.y, record.x, record.record_index))
    lines: list[list[str]] = []
    baseline: int | None = None
    for record in positioned:
        text = record.layout_text.strip()
        if not text:
            continue
        if baseline is None or abs(record.y - baseline) > 2:
            lines.append([])
            baseline = record.y
        lines[-1].append(text)
    return "\n".join("\t".join(parts) for parts in lines)
