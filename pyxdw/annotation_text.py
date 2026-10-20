"""Rewrite the text of a single-line text annotation, including its appearance EMF.

DocuWorks keeps a text annotation's string (``%Text``) and its drawn appearance
(an LZH-compressed EMF in content field ``87``) separately; the Viewer shows the
EMF.  Official checks (XDWAPI 9.0.11 + Viewer, 2026-10-16) found that only a
candidate rewriting both was displayed with the new text, so this module does
both, and resizes the box the way the official API sizes it:

* EMF logical units are 300 dpi pixels.  Half-width characters advance 25,
  full-width 50 (MS 明朝 12 pt, as in every official fixture).
* box width in pixels ``W`` = text advance + 40 (20 px margin each side).
* annotation width (0.01 mm) = ceil(W * 2540 / 300) + 1; EMF frame = that rounded
  up to 1 mm.  Matches the official API for 9-, 13- and 450-character texts.

Only one-line annotations with an inline EMF are handled; others are refused.
"""

from __future__ import annotations

import math
import struct
import unicodedata

from .errors import XdwFormatError, XdwUnsupportedFeatureError, XdwUnsupportedLayoutError
from .limits import _DecodeBudget
from .lzh import LzhDecodeError, compress_lzh
from .page_metadata import _ber_signed_int, ber_fields
from .properties import _parse_table, _table_entry
from .tlv import decode_field, encode_length

_TEXT = b"\x9f\x8f\x65"
_UNICODE_MARK = b"\x9f\x44"
_SIZE_TAGS = (b"\x85", b"\x9f\x8f\x63")
_TABLE = b"\x9f\x33"


def _decode_appearance(cache: dict[bytes, bytes], budget: _DecodeBudget | None = None) -> bytes:
    """Decode an appearance EMF (0x86) within ``max_annotation_emf``."""
    try:
        return (budget or _DecodeBudget()).decompress(
            cache[b"\x86"], int.from_bytes(cache[b"\x81"], "big"), "max_annotation_emf")
    except LzhDecodeError as exc:
        raise XdwFormatError("annotation appearance is not a valid LZH stream") from exc


def _refuse_rotated_text(body, emf: bytes) -> None:
    """Refuse a text edit when the annotation is rotated or its rotation is unclear.

    Rules (S-3): the edit is refused when ``%TextRotationAngle`` is not 0, when it
    is named in the record's table but the field is missing or unreadable, or
    when any EXTCREATEFONTINDIRECTW of the appearance has a non-zero
    ``lfEscapement`` or ``lfOrientation`` (or is too short to tell).  A record
    whose table does not name the attribute is judged by the drawing alone.
    Editing a rotated text box is not verified against the official API.
    """
    from .properties import _read_int, _tag
    refused = XdwUnsupportedFeatureError(
        "text of a rotated text annotation cannot be changed: not verified against "
        "the official API")
    fields = dict((bytes(tag), payload) for tag, payload in body)
    numbers = {name: n for n, _, _, name in _parse_table(fields[_TABLE])}
    if "%TextRotationAngle" in numbers:
        payload = fields.get(_tag(numbers["%TextRotationAngle"]))
        try:
            if payload is None or _read_int(payload) != 0:
                raise refused
        except XdwUnsupportedLayoutError:
            raise refused from None
    for record in _records(emf):
        if struct.unpack_from("<I", record)[0] == 82:          # EXTCREATEFONTINDIRECTW
            if len(record) < 28 or struct.unpack_from("<ii", record, 20) != (0, 0):
                raise refused


def _window_from_clip(emf: bytes) -> bytes:
    """The EMF to edit: as is when the box's window equals its clip rectangle.

    Both are logical units of the appearance EMF (300 dpi px, origin 0,0): the
    SETWINDOWEXTEX extent (W, H) normally equals the INTERSECTCLIPRECT rectangle
    (0, 0, W, H).  A box turned back to 0 degrees after quarter turns can keep a
    window 2 px higher than its clip; the official API edits it as the box of
    its clip (R0-b), so that window is set to the clip's (W, H).  This is done
    only when there is one window and one clip, the clip starts at (0, 0), the
    window is exactly (W, H + 2) and the rest of the drawing passes the S-4
    round-trip check of the verified layout; anything else is refused.
    """
    refused = XdwUnsupportedFeatureError(
        "text box window and clip disagree in a way not verified against the official API")
    records = _records(emf)
    kinds = [struct.unpack_from("<I", r)[0] for r in records]
    windows = [i for i, k in enumerate(kinds) if k == 9]
    clips = [i for i, k in enumerate(kinds) if k == 30]
    if len(windows) != 1 or len(clips) != 1 or len(records[windows[0]]) < 16 or len(records[clips[0]]) < 24:
        raise refused
    window = struct.unpack_from("<2i", records[windows[0]], 8)
    clip = struct.unpack_from("<4i", records[clips[0]], 8)
    if clip == (0, 0, *window):
        return emf
    if clip[:2] != (0, 0) or window != (clip[2], clip[3] + 2):
        raise refused
    try:
        shifted = _unrotated_text_emf(emf, 0)[3]
    except (XdwUnsupportedFeatureError, struct.error):    # struct.error: a truncated record
        raise refused from None
    if not shifted:
        raise refused
    struct.pack_into("<2i", records[windows[0]], 8, clip[2], clip[3])
    return b"".join(records)


def _text_rotation_angle(body, emf: bytes) -> int:
    """Counter-clockwise rotation of a text annotation: 0, 90, 180 or 270.

    Every EXTCREATEFONTINDIRECTW must carry the same lfEscapement and
    lfOrientation, a multiple of 900, and ``%TextRotationAngle`` must agree
    when the record's table names it.  Anything missing, unreadable or
    inconsistent raises XdwUnsupportedFeatureError.
    """
    from .properties import _read_int, _tag
    unclear = XdwUnsupportedFeatureError("text annotation rotation is missing or inconsistent")
    fonts = [r for r in _records(emf) if struct.unpack_from("<I", r)[0] == 82]
    if not fonts or any(len(r) < 28 for r in fonts):
        raise unclear
    angles = {struct.unpack_from("<ii", r, 20) for r in fonts}
    if len(angles) != 1:
        raise unclear
    escapement, orientation = angles.pop()
    if escapement != orientation or escapement not in (0, 900, 1800, 2700):
        raise unclear
    angle = escapement // 10
    fields = dict((bytes(tag), payload) for tag, payload in body)
    numbers = {name: n for n, _, _, name in _parse_table(fields[_TABLE])}
    if "%TextRotationAngle" in numbers:
        payload = fields.get(_tag(numbers["%TextRotationAngle"]))
        try:
            if payload is None or _read_int(payload) != angle:
                raise unclear
        except XdwUnsupportedLayoutError:
            raise unclear from None
    return angle


def _fields(buf: bytes):
    return [[tag, buf[v:e]] for tag, _, v, e in ber_fields(buf)]


def _join(items) -> bytes:
    return b"".join(tag + encode_length(len(payload)) + payload for tag, payload in items)


def _pair(first: int, second: int) -> bytes:
    return b"".join(bytes([len(raw)]) + raw for raw in map(_ber_signed_int, (first, second)))


def _read_pair(payload: bytes) -> tuple[int, int]:
    values, i = [], 0
    for _ in range(2):
        n = payload[i]
        values.append(int.from_bytes(payload[i + 1:i + 1 + n], "big", signed=True))
        i += 1 + n
    return values[0], values[1]


def _is_wide(ch: str) -> bool:
    return unicodedata.east_asian_width(ch) in ("W", "F", "A")


def _records(emf: bytes):
    out, o = [], 0
    while o < len(emf):
        if o + 8 > len(emf):
            raise XdwFormatError(f"truncated EMF record header at 0x{o:X}")
        rtype, size = struct.unpack_from("<II", emf, o)
        if size < 8 or size % 4 or o + size > len(emf):
            raise XdwFormatError(f"invalid EMF record at 0x{o:X}")
        out.append(bytearray(emf[o:o + size]))
        o += size
    return out


def _check_text_emf(emf: bytes) -> None:
    """Refuse an appearance EMF lacking a field the text edit reads or writes (E0).

    The header must be the one first record and EOF the last; the window,
    clip, font, text, polygon and "GDIC" comment records must be long enough
    for the offsets used here, and the text record's string and advances must
    lie inside it and decode as UTF-16.  Anything else raises XdwFormatError,
    before the drawing is rewritten.
    """
    records = _records(emf)
    kinds = [struct.unpack_from("<I", r)[0] for r in records]

    def malformed(what: str) -> XdwFormatError:
        return XdwFormatError(f"annotation appearance is malformed: {what}")

    if not kinds or kinds[0] != 1 or kinds.count(1) != 1 or kinds[-1] != 14:
        raise malformed("header or end record missing or misplaced")
    minimum = {1: 88, 9: 16, 30: 24, 82: 28, 84: 76, 86: 28}
    for r, k in zip(records, kinds):
        if len(r) < minimum.get(k, 8):
            raise malformed(f"record {k} is too short")
        if k == 84:
            n, off_string = struct.unpack_from("<II", r, 44)
            off_dx = struct.unpack_from("<I", r, 72)[0]
            if (n < 1 or off_string < 76 or off_string + 2 * n > len(r)
                    or off_dx < 76 or off_dx + 4 * n > len(r)):
                raise malformed("text string or advances outside the record")
            try:
                bytes(r[off_string:off_string + 2 * n]).decode("utf-16le")
            except UnicodeDecodeError:
                raise malformed("text string is not UTF-16") from None
        elif k == 86 and 28 + 4 * struct.unpack_from("<I", r, 24)[0] > len(r):
            raise malformed("polygon points outside the record")
        elif k == 70 and r[12:16] == b"GDIC" and (
                len(r) < 20 or (struct.unpack_from("<I", r, 16)[0] == 2 and len(r) < 36)):
            raise malformed("GDI comment is too short")


_PX_PER_POINT_TENTH = 50 / 120   # 12 pt font = 50 px tall at 300 dpi (official fixtures)


def _rewrite_emf(emf: bytes, lines: list[str], font_tenths: int | None = None):
    """New EMF, width/height (0.01 mm), frame size (0.01 mm) and device size (px).

    Each line is drawn by its own ``EXTCREATEFONTINDIRECTW, SELECTOBJECT,
    EXTTEXTOUTW, SELECTOBJECT, DELETEOBJECT`` block, 50 px below the previous one.
    """
    records = _records(emf)
    kinds = [struct.unpack_from("<I", r)[0] for r in records]
    text_at = [i for i, k in enumerate(kinds) if k == 84]
    windows = [r for r, k in zip(records, kinds) if k == 9]
    if not text_at or len(windows) != 1:
        raise XdwUnsupportedFeatureError("annotation drawing is not a text box")
    blocks = [(i - 2, i + 3) for i in text_at]
    if any(kinds[a:b] != [82, 37, 84, 37, 40] for a, b in blocks) or any(
            b1 != a2 for (_, b1), (a2, _) in zip(blocks, blocks[1:])):
        raise XdwUnsupportedFeatureError("unknown text-line record layout")
    template = [bytearray(r) for r in records[blocks[0][0]:blocks[0][1]]]
    old_text = template[2]
    n, off_string = struct.unpack_from("<II", old_text, 44)
    off_dx = struct.unpack_from("<I", old_text, 72)[0]
    old_chars = bytes(old_text[off_string:off_string + 2 * n]).decode("utf-16le")
    old_dx = struct.unpack_from(f"<{n}i", old_text, off_dx)
    half = {d // 2 if _is_wide(c) else d for c, d in zip(old_chars, old_dx)}
    if len(half) != 1:
        raise XdwUnsupportedFeatureError("annotation font advance is not uniform")
    unit = half.pop()
    old_font_px = -struct.unpack_from("<i", template[0], 12)[0]      # lfHeight of the line's font
    font_px = old_font_px if font_tenths is None else round(font_tenths * _PX_PER_POINT_TENTH)
    if font_px <= 0:
        raise XdwUnsupportedFeatureError("unknown annotation font height")
    unit = unit * font_px // old_font_px
    pitch = font_px                       # line pitch equals the font height (12 pt: 50, 24 pt: 100)
    old_w, old_h = struct.unpack_from("<ii", windows[0], 8)
    old_widest = max(sum(struct.unpack_from(f"<{struct.unpack_from('<I', records[i], 44)[0]}i", records[i],
                                            struct.unpack_from("<I", records[i], 72)[0])) for i in text_at)
    margin_x = old_w - old_widest
    margin_y = old_h - old_font_px * len(text_at)
    advances = [[2 * unit if _is_wide(c) else unit for c in line] for line in lines]
    w = max(sum(a) for a in advances) + margin_x
    h = pitch * len(lines) + margin_y
    if margin_x < 0 or margin_y < 0 or w <= 0 or h <= 0:
        raise XdwUnsupportedFeatureError("annotation text box has an unexpected size")
    if w > 32767 or h > 32767:                       # POLYGON16 stores the corners in 16 bits
        raise XdwUnsupportedFeatureError("text box too large")
    size = tuple(math.ceil(v * 2540 / 300) + 1 for v in (w, h))
    frame = tuple(math.ceil(v / 100) * 100 for v in size)
    frame_mm = tuple(v // 100 for v in frame)
    # The reference-device size the official writer records; floor(x + 0.3) fits all six
    # official values (271, 449, 201, 11291 px wide; 94, 142 px high), plain rounding does not.
    device = tuple(math.floor(v * 300 / 25.4 + 0.3) for v in frame_mm)

    for r, k in zip(records, kinds):
        if k == 1:                                         # header
            # GDI's drawn bottom: H-1 for one line, H-2 for two in the official fixtures.
            struct.pack_into("<ii", r, 16, w - 2, h - len(lines))     # rclBounds.right/bottom
            struct.pack_into("<ii", r, 32, *frame)         # rclFrame.right/bottom
            struct.pack_into("<ii", r, 72, *device)        # szlDevice
            struct.pack_into("<ii", r, 80, *frame_mm)      # szlMillimeters
            if len(r) >= 108:
                struct.pack_into("<ii", r, 100, frame_mm[0] * 1000, frame_mm[1] * 1000)
        elif k == 9:                                       # SETWINDOWEXTEX
            struct.pack_into("<ii", r, 8, w, h)
        elif k == 30:                                      # INTERSECTCLIPRECT
            struct.pack_into("<ii", r, 16, w, h)
        elif k == 86:                                      # POLYGON16 box outline
            struct.pack_into("<ii", r, 16, w - 2, h - len(lines))
            for p in range(struct.unpack_from("<I", r, 24)[0]):
                x, y = struct.unpack_from("<hh", r, 28 + 4 * p)
                struct.pack_into("<hh", r, 28 + 4 * p, w if x == old_w else x, h if y == old_h else y)
        elif k == 70 and r[12:16] == b"GDIC" and struct.unpack_from("<I", r, 16)[0] == 2:
            value = round(frame_mm[0] * 300 / 25.4)       # 23, 38, 17, 42 mm -> 272, 449, 201, 496
            struct.pack_into("<ii", r, 28, value, value)

    left, top, _, bottom = struct.unpack_from("<4i", old_text, 8)
    ref_x, ref_y = struct.unpack_from("<ii", old_text, 36)
    new_blocks = []
    for k, (line, dx) in enumerate(zip(lines, advances)):
        block = [bytearray(r) for r in template]
        string = line.encode("utf-16le")
        string += b"\0" * (-len(string) % 4)
        head = bytearray(old_text[:76])
        shift = pitch * k
        struct.pack_into("<4i", head, 8, left, top + shift, left + sum(dx) - 1,
                         top + shift + pitch - 1)
        struct.pack_into("<ii", head, 36, ref_x, ref_y + shift)
        struct.pack_into("<II", head, 44, len(line), 76)
        struct.pack_into("<I", head, 72, 76 + len(string))
        record = head + string + struct.pack(f"<{len(line)}i", *dx)
        struct.pack_into("<I", record, 4, len(record))
        block[2] = record
        struct.pack_into("<i", block[0], 12, -font_px)     # EXTCREATEFONTINDIRECTW lfHeight
        new_blocks.extend(block)
    for r, k in zip(records, kinds):                        # the drawing's other font records too
        if k == 82 and -struct.unpack_from("<i", r, 12)[0] == old_font_px:
            struct.pack_into("<i", r, 12, -font_px)
    records[blocks[0][0]:blocks[-1][1]] = new_blocks
    out = bytearray(b"".join(records))
    struct.pack_into("<I", out, 48, len(out))             # header nBytes
    struct.pack_into("<I", out, 52, len(records))         # header nRecords
    return bytes(out), size, frame, device


TRANSPARENT = 0x010101          # XDW_COLOR_NONE
_BACKGROUND_RUN = [20, 37, 39, 37, 19, 86, 19, 20, 37, 37, 40]   # SETROP2 ... POLYGON16 ... DELETEOBJECT


def colorref(color) -> int:
    """COLORREF (0x00BBGGRR) from an int, an (r, g, b) tuple or ``"transparent"``."""
    if color == "transparent":
        return TRANSPARENT
    if isinstance(color, tuple):
        r, g, b = color
        return (b << 16) | (g << 8) | r
    if isinstance(color, int) and 0 <= color <= 0xFFFFFF:
        return color
    raise ValueError("colour must be (r, g, b), a COLORREF int or 'transparent'")


def _insert_before_version(body, numbers: dict[str, int], item) -> None:
    from .properties import _tag
    tags = [t for t, _ in body]
    version = _tag(numbers["%%xdwapi"]) if "%%xdwapi" in numbers else None
    body.insert(tags.index(version) if version in tags else len(body), item)


def _set_fields_by_name(record: bytes, values: dict[str, int]) -> bytes:
    """Set integer fields of a record that its own name table names."""
    from .properties import _int_payload, _tag
    outer = decode_field(record, 0, len(record))
    body = _fields(record[outer.value_offset:outer.end_offset])
    tags = [t for t, _ in body]
    if tags.count(_TABLE) != 1:
        raise XdwUnsupportedFeatureError("record has no name table")
    numbers = {name: n for n, _, _, name in _parse_table(body[tags.index(_TABLE)][1])}
    for name, number in values.items():
        tag = _tag(numbers[name]) if name in numbers else None
        if tag is None or tag not in tags:
            raise XdwUnsupportedFeatureError(f"annotation has no {name} field")
        # The official writer moves each written attribute, in write order, to
        # just before the version field (named "%%xdwapi"; appearance oracle V1-V9).
        del body[tags.index(tag)]
        _insert_before_version(body, numbers, [tag, _int_payload(number)])
        tags = [t for t, _ in body]
    joined = _join(body)
    return record[:1] + encode_length(len(joined)) + joined


def _restyle_emf(emf: bytes, *, text_color=None, brush_color=None, pen_color=None,
                 transparent_background=False) -> bytes:
    records = _records(emf)
    kinds = [struct.unpack_from("<I", r)[0] for r in records]
    def only(kind):
        at = [i for i, k in enumerate(kinds) if k == kind]
        if len(at) != 1:
            raise XdwUnsupportedFeatureError(f"annotation drawing has {len(at)} records of type {kind}")
        return records[at[0]]
    if text_color is not None:
        # The last SETTEXTCOLOR is the one in effect for the text (official V3 changes only it).
        struct.pack_into("<I", records[max(i for i, k in enumerate(kinds) if k == 24)], 8, text_color)
    if brush_color is not None:
        # The last brush is the fill (a sticky note's first brush is its grey shadow).
        struct.pack_into("<I", records[max(i for i, k in enumerate(kinds) if k == 39)], 16, brush_color)
    if pen_color is not None:
        struct.pack_into("<I", only(38), 24, pen_color)        # CREATEPEN lopnColor
    if transparent_background:
        start = kinds.index(39) - 2
        if kinds[start:start + len(_BACKGROUND_RUN)] != _BACKGROUND_RUN:
            raise XdwUnsupportedFeatureError("unknown background drawing layout")
        del records[start:start + len(_BACKGROUND_RUN)]
        texts = [r for r in records if struct.unpack_from("<I", r)[0] == 84]
        bounds = [struct.unpack_from("<4i", r, 8) for r in texts]
        struct.pack_into("<4i", records[0], 8, min(b[0] for b in bounds), min(b[1] for b in bounds),
                         max(b[2] for b in bounds), max(b[3] for b in bounds))
    out = bytearray(b"".join(records))
    struct.pack_into("<II", out, 48, len(out), len(records))     # header nBytes, nRecords
    return bytes(out)


def _replace_cache(content: bytes, transform) -> bytes:
    """Apply *transform* to the inline appearance EMF (field 87) of a content record."""
    outer = decode_field(content, 0, len(content))
    body = _fields(content[outer.value_offset:outer.end_offset])
    tags = [t for t, _ in body]
    cache = _fields(body[tags.index(b"\x87")][1])
    cache_tags = [t for t, _ in cache]
    get = lambda t: cache[cache_tags.index(t)][1]
    emf = transform(_decode_appearance({t: get(t) for t in (b"\x86", b"\x81")}))
    packed = compress_lzh(emf)
    unsigned = lambda v: v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    for item in cache:
        if item[0] == b"\x86":
            item[1] = packed
        elif item[0] == b"\x81":
            item[1] = unsigned(len(emf))
        elif item[0] == b"\x89":
            item[1] = unsigned(len(packed))
    body[tags.index(b"\x87")][1] = _join(cache)
    return content[:1] + encode_length(len(_join(body))) + _join(body)


def style_text_annotation(group: list[bytes], *, color=None, background=None) -> list[bytes]:
    """Text colour and background (colour or ``"transparent"``) of a text annotation."""
    first, content, *rest = group
    fields = {}
    if color is not None:
        fields["%Color"] = colorref(color)
    if background is not None:
        fields["%ATTR_BKGND_COLOR"] = colorref(background)
    if not fields:
        return group
    content = _set_fields_by_name(content, fields)
    transparent = background is not None and colorref(background) == TRANSPARENT
    content = _replace_cache(content, lambda emf: _restyle_emf(
        emf, text_color=fields.get("%Color"),
        brush_color=None if transparent or background is None else fields["%ATTR_BKGND_COLOR"],
        transparent_background=transparent))
    return [first, content, *rest]


def _resize_shape_emf(emf: bytes, kind: str, width: int, height: int) -> bytes:
    """Redraw the default sticky note / rectangle EMF at width x height (0.01 mm).

    Coordinates follow the official XDW_AddAnnotation output at four sizes
    (oracle A1-A4): W, H = round(size * 300 / 2540) px.
    """
    W, H = round(width * 300 / 2540), round(height * 300 / 2540)
    records = _records(emf)
    kinds = [struct.unpack_from("<I", r)[0] for r in records]
    expected = {"sticky": {1, 9, 76, 43, 30}, "rectangle": {1, 9, 86, 43}}[kind]
    if not expected <= set(kinds):
        raise XdwUnsupportedFeatureError("unknown sticky-note/rectangle drawing layout")
    for r, k in zip(records, kinds):
        if k == 1:
            bounds = (0, 0, W - 1, H - 1) if kind == "sticky" else (-28, -28, W + 28, H + 28)
            struct.pack_into("<4i", r, 8, *bounds)
            struct.pack_into("<4i", r, 24, 0, 0, width, height)                  # rclFrame
            struct.pack_into("<4i", r, 72, W, H, round(width / 100), round(height / 100))
            if len(r) >= 108:
                struct.pack_into("<2i", r, 100, width * 10, height * 10)          # micrometres
        elif k == 9:
            struct.pack_into("<2i", r, 8, W, H)
        elif kind == "sticky" and k == 76:                                         # grey shadow
            struct.pack_into("<4i", r, 8, 6, 6, W - 1, H - 1)
            struct.pack_into("<4i", r, 24, 6, 6, W - 6, H - 6)
        elif kind == "sticky" and k == 43:
            struct.pack_into("<4i", r, 8, 0, 0, W - 7, H - 7)
        elif kind == "sticky" and k == 30:
            struct.pack_into("<4i", r, 8, 1, 1, W - 7, H - 7)
        elif kind == "rectangle" and k == 86:
            struct.pack_into("<4i", r, 8, 2, 2, W - 2, H - 2)
            struct.pack_into("<8h", r, 28, 2, 2, 2, H - 2, W - 2, H - 2, W - 2, 2)
        elif kind == "rectangle" and k == 43:
            struct.pack_into("<4i", r, 8, 0, 0, W - 1, H - 1)
    return b"".join(records)


def resize_shape_annotation(group: list[bytes], kind: str, width: int, height: int) -> list[bytes]:
    """Set a sticky note's or rectangle's size (0.01 mm), redrawing its appearance."""
    if width <= 0 or height <= 0:
        raise ValueError("size must be positive")
    first, content, *rest = group
    pair = _pair(width, height)
    outer = decode_field(first, 0, len(first))
    head = _fields(first[outer.value_offset:outer.end_offset])
    for item in head:
        if item[0] == b"\x9f\x8f\x51":
            item[1] = pair
    first = first[:1] + encode_length(len(_join(head))) + _join(head)
    outer = decode_field(content, 0, len(content))
    body = _fields(content[outer.value_offset:outer.end_offset])
    for item in body:
        if item[0] == b"\x85":
            item[1] = pair
    content = content[:1] + encode_length(len(_join(body))) + _join(body)
    content = _replace_cache(content, lambda emf: _resize_shape_emf(emf, kind, width, height))
    W, H = round(width * 300 / 2540), round(height * 300 / 2540)
    outer = decode_field(content, 0, len(content))
    body = _fields(content[outer.value_offset:outer.end_offset])
    tags = [t for t, _ in body]
    cache = _fields(body[tags.index(b"\x87")][1])
    unsigned = lambda v: v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    for item in cache:
        item[1] = {b"\x84": unsigned(width), b"\x85": unsigned(height),
                   b"\x90": unsigned(W), b"\x91": unsigned(H)}.get(item[0], item[1])
    body[tags.index(b"\x87")][1] = _join(cache)
    content = content[:1] + encode_length(len(_join(body))) + _join(body)
    return [first, content, *rest]


def style_shape_annotation(group: list[bytes], kind: str, *, fill=None, border=None) -> list[bytes]:
    """Fill colour of a sticky note or rectangle, and a rectangle's border colour."""
    first, content, *rest = group
    names = {"sticky": ("FSN_COLOR", None), "rectangle": ("RECTATT_RECTCOLOR", "RECTATT_LINECOLOR")}[kind]
    fields = {}
    if fill is not None:
        fields[names[0]] = colorref(fill)
    if border is not None:
        if names[1] is None:
            raise XdwUnsupportedFeatureError("sticky notes have no border colour")
        fields[names[1]] = colorref(border)
    if not fields:
        return group
    content = _set_fields_by_name(content, fields)
    content = _replace_cache(content, lambda emf: _restyle_emf(
        emf, brush_color=fields.get(names[0]), pen_color=fields.get(names[1]) if names[1] else None))
    return [first, content, *rest]


def rewrite_text_annotation(group: list[bytes], text: str, *, unicode: bool | None = None,
                            font_size: float | None = None) -> list[bytes]:
    """Return the annotation's records with *text* as its string and appearance.

    ``unicode`` chooses how the string is stored: UTF-16 (as the official W API
    writes) or single-byte; by default UTF-16 only for non-ASCII text.
    """
    if font_size is not None and not math.isfinite(font_size):
        raise ValueError("font_size must be a finite number")
    lines = text.replace("\r\n", "\n").split("\n")
    if not text or any(not line for line in lines) or "\r" in text.replace("\r\n", ""):
        raise XdwUnsupportedFeatureError("text must be non-empty with no empty lines")
    if any(ord(ch) > 0xFFFF for ch in text):
        # one character is two UTF-16 units in the EMF; not compared with the official API yet
        raise XdwUnsupportedFeatureError("characters outside the BMP (e.g. 𠮷, emoji) are not verified")
    text = "\r\n".join(lines)                         # stored with CRLF, as the official API does
    first, content = group[0], group[1]

    outer = decode_field(content, 0, len(content))
    body = _fields(content[outer.value_offset:outer.end_offset])
    tags = [t for t, _ in body]
    if tags.count(b"\x87") != 1 or tags.count(_TEXT) != 1 or tags.count(_TABLE) != 1:
        raise XdwUnsupportedFeatureError("annotation has no inline text appearance to rewrite")
    cache = _fields(body[tags.index(b"\x87")][1])
    cache_tags = [t for t, _ in cache]
    get = lambda t: cache[cache_tags.index(t)][1]
    emf = _decode_appearance({t: get(t) for t in (b"\x86", b"\x81")})
    _check_text_emf(emf)
    _refuse_rotated_text(body, emf)
    emf = _window_from_clip(emf)
    font_tenths = None if font_size is None else round(font_size * 10)
    new_emf, (width, height), frame, device = _rewrite_emf(emf, lines, font_tenths)
    packed = compress_lzh(new_emf)
    unsigned = lambda v: (v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big"))
    for item in cache:
        if item[0] == b"\x86":
            item[1] = packed
        elif item[0] == b"\x81":
            item[1] = unsigned(len(new_emf))
        elif item[0] == b"\x89":
            item[1] = unsigned(len(packed))
        elif item[0] == b"\x84":
            item[1] = unsigned(frame[0])
        elif item[0] == b"\x85":
            item[1] = unsigned(frame[1])
        elif item[0] == b"\x90":
            item[1] = unsigned(device[0])
        elif item[0] == b"\x91":
            item[1] = unsigned(device[1])
    body[tags.index(b"\x87")][1] = _join(cache)

    # text field: single-byte for ASCII, else UTF-16LE with the 9F 44 marker and "(w" name
    wide = (not text.isascii()) if unicode is None else unicode
    if not wide and not text.isascii():
        raise ValueError("non-ASCII text must be stored as UTF-16")
    body[tags.index(_TEXT)][1] = text.encode("utf-16le") + b"\0\0" if wide else text.encode("ascii") + b"\0"
    text_index = tags.index(_TEXT)
    has_mark = text_index + 1 < len(body) and body[text_index + 1][0] == _UNICODE_MARK
    if wide and not has_mark:
        body.insert(text_index + 1, [_UNICODE_MARK, b"\x01\x00"])
    elif not wide and has_mark:
        del body[text_index + 1]
    tags = [t for t, _ in body]
    table = _parse_table(body[tags.index(_TABLE)][1])
    renamed = [(n, k, ("%Text(w" if wide else "%Text") if name in ("%Text", "%Text(w") else name)
               for n, k, _, name in table]
    body[tags.index(_TABLE)][1] = b"".join(_table_entry(n, k, name) for n, k, name in renamed)
    for tag in _SIZE_TAGS:
        if tag in tags:
            body[tags.index(tag)][1] = _pair(width, height)
    new_content = content[:1] + encode_length(len(_join(body))) + _join(body)
    if font_tenths is not None:
        # %Size (1/10 pt) is written first, then the box size fields it changed.
        new_content = _set_fields_by_name(new_content, {"%Size": font_tenths})
        outer = decode_field(new_content, 0, len(new_content))
        body = _fields(new_content[outer.value_offset:outer.end_offset])
        numbers = {name: n for n, _, _, name in _parse_table(body[[t for t, _ in body].index(_TABLE)][1])}
        for tag in _SIZE_TAGS:
            moved = [item for item in body if item[0] == tag]
            if moved:
                body.remove(moved[0])
                _insert_before_version(body, numbers, moved[0])
        new_content = new_content[:1] + encode_length(len(_join(body))) + _join(body)

    # first record: declared annotation size 9F 8F 51
    outer = decode_field(first, 0, len(first))
    head = _fields(first[outer.value_offset:outer.end_offset])
    for item in head:
        if item[0] == b"\x9f\x8f\x51":
            item[1] = _pair(width, height)
    new_first = first[:1] + encode_length(len(_join(head))) + _join(head)
    return [new_first, new_content, *group[2:]]


def _set_named_int(record: bytes, name: str, update) -> tuple[bytes, int]:
    """Apply *update* to the integer field the record's name table calls *name*."""
    outer = decode_field(record, 0, len(record))
    body = _fields(record[outer.value_offset:outer.end_offset])
    tags = [t for t, _ in body]
    if tags.count(_TABLE) != 1:
        raise XdwUnsupportedFeatureError(f"record has no name table for {name}")
    numbers = [n for n, _, _, entry in _parse_table(body[tags.index(_TABLE)][1]) if entry == name]
    if len(numbers) != 1:
        raise XdwUnsupportedFeatureError(f"record has no unique {name} field")
    from .properties import _int_payload, _read_int, _tag
    tag = _tag(numbers[0])
    if tags.count(tag) != 1:
        raise XdwUnsupportedFeatureError(f"{name} field is missing")
    old = _read_int(body[tags.index(tag)][1])
    new = update(old)
    body[tags.index(tag)][1] = _int_payload(new)
    joined = _join(body)
    return record[:1] + encode_length(len(joined)) + joined, new


def new_text_annotation(page_record: bytes, x: int, y: int, text: str, *, unicode: bool | None = None,
                        font_size: float | None = None):
    """``(page_record, records)``: the page record with its annotation counter
    advanced, and the records of a new text annotation numbered from it."""
    from .annotation_templates import TEXT_ANNOTATION
    from .page_metadata import replace_annotation_int_pair
    from .properties import _int_payload
    page_record, number = _set_named_int(page_record, "lastmid", lambda n: n + 1)
    first, content = TEXT_ANNOTATION
    outer = decode_field(content, 0, len(content))
    body = _fields(content[outer.value_offset:outer.end_offset])
    ids = [i for i, (t, _) in enumerate(body) if t == b"\x83"]
    if len(ids) != 1:
        raise XdwUnsupportedFeatureError("template has no unique annotation number")
    body[ids[0]][1] = _int_payload(number)
    content = content[:1] + encode_length(len(_join(body))) + _join(body)
    first = replace_annotation_int_pair(first, b"\x9f\x34", x, y)
    return page_record, rewrite_text_annotation([first, content], text, unicode=unicode, font_size=font_size)


def new_template_annotation(page_record: bytes, template, x: int, y: int):
    """``(page_record, records)`` for a copy of an official annotation *template*
    numbered from the page's ``lastmid`` counter and moved to (x, y)."""
    from .page_metadata import replace_annotation_int_pair
    from .properties import _int_payload
    page_record, number = _set_named_int(page_record, "lastmid", lambda n: n + 1)
    first, content, *rest = template
    outer = decode_field(content, 0, len(content))
    body = _fields(content[outer.value_offset:outer.end_offset])
    ids = [i for i, (t, _) in enumerate(body) if t == b"\x83"]
    if len(ids) != 1:
        raise XdwUnsupportedFeatureError("template has no unique annotation number")
    body[ids[0]][1] = _int_payload(number)
    content = content[:1] + encode_length(len(_join(body))) + _join(body)
    first = replace_annotation_int_pair(first, b"\x9f\x34", x, y)
    return page_record, [first, content, *rest]


# --- rotating annotations with their page (XDW_RotatePage, oracle 2026-10-19 C2-C5) -----------

_CORNERS = {0: (0, 1, 2, 3), 90: (1, 2, 3, 0), 180: (2, 3, 0, 1), 270: (3, 0, 1, 2)}


def _rotate_text_emf(emf: bytes, degrees: int) -> tuple[bytes, int, int]:
    """Redraw a single-line text box rotated with its page; returns (EMF, W', H') in px."""
    records = _records(emf)
    kinds = [struct.unpack_from("<I", r)[0] for r in records]
    texts = [i for i, k in enumerate(kinds) if k == 84]
    windows = [r for r, k in zip(records, kinds) if k == 9]
    if len(texts) != 1 or len(windows) != 1 or kinds.count(86) != 1:
        raise XdwUnsupportedFeatureError("only single-line text annotations rotate with their page")
    W, H = struct.unpack_from("<2i", windows[0], 8)
    quarter = degrees in (90, 270)
    Wn, Hn = (H + 2, W) if quarter else (W, H)
    text = records[texts[0]]
    left, top, right, bottom = struct.unpack_from("<4i", text, 8)
    advance, line = right - left + 1, bottom - top + 1
    if degrees == 90:      # text runs downwards
        ref = (Wn - 20, 19)
        bounds = (ref[0] - line - 2, ref[1], ref[0] - 1, ref[1] + advance)
    elif degrees == 270:   # text runs upwards
        ref = (20, Hn - 20)
        bounds = (ref[0], ref[1] - advance - 1, ref[0] + line + 1, ref[1] - 1)
    else:                  # upside down
        ref = (W - 19, H - 20)
        bounds = (ref[0] - advance - 1, ref[1] - line, ref[0] - 1, ref[1] - 1)
    struct.pack_into("<4i", text, 8, *bounds)
    struct.pack_into("<2i", text, 36, *ref)
    escapement = ((360 - degrees) % 360) * 10
    for r, k in zip(records, kinds):
        if k == 82:
            struct.pack_into("<2i", r, 20, escapement, escapement)        # lfEscapement, lfOrientation
        elif k == 86:                                                      # box outline, corners rotated
            corners = [(0, 0), (Wn, 0), (Wn, Hn), (0, Hn)]
            points = [corners[i] for i in _CORNERS[degrees]]
            struct.pack_into("<8h", r, 28, *(v for p in points for v in p))
            if quarter:
                struct.pack_into("<4i", r, 8, 0, 0, Wn - 1, Hn - 2)
        elif quarter and k == 1:
            frame = struct.unpack_from("<4i", r, 24)
            dev = struct.unpack_from("<4i", r, 72)
            struct.pack_into("<4i", r, 8, 0, 0, Wn - 1, Hn - 2)
            struct.pack_into("<4i", r, 24, 0, 0, frame[3], frame[2])
            struct.pack_into("<4i", r, 72, dev[1], dev[0], dev[3], dev[2])
            if len(r) >= 108:
                um = struct.unpack_from("<2i", r, 100)
                struct.pack_into("<2i", r, 100, um[1], um[0])
        elif quarter and k == 9:
            struct.pack_into("<2i", r, 8, H, W)
        elif quarter and k == 30:
            struct.pack_into("<4i", r, 8, 0, 0, Wn, Hn)
    return b"".join(records), Wn, Hn


# Re-rotating a text annotation that is already rotated (S-4, oracle 2026-10-20
# R1-R10 and follow-up T1-T6). Keys are (current page rotation, window shifted by a
# quarter-to-straight save, step); only transitions observed with XDW_RotatePage
# are reproduced, others are refused.
_VERIFIED_REROTATIONS = {
    (270, False, 90), (270, False, 180), (270, False, 270),  # R3, T2, R1/R6
    (180, False, 90), (180, False, 180), (180, False, 270),  # R4, R5, R7
    (90, False, 90), (90, False, 180), (90, False, 270),     # R8, T3, R6 step 4/T1
    (180, True, 90), (180, True, 180), (180, True, 270),     # T5, T6, R6 step 3
    (0, True, 90),                                           # T4
}


def _single_record(records, kinds, kind):
    found = [r for r, k in zip(records, kinds) if k == kind]
    if len(found) != 1:
        raise XdwUnsupportedFeatureError("only single-line text annotations rotate with their page")
    return found[0]


def _window_is_clip(emf: bytes) -> bool:
    """True when a text box draws in a window equal to its clip rectangle."""
    records = _records(emf)
    kinds = [struct.unpack_from("<I", r)[0] for r in records]
    window = struct.unpack_from("<2i", _single_record(records, kinds, 9), 8)
    clip = struct.unpack_from("<4i", _single_record(records, kinds, 30), 8)
    return clip == (0, 0, *window)


def _unrotated_text_emf(emf: bytes, current: int) -> tuple[bytes, int, int, bool]:
    """Rebuild the unrotated drawing of a text box rotated by *current* degrees.

    Returns (EMF, W0, H0, shifted).  The unrotated window (W0, H0) is the
    rotated window swapped (90/270) or the clip rectangle (0/180); the text
    advance and line height come from the EXTTEXTOUTW bounds.  The result is
    accepted only if rotating it by *current* gives back the input exactly,
    except that a straight (0/180) box may keep a window 2 px higher than its
    clip after a quarter-turn save (``shifted``).
    """
    records = [bytearray(r) for r in _records(emf)]
    kinds = [struct.unpack_from("<I", r)[0] for r in records]
    for kind in (1, 9, 30, 84, 86):
        _single_record(records, kinds, kind)
    W, H = struct.unpack_from("<2i", _single_record(records, kinds, 9), 8)
    clip = struct.unpack_from("<4i", _single_record(records, kinds, 30), 8)
    left, top, right, bottom = struct.unpack_from("<4i", _single_record(records, kinds, 84), 8)
    if current in (90, 270):
        W0, H0 = H, W
        advance, line = bottom - top, right - left - 1
    else:
        if clip[:2] != (0, 0):
            raise XdwUnsupportedFeatureError("unknown rotated text box layout")
        W0, H0 = clip[2], clip[3]
        if current == 180:
            advance, line = right - left, bottom - top + 1
        else:
            advance, line = right - left + 1, bottom - top + 1
    for r, k in zip(records, kinds):
        if k == 1:
            frame = struct.unpack_from("<4i", r, 24)
            dev = struct.unpack_from("<4i", r, 72)                    # szlDevice, szlMillimeters
            struct.pack_into("<4i", r, 8, 0, 0, W0 - 2, H0 - 1)
            if current in (90, 270):
                struct.pack_into("<4i", r, 24, 0, 0, frame[3], frame[2])
                struct.pack_into("<4i", r, 72, dev[1], dev[0], dev[3], dev[2])
                if len(r) >= 108:
                    um = struct.unpack_from("<2i", r, 100)
                    struct.pack_into("<2i", r, 100, um[1], um[0])
        elif k == 9:
            struct.pack_into("<2i", r, 8, W0, H0)
        elif k == 30:
            struct.pack_into("<4i", r, 8, 0, 0, W0, H0)
        elif k == 82:
            struct.pack_into("<2i", r, 20, 0, 0)
        elif k == 84:
            struct.pack_into("<4i", r, 8, 20, 20, 20 + advance - 1, 20 + line - 1)
            struct.pack_into("<2i", r, 36, 20, 20)
        elif k == 86:
            struct.pack_into("<4i", r, 8, 0, 0, W0 - 2, H0 - 1)
            struct.pack_into("<8h", r, 28, 0, 0, W0, 0, W0, H0, 0, H0)
    unrotated = b"".join(records)
    again = _records(_rotate_text_emf(unrotated, current)[0] if current else unrotated)
    shifted = False
    for original, rebuilt, k in zip(_records(emf), again, kinds):
        if original == rebuilt:
            continue
        if (k == 9 and current in (0, 180) and original[:8] == rebuilt[:8]
                and struct.unpack_from("<2i", original, 8) == (W0, H0 + 2)):
            shifted = True
            continue
        raise XdwUnsupportedFeatureError("rotated text box does not match the verified layout")
    return unrotated, W0, H0, shifted


def _rerotate_text_emf(emf: bytes, current: int, degrees: int) -> tuple[bytes, int, int, int, int]:
    """Rotate an already rotated text box by *degrees* more, as XDW_RotatePage does.

    The drawing is the unrotated box rotated by the total angle; the window
    is the previous clip rectangle turned by the step (height and width
    swapped for a quarter turn).  Returns (EMF, W', H', W0, H0).
    """
    unrotated, W0, H0, shifted = _unrotated_text_emf(emf, current)
    if (current, shifted, degrees) not in _VERIFIED_REROTATIONS:
        raise XdwUnsupportedFeatureError(
            f"rotating a text annotation from {current} by {degrees} degrees is not verified "
            "against the official API")
    total = (current + degrees) % 360
    out, Wn, Hn = _rotate_text_emf(unrotated, total) if total else (unrotated, W0, H0)
    records = _records(emf)
    kinds = [struct.unpack_from("<I", r)[0] for r in records]
    clip = struct.unpack_from("<4i", _single_record(records, kinds, 30), 8)
    window = (clip[3], clip[2]) if degrees in (90, 270) else (clip[2], clip[3])
    records = [bytearray(r) for r in _records(out)]
    for r in records:
        if struct.unpack_from("<I", r)[0] == 9:
            struct.pack_into("<2i", r, 8, *window)
    return b"".join(records), Wn, Hn, W0, H0


def rotate_annotation_group(group: list[bytes], degrees: int, page_w: int, page_h: int) -> list[bytes]:
    """Rotate one annotation with its page, as XDW_RotatePage does.

    The position turns about the page (sizes before rotation); sticky notes and
    rectangles are redrawn at the swapped size; a single-line text box is redrawn
    with rotated text and ``%TextRotationAngle``. A text box that is already
    rotated is redrawn for the total angle (only transitions verified with the
    official API; see ``_VERIFIED_REROTATIONS``). Other kinds are refused.
    """
    from .page_metadata import replace_annotation_int_pair
    first, content, *rest = group
    outer = decode_field(content, 0, len(content))
    body = _fields(content[outer.value_offset:outer.end_offset])
    kind = body[1][1][2] if len(body) > 1 and body[1][0] == b"\x62" and len(body[1][1]) > 2 else None
    subtype = {0x11: "text", 0x1a: "sticky", 0x3d: "rectangle"}.get(kind)
    if subtype is None or rest:
        raise XdwUnsupportedFeatureError("only text, sticky-note and rectangle annotations rotate with a page")
    head_outer = decode_field(first, 0, len(first))
    head = _fields(first[head_outer.value_offset:head_outer.end_offset])
    head = dict(head)
    if b"\x9f\x34" not in head or b"\x9f\x8f\x51" not in head:
        raise XdwFormatError("annotation has no position or size to rotate")
    x, y = _read_pair(head[b"\x9f\x34"])
    w, h = _read_pair(head[b"\x9f\x8f\x51"])
    if degrees == 90:
        x, y = page_h - (y + h), x
    elif degrees == 180:
        x, y = page_w - (x + w), page_h - (y + h)
    else:
        x, y = y, page_w - (x + w)
    first = replace_annotation_int_pair(first, b"\x9f\x34", x, y)
    quarter = degrees in (90, 270)
    if subtype in ("sticky", "rectangle"):
        if quarter:
            first, content = resize_shape_annotation([first, content], subtype, h, w)
        # A half turn writes only the position (oracle T3); a quarter turn also the size.
        first = _to_front(first, [b"\x9f\x8f\x51", b"\x9f\x34", b"\x9f\x36"] if quarter
                          else [b"\x9f\x34"])
        return [first, _to_front(content, [b"\x85", b"\x87"])]
    # text
    emf = _decode_appearance(dict(_fields(dict(body)[b"\x87"])))
    _check_text_emf(emf)                                        # E0-R: every field read below exists
    polygons = [r for r in _records(emf) if struct.unpack_from("<I", r)[0] == 86]
    if any(struct.unpack_from("<I", r, 24)[0] != 4 for r in polygons):
        # rotation writes the four corners of the box outline
        raise XdwUnsupportedFeatureError("text box outline is not a four-point polygon")
    for r in _records(emf):
        k = struct.unpack_from("<I", r)[0]
        values = (struct.unpack_from("<2i", r, 8) if k == 9 else struct.unpack_from("<4i", r, 8) if k == 30
                  else struct.unpack_from("<4i", r, 8) + struct.unpack_from("<2i", r, 36) if k == 84 else ())
        # the outline corners are 16-bit and a quarter turn adds 2 px (fixtures: 0..2336)
        if any(not 0 <= v <= 32765 for v in values):
            raise XdwUnsupportedFeatureError("text box geometry is outside the supported range")
    current = (360 - _text_rotation_angle(body, emf)) % 360     # page rotation already applied
    total = (current + degrees) % 360
    w0, h0 = w, h                                               # box size before any rotation
    if current in (90, 270):
        w0 = h
    new_size = None
    def transform(emf):
        nonlocal new_size, h0
        if not current and _window_is_clip(emf):
            out, Wn, Hn = _rotate_text_emf(emf, degrees)
        else:
            out, Wn, Hn, W0, H0 = _rerotate_text_emf(emf, current, degrees)
            if current in (90, 270):
                if w != math.ceil((H0 + 2) * 2540 / 300) + 1:
                    raise XdwUnsupportedFeatureError("rotated text box size does not match its drawing")
                h0 = math.ceil(H0 * 2540 / 300) + 1
        new_size = (Wn, Hn)
        return out
    content = _replace_cache(content, transform)
    content = _set_fields_by_name(content, {"%TextRotationAngle": (360 - total) % 360})
    if quarter:
        Wn, Hn = new_size
        if total in (90, 270):
            width = math.ceil(Wn * 2540 / 300) + 1
            height = w0                                         # the unrotated width becomes the height
        else:
            width, height = w0, h0
        pair = _pair(width, height)
        head = _fields(first[head_outer.value_offset:])
        outer_first = decode_field(first, 0, len(first))
        head = _fields(first[outer_first.value_offset:outer_first.end_offset])
        for item in head:
            if item[0] == b"\x9f\x8f\x51":
                item[1] = pair
        first = first[:1] + encode_length(len(_join(head))) + _join(head)
        outer = decode_field(content, 0, len(content))
        body = _fields(content[outer.value_offset:outer.end_offset])
        # %NoRotateTextDim: (unrotated width, new box width), or the unrotated size when straight
        unrotated = _pair(w0, width) if total in (90, 270) else _pair(w0, h0)
        for item in body:
            if item[0] == b"\x85":
                item[1] = pair
            elif item[0] == b"\x9f\x8f\x63":
                item[1] = unrotated
        cache_at = [t for t, _ in body].index(b"\x87")
        cache = _fields(body[cache_at][1])
        swap = {b"\x84": b"\x85", b"\x85": b"\x84", b"\x90": b"\x91", b"\x91": b"\x90"}
        values = dict((t, v) for t, v in cache)
        for item in cache:
            if item[0] in swap:
                item[1] = values[swap[item[0]]]
        body[cache_at][1] = _join(cache)
        content = content[:1] + encode_length(len(_join(body))) + _join(body)
    first = _to_front(first, [b"\x9f\x34", b"\x9f\x8f\x51"] if quarter else [b"\x9f\x8f\x51", b"\x9f\x34"])
    content = _to_front(content, [b"\x9f\x8f\x5b", b"\x85", b"\x9f\x8f\x63", b"\x87"] if quarter
                        else [b"\x9f\x8f\x5b", b"\x87"])
    return [first, content]


def _to_front(record: bytes, order: list[bytes]) -> bytes:
    """Move the named fields, in *order*, to just after the record's 80/62 head
    (where XDW_RotatePage leaves the fields it wrote)."""
    outer = decode_field(record, 0, len(record))
    body = _fields(record[outer.value_offset:outer.end_offset])
    moved = [item for tag in order for item in body if item[0] == tag]
    rest = [item for item in body if item not in moved]
    if [t for t, _ in rest[:2]] != [b"\x80", b"\x62"]:
        raise XdwUnsupportedFeatureError("annotation record does not start with 80/62")
    joined = _join(rest[:2] + moved + rest[2:])
    return record[:1] + encode_length(len(joined)) + joined


def annotation_rotates_with_page(group, *, budget: _DecodeBudget | None = None) -> bool:
    """True for annotations rotate_annotation_group reproduces (single-line text,
    sticky notes and rectangles without child annotations)."""
    if len(group) != 2:
        return False
    first, content = group
    outer = decode_field(content, 0, len(content))
    body = _fields(content[outer.value_offset:outer.end_offset])
    kind = body[1][1][2] if len(body) > 1 and body[1][0] == b"\x62" and len(body[1][1]) > 2 else None
    if kind in (0x1a, 0x3d):
        return True
    if kind != 0x11 or b"\x87" not in [t for t, _ in body]:
        return False
    cache = dict(_fields(dict(body)[b"\x87"]))
    emf = _decode_appearance(cache, budget)
    return [struct.unpack_from("<I", r)[0] for r in _records(emf)].count(84) == 1
