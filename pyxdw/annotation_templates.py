"""Default annotation records, built from their field values.

These are the records ``XDW_AddAnnotation`` writes for a default text annotation
("Hello XDW", MS 明朝 12 pt), sticky note (75 x 25 mm) and rectangle (30 x 20 mm,
optionally with a transparent fill), each at (500, 500) or (2000, 2000) in 0.01 mm.
A record is a BER-like field list: a header (kind 3: position, size), and the
content (kind 4: properties named in a ``9F 33`` table, and the appearance as an
LZH-compressed EMF). New annotations are made from them by changing the number,
position, size, text and colours (see annotation_text.py).
"""

from __future__ import annotations

import struct

from .lzh import compress_lzh
from .page_metadata import _ber_signed_int
from .tlv import encode_length

_FIRST_NAME = 2001          # property numbers start here; field tag 9F 8F 51 is number 2001


def _int(value: int) -> bytes:
    raw = _ber_signed_int(value)
    return bytes([len(raw)]) + raw


def _pair(first: int, second: int) -> bytes:
    return _int(first) + _int(second)


def _raw(value: int) -> bytes:
    return _ber_signed_int(value)


def _record(kind: int, fields) -> bytes:
    body = b"\x80" + encode_length(1) + bytes([kind]) + b"".join(
        tag + encode_length(len(payload)) + payload for tag, payload in fields)
    return b"\x62" + encode_length(len(body)) + body


def _tag(number: int) -> bytes:
    return b"\x9f\x8f" + bytes([0x51 + number - _FIRST_NAME])


def _table(entries, first: int) -> bytes:
    """``9F 33`` payload naming properties ``first, first + 1, ...``: (name, kind)."""
    out = b""
    for number, (name, kind) in enumerate(entries, first):
        raw = name.encode("ascii") + b"\0"
        out += _int(number) + _int(kind) + _int(-1) + _int(len(raw)) + bytes([len(raw)]) + raw
    return out


_INT, _TEXT, _PAIR = 2, 4, 107


def _header(x: int, y: int, w: int, h: int, *, extra=()) -> bytes:
    """Kind-3 record: position and size of the annotation."""
    return _record(3, [(b"\x62", b"\x13\x02"), *extra, (b"\x9f\x34", _pair(x, y)),
                       (b"\x9f\x33", _table([("childdim", _PAIR)], _FIRST_NAME)),
                       (_tag(_FIRST_NAME), _pair(w, h))])


def _content(subtype: int, number: int, before, after, first: int, appearance: bytes, *, size=None) -> bytes:
    """Kind-4 record: properties ``before`` the name table, the table, then ``after``."""
    names = [(name, kind) for name, kind, _ in (*before, *after)]
    values = [value for _, _, value in (*before, *after)]
    tags = [_tag(n) for n in range(first, first + len(names))]
    fields = [(b"\x62", b"\x00\x80" + bytes([subtype]))]
    if size is not None:
        fields.append((b"\x85", _pair(*size)))
    fields += list(zip(tags[:len(before)], values[:len(before)]))
    fields += [(b"\x83", _int(number)), (b"\x9f\x33", _table(names, first))]
    fields += list(zip(tags[len(before):], values[len(before):]))
    return _record(4, [*fields, (b"\x87", appearance)])


def _appearance(emf: bytes, size_mm100: tuple[int, int], size_px: tuple[int, int]) -> bytes:
    packed = compress_lzh(emf)
    items = [(0x80, _raw(4)), (0x81, _raw(len(emf))), (0x84, _raw(size_mm100[0])),
             (0x85, _raw(size_mm100[1])), (0x8D, _raw(1)), (0x90, _raw(size_px[0])),
             (0x91, _raw(size_px[1])), (0x89, _raw(len(packed))), (0x86, packed)]
    return b"".join(bytes([tag]) + encode_length(len(payload)) + payload for tag, payload in items)


# --- EMF ------------------------------------------------------------------------------------

def _emr(kind: int, *values: int, fmt: str | None = None) -> bytes:
    if fmt is None:
        fmt, values = f"<{len(values)}I", [v & 0xFFFFFFFF for v in values]
    payload = struct.pack(fmt, *values)
    return struct.pack("<II", kind, 8 + len(payload)) + payload


def _emf(records: list[bytes], bounds, size_mm100, size_px, *, handles: int, palette: int = 0) -> bytes:
    """EMF with an EMR_HEADER (no description) followed by *records*."""
    w, h = size_mm100
    total = 108 + sum(len(r) for r in records)
    header = struct.pack("<II4i4iIIIIHHIIIiiiiIIIii", 1, 108, *bounds, 0, 0, w, h, 0x464D4520, 0x10000,
                         total, len(records) + 1, handles, 0, 0, 0, palette, *size_px, w // 100, h // 100,
                         0, 0, 0, w * 10, h * 10)
    return header + b"".join(records)


_STOCK = 0x80000000                          # stock object handles: WHITE_BRUSH = _STOCK + 0, ...
_GREYS = [v * 0x11 for v in range(16)]
_CUBE = [(r, g, b) for r in range(0, 256, 51) for g in range(0, 256, 51) for b in range(0, 256, 51)]


def _palette_entries(*, with_duplicates: bool) -> bytes:
    """16 greys followed by the 6x6x6 colour cube (greys of the cube optional)."""
    colours = [(v, v, v) for v in _GREYS]
    colours += [c for c in _CUBE if with_duplicates or c not in colours]
    return b"".join(bytes([r, g, b, 0]) for r, g, b in colours)


def _create_palette(index: int) -> bytes:
    entries = _palette_entries(with_duplicates=True)
    return struct.pack("<IIIHH", 49, 16 + len(entries), index, 0x300, len(entries) // 4) + entries


def _eof_with_palette() -> bytes:
    entries = _palette_entries(with_duplicates=False)
    size = 16 + len(entries) + 4
    return struct.pack("<IIII", 14, size, len(entries) // 4, 16) + entries + struct.pack("<I", size)


def _official_face(face: str) -> str:
    """The face name as XDWAPI 9.0.11 stores it in the EMF: its UTF-8 bytes read as CP932."""
    raw = face.encode("utf-8")
    out, i = [], 0
    while i < len(raw):
        width = 2 if 0x81 <= raw[i] <= 0x9F or 0xE0 <= raw[i] <= 0xFC else 1
        try:
            out.append(raw[i:i + width].decode("cp932"))
        except UnicodeDecodeError:
            out.append("・")                 # an invalid pair becomes one "・"
        i += width
    return "".join(out)


def _font(index: int, height: int, charset: int, pitch: int, face: str) -> bytes:
    """EMR_EXTCREATEFONTINDIRECTW with an ENUMLOGFONTEXDV (no full name, style or axes)."""
    logfont = struct.pack("<5i8B", height, 0, 0, 0, 0, 0, 0, 0, charset, 0, 0, 0, pitch)
    logfont += face.encode("utf-16le").ljust(64, b"\0")
    payload = struct.pack("<I", index) + logfont + bytes(256) + struct.pack("<II", 0x08007664, 0)
    return struct.pack("<II", 82, 8 + len(payload)) + payload


def _text_out(bounds, reference, text: str, advance: int) -> bytes:
    """EMR_EXTTEXTOUTW in GM_ADVANCED with one advance width per character."""
    chars = text.encode("utf-16le")
    chars += bytes(-len(chars) % 4)
    dx = struct.pack(f"<{len(text)}i", *([advance] * len(text)))
    payload = struct.pack("<4iIff", *bounds, 2, 0.0, 0.0)
    payload += struct.pack("<2iIII4iI", *reference, len(text), 76, 0, 0, 0, -1, -1, 76 + len(chars))
    payload += chars + dx
    return struct.pack("<II", 84, 8 + len(payload)) + payload


def _polygon16(bounds, points) -> bytes:
    return _emr(86, *bounds, len(points), *(v for p in points for v in p),
                fmt=f"<4iI{2 * len(points)}h")


def _gdi_comment(*values: int, data: bytes = b"") -> bytes:
    """EMR_GDICOMMENT. A DocuWorks comment (*data* starting with "DW") declares only its
    4-byte identifier as the comment length, as the official writer does."""
    payload = data + struct.pack(f"<{len(values)}I", *values)
    size = 4 if data.startswith(b"DW") else len(payload)
    return struct.pack("<III", 70, 12 + len(payload), size) + payload


_GDIC = 0x43494447                            # "GDIC" public comment identifier


def _box(w: int, h: int):
    return [(0, 0), (w, 0), (w, h), (0, h)]


# --- text annotation ------------------------------------------------------------------------

def _text_emf() -> bytes:
    W, H = 265, 90                            # window, px
    face = _official_face("ＭＳ 明朝")
    records = [
        _emr(10, 0, 0), _emr(9, W, H), _emr(33), _emr(33), _emr(115, 0), _emr(28),
        _emr(37, _STOCK + 0), _emr(37, _STOCK + 7), _emr(37, _STOCK + 14),
        _emr(25, 0xFFFFFF), _emr(24, 0), _emr(18, 2), _emr(19, 1), _emr(20, 13), _emr(21, 1),
        _emr(22, 0), _emr(13, 0, 0), _emr(58, 10), _emr(27, 0, 0), _emr(10, 0, 0), _emr(115, 0),
        _gdi_comment(_GDIC, 2, 0, 0, 0x110, 0x110, 0),
        _create_palette(1), _emr(48, 1), _emr(52),
        _font(2, -50, 0x80, 0x11, face), _emr(37, 2), _emr(24, 0), _emr(22, 0), _emr(18, 1),
        _emr(30, 0, 0, W, H), _emr(20, 13), _emr(37, _STOCK + 8),
        _emr(39, 3, 0, 0xFFFFFF, 0), _emr(37, 3), _emr(19, 2),
        _polygon16((0, 0, W - 2, H - 1), _box(W, H)),
        _emr(19, 1), _emr(20, 13), _emr(37, _STOCK + 7), _emr(37, _STOCK + 0), _emr(40, 3),
        _font(3, -50, 0x80, 0x11, face), _emr(37, 3),
        _text_out((20, 20, 244, 69), (20, 20), "Hello XDW", 25),
        _emr(37, 2), _emr(40, 3), _emr(37, _STOCK + 13), _emr(40, 2), _emr(18, 2),
        _gdi_comment(_GDIC, 3),
        _emr(34, -1), _emr(48, _STOCK + 15), _emr(34, -1), _emr(40, 1),
        _eof_with_palette(),
    ]
    return _emf(records, (0, 0, W - 2, H - 1), (2300, 800), (W + 6, H + 4), handles=4, palette=226)


def _text_annotation():
    w, h = 2245, 763                          # 0.01 mm
    zero = _int(0)
    before = [("%Face", _TEXT, "ＭＳ 明朝".encode("utf-8") + b"\0"), ("%Style", _INT, zero),
              ("%Size", _INT, _int(120)), ("%Color", _INT, zero), ("%PitchAndFamily", _INT, _int(0x11)),
              ("%CharSet", _INT, _int(0x80)), ("%ATTR_BKGND_COLOR", _INT, _int(0xFFFFFF)),
              ("%Turnover", _INT, zero), ("%TextVerticalWriting", _INT, zero),
              ("%TextRotationAngle", _INT, zero), ("%TextBetweenLine", _INT, _int(100)),
              ("%Spacing", _INT, zero), ("%TopMargin", _INT, _int(170)), ("%LeftMargin", _INT, _int(170)),
              ("%BottomMargin", _INT, _int(170)), ("%RightMargin", _INT, _int(170)),
              ("%AutoResizeHeight", _INT, zero)]
    after_names = [("%NoRotateTextDim", _PAIR), ("%%xdwapi", _TEXT), ("%Text", _TEXT)]
    first = _FIRST_NAME + 1
    names = [(n, k) for n, k, _ in before] + after_names
    tags = {n: _tag(i) for i, (n, _) in enumerate(names, first)}
    # the official writer puts %Text first, then the size, %NoRotateTextDim and %%xdwapi
    fields = [(b"\x62", b"\x00\x80\x11")]
    fields += [(tags[n], v) for n, _, v in before]
    fields += [(b"\x83", _int(2)), (b"\x9f\x33", _table(names, first)),
               (tags["%Text"], b"Hello XDW\0"), (b"\x85", _pair(w, h)),
               (tags["%NoRotateTextDim"], _pair(w, h)), (tags["%%xdwapi"], b"9.0.8.14\0")]
    appearance = _appearance(_text_emf(), (2300, 800), (271, 94))
    return (_header(500, 500, w, h), _record(4, [*fields, (b"\x87", appearance)]))


# --- sticky note ----------------------------------------------------------------------------

def _sticky_emf() -> bytes:
    W, H = 886, 295
    records = [
        _emr(10, 0, 0), _emr(9, W, H),
        _emr(39, 1, 0, 0x999999, 0), _emr(37, 1),
        _emr(76, 6, 6, W - 1, H - 1, 6, 6, W - 6, H - 6, 0x00F00021, 0, 0,   # EMR_BITBLT, PATCOPY shadow
             1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0, 0, 0, 0, 0, 0, fmt="<4i4iI2i6f6I"),
        _emr(37, _STOCK + 0), _emr(40, 1),
        _emr(39, 1, 0, 0xFFFFFF, 0), _emr(37, 1),
        _emr(38, 2, 0, 0, 0, 0x666666), _emr(37, 2),
        _emr(43, 0, 0, W - 7, H - 7),
        _emr(37, _STOCK + 7), _emr(37, _STOCK + 0), _emr(40, 1), _emr(40, 2),
        _emr(33), _emr(30, 1, 1, W - 7, H - 7), _emr(34, -1),
        struct.pack("<IIIII", 14, 20, 0, 16, 20),
    ]
    return _emf(records, (0, 0, W - 1, H - 1), (7500, 2500), (W, H), handles=3)


def _sticky_note():
    w, h = 7500, 2500
    before = [("FSN_COLOR", _INT, _int(0xFFFFFF)), ("%AutoResize", _INT, _int(0))]
    after = [("%%xdwapi", _TEXT, b"9.0.8.14\0")]
    content = _content(0x1A, 3, before, after, _FIRST_NAME,
                       _appearance(_sticky_emf(), (w, h), (886, 295)), size=(w, h))
    return (_header(2000, 2000, w, h, extra=[(b"\x9f\x36", _int(1))]), content)


# --- rectangle ------------------------------------------------------------------------------

def _rectangle_emf(transparent: bool) -> bytes:
    W, H = 354, 236
    outline = _polygon16((2, 2, W - 2, H - 2), [(2, 2), (2, H - 2), (W - 2, H - 2), (W - 2, 2)])
    if transparent:
        # the outline is stored as DocuWorks comments instead of a drawn polygon
        corners = (2, 2, 2, H - 2, W - 2, H - 2, W - 2, 2)
        shape = [_gdi_comment(data=b"DW02"),
                 _gdi_comment(data=b"DW  " + struct.pack("<I8h", 4, *corners)),
                 _gdi_comment(data=b"DW04")]
    else:
        shape = [outline]
    records = [
        _emr(10, 0, 0), _emr(9, W, H), _emr(37, _STOCK + 8), _emr(20, 9 if transparent else 13),
        _emr(39, 1, 0, 0xFFFFFF, 0), _emr(37, 1), _emr(19, 2), *shape,
        _emr(19, 1), _emr(20, 13), _emr(37, _STOCK + 7), _emr(37, _STOCK + 0), _emr(40, 1),
        _emr(38, 1, 6, 4, 0, 0), _emr(37, 1), _emr(37, _STOCK + 5), _emr(20, 13),
        _emr(43, 0, 0, W - 1, H - 1), _emr(20, 13),
        _emr(37, _STOCK + 7), _emr(37, _STOCK + 0), _emr(40, 1),
        struct.pack("<IIIII", 14, 20, 0, 16, 20),
    ]
    return _emf(records, (-28, -28, W + 28, H + 28), (3000, 2000), (W, H), handles=2)


def _rectangle(transparent: bool = False):
    w, h = 3000, 2000
    props = [("ATTR_FRAMETRANSPARENT", _INT, _int(0)), ("RECTATT_LINE", _INT, _int(1)),
             ("RECTATT_THICK", _INT, _int(1)), ("RECTATT_LINECOLOR", _INT, _int(0)),
             ("RECTATT_DRAW", _INT, _int(1)), ("RECTATT_RECTCOLOR", _INT, _int(0xFFFFFF)),
             ("ATTR_FILLTRANSPARENT", _INT, _int(1 if transparent else 0))]
    xdwapi = [("%%xdwapi", _TEXT, b"9.0.8.14\0")]
    before, after = (props[:6], props[6:] + xdwapi) if transparent else (props, xdwapi)
    content = _content(0x3D, 3 if transparent else 2, before, after, _FIRST_NAME,
                       _appearance(_rectangle_emf(transparent), (w, h), (354, 236)), size=(w, h))
    return (_header(500, 500, w, h), content)


TEXT_ANNOTATION = _text_annotation()
STICKY_NOTE = _sticky_note()
RECTANGLE = _rectangle()
RECTANGLE_TRANSPARENT = _rectangle(transparent=True)
