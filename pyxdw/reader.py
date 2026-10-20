"""High-level, read-only XDW document model.

The implementation deliberately exposes only structures verified against real
samples.  It resolves append-only directory generations, groups known page
resource layouts, decodes the observed raw LZH payloads, and can reproduce an
earlier on-disk generation byte-for-byte.
"""

from __future__ import annotations

import os
import hashlib
import re
import struct
from dataclasses import dataclass, field, replace
from functools import cached_property
from pathlib import Path
from typing import BinaryIO, Sequence

from .errors import (
    XdwError,
    XdwNotXdwError,
    XdwProtectedDocumentError,
    XdwFormatError,
    XdwLimitError,
    XdwUnsupportedFeatureError,
    XdwUnsupportedLayoutError,
)
from .limits import XdwLimits, _DecodeBudget, budget_of
from .emf import EmfTextRecord, emf_text_records, extract_emf_text
from .lzh import LzhDecodeError
from .page_metadata import ber_fields, page_blocks, resource_references
from .tiff import wrap_ccitt_group3_tiff, wrap_ccitt_group4_tiff
from .tlv import TlvField, decode_field, parse_sequence, unsigned_be, value

Pathish = str | os.PathLike[str]


class _ReaderData(bytes):
    """Input bytes that also carry the reader's ``budget``.

    Every resource, generation and page keeps a reference to these bytes, so
    lazily decoded data is charged to the reader it came from.
    """


def _require_image(budget: _DecodeBudget, width: int, height: int, size: int) -> None:
    budget.require("max_image_dimension", max(width, height))
    budget.require("max_image_bytes", size)


@dataclass(frozen=True)
class XdwProtectionInfo:
    """Security envelope information readable without decrypting document data.

    ``UNKNOWN_SECU003`` means the protection kind is not yet verified. For
    this envelope ``raw_kind`` preserves the word at record offset 4; its
    meaning is unconfirmed and must not be interpreted as a vendor enum.
    """

    kind: str
    permissions: tuple[str, ...]
    raw_kind: int
    raw_permissions: int
    resource_tag: int | None


@dataclass(frozen=True)
class XdwProtectedResource:
    """Opaque resource in a protected XDW directory.

    The payload is intentionally not returned: for observed protected documents the
    0x67 value is an encrypted envelope and its key derivation is not part of
    the verified reader.  A digest and offsets are enough to compare files and
    detect loss or reordering without accidentally treating ciphertext as a
    decoded resource.
    """

    index: int
    offset: int
    tag: int
    length: int
    sha256: str


def inspect_protected_resources(
    source: Pathish | BinaryIO | bytes | bytearray | memoryview,
) -> tuple[XdwProtectedResource, ...]:
    """List observed Pswd128/SECU003 resources without attempting decryption."""

    data = _read_input(source)
    for offset in range(max(0, len(data) - 4096), len(data) - 1):
        if data[offset] not in (0x65, 0x68):
            continue
        try:
            directory = decode_field(data, offset, len(data))
            if directory.end_offset != len(data):
                continue
            fields = _field_map(data, directory)
            if value(data, fields[0x88]) not in (b"SECU003\x00", b"Pswd128\x00", b"DWSPswd\x00"):
                continue
            resources = []
            for index, resource_offset in enumerate(_directory_offsets(data, directory)):
                resource = decode_field(data, resource_offset, directory.offset)
                payload = data[resource.value_offset : resource.end_offset]
                resources.append(
                    XdwProtectedResource(
                        index,
                        resource.offset,
                        resource.tag,
                        resource.length,
                        hashlib.sha256(payload).hexdigest(),
                    )
                )
            return tuple(resources)
        except (KeyError, XdwFormatError):
            continue
    return ()


def inspect_protection(
    source: Pathish | BinaryIO | bytes | bytearray | memoryview,
) -> XdwProtectionInfo | None:
    """Return observed XDW security information, or ``None`` when absent.

    This reads only the terminal directory envelope. It does not authenticate,
    decrypt resources, or bypass document permissions.
    """
    data = _read_input(source)
    for offset in range(max(0, len(data) - 4096), len(data) - 1):
        if data[offset] not in (0x65, 0x68):
            continue
        try:
            directory = decode_field(data, offset, len(data))
            if directory.end_offset != len(data):
                continue
            fields = _field_map(data, directory)
            marker = value(data, fields[0x88])
            record = value(data, fields[0x89])
            offsets = _directory_offsets(data, directory)
            if marker in (b"Pswd128\x00", b"DWSPswd\x00") and len(record) == 72:
                # Controlled Windows compatibility pairs and permission changes
                # match these positions; offset 4 is not a confirmed kind.
                raw_kind = int.from_bytes(record[56:60], "little")
                raw_permissions = int.from_bytes(record[60:64], "little")
            elif marker == b"SECU003\x00" and len(record) == 96:
                # The first compatibility oracle did not collect protection_info().
                # Offset 4 cannot be mapped to a vendor enum from its value
                # alone: Pswd128 demonstrates that this inference is unsafe.
                raw_kind = int.from_bytes(record[4:8], "little")
                raw_permissions = int.from_bytes(record[84:88], "little")
            else:
                continue
            names = (
                (0x02, "EDIT_DOCUMENT"),
                (0x04, "EDIT_ANNOTATION"),
                (0x08, "PRINT"),
                (0x10, "COPY"),
            )
            resource_tag = (
                decode_field(data, offsets[0], directory.offset).tag
                if offsets
                else None
            )
            return XdwProtectionInfo(
                "UNKNOWN_SECU003" if marker == b"SECU003\x00" else {
                    1: "PASSWORD",
                    3: "PASSWORD128",
                    4: "PKI",
                    5: "STAMP",
                    6: "CONTEXT_SERVICE",
                    7: "PASSWORD256",
                    8: "PKI256",
                }.get(raw_kind, f"UNKNOWN_{raw_kind}"),
                tuple(name for bit, name in names if raw_permissions & bit),
                raw_kind,
                raw_permissions,
                resource_tag,
            )
        except (KeyError, XdwFormatError):
            continue
    return None


def _read_input(source: Pathish | BinaryIO | bytes | bytearray | memoryview) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        return bytes(source)
    if hasattr(source, "read"):
        result = source.read()
        if not isinstance(result, bytes):
            raise TypeError("binary file object must return bytes")
        return result
    return Path(source).read_bytes()


def _field_map(data: bytes, parent: TlvField) -> dict[int, TlvField]:
    fields = parse_sequence(data, parent.value_offset, parent.end_offset)
    result = {}
    for field in fields:
        if field.tag in result:
            raise XdwFormatError(
                f"0x{parent.offset:X}: duplicate child tag 0x{field.tag:02X}"
            )
        result[field.tag] = field
    return result


@dataclass(frozen=True, repr=False)
class XdwResource:
    """A directory resource or verified inline metadata payload.

    Inline payload offsets refer to decoded metadata, rather than file bytes.
    """

    _data: bytes = field(repr=False, compare=False)
    field: TlvField
    identifier: int
    identifier_size: int
    payload: TlvField
    fields: dict[int, TlvField] | None
    resource_type: int | None
    is_jpeg: bool
    declared_decoded_size: int | None = None

    def __repr__(self) -> str:
        # ``field`` is this class's own attribute name for its TlvField (a
        # dataclass field, hence the shadowing), not the ``dataclasses.field``
        # used above -- a custom repr sidesteps that and, more usefully, skips
        # the deeply nested TlvField/dict detail the default one would print.
        return (
            f"XdwResource(offset=0x{self.offset:X}, identifier=0x{self.identifier:08X}, "
            f"resource_type={'JPEG' if self.is_jpeg else self.resource_type}, "
            f"payload_len={self.payload.length})"
        )

    @classmethod
    def from_field(cls, data: bytes, field: TlvField) -> "XdwResource":
        if field.tag != 0x64:
            raise XdwFormatError(f"0x{field.offset:X}: expected resource tag 0x64")
        children = parse_sequence(data, field.value_offset, field.end_offset)
        if len(children) != 2 or [child.tag for child in children] != [0x81, 0x82]:
            raise XdwFormatError(f"0x{field.offset:X}: unknown resource envelope")
        identifier_field, payload = children
        if not 1 <= identifier_field.length <= 4:
            raise XdwFormatError(f"0x{field.offset:X}: identifier is not 1..4 bytes")
        identifier = unsigned_be(data, identifier_field)

        payload_bytes = value(data, payload)
        is_jpeg = (
            len(payload_bytes) >= 19
            and payload_bytes[16:19] == b"\xff\xd8\xff"
            and payload_bytes.endswith(b"\xff\xd9")
        )
        fields = None
        resource_type = None
        if not is_jpeg:
            try:
                parsed = parse_sequence(data, payload.value_offset, payload.end_offset)
            except XdwFormatError:
                pass
            else:
                fields = {child.tag: child for child in parsed}
                type_field = fields.get(0x80)
                if type_field is not None:
                    resource_type = unsigned_be(data, type_field)

        return cls(
            data,
            field,
            identifier,
            identifier_field.length,
            payload,
            fields,
            resource_type,
            is_jpeg,
        )

    @property
    def offset(self) -> int:
        return self.field.offset

    @property
    def end_offset(self) -> int:
        return self.field.end_offset

    @property
    def raw_bytes(self) -> bytes:
        return self._data[self.field.offset : self.field.end_offset]

    @property
    def payload_bytes(self) -> bytes:
        return value(self._data, self.payload)

    def field_int(self, tag: int, byteorder: str = "big") -> int | None:
        if self.fields is None or tag not in self.fields:
            return None
        return int.from_bytes(value(self._data, self.fields[tag]), byteorder)

    @property
    def width_mm(self) -> float | None:
        raw = self.field_int(0x84)
        return raw / 100 if raw is not None else None

    @property
    def height_mm(self) -> float | None:
        raw = self.field_int(0x85)
        return raw / 100 if raw is not None else None

    @property
    def pixel_width(self) -> int | None:
        if self.resource_type == 7:
            return self._dib_dimensions[0] if self._dib_dimensions else None
        return self.field_int(0x90) or self.field_int(0x87)

    @property
    def pixel_height(self) -> int | None:
        if self.resource_type == 7:
            return self._dib_dimensions[1] if self._dib_dimensions else None
        return self.field_int(0x91) or self.field_int(0x88)

    @cached_property
    def _dib_dimensions(self) -> tuple[int, int] | None:
        data = self.encoded_data
        if data is None or len(data) < 40:
            return None
        header, width, height, planes, depth = struct.unpack_from('<IiiHH', data)
        if header != 40 or width <= 0 or height <= 0 or planes != 1 or depth not in (1, 4, 8, 24):
            return None
        return width, height

    @property
    def dpi(self) -> tuple[float, float] | None:
        if not all(
            (self.width_mm, self.height_mm, self.pixel_width, self.pixel_height)
        ):
            return None
        return (
            self.pixel_width * 25.4 / self.width_mm,
            self.pixel_height * 25.4 / self.height_mm,
        )

    @property
    def encoded_data(self) -> bytes | None:
        if self.fields is None or 0x86 not in self.fields:
            return None
        return value(self._data, self.fields[0x86])

    @cached_property
    def decoded_data(self) -> bytes | None:
        """Decode known headerless LZH resource payloads.

        Types 1 (WMF, e.g. a signature stamp's appearance), 2 and 4 carry their
        decoded length in tag 0x81.  Type 7 has an
        additional DIB wrapper and is exposed through ``page.thumbnail``.

        A resource with no ``tag 0x80``-led payload structure (an annotation
        or OCR auxiliary resource; see ``_find_auxiliary_resource_refs``) has
        no such self-describing length, but its decoded size is recovered
        from the referencing page record and set as
        ``declared_decoded_size``.  Its whole payload is the raw LZH stream in
        that case, rather than a length carried in a ``tag 0x86`` sub-field.
        """

        if self.resource_type is None and self.declared_decoded_size is not None:
            try:
                return budget_of(self._data).decompress(
                    self.payload_bytes, self.declared_decoded_size, "max_lzh_output")
            except LzhDecodeError as exc:
                raise XdwFormatError(
                    f"0x{self.offset:X}: invalid auxiliary resource LZH payload"
                ) from exc

        encoded = self.encoded_data
        expected_size = self.field_int(0x81)
        if self.resource_type not in {1, 2, 4} or encoded is None or expected_size is None:
            return None
        try:
            return budget_of(self._data).decompress(encoded, expected_size, "max_lzh_output")
        except LzhDecodeError as exc:
            raise XdwFormatError(
                f"0x{self.offset:X}: invalid type {self.resource_type} LZH payload"
            ) from exc


class XdwMetadata(dict):
    """Document properties: a plain dict, plus pypdf's ``metadata.title`` style access.

    ``metadata["/Title"]`` (pypdf's PDF key spelling) also works for the
    standard properties.
    """

    _PDF_KEYS = {"/Title": "title", "/Author": "author", "/Subject": "subject",
                 "/Keywords": "keywords"}

    def __missing__(self, key):
        if key in self._PDF_KEYS and self._PDF_KEYS[key] in self:
            return self[self._PDF_KEYS[key]]
        raise KeyError(key)

    title = property(lambda self: self.get("title"))
    author = property(lambda self: self.get("author"))
    subject = property(lambda self: self.get("subject"))
    keywords = property(lambda self: self.get("keywords"))


@dataclass(frozen=True)
class XdwRectangle:
    """pypdf-style page box in PDF points (1/72 inch), origin at the bottom left."""

    left: float
    bottom: float
    right: float
    top: float

    @property
    def width(self) -> float:
        return self.right - self.left

    @property
    def height(self) -> float:
        return self.top - self.bottom


@dataclass(frozen=True)
class XdwEmbeddedImage:
    """A directly embedded image whose native bytes can be extracted."""

    index: int
    resource_offset: int
    format: str
    width: int
    height: int
    data: bytes

    @property
    def extension(self) -> str:
        return {"JPEG": ".jpg", "TIFF": ".tif", "BMP": ".bmp"}.get(self.format, ".bin")

    @property
    def name(self) -> str:
        """File name in pypdf's ``page.images`` style (``Im0.jpg``)."""
        return f"Im{self.index}{self.extension}"


@dataclass(frozen=True)
class XdwDibThumbnail:
    """Decoded type-7 DIB thumbnail structure and LZH-compressed pixels."""

    resource_offset: int
    width: int
    height: int
    bits_per_pixel: int
    x_pixels_per_meter: int
    y_pixels_per_meter: int
    palette_bgra: bytes
    compression_kind: int
    uncompressed_size: int
    scanline_count: int
    compressed_data: bytes
    _budget: _DecodeBudget | None = field(default=None, repr=False, compare=False)

    @property
    def palette_entries(self) -> int:
        return len(self.palette_bgra) // 4

    @property
    def row_stride(self) -> int:
        return ((self.width * self.bits_per_pixel + 31) // 32) * 4

    @cached_property
    def decoded_pixels(self) -> bytes:
        try:
            budget = self._budget or _DecodeBudget()
            _require_image(budget, self.width, self.height, self.uncompressed_size)
            return budget.decompress(self.compressed_data, self.uncompressed_size,
                                     "max_image_bytes")
        except LzhDecodeError as exc:
            raise XdwFormatError(
                f"0x{self.resource_offset:X}: invalid type 7 LZH pixel payload"
            ) from exc

    def to_bmp_bytes(self, *, rows_top_down: bool = False) -> bytes:
        """Build a standard BMP file containing the decoded thumbnail.

        ``rows_top_down`` declares that the stored pixel rows run top to bottom;
        they are then reordered so the bottom-up BMP displays upright.
        """

        dib_header = struct.pack(
            "<IiiHHIIiiII",
            40,
            self.width,
            self.height,
            1,
            self.bits_per_pixel,
            0,
            self.uncompressed_size,
            self.x_pixels_per_meter,
            self.y_pixels_per_meter,
            self.palette_entries,
            self.palette_entries,
        )
        pixel_offset = 14 + len(dib_header) + len(self.palette_bgra)
        pixels = self.decoded_pixels
        if rows_top_down:
            stride = self.row_stride
            pixels = b"".join(
                pixels[row * stride:(row + 1) * stride]
                for row in range(len(pixels) // stride - 1, -1, -1)
            ) + pixels[(len(pixels) // stride) * stride:]
        file_header = struct.pack(
            "<2sIHHI", b"BM", pixel_offset + len(pixels), 0, 0, pixel_offset
        )
        return file_header + dib_header + self.palette_bgra + pixels

    def write_bmp(self, destination: Pathish) -> Path:
        path = Path(destination)
        path.write_bytes(self.to_bmp_bytes())
        return path


def _type7_thumbnail(resource: XdwResource) -> XdwDibThumbnail:
    data = resource.encoded_data
    pixel_offset = resource.field_int(0x81)
    if data is None or pixel_offset is None or len(data) < 56:
        raise XdwFormatError(f"0x{resource.offset:X}: truncated type 7 DIB")

    (
        header_size,
        width,
        height,
        planes,
        bits_per_pixel,
        dib_compression,
        image_size,
        x_pixels_per_meter,
        y_pixels_per_meter,
        colors_used,
        _colors_important,
    ) = struct.unpack_from("<IiiHHIIiiII", data)
    if header_size != 40 or width <= 0 or height <= 0 or planes != 1:
        raise XdwFormatError(f"0x{resource.offset:X}: invalid type 7 BITMAPINFOHEADER")
    if dib_compression != 0 or not (
        (bits_per_pixel in (1, 4, 8) and colors_used > 0)
        or (bits_per_pixel == 24 and colors_used == 0)
    ):
        raise XdwFormatError(f"0x{resource.offset:X}: unsupported type 7 DIB layout")
    if pixel_offset != header_size + colors_used * 4:
        raise XdwFormatError(f"0x{resource.offset:X}: invalid type 7 palette extent")
    if pixel_offset + 16 > len(data):
        raise XdwFormatError(f"0x{resource.offset:X}: truncated type 7 pixel wrapper")

    compression_kind, compressed_size, uncompressed_size, scanlines = (
        struct.unpack_from("<IIII", data, pixel_offset)
    )
    compressed_data = data[pixel_offset + 16 :]
    expected_image_size = ((width * bits_per_pixel + 31) // 32) * 4 * height
    if (
        compressed_size != len(compressed_data)
        or uncompressed_size != image_size
        or uncompressed_size != expected_image_size
        or scanlines != height
    ):
        raise XdwFormatError(f"0x{resource.offset:X}: inconsistent type 7 pixel sizes")
    return XdwDibThumbnail(
        resource.offset,
        width,
        height,
        bits_per_pixel,
        x_pixels_per_meter,
        y_pixels_per_meter,
        data[header_size:pixel_offset],
        compression_kind,
        uncompressed_size,
        scanlines,
        compressed_data,
        _budget=budget_of(resource._data),
    )


def _safe_protection(data):
    try:
        return inspect_protection(data)
    except XdwError:
        return None


_NON_XDW_SIGNATURES = (
    (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP (Office document or archive)"),
    (b"\xd0\xcf\x11\xe0", "OLE compound file (legacy Office)"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"\x89PNG", "PNG"),
    (b"II*\x00", "TIFF"),
    (b"MM\x00*", "TIFF"),
)

_TOP_DOWN_THUMBNAIL_MAIN_TYPES = frozenset({5, 8, 9, 10, 11})

# Page layouts the reader recognizes (main resource first, then preview/objects).
SUPPORTED_PAGE_LAYOUTS = (
    "8+2", "9+2", "8+7", "9+7",     # CCITT G3/G4 scan with a BMP or DIB preview
    "5+7", "5+2",                   # JPEG image page
    "4+JPEG*+7",                    # application (EMF) page with optional JPEG objects
    "4+font*+7",                    # application page with embedded TrueType fonts
    "inline EMF (+JPEG*/font*) + 7 or inline preview",   # EMF kept in the page metadata
    "10+7",                         # full-colour image page (pixels not decodable)
    "11+7",                         # MRC page: JPEG background + CCITT G4 foreground masks
    "7", "7+7",                     # legacy full-page mono DIB
)

# page.image_status values: what the browser/consumer can actually obtain.
IMAGE_PIXELS = "PIXELS_AVAILABLE"        # full-resolution page content is decodable
IMAGE_PREVIEW = "PREVIEW_AVAILABLE"      # only the low-resolution preview is decodable
IMAGE_STRUCTURE = "STRUCTURE_ONLY"       # page, size and resources parse; no image

# page.rotation_support values.
ROTATION_VERIFIED = "verified"            # byte-exact against official XDWAPI rotation output
ROTATION_METADATA_ONLY = "metadata_only"  # page metadata rewritten; no official pixel/output check
ROTATION_UNSUPPORTED = "unsupported"      # refused until an official rotated sample is compared


@dataclass(frozen=True)
class XdwAnnotation:
    """An existing top-level annotation, including any nested child records.

    ``subtype`` is the observed XDW marker code, not a guessed label.
    Native text metadata and EMF text can be extracted; outlined glyphs are not OCR'd.
    Instances are read-only. Page edits preserve their records and resources.
    """

    subtype: int
    resources: tuple[XdwResource, ...]
    raw_metadata: bytes = field(repr=False)

    def _first_record_int_pair(self, tag: bytes) -> tuple[int, int] | None:
        """Read ``tag <len> <n><x..> <n><y..>`` inside the annotation's first record."""

        raw = self.raw_metadata
        try:
            record = decode_field(raw, 0, len(raw))
        except XdwFormatError:
            return None
        start = raw.find(tag, record.value_offset, record.end_offset)
        if start < 0:
            return None
        cursor = start + len(tag) + 1               # skip the field's one-byte length
        values = []
        for _ in range(2):
            if cursor >= record.end_offset:
                return None
            size = raw[cursor]
            if not 1 <= size <= 4 or cursor + 1 + size > record.end_offset:
                return None
            values.append(int.from_bytes(raw[cursor + 1:cursor + 1 + size], "big", signed=True))   # BER signed
            cursor += 1 + size
        return values[0], values[1]

    @property
    def position(self) -> tuple[int, int] | None:
        """Top-left (x, y) in 0.01 mm on the page as displayed, or ``None``.

        Field ``9F 34`` of the first record; matches the official XDWAPI
        nHorPos/nVerPos for every annotation of the official annotation
        fixtures (text, sticky note, rectangle). Markers carry no such field.
        """

        return self._first_record_int_pair(b"\x9f\x34")

    @property
    def size(self) -> tuple[int, int] | None:
        """(width, height) in 0.01 mm, or ``None``.

        Field ``9F 8F 51`` of the first record (matches the official XDWAPI
        nWidth/nHeight, including values wider than 16 bits); otherwise the frame
        of the annotation's first EMF drawing.
        """

        declared = self._first_record_int_pair(b"\x9f\x8f\x51")
        if declared is not None:
            return declared
        for resource in self.resources:
            try:
                data = resource.decoded_data
            except XdwLimitError:
                raise
            except XdwFormatError:
                continue
            if data and len(data) >= 88 and data[:4] == b"\x01\x00\x00\x00" and data[40:44] == b" EMF":
                left, top, right, bottom = struct.unpack_from("<4i", data, 24)
                if right > left and bottom > top:
                    return right - left, bottom - top
        return None

    def extract_text(self, extraction_mode: str = "plain") -> str:
        if extraction_mode not in {"plain", "layout"}:
            raise ValueError("extraction_mode must be 'plain' or 'layout'")
        # Native text annotations store %Text directly in the content record.
        # The attribute descriptor distinguishes %Text from %Text(w).
        if self.subtype == 17:
            records = parse_sequence(self.raw_metadata, 0, len(self.raw_metadata))
            if len(records) >= 2:
                record = records[1]
                fields = list(ber_fields(self.raw_metadata, record.value_offset,
                                         record.end_offset))
                descriptors = [self.raw_metadata[pos:end] for tag, _, pos, end in fields
                               if tag == b"\x9f\x33"]
                texts = [self.raw_metadata[pos:end] for tag, _, pos, end in fields
                         if tag == b"\x9f\x8f\x65"]
                if len(texts) == 1 and len(descriptors) == 1:
                    descriptor = descriptors[0]
                    if (descriptor.endswith(b"%Text(w\0") and len(texts[0]) % 2 == 0
                            and texts[0].endswith(b"\0\0")):
                        return texts[0].decode("utf-16-le").rstrip("\0")
                    if descriptor.endswith(b"%Text\0") and texts[0].endswith(b"\0"):
                        return texts[0].rstrip(b"\0").decode("cp932")
        return "\n".join(
            text
            for resource in self.resources
            if resource.resource_type == 4
            if (
                text := extract_emf_text(
                    resource.decoded_data, extraction_mode=extraction_mode
                )
            )
        )


@dataclass(frozen=True)
class XdwOriginalData:
    """Uncompressed original data captured in a verified metadata trailer."""

    name: str
    data: bytes = field(repr=False)


@dataclass(frozen=True)
class XdwMrcSegment:
    """One foreground mask of an MRC page: paint ``value`` where the mask bit is set."""

    x: int
    y: int
    width: int
    height: int
    rgb: tuple[int, int, int]
    value: int
    group4: bytes = field(repr=False)

    def tiff(self, dpi: tuple[float, float]) -> bytes:
        """The mask as a standard Group 4 TIFF (set bit = foreground)."""
        return wrap_ccitt_group4_tiff(self.group4, self.width, self.height, dpi)


@dataclass(frozen=True)
class XdwMrcLayers:
    """Decoded layout of a type-11 ``.ims`` MRC payload.

    Verified on one 8-bit grey page against the official 200 dpi TIFF export:
    upscale the background JPEG to the page size, then paint each segment's
    ``value`` where its mask is set (mean absolute difference 0.68/255, edges only).
    """

    width: int
    height: int
    dpi: tuple[float, float]
    background_width: int
    background_height: int
    background_jpeg: bytes = field(repr=False)
    segments: tuple[XdwMrcSegment, ...] = ()


_IMS_SIGNATURE = b".ims\x00\x00\x01\x00"
_IMS_TRAILER = b"\xed\xfe\xad\xde\x04\x00\x00\x00"


def _parse_ims(data: bytes, where: str) -> XdwMrcLayers:
    if len(data) < 0x60 or not data.startswith(_IMS_SIGNATURE):
        raise XdwUnsupportedLayoutError(f"{where}: type 11 payload is not an observed .ims container")
    width, height, xdpi, ydpi = struct.unpack_from("<4I", data, 0x08)
    bg_width, bg_height = struct.unpack_from("<2I", data, 0x30)
    jpeg_length = struct.unpack_from("<I", data, 0x5C)[0]
    jpeg = data[0x60 : 0x60 + jpeg_length]
    if len(jpeg) != jpeg_length or not jpeg.startswith(b"\xff\xd8\xff") or not jpeg.endswith(b"\xff\xd9"):
        raise XdwFormatError(f"{where}: invalid .ims background JPEG")
    cursor = (0x60 + jpeg_length + 3) & ~3
    segments = []
    while cursor + 4 <= len(data) and struct.unpack_from("<I", data, cursor)[0] == 3:
        if cursor + 0x44 > len(data):
            raise XdwFormatError(f"{where}: truncated .ims segment header")
        f = struct.unpack_from("<17I", data, cursor)
        x, y, w, h = f[1:5]
        length = f[16]
        mask = data[cursor + 0x44 : cursor + 0x44 + length]
        if (len(mask) != length or w == 0 or h == 0 or (f[5], f[6]) != (w, h)
                or x + w > width or y + h > height):
            raise XdwFormatError(f"{where}: inconsistent .ims segment at 0x{cursor:X}")
        segments.append(XdwMrcSegment(x, y, w, h, (f[10], f[11], f[12]), f[13], mask))
        cursor = (cursor + 0x44 + length + 3) & ~3
    if data[cursor:] != _IMS_TRAILER:
        raise XdwUnsupportedLayoutError(f"{where}: unknown .ims record at 0x{cursor:X}")
    return XdwMrcLayers(width, height, (float(xdpi), float(ydpi)), bg_width, bg_height, jpeg, tuple(segments))


@dataclass(frozen=True, repr=False)
class XdwPage:
    """A page inferred from a verified resource grouping."""

    index: int
    generation_index: int
    resources: tuple[XdwResource, ...]
    rotation: int = 0
    auxiliary_resources: tuple[XdwResource, ...] = ()
    _metadata_records: tuple[bytes, ...] = field(default=(), repr=False, compare=False)
    _document_resources: tuple[XdwResource, ...] = field(
        default=(), repr=False, compare=False
    )
    _inline_content: XdwResource | None = field(default=None, repr=False, compare=False)
    _inline_preview: XdwResource | None = field(default=None, repr=False, compare=False)

    def __repr__(self) -> str:
        detail = (
            f", auxiliary_resources={len(self.auxiliary_resources)}"
            if self.auxiliary_resources
            else ""
        )
        return (
            f"XdwPage(index={self.index}, resource_types={self.resource_types}, "
            f"rotation={self.rotation}{detail})"
        )

    @cached_property
    def annotations(self) -> tuple[XdwAnnotation, ...]:
        """Existing annotations in page order, with nested components grouped."""
        records = self._metadata_records[3:]
        starts = []
        for i, record in enumerate(records):
            outer = decode_field(record, 0, len(record))
            if record[outer.value_offset : outer.value_offset + 3] == b"\x80\x01\x03":
                starts.append(i)
        result = []
        for start, end in zip(starts, starts[1:] + [len(records)]):
            group = records[start:end]
            if len(group) < 2:
                raise XdwUnsupportedLayoutError("annotation lacks a content record")
            content = decode_field(group[1], 0, len(group[1]))
            body = group[1][content.value_offset : content.end_offset]
            if body[:7] != b"\x80\x01\x04\x62\x03\x00\x80":
                raise XdwUnsupportedLayoutError("unknown annotation content marker")
            raw = b"".join(group)
            indices = {
                ref.index for ref in resource_references(raw, self._document_resources)
            }
            result.append(
                XdwAnnotation(
                    body[7],
                    tuple(self._document_resources[i] for i in sorted(indices)),
                    raw,
                )
            )
        return tuple(result)

    @property
    def annotation_resources(self) -> tuple[XdwResource, ...]:
        """Auxiliary resources referenced by annotation records, without duplicates."""
        offsets = {r.offset for a in self.annotations for r in a.resources}
        return tuple(r for r in self.auxiliary_resources if r.offset in offsets)

    @property
    def ocr_resources(self) -> tuple[XdwResource, ...]:
        """Auxiliary text/coordinate resources referenced by the core page record."""
        refs = {
            r.index
            for r in resource_references(
                b"".join(self._metadata_records[:3]), self._document_resources
            )
        }
        offsets = {self._document_resources[i].offset for i in refs}
        return tuple(r for r in self.auxiliary_resources if r.offset in offsets)

    @property
    def all_resources(self) -> tuple[XdwResource, ...]:
        """All core, annotation and OCR resources in source storage order."""
        return tuple(
            sorted((*self.resources, *self.auxiliary_resources), key=lambda r: r.offset)
        )

    @property
    def main_resource(self) -> XdwResource:
        if self._inline_content is not None:
            return self._inline_content
        # Embedded fonts may precede the EMF; they are never the page's content.
        return next((r for r in self.resources
                     if not r.is_jpeg
                     and not (r.resource_type is None and r.declared_decoded_size is not None)),
                    self.resources[0])

    @property
    def resource_types(self) -> tuple[int | str | None, ...]:
        return tuple(
            "JPEG" if resource.is_jpeg else resource.resource_type
            for resource in self.resources
        )

    def rotate(self, angle: int) -> "XdwPage":
        """Rotate clockwise by a multiple of 90 degrees (pypdf ``page.rotate``).

        Like pypdf this changes the page object and returns it; the rotation is
        written when the page is added to an :class:`XdwWriter`, subject to
        :attr:`rotation_support`.
        """
        if angle % 90:
            raise ValueError("rotation angle must be a multiple of 90")
        object.__setattr__(self, "rotation", (self.rotation + angle) % 360)
        return self

    @property
    def mediabox(self) -> "XdwRectangle":
        """Displayed page size in PDF points (pypdf ``page.mediabox``)."""
        width, height = self.width_mm, self.height_mm
        if width is None or height is None:
            raise XdwFormatError("page has no recorded size")
        if self.main_resource.resource_type not in {5, 7} and self.rotation in {90, 270}:
            width, height = height, width
        return XdwRectangle(0.0, 0.0, width / 25.4 * 72, height / 25.4 * 72)

    @property
    def width_mm(self) -> float | None:
        if self.main_resource.resource_type in {5, 7} and self.rotation in {90, 270}:
            return self.main_resource.height_mm
        return self.main_resource.width_mm

    @property
    def height_mm(self) -> float | None:
        if self.main_resource.resource_type in {5, 7} and self.rotation in {90, 270}:
            return self.main_resource.width_mm
        return self.main_resource.height_mm

    @property
    def pixel_width(self) -> int | None:
        return self.main_resource.pixel_width

    @property
    def pixel_height(self) -> int | None:
        return self.main_resource.pixel_height

    @property
    def dpi(self) -> tuple[float, float] | None:
        return self.main_resource.dpi

    @cached_property
    def thumbnail(self) -> XdwDibThumbnail | None:
        """Return the decoded type-7 thumbnail structure, if present."""
        if self._inline_preview is not None:
            return _type7_thumbnail(self._inline_preview)
        # A legacy monochrome image uses type 7 for its full-page content.
        # Its independently chunked pixel stream is not a thumbnail stream.
        resources = self.resources[1:] if self.main_resource.resource_type == 7 else self.resources
        for resource in resources:
            if resource.resource_type == 7:
                return _type7_thumbnail(resource)
        return None

    @cached_property
    def images(self) -> tuple[XdwEmbeddedImage, ...]:
        images = []
        for resource in self.resources:
            if resource.resource_type == 5:
                jpeg = _type5_jpeg_payload(resource)
                if (jpeg is None or not resource.pixel_width or not resource.pixel_height):
                    raise XdwFormatError(f"0x{resource.offset:X}: invalid type 5 JPEG")
                images.append(XdwEmbeddedImage(len(images), resource.offset, 'JPEG',
                                               resource.pixel_width, resource.pixel_height, jpeg))
                continue
            if not resource.is_jpeg:
                continue
            payload = resource.payload_bytes
            declared_size, reserved, width, height = struct.unpack_from(
                "<IIII", payload
            )
            jpeg = payload[16:]
            if declared_size != len(payload) or reserved != 0:
                raise XdwFormatError(
                    f"0x{resource.offset:X}: invalid embedded JPEG descriptor"
                )
            images.append(
                XdwEmbeddedImage(
                    len(images), resource.offset, "JPEG", width, height, jpeg
                )
            )
        # pypdf lists a scanned page's own image too: expose the fax/mono page
        # as a lossless standard container (Group 3/4 TIFF or BMP).
        for fmt, getter in (("TIFF", lambda: self.main_image_tiff), ("BMP", lambda: self.main_image_bmp)):
            try:
                data = getter()
            except XdwLimitError:
                raise
            except XdwError:
                data = None
            if data is not None:
                images.append(XdwEmbeddedImage(len(images), self.main_resource.offset, fmt,
                                               self.pixel_width or 0, self.pixel_height or 0, data))
        return tuple(images)

    @cached_property
    def embedded_fonts(self) -> tuple[bytes, ...]:
        """TrueType fonts embedded in an application page (decoded ``.ttf`` bytes)."""
        return tuple(r.decoded_data for r in self.resources
                     if r.resource_type is None and r.declared_decoded_size is not None)

    @cached_property
    def image_draw_order(self) -> tuple[int, ...]:
        """Indices into :attr:`images` (JPEG objects) in the order the page draws them.

        The page record references an embedded JPEG once per placement, so a
        repeated object appears repeatedly. The EMF marks each placement with a
        DocuWorks ``DWc`` GDI comment (destination rectangle, source size,
        SRCCOPY); the n-th comment whose source size equals the n-th entry here
        is where that image goes. This pairs every object on all 93 observed
        pages with JPEG objects (SDK manuals and samples).
        """
        by_offset = {image.resource_offset: image.index for image in self.images if image.format == "JPEG"}
        if not by_offset or not self._document_resources:
            return ()
        refs = resource_references(b"".join(self._metadata_records[:3]), self._document_resources)
        return tuple(by_offset[self._document_resources[r.index].offset]
                     for r in refs if self._document_resources[r.index].offset in by_offset)

    @cached_property
    def application_data(self) -> bytes | None:
        """Return a decoded EMF for an observed type-4 application page."""

        if self._inline_content is not None:
            return self._inline_content.decoded_data
        for resource in self.resources:
            if resource.resource_type == 4:
                return resource.decoded_data
        return None

    @cached_property
    def main_image_tiff(self) -> bytes | None:
        """Return a standard TIFF for an observed type-8/9 monochrome page."""

        resource = self.main_resource
        data = resource.encoded_data
        if resource.resource_type not in {8, 9} or data is None:
            return None
        if self.pixel_width is None or self.pixel_height is None or self.dpi is None:
            raise XdwFormatError(
                f"0x{resource.offset:X}: fax page lacks TIFF dimensions"
            )

        if resource.resource_type == 8:
            if not data:
                raise XdwFormatError(f"0x{resource.offset:X}: truncated type 8 fax")
            # The complete 0x86 value is the byte-aligned Group 3 strip.  The
            # first bytes vary with the image stream; they are not a separate
            # 16-byte synchronization wrapper or universally related length
            # words.  Keep the payload intact and let the TIFF decoder validate
            # truncation and malformed fax data.
            return wrap_ccitt_group3_tiff(
                data, self.pixel_width, self.pixel_height, self.dpi
            )

        return wrap_ccitt_group4_tiff(
            data, self.pixel_width, self.pixel_height, self.dpi
        )

    @cached_property
    def main_image_bmp(self) -> bytes | None:
        """Decode a full-page type-7 bitmap (mono, or 24-bit colour) into a top-down BMP.

        Corpus image exports store a block count followed by independently
        compressed LZH strips. The pixel rows are top-down despite the
        positive height in the embedded BITMAPINFOHEADER.
        """
        resource = self.main_resource
        if resource.resource_type != 7:
            return None
        data = resource.encoded_data
        offset = resource.field_int(0x81)
        if data is None or offset is None or len(data) < 40:
            raise XdwFormatError("truncated full-page DIB")
        header, width, height, planes, depth, compression, image_size, _, _, colors, _ = struct.unpack_from('<IiiHHIIiiII', data)
        palette = (colors or (1 << depth)) if depth <= 8 else colors
        # Mono pages (1 bpp, 2 colours) and, in business drawings, 24 bpp colour
        # pages share the strip layout; the pixels start after the palette.
        if (header != 40 or width <= 0 or height <= 0 or planes != 1
                or depth not in (1, 4, 8, 24) or compression != 0
                or offset != 40 + 4 * palette or offset + 4 > len(data)):
            raise XdwUnsupportedLayoutError("unknown full-page DIB layout")
        stride = ((width * depth + 31) // 32) * 4
        if image_size != stride * height:
            raise XdwFormatError("full-page DIB image size disagrees with dimensions")
        budget = budget_of(resource._data)
        _require_image(budget, width, height, image_size)
        blocks = struct.unpack_from('<I', data, offset)[0]
        if not 1 <= blocks <= height:
            raise XdwFormatError("invalid full-page DIB block count")
        cursor = offset + 4
        rows = 0
        pixels = bytearray()
        for _ in range(blocks):
            if cursor + 12 > len(data):
                raise XdwFormatError("truncated full-page DIB block header")
            encoded_size, decoded_size, scanlines = struct.unpack_from('<III', data, cursor)
            cursor += 12
            if (scanlines <= 0 or rows + scanlines > height
                    or decoded_size != stride * scanlines
                    or encoded_size <= 0 or cursor + encoded_size > len(data)):
                raise XdwFormatError("inconsistent full-page DIB block sizes")
            try:
                pixels.extend(budget.decompress(data[cursor:cursor + encoded_size],
                                                decoded_size, "max_image_bytes"))
            except LzhDecodeError as exc:
                raise XdwFormatError("invalid full-page DIB LZH block") from exc
            cursor += encoded_size
            rows += scanlines
        if rows != height or cursor != len(data):
            raise XdwFormatError("full-page DIB blocks do not cover the image")
        dib = bytearray(data[:offset])
        struct.pack_into('<i', dib, 8, -height)
        return struct.pack('<2sIHHI', b'BM', 14 + offset + len(pixels), 0, 0, 14 + offset) + dib + pixels

    @cached_property
    def mrc_layers(self) -> XdwMrcLayers | None:
        """Background JPEG and G4 foreground masks of a type-11 MRC page."""

        resource = self.main_resource
        if resource.resource_type != 11:
            return None
        data = resource.encoded_data
        if data is None:
            raise XdwFormatError(f"0x{resource.offset:X}: type 11 page lacks a payload")
        return _parse_ims(data, f"0x{resource.offset:X}")

    @property
    def rotation_support(self) -> str:
        """How :meth:`XdwWriter.rotate_page` treats this page (see ROTATION_* constants).

        (8|9)+2 scans and type-4 application pages, and (since the 2026-10-19
        oracle) (11,7) MRC, (9,7) scans, (5,7) JPEG, (10,7) and inline-EMF pages:
        verified against official rotations. Embedded-font pages and anything
        else are refused (the official API also refuses pages with electronic seals).
        """

        types = self.resource_types
        if self._uses_official_rotation:
            return ROTATION_VERIFIED
        if self.annotations:
            # XDW_RotatePage refuses some annotated pages (a stamp, an annotated
            # OCR scan; oracle C7/C8) and redraws the annotations it can rotate;
            # other annotated pages are refused here too.
            return ROTATION_UNSUPPORTED
        if types in {(8, 2), (9, 2)} or (len(types) >= 2 and types[0] == 4 and types[-1] == 7
                                          and None not in types):   # embedded fonts: see below
            return ROTATION_VERIFIED
        return ROTATION_UNSUPPORTED

    @cached_property
    def _annotations_rotate(self) -> bool:
        from .annotation_text import annotation_rotates_with_page
        from .page_metadata import page_blocks as _blocks
        records = list(self._metadata_records)
        starts = [i for i, r in enumerate(records[2:], 2) if b"\x80\x01\x03" in r]
        groups = [records[a:b] for a, b in zip(starts, starts[1:] + [len(records)])]
        try:
            budget = next((r._data.budget for r in (*self.resources, *self._document_resources)
                           if getattr(r._data, "budget", None) is not None), None)
            return bool(groups) and all(annotation_rotates_with_page(g, budget=budget)
                                        for g in groups)
        except XdwLimitError:
            raise
        except XdwError:
            return False

    @property
    def _uses_official_rotation(self) -> bool:
        """Layouts whose XDW_RotatePage rewrite was measured (oracle 2026-10-19 B1-B8)."""
        # Annotations rotate with the page (oracle C2-C5) when every one is a
        # single-line text box, a sticky note or a rectangle without children.
        if self.annotations and not self._annotations_rotate:
            return False
        types = self.resource_types
        if types in {(11, 7), (9, 7), (5, 7), (10, 7)}:
            return True
        if (None in types and types[-1] == 7                      # embedded fonts (oracle F2/F3)
                and [t for t in types if t not in (None, "JPEG")] == [4, 7]):
            return True
        return self._inline_content is not None and types in {(7,), ()}

    @cached_property
    def image_status(self) -> str:
        """``PIXELS_AVAILABLE``, ``PREVIEW_AVAILABLE`` or ``STRUCTURE_ONLY``.

        Pixels means the page's own content can be decoded at full resolution
        (CCITT TIFF, legacy mono DIB, JPEG, or EMF vector content). A type 10
        page is ``PREVIEW_AVAILABLE``: its pixels are kept but not decoded.
        """

        def available(getter) -> bool:
            try:
                return getter() is not None
            except XdwLimitError:
                raise
            except XdwError:
                return False

        main_type = self.main_resource.resource_type
        if (
            available(lambda: self.main_image_tiff)
            or available(lambda: self.main_image_bmp)
            or available(lambda: self.application_data)
            or available(lambda: self.mrc_layers)
            or (main_type == 5 and available(lambda: self.images or None))
        ):
            return IMAGE_PIXELS
        if available(lambda: self.preview_bmp):
            return IMAGE_PREVIEW
        return IMAGE_STRUCTURE

    @cached_property
    def preview_bmp(self) -> bytes | None:
        """Return a standard BMP preview from an observed type-2 or type-7 resource."""

        thumbnail = self.thumbnail
        if thumbnail is not None:
            # Measured against ground-truth page images (the page's own TIFF/JPEG,
            # or the official BMP export for type 10): type-7 thumbnails of type
            # 5/8/9/10/11 pages store their rows top-down (22 + 1 + 1 pages checked), while
            # type-4 application pages' do not. Inline previews are unverified.
            top_down = (
                self._inline_preview is None
                and self.main_resource.resource_type in _TOP_DOWN_THUMBNAIL_MAIN_TYPES
            )
            return thumbnail.to_bmp_bytes(rows_top_down=top_down)
        for resource in self.resources:
            if resource.resource_type != 2:
                continue
            decoded = resource.decoded_data
            if decoded is None or len(decoded) < 54 or decoded[:2] != b"BM":
                continue
            pixel_offset = struct.unpack_from("<I", decoded, 10)[0]
            header_size, width, height, planes, bits_per_pixel = struct.unpack_from(
                "<IiiHH", decoded, 14
            )
            if (
                header_size != 40
                or width <= 0
                or height == 0
                or planes != 1
                or bits_per_pixel not in {1, 4, 8, 24, 32}
            ):
                continue
            row_stride = ((width * bits_per_pixel + 31) // 32) * 4
            image_size = row_stride * abs(height)
            normalized_size = pixel_offset + image_size
            if not 54 <= pixel_offset <= normalized_size <= len(decoded):
                continue

            # Observed type-2 resources carry a complete 8-bit pixel array, but
            # their embedded BMP header reports one quarter of its true length.
            # Normalize the two size fields when exposing a standalone BMP.
            bitmap = bytearray(decoded[:normalized_size])
            struct.pack_into("<I", bitmap, 2, normalized_size)
            struct.pack_into("<I", bitmap, 34, image_size)
            return bytes(bitmap)
        return None

    def extract_images(
        self, directory: Pathish, prefix: str = "image"
    ) -> tuple[Path, ...]:
        """Write directly embedded native images without transcoding."""
        destination = Path(directory)
        destination.mkdir(parents=True, exist_ok=True)
        paths = []
        for image in self.images:
            path = destination / f"{prefix}_{image.index + 1:03d}{image.extension}"
            path.write_bytes(image.data)
            paths.append(path)
        return tuple(paths)

    def extract_preview(self, destination: Pathish) -> Path:
        """Write the embedded low-resolution BMP preview without rendering."""

        data = self.preview_bmp
        if data is None:
            raise XdwUnsupportedLayoutError("page has no decoded BMP preview")
        path = Path(destination)
        path.write_bytes(data)
        return path

    def extract_application(self, destination: Pathish) -> Path:
        """Write the decoded EMF backing an application page."""

        data = self.application_data
        if data is None:
            raise XdwUnsupportedLayoutError(
                "page is not an observed EMF application page"
            )
        path = Path(destination)
        path.write_bytes(data)
        return path

    def extract_main_image(self, destination: Pathish) -> Path:
        """Write a high-resolution mono image (type 7 BMP or type 8/9 TIFF)."""

        data = self.main_image_bmp or self.main_image_tiff
        if data is None:
            raise XdwUnsupportedLayoutError(
                "page has no decoded high-resolution mono image"
            )
        path = Path(destination)
        path.write_bytes(data)
        return path

    @cached_property
    def ocr_text(self) -> str | None:
        """Return recognized OCR text, when this page has an OCR text resource.

        Corpus OCR samples contain two auxiliary resources for a scanned page: a
        UTF-16LE plain-text stream (one page of recognized text, lines
        separated by CRLF) and a same-length-matched array of per-line
        ``[left, top, right, bottom]`` bounding boxes in 1/100 mm.  Neither is
        a self-describing resource (see ``declared_decoded_size`` on
        :class:`XdwResource`), so both decode to opaque bytes; the text
        stream is told apart from the bounding-box array (and from an
        annotation's opaque OLE resource, observed on an unrelated page) by
        checking whether the decoded bytes are valid, mostly-printable
        UTF-16LE -- verified against the 2026-09-04 OCR sample, where the text
        resource decodes cleanly and the bounding-box resource does not.

        Returns ``None`` when the page has no such resource, as opposed to the
        empty string :meth:`extract_text` uses for "no text at all".
        """

        for resource in self.auxiliary_resources:
            if (
                resource.resource_type is not None
                or resource.declared_decoded_size is None
            ):
                continue
            try:
                decoded = resource.decoded_data
            except XdwLimitError:
                raise
            except XdwFormatError:
                continue
            text = _decode_utf16_text_if_plausible(decoded)
            if text is not None:
                return text
        return None

    def extract_text(
        self, extraction_mode: str = "plain", *, include_annotations: bool = False
    ) -> str:
        """Extract basic text from EMF application pages or OCR'd scans.

        Image-only pages without OCR return an empty string. ``layout`` mode
        for an EMF page orders text by coordinates and exposes large
        character/cell gaps as tabs; OCR text has no per-character layout
        information yet, so both modes currently return the same plain text.
        """

        if extraction_mode not in {"plain", "layout"}:
            raise ValueError("extraction_mode must be 'plain' or 'layout'")
        data = self.application_data
        text = (
            extract_emf_text(data, extraction_mode=extraction_mode)
            if data is not None
            else self.ocr_text or ""
        )
        if include_annotations:
            text = "\n".join(
                part
                for part in (
                    text,
                    *(a.extract_text(extraction_mode) for a in self.annotations),
                )
                if part
            )
        return text

    @cached_property
    def text_records(self) -> tuple[EmfTextRecord, ...]:
        """Return positioned EMF text records for an application page."""

        data = self.application_data
        return emf_text_records(data) if data is not None else ()


@dataclass(frozen=True)
class XdwGeneration:
    """One append-only directory generation."""

    index: int
    directory: TlvField
    resources: tuple[XdwResource, ...]
    pages: tuple[XdwPage, ...]
    tag63: TlvField | None
    expanded_metadata_size: int | None
    removed_resource_offsets: tuple[int, ...]
    added_resource_offsets: tuple[int, ...]
    _data: bytes = field(repr=False, compare=False)

    @property
    def end_offset(self) -> int:
        return self.directory.end_offset

    @property
    def index_tag(self) -> int:
        """Return the directory tag (0x68 for v10, 0x65 for observed v7)."""

        return self.directory.tag

    @cached_property
    def index_values(self) -> dict[int, bytes]:
        """Return raw directory field values, including unknown index tags."""

        return {
            field.tag: value(self._data, field)
            for field in parse_sequence(
                self._data,
                self.directory.value_offset,
                self.directory.end_offset,
            )
        }

    @cached_property
    def integrity_field(self) -> TlvField | None:
        """Return the positional four-byte integrity slot two fields after 0x83.

        Compatibility probes show that the reference reader accepts arbitrary tag octets for this
        field and for the intervening compressed-length field, but rejects a
        changed value, a missing field, or inserting another field in those
        positions.  Fields inserted after the slot are ignored by this check.
        Calling it ``tag 0x85`` is therefore too narrow even though the
        compatibility fixtures commonly use that tag.
        """

        fields = parse_sequence(
            self._data,
            self.directory.value_offset,
            self.directory.end_offset,
        )
        for index, candidate in enumerate(fields[:-2]):
            if candidate.tag == 0x83:
                integrity = fields[index + 2]
                return integrity if integrity.length == 4 else None
        return None

    @property
    def integrity_value(self) -> bytes | None:
        """Return the raw positional integrity value, when present."""

        return (
            value(self._data, self.integrity_field)
            if self.integrity_field is not None
            else None
        )

    @property
    def resource_offsets(self) -> tuple[int, ...]:
        return tuple(resource.offset for resource in self.resources)

    @cached_property
    def compressed_metadata(self) -> bytes | None:
        return value(self._data, self.tag63) if self.tag63 is not None else None

    @cached_property
    def metadata(self) -> bytes | None:
        """Return the decoded tag-0x63 metadata stream, when present."""

        compressed = self.compressed_metadata
        if compressed is None or self.expanded_metadata_size is None:
            return None
        try:
            return budget_of(self._data).decompress(
                compressed, self.expanded_metadata_size, "max_metadata")
        except LzhDecodeError as exc:
            raise XdwFormatError(
                f"0x{self.tag63.offset:X}: invalid tag 0x63 LZH payload"
            ) from exc

    @cached_property
    def document_attributes(self) -> dict[str, str | None]:
        """Return ``{name: value}`` for ``%doc_att_*`` fields in this generation.

        Not to be confused with :attr:`metadata`, which is the raw decoded
        tag-0x63 content stream this is extracted from. Values are ``None``
        when the property marker is present but was left unset (e.g. an
        unfilled "author" field). See :func:`_find_document_attributes`.
        """

        return _find_document_attributes(self.metadata)


def _find_preceding_field(
    data: bytes, tag: int, end: int, declared_length: int | None = None
) -> TlvField | None:
    minimum = max(0, end - (declared_length or end) - 6)
    for offset in range(end - 2, minimum - 1, -1):
        if data[offset] != tag:
            continue
        try:
            field = decode_field(data, offset, end)
        except XdwFormatError:
            continue
        if field.end_offset == end and (
            declared_length is None or field.length == declared_length
        ):
            return field
    return None


def _directory_offsets(data: bytes, directory: TlvField) -> tuple[int, ...]:
    fields = _field_map(data, directory)
    try:
        count = unsigned_be(data, fields[0x80])
    except KeyError as exc:
        raise XdwFormatError("directory lacks count or offset table") from exc
    # Legacy v7 generation 0 uses a zero-resource directory without tag 0x81.
    if count == 0 and 0x81 not in fields:
        return ()
    try:
        offsets_blob = value(data, fields[0x81])
    except KeyError as exc:
        raise XdwFormatError("directory lacks count or offset table") from exc
    if len(offsets_blob) % 4:
        raise XdwFormatError("directory offset table is not 4-byte aligned")
    offsets = struct.unpack(f"<{len(offsets_blob) // 4}I", offsets_blob)
    if len(offsets) != count:
        raise XdwFormatError(
            f"directory count {count} does not match {len(offsets)} offsets"
        )
    return tuple(offsets)


def _find_directories(data: bytes) -> tuple[TlvField, ...]:
    directories = []
    for offset, byte in enumerate(data[:-1]):
        if byte != 0x68:
            continue
        try:
            candidate = decode_field(data, offset, len(data))
            offsets = _directory_offsets(data, candidate)
            fields = _field_map(data, candidate)
            declared_self = fields.get(0x86)
            # Every real directory states its own length in 0x86; without it a
            # stray 0x68 byte in a v7 file can parse as an empty "directory".
            if (
                declared_self is None
                or int.from_bytes(value(data, declared_self), "little")
                != candidate.length
            ):
                continue
            for resource_offset in offsets:
                resource_field = decode_field(data, resource_offset, candidate.offset)
                if (resource_field.tag == 0x67 and 0x88 in fields
                        and value(data, fields[0x88]) in (b"SECU003\x00", b"Pswd128\x00")
                        and candidate.end_offset == len(data)):
                    raise XdwProtectedDocumentError(
                        "DocuWorks protected resource layout "
                        f"({value(data, fields[0x88]).rstrip(bytes(1)).decode('ascii')}/tag 0x67) "
                        "is not supported; "
                        "resource directory is readable but resource decoding is unavailable",
                        _safe_protection(data),
                    )
                XdwResource.from_field(data, resource_field)
        except (KeyError, XdwFormatError):
            continue
        directories.append(candidate)
    if not directories:
        raise XdwFormatError("no self-consistent tag 0x68 resource directory found")
    return tuple(directories)


def _find_legacy_directories(data: bytes) -> tuple[TlvField, ...]:
    """Find observed pre-v10 tag-0x65 directories for explicit diagnostics."""
    directories = []
    for offset, byte in enumerate(data[:-1]):
        if byte != 0x65:
            continue
        try:
            candidate = decode_field(data, offset, len(data))
            fields = _field_map(data, candidate)
            declared_self = fields[0x86]
            if int.from_bytes(value(data, declared_self), "little") != candidate.length:
                continue
            if 0x84 not in fields:
                continue
        except (KeyError, XdwFormatError):
            continue
        directories.append(candidate)
    return tuple(directories)


def _decode_utf16_text_if_plausible(data: bytes | None) -> str | None:
    """Decode *data* as UTF-16LE, returning ``None`` if it is not plausibly text.

    Used to tell an OCR text resource apart from other opaque auxiliary
    resources decoded to the same shape of raw bytes (a bounding-box array,
    an OLE object): those are binary and either fail to decode as UTF-16LE at
    all (an odd length, or containing a lone surrogate) or decode to mostly
    unprintable characters, whereas genuine recognized text is almost
    entirely printable.
    """

    if not data or len(data) % 2:
        return None
    try:
        text = data.decode("utf-16-le").rstrip('\0')
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(
        1 for character in text if character.isprintable() or character in "\r\n\t"
    )
    if printable / len(text) < 0.9:
        return None
    return text


def _decode_doc_attribute_text(raw: bytes) -> str | None:
    """Best-effort decode of a ``%doc_att_*`` name/value field.

    Observed samples encode some document-attribute fields as UTF-16LE (e.g.
    "title") and others as single-byte CP932 (e.g. "author", "keywords"),
    apparently depending on how the property was entered, so both are tried.
    An ASCII marker string re-decoded as UTF-16LE happens to still pass the
    plain printable-ratio check (it lands on assigned-but-nonsensical CJK
    codepoints, which Python considers printable), so whichever candidate
    actually matches the ``"%doc_att_"`` marker prefix wins; otherwise UTF-16LE
    is preferred, matching the encoding used for real text values like titles.
    """

    utf16_text = _decode_utf16_text_if_plausible(raw)
    if utf16_text is not None:
        utf16_text = utf16_text.rstrip("\x00")

    cp932_text: str | None = None
    try:
        candidate = raw.decode("cp932")
    except UnicodeDecodeError:
        candidate = None
    if candidate:
        printable = sum(
            1
            for character in candidate
            if character.isprintable() or character in "\r\n\t"
        )
        if printable / len(candidate) >= 0.9:
            cp932_text = candidate.rstrip("\x00")

    if utf16_text is not None and utf16_text.startswith("%doc_att_"):
        return utf16_text
    if cp932_text is not None and cp932_text.startswith("%doc_att_"):
        return cp932_text
    return utf16_text if utf16_text is not None else cp932_text


def _scan_extended_fields(data: bytes) -> list[tuple[int, int, bytes]]:
    """Read extended fields at record boundaries, excluding opaque payload bytes."""
    result = []
    for record in parse_sequence(data, 0, len(data)):
        for tag, start, pos, end in ber_fields(data, record.value_offset, record.end_offset):
            if tag.startswith(b"\x9f\x8f") or tag == b'\x9f\x44':
                result.append((start, end, data[pos:end]))
    return result


def _find_document_attributes(metadata: bytes | None, *, typed=False):
    """Document properties, read through the root record's name table.

    Falls back to :func:`_scan_document_attributes` (the earlier heuristic)
    only when the root record has no recognizable name table.  Plain mode
    returns strings (integers/dates as decimal text, booleans as "1"/"0").
    """
    if not metadata:
        return {}
    from .properties import read_properties
    try:
        root = parse_sequence(metadata, 0, len(metadata))[0]
        properties = read_properties(metadata[root.offset:root.end_offset])
    except (XdwError, IndexError):
        properties = None
    if not properties:
        return _scan_document_attributes(metadata, typed=typed)
    result = {}
    for prop in properties:
        value = prop.value
        if not typed and value is not None and not isinstance(value, str):
            value = str(int(value))
        result[prop.name] = value
    return result


def _scan_document_attributes(metadata: bytes | None, *, typed=False):
    """Return ``{name: value}`` for every ``%doc_att_<name>`` field in *metadata*.

    Each document property (standard ones like ``title``/``author``/
    ``keywords``, and custom attributes stored under ``usrdef_*`` or
    ``N_n``/``T_n``/``V_n`` triples) is encoded as up to three consecutive
    private-class extended-tag fields: a name marker whose decoded text is
    literally ``"%doc_att_<name>"`` (NUL-terminated), an optional two-byte
    type code (first byte ``0x01``), and an optional value.  The value field
    is entirely omitted when the property was never set (observed for an
    unset "author"); this is detected by requiring byte-exact adjacency
    between fields, since an omitted value leaves the next property's marker
    starting immediately where the type code ends with no room for a value.
    """

    if not metadata:
        return {}
    fields = _scan_extended_fields(metadata)
    attributes: dict[str, str | None] = {}
    index = 0
    while index < len(fields):
        start, end, raw = fields[index]
        text = _decode_doc_attribute_text(raw)
        if text is None or not text.startswith("%doc_att_"):
            index += 1
            continue
        name = text[len("%doc_att_") :]
        cursor = index + 1
        cursor_end = end
        type_code = None
        if (
            cursor < len(fields)
            and fields[cursor][0] == cursor_end
            and 2 <= len(fields[cursor][2]) <= 5
            and fields[cursor][2][0] == len(fields[cursor][2]) - 1
        ):
            type_code = int.from_bytes(fields[cursor][2][1:], "big")
            cursor_end = fields[cursor][1]
            cursor += 1
        if (name.startswith('usrdef_') and type_code in (2, 2000000)
                and cursor < len(fields) and fields[cursor][0] == cursor_end
                and metadata[fields[cursor][0]:fields[cursor][0] + 2] == b'\x9f\x44'
                and fields[cursor][2] == b'\x01\x00'):
            cursor_end = fields[cursor][1]
            cursor += 1
        value = None
        if cursor < len(fields) and fields[cursor][0] == cursor_end:
            raw_value = fields[cursor][2]
            if (name.startswith("usrdef_") and type_code in (2, 2000000)
                    and 2 <= len(raw_value) <= 5 and raw_value[0] == len(raw_value) - 1):
                number = int.from_bytes(raw_value[1:], "big", signed=True)
                if type_code == 2 or number in (0, 1):
                    value = bool(number) if type_code == 2000000 else number
                    if not typed:
                        value = str(int(value))
                    cursor += 1
            elif len(raw_value) >= 6:
                candidate = _decode_doc_attribute_text(raw_value)
                if candidate is not None and not candidate.startswith("%doc_att_"):
                    value = candidate
                    cursor += 1
        attributes[name] = value
        index = cursor
    return attributes


def _find_auxiliary_resource_refs(
    metadata: bytes, resources: Sequence[XdwResource]
) -> dict[int, tuple[int, int | None]]:
    """Find validated private BER references and opaque-resource decoded sizes.

    Both fields and integers can have variable lengths. References are read
    at BER boundaries, never inside opaque text, image or object fields.
    """

    return {
        ref.index: (
            (
                ref.decoded_size
                if ref.decoded_size is not None
                else len(resources[ref.index].payload_bytes)
            ),
            (
                len(resources[ref.index].payload_bytes)
                if ref.decoded_size is not None
                else None
            ),
        )
        for ref in resource_references(metadata, resources)
    }


def _page_pattern_end(resources: Sequence[XdwResource], cursor: int) -> int | None:
    """Return where a known page layout starting at *cursor* ends, or ``None``.

    The layouts :func:`_group_core_pages` recognizes: a scan pair (type 8 or
    9 followed by type 2 or a validated type-7 DIB preview), or a
    type-7-terminated page (type 4 -- an
    application/EMF page, optionally followed by JPEGs -- or type 10, a
    full-color image page observed with no JPEGs between it and its type-7
    preview) ending in the type-7 preview/thumbnail.
    """

    if (
        cursor + 1 < len(resources)
        and resources[cursor].resource_type in {8, 9}
        and resources[cursor + 1].resource_type == 2
    ):
        return cursor + 2
    if (
        cursor + 1 < len(resources)
        and resources[cursor].resource_type in {8, 9}
        and resources[cursor + 1].resource_type == 7
        and resources[cursor + 1]._dib_dimensions is not None
    ):
        return cursor + 2
    if resources[cursor].resource_type in {4, 10, 11}:
        end = cursor + 1
        while end < len(resources) and resources[end].is_jpeg:
            end += 1
        if end < len(resources) and resources[end].resource_type == 7:
            return end + 1
    return None


def _type5_jpeg_payload(resource: XdwResource) -> bytes | None:
    """Return a validated type-5 JPEG, removing only zero end padding."""

    encoded = resource.encoded_data or b""
    if (
        resource.resource_type != 5
        or not resource.pixel_width
        or not resource.pixel_height
        or not encoded.startswith(b"\xff\xd8\xff")
    ):
        return None
    end = encoded.rfind(b"\xff\xd9")
    if end < 0 or any(encoded[end + 2 :]):
        return None
    return encoded[: end + 2]


def _type5_jpeg_is_valid(resource: XdwResource) -> bool:
    """Validate the observed type-5 JPEG payload without decoding pixels."""

    return _type5_jpeg_payload(resource) is not None


def _type2_bmp_dimensions(resource: XdwResource) -> tuple[int, int, int] | None:
    """Return dimensions/depth for a validated type-2 BMP preview.

    The type-2 payload is LZH-compressed.  The observed type-5/type-2 layout
    stores a complete uncompressed BMP after expansion; its header's file-size
    word is not reliable in the corpus, so validation uses the pixel offset,
    stride, and available bytes instead.  No image pixels are returned.
    """

    if resource.resource_type != 2:
        return None
    try:
        bitmap = resource.decoded_data
    except XdwLimitError:
        raise
    except XdwFormatError:
        return None
    if bitmap is None or len(bitmap) < 54 or bitmap[:2] != b"BM":
        return None
    try:
        dib_size = struct.unpack_from("<I", bitmap, 14)[0]
        width, height, planes, bits_per_pixel, compression = struct.unpack_from(
            "<iiHHI", bitmap, 18
        )
        pixel_offset = struct.unpack_from("<I", bitmap, 10)[0]
    except struct.error:
        return None
    if (
        dib_size < 40
        or width <= 0
        or height == 0
        or planes != 1
        or bits_per_pixel not in (1, 4, 8, 24, 32)
        or compression != 0
        or pixel_offset < 14 + dib_size
    ):
        return None
    row_stride = ((width * bits_per_pixel + 31) // 32) * 4
    pixel_end = pixel_offset + row_stride * abs(height)
    if pixel_end > len(bitmap):
        return None
    return width, abs(height), bits_per_pixel


def _group_metadata_pages(resources, generation_index, metadata, legacy_layout=False):
    """Assign auxiliaries from page metadata, not physical adjacency.

    OCR for a later page may physically precede its core resources. In a merge
    it must not be attributed to the preceding page's stamp resources.
    """
    _, blocks, _ = page_blocks(metadata)
    pages = []
    assigned = set()
    for block in blocks:
        refs = {r.index for r in resource_references(b"".join(block), resources)}
        # One embedded JPEG object can be drawn on several pages (observed in the
        # official SDK manual TraySPI.xdw); any other sharing is unexplained.
        if any(not resources[i].is_jpeg for i in assigned & refs):
            raise XdwUnsupportedLayoutError("resource is shared across page blocks")
        ordered = [resources[i] for i in sorted(refs)]
        # Corpus samples from the XDWAPI 9 import path (including
        # annotation-upgraded directories) store
        # JPEG content in type 5 plus a type-7 preview, or a full-page mono
        # DIB in a lone type 7. Require metadata ownership and actual payload
        # signatures instead of treating arbitrary type-7 previews as pages.
        core_refs = {r.index for r in resource_references(b"".join(block[:3]), resources)}
        core = [resources[i] for i in sorted(core_refs)]
        # Embedded TrueType fonts: headerless LZH resources referenced from the
        # core record with their decoded size (see XdwPage.embedded_fonts).
        font_sizes = {resources[r.index].offset: r.decoded_size
                      for r in resource_references(b"".join(block[:3]), resources)
                      if resources[r.index].resource_type is None and r.decoded_size}
        core = [replace(r, declared_decoded_size=font_sizes[r.offset]) if r.offset in font_sizes else r
                for r in core]
        structural = [r for r in core if r.offset not in font_sizes]
        # Embedded JPEG objects of an application page may sit anywhere in it.
        objects = [r for r in structural if r.is_jpeg]
        layout = [r for r in structural if not r.is_jpeg]
        content_record = block[2]
        outer = decode_field(content_record, 0, len(content_record))
        inline = {}
        for tag, start, pos, end in ber_fields(content_record, outer.value_offset, outer.end_offset):
            if tag not in (b'\x87', b'\x9f\x3a'):
                continue
            try:
                fields = {f.tag: f for f in parse_sequence(content_record, pos, end)}
                kind = unsigned_be(content_record, fields[0x80])
            except (KeyError, XdwFormatError):
                continue
            if (tag, kind) not in ((b'\x87', 4), (b'\x9f\x3a', 7)):
                continue
            # This is an actual metadata field, not a fabricated file resource.
            payload = TlvField(start, tag[0], pos - start, end - pos)
            inline[tag] = XdwResource(content_record, payload, 0, 0, payload, fields, kind, False)
        if b'\x87' in inline:
            content = inline[b'\x87']
            emf = content.decoded_data
            # The preview is a type-7 resource, or (one page of the official SDK
            # manual XDWAPI.xdw) inline in field 9F 3A as well, leaving the page
            # without any directory resource.
            inline_preview = inline.get(b'\x9f\x3a')
            # ... or absent altogether (business drawings made of annotations).
            preview_ok = ((len(layout) == 1 and layout[0].resource_type == 7)
                          or (not layout and (inline_preview is None
                                              or inline_preview._dib_dimensions is not None)))
            if (not preview_ok or emf is None
                    or len(emf) < 88 or emf[:4] != b'\x01\x00\x00\x00'
                    or emf[40:44] != b' EMF'):
                raise XdwUnsupportedLayoutError('unknown inline application-page layout')
            pages.append(XdwPage(len(pages), generation_index, tuple(core),
                auxiliary_resources=tuple(resources[i] for i in sorted(refs - core_refs)),
                _inline_content=content,
                _inline_preview=inline_preview if not layout else None))
            assigned.update(refs)
            continue
        if (len(core) == 1 and core[0].resource_type == 9
                and core[0].pixel_width and core[0].pixel_height
                and core[0].encoded_data and b'\x9f\x3a' in inline
                and inline[b'\x9f\x3a']._dib_dimensions is not None):
            pages.append(XdwPage(len(pages), generation_index, tuple(core),
                auxiliary_resources=tuple(resources[i] for i in sorted(refs - core_refs)),
                _inline_preview=inline[b'\x9f\x3a']))
            assigned.update(refs)
            continue
        legacy_image = (
            (len(core) == 2 and core[0].resource_type == 5
             and core[1].resource_type == 7
             and _type5_jpeg_is_valid(core[0])
             and core[1]._dib_dimensions is not None)
            or (len(core) == 2
                and _type5_jpeg_is_valid(core[0])
                and _type2_bmp_dimensions(core[1]) is not None)
            or (len(core) == 1 and _type5_jpeg_is_valid(core[0]))   # JPEG page without preview
            or (len(core) in (1, 2) and core[0].resource_type == 7
                and core[0]._dib_dimensions is not None
                and struct.unpack_from('<H', core[0].encoded_data, 14)[0] in (1, 4, 8, 24)
                and (len(core) == 1 or
                     (core[1].resource_type == 7 and core[1]._dib_dimensions is not None)))
        )
        if legacy_image:
            pages.append(XdwPage(len(pages), generation_index, tuple(core),
                auxiliary_resources=tuple(resources[i] for i in sorted(refs - core_refs))))
            assigned.update(refs)
            continue
        # Application page with embedded TrueType fonts: one type-4 EMF, the
        # fonts (before or after it; both observed) and the type-7 preview last.
        if ((font_sizes or (objects and not structural[0].resource_type == 4))
                and [r.resource_type for r in layout] == [4, 7] and structural[-1].resource_type == 7):
            pages.append(XdwPage(len(pages), generation_index, tuple(core),
                auxiliary_resources=tuple(resources[i] for i in sorted(refs - core_refs))))
            assigned.update(refs)
            continue
        matches = [(i, _page_pattern_end(ordered, i)) for i in range(len(ordered))]
        matches = [(start, end) for start, end in matches if end is not None]
        if len(matches) != 1:
            raise XdwUnsupportedLayoutError(
                "page metadata must reference exactly one core page "
                f"(generation {generation_index}, page {len(pages) + 1}, resources "
                + ",".join("JPEG" if r.is_jpeg else str(r.resource_type) for r in ordered)
                + "; supported layouts: " + ", ".join(SUPPORTED_PAGE_LAYOUTS) + ")"
            )
        start, end = matches[0]
        pages.append(
            XdwPage(
                len(pages),
                generation_index,
                tuple(ordered[start:end]),
                auxiliary_resources=tuple(ordered[:start] + ordered[end:]),
            )
        )
        assigned.update(refs)
    if assigned != set(range(len(resources))):
        raise XdwUnsupportedLayoutError(
            "page metadata does not account for all resources"
        )
    return tuple(pages)


def _group_pages(
    resources: Sequence[XdwResource],
    generation_index: int,
    auxiliary_candidates: frozenset[int] = frozenset(),
) -> tuple[XdwPage, ...]:
    """Group resources into pages, setting aside validated extra resources.

    ``auxiliary_candidates`` names resources (by position in ``resources``)
    that a page's metadata references directly by index -- see
    :func:`_find_auxiliary_resource_refs`.  Every sample observed reuses this
    same descriptor mechanism for a page's *own* content/thumbnail resources
    too, so membership in ``auxiliary_candidates`` cannot by itself
    distinguish "extra" resources from core ones -- a known page layout must
    still take priority wherever one matches.

    With no candidates (the common case, resolved without decoding any
    metadata) this is exactly :func:`_group_core_pages`.  Otherwise it walks
    the resources left to right, greedily preferring a known page layout
    (:func:`_page_pattern_end`) at every position and only consuming a
    (candidate-only) run of extras between/around pages when no layout
    matches there.  An extra run before the first recognized page attaches to
    that page; a run anywhere else attaches to the page immediately before
    it.  This was designed against, and is verified against, a single-page
    stamp annotation (extras only follow the one page), single-page OCR
    (extras only precede it), and a two-page document with independent
    annotations on each page (an extra run sits between the two pages' own
    resources, correctly attaching to the first page rather than merging
    everything into one).
    """

    if not auxiliary_candidates:
        return _group_core_pages(resources, generation_index)

    def unsupported_layout() -> XdwUnsupportedLayoutError:
        return XdwUnsupportedLayoutError(
            "unknown page/resource layout: "
            + ",".join(
                "JPEG" if resource.is_jpeg else str(resource.resource_type)
                for resource in resources
            )
        )

    total = len(resources)
    pages: list[XdwPage] = []
    pending_leading: list[XdwResource] = []
    cursor = 0
    while cursor < total:
        end = _page_pattern_end(resources, cursor)
        if end is not None:
            page = XdwPage(len(pages), generation_index, tuple(resources[cursor:end]))
            if pending_leading:
                page = replace(page, auxiliary_resources=tuple(pending_leading))
                pending_leading = []
            pages.append(page)
            cursor = end
            continue
        if cursor in auxiliary_candidates:
            run_start = cursor
            while (
                cursor < total
                and cursor in auxiliary_candidates
                and _page_pattern_end(resources, cursor) is None
            ):
                cursor += 1
            run = tuple(resources[run_start:cursor])
            if pages:
                pages[-1] = replace(
                    pages[-1],
                    auxiliary_resources=pages[-1].auxiliary_resources + run,
                )
            else:
                pending_leading.extend(run)
            continue
        raise unsupported_layout()

    if not pages:
        raise unsupported_layout()
    return tuple(pages)


def _group_core_pages(
    resources: Sequence[XdwResource], generation_index: int
) -> tuple[XdwPage, ...]:
    types = [resource.resource_type for resource in resources]

    # Scanned/image documents observed as (type 8 or 9) + type 2 per page,
    # with a validated type-7 DIB preview in newer files.
    if len(resources) % 2 == 0 and all(
        types[index] in {8, 9}
        and (
            types[index + 1] == 2
            or (
                types[index + 1] == 7
                and resources[index + 1]._dib_dimensions is not None
            )
        )
        for index in range(0, len(resources), 2)
    ):
        return tuple(
            XdwPage(page_index, generation_index, tuple(resources[index : index + 2]))
            for page_index, index in enumerate(range(0, len(resources), 2))
        )

    # One-page object/full-color-image document observed as type 4 or 10 +
    # JPEG objects + type 7 preview.
    if (
        len(resources) >= 2
        and types[0] in {4, 10, 11}
        and types[-1] == 7
        and all(resource.is_jpeg for resource in resources[1:-1])
    ):
        return (XdwPage(0, generation_index, tuple(resources)),)

    # Mixed documents in the XDWAPI compatibility corpus are a sequence of these same page
    # groups (scan pair or type-4/JPEG*/type-7 application page).  The compact
    # parser below also handles the reverse order and repeated application
    # pages, while rejecting any unobserved ambiguity.
    pages: list[XdwPage] = []
    cursor = 0
    while cursor < len(resources):
        if (
            cursor + 1 < len(resources)
            and types[cursor] in {8, 9}
            and types[cursor + 1] == 2
        ):
            pages.append(
                XdwPage(
                    len(pages),
                    generation_index,
                    tuple(resources[cursor : cursor + 2]),
                )
            )
            cursor += 2
            continue
        if (
            cursor + 1 < len(resources)
            and types[cursor] in {8, 9}
            and types[cursor + 1] == 7
            and resources[cursor + 1]._dib_dimensions is not None
        ):
            pages.append(
                XdwPage(
                    len(pages),
                    generation_index,
                    tuple(resources[cursor : cursor + 2]),
                )
            )
            cursor += 2
            continue
        if types[cursor] in {4, 10, 11}:
            end = cursor + 1
            while end < len(resources) and resources[end].is_jpeg:
                end += 1
            if end < len(resources) and types[end] == 7:
                pages.append(
                    XdwPage(
                        len(pages),
                        generation_index,
                        tuple(resources[cursor : end + 1]),
                    )
                )
                cursor = end + 1
                continue
        break
    if pages and cursor == len(resources):
        return tuple(pages)

    raise XdwUnsupportedLayoutError(
        "unknown page/resource layout: "
        + ",".join(
            "JPEG" if resource.is_jpeg else str(resource.resource_type)
            for resource in resources
        )
    )


def _metadata_record_kind(data: bytes, record: TlvField) -> int | None:
    """Read the first one-byte kind from a metadata record."""

    try:
        child = decode_field(data, record.value_offset, record.end_offset)
    except XdwFormatError:
        return None
    if child.tag != 0x80 or child.length != 1:
        return None
    return value(data, child)[0]


def _metadata_page_rotations(metadata: bytes | None) -> tuple[int, ...]:
    """Return observed page rotations encoded by kind-4 ``0x9f3d`` fields."""

    if metadata is None:
        return ()
    try:
        records = parse_sequence(metadata, 0, len(metadata))
    except XdwFormatError:
        return ()
    rotations: list[int] = []
    cursor = 0
    while cursor + 2 < len(records):
        if (
            _metadata_record_kind(metadata, records[cursor]) == 2
            and _metadata_record_kind(metadata, records[cursor + 1]) == 3
            and _metadata_record_kind(metadata, records[cursor + 2]) == 4
        ):
            raw = metadata[records[cursor + 2].offset : records[cursor + 2].end_offset]
            descriptor = raw.find(b"\x9f\x3d")
            rotation = 0
            if descriptor >= 0 and descriptor + 3 < len(raw):
                length = raw[descriptor + 2]
                payload = raw[descriptor + 3 : descriptor + 3 + length]
                if payload == b"\x01\x5a":
                    rotation = 90
                elif payload == b"\x02\x00\xb4":
                    rotation = 180
                elif payload == b"\x02\x01\x0e":
                    rotation = 270
            rotations.append(rotation)
            cursor += 3
        else:
            cursor += 1
    return tuple(rotations)


class XdwReader:
    """Read the verified structural subset of an XDW file.

    ``pages`` represents the last valid directory generation.  ``generations``
    retains earlier append-only states, which can be recovered byte-for-byte with
    :meth:`write_generation`.
    """

    def __init__(
        self,
        source: Pathish | BinaryIO | bytes | bytearray | memoryview,
        *,
        limits: XdwLimits | None = None,
    ) -> None:
        if limits is not None and not isinstance(limits, XdwLimits):
            raise TypeError("limits must be an XdwLimits instance or None")
        self._data = _ReaderData(_read_input(source))
        self._data.budget = _DecodeBudget(limits)
        self._validate_header()
        protection = inspect_protection(self._data)
        if protection and protection.kind == 'PASSWORD' and protection.resource_tag != 0x64:
            raise XdwProtectedDocumentError('DocuWorks protected resource layout (DWSPswd) is not supported; decryption is unavailable', protection)
        try:
            directories = _find_directories(self._data)
            legacy_layout = False
        except XdwFormatError:
            directories = _find_legacy_directories(self._data)
            if not directories:
                raise
            legacy_layout = True

        generations = []
        previous_offsets: tuple[int, ...] = ()
        for index, directory in enumerate(directories):
            offsets = _directory_offsets(self._data, directory)
            resources = tuple(
                XdwResource.from_field(
                    self._data,
                    decode_field(self._data, offset, directory.offset),
                )
                for offset in offsets
            )
            fields = _field_map(self._data, directory)
            declared_tag63 = (
                unsigned_be(self._data, fields[0x84]) if 0x84 in fields else None
            )
            tag63 = _find_preceding_field(
                self._data, 0x63, directory.offset, declared_tag63
            )
            if declared_tag63 is not None and tag63 is None:
                raise XdwFormatError(
                    f"0x{directory.offset:X}: declared tag 0x63 not found"
                )
            expanded_size = (
                unsigned_be(self._data, fields[0x83]) if 0x83 in fields else None
            )
            removed = tuple(
                offset for offset in previous_offsets if offset not in offsets
            )
            added = tuple(
                offset for offset in offsets if offset not in previous_offsets
            )
            if legacy_layout and not resources:
                pages = ()
            else:
                try:
                    try:
                        pages = _group_pages(resources, index)
                    except XdwUnsupportedLayoutError:
                        # A page can reference resources beyond the recognized
                        # type/JPEG/thumbnail sequence (annotation, OCR).  Decode
                        # metadata only on this fallback path so files without
                        # such extras pay no extra cost.
                        auxiliary_refs: dict[int, tuple[int, int | None]] = {}
                        if tag63 is not None and expanded_size is not None:
                            try:
                                metadata = self._data.budget.decompress(
                                    value(self._data, tag63), expanded_size, "max_metadata"
                                )
                            except LzhDecodeError:
                                metadata = None
                            if metadata is not None:
                                auxiliary_refs = _find_auxiliary_resource_refs(
                                    metadata, resources
                                )
                        if not auxiliary_refs:
                            raise
                        # Attach the recovered decoded size to opaque resources so
                        # XdwResource.decoded_data can decompress them later; this
                        # must happen before grouping so pages/auxiliary_resources
                        # hold the updated resource objects.
                        resources = tuple(
                            (
                                replace(
                                    resource,
                                    declared_decoded_size=auxiliary_refs[position][0],
                                )
                                if position in auxiliary_refs
                                and resource.resource_type is None
                                else resource
                            )
                            for position, resource in enumerate(resources)
                        )
                        pages = _group_metadata_pages(resources, index, metadata, legacy_layout)
                except XdwUnsupportedLayoutError:
                    # An earlier append-only generation may hold a transient
                    # state (observed: a page with only its preview); keep it
                    # as page-less history instead of rejecting the document.
                    if index == len(directories) - 1:
                        raise
                    pages = ()
            generation = XdwGeneration(
                index,
                directory,
                resources,
                pages,
                tag63,
                expanded_size,
                removed if index else (),
                added if index else (),
                self._data,
            )
            try:
                rotations = _metadata_page_rotations(generation.metadata)
            except XdwLimitError:
                raise
            except XdwFormatError:
                if legacy_layout:
                    raise XdwUnsupportedLayoutError(
                        "format version 7 legacy tag 0x65 directory has undecodable metadata"
                    ) from None
                raise
            if (len(rotations) > len(pages) and generation.metadata is not None
                    and not legacy_layout):
                # The resource-only grouping cannot see a page that owns no
                # resource (EMF and preview both inline); trust the metadata.
                pages = _group_metadata_pages(resources, index, generation.metadata, legacy_layout)
                generation = replace(generation, pages=pages)
            if len(rotations) == len(pages):
                pages = tuple(
                    replace(page, rotation=rotations[page.index]) for page in pages
                )
                generation = replace(generation, pages=pages)
            if pages and generation.metadata is not None:
                try:
                    _, blocks, _ = page_blocks(generation.metadata, len(pages))
                except XdwUnsupportedLayoutError:
                    blocks = ()
                if blocks:
                    pages = tuple(
                        replace(
                            page,
                            _metadata_records=blocks[page.index],
                            _document_resources=resources,
                        )
                        for page in pages
                    )
                    generation = replace(generation, pages=pages)
            generations.append(generation)
            previous_offsets = offsets

        self.generations = tuple(generations)
        self.current_generation = self.generations[-1]
        self.pages = self.current_generation.pages
        # A document's current directory must describe at least one page.
        # Older append-only generations may legitimately be empty (for example
        # the initial generation retained before a page is added), so validate
        # only the public current generation. Without this guard, truncated
        # inputs could be accepted as a seemingly valid zero-page document.
        if not self.pages:
            raise XdwFormatError("current XDW directory contains no pages")

    def _validate_header(self) -> None:
        for signature, name in _NON_XDW_SIGNATURES:
            if self._data.startswith(signature):
                raise XdwNotXdwError(f"not an XDW file: the data is {name}", name)
        try:
            header = decode_field(self._data, 0, len(self._data))
        except XdwFormatError:
            header = None
        if header is None or header.tag != 0x60 or header.length != 14:
            raise XdwNotXdwError(
                "not an XDW file: missing the 14-byte tag 0x60 XDW header "
                "(DocuWorks binders .xbd are not supported)"
            )
        fields = _field_map(self._data, header)
        try:
            version_field = fields[0x82]
        except KeyError as exc:
            raise XdwFormatError("XDW header lacks format version tag 0x82") from exc
        if version_field.length != 1:
            raise XdwFormatError("XDW format version is not one byte")
        self.format_version = unsigned_be(self._data, version_field)

    @property
    def limits(self) -> XdwLimits:
        """The decoding limits this reader enforces."""
        return self._data.budget.limits

    @property
    def decoded_bytes(self) -> int:
        """LZH output decoded so far, counted against ``max_total_decoded``."""
        return self._data.budget.used

    @property
    def file_size(self) -> int:
        return len(self._data)

    @property
    def page_count(self) -> int:
        return len(self.pages)

    @property
    def index_tag(self) -> int:
        """Return the current directory tag (0x68 or observed legacy 0x65)."""

        return self.current_generation.index_tag

    @property
    def metadata(self) -> dict[str, str | None]:
        """Return document properties (title, author, keywords, ...) as a dict.

        pypdf-style entry point (``PdfReader.metadata``): keys are property
        names (``"title"``, ``"author"``, ``"keywords"``, custom
        ``"usrdef_*"``/``"N_n"``/``"T_n"``/``"V_n"`` attributes) and values
        are their decoded string content, or ``None`` when the property
        marker exists but no value was ever set. See
        :attr:`XdwGeneration.document_attributes`.
        """

        return XdwMetadata(self.current_generation.document_attributes)

    @property
    def is_encrypted(self) -> bool:
        """Always ``False`` for an opened reader: protected XDW raise on open.

        pypdf compatibility. Use :func:`inspect_protection` to examine a protected
        file without opening it.
        """
        return False

    @cached_property
    def typed_metadata(self) -> dict[str, str | int | bool | None]:
        """Document properties, retaining verified custom integer/boolean types."""
        return _find_document_attributes(self.current_generation.metadata, typed=True)

    @cached_property
    def original_data(self) -> tuple[XdwOriginalData, ...]:
        """Read the captured uncompressed original-data trailer format."""
        metadata = self.current_generation.metadata
        if metadata is None:
            return ()
        _, _, trailer = page_blocks(metadata, self.page_count)
        result = []
        for record in trailer:
            outer = decode_field(record, 0, len(record))
            body = record[outer.value_offset:outer.end_offset]
            if not body.startswith(b'\x80\x01\x02\x62\x02\x10\x00'):
                continue
            values = {tag: body[pos:end] for tag, _, pos, end in ber_fields(body)}
            if values.get(b'\x83') != b'\x01\x01' or not all(
                    tag in values for tag in (b'\x9f\x8f\x51', b'\x9f\x8f\x52')):
                raise XdwUnsupportedFeatureError('unobserved original-data encoding')
            name = values[b'\x9f\x8f\x52'].rstrip(b'\0').decode('cp932')
            result.append(XdwOriginalData(name, values[b'\x9f\x8f\x51']))
        return tuple(result)

    def get_generation_bytes(self, generation: int = -1) -> bytes:
        selected = self.generations[generation]
        return self._data[: selected.end_offset]

    def write_generation(
        self, destination: Pathish | BinaryIO, generation: int = -1
    ) -> None:
        """Write an exact historical prefix ending at the selected directory."""

        data = self.get_generation_bytes(generation)
        if hasattr(destination, "write"):
            written = destination.write(data)
            if written is not None and written != len(data):
                raise OSError(f"short write: {written} of {len(data)} bytes")
            return
        Path(destination).write_bytes(data)

    def get_page_bytes(self, page_index: int) -> bytes:
        """Return a compact one-page XDW without other pages or old history."""

        # Local import avoids a module cycle: writer operations build on the
        # reader model, while this is only a convenience façade.
        from .experimental import extract_page_bytes

        return extract_page_bytes(self, page_index)

    def write_page(
        self,
        destination: Pathish | BinaryIO,
        page_index: int,
    ) -> None:
        """Write one compact page to a filesystem path or binary stream."""

        data = self.get_page_bytes(page_index)
        if hasattr(destination, "write"):
            written = destination.write(data)
            if written is not None and written != len(data):
                raise OSError(f"short write: {written} of {len(data)} bytes")
            return
        Path(destination).write_bytes(data)

    def get_compacted_bytes(self) -> bytes:
        """Return current pages without append-only history or removed resources."""

        from .experimental import compact_document_bytes

        return compact_document_bytes(self)

    def write_compacted(self, destination: Pathish | BinaryIO) -> None:
        """Write only the current document state to a path or binary stream."""

        data = self.get_compacted_bytes()
        if hasattr(destination, "write"):
            written = destination.write(data)
            if written is not None and written != len(data):
                raise OSError(f"short write: {written} of {len(data)} bytes")
            return
        Path(destination).write_bytes(data)

    def extract_text(
        self, extraction_mode: str = "plain", *, include_annotations: bool = False
    ) -> str:
        """Return text from all current pages in page order."""

        return "\n".join(
            page.extract_text(
                extraction_mode=extraction_mode, include_annotations=include_annotations
            )
            for page in self.pages
        )
