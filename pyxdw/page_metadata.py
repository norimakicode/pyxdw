"""Page metadata blocks and size-validated resource references.

Annotation records follow their owning kind-2/3/4 page triple until the
next kind-2 record. Keep those records opaque except for resource references.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .reader import XdwResource
from .errors import XdwFormatError, XdwUnsupportedLayoutError
from .tlv import decode_field, encode_field, parse_sequence


@dataclass(frozen=True)
class ResourceReference:
    start: int
    body_start: int
    end: int
    index: int
    index_end: int
    decoded_size: int | None


def resource_references(
    data: bytes, resources: Sequence[XdwResource]
) -> tuple[ResourceReference, ...]:
    """Recognize private BER descriptors by structure AND resource payload size.

    Long tags and variable integer/length widths are supported. No arbitrary
    81/index patterns in text or image payloads are rewritten.
    """
    refs = []
    if data[:1] == b"\x62":
        records = parse_sequence(data, 0, len(data))
        fields = [
            field
            for record in records
            for field in ber_fields(data, record.value_offset, record.end_offset)
        ]
    else:
        fields = list(ber_fields(data))
    for tag, start, pos, end in fields:
        if tag[0] >> 6 != 3 or not 6 <= end - pos <= 24:
            continue
        try:
            children = parse_sequence(data, pos, end)
        except XdwFormatError:
            continue
        if [f.tag for f in children] not in ([0x81, 0x82], [0x81, 0x82, 0x83]):
            continue
        if any(not 1 <= f.length <= 4 for f in children):
            continue
        values = [
            int.from_bytes(data[f.value_offset : f.end_offset], "big") for f in children
        ]
        index = values[0]
        if index >= len(resources) or values[-1] != len(resources[index].payload_bytes):
            continue
        refs.append(
            ResourceReference(
                start,
                pos,
                end,
                index,
                children[0].end_offset,
                values[1] if len(values) == 3 else None,
            )
        )
    return tuple(refs)


def remap_record(
    record: bytes, resources: Sequence[XdwResource], mapping: Mapping[int, int]
) -> bytes:
    """Rewrite validated references and their BER lengths, preserving all else."""
    outer = decode_field(record, 0, len(record))
    body = record[outer.value_offset : outer.end_offset]
    refs = resource_references(body, resources)
    for ref in reversed(refs):
        if ref.index not in mapping:
            raise XdwUnsupportedLayoutError(
                f"page references unselected resource {ref.index}"
            )
        index = mapping[ref.index]
        raw = index.to_bytes(max(1, (index.bit_length() + 7) // 8), "big")
        value = encode_field(0x81, raw) + body[ref.index_end : ref.end]
        # Original tag can have multiple bytes; find its end again.
        pos = ref.start + 1
        if body[ref.start] & 31 == 31:
            while body[pos] & 128:
                pos += 1
            pos += 1
        tag = body[ref.start : pos]
        body = body[: ref.start] + tag + encode_field(0, value)[1:] + body[ref.end :]
    return encode_field(outer.tag, body)


def page_blocks(
    metadata: bytes, page_count: int | None = None
) -> tuple[tuple[bytes, ...], tuple[tuple[bytes, ...], ...], tuple[bytes, ...]]:
    """Return prefix, complete page subtrees, and global trailer records."""
    fields = parse_sequence(metadata, 0, len(metadata))
    records = tuple(metadata[f.offset : f.end_offset] for f in fields)

    def kind(f):
        body = metadata[f.value_offset : f.end_offset]
        return body[2] if body[:2] == b"\x80\x01" else None

    kinds = [kind(f) for f in fields]
    starts = [i for i, k in enumerate(kinds) if k == 2 and
              records[i][decode_field(records[i], 0, len(records[i])).value_offset:]
              .startswith(b'\x80\x01\x02\x62\x02\x13\x01')]
    if (
        not starts
        or starts[0] != 2
        or (page_count is not None and len(starts) != page_count)
    ):
        raise XdwUnsupportedLayoutError(
            "metadata does not contain the expected page blocks"
        )
    # Global original-data records follow the kind-1/4 and kind-1/6
    # trailers and precede the final kind-1/5 record. They are not pages.
    trailer_start = None
    for i in range(starts[-1] + 3, len(records) - 2):
        bodies = [records[j][decode_field(records[j], 0, len(records[j])).value_offset:]
                  for j in (i, i + 1)]
        if (bodies[0].startswith(b'\x80\x01\x01\x62\x02\x13\x04')
                and bodies[1].startswith(b'\x80\x01\x01\x62\x02\x13\x06')):
            trailer_start = i
            break
    if trailer_start is None or kinds[-1] != 1:
        raise XdwUnsupportedLayoutError("unknown document metadata trailer")
    ends = starts[1:] + [trailer_start]
    blocks = []
    for start, end in zip(starts, ends):
        if kinds[start : start + 3] != [2, 3, 4] or end < start + 3:
            raise XdwUnsupportedLayoutError("page block does not start with kind-2/3/4")
        blocks.append(records[start:end])
    return records[:2], tuple(blocks), records[trailer_start:]


def ber_fields(
    data: bytes, start: int = 0, end: int | None = None
) -> Iterator[tuple[bytes, int, int, int]]:
    """Walk opaque BER fields, including multi-byte tags, without scanning values."""
    end = len(data) if end is None else end
    cursor = start
    while cursor < end:
        begin = cursor
        cursor += 1
        if data[begin] & 31 == 31:
            while cursor < end and data[cursor] & 128:
                cursor += 1
            cursor += 1
        if cursor >= end:
            raise XdwUnsupportedLayoutError("truncated metadata tag")
        tag = data[begin:cursor]
        length = data[cursor]
        cursor += 1
        if length & 128:
            count = length & 127
            if not 1 <= count <= 4 or cursor + count > end:
                raise XdwUnsupportedLayoutError("unsupported metadata field length")
            length = int.from_bytes(data[cursor : cursor + count], "big")
            cursor += count
        stop = cursor + length
        if stop > end:
            raise XdwUnsupportedLayoutError("metadata field exceeds record")
        yield tag, begin, cursor, stop
        cursor = stop


def rotate_page_block(
    block: Sequence[bytes], current_rotation: int, degrees: int
) -> tuple[bytes, ...]:
    """Change page geometry in place, keeping opaque child annotation records.

    Locating fields at BER boundaries avoids matching UTF-16 OCR text bytes.
    Keeping the original field order also makes cumulative rotation independent
    of sample-specific normalization anchors.
    """
    target = (current_rotation + degrees) % 360
    output = []
    for kind, record in zip((2, 3, 4), block[:3]):
        outer = decode_field(record, 0, len(record))
        body = record[outer.value_offset : outer.end_offset]
        fields = list(ber_fields(body))
        dim_tag = b"\x9f\x8f\x51" if kind == 3 else b"\x85"
        dims = [f for f in fields if f[0] == dim_tag]
        if len(dims) != 1:
            raise XdwUnsupportedLayoutError(
                "page geometry lacks a unique dimension field"
            )
        changes = []
        if degrees in (90, 270):
            tag, start, value_start, end = dims[0]
            from .metadata import _swap_dimension_chunks

            swapped = _swap_dimension_chunks(body[value_start:end])
            changes.append((start, end, tag + encode_field(0, swapped)[1:]))
        if kind == 4:
            descriptors = [f for f in fields if f[0] == b"\x9f\x3d"]
            if len(descriptors) > 1:
                raise XdwUnsupportedLayoutError("multiple page rotation descriptors")
            raw = target.to_bytes(max(1, (target.bit_length() + 7) // 8), "big")
            if raw[0] & 128:
                raw = b"\x00" + raw
            descriptor = b"\x9f\x3d" + encode_field(0, bytes([len(raw)]) + raw)[1:]
            if descriptors:
                _, start, _, end = descriptors[0]
            else:
                marker = [f for f in fields if f[0] == b"\x62"]
                if len(marker) != 1:
                    raise XdwUnsupportedLayoutError("page rotation marker is ambiguous")
                start = end = marker[0][3]
            changes.append((start, end, descriptor))
        for start, end, replacement in sorted(changes, reverse=True):
            body = body[:start] + replacement + body[end:]
        output.append(encode_field(outer.tag, body))
    return tuple(output) + tuple(block[3:])


def _ber_signed_int(value: int) -> bytes:
    """Minimal big-endian two's-complement bytes (as in annotation 9F 34 / 9F 8F 51)."""
    length = 1
    while not -(1 << (8 * length - 1)) <= value < (1 << (8 * length - 1)):
        length += 1
    if length > 4:
        raise ValueError("coordinate does not fit in 4 bytes")
    return value.to_bytes(length, "big", signed=True)


def replace_annotation_int_pair(record: bytes, tag: bytes, first: int, second: int) -> bytes:
    """Rewrite a top-level ``<n><a><n><b>`` field of an annotation's first record.

    Verified for the position field ``9F 34``: moving an official text annotation
    this way yields metadata byte-identical to the official API's moved fixture.
    """
    outer = decode_field(record, 0, len(record))
    body = record[outer.value_offset : outer.end_offset]
    matches = [f for f in ber_fields(body) if f[0] == tag]
    if len(matches) != 1:
        raise XdwUnsupportedLayoutError(f"annotation record lacks a unique {tag.hex()} field")
    _, start, _, end = matches[0]
    payload = b"".join(bytes([len(raw)]) + raw for raw in map(_ber_signed_int, (first, second)))
    replacement = tag + encode_field(0, payload)[1:]
    return encode_field(outer.tag, body[:start] + replacement + body[end:])


def _int_pair_payload(first: int, second: int) -> bytes:
    return b"".join(bytes([len(raw)]) + raw for raw in map(_ber_signed_int, (first, second)))


def _read_int_pair(payload: bytes) -> tuple[int, int]:
    values, i = [], 0
    for _ in range(2):
        n = payload[i]
        values.append(int.from_bytes(payload[i + 1:i + 1 + n], "big", signed=True))
        i += 1 + n
    return values[0], values[1]


def official_rotate_page_block(block: Sequence[bytes], current_rotation: int, degrees: int) -> tuple[bytes, ...]:
    """Rotate a page the way XDW_RotatePage rewrites its three page records.

    Measured on official rotations of (11,7) MRC, (9,7), (5,7), (10,7) and
    inline-EMF pages (2026-10-19 oracle B1-B8): resource payloads are untouched;
    every field the API writes moves, in write order, to just after the record's
    ``80``/``62`` head:

    * kind 2: page size ``85`` (swapped for 90/270, written even for 180);
    * kind 3: image size ``9F 8F 51`` (90/270 only), then image origin ``9F 34``,
      rotated about the page so an image larger than the page keeps its overhang;
    * kind 4: its own size ``85`` swapped (90/270 only), rotation ``9F 3D``, then ``9F 3E``.
    """
    if degrees not in (90, 180, 270):
        raise ValueError("degrees must be 90, 180 or 270")
    quarter = degrees in (90, 270)
    target = (current_rotation + degrees) % 360

    def split(record):
        outer = decode_field(record, 0, len(record))
        body = record[outer.value_offset:outer.end_offset]
        return record[:1], [[tag, body[v:e]] for tag, _, v, e in ber_fields(body)]

    def join(head, fields):
        body = b"".join(tag + encode_field(0, payload)[1:] for tag, payload in fields)
        return head + encode_field(0, body)[1:]

    def put_first(fields, written):
        tags = [t for t, _ in written]
        rest = [f for f in fields if f[0] not in tags]
        lead = [f for f in rest[:2] if f[0] in (b"\x80", b"\x62")]
        if len(lead) != 2:
            raise XdwUnsupportedLayoutError("page record does not start with 80/62")
        return lead + written + rest[2:]

    def unique(fields, tag):
        found = [f for f in fields if f[0] == tag]
        if len(found) != 1:
            raise XdwUnsupportedLayoutError(f"page record lacks a unique {tag.hex()} field")
        return found[0][1]

    (h2, f2), (h3, f3), (h4, f4) = (split(r) for r in block[:3])
    page_w, page_h = _read_int_pair(unique(f2, b"\x85"))
    own_w, own_h = _read_int_pair(unique(f4, b"\x85"))     # kind 4 keeps its own (image) size
    image_w, image_h = _read_int_pair(unique(f3, b"\x9f\x8f\x51"))
    x, y = _read_int_pair(unique(f3, b"\x9f\x34"))
    for _ in range(degrees // 90):                       # clockwise quarter turns about the page
        x, y = page_h - (y + image_h), x
        page_w, page_h, image_w, image_h = page_h, page_w, image_h, image_w

    written2 = [[b"\x85", _int_pair_payload(page_w, page_h)]]
    written3 = ([[b"\x9f\x8f\x51", _int_pair_payload(image_w, image_h)]] if quarter else []) + [
        [b"\x9f\x34", _int_pair_payload(x, y)]]
    raw = target.to_bytes(max(1, (target.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    third = [f for f in f4 if f[0] == b"\x9f\x3e"]
    written4 = ([[b"\x85", _int_pair_payload(own_h, own_w)]] if quarter else []) + [
        [b"\x9f\x3d", bytes([len(raw)]) + raw]] + (third if third else [[b"\x9f\x3e", b"\x01\x00"]])
    return (join(h2, put_first(f2, written2)), join(h3, put_first(f3, written3)),
            join(h4, put_first(f4, written4))) + tuple(block[3:])
