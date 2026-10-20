"""Verified transformations for decoded XDW metadata streams."""

from __future__ import annotations

from collections.abc import Sequence

from .errors import XdwUnsupportedLayoutError
from .tlv import TlvField, decode_field, encode_field, parse_sequence, value


def _field_bytes(data: bytes, field: TlvField) -> bytes:
    return data[field.offset:field.end_offset]


def _record_kind(data: bytes, record: TlvField) -> int:
    if record.tag != 0x62:
        raise XdwUnsupportedLayoutError("metadata record is not tag 0x62")
    kind = decode_field(data, record.value_offset, record.end_offset)
    if kind.tag != 0x80 or kind.length != 1:
        raise XdwUnsupportedLayoutError("metadata record lacks a one-byte kind")
    return value(data, kind)[0]


def _find_c7_reference(record_bytes: bytes, start: int) -> int:
    """Return the offset of a C7 resource-reference envelope, or -1.

    The envelope is ``C7 <length> 81 01 <index> ...``. Its own length byte
    grows with a trailing size field that varies with the referenced
    resource's byte size (7 for a small JPEG object, 8+ for a single large
    resource such as a full-color image page), so it is located by its fixed
    ``81 01`` nested-field prefix rather than by an exact overall length.
    """

    cursor = start
    while True:
        index = record_bytes.find(b"\xc7", cursor)
        if index < 0 or index + 4 > len(record_bytes):
            return -1
        if record_bytes[index + 2:index + 4] == b"\x81\x01":
            return index
        cursor = index + 1


def _rewrite_page_resource_indices(
    record_bytes: bytes,
    *,
    old_first_index: int,
    new_first_index: int,
) -> bytes:
    """Rewrite the two resource references in an observed kind-4 page record."""

    if not 0 <= old_first_index <= 0xFE or not 0 <= new_first_index <= 0xFE:
        raise XdwUnsupportedLayoutError(
            "one-byte scanned-page resource indices were exceeded"
        )

    record = decode_field(record_bytes, 0, len(record_bytes))
    if record.tag != 0x62 or record.end_offset != len(record_bytes):
        raise XdwUnsupportedLayoutError("invalid kind-4 metadata envelope")

    kind = decode_field(record_bytes, record.value_offset, record.end_offset)
    marker = decode_field(record_bytes, kind.end_offset, record.end_offset)

    def rewrite_rotated_references() -> bytes:
        c7_index = _find_c7_reference(record_bytes, marker.end_offset)
        df_index = record_bytes.find(b"\xdf\x3a", marker.end_offset)
        if c7_index < 0 or df_index < 0:
            raise XdwUnsupportedLayoutError(
                "kind-4 page metadata has unexpected resource references"
            )
        even_value_offset = c7_index + 4
        # DF begins with a one-byte element-count marker (0x07), so its
        # nested 0x81 value is one byte later than the C7 value.
        odd_value_offset = df_index + 5
        if (
            even_value_offset >= len(record_bytes)
            or odd_value_offset >= len(record_bytes)
            or record_bytes[even_value_offset] != old_first_index
            or record_bytes[odd_value_offset] != old_first_index + 1
        ):
            raise XdwUnsupportedLayoutError(
                "kind-4 rotated metadata has unexpected resource references"
            )
        rewritten = bytearray(record_bytes)
        rewritten[even_value_offset] = new_first_index
        rewritten[odd_value_offset] = new_first_index + 1
        return bytes(rewritten)

    if (
        kind.tag == 0x80
        and value(record_bytes, kind) == b"\x04"
        and marker.tag == 0x62
        and value(record_bytes, marker) == b"\x00\x80\x10"
        and record_bytes[marker.end_offset:marker.end_offset + 2] != b"\xc7\x07"
    ):
        return rewrite_rotated_references()

    first_reference = decode_field(record_bytes, marker.end_offset, record.end_offset)
    second_reference = decode_field(
        record_bytes, first_reference.end_offset, record.end_offset
    )
    if (
        kind.tag != 0x80
        or value(record_bytes, kind) != b"\x04"
        or marker.tag != 0x62
        or value(record_bytes, marker) != b"\x00\x80\x10"
        or first_reference.tag != 0xC7
        or first_reference.length != 7
        or second_reference.tag != 0xDF
        or second_reference.length < 5
        or record_bytes[second_reference.value_offset] != 7
    ):
        raise XdwUnsupportedLayoutError("unknown kind-4 page metadata layout")

    even = decode_field(
        record_bytes, first_reference.value_offset, first_reference.end_offset
    )
    odd = decode_field(
        record_bytes, second_reference.value_offset + 1, second_reference.end_offset
    )
    if (
        even.tag != 0x81
        or even.length != 1
        or odd.tag != 0x81
        or odd.length != 1
        or value(record_bytes, even) != bytes([old_first_index])
        or value(record_bytes, odd) != bytes([old_first_index + 1])
    ):
        # Compatibility 90/180/270-degree edits move a rotation descriptor (and,
        # for 90/270, the dimension field) in front of the C7/DF references.
        # Those descriptor tags are multi-byte values and intentionally opaque
        # to the single-byte TLV parser above.  Locate the two fixed reference
        # envelopes directly as a safe fallback.
        return rewrite_rotated_references()

    rewritten = bytearray(record_bytes)
    rewritten[even.value_offset] = new_first_index
    rewritten[odd.value_offset] = new_first_index + 1
    return bytes(rewritten)


def select_scanned_metadata(
    metadata: bytes,
    page_count: int,
    page_indices: Sequence[int],
) -> bytes:
    """Select/reorder pages in the decoded metadata of the observed scan layout.

    The supplied three-page scan and its one-page-deletion comparison derivative
    establish a layout of two document records, three records per page, and
    three trailing records.  Only the kind-4 page record carries positional
    resource indices; its pair changes from ``2*n, 2*n+1`` to the output page's
    new pair.
    """

    if page_count <= 0:
        raise ValueError("page_count must be positive")
    selected = tuple(page_indices)
    if not selected:
        raise ValueError("at least one page must be selected")
    if any(index < 0 or index >= page_count for index in selected):
        raise IndexError("page index out of range")

    records = parse_sequence(metadata, 0, len(metadata))
    expected_count = 2 + page_count * 3 + 3
    if len(records) != expected_count:
        raise XdwUnsupportedLayoutError(
            f"expected {expected_count} metadata records, found {len(records)}"
        )

    page_records = records[2:2 + page_count * 3]
    for page_index in range(page_count):
        kinds = tuple(
            _record_kind(metadata, page_records[page_index * 3 + offset])
            for offset in range(3)
        )
        if kinds != (2, 3, 4):
            raise XdwUnsupportedLayoutError(
                f"page {page_index + 1} metadata kinds are {kinds}, expected (2, 3, 4)"
            )

    output = [_field_bytes(metadata, record) for record in records[:2]]
    for output_index, source_index in enumerate(selected):
        first, second, third = page_records[source_index * 3:source_index * 3 + 3]
        output.append(_field_bytes(metadata, first))
        output.append(_field_bytes(metadata, second))
        output.append(
            _rewrite_page_resource_indices(
                _field_bytes(metadata, third),
                old_first_index=source_index * 2,
                new_first_index=output_index * 2,
            )
        )
    output.extend(_field_bytes(metadata, record) for record in records[-3:])
    return b"".join(output)


def _swap_dimension_chunks(blob: bytes) -> bytes:
    """Swap a ``<tag><width> <tag><height>`` dimension chunk pair.

    Each chunk is normally 3 bytes (``02`` plus a two-byte value), but grows
    to 4 bytes (``03`` plus a three-byte value) when the encoded physical
    size is too large for two bytes (e.g. an A2-sized full-color page), so
    the split point is derived from the blob's own length instead of a
    hardcoded 3.
    """

    half = len(blob) // 2
    if len(blob) % 2 or half < 2 or blob[0] != blob[half]:
        raise XdwUnsupportedLayoutError("unexpected scanned-page dimension tuple")
    return blob[half:] + blob[:half]


def _rotate_kind2(record_bytes: bytes) -> bytes:
    # The kind-2 record stores physical dimensions in a six-byte 0x85 value.
    marker = b"\x85\x06"
    index = record_bytes.find(marker)
    if index < 0 or record_bytes.find(marker, index + 1) >= 0:
        raise XdwUnsupportedLayoutError("kind-2 record lacks a unique 0x85 dimension")
    if index + 8 > len(record_bytes):
        raise XdwUnsupportedLayoutError("truncated kind-2 dimensions")
    swapped = _swap_dimension_chunks(record_bytes[index + 2:index + 8])
    return record_bytes[:index + 2] + swapped + record_bytes[index + 8:]


def _normalize_application_kind2(
    record_bytes: bytes, current_rotation: int
) -> bytes:
    """Restore the observed application kind-2 record to zero degrees."""

    marker = b"\x62\x02\x13\x01"
    marker_index = _unique_marker(
        record_bytes, marker, 0, "application kind-2 marker"
    )
    marker_end = marker_index + len(marker)
    dimension_field = _find_unique_tag_field(
        record_bytes, 0x85, marker_end, "application kind-2 dimension"
    )
    if dimension_field.offset != marker_end:
        raise XdwUnsupportedLayoutError(
            "rotated application kind-2 dimension is not at the observed position"
        )
    normalized_value = value(record_bytes, dimension_field)
    if current_rotation in {90, 270}:
        normalized_value = _swap_dimension_chunks(normalized_value)
    rewritten = (
        record_bytes[:dimension_field.offset]
        + record_bytes[dimension_field.end_offset:]
    )
    anchor = b"\x9f\x8f\x51\x02\x01\x01"
    anchor_index = _unique_marker(
        rewritten, anchor, marker_end, "application kind-2 dimension anchor"
    )
    anchor_end = anchor_index + len(anchor)
    return (
        rewritten[:anchor_end]
        + encode_field(0x85, normalized_value)
        + rewritten[anchor_end:]
    )


def _rotate_application_kind2(record_bytes: bytes, degrees: int) -> bytes:
    """Encode the byte-exact nonzero application kind-2 orientation."""

    marker = b"\x62\x02\x13\x01"
    marker_index = _unique_marker(
        record_bytes, marker, 0, "application kind-2 marker"
    )
    marker_end = marker_index + len(marker)
    dimension_field = _find_unique_tag_field(
        record_bytes, 0x85, marker_end, "application kind-2 dimension"
    )
    dimension_value = value(record_bytes, dimension_field)
    if degrees in {90, 270}:
        dimension_value = _swap_dimension_chunks(dimension_value)
    rewritten = (
        record_bytes[:dimension_field.offset]
        + record_bytes[dimension_field.end_offset:]
    )
    return (
        rewritten[:marker_end]
        + encode_field(0x85, dimension_value)
        + rewritten[marker_end:]
    )


def _rotate_kind3(record_bytes: bytes) -> bytes:
    # For 90/270 degrees the observed kind-3 record moves 0x9f8f51 before
    # 0x9f34 and swaps the same dimension tuple.  These are fixed-width fields
    # in the verified scan metadata layout.
    first = b"\x9f\x34\x04"
    second = b"\x9f\x8f\x51\x06"
    first_index = record_bytes.find(first)
    second_index = record_bytes.find(second)
    if first_index < 0 or second_index < 0 or first_index >= second_index:
        raise XdwUnsupportedLayoutError("unknown kind-3 rotation field order")
    first_end = first_index + 7  # two-byte tag, one-byte length, four-byte value
    second_end = second_index + 10  # three-byte tag, one-byte length, six-byte value
    if second_end > len(record_bytes):
        raise XdwUnsupportedLayoutError("truncated kind-3 rotation dimensions")
    swapped = _swap_dimension_chunks(record_bytes[second_index + 4:second_end])
    middle = record_bytes[first_end:second_index]
    return (
        record_bytes[:first_index]
        + record_bytes[second_index:second_index + 4]
        + swapped
        + record_bytes[first_index:first_end]
        + middle
        + record_bytes[second_end:]
    )


def _normalize_kind3(
    record_bytes: bytes,
    current_rotation: int,
    *,
    is_application: bool,
) -> bytes:
    """Restore an observed kind-3 record to its unrotated field order."""

    if current_rotation in {0, 180}:
        return record_bytes

    first = b"\x9f\x34\x04"
    second = b"\x9f\x8f\x51\x06"
    first_index = record_bytes.find(first)
    second_index = record_bytes.find(second)
    if (
        first_index < 0
        or second_index < 0
        or second_index >= first_index
        or record_bytes.find(first, first_index + 1) >= 0
        or record_bytes.find(second, second_index + 1) >= 0
    ):
        raise XdwUnsupportedLayoutError("unknown rotated kind-3 field order")
    first_end = first_index + 7
    second_end = second_index + 10
    if first_end > len(record_bytes) or second_end > first_index:
        raise XdwUnsupportedLayoutError("truncated rotated kind-3 fields")

    normalized_dimensions = _swap_dimension_chunks(
        record_bytes[second_index + 4:second_end]
    )
    normalized_second = record_bytes[second_index:second_index + 4] + normalized_dimensions
    prefix = record_bytes[:second_index]
    first_field = record_bytes[first_index:first_end]
    remainder = record_bytes[first_end:]
    if is_application:
        # The application page keeps its child-dimension dictionary between
        # 0x9f34 and the late 0x9f8f51 field in the unrotated representation.
        return prefix + first_field + remainder + normalized_second
    return prefix + first_field + normalized_second + remainder


def _reencode_record(record_bytes: bytes, rewritten: bytes) -> bytes:
    """Re-encode a metadata record after changing its payload length."""

    outer = decode_field(record_bytes, 0, len(record_bytes))
    if outer.tag != 0x62 or outer.end_offset != len(record_bytes):
        raise XdwUnsupportedLayoutError("invalid metadata record envelope")
    return encode_field(outer.tag, rewritten[outer.header_size:])


def _unique_marker(blob: bytes, marker: bytes, start: int, description: str) -> int:
    """Return a unique marker offset or reject an unobserved layout."""

    index = blob.find(marker, start)
    if index < 0 or blob.find(marker, index + 1) >= 0:
        raise XdwUnsupportedLayoutError(f"kind-4 record lacks a unique {description}")
    return index


def _find_unique_tag_field(
    blob: bytes, tag: int, start: int, description: str
) -> TlvField:
    """Decode the sole *tag*-prefixed field at or after *start*.

    Unlike :func:`_unique_marker`, this matches by tag byte only and decodes
    the field's own length rather than assuming a fixed size -- some fields
    (e.g. a page dimension) grow by a byte when their encoded value is too
    large for the size observed on smaller pages.
    """

    marker = bytes([tag])
    index = blob.find(marker, start)
    if index < 0 or blob.find(marker, index + 1) >= 0:
        raise XdwUnsupportedLayoutError(f"kind-4 record lacks a unique {description}")
    return decode_field(blob, index, len(blob))


def _normalize_kind4(
    record_bytes: bytes,
    current_rotation: int,
    *,
    is_application: bool,
) -> bytes:
    """Restore an observed kind-4 record to its unrotated representation."""

    if current_rotation == 0:
        return record_bytes

    marker = b"\x62\x03\x00\x80\x10"
    marker_index = _unique_marker(record_bytes, marker, 0, "page marker")
    marker_end = marker_index + len(marker)
    descriptor_index = _unique_marker(
        record_bytes, b"\x9f\x3d", marker_end, "rotation descriptor"
    )
    descriptor_length = record_bytes[descriptor_index + 2]
    descriptor_end = descriptor_index + 3 + descriptor_length
    if descriptor_end > len(record_bytes):
        raise XdwUnsupportedLayoutError("truncated kind-4 rotation descriptor")
    expected_descriptors = {
        90: b"\x9f\x3d\x02\x01\x5a",
        180: b"\x9f\x3d\x03\x02\x00\xb4",
        270: b"\x9f\x3d\x03\x02\x01\x0e",
    }
    if record_bytes[descriptor_index:descriptor_end] != expected_descriptors[current_rotation]:
        raise XdwUnsupportedLayoutError(
            "kind-4 rotation descriptor disagrees with the current page rotation"
        )

    rewritten = record_bytes[:descriptor_index] + record_bytes[descriptor_end:]
    if is_application:
        status = b"\x9f\x3e\x02\x01\x00"
        status_index = _unique_marker(
            rewritten, status, marker_end, "application rotation-status field"
        )
        # Compatibility application rotations place this field directly after the
        # descriptor; the zero-degree form stores it at the end of kind 4.
        if status_index != descriptor_index:
            raise XdwUnsupportedLayoutError(
                "application rotation-status field is not after the descriptor"
            )
        rewritten = rewritten[:status_index] + rewritten[status_index + len(status):]
    if current_rotation in {90, 270}:
        dimension_index = _unique_marker(
            rewritten, b"\x85\x06", marker_end, "rotation dimension"
        )
        if dimension_index != marker_end or dimension_index + 8 > len(rewritten):
            raise XdwUnsupportedLayoutError(
                "rotated kind-4 dimensions are not at the observed position"
            )
        normalized_dimension = (
            b"\x85\x06"
            + _swap_dimension_chunks(rewritten[dimension_index + 2:dimension_index + 8])
        )
        rewritten = rewritten[:dimension_index] + rewritten[dimension_index + 8:]
        if is_application:
            dimension_anchor = _unique_marker(
                rewritten,
                b"\x9f\x8f\x51\x02\x01",
                marker_end,
                "application dimension anchor",
            )
        else:
            dimension_anchor = _unique_marker(
                rewritten, b"\x8e\x02\x01\x00", marker_end, "scan dimension anchor"
            )
        rewritten = (
            rewritten[:dimension_anchor]
            + normalized_dimension
            + rewritten[dimension_anchor:]
        )

    if not is_application:
        descriptor_anchor = _unique_marker(
            rewritten,
            b"\x9f\x8f\x51\x03\x02\x00\xc8",
            marker_end,
            "scan rotation-descriptor anchor",
        )
        rewritten = (
            rewritten[:descriptor_anchor]
            + b"\x9f\x3d\x02\x01\x00"
            + rewritten[descriptor_anchor:]
        )
    elif is_application:
        rewritten += b"\x9f\x3e\x02\x01\x00"
    return _reencode_record(record_bytes, rewritten)


def _rotate_application_kind4(record_bytes: bytes, degrees: int) -> bytes:
    """Encode the exact kind-4 layout emitted for an application page."""

    marker = b"\x62\x03\x00\x80\x10"
    marker_index = _unique_marker(record_bytes, marker, 0, "page marker")
    marker_end = marker_index + len(marker)
    if record_bytes.find(b"\x9f\x3d", marker_end) >= 0:
        raise XdwUnsupportedLayoutError(
            "application kind-4 record was not normalized before rotation"
        )
    status = b"\x9f\x3e\x02\x01\x00"
    status_index = _unique_marker(
        record_bytes, status, marker_end, "application rotation-status field"
    )
    without_status = record_bytes[:status_index] + record_bytes[status_index + 5:]
    descriptor_values = {
        90: b"\x9f\x3d\x02\x01\x5a",
        180: b"\x9f\x3d\x03\x02\x00\xb4",
        270: b"\x9f\x3d\x03\x02\x01\x0e",
    }
    inserted = descriptor_values[degrees] + status

    if degrees in {90, 270}:
        dimension_index = _unique_marker(
            without_status, b"\x85\x06", marker_end, "rotation dimension"
        )
        if dimension_index + 8 > len(without_status):
            raise XdwUnsupportedLayoutError("truncated kind-4 rotation dimension")
        swapped = _swap_dimension_chunks(
            without_status[dimension_index + 2:dimension_index + 8]
        )
        without_status = (
            without_status[:dimension_index]
            + without_status[dimension_index + 8:]
        )
        inserted = b"\x85\x06" + swapped + inserted

    rewritten = without_status[:marker_end] + inserted + without_status[marker_end:]
    return _reencode_record(record_bytes, rewritten)


def _rotate_kind4(
    record_bytes: bytes, degrees: int, *, is_application: bool = False
) -> bytes:
    # A kind-4 page record has a non-TLV tail, so only the fixed fields needed
    # for rotation are located byte-wise.  The comparison fixture shows one
    # rotation descriptor (0x9f3d) and a six-byte 0x85 dimension tuple.
    if is_application:
        return _rotate_application_kind4(record_bytes, degrees)

    marker = b"\x62\x03\x00\x80\x10"
    marker_index = record_bytes.find(marker)
    dimension_index = record_bytes.find(b"\x85\x06", marker_index + len(marker))
    descriptor_index = record_bytes.find(b"\x9f\x3d", marker_index + len(marker))
    if marker_index < 0 or dimension_index < 0:
        raise XdwUnsupportedLayoutError("kind-4 rotation fields are missing")
    if dimension_index + 8 > len(record_bytes):
        raise XdwUnsupportedLayoutError("truncated kind-4 rotation fields")
    descriptor_present = descriptor_index >= 0
    if descriptor_present:
        if descriptor_index + 3 > len(record_bytes):
            raise XdwUnsupportedLayoutError("truncated kind-4 rotation fields")
        descriptor_length = record_bytes[descriptor_index + 2]
        descriptor_end = descriptor_index + 3 + descriptor_length
        if descriptor_end > len(record_bytes):
            raise XdwUnsupportedLayoutError("truncated kind-4 rotation descriptor")
    else:
        # The supplied unrotated application/EMF page omits 0x9f3d entirely.
        # Treat its late dimension field as the insertion boundary.
        descriptor_index = dimension_index
        descriptor_end = dimension_index

    if degrees == 180:
        replacement = b"\x9f\x3d" + encode_field(0, b"\x02\x00\xb4")[1:]
        rewritten = (
            record_bytes[:marker_index + len(marker)]
            + replacement
            + record_bytes[marker_index + len(marker):descriptor_index]
            + record_bytes[descriptor_end:]
        )
        return _reencode_record(record_bytes, rewritten)

    swapped = _swap_dimension_chunks(
        record_bytes[dimension_index + 2:dimension_index + 8]
    )
    descriptor_value = b"\x01\x5a" if degrees == 90 else b"\x02\x01\x0e"
    replacement_descriptor = b"\x9f\x3d" + encode_field(0, descriptor_value)[1:]

    # Move dimensions and descriptor directly after the inner 0x62 marker,
    # retaining every opaque byte between/after the known fields.
    marker_end = marker_index + len(marker)
    if descriptor_present:
        if not marker_end <= dimension_index < descriptor_index:
            raise XdwUnsupportedLayoutError(
                "kind-4 rotation fields have an unknown order"
            )
        middle = record_bytes[marker_end:descriptor_index]
        relative_dimension = dimension_index - marker_end
        middle = middle[:relative_dimension] + middle[relative_dimension + 8:]
        suffix = record_bytes[descriptor_end:]
    else:
        middle = record_bytes[marker_end:dimension_index]
        suffix = record_bytes[dimension_index + 8:]
    rewritten = (
        record_bytes[:marker_end]
        + b"\x85\x06"
        + swapped
        + replacement_descriptor
        + middle
        + suffix
    )
    return _reencode_record(record_bytes, rewritten)


def rotate_scanned_metadata(
    metadata: bytes,
    page_count: int,
    page_index: int,
    degrees: int,
) -> bytes:
    """Apply an observed 90/180/270-degree page metadata rotation.

    This reproduces the decoded ``tag 0x63`` transformation seen in all nine
    scan comparison files. The same fixed fields also occur in the
    supplied application page, whose unrotated kind-4 record omits 0x9f3d;
    that descriptor is inserted when rotating it. Resources are not touched.
    Directory identity fields remain an outer-writer concern.
    """

    if page_count <= 0:
        raise ValueError("page_count must be positive")
    if isinstance(page_index, bool) or not isinstance(page_index, int):
        raise TypeError("page index must be an integer")
    if page_index < 0 or page_index >= page_count:
        raise IndexError("page index out of range")
    if degrees not in {90, 180, 270}:
        raise ValueError("degrees must be one of 90, 180, or 270")

    records = parse_sequence(metadata, 0, len(metadata))
    expected_count = 2 + page_count * 3 + 3
    if len(records) != expected_count:
        raise XdwUnsupportedLayoutError(
            f"expected {expected_count} metadata records, found {len(records)}"
        )
    page_records = records[2 + page_index * 3:5 + page_index * 3]
    kinds = tuple(_record_kind(metadata, record) for record in page_records)
    if kinds != (2, 3, 4):
        raise XdwUnsupportedLayoutError(
            f"page {page_index + 1} metadata kinds are {kinds}, expected (2, 3, 4)"
        )

    replacements = {
        2: _field_bytes(metadata, page_records[0]),
        3: _field_bytes(metadata, page_records[1]),
        4: _field_bytes(metadata, page_records[2]),
    }
    if degrees in {90, 270}:
        replacements[2] = _rotate_kind2(replacements[2])
        replacements[3] = _rotate_kind3(replacements[3])
    replacements[4] = _rotate_kind4(replacements[4], degrees)

    output = []
    for index, record in enumerate(records):
        if index == 2 + page_index * 3:
            output.append(replacements[2])
        elif index == 3 + page_index * 3:
            output.append(replacements[3])
        elif index == 4 + page_index * 3:
            output.append(replacements[4])
        else:
            output.append(_field_bytes(metadata, record))
    return b"".join(output)


def rotate_page_metadata(
    metadata: bytes,
    page_count: int,
    page_index: int,
    current_rotation: int,
    degrees: int,
    *,
    is_application: bool = False,
) -> bytes:
    """Rotate one page clockwise by an increment from its current orientation.

    The observed on-disk layouts for 90/180/270 degrees are first normalized
    to their zero-degree representation. The cumulative target angle is then
    encoded using the same byte-exact transformation as
    :func:`rotate_scanned_metadata`.
    """

    if page_count <= 0:
        raise ValueError("page_count must be positive")
    if isinstance(page_index, bool) or not isinstance(page_index, int):
        raise TypeError("page index must be an integer")
    if page_index < 0 or page_index >= page_count:
        raise IndexError("page index out of range")
    if current_rotation not in {0, 90, 180, 270}:
        raise ValueError("current_rotation must be one of 0, 90, 180, or 270")
    if degrees not in {90, 180, 270}:
        raise ValueError("degrees must be one of 90, 180, or 270")

    records = parse_sequence(metadata, 0, len(metadata))
    expected_count = 2 + page_count * 3 + 3
    if len(records) != expected_count:
        raise XdwUnsupportedLayoutError(
            f"expected {expected_count} metadata records, found {len(records)}"
        )
    page_records = records[2 + page_index * 3:5 + page_index * 3]
    kinds = tuple(_record_kind(metadata, record) for record in page_records)
    if kinds != (2, 3, 4):
        raise XdwUnsupportedLayoutError(
            f"page {page_index + 1} metadata kinds are {kinds}, expected (2, 3, 4)"
        )

    replacements = {
        2: _field_bytes(metadata, page_records[0]),
        3: _field_bytes(metadata, page_records[1]),
        4: _field_bytes(metadata, page_records[2]),
    }
    if is_application and current_rotation:
        replacements[2] = _normalize_application_kind2(
            replacements[2], current_rotation
        )
    elif current_rotation in {90, 270}:
        replacements[2] = _rotate_kind2(replacements[2])
    replacements[3] = _normalize_kind3(
        replacements[3],
        current_rotation,
        is_application=is_application,
    )
    replacements[4] = _normalize_kind4(
        replacements[4],
        current_rotation,
        is_application=is_application,
    )

    target_rotation = (current_rotation + degrees) % 360
    if target_rotation:
        if is_application:
            replacements[2] = _rotate_application_kind2(
                replacements[2], target_rotation
            )
            if target_rotation in {90, 270}:
                replacements[3] = _rotate_kind3(replacements[3])
        elif target_rotation in {90, 270}:
            replacements[2] = _rotate_kind2(replacements[2])
            replacements[3] = _rotate_kind3(replacements[3])
    if target_rotation:
        replacements[4] = _rotate_kind4(
            replacements[4], target_rotation, is_application=is_application
        )

    output = []
    replacement_start = 2 + page_index * 3
    for index, record in enumerate(records):
        if replacement_start <= index < replacement_start + 3:
            output.append(replacements[index - replacement_start + 2])
        else:
            output.append(_field_bytes(metadata, record))
    return b"".join(output)


def shift_kind4_resource_indices(record_bytes: bytes, shift: int) -> bytes:
    """Shift resource indices in an observed kind-4 page record.

    ``C7`` identifies the main page resource; each observed ``DF`` envelope
    identifies an additional resource (one preview for scan pages, or JPEG
    objects for application pages).  The index is a one-byte value nested in
    ``81 01 <index>``.  Only those fixed envelopes are changed; opaque EMF and
    object metadata bytes remain byte-for-byte intact.
    """

    if isinstance(shift, bool) or not isinstance(shift, int):
        raise TypeError("resource-index shift must be an integer")
    if shift < 0 or shift > 0xFE:
        raise ValueError("resource-index shift must fit in one byte")
    record = decode_field(record_bytes, 0, len(record_bytes))
    if record.tag != 0x62 or record.end_offset != len(record_bytes):
        raise XdwUnsupportedLayoutError("invalid kind-4 metadata envelope")
    kind = decode_field(record_bytes, record.value_offset, record.end_offset)
    if kind.tag != 0x80 or value(record_bytes, kind) != b"\x04":
        raise XdwUnsupportedLayoutError("metadata record is not kind 4")

    rewritten = bytearray(record_bytes)
    c7_index = _find_c7_reference(record_bytes, kind.end_offset)
    if c7_index < 0 or c7_index + 5 > len(record_bytes):
        raise XdwUnsupportedLayoutError("kind-4 record lacks a C7 resource reference")
    c7_value_offset = c7_index + 4
    if record_bytes[c7_index + 2:c7_index + 4] != b"\x81\x01":
        raise XdwUnsupportedLayoutError("unexpected C7 resource reference")
    if record_bytes[c7_value_offset] + shift > 0xFF:
        raise XdwUnsupportedLayoutError("shifted C7 resource index exceeds one byte")
    rewritten[c7_value_offset] = record_bytes[c7_value_offset] + shift

    # DF is either the short observed tag ``df 3a`` or an extended tag such as
    # ``df 82 2d``.  In both forms the first nested field is 81/01/index.
    cursor = c7_index + 2
    references = 0
    while True:
        df_index = record_bytes.find(b"\xdf", cursor)
        if df_index < 0:
            break
        nested = record_bytes.find(b"\x81\x01", df_index + 2)
        if nested < 0:
            break
        value_offset = nested + 2
        if value_offset >= len(record_bytes):
            raise XdwUnsupportedLayoutError("truncated DF resource reference")
        if record_bytes[value_offset] + shift > 0xFF:
            raise XdwUnsupportedLayoutError("shifted DF resource index exceeds one byte")
        rewritten[value_offset] = record_bytes[value_offset] + shift
        references += 1
        cursor = value_offset + 1
    if references == 0:
        raise XdwUnsupportedLayoutError("kind-4 record lacks a DF resource reference")
    return bytes(rewritten)


def remap_kind4_resource_indices(
    record_bytes: bytes, mapping: dict[int, int]
) -> bytes:
    """Remap all observed C7/DF resource indices using an explicit map."""

    if not isinstance(mapping, dict):
        raise TypeError("resource-index mapping must be a dict")
    record = decode_field(record_bytes, 0, len(record_bytes))
    if record.tag != 0x62 or record.end_offset != len(record_bytes):
        raise XdwUnsupportedLayoutError("invalid kind-4 metadata envelope")
    kind = decode_field(record_bytes, record.value_offset, record.end_offset)
    if kind.tag != 0x80 or value(record_bytes, kind) != b"\x04":
        raise XdwUnsupportedLayoutError("metadata record is not kind 4")

    rewritten = bytearray(record_bytes)
    c7_index = _find_c7_reference(record_bytes, kind.end_offset)
    if c7_index < 0 or record_bytes[c7_index + 2:c7_index + 4] != b"\x81\x01":
        raise XdwUnsupportedLayoutError("kind-4 record lacks a C7 resource reference")
    c7_value_offset = c7_index + 4
    try:
        rewritten[c7_value_offset] = mapping[record_bytes[c7_value_offset]]
    except KeyError as exc:
        raise XdwUnsupportedLayoutError("C7 resource index is absent from mapping") from exc

    cursor = c7_index + 2
    references = 0
    while True:
        df_index = record_bytes.find(b"\xdf", cursor)
        if df_index < 0:
            break
        nested = record_bytes.find(b"\x81\x01", df_index + 2)
        if nested < 0:
            break
        value_offset = nested + 2
        old_index = record_bytes[value_offset]
        try:
            rewritten[value_offset] = mapping[old_index]
        except KeyError as exc:
            raise XdwUnsupportedLayoutError(
                f"DF resource index {old_index} is absent from mapping"
            ) from exc
        references += 1
        cursor = value_offset + 1
    if references == 0:
        raise XdwUnsupportedLayoutError("kind-4 record lacks a DF resource reference")
    return bytes(rewritten)
