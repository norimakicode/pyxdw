"""XDW writers for the observed v7/v10 page layouts.

These obey the verified append-only directory format and regenerate the decoded
tag 0x63 metadata. Deletion, rotation and single-page extraction reproduce the
compatibility-corpus reference bytes; document merge produces a compact
single-generation document whose content matches the merge comparison fixture
but omits the dead generations retained by append-only files. The original
unannotated fixtures were accepted by the compatibility Viewer workflow (open, save
and reopen returned the input unchanged). Annotation/OCR preservation and
type-10 rotation are additionally verified locally; Windows rendering of
those newer generated layouts remains unverified.

Directory index values are computed rather than carried over: the four-byte
integrity slot and resource identifiers use :func:`_xor_fold_le32`, and tag 0x82
accumulates orphaned bytes.  Count and length fields must use the BER signed
form (:func:`_ber_signed`) -- omitting the sign byte makes the compatibility
reader interpret a negative length and fail. See notes/UNKNOWN_INDEX_TAGS.md for
the derivations.
"""

from __future__ import annotations

import hashlib
import struct
import os
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import BinaryIO

from .errors import XdwFormatError, XdwUnsupportedFeatureError, XdwVerificationError
from .limits import budget_of
from .lzh import compress_lzh
from .metadata import rotate_page_metadata
from .reader import XdwPage, XdwReader
from .page_metadata import (
    ber_fields,
    page_blocks,
    remap_record,
    replace_annotation_int_pair,
    resource_references,
    rotate_page_block,
)
from .properties import property_for, read_properties, rewrite_root_record
from .tlv import decode_field, encode_field, parse_sequence, value

ReaderInput = (
    XdwReader | str | os.PathLike[str] | BinaryIO | bytes | bytearray | memoryview
)


def _coerce_reader(source: ReaderInput) -> XdwReader:
    """Return *source* as a reader, accepting the same inputs as XdwReader."""

    return source if isinstance(source, XdwReader) else XdwReader(source)


def _check_edit_supported(reader: XdwReader) -> None:
    metadata = reader.current_generation.metadata
    if metadata is not None and len(page_blocks(metadata, reader.page_count)[2]) != 3:
        raise XdwUnsupportedFeatureError('editing documents with original-data trailers is not verified')


def _fresh_resource_identifier(
    resource,
    output_index: int,
    used: set[int],
) -> int:
    """Create a deterministic nonzero 32-bit identifier for one resource.

    Compatibility samples derive the identifier from the resource payload alone,
    with no dependence on output position or document context. Fall back to a private
    scheme only when that value is unusable here (zero, or already taken by a
    different resource), which no observed fixture requires.
    """

    identifier = _xor_fold_le32(resource.payload_bytes)
    if identifier and identifier not in used:
        return identifier

    counter = 0
    while True:
        digest = hashlib.sha256(
            b"xdwfile-resource-id\0"
            + struct.pack("<II", output_index, counter)
            + resource.payload_bytes
        ).digest()
        identifier = int.from_bytes(digest[:4], "big")
        if identifier and identifier not in used:
            return identifier
        counter += 1


def _resource_bytes_with_identifier(resource, identifier: int) -> bytes:
    """Re-encode only a resource envelope identifier, preserving its payload."""

    payload_field = resource._data[
        resource.payload.offset : resource.payload.end_offset
    ]
    return encode_field(
        0x64,
        encode_field(0x81, identifier.to_bytes(4, "big")) + payload_field,
    )


def _unsigned_be(value: int) -> bytes:
    if value < 0:
        raise ValueError("value must not be negative")
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _xor_fold_le32(data: bytes) -> int:
    """XOR every complete little-endian 32-bit word, ignoring trailing bytes.

    Corpus comparisons match both resource identifiers and the directory integrity
    slot with this fold. Verified against the collected fixtures: the slot
    equals the fold of the tag 0x63 compressed payload in all 830 observed
    generations, and a reassigned resource identifier equals the fold of that
    resource's payload in all 43 observed cases plus ten single-bit probes.
    """

    accumulator = 0
    for offset in range(0, len(data) - len(data) % 4, 4):
        accumulator ^= int.from_bytes(data[offset : offset + 4], "little")
    return accumulator


def _ber_signed(value: int) -> bytes:
    """Encode a directory tag 0x82 value seen in compatibility files.

    Compatibility files use a BER-style signed integer: a leading zero byte is
    prepended when the high bit of the first byte would be set.  Verified
    against all 91 observed corpus generations.
    """

    if value < 0:
        raise ValueError("value must not be negative")
    if value == 0:
        return b"\x00"
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return b"\x00" + raw if raw[0] & 0x80 else raw


def _record_total(field) -> int:
    return field.header_size + field.length if field is not None else 0


def _integrity_slot_index(fields: Sequence) -> int | None:
    """Return the index of the four-byte integrity slot in a directory.

    Compatibility probes show the reference reader locates this field positionally -- two fields
    after tag 0x83 -- and ignores its tag octet, so it is found the same way
    here instead of by searching for tag 0x85.
    """

    for index, field in enumerate(fields[:-2]):
        if field.tag == 0x83:
            candidate = fields[index + 2]
            return index + 2 if candidate.length == 4 else None
    return None


def _validated_indices(
    reader: XdwReader,
    page_indices: Sequence[int],
    *,
    allow_empty: bool,
    allow_duplicates: bool = False,
) -> tuple[int, ...]:
    indices = tuple(page_indices)
    if not allow_empty and not indices:
        raise ValueError("at least one page must be selected")
    if any(isinstance(index, bool) or not isinstance(index, int) for index in indices):
        raise TypeError("page indices must be integers")
    if not allow_duplicates and len(set(indices)) != len(indices):
        raise ValueError("duplicate page indices are not supported")
    if any(index < 0 or index >= reader.page_count for index in indices):
        raise IndexError("page index out of range")
    return indices


def select_pages_bytes(reader: XdwReader, page_indices: Sequence[int]) -> bytes:
    """Append a page-selection generation and return the candidate XDW bytes.

    Structural validity is checked by :class:`XdwReader`.  The generated raw LH4
    stream and every directory index value are byte-exact against the collected
    deletion and rotation comparison fixtures. Page indices are zero-based. Repeated indices create independent resource
    copies, matching the page-duplication behavior expected from pypdf.
    """
    _check_edit_supported(reader)
    if reader.format_version not in {7, 10}:
        raise XdwUnsupportedFeatureError(
            "editing is implemented only for observed v7 and v10 documents"
        )
    selected = _validated_indices(
        reader, page_indices, allow_empty=False, allow_duplicates=True
    )

    # A directory cannot safely refer to the same resource envelope twice.
    # Materialize repeated pages as independent resource copies through the
    # existing merge path instead.
    if len(set(selected)) != len(selected):
        single_pages: dict[int, XdwReader] = {}
        ordered: list[XdwReader] = []
        for page_index in selected:
            if page_index not in single_pages:
                single_pages[page_index] = XdwReader(
                    select_pages_bytes(reader, (page_index,)), limits=reader.limits
                )
            ordered.append(single_pages[page_index])
        return merge_documents_bytes(ordered)

    generation = reader.current_generation
    metadata = generation.metadata
    if metadata is None:
        raise XdwUnsupportedFeatureError("current generation has no decoded tag 0x63")
    # A JPEG object can be shared by several pages: list each envelope once.
    resources = tuple({
        resource.offset: resource
        for page_index in selected
        for resource in reader.pages[page_index].all_resources
    }.values())
    prefix, blocks, trailer = page_blocks(metadata, reader.page_count)
    old_indices = {r.offset: i for i, r in enumerate(generation.resources)}
    mapping = {old_indices[r.offset]: i for i, r in enumerate(resources)}
    rewritten_metadata = b"".join(
        (
            *prefix,
            *(
                remap_record(record, generation.resources, mapping)
                for i in selected
                for record in blocks[i]
            ),
            *trailer,
        )
    )
    candidate = _append_generation(reader, rewritten_metadata, resources)
    _validate_preserved_pages([reader.pages[i] for i in selected], XdwReader(candidate, limits=reader.limits))
    return candidate


def remove_annotation_bytes(reader: XdwReader, page_index: int, annotation_index: int) -> bytes:
    """Remove one annotation metadata group while preserving page resources."""
    _check_edit_supported(reader)
    _validated_indices(reader, (page_index,), allow_empty=False)
    page = reader.pages[page_index]
    if annotation_index < 0 or annotation_index >= len(page.annotations):
        raise IndexError("annotation index out of range")
    generation = reader.current_generation
    if generation.metadata is None:
        raise XdwUnsupportedFeatureError("current generation has no decoded tag 0x63")
    prefix, page_blocks_list, trailer = page_blocks(generation.metadata, reader.page_count)
    blocks = list(page_blocks_list)
    records = list(blocks[page_index])
    starts = [i for i, rec in enumerate(records[2:], start=2) if b"\x80\x01\x03" in rec]
    if annotation_index >= len(starts):
        raise XdwUnsupportedFeatureError("annotation metadata cannot be located")
    begin = starts[annotation_index]
    end = starts[annotation_index + 1] if annotation_index + 1 < len(starts) else len(records)
    blocks[page_index] = tuple(records[:begin] + records[end:])
    referenced = set()
    for block in blocks:
        for rec in block:
            referenced.update(generation.resources[ref.index].offset for ref in resource_references(rec, generation.resources))
    resources_list = []
    seen_offsets = set()
    for i in range(reader.page_count):
        for resource in reader.pages[i].all_resources:
            if resource.offset in referenced and resource.offset not in seen_offsets:
                resources_list.append(resource)
                seen_offsets.add(resource.offset)
    resources = tuple(resources_list)
    old_indices = {r.offset: i for i, r in enumerate(generation.resources)}
    mapping = {old_indices[r.offset]: i for i, r in enumerate(resources)}
    rewritten = b"".join((*prefix, *(remap_record(rec, generation.resources, mapping) for block in blocks for rec in block), *trailer))
    candidate = _append_generation(reader, rewritten, resources)
    result = XdwReader(candidate, limits=reader.limits)
    if len(result.pages) != reader.page_count:
        raise XdwUnsupportedFeatureError("edited page count changed unexpectedly")
    for before, after in zip(reader.pages, result.pages):
        if [r.payload_bytes for r in before.resources] != [r.payload_bytes for r in after.resources]:
            raise XdwUnsupportedFeatureError("core page resource changed")
    return candidate


def move_annotation_bytes(
    reader: XdwReader, page_index: int, annotation_index: int, x: int, y: int
) -> bytes:
    """Move one top-level annotation to (x, y) in 0.01 mm on the displayed page.

    Only the annotation's position field changes; every resource and all other
    metadata bytes are kept. Verified: the result's metadata is byte-identical to
    the official API's fixtures that place the same text annotation elsewhere.
    Child annotations (if any) are left untouched.
    """
    _check_edit_supported(reader)
    _validated_indices(reader, (page_index,), allow_empty=False)
    page = reader.pages[page_index]
    if annotation_index < 0 or annotation_index >= len(page.annotations):
        raise IndexError("annotation index out of range")
    generation = reader.current_generation
    if generation.metadata is None:
        raise XdwUnsupportedFeatureError("current generation has no decoded tag 0x63")
    prefix, page_blocks_list, trailer = page_blocks(generation.metadata, reader.page_count)
    blocks = list(page_blocks_list)
    records = list(blocks[page_index])
    starts = [i for i, rec in enumerate(records[2:], start=2) if b"\x80\x01\x03" in rec]
    if annotation_index >= len(starts):
        raise XdwUnsupportedFeatureError("annotation metadata cannot be located")
    begin = starts[annotation_index]
    records[begin] = replace_annotation_int_pair(records[begin], b"\x9f\x34", x, y)
    blocks[page_index] = tuple(records)
    rewritten = b"".join((*prefix, *(rec for block in blocks for rec in block), *trailer))
    candidate = _append_generation(reader, rewritten, generation.resources)
    result = XdwReader(candidate, limits=reader.limits)
    _validate_preserved_pages(reader.pages, result)
    if result.pages[page_index].annotations[annotation_index].position != (x, y):
        raise XdwVerificationError("moved annotation did not round-trip")
    return candidate


_PDF_PROPERTY_NAMES = {"/Title": "title", "/Author": "author", "/Subject": "subject",
                       "/Keywords": "keywords"}


def set_document_properties_bytes(reader: XdwReader, properties) -> bytes:
    """Set document properties (pypdf ``add_metadata``) and append a generation.

    Keys are XDW property names (``"title"``, ``"author"``, ``"keywords"``,
    ``"usrdef_<name>"`` ...) or pypdf's ``"/Title"`` style; values are str,
    int or bool (``None`` = the property exists without a value).  Existing
    properties keep their order; new ones are appended.  The root record is
    rebuilt in the official XDWAPI layout (verified byte-for-byte when setting
    one property on a document without properties).
    """
    _check_edit_supported(reader)
    generation = reader.current_generation
    metadata = generation.metadata
    if metadata is None:
        raise XdwUnsupportedFeatureError("current generation has no decoded tag 0x63")
    root = parse_sequence(metadata, 0, len(metadata))[0]
    record = metadata[root.offset:root.end_offset]
    current = list(read_properties(record))
    for key, val in dict(properties).items():
        name = _PDF_PROPERTY_NAMES.get(key, key)
        if not isinstance(name, str) or not name or name.startswith("/"):
            raise ValueError(f"unsupported property name: {key!r}")
        new = property_for(name, val)
        for i, prop in enumerate(current):
            if prop.name == name:
                current[i] = new
                break
        else:
            current.append(new)
    rewritten = rewrite_root_record(record, current) + metadata[root.end_offset:]
    candidate = _append_generation(reader, metadata[:root.offset] + rewritten, generation.resources)
    result = XdwReader(candidate, limits=reader.limits)
    _validate_preserved_pages(reader.pages, result)
    expected = {p.name: p.value for p in current}
    actual = dict(result.typed_metadata)
    if actual != expected:
        raise XdwVerificationError(f"properties did not round-trip: {actual!r} != {expected!r}")
    return candidate


def set_annotation_text_bytes(
    reader: XdwReader, page_index: int, annotation_index: int, text: str
) -> bytes:
    """Change a single-line text annotation's string and its drawn appearance.

    The box is resized like the official API sizes it. See
    :mod:`pyxdw.annotation_text`.
    """
    from .annotation_text import rewrite_text_annotation
    _check_edit_supported(reader)
    _validated_indices(reader, (page_index,), allow_empty=False)
    page = reader.pages[page_index]
    if annotation_index < 0 or annotation_index >= len(page.annotations):
        raise IndexError("annotation index out of range")
    generation = reader.current_generation
    if generation.metadata is None:
        raise XdwUnsupportedFeatureError("current generation has no decoded tag 0x63")
    prefix, page_blocks_list, trailer = page_blocks(generation.metadata, reader.page_count)
    blocks = list(page_blocks_list)
    records = list(blocks[page_index])
    starts = [i for i, rec in enumerate(records[2:], start=2) if b"\x80\x01\x03" in rec]
    if annotation_index >= len(starts):
        raise XdwUnsupportedFeatureError("annotation metadata cannot be located")
    begin = starts[annotation_index]
    end = starts[annotation_index + 1] if annotation_index + 1 < len(starts) else len(records)
    records[begin:end] = rewrite_text_annotation(records[begin:end], text)
    blocks[page_index] = tuple(records)
    rewritten = b"".join((*prefix, *(rec for block in blocks for rec in block), *trailer))
    candidate = _append_generation(reader, rewritten, generation.resources)
    result = XdwReader(candidate, limits=reader.limits)
    _validate_preserved_pages(reader.pages, result)
    crlf = lambda value: value.replace("\r\n", "\n")
    if crlf(result.pages[page_index].annotations[annotation_index].extract_text()) != crlf(text):
        raise XdwVerificationError("annotation text did not round-trip")
    return candidate


def add_text_annotation_bytes(
    reader: XdwReader, page_index: int, x: int, y: int, text: str, *, unicode: bool | None = None,
    font_size: float | None = None, color=None, background=None,
) -> bytes:
    """Add a single-line text annotation at (x, y) (0.01 mm) on a page.

    Built from an official XDWAPI text annotation (MS 明朝 12 pt); the result
    matches what ``XDW_AddAnnotation`` writes for the same text and position.
    ``unicode=True`` stores the text as UTF-16 like the W API does.
    """
    from .annotation_text import new_text_annotation
    _check_edit_supported(reader)
    _validated_indices(reader, (page_index,), allow_empty=False)
    generation = reader.current_generation
    if generation.metadata is None:
        raise XdwUnsupportedFeatureError("current generation has no decoded tag 0x63")
    prefix, page_blocks_list, trailer = page_blocks(generation.metadata, reader.page_count)
    blocks = list(page_blocks_list)
    records = list(blocks[page_index])
    records[0], added = new_text_annotation(records[0], x, y, text, unicode=unicode, font_size=font_size)
    from .annotation_text import style_text_annotation
    added = style_text_annotation(added, color=color, background=background)
    blocks[page_index] = tuple(records + added)
    rewritten = b"".join((*prefix, *(rec for block in blocks for rec in block), *trailer))
    candidate = _append_generation(reader, rewritten, generation.resources)
    result = XdwReader(candidate, limits=reader.limits)
    _validate_preserved_pages(reader.pages, result)
    before = reader.pages[page_index].annotations
    after = result.pages[page_index].annotations
    crlf = lambda value: value.replace("\r\n", "\n")
    if (len(after) != len(before) + 1 or crlf(after[-1].extract_text()) != crlf(text)
            or after[-1].position != (x, y)
            or [a.raw_metadata for a in after[:-1]] != [a.raw_metadata for a in before]):
        raise XdwVerificationError("added annotation did not round-trip")
    return candidate


def add_shape_annotation_bytes(reader: XdwReader, page_index: int, kind: str, x: int, y: int,
                               *, fill=None, border=None, size: tuple[int, int] | None = None) -> bytes:
    """Add a default sticky note (``kind="sticky"``, 75 x 25 mm) or rectangle
    (``"rectangle"``, 30 x 20 mm) at (x, y) in 0.01 mm, as the official API draws them."""
    from .annotation_templates import RECTANGLE, STICKY_NOTE
    from .annotation_text import new_template_annotation
    templates = {"sticky": STICKY_NOTE, "rectangle": RECTANGLE}
    if kind not in templates:
        raise ValueError(f"kind must be one of {sorted(templates)}")
    _check_edit_supported(reader)
    _validated_indices(reader, (page_index,), allow_empty=False)
    generation = reader.current_generation
    if generation.metadata is None:
        raise XdwUnsupportedFeatureError("current generation has no decoded tag 0x63")
    prefix, page_blocks_list, trailer = page_blocks(generation.metadata, reader.page_count)
    blocks = list(page_blocks_list)
    records = list(blocks[page_index])
    from .annotation_text import TRANSPARENT, colorref, style_shape_annotation
    template = templates[kind]
    if kind == "rectangle" and fill is not None and colorref(fill) == TRANSPARENT:
        from .annotation_templates import RECTANGLE_TRANSPARENT
        template, fill = RECTANGLE_TRANSPARENT, None
    if size is not None and template is not templates[kind]:
        raise XdwUnsupportedFeatureError("resizing a transparent rectangle is not verified")
    records[0], added = new_template_annotation(records[0], template, x, y)
    if size is not None:
        from .annotation_text import resize_shape_annotation
        added = resize_shape_annotation(added, kind, *size)
    added = style_shape_annotation(added, kind, fill=fill, border=border)
    blocks[page_index] = tuple(records + added)
    rewritten = b"".join((*prefix, *(rec for block in blocks for rec in block), *trailer))
    candidate = _append_generation(reader, rewritten, generation.resources)
    result = XdwReader(candidate, limits=reader.limits)
    _validate_preserved_pages(reader.pages, result)
    after = result.pages[page_index].annotations
    if len(after) != len(reader.pages[page_index].annotations) + 1 or after[-1].position != (x, y):
        raise XdwVerificationError("added annotation did not round-trip")
    return candidate


def _validate_preserved_pages(expected, result):
    """Never return an output that drops or reassigns a page's resources."""
    if len(expected) != len(result.pages):
        raise XdwUnsupportedFeatureError("edited page count changed unexpectedly")
    for before, after in zip(expected, result.pages):
        for name in ("resources", "auxiliary_resources"):
            old = [
                (r.payload_bytes, r.declared_decoded_size)
                for r in getattr(before, name)
            ]
            new = [
                (r.payload_bytes, r.declared_decoded_size) for r in getattr(after, name)
            ]
            # A JPEG object shared with an earlier page may move in directory
            # order; the page still owns exactly the same envelopes.
            if old != new and not (any(r.is_jpeg for r in getattr(before, name))
                                   and sorted(old, key=repr) == sorted(new, key=repr)):
                raise XdwUnsupportedFeatureError(
                    f"editing did not preserve page {name}"
                )


def _append_generation(
    reader: XdwReader,
    rewritten_metadata: bytes,
    resources: Sequence,
) -> bytes:
    """Append an observed v7/v10 directory generation for a resource set."""

    generation = reader.current_generation
    # Validate the complete metadata record stream before compressing it. The
    # reader can still recover resources when optional metadata is malformed,
    # but the writer must never emit such a candidate.
    parse_sequence(rewritten_metadata, 0, len(rewritten_metadata))
    compressed_metadata = compress_lzh(rewritten_metadata)
    resources = tuple(resources)
    offsets = b"".join(struct.pack("<I", resource.offset) for resource in resources)
    new_resource_indices = {
        resource.offset: index for index, resource in enumerate(resources)
    }

    directory_children = parse_sequence(
        reader._data,
        generation.directory.value_offset,
        generation.directory.end_offset,
    )
    slot_index = _integrity_slot_index(directory_children)

    # tag 0x82 accumulates the bytes this document has orphaned: the previous
    # generation's metadata record and directory always fall out of use, plus
    # any resource envelopes the new generation stops referencing.  Verified
    # with zero residual across all 31 v10 generation transitions in the corpus.
    # v7 adds a small per-generation correction that the comparison data does not
    # v7 keeps the source value.
    dropped_size = sum(
        len(resource.raw_bytes)
        for resource in generation.resources
        if resource.offset not in {new.offset for new in resources}
    )
    tag82_value = (
        int.from_bytes(generation.index_values.get(0x82, b"\x00"), "big")
        + _record_total(generation.tag63)
        + _record_total(generation.directory)
        + dropped_size
    )

    encoded_children: list[bytes] = []
    self_length_index = None
    for position, child in enumerate(directory_children):
        if position == slot_index:
            encoded_children.append(
                encode_field(
                    child.tag, _xor_fold_le32(compressed_metadata).to_bytes(4, "big")
                )
            )
        elif child.tag == 0x82 and reader.format_version == 10:
            encoded_children.append(encode_field(0x82, _ber_signed(tag82_value)))
        elif child.tag == 0x80:
            encoded_children.append(encode_field(0x80, _ber_signed(len(resources))))
        elif child.tag == 0x81:
            # DocuWorks omits the offset list of a directory without resources
            # (business drawings made only of an inline EMF); an empty 0x81
            # field makes the official Viewer refuse the file.
            if resources:
                encoded_children.append(encode_field(0x81, offsets))
        elif child.tag == 0x83:
            encoded_children.append(
                encode_field(0x83, _ber_signed(len(rewritten_metadata)))
            )
        elif child.tag == 0x84:
            encoded_children.append(
                encode_field(0x84, _ber_signed(len(compressed_metadata)))
            )
        elif child.tag == 0x8D:
            raw = value(reader._data, child)
            if len(raw) % 8:
                raise XdwUnsupportedFeatureError("unknown tag 0x8D mapping layout")
            mappings = []
            for position in range(0, len(raw), 8):
                old_index, identifier = struct.unpack_from("<II", raw, position)
                if old_index >= len(generation.resources):
                    raise XdwUnsupportedFeatureError(
                        "tag 0x8D resource index out of range"
                    )
                resource_offset = generation.resources[old_index].offset
                if resource_offset in new_resource_indices:
                    mappings.append(
                        struct.pack(
                            "<II", new_resource_indices[resource_offset], identifier
                        )
                    )
            encoded_children.append(encode_field(0x8D, b"".join(mappings)))
        elif child.tag == 0x86:
            self_length_index = len(encoded_children)
            encoded_children.append(b"")
        else:
            encoded_children.append(reader._data[child.offset : child.end_offset])

    if self_length_index is None:
        raise XdwUnsupportedFeatureError("directory has no self-length tag 0x86")
    # tag 0x86 itself is always a 2-byte header plus a 4-byte LE integer.
    directory_payload_length = sum(map(len, encoded_children)) + 6
    encoded_children[self_length_index] = encode_field(
        0x86, struct.pack("<I", directory_payload_length)
    )
    directory = encode_field(generation.index_tag, b"".join(encoded_children))
    tag63 = encode_field(0x63, compressed_metadata)
    update = encode_field(0x61, tag63 + directory)
    candidate = reader._data + update

    # Refuse to return a writer bug even though semantic interoperability remains experimental.
    parsed = XdwReader(candidate, limits=reader.limits)
    expected_offsets = tuple(resource.offset for resource in resources)
    if parsed.current_generation.resource_offsets != expected_offsets:
        raise XdwVerificationError("generated directory did not round-trip")
    if parsed.current_generation.metadata != rewritten_metadata:
        raise XdwVerificationError("generated metadata did not round-trip")
    return candidate


def rotate_page_bytes(reader: XdwReader, page_index: int, degrees: int) -> bytes:
    """Append a candidate generation rotating one observed page clockwise.

    The decoded metadata transformation is byte-exact against all nine
    90/180/270-degree comparison files supplied for the three-page scan.
    The observed application/EMF layout is also byte-exact against its three
    rotation comparison fixtures. ``degrees`` is an increment from
    the current orientation, so two successive 90-degree calls produce 180
    degrees. Resource payloads remain untouched and directory integrity values
    are recomputed. Annotated and type-10 pages use BER field boundaries to
    update geometry while retaining their complete annotation subtrees.
    Those newer layouts have local preservation tests, not Windows rendering
    verification.
    """

    _check_edit_supported(reader)
    if reader.format_version not in {7, 9, 10}:
        raise XdwUnsupportedFeatureError(
            "rotation editing is implemented only for observed v7/v9/v10 documents"
        )
    if isinstance(page_index, bool) or not isinstance(page_index, int):
        raise TypeError("page index must be an integer")
    if page_index < 0 or page_index >= reader.page_count:
        raise IndexError("page index out of range")
    if degrees not in {90, 180, 270}:
        raise ValueError("degrees must be one of 90, 180, or 270")
    page = reader.pages[page_index]
    page_types = page.resource_types
    is_scan = page_types in {(8, 2), (9, 2)}
    is_application = len(page_types) >= 2 and page_types[0] == 4 and page_types[-1] == 7
    is_color = page_types == (10, 7)
    if page.rotation_support == "unsupported":
        raise XdwUnsupportedFeatureError(
            "rotation is implemented only for observed scan, EMF or type-10 pages "
            f"(page {page_index + 1} has resources "
            + ",".join("JPEG" if t == "JPEG" else str(t) for t in page_types) + ")"
        )
    metadata = reader.current_generation.metadata
    if metadata is None:
        raise XdwUnsupportedFeatureError("current generation has no decoded tag 0x63")
    if reader.format_version == 9 and page_types != (11, 7):
        raise XdwUnsupportedFeatureError("v9 rotation is verified only for MRC (11,7) pages")
    if page._uses_official_rotation:
        # Layouts compared with XDW_RotatePage on 2026-10-19 (oracle B1-B8).
        from .annotation_text import rotate_annotation_group
        from .page_metadata import _read_int_pair, ber_fields as _fields, official_rotate_page_block
        prefix, blocks, trailer = page_blocks(metadata, reader.page_count)
        blocks = list(blocks)
        records = list(blocks[page_index])
        head = records[0]
        outer = decode_field(head, 0, len(head))
        page_w, page_h = _read_int_pair(
            next(head[outer.value_offset + v:outer.value_offset + e]
                 for t, _, v, e in _fields(head[outer.value_offset:outer.end_offset]) if t == b"\x85"))
        starts = [i for i, r in enumerate(records[2:], 2) if b"\x80\x01\x03" in r]
        for a, b in reversed(list(zip(starts, starts[1:] + [len(records)]))):
            records[a:b] = rotate_annotation_group(records[a:b], degrees, page_w, page_h)
        blocks[page_index] = official_rotate_page_block(records, page.rotation, degrees)
        rewritten_metadata = b"".join((*prefix, *(r for b in blocks for r in b), *trailer))
    elif is_color or any(
        page.auxiliary_resources or len(page._metadata_records) > 3
        for page in reader.pages
    ):
        prefix, blocks, trailer = page_blocks(metadata, reader.page_count)
        blocks = list(blocks)
        blocks[page_index] = rotate_page_block(
            blocks[page_index],
            reader.pages[page_index].rotation,
            degrees,
        )
        rewritten_metadata = b"".join(
            (*prefix, *(r for b in blocks for r in b), *trailer)
        )
    else:
        rewritten_metadata = rotate_page_metadata(
            metadata,
            reader.page_count,
            page_index,
            reader.pages[page_index].rotation,
            degrees,
            is_application=is_application,
        )
    candidate = _append_generation(
        reader, rewritten_metadata, reader.current_generation.resources
    )
    _validate_preserved_pages(reader.pages, XdwReader(candidate, limits=reader.limits))
    return candidate


def _normalize_merge_kind2(record_bytes: bytes, page_number: int) -> bytes:
    """Normalize the observed page-number field used by the merge path.

    In the supplied v10 merge comparison, every kind-2 page record carries a
    page-number field ``83`` at the end of the record.  The first scan page and
    the application-page source place that field earlier; the merge operation
    moves it to the end and rewrites the page number.  The number is a
    ``<n><signed big-endian>`` integer as the official 261-page SDK manual
    writes it (``01 7f``, ``02 00 80``, ``02 01 00``).
    """

    from .page_metadata import _ber_signed_int
    if page_number < 1:
        raise XdwUnsupportedFeatureError("merged page number must be positive")
    outer = decode_field(record_bytes, 0, len(record_bytes))
    body = record_bytes[outer.value_offset : outer.end_offset]
    fields = [(tag, start, end) for tag, start, _, end in ber_fields(body)]
    numbered = [f for f in fields if f[0] == b"\x83"]
    if not numbered:
        return record_bytes
    _, start, end = numbered[0]
    raw = _ber_signed_int(page_number)
    replacement = encode_field(0x83, bytes([len(raw)]) + raw)
    body = body[:start] + body[end:] + replacement
    return encode_field(outer.tag, body)


def _normalize_merge_root(record_bytes: bytes, total_pages: int) -> bytes:
    """Normalize the document root record seen in the mixed merge comparison.

    Its ``9F 8F 51`` counter is a ``<n><signed big-endian>`` integer (the 261-page
    SDK manual stores ``02 01 06``).  Application roots place it after ``9F 33``;
    the merge comparison puts it before that field.
    """

    from .page_metadata import _ber_signed_int
    if total_pages < 1:
        raise XdwUnsupportedFeatureError("merged page count must be positive")
    outer = decode_field(record_bytes, 0, len(record_bytes))
    body = record_bytes[outer.value_offset : outer.end_offset]
    fields = [(tag, start, end) for tag, start, _, end in ber_fields(body)]
    counters = [f for f in fields if f[0] == b"\x9f\x8f\x51"]
    if not counters:
        return record_bytes
    _, start, end = counters[0]
    raw = _ber_signed_int(total_pages)
    payload = bytes([len(raw)]) + raw
    normalized_field = b"\x9f\x8f\x51" + bytes([len(payload)]) + payload
    without = body[:start] + body[end:]
    tables = [f for f in ber_fields(without) if f[0] == b"\x9f\x33"]
    at = tables[0][1] if tables else start
    return encode_field(outer.tag, without[:at] + normalized_field + without[at:])


def _normalize_scan_export_root(record_bytes: bytes, page_identifier: int) -> bytes:
    """Move and advance the scan-document page identifier on page export."""

    if not 1 <= page_identifier <= 0xFF:
        raise XdwUnsupportedFeatureError("export page identifier exceeds one byte")
    marker = b"\x9f\x8f\x51\x02\x01"
    index = record_bytes.find(marker)
    field_end = index + len(marker) + 1
    if index < 0 or field_end > len(record_bytes):
        return record_bytes
    field = marker + bytes([page_identifier])
    return record_bytes[:index] + record_bytes[field_end:] + field


def _next_scan_export_identifier(
    reader: XdwReader, *, forced: bool = False
) -> int | None:
    """Return the identifier allocated by the observed one-page export path.

    Single-page export comparisons advance this identifier by one and move it to
    the end of the root record, for scan and application documents alike.  A
    document that was already single-page cannot be recognized by looking at
    earlier generations, so the export path states its intent with *forced*.
    """

    if reader.format_version not in {7, 10} or reader.page_count != 1:
        return None
    if not forced and not any(
        len(generation.pages) > 1 for generation in reader.generations[:-1]
    ):
        return None
    metadata = reader.current_generation.metadata
    if metadata is None:
        return None
    records = parse_sequence(metadata, 0, len(metadata))
    if len(records) < 2:
        return None
    root = metadata[records[1].offset : records[1].end_offset]
    marker = b"\x9f\x8f\x51\x02\x01"
    index = root.find(marker)
    if index < 0 or index + len(marker) >= len(root):
        return None
    current_identifier = root[index + len(marker)]
    if current_identifier == 0xFF:
        raise XdwUnsupportedFeatureError("scan export identifier is exhausted")
    return current_identifier + 1


def _has_application_page(reader: XdwReader) -> bool:
    return any(
        page.resource_types and page.resource_types[0] == 4 for page in reader.pages
    )


def merge_documents_bytes(
    readers: Iterable[ReaderInput], *, page_export: bool = False
) -> bytes:
    """Build a readable v7/v10 candidate by concatenating documents.

    Resource payloads are copied without transcoding and page metadata is concatenated
    in the same kind-2/3/4 form observed in the cross-document merge comparison.
    The implementation currently targets documents whose page metadata exposes
    those triples (the supplied scan and one-page EMF/JPEG samples). Mixed v7/v10
    inputs use a v10 input as the output container. Zero or duplicate resource
    identifiers are replaced with deterministic,
    unique 4-byte values; all already-unique nonzero identifiers are preserved.
    The output is one compact generation: tag 0x82 is zero because nothing has
    been orphaned yet, and the integrity slot is recomputed. The compatibility
    Viewer accepts the result even though the reference merge keeps its intermediate
    generations and is therefore larger.
    """

    sources = tuple(_coerce_reader(source) for source in readers)
    for reader in sources:
        _check_edit_supported(reader)
    if not sources:
        raise ValueError("at least one XDW reader is required")
    first = sources[0]
    if first.format_version not in {7, 10}:
        raise XdwUnsupportedFeatureError(
            "only observed v7 and v10 XDW inputs are supported"
        )
    if any(source.format_version not in {7, 10} for source in sources):
        raise XdwUnsupportedFeatureError(
            "only observed v7 and v10 XDW inputs are supported"
        )
    # A v10 header/directory is the common output envelope when versions are
    # mixed. All-v7 merges retain the observed v7 header and initial empty
    # generation from the first source.
    container = next(
        (source for source in sources if source.format_version == 10),
        first,
    )

    total_pages = sum(source.page_count for source in sources)
    scan_export_identifier = (
        _next_scan_export_identifier(sources[0], forced=page_export)
        if len(sources) == 1
        else None
    )
    metadata_parts: list[bytes] = []
    all_resources = []
    resource_shift = 0

    # A mixed scan/application merge uses the application document's compact
    # root/trailer records as the output envelope.  This is the layout observed
    # in ``testdata/oracle-outputs/oracle-output/merge_external.xdw``; scan-only merges retain the first
    # source envelope because no alternate root has been established.
    template = next(
        (source for source in sources if _has_application_page(source)),
        first,
    )
    template_metadata = template.current_generation.metadata
    if template_metadata is None:
        raise XdwUnsupportedFeatureError("merge template has no decoded metadata")
    template_records = parse_sequence(template_metadata, 0, len(template_metadata))
    if len(template_records) < 5:
        raise XdwUnsupportedFeatureError("merge template metadata has no page records")

    # Document/global prefix and trailing records are emitted once from the
    # chosen template, matching the mixed-merge comparison.
    metadata_parts.extend(
        template_metadata[record.offset : record.end_offset]
        for record in template_records[:2]
    )

    output_page_number = 0
    for source in sources:
        metadata = source.current_generation.metadata
        if metadata is None:
            raise XdwUnsupportedFeatureError("input has no decoded tag 0x63 metadata")
        _, blocks, _ = page_blocks(metadata, source.page_count)
        mapping = {
            i: i + resource_shift
            for i in range(len(source.current_generation.resources))
        }
        for block in blocks:
            first_record, second_record, third_record = block[:3]
            output_page_number += 1
            metadata_parts.append(
                _normalize_merge_kind2(
                    first_record,
                    scan_export_identifier or output_page_number,
                )
            )
            metadata_parts.append(second_record)
            metadata_parts.extend(
                remap_record(record, source.current_generation.resources, mapping)
                for record in block[2:]
            )
        all_resources.extend(source.current_generation.resources)
        resource_shift += len(source.current_generation.resources)

    metadata_parts.extend(
        template_metadata[record.offset : record.end_offset]
        for record in template_records[-3:]
    )
    rewritten_metadata = b"".join(metadata_parts)

    # Normalize the root's total-page field only for the mixed observed layout.
    # Scan-only input has no application root to use as a template.
    if _has_application_page(template) or scan_export_identifier is not None:
        root_records = parse_sequence(rewritten_metadata, 0, len(rewritten_metadata))
        if len(root_records) >= 2:
            root = rewritten_metadata[
                root_records[1].offset : root_records[1].end_offset
            ]
            normalized_root = (
                _normalize_scan_export_root(root, scan_export_identifier)
                if scan_export_identifier is not None
                else _normalize_merge_root(root, total_pages)
            )
            rewritten_metadata = (
                rewritten_metadata[: root_records[1].offset]
                + normalized_root
                + rewritten_metadata[root_records[1].end_offset :]
            )

    parse_sequence(rewritten_metadata, 0, len(rewritten_metadata))

    # The generated reference documents put the resources, the tag 0x63 metadata
    # and the directory inside one tag 0x61 record: ``page_00N_official.xdw`` wraps
    # everything after the tag 0x60 header, and the v7 merges wrap everything
    # after the header plus an initial resource-free generation record.
    #
    # Append-only sources instead open with a ``61 01`` stub whose length was
    # never backfilled and therefore overlaps the first resource.  Carrying it
    # over would emit that stub and leave the body unwrapped, so the prefix
    # keeps only leading records that genuinely end before the first resource.
    first_resource_offset = min(
        resource.offset
        for generation in container.generations
        for resource in generation.resources
    )
    header_field = decode_field(container._data, 0, len(container._data))
    if header_field.tag != 0x60:
        raise XdwUnsupportedFeatureError(
            "document does not start with a tag 0x60 header"
        )
    prefix_end = header_field.end_offset
    while prefix_end < first_resource_offset:
        try:
            leading = decode_field(container._data, prefix_end, len(container._data))
        except XdwFormatError:
            break
        if leading.tag != 0x61 or leading.end_offset > first_resource_offset:
            break
        prefix_end = leading.end_offset
    prefix = container._data[:prefix_end]
    used_identifiers: set[int] = set()
    output_identifiers: list[int] = []
    encoded_resources: list[bytes] = []
    for output_index, resource in enumerate(all_resources):
        identifier = resource.identifier
        if identifier == 0 or identifier in used_identifiers:
            identifier = _fresh_resource_identifier(
                resource, output_index, used_identifiers
            )
        used_identifiers.add(identifier)
        output_identifiers.append(identifier)
        encoded_resources.append(
            resource.raw_bytes
            if identifier == resource.identifier
            else _resource_bytes_with_identifier(resource, identifier)
        )
    resource_blob = b"".join(encoded_resources)
    compressed_metadata = compress_lzh(rewritten_metadata)

    base_fields = parse_sequence(
        container._data,
        container.current_generation.directory.value_offset,
        container.current_generation.directory.end_offset,
    )
    jpeg_mappings = []
    for index, resource in enumerate(all_resources):
        if resource.is_jpeg:
            jpeg_mappings.append(struct.pack("<II", index, output_identifiers[index]))

    slot_index = _integrity_slot_index(base_fields)

    def build_directory(new_offsets: Sequence[int]) -> bytes:
        encoded_children: list[bytes] = []
        self_length_index = None
        saw_8d = False
        for position, child in enumerate(base_fields):
            if position == slot_index:
                encoded_children.append(
                    encode_field(
                        child.tag,
                        _xor_fold_le32(compressed_metadata).to_bytes(4, "big"),
                    )
                )
            elif child.tag == 0x80:
                encoded_children.append(
                    encode_field(0x80, _ber_signed(len(all_resources)))
                )
            elif child.tag == 0x81:
                encoded_children.append(
                    encode_field(
                        0x81,
                        b"".join(struct.pack("<I", offset) for offset in new_offsets),
                    )
                )
            elif child.tag == 0x83:
                encoded_children.append(
                    encode_field(0x83, _ber_signed(len(rewritten_metadata)))
                )
            elif child.tag == 0x84:
                encoded_children.append(
                    encode_field(0x84, _ber_signed(len(compressed_metadata)))
                )
            elif child.tag == 0x8D:
                saw_8d = True
                encoded_children.append(encode_field(0x8D, b"".join(jpeg_mappings)))
            elif child.tag == 0x82:
                if jpeg_mappings and not saw_8d:
                    # A scan-only base directory has no 0x8D field; the mixed-merge
                    # mixed merge inserts the JPEG index map between 0x81 and 0x82.
                    encoded_children.append(encode_field(0x8D, b"".join(jpeg_mappings)))
                    saw_8d = True
                # A newly built document has orphaned nothing yet, and every
                # compact single-generation corpus fixture stores zero.
                encoded_children.append(encode_field(0x82, _ber_signed(0)))
            elif child.tag == 0x86:
                self_length_index = len(encoded_children)
                encoded_children.append(b"")
            else:
                encoded_children.append(
                    container._data[child.offset : child.end_offset]
                )
        if self_length_index is None:
            raise XdwUnsupportedFeatureError("directory has no self-length tag 0x86")
        if jpeg_mappings and not saw_8d:
            raise XdwUnsupportedFeatureError("could not place JPEG tag 0x8D mapping")
        directory_length = sum(map(len, encoded_children)) + 6
        encoded_children[self_length_index] = encode_field(
            0x86, struct.pack("<I", directory_length)
        )
        return encode_field(container.index_tag, b"".join(encoded_children))

    # The resource offsets recorded in tag 0x81 are absolute, so they depend on
    # the size of the tag 0x61 header that wraps the body, which in turn depends
    # on the body length.  The body *length* does not depend on the offset
    # values, so this converges after at most one correction.
    body_start = len(prefix) + 2
    while True:
        new_offsets = []
        cursor = body_start
        for encoded_resource in encoded_resources:
            new_offsets.append(cursor)
            cursor += len(encoded_resource)
        directory = build_directory(new_offsets)
        body = resource_blob + encode_field(0x63, compressed_metadata) + directory
        wrapped = encode_field(0x61, body)
        corrected_start = len(prefix) + (len(wrapped) - len(body))
        if corrected_start == body_start:
            candidate = prefix + wrapped
            break
        body_start = corrected_start
    parsed = XdwReader(candidate, limits=reader.limits)
    _validate_preserved_pages([p for source in sources for p in source.pages], parsed)
    if parsed.page_count != sum(source.page_count for source in sources):
        raise XdwVerificationError("merged candidate page count did not round-trip")
    if parsed.current_generation.metadata != rewritten_metadata:
        raise XdwVerificationError("merged metadata did not round-trip")
    parsed_identifiers = [
        resource.identifier for resource in parsed.current_generation.resources
    ]
    if any(identifier == 0 for identifier in parsed_identifiers):
        raise XdwVerificationError("merged resource identifier remained zero")
    if len(set(parsed_identifiers)) != len(parsed_identifiers):
        raise XdwVerificationError("merged resource identifiers are not unique")
    return candidate


def compact_document_bytes(source: ReaderInput) -> bytes:
    """Rebuild a v7/v10 XDW from only its current pages and resources.

    Append-only history and resources no longer referenced by the current
    directory are physically omitted. Resource payloads and current decoded
    metadata are preserved; zero/duplicate identifiers are normalized by the
    same deterministic rules as document merge.
    """

    reader = _coerce_reader(source)
    candidate = merge_documents_bytes((reader,))
    parsed = XdwReader(candidate, limits=reader.limits)
    historical_content = any(
        generation.pages or generation.resources
        for generation in parsed.generations[:-1]
    )
    if historical_content:
        raise XdwVerificationError(
            "compacted document retained old page/resource generations"
        )
    if reader.format_version == 10 and len(parsed.generations) != 1:
        raise XdwVerificationError("compacted v10 document retained old generations")
    if parsed.page_count != reader.page_count:
        raise XdwVerificationError("compacted document page count changed")
    expected_payloads = [
        resource.payload_bytes for resource in reader.current_generation.resources
    ]
    actual_payloads = [
        resource.payload_bytes for resource in parsed.current_generation.resources
    ]
    if actual_payloads != expected_payloads:
        raise XdwVerificationError("compacted document resource payloads changed")
    return candidate


def delete_pages_bytes(reader: XdwReader, page_indices: Sequence[int]) -> bytes:
    """Append a generation with the requested zero-based pages removed.

    This is a convenience wrapper around :func:`select_pages_bytes` and has
    the same interoperability limitation.  Deleting every page is rejected
    because no zero-page XDW sample has been observed.
    """
    deleted = _validated_indices(reader, page_indices, allow_empty=True)
    if not deleted:
        return reader._data

    deleted_set = set(deleted)
    remaining = tuple(
        index for index in range(reader.page_count) if index not in deleted_set
    )
    if not remaining:
        raise ValueError("deleting every page is unsupported")
    return select_pages_bytes(reader, remaining)


def extract_page_bytes(reader: XdwReader, page_index: int) -> bytes:
    """Return one compact XDW containing only the selected zero-based page.

    Unlike :func:`select_pages_bytes`, this deliberately removes the source's
    append-only history and unselected resource envelopes. This prevents other
    pages from remaining recoverable in a nominally single-page output.
    """

    selected_index = _validated_indices(reader, (page_index,), allow_empty=False)[0]
    selected = XdwReader(select_pages_bytes(reader, (selected_index,)), limits=reader.limits)
    candidate = merge_documents_bytes((selected,), page_export=True)
    parsed = XdwReader(candidate, limits=reader.limits)
    historical_content = any(
        generation.pages or generation.resources
        for generation in parsed.generations[:-1]
    )
    if parsed.page_count != 1 or historical_content:
        raise XdwVerificationError("compact page extraction did not round-trip")
    return candidate


def split_document_bytes(
    reader: ReaderInput,
    page_groups: Iterable[Sequence[int]],
) -> tuple[bytes, ...]:
    """Return one compact XDW for each explicit group of page indices.

    Groups may reorder or repeat pages. Every output contains only the selected
    current-page resources and no recoverable input history.
    """

    source = _coerce_reader(reader)
    groups = tuple(
        _validated_indices(
            source,
            group,
            allow_empty=False,
            allow_duplicates=True,
        )
        for group in page_groups
    )
    if not groups:
        raise ValueError("at least one page group is required")
    return tuple(
        compact_document_bytes(select_pages_bytes(source, group)) for group in groups
    )


def split_pages_bytes(
    reader: ReaderInput,
    pages_per_file: int = 1,
) -> tuple[bytes, ...]:
    """Split current pages into compact consecutive chunks.

    ``pages_per_file=1`` preserves the original one-page-per-output behavior.
    """

    if isinstance(pages_per_file, bool) or not isinstance(pages_per_file, int):
        raise TypeError("pages_per_file must be an integer")
    if pages_per_file <= 0:
        raise ValueError("pages_per_file must be positive")
    source = _coerce_reader(reader)
    if source.page_count == 0:
        return ()
    groups = (
        tuple(range(start, min(start + pages_per_file, source.page_count)))
        for start in range(0, source.page_count, pages_per_file)
    )
    return split_document_bytes(source, groups)


class _WriterPages(Sequence):
    """Live view of :attr:`XdwWriter.pages` (``del writer.pages[0]`` removes a page)."""

    def __init__(self, writer: "XdwWriter") -> None:
        self._writer = writer

    def __len__(self) -> int:
        return self._writer.page_count

    def __getitem__(self, index):
        return self._writer._current_pages()[index]

    def __delitem__(self, index) -> None:
        indices = range(len(self))[index]
        for i in sorted([indices] if isinstance(indices, int) else indices, reverse=True):
            self._writer.remove_page(i)

    def __eq__(self, other) -> bool:
        return tuple(self) == tuple(other) if isinstance(other, Sequence) else NotImplemented

    def __repr__(self) -> str:
        return f"XdwWriterPages({list(self)!r})"


class XdwWriter:
    """pypdf-style stateful writer for observed v7/v10 XDW page editing.

    The writer supports selection, duplication, deletion, insertion and
    reordering. Sources accepted by :class:`XdwReader` can be passed directly
    to the constructor, ``append``, and :meth:`merge`. Cross-document operations
    materialize an observed v7/v10 merge candidate. Mixed-version output uses
    a v10 container. Output has the same
    interoperability caveat as :func:`select_pages_bytes`.
    """

    def __init__(
        self, source: ReaderInput | None = None, *, clone_from: ReaderInput | None = None
    ) -> None:
        self._reader: XdwReader | None = None
        self._page_indices: list[int] = []
        if source is not None and clone_from is not None:
            raise TypeError("pass either source or clone_from, not both")
        source = clone_from if clone_from is not None else source   # pypdf: PdfWriter(clone_from=...)
        if source is not None:
            self.clone_document_from_reader(source)

    def __enter__(self) -> "XdwWriter":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def add_metadata(self, infos) -> None:
        """Set document properties (pypdf ``PdfWriter.add_metadata``).

        ``writer.add_metadata({"/Title": "...", "usrdef_承認": True})``.
        See :func:`set_document_properties_bytes`.
        """
        reader = self._materialized_reader()
        self._reader = XdwReader(set_document_properties_bytes(reader, infos), limits=reader.limits)
        self._page_indices = list(range(self._reader.page_count))

    def close(self) -> None:
        """pypdf compatibility: nothing is held open, so this only releases the pages."""
        self._reader = None
        self._page_indices = []

    @classmethod
    def merge(cls, readers: Iterable[ReaderInput]) -> "XdwWriter":
        """Create a writer from a pure-Python v7/v10 merge candidate."""

        return cls(XdwReader(merge_documents_bytes(readers)))

    @property
    def pages(self) -> "_WriterPages":
        """The writer's pages; supports ``len``, indexing, iteration and ``del``."""
        return _WriterPages(self)

    def _current_pages(self) -> tuple[XdwPage, ...]:
        if self._reader is None:
            return ()
        return tuple(self._reader.pages[index] for index in self._page_indices)

    def _apply_requested_rotation(self, page: XdwPage, writer_index: int) -> None:
        """Write a rotation requested with ``page.rotate()`` (pypdf style)."""
        source, page_index = self._page_source(page)
        delta = (page.rotation - source.pages[page_index].rotation) % 360
        if delta:
            try:
                self.rotate_page(writer_index, delta)
            except XdwUnsupportedFeatureError:
                self.remove_page(writer_index)   # leave the writer as it was before the add
                raise

    @property
    def page_count(self) -> int:
        return len(self._page_indices)

    def _require_reader(self) -> XdwReader:
        if self._reader is None:
            raise ValueError("writer has no source document")
        return self._reader

    @staticmethod
    def _same_source(left: XdwReader, right: XdwReader) -> bool:
        return left.format_version == right.format_version and left._data == right._data

    def _accept_reader(self, reader: XdwReader) -> XdwReader:
        if not isinstance(reader, XdwReader):
            raise TypeError("source must be an XdwReader")
        if self._reader is None:
            self._reader = reader
        elif not self._same_source(self._reader, reader):
            raise XdwUnsupportedFeatureError(
                "cross-document append/merge requires regenerating resource "
                "identifiers and tag 0x63 metadata"
            )
        return self._reader

    @staticmethod
    def _page_source(page: XdwPage) -> tuple[XdwReader, int]:
        if not isinstance(page, XdwPage):
            raise TypeError("page must be an XdwPage")
        if not page.resources:
            raise ValueError("page has no resources")
        candidate = XdwReader(page.resources[0]._data,
                              limits=budget_of(page.resources[0]._data).limits)
        if page.generation_index != candidate.current_generation.index:
            raise XdwUnsupportedFeatureError(
                "only pages from the current directory generation are writable"
            )
        if page.index < 0 or page.index >= candidate.page_count:
            raise ValueError("page index does not exist in its source")
        expected = tuple(
            resource.offset for resource in candidate.pages[page.index].resources
        )
        actual = tuple(resource.offset for resource in page.resources)
        if expected != actual:
            raise ValueError("page does not match its source document")
        return candidate, page.index

    def _page_index(self, page: XdwPage) -> int:
        candidate, page_index = self._page_source(page)
        self._accept_reader(candidate)
        return page_index

    def _materialized_reader(self) -> XdwReader:
        """Return a reader whose natural page order equals the writer state."""

        reader = self._require_reader()
        if not self._page_indices:
            raise ValueError("an XDW writer cannot contain zero pages")
        if self._page_indices == list(range(reader.page_count)):
            return reader
        return XdwReader(select_pages_bytes(reader, tuple(self._page_indices)), limits=reader.limits)

    def clone_document_from_reader(self, source: ReaderInput) -> None:
        """Replace writer state with every current page from *source*."""
        reader = _coerce_reader(source)
        self._reader = None
        self._page_indices = []
        self._accept_reader(reader)
        self._page_indices.extend(range(reader.page_count))

    def append(
        self,
        source: ReaderInput,
        pages: Sequence[int] | None = None,
    ) -> None:
        """Append pages from a reader, path, bytes, or binary stream."""
        reader = _coerce_reader(source)
        selected = _validated_indices(
            reader,
            range(reader.page_count) if pages is None else pages,
            allow_empty=True,
            allow_duplicates=True,
        )
        if self._reader is None:
            self._accept_reader(reader)
            self._page_indices.extend(selected)
            return

        if not self._page_indices:
            self._reader = None
            self._accept_reader(reader)
            self._page_indices.extend(selected)
            return

        if not self._same_source(self._reader, reader):
            if not selected:
                return
            # Materialize the writer's current page order and the requested
            # external subset as readable candidates, then merge their
            # resources/metadata.  This keeps append composable after remove,
            # select, reverse, or rotate operations.
            base = self._materialized_reader()
            addition = reader
            if selected != tuple(range(reader.page_count)):
                addition = XdwReader(select_pages_bytes(reader, selected), limits=reader.limits)
            merged = XdwReader(merge_documents_bytes((base, addition)), limits=base.limits)
            self._reader = merged
            self._page_indices = list(range(merged.page_count))
            return

        for page_index in selected:
            self._page_indices.append(page_index)

    @staticmethod
    def _normalized_insertion_index(index: int, length: int) -> int:
        """Normalize an index with the same clamping rules as ``list.insert``."""

        if isinstance(index, bool) or not isinstance(index, int):
            raise TypeError("writer page index must be an integer")
        if index < 0:
            return max(0, length + index)
        return min(index, length)

    def insert_document(
        self,
        source: ReaderInput,
        index: int = 0,
        pages: Sequence[int] | None = None,
    ) -> None:
        """Insert selected pages from an XDW at one writer position.

        ``pages`` contains zero-based indices in *source*. Repeated indices are
        materialized as independent resource copies. The insertion index uses
        Python ``list.insert`` clamping semantics and refers to the current
        writer order.
        """

        insertion = self._normalized_insertion_index(index, len(self._page_indices))
        reader = _coerce_reader(source)
        selected = _validated_indices(
            reader,
            range(reader.page_count) if pages is None else pages,
            allow_empty=True,
            allow_duplicates=True,
        )
        if not selected:
            return
        if self._reader is None or not self._page_indices:
            self._reader = reader
            self._page_indices = list(selected)
            return
        if self._same_source(self._reader, reader):
            self._page_indices[insertion:insertion] = selected
            return

        base = self._materialized_reader()
        addition = reader
        if selected != tuple(range(reader.page_count)):
            addition = XdwReader(select_pages_bytes(reader, selected), limits=reader.limits)
        merged = XdwReader(merge_documents_bytes((base, addition)), limits=base.limits)
        external_indices = list(
            range(base.page_count, base.page_count + addition.page_count)
        )
        order = list(range(base.page_count))
        order[insertion:insertion] = external_indices
        self._reader = merged
        self._page_indices = order

    def add_page(self, page: XdwPage) -> XdwPage:
        """Append one current-generation page, including from another XDW.

        Returns the page as it now exists in the writer (``pypdf.PdfWriter
        .add_page`` does the same), which is a distinct object from *page*
        whenever this materializes a cross-document merge.
        """

        source, page_index = self._page_source(page)
        if self._reader is None or self._same_source(self._reader, source):
            self._accept_reader(source)
            self._page_indices.append(page_index)
        else:
            self.append(source, pages=(page_index,))
        self._apply_requested_rotation(page, self.page_count - 1)
        return self.pages[-1]

    def insert_page(self, page: XdwPage, index: int = 0) -> XdwPage:
        """Insert one current-generation page at a writer position.

        Returns the page as it now exists in the writer, at the position it
        landed after ``list.insert``-style clamping of *index* (matching
        ``pypdf.PdfWriter.insert_page``).
        """

        if isinstance(index, bool) or not isinstance(index, int):
            raise TypeError("writer page index must be an integer")
        source, page_index = self._page_source(page)
        if self._reader is None or not self._page_indices:
            self._reader = source
            self._page_indices = [page_index]
            self._apply_requested_rotation(page, 0)
            return self.pages[0]

        landed = self._normalized_insertion_index(index, len(self._page_indices))
        if self._same_source(self._reader, source):
            self._page_indices.insert(index, page_index)
            self._apply_requested_rotation(page, landed)
            return self.pages[landed]

        base = self._materialized_reader()
        addition = source
        if page_index != 0 or source.page_count != 1:
            addition = XdwReader(select_pages_bytes(source, (page_index,)), limits=source.limits)
        merged = XdwReader(merge_documents_bytes((base, addition)), limits=base.limits)
        external_index = base.page_count
        order = list(range(base.page_count))
        order.insert(index, external_index)
        self._reader = merged
        self._page_indices = order
        self._apply_requested_rotation(page, landed)
        return self.pages[landed]

    def remove_page(self, page_or_index: XdwPage | int) -> XdwPage:
        """Remove and return a writer page by writer index or page object."""
        reader = self._require_reader()
        if isinstance(page_or_index, XdwPage):
            source_index = self._page_index(page_or_index)
            try:
                writer_index = self._page_indices.index(source_index)
            except ValueError as exc:
                raise ValueError("page is not present in writer") from exc
        elif isinstance(page_or_index, bool) or not isinstance(page_or_index, int):
            raise TypeError("page must be an XdwPage or integer index")
        else:
            writer_index = page_or_index
        source_index = self._page_indices.pop(writer_index)
        return reader.pages[source_index]

    def select_pages(self, page_indices: Sequence[int]) -> None:
        """Replace writer order with source-page indices."""
        reader = self._require_reader()
        selected = _validated_indices(
            reader, page_indices, allow_empty=False, allow_duplicates=True
        )
        self._page_indices = list(selected)

    def reverse_pages(self) -> None:
        """Reverse the current writer page order in place."""
        self._page_indices.reverse()

    def rotate_page(self, page_index: int, degrees: int) -> None:
        """Rotate a writer page clockwise and make the result the new source.

        Applying the operation immediately keeps subsequent remove/select calls
        composable while preserving the append-only history in the candidate.
        Successive calls are cumulative.
        """

        reader = self._require_reader()
        if isinstance(page_index, bool) or not isinstance(page_index, int):
            raise TypeError("page index must be an integer")
        if page_index < 0 or page_index >= len(self._page_indices):
            raise IndexError("writer page index out of range")
        if self._page_indices != list(range(reader.page_count)):
            reader = self._materialized_reader()      # adopted only if the rotation succeeds
        rotated = rotate_page_bytes(reader, page_index, degrees)
        self._reader = XdwReader(rotated, limits=reader.limits)
        self._page_indices = list(range(self._reader.page_count))

    def remove_annotation(self, page_index: int, annotation_index: int) -> XdwAnnotation:
        """Remove and return an annotation from the current writer page."""
        from .reader import XdwAnnotation
        reader = self._materialized_reader()
        annotation = reader.pages[page_index].annotations[annotation_index]
        self._reader = XdwReader(remove_annotation_bytes(reader, page_index, annotation_index), limits=reader.limits)
        self._page_indices = list(range(self._reader.page_count))
        return annotation

    def move_annotation(self, page_index: int, annotation_index: int, x: int, y: int) -> None:
        """Move an annotation to (x, y), 0.01 mm on the displayed page."""
        reader = self._materialized_reader()
        self._reader = XdwReader(move_annotation_bytes(reader, page_index, annotation_index, x, y), limits=reader.limits)
        self._page_indices = list(range(self._reader.page_count))

    def set_annotation_text(self, page_index: int, annotation_index: int, text: str) -> None:
        """Change a single-line text annotation's text (string and appearance)."""
        reader = self._materialized_reader()
        self._reader = XdwReader(set_annotation_text_bytes(reader, page_index, annotation_index, text), limits=reader.limits)
        self._page_indices = list(range(self._reader.page_count))

    def add_text_annotation(self, page_index: int, x: int, y: int, text: str, *,
                            font_size: float | None = None, color=None, background=None) -> None:
        """Add a text annotation at (x, y), 0.01 mm on the displayed page.

        ``font_size`` in points; ``color``/``background`` as (r, g, b), COLORREF
        or ``background="transparent"``.
        """
        reader = self._materialized_reader()
        self._reader = XdwReader(add_text_annotation_bytes(
            reader, page_index, x, y, text, font_size=font_size, color=color, background=background), limits=reader.limits)
        self._page_indices = list(range(self._reader.page_count))

    def add_sticky_note(self, page_index: int, x: int, y: int, *, color=None,
                        size: tuple[int, int] | None = None) -> None:
        """Add a sticky note at (x, y), 0.01 mm; ``size`` (w, h) in 0.01 mm, default 75 x 25 mm."""
        reader = self._materialized_reader()
        self._reader = XdwReader(add_shape_annotation_bytes(
            reader, page_index, "sticky", x, y, fill=color, size=size), limits=reader.limits)
        self._page_indices = list(range(self._reader.page_count))

    def add_rectangle(self, page_index: int, x: int, y: int, *, fill=None, border=None,
                      size: tuple[int, int] | None = None) -> None:
        """Add a rectangle at (x, y), 0.01 mm; ``size`` default 30 x 20 mm; ``fill`` may be "transparent"."""
        reader = self._materialized_reader()
        self._reader = XdwReader(add_shape_annotation_bytes(
            reader, page_index, "rectangle", x, y, fill=fill, border=border, size=size), limits=reader.limits)
        self._page_indices = list(range(self._reader.page_count))

    def remove_annotations(self, page_index: int) -> tuple[XdwAnnotation, ...]:
        """Remove and return all annotations from one writer page."""
        reader = self._materialized_reader()
        annotations = reader.pages[page_index].annotations
        for annotation_index in range(len(annotations) - 1, -1, -1):
            reader = XdwReader(
                remove_annotation_bytes(reader, page_index, annotation_index), limits=reader.limits
            )
        self._reader = reader
        self._page_indices = list(range(reader.page_count))
        return annotations

    def to_bytes(self, *, compact: bool = True) -> bytes:
        """Build the candidate, omitting history and removed pages by default.

        Pass ``compact=False`` to retain the append-only history used by XDW files.
        Format v9 (MRC) documents are never compacted: their edits stay appended
        and earlier content remains in the file. The low-level ``select_pages_bytes``/``delete_pages_bytes`` functions
        also remain append-only.
        """
        reader = self._require_reader()
        if not self._page_indices:
            raise ValueError("an XDW writer cannot contain zero pages")
        indices = tuple(self._page_indices)
        if indices == tuple(range(reader.page_count)):
            data = reader._data
        else:
            data = select_pages_bytes(reader, indices)
        if compact and XdwReader(data, limits=reader.limits).format_version == 9:
            # v9 (MRC) documents are edited by appending, as XDW_RotatePage does;
            # compacting needs the merge path, which is verified for v7/v10 only.
            return data
        return compact_document_bytes(data) if compact else data

    def write(
        self,
        destination: str | os.PathLike[str] | BinaryIO,
        *,
        compact: bool = True,
    ) -> None:
        """Write current pages, physically omitting old content by default
        (except for format v9 documents; see :meth:`to_bytes`)."""
        data = self.to_bytes(compact=compact)
        if hasattr(destination, "write"):
            written = destination.write(data)
            if written is not None and written != len(data):
                raise OSError(f"short write: {written} of {len(data)} bytes")
            return
        Path(destination).write_bytes(data)
