"""Document properties (``%doc_att_*``) in the root metadata record: read and rewrite.

The root record carries a name table (field ``9F 33``) that gives every private
field number its name and kind, then one field per number:

    %doc_att_N_<i>   property name    (string; "(w" suffix = UTF-16LE, else CP932)
    %doc_att_T_<i>   property type    4 string, 2 integer, 2000000 boolean, 1000000 date
    %doc_att_V_<i>   property value   omitted when the property has no value
    %doc_att_Count   number of properties

Field numbers and order differ between files, so properties are always resolved
through the table.  :func:`rewrite_root_record` emits the layout the official
XDWAPI 9.0.11 writes when it sets a property on a document without any (verified
byte-for-byte on six official cases); other fields of the record are kept.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import XdwUnsupportedFeatureError, XdwUnsupportedLayoutError
from .page_metadata import _ber_signed_int, ber_fields
from .tlv import decode_field, encode_length

TYPE_STRING, TYPE_INTEGER, TYPE_BOOLEAN, TYPE_DATE = 4, 2, 2000000, 1000000
_TABLE_TAG = b"\x9f\x33"
_UNICODE_MARK = b"\x9f\x44"          # observed beside the property fields, value 0
_FIRST_NUMBER = 2001                  # 9F 8F 51


@dataclass(frozen=True)
class DocumentProperty:
    name: str
    type: int
    value: str | int | bool | None


def _tag(number: int) -> bytes:
    """BER private-class constructed?-no: 0x9F + base-128 tag number (as observed)."""
    digits = []
    while True:
        digits.append(number & 0x7F)
        number >>= 7
        if not number:
            break
    digits.reverse()
    return b"\x9f" + bytes([d | 0x80 for d in digits[:-1]] + [digits[-1]])


def _number(tag: bytes) -> int | None:
    if len(tag) < 2 or tag[0] != 0x9F:
        return None
    value = 0
    for byte in tag[1:]:
        value = (value << 7) | (byte & 0x7F)
    return value


def _field(tag: bytes, payload: bytes) -> bytes:
    return tag + encode_length(len(payload)) + payload


def _parse_table(payload: bytes) -> list[tuple[int, int, int, str]]:
    """``[(number, kind, flag, name)]`` from a 9F 33 name table."""
    entries, i = [], 0
    try:
        while i < len(payload):
            if payload[i] != 2:
                raise ValueError
            number = int.from_bytes(payload[i + 1:i + 3], "big")
            if payload[i + 3] != 1 or payload[i + 5] != 1 or payload[i + 7] != 1:
                raise ValueError
            kind, flag, size = payload[i + 4], payload[i + 6], payload[i + 8]
            if payload[i + 9] != size:
                raise ValueError
            name = payload[i + 10:i + 10 + size]
            if len(name) != size or not name.endswith(b"\0"):
                raise ValueError
            entries.append((number, kind, flag, name[:-1].decode("ascii")))
            i += 10 + size
    except (ValueError, IndexError, UnicodeDecodeError):
        raise XdwUnsupportedLayoutError("unknown root name-table layout") from None
    return entries


def _table_entry(number: int, kind: int, name: str) -> bytes:
    raw = name.encode("ascii") + b"\0"
    return b"\x02" + number.to_bytes(2, "big") + bytes([1, kind, 1, 0xFF, 1, len(raw), len(raw)]) + raw


def _int_payload(value: int) -> bytes:
    raw = _ber_signed_int(value)
    return bytes([len(raw)]) + raw


def _read_int(payload: bytes) -> int:
    if not payload or payload[0] != len(payload) - 1:
        raise XdwUnsupportedLayoutError("unknown property integer layout")
    return int.from_bytes(payload[1:], "big", signed=True)


def _read_text(payload: bytes, wide: bool) -> str:
    return (payload.decode("utf-16le") if wide else payload.decode("cp932")).rstrip("\0")


def _split(record: bytes):
    outer = decode_field(record, 0, len(record))
    body = record[outer.value_offset:outer.end_offset]
    fields = [(tag, body[start:end], body[value:end]) for tag, start, value, end in ber_fields(body)]
    return record[:1], fields


def read_properties(record: bytes) -> list[DocumentProperty]:
    """Document properties of a root record, in their stored order."""
    _, fields = _split(record)
    tables = [payload for tag, _, payload in fields if tag == _TABLE_TAG]
    if not tables:
        return []
    names = {number: name for number, _, _, name in _parse_table(tables[0])}
    by_name = {}
    for tag, _, payload in fields:
        name = names.get(_number(tag))
        if name and name.startswith("%doc_att_"):
            by_name[name] = payload
    if "%doc_att_Count" not in by_name:
        return []
    result = []
    for i in range(1, _read_int(by_name["%doc_att_Count"]) + 1):
        name_key = next((k for k in (f"%doc_att_N_{i}(w", f"%doc_att_N_{i}") if k in by_name), None)
        if name_key is None or f"%doc_att_T_{i}" not in by_name:
            raise XdwUnsupportedLayoutError(f"property {i} lacks its name or type")
        name = _read_text(by_name[name_key], name_key.endswith("(w"))
        if not name.startswith("%doc_att_"):
            raise XdwUnsupportedLayoutError("property name lacks the %doc_att_ prefix")
        kind = _read_int(by_name[f"%doc_att_T_{i}"])
        value_key = next((k for k in (f"%doc_att_V_{i}(w", f"%doc_att_V_{i}") if k in by_name), None)
        value = None
        if value_key is not None:
            raw = by_name[value_key]
            if kind == TYPE_STRING:
                value = _read_text(raw, value_key.endswith("(w"))
            elif kind == TYPE_BOOLEAN:
                value = bool(_read_int(raw))
            else:
                value = _read_int(raw)
        result.append(DocumentProperty(name[len("%doc_att_"):], kind, value))
    return result


def rewrite_root_record(record: bytes, properties: list[DocumentProperty]) -> bytes:
    """Replace a root record's properties, keeping every other field."""
    head, fields = _split(record)
    tables = [payload for tag, _, payload in fields if tag == _TABLE_TAG]
    table = _parse_table(tables[0]) if tables else []
    if len(tables) > 1:
        raise XdwUnsupportedLayoutError("root record has several name tables")
    property_numbers = {n for n, _, _, name in table if name.startswith("%doc_att_")}
    other_entries = [(n, k, name) for n, k, _, name in table if n not in property_numbers]
    kept = [(tag, raw) for tag, raw, _ in fields
            if tag != _TABLE_TAG and _number(tag) not in property_numbers]
    has_mark = any(tag == _UNICODE_MARK for tag, _ in kept)
    next_number = max([_FIRST_NUMBER - 1] + [n for n, _, _ in other_entries]) + 1

    new_fields, entries = [], []
    def add(name: str, kind: int, payload: bytes) -> None:
        nonlocal next_number
        new_fields.append(_field(_tag(next_number), payload))
        entries.append(_table_entry(next_number, kind, name))
        next_number += 1

    for i, prop in enumerate(properties, 1):
        if not prop.name or not isinstance(prop.name, str):
            raise ValueError("property names must be non-empty strings")
        add(f"%doc_att_N_{i}(w", 4, f"%doc_att_{prop.name}\0".encode("utf-16le"))
        add(f"%doc_att_T_{i}", 2, _int_payload(prop.type))
        if prop.type != TYPE_STRING and not has_mark:
            new_fields.append(_field(_UNICODE_MARK, b"\x01\x00"))   # official position: after T
            has_mark = True
        if prop.value is None:
            continue
        if prop.type == TYPE_STRING:
            add(f"%doc_att_V_{i}(w", 4, f"{prop.value}\0".encode("utf-16le"))
            if not has_mark:
                new_fields.append(_field(_UNICODE_MARK, b"\x01\x00"))   # official position: after V
                has_mark = True
        elif prop.type in (TYPE_INTEGER, TYPE_BOOLEAN, TYPE_DATE):
            add(f"%doc_att_V_{i}", 2, _int_payload(int(prop.value)))
        else:
            raise XdwUnsupportedFeatureError(f"unknown property type {prop.type}")
    count_field = []
    if properties:
        count_number = next_number
        count_field = [_field(_tag(count_number), _int_payload(len(properties)))]
        entries.append(_table_entry(count_number, 2, "%doc_att_Count"))

    table_payload = b"".join(_table_entry(n, k, name) for n, k, name in other_entries) + b"".join(entries)
    # Official order: kept leading fields (80, 62, ...), properties, table, count.
    body = b"".join(raw for _, raw in kept) + b"".join(new_fields)
    if table_payload:
        body += _field(_TABLE_TAG, table_payload)
    body += b"".join(count_field)
    return head + encode_length(len(body)) + body


def property_for(name: str, value) -> DocumentProperty:
    """A property from a Python value (str, bool, int; None = no value)."""
    if isinstance(value, bool):
        return DocumentProperty(name, TYPE_BOOLEAN, value)
    if isinstance(value, int):
        return DocumentProperty(name, TYPE_INTEGER, value)
    if value is None or isinstance(value, str):
        return DocumentProperty(name, TYPE_STRING, value)
    raise TypeError(f"unsupported property value type: {type(value).__name__}")
