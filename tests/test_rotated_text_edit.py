"""Text edits refuse rotated text annotations (S-3) and edit boxes whose window
stayed 2 px higher than the clip (R0-b); synthetic data, no fixtures."""

from __future__ import annotations

import struct
import unittest

from pyxdw import XdwError, XdwFormatError, XdwUnsupportedFeatureError
from pyxdw import annotation_text as at
from pyxdw.annotation_templates import TEXT_ANNOTATION
from pyxdw.properties import _parse_table, _table_entry, _tag
from pyxdw.tlv import decode_field, encode_length

ANGLE = "%TextRotationAngle"


def _body(content: bytes):
    outer = decode_field(content, 0, len(content))
    return at._fields(content[outer.value_offset:outer.end_offset])


def _record(body) -> bytes:
    joined = at._join(body)
    return b"\x62" + encode_length(len(joined)) + joined


def with_angle(content: bytes, angle: int) -> bytes:
    return at._set_fields_by_name(content, {ANGLE: angle})


def without_angle_field(content: bytes) -> bytes:
    """Keep the name-table entry but drop the field itself."""
    body = _body(content)
    numbers = {name: n for n, _, _, name in _parse_table(dict(body)[at._TABLE])}
    return _record([item for item in body if item[0] != _tag(numbers[ANGLE])])


def without_angle_name(content: bytes) -> bytes:
    """Drop both the field and its name-table entry (an attribute that is not defined)."""
    body = _body(content)
    entries = _parse_table(dict(body)[at._TABLE])
    number = next(n for n, _, _, name in entries if name == ANGLE)
    kept = []
    for item in body:
        if item[0] == _tag(number):
            continue
        if item[0] == at._TABLE:
            item = [item[0], b"".join(_table_entry(n, k, name)
                                      for n, k, _, name in entries if name != ANGLE)]
        kept.append(item)
    return _record(kept)


def with_font(content: bytes, *, escapement: int = 0, orientation: int = 0) -> bytes:
    def transform(emf: bytes) -> bytes:
        records = at._records(emf)
        for record in records:
            if struct.unpack_from("<I", record)[0] == 82:     # EXTCREATEFONTINDIRECTW
                struct.pack_into("<ii", record, 20, escapement, orientation)
        return b"".join(records)
    return at._replace_cache(content, transform)


def with_window(content: bytes, width: int) -> bytes:
    def transform(emf: bytes) -> bytes:
        records = at._records(emf)
        for record in records:
            if struct.unpack_from("<I", record)[0] == 9:      # SETWINDOWEXTEX
                struct.pack_into("<i", record, 8, width)
        return b"".join(records)
    return at._replace_cache(content, transform)


def with_records(emf: bytes, *, window=(0, 0), clip_origin=None, extra=None, drop=None,
                 reference=None, header_bounds=None, truncate=None) -> bytes:
    """Change the window extent by *window* (dw, dh) and other EMF details."""
    out = []
    for record in at._records(emf):
        kind = struct.unpack_from("<I", record)[0]
        if kind == drop:
            continue
        if kind == 9:                                      # SETWINDOWEXTEX
            width, height = struct.unpack_from("<2i", record, 8)
            struct.pack_into("<2i", record, 8, width + window[0], height + window[1])
        elif kind == 30 and clip_origin:                   # INTERSECTCLIPRECT
            struct.pack_into("<2i", record, 8, *clip_origin)
        elif kind == 84 and reference:                     # EXTTEXTOUTW reference point
            struct.pack_into("<2i", record, 36, *reference)
        elif kind == 1 and header_bounds:                  # header rclBounds right/bottom
            struct.pack_into("<2i", record, 16, *header_bounds)
        if kind == truncate:
            record = record[:12]
            struct.pack_into("<I", record, 4, 12)
        out.append(record)
        if kind == extra:
            out.append(record)
    return b"".join(out)


class RotatedTextEditTest(unittest.TestCase):
    def edit(self, content: bytes):
        return at.rewrite_text_annotation([TEXT_ANNOTATION[0], content], "x")

    def assert_refused(self, content: bytes):
        try:
            self.edit(content)
        except XdwUnsupportedFeatureError:
            return
        except Exception as exc:       # e.g. struct.error from a truncated record
            self.fail(f"raised {type(exc).__name__}, not XdwUnsupportedFeatureError")
        self.fail("edit was not refused")

    def test_unrotated_template_still_edits(self):
        first, content = self.edit(TEXT_ANNOTATION[1])
        self.assertNotEqual(content, TEXT_ANNOTATION[1])

    def test_any_nonzero_angle_is_refused(self):
        content = TEXT_ANNOTATION[1]
        for angle in (90, 180, 270, 45, 1, -90):
            with self.subTest(angle=angle):
                self.assert_refused(with_font(with_angle(content, angle),
                                              escapement=angle * 10, orientation=angle * 10))

    def test_attribute_and_drawing_disagree(self):
        content = TEXT_ANNOTATION[1]
        cases = {
            "attribute only": with_angle(content, 90),
            "escapement only": with_font(content, escapement=900),
            "orientation only": with_font(content, orientation=900),
            "attribute 0, drawing 180": with_font(with_angle(content, 0), escapement=1800,
                                                  orientation=1800),
        }
        for name, variant in cases.items():
            with self.subTest(name):
                self.assert_refused(variant)

    def test_missing_attribute(self):
        content = TEXT_ANNOTATION[1]
        # Named in the table but absent: the record is inconsistent, so refuse.
        self.assert_refused(without_angle_field(content))
        # Not defined at all: the drawing decides.
        self.edit(without_angle_name(content))
        self.assert_refused(with_font(without_angle_name(content), escapement=900))

    def test_window_two_px_higher_than_clip_edits_like_the_clip(self):
        # A text box turned back to 0 degrees can keep a window 2 px higher than
        # its clip; the official API edits it as the box of its clip (R0-b).
        shifted = at._replace_cache(TEXT_ANNOTATION[1], lambda emf: with_records(emf, window=(0, 2)))
        for text in ("x", "Hello PDF", "Hello XDW long text 1234", "ab\ncd"):
            with self.subTest(text=text):
                self.assertEqual(at.rewrite_text_annotation([TEXT_ANNOTATION[0], shifted], text),
                                 at.rewrite_text_annotation([TEXT_ANNOTATION[0], TEXT_ANNOTATION[1]], text))

    def test_other_window_and_clip_differences_are_refused(self):
        cases = {
            "window 1 px higher": dict(window=(0, 1)),
            "window 3 px higher": dict(window=(0, 3)),
            "window 2 px lower": dict(window=(0, -2)),
            "window 2 px wider": dict(window=(2, 0)),
            "window 2 px wider and higher": dict(window=(2, 2)),
            "clip origin moved": dict(window=(0, 2), clip_origin=(2, 0)),
            "two windows": dict(window=(0, 2), extra=9),
            "two clips": dict(window=(0, 2), extra=30),
            "no window": dict(drop=9),
            "no clip": dict(drop=30),
            "no clip, window 2 px higher": dict(window=(0, 2), drop=30),
            # an EMF that differs from the verified layout beyond the window
            "text reference point moved": dict(window=(0, 2), reference=(29, 29)),
            "header bounds changed": dict(window=(0, 2), header_bounds=(10, 10)),
        }
        for name, change in cases.items():
            with self.subTest(name):
                self.assert_refused(at._replace_cache(TEXT_ANNOTATION[1],
                                                      lambda emf: with_records(emf, **change)))

    def test_shifted_window_with_truncated_records_is_a_format_error(self):
        # The structure check (E0) runs before the window/clip check.
        for kind in (1, 84, 86):
            with self.subTest(record=kind):
                content = at._replace_cache(TEXT_ANNOTATION[1],
                                            lambda emf: with_records(emf, window=(0, 2), truncate=kind))
                with self.assertRaises(XdwFormatError):
                    self.edit(content)

    def test_shifted_window_still_refuses_rotated_text(self):
        # S-3 runs first: a shifted window does not make a rotated box editable.
        content = at._replace_cache(TEXT_ANNOTATION[1], lambda emf: with_records(emf, window=(0, 2)))
        self.assert_refused(with_font(with_angle(content, 90), escapement=900, orientation=900))

    def test_missing_clip_is_refused(self):
        def without_clip(emf):
            return b"".join(r for r in at._records(emf) if struct.unpack_from("<I", r)[0] != 30)
        self.assert_refused(at._replace_cache(TEXT_ANNOTATION[1], without_clip))

    def test_negative_margin_is_an_xdw_error(self):
        with self.assertRaises(XdwError) as caught:
            self.edit(with_window(TEXT_ANNOTATION[1], 10))
        self.assertNotIsInstance(caught.exception, OverflowError)


if __name__ == "__main__":
    unittest.main()
