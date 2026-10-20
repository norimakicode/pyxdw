"""Text edits refuse rotated text annotations (S-3) and edit boxes turned back to
0 degrees like the official API (R0-b), on external fixtures."""

from __future__ import annotations

import os as _os
from pathlib import Path
import random
import struct
import unittest
from unittest import mock

from pyxdw import XdwError, XdwFormatError, XdwReader, XdwUnsupportedFeatureError, XdwWriter
from pyxdw import annotation_text as at
from pyxdw.tlv import decode_field

TESTDATA = Path(_os.environ.get("PYXDW_TESTDATA", Path(__file__).resolve().parents[1] / "testdata"))
if not TESTDATA.is_dir():
    raise unittest.SkipTest("set PYXDW_TESTDATA to a folder of XDW fixtures (see docs/validation.md)")

ADDED = [TESTDATA / "annotation-add-api9" / name for name in ("N1.xdw", "N3.xdw")]
OFFICIAL = TESTDATA / "annotated-font-rotation-api9"   # C2 180°, C3 270°, C4 90°
TEXT_EDITS = TESTDATA / "r0-textedit-api9"   # official %Text edits, 2026-10-20 (R0-b)
TEXTS = {"S": "x", "M": "Hello PDF", "L": "Hello XDW long text 1234"}
SHIFTED = ("s4-rerotation-api9/R3/step2.xdw", "s4-followup-api9/T4/step2.xdw",
           "s4-rerotation-api9/R6/step4.xdw", "s4-followup-api9/T1/step2.xdw")


def text_group(data: bytes) -> list[bytes]:
    """Records of the first annotation on page 1."""
    records = list(XdwReader(data).pages[0]._metadata_records)
    starts = [i for i, r in enumerate(records[2:], 2) if b"\x80\x01\x03" in r]
    return records[starts[0]:starts[1] if len(starts) > 1 else len(records)]


def fields(record: bytes):
    outer = decode_field(record, 0, len(record))
    return [(bytes(t), bytes(v)) for t, v in at._fields(record[outer.value_offset:outer.end_offset])]


def values(group: list[bytes]):
    """Field values regardless of order: first record, body, cache (without the
    compressed stream) and EMF records by kind (EXTTEXTOUTW padding masked)."""
    body = fields(group[1])
    cache = [(bytes(t), bytes(v)) for t, v in at._fields(dict(body)[b"\x87"])]
    emf = []
    for record in at._records(at._decode_appearance(dict(cache))):
        if struct.unpack_from("<I", record)[0] == 84:      # the official writer pads with junk
            count, offset = struct.unpack_from("<II", record, 44)
            dx = struct.unpack_from("<I", record, 72)[0]
            record[offset + 2 * count:dx] = bytes(dx - offset - 2 * count)
        emf.append((struct.unpack_from("<I", record)[0], bytes(record)))
    return (sorted(fields(group[0])), sorted((t, v) for t, v in body if t != b"\x87"),
            sorted((t, v) for t, v in cache if t not in (b"\x86", b"\x89")), emf)


def emf_of(data: bytes) -> bytes:
    return values(text_group(data))[3]


class RotatedTextEditFixtureTest(unittest.TestCase):
    def assert_refused_without_change(self, writer: XdwWriter, error=XdwUnsupportedFeatureError):
        before = writer.to_bytes()
        state = (writer._reader, list(writer._page_indices))
        with self.assertRaises(error):
            writer.set_annotation_text(0, 0, "x")
        self.assertEqual((writer._reader, list(writer._page_indices)), state)
        self.assertEqual(writer.to_bytes(), before)

    def test_pyxdw_rotated_pages(self):
        for path in ADDED:
            for degrees in (90, 180, 270):
                with self.subTest(path=path.name, degrees=degrees):
                    writer = XdwWriter(XdwReader(path))
                    writer.rotate_page(0, degrees)
                    self.assert_refused_without_change(writer)

    def test_officially_rotated_pages(self):
        for name in ("C2", "C3", "C4"):
            with self.subTest(name=name):
                writer = XdwWriter(XdwReader(OFFICIAL / f"{name}.xdw"))
                self.assert_refused_without_change(writer)

    def test_returned_to_zero_with_shifted_window_is_editable(self):
        # Official rotations back to 0 degrees whose window stayed 2 px higher than
        # the clip (R3/T4 270+90, R6 270x4, T1 90+270 with a sticky note): R0-b.
        for name in SHIFTED:
            path = TESTDATA / name
            if not path.exists():
                self.skipTest("S-4 oracle fixtures are not available")
            with self.subTest(name=name):
                writer = XdwWriter(XdwReader(path))
                position = dict(fields(text_group(path.read_bytes())[0]))[b"\x9f\x34"]
                writer.set_annotation_text(0, 0, "x")
                data = writer.to_bytes()
                self.assertEqual(XdwReader(data).pages[0].annotations[0].extract_text(), "x")
                self.assertEqual(dict(fields(text_group(data)[0]))[b"\x9f\x34"], position)

    def test_shifted_window_edits_match_official_values(self):
        # The official API edits a shifted box as its clip: the same values as its
        # own edit, except the known 1 px bounds of a one-character box (header,
        # GDI comment, polygon: EMF records 1, 70, 86) and the field order.
        if not TEXT_EDITS.is_dir():
            self.skipTest("r0-textedit-api9 fixtures are not available")
        compared = 0
        for base in ("BR3", "BR6", "DT1"):
            for size, text in TEXTS.items():
                case = TEXT_EDITS / f"{base}_{size}"
                with self.subTest(case=case.name):
                    group = text_group((case / "before.xdw").read_bytes())
                    mine = values(at.rewrite_text_annotation(group, text, unicode=True))   # W API storage
                    official = values(text_group((case / "after.xdw").read_bytes()))
                    self.assertEqual(mine[:3], official[:3])
                    self.assertEqual([k for k, _ in mine[3]], [k for k, _ in official[3]])
                    differing = {k for (k, a), (_, b) in zip(mine[3], official[3]) if a != b}
                    self.assertLessEqual(differing, {1, 70, 86} if size == "S" else set())
                    compared += 1
        self.assertEqual(compared, 9)

    def test_shifted_window_edits_equal_normal_edits(self):
        if not TEXT_EDITS.is_dir():
            self.skipTest("r0-textedit-api9 fixtures are not available")
        for size, text in TEXTS.items():
            writer = XdwWriter(XdwReader(TEXT_EDITS / f"N0_{size}" / "before.xdw"))
            writer.set_annotation_text(0, 0, text)
            normal = emf_of(writer.to_bytes())
            for base in ("BR3", "BR6", "DT1"):
                with self.subTest(case=f"{base}_{size}"):
                    path = TEXT_EDITS / f"{base}_{size}" / "before.xdw"
                    writer = XdwWriter(XdwReader(path))
                    writer.set_annotation_text(0, 0, text)
                    data = writer.to_bytes()
                    self.assertEqual(emf_of(data), normal)
                    position = dict(fields(text_group(data)[0]))[b"\x9f\x34"]
                    official = dict(fields(text_group((TEXT_EDITS / f"{base}_{size}" / "after.xdw")
                                                      .read_bytes())[0]))[b"\x9f\x34"]
                    self.assertEqual(position, official)      # D keeps its vertical position 483
                    if base == "DT1":
                        self.assertEqual(XdwReader(data).pages[0].annotations[0].position[1], 483)

    def test_unverified_shift_changes_nothing(self):
        # Shifted boxes that differ from the verified one are refused through the
        # writer, which keeps its reader, page order and bytes.
        decode = at._decode_appearance
        for name, change in {"window 3 px higher": (0, 1), "window 2 px wider": (2, -2)}.items():
            def shifted_more(cache, budget=None, change=change):
                records = at._records(decode(cache, budget))
                for record in records:
                    if struct.unpack_from("<I", record)[0] == 9:
                        w, h = struct.unpack_from("<2i", record, 8)
                        struct.pack_into("<2i", record, 8, w + change[0], h + change[1])
                return b"".join(records)
            for path in SHIFTED:
                with self.subTest(name=name, path=path):
                    writer = XdwWriter(XdwReader(TESTDATA / path))
                    with mock.patch.object(at, "_decode_appearance", shifted_more):
                        self.assert_refused_without_change(writer)

    def test_malformed_appearance_changes_nothing(self):
        # A text record cut short is a format error (E0) through the writer, for an
        # unrotated box and for a box turned back to 0 degrees (R0-b).
        decode = at._decode_appearance

        def text_record_cut(cache, budget=None):
            records = at._records(decode(cache, budget))
            for i, record in enumerate(records):
                if struct.unpack_from("<I", record)[0] == 84:
                    records[i] = record[:60]
                    struct.pack_into("<I", records[i], 4, 60)
            return b"".join(records)
        paths = [*ADDED, *(TESTDATA / name for name in SHIFTED)]
        for path in paths:
            if not path.exists():
                continue
            with self.subTest(path=path.name):
                writer = XdwWriter(XdwReader(path))
                with mock.patch.object(at, "_decode_appearance", text_record_cut):
                    self.assert_refused_without_change(writer, XdwFormatError)

    def test_returned_to_zero_with_matching_window_is_editable(self):
        # R5 (180+180) equals an unrotated box; T6 (270+270+180) only moved.
        for name in ("s4-rerotation-api9/R5/step2.xdw", "s4-followup-api9/T6/step3.xdw"):
            path = TESTDATA / name
            if not path.exists():
                self.skipTest("S-4 oracle fixtures are not available")
            with self.subTest(name=name):
                writer = XdwWriter(XdwReader(path))
                writer.set_annotation_text(0, 0, "x")
                self.assertEqual(XdwReader(writer.to_bytes()).pages[0].annotations[0].extract_text(), "x")

    def test_unrotated_edit_still_works(self):
        for path in ADDED:
            with self.subTest(path=path.name):
                writer = XdwWriter(XdwReader(path))
                writer.set_annotation_text(0, 0, "x")
                result = XdwReader(writer.to_bytes())
                self.assertEqual(result.pages[0].annotations[0].extract_text(), "x")

    def test_rotate_then_edit_raises_only_xdw_errors(self):
        seeds = [path.read_bytes() for path in ADDED]
        generator = random.Random(20261020)
        for case in range(30):
            data = bytearray(generator.choice(seeds))
            for _ in range(generator.choice((1, 2, 4))):
                position = generator.randrange(len(data))
                data[position] ^= 1 << generator.randrange(8)
            with self.subTest(case=case):
                try:
                    writer = XdwWriter(XdwReader(bytes(data)))
                    writer.rotate_page(0, generator.choice((90, 180, 270)))
                    writer.set_annotation_text(0, 0, "x")
                except XdwError:
                    pass


if __name__ == "__main__":
    unittest.main()
