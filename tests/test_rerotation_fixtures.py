"""Re-rotation against the official XDW_RotatePage step files (S-4 oracle, 2026-10-20)."""

from __future__ import annotations

import json
import os as _os
from pathlib import Path
import struct
import unittest
from unittest import mock

from pyxdw import XdwFormatError, XdwReader, XdwUnsupportedFeatureError, XdwWriter
from pyxdw import experimental
from pyxdw import annotation_text as at
from pyxdw.tlv import decode_field

TESTDATA = Path(_os.environ.get("PYXDW_TESTDATA", Path(__file__).resolve().parents[1] / "testdata"))
if not TESTDATA.is_dir():
    raise unittest.SkipTest("set PYXDW_TESTDATA to a folder of XDW fixtures (see docs/validation.md)")
ORACLE = TESTDATA / "s4-rerotation-api9"
FOLLOWUP = TESTDATA / "s4-followup-api9"          # T1-T6, 2026-10-20 follow-up run
HALF_TURN = TESTDATA / "s4-shape180-api9"          # H1-H4: unrotated sticky notes / rectangles at 180
if not ORACLE.is_dir() or not FOLLOWUP.is_dir() or not HALF_TURN.is_dir():
    raise unittest.SkipTest("s4-rerotation-api9 / s4-followup-api9 / s4-shape180-api9 fixtures are not available")


def annotations(data: bytes):
    """Per annotation: (first record, content fields without the compressed
    stream, EMF records with EXTTEXTOUTW padding masked)."""
    page = XdwReader(data).pages[0]
    records = list(page._metadata_records)
    starts = [i for i, r in enumerate(records[2:], 2) if b"\x80\x01\x03" in r]
    out = []
    for a, b in zip(starts, starts[1:] + [len(records)]):
        first, content = records[a], records[a + 1]
        outer = decode_field(content, 0, len(content))
        body = [(bytes(t), bytes(v)) for t, v in at._fields(content[outer.value_offset:outer.end_offset])]
        cache = [(bytes(t), bytes(v)) for t, v in at._fields(dict(body)[b"\x87"])]
        emf = None
        if body[1][1][2] == 0x11:
            emf = []
            for record in at._records(at._decode_appearance(dict(cache))):
                if struct.unpack_from("<I", record)[0] == 84:     # official writer pads with junk
                    count, offset = struct.unpack_from("<II", record, 44)
                    dx = struct.unpack_from("<I", record, 72)[0]
                    record[offset + 2 * count:dx] = bytes(dx - offset - 2 * count)
                emf.append(bytes(record))
        out.append((first, [(t, v) for t, v in body if t != b"\x87"],
                    [(t, v) for t, v in cache if t not in (b"\x86", b"\x89")], emf))
    return out


class OfficialRerotationTest(unittest.TestCase):
    def test_saved_steps_match_official_output(self):
        compared = 0
        case_dirs = ([p for p in ORACLE.glob("R*") if p.is_dir()] + [p for p in FOLLOWUP.glob("T*") if p.is_dir()]
                     + [p for p in HALF_TURN.glob("H*") if p.is_dir()])
        for case_dir in sorted(case_dirs):
            result = json.loads((case_dir / "result.json").read_text(encoding="utf-8"))
            if result["case"]["session"] != "separate":
                continue
            data = (case_dir / "before.xdw").read_bytes()
            for degrees, step in zip(result["case"]["steps"], result["steps"]):
                with self.subTest(case=case_dir.name, step=step["file"]):
                    writer = XdwWriter(XdwReader(data))
                    writer.rotate_page(0, degrees)
                    data = writer.to_bytes()
                    official = (case_dir / step["file"]).read_bytes()
                    self.assertEqual(annotations(data), annotations(official))
                    compared += 1
        self.assertEqual(compared, 19 + 15 + 5)   # R1, R3-R10, T1-T6, H1-H4/H1b: every saved step

    def test_same_session_rotations_follow_saved_semantics(self):
        # pyxdw writes the document after each rotation, so R2 (two turns on one
        # official handle) is reproduced as R1 (the same turns, saved between).
        writer = XdwWriter(XdwReader((ORACLE / "R2" / "before.xdw").read_bytes()))
        writer.rotate_page(0, 270)
        writer.rotate_page(0, 270)
        self.assertEqual(annotations(writer.to_bytes()),
                         annotations((ORACLE / "R1" / "step2.xdw").read_bytes()))

    def test_unverified_steps_change_nothing(self):
        # Back at 0 degrees with a shifted window, only +90 is verified (T4).
        cases = [("R3/step2.xdw", 180), ("R3/step2.xdw", 270), ("R6/step4.xdw", 180), ("R6/step4.xdw", 270)]
        for name, degrees in cases:
            with self.subTest(name=name, degrees=degrees):
                writer = XdwWriter(XdwReader((ORACLE / name).read_bytes()))
                before = writer.to_bytes()
                state = (writer._reader, list(writer._page_indices))
                with self.assertRaises(XdwUnsupportedFeatureError):
                    writer.rotate_page(0, degrees)
                self.assertEqual((writer._reader, list(writer._page_indices)), state)
                self.assertEqual(writer.to_bytes(), before)

    def assert_rotation_refused_without_change(self, writer: XdwWriter, error, degrees: int = 90):
        before = writer.to_bytes()
        state = (writer._reader, list(writer._page_indices))
        with self.assertRaises(error):
            writer.rotate_page(0, degrees)
        self.assertEqual((writer._reader, list(writer._page_indices)), state)
        self.assertEqual(writer.to_bytes(), before)

    def test_malformed_appearance_rotation_changes_nothing(self):
        # A text record cut short is a format error (E0-R) for unrotated, rotated and
        # shifted-window text boxes, and the writer keeps its state.
        decode = at._decode_appearance

        def text_record_cut(cache, budget=None):
            records = at._records(decode(cache, budget))
            for i, record in enumerate(records):
                if struct.unpack_from("<I", record)[0] == 84:
                    records[i] = record[:32]
                    struct.pack_into("<I", records[i], 4, 32)
            return b"".join(bytes(r) for r in records)
        rotate = at.rotate_annotation_group

        def rotating_damaged(*args, **kwargs):
            # damage only what the rotation reads, not the page checks before it
            with mock.patch.object(at, "_decode_appearance", text_record_cut):
                return rotate(*args, **kwargs)
        paths = [TESTDATA / "annotation-add-api9" / "N1.xdw", TESTDATA / "annotation-add-api9" / "N3.xdw",
                 *(TESTDATA / "annotated-font-rotation-api9" / f"{n}.xdw" for n in ("C2", "C3", "C4")),
                 ORACLE / "R3" / "step2.xdw", FOLLOWUP / "T4" / "step2.xdw", ORACLE / "R6" / "step4.xdw",
                 FOLLOWUP / "T1" / "step2.xdw"]
        for path in paths:
            if not path.exists():
                continue
            for degrees in (90, 180, 270):
                with self.subTest(path=f"{path.parent.name}/{path.name}", degrees=degrees):
                    writer = XdwWriter(XdwReader(path))
                    with mock.patch.object(at, "rotate_annotation_group", rotating_damaged):
                        self.assert_rotation_refused_without_change(writer, XdwFormatError, degrees)

    def test_refused_rotation_of_reordered_pages_changes_nothing(self):
        # R-3: the writer adopted its reordered reader before rotating, so a refused
        # rotation still replaced its reader and page order.
        for name in ("corpus-api9/pages_2.xdw", "annotation-add-api9/N4.xdw"):
            path = TESTDATA / name
            if not path.exists():
                continue
            with self.subTest(name=name):
                writer = XdwWriter(XdwReader(path))
                writer.reverse_pages()
                with mock.patch.object(experimental, "rotate_page_bytes",
                                       side_effect=XdwFormatError("refused")):
                    self.assert_rotation_refused_without_change(writer, XdwFormatError)

    def test_rotation_of_reordered_pages_is_unchanged(self):
        # The successful result is the rotation of the reordered document, as before.
        for name in ("corpus-api9/pages_2.xdw", "annotation-add-api9/N4.xdw"):
            path = TESTDATA / name
            if not path.exists():
                continue
            with self.subTest(name=name):
                writer = XdwWriter(XdwReader(path))
                writer.reverse_pages()
                reordered = writer._materialized_reader()
                expected = experimental.rotate_page_bytes(reordered, 0, 90)
                writer.rotate_page(0, 90)
                self.assertEqual(writer.to_bytes(), XdwWriter(XdwReader(expected)).to_bytes())
                self.assertEqual(writer.to_bytes(compact=False), expected)
                self.assertEqual(writer._page_indices, list(range(reordered.page_count)))

    def test_rerotated_text_is_still_not_editable(self):
        writer = XdwWriter(XdwReader((ORACLE / "R1" / "step1.xdw").read_bytes()))
        writer.rotate_page(0, 270)
        with self.assertRaises(XdwUnsupportedFeatureError):
            writer.set_annotation_text(0, 0, "x")


if __name__ == "__main__":
    unittest.main()
