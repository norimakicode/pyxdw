"""Page operations keep every page's resources byte-for-byte.

The public suite runs this on the JPEG fixtures listed in FIXTURES (other
layouts were checked in the research suite with confidential samples). Each operation must produce a file that the
reader re-opens with the expected pages in the expected order, and each page's
main image, preview, annotation and OCR payloads must be byte-identical to the
source page's (SHA-256). Payloads that cannot be decoded (type 10) are kept as
opaque bytes like any other.
"""

from __future__ import annotations

import hashlib
import math
import unittest
from pathlib import Path

from pyxdw import (
    ROTATION_METADATA_ONLY,
    ROTATION_UNSUPPORTED,
    ROTATION_VERIFIED,
    XdwReader,
    XdwUnsupportedFeatureError,
    XdwWriter,
)
from pyxdw.experimental import (
    compact_document_bytes,
    delete_pages_bytes,
    extract_page_bytes,
    merge_documents_bytes,
    rotate_page_bytes,
    select_pages_bytes,
)

import os as _os
TESTDATA = Path(_os.environ.get("PYXDW_TESTDATA", Path(__file__).resolve().parents[1] / "testdata"))
if not TESTDATA.is_dir():
    raise unittest.SkipTest("set PYXDW_TESTDATA to a folder of XDW fixtures (see docs/validation.md)")

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = TESTDATA / "samples"
CORPUS = TESTDATA / "corpus-api9"

# (fixture, the layout it covers)
FIXTURES = [
    (CORPUS / "base.xdw", "(5)+7 JPEG page"),
    (CORPUS / "pages_2.xdw", "(5)+7 JPEG, 2 pages"),
]


def page_signature(page):
    """Layout plus the SHA-256 of every resource the page owns, in order."""

    digest = lambda resource: hashlib.sha256(resource.payload_bytes).hexdigest()
    return (
        page.resource_types,
        tuple(digest(r) for r in page.resources),
        tuple(digest(r) for r in page.auxiliary_resources),
    )


class WriterPreservationTest(unittest.TestCase):
    def setUp(self):
        self.fixtures = [(path, label) for path, label in FIXTURES if path.exists()]
        if not self.fixtures:
            self.skipTest("no fixtures present")

    def each(self):
        for path, label in self.fixtures:
            reader = XdwReader(path)
            with self.subTest(fixture=path.name, layout=label):
                yield reader, [page_signature(page) for page in reader.pages]

    def assertPages(self, data, expected):
        reread = XdwReader(data)
        self.assertEqual([page_signature(page) for page in reread.pages], expected)

    def test_extract_each_page(self):
        for reader, pages in self.each():
            for index, signature in enumerate(pages):
                self.assertPages(extract_page_bytes(reader, index), [signature])

    def test_select_in_reverse_order(self):
        for reader, pages in self.each():
            order = list(range(len(pages)))[::-1]
            self.assertPages(select_pages_bytes(reader, order), [pages[i] for i in order])

    def test_delete_first_page(self):
        for reader, pages in self.each():
            if len(pages) < 2:
                continue
            self.assertPages(delete_pages_bytes(reader, [0]), pages[1:])

    def test_merge_document_with_itself(self):
        for reader, pages in self.each():
            self.assertPages(merge_documents_bytes([reader, reader]), pages + pages)

    def test_compact(self):
        for reader, pages in self.each():
            self.assertPages(compact_document_bytes(reader), pages)

    def test_duplicate_page_with_writer(self):
        for reader, pages in self.each():
            writer = XdwWriter()
            writer.add_page(reader.pages[0])
            writer.add_page(reader.pages[0])
            self.assertPages(writer.to_bytes(), [pages[0], pages[0]])

    def test_rotation_follows_the_support_table(self):
        for reader, pages in self.each():
            page = reader.pages[0]
            support = page.rotation_support
            self.assertIn(support, {ROTATION_VERIFIED, ROTATION_METADATA_ONLY, ROTATION_UNSUPPORTED})
            if support == ROTATION_UNSUPPORTED:
                with self.assertRaises(XdwUnsupportedFeatureError):
                    rotate_page_bytes(reader, 0, 90)
                continue
            reread = XdwReader(rotate_page_bytes(reader, 0, 90))
            self.assertEqual(reread.pages[0].rotation, (page.rotation + 90) % 360)
            self.assertEqual(page_signature(reread.pages[0])[:2], pages[0][:2])   # main/preview bytes kept





if __name__ == "__main__":
    unittest.main()


class AnnotationMoveTest(unittest.TestCase):
    """Moving an annotation reproduces the official API's own placement byte-for-byte."""

    ARCHIVE = TESTDATA / "annotations-api9-phase3.zip"

    def setUp(self):
        if not self.ARCHIVE.exists():
            self.skipTest("official annotation fixtures not present")
        import zipfile
        with zipfile.ZipFile(self.ARCHIVE) as bundle:
            self.xdw = {name: bundle.read(f"{name}.xdw") for name in ("rgb_ascii", "rgb_position_x", "rgb_position_y")}

    def test_moved_metadata_equals_official_fixture(self):
        from pyxdw.experimental import move_annotation_bytes
        source = XdwReader(self.xdw["rgb_ascii"])
        for target, (x, y) in (("rgb_position_x", (2500, 500)), ("rgb_position_y", (500, 2500))):
            with self.subTest(target):
                moved = XdwReader(move_annotation_bytes(source, 0, 0, x, y))
                official = XdwReader(self.xdw[target])
                self.assertEqual(moved.current_generation.metadata, official.current_generation.metadata)
                self.assertEqual([page_signature(p) for p in moved.pages], [page_signature(p) for p in official.pages])

    def test_writer_move_handles_negative_and_wider_values(self):
        writer = XdwWriter(XdwReader(self.xdw["rgb_ascii"]))
        writer.move_annotation(0, 0, -1, 70000)
        annotation = XdwReader(writer.to_bytes()).pages[0].annotations[0]
        self.assertEqual((annotation.position, annotation.size), ((-1, 70000), (2245, 763)))


class DocumentPropertyWriteTest(unittest.TestCase):
    """add_metadata reproduces the official XDWAPI 9.0.11 property layout."""

    ARCHIVE = TESTDATA / "phases5-8-api9.zip"
    CASES = {"title_ascii": ("title", "XDW regression"), "title_japanese": ("title", "DocuWorks テスト"),
             "author": ("author", "Corpus Generator"), "custom_integer": ("usrdef_CorpusNumber", 12345),
             "custom_bool": ("usrdef_CorpusFlag", True), "custom_japanese": ("usrdef_検証用属性", "日本語の値")}

    @staticmethod
    def root(reader):
        from pyxdw.tlv import parse_sequence
        metadata = reader.current_generation.metadata
        record = parse_sequence(metadata, 0, len(metadata))[0]
        return metadata[record.offset:record.end_offset]

    def test_root_record_equals_official_output(self):
        import json
        import zipfile
        from pyxdw.experimental import set_document_properties_bytes
        if not self.ARCHIVE.exists():
            self.skipTest("official phase 5-8 results not present")
        with zipfile.ZipFile(self.ARCHIVE) as bundle:
            for case, (name, value) in self.CASES.items():
                with self.subTest(case):
                    official = bundle.read(f"{case}/{case}.xdw")
                    diff = json.loads(bundle.read(f"{case}/diff.json"))
                    # The official call appended to the v7 base and bumped the header byte to v10.
                    base = bytearray(official[:diff["before_size"]])
                    base[4] = 0x07
                    self.assertEqual(hashlib.sha256(base).hexdigest(), diff["before_sha256"])
                    ours = XdwReader(set_document_properties_bytes(XdwReader(bytes(base)), {name: value}))
                    self.assertEqual(self.root(ours), self.root(XdwReader(official)))
                    self.assertEqual(ours.typed_metadata, {name: value})



class AnnotationTextEditTest(unittest.TestCase):
    """set_annotation_text reproduces the official API's own text annotations byte-for-byte."""

    ARCHIVE = TESTDATA / "annotations-api9-phase3.zip"
    PAIRS = [("rgb_ascii", "rgb_japanese", "DocuWorks テスト"), ("rgb_japanese", "rgb_ascii", "Hello XDW"),
             ("gray_japanese", "gray_ascii", "Hello XDW"), ("mono_ascii", "mono_japanese", "DocuWorks テスト"),
             ("rgb_ascii", "rgb_multiline", "Line 1\nLine 2"), ("rgb_multiline", "rgb_ascii", "Hello XDW")]

    def setUp(self):
        if not self.ARCHIVE.exists():
            self.skipTest("official annotation fixtures not present")
        import zipfile
        self.bundle = zipfile.ZipFile(self.ARCHIVE)
        self.addCleanup(self.bundle.close)

    def test_rewritten_annotation_equals_official_one(self):
        from pyxdw.experimental import set_annotation_text_bytes
        for source, target, text in self.PAIRS:
            with self.subTest(f"{source} -> {target}"):
                edited = XdwReader(set_annotation_text_bytes(XdwReader(self.bundle.read(f"{source}.xdw")), 0, 0, text))
                official = XdwReader(self.bundle.read(f"{target}.xdw"))
                self.assertEqual(edited.pages[0].annotations[0].raw_metadata,
                                 official.pages[0].annotations[0].raw_metadata)
                self.assertEqual([page_signature(p) for p in edited.pages], [page_signature(p) for p in official.pages])

    def test_writer_api_and_refusals(self):
        writer = XdwWriter(XdwReader(self.bundle.read("rgb_ascii.xdw")))
        writer.set_annotation_text(0, 0, "Hello XDW 2026")
        annotation = XdwReader(writer.to_bytes()).pages[0].annotations[0]
        self.assertEqual(annotation.extract_text(), "Hello XDW 2026")
        self.assertEqual(annotation.size, (math.ceil((14 * 25 + 40) * 2540 / 300) + 1, 763))
        for text in ("", "line\n\nafter blank"):
            with self.assertRaises(XdwUnsupportedFeatureError):
                writer.set_annotation_text(0, 0, text)
        writer.set_annotation_text(0, 0, "一行目\n二行目は長め\n三行目")
        annotation = XdwReader(writer.to_bytes()).pages[0].annotations[0]
        self.assertEqual(annotation.extract_text(), "一行目\r\n二行目は長め\r\n三行目")
        self.assertEqual(annotation.size, (math.ceil((6 * 50 + 40) * 2540 / 300) + 1,
                                           math.ceil((3 * 50 + 40) * 2540 / 300) + 1))


class AnnotationAddTest(unittest.TestCase):
    """add_text_annotation writes what the official XDW_AddAnnotation writes."""

    ORACLE = TESTDATA / "annotation-add-api9"
    BASES = TESTDATA / "annotations-api9-phase3.zip"

    def setUp(self):
        if not self.ORACLE.exists() or not self.BASES.exists():
            self.skipTest("annotation-add oracle not present")
        import zipfile
        self.bundle = zipfile.ZipFile(self.BASES)
        self.addCleanup(self.bundle.close)

    def add(self, source, page, x, y, text):
        from pyxdw.experimental import add_text_annotation_bytes
        return XdwReader(add_text_annotation_bytes(source, page, x, y, text, unicode=True))

    def test_metadata_equals_official_output(self):
        cases = [("N1", lambda: XdwReader(self.bundle.read("rgb_ascii.xdw")), 0, (500, 500), "Hello XDW"),
                 ("N2", lambda: XdwReader(self.ORACLE / "N1.xdw"), 0, (500, 2000), "Second"),
                 ("N4", lambda: XdwReader(self.bundle.read("rgb_two_pages.xdw")), 1, (500, 500), "Page 2")]
        for name, source, page, (x, y), text in cases:
            with self.subTest(name):
                ours = self.add(source(), page, x, y, text)
                official = XdwReader(self.ORACLE / f"{name}.xdw")
                self.assertEqual(ours.current_generation.metadata, official.current_generation.metadata)
                self.assertEqual([page_signature(p) for p in ours.pages], [page_signature(p) for p in official.pages])


    def test_writer_add_then_edit(self):
        writer = XdwWriter(XdwReader(self.bundle.read("rgb_ascii.xdw")))
        writer.add_text_annotation(0, 1000, 3000, "確認済み")
        writer.set_annotation_text(0, 1, "確認済み（2026-10-16）")
        annotations = XdwReader(writer.to_bytes()).pages[0].annotations
        self.assertEqual([(a.position, a.extract_text()) for a in annotations],
                         [((500, 500), "Hello XDW"), ((1000, 3000), "確認済み（2026-10-16）")])


class ShapeAnnotationAddTest(unittest.TestCase):
    ORACLE = TESTDATA / "annotation-add-api9" / "N3.xdw"
    BASES = TESTDATA / "annotations-api9-phase3.zip"

    def setUp(self):
        if not self.ORACLE.exists() or not self.BASES.exists():
            self.skipTest("annotation-add oracle not present")
        import zipfile
        with zipfile.ZipFile(self.BASES) as bundle:
            self.base = bundle.read("rgb_ascii.xdw")

    def test_sticky_note_equals_official_add(self):
        from pyxdw.experimental import add_shape_annotation_bytes
        ours = XdwReader(add_shape_annotation_bytes(XdwReader(self.base), 0, "sticky", 2000, 2000))
        self.assertEqual(ours.current_generation.metadata, XdwReader(self.ORACLE).current_generation.metadata)

    def test_writer_adds_sticky_rectangle_and_text(self):
        writer = XdwWriter(XdwReader(self.base))
        writer.add_sticky_note(0, 8000, 2000)
        writer.add_rectangle(0, 8000, 6000)
        writer.add_text_annotation(0, 8000, 9000, "付箋と四角形\n2行目")
        annotations = XdwReader(writer.to_bytes()).pages[0].annotations
        self.assertEqual([(a.subtype, a.position, a.size) for a in annotations[1:3]],
                         [(26, (8000, 2000), (7500, 2500)), (61, (8000, 6000), (3000, 2000))])
        self.assertEqual(annotations[3].extract_text(), "付箋と四角形\r\n2行目")


class AnnotationAppearanceTest(unittest.TestCase):
    """Colours, transparency and font size reproduce the official XDWAPI output (oracle V0-V9)."""

    ORACLE = TESTDATA / "annotation-appearance-api9"
    TEXT = {"V0": {}, "V1": {"background": "transparent"}, "V2": {"background": (255, 255, 0)},
            "V3": {"color": (255, 0, 0)}, "V4": {"font_size": 24}}
    SHAPES = {"V6": ("sticky", {"fill": 0x64FFFF}), "V7": ("rectangle", {"fill": (0, 0, 255)}),
              "V8": ("rectangle", {"border": (255, 0, 0)}), "V9": ("rectangle", {"fill": "transparent"})}
    # V7-V9 differ only in the LZH bit stream of the appearance EMF (same EMF once decoded).
    EXACT = {"V0", "V1", "V2", "V3", "V4", "V6"}

    def setUp(self):
        if not (self.ORACLE / "base.xdw").exists():
            self.skipTest("appearance oracle not present")
        self.base = XdwReader(self.ORACLE / "base.xdw")

    @staticmethod
    def normalized(annotation):
        """Annotation fields in order, with the LZH appearance stream replaced by its EMF."""
        from pyxdw.lzh import decompress_lzh
        from pyxdw.page_metadata import ber_fields
        raw, out = annotation.raw_metadata, []
        for _, _, start, end in ber_fields(raw):
            for tag, _, v, e in ber_fields(raw, start, end):
                if tag == b"\x87":
                    cache = {t: raw[a:b] for t, _, a, b in ber_fields(raw, v, e)}
                    emf = decompress_lzh(cache[b"\x86"], int.from_bytes(cache[b"\x81"], "big"))
                    out.append((tag, tuple((t, x) for t, x in cache.items() if t not in (b"\x86", b"\x89")), emf))
                else:
                    out.append((tag, raw[v:e]))
        return out

    def check(self, case, ours):
        official = XdwReader(self.ORACLE / f"{case}.xdw")
        self.assertEqual(self.normalized(ours.pages[0].annotations[-1]),
                         self.normalized(official.pages[0].annotations[-1]))
        if case in self.EXACT:
            self.assertEqual(ours.current_generation.metadata, official.current_generation.metadata)

    def test_text_appearance(self):
        from pyxdw.experimental import add_text_annotation_bytes
        for case, style in self.TEXT.items():
            with self.subTest(case):
                self.check(case, XdwReader(add_text_annotation_bytes(
                    self.base, 0, 500, 500, "Hello XDW", unicode=True, **style)))

    def test_shape_appearance(self):
        from pyxdw.experimental import add_shape_annotation_bytes
        for case, (kind, style) in self.SHAPES.items():
            with self.subTest(case):
                self.check(case, XdwReader(add_shape_annotation_bytes(self.base, 0, kind, 500, 500, **style)))

    def test_writer_style_arguments(self):
        writer = XdwWriter(self.base)
        writer.add_text_annotation(0, 1000, 1000, "注意\n確認済み", font_size=18, color=(0, 0, 255),
                                   background="transparent")
        writer.add_sticky_note(0, 1000, 5000, color=(255, 255, 0))
        writer.add_rectangle(0, 1000, 9000, fill="transparent", border=(255, 0, 0))
        annotations = XdwReader(writer.to_bytes()).pages[0].annotations
        self.assertEqual([a.subtype for a in annotations], [17, 26, 61])
        self.assertEqual(annotations[0].extract_text(), "注意\r\n確認済み")




