from __future__ import annotations

import hashlib
import io
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path
from types import SimpleNamespace

from pyxdw import (
    XdwReader,
    XdwFormatError,
    XdwUnsupportedFeatureError,
    XdwUnsupportedLayoutError,
)
from pyxdw.emf import extract_emf_text
from pyxdw.experimental import (
    XdwWriter,
    compact_document_bytes,
    delete_pages_bytes,
    extract_page_bytes,
    merge_documents_bytes,
    rotate_page_bytes,
    select_pages_bytes,
    split_document_bytes,
    split_pages_bytes,
)
from pyxdw.writer import XdwWriter as PublicXdwWriter
from pyxdw.__main__ import main as cli_main
from pyxdw.lzh import (
    compress_lzh,
    compress_lzh_literals,
    decompress_lzh,
)
from pyxdw.metadata import select_scanned_metadata
from dataclasses import replace

from pyxdw.reader import (
    XdwResource,
    _group_pages,
    _type2_bmp_dimensions,
    _type5_jpeg_is_valid,
    _type5_jpeg_payload,
)
from pyxdw.tlv import decode_field, encode_field, parse_sequence

import os as _os
TESTDATA = Path(_os.environ.get("PYXDW_TESTDATA", Path(__file__).resolve().parents[1] / "testdata"))
if not TESTDATA.is_dir():
    raise unittest.SkipTest("set PYXDW_TESTDATA to a folder of XDW fixtures (see docs/validation.md)")

try:
    from PIL import Image
except ImportError:
    Image = None


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = TESTDATA / "samples"
ORACLE_OUTPUT2 = TESTDATA / "oracle-outputs/oracle-output2"


class XdwReaderTest(unittest.TestCase):












































    def test_mixed_oracle_merge_is_readable(self) -> None:
        reader = XdwReader(TESTDATA / "oracle-outputs/oracle-output" / "merge_external.xdw")
        self.assertEqual(reader.page_count, 4)
        self.assertEqual([page.resource_types[:2] for page in reader.pages[:3]],
                         [(8, 2), (9, 2), (8, 2)])
        self.assertEqual(reader.pages[3].resource_types[0], 4)
        self.assertEqual(reader.pages[3].resource_types[-1], 7)
        self.assertEqual(len(reader.pages[3].images), 25)
        split = tuple(XdwReader(data) for data in split_pages_bytes(reader))
        self.assertEqual([item.page_count for item in split], [1, 1, 1, 1])
        self.assertEqual(len(split[3].pages[0].images), 25)





    def test_legacy_v7_select_rotate_compact_and_split(self) -> None:
        source = XdwReader(TESTDATA / "oracle-outputs/oracle-output" / "merge_forward.xdw")
        source_payloads = [
            [resource.payload_bytes for resource in page.resources]
            for page in source.pages
        ]

        selected = XdwReader(select_pages_bytes(source, (2, 0)))
        self.assertEqual((selected.format_version, selected.index_tag), (7, 0x65))
        self.assertEqual([page.pixel_height for page in selected.pages], [2259, 2304])
        self.assertEqual(
            selected.current_generation.index_values[0x82],
            source.current_generation.index_values[0x82],
        )

        rotated = XdwReader(rotate_page_bytes(source, 0, 90))
        self.assertEqual(rotated.pages[0].rotation, 90)
        self.assertEqual(
            [resource.payload_bytes for resource in rotated.pages[0].resources],
            source_payloads[0],
        )

        compacted = XdwReader(compact_document_bytes(source))
        self.assertEqual((compacted.format_version, compacted.index_tag), (7, 0x65))
        self.assertEqual(len(compacted.generations), 2)
        self.assertFalse(compacted.generations[0].pages)
        self.assertFalse(compacted.generations[0].resources)

        split = tuple(XdwReader(data) for data in split_pages_bytes(source))
        self.assertEqual([item.page_count for item in split], [1, 1, 1])
        self.assertTrue(all(item.format_version == 7 for item in split))
        for index, item in enumerate(split):
            self.assertEqual(
                [resource.payload_bytes for resource in item.pages[0].resources],
                source_payloads[index],
            )

        merged = XdwReader(merge_documents_bytes((split[2], split[0])))
        self.assertEqual((merged.format_version, merged.index_tag), (7, 0x65))
        self.assertEqual([page.pixel_height for page in merged.pages], [2259, 2304])

    def test_writer_edits_legacy_v7_page_order(self) -> None:
        source = XdwReader(TESTDATA / "oracle-outputs/oracle-output" / "merge_forward.xdw")
        writer = XdwWriter(source)
        writer.remove_page(1)
        writer.rotate_page(0, 90)
        candidate = XdwReader(writer.to_bytes())
        self.assertEqual(candidate.format_version, 7)
        self.assertEqual(candidate.page_count, 2)
        self.assertEqual([page.rotation for page in candidate.pages], [90, 0])

























    def test_oracle_legacy_merge_is_readable(self) -> None:
        reader = XdwReader(TESTDATA / "oracle-outputs/oracle-output" / "merge_forward.xdw")
        self.assertEqual(reader.format_version, 7)
        self.assertEqual(reader.index_tag, 0x65)
        self.assertEqual(reader.page_count, 3)
        self.assertEqual(len(reader.generations), 4)
        self.assertEqual([len(g.pages) for g in reader.generations], [0, 1, 2, 3])
        self.assertEqual(
            [page.resource_types for page in reader.pages], [(8, 2), (9, 2), (8, 2)]
        )
        reverse = XdwReader(TESTDATA / "oracle-outputs/oracle-output" / "merge_reverse.xdw")
        self.assertEqual(
            [page.main_resource.resource_type for page in reverse.pages], [8, 9, 8]
        )
        self.assertEqual(
            reverse.pages[0].main_resource.encoded_data,
            reader.pages[2].main_resource.encoded_data,
        )



if __name__ == "__main__":
    unittest.main()


class PreviewOrientationAndAnnotationPositionTest(unittest.TestCase):
    """Preview rows are upright for every page type with a ground truth, and
    annotation positions match the official XDWAPI."""

    def _assert_upright(self, page, truth_bytes_or_path):
        try:
            from PIL import Image, ImageChops, ImageOps, ImageStat
        except ImportError:
            self.skipTest("Pillow required for orientation check")
        import io
        preview = Image.open(io.BytesIO(page.preview_bmp)).convert("L")
        source = truth_bytes_or_path
        truth = Image.open(io.BytesIO(source) if isinstance(source, bytes) else source)
        truth.load()
        truth = truth.convert("L").resize(preview.size)
        diff = lambda a, b: sum(ImageStat.Stat(ImageChops.difference(a, b)).mean)
        self.assertLess(diff(preview, truth), diff(ImageOps.flip(preview), truth))


    def test_annotation_position_matches_official_api(self):
        import json
        import zipfile
        archive = TESTDATA / "annotations-api9-phase3.zip"
        with zipfile.ZipFile(archive) as bundle:
            report = json.loads(bundle.read("report.json"))
            checked = 0
            for case in report["cases"]:
                expected = [a for block in case["annotations"] for a in block["annotations"]]
                reader = XdwReader(bundle.read(case["id"] + ".xdw"))
                found = [a for page in reader.pages for a in page.annotations]
                self.assertEqual(len(found), len(expected), case["id"])
                for annotation, truth in zip(found, expected):
                    self.assertEqual(annotation.position, (truth["nHorPos"], truth["nVerPos"]), case["id"])
                    self.assertEqual(annotation.size, (truth["nWidth"], truth["nHeight"]), case["id"])
                    checked += 1
        self.assertEqual(checked, 22)





class UnsupportedInputClassificationTest(unittest.TestCase):
    def test_protected_document_reports_protection_without_decrypting(self):
        from pyxdw import XdwProtectedDocumentError
        path = TESTDATA / "fujifilm-official" / "Windows11_JP_K1_2.xdw"
        if not path.exists():
            self.skipTest("fixture not present")
        with self.assertRaises(XdwProtectedDocumentError) as caught:
            XdwReader(path)
        self.assertIsInstance(caught.exception, XdwUnsupportedFeatureError)   # old handlers still catch it
        self.assertEqual(caught.exception.protection.kind, "UNKNOWN_SECU003")

    def test_non_xdw_input_is_named(self):
        from pyxdw import XdwNotXdwError
        for data, detected in [(b"%PDF-1.7\n", "PDF"), (b"PK\x03\x04rest", "ZIP (Office document or archive)"),
                               (b"plain text", None), (b"", None)]:
            with self.subTest(data[:8]):
                with self.assertRaises(XdwNotXdwError) as caught:
                    XdwReader(data)
                self.assertIsInstance(caught.exception, XdwFormatError)
                self.assertEqual(caught.exception.detected, detected)










