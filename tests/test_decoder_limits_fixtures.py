"""Decompression limits wired through XdwReader/XdwWriter, on external fixtures."""

from __future__ import annotations

import dataclasses
import os as _os
from pathlib import Path
import random
import unittest

from pyxdw import (ROTATION_UNSUPPORTED, XdwError, XdwLimitError, XdwLimits, XdwReader,
                   XdwWriter)
from pyxdw.annotation_templates import TEXT_ANNOTATION

from test_decoder_limits import with_cache

TESTDATA = Path(_os.environ.get("PYXDW_TESTDATA", Path(__file__).resolve().parents[1] / "testdata"))
if not TESTDATA.is_dir():
    raise unittest.SkipTest("set PYXDW_TESTDATA to a folder of XDW fixtures (see docs/validation.md)")

PAGES = TESTDATA / "corpus-api9" / "pages_2.xdw"
BITMAP = TESTDATA / "corpus-api9" / "color_mono.xdw"   # full-page DIB
THUMBNAIL = TESTDATA / "corpus-api9" / "base.xdw"       # type 7 thumbnail
ANNOTATED = TESTDATA / "annotation-add-api9" / "N1.xdw"


class ReaderLimitTest(unittest.TestCase):
    def test_defaults_accept_fixtures(self):
        for path in (PAGES, BITMAP, ANNOTATED):
            with self.subTest(path=path.name):
                reader = XdwReader(path)
                self.assertEqual(reader.limits, XdwLimits())
                self.assertIsNotNone(reader.metadata)

    def test_metadata_limit_applies_when_opening(self):
        with self.assertRaises(XdwLimitError) as caught:
            XdwReader(PAGES, limits=XdwLimits(max_metadata=100))
        self.assertEqual(caught.exception.limit_name, "max_metadata")

    def test_total_budget_applies_when_opening(self):
        with self.assertRaises(XdwLimitError) as caught:
            XdwReader(PAGES, limits=XdwLimits(max_total_decoded=100))
        self.assertEqual(caught.exception.limit_name, "max_total_decoded")

    def test_cached_results_are_counted_once(self):
        reader = XdwReader(PAGES)
        self.assertGreater(reader.decoded_bytes, 0)
        reader.metadata
        used = reader.decoded_bytes
        reader.metadata
        reader.pages[0].text_records
        reader.pages[0].text_records
        once = reader.decoded_bytes
        reader.pages[0].text_records
        self.assertEqual(reader.decoded_bytes, once)
        self.assertGreaterEqual(once, used)

    def test_image_limits(self):
        reader = XdwReader(BITMAP)
        self.assertIsNotNone(reader.pages[0].main_image_bmp)
        for limits, name in ((XdwLimits(max_image_bytes=1000), "max_image_bytes"),
                             (XdwLimits(max_image_dimension=10), "max_image_dimension")):
            with self.subTest(name=name):
                page = XdwReader(BITMAP, limits=limits).pages[0]
                with self.assertRaises(XdwLimitError) as caught:
                    page.main_image_bmp
                self.assertEqual(caught.exception.limit_name, name)
                # Helpers that treat decode errors as "unavailable" must not hide limits.
                with self.assertRaises(XdwLimitError):
                    XdwReader(BITMAP, limits=limits).pages[0].image_status
        thumbnail = XdwReader(THUMBNAIL, limits=XdwLimits(max_image_bytes=10)).pages[0].thumbnail
        with self.assertRaises(XdwLimitError) as caught:
            thumbnail.decoded_pixels
        self.assertEqual(caught.exception.limit_name, "max_image_bytes")

    def test_annotation_limit_is_not_swallowed(self):
        page = XdwReader(ANNOTATED, limits=XdwLimits(max_annotation_emf=10)).pages[0]
        with self.assertRaises(XdwLimitError) as caught:
            page.rotation_support
        self.assertEqual(caught.exception.limit_name, "max_annotation_emf")

    def test_corrupt_annotation_degrades_rotation_support(self):
        page = XdwReader(ANNOTATED).pages[0]
        records = list(page._metadata_records)
        index = next(i for i, r in enumerate(records) if i >= 2 and b"\x80\x01\x03" in r)
        records[index:index + 2] = [TEXT_ANNOTATION[0],
                                    with_cache(TEXT_ANNOTATION[1], b"\xff" * 40, 3552)]
        broken = dataclasses.replace(page, _metadata_records=tuple(records))
        self.assertEqual(broken.rotation_support, ROTATION_UNSUPPORTED)

    def test_writer_keeps_reader_limits(self):
        limits = XdwLimits(max_lzh_output=32 << 20)
        writer = XdwWriter(XdwReader(ANNOTATED, limits=limits))
        writer.set_annotation_text(0, 0, "x")
        self.assertEqual(writer._reader.limits, limits)
        writer.rotate_page(0, 180)
        self.assertEqual(writer._reader.limits, limits)
        XdwReader(writer.to_bytes())


class PublicApiErrorTest(unittest.TestCase):
    """Malformed input must surface as XdwError subclasses only (SECURITY.md)."""

    def test_mutated_fixtures_raise_only_xdw_errors(self):
        seeds = [path.read_bytes() for path in (PAGES, BITMAP, ANNOTATED)]
        generator = random.Random(20261020)
        for case in range(60):
            data = bytearray(generator.choice(seeds))
            for _ in range(generator.choice((1, 2, 4, 8))):
                position = generator.randrange(len(data))
                data[position] ^= 1 << generator.randrange(8)
            with self.subTest(case=case):
                try:
                    reader = XdwReader(bytes(data))
                    reader.extract_text()
                    for page in reader.pages:
                        page.annotations, page.text_records, page.rotation_support
                        page.preview_bmp, page.main_image_bmp, page.images
                    if reader.pages:
                        writer = XdwWriter(reader)
                        writer.rotate_page(0, 90)
                        writer.to_bytes()
                        if reader.pages[0].annotations:
                            writer = XdwWriter(reader)
                            writer.set_annotation_text(0, 0, "x")
                            writer.to_bytes()
                except XdwError:
                    pass


if __name__ == "__main__":
    unittest.main()
