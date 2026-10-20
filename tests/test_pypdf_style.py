"""The pypdf idioms a user would try first work the same way on XDW.

Uses XDW files generated with the official DocuWorks API (see docs/validation.md);
skipped when PYXDW_TESTDATA does not point to them.
"""

from __future__ import annotations

import io
import os
import unittest
import zipfile
from pathlib import Path

from pyxdw import XdwReader, XdwWriter

TESTDATA = Path(os.environ.get("PYXDW_TESTDATA", Path(__file__).resolve().parents[1] / "testdata"))
if not TESTDATA.is_dir():
    raise unittest.SkipTest("set PYXDW_TESTDATA to a folder of XDW fixtures (see docs/validation.md)")

TWO_PAGES = TESTDATA / "corpus-api9" / "pages_2.xdw"          # JPEG pages (5,7)
PROPERTIES = TESTDATA / "phases5-8-api9.zip"                   # title_ascii/title_ascii.xdw


def need(*paths):
    missing = [p for p in paths if not p.exists()]
    if missing:
        raise unittest.SkipTest(f"fixture missing: {missing[0].name}")


class PypdfStyleTest(unittest.TestCase):
    def test_read_iterate_extract(self):
        need(TWO_PAGES)
        reader = XdwReader(TWO_PAGES)
        self.assertEqual(len(reader.pages), 2)
        self.assertEqual([p.index for p in reader.pages[0:2]], [0, 1])
        self.assertEqual(reader.pages[-1].index, 1)
        self.assertIsInstance(reader.pages[0].extract_text(), str)
        self.assertFalse(reader.is_encrypted)

    def test_metadata_attributes_and_pdf_keys(self):
        need(PROPERTIES)
        with zipfile.ZipFile(PROPERTIES) as bundle:
            metadata = XdwReader(bundle.read("title_ascii/title_ascii.xdw")).metadata
        self.assertEqual(metadata.title, "XDW regression")
        self.assertEqual(metadata["/Title"], metadata["title"])
        self.assertIsInstance(metadata, dict)

    def test_mediabox_in_points(self):
        need(TWO_PAGES)
        page = XdwReader(TWO_PAGES).pages[0]
        self.assertAlmostEqual(page.mediabox.width, page.width_mm / 25.4 * 72)
        self.assertAlmostEqual(page.mediabox.height, page.height_mm / 25.4 * 72)

    def test_jpeg_page_lists_its_image(self):
        need(TWO_PAGES)
        images = XdwReader(TWO_PAGES).pages[0].images
        self.assertEqual(images[0].name, "Im0.jpg")
        self.assertTrue(images[0].data.startswith(b"\xff\xd8\xff"))

    def test_writer_copy_with_context_manager(self):
        need(TWO_PAGES)
        reader, out = XdwReader(TWO_PAGES), io.BytesIO()
        with XdwWriter() as writer:
            for page in reader.pages:
                writer.add_page(page)
            writer.write(out)
        self.assertEqual(len(XdwReader(out.getvalue()).pages), 2)

    def test_clone_from_append_and_delete(self):
        need(TWO_PAGES)
        writer = XdwWriter(clone_from=XdwReader(TWO_PAGES))
        writer.append(TWO_PAGES, pages=(1,))
        self.assertEqual(len(writer.pages), 3)
        del writer.pages[0]
        self.assertEqual(len(XdwReader(writer.to_bytes()).pages), 2)

    def test_rotate_page_then_add(self):
        need(TWO_PAGES)
        reader, writer = XdwReader(TWO_PAGES), XdwWriter()
        for page in reader.pages:
            writer.add_page(page.rotate(90) if page.index == 1 else page)
        self.assertEqual([p.rotation for p in XdwReader(writer.to_bytes()).pages], [0, 90])

    def test_add_metadata(self):
        need(TWO_PAGES)
        writer = XdwWriter(XdwReader(TWO_PAGES))
        writer.add_metadata({"/Title": "Report", "usrdef_Checked": True, "usrdef_Count": 3})
        metadata = XdwReader(writer.to_bytes()).metadata
        self.assertEqual((metadata.title, metadata["usrdef_Checked"], metadata["usrdef_Count"]), ("Report", "1", "3"))


if __name__ == "__main__":
    unittest.main()
