"""Checks that need no XDW sample files (they always run)."""

from __future__ import annotations

import os
import random
import unittest

import pyxdw
from pyxdw import XdwFormatError, XdwNotXdwError, XdwReader, XdwUnsupportedFeatureError
from pyxdw.lzh import compress_lzh, decompress_lzh
from pyxdw.tlv import decode_field, encode_field


class CoreTest(unittest.TestCase):
    def test_package_imports_without_docuworks(self):
        self.assertTrue(pyxdw.__version__)
        for name in ("XdwReader", "XdwWriter", "XdwPage", "XdwAnnotation", "XdwError"):
            self.assertTrue(hasattr(pyxdw, name), name)

    def test_lzh_round_trip(self):
        generator = random.Random(0)
        samples = [b"", b"a", b"abcabcabcabc" * 50, bytes(generator.randrange(256) for _ in range(5000)),
                   ("DocuWorks XDW テスト " * 40).encode("utf-8")]
        for data in samples:
            with self.subTest(size=len(data)):
                self.assertEqual(decompress_lzh(compress_lzh(data), len(data)), data)

    def test_tlv_round_trip(self):
        payload = os.urandom(300)
        encoded = encode_field(0x64, payload)
        field = decode_field(encoded, 0, len(encoded))
        self.assertEqual((field.tag, encoded[field.value_offset:field.end_offset]), (0x64, payload))

    def test_non_xdw_inputs_are_classified(self):
        for data, detected in ((b"%PDF-1.7\n", "PDF"), (b"PK\x03\x04", "ZIP")):
            with self.subTest(detected):
                with self.assertRaises(XdwNotXdwError) as caught:
                    XdwReader(data + bytes(64))
                self.assertIsInstance(caught.exception, XdwFormatError)
                self.assertIn(detected, caught.exception.detected)

    def test_malformed_emf_records_are_rejected(self):
        from pyxdw.annotation_text import _records
        for data in (bytes(8), b"\x01\x00\x00\x00", (1).to_bytes(4, "little") + (64).to_bytes(4, "little")):
            with self.subTest(data=data.hex()):
                with self.assertRaises(XdwFormatError):
                    _records(data)

    def test_annotation_edit_with_broken_appearance_stops(self):
        from pyxdw.annotation_templates import TEXT_ANNOTATION
        from pyxdw.annotation_text import _replace_cache, rewrite_text_annotation
        group = list(TEXT_ANNOTATION)
        group[1] = _replace_cache(group[1], lambda emf: bytes(8))
        with self.assertRaises(XdwFormatError):
            rewrite_text_annotation(group, "Changed")

    def test_text_outside_the_bmp_is_refused(self):
        from pyxdw.annotation_templates import TEXT_ANNOTATION
        from pyxdw.annotation_text import rewrite_text_annotation
        for text in ("確認😀", "𠮷野家"):
            with self.subTest(text=text):
                with self.assertRaises(XdwUnsupportedFeatureError):
                    rewrite_text_annotation(list(TEXT_ANNOTATION), text)


if __name__ == "__main__":
    unittest.main()
