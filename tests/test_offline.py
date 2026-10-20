"""Reader and LZH checks built from synthetic data (always run)."""

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


class OfflineTest(unittest.TestCase):
    def test_type5_jpeg_and_type2_bmp_validation(self) -> None:
        """The type-5/type-2 candidate requires both validated payloads."""
        width, height, bits = 103, 146, 24
        stride = ((width * bits + 31) // 32) * 4
        pixel_offset = 54
        bitmap = bytearray(pixel_offset + stride * height)
        bitmap[:2] = b"BM"
        struct.pack_into("<I", bitmap, 10, pixel_offset)
        struct.pack_into("<I", bitmap, 14, 40)
        struct.pack_into("<iiHHI", bitmap, 18, width, height, 1, bits, 0)
        bmp = SimpleNamespace(resource_type=2, decoded_data=bytes(bitmap))
        jpeg = SimpleNamespace(
            resource_type=5,
            pixel_width=4964,
            pixel_height=7020,
            encoded_data=b"\xff\xd8\xffpayload\xff\xd9\x00\x00",
        )
        self.assertEqual(_type2_bmp_dimensions(bmp), (103, 146, 24))
        self.assertTrue(_type5_jpeg_is_valid(jpeg))
        self.assertEqual(_type5_jpeg_payload(jpeg), b"\xff\xd8\xffpayload\xff\xd9")
        bad_bmp = SimpleNamespace(resource_type=2, decoded_data=bytes(bitmap[:-1]))
        self.assertIsNone(_type2_bmp_dimensions(bad_bmp))
        self.assertFalse(
            _type5_jpeg_is_valid(
                SimpleNamespace(
                    resource_type=5,
                    pixel_width=4964,
                    pixel_height=7020,
                    encoded_data=b"not-jpeg",
                )
            )
        )
        self.assertFalse(
            _type5_jpeg_is_valid(
                SimpleNamespace(
                    resource_type=5,
                    pixel_width=4964,
                    pixel_height=7020,
                    encoded_data=b"\xff\xd8\xffpayload\xff\xd9\x01",
                )
            )
        )

    def test_literal_only_lzh_encoder_round_trips(self) -> None:
        for data in (b"", b"XDW metadata", bytes(range(256)) * 300):
            encoded = compress_lzh_literals(data)
            self.assertEqual(decompress_lzh(encoded, len(data)), data)

    def test_dynamic_lzh_encoder_round_trips_and_uses_matches(self) -> None:
        data = (b"<record tag=0x62>" * 800) + bytes(range(256))
        encoded = compress_lzh(data)
        self.assertEqual(decompress_lzh(encoded, len(data)), data)
        # Dynamic LZSS output should be materially smaller than the deliberately
        # literal-only reference stream for repetitive metadata-like input.
        self.assertLess(len(encoded), len(compress_lzh_literals(data)))

    def test_legacy_directory_is_reported_as_unsupported_not_corrupt(self) -> None:
        header = encode_field(
            0x60,
            encode_field(0x82, b"\x07")
            + encode_field(0x80, b"\x00\xC0\x13")
            + encode_field(0x83, b"\x01\x0D\x0A\x01"),
        )
        legacy_payload = (
            encode_field(0x80, b"\x00")
            + encode_field(0x82, b"\x00")
            + encode_field(0x83, b"\x34\xD7")
            + encode_field(0x84, b"\x00")
            + encode_field(0x85, b"\x00\x00\x00\x00")
            + encode_field(0x86, (25).to_bytes(4, "little"))
        )
        data = header + encode_field(
            0x61,
            encode_field(0x63, b"") + encode_field(0x65, legacy_payload),
        )
        with self.assertRaisesRegex(
            XdwUnsupportedLayoutError, "format version 7.*legacy tag 0x65"
        ):
            XdwReader(data)


if __name__ == "__main__":
    unittest.main()
