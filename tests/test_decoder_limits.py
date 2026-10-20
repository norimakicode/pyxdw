"""Decompression limits and exception hierarchy (S-1, S-2); no XDW fixtures needed."""

from __future__ import annotations

import time
import tracemalloc
import unittest

from pyxdw import XdwError, XdwFormatError, XdwLimitError, XdwLimits
from pyxdw import annotation_text as at
from pyxdw.annotation_templates import TEXT_ANNOTATION
from pyxdw.lzh import LzhDecodeError, compress_lzh, decompress_lzh
from pyxdw.tlv import decode_field, encode_length


def _bits(fields) -> bytes:
    acc = width = 0
    for value, count in fields:
        acc = (acc << count) | value
        width += count
    acc <<= -width % 8
    return acc.to_bytes((width + 7) // 8, "big")


def _block(count: int, main_symbol: int):
    # Constant length, main and position trees consume no bits per symbol.
    return [(count, 16), (0, 5), (0, 5), (0, 9), (main_symbol, 9), (0, 4), (0, 4)]


def bomb(match_blocks: int) -> bytes:
    """One literal, then blocks of 65,535 matches of 256 bytes (about 16 MiB each)."""
    fields = _block(1, ord("A"))
    for _ in range(match_blocks):
        fields += _block(0xFFFF, 509)
    return _bits(fields + [(0, 16)])


def with_cache(content: bytes, payload: bytes, size: int) -> bytes:
    """Replace the appearance stream (0x86) and its declared size (0x81)."""
    outer = decode_field(content, 0, len(content))
    body = at._fields(content[outer.value_offset:outer.end_offset])
    tags = [t for t, _ in body]
    cache = at._fields(body[tags.index(b"\x87")][1])
    for item in cache:
        if item[0] == b"\x86":
            item[1] = payload
        elif item[0] == b"\x81":
            item[1] = size.to_bytes(max(1, (size.bit_length() + 8) // 8), "big")
    body[tags.index(b"\x87")][1] = at._join(cache)
    return content[:1] + encode_length(len(at._join(body))) + at._join(body)


class DecoderLimitTest(unittest.TestCase):
    def test_constant_tree_bomb_stops_at_default_limit(self):
        data = bomb(5)  # would expand to about 80 MiB
        self.assertLess(len(data), 64)
        tracemalloc.start()
        started = time.perf_counter()
        with self.assertRaises(XdwLimitError) as caught:
            decompress_lzh(data)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertEqual(caught.exception.limit_name, "max_output")
        self.assertLess(peak, 3 * (64 << 20))
        self.assertLess(elapsed, 30)

    def test_explicit_limit_is_never_exceeded(self):
        tracemalloc.start()
        with self.assertRaises(XdwLimitError) as caught:
            decompress_lzh(bomb(1), max_output=1 << 20)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertEqual(caught.exception.limit, 1 << 20)
        self.assertLess(peak, 4 << 20)

    def test_declared_size_over_limit_is_rejected_before_decoding(self):
        started = time.perf_counter()
        with self.assertRaises(XdwLimitError) as caught:
            decompress_lzh(bomb(1000), 1 << 40)
        self.assertLess(time.perf_counter() - started, 0.5)
        self.assertEqual(caught.exception.requested, 1 << 40)

    def test_limit_boundary(self):
        data = bytes(range(256)) * 4
        packed = compress_lzh(data)
        terminated = packed + bytes(2)  # XDW streams omit the zero-size end block
        self.assertEqual(decompress_lzh(packed, len(data), max_output=len(data)), data)
        self.assertEqual(decompress_lzh(terminated, max_output=len(data)), data)
        with self.assertRaises(XdwLimitError):
            decompress_lzh(packed, len(data), max_output=len(data) - 1)
        with self.assertRaises(XdwLimitError):
            decompress_lzh(terminated, max_output=len(data) - 1)

    def test_unlimited_decoding_must_be_explicit(self):
        output = decompress_lzh(bomb(1), max_output=None)
        self.assertEqual(len(output), 1 + 0xFFFF * 256)

    def test_declared_size_mismatch_stays_a_format_error(self):
        packed = compress_lzh(b"abc" * 100)
        with self.assertRaises(LzhDecodeError) as caught:
            decompress_lzh(packed, 10)
        self.assertNotIsInstance(caught.exception, XdwLimitError)

    def test_invalid_max_output(self):
        for value in (-1, 1.5, True, "1"):
            with self.subTest(value=value):
                with self.assertRaises((TypeError, ValueError)):
                    decompress_lzh(b"", max_output=value)


class ExceptionHierarchyTest(unittest.TestCase):
    def test_lzh_errors_are_xdw_format_errors(self):
        self.assertTrue(issubclass(LzhDecodeError, XdwFormatError))
        self.assertTrue(issubclass(LzhDecodeError, XdwError))
        self.assertTrue(issubclass(LzhDecodeError, ValueError))
        with self.assertRaises(XdwFormatError):
            decompress_lzh(b"\x00\x01", 5)

    def test_limit_error_is_separate_from_decode_errors(self):
        self.assertTrue(issubclass(XdwLimitError, XdwFormatError))
        self.assertFalse(issubclass(XdwLimitError, LzhDecodeError))


class LimitsConfigTest(unittest.TestCase):
    def test_defaults(self):
        limits = XdwLimits()
        self.assertEqual(limits.max_lzh_output, 64 << 20)
        self.assertEqual(limits.max_metadata, 16 << 20)
        self.assertEqual(limits.max_annotation_emf, 16 << 20)
        self.assertEqual(limits.max_image_bytes, 512 << 20)
        self.assertEqual(limits.max_image_dimension, 65_535)
        self.assertEqual(limits.max_total_decoded, 1 << 30)

    def test_values_are_validated(self):
        for name in ("max_lzh_output", "max_metadata", "max_annotation_emf",
                     "max_image_bytes", "max_image_dimension", "max_total_decoded"):
            for value in (0, -1, 1.0, True, None, "8"):
                with self.subTest(name=name, value=value):
                    with self.assertRaises((TypeError, ValueError)):
                        XdwLimits(**{name: value})

    def test_frozen(self):
        with self.assertRaises(Exception):
            XdwLimits().max_metadata = 1


class AnnotationDecodeTest(unittest.TestCase):
    def test_corrupt_appearance_is_a_format_error(self):
        first, content = TEXT_ANNOTATION
        broken = [first, with_cache(content, b"\xff" * 40, 3552)]
        with self.assertRaises(XdwFormatError) as caught:
            at.annotation_rotates_with_page(broken)
        self.assertNotIsInstance(caught.exception, XdwLimitError)
        with self.assertRaises(XdwFormatError):
            at.rewrite_text_annotation(broken, "Changed")

    def test_oversized_appearance_raises_limit_error(self):
        first, content = TEXT_ANNOTATION
        huge = [first, with_cache(content, bomb(2), 1 << 40)]
        for call in (lambda: at.annotation_rotates_with_page(huge),
                     lambda: at.rewrite_text_annotation(huge, "Changed")):
            started = time.perf_counter()
            with self.assertRaises(XdwLimitError):
                call()
            self.assertLess(time.perf_counter() - started, 0.5)

    def test_missing_position_is_a_format_error(self):
        first, content = TEXT_ANNOTATION
        stripped = first.replace(b"\x9f\x34", b"\x9f\x35", 1)
        self.assertNotEqual(stripped, first)
        with self.assertRaises(XdwFormatError):
            at.rotate_annotation_group([stripped, content], 90, 2100, 2970)


if __name__ == "__main__":
    unittest.main()
