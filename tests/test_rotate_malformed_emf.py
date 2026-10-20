"""Rotating a text annotation rejects malformed appearance EMFs with XdwError (E0-R);
synthetic data, no fixtures."""

from __future__ import annotations

import random
import struct
import unittest

from pyxdw import XdwError, XdwFormatError, XdwUnsupportedFeatureError
from pyxdw import annotation_text as at
from pyxdw.annotation_templates import TEXT_ANNOTATION

PAGE = (20997, 29701)          # A4 portrait, 0.01 mm


def kind(record) -> int:
    return struct.unpack_from("<I", record)[0]


def with_emf(transform, content: bytes = TEXT_ANNOTATION[1]) -> bytes:
    def apply(emf):
        records = transform(at._records(emf))
        for record in records:
            struct.pack_into("<I", record, 4, len(record))
        return b"".join(bytes(r) for r in records)
    return at._replace_cache(content, apply)


def truncated(target: int, size: int):
    def transform(records):
        for i, record in enumerate(records):
            if kind(record) == target:
                records[i] = record[:size]
                break
        return records
    return transform


def field(target: int, offset: int, fmt: str, value):
    def transform(records):
        for record in records:
            if kind(record) == target:
                struct.pack_into(fmt, record, offset, value)
        return records
    return transform


def polygon_points(count: int):
    def transform(records):
        for i, record in enumerate(records):
            if kind(record) == 86:
                points = bytes(record[28:44])
                records[i] = record[:28] + (points * 2)[:4 * count]
                struct.pack_into("<I", records[i], 24, count)
        return records
    return transform


def rotate(content: bytes, degrees: int):
    return at.rotate_annotation_group([TEXT_ANNOTATION[0], content], degrees, *PAGE)


# A box turned back to 0 degrees whose window stayed 2 px higher than its clip;
# rotating it takes the re-rotation path (_rerotate_text_emf).
def _window_two_px_higher(emf: bytes) -> bytes:
    records = at._records(emf)
    for record in records:
        if kind(record) == 9:                                  # SETWINDOWEXTEX
            width, height = struct.unpack_from("<2i", record, 8)
            struct.pack_into("<2i", record, 8, width, height + 2)
    return b"".join(bytes(r) for r in records)


SHIFTED = at._replace_cache(TEXT_ANNOTATION[1], _window_two_px_higher)


class MalformedRotationEmfTest(unittest.TestCase):
    def assert_raises_exactly(self, error, content: bytes, degrees: int):
        try:
            rotate(content, degrees)
        except error:
            return
        except Exception as exc:
            self.fail(f"raised {type(exc).__name__}: {exc}, not {error.__name__}")
        self.fail(f"rotation did not raise {error.__name__}")

    def test_records_cut_short_are_format_errors(self):
        cuts = {1: range(8, 88, 4), 9: range(8, 16, 4), 30: range(8, 24, 4), 82: range(8, 28, 4),
                84: range(8, 132, 4), 86: range(8, 44, 4), 70: range(16, 36, 4)}
        for target, sizes in cuts.items():
            for size in sizes:
                for degrees in (90, 180, 270):
                    with self.subTest(record=target, size=size, degrees=degrees):
                        self.assert_raises_exactly(XdwFormatError, with_emf(truncated(target, size)), degrees)

    def test_fields_out_of_range_and_misplaced_records(self):
        cases = {
            "too many characters": field(84, 44, "<I", 10 ** 6),
            "string beyond the record": field(84, 48, "<I", 10 ** 6),
            "advances beyond the record": field(84, 72, "<I", 10 ** 6),
            "unpaired surrogate": field(84, 76, "<H", 0xD800),
            "polygon points beyond the record": field(86, 24, "<I", 10 ** 6),
            "no header": lambda rs: [r for r in rs if kind(r) != 1],
            "two headers": lambda rs: rs[:1] + [bytearray(rs[0])] + rs[1:],
            "no end record": lambda rs: [r for r in rs if kind(r) != 14],
        }
        for name, transform in cases.items():
            for degrees in (90, 180, 270):
                with self.subTest(name, degrees=degrees):
                    self.assert_raises_exactly(XdwFormatError, with_emf(transform), degrees)

    def test_box_outline_must_have_four_points(self):
        # Rotation writes the four corners; other outlines are not the verified layout.
        for count in (3, 5):
            for degrees in (90, 180, 270):
                with self.subTest(points=count, degrees=degrees):
                    self.assert_raises_exactly(XdwUnsupportedFeatureError, with_emf(polygon_points(count)),
                                               degrees)

    def test_geometry_outside_the_16_bit_range_is_unsupported(self):
        # The box outline stores corners in 16 bits and a quarter turn adds 2 px,
        # so window, clip and text coordinates must stay within 0..32765.
        cases = {
            "window width": field(9, 8, "<i", 40000),
            "window height": field(9, 12, "<i", 40000),
            "clip bottom": field(30, 20, "<i", 1140770579),       # random-damage case 209
            "clip right": field(30, 16, "<i", 32766),
            "negative clip": field(30, 16, "<i", -5),
            "text bounds": field(84, 16, "<i", 2 ** 31 - 1),
            "text reference": field(84, 36, "<i", -2 ** 31),
        }
        for name, transform in cases.items():
            for base in (TEXT_ANNOTATION[1], SHIFTED):
                for degrees in (90, 180, 270):
                    with self.subTest(name, shifted=base is SHIFTED, degrees=degrees):
                        self.assert_raises_exactly(XdwUnsupportedFeatureError, with_emf(transform, base),
                                                   degrees)

    def test_geometry_range_boundaries(self):
        def box(width, height):
            def transform(records):
                for record in records:
                    if kind(record) == 9:                      # window equal to the clip
                        struct.pack_into("<2i", record, 8, width, height)
                    elif kind(record) == 30:
                        struct.pack_into("<4i", record, 8, 0, 0, width, height)
                return records
            return transform
        accepted = {"box 32765 wide": box(32765, 90), "box 32765 high": box(265, 32765),
                    "text bounds right 32765": field(84, 16, "<i", 32765),
                    "text reference 0": field(84, 36, "<i", 0)}
        refused = {"box 32766 wide": box(32766, 90), "box 32766 high": box(265, 32766),
                   "text bounds right 32766": field(84, 16, "<i", 32766),
                   "text reference -1": field(84, 36, "<i", -1), "clip left -1": field(30, 8, "<i", -1)}
        for degrees in (90, 180, 270):
            for name, transform in accepted.items():
                with self.subTest(name, degrees=degrees):
                    rotate(with_emf(transform), degrees)
            for name, transform in refused.items():
                with self.subTest(name, degrees=degrees):
                    self.assert_raises_exactly(XdwUnsupportedFeatureError, with_emf(transform), degrees)

    def test_malformed_record_wins_over_out_of_range_values(self):
        # The input EMF itself is invalid: a format error, whatever its coordinates.
        def cut_and_huge(records):
            records = truncated(84, 32)(records)
            for record in records:
                if kind(record) == 9:
                    struct.pack_into("<i", record, 8, 40000)
            return records
        for degrees in (90, 180, 270):
            with self.subTest(degrees=degrees):
                self.assert_raises_exactly(XdwFormatError, with_emf(cut_and_huge), degrees)

    def test_template_still_rotates(self):
        for degrees in (90, 180, 270):
            with self.subTest(degrees=degrees):
                first, content = rotate(TEXT_ANNOTATION[1], degrees)
                self.assertNotEqual(content, TEXT_ANNOTATION[1])
        rotate(SHIFTED, 90)                       # the verified re-rotation from a shifted window

    def test_random_damage_raises_only_xdw_errors(self):
        generator = random.Random(20261022)
        for case in range(300):
            def damage(records):
                for _ in range(generator.choice((1, 2, 3))):
                    i = generator.randrange(len(records))
                    action = generator.randrange(4)
                    if action == 0 and len(records[i]) > 8:
                        records[i] = records[i][:generator.randrange(8, len(records[i]), 4)]
                    elif action == 1 and len(records[i]) >= 12:
                        offset = generator.randrange(8, len(records[i]) - 3)
                        struct.pack_into("<I", records[i], offset, generator.getrandbits(32))
                    elif action == 2:
                        del records[i]
                    else:
                        records.insert(i, bytearray(records[generator.randrange(len(records))]))
                return records
            base = generator.choice((TEXT_ANNOTATION[1], SHIFTED))
            with self.subTest(case=case):
                try:
                    rotate(with_emf(damage, base), generator.choice((90, 180, 270)))
                except XdwError:
                    pass
                except Exception as exc:
                    self.fail(f"raised {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    unittest.main()
