"""Text edits reject malformed appearance EMFs and oversize boxes with XdwError (E0);
synthetic data, no fixtures."""

from __future__ import annotations

import random
import struct
import unittest

from pyxdw import XdwError, XdwFormatError, XdwUnsupportedFeatureError
from pyxdw import annotation_text as at
from pyxdw.annotation_templates import TEXT_ANNOTATION


def kind(record) -> int:
    return struct.unpack_from("<I", record)[0]


def joined(records) -> bytes:
    for record in records:
        struct.pack_into("<I", record, 4, len(record))
    return b"".join(bytes(r) for r in records)


def with_emf(transform) -> bytes:
    """The template's content record with its EMF records passed through *transform*."""
    return at._replace_cache(TEXT_ANNOTATION[1], lambda emf: joined(transform(at._records(emf))))


def truncated(target: int, size: int, nth: int = 0):
    def transform(records):
        seen = 0
        for i, record in enumerate(records):
            if kind(record) == target:
                if seen == nth:
                    records[i] = record[:size]
                    break
                seen += 1
        return records
    return transform


def field(target: int, offset: int, fmt: str, value):
    def transform(records):
        for record in records:
            if kind(record) == target:
                struct.pack_into(fmt, record, offset, value)
        return records
    return transform


def edit(content: bytes, text: str = "x", **options):
    return at.rewrite_text_annotation([TEXT_ANNOTATION[0], content], text, **options)


class MalformedTextEmfTest(unittest.TestCase):
    def assert_raises_exactly(self, error, content: bytes, text: str = "x", **options):
        try:
            edit(content, text, **options)
        except error:
            return
        except Exception as exc:
            self.fail(f"raised {type(exc).__name__}: {exc}, not {error.__name__}")
        self.fail(f"edit did not raise {error.__name__}")

    def test_records_cut_short_are_format_errors(self):
        # Every field the edit reads or writes must lie inside its record.
        minimum = {1: 88, 9: 16, 30: 24, 82: 28, 84: 76, 86: 28}
        for target, needed in minimum.items():
            for size in range(8, needed, 4):
                with self.subTest(record=target, size=size):
                    self.assert_raises_exactly(XdwFormatError, with_emf(truncated(target, size)))
        for size in range(8, 132, 4):                       # EXTTEXTOUTW: string and advances too
            with self.subTest(record=84, size=size):
                self.assert_raises_exactly(XdwFormatError, with_emf(truncated(84, size)))
        for size in range(8, 44, 4):                        # POLYGON16: its points too
            with self.subTest(record=86, size=size):
                self.assert_raises_exactly(XdwFormatError, with_emf(truncated(86, size)))
        for size in range(20, 36, 4):                       # GDI comment "GDIC" type 2 (written at 28..35)
            with self.subTest(record=70, size=size):
                self.assert_raises_exactly(XdwFormatError, with_emf(truncated(70, size)))
        with self.subTest(record=70, size=16):              # "GDIC" without its type
            self.assert_raises_exactly(XdwFormatError, with_emf(truncated(70, 16)))

    def test_text_record_fields_out_of_range(self):
        cases = {
            "no characters": field(84, 44, "<I", 0),
            "too many characters": field(84, 44, "<I", 10 ** 6),
            "string beyond the record": field(84, 48, "<I", 10 ** 6),
            "string inside the fixed part": field(84, 48, "<I", 40),
            "advances beyond the record": field(84, 72, "<I", 10 ** 6),
            "unpaired surrogate": field(84, 76, "<H", 0xD800),
            "polygon points beyond the record": field(86, 24, "<I", 10 ** 6),
        }
        for name, transform in cases.items():
            with self.subTest(name):
                self.assert_raises_exactly(XdwFormatError, with_emf(transform))

    def test_header_and_end_records(self):
        cases = {
            "no header": lambda rs: [r for r in rs if kind(r) != 1],
            "two headers": lambda rs: rs[:1] + [bytearray(rs[0])] + rs[1:],
            "header not first": lambda rs: rs[1:2] + rs[:1] + rs[2:],
            "no end record": lambda rs: [r for r in rs if kind(r) != 14],
            "end record not last": lambda rs: rs[:-2] + rs[-1:] + rs[-2:-1],
        }
        for name, transform in cases.items():
            with self.subTest(name):
                self.assert_raises_exactly(XdwFormatError, with_emf(transform))

    def test_oversize_boxes_are_unsupported(self):
        # POLYGON16 stores the box corners as 16-bit values.
        self.assert_raises_exactly(XdwUnsupportedFeatureError, TEXT_ANNOTATION[1], "x" * 2000)
        self.assert_raises_exactly(XdwUnsupportedFeatureError, TEXT_ANNOTATION[1], "\n".join(["x"] * 1000))
        edit(TEXT_ANNOTATION[1], "x" * 1300)                # still within the limit

    def test_font_size_must_be_finite(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(font_size=value):
                self.assert_raises_exactly(ValueError, TEXT_ANNOTATION[1], font_size=value)
                with self.assertRaises(ValueError) as caught:
                    edit(TEXT_ANNOTATION[1], font_size=value)
                self.assertNotIsInstance(caught.exception, XdwError)
        for value in (0.01, -5):
            with self.subTest(font_size=value):
                self.assert_raises_exactly(XdwUnsupportedFeatureError, TEXT_ANNOTATION[1], font_size=value)

    def test_template_still_edits(self):
        for text, options in (("x", {}), ("Hello PDF", {}), ("ab\ncd", {}), ("あい", {}),
                              ("x", {"font_size": 24}), ("x", {"unicode": True})):
            with self.subTest(text=text, **options):
                first, content = edit(TEXT_ANNOTATION[1], text, **options)
                self.assertNotEqual(content, TEXT_ANNOTATION[1])

    def test_random_damage_raises_only_xdw_errors(self):
        # Damage the decoded EMF (not the LZH stream) so the edit code sees it.
        generator = random.Random(20261021)
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
            with self.subTest(case=case):
                try:
                    edit(with_emf(damage), generator.choice(("x", "Hello PDF", "ab\ncd")))
                except XdwError:
                    pass
                except Exception as exc:
                    self.fail(f"raised {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    unittest.main()
