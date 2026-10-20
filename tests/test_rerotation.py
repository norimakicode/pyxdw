"""Re-rotating rotated text annotations (S-4); synthetic data, no fixtures."""

from __future__ import annotations

import struct
import unittest

from pyxdw import XdwUnsupportedFeatureError
from pyxdw import annotation_text as at
from pyxdw.annotation_templates import TEXT_ANNOTATION
from pyxdw.tlv import decode_field

PAGE = (20997, 29701)


def rotate(group, degrees, page=PAGE):
    return at.rotate_annotation_group(list(group), degrees, *page)


def appearance(group):
    content = group[1]
    outer = decode_field(content, 0, len(content))
    body = at._fields(content[outer.value_offset:outer.end_offset])
    emf = at._decode_appearance(dict(at._fields(dict(body)[b"\x87"])))
    return body, emf


def angle(group) -> int:
    return at._text_rotation_angle(*appearance(group))


def window(group):
    _, emf = appearance(group)
    for record in at._records(emf):
        if struct.unpack_from("<I", record)[0] == 9:
            return struct.unpack_from("<2i", record, 8)


class RerotationTest(unittest.TestCase):
    def test_angle_accumulates(self):
        group = list(TEXT_ANNOTATION)
        expected = {270: 90, 180: 180, 90: 270, 0: 0}
        total = 0
        for degrees in (270, 270, 270, 270):
            group = rotate(group, degrees)
            total = (total + degrees) % 360
            self.assertEqual(angle(group), expected[total])

    def test_unrotated_rebuild_matches_template(self):
        # Rotating the template and rebuilding its unrotated drawing gives the
        # template's drawing back.
        _, original = appearance(TEXT_ANNOTATION)
        for degrees in (90, 180, 270):
            with self.subTest(degrees=degrees):
                _, emf = appearance(rotate(TEXT_ANNOTATION, degrees))
                rebuilt, *_ = at._unrotated_text_emf(emf, degrees)
                self.assertEqual(rebuilt, original)

    def test_quarter_then_quarter_window_follows_previous_clip(self):
        quarter = rotate(TEXT_ANNOTATION, 270)
        straight = rotate(quarter, 270)
        _, emf = appearance(quarter)
        clip = next(struct.unpack_from("<4i", r, 8) for r in at._records(emf)
                    if struct.unpack_from("<I", r)[0] == 30)
        self.assertEqual(window(straight), (clip[3], clip[2]))

    def test_previously_refused_transitions_now_follow_the_rule(self):
        # 270/90 + 180 (T2/T3): the window is the previous clip turned by 180.
        for first in (270, 90):
            with self.subTest(first=first):
                quarter = rotate(TEXT_ANNOTATION, first)
                _, emf = appearance(quarter)
                clip = next(struct.unpack_from("<4i", r, 8) for r in at._records(emf)
                            if struct.unpack_from("<I", r)[0] == 30)
                turned = rotate(quarter, 180)
                self.assertEqual(window(turned), (clip[2], clip[3]))
                self.assertEqual(angle(turned), (angle(quarter) + 180) % 360)

    def test_unverified_transitions_are_refused(self):
        # A quarter-turn round trip leaves a shifted window at 0 degrees; only +90
        # from there was observed with the official API.
        cycled = rotate(rotate(TEXT_ANNOTATION, 270), 90)
        self.assertNotEqual(window(cycled), window(TEXT_ANNOTATION))
        rotate(cycled, 90)
        for degrees in (180, 270):
            with self.subTest(degrees=degrees):
                with self.assertRaises(XdwUnsupportedFeatureError):
                    rotate(cycled, degrees)

    def test_layout_mismatch_is_refused(self):
        rotated = rotate(TEXT_ANNOTATION, 270)

        def move_text(emf):
            records = at._records(emf)
            for record in records:
                if struct.unpack_from("<I", record)[0] == 84:
                    x, y = struct.unpack_from("<2i", record, 36)
                    struct.pack_into("<2i", record, 36, x + 1, y)
            return b"".join(records)
        broken = [rotated[0], at._replace_cache(rotated[1], move_text)]
        with self.assertRaises(XdwUnsupportedFeatureError):
            rotate(broken, 270)

    def test_rotated_text_still_cannot_be_edited(self):
        for first, second in ((180, 90), (180, 270), (270, 270)):      # totals 270, 90, 180
            with self.subTest(first=first, second=second):
                with self.assertRaises(XdwUnsupportedFeatureError):
                    at.rewrite_text_annotation(rotate(rotate(TEXT_ANNOTATION, first), second), "x")
        # Turned back to 0 degrees without a shifted window, the text is editable again.
        at.rewrite_text_annotation(rotate(rotate(TEXT_ANNOTATION, 180), 180), "x")


if __name__ == "__main__":
    unittest.main()
