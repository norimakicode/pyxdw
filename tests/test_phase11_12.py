import json
from pathlib import Path
import unittest
import zipfile

from pyxdw import XdwFormatError, XdwReader, XdwUnsupportedFeatureError

import os as _os
TESTDATA = Path(_os.environ.get("PYXDW_TESTDATA", Path(__file__).resolve().parents[1] / "testdata"))
if not TESTDATA.is_dir():
    raise unittest.SkipTest("set PYXDW_TESTDATA to a folder of XDW fixtures (see docs/validation.md)")


ROOT = Path(__file__).resolve().parents[1]
CORPUS = TESTDATA / "phases5-8-api9.zip"


class Phase11ReaderIntegrityTests(unittest.TestCase):
    def test_current_generation_cannot_be_empty(self):
        with zipfile.ZipFile(CORPUS) as archive:
            data = archive.read("render_rgb/render_rgb.xdw")
        for candidate in (data[:-1], data[: len(data) // 2]):
            with self.subTest(size=len(candidate)):
                with self.assertRaises(XdwFormatError):
                    XdwReader(candidate)

    def test_valid_append_only_history_can_have_empty_initial_generation(self):
        path = TESTDATA / "corpus-api9" / "base.xdw"
        reader = XdwReader(path)
        self.assertTrue(reader.pages)
        self.assertTrue(any(not generation.pages for generation in reader.generations[:-1]))


class Phase12CorpusRegressionTests(unittest.TestCase):
    def test_all_official_protected_cases_still_expose_the_same_envelope(self):
        with zipfile.ZipFile(CORPUS) as archive:
            report = json.loads(archive.read("report.json"))
            count = 0
            for case in report["cases"]:
                if case["request"]["operation"] != "protect":
                    continue
                name = case["request"]["id"]
                data = archive.read(f"{name}/{name}.xdw")
                with self.subTest(case=name):
                    with self.assertRaises(XdwUnsupportedFeatureError):
                        # Protected layouts remain intentionally unsupported by
                        # the Reader; the explicit exception is part of the API.
                        XdwReader(data)
                count += 1
            self.assertEqual(count, 9)
