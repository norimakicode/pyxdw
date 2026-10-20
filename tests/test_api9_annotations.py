import hashlib
import json
from pathlib import Path
import unittest
import zipfile

from pyxdw import XdwReader

import os as _os
TESTDATA = Path(_os.environ.get("PYXDW_TESTDATA", Path(__file__).resolve().parents[1] / "testdata"))
if not TESTDATA.is_dir():
    raise unittest.SkipTest("set PYXDW_TESTDATA to a folder of XDW fixtures (see docs/validation.md)")


CORPUS = TESTDATA / 'annotations-api9-phase3.zip'


class OfficialAnnotationTests(unittest.TestCase):
    def test_twenty_official_annotation_cases(self):
        with zipfile.ZipFile(CORPUS) as archive:
            report = json.loads(archive.read('report.json'))
            hashes = json.loads(archive.read('sha256.json'))
            self.assertEqual(len(report['cases']), 20)
            for case in report['cases']:
                with self.subTest(case=case['id']):
                    self.assertEqual(case['api_status'], 'pass')
                    name = case['id'] + '.xdw'
                    data = archive.read(name)
                    self.assertEqual(hashlib.sha256(data).hexdigest(), hashes[name])
                    pages = XdwReader(data).pages
                    self.assertEqual(len(pages), len(case['annotations']))
                    for page, oracle in zip(pages, case['annotations']):
                        self.assertEqual(page.rotation, case['request'].get('rotation', 0))
                        self.assertEqual(len(page.annotations), len(oracle['annotations']))
                        for annotation, observed in zip(page.annotations, oracle['annotations']):
                            self.assertEqual(annotation.subtype, observed['nAnnotationType'] - 32768)
                            # W getter bytes are UTF-16LE for both stored text types.
                            expected = bytes.fromhex(observed['bytes_hex']).decode('utf-16-le').rstrip('\0') if 'bytes_hex' in observed else ''
                            self.assertEqual(annotation.extract_text().rstrip('\r\n'), expected.rstrip('\r\n'))
