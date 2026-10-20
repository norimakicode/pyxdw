import unittest
import json
import zipfile
import hashlib
from pathlib import Path
from pyxdw import (XdwReader, XdwUnsupportedFeatureError, inspect_protection,
                     inspect_protected_resources)
from pyxdw.reader import _directory_offsets, _field_map
from pyxdw.tlv import decode_field

import os as _os
TESTDATA = Path(_os.environ.get("PYXDW_TESTDATA", Path(__file__).resolve().parents[1] / "testdata"))
if not TESTDATA.is_dir():
    raise unittest.SkipTest("set PYXDW_TESTDATA to a folder of XDW fixtures (see docs/validation.md)")


class V11ResourceDirectoryTests(unittest.TestCase):
    def test_controlled_password128_permissions_match_windows(self):
        archive = TESTDATA / 'oracle-inputs/password128-results-wbww8xjl.zip'
        if not archive.exists():
            self.skipTest('controlled password fixtures not present')
        with zipfile.ZipFile(archive) as z:
            manifest = json.loads(z.read('manifest.json'))
            self.assertIsNone(inspect_protection(z.read('plain.xdw')))
            for case in manifest['cases']:
                with self.subTest(case=case['file']['path']):
                    info = inspect_protection(z.read(case['file']['path']))
                    self.assertEqual(info.kind, case['protection'][0])
                    self.assertEqual(info.permissions, tuple(case['protection'][1].split(',')))

    def test_official_docuworks8_directories(self):
        root = TESTDATA / 'fujifilm-official'
        for name, offset, count in [('Windows11_JP_K1_2.xdw', 539829, 31),
                                    ('Windows10_ServerOS_JP_K1.xdw', 434841, 28)]:
            with self.subTest(name=name):
                path = root / name
                if not path.exists():
                    self.skipTest('official fixtures not downloaded')
                data = path.read_bytes()
                directory = decode_field(data, offset)
                self.assertEqual(directory.end_offset, len(data))
                offsets = _directory_offsets(data, directory)
                self.assertEqual(len(offsets), count)
                self.assertEqual(decode_field(data, offsets[0], offset).tag, 0x67)
                protection = inspect_protection(data)
                self.assertEqual(protection.kind, 'UNKNOWN_SECU003')
                self.assertEqual(protection.raw_kind, 3)
                self.assertEqual(protection.permissions, ('PRINT',))
                self.assertEqual(protection.resource_tag, 0x67)
                protected = inspect_protected_resources(data)
                self.assertEqual(len(protected), count)
                self.assertTrue(all(item.tag == 0x67 for item in protected))
                self.assertTrue(all(len(item.sha256) == 64 for item in protected))
                with self.assertRaisesRegex(XdwUnsupportedFeatureError, 'SECU003'):
                    XdwReader(data)
                # A changed unconfirmed word must not become a verified API kind.
                record = _field_map(data, directory)[0x89]
                changed = bytearray(data)
                changed[record.value_offset+4:record.value_offset+8] = (7).to_bytes(4, 'little')
                self.assertEqual(inspect_protection(changed).kind, 'UNKNOWN_SECU003')

    def test_password128_image_resources_are_inspectable_but_not_decodable(self):
        archive = TESTDATA / 'oracle-inputs/password128-results-m4au0ebl.zip'
        if not archive.exists():
            self.skipTest('controlled image fixtures not present')
        with zipfile.ZipFile(archive) as z:
            manifest = json.loads(z.read('manifest.json'))
            for case in manifest['cases']:
                with self.subTest(case=case['file']['path']):
                    data = z.read(case['file']['path'])
                    info = inspect_protection(data)
                    self.assertEqual(info.kind, case['protection'][0])
                    self.assertEqual(info.permissions, tuple(case['protection'][1].split(',')))
                    protected = inspect_protected_resources(data)
                    self.assertEqual(len(protected), 2)
                    for item in protected:
                        f = decode_field(data, item.offset)
                        self.assertEqual(item.sha256, hashlib.sha256(data[f.value_offset:f.end_offset]).hexdigest())
                    with self.assertRaisesRegex(XdwUnsupportedFeatureError, 'Pswd128'):
                        XdwReader(data)
