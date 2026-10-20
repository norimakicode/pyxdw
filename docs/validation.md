# Validation

## Method

1. A script on Windows calls the official DocuWorks API (XDWAPI 9.0.11) through
   `ctypes` to create documents and apply an operation (e.g. `XDW_RotatePage`,
   `XDW_AddAnnotation`).
2. pyxdw applies the same operation to the same input.
3. The two outputs are compared after decompression, byte for byte. Every
   difference is either fixed or explained (see [limitations](limitations.md)).
4. The pyxdw output is opened in DocuWorks Viewer and checked visually.

Additionally, a set of 746 real-world documents was read without error. Those
files are confidential and not published.

## Fixtures are not distributed

XDW samples and the scripts that drive XDWAPI are not part of this repository.
Real documents are confidential; redistribution rights for generated fixtures
have not been established. Using licensed software does not itself establish
permission to redistribute its output.
Tests that need fixtures skip unless `PYXDW_TESTDATA` names a folder:

```bash
PYXDW_TESTDATA=/path/to/fixtures python -m unittest discover -s tests
```

Expected names are visible in the tests (e.g. `corpus-api9/pages_2.xdw`, a two
page JPEG document). To make your own, use the DocuWorks API of the
DocuWorks Development Tool Kit (distributed to DocuWorks licensees through
FUJIFILM BI Direct; its API reference is included in the kit), e.g.
`XDW_CreateXdwFromImageFile`, `XDW_RotatePage` and `XDW_AddAnnotation`.
Support information for the kit:
<https://www.fujifilm.com/fb/ja/support/software/document-management/docuworks/info/dw-sdk/003>

## Offline coverage and skipped tests

At commit `7973aeb`, the public tests were run on macOS arm64 with Python
3.14.5, without DocuWorks, XDWAPI or Windows. Both the normal run and a run
with `python -O` reported 80 tests, no failures and 10 fixture-dependent
modules skipped. Those skips mean missing external test data, not a missing
DocuWorks installation. Offline tests cover imports, LZH and TLV round trips,
decompression limits, image-layout validation, malformed EMF rejection,
write self-check failures, unsupported annotation characters and unsupported
legacy layouts.

| Skipped module | External fixture coverage |
|---|---|
| `test_api9_annotations` | Annotation values compared with official API records |
| `test_decoder_limits_fixtures` | Reader/writer decompression limits on XDW resources |
| `test_phase11_12` | Truncated input, append-only generations, protected cases |
| `test_pypdf_style` | Reader/writer usage, images, properties, page operations |
| `test_reader` | Legacy/mixed layouts and annotation/protection values |
| `test_rerotation_fixtures` | Repeated rotations compared with official API stages |
| `test_rotated_text_edit_fixtures` | Text edits on rotated annotations compared with official output |
| `test_secu003` | Protected-resource envelope inspection |
| `test_write_verification_fixtures` | Write self-check failures exercised on real layouts |
| `test_writer_preservation` | Page preservation, annotation/property writes and appearance |

Setting `PYXDW_TESTDATA` requires the expected directory layout and archives,
not just an arbitrary XDW file. The baseline suite does not verify all supported
write paths. At commit `7973aeb`, the full external fixture suite ran 147 tests
without failure, and the S-4 checks continued to match all 39 official stages.
It used the same macOS arm64 / Python 3.14.5 environment, with
`PYXDW_TESTDATA` pointing to the external research fixtures. Those fixtures are
not part of the repository or distribution artifacts. Neither suite's success
substitutes for a new write feature's official API comparison and Viewer check.
Image-related checks may additionally require the optional `test` extra
(`python -m pip install '.[test]'`).

A redistributable minimal fixture would improve independent end-to-end
validation. None is included until its provenance and redistribution rights
are established. Keep confidential documents and local fixture paths out of
Git. The README example requires a suitable input supplied by the user and
writes its results into the current directory.
