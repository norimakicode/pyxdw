# pyxdw

Pure-Python reader and writer for DocuWorks (`.xdw`) documents.

pyxdw reads and edits XDW files without DocuWorks, XDWAPI or any Windows
component. It requires Python 3.10+ and has no runtime dependencies.
This is a personal project. Third-party origins are documented in the License
section below.

> **Unofficial.** pyxdw is not affiliated with, endorsed by or supported by
> FUJIFILM Business Innovation. DocuWorks is a registered trademark or trademark
> of FUJIFILM Business Innovation Corp. The file format was studied only by
> comparing files written by the official DocuWorks API; the published code
> contains no code or data obtained by decompiling or disassembling DocuWorks software.

Japanese: [README.ja.md](README.ja.md)

## Status

Alpha (0.4.0). Byte-level behaviour was checked against the official
DocuWorks API 9.0.11 for the cases listed in [docs/validation.md](docs/validation.md).
Tested only on macOS (arm64) with Python 3.14. Linux and Windows have not been tested.

## Install

```bash
pip install git+https://github.com/norimakicode/pyxdw.git
```

PyPI distribution is not available. Install from GitHub with the command above,
or use `python -m pip install .` from a local checkout.

## Usage

The API follows pypdf naming.

```python
from pyxdw import XdwReader, XdwWriter

reader = XdwReader("document.xdw")
print(len(reader.pages), reader.metadata.title)
for page in reader.pages:
    print(page.mediabox.width, page.mediabox.height, page.rotation)
    for image in page.images:          # JPEG / G3 / G4 / BMP, not re-encoded
        open(f"p{page.index + 1}_{image.name}", "wb").write(image.data)

with XdwWriter() as writer:
    for page in reversed(reader.pages):
        writer.add_page(page)
    writer.rotate_page(0, 90)
    writer.add_text_annotation(0, 1000, 1000, "Checked", color=(255, 0, 0))
    writer.add_metadata({"/Title": "Report"})
    writer.write("output.xdw")
```

Command line:

```bash
pyxdw info document.xdw
```

Other commands: `text`, `extract`, `extract-page`, `compact`, `select`,
`delete`, `split`, `rotate`, `merge`. Runnable scripts are in [examples/](examples/).

## Features

| | |
|---|---|
| Read | pages, size, rotation, properties, annotations and their text, page images |
| Page editing | copy, reorder, delete, insert, merge documents, rotate (verified layouts) |
| Annotations | add text / sticky note / rectangle, move, change text, delete (no characters outside the BMP; text of a rotated text annotation cannot be changed) |
| Properties | title and user-defined properties |
| Not supported | encrypted or signed documents, binders (`.xbd`), rendering, OCR |

Operations that would produce an unverified result raise
`XdwUnsupportedFeatureError` instead of writing a file. Details:
[supported features](docs/supported_features.md), [limitations](docs/limitations.md),
[compatibility](docs/compatibility.md), [architecture](docs/architecture.md).

## Formats and public API

Reads XDW v7, v9 and v10 bodies. Page selection, merging and compaction are
verified for v7/v10; v9 writing is limited and retains earlier generations.
See [compatibility](docs/compatibility.md).

Import the main API from `pyxdw`: `XdwReader`, `XdwWriter`, `XdwPage`,
`XdwAnnotation`, `XdwError` and `XdwUnsupportedFeatureError`.
`XdwReader` exposes `pages`, `metadata` and `extract_text()`; page objects expose
`images`, `annotations` and `extract_text()`. `XdwWriter` provides page editing,
annotation editing, `add_metadata()` and `write()` as illustrated above.
The full export list is in [pyxdw/__init__.py](pyxdw/__init__.py).

## Known limitations

Only verified input layouts can be edited. Text annotations cannot contain
characters outside the BMP (such as emoji and some supplementary kanji), and the
text of a rotated text annotation cannot be changed.
A v9 document retains history even with `compact=True`; do not use that option
to sanitize old content. Image extraction does not render pages, and reading
stored OCR text does not perform OCR. See [limitations](docs/limitations.md)
for annotation rotation and compression differences.

The example needs an unprotected input with a verified editable layout, such
as a two-page JPEG document. It creates image files and `output.xdw` in the
current directory. Coordinates for annotations are in 0.01 mm.

## Tests

```bash
python -m unittest discover -s tests
```

XDW sample files are not distributed. Tests that need them skip unless
`PYXDW_TESTDATA` points to a folder of fixtures; see
[docs/validation.md](docs/validation.md) for how to make them with the official
DocuWorks API. The skipped modules need external fixtures, not a DocuWorks
installation. Offline tests cover codec and parser behaviour; full document
editing checks need those fixtures. See the coverage details in the validation guide.

## License

[MIT License](LICENSE). Copyright (c) 2026 Norimaki Code.

Parts of the LZH codec correspond to Haruhiko Okumura's public-domain ar002 and may be
adapted from it. See [NOTICE](NOTICE) and [third-party origins](docs/third_party.md).
