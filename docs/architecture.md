# Architecture

| Module | Role |
|---|---|
| `tlv.py` | BER-like tag/length/value fields used throughout the format |
| `lzh.py` | LZH-style compression of the document body (decode and encode) |
| `reader.py` | `XdwReader`, `XdwPage`, `XdwAnnotation`; page records, resources, rotation support policy |
| `writer.py` | pypdf-style `XdwWriter` facade |
| `experimental.py` | byte-level document builders (page operations, annotations, properties) |
| `page_metadata.py` | page record fields, official rotation of page blocks |
| `annotation_text.py` / `annotation_templates.py` | annotation records, EMF appearance, rotation and resizing |
| `emf.py`, `tiff.py` | EMF parsing, wrapping CCITT G3/G4 data as TIFF |
| `metadata.py`, `properties.py` | document properties (`%doc_att_*`, user-defined) |
| `errors.py` | exception hierarchy (`XdwError` …) |
| `__main__.py` | `pyxdw` command line |

Design rules: pure Python, no DocuWorks; reading is tolerant, writing is strict.
A write operation is allowed only for page layouts listed in
`SUPPORTED_PAGE_LAYOUTS` and annotation types whose output was compared with the
official API; otherwise `XdwUnsupportedFeatureError` is raised. Untouched
records are copied byte for byte.
