# Changelog

## 0.4.0 (unreleased)

First public snapshot.

- Read pages, properties, annotations and page images of XDW 7/9/10 documents,
  including MRC (type 11) and lossless (type 10) pages.
- pypdf-style `XdwReader` / `XdwWriter`: copy, reorder, delete, insert, merge.
- Page rotation matching the official `XDW_RotatePage` output for the verified layouts,
  including pages with rotatable annotations and embedded-font pages.
- Add, move, re-text and delete text, sticky-note and rectangle annotations
  (colour, background, size, multi-line).
- `add_metadata` for title and user-defined properties.
- `pyxdw` command line tool.
- Decompression limits (`XdwLimits`, `XdwReader(limits=)`, `XdwLimitError`).
  LZH decode errors are now `XdwFormatError` subclasses (still `ValueError`).
- Changing the text of a text annotation turned back to 0° by quarter turns, whose
  drawing window stayed 2 px higher than its clip rectangle, edits the box of the
  clip as the official API does; other window/clip differences raise
  `XdwUnsupportedFeatureError`.
- Changing the text of a text annotation whose appearance EMF is malformed (a record
  cut short, a string outside its record, no header) raises `XdwFormatError` instead of
  `struct.error` or `UnicodeDecodeError`; a header-less EMF is no longer rewritten
  silently. A box wider or higher than 32,767 px raises `XdwUnsupportedFeatureError`,
  and a non-finite `font_size` raises `ValueError`.
- A write whose output fails pyxdw's own read-back check raises the new
  `XdwVerificationError` (an `XdwError`, and still an `AssertionError`) instead of a
  plain `AssertionError`. The 16 checks are explicit and run under `python -O` too.
- Rotating a page whose text annotation has a malformed appearance EMF raises
  `XdwFormatError` instead of `struct.error`; a box outline that is not a four-point
  polygon, or window, clip or text coordinates outside 0..32,765 px, raise
  `XdwUnsupportedFeatureError`. `XdwWriter.rotate_page` on reordered pages no longer
  replaces the writer's state when the rotation is refused.
- Changing the text of a rotated text annotation now raises
  `XdwUnsupportedFeatureError` (it raised `OverflowError` at 90°/270° and wrote an
  unverified appearance at 180°).
- Rotating a page whose text annotation is already rotated now accumulates the
  angle as `XDW_RotatePage` does (it wrote the step as an absolute angle); unverified
  transitions raise `XdwUnsupportedFeatureError`.
- A half turn of a sticky note or rectangle now moves only its position field to the
  front of the record, matching `XDW_RotatePage` (field order only; values unchanged).
