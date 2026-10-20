# Limitations

- No rendering: pyxdw cannot draw a page; it returns the stored image data.
- Rotation is refused for page layouts and annotation types that were not verified.
  A text annotation case at 90° is still refused by the official API for a reason
  not yet understood.
- Nested sticky notes, markers and multi-line text annotations are not rotated.
- Rotating again a page whose text annotation is already rotated reproduces the
  official result for every step from 90°, 180° and 270°. A text box back at 0°
  after a quarter-turn round trip (its window 2 px higher than its clip) can
  only be turned by +90; other steps from there, and text boxes whose drawing
  does not match the verified layout, raise `XdwUnsupportedFeatureError`. pyxdw
  writes the document after every rotation, so two rotations in one writer give
  the result of the official API saving between them, which differs slightly
  (window, position, field order) from two turns on one official handle.
- The text of a rotated text annotation cannot be changed (`XdwUnsupportedFeatureError`).
  This covers any non-zero `%TextRotationAngle` or font escapement/orientation,
  including 180°, whether pyxdw or DocuWorks rotated it. The official output for
  such an edit has not been compared. A text box turned back to 0° whose window
  is 2 px higher than its clip rectangle (after quarter turns) is edited as the box
  of its clip, as the official API does (values compared; field order and the 1 px
  bounds of a one-character box differ as for any text edit; DocuWorks Viewer
  shows it identically). Any other difference between window and clip, or a drawing
  that does not match the verified layout, raises `XdwUnsupportedFeatureError`.
- A text annotation's box can be at most 32,767 px (about 2.77 m at 300 dpi) wide or
  high after a text change; longer text raises `XdwUnsupportedFeatureError`. The
  official API's own limit has not been compared.
- The LZH encoder is not bit-identical to DocuWorks: about one byte in rare cases
  differs while decoding to the same data.
- The official writer leaves uninitialised padding in rotated text records; pyxdw
  writes zeros there, so those bytes differ.
- Encrypted, signed and binder documents are not supported.
- Only macOS has been tested.
- Decoding is bounded by `XdwLimits` (pass `XdwReader(path, limits=XdwLimits(...))`).
  Defaults: 64 MiB per LZH stream, 16 MiB for metadata and for an annotation
  appearance, 512 MiB and 65,535 pixels per side for an image, and 1 GiB of LZH
  output in total per reader. A document beyond these raises `XdwLimitError`.
  The total counts decoded LZH bytes only; it is not a limit on process memory
  (copies, BMP/TIFF assembly and Python overhead are not counted, and one decode
  briefly needs about twice its output).
