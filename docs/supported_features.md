# Supported features

Levels:
- **verified (write)** = output compared with the official DocuWorks API 9.0.11 and
  opened in DocuWorks Viewer;
- **verified (read)** = values compared with what the official API reports for the
  test files; reading a further 746 real-world files without error is a robustness
  check, not proof that every value was correct;
- **implemented** = works on the test files but not compared against the official API;
- **unsupported** = raises an error.

| Feature | Level |
|---|---|
| Read page count, size, rotation, page layout | verified (read) |
| Read properties (title, user-defined) | verified (read) |
| Read annotations: type, position, size, text | verified (read) |
| Extract page images (JPEG, G3/G4 as TIFF, BMP), preview BMP | implemented |
| Extract text of text annotations / OCR text | implemented |
| Copy, reorder, delete, insert pages; merge documents (v7/v10 bodies) | verified |
| Rotate pages: layouts in `SUPPORTED_PAGE_LAYOUTS`, embedded-font pages, inline EMF | verified (byte match except explained padding) |
| Rotate pages carrying text / sticky-note / rectangle annotations | verified |
| Rotate again a page whose text annotation is already rotated | verified (all steps from 90°/180°/270°; from 0° after a quarter-turn round trip only +90); others raise `XdwUnsupportedFeatureError` |
| Rotate pages with other annotations, stamps, seals, annotated OCR scans | unsupported (the official API refuses too) |
| Add text annotation (font size, colour, background, multi-line) | verified |
| Annotation text outside the BMP (𠮷, emoji) | unsupported |
| Re-text a rotated text annotation (`%TextRotationAngle` or font escapement/orientation not 0) | unsupported (`XdwUnsupportedFeatureError`; official output not compared) |
| Re-text a text annotation turned back to 0° whose window is 2 px higher than its clip | verified (values match the official API; Viewer 2026-10-20); other window/clip differences raise `XdwUnsupportedFeatureError` |
| Add sticky note / rectangle (colour, fill, border, size) | verified |
| Rectangle with a transparent fill | verified (Viewer re-checked 2026-10-19 after the template rewrite) |
| Move, re-text, delete annotations | verified |
| `add_metadata` (title, user-defined properties) | verified |
| Encrypted / password-protected / signed documents | unsupported (`XdwProtectedDocumentError`) |
| Binders `.xbd`, rendering pages, OCR | unsupported |
| Editing documents with attached original files | unsupported |
