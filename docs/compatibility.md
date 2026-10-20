# Compatibility

- Python: 3.10 or later is declared; only 3.14.5 has been run.
- OS: tested on macOS (arm64) only. The code uses no OS-specific APIs, but Linux
  and Windows are untested.
- XDW format versions: reading v7, v9, v10 bodies. Writing keeps the input version.
  v9 (MRC) documents are never compacted, even with `compact=True`: edits are
  appended and earlier content stays in the file. Do not rely on `compact` to
  remove removed pages or old text from a v9 document.
- Reference implementation: DocuWorks API (XDWAPI) 9.0.11 on Windows.
- Files from other DocuWorks versions are expected to read but were not checked
  systematically.
