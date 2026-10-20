# Notes for AI coding agents

- Library code is in `pyxdw/`; it must stay pure Python with no runtime dependencies
  and must never call DocuWorks, XDWAPI or Windows APIs.
- Do not add XDW sample files, DocuWorks SDK files, DLLs or anything produced from
  business documents to the repository. Fixtures live outside it (`PYXDW_TESTDATA`).
- A write path counts as supported only after its output was compared with the
  official DocuWorks API and opened in DocuWorks Viewer. Anything else must raise
  `XdwUnsupportedFeatureError`, not guess.
- Run `python -m unittest discover -s tests` before and after a change.
- Keep the README feature table and `docs/supported_features.md` in sync with the code.
