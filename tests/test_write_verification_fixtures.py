"""Each write self-check raises XdwVerificationError, also under python -O (E0-S),
on external fixtures.

The checks read the candidate back with ``XdwReader``; these tests replace the
reader used inside ``pyxdw.experimental`` with one that misreports a single value
of that read-back, so the candidate itself is unchanged.
"""

from __future__ import annotations

from contextlib import ExitStack
import os as _os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest import mock

from pyxdw import XdwError, XdwReader, XdwVerificationError, XdwWriter
from pyxdw import experimental
from pyxdw.reader import XdwAnnotation

TESTDATA = Path(_os.environ.get("PYXDW_TESTDATA", Path(__file__).resolve().parents[1] / "testdata"))
if not TESTDATA.is_dir():
    raise unittest.SkipTest("set PYXDW_TESTDATA to a folder of XDW fixtures (see docs/validation.md)")
TEXT = TESTDATA / "annotation-add-api9" / "N1.xdw"           # v10, one page, one text annotation
TWO_PAGES = TESTDATA / "corpus-api9" / "pages_2.xdw"         # v7, two JPEG pages, three generations
V10_HISTORY = TESTDATA / "annotated-font-rotation-api9" / "F2.xdw"   # v10, two generations
for _path in (TEXT, TWO_PAGES, V10_HISTORY):
    if not _path.exists():
        raise unittest.SkipTest(f"{_path.name} fixture is not available")


class _Generation:
    """A generation that reports some attributes differently."""

    def __init__(self, real, **attributes):
        self._real = real
        self.__dict__.update(attributes)

    def __getattr__(self, name):
        return getattr(self._real, name)


def misreporting_reader(*, skip: int = 0, page_count=None, typed_metadata=None,
                        current_generation=None, generations=None):
    """An XdwReader class whose instances misreport the given values, except those
    built while ``state["paused"]`` and the first *skip* others."""
    real = experimental.XdwReader
    state = {"built": 0, "paused": False}

    class Misreporting(real):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            if not state["paused"]:
                state["built"] += 1
            self._misreport = not state["paused"] and state["built"] > skip
            if self._misreport and current_generation is not None:
                self.current_generation = current_generation(self.current_generation)
            if self._misreport and generations is not None:
                self.generations = generations(self.generations)

        @property
        def page_count(self):
            count = len(self.pages)
            return page_count(count) if self._misreport and page_count else count

        @property
        def typed_metadata(self):
            value = real.typed_metadata.func(self)
            return typed_metadata(value) if self._misreport and typed_metadata else value

    return Misreporting, state


def honest(reader_class, state, path):
    """A reader of *reader_class* (so isinstance checks accept it) that reports truly."""
    state["paused"] = True
    try:
        return reader_class(path)
    finally:
        state["paused"] = False


def honest_merge(state):
    """merge_documents_bytes with honest readers inside it (for compact/extract)."""
    merge = experimental.merge_documents_bytes

    def wrapped(*args, **kwargs):
        state["paused"] = True
        try:
            return merge(*args, **kwargs)
        finally:
            state["paused"] = False
    return wrapped


def resources_with(**attributes):
    def change(generation):
        fake = [types.SimpleNamespace(identifier=r.identifier, payload_bytes=r.payload_bytes,
                                      offset=r.offset) for r in generation.resources]
        for i, resource in enumerate(fake):
            for name, value in attributes.items():
                setattr(resource, name, value(i) if callable(value) else value)
        return _Generation(generation, resources=tuple(fake))
    return change


class WriteVerificationFixtureTest(unittest.TestCase):
    def assert_verification_error(self, message: str, call):
        with self.assertRaises(XdwVerificationError) as caught:
            call()
        self.assertEqual(str(caught.exception), message)
        self.assertIsInstance(caught.exception, XdwError)
        self.assertIsInstance(caught.exception, AssertionError)

    def assert_writer_refuses(self, message: str, writer: XdwWriter, call, *patches):
        before = writer.to_bytes()
        state = (writer._reader, list(writer._page_indices))
        with ExitStack() as stack:              # misreport only during the write itself
            for patch in patches:
                stack.enter_context(patch)
            self.assert_verification_error(message, call)
        self.assertEqual((writer._reader, list(writer._page_indices)), state)
        self.assertEqual(writer.to_bytes(), before)

    # -- annotation and property writes (sites 1-5) ---------------------------------

    def test_moved_annotation(self):
        writer = XdwWriter(XdwReader(TEXT))
        self.assert_writer_refuses("moved annotation did not round-trip", writer,
                                   lambda: writer.move_annotation(0, 0, 1000, 1000),
                                   mock.patch.object(XdwAnnotation, "position", property(lambda self: (-1, -1))))

    def test_properties(self):
        writer = XdwWriter(XdwReader(TEXT))
        before = writer.to_bytes()
        state = (writer._reader, list(writer._page_indices))
        reader, _ = misreporting_reader(typed_metadata=lambda value: {})
        with mock.patch.object(experimental, "XdwReader", reader):
            with self.assertRaises(XdwVerificationError) as caught:
                writer.add_metadata({"/Title": "checked"})
        self.assertTrue(str(caught.exception).startswith("properties did not round-trip"))
        self.assertIsInstance(caught.exception, AssertionError)
        self.assertEqual((writer._reader, list(writer._page_indices)), state)
        self.assertEqual(writer.to_bytes(), before)

    def test_annotation_text(self):
        writer = XdwWriter(XdwReader(TEXT))
        self.assert_writer_refuses("annotation text did not round-trip", writer,
                                   lambda: writer.set_annotation_text(0, 0, "x"),
                                   mock.patch.object(XdwAnnotation, "extract_text", lambda self, *a, **k: "other"))

    def test_added_text_annotation(self):
        writer = XdwWriter(XdwReader(TEXT))
        self.assert_writer_refuses("added annotation did not round-trip", writer,
                                   lambda: writer.add_text_annotation(0, 1000, 1000, "x"),
                                   mock.patch.object(XdwAnnotation, "extract_text", lambda self, *a, **k: "other"))

    def test_added_shape_annotation(self):
        for method in ("add_sticky_note", "add_rectangle"):
            with self.subTest(method):
                writer = XdwWriter(XdwReader(TEXT))
                self.assert_writer_refuses("added annotation did not round-trip", writer,
                                           lambda: getattr(writer, method)(0, 1000, 1000),
                                           mock.patch.object(XdwAnnotation, "position",
                                                             property(lambda self: (-1, -1))))

    # -- appended generation (sites 6-7), reached here through a page rotation ------

    def test_appended_generation(self):
        cases = {
            "generated directory did not round-trip":
                lambda g: _Generation(g, resource_offsets=(-1,)),
            "generated metadata did not round-trip":
                lambda g: _Generation(g, metadata=b"other"),
        }
        for message, change in cases.items():
            with self.subTest(message):
                writer = XdwWriter(XdwReader(TWO_PAGES))
                reader, _ = misreporting_reader(current_generation=change)
                self.assert_writer_refuses(message, writer, lambda: writer.rotate_page(0, 90),
                                           mock.patch.object(experimental, "XdwReader", reader))

    # -- merge (sites 8-11) ---------------------------------------------------------

    def test_merge(self):
        cases = {
            "merged candidate page count did not round-trip": dict(page_count=lambda n: n + 1),
            "merged metadata did not round-trip":
                dict(current_generation=lambda g: _Generation(g, metadata=b"other")),
            "merged resource identifier remained zero":
                dict(current_generation=resources_with(identifier=0)),
            "merged resource identifiers are not unique":
                dict(current_generation=resources_with(identifier=7)),
        }
        for message, misreport in cases.items():
            with self.subTest(message):
                reader, state = misreporting_reader(**misreport)
                sources = (honest(reader, state, TWO_PAGES), honest(reader, state, TWO_PAGES))
                with mock.patch.object(experimental, "XdwReader", reader):
                    self.assert_verification_error(message, lambda: experimental.merge_documents_bytes(sources))
                    self.assert_verification_error(message, lambda: XdwWriter.merge(sources))

    # -- compact and page extraction (sites 12-16) ---------------------------------

    def test_compact(self):
        empty = types.SimpleNamespace(pages=(), resources=())
        held = types.SimpleNamespace(pages=(object(),), resources=())
        cases = {
            "compacted document retained old page/resource generations":
                (TWO_PAGES, dict(generations=lambda gens: (held, *gens))),
            "compacted v10 document retained old generations":
                (V10_HISTORY, dict(generations=lambda gens: (empty, *gens))),
            "compacted document page count changed": (TWO_PAGES, dict(page_count=lambda n: n + 1)),
            "compacted document resource payloads changed":
                (TWO_PAGES, dict(current_generation=resources_with(payload_bytes=b"other"))),
        }
        for message, (path, misreport) in cases.items():
            with self.subTest(message):
                reader, state = misreporting_reader(**misreport)
                source = honest(reader, state, path)
                with mock.patch.object(experimental, "XdwReader", reader), \
                        mock.patch.object(experimental, "merge_documents_bytes", honest_merge(state)):
                    self.assert_verification_error(message, lambda: experimental.compact_document_bytes(source))

    def test_extract_page(self):
        # reads before the extraction's own: two in select_pages_bytes, then the selected page
        for name, misreport in {"page count": dict(skip=3, page_count=lambda n: n + 1),
                                "history": dict(skip=3, generations=lambda gens: (
                                    types.SimpleNamespace(pages=(object(),), resources=()), *gens))}.items():
            with self.subTest(name):
                reader, state = misreporting_reader(**misreport)
                source = honest(reader, state, TWO_PAGES)
                with mock.patch.object(experimental, "XdwReader", reader), \
                        mock.patch.object(experimental, "merge_documents_bytes", honest_merge(state)):
                    self.assert_verification_error("compact page extraction did not round-trip",
                                                   lambda: experimental.extract_page_bytes(source, 0))

    # -- the same checks with python -O ---------------------------------------------

    def test_checks_run_under_python_optimize(self):
        script = f"""
import sys
from unittest import mock
sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})
import pyxdw
from pyxdw import XdwReader, XdwVerificationError, XdwWriter, experimental
from pyxdw.reader import XdwAnnotation
import test_write_verification_fixtures as t
assert sys.flags.optimize == 1          # this line itself is skipped under -O
print("optimize", sys.flags.optimize)
writer = XdwWriter(XdwReader({str(TEXT)!r}))
with mock.patch.object(XdwAnnotation, "extract_text", lambda self, *a, **k: "other"):
    try:
        writer.set_annotation_text(0, 0, "x")
        print("text: no error")
    except XdwVerificationError as exc:
        print("text:", type(exc).__name__, exc)
reader, state = t.misreporting_reader(page_count=lambda n: n + 1)
source = t.honest(reader, state, {str(TWO_PAGES)!r})
with mock.patch.object(experimental, "XdwReader", reader), \\
        mock.patch.object(experimental, "merge_documents_bytes", t.honest_merge(state)):
    try:
        experimental.compact_document_bytes(source)
        print("compact: no error")
    except XdwVerificationError as exc:
        print("compact:", type(exc).__name__, exc)
"""
        env = dict(_os.environ, PYXDW_TESTDATA=str(TESTDATA),
                   PYTHONPATH=str(Path(__file__).resolve().parents[1]), PYTHONDONTWRITEBYTECODE="1")
        done = subprocess.run([sys.executable, "-O", "-c", script], capture_output=True, text=True,
                              env=env, timeout=300)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.splitlines(), [
            "optimize 1",
            "text: XdwVerificationError annotation text did not round-trip",
            "compact: XdwVerificationError compacted document page count changed",
        ])


if __name__ == "__main__":
    unittest.main()
