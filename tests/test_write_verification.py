"""Write self-checks raise XdwVerificationError and never depend on assert (E0-S);
no fixtures."""

from __future__ import annotations

import ast
from pathlib import Path
import unittest

import pyxdw
from pyxdw import XdwError, XdwVerificationError

PACKAGE = Path(pyxdw.__file__).resolve().parent


class WriteVerificationErrorTest(unittest.TestCase):
    def test_hierarchy(self):
        # An XdwError for callers catching pyxdw errors; still an AssertionError for
        # callers that caught the earlier AssertionError.
        self.assertTrue(issubclass(XdwVerificationError, XdwError))
        self.assertTrue(issubclass(XdwVerificationError, AssertionError))
        self.assertIn("XdwVerificationError", pyxdw.__all__)
        self.assertIs(pyxdw.errors.XdwVerificationError, XdwVerificationError)

    def test_no_check_relies_on_assert_or_assertion_error(self):
        # assert statements disappear under python -O; plain AssertionError is not an XdwError.
        found = []
        for path in sorted(PACKAGE.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Assert):
                    found.append(f"{path.name}:{node.lineno} assert")
                elif isinstance(node, ast.Raise) and node.exc is not None:
                    target = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
                    if isinstance(target, ast.Name) and target.id == "AssertionError":
                        found.append(f"{path.name}:{node.lineno} raise AssertionError")
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
