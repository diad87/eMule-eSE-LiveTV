#!/usr/bin/env python3
"""Document-checker regressions, not eMule product acceptance tests."""

import contextlib
import importlib.util
import io
from pathlib import Path
import re
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE = importlib.util.spec_from_file_location("v93_check", ROOT / "tools/check_v93_specification.py")
checker = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(checker)


class SpecificationCheckerTests(unittest.TestCase):
    def setUp(self):
        self.original_read = Path.read_text
        self.document = checker.SPEC.read_text(encoding="utf-8")

    def run_document(self, document):
        def read(path, *args, **kwargs):
            return document if path == checker.SPEC else self.original_read(path, *args, **kwargs)
        with patch.object(Path, "read_text", read), contextlib.redirect_stdout(io.StringIO()):
            return checker.main()

    def assert_rejected(self, document, message):
        with self.assertRaisesRegex(ValueError, message):
            self.run_document(document)

    def test_current_document(self):
        self.assertEqual(self.run_document(self.document), 0)

    def test_missing_requirement_mapping(self):
        self.assert_rejected(
            self.document.replace("| `AI-F01` | C | `NC-C01` |\n", ""), "trace differs"
        )

    def test_duplicate_primary_test(self):
        self.assert_rejected(
            self.document.replace("| `AI-F02` | F | `EP-F02` |", "| `AI-F02` | F | `NC-C01` |"),
            "primary test must be uniquely",
        )

    def test_owner_must_match_plan(self):
        self.assert_rejected(
            self.document.replace("| `AI-F01` | C | `NC-C01` |", "| `AI-F01` | A | `NC-C01` |"),
            "owner differs from plan",
        )

    def test_missing_delta(self):
        modified = re.sub(r"(?m)^\| `AI16-D19` \|[^\n]*\n", "", self.document)
        self.assert_rejected(modified, "missing 1.6 delta")

    def test_missing_local_link(self):
        self.assert_rejected(
            self.document + "\n[bad](__nonexistent_v93_checker_fixture__.md)\n", "local link does not exist"
        )

    def test_malformed_table(self):
        self.assert_rejected(
            self.document + "\n| A | B |\n|---|---|\n| 1 | 2 | 3 |\n", "malformed Markdown table"
        )

    def test_unclosed_code_fence(self):
        self.assert_rejected(self.document + "\n```text\nunclosed\n", "unclosed code fence")


if __name__ == "__main__":
    unittest.main()
