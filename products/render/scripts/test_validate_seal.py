# SPDX-License-Identifier: Apache-2.0
"""Unit tests for validate-seal.py that need no PDF validator installed.

The end-to-end run against real sealed PDFs is documented in the script's
usage; these tests cover the first-revision cut and the failure reporting.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
SCRIPT_PATH = Path(__file__).with_name("validate-seal.py")
SPEC = importlib.util.spec_from_file_location("render_validate_seal", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)

FIRST = b"%PDF-2.0\nbody\nxref\n0 1\ntrailer\n<< >>\nstartxref\n9\n%%EOF"
UPDATE = b"\nxref\n0 1\ntrailer\n<< /Prev 9 >>\nstartxref\n%d\n%%%%EOF\n"


def sealed(first: bytes = FIRST) -> bytes:
    update_xref = len(first) + 1
    return first + UPDATE % update_xref


class FirstRevisionEndTests(unittest.TestCase):
    def test_cut_is_the_original_eof_without_the_update_newline(self) -> None:
        pdf = sealed()
        end = VALIDATOR.first_revision_end(pdf)
        self.assertEqual(end, len(FIRST))
        self.assertEqual(
            hashlib.sha256(pdf[:end]).hexdigest(), hashlib.sha256(FIRST).hexdigest()
        )

    def test_unsigned_file_has_no_cut(self) -> None:
        self.assertIsNone(VALIDATOR.first_revision_end(FIRST))

    def test_update_without_prev_has_no_cut(self) -> None:
        pdf = FIRST + b"\nxref\ntrailer\n<< >>\nstartxref\n%d\n%%%%EOF\n" % (
            len(FIRST) + 1
        )
        self.assertIsNone(VALIDATOR.first_revision_end(pdf))


class MainTests(unittest.TestCase):
    def run_main(self, *args: str) -> tuple[int, dict]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = VALIDATOR.main(list(args))
        return code, json.loads(out.getvalue())

    def test_unreadable_pdf_fails_with_a_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root.pem"
            root.write_text("")
            code, report = self.run_main(
                "--pdf", str(Path(temporary) / "missing.pdf"), "--trust-root", str(root)
            )
        self.assertEqual(code, 1)
        self.assertFalse(report["ok"])
        self.assertFalse(report["checks"][0]["ok"])


if __name__ == "__main__":
    unittest.main()
