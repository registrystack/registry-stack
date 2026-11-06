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


class FirstRevisionCheckTests(unittest.TestCase):
    def test_the_labelled_digest_of_the_first_revision_passes(self) -> None:
        digest = "sha256:" + hashlib.sha256(FIRST).hexdigest()
        result = VALIDATOR.first_revision_check(sealed(), digest)
        self.assertEqual(result["name"], "first-revision-digest")
        self.assertTrue(result["ok"])
        self.assertEqual(
            result["detail"], {"firstRevisionLength": len(FIRST), "digest": digest}
        )

    def test_another_digest_or_no_cut_fails(self) -> None:
        other = "sha256:" + "0" * 64
        self.assertFalse(VALIDATOR.first_revision_check(sealed(), other)["ok"])
        digest = "sha256:" + hashlib.sha256(FIRST).hexdigest()
        unsigned = VALIDATOR.first_revision_check(FIRST, digest)
        self.assertFalse(unsigned["ok"])
        self.assertEqual(
            unsigned["detail"], {"firstRevisionLength": None, "digest": None}
        )


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

    def test_a_document_digest_must_be_labelled(self) -> None:
        bare = hashlib.sha256(FIRST).hexdigest()
        for value in [bare, "SHA256:" + bare, "sha256:" + bare.upper()]:
            with self.assertRaises(SystemExit) as refused, contextlib.redirect_stderr(
                io.StringIO()
            ) as stderr:
                VALIDATOR.main(
                    ["--pdf", "x.pdf", "--trust-root", "r.pem", "--document-digest", value]
                )
            self.assertEqual(refused.exception.code, 2, value)
            self.assertIn("sha256:<64 lowercase hex digits>", stderr.getvalue())

    def test_the_retired_flag_is_refused(self) -> None:
        with self.assertRaises(SystemExit) as refused, contextlib.redirect_stderr(
            io.StringIO()
        ):
            VALIDATOR.main(
                ["--pdf", "x.pdf", "--trust-root", "r.pem", "--document-sha256", "0" * 64]
            )
        self.assertEqual(refused.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
