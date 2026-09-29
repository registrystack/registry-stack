#!/usr/bin/env python3
from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import release_roster  # noqa: E402


class ReleaseRosterTest(unittest.TestCase):
    def test_render_and_oid4vci_image_begin_at_v0_38(self) -> None:
        self.assertEqual((0, 38, 0), release_roster.RENDER_FIRST_RELEASE)
        self.assertEqual(
            (0, 38, 0),
            release_roster.EVIDENCE_OID4VCI_IMAGE_FIRST_RELEASE,
        )
        for helper in (
            release_roster.render_in_release,
            release_roster.evidence_oid4vci_image_in_release,
        ):
            with self.subTest(helper=helper.__name__):
                self.assertFalse(helper((0, 37, 0)))
                self.assertFalse(helper((0, 37, 99)))
                self.assertTrue(helper((0, 38, 0)))
                self.assertTrue(helper((1, 0, 0)))

    def test_first_release_constants_are_read_at_call_time(self) -> None:
        for constant, helper in (
            ("RENDER_FIRST_RELEASE", release_roster.render_in_release),
            (
                "EVIDENCE_OID4VCI_IMAGE_FIRST_RELEASE",
                release_roster.evidence_oid4vci_image_in_release,
            ),
        ):
            with self.subTest(constant=constant), mock.patch.object(
                release_roster, constant, None
            ):
                self.assertFalse(helper((1, 0, 0)))

    def test_cli_reports_the_version_selected_roster(self) -> None:
        for command in (
            "render-in-release",
            "evidence-oid4vci-image-in-release",
        ):
            for version, expected in (("0.37.9", "false\n"), ("v0.38.0", "true\n")):
                with self.subTest(command=command, version=version):
                    stdout = io.StringIO()
                    with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                        result = release_roster.main([command, version])
                    self.assertEqual(0, result)
                    self.assertEqual(expected, stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
