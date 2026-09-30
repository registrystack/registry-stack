#!/usr/bin/env python3
from __future__ import annotations

import io
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import TestCase, main, mock

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import release_roster  # noqa: E402


HELD_SURFACES = (
    ("BREG_SERVICES_FIRST_RELEASE", release_roster.breg_services_in_release),
    ("MESSAGING_FIRST_RELEASE", release_roster.messaging_in_release),
    ("RENDER_FIRST_RELEASE", release_roster.render_in_release),
    (
        "EVIDENCE_OID4VCI_IMAGE_FIRST_RELEASE",
        release_roster.evidence_oid4vci_image_in_release,
    ),
)
V0_38_SURFACES = (
    ("DISCOVERYCTL_FIRST_RELEASE", release_roster.discoveryctl_in_release),
    ("SCHEDULING_BINARY_FIRST_RELEASE", release_roster.scheduling_binary_in_release),
)
COMMANDS = (
    ("breg-services-in-release", "BREG_SERVICES_FIRST_RELEASE"),
    ("messaging-in-release", "MESSAGING_FIRST_RELEASE"),
    ("discoveryctl-in-release", "DISCOVERYCTL_FIRST_RELEASE"),
    ("scheduling-binary-in-release", "SCHEDULING_BINARY_FIRST_RELEASE"),
    ("render-in-release", "RENDER_FIRST_RELEASE"),
    ("evidence-oid4vci-image-in-release", "EVIDENCE_OID4VCI_IMAGE_FIRST_RELEASE"),
)


def run_cli(command: str, version: str) -> tuple[int, str]:
    stdout = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
        result = release_roster.main([command, version])
    return result, stdout.getvalue()


class ReleaseRosterTest(TestCase):
    def test_new_release_surfaces_begin_at_v0_38(self) -> None:
        for constant, helper in V0_38_SURFACES:
            with self.subTest(constant=constant):
                self.assertEqual((0, 38, 0), getattr(release_roster, constant))
                self.assertFalse(helper((0, 37, 0)))
                self.assertFalse(helper((0, 37, 99)))
                self.assertTrue(helper((0, 38, 0)))
                self.assertTrue(helper((1, 0, 0)))

    def test_held_surfaces_join_no_release(self) -> None:
        for constant, helper in HELD_SURFACES:
            with self.subTest(constant=constant):
                self.assertIsNone(getattr(release_roster, constant))
                self.assertFalse(helper((0, 38, 0)))
                self.assertFalse(helper((1, 0, 0)))

    def test_a_named_first_release_selects_that_release_onward(self) -> None:
        for constant, helper in HELD_SURFACES:
            with self.subTest(constant=constant), mock.patch.object(
                release_roster, constant, (0, 39, 0)
            ):
                self.assertFalse(helper((0, 38, 99)))
                self.assertTrue(helper((0, 39, 0)))
                self.assertTrue(helper((1, 0, 0)))

    def test_first_release_constants_are_read_at_call_time(self) -> None:
        for constant, helper in (*HELD_SURFACES, *V0_38_SURFACES):
            with self.subTest(constant=constant), mock.patch.object(
                release_roster, constant, None
            ):
                self.assertFalse(helper((1, 0, 0)))

    def test_cli_reports_the_version_selected_roster(self) -> None:
        for command, constant in COMMANDS:
            for version, expected in (("0.37.9", "false\n"), ("v0.38.0", "true\n")):
                with self.subTest(command=command, version=version), mock.patch.object(
                    release_roster, constant, (0, 38, 0)
                ):
                    self.assertEqual((0, expected), run_cli(command, version))

    def test_cli_reports_held_surfaces_as_absent(self) -> None:
        held = {constant for constant, _helper in HELD_SURFACES}
        for command, constant in COMMANDS:
            expected = "false\n" if constant in held else "true\n"
            with self.subTest(command=command):
                self.assertEqual((0, expected), run_cli(command, "0.38.0"))


if __name__ == "__main__":
    main()
