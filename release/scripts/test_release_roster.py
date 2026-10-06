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


class ReleaseRosterTest(TestCase):
    def test_new_release_surfaces_begin_at_v0_38(self) -> None:
        for constant, helper in (
            ("BREG_SERVICES_FIRST_RELEASE", release_roster.breg_services_in_release),
            ("MESSAGING_FIRST_RELEASE", release_roster.messaging_in_release),
            ("DISCOVERYCTL_FIRST_RELEASE", release_roster.discoveryctl_in_release),
            ("SCHEDULING_BINARY_FIRST_RELEASE", release_roster.scheduling_binary_in_release),
            ("RENDER_FIRST_RELEASE", release_roster.render_in_release),
            (
                "EVIDENCE_OID4VCI_IMAGE_FIRST_RELEASE",
                release_roster.evidence_oid4vci_image_in_release,
            ),
        ):
            with self.subTest(constant=constant):
                self.assertEqual((0, 38, 0), getattr(release_roster, constant))
                self.assertFalse(helper((0, 37, 0)))
                self.assertFalse(helper((0, 37, 99)))
                self.assertTrue(helper((0, 38, 0)))
                self.assertTrue(helper((1, 0, 0)))

    def test_first_release_constants_are_read_at_call_time(self) -> None:
        for constant, helper in (
            ("BREG_SERVICES_FIRST_RELEASE", release_roster.breg_services_in_release),
            ("MESSAGING_FIRST_RELEASE", release_roster.messaging_in_release),
            ("DISCOVERYCTL_FIRST_RELEASE", release_roster.discoveryctl_in_release),
            ("SCHEDULING_BINARY_FIRST_RELEASE", release_roster.scheduling_binary_in_release),
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

    def test_unified_clients_carry_scheduling_from_v0_40(self) -> None:
        self.assertEqual((0, 40, 0), release_roster.SCHEDULING_CLIENT_FIRST_RELEASE)
        self.assertFalse(release_roster.scheduling_client_in_release((0, 39, 0)))
        self.assertFalse(release_roster.scheduling_client_in_release((0, 39, 99)))
        self.assertTrue(release_roster.scheduling_client_in_release((0, 40, 0)))
        self.assertTrue(release_roster.scheduling_client_in_release((1, 0, 0)))
        with mock.patch.object(release_roster, "SCHEDULING_CLIENT_FIRST_RELEASE", None):
            self.assertFalse(release_roster.scheduling_client_in_release((1, 0, 0)))

    def test_relay_is_retired_from_v0_39(self) -> None:
        self.assertEqual((0, 39, 0), release_roster.RELAY_RETIREMENT_RELEASE)
        self.assertTrue(release_roster.relay_in_release((0, 38, 0)))
        self.assertTrue(release_roster.relay_in_release((0, 38, 99)))
        self.assertFalse(release_roster.relay_in_release((0, 39, 0)))
        self.assertFalse(release_roster.relay_in_release((1, 0, 0)))

    def test_cli_reports_the_version_selected_roster(self) -> None:
        for command in (
            "breg-services-in-release",
            "messaging-in-release",
            "discoveryctl-in-release",
            "scheduling-binary-in-release",
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

        for version, expected in (("0.39.9", "false\n"), ("v0.40.0", "true\n")):
            with self.subTest(command="scheduling-client-in-release", version=version):
                stdout = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                    result = release_roster.main(["scheduling-client-in-release", version])
                self.assertEqual(0, result)
                self.assertEqual(expected, stdout.getvalue())

        for version, expected in (("0.38.99", "true\n"), ("v0.39.0", "false\n")):
            with self.subTest(command="relay-in-release", version=version):
                stdout = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                    result = release_roster.main(["relay-in-release", version])
                self.assertEqual(0, result)
                self.assertEqual(expected, stdout.getvalue())


if __name__ == "__main__":
    main()
