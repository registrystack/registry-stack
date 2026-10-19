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

    def test_scheduling_installer_is_published_from_v0_42(self) -> None:
        self.assertEqual((0, 42, 0), release_roster.SCHEDULING_INSTALLER_FIRST_RELEASE)
        self.assertFalse(release_roster.scheduling_installer_in_release((0, 41, 0)))
        self.assertFalse(release_roster.scheduling_installer_in_release((0, 41, 99)))
        self.assertTrue(release_roster.scheduling_installer_in_release((0, 42, 0)))
        self.assertTrue(release_roster.scheduling_installer_in_release((1, 0, 0)))
        with mock.patch.object(release_roster, "SCHEDULING_INSTALLER_FIRST_RELEASE", None):
            self.assertFalse(release_roster.scheduling_installer_in_release((1, 0, 0)))
        for version, expected in (("0.41.9", "false\n"), ("v0.42.0", "true\n")):
            with self.subTest(command="scheduling-installer-in-release", version=version):
                stdout = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                    result = release_roster.main(["scheduling-installer-in-release", version])
                self.assertEqual(0, result)
                self.assertEqual(expected, stdout.getvalue())

    def test_unified_clients_hold_coordinator_until_its_client_returns(self) -> None:
        self.assertIsNone(release_roster.COORDINATOR_CLIENT_FIRST_RELEASE)
        for version in ((0, 41, 0), (0, 42, 0), (1, 0, 0)):
            self.assertFalse(release_roster.coordinator_client_in_release(version))
        with mock.patch.object(release_roster, "COORDINATOR_CLIENT_FIRST_RELEASE", (0, 42, 0)):
            self.assertFalse(release_roster.coordinator_client_in_release((0, 41, 99)))
            self.assertTrue(release_roster.coordinator_client_in_release((0, 42, 0)))

    def test_coordinator_runtime_is_held_until_release_prerequisites_are_ready(self) -> None:
        self.assertIsNone(release_roster.COORDINATOR_FIRST_RELEASE)
        for version in ((0, 41, 0), (0, 42, 0), (1, 0, 0)):
            self.assertFalse(release_roster.coordinator_in_release(version))
        with mock.patch.object(release_roster, "COORDINATOR_FIRST_RELEASE", (0, 42, 0)):
            self.assertFalse(release_roster.coordinator_in_release((0, 41, 99)))
            self.assertTrue(release_roster.coordinator_in_release((0, 42, 0)))

    def test_relay_is_retired_from_v0_39(self) -> None:
        self.assertEqual((0, 39, 0), release_roster.RELAY_RETIREMENT_RELEASE)
        self.assertTrue(release_roster.relay_in_release((0, 38, 0)))
        self.assertTrue(release_roster.relay_in_release((0, 38, 99)))
        self.assertFalse(release_roster.relay_in_release((0, 39, 0)))
        self.assertFalse(release_roster.relay_in_release((1, 0, 0)))

    def test_python_wheels_use_the_311_stable_abi_from_v0_41(self) -> None:
        self.assertEqual((0, 41, 0), release_roster.PYTHON_311_ABI_FIRST_RELEASE)
        self.assertEqual("cp310-abi3", release_roster.python_wheel_abi_tag((0, 40, 0)))
        self.assertEqual("cp310-abi3", release_roster.python_wheel_abi_tag((0, 40, 99)))
        self.assertEqual("cp311-abi3", release_roster.python_wheel_abi_tag((0, 41, 0)))
        self.assertEqual("cp311-abi3", release_roster.python_wheel_abi_tag((1, 0, 0)))

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

        for command in ("coordinator-client-in-release", "coordinator-in-release"):
            for version, expected in (("0.41.9", "false\n"), ("v0.42.0", "false\n")):
                with self.subTest(command=command, version=version):
                    stdout = io.StringIO()
                    with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                        result = release_roster.main([command, version])
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
