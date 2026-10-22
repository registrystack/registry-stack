#!/usr/bin/env python3
"""Tests for the installed Discovery distribution smoke."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest.mock
from contextlib import redirect_stderr


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release/scripts/smoke_discovery_distribution.py"


def load_smoke():
    spec = importlib.util.spec_from_file_location(
        "smoke_discovery_distribution", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Discovery distribution smoke")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DiscoveryDistributionSmokeTests(unittest.TestCase):
    def test_readiness_timeout_retains_last_connection_failure(self) -> None:
        failure = self.smoke.urllib.error.URLError("connection refused")
        process = unittest.mock.Mock()
        process.poll.return_value = None
        with (
            unittest.mock.patch.object(
                self.smoke.time, "monotonic", side_effect=[0, 0, 16]
            ),
            unittest.mock.patch.object(self.smoke.time, "sleep"),
            unittest.mock.patch.object(
                self.smoke.urllib.request, "urlopen", side_effect=failure
            ),
        ):
            with self.assertRaises(self.smoke.SmokeError) as caught:
                self.smoke._wait_until_ready("http://127.0.0.1:1/", process)
        self.assertIs(caught.exception.__cause__, failure)

    def setUp(self) -> None:
        self.smoke = load_smoke()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_cli_requires_exactly_one_client_source(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.smoke.parse_args(["--bin-dir", str(self.root)])
            with self.assertRaises(SystemExit):
                self.smoke.parse_args(
                    [
                        "--bin-dir",
                        str(self.root),
                        "--client-dir",
                        str(self.root),
                        "--client-tarball",
                        str(self.root / "client.tgz"),
                    ]
                )

    def test_binary_pair_must_be_executable_and_report_one_version(self) -> None:
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        self.write_command(bin_dir / "discovery", "discovery 0.44.0")
        self.write_command(bin_dir / "discoveryctl", "discoveryctl 0.44.1")

        with self.assertRaisesRegex(ValueError, "same product version"):
            self.smoke.validate_binary_pair(bin_dir)

        self.write_command(bin_dir / "discoveryctl", "discoveryctl 0.44.0")
        (bin_dir / "discoveryctl").chmod(stat.S_IRUSR | stat.S_IWUSR)
        with self.assertRaisesRegex(ValueError, "not executable"):
            self.smoke.validate_binary_pair(bin_dir)

    def test_client_directory_requires_unified_root_and_matching_native_package(
        self,
    ) -> None:
        client = self.root / "client"
        self.write_client_tree(client, native_version="0.44.1")
        with self.assertRaisesRegex(ValueError, "native package version"):
            self.smoke.validate_client_directory(client)

        self.write_client_tree(client, native_version="0.44.0")
        validated = self.smoke.validate_client_directory(client)
        self.assertEqual(client.resolve(), validated.root)
        self.assertEqual("0.44.0", validated.version)

        (client / "package.json").write_text(
            json.dumps(
                {"name": "@registrystack/discovery-client", "version": "0.44.0"}
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "unified @registrystack/client"):
            self.smoke.validate_client_directory(client)

    def test_tarball_source_refuses_unsafe_or_incomplete_candidate_packages(
        self,
    ) -> None:
        unsafe = self.root / "registrystack-client-0.44.0.tgz"
        self.write_tarball(
            unsafe,
            {
                "package/package.json": json.dumps(
                    {"name": "@registrystack/client", "version": "0.44.0"}
                ).encode(),
                "../outside": b"not allowed",
            },
        )
        with self.assertRaisesRegex(ValueError, "unsafe archive member"):
            self.smoke.validate_client_tarballs(unsafe)

        unsafe.unlink()
        platform = self.smoke.node_platform()
        self.write_root_tarball(unsafe, platform)
        with self.assertRaisesRegex(ValueError, "matching native candidate package"):
            self.smoke.validate_client_tarballs(unsafe)

        native = self.root / f"registrystack-client-{platform}-0.44.0.tgz"
        self.write_tarball(
            native,
            {
                "package/package.json": json.dumps(
                    {
                        "name": f"@registrystack/client-{platform}",
                        "version": "0.44.0",
                    }
                ).encode(),
                f"package/discovery-client.{platform}.node": b"native",
            },
        )
        validated = self.smoke.validate_client_tarballs(unsafe)
        self.assertEqual(unsafe.resolve(), validated.root)
        self.assertEqual(native.resolve(), validated.native)
        self.assertEqual("0.44.0", validated.version)

    def test_node_environment_does_not_forward_credentials(self) -> None:
        environment = self.smoke.node_environment(
            {
                "PATH": "/usr/bin",
                "HOME": str(self.root),
                "TMPDIR": str(self.root),
                "NODE_OPTIONS": "--no-warnings",
                "GITHUB_TOKEN": "secret",
                "AUTHORIZATION": "secret",
                "DISCOVERY_API_KEY": "secret",
            },
            self.root,
        )
        self.assertEqual("/usr/bin", environment["PATH"])
        self.assertEqual(str(self.root), environment["TMPDIR"])
        self.assertNotIn("NODE_OPTIONS", environment)
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertNotIn("AUTHORIZATION", environment)
        self.assertNotIn("DISCOVERY_API_KEY", environment)

    def test_node_journey_keeps_auth_and_acceptance_local(self) -> None:
        source = self.smoke.NODE_JOURNEY
        self.assertIn("authorization: 'Bearer must-be-refused'", source)
        self.assertIn("error.kind === 'configuration'", source)
        self.assertIn("acceptSelection(selection, () => false)", source)
        self.assertIn("error.kind === 'local-acceptance-refused'", source)
        self.assertIn("resolveEvidenceTypes", source)
        self.assertIn("searchEvidenceServices", source)

    def write_command(self, path: Path, output: str) -> None:
        path.write_text(
            f"#!/usr/bin/env bash\nprintf '%s\\n' '{output}'\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def write_client_tree(self, root: Path, *, native_version: str) -> None:
        platform = self.smoke.node_platform()
        native = root / "node_modules" / "@registrystack" / f"client-{platform}"
        native.mkdir(parents=True, exist_ok=True)
        (root / "discovery").mkdir(parents=True, exist_ok=True)
        (root / "index.js").write_text("module.exports = {};\n", encoding="utf-8")
        (root / "native.js").write_text("module.exports = {};\n", encoding="utf-8")
        (root / "discovery/client.js").write_text(
            "module.exports = {};\n", encoding="utf-8"
        )
        (root / "package.json").write_text(
            json.dumps(
                {
                    "name": "@registrystack/client",
                    "version": "0.44.0",
                    "optionalDependencies": {
                        f"@registrystack/client-{platform}": "0.44.0"
                    },
                }
            ),
            encoding="utf-8",
        )
        (native / "package.json").write_text(
            json.dumps(
                {
                    "name": f"@registrystack/client-{platform}",
                    "version": native_version,
                }
            ),
            encoding="utf-8",
        )
        (native / f"discovery-client.{platform}.node").write_bytes(b"native")

    def write_root_tarball(self, path: Path, platform: str) -> None:
        self.write_tarball(
            path,
            {
                "package/package.json": json.dumps(
                    {
                        "name": "@registrystack/client",
                        "version": "0.44.0",
                        "optionalDependencies": {
                            f"@registrystack/client-{platform}": "0.44.0"
                        },
                    }
                ).encode(),
                "package/index.js": b"module.exports = {};\n",
                "package/native.js": b"module.exports = {};\n",
                "package/discovery/client.js": b"module.exports = {};\n",
            },
        )

    @staticmethod
    def write_tarball(path: Path, members: dict[str, bytes]) -> None:
        with tarfile.open(path, "w:gz") as archive:
            for name, body in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))


if __name__ == "__main__":
    unittest.main()
