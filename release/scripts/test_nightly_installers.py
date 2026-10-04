#!/usr/bin/env python3
"""Synthetic network tests for the installers' stable and nightly bootstrap."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLERS = {
    "breg": ROOT / "crates/registry-breg/install.sh",
    "evidencectl": ROOT / "crates/registry-evidencectl/install.sh",
    "casework": ROOT / "crates/registry-casework/install.sh",
    "scheduling": ROOT / "crates/registry-scheduling/install.sh",
}
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
TAG = f"v0.99.0-nightly.20261002.{SOURCE_SHA}"


class InstallerBootstrapTests(unittest.TestCase):
    def test_generated_channel_resolvers_are_current(self) -> None:
        result = subprocess.run(
            ["python3", str(ROOT / "release/scripts/render-installer-channel.py"), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)

    def test_latest_numbered_release_executes_the_stable_pinned_installer(self) -> None:
        for product, installer in INSTALLERS.items():
            with self.subTest(product=product), BootstrapFixture(product, installer) as fixture:
                result = fixture.run()
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual("v0.98.0\n", fixture.marker.read_text())
                self.assertIn("Resolved latest numbered release to v0.98.0", result.stdout)
                self.assertEqual(
                    [
                        f"https://github.com/registrystack/registry-stack/releases/latest/download/{product}-install.sh"
                    ],
                    fixture.requests(),
                )

    def test_nightly_channel_verifies_and_executes_one_immutable_installer(self) -> None:
        for product, installer in INSTALLERS.items():
            with self.subTest(product=product), BootstrapFixture(product, installer) as fixture:
                result = fixture.run("--channel", "nightly")
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(f"{TAG}\n", fixture.marker.read_text())
                self.assertIn(f"Resolved nightly build {TAG} from source {SOURCE_SHA}", result.stdout)
                requests = fixture.requests()
                self.assertEqual(1, sum(url.endswith("nightly-channel/nightly.json") for url in requests))
                self.assertEqual(2, len(requests), requests)

    def test_build_uses_the_immutable_manifest_and_installer(self) -> None:
        for product, installer in INSTALLERS.items():
            with self.subTest(product=product), BootstrapFixture(product, installer) as fixture:
                result = fixture.run("--build", TAG)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(f"{TAG}\n", fixture.marker.read_text())
                requests = fixture.requests()
                self.assertEqual(
                    f"https://github.com/registrystack/registry-stack/releases/download/{TAG}/nightly.json",
                    requests[0],
                )
                self.assertEqual(2, len(requests), requests)

    def test_minified_manifest_and_reordered_asset_fields_are_supported(self) -> None:
        with BootstrapFixture("breg", INSTALLERS["breg"]) as fixture:
            manifest = json.loads(fixture.manifest.read_text())
            asset = manifest["assets"][0]
            manifest["assets"] = [
                {"sha256": asset["sha256"], "name": asset["name"]}
            ]
            fixture.manifest.write_text(json.dumps(manifest, separators=(",", ":")))
            result = fixture.run("--channel", "nightly")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(f"{TAG}\n", fixture.marker.read_text())

    def test_current_schema_manifest_with_a_source_roster_is_supported(self) -> None:
        roster = {
            "profile": "registry-stack.nightly-roster.v2.0",
            "images": ["breg", "evidence"],
            "installers": sorted(INSTALLERS),
            "payloads": ["THIRD_PARTY_NOTICES", f"breg-{TAG}-linux-amd64"],
        }
        for product, installer in INSTALLERS.items():
            with self.subTest(product=product), BootstrapFixture(product, installer) as fixture:
                manifest = json.loads(fixture.manifest.read_text())
                manifest["schema_version"] = "registry-stack.nightly.v2"
                manifest["roster"] = roster
                fixture.manifest.write_text(json.dumps(manifest, indent=2) + "\n")
                result = fixture.run("--channel", "nightly")
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(f"{TAG}\n", fixture.marker.read_text())

    def test_unsupported_schema_refuses_before_downloading_an_installer(self) -> None:
        with BootstrapFixture("breg", INSTALLERS["breg"]) as fixture:
            manifest = json.loads(fixture.manifest.read_text())
            manifest["schema_version"] = "registry-stack.nightly.v3"
            fixture.manifest.write_text(json.dumps(manifest, indent=2) + "\n")
            result = fixture.run("--channel", "nightly")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("unsupported schema_version", result.stderr)
            self.assertFalse(fixture.marker.exists())
            self.assertEqual(1, len(fixture.requests()), fixture.requests())

    def test_missing_manifest_refuses_before_executing_an_installer(self) -> None:
        with BootstrapFixture("breg", INSTALLERS["breg"]) as fixture:
            fixture.manifest.unlink()
            result = fixture.run("--channel", "nightly")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Could not download nightly metadata", result.stderr)
            self.assertFalse(fixture.marker.exists())

    def test_build_refuses_manifest_for_a_different_tag_before_download(self) -> None:
        with BootstrapFixture("breg", INSTALLERS["breg"]) as fixture:
            other_sha = "fedcba9876543210fedcba9876543210fedcba98"
            requested = f"v0.99.0-nightly.20261002.{other_sha}"
            result = fixture.run("--build", requested)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("while installing", result.stderr)
            self.assertFalse(fixture.marker.exists())
            self.assertEqual(1, len(fixture.requests()), fixture.requests())

    def test_checksum_mismatch_refuses_before_executing_an_installer(self) -> None:
        with BootstrapFixture("breg", INSTALLERS["breg"]) as fixture:
            manifest = json.loads(fixture.manifest.read_text())
            manifest["assets"][0]["sha256"] = "0" * 64
            fixture.manifest.write_text(json.dumps(manifest, indent=2) + "\n")
            result = fixture.run("--channel", "nightly")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Checksum verification failed", result.stderr)
            self.assertFalse(fixture.marker.exists())

    def test_published_installer_refuses_a_conflicting_selector(self) -> None:
        with BootstrapFixture("breg", INSTALLERS["breg"]) as fixture:
            published = fixture.root / "breg-v0.98.0-install.sh"
            source = INSTALLERS["breg"].read_text().replace(
                'default_version=""', 'default_version="v0.98.0"', 1
            )
            published.write_text(source)
            result = fixture.run_path(published, "--channel", "nightly")
            self.assertEqual(2, result.returncode)
            self.assertIn("already pinned to v0.98.0", result.stderr)
            self.assertFalse(fixture.marker.exists())
            self.assertEqual([], fixture.requests())


class BootstrapFixture:
    def __init__(self, product: str, installer: Path) -> None:
        self.product = product
        self.installer = installer
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self.marker = self.root / "executed"
        self.log = self.root / "requests"
        self.stable_installer = self.root / "stable-installer"
        self.nightly_installer = self.root / "nightly-installer"
        self.manifest = self.root / "nightly.json"
        self._write_pinned(self.stable_installer, "v0.98.0")
        self._write_pinned(self.nightly_installer, TAG)
        digest = hashlib.sha256(self.nightly_installer.read_bytes()).hexdigest()
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": "registry-stack.nightly.v1",
                    "tag": TAG,
                    "version": TAG.removeprefix("v"),
                    "base_version": "0.99.0",
                    "source_sha": SOURCE_SHA,
                    "created_at": "2026-10-02T01:02:03Z",
                    "assets": [
                        {
                            "name": f"{product}-{TAG}-install.sh",
                            "sha256": digest,
                        }
                    ],
                    "images": {},
                },
                indent=2,
            )
            + "\n"
        )
        curl = self.fake_bin / "curl"
        curl.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
url=""
destination=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -o) destination="$2"; shift 2 ;;
    http://*|https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
printf '%s\n' "$url" >> "$FAKE_CURL_LOG"
case "$url" in
  */releases/latest/download/*-install.sh) source="$FAKE_STABLE_INSTALLER" ;;
  */nightly-channel/nightly.json|*/releases/download/*/nightly.json) source="$FAKE_NIGHTLY_MANIFEST" ;;
  */releases/download/*/*-install.sh) source="$FAKE_NIGHTLY_INSTALLER" ;;
  *) exit 22 ;;
esac
[[ -f "$source" ]] || exit 22
cp "$source" "$destination"
"""
        )
        curl.chmod(curl.stat().st_mode | stat.S_IXUSR)

    def __enter__(self) -> "BootstrapFixture":
        return self

    def __exit__(self, *_: object) -> None:
        self.temporary.cleanup()

    def _write_pinned(self, path: Path, version: str) -> None:
        path.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            f'default_version="{version}"\n'
            'printf "%s\\n" "$default_version" > "$TEST_INSTALLER_MARKER"\n'
        )

    def run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return self.run_path(self.installer, *arguments)

    def run_path(self, path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.fake_bin}:/usr/bin:/bin",
                "FAKE_CURL_LOG": str(self.log),
                "FAKE_STABLE_INSTALLER": str(self.stable_installer),
                "FAKE_NIGHTLY_MANIFEST": str(self.manifest),
                "FAKE_NIGHTLY_INSTALLER": str(self.nightly_installer),
                "TEST_INSTALLER_MARKER": str(self.marker),
            }
        )
        return subprocess.run(
            ["bash", str(path), *arguments],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def requests(self) -> list[str]:
        if not self.log.exists():
            return []
        return self.log.read_text().splitlines()


if __name__ == "__main__":
    unittest.main()
