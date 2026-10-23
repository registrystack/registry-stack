#!/usr/bin/env python3
"""Local end-to-end tests for the independently versioned Discovery installer."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "crates/registry-discovery/install.sh"


class DiscoveryInstallerTests(unittest.TestCase):
    def test_source_installer_requires_an_explicit_product_version(self) -> None:
        with InstallerFixture() as fixture:
            result = fixture.run(select_version=False)

            self.assertNotEqual(0, result.returncode)
            self.assertIn("Pass --version", result.stderr)
            self.assertEqual([], fixture.requests())
            self.assertFalse(fixture.install_dir.exists())

            help_result = fixture.run("--help", select_version=False)
            self.assertEqual(0, help_result.returncode, help_result.stderr)
            self.assertIn(
                "Independent numbered Discovery releases support Linux amd64.",
                help_result.stdout,
            )

    def test_source_installer_accepts_an_explicit_environment_version(self) -> None:
        with InstallerFixture() as fixture:
            result = fixture.run(select_version=False, version_env="v1.2.3")

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("discovery 1.2.3\n", fixture.version("discovery"))
            self.assertEqual("discoveryctl 1.2.3\n", fixture.version("discoveryctl"))

    def test_local_assets_install_one_atomic_runtime_and_tool_pair(self) -> None:
        with InstallerFixture() as fixture:
            result = fixture.run()

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("discovery 1.2.3\n", fixture.version("discovery"))
            self.assertEqual("discoveryctl 1.2.3\n", fixture.version("discoveryctl"))
            current = fixture.install_dir / ".discovery-current"
            self.assertTrue(current.is_symlink())
            for binary in ("discovery", "discoveryctl"):
                installed = fixture.install_dir / binary
                self.assertTrue(installed.is_symlink())
                self.assertEqual(f".discovery-current/{binary}", os.readlink(installed))
                self.assertTrue(installed.stat().st_mode & stat.S_IXUSR)

    def test_pinned_candidate_uses_its_embedded_version_and_refuses_drift(self) -> None:
        with InstallerFixture() as fixture:
            pinned = fixture.root / "discovery-v1.2.3-install.sh"
            pinned.write_text(
                INSTALLER.read_text(encoding="utf-8").replace(
                    'default_version=""',
                    'default_version="v1.2.3"',
                    1,
                ),
                encoding="utf-8",
            )
            result = fixture.run_path(pinned)
            self.assertEqual(0, result.returncode, result.stderr)

            refused = fixture.run_path(
                pinned,
                "--version",
                "v1.2.4",
            )
            self.assertNotEqual(0, refused.returncode)
            self.assertIn("does not match the released installer", refused.stderr)

    def test_tampered_checksum_leaves_existing_commands_unchanged(self) -> None:
        with InstallerFixture() as fixture:
            fixture.write_existing_commands()
            fixture.asset("discoveryctl").write_bytes(b"tampered\n")

            result = fixture.run()

            self.assertNotEqual(0, result.returncode)
            self.assertIn("Checksum verification failed", result.stderr)
            fixture.assert_existing_commands()

    def test_missing_second_asset_leaves_existing_commands_unchanged(self) -> None:
        with InstallerFixture() as fixture:
            fixture.write_existing_commands()
            fixture.asset("discoveryctl").unlink()

            result = fixture.run()

            self.assertNotEqual(0, result.returncode)
            self.assertIn("discoveryctl", result.stderr)
            fixture.assert_existing_commands()

    def test_failed_command_adoption_rolls_back_the_complete_pair(self) -> None:
        with InstallerFixture() as fixture:
            fixture.write_existing_commands()

            result = fixture.run(
                fail_move_destination=fixture.install_dir / "discoveryctl",
            )

            self.assertNotEqual(0, result.returncode)
            fixture.assert_existing_commands()
            current = fixture.install_dir / ".discovery-current"
            self.assertFalse(current.exists() or current.is_symlink())

    def test_embedded_binary_version_mismatch_leaves_existing_commands_unchanged(
        self,
    ) -> None:
        with InstallerFixture() as fixture:
            fixture.write_existing_commands()
            fixture.write_assets(version="1.2.2")

            result = fixture.run()

            self.assertNotEqual(0, result.returncode)
            self.assertIn("unexpected embedded version", result.stderr)
            fixture.assert_existing_commands()

    def test_upgrade_switches_both_commands_through_one_pointer(self) -> None:
        with InstallerFixture() as fixture:
            fixture.write_assets(version="1.2.2", marker="v1.2.2")
            first = fixture.run("--version", "v1.2.2", select_version=False)
            self.assertEqual(0, first.returncode, first.stderr)
            previous = os.readlink(fixture.install_dir / ".discovery-current")

            fixture.write_assets(version="1.2.3", marker="v1.2.3")
            second = fixture.run()

            self.assertEqual(0, second.returncode, second.stderr)
            current = os.readlink(fixture.install_dir / ".discovery-current")
            self.assertNotEqual(previous, current)
            self.assertEqual("discovery 1.2.3\n", fixture.version("discovery"))
            self.assertEqual("discoveryctl 1.2.3\n", fixture.version("discoveryctl"))

    def test_downloads_use_the_product_tag_path_and_asset_version_marker(self) -> None:
        with InstallerFixture() as fixture:
            result = fixture.run(use_local_assets=False)

            self.assertEqual(0, result.returncode, result.stderr)
            base = (
                "https://github.com/registrystack/registry-stack/releases/download/"
                "discovery%2Fv1.2.3"
            )
            self.assertEqual(
                [
                    f"{base}/discovery-v1.2.3-linux-amd64",
                    f"{base}/discoveryctl-v1.2.3-linux-amd64",
                    f"{base}/SHA256SUMS",
                ],
                fixture.requests(),
            )
            self.assertIn(
                "https://github.com/registrystack/registry-stack/blob/"
                "discovery%2Fv1.2.3/release/VERIFY.md",
                result.stdout,
            )
            self.assertNotIn(
                "/releases/download/discovery/v1.2.3",
                "\n".join(fixture.requests()),
            )

    def test_stack_packaged_installer_uses_stack_tag_on_every_native_platform(
        self,
    ) -> None:
        for os_name, architecture, platform in (
            ("Linux", "x86_64", "linux-amd64"),
            ("Linux", "aarch64", "linux-arm64"),
            ("Darwin", "arm64", "macos-arm64"),
        ):
            with self.subTest(platform=platform), InstallerFixture(
                os_name=os_name, architecture=architecture
            ) as fixture:
                fixture.write_assets(version="0.44.0", marker="v0.44.0")
                package = fixture.root / "package"
                packaged = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "release/scripts/additional_installers.py"),
                        "--package",
                        str(package),
                        "--version",
                        "0.44.0",
                        "--tag",
                        "v0.44.0",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(0, packaged.returncode, packaged.stderr)

                result = fixture.run_path(
                    package / "discovery-v0.44.0-install.sh",
                    use_local_assets=False,
                )

                self.assertEqual(0, result.returncode, result.stderr)
                base = (
                    "https://github.com/registrystack/registry-stack/releases/"
                    "download/v0.44.0"
                )
                suffix = ".tar.gz" if platform == "macos-arm64" else ""
                self.assertEqual(
                    [
                        f"{base}/discovery-v0.44.0-{platform}{suffix}",
                        f"{base}/discoveryctl-v0.44.0-{platform}{suffix}",
                        f"{base}/SHA256SUMS",
                    ],
                    fixture.requests(),
                )
                help_result = fixture.run_path(
                    package / "discovery-v0.44.0-install.sh", "--help"
                )
                self.assertEqual(0, help_result.returncode, help_result.stderr)
                self.assertIn(
                    "This Stack installer supports Linux amd64, Linux arm64, "
                    "and macOS arm64.",
                    help_result.stdout,
                )

    def test_historical_stack_namespace_keeps_its_linux_amd64_inventory(self) -> None:
        source = (
            INSTALLER.read_text(encoding="utf-8")
            .replace('default_version=""', 'default_version="v0.43.0"', 1)
            .replace('release_namespace="discovery"', 'release_namespace="stack"', 1)
        )
        with InstallerFixture() as fixture:
            fixture.write_assets(version="0.43.0", marker="v0.43.0")
            pinned = fixture.root / "discovery-v0.43.0-install.sh"
            pinned.write_text(source, encoding="utf-8")

            result = fixture.run_path(pinned, use_local_assets=False)

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(
                all("/releases/download/v0.43.0/" in url for url in fixture.requests())
            )

        with InstallerFixture(os_name="Linux", architecture="aarch64") as fixture:
            pinned = fixture.root / "discovery-v0.43.0-install.sh"
            pinned.write_text(source, encoding="utf-8")

            result = fixture.run_path(pinned, use_local_assets=False)

            self.assertNotEqual(0, result.returncode)
            self.assertIn("Linux amd64 only", result.stderr)
            self.assertEqual([], fixture.requests())

    def test_nightly_uses_the_global_tag_and_product_binary_version(self) -> None:
        source_sha = "a" * 40
        marker = f"v9.8.7-nightly.20261023.{source_sha}"
        product_version = f"1.2.3-nightly.20261023.{source_sha}"
        for os_name, architecture, platform in (
            ("Linux", "x86_64", "linux-amd64"),
            ("Linux", "aarch64", "linux-arm64"),
            ("Darwin", "arm64", "macos-arm64"),
        ):
            with self.subTest(platform=platform), InstallerFixture(
                os_name=os_name, architecture=architecture
            ) as fixture:
                fixture.write_assets(version=product_version, marker=marker)
                pinned = fixture.root / f"discovery-{marker}-install.sh"
                pinned.write_text(
                    INSTALLER.read_text(encoding="utf-8").replace(
                        'default_version=""',
                        f'default_version="{marker}"',
                        1,
                    ),
                    encoding="utf-8",
                )

                result = fixture.run_path(
                    pinned,
                    use_local_assets=False,
                )

                self.assertEqual(0, result.returncode, result.stderr)
                base = (
                    "https://github.com/registrystack/registry-stack/releases/download/"
                    f"{marker}"
                )
                suffix = ".tar.gz" if platform == "macos-arm64" else ""
                self.assertEqual(
                    [
                        f"{base}/discovery-{marker}-{platform}{suffix}",
                        f"{base}/discoveryctl-{marker}-{platform}{suffix}",
                        f"{base}/SHA256SUMS",
                    ],
                    fixture.requests(),
                )
                self.assertEqual(
                    f"discovery {product_version}\n",
                    fixture.version("discovery"),
                )
                self.assertEqual(
                    f"discoveryctl {product_version}\n",
                    fixture.version("discoveryctl"),
                )

    def test_noncanonical_or_unsupported_selection_refuses_before_download(self) -> None:
        for version in ("1.2.3", "v01.2.3", "v1.2.3/other", "v1.2"):
            with self.subTest(version=version), InstallerFixture() as fixture:
                result = fixture.run(
                    "--version",
                    version,
                    select_version=False,
                    use_local_assets=False,
                )
                self.assertNotEqual(0, result.returncode)
                self.assertIn("canonical Registry Discovery version", result.stderr)
                self.assertEqual([], fixture.requests())

        with InstallerFixture(os_name="Darwin", architecture="arm64") as fixture:
            result = fixture.run(use_local_assets=False)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Linux amd64", result.stderr)
            self.assertEqual([], fixture.requests())

    def test_old_glibc_refuses_before_download_and_preserves_existing_pair(self) -> None:
        with InstallerFixture() as fixture:
            fixture.write_existing_commands()
            fixture.write_libc(
                getconf="printf 'glibc 2.28\\n'",
                ldd="printf 'ldd (GNU libc) 2.28\\n'",
            )

            result = fixture.run(use_local_assets=False)

            self.assertNotEqual(0, result.returncode)
            self.assertIn("This system has GNU libc 2.28", result.stderr)
            self.assertIn("Nothing was installed", result.stderr)
            self.assertEqual([], fixture.requests())
            fixture.assert_existing_commands()


class InstallerFixture:
    def __init__(
        self,
        *,
        os_name: str = "Linux",
        architecture: str = "x86_64",
    ) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.assets = self.root / "assets"
        self.install_dir = self.root / "install/bin"
        self.fake_bin = self.root / "fake-bin"
        self.log = self.root / "requests"
        self.assets.mkdir()
        self.fake_bin.mkdir()
        self.os_label = "macos" if os_name == "Darwin" else "linux"
        self.arch_label = "arm64" if architecture in {"arm64", "aarch64"} else "amd64"
        self._write_uname(os_name, architecture)
        self._write_curl()
        self._write_mv()
        self.write_assets(version="1.2.3", marker="v1.2.3")

    def __enter__(self) -> "InstallerFixture":
        return self

    def __exit__(self, *_: object) -> None:
        self.temporary.cleanup()

    def asset(self, binary: str, marker: str = "v1.2.3") -> Path:
        suffix = ".tar.gz" if self.os_label == "macos" else ""
        return self.assets / (
            f"{binary}-{marker}-{self.os_label}-{self.arch_label}{suffix}"
        )

    def write_assets(self, *, version: str, marker: str = "v1.2.3") -> None:
        entries = []
        for binary in ("discovery", "discoveryctl"):
            body = (
                "#!/bin/sh\n"
                'if [ "${1:-}" = "--version" ]; then\n'
                f"  printf '{binary} {version}\\n'\n"
                "  exit 0\n"
                "fi\n"
                "exit 2\n"
            ).encode()
            path = self.asset(binary, marker)
            if self.os_label == "macos":
                with tarfile.open(path, "w:gz") as archive:
                    executable = tarfile.TarInfo(path.name.removesuffix(".tar.gz"))
                    executable.size = len(body)
                    executable.mode = 0o755
                    archive.addfile(executable, fileobj=io.BytesIO(body))
                    notice_body = b"test notice\n"
                    notice = tarfile.TarInfo("THIRD_PARTY_NOTICES")
                    notice.size = len(notice_body)
                    archive.addfile(
                        notice, fileobj=io.BytesIO(notice_body)
                    )
                    if binary == "discoveryctl":
                        library_body = b"test library\n"
                        library = tarfile.TarInfo("libaws_lc_fips_crypto.dylib")
                        library.size = len(library_body)
                        library.mode = 0o755
                        archive.addfile(library, fileobj=io.BytesIO(library_body))
            else:
                path.write_bytes(body)
                path.chmod(0o755)
            entries.append(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            )
        (self.assets / "SHA256SUMS").write_text("".join(entries), encoding="utf-8")

    def write_existing_commands(self) -> None:
        self.install_dir.mkdir(parents=True)
        for binary in ("discovery", "discoveryctl"):
            path = self.install_dir / binary
            path.write_text(f"existing {binary}\n", encoding="utf-8")
            path.chmod(0o755)

    def assert_existing_commands(self) -> None:
        for binary in ("discovery", "discoveryctl"):
            path = self.install_dir / binary
            self.assert_path_is_regular(path)
            if path.read_text(encoding="utf-8") != f"existing {binary}\n":
                raise AssertionError(f"installer changed existing {binary}")

    @staticmethod
    def assert_path_is_regular(path: Path) -> None:
        if path.is_symlink() or not path.is_file():
            raise AssertionError(f"expected unchanged regular file at {path}")

    def version(self, binary: str) -> str:
        return subprocess.run(
            [str(self.install_dir / binary), "--version"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def run(
        self,
        *arguments: str,
        select_version: bool = True,
        use_local_assets: bool = True,
        version_env: str | None = None,
        fail_move_destination: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if select_version and not arguments:
            arguments = ("--version", "v1.2.3")
        return self.run_path(
            INSTALLER,
            *arguments,
            use_local_assets=use_local_assets,
            version_env=version_env,
            fail_move_destination=fail_move_destination,
        )

    def run_path(
        self,
        path: Path,
        *arguments: str,
        use_local_assets: bool = True,
        version_env: str | None = None,
        fail_move_destination: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("DISCOVERY_VERSION", None)
        environment.update(
            {
                "PATH": f"{self.fake_bin}:/usr/bin:/bin",
                "DISCOVERY_INSTALL_DIR": str(self.install_dir),
                "FAKE_CURL_ASSET_DIR": str(self.assets),
                "FAKE_CURL_LOG": str(self.log),
            }
        )
        if version_env is not None:
            environment["DISCOVERY_VERSION"] = version_env
        if fail_move_destination is not None:
            environment["FAIL_MOVE_DESTINATION"] = str(fail_move_destination)
            environment["FAIL_MOVE_MARKER"] = str(self.root / "move-failed")
        if use_local_assets:
            environment["DISCOVERY_ASSET_DIR"] = str(self.assets)
        else:
            environment.pop("DISCOVERY_ASSET_DIR", None)
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
        return self.log.read_text(encoding="utf-8").splitlines()

    def _write_uname(self, os_name: str, architecture: str) -> None:
        path = self.fake_bin / "uname"
        path.write_text(
            "#!/bin/sh\n"
            'case "${1:-}" in\n'
            f"  -s) printf '{os_name}\\n' ;;\n"
            f"  -m) printf '{architecture}\\n' ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def _write_curl(self) -> None:
        path = self.fake_bin / "curl"
        path.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'url=""\n'
            'destination=""\n'
            'while [[ "$#" -gt 0 ]]; do\n'
            '  case "$1" in\n'
            '    -o) destination="$2"; shift 2 ;;\n'
            '    http://*|https://*) url="$1"; shift ;;\n'
            '    *) shift ;;\n'
            "  esac\n"
            "done\n"
            'printf "%s\\n" "$url" >> "$FAKE_CURL_LOG"\n'
            'source="$FAKE_CURL_ASSET_DIR/${url##*/}"\n'
            '[[ -f "$source" ]] || exit 22\n'
            'cp "$source" "$destination"\n',
            encoding="utf-8",
        )
        path.chmod(0o755)

    def write_libc(self, *, getconf: str, ldd: str) -> None:
        for name, body in (("getconf", getconf), ("ldd", ldd)):
            path = self.fake_bin / name
            path.write_text(
                f"#!/bin/sh\nset -eu\n{body}\n",
                encoding="utf-8",
            )
            path.chmod(0o755)

    def _write_mv(self) -> None:
        path = self.fake_bin / "mv"
        path.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'if [[ "${1:-}" = "--version" ]]; then\n'
            '  exec /bin/mv --version\n'
            "fi\n"
            'destination="${@: -1}"\n'
            'if [[ -n "${FAIL_MOVE_DESTINATION:-}" && '
            '"$destination" = "$FAIL_MOVE_DESTINATION" && '
            '! -e "$FAIL_MOVE_MARKER" ]]; then\n'
            '  : > "$FAIL_MOVE_MARKER"\n'
            "  exit 73\n"
            "fi\n"
            'exec /bin/mv "$@"\n',
            encoding="utf-8",
        )
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
