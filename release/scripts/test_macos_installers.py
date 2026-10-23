"""Exercise transactional installers with self-contained macOS binary bundles."""

from __future__ import annotations

import hashlib
import io
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import release_roster  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
INSTALLERS = (
    ("registry-breg", "BREG", ("breg", "bregctl")),
    ("registry-casework", "CASEWORK", ("casework", "caseworkctl")),
    ("registry-evidencectl", "EVIDENCECTL", ("evidence", "evidencectl", "evidence-oid4vci")),
    # The Scheduling runtime is Linux amd64 only; macOS publishes schedulingctl.
    ("registry-scheduling", "SCHEDULING", ("schedulingctl",)),
) + tuple(spec for name, spec in release_roster.ADDITIONAL_INSTALLERS.items() if name != "registry-manifest")
LIBRARY = "libaws_lc_fips_0_14_2_crypto.dylib"
DISCOVERY_NIGHTLY_1 = "v0.44.0-nightly.20261023." + "a" * 40
DISCOVERY_NIGHTLY_2 = "v0.45.0-nightly.20261024." + "b" * 40


def version_output(binary: str, version: str) -> str:
    output = f"{binary} {version[1:]}"
    if binary == "registry-render":
        pin = re.search(r'pub const TYPST_PIN: &str = "([^"]+)"', (ROOT / "crates/registry-render/src/lib.rs").read_text()).group(1)
        output += f" (typst {pin})"
    return output


class MacOSInstallerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="registry-macos-installer-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.commands = self.root / "commands"
        self.commands.mkdir()
        uname = self.commands / "uname"
        uname.write_text(
            "#!/bin/sh\ncase \"$1\" in -s) echo Darwin;; -m) echo arm64;; *) exit 1;; esac\n"
        )
        uname.chmod(0o755)
        if platform.system() != "Darwin":
            # Exercise the macOS installer branch with GNU mv on Linux CI.
            move = self.commands / "mv"
            move.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = -fh ]; then shift; set -- -Tf \"$@\"; fi\n"
                f"exec {shutil.which('mv')} \"$@\"\n"
            )
            move.chmod(0o755)

    def assets(
        self,
        name: str,
        binaries: tuple[str, ...],
        version: str,
        defect: str = "",
        plain_binaries: tuple[str, ...] = (),
    ) -> Path:
        directory = self.root / name
        directory.mkdir()
        checksums: list[str] = []
        for index, binary in enumerate(binaries):
            stem = f"{binary}-{version}-macos-arm64"
            # Each executable deliberately has different library bytes under
            # the same basename. The installer must preserve both closures.
            library = f"{binary}-{version}-module".encode()
            library_assertion = (
                ""
                if binary in plain_binaries
                else f"assert (Path(sys.argv[0]).resolve().parent / {LIBRARY!r}).read_bytes() == {library!r}\n"
            )
            executable = (
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                "import os, sys\n"
                "assert not any(k.startswith('DYLD_') for k in os.environ)\n"
                f"{library_assertion}"
                f"print({version_output(binary, version)!r})\n"
            ).encode()
            members = [(stem, executable, 0o755)]
            if binary not in plain_binaries:
                members.append((LIBRARY, library, 0o755))
            members.append(("THIRD_PARTY_NOTICES", b"notices\n", 0o644))
            if defect and index == 0:
                if defect == "missing-library":
                    members.pop(1)
                elif defect == "duplicate":
                    members.append(members[1])
                elif defect == "traversal":
                    members.append(("../escaped", b"unexpected", 0o755))
                elif defect == "unexpected-library":
                    members.insert(1, (LIBRARY, library, 0o755))
                elif defect == "mode":
                    members[0] = (stem, executable, 0o644)
                elif defect == "wrong-version":
                    members[0] = (stem, b"#!/bin/sh\necho wrong-version\n", 0o755)
            archive_path = directory / f"{stem}.tar.gz"
            with tarfile.open(archive_path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
                for member_name, payload, mode in members:
                    member = tarfile.TarInfo(member_name)
                    member.mode = mode
                    member.size = len(payload)
                    if (
                        defect == "symlink"
                        and index == 0
                        and (
                            member_name == LIBRARY
                            or (binary in plain_binaries and member_name == stem)
                        )
                    ):
                        member.type = tarfile.SYMTYPE
                        member.linkname = "../external-library"
                        member.size = 0
                        archive.addfile(member)
                    else:
                        archive.addfile(member, io.BytesIO(payload))
            checksums.append(f"{hashlib.sha256(archive_path.read_bytes()).hexdigest()}  {archive_path.name}\n")
        (directory / "SHA256SUMS").write_text("".join(checksums))
        return directory

    def install(
        self, product: str, prefix: str, version: str, assets: Path, destination: Path
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            "PATH": f"{self.commands}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
            "LANG": "C",
            f"{prefix}_VERSION": version,
            f"{prefix}_ASSET_DIR": str(assets),
            f"{prefix}_INSTALL_DIR": str(destination),
            "DYLD_LIBRARY_PATH": "/must-not-be-used",
            "DYLD_FALLBACK_LIBRARY_PATH": "/must-not-be-used",
            "DYLD_INSERT_LIBRARIES": "/must-not-be-used",
        }
        # macOS interprets DYLD_INSERT_LIBRARIES before the script can clear it;
        # use the non-injecting search variables for a real macOS test process.
        if platform.system() == "Darwin":
            environment.pop("DYLD_INSERT_LIBRARIES")
        return subprocess.run(
            ["bash", str(ROOT / "crates" / product / "install.sh")],
            env=environment, capture_output=True, text=True, check=False,
        )

    def assert_commands(self, directory: Path, binaries: tuple[str, ...], version: str) -> None:
        for binary in binaries:
            result = subprocess.run(
                [str(directory / binary), "--version"],
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(version_output(binary, version) + "\n", result.stdout)

    def test_current_scheduling_installs_runtime_and_ctl_together(self):
        binaries = ("scheduling", "schedulingctl")
        assets = self.assets("current-scheduling", binaries, "v0.44.0")
        destination = self.root / "scheduling-current"
        result = self.install("registry-scheduling", "SCHEDULING", "v0.44.0", assets, destination)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assert_commands(destination, binaries, "v0.44.0")

    def test_manifest_installs_a_plain_macos_binary_without_crypto_libraries(self):
        assets = self.root / "manifest-assets"
        assets.mkdir()
        name = "registry-manifest-v0.44.0-macos-arm64"
        payload = b"#!/bin/sh\nprintf 'registry-manifest 0.44.0\\n'\n"
        (assets / name).write_bytes(payload)
        (assets / "SHA256SUMS").write_text(f"{hashlib.sha256(payload).hexdigest()}  {name}\n")
        destination = self.root / "manifest-installed"
        result = self.install("registry-manifest-cli", "REGISTRY_MANIFEST", "v0.44.0", assets, destination)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assert_commands(destination, ("registry-manifest",), "v0.44.0")

    def test_discovery_installs_plain_runtime_and_fips_operator_tool(self):
        binaries = ("discovery", "discoveryctl")
        assets = self.assets(
            "discovery-mixed",
            binaries,
            DISCOVERY_NIGHTLY_1,
            plain_binaries=("discovery",),
        )
        destination = self.root / "discovery-mixed-installed"
        result = self.install(
            "registry-discovery", "DISCOVERY", DISCOVERY_NIGHTLY_1, assets, destination
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assert_commands(destination, binaries, DISCOVERY_NIGHTLY_1)
        self.assertFalse(
            ((destination / "discovery").resolve().parent / LIBRARY).exists()
        )
        self.assertEqual(
            f"discoveryctl-{DISCOVERY_NIGHTLY_1}-module".encode(),
            ((destination / "discoveryctl").resolve().parent / LIBRARY).read_bytes(),
        )

    def test_invalid_plain_discovery_archive_never_replaces_installed_toolset(self):
        binaries = ("discovery", "discoveryctl")
        initial = self.assets(
            "discovery-plain-initial",
            binaries,
            DISCOVERY_NIGHTLY_1,
            plain_binaries=("discovery",),
        )
        destination = self.root / "discovery-plain-installed"
        result = self.install(
            "registry-discovery", "DISCOVERY", DISCOVERY_NIGHTLY_1, initial, destination
        )
        self.assertEqual(0, result.returncode, result.stderr)
        targets = [(destination / binary).resolve() for binary in binaries]
        for defect in (
            "missing-library",
            "duplicate",
            "traversal",
            "unexpected-library",
            "symlink",
            "mode",
        ):
            with self.subTest(defect=defect):
                assets = self.assets(
                    f"discovery-plain-{defect}",
                    binaries,
                    DISCOVERY_NIGHTLY_2,
                    defect,
                    plain_binaries=("discovery",),
                )
                result = self.install(
                    "registry-discovery",
                    "DISCOVERY",
                    DISCOVERY_NIGHTLY_2,
                    assets,
                    destination,
                )
                self.assertNotEqual(0, result.returncode)
                self.assertEqual(
                    targets,
                    [(destination / binary).resolve() for binary in binaries],
                )
                self.assert_commands(destination, binaries, DISCOVERY_NIGHTLY_1)
                self.assertFalse((self.root / "escaped").exists())

    def test_all_installers_keep_each_binary_with_its_own_libraries(self) -> None:
        for product, prefix, binaries in INSTALLERS:
            with self.subTest(product=product):
                version = (
                    DISCOVERY_NIGHTLY_1
                    if product == "registry-discovery"
                    else "v0.33.0"
                )
                plain_binaries = (
                    ("discovery",) if product == "registry-discovery" else ()
                )
                assets = self.assets(
                    product,
                    binaries,
                    version,
                    plain_binaries=plain_binaries,
                )
                destination = self.root / f"{product}-installed"
                result = self.install(product, prefix, version, assets, destination)
                self.assertEqual(0, result.returncode, result.stderr)
                guide = (
                    "release/NIGHTLY.md"
                    if product == "registry-discovery"
                    else "release/VERIFY.md"
                )
                self.assertIn(f"/blob/{version}/{guide}", result.stdout)
                self.assert_commands(destination, binaries, version)
                for binary in binaries:
                    if binary in plain_binaries:
                        self.assertFalse(
                            ((destination / binary).resolve().parent / LIBRARY).exists()
                        )
                        continue
                    self.assertEqual(
                        f"{binary}-{version}-module".encode(),
                        ((destination / binary).resolve().parent / LIBRARY).read_bytes(),
                    )

    def test_invalid_or_unusable_bundle_never_replaces_installed_toolset(self) -> None:
        for product, prefix, binaries in INSTALLERS:
            with self.subTest(product=product):
                initial_version = (
                    DISCOVERY_NIGHTLY_1
                    if product == "registry-discovery"
                    else "v0.33.0"
                )
                update_version = (
                    DISCOVERY_NIGHTLY_2
                    if product == "registry-discovery"
                    else "v0.34.0"
                )
                plain_binaries = (
                    ("discovery",) if product == "registry-discovery" else ()
                )
                initial = self.assets(
                    f"{product}-initial",
                    binaries,
                    initial_version,
                    plain_binaries=plain_binaries,
                )
                destination = self.root / f"{product}-installed"
                result = self.install(
                    product, prefix, initial_version, initial, destination
                )
                self.assertEqual(0, result.returncode, result.stderr)
                targets = [(destination / binary).resolve() for binary in binaries]
                for defect in ("missing-library", "duplicate", "traversal", "symlink", "mode", "wrong-version"):
                    with self.subTest(defect=defect):
                        assets = self.assets(
                            f"{product}-{defect}",
                            binaries,
                            update_version,
                            defect,
                            plain_binaries=plain_binaries,
                        )
                        result = self.install(
                            product, prefix, update_version, assets, destination
                        )
                        self.assertNotEqual(0, result.returncode)
                        self.assertEqual(targets, [(destination / binary).resolve() for binary in binaries])
                        self.assert_commands(destination, binaries, initial_version)
                        self.assertFalse((self.root / "escaped").exists())


if __name__ == "__main__":
    unittest.main()
