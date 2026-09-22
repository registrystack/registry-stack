"""Exercise transactional installers with self-contained macOS binary bundles."""

from __future__ import annotations

import hashlib
import io
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLERS = (
    ("registry-breg", "BREG", ("breg", "bregctl")),
    ("registry-casework", "CASEWORK", ("casework", "caseworkctl")),
    ("registry-evidencectl", "EVIDENCECTL", ("evidence", "evidencectl", "evidence-oid4vci")),
)
LIBRARY = "libaws_lc_fips_0_14_2_crypto.dylib"


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
        self, name: str, binaries: tuple[str, ...], version: str, defect: str = ""
    ) -> Path:
        directory = self.root / name
        directory.mkdir()
        checksums: list[str] = []
        for index, binary in enumerate(binaries):
            stem = f"{binary}-{version}-macos-arm64"
            # Each executable deliberately has different library bytes under
            # the same basename. The installer must preserve both closures.
            library = f"{binary}-{version}-module".encode()
            executable = (
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                "import os, sys\n"
                "assert not any(k.startswith('DYLD_') for k in os.environ)\n"
                f"assert (Path(sys.argv[0]).resolve().parent / {LIBRARY!r}).read_bytes() == {library!r}\n"
                f"print({f'{binary} {version[1:]}'!r})\n"
            ).encode()
            members = [(stem, executable, 0o755), (LIBRARY, library, 0o755), ("THIRD_PARTY_NOTICES", b"notices\n", 0o644)]
            if defect and index == 0:
                if defect == "missing-library":
                    members.pop(1)
                elif defect == "duplicate":
                    members.append(members[1])
                elif defect == "traversal":
                    members.append(("../escaped", b"unexpected", 0o755))
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
                    if defect == "symlink" and index == 0 and member_name == LIBRARY:
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
            self.assertEqual(f"{binary} {version[1:]}\n", result.stdout)

    def test_all_installers_keep_each_binary_with_its_own_libraries(self) -> None:
        for product, prefix, binaries in INSTALLERS:
            with self.subTest(product=product):
                assets = self.assets(product, binaries, "v0.33.0")
                destination = self.root / f"{product}-installed"
                result = self.install(product, prefix, "v0.33.0", assets, destination)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assert_commands(destination, binaries, "v0.33.0")
                for binary in binaries:
                    self.assertEqual(
                        f"{binary}-v0.33.0-module".encode(),
                        ((destination / binary).resolve().parent / LIBRARY).read_bytes(),
                    )

    def test_invalid_or_unusable_bundle_never_replaces_installed_toolset(self) -> None:
        for product, prefix, binaries in INSTALLERS:
            with self.subTest(product=product):
                initial = self.assets(f"{product}-initial", binaries, "v0.33.0")
                destination = self.root / f"{product}-installed"
                result = self.install(product, prefix, "v0.33.0", initial, destination)
                self.assertEqual(0, result.returncode, result.stderr)
                targets = [(destination / binary).resolve() for binary in binaries]
                for defect in ("missing-library", "duplicate", "traversal", "symlink", "mode", "wrong-version"):
                    with self.subTest(defect=defect):
                        assets = self.assets(f"{product}-{defect}", binaries, "v0.34.0", defect)
                        result = self.install(product, prefix, "v0.34.0", assets, destination)
                        self.assertNotEqual(0, result.returncode)
                        self.assertEqual(targets, [(destination / binary).resolve() for binary in binaries])
                        self.assert_commands(destination, binaries, "v0.33.0")
                        self.assertFalse((self.root / "escaped").exists())


if __name__ == "__main__":
    unittest.main()
