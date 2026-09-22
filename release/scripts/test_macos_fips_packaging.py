#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import io
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release/scripts/macos_fips_packaging.py"
SPEC = importlib.util.spec_from_file_location("macos_fips_packaging", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

CRYPTO = "libaws_lc_fips_0_14_2_crypto.dylib"
WRAPPER = "libaws_lc_fips_0_14_2_rust_wrapper.dylib"


class MacosFipsPackagingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self._tool(
            "otool",
            """#!/usr/bin/env python3
import sys
from pathlib import Path
path = Path(sys.argv[-1])
print(f"{path}:")
for line in path.read_text().splitlines():
    if line.startswith(("id=", "load=")):
        print(f"\t{line.split('=', 1)[1]} (compatibility version 0.0.0, current version 0.0.0)")
""",
        )
        self._tool(
            "install_name_tool",
            """#!/usr/bin/env python3
import sys
from pathlib import Path
if sys.argv[1] != "-change":
    raise SystemExit(2)
old, new, name = sys.argv[2:]
path = Path(name)
body = path.read_text()
if old not in body:
    raise SystemExit(3)
path.write_text(body.replace(old, new))
""",
        )
        self._tool("codesign", "#!/bin/sh\nexit 0\n")
        environment = os.environ.copy()
        environment["PATH"] = f"{self.tools}{os.pathsep}{environment['PATH']}"
        self.environment = mock.patch.dict(os.environ, environment, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def _tool(self, name: str, body: str) -> None:
        path = self.tools / name
        path.write_text(body)
        path.chmod(0o755)

    @staticmethod
    def _macho(path: Path, *loads: str, identity: str | None = None) -> None:
        lines = []
        if identity is not None:
            lines.append(f"id={identity}")
        lines.extend(f"load={load}" for load in loads)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n")
        path.chmod(0o755)

    def test_relocates_recursive_fips_closure_relative_to_each_consumer(self) -> None:
        package = self.root / "package"
        consumer = package / "registry_client" / "evidence" / "native.so"
        self._macho(consumer, f"@rpath/{CRYPTO}")
        libraries = self.root / "build"
        self._macho(
            libraries / CRYPTO,
            f"@rpath/{WRAPPER}",
            identity=f"@rpath/{CRYPTO}",
        )
        self._macho(
            libraries / WRAPPER,
            identity=f"@rpath/{WRAPPER}",
        )
        destination = package / "registry_client" / ".dylibs"

        names = MODULE.bundle_macos_fips([consumer], [libraries], destination)

        self.assertEqual([CRYPTO, WRAPPER], names)
        self.assertIn(f"load=@loader_path/../.dylibs/{CRYPTO}", consumer.read_text())
        self.assertIn(
            f"load=@loader_path/{WRAPPER}", (destination / CRYPTO).read_text()
        )
        self.assertIn(f"id=@rpath/{CRYPTO}", (destination / CRYPTO).read_text())
        self.assertTrue((destination / WRAPPER).is_file())

    def test_missing_and_nonidentical_libraries_are_refused(self) -> None:
        consumer = self.root / "consumer"
        self._macho(consumer, f"@rpath/{CRYPTO}")
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaisesRegex(MODULE.PackagingError, "resolved to 0 files"):
            MODULE.bundle_macos_fips([consumer], [empty], self.root / "missing")

        roots = [self.root / "one", self.root / "two"]
        self._macho(roots[0] / CRYPTO, identity=f"@rpath/{CRYPTO}")
        self._macho(
            roots[1] / CRYPTO,
            "/usr/lib/libSystem.B.dylib",
            identity=f"@rpath/{CRYPTO}",
        )
        with self.assertRaisesRegex(MODULE.PackagingError, "2 nonidentical files"):
            MODULE.bundle_macos_fips([consumer], roots, self.root / "ambiguous")

    def test_byte_identical_library_copies_are_one_unambiguous_input(self) -> None:
        consumer = self.root / "consumer"
        self._macho(consumer, f"@rpath/{CRYPTO}")
        roots = [self.root / "one", self.root / "two"]
        for root in roots:
            self._macho(root / CRYPTO, identity=f"@rpath/{CRYPTO}")

        destination = self.root / "destination"
        self.assertEqual(
            [CRYPTO], MODULE.bundle_macos_fips([consumer], roots, destination)
        )
        self.assertTrue((destination / CRYPTO).is_file())

    def test_symlinked_or_nonregular_library_is_refused(self) -> None:
        consumer = self.root / "consumer"
        self._macho(consumer, f"@rpath/{CRYPTO}")
        for kind in ("symlink", "directory"):
            with self.subTest(kind=kind):
                root = self.root / kind
                root.mkdir()
                candidate = root / CRYPTO
                if kind == "symlink":
                    source = self.root / "real-library"
                    self._macho(source, identity=f"@rpath/{CRYPTO}")
                    candidate.symlink_to(source)
                else:
                    candidate.mkdir()
                with self.assertRaisesRegex(
                    MODULE.PackagingError, "must be a regular file"
                ):
                    MODULE.bundle_macos_fips(
                        [consumer], [root], self.root / f"destination-{kind}"
                    )

    def test_absolute_fips_load_is_refused(self) -> None:
        consumer = self.root / "consumer"
        self._macho(consumer, f"/private/tmp/build/{CRYPTO}")
        libraries = self.root / "build"
        self._macho(libraries / CRYPTO, identity=f"@rpath/{CRYPTO}")
        with self.assertRaisesRegex(MODULE.PackagingError, "unsupported.*load"):
            MODULE.bundle_macos_fips([consumer], [libraries], self.root / "destination")

    def test_archive_is_deterministic_and_strictly_extractable(self) -> None:
        binary = self.root / "evidence"
        self._macho(binary, f"@rpath/{CRYPTO}")
        libraries = self.root / "build"
        self._macho(libraries / CRYPTO, identity=f"@rpath/{CRYPTO}")
        notice = self.root / "NOTICE"
        notice.write_text("AWS-LC notice\n")
        asset = "evidence-v0.33.0-macos-arm64"
        archives = [self.root / "first.tar.gz", self.root / "second.tar.gz"]
        for archive in archives:
            self.assertEqual(
                [CRYPTO],
                MODULE.archive_macos_fips_binary(
                    binary=binary,
                    asset_name=asset,
                    library_roots=[libraries],
                    notice=notice,
                    output=archive,
                ),
            )
        self.assertEqual(archives[0].read_bytes(), archives[1].read_bytes())

        with tarfile.open(archives[0], "r:gz") as package:
            self.assertEqual([asset, CRYPTO, "THIRD_PARTY_NOTICES"], package.getnames())
            modes = {member.name: stat.S_IMODE(member.mode) for member in package}
        self.assertEqual(
            {asset: 0o755, CRYPTO: 0o755, "THIRD_PARTY_NOTICES": 0o644},
            modes,
        )
        extracted = self.root / "extracted"
        executable = MODULE.extract_macos_binary_archive(archives[0], extracted, asset)
        self.assertEqual(extracted / asset, executable)
        self.assertIn(f"@loader_path/{CRYPTO}", executable.read_text())

    def test_extractor_refuses_noncanonical_or_unsafe_members(self) -> None:
        asset = "evidence-v0.33.0-macos-arm64"
        cases = {
            "unexpected": [
                (asset, 0o755),
                (CRYPTO, 0o755),
                ("extra", 0o644),
                ("THIRD_PARTY_NOTICES", 0o644),
            ],
            "path": [
                (asset, 0o755),
                (f"lib/{CRYPTO}", 0o755),
                ("THIRD_PARTY_NOTICES", 0o644),
            ],
            "mode": [(asset, 0o644), (CRYPTO, 0o755), ("THIRD_PARTY_NOTICES", 0o644)],
            "duplicate": [
                (asset, 0o755),
                (CRYPTO, 0o755),
                (CRYPTO, 0o755),
                ("THIRD_PARTY_NOTICES", 0o644),
            ],
        }
        for name, members in cases.items():
            with self.subTest(name=name):
                archive = self.root / f"{name}.tar.gz"
                with tarfile.open(
                    archive, "w:gz", format=tarfile.GNU_FORMAT
                ) as package:
                    for member_name, mode in members:
                        info = tarfile.TarInfo(member_name)
                        info.size = 1
                        info.mode = mode
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mtime = 0
                        package.addfile(info, io.BytesIO(b"x"))
                with self.assertRaises(MODULE.PackagingError):
                    MODULE.extract_macos_binary_archive(
                        archive, self.root / f"extract-{name}", asset
                    )


if __name__ == "__main__":
    unittest.main()
