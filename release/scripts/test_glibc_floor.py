# SPDX-License-Identifier: Apache-2.0
"""Tests for the shared glibc floor: the build gate and the installer preflight."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "release/scripts/check-glibc-floor.sh"
FLOOR_FILE = ROOT / "release/glibc-floor.env"

RENDERER_PATH = Path(__file__).with_name("render-installer-libc-preflight.py")
SPEC = importlib.util.spec_from_file_location(
    "render_installer_libc_preflight", RENDERER_PATH
)
assert SPEC and SPEC.loader
RENDERER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDERER)

# A readelf stand-in. Each line of the table names one binary, the highest
# versioned glibc symbol it imports, and an optional strong unversioned import.
FAKE_READELF = """#!/usr/bin/env bash
set -euo pipefail
binary="${!#}"
name="${binary##*/}"
row="$(awk -v name="$name" -F '|' '$1 == name {print $2 "|" $3}' "${READELF_TABLE}")"
highest="${row%%|*}"
unversioned="${row##*|}"
case "$1" in
  --version-info)
    if [[ -n "${highest}" ]]; then
      printf '  0x0020: Name: GLIBC_2.17  Flags: none  Version: 2\\n'
      printf '  0x0030: Name: %s  Flags: none  Version: 3\\n' "${highest}"
    fi
    ;;
  --wide)
    printf 'Symbol table \\x27.dynsym\\x27 contains 3 entries:\\n'
    printf '   Num:    Value          Size Type    Bind   Vis      Ndx Name\\n'
    printf '     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.17\\n'
    printf '     2: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __gmon_start__\\n'
    if [[ -n "${unversioned}" ]]; then
      printf '     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND %s\\n' "${unversioned}"
    fi
    ;;
  *)
    printf 'unexpected readelf invocation: %s\\n' "$*" >&2
    exit 2
    ;;
esac
"""


def repository_floor() -> str:
    match = re.search(
        r"^REGISTRY_GLIBC_FLOOR=([0-9]+\.[0-9]+)$",
        FLOOR_FILE.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert match, "release/glibc-floor.env declares REGISTRY_GLIBC_FLOOR"
    return match.group(1)


class GlibcFloorGateTests(unittest.TestCase):
    """The gate that refuses a release binary built above the floor."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        readelf = self.fake_bin / "readelf"
        readelf.write_text(FAKE_READELF, encoding="utf-8")
        readelf.chmod(0o755)
        self.table = self.root / "readelf-table"
        self.binaries = self.root / "bin"
        self.binaries.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def gate_for(self, floor: str) -> Path:
        """A copy of the gate beside a floor file under test."""
        scripts = self.root / "release/scripts"
        scripts.mkdir(parents=True, exist_ok=True)
        gate = scripts / "check-glibc-floor.sh"
        gate.write_bytes(GATE.read_bytes())
        gate.chmod(0o755)
        (self.root / "release/glibc-floor.env").write_text(
            f"REGISTRY_GLIBC_FLOOR={floor}\n", encoding="utf-8"
        )
        return gate

    def declare(self, rows: dict[str, tuple[str, str]]) -> list[str]:
        lines = []
        paths = []
        for name, (highest, unversioned) in rows.items():
            lines.append(f"{name}|{highest}|{unversioned}")
            path = self.binaries / name
            path.write_text("not a real binary\n", encoding="utf-8")
            paths.append(str(path))
        self.table.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return paths

    def run_gate(self, floor: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.gate_for(floor)), *arguments],
            env={
                **os.environ,
                "PATH": f"{self.fake_bin}:{os.environ.get('PATH', '')}",
                "READELF_TABLE": str(self.table),
            },
            capture_output=True,
            text=True,
            check=False,
        )

    def test_accepts_binaries_at_or_below_the_floor(self) -> None:
        paths = self.declare(
            {
                "evidence": ("GLIBC_2.35", ""),
                "mint": ("GLIBC_2.34", ""),
                "breg": ("GLIBC_2.17", ""),
            }
        )
        result = self.run_gate("2.35", *paths)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("requires GLIBC_2.35, at or below the GLIBC_2.35 floor", result.stdout)
        self.assertIn("requires GLIBC_2.34, at or below", result.stdout)

    def test_refuses_a_binary_above_the_floor(self) -> None:
        paths = self.declare(
            {"evidence": ("GLIBC_2.35", ""), "evidencectl": ("GLIBC_2.39", "")}
        )
        result = self.run_gate("2.35", *paths)
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "evidencectl requires GLIBC_2.39 above the GLIBC_2.35 floor", result.stderr
        )
        self.assertIn("failed for 1 of 2 binaries", result.stderr)

    def test_refuses_a_binary_with_a_strong_unversioned_import(self) -> None:
        paths = self.declare({"breg": ("GLIBC_2.34", "__isoc23_strtol")})
        result = self.run_gate("2.35", *paths)
        self.assertEqual(result.returncode, 1)
        self.assertIn("strong unversioned imports", result.stderr)
        self.assertIn("__isoc23_strtol", result.stderr)

    def test_refuses_a_binary_that_declares_no_glibc_version(self) -> None:
        paths = self.declare({"relay": ("", "")})
        result = self.run_gate("2.35", *paths)
        self.assertEqual(result.returncode, 1)
        self.assertIn("imports no versioned glibc symbol", result.stderr)

    def test_refuses_a_missing_file_and_an_empty_invocation(self) -> None:
        self.declare({"relay": ("GLIBC_2.34", "")})
        missing = self.run_gate("2.35", str(self.binaries / "absent"))
        self.assertEqual(missing.returncode, 1)
        self.assertIn("is not a file", missing.stderr)
        empty = self.run_gate("2.35")
        self.assertEqual(empty.returncode, 2)
        self.assertIn("usage:", empty.stderr)

    def test_refuses_a_floor_file_that_is_not_a_version(self) -> None:
        paths = self.declare({"relay": ("GLIBC_2.34", "")})
        result = self.run_gate("trixie", *paths)
        self.assertEqual(result.returncode, 2)
        self.assertIn("must name a MAJOR.MINOR glibc version", result.stderr)

    def test_reads_the_repository_floor(self) -> None:
        paths = self.declare({"relay": ("GLIBC_2.17", "")})
        scripts = self.root / "release/scripts"
        scripts.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [str(GATE), *paths],
            env={
                **os.environ,
                "PATH": f"{self.fake_bin}:{os.environ.get('PATH', '')}",
                "READELF_TABLE": str(self.table),
            },
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"GLIBC_{repository_floor()} floor", result.stdout)


class InstallerPreflightTests(unittest.TestCase):
    """The generated block the three published installers carry."""

    @staticmethod
    def renderer(*arguments: str) -> int:
        """Run the generator with its progress reporting captured."""
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            return RENDERER.main(list(arguments))

    def test_repository_installers_are_current(self) -> None:
        self.assertEqual(self.renderer("--check"), 0)

    def test_every_published_installer_is_covered(self) -> None:
        covered = {installer.path for installer in RENDERER.INSTALLERS}
        published = {
            path.relative_to(ROOT)
            for path in ROOT.glob("crates/*/install.sh")
        }
        self.assertEqual(covered, published)

    def test_check_reports_a_stale_installer_and_write_repairs_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for installer in RENDERER.INSTALLERS:
                target = root / installer.path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / installer.path).read_bytes())
            floor_file = root / RENDERER.FLOOR_FILE
            floor_file.parent.mkdir(parents=True, exist_ok=True)
            floor_file.write_text("REGISTRY_GLIBC_FLOOR=2.28\n", encoding="utf-8")

            self.assertEqual(self.renderer("--check", "--root", str(root)), 1)
            self.assertEqual(self.renderer("--write", "--root", str(root)), 0)
            self.assertEqual(self.renderer("--check", "--root", str(root)), 0)
            for installer in RENDERER.INSTALLERS:
                text = (root / installer.path).read_text(encoding="utf-8")
                self.assertIn('libc_floor="2.28"', text)
                self.assertEqual(text.count(RENDERER.BEGIN), 1)
                self.assertEqual(text.count(RENDERER.END), 1)

    def test_generated_block_refuses_musl_and_an_old_glibc_before_downloading(
        self,
    ) -> None:
        floor = repository_floor()
        for installer in RENDERER.INSTALLERS:
            with self.subTest(installer=str(installer.path)):
                text = (ROOT / installer.path).read_text(encoding="utf-8")
                block = text[text.index(RENDERER.BEGIN) : text.index(RENDERER.END)]
                self.assertIn(f'libc_floor="{floor}"', block)
                self.assertIn(
                    f"No musl build of {installer.product} is published", block
                )
                self.assertIn("Nothing was installed", block)
                self.assertIn('if [ "$os_label" = "linux" ]; then', block)
                self.assertLess(text.index(RENDERER.END), text.index(RENDERER.ANCHOR))

    def test_generated_block_trusts_the_active_libc(self) -> None:
        """The libc the system runs on decides, read from glibc's getconf. A musl
        loader installed beside glibc for cross builds is not a musl system, and
        a musl system without a GNU_LIBC_VERSION answer is refused. The check never
        pipes the ldd report into grep: under pipefail bash loses the match
        whenever grep exits before the report is fully written."""
        floor = repository_floor()
        block = RENDERER.render(RENDERER.INSTALLERS[0], floor)
        self.assertNotRegex(block, r"\|\s*grep\b")
        scenarios = {
            "glibc beside a musl loader": (
                {"getconf": "printf 'glibc 2.41\\n'",
                 "ldd": "printf 'ldd (Debian GLIBC 2.41-12) 2.41\\n'",
                 "ls": "exit 0"},
                0,
                "",
            ),
            "musl with a getconf that has no GNU_LIBC_VERSION": (
                {"getconf": "printf 'getconf: GNU_LIBC_VERSION: unknown variable\\n' >&2; exit 1",
                 "ldd": "printf 'musl libc (aarch64)\\nVersion 1.2.5\\n' >&2; exit 1",
                 "ls": "exit 0"},
                1,
                "No musl build",
            ),
            "musl without getconf": (
                {"getconf": "exit 127",
                 "ldd": "printf 'musl libc (x86_64)\\nVersion 1.2.5\\n' >&2; exit 1",
                 "ls": "exit 2"},
                1,
                "No musl build",
            ),
            "glibc below the floor": (
                {"getconf": "printf 'glibc 2.28\\n'",
                 "ldd": "printf 'ldd (GNU libc) 2.28\\n'",
                 "ls": "exit 2"},
                1,
                "need " + floor,
            ),
        }
        for name, (fakes, expected_status, expected_message) in scenarios.items():
            with self.subTest(scenario=name), tempfile.TemporaryDirectory() as temporary:
                fake_bin = Path(temporary) / "bin"
                fake_bin.mkdir()
                for command, body in fakes.items():
                    fake = fake_bin / command
                    fake.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
                    fake.chmod(0o755)
                script = Path(temporary) / "preflight.sh"
                script.write_text(
                    "set -euo pipefail\nos_label=linux\nrepo=example/repo\n"
                    + block
                    + "printf 'preflight passed\\n'\n",
                    encoding="utf-8",
                )
                result = subprocess.run(
                    ["bash", str(script)],
                    env={"PATH": f"{fake_bin}:{os.environ.get('PATH', '')}"},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, expected_status, result.stderr)
                self.assertIn(expected_message, result.stderr)
                self.assertEqual(
                    result.stdout, "preflight passed\n" if expected_status == 0 else ""
                )

    def test_generated_block_stays_within_stock_macos_bash(self) -> None:
        for installer in RENDERER.INSTALLERS:
            with self.subTest(installer=str(installer.path)):
                block = RENDERER.render(installer, repository_floor())
                for construct in ("declare -A", "mapfile", "readarray", "${!", "[["):
                    self.assertNotIn(construct, block)


class SharedFloorTests(unittest.TestCase):
    """One home for the floor, and one home for the Zig pin that serves it."""

    def test_no_release_script_repeats_the_floor(self) -> None:
        floor = repository_floor()
        for relative in (
            "release/scripts/build-release-binaries.sh",
            "release/scripts/check-glibc-floor.sh",
            "release/scripts/zig-glibc-compiler",
            "release/docker/Dockerfile.builder",
        ):
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertNotIn(
                    floor,
                    text,
                    f"{relative} must read the floor from release/glibc-floor.env",
                )

    def test_release_build_gates_every_staged_binary(self) -> None:
        recipe = (ROOT / "release/scripts/build-release-binaries.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("prepare_zig_toolchain", recipe)
        self.assertIn('REGISTRY_ZIG_TARGET="${zig_arch}-linux-gnu.${floor}"', recipe)
        self.assertIn("local staged_binaries=(dist/bin/* dist/image-bin/*)", recipe)
        self.assertIn(
            '"${script_dir}/check-glibc-floor.sh" "${staged_binaries[@]}"', recipe
        )
        self.assertTrue(os.access(GATE, os.X_OK), "the gate must be executable")

    def test_release_build_keeps_the_zig_cache_out_of_the_checkout(self) -> None:
        # The builder runs with HOME set to the mounted checkout, so a Zig
        # invocation that picks its own cache directory writes tens of
        # megabytes of build artefacts into the working tree it is building
        # from. Both cache directories are therefore named explicitly, inside
        # the wrapper directory the run removes when it exits.
        recipe = (ROOT / "release/scripts/build-release-binaries.sh").read_text(
            encoding="utf-8"
        )
        for variable in ("ZIG_GLOBAL_CACHE_DIR", "ZIG_LOCAL_CACHE_DIR"):
            with self.subTest(variable=variable):
                self.assertIn(
                    f'export {variable}="${{release_zig_wrapper_root}}/', recipe
                )

    def test_zig_pin_matches_the_node_client_requirements(self) -> None:
        def ziglang_block(relative: str) -> list[str]:
            text = (ROOT / relative).read_text(encoding="utf-8")
            lines = text.splitlines()
            start = next(
                index
                for index, line in enumerate(lines)
                if line.startswith("ziglang==")
            )
            end = start + 1
            while end < len(lines) and lines[end].startswith("    --hash="):
                end += 1
            return [line.rstrip(" \\") for line in lines[start:end]]

        self.assertEqual(
            ziglang_block("release/requirements/ziglang-0.12.1.txt"),
            ziglang_block("release/requirements/maturin-1.9.6.txt"),
        )


if __name__ == "__main__":
    unittest.main()
