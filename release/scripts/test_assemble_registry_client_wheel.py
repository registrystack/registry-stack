#!/usr/bin/env python3
from __future__ import annotations

import csv
import io
import subprocess
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release/scripts/assemble-registry-client-wheel.py"
PRODUCTS = ("discovery", "evidence", "relay", "breg")
TAG = "cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64"


class AssembleRegistryClientWheelTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.directory = Path(self.temporary_directory.name)
        self.version = tomllib.loads(
            (ROOT / "crates/registry-stack-client-py/pyproject.toml").read_text(
                encoding="utf-8"
            )
        )["project"]["version"]
        self.wheels: dict[str, Path] = {}
        for product in PRODUCTS:
            wheel = self.directory / (
                f"registry_{product}_client-{self.version}-{TAG}.whl"
            )
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(
                    f"registry_{product}_client/__init__.py",
                    f"PRODUCT = {product!r}\n",
                )
                archive.writestr(
                    f"registry_{product}_client/native.abi3.so",
                    f"{product} native".encode(),
                )
                if product == "evidence":
                    archive.writestr(
                        "registry_evidence_client.libs/libfixture.so",
                        b"linked fixture",
                    )
                archive.writestr(
                    f"registry_{product}_client-{self.version}.dist-info/METADATA",
                    f"Name: registry-{product}-client\nVersion: {self.version}\n",
                )
            self.wheels[product] = wheel

    def run_assembler(
        self, *, version: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        command = [
            "python3",
            str(SCRIPT),
            "--version",
            version or self.version,
            "--output-dir",
            str(self.directory / "dist"),
        ]
        for product, wheel in self.wheels.items():
            command.extend((f"--{product}-wheel", str(wheel)))
        return subprocess.run(command, capture_output=True, text=True, check=False)

    def test_assembles_one_installable_distribution_identity(self) -> None:
        result = self.run_assembler()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = Path(result.stdout.strip())
        self.assertEqual(
            output.name,
            f"registry_stack_client-{self.version}-{TAG}.whl",
        )
        with zipfile.ZipFile(output) as archive:
            names = set(archive.namelist())
            for product in PRODUCTS:
                prefix = f"registry_client/{product}"
                self.assertIn(f"{prefix}/__init__.py", names)
                self.assertIn(f"{prefix}/native.abi3.so", names)
                self.assertFalse(
                    any(
                        name.startswith(f"registry_{product}_client/") for name in names
                    )
                )
            self.assertIn("registry_client/__init__.py", names)
            self.assertIn(
                "registry_client/registry_evidence_client.libs/libfixture.so",
                names,
            )
            self.assertFalse(
                any(
                    f"registry_breg_client-{self.version}.dist-info" in name
                    for name in names
                )
            )
            dist_info = f"registry_stack_client-{self.version}.dist-info"
            metadata = archive.read(f"{dist_info}/METADATA").decode()
            self.assertIn("Name: registry-stack-client\n", metadata)
            self.assertIn(f"Version: {self.version}\n", metadata)
            facade = archive.read("registry_client/__init__.py").decode()
            self.assertIn(f'__version__ = "{self.version}"', facade)
            for product in PRODUCTS:
                self.assertIn(
                    f"import registry_client.{product} as {product}",
                    facade,
                )
            rows = list(
                csv.reader(io.StringIO(archive.read(f"{dist_info}/RECORD").decode()))
            )
            recorded = {row[0] for row in rows}
            self.assertEqual(recorded, names)

    def test_the_pypi_page_states_the_install_name_and_the_import_name(self) -> None:
        result = self.run_assembler()
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(Path(result.stdout.strip())) as archive:
            dist_info = f"registry_stack_client-{self.version}.dist-info"
            metadata = archive.read(f"{dist_info}/METADATA").decode()
        self.assertIn("Description-Content-Type: text/markdown\n", metadata)
        _, _, description = metadata.partition("\n\n")
        self.assertIn("pip install \"registry-stack-client", description)
        self.assertIn("from registry_client import", description)
        # The README wraps its lines, so compare against the unwrapped prose.
        prose = " ".join(description.split())
        self.assertIn(
            "installs as `registry-stack-client` and imports as `registry_client`",
            prose,
        )
        for product in PRODUCTS:
            self.assertIn(f"`registry_client.{product}`", description)

    def test_unified_and_legacy_distributions_never_own_the_same_path(self) -> None:
        result = self.run_assembler()
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(Path(result.stdout.strip())) as archive:
            unified_paths = set(archive.namelist())
        for product, wheel in self.wheels.items():
            with zipfile.ZipFile(wheel) as archive:
                legacy_paths = {
                    name
                    for name in archive.namelist()
                    if ".dist-info/" not in name and not name.endswith("/")
                }
            self.assertTrue(legacy_paths)
            self.assertTrue(unified_paths.isdisjoint(legacy_paths), product)

    def test_rejects_an_input_for_another_version(self) -> None:
        result = self.run_assembler(version="99.0.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("facade version does not match 99.0.0", result.stderr)

    def test_repeated_assembly_is_byte_for_byte_deterministic(self) -> None:
        first = self.run_assembler()
        self.assertEqual(first.returncode, 0, first.stderr)
        first_bytes = Path(first.stdout.strip()).read_bytes()

        second = self.run_assembler()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first_bytes, Path(second.stdout.strip()).read_bytes())


if __name__ == "__main__":
    unittest.main()
