#!/usr/bin/env python3
from __future__ import annotations

import csv
import importlib.util
import io
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release/scripts/assemble-registry-client-wheel.py"
PRODUCTS = ("discovery", "evidence", "relay", "breg", "casework")
TAG = "cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "assemble_registry_client_wheel", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
                if product == "casework":
                    archive.writestr(
                        "registry_casework_client/__init__.pyi",
                        "class CaseworkClient: ...\n",
                    )
                    archive.writestr("registry_casework_client/py.typed", b"")
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
        self, *, version: str | None = None, include_casework: bool = False
    ) -> subprocess.CompletedProcess[str]:
        command = [
            "python3",
            str(SCRIPT),
            "--version",
            version or self.version,
            "--output-dir",
            str(self.directory / "dist"),
        ]
        if include_casework:
            command.append("--include-casework")
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
            self.assertEqual(
                archive.read("registry_client/casework/__init__.pyi"),
                b"class CaseworkClient: ...\n",
            )
            self.assertIn("registry_client/casework/py.typed", names)
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
            self.assertEqual(
                archive.read(f"{dist_info}/licenses/THIRD_PARTY_NOTICES"),
                (ROOT / "THIRD_PARTY_NOTICES").read_bytes(),
            )
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

    def test_assembled_facade_imports_all_five_product_namespaces(self) -> None:
        result = self.run_assembler()
        self.assertEqual(result.returncode, 0, result.stderr)
        # The fixture modules exercise facade imports without claiming a native
        # build. Native extension loading remains covered by the package smoke.
        import_script = (
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "from registry_client import discovery, evidence, relay, breg, casework; "
            "print(discovery.PRODUCT, evidence.PRODUCT, relay.PRODUCT, breg.PRODUCT, casework.PRODUCT)"
        )
        imported = subprocess.run(
            [
                sys.executable, "-I", "-c", import_script,
                result.stdout.strip(),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertEqual(imported.stdout.strip(), "discovery evidence relay breg casework")

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

    def test_0_29_refuses_the_casework_facade_without_explicit_selection(self) -> None:
        result = self.run_assembler(version="0.29.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("explicit --include-casework", result.stderr)

    def test_repeated_assembly_is_byte_for_byte_deterministic(self) -> None:
        first = self.run_assembler()
        self.assertEqual(first.returncode, 0, first.stderr)
        first_bytes = Path(first.stdout.strip()).read_bytes()

        second = self.run_assembler()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first_bytes, Path(second.stdout.strip()).read_bytes())

    def test_macos_extensions_are_relinked_before_wheel_recording(self) -> None:
        module = load_module()
        files = {
            f"registry_client/{product}/native.abi3.so": product.encode()
            for product in PRODUCTS
        }
        files["registry_client/discovery/client.py"] = b"class Client: pass\n"
        seen: dict[str, object] = {}

        def fake_bundle(*, consumers, library_roots, library_directory):
            seen["consumers"] = [
                path.relative_to(library_directory.parents[1]).as_posix()
                for path in consumers
            ]
            seen["library_roots"] = list(library_roots)
            for consumer in consumers:
                consumer.write_bytes(consumer.read_bytes() + b" signed")
            library_directory.mkdir(parents=True)
            (library_directory / "libaws_lc_fips_crypto.dylib").write_bytes(
                b"signed crypto"
            )
            return ["libaws_lc_fips_crypto.dylib"]

        module.bundle_macos_fips = fake_bundle
        bundled = module.bundle_macos_wheel_files(files, [Path("/cargo-target")])

        self.assertEqual(
            seen["consumers"],
            sorted(
                f"registry_client/{product}/native.abi3.so" for product in PRODUCTS
            ),
        )
        self.assertEqual(seen["library_roots"], [Path("/cargo-target")])
        for product in PRODUCTS:
            self.assertEqual(
                bundled[f"registry_client/{product}/native.abi3.so"],
                product.encode() + b" signed",
            )
        self.assertEqual(
            bundled["registry_client/.dylibs/libaws_lc_fips_crypto.dylib"],
            b"signed crypto",
        )
        self.assertEqual(
            bundled["registry_client/discovery/client.py"],
            b"class Client: pass\n",
        )


if __name__ == "__main__":
    unittest.main()
