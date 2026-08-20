#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("client_registry.py")


def load_module():
    spec = importlib.util.spec_from_file_location("client_registry", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_npm_package(
    path: Path,
    *,
    name: str,
    version: str,
    binary: str | None = None,
    optional_dependencies: dict[str, str] | None = None,
) -> None:
    metadata: dict[str, object] = {"name": name, "version": version}
    if optional_dependencies is not None:
        metadata["optionalDependencies"] = optional_dependencies
    entries = {
        "package/package.json": json.dumps(metadata).encode(),
        "package/LICENSE": b"license\n",
    }
    if binary is not None:
        entries[f"package/{binary}"] = b"native\n"
    with tarfile.open(path, mode="w:gz") as archive:
        for member_name, payload in entries.items():
            info = tarfile.TarInfo(member_name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def write_wheel(path: Path, *, project: str = "registry-relay-client") -> None:
    with zipfile.ZipFile(path, mode="w") as archive:
        archive.writestr(
            "registry_relay_client-1.2.3.dist-info/METADATA",
            f"Name: {project}\nVersion: 1.2.3\n",
        )


class ClientRegistryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary_directory.name)
        self.version = "1.2.3"
        self.client = "relay"
        self._write_distribution(self.client)

    def _write_distribution(self, client: str) -> None:
        definition = self.module.client_definition(client)
        optional = {
            f"{definition.npm_root_package}-{platform}": self.version
            for platform, _binary in self.module.npm_platforms(client)
        }
        for path, (platform, binary) in zip(
            self.module.npm_tarballs(self.directory, self.version, client)[:-1],
            self.module.npm_platforms(client),
            strict=True,
        ):
            write_npm_package(
                path,
                name=f"{definition.npm_root_package}-{platform}",
                version=self.version,
                binary=binary,
            )
        write_npm_package(
            self.module.npm_tarballs(self.directory, self.version, client)[-1],
            name=definition.npm_root_package,
            version=self.version,
            optional_dependencies=optional,
        )
        for path in self.module.wheel_paths(self.directory, self.version, client):
            write_wheel(path, project=definition.pypi_project)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_validates_closed_publishable_distribution(self) -> None:
        self.module.validate_distribution(self.directory, self.version, self.client)

    def test_validates_both_clients_independently(self) -> None:
        self._write_distribution("evidence")
        self._write_distribution("discovery")
        self.module.validate_distribution(self.directory, self.version, "discovery")
        self.module.validate_distribution(self.directory, self.version, "evidence")
        self.module.validate_distribution(self.directory, self.version, "relay")

    def test_public_linux_wheels_use_manylinux_tags(self) -> None:
        names = {
            path.name
            for path in self.module.wheel_paths(
                self.directory, self.version, self.client
            )
        }
        self.assertIn(
            "registry_relay_client-1.2.3-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
            names,
        )
        self.assertIn(
            "registry_relay_client-1.2.3-cp310-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl",
            names,
        )
        self.assertFalse(any("abi3-linux_" in name for name in names))

    def test_rejects_root_package_with_a_native_binary(self) -> None:
        definition = self.module.client_definition(self.client)
        root = self.module.npm_tarballs(
            self.directory, self.version, self.client
        )[-1]
        write_npm_package(
            root,
            name=definition.npm_root_package,
            version=self.version,
            binary="relay-client.linux-x64-gnu.node",
            optional_dependencies={
                f"{definition.npm_root_package}-{platform}": self.version
                for platform, _binary in self.module.npm_platforms(self.client)
            },
        )
        with self.assertRaisesRegex(
            self.module.ClientRegistryError,
            "must not contain a native binary",
        ):
            self.module.validate_npm_packages(
                self.directory, self.version, self.client
            )

    def test_rejects_wheel_metadata_for_another_project(self) -> None:
        wheel = self.module.wheel_paths(
            self.directory, self.version, self.client
        )[0]
        write_wheel(wheel, project="another-project")
        with self.assertRaisesRegex(
            self.module.ClientRegistryError,
            "wrong name or version",
        ):
            self.module.validate_wheels(self.directory, self.version, self.client)

    def test_npm_retry_accepts_only_exact_integrity(self) -> None:
        tarball = self.module.npm_tarballs(
            self.directory, self.version, self.client
        )[0]
        package, _names = self.module.npm_package_metadata(tarball)
        metadata = {
            "name": package["name"],
            "version": self.version,
            "dist": {"integrity": self.module.npm_integrity(tarball)},
        }
        self.assertEqual(
            "present", self.module.npm_registry_state(tarball, metadata)
        )
        metadata["dist"]["integrity"] = "sha512-different"
        with self.assertRaisesRegex(
            self.module.ClientRegistryError,
            "immutable",
        ):
            self.module.npm_registry_state(tarball, metadata)

    def test_pypi_retry_accepts_exact_partial_then_complete_state(self) -> None:
        definition = self.module.client_definition(self.client)
        wheels = self.module.wheel_paths(self.directory, self.version, self.client)
        entries = [
            {
                "filename": path.name,
                "digests": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
            }
            for path in wheels
        ]
        metadata = {
            "info": {
                "name": definition.pypi_project,
                "version": self.version,
            },
            "urls": entries[:1],
        }
        self.assertEqual(
            "partial",
            self.module.pypi_registry_state(
                wheels, self.version, metadata, self.client
            ),
        )
        metadata["urls"] = entries
        self.assertEqual(
            "present",
            self.module.pypi_registry_state(
                wheels, self.version, metadata, self.client
            ),
        )

    def test_pypi_retry_rejects_an_unexpected_or_changed_file(self) -> None:
        definition = self.module.client_definition(self.client)
        wheels = self.module.wheel_paths(self.directory, self.version, self.client)
        metadata = {
            "info": {
                "name": definition.pypi_project,
                "version": self.version,
            },
            "urls": [
                {
                    "filename": wheels[0].name,
                    "digests": {"sha256": "0" * 64},
                }
            ],
        }
        with self.assertRaisesRegex(
            self.module.ClientRegistryError,
            "immutable",
        ):
            self.module.pypi_registry_state(
                wheels, self.version, metadata, self.client
            )


class BindOptionalDependenciesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.directory = Path(self.temporary_directory.name)
        self.version = "1.2.3"
        self.client = "relay"
        self.definition = self.module.client_definition(self.client)
        self.package_json = self.directory / "package.json"
        self._write_manifest(
            name=self.definition.npm_root_package,
            version=self.version,
        )

    def _write_manifest(self, **fields: object) -> None:
        self.package_json.write_text(
            json.dumps(fields, indent=2) + "\n", encoding="utf-8"
        )

    def _read_manifest(self) -> dict:
        return json.loads(self.package_json.read_text(encoding="utf-8"))

    def _expected(self) -> dict[str, str]:
        return {
            f"{self.definition.npm_root_package}-{platform}": self.version
            for platform, _binary in self.module.npm_platforms(self.client)
        }

    def test_binds_every_platform_at_the_exact_version(self) -> None:
        self.module.bind_optional_dependencies(
            self.package_json, self.version, self.client
        )
        self.assertEqual(
            self._read_manifest()["optionalDependencies"], self._expected()
        )

    def test_binds_what_the_packed_root_package_is_validated_against(self) -> None:
        # The binding and the gate that proves it must not drift apart. Both
        # read one platform list, so a platform added to either is required by
        # the other in the same commit.
        self.module.bind_optional_dependencies(
            self.package_json, self.version, self.client
        )
        tarballs = self.module.npm_tarballs(
            self.directory, self.version, self.client
        )
        write_npm_package(
            tarballs[-1],
            name=self.definition.npm_root_package,
            version=self.version,
            optional_dependencies=self._read_manifest()["optionalDependencies"],
        )
        for path, (platform, binary) in zip(
            tarballs[:-1],
            self.module.npm_platforms(self.client),
            strict=True,
        ):
            write_npm_package(
                path,
                name=f"{self.definition.npm_root_package}-{platform}",
                version=self.version,
                binary=binary,
            )
        self.module.validate_npm_packages(self.directory, self.version, self.client)

    def test_repeats_byte_for_byte(self) -> None:
        self.module.bind_optional_dependencies(
            self.package_json, self.version, self.client
        )
        once = self.package_json.read_bytes()
        self.module.bind_optional_dependencies(
            self.package_json, self.version, self.client
        )
        self.assertEqual(self.package_json.read_bytes(), once)

    def test_keeps_every_other_manifest_field(self) -> None:
        self._write_manifest(
            name=self.definition.npm_root_package,
            version=self.version,
            files=["client.js"],
            devDependencies={"@napi-rs/cli": "3.8.2"},
        )
        self.module.bind_optional_dependencies(
            self.package_json, self.version, self.client
        )
        manifest = self._read_manifest()
        self.assertEqual(manifest["files"], ["client.js"])
        self.assertEqual(manifest["devDependencies"], {"@napi-rs/cli": "3.8.2"})

    def test_refuses_a_manifest_at_another_version(self) -> None:
        self._write_manifest(
            name=self.definition.npm_root_package,
            version="9.9.9",
        )
        with self.assertRaisesRegex(self.module.ClientRegistryError, "must identify"):
            self.module.bind_optional_dependencies(
                self.package_json, self.version, self.client
            )

    def test_refuses_a_manifest_for_another_client(self) -> None:
        self._write_manifest(
            name="@registrystack/evidence-client",
            version=self.version,
        )
        with self.assertRaisesRegex(self.module.ClientRegistryError, "must identify"):
            self.module.bind_optional_dependencies(
                self.package_json, self.version, self.client
            )

    def test_refuses_a_missing_manifest(self) -> None:
        with self.assertRaises(self.module.ClientRegistryError):
            self.module.bind_optional_dependencies(
                self.directory / "absent.json", self.version, self.client
            )

    def test_command_line_binds_the_manifest(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = self.module.main(
                [
                    "bind-optional-deps",
                    "--package-json",
                    str(self.package_json),
                    "--version",
                    self.version,
                    "--client",
                    self.client,
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue(), "bound\n")
        self.assertEqual(
            self._read_manifest()["optionalDependencies"], self._expected()
        )


if __name__ == "__main__":
    unittest.main()
