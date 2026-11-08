# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the maintained Debian 13 image policy."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-debian13-images.py")
SPEC = importlib.util.spec_from_file_location("check_debian13_images", SCRIPT)
assert SPEC and SPEC.loader
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class ReleaseImagePolicyTests(unittest.TestCase):
    def repository_copy(self, root: Path) -> None:
        for relative in POLICY.MAINTAINED_TEXT_PATHS:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(POLICY.ROOT.joinpath(relative).read_bytes())


    def test_official_runtime_images_are_required_maintained_surfaces(self) -> None:
        self.assertEqual(
            {
                Path("release/docker/Dockerfile.discovery"),
                Path("release/docker/Dockerfile.evidence"),
                Path("release/docker/Dockerfile.evidence-oid4vci"),
                Path("release/docker/Dockerfile.registry-render"),
                Path("release/docker/Dockerfile.breg"),
                Path("release/docker/Dockerfile.breg-mcp"),
                Path("release/docker/Dockerfile.breg-review"),
                Path("release/docker/Dockerfile.casework"),
                Path("release/docker/Dockerfile.scheduling"),
                Path("release/docker/Dockerfile.messaging"),
                Path("release/docker/Dockerfile.coordinator"),
            },
            set(POLICY.DOCKERFILES),
        )
        self.assertEqual(
            {
                Path("release/docker/Dockerfile.discovery"),
                Path("release/docker/Dockerfile.evidence"),
                Path("release/docker/Dockerfile.evidence-oid4vci"),
                Path("release/docker/Dockerfile.registry-render"),
                Path("release/docker/Dockerfile.breg"),
                Path("release/docker/Dockerfile.breg-mcp"),
                Path("release/docker/Dockerfile.breg-review"),
                Path("release/docker/Dockerfile.casework"),
                Path("release/docker/Dockerfile.scheduling"),
                Path("release/docker/Dockerfile.messaging"),
                Path("release/docker/Dockerfile.coordinator"),
            },
            set(POLICY.HTTP_PROBE_DOCKERFILES),
        )

    def test_unrostered_release_dockerfile_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository_copy(root)
            unexpected = root / "release/docker/Dockerfile.unreviewed"
            unexpected.write_text("FROM scratch\n", encoding="utf-8")

            failures = POLICY.check_repository(root)

            self.assertIn(
                "release Dockerfile policy does not cover files: "
                "release/docker/Dockerfile.unreviewed",
                failures,
            )

    def test_release_builder_pins_base_snapshot_and_native_tools(self) -> None:
        self.assertEqual(
            (Path("release/docker/Dockerfile.builder"),),
            POLICY.RUST_BUILDER_DOCKERFILES,
        )
        mutations = (
            (
                POLICY.DOCKERFILE_FRONTEND,
                "docker/dockerfile:1",
                "pinned Dockerfile frontend",
            ),
            (
                POLICY.RUST_BUILDER,
                "rust:1.95-trixie",
                "pinned Debian 13 Rust builder",
            ),
            (
                POLICY.RUST_BUILDER_SNAPSHOT,
                "latest",
                "dated Debian package snapshot",
            ),
            (
                POLICY.RUST_BUILDER_CMAKE,
                "cmake",
                "exact CMake build package",
            ),
            (
                POLICY.RUST_BUILDER_GO,
                "golang-go",
                "exact Go build package",
            ),
            (
                POLICY.RUST_BUILDER_LIBCLANG,
                "libclang-19-dev",
                "exact libclang build package",
            ),
            (
                POLICY.RUST_BUILDER_PROTOC,
                "protobuf-compiler",
                "exact protobuf build package",
            ),
            (
                POLICY.RUST_BUILDER_PIP,
                "python3-pip",
                "exact pip build package",
            ),
            (
                POLICY.RUST_BUILDER_ZIG_REQUIREMENTS,
                "release/requirements/ziglang.txt",
                "hash-pinned Zig requirements file",
            ),
            (
                POLICY.RUST_BUILDER_HASHED_INSTALL,
                "--no-deps",
                "hash-checked Python install",
            ),
        )
        for original, replacement, expected in mutations:
            with self.subTest(expected=expected):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.repository_copy(root)
                    dockerfile = root / "release/docker/Dockerfile.builder"
                    dockerfile.write_text(
                        dockerfile.read_text(encoding="utf-8").replace(
                            original, replacement, 1
                        ),
                        encoding="utf-8",
                    )

                    failures = POLICY.check_repository(root)

                    self.assertTrue(
                        any(
                            "Dockerfile.builder" in failure
                            and expected in failure
                            for failure in failures
                        ),
                        failures,
                    )

    def test_runtime_package_overlay_fixes_libc6_libssl3t64_and_zlib1g(self) -> None:
        self.assertEqual(
            Path("release/scripts/install-runtime-packages.sh"),
            POLICY.RUNTIME_PACKAGE_INSTALLER,
        )
        self.assertEqual(
            {
                "libc6": (
                    "2.41-12+deb13u4",
                    {
                        "amd64": "967aa62605721081c3eb2a17650611a792aa802d76a6511d1840242623d204c9",
                        "arm64": "8784eda966b189c777a384dac5ce009e8fc9b52d006926c5a013e7fa8aa688cc",
                    },
                ),
                "libssl3t64": (
                    "3.5.7-1~deb13u3",
                    {
                        "amd64": "ff16bc048bcd7d1b256094450b79c77947d8e76fe2a24bd99b91021d591fa074",
                        "arm64": "d0681293a160392186c6ef85a165e40603d1628a099936137d24d391bd591f97",
                    },
                ),
                "zlib1g": (
                    "1:1.3.dfsg+really1.3.1-1+deb13u1",
                    {
                        "amd64": "8c27c342230503b73dfde629642c3b352e87b554e06d60cf58772f236a305ceb",
                        "arm64": "0e41b3d7ad8ad7fcd36dd4d61ca91a70018478fc4af652e044f4be770784ddff",
                    },
                ),
            },
            {
                name: (package["version"], package["sha256"])
                for name, package in POLICY.RUNTIME_PACKAGES.items()
            },
        )
        self.assertIn(
            "ADD --checksum=sha256:"
            "ff16bc048bcd7d1b256094450b79c77947d8e76fe2a24bd99b91021d591fa074 "
            "https://snapshot.debian.org/archive/debian-security/20260930T060347Z/"
            "pool/updates/main/o/openssl/libssl3t64_3.5.7-1~deb13u3_amd64.deb "
            "/workspace/runtime-packages/libssl3t64_3.5.7-1~deb13u3_amd64.deb",
            POLICY.RUNTIME_PACKAGE_ADDS,
        )
        # Debian package file names leave out the version's epoch.
        self.assertIn(
            "ADD --checksum=sha256:"
            "0e41b3d7ad8ad7fcd36dd4d61ca91a70018478fc4af652e044f4be770784ddff "
            "https://snapshot.debian.org/archive/debian-security/20261107T075304Z/"
            "pool/updates/main/z/zlib/zlib1g_1.3.dfsg+really1.3.1-1+deb13u1_arm64.deb "
            "/workspace/runtime-packages/zlib1g_1.3.dfsg+really1.3.1-1+deb13u1_arm64.deb",
            POLICY.RUNTIME_PACKAGE_ADDS,
        )
        self.assertEqual([], POLICY.check_repository())

    def test_runtime_package_overlay_is_fully_pinned(self) -> None:
        mutations = [
            (
                "install_package libc6 2.41-12+deb13u4",
                "install_package libc6 2.41-12+deb13u3",
                "exact fixed runtime libc6 version",
            ),
            (
                "install_package libssl3t64 3.5.7-1~deb13u3",
                "install_package libssl3t64 3.5.7-1~deb13u2",
                "exact fixed runtime libssl3t64 version",
            ),
            (
                "install_package zlib1g 1:1.3.dfsg+really1.3.1-1+deb13u1",
                "install_package zlib1g 1:1.3.dfsg+really1.3.1-1+b1",
                "exact fixed runtime zlib1g version",
            ),
        ]
        for name, package in POLICY.RUNTIME_PACKAGES.items():
            for architecture in ("amd64", "arm64"):
                mutations.append(
                    (
                        package["sha256"][architecture],
                        "0" * 64,
                        f"{architecture} runtime {name} checksum",
                    )
                )
        for original, replacement, expected in mutations:
            with (
                self.subTest(expected=expected),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                self.repository_copy(root)
                installer = root / POLICY.RUNTIME_PACKAGE_INSTALLER
                text = installer.read_text(encoding="utf-8")
                self.assertIn(original, text)
                installer.write_text(
                    text.replace(original, replacement, 1),
                    encoding="utf-8",
                )

                failures = POLICY.check_repository(root)

                self.assertTrue(
                    any(expected in failure for failure in failures), failures
                )

    def test_runtime_package_installer_requires_the_libssl3t64_checksum(self) -> None:
        for checksum in (
            "ff16bc048bcd7d1b256094450b79c77947d8e76fe2a24bd99b91021d591fa074",
            "d0681293a160392186c6ef85a165e40603d1628a099936137d24d391bd591f97",
        ):
            with (
                self.subTest(checksum=checksum),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                self.repository_copy(root)
                installer = root / "release/scripts/install-runtime-packages.sh"
                text = installer.read_text(encoding="utf-8")
                self.assertIn(checksum, text)
                installer.write_text(text.replace(checksum, ""), encoding="utf-8")

                failures = POLICY.check_repository(root)

                self.assertTrue(
                    any(
                        "install-runtime-packages.sh" in failure
                        and "runtime libssl3t64 checksum" in failure
                        for failure in failures
                    ),
                    failures,
                )

    def test_runtime_package_overlay_requires_complete_package_metadata(self) -> None:
        mutations = (
            ("sha256sum --check --strict", "sha256sum", "strict runtime package checksum check"),
            ("dpkg-deb --extract", "tar --extract", "runtime package extraction"),
            ("dpkg-deb --control", "true", "runtime package control extraction"),
            (
                'status.d/${package}.md5sums"',
                'status.d/${package}.stale-md5sums"',
                "runtime package file metadata",
            ),
            (
                'dpkg-deb --field "$archive" >"$runtime_root/var/lib/dpkg/status.d/${package}"',
                'dpkg-deb --field "$archive" >/dev/null',
                "runtime package metadata",
            ),
            ('dpkg-deb --field "$archive" Package', "printf libc6", "runtime package identity"),
            ('dpkg-deb --field "$archive" Version', "printf 0", "runtime package version identity"),
            ('dpkg-deb --field "$archive" Architecture', "printf amd64", "runtime package architecture identity"),
        )
        for original, replacement, expected in mutations:
            with (
                self.subTest(expected=expected),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                self.repository_copy(root)
                installer = root / POLICY.RUNTIME_PACKAGE_INSTALLER
                text = installer.read_text(encoding="utf-8")
                self.assertIn(original, text)
                installer.write_text(
                    text.replace(original, replacement, 1),
                    encoding="utf-8",
                )

                failures = POLICY.check_repository(root)

                self.assertTrue(
                    any(expected in failure for failure in failures), failures
                )

    def test_runtime_package_installer_rejects_remote_package_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository_copy(root)
            installer = root / POLICY.RUNTIME_PACKAGE_INSTALLER
            installer.write_text(
                installer.read_text(encoding="utf-8")
                + "\ncurl https://packages.example.invalid/libc6.deb\n",
                encoding="utf-8",
            )

            failures = POLICY.check_repository(root)

            self.assertTrue(
                any(
                    "installer must not fetch remote sources" in failure
                    for failure in failures
                ),
                failures,
            )

    def test_runtime_package_installer_finds_archives_named_without_the_epoch(
        self,
    ) -> None:
        # Debian package file names leave out the version's epoch, while the
        # Version field the installer checks keeps it. The fake tools answer
        # for an archive whose first line is its Package and second its Version.
        archives = {
            "libc6_2.41-12+deb13u4_amd64.deb": ("libc6", "2.41-12+deb13u4"),
            "libssl3t64_3.5.7-1~deb13u3_amd64.deb": ("libssl3t64", "3.5.7-1~deb13u3"),
            "zlib1g_1.3.dfsg+really1.3.1-1+deb13u1_amd64.deb": (
                "zlib1g",
                "1:1.3.dfsg+really1.3.1-1+deb13u1",
            ),
        }
        self.assertEqual(
            {name for name, _version in archives.values()},
            set(POLICY.RUNTIME_PACKAGES),
        )
        fake_tools = {
            "dpkg": 'test "$1" = --print-architecture\nprintf "amd64\\n"\n',
            "dpkg-deb": (
                'case "$1" in\n'
                "--field)\n"
                '\tcase "${3-}" in\n'
                '\tPackage) sed -n 1p "$2" ;;\n'
                '\tVersion) sed -n 2p "$2" ;;\n'
                '\tArchitecture) printf "amd64\\n" ;;\n'
                '\t"") printf "Package: %s\\nVersion: %s\\n" '
                '"$(sed -n 1p "$2")" "$(sed -n 2p "$2")" ;;\n'
                "\t*) exit 2 ;;\n"
                "\tesac\n"
                "\t;;\n"
                '--control) mkdir -p "$3" && : >"$3/md5sums" ;;\n'
                '--extract) mkdir -p "$3" ;;\n'
                "*) exit 2 ;;\n"
                "esac\n"
            ),
            "sha256sum": (
                'test "$*" = "--check --strict"\n'
                "read -r checksum archive\n"
                'test -n "$checksum" && test -f "$archive"\n'
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            fake_bin = base / "bin"
            fake_bin.mkdir()
            for tool, body in fake_tools.items():
                path = fake_bin / tool
                path.write_text(f"#!/bin/sh\nset -eu\n{body}", encoding="utf-8")
                path.chmod(0o755)
            package_dir = base / "runtime-packages"
            package_dir.mkdir()
            for filename, (name, version) in archives.items():
                (package_dir / filename).write_text(
                    f"{name}\n{version}\n", encoding="utf-8"
                )
            runtime_root = base / "runtime-root"
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"

            result = subprocess.run(
                [
                    "sh",
                    str(POLICY.ROOT / POLICY.RUNTIME_PACKAGE_INSTALLER),
                    str(runtime_root),
                    str(package_dir),
                ],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )

            self.assertEqual(0, result.returncode, result.stderr)
            status = runtime_root / "var/lib/dpkg/status.d"
            for name, version in archives.values():
                self.assertEqual(
                    f"Package: {name}\nVersion: {version}\n",
                    (status / name).read_text(encoding="utf-8"),
                )
                self.assertTrue((status / f"{name}.md5sums").is_file())

    def test_release_images_pin_dated_runtime_package_inputs(self) -> None:
        relative = Path("release/docker/Dockerfile.evidence")
        for name, package in POLICY.RUNTIME_PACKAGES.items():
            for runtime_package_add in POLICY.RUNTIME_PACKAGE_ADDS:
                if f"/{name}_" not in runtime_package_add:
                    continue
                with (
                    self.subTest(runtime_package_add=runtime_package_add),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    root = Path(temporary)
                    self.repository_copy(root)
                    dockerfile = root / relative
                    dockerfile.write_text(
                        dockerfile.read_text(encoding="utf-8").replace(
                            runtime_package_add,
                            runtime_package_add.replace(
                                package["snapshot"], "latest"
                            ),
                            1,
                        ),
                        encoding="utf-8",
                    )

                    failures = POLICY.check_repository(root)

                    self.assertTrue(
                        any(
                            str(relative) in failure
                            and "fixed runtime package input" in failure
                            for failure in failures
                        ),
                        failures,
                    )

    def test_images_refuse_a_missing_security_package_input(self) -> None:
        discovery = (POLICY.ROOT / "release/docker/Dockerfile.discovery").read_text(
            encoding="utf-8"
        )
        security_adds = []
        for marker in (
            "/libssl3t64_3.5.7-1~deb13u3_",
            "/zlib1g_1.3.dfsg+really1.3.1-1+deb13u1_",
        ):
            package_adds = [
                line
                for line in discovery.splitlines()
                if line.startswith("ADD ") and marker in line
            ]
            self.assertEqual(2, len(package_adds), marker)
            security_adds += package_adds
        for relative in POLICY.DOCKERFILES + POLICY.ADOPTER_DOCKERFILES:
            for security_add in security_adds:
                with (
                    self.subTest(relative=relative, security_add=security_add),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    root = Path(temporary)
                    self.repository_copy(root)
                    dockerfile = root / relative
                    text = dockerfile.read_text(encoding="utf-8")
                    self.assertIn(f"{security_add}\n", text)
                    dockerfile.write_text(
                        text.replace(f"{security_add}\n", "", 1),
                        encoding="utf-8",
                    )

                    failures = POLICY.check_repository(root)

                    self.assertTrue(
                        any(
                            str(relative) in failure
                            and "fixed runtime package input" in failure
                            for failure in failures
                        ),
                        failures,
                    )

    def test_release_images_require_the_fixed_runtime_package_overlay(self) -> None:
        for relative in POLICY.DOCKERFILES:
            with (
                self.subTest(relative=relative),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                self.repository_copy(root)
                dockerfile = root / relative
                dockerfile.write_text(
                    dockerfile.read_text(encoding="utf-8").replace(
                        POLICY.RUNTIME_PACKAGE_COMMAND,
                        "/bin/true",
                        1,
                    ),
                    encoding="utf-8",
                )

                failures = POLICY.check_repository(root)

                self.assertTrue(
                    any(
                        str(relative) in failure
                        and "fixed runtime package overlay" in failure
                        for failure in failures
                    ),
                    failures,
                )

    def test_adopter_images_keep_libc_root_owned_and_normalize_metadata(self) -> None:
        relative = Path("docker/Dockerfile")
        mutations = (
            (
                "chown -R 65532:65532 /workspace/runtime-root/var/lib/registry-evidence",
                "chown -R 65532:65532 /workspace/runtime-root",
                "must not make the complete libc root nonroot-owned",
            ),
            (
                POLICY.RUNTIME_ROOT_NORMALIZATION,
                "/bin/true",
                "each adopter runtime must normalize fixed runtime package metadata",
            ),
        )
        for original, replacement, expected in mutations:
            with (
                self.subTest(expected=expected),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                self.repository_copy(root)
                dockerfile = root / relative
                dockerfile.write_text(
                    dockerfile.read_text(encoding="utf-8").replace(
                        original, replacement, 1
                    ),
                    encoding="utf-8",
                )

                failures = POLICY.check_repository(root)

                self.assertTrue(
                    any(expected in failure for failure in failures), failures
                )

    def test_http_probed_images_bind_fixed_config_and_entrypoint(self) -> None:
        # A service that reads no environment variable binds its configuration
        # through the command; one that declares an environment binds it there.
        wrong = {
            "environment": "ENV WRONG_CONFIG=/tmp/config.yaml",
            "command": 'CMD ["--runtime", "/tmp/runtime.yaml"]',
        }
        for relative, contract in POLICY.HTTP_PROBE_DOCKERFILES.items():
            key = "environment" if "environment" in contract else "command"
            with self.subTest(relative=relative, key=key):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.repository_copy(root)
                    dockerfile = root / relative
                    dockerfile.write_text(
                        dockerfile.read_text(encoding="utf-8").replace(
                            contract[key],
                            wrong[key],
                        ),
                        encoding="utf-8",
                    )
                    failures = POLICY.check_repository(root)
                    self.assertTrue(
                        any(
                            str(relative) in failure
                            and f"fixed {contract['binary']} {key}" in failure
                            for failure in failures
                        ),
                        failures,
                    )

    def test_stateful_images_carry_their_operator_tool_beside_the_runtime(
        self,
    ) -> None:
        self.assertEqual(
            {
                Path("release/docker/Dockerfile.breg"): "bregctl",
                Path("release/docker/Dockerfile.casework"): "caseworkctl",
                Path("release/docker/Dockerfile.scheduling"): "schedulingctl",
                Path("release/docker/Dockerfile.messaging"): "messagingctl",
                Path("release/docker/Dockerfile.coordinator"): "coordinatorctl",
            },
            {
                relative: contract["tool"]
                for relative, contract in POLICY.HTTP_PROBE_DOCKERFILES.items()
                if "tool" in contract
            },
        )
        self.assertEqual([], POLICY.check_repository())

    def test_operator_tool_install_is_required_and_normalized(self) -> None:
        for relative, contract in POLICY.HTTP_PROBE_DOCKERFILES.items():
            if "tool" not in contract:
                continue
            tool = contract["tool"]
            command = (
                f"install -m 0755 /workspace/image-bin/{tool} "
                f"/workspace/runtime-root/usr/local/bin/{tool}"
            )
            install = f"    && {command} \\\n"
            normalization = f"    && {POLICY.RUNTIME_ROOT_NORMALIZATION}\n"
            mutations = {
                "missing": lambda text: text.replace(install, ""),
                "after normalization": lambda text: text.replace(
                    install, ""
                ).replace(
                    normalization,
                    normalization.rstrip("\n") + f" \\\n    && {command}\n",
                ),
            }
            for case, mutate in mutations.items():
                with self.subTest(relative=relative, case=case):
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        self.repository_copy(root)
                        dockerfile = root / relative
                        text = dockerfile.read_text(encoding="utf-8")
                        self.assertIn(install, text)
                        mutated = mutate(text)
                        self.assertNotEqual(text, mutated)
                        dockerfile.write_text(mutated, encoding="utf-8")
                        failures = POLICY.check_repository(root)
                        self.assertTrue(
                            any(
                                str(relative) in failure and tool in failure
                                for failure in failures
                            ),
                            failures,
                        )

    def test_operator_tools_cannot_be_optional(self) -> None:
        for relative, contract in POLICY.HTTP_PROBE_DOCKERFILES.items():
            if "tool" not in contract:
                continue
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.repository_copy(root)
                    dockerfile = root / relative
                    tool = contract["tool"]
                    command = (
                        f"install -m 0755 /workspace/image-bin/{tool} "
                        f"/workspace/runtime-root/usr/local/bin/{tool}"
                    )
                    text = dockerfile.read_text(encoding="utf-8")
                    mutated = text.replace(
                        f"    && {command} \\\n",
                        f"    && if [ -e /workspace/image-bin/{tool} ]; then \\\n"
                        f"        {command}; \\\n"
                        "    fi \\\n",
                    )
                    self.assertNotEqual(text, mutated)
                    dockerfile.write_text(mutated, encoding="utf-8")

                    failures = POLICY.check_repository(root)

                    self.assertTrue(
                        any(
                            str(relative) in failure
                            and "must be required by every release image build"
                            in failure
                            for failure in failures
                        ),
                        failures,
                    )

    def test_operator_tool_never_becomes_the_image_entrypoint(self) -> None:
        for relative, contract in POLICY.HTTP_PROBE_DOCKERFILES.items():
            if "tool" not in contract:
                continue
            tool = contract["tool"]
            for replacement in (
                f'ENTRYPOINT ["/usr/local/bin/{tool}"]',
                contract["entrypoint"] + f'\nENTRYPOINT ["/usr/local/bin/{tool}"]',
            ):
                with self.subTest(relative=relative, replacement=replacement):
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        self.repository_copy(root)
                        dockerfile = root / relative
                        dockerfile.write_text(
                            dockerfile.read_text(encoding="utf-8").replace(
                                contract["entrypoint"], replacement
                            ),
                            encoding="utf-8",
                        )
                        failures = POLICY.check_repository(root)
                        self.assertTrue(
                            any(
                                str(relative) in failure
                                and "ENTRYPOINT" in failure
                                or f"fixed {contract['binary']} entrypoint" in failure
                                for failure in failures
                            ),
                            failures,
                        )

    def test_image_without_an_environment_contract_declares_no_environment(
        self,
    ) -> None:
        # An unbound ENV would be a second configuration source the contract
        # does not describe, so declaring no environment must mean carrying none.
        for relative, contract in POLICY.HTTP_PROBE_DOCKERFILES.items():
            if "environment" in contract:
                continue
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.repository_copy(root)
                    dockerfile = root / relative
                    dockerfile.write_text(
                        dockerfile.read_text(encoding="utf-8").replace(
                            contract["entrypoint"],
                            "ENV SMUGGLED_CONFIG=/tmp/config.yaml\n"
                            + contract["entrypoint"],
                        ),
                        encoding="utf-8",
                    )
                    failures = POLICY.check_repository(root)
                    self.assertTrue(
                        any(
                            str(relative) in failure
                            and "must declare no runtime environment" in failure
                            for failure in failures
                        ),
                        failures,
                    )






    def test_adopter_image_is_a_required_maintained_surface(self) -> None:
        self.assertEqual(
            (Path("docker/Dockerfile"),),
            POLICY.ADOPTER_DOCKERFILES,
        )
        self.assertIn(Path("docker/Dockerfile"), POLICY.MAINTAINED_TEXT_PATHS)

    def test_adopter_image_requires_pinned_upstream_bases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository_copy(root)
            dockerfile = root / "docker/Dockerfile"
            dockerfile.write_text(
                dockerfile.read_text(encoding="utf-8").replace(
                    f"FROM {POLICY.RUST_BUILDER} AS chef",
                    "FROM rust:1.95-trixie AS chef",
                ),
                encoding="utf-8",
            )

            failures = POLICY.check_repository(root)

            self.assertTrue(
                any(
                    "docker/Dockerfile" in failure
                    and "upstream base is not pinned" in failure
                    for failure in failures
                ),
                failures,
            )

    def test_adopter_distroless_stages_forbid_shell_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository_copy(root)
            dockerfile = root / "docker/Dockerfile"
            dockerfile.write_text(
                dockerfile.read_text(encoding="utf-8").replace(
                    "COPY --from=evidence-builder /workspace/runtime-root/ /\n",
                    "COPY --from=evidence-builder /workspace/runtime-root/ /\n"
                    "RUN /bin/sh -c true\n",
                    1,
                ),
                encoding="utf-8",
            )

            failures = POLICY.check_repository(root)

            self.assertTrue(
                any(
                    "docker/Dockerfile" in failure
                    and "Distroless runtime contains" in failure
                    for failure in failures
                ),
                failures,
            )


if __name__ == "__main__":
    unittest.main()
