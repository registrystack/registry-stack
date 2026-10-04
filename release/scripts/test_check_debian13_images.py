# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the maintained Debian 13 image policy."""

from __future__ import annotations

import importlib.util
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

    def test_relay_v2_image_is_a_required_maintained_surface(self) -> None:
        self.assertIn(Path("release/docker/Dockerfile.relay"), POLICY.DOCKERFILES)
        self.assertNotIn(
            Path("release/docker/Dockerfile.registry-relay"), POLICY.DOCKERFILES
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository_copy(root)
            dockerfile = root / "release/docker/Dockerfile.relay"
            dockerfile.write_text(
                dockerfile.read_text(encoding="utf-8").replace(
                    'ENTRYPOINT ["/usr/local/bin/relay"]',
                    'ENTRYPOINT ["relay"]',
                ),
                encoding="utf-8",
            )

            failures = POLICY.check_repository(root)

            self.assertTrue(
                any(
                    "Dockerfile.relay" in failure
                    and "absolute Relay V2 entrypoint" in failure
                    for failure in failures
                ),
                failures,
            )

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
                Path("release/docker/Dockerfile.relay"),
                Path("release/docker/Dockerfile.scheduling"),
                Path("release/docker/Dockerfile.messaging"),
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

    def test_runtime_package_overlay_fixes_libc6_and_libssl3t64(self) -> None:
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

    def test_release_images_pin_dated_runtime_package_inputs(self) -> None:
        relative = Path("release/docker/Dockerfile.relay")
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

    def test_images_refuse_a_missing_libssl3t64_package_input(self) -> None:
        libssl_adds = [
            line
            for line in (POLICY.ROOT / "release/docker/Dockerfile.discovery")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.startswith("ADD ") and "/libssl3t64_3.5.7-1~deb13u3_" in line
        ]
        self.assertEqual(2, len(libssl_adds))
        for relative in POLICY.DOCKERFILES + POLICY.ADOPTER_DOCKERFILES:
            for libssl_add in libssl_adds:
                with (
                    self.subTest(relative=relative, libssl_add=libssl_add),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    root = Path(temporary)
                    self.repository_copy(root)
                    dockerfile = root / relative
                    text = dockerfile.read_text(encoding="utf-8")
                    self.assertIn(f"{libssl_add}\n", text)
                    dockerfile.write_text(
                        text.replace(f"{libssl_add}\n", "", 1),
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

    def test_relay_v2_image_binds_the_runtime_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository_copy(root)
            dockerfile = root / "release/docker/Dockerfile.relay"
            dockerfile.write_text(
                dockerfile.read_text(encoding="utf-8").replace(
                    'CMD ["serve", "--runtime-config", "/etc/relay/runtime.yaml"]',
                    'CMD ["serve"]',
                ),
                encoding="utf-8",
            )

            failures = POLICY.check_repository(root)

            self.assertTrue(
                any(
                    "Dockerfile.relay" in failure
                    and "runtime configuration binding" in failure
                    for failure in failures
                ),
                failures,
            )

    def test_relay_v2_release_recipe_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository_copy(root)

            self.assertEqual([], POLICY.check_repository(root))

    def test_relay_v2_rejects_runtime_preparation_mutations(self) -> None:
        mutations = (
            "chown 65532:65532 /workspace/runtime-root/etc/relay",
            "chown -R 65532:65532 /workspace/runtime-root/etc",
            "chmod 0777 /workspace/runtime-root/etc",
            "chmod g+w /workspace/runtime-root",
            "install -d -o 65532 -g 65532 -m 0777 /workspace/runtime-root/etc",
            "chmod 0777 /workspace/runtime-root/etc/*",
            "chown 65532:65532 `/bin/echo /workspace/runtime-root/etc`",
            "command cd /workspace/runtime-root && chmod 0777 etc",
            "(cd /workspace/runtime-root && chmod 0777 etc)",
            "( cd /workspace/runtime-root && chmod 0777 etc )",
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                self.repository_copy(root)
                dockerfile = root / "release/docker/Dockerfile.relay"
                dockerfile.write_text(
                    dockerfile.read_text(encoding="utf-8").replace(
                        "    && find /workspace/runtime-root",
                        f"    && {mutation} \\\n    && find /workspace/runtime-root",
                    ),
                    encoding="utf-8",
                )

                failures = POLICY.check_repository(root)
                self.assertTrue(
                    any("runtime preparation stage" in failure for failure in failures),
                    failures,
                )

        for replacement in (
            "install -d -o 65532 -g 65532 -m 0755",
            "install -d -o 0 -g 0 -m 0775",
        ):
            with (
                self.subTest(replacement=replacement),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                self.repository_copy(root)
                dockerfile = root / "release/docker/Dockerfile.relay"
                dockerfile.write_text(
                    dockerfile.read_text(encoding="utf-8").replace(
                        "install -d -o 0 -g 0 -m 0755", replacement, 1
                    ),
                    encoding="utf-8",
                )
                self.assertTrue(
                    any(
                        "runtime preparation stage" in failure
                        for failure in POLICY.check_repository(root)
                    )
                )

    def test_relay_v2_rejects_runtime_copy_mutations(self) -> None:
        canonical = "COPY --from=runtime-root /workspace/runtime-root/ /"
        runtime_base = f"FROM {POLICY.DISTROLESS_RUNTIME} AS runtime"
        mutations = (
            "COPY --from=runtime-root --chown=65532:65532 /workspace/runtime-root/ /",
            "COPY --from=runtime-root --chown 65532:65532 /workspace/runtime-root/ /",
            "COPY --from=runtime-root --chmod=0777 /workspace/runtime-root/ /",
            canonical + "\nCOPY --from=runtime-root --chmod=0777 "
            "/workspace/runtime-root/etc/ /etc/",
            canonical + "\nCOPY --from=runtime-root --chown=65532:65532 "
            "/workspace/runtime-root/etc /",
            canonical + f"\n{runtime_base}-shadow",
            canonical + f"\n{runtime_base}",
            canonical + "\nADD --chown=65532:65532 --chmod=0777 LICENSE /etc/relay/",
            canonical + "\nUSER 0",
            canonical
            + f"\nFROM {POLICY.DISTROLESS_RUNTIME} AS post\n"
            + "COPY --from=runtime-root /workspace/runtime-root/ /\nUSER 0",
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                self.repository_copy(root)
                dockerfile = root / "release/docker/Dockerfile.relay"
                dockerfile.write_text(
                    dockerfile.read_text(encoding="utf-8").replace(canonical, mutation),
                    encoding="utf-8",
                )
                failures = POLICY.check_repository(root)
                self.assertTrue(
                    any(
                        "metadata-preserving release recipe" in failure
                        for failure in failures
                    ),
                    failures,
                )

    def test_relay_v2_image_healthcheck_endpoint_is_configurable(self) -> None:
        mutations = (
            (
                "ENV RELAY_HEALTHCHECK_URL=http://127.0.0.1:8080/health",
                "ENV RELAY_HEALTHCHECK_URL=http://127.0.0.1:18080/health",
                "safe configurable Relay V2 healthcheck default",
            ),
            (
                'CMD ["/usr/local/bin/relay", "healthcheck"]',
                'CMD ["/usr/local/bin/relay", "healthcheck", "--url", '
                '"http://127.0.0.1:8080/health"]',
                "environment-aware Relay V2 healthcheck",
            ),
        )
        for original, replacement, expected in mutations:
            with self.subTest(expected=expected):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.repository_copy(root)
                    dockerfile = root / "release/docker/Dockerfile.relay"
                    dockerfile.write_text(
                        dockerfile.read_text(encoding="utf-8").replace(
                            original,
                            replacement,
                        ),
                        encoding="utf-8",
                    )

                    failures = POLICY.check_repository(root)

                    self.assertTrue(
                        any(
                            "Dockerfile.relay" in failure and expected in failure
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
