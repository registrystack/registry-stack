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
                Path("release/docker/Dockerfile.mint"),
                Path("release/docker/Dockerfile.breg"),
                Path("release/docker/Dockerfile.relay"),
            },
            set(POLICY.DOCKERFILES),
        )
        self.assertEqual(
            {
                Path("release/docker/Dockerfile.discovery"),
                Path("release/docker/Dockerfile.evidence"),
                Path("release/docker/Dockerfile.mint"),
                Path("release/docker/Dockerfile.breg"),
            },
            set(POLICY.HTTP_PROBE_DOCKERFILES),
        )

    def test_release_builder_pins_base_snapshot_and_native_tools(self) -> None:
        self.assertEqual(
            (Path("release/docker/Dockerfile.builder"),),
            POLICY.RUST_BUILDER_DOCKERFILES,
        )
        mutations = (
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
                POLICY.RUST_BUILDER_LIBCLANG,
                "libclang-19-dev",
                "exact libclang build package",
            ),
            (
                POLICY.RUST_BUILDER_PROTOC,
                "protobuf-compiler",
                "exact protobuf build package",
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

    def test_http_probed_images_bind_fixed_config_and_entrypoint(self) -> None:
        # Discovery reads no environment variable, so its configuration binding
        # is the command; the others bind it through the environment.
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
                    'CMD ["serve", "--runtime", "/etc/relay/runtime.yaml"]',
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

    def test_mint_and_evidence_image_is_a_required_maintained_surface(self) -> None:
        self.assertEqual(
            (Path("docker/Dockerfile"),),
            POLICY.ADOPTER_DOCKERFILES,
        )
        self.assertIn(Path("docker/Dockerfile"), POLICY.MAINTAINED_TEXT_PATHS)

    def test_mint_and_evidence_image_requires_pinned_upstream_bases(self) -> None:
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

    def test_mint_and_evidence_distroless_stages_forbid_shell_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository_copy(root)
            dockerfile = root / "docker/Dockerfile"
            dockerfile.write_text(
                dockerfile.read_text(encoding="utf-8").replace(
                    "COPY --from=mint-builder /workspace/runtime-root/ /\n",
                    "COPY --from=mint-builder /workspace/runtime-root/ /\n"
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
