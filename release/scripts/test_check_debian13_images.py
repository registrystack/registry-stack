#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release/scripts/check-debian13-images.py"
TUTORIAL_CHECK = Path("docs/site/scripts/check-registryctl-tutorials.sh")
RELEASE_WORKFLOW = Path(".github/workflows/release.yml")
RELEASE_BINARY_RECIPE = Path("release/scripts/build-release-binaries.sh")
LIVE_JOURNEY = Path(
    "crates/registry-relay/scripts/run-live-consultation-journey.sh"
)
CI_WORKFLOW = Path(".github/workflows/ci.yml")

EXPECTED_SURFACES = {
    CI_WORKFLOW,
    RELEASE_WORKFLOW,
    Path("crates/registry-relay/Dockerfile"),
    Path("crates/registry-relay/Dockerfile.demo"),
    Path("crates/registry-relay/docs/ops.md"),
    Path("crates/registry-relay/docs/security-assurance.md"),
    Path("crates/registry-relay/scripts/check_docker_build_contract.py"),
    LIVE_JOURNEY,
    TUTORIAL_CHECK,
    Path("products/notary/Dockerfile"),
    Path("products/notary/docs/security-assurance.md"),
    Path("release/docker/Dockerfile.registry-notary"),
    Path("release/docker/Dockerfile.registry-relay"),
    RELEASE_BINARY_RECIPE,
}


def load_module():
    spec = importlib.util.spec_from_file_location("check_debian13_images", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Debian13ImageCheckTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def fixture(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative in self.module.MAINTAINED_TEXT_PATHS:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        return root

    def assert_has_failure(
        self,
        root: Path,
        fragment: str,
    ) -> None:
        failures = self.module.check_repository(root)
        self.assertTrue(
            any(fragment in failure for failure in failures),
            failures,
        )

    def runtime_directives(self, relative: Path) -> tuple[str, str, str]:
        product = "relay" if relative in self.module.RELAY_DOCKERFILES else "notary"
        binary = f"/usr/local/bin/registry-{product}"
        return (
            "HEALTHCHECK --interval=30s --timeout=5s "
            f'--start-period=10s --retries=3 CMD ["{binary}", "healthcheck"]',
            f'ENTRYPOINT ["{binary}"]',
            f"WORKDIR /var/lib/registry-{product}",
        )

    def test_current_repository_follows_contract(self) -> None:
        self.assertEqual([], self.module.check_repository(ROOT))

    def test_inventory_covers_every_maintained_surface(self) -> None:
        self.assertEqual(EXPECTED_SURFACES, set(self.module.MAINTAINED_TEXT_PATHS))
        for relative in EXPECTED_SURFACES:
            with self.subTest(relative=relative):
                self.assertTrue((ROOT / relative).is_file())

        failures = self.module.check_repository(Path("/does-not-exist"))
        for relative in EXPECTED_SURFACES:
            with self.subTest(missing=relative):
                self.assertIn(
                    f"missing maintained image surface: {relative}",
                    failures,
                )

    def test_retired_markers_are_rejected_regardless_of_text_syntax(self) -> None:
        cases = (
            "# historical book" + "worm image\n",
            'IMAGE="debian' + '12"\n',
            "base: Debian 12\n",
            "base: debian-12\n",
            "base: debian_12\n",
            "base: debian:12\n",
            "base: Debian v12\n",
            '{"base": "BOOK' + 'WORM"}\n',
        )
        for suffix in cases:
            with self.subTest(suffix=suffix):
                root = self.fixture()
                target = root / TUTORIAL_CHECK
                target.write_text(
                    target.read_text(encoding="utf-8") + suffix,
                    encoding="utf-8",
                )
                self.assert_has_failure(
                    root,
                    f"{TUTORIAL_CHECK}: retired Debian image generation marker remains",
                )

    def test_retired_marker_does_not_expand_to_slash_or_dot_separators(
        self,
    ) -> None:
        for suffix in (
            "base: Debian/12\n",
            "base: Debian.12\n",
            "base: Debian/v12\n",
            "base: Debian.v12\n",
        ):
            with self.subTest(suffix=suffix):
                root = self.fixture()
                target = root / TUTORIAL_CHECK
                target.write_text(
                    target.read_text(encoding="utf-8") + suffix,
                    encoding="utf-8",
                )
                self.assertEqual([], self.module.check_repository(root))

    def test_tutorial_builder_must_match_the_exact_pinned_image(self) -> None:
        exact = f'BUILDER_IMAGE="{self.module.RUST_BUILDER}"'
        cases = (
            "",
            'BUILDER_IMAGE="rust:1.94-trixie@sha256:' + "a" * 64 + '"',
            'BUILDER_IMAGE="rust:1.95-trixie"',
        )
        for replacement in cases:
            with self.subTest(replacement=replacement):
                root = self.fixture()
                target = root / TUTORIAL_CHECK
                text = target.read_text(encoding="utf-8")
                self.assertIn(exact, text)
                target.write_text(
                    text.replace(exact, replacement, 1),
                    encoding="utf-8",
                )
                self.assert_has_failure(
                    root,
                    "missing pinned Debian 13 registryctl tutorial builder",
                )

    def test_builder_contract_lines_cannot_be_shadowed_by_comments(self) -> None:
        pin = self.module.RUST_BUILDER
        cases = (
            (
                RELEASE_WORKFLOW,
                f"  RELEASE_BUILDER_IMAGE: {pin}",
                f"  # RELEASE_BUILDER_IMAGE: {pin}\n"
                "  RELEASE_BUILDER_IMAGE: rust:1.95-trixie",
                "missing pinned Debian 13 release builder",
            ),
            (
                RELEASE_BINARY_RECIPE,
                f'default_builder_image="{pin}"',
                f'# default_builder_image="{pin}"\n'
                'default_builder_image="rust:1.95-trixie"',
                "missing pinned Debian 13 release recipe builder",
            ),
            (
                TUTORIAL_CHECK,
                f'BUILDER_IMAGE="{pin}"',
                f'# BUILDER_IMAGE="{pin}"\nBUILDER_IMAGE="rust:1.95-trixie"',
                "missing pinned Debian 13 registryctl tutorial builder",
            ),
            (
                LIVE_JOURNEY,
                f"    {pin} \\",
                f"    # {pin} \\\n    rust:1.95-trixie \\",
                "missing pinned Debian 13 live-journey builder",
            ),
        )
        for relative, exact, replacement, failure in cases:
            with self.subTest(relative=relative):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                self.assertIn(exact, text)
                target.write_text(
                    text.replace(exact, replacement, 1),
                    encoding="utf-8",
                )
                self.assert_has_failure(root, failure)

    def test_builder_contracts_reject_earlier_and_later_active_overrides(
        self,
    ) -> None:
        pin = self.module.RUST_BUILDER
        cases = (
            (
                RELEASE_WORKFLOW,
                f"  RELEASE_BUILDER_IMAGE: {pin}",
                "  RELEASE_BUILDER_IMAGE: rust:1.95-trixie",
                "missing pinned Debian 13 release builder",
            ),
            (
                RELEASE_BINARY_RECIPE,
                f'default_builder_image="{pin}"',
                'default_builder_image="rust:1.95-trixie"',
                "missing pinned Debian 13 release recipe builder",
            ),
            (
                TUTORIAL_CHECK,
                f'BUILDER_IMAGE="{pin}"',
                'BUILDER_IMAGE="rust:1.95-trixie"',
                "missing pinned Debian 13 registryctl tutorial builder",
            ),
        )
        for relative, exact, override, failure in cases:
            for replacement in (f"{override}\n{exact}", f"{exact}\n{override}"):
                with self.subTest(relative=relative, replacement=replacement):
                    root = self.fixture()
                    target = root / relative
                    text = target.read_text(encoding="utf-8")
                    target.write_text(
                        text.replace(exact, replacement, 1),
                        encoding="utf-8",
                    )
                    self.assert_has_failure(root, failure)

        root = self.fixture()
        target = root / LIVE_JOURNEY
        exact = f"    {pin} \\"
        text = target.read_text(encoding="utf-8")
        target.write_text(
            text.replace(exact, exact + "\n    rust:1.95-trixie \\", 1),
            encoding="utf-8",
        )
        self.assert_has_failure(
            root,
            "missing pinned Debian 13 live-journey builder",
        )

    def test_shell_builder_contracts_allow_only_one_canonical_assignment(
        self,
    ) -> None:
        pin = self.module.RUST_BUILDER
        cases = (
            (
                RELEASE_BINARY_RECIPE,
                f'default_builder_image="{pin}"',
                "default_builder_image",
                "missing pinned Debian 13 release recipe builder",
            ),
            (
                TUTORIAL_CHECK,
                f'BUILDER_IMAGE="{pin}"',
                "BUILDER_IMAGE",
                "missing pinned Debian 13 registryctl tutorial builder",
            ),
        )
        for relative, exact, variable, failure in cases:
            for prefix in ("readonly ", "export "):
                with self.subTest(
                    relative=relative,
                    prefix=prefix,
                    valid=True,
                ):
                    root = self.fixture()
                    target = root / relative
                    text = target.read_text(encoding="utf-8")
                    target.write_text(
                        text.replace(exact, prefix + exact, 1),
                        encoding="utf-8",
                    )
                    self.assertEqual([], self.module.check_repository(root))

            invalid_replacements = (
                f"readonly {exact}\nexport {exact}",
                f'readonly {variable}="rust:1.95-trixie"',
                f'export {variable}="rust:1.95-trixie"',
            )
            for replacement in invalid_replacements:
                with self.subTest(
                    relative=relative,
                    replacement=replacement,
                    valid=False,
                ):
                    root = self.fixture()
                    target = root / relative
                    text = target.read_text(encoding="utf-8")
                    target.write_text(
                        text.replace(exact, replacement, 1),
                        encoding="utf-8",
                    )
                    self.assert_has_failure(root, failure)

    def test_builder_handoffs_and_docker_consumers_remain_exact(self) -> None:
        cases = (
            (
                RELEASE_BINARY_RECIPE,
                self.module.RELEASE_BUILDER_HANDOFF,
                'release_builder_image="rust:1.95-trixie"',
                "missing release builder handoff",
            ),
            (
                RELEASE_BINARY_RECIPE,
                self.module.RELEASE_BUILDER_CONSUMER,
                '  "rust:1.95-trixie" \\',
                "missing release Docker builder consumer",
            ),
            (
                TUTORIAL_CHECK,
                self.module.TUTORIAL_BUILDER_CONSUMER,
                '\t\t"rust:1.95-trixie" \\',
                "missing registryctl tutorial Docker builder consumer",
            ),
        )
        for relative, exact, unpinned, failure in cases:
            for replacement in (unpinned, f"{exact}\n{exact}"):
                with self.subTest(
                    relative=relative,
                    replacement=replacement,
                ):
                    root = self.fixture()
                    target = root / relative
                    text = target.read_text(encoding="utf-8")
                    self.assertIn(exact, text)
                    target.write_text(
                        text.replace(exact, replacement, 1),
                        encoding="utf-8",
                    )
                    self.assert_has_failure(root, failure)

    def test_every_dockerfile_base_requires_an_immutable_digest(self) -> None:
        for relative in self.module.DOCKERFILES:
            with self.subTest(relative=relative):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                base = next(self.module.FROM_RE.finditer(text)).group("base")
                self.assertIn("@sha256:", base)
                target.write_text(
                    text.replace(base, base.split("@sha256:", 1)[0], 1),
                    encoding="utf-8",
                )
                self.assert_has_failure(
                    root,
                    f"{relative}: upstream base is not pinned by immutable digest",
                )

    def test_dockerfile_stages_reject_forced_platforms(self) -> None:
        for relative in self.module.DOCKERFILES:
            for stage_index in (0, 1):
                with self.subTest(
                    relative=relative,
                    stage_index=stage_index,
                ):
                    root = self.fixture()
                    target = root / relative
                    text = target.read_text(encoding="utf-8")
                    stage = list(self.module.FROM_RE.finditer(text))[stage_index]
                    original = stage.group(0)
                    forced = original.replace(
                        "FROM ",
                        "FROM --platform=linux/amd64 ",
                        1,
                    )
                    target.write_text(
                        text[: stage.start()] + forced + text[stage.end() :],
                        encoding="utf-8",
                    )
                    self.assert_has_failure(
                        root,
                        f"{relative}: Dockerfile stage sequence must be exactly",
                    )

    def test_distroless_runtime_is_the_final_dockerfile_stage(self) -> None:
        pinned_alpine = "alpine:3.22@sha256:" + "a" * 64
        for relative in self.module.DOCKERFILES:
            additions = (
                f"\n  from {pinned_alpine} as debug\n",
                f"\n# FROM {self.module.DISTROLESS_RUNTIME} AS runtime\n"
                f"  from {self.module.DEBIAN_PREPARATION} as debug\n",
            )
            for addition in additions:
                with self.subTest(relative=relative, addition=addition):
                    root = self.fixture()
                    target = root / relative
                    text = target.read_text(encoding="utf-8")
                    target.write_text(text + addition, encoding="utf-8")
                    self.assert_has_failure(
                        root,
                        f"{relative}: Dockerfile stage sequence must be exactly",
                    )

    def test_dockerfile_stage_sequence_rejects_aliases_duplicates_and_empty_runtime(
        self,
    ) -> None:
        runtime = f"FROM {self.module.DISTROLESS_RUNTIME} AS runtime"
        for relative in self.module.DOCKERFILES:
            with self.subTest(relative=relative, mutation="alias"):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                target.write_text(
                    text.replace(runtime, runtime.replace("runtime", "final"), 1),
                    encoding="utf-8",
                )
                self.assert_has_failure(
                    root,
                    f"{relative}: Dockerfile stage sequence must be exactly",
                )

            with self.subTest(relative=relative, mutation="duplicate"):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                target.write_text(text + f"\n{runtime}\n", encoding="utf-8")
                self.assert_has_failure(
                    root,
                    f"{relative}: Dockerfile stage sequence must be exactly",
                )

            with self.subTest(relative=relative, mutation="empty"):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                final_stage = list(self.module.FROM_RE.finditer(text))[-1]
                target.write_text(
                    text[: final_stage.end()] + "\n",
                    encoding="utf-8",
                )
                self.assert_has_failure(root, f"{relative}: missing binary healthcheck")

    def test_runtime_directives_must_be_active_in_the_final_stage(self) -> None:
        for relative in self.module.DOCKERFILES:
            for directive in self.runtime_directives(relative):
                with self.subTest(relative=relative, directive=directive):
                    root = self.fixture()
                    target = root / relative
                    text = target.read_text(encoding="utf-8")
                    final_stage = list(self.module.FROM_RE.finditer(text))[-1]
                    prefix = text[: final_stage.start()]
                    runtime = text[final_stage.start() :]
                    self.assertIn(f"\n{directive}\n", runtime)
                    runtime = runtime.replace(
                        f"\n{directive}\n",
                        f"\n# {directive}\n",
                        1,
                    )
                    target.write_text(
                        prefix + directive + "\n" + runtime,
                        encoding="utf-8",
                    )
                    self.assert_has_failure(root, f"{relative}: missing")

    def test_runtime_directive_overrides_and_users_are_rejected(self) -> None:
        overrides = (
            ("  healthcheck NONE", "exactly one active HEALTHCHECK"),
            ('  entrypoint ["/tmp/override"]', "exactly one active ENTRYPOINT"),
            ("  workdir /tmp", "exactly one active WORKDIR"),
            ("USER 0", "must inherit the nonroot base user"),
        )
        comments = "\n".join(
            (
                "# HEALTHCHECK NONE",
                '# ENTRYPOINT ["/tmp/override"]',
                "# WORKDIR /tmp",
                "# USER 0",
            )
        )
        for relative in self.module.DOCKERFILES:
            for override, failure in overrides:
                with self.subTest(relative=relative, override=override):
                    root = self.fixture()
                    target = root / relative
                    text = target.read_text(encoding="utf-8")
                    target.write_text(
                        text + f"\n{override}\n",
                        encoding="utf-8",
                    )
                    self.assert_has_failure(root, failure)

            with self.subTest(relative=relative, comments=True):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                target.write_text(
                    text + f"\n{comments}\n",
                    encoding="utf-8",
                )
                self.assertEqual([], self.module.check_repository(root))

    def test_tutorial_cache_is_bound_to_the_builder_script_without_fallback(
        self,
    ) -> None:
        exact = self.module.TUTORIAL_CACHE_KEY
        cases = (
            ("", "missing registryctl tutorial builder cache key"),
            (
                f"          # {exact.strip()}",
                "missing registryctl tutorial builder cache key",
            ),
            (
                "          key: registryctl-tutorial-${{ runner.os }}-"
                "${{ hashFiles('Cargo.lock') }}",
                "missing registryctl tutorial builder cache key",
            ),
            (
                exact
                + "\n          restore-keys: |\n"
                "            registryctl-tutorial-${{ runner.os }}-",
                "must not use restore-keys fallback",
            ),
            (
                exact
                + "\n          'restore-keys': |\n"
                "            registryctl-tutorial-${{ runner.os }}-",
                "must not use restore-keys fallback",
            ),
            (
                exact
                + '\n          "restore-keys": |\n'
                "            registryctl-tutorial-${{ runner.os }}-",
                "must not use restore-keys fallback",
            ),
        )
        for replacement, failure in cases:
            with self.subTest(replacement=replacement):
                root = self.fixture()
                target = root / CI_WORKFLOW
                text = target.read_text(encoding="utf-8")
                self.assertIn(exact, text)
                target.write_text(
                    text.replace(exact, replacement, 1),
                    encoding="utf-8",
                )
                self.assert_has_failure(root, failure)

        wrong_key = (
            "          key: registryctl-tutorial-${{ runner.os }}-"
            "${{ hashFiles('Cargo.lock') }}"
        )
        root = self.fixture()
        target = root / CI_WORKFLOW
        text = target.read_text(encoding="utf-8")
        target.write_text(
            text.replace(
                exact,
                wrong_key
                + "\n      - uses: example.invalid/cache@v1\n"
                "        with:\n"
                + exact,
                1,
            ),
            encoding="utf-8",
        )
        self.assert_has_failure(
            root,
            "missing registryctl tutorial builder cache key",
        )

        root = self.fixture()
        target = root / CI_WORKFLOW
        text = target.read_text(encoding="utf-8")
        target.write_text(
            text.replace(
                exact,
                exact
                + "\n      - run: true\n"
                "        env:\n"
                "          restore-keys: belongs-to-next-step",
                1,
            ),
            encoding="utf-8",
        )
        self.assertEqual([], self.module.check_repository(root))

    def test_every_runtime_stays_distroless_and_shell_free(self) -> None:
        marker = f"FROM {self.module.DISTROLESS_RUNTIME} AS runtime"
        mutable_runtime = "FROM debian:trixie-slim AS runtime"
        healthcheck = (
            "HEALTHCHECK --interval=30s --timeout=5s "
            "--start-period=10s --retries=3"
        )
        for relative in self.module.DOCKERFILES:
            with self.subTest(relative=relative, invariant="distroless"):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                self.assertIn(marker, text)
                target.write_text(
                    text.replace(marker, mutable_runtime, 1),
                    encoding="utf-8",
                )
                self.assert_has_failure(
                    root,
                    f"{relative}: Dockerfile stage sequence must be exactly",
                )

            with self.subTest(relative=relative, invariant="runtime"):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                self.assertIn(marker, text)
                target.write_text(
                    text.replace(marker, marker + "\nRUN true", 1),
                    encoding="utf-8",
                )
                self.assert_has_failure(
                    root,
                    f"{relative}: final Distroless runtime contains 'RUN'",
                )

            with self.subTest(relative=relative, invariant="healthcheck"):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                self.assertIn(healthcheck, text)
                target.write_text(
                    text.replace(healthcheck, "HEALTHCHECK --none", 1),
                    encoding="utf-8",
                )
                self.assert_has_failure(
                    root,
                    f"{relative}: missing binary healthcheck",
                )


if __name__ == "__main__":
    unittest.main()
