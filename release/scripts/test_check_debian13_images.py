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

    def test_every_dockerfile_base_requires_an_immutable_digest(self) -> None:
        for relative in self.module.DOCKERFILES:
            with self.subTest(relative=relative):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                base = self.module.FROM_RE.findall(text)[0]
                self.assertIn("@sha256:", base)
                target.write_text(
                    text.replace(base, base.split("@sha256:", 1)[0], 1),
                    encoding="utf-8",
                )
                self.assert_has_failure(
                    root,
                    f"{relative}: upstream base is not pinned by immutable digest",
                )

    def test_distroless_runtime_is_the_final_dockerfile_stage(self) -> None:
        pinned_alpine = "alpine:3.22@sha256:" + "a" * 64
        for relative in self.module.DOCKERFILES:
            additions = (
                f"\nFROM {pinned_alpine} AS debug\n",
                f"\n# FROM {self.module.DISTROLESS_RUNTIME} AS runtime\n"
                f"FROM {self.module.DEBIAN_PREPARATION} AS debug\n",
            )
            for addition in additions:
                with self.subTest(relative=relative, addition=addition):
                    root = self.fixture()
                    target = root / relative
                    text = target.read_text(encoding="utf-8")
                    target.write_text(text + addition, encoding="utf-8")
                    self.assert_has_failure(
                        root,
                        f"{relative}: final Dockerfile stage must use pinned "
                        "Distroless Debian 13 runtime",
                    )

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
                    f"{relative}: missing Distroless Debian 13 non-root final runtime",
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
