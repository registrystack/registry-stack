#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release/scripts/check-debian13-images.py"


def load_module():
    spec = importlib.util.spec_from_file_location("check_debian13_images", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Debian13ImageCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def copy_required_surfaces(self, root: Path) -> None:
        for relative in self.module.REQUIRED_PRODUCT_SURFACES:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)

    def test_real_repository_follows_debian13_contract(self) -> None:
        self.assertEqual([], self.module.check_repository(ROOT))

    def test_discovery_covers_dockerfiles_and_active_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dockerfile = Path("Dockerfile.worker")
            script = Path("docs/site/scripts/build-example.sh")
            note = Path("release/notes/v0.1.0.md")
            research = Path("docs/site/.research/container-notes.md")
            for relative in (dockerfile, script, note, research):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("fixture\n", encoding="utf-8")

            discovered = self.module.discover_maintained_surfaces(root)

            self.assertIn(dockerfile, discovered)
            self.assertIn(script, discovered)
            self.assertNotIn(note, discovered)
            self.assertNotIn(research, discovered)

    def test_discovered_dockerfile_rejects_retired_unpinned_base(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            dockerfile = root / "products/example/Dockerfile"
            dockerfile.parent.mkdir(parents=True, exist_ok=True)
            dockerfile.write_text(
                "FROM rust:1.95-" + "book" + "worm\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "retired Debian image generation marker" in failure
                    for failure in failures
                ),
                failures,
            )
            self.assertTrue(
                any(
                    "upstream base is not pinned by immutable digest" in failure
                    for failure in failures
                ),
                failures,
            )

    def test_discovered_script_rejects_unpinned_debian_derived_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "docs/site/scripts/build-example.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "#!/usr/bin/env bash\n"
                "docker run --rm rust:1.95-" + "trixie cargo build --locked\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "Debian-derived image reference is not pinned by immutable digest"
                    in failure
                    and "docs/site/scripts/build-example.sh:2" in failure
                    for failure in failures
                ),
                failures,
            )

    def test_discovered_script_rejects_version_only_debian_default_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "docs/site/scripts/build-example.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "#!/usr/bin/env bash\n"
                "docker run --rm node:22 npm test\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "Debian-derived image reference is not pinned by immutable digest"
                    in failure
                    and "docs/site/scripts/build-example.sh:2" in failure
                    and failure.endswith(": node:22")
                    for failure in failures
                ),
                failures,
            )

    def test_discovered_script_parses_docker_container_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "docs/site/scripts/build-example.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "#!/usr/bin/env bash\n"
                "docker container run --rm rust:1.95-trixie cargo build --locked\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "Debian-derived image reference is not pinned by immutable digest"
                    in failure
                    and "docs/site/scripts/build-example.sh:2" in failure
                    and failure.endswith(": rust:1.95-trixie")
                    for failure in failures
                ),
                failures,
            )

    def test_discovered_script_treats_docker_boolean_run_flags_as_valueless(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "docs/site/scripts/build-example.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "#!/usr/bin/env bash\n"
                "docker run --rm --init --no-healthcheck --oom-kill-disable debian true\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "docs/site/scripts/build-example.sh:2" in failure
                    and failure.endswith(": debian")
                    for failure in failures
                ),
                failures,
            )

    def test_discovered_script_rejects_untagged_debian_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "docs/site/scripts/build-example.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "#!/usr/bin/env bash\n"
                "docker run --rm debian apt-get update\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "Debian-derived image reference is not pinned by immutable digest"
                    in failure
                    and "docs/site/scripts/build-example.sh:2" in failure
                    and failure.endswith(": debian")
                    for failure in failures
                ),
                failures,
            )

    def test_discovered_yaml_rejects_untagged_debian_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            compose = root / "products/example/compose.yaml"
            compose.parent.mkdir(parents=True, exist_ok=True)
            compose.write_text(
                "services:\n"
                "  helper:\n"
                "    image: debian\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "Debian-derived image reference is not pinned by immutable digest"
                    in failure
                    and "products/example/compose.yaml:3" in failure
                    and failure.endswith(": debian")
                    for failure in failures
                ),
                failures,
            )

    def test_untagged_detection_ignores_comments_and_yaml_prose(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "docs/site/scripts/explain-example.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "# docker run --rm debian apt-get update\n",
                encoding="utf-8",
            )
            metadata = root / "products/example/metadata.yaml"
            metadata.parent.mkdir(parents=True, exist_ok=True)
            metadata.write_text(
                'description: "docker run --rm debian is an unsafe example"\n'
                "base: debian\n"
                "container_note: debian\n",
                encoding="utf-8",
            )

            self.assertEqual([], self.module.check_repository(root))

    def test_discovered_workflow_rejects_untagged_container_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            workflow = root / ".github/workflows/example.yml"
            workflow.parent.mkdir(parents=True, exist_ok=True)
            workflow.write_text(
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    container: debian\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    ".github/workflows/example.yml:4" in failure
                    and failure.endswith(": debian")
                    for failure in failures
                ),
                failures,
            )

    def test_discovered_js_ts_rejects_bare_image_declarations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "docs/site/scripts/images.ts"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                'const image = "debian";\n'
                "let builderImage: string = 'node:22';\n"
                'var container = "python:3.12";\n',
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(any("images.ts:1" in failure for failure in failures), failures)
            self.assertTrue(
                any(
                    "images.ts:2" in failure and failure.endswith(": node:22")
                    for failure in failures
                ),
                failures,
            )
            self.assertTrue(
                any(
                    "images.ts:3" in failure and failure.endswith(": python:3.12")
                    for failure in failures
                ),
                failures,
            )

    def test_wrapped_python_and_ts_image_assignments_keep_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            python_script = root / "products/example/scripts/build_image.py"
            python_script.parent.mkdir(parents=True, exist_ok=True)
            python_script.write_text(
                "BUILDER_IMAGE = (\n"
                "    'rust:1.95-trixie'\n"
                ")\n",
                encoding="utf-8",
            )
            ts_script = root / "docs/site/scripts/images.ts"
            ts_script.parent.mkdir(parents=True, exist_ok=True)
            ts_script.write_text(
                "const builderImage =\n"
                "  'node:22';\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "products/example/scripts/build_image.py:2" in failure
                    and failure.endswith(": rust:1.95-trixie")
                    for failure in failures
                ),
                failures,
            )
            self.assertTrue(
                any(
                    "docs/site/scripts/images.ts:2" in failure
                    and failure.endswith(": node:22")
                    for failure in failures
                ),
                failures,
            )

    def test_registryctl_tutorial_cache_key_must_include_builder_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            tutorial = root / self.module.REGISTRYCTL_TUTORIAL_SCRIPT
            text = tutorial.read_text(encoding="utf-8")
            tutorial.write_text(
                text.replace(
                    'BUILDER_CACHE_KEY="${BUILDER_IMAGE##*@sha256:}"\n',
                    "",
                ).replace(
                    "registryctl-tutorial-linux-amd64-$BUILDER_CACHE_KEY",
                    "registryctl-tutorial-linux-amd64",
                ).replace(
                    "registryctl-tutorial-cargo-home-$BUILDER_CACHE_KEY",
                    "registryctl-tutorial-cargo-home",
                ),
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any("Debian 13 builder identity cache key" in failure for failure in failures),
                failures,
            )
            self.assertTrue(
                any("builder-keyed linux target cache" in failure for failure in failures),
                failures,
            )
            self.assertTrue(
                any("builder-keyed Cargo home cache" in failure for failure in failures),
                failures,
            )

    def test_dockerfile_internal_stage_reference_needs_no_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            dockerfile = root / "products/example/Dockerfile"
            dockerfile.parent.mkdir(parents=True, exist_ok=True)
            dockerfile.write_text(
                f"FROM {self.module.RUST_BUILDER} AS builder\n"
                "FROM builder AS runtime\n",
                encoding="utf-8",
            )

            self.assertEqual([], self.module.check_repository(root))

    def test_discovered_python_script_rejects_unpinned_builder_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "products/example/scripts/build_image.py"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                'BUILDER_IMAGE = "rust:1.95-' + 'trixie"\n',
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "Debian-derived image reference is not pinned by immutable digest"
                    in failure
                    and "products/example/scripts/build_image.py:1" in failure
                    for failure in failures
                ),
                failures,
            )

    def test_history_and_research_are_outside_the_maintained_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            retired_reference = "Debian " + "12 and Book" + "worm\n"
            for relative in (
                Path("release/notes/v0.1.0.md"),
                Path("docs/site/.research/container-notes.md"),
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(retired_reference, encoding="utf-8")

            self.assertEqual([], self.module.check_repository(root))


if __name__ == "__main__":
    unittest.main()
