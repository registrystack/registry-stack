#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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

    def test_discovered_dockerfile_rejects_external_copy_from_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            dockerfile = root / "products/example/Dockerfile"
            dockerfile.parent.mkdir(parents=True, exist_ok=True)
            dockerfile.write_text(
                "FROM scratch\n"
                "COPY --from=debian:book" + "worm@sha256:" + "a" * 64
                + " /etc/os-release /os-release\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "products/example/Dockerfile:2" in failure
                    and "retired Debian image generation marker" in failure
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
                "docker run --rm --init --no-healthcheck "
                "--oom-kill-disable --sig-proxy debian true\n",
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

    def test_discovered_script_rejects_private_registry_untagged_debian_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "docs/site/scripts/build-example.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "#!/usr/bin/env bash\n"
                "docker run --rm localhost:5000/debian true\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "docs/site/scripts/build-example.sh:2" in failure
                    and failure.endswith(": localhost:5000/debian")
                    for failure in failures
                ),
                failures,
            )

    def test_discovered_script_strips_same_line_shell_separator_after_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "docs/site/scripts/build-example.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "#!/usr/bin/env bash\n"
                "docker run --rm debian; echo ok\n",
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

    def test_discovered_script_parses_docker_global_options(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "docs/site/scripts/build-example.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "#!/usr/bin/env bash\n"
                "docker --context ci run --rm debian true\n",
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

    def test_discovered_script_scans_after_shell_list_operators(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "docs/site/scripts/build-example.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "#!/usr/bin/env bash\n"
                'cd "$PWD" && docker run --rm debian true\n'
                "echo ok; podman run --rm node:22 true\n"
                "echo ok & docker run --rm python:3.12 true\n"
                "echo ok |& podman run --rm rust:1.95-trixie true\n",
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
            self.assertTrue(
                any(
                    "docs/site/scripts/build-example.sh:3" in failure
                    and failure.endswith(": node:22")
                    for failure in failures
                ),
                failures,
            )
            self.assertTrue(any("build-example.sh:4" in item for item in failures))
            self.assertTrue(any("build-example.sh:5" in item for item in failures))

    def test_shell_control_prefixes_find_image_references(self) -> None:
        cases = {
            "if docker run --rm debian true; then": ["debian"],
            "while podman run --rm node:22 true; do": ["node:22"],
            "until docker run --rm python:3.12 true; do": ["python:3.12"],
            "! docker run --rm rust:1.95-trixie true": ["rust:1.95-trixie"],
            "time docker run --rm debian true": ["debian"],
            "time -p docker run --rm node:22 true": ["node:22"],
            "time -- podman run --rm python:3.12 true": ["python:3.12"],
            "{ docker run --rm debian true; }": ["debian"],
            "(podman run --rm node:22 true)": ["node:22"],
            "if ! time -p docker run --rm rust:1.95-trixie true; then": [
                "rust:1.95-trixie"
            ],
            "if true; then docker run --rm debian true; fi": ["debian"],
            "while true; do podman run --rm node:22 true; done": ["node:22"],
        }

        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(
                    expected,
                    self.module.command_image_references_in_command(command),
                )

    def test_shell_wrapper_options_find_image_references(self) -> None:
        cases = {
            "sudo -E docker run --rm debian true": ["debian"],
            "env -i podman run --rm node:22 true": ["node:22"],
            "command -- docker run --rm python:3.12 true": ["python:3.12"],
            "sudo -u root env -u EXAMPLE command -p "
            "docker run --rm rust:1.95-trixie true": ["rust:1.95-trixie"],
            "sudo --preserve-env=CI time -p "
            "podman run --rm debian true": ["debian"],
            "sudo -A docker run --rm debian true": ["debian"],
            "sudo -i podman run --rm node:22 true": ["node:22"],
            "sudo -P docker run --rm python:3.12 true": ["python:3.12"],
        }

        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(
                    expected,
                    self.module.command_image_references_in_command(command),
                )

    def test_shell_launchers_are_unwrapped_with_a_depth_bound(self) -> None:
        cases = {
            'sh -c "docker run --rm debian true"': ["debian"],
            'sudo -A bash -lc "podman run --rm node:22 true"': ["node:22"],
            "env -S 'bash -c \"docker run --rm python:3.12 true\"'": [
                "python:3.12"
            ],
            "env --split-string='sh -c \"podman run --rm rust:1.95-trixie\"'": [
                "rust:1.95-trixie"
            ],
            "env -Ssh -c 'docker run --rm debian true'": ["debian"],
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(
                    expected,
                    self.module.command_image_references_in_command(command),
                )

        nested = "docker run --rm debian true"
        for _ in range(self.module.MAX_SHELL_RECURSION_DEPTH + 1):
            nested = f"sh -c {self.module.shlex.quote(nested)}"
        with self.assertRaisesRegex(
            self.module.ImageSurfaceError,
            "shell command nesting exceeds",
        ):
            self.module.command_image_references_in_command(nested)
        with self.assertRaisesRegex(
            self.module.ImageSurfaceError,
            "shell command exceeds",
        ):
            self.module.command_image_references_in_command(
                "x" * (self.module.MAX_SHELL_COMMAND_CHARS + 1)
            )

    def test_shell_parser_rejects_invalid_control_and_wrapper_prefixes(self) -> None:
        commands = (
            "if then docker run --rm debian true",
            "while until docker run --rm debian true",
            "! if docker run --rm debian true",
            "time while docker run --rm debian true",
            "time -- -p docker run --rm debian true",
            "sudo if docker run --rm debian true",
            "sudo --unknown docker run --rm debian true",
            "sudo -v docker run --rm debian true",
            "env --unknown docker run --rm debian true",
            "command -v docker run --rm debian true",
        )

        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(
                    [],
                    self.module.command_image_references_in_command(command),
                )

    def test_command_scan_ignores_prose_prefixes(self) -> None:
        commands = (
            "echo if docker run --rm debian true",
            "printf '%s\\n' time docker run --rm node:22 true",
            "description: if docker run --rm debian true",
            "notes: time -p docker run --rm node:22 true",
            "a sentence about { docker run --rm debian true; }",
        )

        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(
                    [],
                    self.module.command_image_references_in_command(command),
                )

    def test_yaml_supported_executable_contexts_find_image_references(self) -> None:
        cases = {
            "workflow literal": (
                Path(".github/workflows/example.yml"),
                "jobs:\n"
                "  test:\n"
                "    steps:\n"
                "      - run: |\n"
                "          command -- docker run --rm python:3.12 true\n",
                [(5, "python:3.12")],
            ),
            "workflow folded reports scalar start": (
                Path(".github/workflows/example.yml"),
                "jobs:\n"
                "  test:\n"
                "    steps:\n"
                "      - run: >\n"
                "          sudo -E docker run --rm\n"
                "          rust:1.95-trixie true\n",
                [(4, "rust:1.95-trixie")],
            ),
            "compose argv": (
                Path("compose.yaml"),
                "services:\n"
                "  helper:\n"
                "    image: debian\n"
                "    command: [sh, -c, \"podman run --rm node:22 true\"]\n",
                [(3, "debian"), (4, "node:22")],
            ),
            "Kubernetes command and args": (
                Path("pod.yaml"),
                "apiVersion: v1\n"
                "kind: Pod\n"
                "spec:\n"
                "  containers:\n"
                "    - name: helper\n"
                "      image: debian\n"
                "      command: [sh, -c]\n"
                "      args: [\"docker run --rm python:3.12 true\"]\n",
                [(6, "debian"), (7, "python:3.12")],
            ),
            "image variable": (
                Path("images.yaml"),
                "BUILDER_IMAGE: debian\n",
                [(1, "debian")],
            ),
        }

        for name, (relative, text, expected) in cases.items():
            with self.subTest(name=name):
                self.assertEqual(
                    expected,
                    self.module.image_references(relative, text),
                )

    def test_yaml_domain_data_is_not_executable(self) -> None:
        text = (
            "experiment:\n"
            "  run: docker run --rm debian true\n"
            "capability:\n"
            "  script: docker run --rm node:22 true\n"
            "metadata:\n"
            "  command: [docker, run, --rm, python:3.12]\n"
        )

        self.assertEqual([], self.module.image_references(Path("data.yaml"), text))

    def test_yaml_all_documents_are_scanned(self) -> None:
        text = (
            "experiment:\n"
            "  run: docker run --rm debian true\n"
            "---\n"
            "services:\n"
            "  helper:\n"
            "    image: node:22\n"
            "---\n"
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            "      - run: docker run --rm python:3.12 true\n"
        )
        self.assertEqual(
            [(6, "node:22"), (11, "python:3.12")],
            self.module.image_references(Path("example.yaml"), text),
        )

    def test_malformed_yaml_fails_the_repository_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            manifest = root / "products/example/broken.yaml"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text("jobs:\n  broken: [\n", encoding="utf-8")

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "products/example/broken.yaml: image scan failed: invalid YAML"
                    in failure
                    for failure in failures
                ),
                failures,
            )

    def test_yaml_parser_recursion_and_depth_fail_explicitly(self) -> None:
        self.module.compose_yaml_documents.cache_clear()
        with mock.patch.object(
            self.module.yaml,
            "compose_all",
            side_effect=RecursionError,
        ):
            with self.assertRaisesRegex(
                self.module.ImageSurfaceError,
                "YAML parser recursion limit exceeded",
            ):
                self.module.image_references(Path("recursive.yaml"), "jobs: {}\n")

        deep = "".join(
            f"{'  ' * depth}level_{depth}:\n" for depth in range(6)
        ) + "            value: true\n"
        with mock.patch.object(self.module, "MAX_YAML_DEPTH", 3):
            with self.assertRaisesRegex(
                self.module.ImageSurfaceError,
                "YAML nesting exceeds",
            ):
                self.module.image_references(Path("deep.yaml"), deep)
        with mock.patch.object(self.module, "MAX_YAML_DOCUMENTS", 2):
            with self.assertRaisesRegex(
                self.module.ImageSurfaceError,
                "YAML input exceeds 2 documents",
            ):
                self.module.image_references(
                    Path("documents.yaml"),
                    "---\n---\n---\n",
                )

    def test_missing_pyyaml_fails_with_dependency_name(self) -> None:
        self.module.compose_yaml_documents.cache_clear()
        with (
            mock.patch.object(self.module, "yaml", None),
            mock.patch.object(
                self.module,
                "YAML_IMPORT_ERROR",
                ImportError("No module named yaml"),
            ),
        ):
            with self.assertRaisesRegex(
                self.module.ImageSurfaceError,
                "PyYAML is required",
            ):
                self.module.image_references(Path("missing.yaml"), "jobs: {}\n")

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

    def test_discovered_kubernetes_yaml_rejects_container_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            manifest = root / "products/example/pod.yaml"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(
                "apiVersion: v1\n"
                "kind: Pod\n"
                "spec:\n"
                "  containers:\n"
                "    - name: helper\n"
                "      image: debian\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "products/example/pod.yaml:6" in failure
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
            retired_bookworm = f"rust:1.95-{'book' + 'worm'}@sha256:{'a' * 64}"
            metadata.write_text(
                'description: "docker run --rm debian is an unsafe example"\n'
                f"# docker run --rm {retired_bookworm} cargo build\n"
                f"notes: {retired_bookworm}\n"
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

    def test_discovered_workflow_rejects_docker_image_action(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            workflow = root / ".github/workflows/example.yml"
            workflow.parent.mkdir(parents=True, exist_ok=True)
            workflow.write_text(
                "jobs:\n"
                "  test:\n"
                "    steps:\n"
                "      - uses: docker://debian:book" + "worm@sha256:" + "a" * 64 + "\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    ".github/workflows/example.yml:4" in failure
                    and "retired Debian image generation marker" in failure
                    for failure in failures
                ),
                failures,
            )

    def test_discovered_script_rejects_retired_digest_pinned_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "docs/site/scripts/build-example.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            retired_bookworm = f"rust:1.95-{'book' + 'worm'}@sha256:{'a' * 64}"
            script.write_text(
                "#!/usr/bin/env bash\n"
                f"docker run --rm {retired_bookworm} cargo build --locked\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "retired Debian image generation marker remains in image reference"
                    in failure
                    and "docs/site/scripts/build-example.sh:2" in failure
                    and "bookworm" in failure
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

    def test_discovered_shell_rejects_prefixed_image_declarations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            script = root / "docs/site/scripts/build-example.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "#!/usr/bin/env bash\n"
                "local BUILDER_IMAGE=debian\n"
                "readonly RUNTIME_IMAGE=rust:1.95-book" + "worm\n",
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
            self.assertTrue(
                any(
                    "docs/site/scripts/build-example.sh:3" in failure
                    and "retired Debian image generation marker" in failure
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
            workflow = root / self.module.CI_WORKFLOW
            text = workflow.read_text(encoding="utf-8")
            workflow.write_text(
                text.replace(
                    "key: registryctl-tutorial-${{ runner.os }}-${{ "
                    "hashFiles('docs/site/scripts/check-registryctl-tutorials.sh') "
                    "}}-${{ hashFiles('Cargo.lock') }}",
                    "key: registryctl-tutorial-${{ runner.os }}-rust-1.95.0-"
                    "${{ hashFiles('Cargo.lock') }}\n"
                    "          restore-keys: |\n"
                    "            registryctl-tutorial-${{ runner.os }}-rust-1.95.0-",
                ),
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "cache key including builder-bearing script" in failure
                    for failure in failures
                ),
                failures,
            )
            self.assertTrue(
                any(
                    "must not restore from pre-builder-identity keys" in failure
                    for failure in failures
                ),
                failures,
            )

    def test_registryctl_tutorial_host_paths_must_match_container_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            tutorial = root / self.module.REGISTRYCTL_TUTORIAL_SCRIPT
            text = tutorial.read_text(encoding="utf-8")
            linux_target = (
                'LINUX_TARGET="$REPO_ROOT/target/registryctl-tutorial-linux-amd64"'
            )
            cargo_home = (
                'CARGO_HOME_DIR="$REPO_ROOT/target/registryctl-tutorial-cargo-home"'
            )
            tutorial.write_text(
                text.replace(
                    linux_target,
                    linux_target.removesuffix('"') + '-$BUILDER_CACHE_KEY"',
                ).replace(
                    cargo_home,
                    cargo_home.removesuffix('"') + '-$BUILDER_CACHE_KEY"',
                ),
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "linux target path matching container target" in failure
                    for failure in failures
                ),
                failures,
            )
            self.assertTrue(
                any(
                    "Cargo home path matching container Cargo home" in failure
                    for failure in failures
                ),
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
                "FROM builder AS runtime\n"
                "COPY --from=builder /usr/local/bin/tool /usr/local/bin/tool\n",
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

    def test_discovered_markdown_rejects_executable_code_block_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            doc = root / "crates/registry-relay/docs/example.md"
            doc.parent.mkdir(parents=True, exist_ok=True)
            doc.write_text(
                "Run the example:\n"
                "```bash\n"
                "docker run --rm debian true\n"
                "```\n"
                "```console\n"
                "$ docker run --rm node:22 true\n"
                "```\n",
                encoding="utf-8",
            )

            failures = self.module.check_repository(root)

            self.assertTrue(
                any(
                    "crates/registry-relay/docs/example.md:3" in failure
                    and failure.endswith(": debian")
                    for failure in failures
                ),
                failures,
            )
            self.assertTrue(
                any(
                    "crates/registry-relay/docs/example.md:6" in failure
                    and failure.endswith(": node:22")
                    for failure in failures
                ),
                failures,
            )

    def test_markdown_scan_ignores_prose_and_nonexecutable_fences(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required_surfaces(root)
            doc = root / "crates/registry-relay/docs/example.md"
            doc.parent.mkdir(parents=True, exist_ok=True)
            doc.write_text(
                "A sentence can discuss docker run --rm debian true.\n"
                "```text\n"
                "docker run --rm debian true\n"
                "```\n",
                encoding="utf-8",
            )

            self.assertEqual([], self.module.check_repository(root))

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
