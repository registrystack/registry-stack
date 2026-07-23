#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release/scripts/check-debian13-images.py"
DIGEST = "a" * 64
PINNED_RUST = f"rust:1.95-trixie@sha256:{DIGEST}"


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

    def scan(self, relative: str, text: str) -> list[str]:
        return self.module.scan_surface(Path(relative), text)

    def assert_failure(self, relative: str, text: str, fragment: str) -> None:
        failures = self.scan(relative, text)
        self.assertTrue(any(fragment in item for item in failures), failures)

    def assert_clean(self, relative: str, text: str) -> None:
        self.assertEqual([], self.scan(relative, text))

    def copy_required(self, root: Path) -> None:
        for relative in self.module.REQUIRED_PRODUCT_SURFACES:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)

    def test_real_repository_follows_debian13_contract(self) -> None:
        self.assertEqual([], self.module.check_repository(ROOT))

    def test_discovery_uses_tracked_files_and_documented_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tracked = (
                Path("Dockerfile.worker"),
                Path("scripts/check.sh"),
                Path("release/notes/old.md"),
                Path("docs/.research/notes.md"),
                Path("external/vendor.md"),
                Path("crates/example/resources/scalar/generated.js"),
                Path("release/scripts/test_check_debian13_images.py"),
            )
            for relative in tracked:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("fixture\n")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "add", "."],
                check=True,
            )
            (root / "untracked.sh").write_text("fixture\n")

            discovered = self.module.discover_maintained_surfaces(root)

            self.assertIn(Path("Dockerfile.worker"), discovered)
            self.assertIn(Path("scripts/check.sh"), discovered)
            for relative in tracked[2:] + (Path("untracked.sh"),):
                self.assertNotIn(relative, discovered)

    def test_path_file_line_and_total_bounds_fail_explicitly(self) -> None:
        listed = b"\0".join(
            f"file-{index}".encode()
            for index in range(self.module.MAX_TRACKED_PATHS + 1)
        )
        completed = subprocess.CompletedProcess([], 0, stdout=listed)
        with (
            mock.patch.object(
                self.module.subprocess,
                "run",
                return_value=completed,
            ),
            self.assertRaisesRegex(
                self.module.ImageSurfaceError,
                "tracked path count exceeds",
            ),
        ):
            self.module.discover_maintained_surfaces(Path("/unused"))

        with self.assertRaisesRegex(
            self.module.ImageSurfaceError,
            "text file exceeds",
        ):
            self.scan(
                "large.yaml",
                "x" * (self.module.MAX_TEXT_FILE_BYTES + 1),
            )
        with self.assertRaisesRegex(
            self.module.ImageSurfaceError,
            "line exceeds",
        ):
            self.scan(
                "line.yaml",
                "x" * (self.module.MAX_LINE_CHARS + 1),
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required(root)
            with mock.patch.object(self.module, "MAX_TOTAL_TEXT_BYTES", 1):
                failures = self.module.check_repository(root)
            self.assertEqual(
                ["maintained text exceeds 1 total bytes"],
                failures,
            )

    def test_debian_family_literal_policy_is_table_driven(self) -> None:
        cases = [
            ("Dockerfile", f"FROM {PINNED_RUST}\n", None),
            ("compose.yaml", f"services:\n  app:\n    image: {PINNED_RUST}\n", None),
            (
                "script.sh",
                "docker run --rm rust:1.95-trixie true\n",
                "not pinned by immutable digest",
            ),
            (
                "workflow.yml",
                f"env:\n  BUILDER_IMAGE: rust:1.95@sha256:{DIGEST}\n",
                "does not declare Trixie/Debian 13",
            ),
            (
                "compose.yaml",
                "image: registry.local/team_name/debian:trixie\n",
                "not pinned by immutable digest",
            ),
            (
                "script.sh",
                "docker run registry.local/first_team/second_team/rust:1.95-trixie\n",
                "not pinned by immutable digest",
            ),
            (
                "compose.yaml",
                "image: registry.local/team_name/rust\n",
                "bare Debian-default",
            ),
            (
                "compose.yaml",
                "image: registry.local/first_team/second_team/postgres\n",
                "bare Debian-default",
            ),
            (
                "Dockerfile",
                f"FROM rust:1.95-trixie@sha256:{DIGEST.upper()}\n",
                None,
            ),
            (
                "guide.md",
                "Use registry.local/team_name/debian:trixie in prose.\n",
                None,
            ),
            (
                "guide.md",
                "Mirror registry.local/first_team/second_team/rust in prose.\n",
                None,
            ),
            (
                "images.py",
                "BUILDER_IMAGE: str = 'python:3.13-slim-trixie'\n",
                "not pinned by immutable digest",
            ),
            (
                "images.ts",
                "const builderImage = 'golang:1.25-trixie';\n",
                "not pinned by immutable digest",
            ),
            ("module.js", "import path from 'node:path';\n", None),
            ("data.yaml", "identifier: did:web\nport: 65532:65532\n", None),
        ]
        for family, version in (
            ("rust", "1.95"),
            ("node", "22"),
            ("python", "3.13"),
            ("golang", "1.25"),
            ("postgres", "16"),
        ):
            cases.extend(
                (
                    (
                        "compose.yaml",
                        f"{'container' if family == 'node' else 'image'}: {family}\n",
                        "bare Debian-default",
                    ),
                    ("build.sh", f"BUILDER_IMAGE='{family}'\n", "bare Debian-default"),
                    (
                        "script.sh",
                        f"docker run --rm {family} true\n",
                        "bare Debian-default",
                    ),
                    (
                        "script.sh",
                        f"docker run --rm {family}:{version}\n",
                        "not pinned",
                    ),
                    (
                        "script.sh",
                        f"docker run --rm {family}:{version}-slim\n",
                        "not pinned",
                    ),
                    (
                        "workflow.yml",
                        f"container: {family}@sha256:{DIGEST}\n",
                        "does not declare",
                    ),
                    (
                        "compose.yaml",
                        f"image: registry.test:5000/team/{family}\n",
                        "bare Debian-default",
                    ),
                    (
                        "workflow.yml",
                        f"container: registry.test/team/{family}@sha256:{DIGEST}\n",
                        "does not declare",
                    ),
                    ("script.sh", f"docker run {family}:{version}-alpine\n", None),
                    ("script.sh", f"docker run {family}:{version}-windows\n", None),
                    ("guide.md", f"The {family} image is available.\n", None),
                )
            )
        for relative, text, expected in cases:
            with self.subTest(relative=relative, text=text):
                failures = self.scan(relative, text)
                if expected is None:
                    self.assertEqual([], failures)
                else:
                    self.assertTrue(
                        any(expected in failure for failure in failures),
                        failures,
                    )

    def test_retired_markers_are_global_with_markdown_prose_exemptions(self) -> None:
        for text in (
            "Historical book" + "worm base\n",
            "# image used bullseye during testing\n",
            "unused_image: debian" + "12\n",
        ):
            with self.subTest(text=text):
                self.assert_failure(
                    "notes.txt",
                    text,
                    "retired Debian image generation marker",
                )

        self.assert_clean(
            "design.md",
            "The book"
            "worm comparison remains historical. "
            "<!-- debian13-policy: allow-prose "
            'reason="historical comparison only" -->\n',
        )
        invalid = (
            "```sh\n"
            "# book"
            "worm <!-- debian13-policy: allow-prose "
            'reason="historical comparison only" -->\n'
            "```\n"
        )
        failures = self.scan("design.md", invalid)
        self.assertTrue(
            any("invalid Debian image prose exemption" in item for item in failures),
            failures,
        )
        self.assertTrue(
            any("retired Debian image" in item for item in failures),
            failures,
        )

    def test_wrappers_options_operators_and_malformed_shell_still_scan_literals(
        self,
    ) -> None:
        commands = (
            "docker --tlsverify pull -a rust:1.95-trixie",
            "podman --remote pull --all-tags rust:1.95-trixie",
            "docker image pull --disable-content-trust rust:1.95-trixie",
            "/usr/bin/docker run --rm rust:1.95-trixie",
            "env -S '-i /usr/bin/docker run --rm rust:1.95-trixie'",
            "sudo -s /usr/bin/docker run --rm rust:1.95-trixie",
            "bash --noprofile -c 'docker run --rm rust:1.95-trixie'",
            "if ! time -p docker run --rm rust:1.95-trixie; then true; fi",
            "echo ok; podman run --unknown value rust:1.95-trixie",
            "docker unknown rust:1.95-trixie",
            "docker run 'rust:1.95-trixie",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assert_failure(
                    "script.sh",
                    command + "\n",
                    "not pinned by immutable digest",
                )

        for command in (
            f"docker run --unknown value {PINNED_RUST}",
            f"sudo --unknown docker unknown {PINNED_RUST}",
            f"bash --unknown -c 'docker run {PINNED_RUST}'",
        ):
            with self.subTest(command=command):
                self.assert_clean("script.sh", command + "\n")

    def test_bare_debian_is_finite_to_image_code_contexts(self) -> None:
        cases = (
            ("Dockerfile", "FROM debian\n"),
            ("images/relay.dockerfile", "FROM debian\n"),
            ("Dockerfile", "COPY --from=localhost:5000/debian /x /x\n"),
            ("Dockerfile", "RUN --mount=from=debian,target=/x true\n"),
            ("compose.yaml", "services:\n  app:\n    image: debian\n"),
            ("workflow.yml", "jobs:\n  test:\n    container: debian\n"),
            ("images.py", "BUILDER_IMAGE = 'debian'\n"),
            ("script.sh", "docker run --rm debian true\n"),
            ("guide.md", "```console\n$ podman pull debian\n```\n"),
        )
        for relative, text in cases:
            with self.subTest(relative=relative, text=text):
                self.assert_failure(
                    relative,
                    text,
                    "bare Debian image reference",
                )

        for relative, text in (
            ("images/relay.dockerfile", f"FROM {PINNED_RUST}\n"),
            ("guide.md", "Debian is the supported distribution.\n"),
            ("guide.md", "```text\ndocker run debian\n```\n"),
            ("script.sh", "# docker run --rm debian\n"),
            ("module.js", '// docker run "$OTHER_IMAGE"\n'),
            ("module.py", "distribution = 'debian'\n"),
            ("module.py", "distribution = 'Debian'\n"),
        ):
            with self.subTest(relative=relative, text=text):
                self.assert_clean(relative, text)

    def test_image_assignments_resolve_literals_and_reject_computation(self) -> None:
        clean = (
            f'DEFAULT_BUILDER_IMAGE="{PINNED_RUST}"\n'
            'BUILDER_IMAGE="${DEFAULT_BUILDER_IMAGE}"\n'
            'docker run --rm "$BUILDER_IMAGE" true\n'
        )
        self.assert_clean("build.sh", clean)
        self.assert_clean(
            "function.sh",
            'start() {\n  local image="$1"\n  docker run "$image"\n}\n',
        )
        self.assert_clean(
            "local.sh",
            'RELAY_IMAGE="registryctl-relay:$RUN_ID"\ndocker run "$RELAY_IMAGE"\n',
        )
        self.assert_clean(
            "static.sh",
            'APP_IMAGE="alpine:3.22"\ndocker run --rm "$APP_IMAGE"\n',
        )
        self.assert_clean(
            "fallback.sh",
            'FIRST_IMAGE="alpine:3.22"\nSECOND_IMAGE="busybox:1.37"\n'
            'APP_IMAGE="${FIRST_IMAGE:-$SECOND_IMAGE}"\n'
            'docker run --rm "$APP_IMAGE"\n',
        )

        cases = (
            (
                "computed.sh",
                'APP_IMAGE="$(select-image)"\ndocker run --rm "$APP_IMAGE"\n',
                "unresolved image variables: app_image",
            ),
            (
                "alias.sh",
                'OTHER_IMAGE="$(select-image)"\nAPP_IMAGE="$OTHER_IMAGE"\n'
                'docker run --rm "$APP_IMAGE"\n',
                "unresolved image variables: app_image",
            ),
            (
                "multi.sh",
                'GOOD_IMAGE="alpine:3.22"\nBAD_IMAGE="$(select-image)"\n'
                'APP_IMAGE="${GOOD_IMAGE:-$BAD_IMAGE}"\n'
                'docker run --rm "$APP_IMAGE"\n',
                "unresolved image variables: app_image",
            ),
            (
                "images.py",
                "BUILDER_IMAGE = make_image()\n",
                "computed or unresolved image assignment",
            ),
            (
                "images.ts",
                "const builderImage = 'rust:1.95-' + 'trixie';\n",
                "computed or unresolved image assignment",
            ),
            (
                "cycle.sh",
                'BASE_IMAGE="$BUILDER_IMAGE"\nBUILDER_IMAGE="$BASE_IMAGE"\n',
                "computed or unresolved image assignment",
            ),
            (
                "build.sh",
                'docker run --rm "$OTHER_IMAGE"\n',
                "must use a literal or a statically resolved *_IMAGE assignment",
            ),
            (
                "build.sh",
                'docker run --publish 127.0.0.1:8080 "$OTHER_IMAGE"\n',
                "must use a literal or a statically resolved *_IMAGE assignment",
            ),
            (
                "build.sh",
                'OTHER_IMAGE="$(compute)"\nBUILDER_IMAGE="$OTHER_IMAGE"\n',
                "computed or unresolved image assignment",
            ),
            (
                "build.sh",
                'docker pull "$container"\n',
                "must use a literal or a statically resolved *_IMAGE assignment",
            ),
        )
        for relative, text, expected in cases:
            with self.subTest(relative=relative):
                self.assert_failure(relative, text, expected)

    def test_image_templates_use_only_bounded_static_forms(self) -> None:
        cases = (
            'APP_IMAGE="${UNSAFE_IMAGE:-alpine:3.22}"\n',
            'APP_IMAGE="${BASE_IMAGE/alpine/$TARGET}"\n',
            'APP_IMAGE="${REPOSITORY}:${TAG}"\n',
            'APP_IMAGE="rust:$TAG"\n',
        )
        for assignment in cases:
            with self.subTest(assignment=assignment):
                self.assert_failure(
                    "template.sh",
                    assignment + 'docker run --rm "$APP_IMAGE"\n',
                    "unresolved image variables: app_image",
                )

        self.assert_clean(
            "aliases.sh",
            'FIRST_IMAGE="alpine:3.22"\nSECOND_IMAGE="busybox:1.37"\n'
            'APP_IMAGE="${FIRST_IMAGE:-$SECOND_IMAGE}"\n'
            'docker run --rm "$APP_IMAGE"\n',
        )
        self.assert_clean(
            "tag.sh",
            'APP_IMAGE="registryctl-relay:$RUN_ID"\ndocker run --rm "$APP_IMAGE"\n',
        )

    def test_yaml_literals_cover_compose_merges_matrices_and_kubernetes(self) -> None:
        cases = (
            (
                "compose.yaml",
                "x-service: &defaults\n  image: rust:1.95-trixie\n"
                "services:\n  app:\n    <<: *defaults\n",
            ),
            (
                ".github/workflows/example.yml",
                "jobs:\n  test:\n    strategy:\n      matrix:\n"
                "        image: [rust:1.95-trixie]\n        include:\n"
                "          - image: rust:1.95-trixie\n"
                "        unused_image: [rust:1.95-trixie]\n"
                "    container: ${{ matrix.image }}\n",
            ),
            (
                "pod.yaml",
                "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - image: rust:1.95-trixie\n",
            ),
            ("malformed.yaml", "jobs: [\nimage: rust:1.95-trixie\n"),
            ("documents.yaml", "description: first\n---\nimage: rust:1.95-trixie\n"),
        )
        for relative, text in cases:
            with self.subTest(relative=relative):
                self.assert_failure(
                    relative,
                    text,
                    "not pinned by immutable digest",
                )

    def test_compose_entrypoint_and_command_form_one_image_consumer(self) -> None:
        self.assert_failure(
            "compose.yaml",
            "services:\n  app:\n    entrypoint: [docker]\n"
            "    command: [run, --rm, debian]\n",
            "bare Debian image reference",
        )
        self.assert_clean(
            "compose.yaml",
            "services:\n  app:\n    entrypoint: [docker]\n"
            f"    command: [run, --rm, {PINNED_RUST}]\n",
        )
        self.assert_clean(
            "compose.yaml",
            "services:\n  first:\n    entrypoint: [docker]\n"
            "  second:\n    command: [run, --rm, debian]\n",
        )
        self.assert_clean(
            "compose.yaml",
            "services:\n  app:\n    entrypoint: [echo, docker]\n"
            "    command: [run, --rm, debian]\n",
        )

    def test_compose_block_sequences_preserve_mapping_and_list_scope(self) -> None:
        self.assert_failure(
            "compose.yaml",
            "services:\n  app:\n    entrypoint:\n      - docker\n"
            "    command:\n      - run\n      - --rm\n      - debian\n",
            "bare Debian image reference",
        )
        self.assert_clean(
            "compose.yaml",
            "services:\n  app:\n    entrypoint:\n      - docker\n"
            f"    command:\n      - run\n      - --rm\n      - {PINNED_RUST}\n",
        )
        self.assert_clean(
            "compose.yaml",
            "items:\n  - entrypoint: [docker]\n  - command: [run, --rm, debian]\n",
        )
        self.assert_failure(
            "compose.yaml",
            "items:\n  - name: app\n    entrypoint: [docker]\n"
            "    command: [run, --rm, debian]\n",
            "bare Debian image reference",
        )

    def test_container_cli_scans_only_the_bounded_image_operand(self) -> None:
        for command in (
            "docker run --name postgres alpine:3.22 true\n",
            "docker run alpine:3.22 python -V\n",
            "docker create --env NAME=postgres busybox:1.37 python\n",
        ):
            with self.subTest(command=command):
                self.assert_clean("helper.sh", command)

        for command, family in (
            ("docker run --name app postgres true\n", "postgres"),
            ("docker run python -V\n", "python"),
            ("docker pull --platform linux/amd64 rust:1.95\n", "rust:1.95"),
        ):
            with self.subTest(command=command):
                self.assert_failure("helper.sh", command, family)

    def test_multiline_container_commands_scan_the_joined_operand(self) -> None:
        self.assert_failure(
            "helper.sh",
            "docker run --rm \\\n  debian true\n",
            "bare Debian image reference",
        )
        self.assert_clean(
            "helper.sh",
            f"docker run --rm \\\n  {PINNED_RUST} true\n",
        )

    def test_extensionless_executable_and_shebang_helpers_are_code(self) -> None:
        text = "#!/bin/sh\ndocker run --rm debian\n"
        self.assert_failure(
            "release/scripts/registry-release",
            text,
            "bare Debian image reference",
        )
        failures = self.module.scan_surface(
            Path("tools/runner"),
            "docker run --rm debian\n",
            executable=True,
        )
        self.assertTrue(
            any("bare Debian image reference" in failure for failure in failures),
            failures,
        )
        self.assert_clean(
            "notes/helper",
            "This prose says docker run --rm debian without a shebang.\n",
        )

    def test_docker_image_build_contexts_follow_the_image_policy(self) -> None:
        self.assert_failure(
            "build.sh",
            "docker buildx build --build-context base=docker-image://debian .\n",
            "Docker build context",
        )
        self.assert_failure(
            "build.sh",
            "docker build --build-context base=docker-image://rust:1.95-trixie .\n",
            "Docker build context",
        )
        failures = self.scan(
            "build.sh",
            "docker build --build-context base=docker-image://rust:1.95-trixie .\n",
        )
        self.assertFalse(
            any("Debian-derived image reference" in failure for failure in failures),
            failures,
        )
        self.assert_clean(
            "build.sh",
            "docker buildx build --build-context "
            f"base=docker-image://{PINNED_RUST} .\n",
        )
        self.assert_clean(
            "build.sh",
            "docker buildx build --build-context base=docker-image://alpine:3.22 .\n",
        )
        self.assert_clean(
            "guide.md",
            "Prose mentions --build-context base=docker-image://debian.\n",
        )

    def test_postgresql_conformance_workflow_selects_static_images(self) -> None:
        script_path = Path("products/notary/scripts/postgresql-conformance.sh")
        script = (ROOT / script_path).read_text()
        workflow = (
            ROOT / ".github/workflows/notary-postgres-conformance.yml"
        ).read_text()
        selections = {
            "16": (
                "postgres:16.13-alpine",
                "postgres:16.14-alpine",
                "postgres:17.10-alpine",
            ),
            "17": (
                "postgres:17.9-alpine",
                "postgres:17.10-alpine",
                "postgres:18.4-alpine",
            ),
            "18": (
                "postgres:18.3-alpine",
                "postgres:18.4-alpine",
                "postgres:18.4-alpine",
            ),
        }
        for major, (source, target, restore) in selections.items():
            with self.subTest(major=major):
                self.assertIn(f'- postgresql: "{major}"', workflow)
                self.assertIn(
                    f'  {major})\n    default_source_image="{source}"\n'
                    f'    default_target_image="{target}"\n'
                    f'    default_restore_image="{restore}"\n',
                    script,
                )
        self.assertNotIn("NOTARY_POSTGRES_SOURCE_IMAGE", script + workflow)
        self.assertNotIn("NOTARY_POSTGRES_TARGET_IMAGE", script + workflow)
        self.assertNotIn("NOTARY_POSTGRES_RESTORE_IMAGE", script + workflow)
        self.assert_clean(script_path.as_posix(), script)

        override = (
            'source_image="${NOTARY_POSTGRES_SOURCE_IMAGE:-${default_source_image}}"'
        )
        mutated = script.replace('source_image="${default_source_image}"', override)
        self.assertNotEqual(script, mutated)
        self.assert_failure(
            script_path.as_posix(),
            mutated,
            "unresolved image variables: source_image",
        )

    def test_markdown_scans_only_executable_fences(self) -> None:
        self.assert_failure(
            "guide.md",
            "```sh\ndocker run --rm rust:1.95-trixie\n```\n",
            "not pinned by immutable digest",
        )
        self.assert_clean(
            "guide.md",
            "Example prose mentions rust:1.95-trixie.\n"
            "```text\n"
            "docker run --rm rust:1.95-trixie\n"
            "```\n",
        )

    def test_repository_dockerfile_discovery_checks_external_and_internal_stages(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required(root)
            dockerfile = root / "products/example/Dockerfile"
            dockerfile.parent.mkdir(parents=True)
            dockerfile.write_text(
                "FROM scratch AS assets\n"
                "FROM assets AS final\n"
                "COPY --from=debian /etc/os-release /os-release\n"
            )
            failures = self.module.check_repository(root)
            self.assertTrue(
                any("bare Debian image reference" in item for item in failures),
                failures,
            )
            self.assertFalse(
                any(
                    "upstream base is not pinned" in item and "assets" in item
                    for item in failures
                ),
                failures,
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required(root)
            dockerfile = root / "Dockerfile.worker"
            dockerfile.write_text("FROM alpine:3.22\n")
            failures = self.module.check_repository(root)
            self.assertTrue(
                any(
                    "Dockerfile.worker: upstream base is not pinned" in item
                    for item in failures
                ),
                failures,
            )

    def test_product_contract_mutations_are_reported(self) -> None:
        mutations = (
            (
                Path("crates/registry-relay/Dockerfile"),
                "/usr/local/bin/registry-relay-rhai-worker",
                "/usr/local/bin/removed-worker",
                "Relay worker binary",
            ),
            (
                Path("products/notary/Dockerfile"),
                "registry-notary-cel-worker",
                "removed-cel-worker",
                "Notary CEL worker binary",
            ),
            (
                Path("release/docker/Dockerfile.registry-relay"),
                "# syntax=",
                "# moved-syntax=",
                "frontend must be the first line",
            ),
            (
                Path("release/scripts/build-release-binaries.sh"),
                "--features registry-notary/registry-notary-cel,registry-notary/pkcs11",
                "--features registry-notary/registry-notary-cel",
                "PKCS#11-enabled release build",
            ),
            (
                Path("docs/site/scripts/check-registryctl-tutorials.sh"),
                'LINUX_TARGET="$REPO_ROOT/target/registryctl-tutorial-linux-amd64"',
                'LINUX_TARGET="$REPO_ROOT/target/other"',
                "registryctl tutorial linux target path",
            ),
            (
                Path(".github/workflows/ci.yml"),
                "hashFiles('docs/site/scripts/check-registryctl-tutorials.sh')",
                "hashFiles('Cargo.lock')",
                "registryctl tutorial cache builder identity",
            ),
            (
                Path("crates/registry-relay/scripts/run-live-consultation-journey.sh"),
                "postgres:16-trixie@sha256:",
                "postgres:16@",
                "pinned Debian 13 live-journey PostgreSQL",
            ),
        )
        for path, old, new, expected in mutations:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.copy_required(root)
                target = root / path
                text = target.read_text()
                self.assertIn(old, text)
                target.write_text(text.replace(old, new))
                failures = self.module.check_repository(root)
                self.assertTrue(
                    any(expected in item for item in failures),
                    failures,
                )

    def test_missing_required_surface_and_cache_restore_key_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required(root)
            missing = root / "products/notary/Dockerfile"
            missing.unlink()
            failures = self.module.check_repository(root)
            self.assertTrue(
                any("missing maintained image surface" in item for item in failures),
                failures,
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_required(root)
            workflow = root / ".github/workflows/ci.yml"
            text = workflow.read_text()
            marker = "- name: Execute registryctl tutorials from source"
            workflow.write_text(
                text.replace(marker, "restore-keys: old-key\n      " + marker, 1)
            )
            failures = self.module.check_repository(root)
            self.assertTrue(
                any("must not restore" in item for item in failures),
                failures,
            )


if __name__ == "__main__":
    unittest.main()
