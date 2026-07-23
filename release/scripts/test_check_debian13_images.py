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
NOTARY_POSTGRES_WORKFLOW = Path(
    ".github/workflows/notary-postgres-conformance.yml"
)
RELAY_POSTGRES_WORKFLOW = Path(
    ".github/workflows/relay-postgres-conformance.yml"
)

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

    def write_workflow(self, root: Path, name: str, text: str) -> Path:
        target = root / ".github" / "workflows" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

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

    def runtime_directives(self, relative: Path) -> tuple[str, ...]:
        product = "relay" if relative in self.module.RELAY_DOCKERFILES else "notary"
        binary = f"/usr/local/bin/registry-{product}"
        return (
            "HEALTHCHECK --interval=30s --timeout=5s "
            f'--start-period=10s --retries=3 CMD ["{binary}", "healthcheck"]',
            f'ENTRYPOINT ["{binary}"]',
            f"WORKDIR /var/lib/registry-{product}",
            f'CMD ["--config", "/etc/registry-{product}/config.yaml"]',
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

    def test_workflow_image_allowlist_has_only_reviewed_postgres_images(
        self,
    ) -> None:
        relay_image = "postgres:${{ matrix.postgresql }}-alpine"
        notary_images = {
            "postgres:16.13-alpine",
            "postgres:16.14-alpine",
            "postgres:17.9-alpine",
            "postgres:17.10-alpine",
            "postgres:18.3-alpine",
            "postgres:18.4-alpine",
        }
        self.assertEqual(
            {(RELAY_POSTGRES_WORKFLOW, relay_image)}
            | {(NOTARY_POSTGRES_WORKFLOW, image) for image in notary_images},
            set(self.module.WORKFLOW_IMAGE_ALLOWLIST),
        )
        self.assertEqual(
            {"image", "source_image", "target_image"},
            set(self.module.WORKFLOW_IMAGE_KEYS),
        )
        for rationale in self.module.WORKFLOW_IMAGE_ALLOWLIST.values():
            self.assertIn("not a project-owned Debian image", rationale)

        workflow = (
            "name: External PostgreSQL conformance\n"
            "jobs:\n"
            "  state-plane:\n"
            "    services:\n"
            "      postgres:\n"
            f'        image: "{relay_image}"\n'
        )
        root = self.fixture()
        self.write_workflow(root, RELAY_POSTGRES_WORKFLOW.name, workflow)
        notary_target = root / NOTARY_POSTGRES_WORKFLOW
        shutil.copyfile(ROOT / NOTARY_POSTGRES_WORKFLOW, notary_target)
        self.assertEqual([], self.module.check_repository(root))

        root = self.fixture()
        self.write_workflow(root, "copied-postgres.yml", workflow)
        self.assert_has_failure(
            root,
            "copied-postgres.yml: workflow image reference is not allowlisted",
        )

    def test_dynamic_workflow_images_are_denied_from_structured_forms(
        self,
    ) -> None:
        digest_image = "ghcr.io/example/tool@sha256:" + "a" * 64
        cases = (
            (
                "scalar-container.yaml",
                "name: Scalar container\n"
                "jobs:\n"
                "  build:\n"
                "    container: rust:1.95-trixie\n",
            ),
            (
                "flow-container.yml",
                'name: Flow container\njobs: {build: {container: "'
                + digest_image
                + '"}}\n',
            ),
            (
                "anchored-container.yml",
                "name: Anchored container\n"
                "x-builder: &builder rust:1.95-trixie\n"
                "jobs:\n"
                "  build:\n"
                "    container: *builder\n",
            ),
            (
                "mapping-container.yml",
                "name: Mapping container\n"
                "jobs:\n"
                "  build:\n"
                f'    container: {{image: "{digest_image}"}}\n',
            ),
            (
                "service-image.yml",
                "name: Service image\n"
                "jobs:\n"
                "  build:\n"
                "    services:\n"
                "      database:\n"
                f'        image: "{digest_image}"\n',
            ),
            (
                "docker-uses.yml",
                "name: Docker action\n"
                "jobs:\n"
                "  build:\n"
                "    steps:\n"
                "      - uses: docker://alpine:3.22\n",
            ),
            (
                "matrix-source-image.yml",
                "name: Migration source\n"
                "jobs:\n"
                "  build:\n"
                "    strategy:\n"
                "      matrix:\n"
                "        include:\n"
                "          - source_image: postgres:16.13-alpine\n",
            ),
            (
                "flow-target-image.yml",
                "name: Migration target\n"
                "jobs: {build: {strategy: {matrix: {include: "
                '[{target_image: "postgres:16.14-alpine"}]}}}}\n',
            ),
        )
        for name, workflow in cases:
            with self.subTest(name=name):
                root = self.fixture()
                relative = Path(".github/workflows") / name
                self.assertNotIn(relative, self.module.MAINTAINED_TEXT_PATHS)
                self.write_workflow(root, name, workflow)
                self.assert_has_failure(
                    root,
                    f"{relative}: workflow image reference is not allowlisted",
                )

    def test_notary_matrix_images_are_bound_to_the_owning_workflow(
        self,
    ) -> None:
        source = (ROOT / NOTARY_POSTGRES_WORKFLOW).read_text(encoding="utf-8")
        for key, reviewed, replacement in (
            ("source_image", "postgres:16.13-alpine", "postgres:16-alpine"),
            ("target_image", "postgres:16.14-alpine", "postgres:17-alpine"),
        ):
            with self.subTest(key=key):
                root = self.fixture()
                self.write_workflow(
                    root,
                    NOTARY_POSTGRES_WORKFLOW.name,
                    source.replace(
                        f"{key}: {reviewed}",
                        f"{key}: {replacement}",
                        1,
                    ),
                )
                failures = self.module.check_repository(root)
                self.assertTrue(
                    any(
                        f"{NOTARY_POSTGRES_WORKFLOW}: workflow image "
                        "reference is not allowlisted" in failure
                        for failure in failures
                    ),
                    failures,
                )
                self.assertNotIn(replacement, "\n".join(failures))

    def test_workflow_image_inventory_fails_closed(self) -> None:
        cases = (
            (
                "malformed.yml",
                "jobs: [\n",
                "workflow YAML parse failed",
            ),
            (
                "root-list.yml",
                "- jobs\n",
                "workflow YAML root must be a mapping",
            ),
            (
                "container-list.yml",
                "jobs:\n"
                "  build:\n"
                "    container:\n"
                "      - rust:1.95-trixie\n",
                "unsupported workflow image value",
            ),
            (
                "container-without-image.yml",
                "jobs:\n"
                "  build:\n"
                "    container:\n"
                "      options: --read-only\n",
                "unsupported workflow image value",
            ),
            (
                "mapping-image.yml",
                "jobs:\n"
                "  build:\n"
                "    services:\n"
                "      database:\n"
                "        image:\n"
                "          name: rust:1.95-trixie\n",
                "unsupported workflow image value",
            ),
            (
                "empty-docker-uses.yml",
                "jobs:\n"
                "  build:\n"
                "    steps:\n"
                "      - uses: docker://\n",
                "unsupported workflow image value",
            ),
            (
                "invalid-source-image.yml",
                "jobs:\n"
                "  build:\n"
                "    strategy:\n"
                "      matrix:\n"
                "        include:\n"
                "          - source_image: []\n",
                "unsupported workflow image value",
            ),
        )
        for name, workflow, failure in cases:
            with self.subTest(name=name):
                root = self.fixture()
                self.write_workflow(root, name, workflow)
                self.assert_has_failure(root, failure)

    def test_retired_markers_cover_dynamically_discovered_workflows(
        self,
    ) -> None:
        root = self.fixture()
        relative = Path(".github/workflows/dynamic-policy.yaml")
        self.write_workflow(
            root,
            relative.name,
            "name: Debian v12 compatibility\njobs: {}\n",
        )
        self.assert_has_failure(
            root,
            f"{relative}: retired Debian image generation marker remains",
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
            (
                RELEASE_BINARY_RECIPE,
                self.module.RELEASE_BUILDER_HANDOFF,
                "release_builder_image",
                "missing release builder handoff",
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

    def test_live_journey_uses_the_reviewed_postgres_alpine_image(
        self,
    ) -> None:
        exact = self.module.LIVE_JOURNEY_POSTGRES_ASSIGNMENT
        self.assertEqual(
            'readonly POSTGRES_IMAGE="postgres:16.13-alpine"',
            exact,
        )
        cases = (
            'readonly POSTGRES_IMAGE="postgres:16"',
            'readonly POSTGRES_IMAGE="postgres:16-alpine"',
            'readonly POSTGRES_IMAGE="postgres:17.9-alpine"',
            f"{exact}\n" + 'POSTGRES_IMAGE="postgres:16"',
            f"# {exact}\n" + 'POSTGRES_IMAGE="postgres:16"',
        )
        failure = (
            "live-journey PostgreSQL image assignment must remain the "
            "single reviewed value"
        )
        for replacement in cases:
            with self.subTest(replacement=replacement):
                root = self.fixture()
                target = root / LIVE_JOURNEY
                text = target.read_text(encoding="utf-8")
                self.assertIn(exact, text)
                target.write_text(
                    text.replace(exact, replacement, 1),
                    encoding="utf-8",
                )
                failures = self.module.check_repository(root)
                self.assertTrue(
                    any(failure in item for item in failures),
                    failures,
                )
                for line in replacement.splitlines():
                    if line != exact:
                        self.assertNotIn(line, "\n".join(failures))

    def test_live_journey_postgres_consumers_are_bound_to_both_commands(
        self,
    ) -> None:
        consumer = self.module.LIVE_JOURNEY_POSTGRES_CONSUMER
        replacement = '  "postgres:17.9-alpine" \\'
        failure_fragments = (
            "live-journey PostgreSQL certificate setup command",
            "live-journey PostgreSQL server command",
        )
        source = (ROOT / LIVE_JOURNEY).read_text(encoding="utf-8")
        self.assertEqual(2, source.splitlines().count(consumer))
        indexes = [
            index for index, line in enumerate(source.splitlines()) if line == consumer
        ]
        for occurrence, failure in zip(indexes, failure_fragments):
            with self.subTest(occurrence=occurrence):
                root = self.fixture()
                target = root / LIVE_JOURNEY
                lines = source.splitlines()
                lines[occurrence] = replacement
                lines.append(consumer)
                target.write_text("\n".join(lines) + "\n", encoding="utf-8")
                failures = self.module.check_repository(root)
                self.assertTrue(
                    any(failure in item for item in failures),
                    failures,
                )
                self.assertNotIn(replacement, "\n".join(failures))

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
                "missing release Docker builder command tail",
            ),
            (
                TUTORIAL_CHECK,
                self.module.TUTORIAL_BUILDER_CONSUMER,
                '\t\t"rust:1.95-trixie" \\',
                "missing registryctl tutorial Docker builder command tail",
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

    def test_docker_builder_tails_reject_preceding_positional_images(
        self,
    ) -> None:
        cases = (
            (
                RELEASE_BINARY_RECIPE,
                self.module.RELEASE_BUILDER_PREFIX,
                self.module.RELEASE_BUILDER_CONSUMER,
                "  ",
                "does not match the exact expected header/options/image prefix",
            ),
            (
                TUTORIAL_CHECK,
                self.module.TUTORIAL_BUILDER_PREFIX,
                self.module.TUTORIAL_BUILDER_CONSUMER,
                "\t\t",
                "does not match the exact expected header/options/image prefix",
            ),
            (
                LIVE_JOURNEY,
                self.module.LIVE_JOURNEY_BUILDER_PREFIX,
                self.module.LIVE_JOURNEY_BUILDER,
                "    ",
                "does not match the exact expected header/options/image prefix",
            ),
        )
        for (
            relative,
            expected_prefix,
            approved,
            indentation,
            failure,
        ) in cases:
            command_start = expected_prefix[0]
            last_option = expected_prefix[-2]
            for image in ("alpine:3.22", "debian:trixie-slim"):
                positional = f"{indentation}{image} \\"
                positions = (
                    (
                        "before-first-option",
                        command_start,
                        command_start + "\n" + positional,
                    ),
                    (
                        "before-last-option",
                        last_option,
                        positional + "\n" + last_option,
                    ),
                    (
                        "before-approved-image",
                        approved,
                        positional + "\n" + approved,
                    ),
                )
                for position, anchor, replacement in positions:
                    with self.subTest(
                        relative=relative,
                        image=image,
                        position=position,
                    ):
                        root = self.fixture()
                        target = root / relative
                        text = target.read_text(encoding="utf-8")
                        self.assertIn(anchor, text)
                        target.write_text(
                            text.replace(anchor, replacement, 1),
                            encoding="utf-8",
                        )
                        self.assert_has_failure(root, failure)

    def test_docker_builder_prefixes_reject_images_on_option_lines(
        self,
    ) -> None:
        cases = (
            (
                RELEASE_BINARY_RECIPE,
                self.module.RELEASE_BUILDER_PREFIX,
            ),
            (
                TUTORIAL_CHECK,
                self.module.TUTORIAL_BUILDER_PREFIX,
            ),
            (
                LIVE_JOURNEY,
                self.module.LIVE_JOURNEY_BUILDER_PREFIX,
            ),
        )
        failure = "does not match the exact expected header/options/image prefix"
        for relative, expected_prefix in cases:
            for image in ("alpine:3.22", "debian:trixie-slim"):
                for position, option in (
                    ("early", expected_prefix[1]),
                    ("late", expected_prefix[-2]),
                ):
                    with self.subTest(
                        relative=relative,
                        image=image,
                        position=position,
                    ):
                        root = self.fixture()
                        target = root / relative
                        text = target.read_text(encoding="utf-8")
                        self.assertIn(option, text)
                        mutated = option[:-1] + f"{image} \\"
                        target.write_text(
                            text.replace(option, mutated, 1),
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

    def test_dockerfile_copy_sources_are_reviewed_stages_or_contexts(
        self,
    ) -> None:
        self.assertEqual(
            set(self.module.DOCKERFILES),
            set(self.module.DOCKERFILE_NAMED_CONTEXTS),
        )
        for relative in self.module.DOCKERFILES:
            with self.subTest(relative=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                aliases = {
                    match.group("alias").casefold()
                    for match in self.module.FROM_RE.finditer(text)
                    if match.group("alias") is not None
                }
                failures: list[str] = []
                sources = set(
                    self.module.collect_dockerfile_copy_sources(
                        text,
                        relative,
                        failures,
                    )
                )
                self.assertEqual([], failures)
                external_sources = {
                    source for source in sources if source.casefold() not in aliases
                }
                self.assertEqual(
                    self.module.DOCKERFILE_NAMED_CONTEXTS[relative],
                    external_sources,
                )

    def test_dockerfile_copy_sources_reject_external_images_and_contexts(
        self,
    ) -> None:
        sources = (
            "unreviewed-context",
            "alpine:3.22",
            "ghcr.io/example/tool@sha256:" + "a" * 64,
        )
        failure = (
            "COPY --from source is not a declared stage or reviewed named "
            "build context"
        )
        for relative in self.module.DOCKERFILES:
            for source in sources:
                with self.subTest(relative=relative, source=source):
                    root = self.fixture()
                    target = root / relative
                    text = target.read_text(encoding="utf-8")
                    target.write_text(
                        text + f"\n  copy --chown=65532:65532 --from={source} "
                        "/bin/tool /bin/tool\n",
                        encoding="utf-8",
                    )
                    failures = self.module.check_repository(root)
                    self.assertTrue(
                        any(failure in item for item in failures),
                        failures,
                    )
                    self.assertNotIn(source, "\n".join(failures))

    def test_multiline_dockerfile_copy_sources_allow_reviewed_sources(
        self,
    ) -> None:
        cases = (
            (
                Path("crates/registry-relay/Dockerfile"),
                (
                    "COPY --from=registry-platform /Cargo.toml /Cargo.lock "
                    "/workspace/registry-platform/"
                ),
                "COPY --chown=0:0 \\\n"
                "  # Supplied as a named BuildKit context.\n"
                "  --from=registry-platform \\\n"
                "  /Cargo.toml /Cargo.lock /workspace/registry-platform/",
            ),
            (
                Path("release/docker/Dockerfile.registry-relay"),
                "COPY --from=runtime-root /workspace/runtime-root/ /",
                "COPY \\\n"
                "  --from=runtime-root \\\n"
                "  --chown=65532:65532 \\\n"
                "  /workspace/runtime-root/ /",
            ),
        )
        for relative, exact, multiline in cases:
            with self.subTest(relative=relative):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                self.assertIn(exact, text)
                target.write_text(
                    text.replace(exact, multiline, 1),
                    encoding="utf-8",
                )
                self.assertEqual([], self.module.check_repository(root))

    def test_multiline_dockerfile_copy_sources_reject_external_images(
        self,
    ) -> None:
        relative = Path("crates/registry-relay/Dockerfile")
        sources = (
            "alpine:3.22",
            "ghcr.io/example/tool@sha256:" + "a" * 64,
        )
        instructions = (
            "COPY \\\n"
            "  --from={source} \\\n"
            "  /bin/tool /bin/tool\n",
            "COPY --chown=65532:65532 \\\n"
            "  --from={source} \\\n"
            "  /bin/tool /bin/tool\n",
            "COPY --from={source} \\\n"
            "  --chown=65532:65532 \\\n"
            "  /bin/tool /bin/tool\n",
            "COPY --chown=65532:65532 \\\n"
            "  # The source option remains part of this instruction.\n"
            "  --from={source} \\\n"
            "  /bin/tool /bin/tool\n",
        )
        failure = (
            "COPY --from source is not a declared stage or reviewed named "
            "build context"
        )
        for source in sources:
            for instruction in instructions:
                with self.subTest(source=source, instruction=instruction):
                    root = self.fixture()
                    target = root / relative
                    text = target.read_text(encoding="utf-8")
                    target.write_text(
                        text + "\n" + instruction.format(source=source),
                        encoding="utf-8",
                    )
                    failures = self.module.check_repository(root)
                    self.assertTrue(
                        any(failure in item for item in failures),
                        failures,
                    )
                    self.assertNotIn(source, "\n".join(failures))

    def test_dockerfile_copy_normalization_fails_closed(self) -> None:
        relative = Path("crates/registry-relay/Dockerfile")
        cases = (
            (
                "unterminated",
                "",
                "\nCOPY --chown=65532:65532 \\\n"
                "  # No continued instruction follows.\n",
                "unterminated Dockerfile line continuation",
            ),
            (
                "alternate-escape",
                "# escape=`\n",
                "\nCOPY --chown=65532:65532 `\n"
                "  --from=alpine:3.22 `\n"
                "  /bin/tool /bin/tool\n",
                "unsupported Dockerfile escape directive",
            ),
        )
        for name, prefix, suffix, failure in cases:
            with self.subTest(name=name):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                target.write_text(prefix + text + suffix, encoding="utf-8")
                self.assert_has_failure(root, failure)

    def test_multiline_copy_source_tokens_cannot_shadow_reviewed_names(
        self,
    ) -> None:
        relative = Path("crates/registry-relay/Dockerfile")
        for reviewed in ("builder", "registry-platform"):
            with self.subTest(reviewed=reviewed):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                target.write_text(
                    text
                    + f"\nCOPY --from={reviewed}\\\n"
                    "-external \\\n"
                    "  /bin/tool /bin/tool\n",
                    encoding="utf-8",
                )
                self.assert_has_failure(
                    root,
                    f"{relative}: COPY --from source is not a declared stage "
                    "or reviewed named build context",
                )

    def test_dockerfile_named_context_allowlist_is_path_bounded(self) -> None:
        for relative, contexts in self.module.DOCKERFILE_NAMED_CONTEXTS.items():
            for context in contexts:
                with self.subTest(relative=relative, context=context):
                    root = self.fixture()
                    target = root / relative
                    text = target.read_text(encoding="utf-8")
                    exact = f"--from={context}"
                    self.assertIn(exact, text)
                    target.write_text(
                        text.replace(
                            exact,
                            f"--from={context}-copy",
                            1,
                        ),
                        encoding="utf-8",
                    )
                    self.assert_has_failure(
                        root,
                        f"{relative}: COPY --from source is not a declared "
                        "stage or reviewed named build context",
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
            (
                '  cmd ["--config", "/tmp/override.yaml"]',
                "exactly one active CMD",
            ),
            ("USER 0", "must inherit the nonroot base user"),
            (
                "  volume /var/lib/registry",
                "declare no writable VOLUME mount surfaces",
            ),
        )
        comments = "\n".join(
            (
                "# HEALTHCHECK NONE",
                '# ENTRYPOINT ["/tmp/override"]',
                "# WORKDIR /tmp",
                '# CMD ["--config", "/tmp/override.yaml"]',
                "# USER 0",
                "# VOLUME /var/lib/registry",
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

            with self.subTest(relative=relative, replaced_cmd=True):
                root = self.fixture()
                target = root / relative
                text = target.read_text(encoding="utf-8")
                canonical_cmd = self.runtime_directives(relative)[-1]
                target.write_text(
                    text.replace(
                        canonical_cmd,
                        'CMD ["/tmp/override"]',
                        1,
                    ),
                    encoding="utf-8",
                )
                self.assert_has_failure(root, "exactly one active CMD")

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
        for allowed in self.module.TUTORIAL_CACHE_KEYS[1:]:
            with self.subTest(allowed=allowed):
                root = self.fixture()
                target = root / CI_WORKFLOW
                text = target.read_text(encoding="utf-8")
                target.write_text(
                    text.replace(exact, allowed, 1),
                    encoding="utf-8",
                )
                self.assertEqual([], self.module.check_repository(root))

        wrong_value = (
            "registryctl-tutorial-${{ runner.os }}-"
            "${{ hashFiles('Cargo.lock') }}"
        )
        cases = (
            ("", "missing registryctl tutorial builder cache key"),
            (
                f"          # {exact.strip()}",
                "missing registryctl tutorial builder cache key",
            ),
            (
                f"          key: {wrong_value}",
                "missing registryctl tutorial builder cache key",
            ),
            (
                f"          'key': {wrong_value}",
                "missing registryctl tutorial builder cache key",
            ),
            (
                f'          "key": {wrong_value}',
                "missing registryctl tutorial builder cache key",
            ),
            (
                exact + "\n" + self.module.TUTORIAL_CACHE_KEYS[1],
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
