#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "release/scripts/registry-release"
POSTGRESQL_REF_PATH = ROOT / "release/registryctl-postgresql-image.ref"
IMAGE_DIGEST = "sha256:" + "a" * 64
IMAGE_DIGEST_REF = f"ghcr.io/registrystack/registry-notary@{IMAGE_DIGEST}"
NATIVE_CLI_AUTHORING_COMMANDS = (
    '"${registryctl}" init --from spreadsheet --project-dir "${project_dir}"',
    '"${registryctl}" test --project-dir "${project_dir}"',
    '"${registryctl}" preflight --project-dir "${project_dir}" --environment local',
    '"${registryctl}" check --project-dir "${project_dir}" '
    "--environment local --explain",
    '"${registryctl}" build --project-dir "${project_dir}" --environment local',
)
NATIVE_CLI_PROVENANCE_CONTROLS = (
    'candidate_expected_sha256="$(expected_sha256_for "${asset}")"',
    'candidate_actual_sha256="$(sha256_file "${candidate_binary}")"',
    '"${candidate_actual_sha256}" != "${candidate_expected_sha256}"',
    'installer_expected_sha256="$(expected_sha256_for "${installer_asset}")"',
    'installer_actual_sha256="$(sha256_file "${installer}")"',
    '"${installer_actual_sha256}" != "${installer_expected_sha256}"',
    'run_sanitized_command install bash "${installer}"',
    'installed_sha256="$(sha256_file "${registryctl}")"',
    '"${installed_sha256}" != "${candidate_expected_sha256}"',
    'cmp -s "${candidate_binary}" "${registryctl}"',
)


def native_cli_authoring_command_positions(script: str) -> list[int]:
    return [script.index(command) for command in NATIVE_CLI_AUTHORING_COMMANDS]


def native_cli_provenance_control_positions(script: str) -> list[int]:
    return [script.index(control) for control in NATIVE_CLI_PROVENANCE_CONTROLS]


def load_debian13_image_check():
    path = ROOT / "release/scripts/check-debian13-images.py"
    spec = importlib.util.spec_from_file_location("check_debian13_images", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_registryctl_image_lock():
    path = ROOT / "release/scripts/registryctl_image_lock.py"
    spec = importlib.util.spec_from_file_location("registryctl_image_lock", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_registry_release():
    module_name = "registry_release_module"
    loader = SourceFileLoader(module_name, str(TOOL))
    spec = importlib.util.spec_from_loader(module_name, loader)
    if spec is None:
        raise ImportError(f"could not load module spec from {TOOL}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(TOOL.parent))
    try:
        loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class RegistryReleaseTest(unittest.TestCase):
    def test_candidate_request_requires_current_source_workflow_revision(
        self,
    ) -> None:
        registry_release = load_registry_release()
        source = "a" * 40
        context = {
            "repo": ROOT,
            "selected": {"data": {"stack": {}}},
        }
        with (
            mock.patch.object(
                registry_release,
                "prepare_release_context",
                return_value=context,
            ),
            mock.patch.object(
                registry_release,
                "refresh_protected_main",
                return_value=source,
            ),
            mock.patch.object(
                registry_release,
                "resolve_commit",
                return_value=source,
            ),
            mock.patch.object(registry_release, "run_checked") as dispatch,
        ):
            accepted = registry_release.request_release_candidate(
                ROOT,
                "1.2.3",
                "beta-20",
                source,
                "origin/main",
                "registrystack/registry-stack",
                print_request=False,
            )

        self.assertEqual(0, accepted)
        dispatch.assert_called_once()

        stale_source = "b" * 40

        def resolve(_repo: Path, revision: str, _description: str) -> str:
            return stale_source if revision == stale_source else source

        with (
            mock.patch.object(
                registry_release,
                "prepare_release_context",
                return_value=context,
            ),
            mock.patch.object(
                registry_release,
                "refresh_protected_main",
                return_value=source,
            ),
            mock.patch.object(
                registry_release,
                "resolve_commit",
                side_effect=resolve,
            ),
            mock.patch.object(registry_release, "run_checked") as no_dispatch,
        ):
            rejected = registry_release.request_release_candidate(
                ROOT,
                "1.2.3",
                "beta-20",
                stale_source,
                "origin/main",
                "registrystack/registry-stack",
                print_request=False,
            )

        self.assertEqual(1, rejected)
        no_dispatch.assert_not_called()

    def test_candidate_ancestry_accepts_main_advancement_and_rejects_unreachable_source(
        self,
    ) -> None:
        registry_release = load_registry_release()
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"],
                cwd=repo,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Test"],
                cwd=repo,
                check=True,
            )
            (repo / "source").write_text("source\n", encoding="utf-8")
            subprocess.run(["git", "add", "source"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-m", "source"], cwd=repo, check=True)
            source = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo, text=True
            ).strip()
            (repo / "advance").write_text("advance\n", encoding="utf-8")
            subprocess.run(["git", "add", "advance"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-m", "advance"], cwd=repo, check=True)
            advanced_main = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo, text=True
            ).strip()

            registry_release.validate_candidate_ancestry(
                repo,
                source_sha=source,
                workflow_revision=source,
                protected_main_sha=advanced_main,
            )

            tree = subprocess.check_output(
                ["git", "rev-parse", f"{source}^{{tree}}"], cwd=repo, text=True
            ).strip()
            unrelated = subprocess.check_output(
                ["git", "commit-tree", tree, "-m", "unrelated"],
                cwd=repo,
                text=True,
            ).strip()
            with self.assertRaisesRegex(
                registry_release.ReleasePlanError,
                "not reachable from protected main",
            ):
                registry_release.validate_candidate_ancestry(
                    repo,
                    source_sha=unrelated,
                    workflow_revision=source,
                    protected_main_sha=advanced_main,
                )

    def test_candidate_artifact_download_removes_transport_archive(self) -> None:
        registry_release = load_registry_release()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination = root / "candidate" / "payload"
            archive = destination.parent / "artifact-42.zip"

            def download(_endpoint: str, path: Path) -> None:
                self.assertTrue(path.parent.is_dir())
                path.write_bytes(b"archive")

            def extract(
                path: Path,
                output: Path,
                *,
                expected_sha256: str,
            ) -> None:
                self.assertEqual(archive, path)
                self.assertEqual("a" * 64, expected_sha256)
                output.mkdir()
                (output / "payload.txt").write_text("verified\n", encoding="utf-8")

            with (
                mock.patch.object(
                    registry_release,
                    "download_gh_api_bytes",
                    side_effect=download,
                ),
                mock.patch.object(
                    registry_release.release_candidate,
                    "extract_artifact_archive",
                    side_effect=extract,
                ),
            ):
                registry_release.download_candidate_artifact(
                    "registrystack/registry-stack",
                    42,
                    destination,
                    expected_archive_sha256="a" * 64,
                )

            self.assertFalse(archive.exists())
            self.assertEqual(
                "verified\n",
                (destination / "payload.txt").read_text(encoding="utf-8"),
            )

    def test_candidate_artifact_download_removes_archive_after_rejection(self) -> None:
        registry_release = load_registry_release()
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "candidate" / "payload"
            archive = destination.parent / "artifact-42.zip"

            def download(_endpoint: str, path: Path) -> None:
                path.write_bytes(b"archive")

            with (
                mock.patch.object(
                    registry_release,
                    "download_gh_api_bytes",
                    side_effect=download,
                ),
                mock.patch.object(
                    registry_release.release_candidate,
                    "extract_artifact_archive",
                    side_effect=registry_release.release_candidate.CandidateError(
                        "digest mismatch"
                    ),
                ),
                self.assertRaisesRegex(
                    registry_release.ReleasePlanError,
                    "cannot verify candidate artifact 42: digest mismatch",
                ),
            ):
                registry_release.download_candidate_artifact(
                    "registrystack/registry-stack",
                    42,
                    destination,
                    expected_archive_sha256="a" * 64,
                )

            self.assertFalse(archive.exists())

    def test_registryctl_image_lock_schema_boundary_preserves_historical_v1(
        self,
    ) -> None:
        image_lock = load_registryctl_image_lock()

        self.assertEqual(
            image_lock.SCHEMA_V1,
            image_lock.schema_for_release_version("0.13.0"),
        )
        self.assertEqual(
            image_lock.SCHEMA_V2,
            image_lock.schema_for_release_version("0.14.0"),
        )

    def test_registryctl_image_lock_validates_v1_and_reviewed_v2_images(
        self,
    ) -> None:
        image_lock = load_registryctl_image_lock()
        product_images = {
            "registry-relay": (
                "ghcr.io/registrystack/registry-relay@sha256:" + "a" * 64
            ),
            "registry-notary": (
                "ghcr.io/registrystack/registry-notary@sha256:" + "b" * 64
            ),
        }

        self.assertEqual(
            product_images,
            image_lock.validate_images(image_lock.SCHEMA_V1, product_images),
        )

        v2_images = {
            **product_images,
            "postgresql": image_lock.reviewed_postgresql_image_ref(),
        }
        self.assertEqual(
            v2_images,
            image_lock.validate_images(image_lock.SCHEMA_V2, v2_images),
        )

        without_postgresql = dict(v2_images)
        del without_postgresql["postgresql"]
        with self.assertRaisesRegex(ValueError, "must contain exactly"):
            image_lock.validate_images(
                image_lock.SCHEMA_V2,
                without_postgresql,
            )

        drifted_postgresql = dict(v2_images)
        drifted_postgresql["postgresql"] = (
            "docker.io/library/postgres@sha256:" + "c" * 64
        )
        with self.assertRaisesRegex(ValueError, "reviewed release-tooling pin"):
            image_lock.validate_images(
                image_lock.SCHEMA_V2,
                drifted_postgresql,
            )

    def test_registryctl_image_lock_rejects_another_postgresql_input(self) -> None:
        image_lock = load_registryctl_image_lock()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "postgresql.ref"
            path.write_text(
                "docker.io/library/postgres@sha256:" + "c" * 64 + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "reviewed release-tooling pin"):
                image_lock.read_reviewed_postgresql_image_ref(path)

    def test_required_ci_contexts_wrap_path_gated_jobs(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        )
        jobs = workflow["jobs"]
        required_contexts = {
            "release-tool": (
                "release-tool-required",
                "Release tooling",
                "release_tool",
            ),
            "release-source-proof": (
                "release-source-proof-required",
                "Release source proof",
                "release_source_proof",
            ),
            "docs": (
                "docs-required",
                "Docs",
                "docs",
            ),
        }

        for check_job_id, (
            required_job_id,
            context_name,
            path_output,
        ) in required_contexts.items():
            with self.subTest(context=context_name):
                check_job = jobs[check_job_id]
                self.assertEqual(f"{context_name} checks", check_job["name"])
                self.assertEqual(
                    f"needs.changes.outputs.{path_output} == 'true'",
                    check_job["if"],
                )

                required_job = jobs[required_job_id]
                self.assertEqual(context_name, required_job["name"])
                expected_needs = {"changes", check_job_id}
                if check_job_id == "docs":
                    expected_needs.add("docs-archives")
                self.assertEqual(expected_needs, set(required_job["needs"]))
                self.assertEqual("${{ always() }}", required_job["if"])
                self.assertEqual(1, len(required_job["steps"]))
                step = required_job["steps"][0]
                self.assertEqual(
                    "${{ needs.changes.result }}",
                    step["env"]["CHANGES_RESULT"],
                )
                self.assertEqual(
                    f"${{{{ needs.changes.outputs.{path_output} }}}}",
                    step["env"]["REQUIRED"],
                )
                self.assertEqual(
                    f"${{{{ needs.{check_job_id}.result }}}}",
                    step["env"]["RESULT"],
                )
                self.assertIn(
                    "success:true:success|success:false:skipped",
                    step["run"],
                )

    def test_required_rust_context_aggregates_path_gated_shards(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        )
        jobs = workflow["jobs"]
        rust_result = jobs["rust-result"]

        self.assertEqual("Rust workspace", rust_result["name"])
        self.assertEqual("always()", rust_result["if"])
        self.assertEqual(
            {
                "changes",
                "rust-policy",
                "rust-quality",
                "rust-tests",
                "notary-contracts",
                "relay-contracts",
            },
            set(rust_result["needs"]),
        )
        self.assertEqual(
            "${{ toJSON(needs) }}",
            rust_result["env"]["RUST_JOB_RESULTS"],
        )
        self.assertEqual(1, len(rust_result["steps"]))
        self.assertIn(
            'details["result"] not in {"success", "skipped"}',
            rust_result["steps"][0]["run"],
        )

    def legacy_maintained_images_follow_debian13_contract(self) -> None:
        module = load_debian13_image_check()
        self.assertEqual([], module.check_repository(ROOT))

    def test_debian13_contract_rejects_retired_base_and_unpinned_base(self) -> None:
        module = load_debian13_image_check()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in module.MAINTAINED_TEXT_PATHS:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(
                    (ROOT / relative).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )

            relay_dockerfile = root / "crates/registry-relay/Dockerfile"
            text = relay_dockerfile.read_text(encoding="utf-8")
            text = text.replace(
                module.RUST_BUILDER,
                "rust:1.95-" + "book" + "worm",
                1,
            )
            relay_dockerfile.write_text(text, encoding="utf-8")

            failures = module.check_repository(root)
            self.assertTrue(
                any(
                    "retired Debian image generation marker" in failure
                    for failure in failures
                )
            )
            self.assertTrue(
                any("not pinned by immutable digest" in failure for failure in failures)
            )

    def test_debian13_contract_binds_builder_to_candidate_workflow(self) -> None:
        module = load_debian13_image_check()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in module.MAINTAINED_TEXT_PATHS:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(
                    (ROOT / relative).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )

            candidate_path = root / ".github/workflows/release-candidate.yml"
            candidate = candidate_path.read_text(encoding="utf-8").replace(
                f"  RELEASE_BUILDER_IMAGE: {module.RUST_BUILDER}\n",
                "",
                1,
            )
            candidate_path.write_text(candidate, encoding="utf-8")

            release_path = root / ".github/workflows/release.yml"
            release = release_path.read_text(encoding="utf-8").replace(
                "env:\n",
                f"env:\n  RELEASE_BUILDER_IMAGE: {module.RUST_BUILDER}\n",
                1,
            )
            release_path.write_text(release, encoding="utf-8")

            failures = module.check_repository(root)
            self.assertTrue(
                any(
                    ".github/workflows/release-candidate.yml: missing pinned "
                    "Debian 13 release builder" in failure
                    for failure in failures
                )
            )
            self.assertTrue(
                any(
                    "promotion workflow must not rebuild candidate artifacts"
                    in failure
                    for failure in failures
                )
            )

    def test_source_tutorial_does_not_claim_a_container_builder(self) -> None:
        module = load_debian13_image_check()
        tutorial = (
            ROOT / "docs/site/scripts/check-registryctl-tutorials.sh"
        ).read_text(encoding="utf-8")

        self.assertNotIn("BUILDER_IMAGE=", tutorial)
        self.assertNotIn(module.RUST_BUILDER, tutorial)
        self.assertIn(
            "exact runtime sequence is release-gated from the sealed candidate payload",
            tutorial,
        )

    def test_contributing_documents_major_functionality_test_policy(self) -> None:
        text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")

        self.assertIn("major new functionality MUST add", text)
        self.assertIn("automated test suite", text)
        self.assertIn("change proposal or pull request", text)

    def test_contributing_documents_repeatable_build_policy(self) -> None:
        text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")

        self.assertIn("Repeatable Builds And Generated Outputs", text)
        self.assertIn("exactly the same bit-for-bit result", text)
        self.assertIn(".github/workflows/release.yml", text)

    def test_registryctl_installer_uses_the_versioned_release_asset(self) -> None:
        text = (ROOT / "crates/registryctl/README.md").read_text(encoding="utf-8")

        self.assertIn("registryctl-${tag}-install.sh", text)
        self.assertIn('bash "./registryctl-${tag}-install.sh"', text)
        self.assertNotIn("raw.githubusercontent.com", text)

    def test_release_image_packaging_uses_release_dockerfiles(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        recipe = (ROOT / "release/scripts/build-release-image.sh").read_text(
            encoding="utf-8"
        )
        release_dockerfiles = [
            "release/docker/Dockerfile.registry-notary",
            "release/docker/Dockerfile.registry-relay",
        ]

        for dockerfile in release_dockerfiles:
            self.assertIn("release/docker/Dockerfile.${name}", recipe)
            text = (ROOT / dockerfile).read_text(encoding="utf-8")
            self.assertIn("dist/image-bin", text)
        self.assertIn("release/scripts/build-release-image.sh", workflow)

    def legacy_candidate_workflow_explicitly_binds_dispatch_action(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("REQUEST_EVENT_ACTION: ${{ github.event.action }}", workflow)
        self.assertIn('"${REQUEST_EVENT_ACTION}" != "release_candidate"', workflow)
        self.assertNotIn("GITHUB_EVENT_ACTION", workflow)

    def legacy_candidate_binary_inventory_validates_sorted_lists(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        compare_step = workflow[
            workflow.index("      - name: Validate canonical binary inventory") :
            workflow.index(
                "      - name: Install pinned candidate inspection tools"
            )
        ]
        expected_block = compare_step[
            compare_step.index('expected="$(') :
            compare_step.index('          )"', compare_step.index('expected="$('))
        ]

        self.assertIn("| sort", expected_block)
        self.assertIn(
            'actual="$(find inputs/build-a/dist/bin '
            "-maxdepth 1 -type f -printf '%f\\n' | sort)\"",
            compare_step,
        )

    def legacy_release_images_publish_and_executably_verify_oci_labels(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        images_job = workflow[
            workflow.index("\n  build-a:") : workflow.index("\n  other-platforms:")
        ]
        verification_job = workflow[workflow.index("\n  verify-candidate:") :]
        recipe = (ROOT / "release/scripts/build-release-image.sh").read_text(
            encoding="utf-8"
        )

        for label in (
            '"org.opencontainers.image.source=${source_label}"',
            '"org.opencontainers.image.revision=${revision_label}"',
            '"org.opencontainers.image.version=${version_label}"',
        ):
            self.assertIn(label, recipe)
        self.assertEqual(1, images_job.count("release/scripts/build-release-image.sh"))
        self.assertNotIn("docker buildx build", images_job)
        for smoke_only_environment in (
            "RELEASE_IMAGE_CONTEXT",
            "RELEASE_IMAGE_NO_CACHE",
            "RELEASE_IMAGE_REGISTRY_INSECURE",
            "RELEASE_BUILDKIT_NETWORK",
        ):
            self.assertNotIn(smoke_only_environment, images_job)
        checker = "python3 release/scripts/check-release-image-oci-labels.py"
        self.assertEqual(1, verification_job.count(checker))
        self.assertIn(
            '--source "https://github.com/${GITHUB_REPOSITORY}"', verification_job
        )
        self.assertIn(
            '--revision "${{ needs.validate.outputs.source_sha }}"', verification_job
        )
        self.assertIn(
            '--version "${{ needs.validate.outputs.version }}"', verification_job
        )
        self.assertIn(
            'relay_features="$(<crates/registry-relay/canonical-release-features.txt)"',
            verification_job,
        )
        self.assertIn(
            '--expected-label "org.registrystack.registry-relay.features=${relay_features}"',
            verification_job,
        )
        self.assertNotIn("{{json .Image.config}}", workflow)

    def legacy_release_cargo_cache_is_scoped_to_builder_image(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        binaries_job = workflow[
            workflow.index("\n  build-a:") : workflow.index("\n  other-platforms:")
        ]

        fingerprint_step = binaries_job.index("Fingerprint exact-key Cargo cache")
        cache_step = binaries_job.index("Restore exact-key Cargo cache")
        self.assertLess(fingerprint_step, cache_step)
        self.assertIn(
            "printf '%s' \"${RELEASE_BUILDER_IMAGE}\" | sha256sum",
            binaries_job,
        )
        self.assertIn(
            "sha256sum release/scripts/build-release-binaries.sh",
            binaries_job,
        )
        self.assertIn("recipe_fingerprint", binaries_job)
        self.assertIn("builder_fingerprint", binaries_job)
        self.assertIn("recipe_fingerprint", binaries_job)
        self.assertNotIn("restore-keys:", binaries_job)
        self.assertNotIn(
            "registry-stack-release-cargo-${{ runner.os }}-rust-1.95.0-",
            binaries_job,
        )

    def legacy_release_build_wrappers_are_executable_and_canonical(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        ci_workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        binaries_job = workflow[
            workflow.index("\n  build-a:") : workflow.index("\n  other-platforms:")
        ]
        images_job = workflow[
            workflow.index("\n  build-a:") : workflow.index("\n  other-platforms:")
        ]
        binary_recipe_path = ROOT / "release/scripts/build-release-binaries.sh"
        image_recipe_path = ROOT / "release/scripts/build-release-image.sh"
        binary_recipe = binary_recipe_path.read_text(encoding="utf-8")
        image_recipe = image_recipe_path.read_text(encoding="utf-8")

        self.assertTrue(binary_recipe_path.stat().st_mode & stat.S_IXUSR)
        self.assertTrue(image_recipe_path.stat().st_mode & stat.S_IXUSR)
        self.assertEqual(
            1,
            binaries_job.count(
                'release/scripts/build-release-binaries.sh "${{ needs.validate.outputs.version }}"'
            ),
        )
        self.assertNotIn("docker run --rm", binaries_job)
        self.assertIn('--volume "${repo_root}:/workspace"', binary_recipe)
        self.assertIn(
            '--volume "${release_cargo_home}:/workspace/.cargo-home"', binary_recipe
        )
        self.assertIn(
            '--volume "${release_target_dir}:/workspace/target"', binary_recipe
        )
        self.assertIn("--env CARGO_HOME=/workspace/.cargo-home", binary_recipe)
        self.assertIn("--env CARGO_TARGET_DIR=/workspace/target", binary_recipe)
        self.assertIn("--env CARGO_INCREMENTAL=0", binary_recipe)
        self.assertIn("--env HOME=/workspace", binary_recipe)
        self.assertIn("--platform linux/amd64", binary_recipe)
        self.assertIn("--locked", binary_recipe)
        self.assertIn(
            "--remap-path-prefix=/workspace/.cargo-home=/cargo-home", binary_recipe
        )
        self.assertIn("--remap-path-prefix=/workspace=/source", binary_recipe)
        self.assertIn(
            "registry-notary/registry-notary-cel,registry-notary/pkcs11",
            binary_recipe,
        )
        self.assertIn("RELEASE_BUILDER_IMAGE must remain pinned", binary_recipe)
        self.assertIn(
            '"${RELEASE_BUILDER_IMAGE}" != "${default_builder_image}"', binary_recipe
        )
        self.assertIn(
            'rm -rf -- "${repo_root}/dist/bin" "${repo_root}/dist/image-bin"',
            binary_recipe,
        )

        cargo_commands = [
            "cargo build" + chunk.split("\n    cp ", 1)[0]
            for chunk in binary_recipe.split("cargo build")[1:]
        ]
        registryctl_commands = [
            command for command in cargo_commands if "-p registryctl" in command
        ]
        relay_commands = [
            command for command in cargo_commands if "-p registry-relay" in command
        ]
        self.assertEqual(1, len(registryctl_commands), cargo_commands)
        self.assertEqual(1, len(relay_commands), cargo_commands)
        self.assertNotEqual(registryctl_commands[0], relay_commands[0])
        self.assertNotIn("-p registry-relay", registryctl_commands[0])
        self.assertNotIn("-p registryctl", relay_commands[0])
        self.assertIn("--no-default-features", relay_commands[0])
        self.assertIn(
            "crates/registry-relay/canonical-release-features.txt",
            binary_recipe,
        )
        self.assertIn(
            '--env RELEASE_RELAY_FEATURES="${relay_release_features}"',
            binary_recipe,
        )
        self.assertIn(
            'REGISTRY_RELAY_FEATURES="${RELEASE_RELAY_FEATURES}"',
            binary_recipe,
        )
        self.assertIn('--features "${RELEASE_RELAY_FEATURES}"', relay_commands[0])
        feature_check = (
            "python3 release/scripts/check-release-relay-features.py "
            "target/release/registry-relay"
        )
        self.assertIn(feature_check, binary_recipe)
        self.assertLess(
            binary_recipe.index(relay_commands[0]), binary_recipe.index(feature_check)
        )
        self.assertLess(
            binary_recipe.index(feature_check),
            binary_recipe.index(
                "cp target/release/registry-relay dist/image-bin/registry-relay"
            ),
        )

        self.assertEqual(1, images_job.count("release/scripts/build-release-image.sh"))
        self.assertNotIn("docker buildx build", images_job)
        self.assertIn("registry-notary|registry-relay", image_recipe)
        self.assertIn(
            "crates/registry-relay/canonical-release-features.txt",
            image_recipe,
        )
        self.assertIn(
            "org.registrystack.registry-relay.features=${relay_release_features}",
            image_recipe,
        )
        self.assertIn("SOURCE_DATE_EPOCH=${source_date_epoch}", image_recipe)
        self.assertIn("source_date_epoch=0", image_recipe)
        self.assertNotIn("${SOURCE_DATE_EPOCH", image_recipe)
        self.assertNotIn("${RELEASE_BUILDKIT_IMAGE", image_recipe)
        self.assertIn(
            "type=registry,push=true,rewrite-timestamp=true,compatibility-version=20",
            image_recipe,
        )
        self.assertIn(
            "type=oci,dest=${RELEASE_IMAGE_OCI_LAYOUT},tar=false,"
            "rewrite-timestamp=true,compatibility-version=20",
            image_recipe,
        )
        self.assertIn("provenance_args+=(--provenance=false)", image_recipe)
        self.assertIn('if [[ -n "${RELEASE_IMAGE_OCI_LAYOUT:-}" ]]', image_recipe)
        self.assertNotIn("RELEASE_IMAGE_OCI_LAYOUT", images_job)
        self.assertIn("--metadata-file", image_recipe)
        self.assertIn(
            "moby/buildkit:v0.31.2@sha256:"
            "2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec",
            image_recipe,
        )
        self.assertIn("--driver docker-container", image_recipe)
        self.assertIn("must use the docker-container driver", image_recipe)
        self.assertIn("docker ps --all --format '{{.Names}}'", image_recipe)
        self.assertIn("buildx_buildkit_${release_buildx_builder}0", image_recipe)
        self.assertIn("docker inspect --format '{{.Config.Image}}'", image_recipe)
        self.assertIn(
            'default_buildkit_repo_digest="moby/buildkit@sha256:'
            '2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec"',
            image_recipe,
        )
        self.assertIn("docker image inspect --format", image_recipe)
        self.assertNotIn("--use", image_recipe)
        self.assertIn("docker buildx version", image_recipe)
        self.assertIn("v0\\.33\\.0", image_recipe)
        self.assertIn("RELEASE_IMAGE_NO_CACHE", image_recipe)
        self.assertIn("RELEASE_IMAGE_OCI_LAYOUT", image_recipe)
        self.assertIn("RELEASE_IMAGE_REGISTRY_INSECURE", image_recipe)
        self.assertIn("RELEASE_IMAGE_CONTEXT", image_recipe)
        self.assertIn("BuildKit( version:)?[[:space:]]+v0\\.31\\.2", image_recipe)
        self.assertIn("RELEASE_BUILDX_VERSION: v0.33.0", workflow)
        self.assertIn("version: ${{ env.RELEASE_BUILDX_VERSION }}", images_job)
        self.assertIn(
            "driver-opts: image=${{ env.RELEASE_BUILDKIT_IMAGE }}",
            images_job,
        )
        release_tool_job = ci_workflow[
            ci_workflow.index("\n  release-tool:") : ci_workflow.index(
                "\n  release-source-proof:"
            )
        ]
        self.assertIn("version: v0.33.0", release_tool_job)
        self.assertIn(
            "driver-opts: image=moby/buildkit:v0.31.2@sha256:"
            "2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec",
            release_tool_job,
        )
        self.assertLess(
            release_tool_job.index("name: Set up Docker Buildx"),
            release_tool_job.index("name: Smoke release image OCI labels"),
        )
        for dockerfile in (
            ROOT / "release/docker/Dockerfile.registry-notary",
            ROOT / "release/docker/Dockerfile.registry-relay",
        ):
            self.assertTrue(
                dockerfile.read_text(encoding="utf-8").startswith(
                    "# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e\n"
                ),
                dockerfile,
            )
            dockerfile_text = dockerfile.read_text(encoding="utf-8")
            self.assertIn("ARG SOURCE_DATE_EPOCH=0", dockerfile_text)
            self.assertIn(
                "RUN --mount=type=bind,source=dist/image-bin,"
                "target=/workspace/image-bin",
                dockerfile_text,
            )
            self.assertIn(
                'find /workspace/runtime-root -exec touch -h --date="@${SOURCE_DATE_EPOCH}" {} +',
                dockerfile_text,
            )

    def legacy_release_records_cache_and_duration_telemetry(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        promotion = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        binaries_job = workflow[
            workflow.index("\n  build-a:") : workflow.index("\n  other-platforms:")
        ]
        receipt_job = workflow[workflow.index("\n  verify-candidate:") :]
        candidate_telemetry = workflow[workflow.index("\n  candidate-telemetry:") :]
        promotion_telemetry = promotion[promotion.index("\n  release-telemetry:") :]

        self.assertIn(
            "name: Restore exact-key Cargo cache\n        id: cargo-cache", binaries_job
        )
        self.assertIn("steps.cargo-cache.outputs.cache-hit", binaries_job)
        self.assertIn("exact_key_hit", binaries_job)
        self.assertIn("Start peak-storage sampler", binaries_job)
        self.assertIn("Stop peak-storage sampler", binaries_job)
        self.assertIn("storage-measurement-a.json", binaries_job)
        self.assertIn("Create closed candidate receipt", receipt_job)
        self.assertIn("cargo_cache", receipt_job)
        self.assertIn("Create compact candidate telemetry evidence", receipt_job)
        self.assertIn(
            "registry-stack-candidate-telemetry-evidence-run-",
            candidate_telemetry,
        )
        self.assertNotIn("pattern: registry-stack-candidate-*", candidate_telemetry)
        for field in (
            "queue_delay_seconds",
            "wall_clock_seconds",
            "wall_clock_excluding_queue_seconds",
            "runner_occupancy_seconds",
            "cache_state",
            "peak_storage_evidence",
            "candidate_wall_clock_budget_seconds:3600",
            "total_runner_seconds_budget:8000",
        ):
            self.assertIn(field, candidate_telemetry)
        for field in (
            "queue_seconds",
            "total_wall_clock_seconds",
            "queue_delay_seconds",
            "runner_occupancy_seconds",
            "candidate_evidence",
            "candidate_cache",
            "candidate_storage",
            "total_completed_runner_seconds",
            "candidate_wall_clock_budget_seconds:3600",
            "promotion_wall_clock_budget_seconds:1200",
            "total_runner_seconds_budget:8000",
        ):
            self.assertIn(field, promotion_telemetry)
        self.assertIn(
            "Download verified candidate measurements for telemetry",
            promotion_telemetry,
        )
        self.assertIn("continue-on-error: true", promotion_telemetry)
        self.assertNotIn(
            """test "$(jq -r 'length' <<<"${candidate_storage}")" = 5""",
            promotion_telemetry,
        )
        self.assertNotIn(
            'cache_state:"closed receipt builds.a.cargo_cache"',
            promotion_telemetry,
        )
        self.assertIn("retention-days: 7", candidate_telemetry)
        self.assertIn("retention-days: 7", promotion_telemetry)

    def test_release_image_scans_are_policy_enforced_and_preserved(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        assemble = workflow.split("\n  assemble:", 1)[1].split("\n  attest:", 1)[0]
        scan_step = assemble.index("Verify and scan exact candidate images")
        package_step = assemble.index(
            "Assemble public payload and run install and authoring smoke"
        )
        self.assertLess(scan_step, package_step)
        scan_body = assemble[scan_step:package_step]
        self.assertIn("scan_image() {", scan_body)
        self.assertIn('grype "${image_ref}" -o json > "${report}"', scan_body)
        self.assertIn("set +e", scan_body)
        self.assertIn('status=$?', scan_body)
        self.assertIn('(.matches | type == "array")', scan_body)
        self.assertIn('(.source.type == "image")', scan_body)
        self.assertIn(
            ".descriptor.db.built // .descriptor.db.status.built",
            scan_body,
        )
        self.assertIn(
            'test("checksum=sha256%3A[0-9a-fA-F]{64}")',
            scan_body,
        )
        self.assertIn(
            "Grype did not emit a complete scan report",
            scan_body,
        )
        self.assertIn(
            "enforcing its complete report through the reviewed advisory policy",
            scan_body,
        )
        self.assertIn("now_epoch - db_built_epoch > 259200", scan_body)
        self.assertIn(
            "candidate/security/images/postgresql.digest",
            scan_body,
        )
        self.assertIn(
            "candidate/security/image-sbom/postgresql.spdx.json",
            scan_body,
        )
        self.assertIn(
            "release/scripts/registry-release bind-spdx-subject",
            scan_body,
        )
        self.assertIn('--digest-ref "${postgresql_ref}"', scan_body)
        self.assertIn(
            "candidate/security/syft/postgresql.syft.json",
            scan_body,
        )
        self.assertIn(
            "candidate/security/grype/postgresql.grype.json",
            scan_body,
        )
        self.assertIn("candidate/security/rootfs/postgresql", scan_body)
        self.assertIn('crane digest "${postgresql_ref}"', scan_body)
        self.assertIn(
            "python3 release/scripts/check_postgresql_advisory_policy.py",
            scan_body,
        )
        self.assertIn(
            "candidate/security/grype/postgresql.grype.json",
            scan_body,
        )
        self.assertIn(
            "--baseline release/security/postgresql-advisory-baseline.json",
            scan_body,
        )
        self.assertIn(
            "--syft-report candidate/security/syft/postgresql.syft.json",
            scan_body,
        )
        self.assertIn(
            "--rootfs candidate/security/rootfs/postgresql",
            scan_body,
        )
        self.assertIn('--expected-image "${postgresql_ref}"', scan_body)
        postgresql_ref_read = scan_body.index(
            'postgresql_ref="$(tr -d \'\\n\' < release/registryctl-postgresql-image.ref)"'
        )
        expected_image = scan_body.index(
            '--expected-image "${postgresql_ref}"'
        )
        self.assertLess(postgresql_ref_read, expected_image)
        self.assertIn('"postgresql-runtime"', scan_body)
        package_body = assemble[package_step:]
        self.assertIn(
            "images image-sbom syft grype advisory-verdict.json",
            package_body,
        )
        self.assertNotIn(
            "cp candidate/security/grype/*.grype.json",
            package_body,
        )

    def test_postgresql_scan_workflow_contract_detects_structural_mutations(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        assemble = workflow.split("\n  assemble:", 1)[1].split("\n  attest:", 1)[0]

        def assert_contract(text: str) -> None:
            for fragment in (
                'grype "${image_ref}" -o json > "${report}"',
                "Grype did not emit a complete scan report",
                "now_epoch - db_built_epoch > 259200",
                '[[ "$(crane digest "${postgresql_ref}")"'
                ' != "${postgresql_digest}" ]]',
                "python3 release/scripts/check_postgresql_advisory_policy.py",
                '"postgresql-runtime"',
                "images image-sbom syft grype advisory-verdict.json",
            ):
                self.assertIn(fragment, text)

        assert_contract(assemble)
        for fragment in (
            'grype "${image_ref}" -o json > "${report}"',
            "Grype did not emit a complete scan report",
            "now_epoch - db_built_epoch > 259200",
            '[[ "$(crane digest "${postgresql_ref}")"'
            ' != "${postgresql_digest}" ]]',
            "python3 release/scripts/check_postgresql_advisory_policy.py",
            '"postgresql-runtime"',
            "images image-sbom syft grype advisory-verdict.json",
        ):
            with self.subTest(fragment=fragment):
                with self.assertRaises(AssertionError):
                    assert_contract(assemble.replace(fragment, "", 1))

    def test_postgresql_advisory_policy_fails_closed(self) -> None:
        digest = "sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
        layer = "sha256:" + "c" * 64
        image_ref = f"docker.io/library/postgres@{digest}"
        target = {
            "userInput": image_ref,
            "repoDigests": [image_ref],
            "architecture": "amd64",
            "os": "linux",
            "layers": [{"digest": layer}],
        }
        artifact = {
            "id": "postgresql-server",
            "name": "postgresql-18",
            "version": "18.0",
            "type": "deb",
            "locations": [{"path": "/var/lib/dpkg/status", "layerID": layer}],
        }
        baseline = ROOT / "release/security/postgresql-advisory-baseline.json"
        checker = ROOT / "release/scripts/check_postgresql_advisory_policy.py"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "postgresql.grype.json"
            syft_path = root / "postgresql.syft.json"
            rootfs = root / "rootfs"
            rootfs.mkdir()

            def run_checker(
                severity: str,
                fix: dict[str, object],
                grype_artifact: dict[str, object] | None = None,
                syft_artifact: dict[str, object] | None = None,
                expected_image: str = image_ref,
            ) -> subprocess.CompletedProcess[str]:
                grype_artifact = grype_artifact or artifact
                syft_artifact = syft_artifact or artifact
                report_path.write_text(
                    json.dumps(
                        {
                            "source": {"type": "image", "target": target},
                            "matches": [
                                {
                                    "vulnerability": {
                                        "id": "CVE-2026-0001",
                                        "severity": severity,
                                        "fix": fix,
                                    },
                                    "artifact": grype_artifact,
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                syft_path.write_text(
                    json.dumps(
                        {
                            "source": {"type": "image", "metadata": target},
                            "artifacts": [syft_artifact],
                            "files": [],
                        }
                    ),
                    encoding="utf-8",
                )
                result = subprocess.run(
                    [
                        sys.executable,
                        str(checker),
                        str(report_path),
                        "--baseline",
                        str(baseline),
                        "--syft-report",
                        str(syft_path),
                        "--rootfs",
                        str(rootfs),
                        "--expected-image",
                        expected_image,
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                return result

            high_result = run_checker(
                "High", {"versions": [], "state": "not-fixed"}
            )
            self.assertEqual(1, high_result.returncode, high_result.stderr)
            self.assertIn(
                "blocking finding: CVE-2026-0001 severity=High", high_result.stderr
            )

            fixable_result = run_checker(
                "Low", {"versions": ["18.0.1"], "state": "fixed"}
            )
            self.assertEqual(1, fixable_result.returncode, fixable_result.stderr)
            self.assertIn(
                "blocking finding: CVE-2026-0001 severity=Low",
                fixable_result.stderr,
            )
            self.assertIn("fixable=True", fixable_result.stderr)

            extra_metadata_result = run_checker(
                "Low",
                {"versions": [], "state": "not-fixed"},
                {**artifact, "foundBy": "grype-only-metadata"},
            )
            self.assertEqual(0, extra_metadata_result.returncode, extra_metadata_result.stderr)

            empty_fix_state_result = run_checker(
                "Low", {"versions": [], "state": ""}
            )
            self.assertEqual(
                0,
                empty_fix_state_result.returncode,
                empty_fix_state_result.stderr,
            )

            gosu_artifact = {
                "id": "gosu-stdlib",
                "name": "stdlib",
                "version": "go1.24.6",
                "type": "go-module",
                "locations": [{"path": "/usr/local/bin/gosu", "layerID": layer}],
            }
            gosu_result = run_checker(
                "Critical",
                {"versions": ["1.24.13"], "state": "fixed"},
                gosu_artifact,
                gosu_artifact,
            )
            self.assertEqual(0, gosu_result.returncode, gosu_result.stderr)

            other_image = "docker.io/library/postgres@sha256:" + "e" * 64
            target["userInput"] = other_image
            target["repoDigests"] = [other_image]
            unreviewed_gosu_result = run_checker(
                "Critical",
                {"versions": ["1.24.13"], "state": "fixed"},
                gosu_artifact,
                gosu_artifact,
                expected_image=other_image,
            )
            self.assertEqual(1, unreviewed_gosu_result.returncode)
            self.assertIn(
                "blocking finding: CVE-2026-0001 severity=Critical",
                unreviewed_gosu_result.stderr,
            )
            target["userInput"] = image_ref
            target["repoDigests"] = [image_ref]

            other_go_binary = {
                **gosu_artifact,
                "locations": [{"path": "/usr/local/bin/other", "layerID": layer}],
            }
            other_go_binary_result = run_checker(
                "Critical",
                {"versions": ["1.24.13"], "state": "fixed"},
                other_go_binary,
                other_go_binary,
            )
            self.assertEqual(1, other_go_binary_result.returncode)
            self.assertIn(
                "blocking finding: CVE-2026-0001 severity=Critical",
                other_go_binary_result.stderr,
            )

            target["repoDigests"] = [
                f"index.docker.io/library/postgres@{digest}"
            ]
            normalized_repository_result = run_checker(
                "Low", {"versions": [], "state": "not-fixed"}
            )
            self.assertEqual(
                0,
                normalized_repository_result.returncode,
                normalized_repository_result.stderr,
            )

            target["repoDigests"] = [
                "index.docker.io/library/postgres@sha256:" + "d" * 64
            ]
            wrong_digest_result = run_checker(
                "Low", {"versions": [], "state": "not-fixed"}
            )
            self.assertEqual(1, wrong_digest_result.returncode)
            self.assertIn(
                "image target digest must appear in repoDigests",
                wrong_digest_result.stderr,
            )
            target["repoDigests"] = [image_ref]

            mismatch_result = run_checker(
                "Low",
                {"versions": [], "state": "not-fixed"},
                {**artifact, "version": "18.0.1"},
            )
            self.assertEqual(1, mismatch_result.returncode)
            self.assertIn(
                "grype finding artifact does not match the Syft package model",
                mismatch_result.stderr,
            )

    def legacy_release_packaging_excludes_retired_notary_source_sidecar(self) -> None:
        retired_names = (
            "registry-notary-source-adapter-sidecar",
            "registry-notary-openfn-sidecar",
        )
        current_surfaces = (
            ROOT / ".github/workflows/release.yml",
            ROOT / ".github/workflows/release-capsule-backfill.yml",
            ROOT / "release/scripts/registry-release",
        )

        for path in current_surfaces:
            text = path.read_text(encoding="utf-8")
            for retired_name in retired_names:
                self.assertNotIn(retired_name, text, path)
        self.assertFalse(
            (ROOT / "release/docker/Dockerfile.registry-notary-openfn-sidecar").exists()
        )

    def test_relay_packaging_includes_dedicated_rhai_worker(self) -> None:
        binary_recipe = (ROOT / "release/scripts/build-release-binaries.sh").read_text(
            encoding="utf-8"
        )
        worker = "registry-relay-rhai-worker"

        for dockerfile in (
            "crates/registry-relay/Dockerfile",
            "crates/registry-relay/Dockerfile.demo",
            "release/docker/Dockerfile.registry-relay",
        ):
            text = (ROOT / dockerfile).read_text(encoding="utf-8")
            self.assertIn(f"/usr/local/bin/{worker}", text)

        self.assertIn(
            f'"dist/bin/{worker}-${{RELEASE_TAG}}-linux-amd64"',
            binary_recipe,
        )
        self.assertIn(f"dist/image-bin/{worker}", binary_recipe)
        release_dockerfile = (
            ROOT / "release/docker/Dockerfile.registry-relay"
        ).read_text(encoding="utf-8")
        self.assertIn(
            f"install -m 0755 /workspace/image-bin/{worker} "
            f"/workspace/runtime-root/usr/local/bin/{worker}",
            release_dockerfile,
        )
        self.assertIn(f"dist/image-bin/{worker}", binary_recipe)

    def test_notary_packaging_includes_dedicated_cel_worker(self) -> None:
        binary_recipe = (ROOT / "release/scripts/build-release-binaries.sh").read_text(
            encoding="utf-8"
        )
        worker = "registry-notary-cel-worker"

        product_dockerfile = (ROOT / "products/notary/Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(worker, product_dockerfile)

        self.assertIn(
            f'"dist/bin/{worker}-${{RELEASE_TAG}}-linux-amd64"',
            binary_recipe,
        )
        self.assertIn(f"dist/image-bin/{worker}", binary_recipe)
        self.assertIn(
            f"--bin {worker}",
            binary_recipe,
        )
        release_dockerfile = (
            ROOT / "release/docker/Dockerfile.registry-notary"
        ).read_text(encoding="utf-8")
        self.assertIn(
            f"install -m 0755 /workspace/image-bin/{worker} "
            f"/workspace/runtime-root/usr/local/bin/{worker}",
            release_dockerfile,
        )
        self.assertIn(f"dist/image-bin/{worker}", binary_recipe)

    def legacy_release_workflow_publishes_cross_platform_registryctl_binaries(
        self,
    ) -> None:
        # The hermetic linux/amd64 builder cannot produce macOS or arm64 binaries,
        # so registryctl-<tag>-macos-arm64 and -linux-arm64 are built natively on a
        # runner matrix. install.sh expects exactly these asset names.
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("macos-14", workflow)
        self.assertIn("ubuntu-24.04-arm", workflow)
        self.assertIn("aarch64-apple-darwin", workflow)
        self.assertIn("aarch64-unknown-linux-gnu", workflow)
        for asset in ("macos-arm64", "linux-arm64"):
            self.assertIn(asset, workflow)
            self.assertIn(f"registry-stack-candidate-{asset}", workflow)

    def legacy_candidate_native_platforms_execute_installed_cli_authoring_sequence(
        self,
    ) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/release-candidate.yml").read_text(
                encoding="utf-8"
            )
        )
        job = workflow["jobs"]["verify-cli-platforms"]
        platforms = {
            entry["asset"]: entry["runner"]
            for entry in job["strategy"]["matrix"]["include"]
        }
        self.assertEqual(
            {
                "macos-arm64": "macos-14",
                "linux-arm64": "ubuntu-24.04-arm",
            },
            platforms,
        )
        self.assertEqual(
            {"validate", "verify-candidate"},
            set(job["needs"]),
        )
        self.assertEqual("read", job["permissions"]["actions"])
        self.assertEqual("read", job["permissions"]["contents"])
        self.assertNotIn("id-token", job["permissions"])

        job_scripts = [
            step.get("run", "")
            for step in job["steps"]
            if isinstance(step, dict)
        ]
        script = next(
            script
            for script in job_scripts
            if "REGISTRYCTL_ASSET_DIR=\"${asset_dir}\"" in script
        )
        uses = [
            step.get("uses", "")
            for step in job["steps"]
            if isinstance(step, dict)
        ]
        self.assertTrue(
            any(use.startswith("actions/download-artifact@") for use in uses)
        )
        self.assertFalse(
            any(use.startswith("actions/checkout@") for use in uses)
        )
        self.assertIn(
            'REGISTRYCTL_ASSET_DIR="${asset_dir}"',
            script,
        )
        self.assertIn(
            'REGISTRYCTL_INSTALL_DIR="${GITHUB_WORKSPACE}/install"',
            script,
        )
        self.assertIn(
            'registryctl="${GITHUB_WORKSPACE}/install/registryctl"',
            script,
        )
        self.assertIn(
            'asset="registryctl-${{ needs.validate.outputs.tag }}-${{ matrix.asset }}"',
            script,
        )
        self.assertIn('candidate_binary="${asset_dir}/${asset}"', script)
        self.assertIn(
            'installer_asset="registryctl-${{ needs.validate.outputs.tag }}-install.sh"',
            script,
        )
        self.assertIn('installer="${asset_dir}/${installer_asset}"', script)
        self.assertIn('"${asset_dir}/SHA256SUMS"', script)
        self.assertIn("Sealed candidate checksum mismatch", script)
        self.assertIn("command -v shasum", script)
        self.assertIn("command -v sha256sum", script)
        provenance_positions = native_cli_provenance_control_positions(script)
        self.assertEqual(sorted(provenance_positions), provenance_positions)
        self.assertLess(
            script.index('installer_actual_sha256="$(sha256_file "${installer}")"'),
            script.index('run_sanitized_command install bash "${installer}"'),
        )
        self.assertLess(
            script.index('installed_sha256="$(sha256_file "${registryctl}")"'),
            script.index('actual="$("${registryctl}" --version)"'),
        )
        self.assertIn(
            "Installed Registryctl bytes do not match the sealed candidate",
            script,
        )
        self.assertIn("command -v registryctl", script)
        self.assertIn("command -v registry-relay", script)
        self.assertIn("command -v registry-notary", script)
        self.assertIn("lsof -nP -iTCP:4242 -sTCP:LISTEN", script)
        positions = native_cli_authoring_command_positions(script)
        self.assertEqual(sorted(positions), positions)
        self.assertIn('authoring_root="$(mktemp -d ', script)
        self.assertIn(
            'project_dir="${authoring_root}/spreadsheet-project"',
            script,
        )
        self.assertIn('rm -rf "${authoring_root}"', script)
        self.assertIn("trap cleanup EXIT", script)
        self.assertIn("run_sanitized_command", script)
        self.assertIn('"status=passed" > "platform-cli-report/${report}.log"', script)
        self.assertIn('rm -f "${raw_log}"', script)
        self.assertNotIn('"${registryctl}" start', script)
        self.assertNotIn("docker", script.lower())
        self.assertNotIn("gh ", script)
        self.assertNotIn("curl ", script)
        self.assertNotIn("wget ", script)

        self.assertIn("verify-cli-platforms", workflow["jobs"]["attest-candidate"]["needs"])
        self.assertIn(
            "verify-cli-platforms", workflow["jobs"]["candidate-telemetry"]["needs"]
        )

    def test_candidate_native_platform_verifier_rejects_version_only_control(
        self,
    ) -> None:
        version_only_verifier = (
            'registryctl="${GITHUB_WORKSPACE}/install/registryctl"\n'
            'actual="$("${registryctl}" --version)"\n'
        )
        self.assertIn("--version", version_only_verifier)
        with self.assertRaises(ValueError):
            native_cli_authoring_command_positions(version_only_verifier)
        with self.assertRaises(ValueError):
            native_cli_provenance_control_positions(version_only_verifier)

    def test_candidate_native_platform_verifier_requires_verified_installer_and_output(
        self,
    ) -> None:
        complete = "\n".join(NATIVE_CLI_PROVENANCE_CONTROLS)
        self.assertEqual(
            sorted(native_cli_provenance_control_positions(complete)),
            native_cli_provenance_control_positions(complete),
        )

        for omitted in (
            'installer_expected_sha256="$(expected_sha256_for "${installer_asset}")"',
            'installer_actual_sha256="$(sha256_file "${installer}")"',
            '"${installer_actual_sha256}" != "${installer_expected_sha256}"',
            'installed_sha256="$(sha256_file "${registryctl}")"',
            '"${installed_sha256}" != "${candidate_expected_sha256}"',
            'cmp -s "${candidate_binary}" "${registryctl}"',
        ):
            with self.subTest(omitted=omitted):
                incomplete = complete.replace(omitted, "", 1)
                with self.assertRaises(ValueError):
                    native_cli_provenance_control_positions(incomplete)

    def legacy_release_workflow_does_not_execute_downloaded_binaries_when_publishing(
        self,
    ) -> None:
        workflow_path = ROOT / ".github/workflows/release.yml"
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        verification_job = workflow["jobs"]["verify-candidate"]
        self.assertNotIn("id-token", verification_job["permissions"])
        self.assertNotIn("write", verification_job["permissions"].values())

        for job_name in ("publish-images", "github-release"):
            publish_job = workflow["jobs"][job_name]
            publish_steps = publish_job["steps"]
            publish_script = "\n".join(
                step.get("run", "") for step in publish_steps if isinstance(step, dict)
            )
            checkout = next(
                step
                for step in publish_steps
                if step.get("name", "").startswith("Checkout exact tag target")
            )
            self.assertFalse(checkout["with"]["persist-credentials"])
            self.assertNotIn("verify-registryctl-binary-version", publish_script)
            self.assertNotRegex(
                publish_script,
                r"(?m)^\s*[\"']?(?:\./)?(?:promotion/.*/)?registryctl-",
            )
            self.assertNotRegex(
                publish_script,
                r"(?m)^\s*chmod\b[^\n]*(?:promotion|dist)/",
            )

        candidate = yaml.safe_load(
            (ROOT / ".github/workflows/release-candidate.yml").read_text(
                encoding="utf-8"
            )
        )
        build_job = candidate["jobs"]["build-a"]
        self.assertEqual("read", build_job["permissions"]["contents"])
        build_script = "\n".join(
            step.get("run", "") for step in build_job["steps"] if isinstance(step, dict)
        )
        self.assertIn("build-release-binaries.sh", build_script)
        self.assertEqual(
            "read", candidate["jobs"]["other-platforms"]["permissions"]["contents"]
        )
        self.assertNotIn(
            "id-token", candidate["jobs"]["verify-candidate"]["permissions"]
        )
        attestation_job = candidate["jobs"]["attest-candidate"]
        self.assertEqual("write", attestation_job["permissions"]["id-token"])
        attestation_script = "\n".join(
            step.get("run", "")
            for step in attestation_job["steps"]
            if isinstance(step, dict)
        )
        self.assertIn("release_candidate.py verify", attestation_script)
        self.assertNotIn("gh api", attestation_script)
        self.assertNotIn("extract-artifact", attestation_script)
        self.assertNotIn("verify-attempt-artifacts", attestation_script)
        self.assertNotIn("build-release-binaries.sh", attestation_script)
        self.assertNotRegex(
            attestation_script,
            r"(?m)^\s*(?:\./)?release/scripts/build-release-binaries\.sh\b",
        )
        self.assertNotRegex(attestation_script, r"(?m)^\s*cargo build\b")
        step_names = [step.get("name") for step in attestation_job["steps"]]
        self.assertLess(
            step_names.index(
                "Reverify every hash-bound subject before requesting OIDC"
            ),
            step_names.index("Attest candidate payload artifacts"),
        )

    def legacy_release_workflow_freezes_non_signature_provenance_subjects(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        )
        publish_steps = workflow["jobs"]["github-release"]["steps"]
        step_names = [step.get("name") for step in publish_steps]
        subjects_name = "Generate exact provenance subjects"
        inventory_name = "Record exact pre-provenance inventory"
        signing_name = "Sign promoted release evidence"

        self.assertLess(step_names.index(subjects_name), step_names.index(signing_name))
        self.assertLess(
            step_names.index(inventory_name), step_names.index(signing_name)
        )

        steps_by_name = {
            step.get("name"): step for step in publish_steps if isinstance(step, dict)
        }
        subjects_script = steps_by_name[subjects_name]["run"]
        signing_script = steps_by_name[signing_name]["run"]
        reconcile_script = "\n".join(
            step.get("run", "")
            for step in workflow["jobs"]["reconcile"]["steps"]
            if isinstance(step, dict)
        )

        self.assertIn("-name '*.sig' -o -name '*.pem'", subjects_script)
        self.assertIn(
            "Signature material exists before provenance subjects are frozen",
            subjects_script,
        )
        self.assertIn("generated-signatures.sha256", signing_script)
        self.assertIn(
            "dist/reconciliation/provenance-subjects.sha256", signing_script
        )
        self.assertIn("generated-signatures.sha256", reconcile_script)
        self.assertIn('sha256sum "downloaded/${name}"', reconcile_script)
        self.assertIn(
            "reconciliation/generated-signatures.sha256", reconcile_script
        )

    def legacy_release_workflow_never_replaces_published_assets(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        step = workflow[
            workflow.index("      - name: Create immutable GitHub Release") :
        ]

        self.assertIn("Build fail-closed prewrite promotion state", workflow)
        self.assertIn(
            "Recheck all public destinations immediately before first write",
            workflow,
        )
        first_write_barrier = workflow.index(
            "Recheck all public destinations immediately before first write"
        )
        first_image_write = workflow.index('crane copy "${staging}" "${public}"')
        self.assertLess(first_write_barrier, first_image_write)
        barrier = workflow[first_write_barrier:first_image_write]
        self.assertIn("releases/tags/${tag}", barrier)
        self.assertIn("release_status", barrier)
        for image in ("registry-notary", "registry-relay"):
            self.assertIn(image, barrier)
        self.assertNotIn("gh release upload", step)
        self.assertNotIn("--clobber", step)
        self.assertIn('gh release create "${{ needs.verify.outputs.tag }}"', step)
        self.assertIn("--verify-tag", step)
        self.assertIn("GitHub Release is no longer absent", step)

    def legacy_release_workflow_builds_docs_without_publish_permissions(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        )
        docs_job = workflow["jobs"]["docs-archive"]
        publisher = workflow["jobs"]["github-release"]
        self.assertEqual(["verify"], [docs_job["needs"]])
        self.assertEqual({"contents": "read"}, docs_job["permissions"])
        checkout = next(
            step
            for step in docs_job["steps"]
            if step.get("name", "").startswith("Checkout exact tag target")
        )
        self.assertFalse(checkout["with"]["persist-credentials"])
        docs_script = "\n".join(
            step.get("run", "")
            for step in docs_job["steps"]
            if isinstance(step, dict)
        )
        self.assertIn("npm run build:archive", docs_script)
        self.assertIn("--verify-lock", docs_script)
        self.assertIn("docs-archive", publisher["needs"])
        self.assertIn("docs-archive", workflow["jobs"]["publish-images"]["needs"])
        publish_script = "\n".join(
            step.get("run", "")
            for step in publisher["steps"]
            if isinstance(step, dict)
        )
        self.assertIn("does not match immutable lock", publish_script)
        self.assertIn("--require-registry-docs-archive", publish_script)
        self.assertIn("--require-registryctl-installer", publish_script)

    def legacy_candidate_receipt_checks_its_in_progress_run_identity(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        receipt_step = workflow[
            workflow.index(
                "      - name: Create closed candidate receipt"
            ) : workflow.index(
                "      - name: Create compact candidate telemetry evidence"
            )
        ]

        self.assertIn('/actions/runs/${GITHUB_RUN_ID}"', receipt_step)
        self.assertIn('.status == "in_progress"', receipt_step)
        self.assertIn(".conclusion == null", receipt_step)
        self.assertNotIn('.conclusion == "success"', receipt_step)

    def legacy_candidate_promotion_has_closed_no_rebuild_publish_gates(self) -> None:
        path = ROOT / ".github/workflows/release.yml"
        text = path.read_text(encoding="utf-8")
        workflow = yaml.safe_load(text)
        verification = workflow["jobs"]["verify-candidate"]
        publish_images = workflow["jobs"]["publish-images"]
        reconcile = workflow["jobs"]["reconcile"]
        extended = workflow["jobs"]["extended-proof"]
        verification_script = "\n".join(
            step.get("run", "")
            for step in verification["steps"]
            if isinstance(step, dict)
        )
        source_verification = next(
            step["run"]
            for step in workflow["jobs"]["verify"]["steps"]
            if step.get("name") == "Validate tag source without rebuilding"
        )
        publish_script = "\n".join(
            step.get("run", "")
            for step in publish_images["steps"]
            if isinstance(step, dict)
        )
        reconcile_script = "\n".join(
            step.get("run", "") for step in reconcile["steps"] if isinstance(step, dict)
        )

        self.assertNotIn("write", verification["permissions"].values())
        self.assertIn("--release-id", verification_script)
        self.assertIn(
            "mapfile -t records < <(jq -c '.artifacts[]' \"${receipt}\")",
            verification_script,
        )
        self.assertNotIn("${#records[@]}", verification_script)
        self.assertIn(
            'if [[ "${GITHUB_EVENT_NAME}" != "repository_dispatch" ]]; then\n'
            '  test "$(git rev-parse refs/remotes/origin/main)" = \\\n'
            '    "${{ steps.release.outputs.tag_target }}"',
            source_verification,
        )
        self.assertEqual("read", publish_images["permissions"]["contents"])
        self.assertEqual("write", publish_images["permissions"]["packages"])
        self.assertNotIn("id-token", publish_images["permissions"])
        self.assertIn("releases/tags/${tag}", publish_script)
        self.assertIn("packages/container/${name}/versions", publish_script)
        self.assertIn(r"awk '/^HTTP\//", publish_script)
        self.assertNotIn(r"awk '/^HTTP\\//", publish_script)
        self.assertLess(
            publish_script.index("release_status"),
            publish_script.index('crane copy "${staging}" "${public}"'),
        )
        self.assertNotRegex(
            text,
            r"(?m)^\s+release/scripts/build-release-(?:binaries|image)\.sh\b",
        )
        self.assertIn("release-provenance", reconcile["needs"])
        self.assertIn("slsa-verifier verify-artifact", reconcile_script)
        self.assertIn("verify-slsa-subjects", reconcile_script)
        self.assertIn("reconcile", extended["needs"])
        self.assertNotRegex(text, r"(?m)^\s*git (?:push|tag|update-ref)\b")

    def legacy_release_workflow_removes_for_each_ref_record_separators(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        )
        scripts = [
            step["run"]
            for job in workflow["jobs"].values()
            for step in job.get("steps", [])
            if "git for-each-ref --format='%(contents)'" in step.get("run", "")
        ]

        self.assertEqual(2, len(scripts))
        for script in scripts:
            self.assertIn('message.endswith("\\n")', script)
            self.assertIn("message[:-1]", script)

    def legacy_release_workflow_publishes_digest_bound_release_file_sboms(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        candidate = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        candidate_workflow = yaml.safe_load(candidate)
        backfill = (ROOT / ".github/workflows/release-capsule-backfill.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("Generate release file SBOMs", workflow)
        self.assertIn("dist/binary-sbom", workflow)
        self.assertIn("dist/image-binary-sbom", candidate)
        self.assertIn("image-input-${asset}.spdx.json", candidate)
        self.assertIn("bind-spdx-file-subject", workflow)
        self.assertIn("bind-spdx-file-subject", candidate)
        self.assertIn("render-registryctl-image-lock", workflow)
        self.assertIn("verify-registryctl-image-lock-release-version", workflow)
        self.assertIn(
            "--postgresql-ref-file release/registryctl-postgresql-image.ref",
            workflow,
        )
        self.assertIn(
            "--postgresql-ref-file release/registryctl-postgresql-image.ref",
            candidate,
        )
        self.assertIn(
            '"${payload}/dist/images/postgresql.digest"',
            workflow,
        )
        self.assertIn(
            'crane digest "${candidate_postgresql}"',
            workflow,
        )
        self.assertIn("verify-registryctl-binary-version", candidate)
        self.assertLess(
            candidate.index("Verify built registryctl binary version"),
            candidate.index("Upload exact Build A artifact"),
        )
        self.assertLess(
            candidate.index("Verify native registryctl binary version"),
            candidate.index("Upload exact platform artifact"),
        )
        self.assertIn("--require-registryctl-image-lock", workflow)
        self.assertIn("--require-registryctl-installer", workflow)
        self.assertIn(
            "registryctl-${{ needs.verify.outputs.tag }}-image-lock.json", workflow
        )
        self.assertIn(
            'installer="registryctl-${{ needs.validate.outputs.tag }}-install.sh"',
            candidate,
        )
        self.assertIn(
            'cp crates/registryctl/install.sh "dist/candidate/dist/bin/${installer}"',
            candidate,
        )
        self.assertIn("Run exact first-country release-form journey before sealing", candidate)
        self.assertIn("first-country-release-form.py run", candidate)
        self.assertIn("first-country-release-form.py verify", candidate)
        self.assertIn("first-country-release-form.py verify", workflow)
        self.assertIn("verify-cli-platforms:", candidate)
        self.assertIn("runner: macos-14", candidate)
        self.assertIn("runner: ubuntu-24.04-arm", candidate)
        self.assertIn(
            "verify-cli-platforms",
            candidate_workflow["jobs"]["attest-candidate"]["needs"],
        )
        self.assertLess(
            candidate.index("render-registryctl-image-lock"),
            candidate.index("Run exact first-country release-form journey before sealing"),
        )
        self.assertLess(
            candidate.index("Run exact first-country release-form journey before sealing"),
            candidate.index("Upload exact candidate payload"),
        )
        self.assertLess(
            workflow.index("first-country-release-form.py verify"),
            workflow.index("Build fail-closed prewrite promotion state"),
        )
        self.assertLess(
            workflow.index("Stage exact candidate release files"),
            workflow.index("Render tag-bound image lock and checksums"),
        )
        self.assertLess(
            workflow.index("Render tag-bound image lock and checksums"),
            workflow.index("Generate release file SBOMs"),
        )
        self.assertIn("Generate digest-bound binary SBOMs", backfill)
        self.assertIn("dist/staged/binary-sbom", backfill)
        self.assertIn("--binary-sbom-dir", backfill)

    def legacy_capsule_backfill_resolves_manifest_for_requested_tag(self) -> None:
        backfill = (ROOT / ".github/workflows/release-capsule-backfill.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('version="${TAG#v}"', backfill)
        self.assertIn("if (( major > 0 || minor >= 9 )); then", backfill)
        self.assertIn("--require-registryctl-image-lock", backfill)
        self.assertIn(
            'glob.glob("release-source/release/manifests/registry-stack-*.yaml")',
            backfill,
        )
        self.assertIn("expected exactly one release manifest for {version}", backfill)
        self.assertEqual(2, backfill.count('"${RELEASE_MANIFEST}"'))
        self.assertNotIn(
            "release-source/release/manifests/registry-stack-beta-6.yaml", backfill
        )

    def legacy_capsule_backfill_privileged_job_uses_protected_tooling(
        self,
    ) -> None:
        workflow_path = ROOT / ".github/workflows/release-capsule-backfill.yml"
        backfill = workflow_path.read_text(encoding="utf-8")
        workflow = yaml.safe_load(backfill)
        steps = workflow["jobs"]["backfill"]["steps"]
        triggers = workflow.get("on", workflow.get(True))

        self.assertEqual(
            {
                "repository_dispatch": {
                    "types": ["release-capsule-backfill"],
                }
            },
            triggers,
        )
        self.assertNotIn("workflow_dispatch:", backfill)
        self.assertNotIn("${{ inputs.", backfill)
        self.assertIn("github.event.client_payload.tag", backfill)

        generator_checkout = next(
            step
            for step in steps
            if step.get("name") == "Checkout protected capsule tooling"
        )
        self.assertEqual(
            "${{ github.sha }}",
            generator_checkout["with"]["ref"],
        )
        self.assertFalse(generator_checkout["with"]["persist-credentials"])

        release_checkout = next(
            step for step in steps if step.get("name") == "Checkout release source"
        )
        self.assertEqual(
            "${{ github.event.client_payload.tag }}",
            release_checkout["with"]["ref"],
        )
        self.assertFalse(release_checkout["with"]["persist-credentials"])

    def test_validate_beta_6_manifest(self) -> None:
        result = run_tool("validate", "release/manifests/registry-stack-beta-6.yaml")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("validated", result.stdout)

    def test_validate_docsets_matches_release_manifests(self) -> None:
        result = run_tool("validate-docsets")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertRegex(
            result.stdout,
            r"validated [1-9][0-9]* versioned docsets against release manifests",
        )

    def test_validate_docsets_rejects_external_ref_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            data = yaml.safe_load(docsets.read_text(encoding="utf-8"))
            data["docsets"][0]["products"]["crosswalk"]["ref"] = "b" * 40
            docsets.write_text(yaml.safe_dump(data), encoding="utf-8")

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("external crosswalk ref", result.stderr)

    def test_validate_docsets_rejects_monorepo_ref_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            data = yaml.safe_load(docsets.read_text(encoding="utf-8"))
            data["docsets"][0]["products"]["registry-stack"]["ref"] = "b" * 40
            docsets.write_text(yaml.safe_dump(data), encoding="utf-8")

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("product registry-stack ref", result.stderr)

    def test_validate_docsets_rejects_source_marker_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            data = yaml.safe_load(docsets.read_text(encoding="utf-8"))
            data["docsets"][0]["source"] = "manual-docset"
            docsets.write_text(yaml.safe_dump(data), encoding="utf-8")

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("source 'manual-docset'", result.stderr)

    def test_validate_docsets_rejects_candidate_docs_for_released_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            manifest_path = manifest_dir / "registry-stack-beta-6.yaml"
            manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            manifest["stack"]["status"] = "released"
            manifest_path.write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            data = yaml.safe_load(docsets.read_text(encoding="utf-8"))
            data["released"] = "v0.8.0"
            data["docsets"][0]["availability"] = "candidate"
            docsets.write_text(
                yaml.safe_dump(data, sort_keys=False),
                encoding="utf-8",
            )

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn(
            "docset v0.8.0 availability must be 'released' because its "
            "release manifest status is 'released'",
            result.stderr,
        )

    def test_validate_docsets_rejects_stale_released_selector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            manifest_path = manifest_dir / "registry-stack-beta-6.yaml"
            manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            manifest["stack"]["status"] = "released"
            manifest_path.write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            data = yaml.safe_load(docsets.read_text(encoding="utf-8"))
            data["released"] = "v0.7.0"
            data["docsets"][0]["availability"] = "released"
            docsets.write_text(
                yaml.safe_dump(data, sort_keys=False),
                encoding="utf-8",
            )

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn(
            "docsets.yaml released selector must be 'v0.8.0', the newest "
            "released manifest, not 'v0.7.0'",
            result.stderr,
        )

    def test_validate_docsets_rejects_missing_release_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, docsets = write_docset_fixture(root)
            empty_manifest_dir = root / "empty-manifests"
            empty_manifest_dir.mkdir()

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(empty_manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("has no release manifest", result.stderr)

    def test_validate_docsets_rejects_missing_archive_lock_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            archive_lock = root / "archive-lock.yaml"
            archive_lock.write_text(
                yaml.safe_dump(
                    {
                        "schema_version": "registry-docs.archive-lock.v1",
                        "archives": {},
                    }
                ),
                encoding="utf-8",
            )

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
                "--archive-lock",
                str(archive_lock),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("missing archived docset v0.8.0", result.stderr)

    def test_validate_docsets_accepts_historical_and_dual_tree_archive_locks(
        self,
    ) -> None:
        shapes = (
            {
                "bundle_sha256": "a" * 64,
                "tree_sha256": "b" * 64,
            },
            {
                "bundle_sha256": "a" * 64,
                "root_tree_sha256": "b" * 64,
                "version_tree_sha256": "c" * 64,
            },
        )
        for entry in shapes:
            with self.subTest(fields=sorted(entry)), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                manifest_dir, docsets = write_docset_fixture(root)
                archive_lock = root / "archive-lock.yaml"
                archive_lock.write_text(
                    yaml.safe_dump(
                        {
                            "schema_version": "registry-docs.archive-lock.v1",
                            "archives": {"v0.8.0": entry},
                        },
                        sort_keys=False,
                    ),
                    encoding="utf-8",
                )

                result = run_tool(
                    "validate-docsets",
                    "--manifest-dir",
                    str(manifest_dir),
                    "--docsets",
                    str(docsets),
                    "--archive-lock",
                    str(archive_lock),
                )

            self.assertEqual(0, result.returncode, result.stderr)

    def test_validate_docsets_rejects_mixed_partial_and_open_archive_locks(
        self,
    ) -> None:
        invalid_entries = (
            (
                {
                    "bundle_sha256": "a" * 64,
                    "root_tree_sha256": "b" * 64,
                },
                "must contain exactly",
            ),
            (
                {
                    "bundle_sha256": "a" * 64,
                    "tree_sha256": "b" * 64,
                    "root_tree_sha256": "c" * 64,
                    "version_tree_sha256": "d" * 64,
                },
                "must contain exactly",
            ),
            (
                {
                    "bundle_sha256": "a" * 64,
                    "tree_sha256": "b" * 64,
                    "telemetry": "not promotion data",
                },
                "unknown field telemetry",
            ),
            (
                {
                    "bundle_sha256": "a" * 64,
                    "root_tree_sha256": "b" * 64,
                    "version_tree_sha256": "INVALID",
                },
                "version_tree_sha256 must be 64 lowercase hex characters",
            ),
        )
        for entry, expected in invalid_entries:
            with self.subTest(fields=sorted(entry)), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                manifest_dir, docsets = write_docset_fixture(root)
                archive_lock = root / "archive-lock.yaml"
                archive_lock.write_text(
                    yaml.safe_dump(
                        {
                            "schema_version": "registry-docs.archive-lock.v1",
                            "archives": {"v0.8.0": entry},
                        },
                        sort_keys=False,
                    ),
                    encoding="utf-8",
                )

                result = run_tool(
                    "validate-docsets",
                    "--manifest-dir",
                    str(manifest_dir),
                    "--docsets",
                    str(docsets),
                    "--archive-lock",
                    str(archive_lock),
                )

            self.assertNotEqual(0, result.returncode)
            self.assertIn(expected, result.stderr)

    def test_audit_import_map(self) -> None:
        result = run_tool("audit", "release/manifests/import-map-2026-06-24.yaml")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("audited 7 imports", result.stdout)

    def test_removed_stub_commands_are_not_registered(self) -> None:
        for command in ("classify-warning", "generate-docset", "collect-artifacts"):
            with self.subTest(command=command):
                result = run_tool(command)
                self.assertEqual(2, result.returncode)
                self.assertIn("invalid choice", result.stderr)

    def test_validate_rejects_mismatched_source_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_manifest(Path(tmp), source_tag="v9.9.9")
            result = run_tool("validate", str(manifest))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("stack.source_tag must be v0.8.0", result.stderr)

    def test_validate_rejects_head_for_non_draft_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_manifest(
                Path(tmp), source_ref="HEAD", status="release-candidate"
            )
            result = run_tool("validate", str(manifest))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("stack.source_ref may be HEAD only", result.stderr)

    def test_validate_accepts_active_manifest_without_future_source_or_status(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_manifest(Path(tmp))
            data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            data["stack"].pop("source_ref")
            data["stack"].pop("status")
            manifest.write_text(
                yaml.safe_dump(data, sort_keys=False),
                encoding="utf-8",
            )

            result = run_tool("validate", str(manifest))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("validated", result.stdout)

    def test_validate_rejects_partially_removed_legacy_source_state(self) -> None:
        for removed in ("source_ref", "status"):
            with self.subTest(removed=removed), tempfile.TemporaryDirectory() as tmp:
                manifest = write_manifest(Path(tmp))
                data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
                data["stack"].pop(removed)
                manifest.write_text(
                    yaml.safe_dump(data, sort_keys=False),
                    encoding="utf-8",
                )

                result = run_tool("validate", str(manifest))

            self.assertNotEqual(0, result.returncode)
            self.assertIn(
                "must both be present for a historical manifest or both omitted",
                result.stderr,
            )

    def test_validate_requires_registryctl_image_lock_for_v0_9_and_later(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = write_manifest(
                root,
                version="0.9.0",
                include_registryctl_image_lock=False,
            )
            rejected = run_tool("validate", str(missing))
            included = write_manifest(root, version="0.9.0")
            accepted = run_tool("validate", str(included))

        self.assertNotEqual(0, rejected.returncode)
        self.assertIn(
            "artifact registryctl-image-lock is required for version 0.9.0 or later",
            rejected.stderr,
        )
        self.assertEqual(0, accepted.returncode, accepted.stderr)

    def test_validate_requires_exact_v0_10_artifact_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = write_manifest(root, version="0.10.0")
            accepted = run_tool("validate", str(manifest))

            data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            del data["artifacts"]["registry-notary-cel-worker"]
            data["artifacts"]["registry-lab"] = "0.10.0"
            manifest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
            rejected = run_tool("validate", str(manifest))

        self.assertEqual(0, accepted.returncode, accepted.stderr)
        self.assertNotEqual(0, rejected.returncode)
        self.assertIn("artifact inventory for version 0.10.0 or later", rejected.stderr)
        self.assertIn("missing registry-notary-cel-worker", rejected.stderr)
        self.assertIn("unexpected registry-lab", rejected.stderr)

    def test_validate_accepts_declared_registryctl_installer_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_manifest(
                Path(tmp),
                version="0.14.0",
                include_registryctl_installer=True,
            )
            result = run_tool("validate", str(manifest))

        self.assertEqual(0, result.returncode, result.stderr)

    def test_validate_requires_registryctl_installer_for_v0_14_and_later(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = write_manifest(
                root,
                version="0.14.0",
                include_registryctl_installer=False,
            )
            rejected = run_tool("validate", str(missing))
            included = write_manifest(root, version="0.14.0")
            accepted = run_tool("validate", str(included))

        self.assertNotEqual(0, rejected.returncode)
        self.assertIn(
            "artifact registryctl-installer is required for version 0.14.0 or later",
            rejected.stderr,
        )
        self.assertEqual(0, accepted.returncode, accepted.stderr)

    def test_render_registryctl_image_lock_from_exact_release_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = write_manifest(root, version="0.9.0")
            relay_digest = root / "registry-relay.digest"
            notary_digest = root / "registry-notary.digest"
            relay_ref = f"ghcr.io/registrystack/registry-relay@{IMAGE_DIGEST}"
            notary_ref = f"ghcr.io/registrystack/registry-notary@{IMAGE_DIGEST}"
            relay_digest.write_text(f"{relay_ref}\n", encoding="utf-8")
            notary_digest.write_text(f"{notary_ref}\n", encoding="utf-8")
            output = root / "registryctl-v0.9.0-image-lock.json"

            result = run_tool(
                "render-registryctl-image-lock",
                str(manifest),
                "--relay-digest",
                str(relay_digest),
                "--notary-digest",
                str(notary_digest),
                "--tag-target",
                "b" * 40,
                "--output",
                str(output),
            )
            document = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            {
                "schema_version": "registryctl.release_image_lock.v1",
                "release_tag": "v0.9.0",
                "manifest_source_ref": "f30a541df539c2e16de09733c5944c744a60493c",
                "tag_target": "b" * 40,
                "platform": "linux/amd64",
                "images": {
                    "registry-relay": relay_ref,
                    "registry-notary": notary_ref,
                },
            },
            document,
        )

    def test_active_manifest_validates_and_renders_image_lock_from_explicit_source(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = write_manifest(root, version="0.14.0")
            data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            data["stack"].pop("source_ref")
            data["stack"].pop("status")
            manifest.write_text(
                yaml.safe_dump(data, sort_keys=False),
                encoding="utf-8",
            )
            relay_digest = root / "registry-relay.digest"
            notary_digest = root / "registry-notary.digest"
            relay_digest.write_text(
                f"ghcr.io/registrystack/registry-relay@{IMAGE_DIGEST}\n",
                encoding="utf-8",
            )
            notary_digest.write_text(
                f"ghcr.io/registrystack/registry-notary@{IMAGE_DIGEST}\n",
                encoding="utf-8",
            )
            source_sha = "c" * 40
            output = root / "registryctl-v0.14.0-image-lock.json"

            validated = run_tool("validate", str(manifest))
            rendered = run_tool(
                "render-registryctl-image-lock",
                str(manifest),
                "--relay-digest",
                str(relay_digest),
                "--notary-digest",
                str(notary_digest),
                "--postgresql-ref-file",
                str(POSTGRESQL_REF_PATH),
                "--source-sha",
                source_sha,
                "--tag-target",
                source_sha,
                "--output",
                str(output),
            )
            document = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(0, validated.returncode, validated.stderr)
        self.assertEqual(0, rendered.returncode, rendered.stderr)
        self.assertEqual(source_sha, document["manifest_source_ref"])
        self.assertEqual(source_sha, document["tag_target"])

    def test_active_manifest_image_lock_requires_matching_explicit_source(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = write_manifest(root, version="0.14.0")
            data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            data["stack"].pop("source_ref")
            data["stack"].pop("status")
            manifest.write_text(
                yaml.safe_dump(data, sort_keys=False),
                encoding="utf-8",
            )
            relay_digest = root / "registry-relay.digest"
            notary_digest = root / "registry-notary.digest"
            for path, name in (
                (relay_digest, "registry-relay"),
                (notary_digest, "registry-notary"),
            ):
                path.write_text(
                    f"ghcr.io/registrystack/{name}@{IMAGE_DIGEST}\n",
                    encoding="utf-8",
                )
            base = [
                "render-registryctl-image-lock",
                str(manifest),
                "--relay-digest",
                str(relay_digest),
                "--notary-digest",
                str(notary_digest),
                "--postgresql-ref-file",
                str(POSTGRESQL_REF_PATH),
                "--tag-target",
                "c" * 40,
                "--output",
                str(root / "registryctl-v0.14.0-image-lock.json"),
            ]

            missing = run_tool(*base)
            mismatch = run_tool(
                *base,
                "--source-sha",
                "d" * 40,
            )

        self.assertNotEqual(0, missing.returncode)
        self.assertIn("requires --source-sha", missing.stderr)
        self.assertNotEqual(0, mismatch.returncode)
        self.assertIn("tag target must equal --source-sha", mismatch.stderr)

    def test_registryctl_image_lock_release_version_gate(self) -> None:
        rejected = run_tool(
            "verify-registryctl-image-lock-release-version",
            "--version",
            "0.8.5",
        )
        accepted = run_tool(
            "verify-registryctl-image-lock-release-version",
            "--version",
            "0.9.0",
        )

        self.assertNotEqual(0, rejected.returncode)
        self.assertIn("require version 0.9.0 or later", rejected.stderr)
        self.assertEqual(0, accepted.returncode, accepted.stderr)
        self.assertIn(
            "verified registryctl image lock release version 0.9.0", accepted.stdout
        )

    def test_render_registryctl_image_lock_v2_includes_reviewed_postgresql(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = write_manifest(root, version="0.14.0")
            relay_digest = root / "registry-relay.digest"
            notary_digest = root / "registry-notary.digest"
            relay_ref = f"ghcr.io/registrystack/registry-relay@{IMAGE_DIGEST}"
            notary_ref = f"ghcr.io/registrystack/registry-notary@{IMAGE_DIGEST}"
            relay_digest.write_text(f"{relay_ref}\n", encoding="utf-8")
            notary_digest.write_text(f"{notary_ref}\n", encoding="utf-8")
            output = root / "registryctl-v0.14.0-image-lock.json"

            result = run_tool(
                "render-registryctl-image-lock",
                str(manifest),
                "--relay-digest",
                str(relay_digest),
                "--notary-digest",
                str(notary_digest),
                "--postgresql-ref-file",
                str(POSTGRESQL_REF_PATH),
                "--tag-target",
                "b" * 40,
                "--output",
                str(output),
            )
            document = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            "registryctl.release_image_lock.v2",
            document["schema_version"],
        )
        self.assertEqual(
            {
                "registry-relay": relay_ref,
                "registry-notary": notary_ref,
                "postgresql": POSTGRESQL_REF_PATH.read_text(encoding="utf-8").strip(),
            },
            document["images"],
        )

    def test_render_registryctl_image_lock_v2_requires_postgresql_ref(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = write_manifest(root, version="0.14.0")
            relay_digest = root / "registry-relay.digest"
            notary_digest = root / "registry-notary.digest"
            relay_digest.write_text(
                f"ghcr.io/registrystack/registry-relay@{IMAGE_DIGEST}\n",
                encoding="utf-8",
            )
            notary_digest.write_text(
                f"ghcr.io/registrystack/registry-notary@{IMAGE_DIGEST}\n",
                encoding="utf-8",
            )

            result = run_tool(
                "render-registryctl-image-lock",
                str(manifest),
                "--relay-digest",
                str(relay_digest),
                "--notary-digest",
                str(notary_digest),
                "--tag-target",
                "b" * 40,
                "--output",
                str(root / "registryctl-v0.14.0-image-lock.json"),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("v2 requires --postgresql-ref-file", result.stderr)

    def test_render_registryctl_image_lock_rejects_pre_0_9_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = write_manifest(root, version="0.8.5")
            relay_digest = root / "registry-relay.digest"
            notary_digest = root / "registry-notary.digest"
            relay_digest.write_text(
                f"ghcr.io/registrystack/registry-relay@{IMAGE_DIGEST}\n",
                encoding="utf-8",
            )
            notary_digest.write_text(
                f"ghcr.io/registrystack/registry-notary@{IMAGE_DIGEST}\n",
                encoding="utf-8",
            )
            output = root / "registryctl-v0.8.5-image-lock.json"

            result = run_tool(
                "render-registryctl-image-lock",
                str(manifest),
                "--relay-digest",
                str(relay_digest),
                "--notary-digest",
                str(notary_digest),
                "--tag-target",
                "b" * 40,
                "--output",
                str(output),
            )

            self.assertFalse(output.exists())

        self.assertNotEqual(0, result.returncode)
        self.assertIn("require version 0.9.0 or later", result.stderr)

    def test_verify_registryctl_binary_version_matches_manifest_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "registryctl"
            binary.write_text(
                "#!/bin/sh\nprintf 'registryctl 0.8.0\\n'\n", encoding="utf-8"
            )
            binary.chmod(0o755)

            matching = run_tool(
                "verify-registryctl-binary-version",
                str(binary),
                "--version",
                "0.8.0",
            )
            mismatch = run_tool(
                "verify-registryctl-binary-version",
                str(binary),
                "--version",
                "0.9.0",
            )

        self.assertEqual(0, matching.returncode, matching.stderr)
        self.assertIn("verified registryctl binary version 0.8.0", matching.stdout)
        self.assertNotEqual(0, mismatch.returncode)
        self.assertIn(
            "registryctl binary version must be exactly 'registryctl 0.9.0'",
            mismatch.stderr,
        )

    def test_verify_registryctl_binary_version_does_not_require_pyyaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "registryctl"
            binary.write_text(
                "#!/bin/sh\nprintf 'registryctl 0.15.0\\n'\n", encoding="utf-8"
            )
            binary.chmod(0o755)

            result = subprocess.run(
                [
                    sys.executable,
                    "-S",
                    str(TOOL),
                    "verify-registryctl-binary-version",
                    str(binary),
                    "--version",
                    "0.15.0",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(
            "verified registryctl binary version 0.15.0", result.stdout
        )

    def test_render_registryctl_image_lock_rejects_wrong_repository_and_filename(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = write_manifest(root, version="0.9.0")
            relay_digest = root / "registry-relay.digest"
            notary_digest = root / "registry-notary.digest"
            relay_digest.write_text(
                f"ghcr.io/example/registry-relay@{IMAGE_DIGEST}\n", encoding="utf-8"
            )
            notary_digest.write_text(
                f"ghcr.io/registrystack/registry-notary@{IMAGE_DIGEST}\n",
                encoding="utf-8",
            )

            wrong_repo = run_tool(
                "render-registryctl-image-lock",
                str(manifest),
                "--relay-digest",
                str(relay_digest),
                "--notary-digest",
                str(notary_digest),
                "--tag-target",
                "b" * 40,
                "--output",
                str(root / "registryctl-v0.9.0-image-lock.json"),
            )
            relay_digest.write_text(
                f"ghcr.io/registrystack/registry-relay@{IMAGE_DIGEST}\n",
                encoding="utf-8",
            )
            wrong_name = run_tool(
                "render-registryctl-image-lock",
                str(manifest),
                "--relay-digest",
                str(relay_digest),
                "--notary-digest",
                str(notary_digest),
                "--tag-target",
                "b" * 40,
                "--output",
                str(root / "image-lock.json"),
            )

        self.assertNotEqual(0, wrong_repo.returncode)
        self.assertIn(
            "repository must be ghcr.io/registrystack/registry-relay", wrong_repo.stderr
        )
        self.assertNotEqual(0, wrong_name.returncode)
        self.assertIn(
            "output filename must be registryctl-v0.9.0-image-lock.json",
            wrong_name.stderr,
        )

    def test_validate_source_accepts_ancestor_source_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            source_ref = commit_file(repo, "source.txt", "source\n")
            commit_file(repo, "release.txt", "release\n")
            git(repo, "tag", "v0.8.0")
            manifest = write_manifest(repo, source_ref=source_ref)

            result = run_tool(
                "validate-source",
                str(manifest),
                "--tag",
                "v0.8.0",
                "--repo",
                str(repo),
                "--default-branch",
                "main",
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("validated source lineage", result.stdout)

    def test_validate_source_rejects_mismatched_source_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            source_ref = commit_file(repo, "source.txt", "source\n")
            git(repo, "tag", "v0.8.0")
            manifest = write_manifest(repo, source_ref=source_ref, source_tag="v9.9.9")

            result = run_tool(
                "validate-source",
                str(manifest),
                "--tag",
                "v0.8.0",
                "--repo",
                str(repo),
                "--default-branch",
                "main",
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("does not match checked-out release tag", result.stderr)

    def test_validate_source_rejects_non_ancestor_source_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            commit_file(repo, "main.txt", "main\n")
            git(repo, "checkout", "-b", "side")
            side_ref = commit_file(repo, "side.txt", "side\n")
            git(repo, "checkout", "main")
            commit_file(repo, "release.txt", "release\n")
            git(repo, "tag", "v0.8.0")
            manifest = write_manifest(repo, source_ref=side_ref)

            result = run_tool(
                "validate-source",
                str(manifest),
                "--tag",
                "v0.8.0",
                "--repo",
                str(repo),
                "--default-branch",
                "main",
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("is not an ancestor of release tag target", result.stderr)

    def test_validate_source_allows_draft_not_reachable_from_default_branch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            commit_file(repo, "main.txt", "main\n")
            git(repo, "checkout", "--orphan", "draft")
            commit_file(repo, "draft.txt", "draft\n")
            git(repo, "tag", "v0.8.0")
            manifest = write_manifest(repo, source_ref="HEAD", status="draft")

            result = run_tool(
                "validate-source",
                str(manifest),
                "--tag",
                "v0.8.0",
                "--repo",
                str(repo),
                "--default-branch",
                "main",
            )

        self.assertEqual(0, result.returncode, result.stderr)

    def legacy_render_capsule_combines_binary_and_image_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            output_json = root / "capsule.json"
            output_md = root / "capsule.md"

            result = render_capsule(
                manifest, binary_dir, image_dir, output_json, output_md, root
            )

            evidence = json.loads(output_json.read_text(encoding="utf-8"))
            capsule_markdown = output_md.read_text(encoding="utf-8")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(1, len(evidence["binaries"]))
        self.assertEqual(1, len(evidence["images"]))
        self.assertEqual(
            "registryctl-v0.8.0-linux-amd64.spdx.json",
            evidence["binaries"][0]["sbom"]["asset_name"],
        )
        self.assertNotIn("signing_status", evidence["binaries"][0])
        self.assertNotIn("attestation_status", evidence["binaries"][0])
        self.assertNotIn("signing_status", evidence["images"][0])
        self.assertNotIn("attestation_status", evidence["images"][0])
        self.assertIn("Release Trust Capsule", capsule_markdown)
        self.assertIn(
            "SBOM `registryctl-v0.8.0-linux-amd64.spdx.json`", capsule_markdown
        )
        self.assertNotIn("signing `", capsule_markdown)
        self.assertNotIn("attestation `", capsule_markdown)

    def legacy_render_capsule_records_postgresql_as_digest_bound_supporting_image(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            postgresql_ref = f"docker.io/library/postgres@{IMAGE_DIGEST}"
            (image_dir / "postgresql.digest").write_text(
                f"{postgresql_ref}\n",
                encoding="utf-8",
            )
            (image_dir / "postgresql.spdx.json").write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "name": "postgresql",
                        "documentDescribes": ["SPDXRef-postgresql-image"],
                        "packages": [
                            {
                                "SPDXID": "SPDXRef-postgresql-image",
                                "name": "docker.io/library/postgres",
                                "externalRefs": [
                                    {
                                        "referenceType": "purl",
                                        "referenceLocator": f"pkg:oci/postgres@{IMAGE_DIGEST}",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (image_dir / "postgresql.grype.json").write_text(
                json.dumps(
                    {
                        "descriptor": {
                            "version": "0.114.0",
                            "db": {"built": "2026-06-24T00:00:00Z"},
                        },
                        "source": {"target": {"userInput": postgresql_ref}},
                        "matches": [],
                    }
                ),
                encoding="utf-8",
            )
            output_json = root / "capsule.json"

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                output_json,
                root / "capsule.md",
                root,
            )
            evidence = json.loads(output_json.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        postgresql = next(
            image for image in evidence["images"] if image["name"] == "postgresql"
        )
        self.assertEqual("supporting-runtime-image", postgresql["role"])
        self.assertIsNone(postgresql["tag"])
        self.assertIsNone(postgresql["tag_ref"])
        self.assertEqual(postgresql_ref, postgresql["digest_ref"])

    def legacy_render_capsule_classifies_required_image_lock_as_release_file(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            tag_target = git(root, "rev-parse", "v0.8.0^{commit}")
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            add_registryctl_image_lock_fixture(
                binary_dir,
                manifest_source_ref=source_ref,
                tag_target=tag_target,
            )
            binary_sbom_dir = write_binary_sbom_fixture(root, binary_dir)
            image_dir = write_image_fixture(root)
            output_json = root / "capsule.json"
            output_md = root / "capsule.md"

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                output_json,
                output_md,
                root,
                binary_sbom_dir=binary_sbom_dir,
                require_registryctl_image_lock=True,
            )
            evidence = json.loads(output_json.read_text(encoding="utf-8"))
            markdown = output_md.read_text(encoding="utf-8")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(1, len(evidence["binaries"]))
        self.assertEqual(1, len(evidence["release_files"]))
        release_file = evidence["release_files"][0]
        self.assertEqual("registryctl-release-image-lock", release_file["kind"])
        self.assertEqual("registryctl-v0.8.0-image-lock.json", release_file["name"])
        self.assertEqual(
            "registryctl-v0.8.0-image-lock.json.spdx.json",
            release_file["sbom"]["asset_name"],
        )
        self.assertNotIn(
            release_file["name"], {item["name"] for item in evidence["binaries"]}
        )
        self.assertIn("## Release files", markdown)

    def legacy_render_capsule_required_image_lock_fails_when_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                root / "capsule.json",
                root / "capsule.md",
                root,
                require_registryctl_image_lock=True,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn(
            "requires exactly one registryctl release image lock", result.stderr
        )

    def legacy_render_capsule_classifies_required_docs_archive_as_release_file(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            docs_archive = binary_dir / "registry-docs-v0.8.0.tar.gz"
            docs_archive.write_bytes(b"immutable docs bundle\n")
            checksums = "".join(
                subprocess.check_output(
                    ["sha256sum", path.name],
                    cwd=binary_dir,
                    text=True,
                )
                for path in sorted(binary_dir.iterdir())
                if path.is_file() and path.name != "SHA256SUMS"
            )
            (binary_dir / "SHA256SUMS").write_text(checksums, encoding="utf-8")
            binary_sbom_dir = write_binary_sbom_fixture(root, binary_dir)
            image_dir = write_image_fixture(root)
            output_json = root / "capsule.json"

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                output_json,
                root / "capsule.md",
                root,
                binary_sbom_dir=binary_sbom_dir,
                require_registry_docs_archive=True,
            )
            evidence = json.loads(output_json.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        docs_files = [
            item
            for item in evidence["release_files"]
            if item["kind"] == "registry-docs-archive"
        ]
        self.assertEqual(1, len(docs_files))
        self.assertEqual("registry-docs-v0.8.0.tar.gz", docs_files[0]["name"])

    def legacy_render_capsule_required_docs_archive_fails_when_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            result = render_capsule(
                manifest,
                write_binary_fixture(root),
                write_image_fixture(root),
                root / "capsule.json",
                root / "capsule.md",
                root,
                require_registry_docs_archive=True,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("requires exactly one registry docs archive", result.stderr)

    def legacy_render_capsule_classifies_declared_registryctl_installer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(
                root,
                source_ref=source_ref,
                include_registryctl_installer=True,
            )
            binary_dir = write_binary_fixture(root)
            installer = binary_dir / "registryctl-v0.8.0-install.sh"
            installer.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            checksums = "".join(
                subprocess.check_output(
                    ["sha256sum", path.name],
                    cwd=binary_dir,
                    text=True,
                )
                for path in sorted(binary_dir.iterdir())
                if path.is_file() and path.name != "SHA256SUMS"
            )
            (binary_dir / "SHA256SUMS").write_text(checksums, encoding="utf-8")
            binary_sbom_dir = write_binary_sbom_fixture(root, binary_dir)
            output_json = root / "capsule.json"

            result = render_capsule(
                manifest,
                binary_dir,
                write_image_fixture(root),
                output_json,
                root / "capsule.md",
                root,
                binary_sbom_dir=binary_sbom_dir,
                require_registryctl_installer=True,
            )
            evidence = json.loads(output_json.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        installers = [
            item
            for item in evidence["release_files"]
            if item["kind"] == "registryctl-installer"
        ]
        self.assertEqual(1, len(installers))
        self.assertEqual("registryctl-v0.8.0-install.sh", installers[0]["name"])
        self.assertNotIn(
            installers[0]["name"],
            {item["name"] for item in evidence["binaries"]},
        )

    def legacy_render_capsule_requires_installer_declaration_and_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            undeclared_root = root / "undeclared"
            undeclared_root.mkdir()
            source_ref = init_release_repo(undeclared_root)
            undeclared = write_manifest(undeclared_root, source_ref=source_ref)
            missing_declaration = render_capsule(
                undeclared,
                write_binary_fixture(undeclared_root),
                write_image_fixture(undeclared_root),
                undeclared_root / "capsule.json",
                undeclared_root / "capsule.md",
                undeclared_root,
                require_registryctl_installer=True,
            )

            declared_root = root / "declared"
            declared_root.mkdir()
            source_ref = init_release_repo(declared_root)
            declared = write_manifest(
                declared_root,
                source_ref=source_ref,
                include_registryctl_installer=True,
            )
            missing_file = render_capsule(
                declared,
                write_binary_fixture(declared_root),
                write_image_fixture(declared_root),
                declared_root / "capsule.json",
                declared_root / "capsule.md",
                declared_root,
                require_registryctl_installer=True,
            )

        self.assertNotEqual(0, missing_declaration.returncode)
        self.assertIn(
            "requires manifest artifact registryctl-installer",
            missing_declaration.stderr,
        )
        self.assertNotEqual(0, missing_file.returncode)
        self.assertIn(
            "requires exactly one registryctl installer",
            missing_file.stderr,
        )

    def legacy_render_capsule_includes_cross_platform_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_multiplatform_binary_fixture(root)
            image_dir = write_image_fixture(root)
            output_json = root / "capsule.json"
            output_md = root / "capsule.md"

            result = render_capsule(
                manifest, binary_dir, image_dir, output_json, output_md, root
            )

            evidence = json.loads(output_json.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        names = {binary["name"] for binary in evidence["binaries"]}
        self.assertEqual(
            {
                "registryctl-v0.8.0-linux-amd64",
                "registryctl-v0.8.0-linux-arm64",
                "registryctl-v0.8.0-macos-arm64",
            },
            names,
        )

    def legacy_render_capsule_rejects_grype_subject_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(
                root,
                grype_subject="ghcr.io/registrystack/registry-notary@sha256:"
                + "b" * 64,
            )
            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                root / "capsule.json",
                root / "capsule.md",
                root,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("does not match digest ref", result.stderr)

    def legacy_render_capsule_accepts_promoted_candidate_grype_subject(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(
                root,
                grype_subject=(
                    "ghcr.io/registrystack/registry-notary-candidate@"
                    + IMAGE_DIGEST
                ),
            )
            output_json = root / "capsule.json"

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                output_json,
                root / "capsule.md",
                root,
            )
            evidence = json.loads(output_json.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            IMAGE_DIGEST_REF,
            evidence["images"][0]["vulnerability_scan"]["subject"],
        )

    def legacy_render_capsule_rejects_unrelated_grype_repo_with_same_digest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(
                root,
                grype_subject=(
                    "ghcr.io/registrystack/registry-notary-other@" + IMAGE_DIGEST
                ),
            )

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                root / "capsule.json",
                root / "capsule.md",
                root,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("does not match digest ref", result.stderr)

    def legacy_render_capsule_ignores_stale_status_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (image_dir / "registry-notary.status.json").write_text(
                json.dumps(
                    {"signing_status": "unknown", "attestation_status": "not-present"}
                ),
                encoding="utf-8",
            )
            output_json = root / "capsule.json"
            result = render_capsule(
                manifest, binary_dir, image_dir, output_json, root / "capsule.md", root
            )
            evidence = json.loads(output_json.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("signing_status", evidence["images"][0])
        self.assertNotIn("attestation_status", evidence["images"][0])

    def legacy_render_capsule_rejects_missing_required_image_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (image_dir / "registry-notary.spdx.json").unlink()
            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                root / "capsule.json",
                root / "capsule.md",
                root,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("missing an SBOM file", result.stderr)

    def legacy_render_capsule_rejects_sbom_without_digest_subject(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (image_dir / "registry-notary.spdx.json").write_text(
                json.dumps({"spdxVersion": "SPDX-2.3", "name": "unrelated"}),
                encoding="utf-8",
            )

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                root / "capsule.json",
                root / "capsule.md",
                root,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("SBOM subject does not contain digest", result.stderr)

    def legacy_render_capsule_rejects_digest_only_in_spdx_comment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (image_dir / "registry-notary.spdx.json").write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "name": "unrelated",
                        "documentDescribes": ["SPDXRef-unrelated"],
                        "packages": [
                            {
                                "SPDXID": "SPDXRef-unrelated",
                                "name": "unrelated",
                                "comment": f"mentions {IMAGE_DIGEST_REF} but is not the subject",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                root / "capsule.json",
                root / "capsule.md",
                root,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("SBOM subject does not contain digest", result.stderr)

    def legacy_render_capsule_rejects_grype_without_digest_subject(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (image_dir / "registry-notary.grype.json").write_text(
                json.dumps({"descriptor": {"version": "0.114.0"}, "matches": []}),
                encoding="utf-8",
            )

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                root / "capsule.json",
                root / "capsule.md",
                root,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("Grype report has no digest-bound subject", result.stderr)

    def legacy_render_capsule_rejects_bogus_binary_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (binary_dir / "SHA256SUMS").write_text(
                "0000000000000000000000000000000000000000000000000000000000000000  registryctl-v0.8.0-linux-amd64\n",
                encoding="utf-8",
            )

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                root / "capsule.json",
                root / "capsule.md",
                root,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("SHA256SUMS entry does not match file contents", result.stderr)

    def legacy_render_capsule_rejects_missing_binary_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            binary_sbom_dir = root / "binary-sbom"
            binary_sbom_dir.mkdir()
            image_dir = write_image_fixture(root)

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                root / "capsule.json",
                root / "capsule.md",
                root,
                binary_sbom_dir=binary_sbom_dir,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("missing a file SBOM", result.stderr)

    def legacy_render_capsule_rejects_binary_sbom_without_digest_subject(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            binary_sbom_dir = write_binary_sbom_fixture(root, binary_dir)
            image_dir = write_image_fixture(root)
            (binary_sbom_dir / "registryctl-v0.8.0-linux-amd64.spdx.json").write_text(
                json.dumps({"spdxVersion": "SPDX-2.3", "name": "unrelated"}),
                encoding="utf-8",
            )

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                root / "capsule.json",
                root / "capsule.md",
                root,
                binary_sbom_dir=binary_sbom_dir,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("SBOM subject does not contain sha256", result.stderr)

    def legacy_render_capsule_rejects_invalid_digest_ref_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (image_dir / "registry-notary.digest").write_text(
                "ghcr.io/registrystack/registry-notary@sha256:1234\n",
                encoding="utf-8",
            )

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                root / "capsule.json",
                root / "capsule.md",
                root,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("digest ref must match image@sha256:<64 hex>", result.stderr)

    def legacy_render_capsule_rejects_mismatched_source_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref, source_tag="v9.9.9")
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)

            result = render_capsule(
                manifest,
                binary_dir,
                image_dir,
                root / "capsule.json",
                root / "capsule.md",
                root,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("does not match checked-out release tag", result.stderr)

    def legacy_render_capsule_prefers_digest_bound_backfill_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(
                root, grype_subject="ghcr.io/registrystack/registry-notary:v0.8.0"
            )
            (image_dir / "registry-notary.digest-bound.spdx.json").write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "name": "registry-notary-digest-bound",
                        "documentDescribes": ["SPDXRef-registry-notary-image"],
                        "packages": [
                            {
                                "SPDXID": "SPDXRef-registry-notary-image",
                                "name": "ghcr.io/registrystack/registry-notary",
                                "externalRefs": [
                                    {
                                        "referenceType": "purl",
                                        "referenceLocator": f"pkg:oci/registry-notary@{IMAGE_DIGEST}",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (image_dir / "registry-notary.digest-bound.grype.json").write_text(
                json.dumps(
                    {
                        "descriptor": {
                            "version": "0.114.0",
                            "db": {"built": "2026-06-24T00:00:00Z"},
                        },
                        "source": {"target": {"userInput": IMAGE_DIGEST_REF}},
                        "matches": [],
                    }
                ),
                encoding="utf-8",
            )
            output_json = root / "capsule.json"

            result = render_capsule(
                manifest, binary_dir, image_dir, output_json, root / "capsule.md", root
            )

            evidence = json.loads(output_json.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            "registry-notary.digest-bound.spdx.json",
            evidence["images"][0]["sbom"]["asset_name"],
        )
        self.assertEqual(
            "registry-notary.digest-bound.grype.json",
            evidence["images"][0]["vulnerability_scan"]["asset_name"],
        )

    def legacy_stage_capsule_backfill_assets_copies_expected_release_assets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset_dir = write_release_asset_fixture(root)
            binary_dir = root / "staged-bin"
            image_dir = root / "staged-images"

            result = run_tool(
                "stage-capsule-backfill-assets",
                str(asset_dir),
                "--tag",
                "v0.8.0",
                "--binary-dir",
                str(binary_dir),
                "--image-evidence-dir",
                str(image_dir),
            )

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue((binary_dir / "registryctl-v0.8.0-linux-amd64").is_file())
            self.assertTrue(
                (binary_dir / "registry-manifest-v0.8.0-linux-amd64").is_file()
            )
            self.assertTrue(
                (binary_dir / "registry-relay-v0.8.0-linux-amd64").is_file()
            )
            self.assertTrue(
                (binary_dir / "registry-relay-rhai-worker-v0.8.0-linux-amd64").is_file()
            )
            self.assertTrue(
                (binary_dir / "registry-notary-cel-worker-v0.8.0-linux-amd64").is_file()
            )
            self.assertTrue(
                (binary_dir / "registry-notary-v0.8.0-linux-amd64").is_file()
            )
            self.assertTrue((binary_dir / "SHA256SUMS").is_file())
            self.assertTrue((image_dir / "registry-notary.digest").is_file())
            self.assertTrue((image_dir / "registry-relay.digest").is_file())
            self.assertFalse(
                (image_dir / "registry-notary-source-adapter-sidecar.digest").exists()
            )
            self.assertFalse((image_dir / "registry-relay.grype.json").exists())
            self.assertFalse(
                (image_dir / "registry-stack-v0.8.0-release-evidence.json").exists()
            )
            # Cross-platform binaries are optional and absent in this fixture.
            self.assertFalse((binary_dir / "registryctl-v0.8.0-macos-arm64").exists())
            self.assertFalse((binary_dir / "registryctl-v0.8.0-linux-arm64").exists())

    def legacy_stage_capsule_backfill_assets_stages_optional_cross_platform_binaries(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset_dir = write_release_asset_fixture(root, include_cross_platform=True)
            binary_dir = root / "staged-bin"
            image_dir = root / "staged-images"

            result = run_tool(
                "stage-capsule-backfill-assets",
                str(asset_dir),
                "--tag",
                "v0.8.0",
                "--binary-dir",
                str(binary_dir),
                "--image-evidence-dir",
                str(image_dir),
            )

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue((binary_dir / "registryctl-v0.8.0-macos-arm64").is_file())
            self.assertTrue((binary_dir / "registryctl-v0.8.0-linux-arm64").is_file())
            # Required amd64 binaries are still staged alongside the optional ones.
            self.assertTrue((binary_dir / "registryctl-v0.8.0-linux-amd64").is_file())

    def legacy_stage_capsule_backfill_assets_stages_optional_registryctl_image_lock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset_dir = write_release_asset_fixture(root, include_image_lock=True)
            binary_dir = root / "staged-bin"

            result = run_tool(
                "stage-capsule-backfill-assets",
                str(asset_dir),
                "--tag",
                "v0.8.0",
                "--binary-dir",
                str(binary_dir),
                "--image-evidence-dir",
                str(root / "staged-images"),
            )

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(
                (binary_dir / "registryctl-v0.8.0-image-lock.json").is_file()
            )
            self.assertIn("1/1 optional release files", result.stdout)

    def legacy_stage_capsule_backfill_assets_requires_v010_worker_binaries(self) -> None:
        for missing_name in (
            "registry-relay-rhai-worker-v0.10.0-linux-amd64",
            "registry-notary-cel-worker-v0.10.0-linux-amd64",
        ):
            with (
                self.subTest(missing_name=missing_name),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                asset_dir = write_release_asset_fixture(
                    root,
                    tag="v0.10.0",
                    include_image_lock=True,
                )
                (asset_dir / missing_name).unlink()

                result = run_tool(
                    "stage-capsule-backfill-assets",
                    str(asset_dir),
                    "--tag",
                    "v0.10.0",
                    "--binary-dir",
                    str(root / "staged-bin"),
                    "--image-evidence-dir",
                    str(root / "staged-images"),
                )

                self.assertNotEqual(0, result.returncode)
                self.assertIn(f"missing release asset {missing_name}", result.stderr)

    def legacy_stage_capsule_backfill_assets_requires_v09_registryctl_image_lock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset_dir = write_release_asset_fixture(root, tag="v0.9.0")

            result = run_tool(
                "stage-capsule-backfill-assets",
                str(asset_dir),
                "--tag",
                "v0.9.0",
                "--binary-dir",
                str(root / "staged-bin"),
                "--image-evidence-dir",
                str(root / "staged-images"),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn(
            "missing release asset registryctl-v0.9.0-image-lock.json",
            result.stderr,
        )

    def legacy_stage_capsule_backfill_assets_rejects_missing_release_asset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset_dir = write_release_asset_fixture(root)
            (asset_dir / "registry-relay.digest").unlink()

            result = run_tool(
                "stage-capsule-backfill-assets",
                str(asset_dir),
                "--tag",
                "v0.8.0",
                "--binary-dir",
                str(root / "staged-bin"),
                "--image-evidence-dir",
                str(root / "staged-images"),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("missing release asset registry-relay.digest", result.stderr)

    def test_bind_spdx_subject_adds_digest_bound_described_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spdx = root / "registry-notary.spdx.json"
            spdx.write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "name": "syft-registry-notary-output",
                        "documentDescribes": ["SPDXRef-DocumentRoot"],
                        "packages": [
                            {
                                "SPDXID": "SPDXRef-DocumentRoot",
                                "name": "registry-notary",
                                "downloadLocation": "NOASSERTION",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = run_tool(
                "bind-spdx-subject",
                str(spdx),
                "--image-name",
                "registry-notary",
                "--digest-ref",
                IMAGE_DIGEST_REF,
            )

            data = json.loads(spdx.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        described = set(data["documentDescribes"])
        subject_packages = [
            package for package in data["packages"] if package["SPDXID"] in described
        ]
        self.assertTrue(
            any(package["name"] == IMAGE_DIGEST_REF for package in subject_packages)
        )
        self.assertTrue(
            any(IMAGE_DIGEST in json.dumps(package) for package in subject_packages)
        )

    def test_bind_spdx_file_subject_adds_sha256_bound_described_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spdx = root / "registryctl.spdx.json"
            digest = "a" * 64
            spdx.write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "name": "syft-registryctl-output",
                        "documentDescribes": ["SPDXRef-DocumentRoot"],
                        "packages": [
                            {
                                "SPDXID": "SPDXRef-DocumentRoot",
                                "name": "registryctl",
                                "downloadLocation": "NOASSERTION",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = run_tool(
                "bind-spdx-file-subject",
                str(spdx),
                "--file-name",
                "registryctl-v0.8.0-linux-amd64",
                "--sha256",
                digest,
            )

            data = json.loads(spdx.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        described = set(data["documentDescribes"])
        subject_packages = [
            package for package in data["packages"] if package["SPDXID"] in described
        ]
        self.assertTrue(
            any(
                package["name"] == "registryctl-v0.8.0-linux-amd64"
                and package["checksums"][0]["checksumValue"] == digest
                for package in subject_packages
            )
        )


def run_tool(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def init_repo(repo: Path) -> Path:
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "release-test@example.invalid")
    git(repo, "config", "user.name", "Release Test")
    return repo


def init_release_repo(repo: Path) -> str:
    init_repo(repo)
    source_ref = commit_file(repo, "source.txt", "source\n")
    commit_file(repo, "release.txt", "release\n")
    git(repo, "tag", "v0.8.0")
    return source_ref


def commit_file(repo: Path, name: str, body: str) -> str:
    path = repo / name
    path.write_text(body, encoding="utf-8")
    git(repo, "add", name)
    git(repo, "commit", "-m", f"add {name}")
    return git(repo, "rev-parse", "HEAD")


def write_manifest(
    directory: Path,
    *,
    source_ref: str = "f30a541df539c2e16de09733c5944c744a60493c",
    source_tag: str | None = None,
    status: str = "release-candidate",
    version: str = "0.8.0",
    include_registryctl_image_lock: bool | None = None,
    include_registryctl_installer: bool | None = None,
) -> Path:
    if source_tag is None:
        source_tag = f"v{version}"
    version_tuple = tuple(int(part) for part in version.split("."))
    if version_tuple >= (0, 10, 0):
        artifacts = {
            "registry-notary": version,
            "registry-notary-cel-worker": version,
            "registry-relay": version,
            "registry-relay-rhai-worker": version,
            "registry-manifest-cli": version,
            "registryctl": version,
            "registryctl-image-lock": version,
            "registry-docs": version,
        }
    else:
        artifacts = {
            "registry-notary": version,
            "registry-relay": version,
        }
    if include_registryctl_image_lock is None:
        include_registryctl_image_lock = version_tuple >= (0, 9, 0)
    if include_registryctl_image_lock:
        artifacts["registryctl-image-lock"] = version
    else:
        artifacts.pop("registryctl-image-lock", None)
    if include_registryctl_installer is None:
        include_registryctl_installer = version_tuple >= (0, 14, 0)
    if include_registryctl_installer:
        artifacts["registryctl-installer"] = version
    manifest = {
        "stack": {
            "release": "beta-6",
            "version": version,
            "source_repo": "registrystack/registry-stack",
            "source_ref": source_ref,
            "source_tag": source_tag,
            "status": status,
        },
        "artifacts": artifacts,
        "external": {
            "crosswalk": {
                "repo": "PublicSchema/crosswalk",
                "ref": "1d44ec735fdc8a7c719264b339574371e8330337",
                "status": "tested external input",
            },
        },
    }
    path = directory / "release-manifest.yaml"
    path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return path


def write_docset_fixture(root: Path) -> tuple[Path, Path]:
    manifest_dir = root / "manifests"
    manifest_dir.mkdir()
    manifest = write_manifest(manifest_dir)
    manifest.rename(manifest_dir / "registry-stack-beta-6.yaml")
    docsets = root / "docsets.yaml"
    docsets.write_text(
        yaml.safe_dump(
            {
                "current": "latest",
                "docsets": [
                    {
                        "id": "v0.8.0",
                        "status": "archived",
                        "source": "registry-stack-v0.8.0",
                        "products": {
                            "registry-stack": {
                                "version": "v0.8.0",
                                "ref": "f30a541df539c2e16de09733c5944c744a60493c",
                            },
                            "crosswalk": {
                                "version": "crosswalk-core-v0.2.0",
                                "ref": "1d44ec735fdc8a7c719264b339574371e8330337",
                            },
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (root / "archive-lock.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": "registry-docs.archive-lock.v1",
                "archives": {
                    "v0.8.0": {
                        "bundle_sha256": "a" * 64,
                        "tree_sha256": "b" * 64,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return manifest_dir, docsets


def write_binary_fixture(root: Path) -> Path:
    binary_dir = root / "bin"
    binary_dir.mkdir()
    binary = binary_dir / "registryctl-v0.8.0-linux-amd64"
    binary.write_text("binary fixture\n", encoding="utf-8")
    checksum = subprocess.check_output(
        ["sha256sum", binary.name], cwd=binary_dir, text=True
    )
    (binary_dir / "SHA256SUMS").write_text(checksum, encoding="utf-8")
    return binary_dir


def add_registryctl_image_lock_fixture(
    binary_dir: Path,
    *,
    manifest_source_ref: str,
    tag_target: str,
) -> Path:
    image_lock = binary_dir / "registryctl-v0.8.0-image-lock.json"
    image_lock.write_text(
        json.dumps(
            {
                "schema_version": "registryctl.release_image_lock.v1",
                "release_tag": "v0.8.0",
                "manifest_source_ref": manifest_source_ref,
                "tag_target": tag_target,
                "platform": "linux/amd64",
                "images": {
                    "registry-relay": f"ghcr.io/registrystack/registry-relay@{IMAGE_DIGEST}",
                    "registry-notary": f"ghcr.io/registrystack/registry-notary@{IMAGE_DIGEST}",
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    checksums = []
    for path in sorted(binary_dir.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            checksums.append(
                subprocess.check_output(
                    ["sha256sum", path.name], cwd=binary_dir, text=True
                )
            )
    (binary_dir / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
    return image_lock


def write_multiplatform_binary_fixture(root: Path) -> Path:
    binary_dir = root / "bin"
    binary_dir.mkdir()
    names = [
        "registryctl-v0.8.0-linux-amd64",
        "registryctl-v0.8.0-linux-arm64",
        "registryctl-v0.8.0-macos-arm64",
    ]
    checksums = []
    for name in names:
        (binary_dir / name).write_text(f"{name} fixture\n", encoding="utf-8")
        checksums.append(
            subprocess.check_output(["sha256sum", name], cwd=binary_dir, text=True)
        )
    (binary_dir / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
    return binary_dir


def write_binary_sbom_fixture(root: Path, binary_dir: Path) -> Path:
    sbom_dir = root / "binary-sbom"
    sbom_dir.mkdir(exist_ok=True)
    for binary in sorted(binary_dir.iterdir()):
        if not binary.is_file() or binary.name == "SHA256SUMS":
            continue
        digest = subprocess.check_output(
            ["sha256sum", binary.name],
            cwd=binary_dir,
            text=True,
        ).split()[0]
        subject_id = f"SPDXRef-RegistryStack-{binary.name}-sha256-subject"
        (sbom_dir / f"{binary.name}.spdx.json").write_text(
            json.dumps(
                {
                    "spdxVersion": "SPDX-2.3",
                    "name": f"{binary.name}-sbom",
                    "documentDescribes": [subject_id],
                    "packages": [
                        {
                            "SPDXID": subject_id,
                            "name": binary.name,
                            "packageFileName": binary.name,
                            "downloadLocation": "NOASSERTION",
                            "filesAnalyzed": False,
                            "checksums": [
                                {
                                    "algorithm": "SHA256",
                                    "checksumValue": digest,
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
    return sbom_dir


def write_release_asset_fixture(
    root: Path,
    *,
    tag: str = "v0.8.0",
    include_cross_platform: bool = False,
    include_image_lock: bool = False,
) -> Path:
    asset_dir = root / "release-assets"
    asset_dir.mkdir()
    binary_names = [
        f"registryctl-{tag}-linux-amd64",
        f"registry-manifest-{tag}-linux-amd64",
        f"registry-relay-{tag}-linux-amd64",
        f"registry-relay-rhai-worker-{tag}-linux-amd64",
        f"registry-notary-{tag}-linux-amd64",
        f"registry-notary-cel-worker-{tag}-linux-amd64",
    ]
    if include_cross_platform:
        binary_names += [
            f"registryctl-{tag}-macos-arm64",
            f"registryctl-{tag}-linux-arm64",
        ]
    if include_image_lock:
        binary_names.append(f"registryctl-{tag}-image-lock.json")
    checksums = []
    for name in binary_names:
        path = asset_dir / name
        path.write_text(f"{name}\n", encoding="utf-8")
        checksums.append(
            subprocess.check_output(["sha256sum", name], cwd=asset_dir, text=True)
        )
    (asset_dir / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
    for image in ("registry-notary", "registry-relay"):
        (asset_dir / f"{image}.digest").write_text(
            f"{IMAGE_DIGEST_REF}\n", encoding="utf-8"
        )
        (asset_dir / f"{image}.spdx.json").write_text("{}", encoding="utf-8")
        (asset_dir / f"{image}.grype.json").write_text("{}", encoding="utf-8")
        (asset_dir / f"{image}.metadata.json").write_text("{}", encoding="utf-8")
    (asset_dir / f"registry-stack-{tag}-release-evidence.json").write_text(
        "{}", encoding="utf-8"
    )
    return asset_dir


def write_image_fixture(
    root: Path,
    *,
    grype_subject: str = IMAGE_DIGEST_REF,
) -> Path:
    image_dir = root / "image-evidence"
    image_dir.mkdir()
    (image_dir / "registry-notary.digest").write_text(
        f"{IMAGE_DIGEST_REF}\n",
        encoding="utf-8",
    )
    (image_dir / "registry-notary.spdx.json").write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "name": "registry-notary",
                "documentDescribes": ["SPDXRef-registry-notary-image"],
                "packages": [
                    {
                        "SPDXID": "SPDXRef-registry-notary-image",
                        "name": "ghcr.io/registrystack/registry-notary",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": f"pkg:oci/registry-notary@{IMAGE_DIGEST}",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (image_dir / "registry-notary.grype.json").write_text(
        json.dumps(
            {
                "descriptor": {
                    "version": "0.114.0",
                    "db": {"built": "2026-06-24T00:00:00Z"},
                },
                "source": {"target": {"userInput": grype_subject}},
                "matches": [{"vulnerability": {"severity": "High"}}],
            }
        ),
        encoding="utf-8",
    )
    return image_dir


def render_capsule(
    manifest: Path,
    binary_dir: Path,
    image_dir: Path,
    output_json: Path,
    output_md: Path,
    repo: Path,
    *,
    binary_sbom_dir: Path | None = None,
    require_registryctl_image_lock: bool = False,
    require_registry_docs_archive: bool = False,
    require_registryctl_installer: bool = False,
) -> subprocess.CompletedProcess[str]:
    if binary_sbom_dir is None:
        binary_sbom_dir = write_binary_sbom_fixture(repo, binary_dir)
    args = [
        "render-capsule",
        str(manifest),
        "--tag",
        "v0.8.0",
        "--version",
        "0.8.0",
        "--binary-dir",
        str(binary_dir),
        "--binary-sbom-dir",
        str(binary_sbom_dir),
        "--image-evidence-dir",
        str(image_dir),
        "--output-json",
        str(output_json),
        "--output-markdown",
        str(output_md),
        "--workflow-run-url",
        "https://github.com/registrystack/registry-stack/actions/runs/1",
        "--workflow-run-id",
        "1",
        "--repo",
        str(repo),
        "--default-branch",
        "main",
    ]
    if require_registryctl_image_lock:
        args.append("--require-registryctl-image-lock")
    if require_registry_docs_archive:
        args.append("--require-registry-docs-archive")
    if require_registryctl_installer:
        args.append("--require-registryctl-installer")
    return run_tool(*args)


if __name__ == "__main__":
    unittest.main()
