#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "release/scripts/registry-release"
IMAGE_DIGEST = "sha256:" + "a" * 64
IMAGE_DIGEST_REF = f"ghcr.io/registrystack/registry-notary@{IMAGE_DIGEST}"


def load_debian13_image_check():
    path = ROOT / "release/scripts/check-debian13-images.py"
    spec = importlib.util.spec_from_file_location("check_debian13_images", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RegistryReleaseTest(unittest.TestCase):
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
                self.assertEqual(
                    {"changes", check_job_id},
                    set(required_job["needs"]),
                )
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

    def test_maintained_images_follow_debian13_contract(self) -> None:
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

    def test_debian13_contract_rejects_other_tutorial_builders(self) -> None:
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

            tutorial = root / "docs/site/scripts/check-registryctl-tutorials.sh"
            text = tutorial.read_text(encoding="utf-8")
            tutorial.write_text(
                text.replace(module.RUST_BUILDER, "rust:1.95-debian-12", 1),
                encoding="utf-8",
            )

            failures = module.check_repository(root)
            self.assertTrue(
                any(
                    "retired Debian image generation marker" in failure
                    for failure in failures
                )
            )
            self.assertTrue(
                any(
                    "pinned Debian 13 tutorial builder" in failure
                    for failure in failures
                )
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

    def test_registryctl_alternate_installer_uses_the_target_release_tag(self) -> None:
        text = (ROOT / "crates/registryctl/README.md").read_text(encoding="utf-8")

        self.assertIn(
            "refs/tags/vX.Y.Z/crates/registryctl/install.sh | "
            "REGISTRYCTL_VERSION=vX.Y.Z bash",
            text,
        )

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

    def test_release_images_publish_and_executably_verify_oci_labels(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        images_job = workflow[
            workflow.index("\n  build-a:") : workflow.index("\n  build-b:")
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

    def test_release_cargo_cache_is_scoped_to_builder_image(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        binaries_job = workflow[
            workflow.index("\n  build-a:") : workflow.index("\n  build-b:")
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

    def test_release_build_wrappers_are_executable_and_canonical(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        ci_workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        binaries_job = workflow[
            workflow.index("\n  build-a:") : workflow.index("\n  build-b:")
        ]
        images_job = workflow[
            workflow.index("\n  build-a:") : workflow.index("\n  build-b:")
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

    def test_release_records_cache_and_duration_telemetry(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        promotion = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        binaries_job = workflow[
            workflow.index("\n  build-a:") : workflow.index("\n  build-b:")
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
        images_job = workflow[workflow.index("\n  verify-candidate:") :]

        scan_step = images_job.index("Scan immutable staging digests")
        enforcement_step = images_job.index("Enforce advisory policy")
        upload_step = images_job.index("Upload exact candidate payload")
        self.assertLess(scan_step, enforcement_step)
        self.assertLess(enforcement_step, upload_step)
        self.assertIn(
            "grype dist/candidate/dist/grype/registry-notary.grype.json",
            images_job,
        )
        self.assertIn(
            "grype dist/candidate/dist/grype/registry-relay.grype.json",
            images_job,
        )
        self.assertIn("--syft-report", images_job)
        self.assertIn("--rootfs", images_job)
        self.assertIn("retention-days: 7", images_job[upload_step:])

    def test_release_packaging_excludes_retired_notary_source_sidecar(self) -> None:
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

    def test_release_workflow_publishes_cross_platform_registryctl_binaries(
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

    def test_release_workflow_does_not_execute_downloaded_binaries_when_publishing(
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

    def test_release_workflow_never_replaces_published_assets(self) -> None:
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

    def test_candidate_receipt_checks_its_in_progress_run_identity(self) -> None:
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

    def test_candidate_promotion_has_closed_no_rebuild_publish_gates(self) -> None:
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
            'test "$(git rev-parse refs/remotes/origin/main)" = \\\n'
            '  "${{ steps.release.outputs.tag_target }}"',
            source_verification,
        )
        self.assertEqual("read", publish_images["permissions"]["contents"])
        self.assertEqual("write", publish_images["permissions"]["packages"])
        self.assertNotIn("id-token", publish_images["permissions"])
        self.assertIn("releases/tags/${tag}", publish_script)
        self.assertIn("packages/container/${name}/versions", publish_script)
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

    def test_release_workflow_publishes_digest_bound_release_file_sboms(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        candidate = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
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
        self.assertIn(
            "registryctl-${{ needs.verify.outputs.tag }}-image-lock.json", workflow
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

    def test_capsule_backfill_resolves_manifest_for_requested_tag(self) -> None:
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

    def test_capsule_backfill_privileged_job_uses_protected_tooling(
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
        self.assertIn("validated 11 versioned docsets", result.stdout)

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

    def test_render_capsule_combines_binary_and_image_evidence(self) -> None:
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

    def test_render_capsule_classifies_required_image_lock_as_release_file(
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

    def test_render_capsule_required_image_lock_fails_when_omitted(self) -> None:
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

    def test_render_capsule_includes_cross_platform_binaries(self) -> None:
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

    def test_render_capsule_rejects_grype_subject_digest_mismatch(self) -> None:
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

    def test_render_capsule_ignores_stale_status_files(self) -> None:
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

    def test_render_capsule_rejects_missing_required_image_evidence(self) -> None:
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

    def test_render_capsule_rejects_sbom_without_digest_subject(self) -> None:
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

    def test_render_capsule_rejects_digest_only_in_spdx_comment(self) -> None:
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

    def test_render_capsule_rejects_grype_without_digest_subject(self) -> None:
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

    def test_render_capsule_rejects_bogus_binary_checksum(self) -> None:
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

    def test_render_capsule_rejects_missing_binary_sbom(self) -> None:
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

    def test_render_capsule_rejects_binary_sbom_without_digest_subject(self) -> None:
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

    def test_render_capsule_rejects_invalid_digest_ref_shape(self) -> None:
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

    def test_render_capsule_rejects_mismatched_source_tag(self) -> None:
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

    def test_render_capsule_prefers_digest_bound_backfill_evidence(self) -> None:
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

    def test_stage_capsule_backfill_assets_copies_expected_release_assets(self) -> None:
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

    def test_stage_capsule_backfill_assets_stages_optional_cross_platform_binaries(
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

    def test_stage_capsule_backfill_assets_stages_optional_registryctl_image_lock(
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

    def test_stage_capsule_backfill_assets_requires_v010_worker_binaries(self) -> None:
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

    def test_stage_capsule_backfill_assets_requires_v09_registryctl_image_lock(
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

    def test_stage_capsule_backfill_assets_rejects_missing_release_asset(self) -> None:
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
    return run_tool(*args)


if __name__ == "__main__":
    unittest.main()
