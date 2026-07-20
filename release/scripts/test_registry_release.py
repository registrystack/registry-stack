#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
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
                any("retired Debian image generation marker" in failure for failure in failures)
            )
            self.assertTrue(
                any("not pinned by immutable digest" in failure for failure in failures)
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
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        release_dockerfiles = [
            "release/docker/Dockerfile.registry-notary",
            "release/docker/Dockerfile.registry-relay",
        ]

        for dockerfile in release_dockerfiles:
            self.assertIn(dockerfile, workflow)
            text = (ROOT / dockerfile).read_text(encoding="utf-8")
            self.assertIn("dist/image-bin", text)

    def test_release_images_publish_and_executably_verify_oci_labels(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        images_job = workflow[
            workflow.index("\n  images:") : workflow.index("\n  github-release:")
        ]

        for label in (
            '--label "org.opencontainers.image.source=https://github.com/${GITHUB_REPOSITORY}"',
            '--label "org.opencontainers.image.revision=${{ needs.verify.outputs.tag_target }}"',
            '--label "org.opencontainers.image.version=${{ needs.verify.outputs.version }}"',
        ):
            self.assertEqual(1, images_job.count(label))
        checker = "python3 release/scripts/check-release-image-oci-labels.py"
        self.assertEqual(1, images_job.count(checker))
        self.assertLess(images_job.index('local digest_ref="'), images_job.index(checker))
        self.assertIn('--source "https://github.com/${GITHUB_REPOSITORY}"', images_job)
        self.assertIn('--revision "${{ needs.verify.outputs.tag_target }}"', images_job)
        self.assertIn('--version "${{ needs.verify.outputs.version }}"', images_job)
        self.assertNotIn("{{json .Image.config}}", workflow)

    def test_release_cargo_cache_is_scoped_to_builder_image(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        binaries_job = workflow[
            workflow.index("\n  binaries:") : workflow.index("\n  registryctl-extra-binaries:")
        ]

        fingerprint_step = binaries_job.index("Fingerprint release builder")
        cache_step = binaries_job.index("Restore Cargo release cache")
        self.assertLess(fingerprint_step, cache_step)
        self.assertIn(
            "printf '%s' \"${RELEASE_BUILDER_IMAGE}\" | sha256sum",
            binaries_job,
        )
        builder_fingerprint = "${{ steps.release-builder.outputs.fingerprint }}"
        self.assertGreaterEqual(binaries_job.count(builder_fingerprint), 2)
        self.assertNotIn(
            "registry-stack-release-cargo-${{ runner.os }}-rust-1.95.0-",
            binaries_job,
        )

    def test_release_records_cache_and_duration_telemetry(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        binaries_job = workflow[
            workflow.index("\n  binaries:") : workflow.index("\n  registryctl-extra-binaries:")
        ]
        telemetry_job = workflow[workflow.index("\n  release-telemetry:") :]

        self.assertIn("name: Restore Cargo release cache\n        id: cargo-cache", binaries_job)
        self.assertIn("steps.cargo-cache.outputs.cache-hit", binaries_job)
        self.assertIn("registry-stack.release-binary-telemetry.v1", binaries_job)
        self.assertIn("exact_key_hit", binaries_job)
        self.assertIn("duration_seconds", binaries_job)
        self.assertIn("name: Upload binary build telemetry", binaries_job)
        self.assertIn("if: ${{ always() }}", binaries_job)

        self.assertIn("name: Record release workflow telemetry", telemetry_job)
        self.assertIn("if: ${{ always() }}", telemetry_job)
        self.assertIn("actions: read", telemetry_job)
        self.assertIn("registry-stack.release-workflow-telemetry.v1", telemetry_job)
        self.assertIn("elapsed_to_collector_seconds", telemetry_job)
        self.assertIn("completed_runner_minutes", telemetry_job)
        self.assertIn("name: Upload workflow telemetry", telemetry_job)

    def test_release_workflow_publishes_and_verifies_bounded_evidence(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        consumer_job = workflow[
            workflow.index("\n  verify-published-release:") : workflow.index("\n  release-evidence:")
        ]
        evidence_job = workflow[
            workflow.index("\n  release-evidence:") : workflow.index("\n  release-evidence-provenance:")
        ]
        final_job = workflow[
            workflow.index("\n  verify-release-evidence:") : workflow.index("\n  release-telemetry:")
        ]

        self.assertIn("- release-provenance", consumer_job)
        self.assertIn("- verify-release-provenance", consumer_job)
        self.assertIn("Assert clean verifier checkout", consumer_job)
        self.assertIn("registry-release verify-published", consumer_job)
        self.assertIn("SLSA_VERIFIER_LINUX_AMD64_SHA256", consumer_job)
        self.assertIn("registry-stack-post-publication-verification", consumer_job)

        self.assertIn("- verify-published-release", evidence_job)
        self.assertIn("registry-release collect-evidence-bundle", evidence_job)
        self.assertIn("registry-release render-release-closeout", evidence_job)
        self.assertIn("test \"$(find dist/release-assets -maxdepth 1 -type f | wc -l)\" -eq 106", evidence_job)
        self.assertIn("test \"${#assets[@]}\" -eq 6", evidence_job)
        self.assertIn("cosign sign-blob --yes", evidence_job)

        self.assertIn("test \"$(find dist/release-evidence -maxdepth 1 -type f | wc -l)\" -eq 7", final_job)
        self.assertIn("expected_finalization_assets", final_job)
        self.assertIn("diff -u \"${RUNNER_TEMP}/expected-final-assets\"", final_job)
        self.assertIn("slsa-verifier verify-artifact", final_job)
        self.assertIn("verify_provenance_subjects", final_job)
        telemetry_job = workflow[workflow.index("\n  release-telemetry:") :]
        self.assertIn("- verify-release-evidence", telemetry_job)

    def test_release_image_scans_are_policy_enforced_and_preserved(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        images_job = workflow[
            workflow.index("\n  images:") : workflow.index("\n  github-release:")
        ]

        scan_step = images_job.index("Build, push, and scan images")
        enforcement_step = images_job.index("Enforce release image scan policy")
        upload_step = images_job.index("Upload image evidence")
        self.assertLess(scan_step, enforcement_step)
        self.assertLess(enforcement_step, upload_step)
        self.assertIn(
            "grype dist/grype/registry-notary.grype.json \\\n"
            "            --subject registry-notary-image",
            images_job,
        )
        self.assertIn(
            "grype dist/grype/registry-relay.grype.json \\\n"
            "            --subject registry-relay-image",
            images_job,
        )
        self.assertIn("exit \"${status}\"", images_job)
        self.assertIn("if: ${{ always() }}", images_job[upload_step:])
        self.assertIn("dist/grype/*", images_job[upload_step:])

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
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        worker = "registry-relay-rhai-worker"

        for dockerfile in (
            "crates/registry-relay/Dockerfile",
            "crates/registry-relay/Dockerfile.demo",
            "release/docker/Dockerfile.registry-relay",
        ):
            text = (ROOT / dockerfile).read_text(encoding="utf-8")
            self.assertIn(f"/usr/local/bin/{worker}", text)

        self.assertIn(
            f'"dist/bin/{worker}-${{{{ needs.verify.outputs.tag }}}}-linux-amd64"',
            workflow,
        )
        self.assertIn(f"dist/image-bin/{worker}", workflow)
        release_dockerfile = (ROOT / "release/docker/Dockerfile.registry-relay").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            f"COPY --chmod=0755 dist/image-bin/{worker} /usr/local/bin/{worker}",
            release_dockerfile,
        )
        self.assertRegex(workflow, rf"chmod 0755[^\n]*dist/image-bin/{worker}")

    def test_notary_packaging_includes_dedicated_cel_worker(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        worker = "registry-notary-cel-worker"

        product_dockerfile = (ROOT / "products/notary/Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(worker, product_dockerfile)

        self.assertIn(
            f'"dist/bin/{worker}-${{{{ needs.verify.outputs.tag }}}}-linux-amd64"',
            workflow,
        )
        self.assertIn(f"dist/image-bin/{worker}", workflow)
        self.assertIn(
            f"--bin {worker}",
            workflow,
        )
        release_dockerfile = (ROOT / "release/docker/Dockerfile.registry-notary").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            f"COPY --chmod=0755 dist/image-bin/{worker} /usr/local/bin/{worker}",
            release_dockerfile,
        )
        self.assertRegex(workflow, rf"chmod 0755[^\n]*dist/image-bin/{worker}")

    def test_release_workflow_publishes_cross_platform_registryctl_binaries(self) -> None:
        # The hermetic linux/amd64 builder cannot produce macOS or arm64 binaries,
        # so registryctl-<tag>-macos-arm64 and -linux-arm64 are built natively on a
        # runner matrix. install.sh expects exactly these asset names.
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("macos-14", workflow)
        self.assertIn("ubuntu-24.04-arm", workflow)
        self.assertIn("aarch64-apple-darwin", workflow)
        self.assertIn("aarch64-unknown-linux-gnu", workflow)
        for asset in ("macos-arm64", "linux-arm64"):
            self.assertIn(asset, workflow)
            self.assertIn(f"registry-stack-registryctl-{asset}", workflow)

    def test_release_workflow_publishes_digest_bound_release_file_sboms(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        backfill = (ROOT / ".github/workflows/release-capsule-backfill.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("Generate release file SBOMs", workflow)
        self.assertIn("dist/binary-sbom", workflow)
        self.assertIn("Generate image binary SBOMs", workflow)
        self.assertIn("dist/image-binary-sbom", workflow)
        self.assertIn("image-input-${asset}.spdx.json", workflow)
        self.assertIn("bind-spdx-file-subject", workflow)
        self.assertIn("render-registryctl-image-lock", workflow)
        self.assertIn("verify-registryctl-image-lock-release-version", workflow)
        self.assertIn("verify-registryctl-binary-version", workflow)
        self.assertIn(
            'chmod 0755 "dist/bin/registryctl-${{ needs.verify.outputs.tag }}-linux-amd64"',
            workflow,
        )
        self.assertLess(
            workflow.index("Verify lock-bearing release version"),
            workflow.index("\n  binaries:"),
        )
        self.assertLess(
            workflow.index("Verify built registryctl binary version"),
            workflow.index("Upload binary artifacts"),
        )
        images_job = workflow[workflow.index("\n  images:") : workflow.index("\n  github-release:")]
        self.assertIn("needs:\n      - verify\n      - binaries", images_job)
        self.assertIn("Build, push, and scan images", images_job)
        self.assertIn("--require-registryctl-image-lock", workflow)
        self.assertIn("registryctl-${{ needs.verify.outputs.tag }}-image-lock.json", workflow)
        self.assertLess(
            workflow.index("Verify registryctl binary version"),
            workflow.index("Render registryctl release image lock"),
        )
        self.assertLess(
            workflow.index("Download image evidence"),
            workflow.index("Render registryctl release image lock"),
        )
        self.assertLess(
            workflow.index("Render registryctl release image lock"),
            workflow.index("Refresh release file checksums"),
        )
        self.assertLess(
            workflow.index("Refresh release file checksums"),
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

    def test_validate_beta_6_manifest(self) -> None:
        result = run_tool("validate", "release/manifests/registry-stack-beta-6.yaml")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("validated", result.stdout)

    def test_validate_docsets_matches_release_manifests(self) -> None:
        result = run_tool("validate-docsets")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("validated 8 versioned docsets", result.stdout)

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
            manifest = write_manifest(Path(tmp), source_ref="HEAD", status="release-candidate")
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
        self.assertIn("verified registryctl image lock release version 0.9.0", accepted.stdout)

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
            binary.write_text("#!/bin/sh\nprintf 'registryctl 0.8.0\\n'\n", encoding="utf-8")
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

    def test_render_registryctl_image_lock_rejects_wrong_repository_and_filename(self) -> None:
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
                f"ghcr.io/registrystack/registry-relay@{IMAGE_DIGEST}\n", encoding="utf-8"
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
        self.assertIn("repository must be ghcr.io/registrystack/registry-relay", wrong_repo.stderr)
        self.assertNotEqual(0, wrong_name.returncode)
        self.assertIn("output filename must be registryctl-v0.9.0-image-lock.json", wrong_name.stderr)

    def test_validate_source_accepts_ancestor_source_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            source_ref = commit_file(repo, "source.txt", "source\n")
            commit_file(repo, "release.txt", "release\n")
            git(repo, "tag", "v0.8.0")
            manifest = write_manifest(repo, source_ref=source_ref)

            result = run_tool("validate-source", str(manifest), "--tag", "v0.8.0", "--repo", str(repo), "--default-branch", "main")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("validated source lineage", result.stdout)

    def test_validate_source_rejects_mismatched_source_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            source_ref = commit_file(repo, "source.txt", "source\n")
            git(repo, "tag", "v0.8.0")
            manifest = write_manifest(repo, source_ref=source_ref, source_tag="v9.9.9")

            result = run_tool("validate-source", str(manifest), "--tag", "v0.8.0", "--repo", str(repo), "--default-branch", "main")

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

            result = run_tool("validate-source", str(manifest), "--tag", "v0.8.0", "--repo", str(repo), "--default-branch", "main")

        self.assertNotEqual(0, result.returncode)
        self.assertIn("is not an ancestor of release tag target", result.stderr)

    def test_validate_source_allows_draft_not_reachable_from_default_branch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            commit_file(repo, "main.txt", "main\n")
            git(repo, "checkout", "--orphan", "draft")
            commit_file(repo, "draft.txt", "draft\n")
            git(repo, "tag", "v0.8.0")
            manifest = write_manifest(repo, source_ref="HEAD", status="draft")

            result = run_tool("validate-source", str(manifest), "--tag", "v0.8.0", "--repo", str(repo), "--default-branch", "main")

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

            result = render_capsule(manifest, binary_dir, image_dir, output_json, output_md, root)

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
        self.assertIn("SBOM `registryctl-v0.8.0-linux-amd64.spdx.json`", capsule_markdown)
        self.assertNotIn("signing `", capsule_markdown)
        self.assertNotIn("attestation `", capsule_markdown)

    def test_render_capsule_classifies_required_image_lock_as_release_file(self) -> None:
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
        self.assertNotIn(release_file["name"], {item["name"] for item in evidence["binaries"]})
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
        self.assertIn("requires exactly one registryctl release image lock", result.stderr)

    def test_render_capsule_includes_cross_platform_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_multiplatform_binary_fixture(root)
            image_dir = write_image_fixture(root)
            output_json = root / "capsule.json"
            output_md = root / "capsule.md"

            result = render_capsule(manifest, binary_dir, image_dir, output_json, output_md, root)

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
            image_dir = write_image_fixture(root, grype_subject="ghcr.io/registrystack/registry-notary@sha256:" + "b" * 64)
            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

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
                json.dumps({"signing_status": "unknown", "attestation_status": "not-present"}),
                encoding="utf-8",
            )
            output_json = root / "capsule.json"
            result = render_capsule(manifest, binary_dir, image_dir, output_json, root / "capsule.md", root)
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
            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

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

            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

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

            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

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

            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

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

            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

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

            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("digest ref must match image@sha256:<64 hex>", result.stderr)

    def test_render_capsule_rejects_mismatched_source_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref, source_tag="v9.9.9")
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)

            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("does not match checked-out release tag", result.stderr)

    def test_render_capsule_prefers_digest_bound_backfill_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root, grype_subject="ghcr.io/registrystack/registry-notary:v0.8.0")
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

            result = render_capsule(manifest, binary_dir, image_dir, output_json, root / "capsule.md", root)

            evidence = json.loads(output_json.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("registry-notary.digest-bound.spdx.json", evidence["images"][0]["sbom"]["asset_name"])
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
            self.assertTrue((binary_dir / "registry-manifest-v0.8.0-linux-amd64").is_file())
            self.assertTrue((binary_dir / "registry-relay-v0.8.0-linux-amd64").is_file())
            self.assertTrue(
                (binary_dir / "registry-relay-rhai-worker-v0.8.0-linux-amd64").is_file()
            )
            self.assertTrue(
                (binary_dir / "registry-notary-cel-worker-v0.8.0-linux-amd64").is_file()
            )
            self.assertTrue((binary_dir / "registry-notary-v0.8.0-linux-amd64").is_file())
            self.assertTrue((binary_dir / "SHA256SUMS").is_file())
            self.assertTrue((image_dir / "registry-notary.digest").is_file())
            self.assertTrue((image_dir / "registry-relay.digest").is_file())
            self.assertFalse((image_dir / "registry-notary-source-adapter-sidecar.digest").exists())
            self.assertFalse((image_dir / "registry-relay.grype.json").exists())
            self.assertFalse((image_dir / "registry-stack-v0.8.0-release-evidence.json").exists())
            # Cross-platform binaries are optional and absent in this fixture.
            self.assertFalse((binary_dir / "registryctl-v0.8.0-macos-arm64").exists())
            self.assertFalse((binary_dir / "registryctl-v0.8.0-linux-arm64").exists())

    def test_stage_capsule_backfill_assets_stages_optional_cross_platform_binaries(self) -> None:
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

    def test_stage_capsule_backfill_assets_stages_optional_registryctl_image_lock(self) -> None:
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
            self.assertTrue((binary_dir / "registryctl-v0.8.0-image-lock.json").is_file())
            self.assertIn("1/1 optional release files", result.stdout)

    def test_stage_capsule_backfill_assets_requires_v010_worker_binaries(self) -> None:
        for missing_name in (
            "registry-relay-rhai-worker-v0.10.0-linux-amd64",
            "registry-notary-cel-worker-v0.10.0-linux-amd64",
        ):
            with self.subTest(missing_name=missing_name), tempfile.TemporaryDirectory() as tmp:
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

    def test_stage_capsule_backfill_assets_requires_v09_registryctl_image_lock(self) -> None:
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
        subject_packages = [package for package in data["packages"] if package["SPDXID"] in described]
        self.assertTrue(any(package["name"] == IMAGE_DIGEST_REF for package in subject_packages))
        self.assertTrue(any(IMAGE_DIGEST in json.dumps(package) for package in subject_packages))

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
    checksum = subprocess.check_output(["sha256sum", binary.name], cwd=binary_dir, text=True)
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
                subprocess.check_output(["sha256sum", path.name], cwd=binary_dir, text=True)
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
        checksums.append(subprocess.check_output(["sha256sum", name], cwd=binary_dir, text=True))
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
        checksums.append(subprocess.check_output(["sha256sum", name], cwd=asset_dir, text=True))
    (asset_dir / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
    for image in ("registry-notary", "registry-relay"):
        (asset_dir / f"{image}.digest").write_text(f"{IMAGE_DIGEST_REF}\n", encoding="utf-8")
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
