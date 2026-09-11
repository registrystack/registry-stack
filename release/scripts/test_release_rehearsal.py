#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release-rehearsal.yml"
SCRIPT = ROOT / "release/scripts/rehearse-release"


class ReleaseRehearsalTest(unittest.TestCase):
    def test_workflow_is_manual_read_only_and_ubuntu_bounded(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        document = yaml.safe_load(text)
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("push:", trigger)
        self.assertNotIn("pull_request:", trigger)
        self.assertNotIn("schedule:", trigger)
        self.assertIn("${{ inputs.request_id }}", document["run-name"])
        self.assertIn("request_id:", trigger)
        self.assertIn("required: true", trigger)
        triggers = document.get("on", document.get(True))
        advisory_input = triggers["workflow_dispatch"]["inputs"]["advisory_evidence"]
        self.assertEqual(
            {
                "description": "Collect review-only image advisory evidence",
                "required": False,
                "default": False,
                "type": "boolean",
            },
            advisory_input,
        )
        self.assertEqual({"contents": "read"}, document["permissions"])
        self.assertEqual(
            [
                "validate",
                "rehearse",
                "canonical-linux-binaries",
                "canonical-linux",
                "node-clients",
            ],
            list(document["jobs"]),
        )
        validate = document["jobs"]["validate"]
        self.assertEqual("ubuntu-24.04", validate["runs-on"])
        self.assertLessEqual(validate["timeout-minutes"], 5)
        self.assertEqual({"contents": "read"}, validate["permissions"])
        self.assertEqual("Require a branch rehearsal", validate["steps"][0]["name"])
        onboarding = next(
            step
            for step in validate["steps"]
            if step.get("name") == "Check complete release image onboarding"
        )
        self.assertEqual(
            "${{ inputs.version }}", onboarding["env"]["REHEARSAL_VERSION"]
        )
        self.assertEqual(
            "${{ inputs.advisory_evidence }}",
            onboarding["env"]["REHEARSAL_ADVISORY_EVIDENCE"],
        )
        self.assertIn("check-image-onboarding", onboarding["run"])
        self.assertIn('--version "${REHEARSAL_VERSION}"', onboarding["run"])
        self.assertIn(
            'case "${REHEARSAL_ADVISORY_EVIDENCE}" in', onboarding["run"]
        )
        self.assertEqual(1, onboarding["run"].count("--allow-missing-baseline"))
        self.assertIn("true) onboarding+=(--allow-missing-baseline)", onboarding["run"])
        self.assertIn("false) ;;", onboarding["run"])
        self.assertIn("advisory_evidence must be a typed boolean", onboarding["run"])
        self.assertNotIn("${{ inputs.", onboarding["run"])
        self.assertEqual(text.count("Require a branch rehearsal"), 1)
        for job_name in ("rehearse", "canonical-linux-binaries", "node-clients"):
            self.assertEqual("validate", document["jobs"][job_name]["needs"])
        self.assertEqual(
            ["validate", "canonical-linux-binaries"],
            document["jobs"]["canonical-linux"]["needs"],
        )
        job = document["jobs"]["rehearse"]
        self.assertEqual("ubuntu-24.04", job["runs-on"])
        self.assertLessEqual(job["timeout-minutes"], 15)
        self.assertFalse(any("upload-artifact@" in str(step) for step in job["steps"]))
        rehearsal = job["steps"][-1]
        self.assertEqual("${{ inputs.version }}", rehearsal["env"]["REHEARSAL_VERSION"])
        self.assertEqual(
            "${{ inputs.release_id }}",
            rehearsal["env"]["REHEARSAL_RELEASE_ID"],
        )
        self.assertNotIn("${{ inputs.", rehearsal["run"])

        canonical = document["jobs"]["canonical-linux"]
        self.assertEqual("ubuntu-24.04", canonical["runs-on"])
        self.assertLessEqual(canonical["timeout-minutes"], 90)
        self.assertEqual(
            {"actions": "read", "contents": "read"}, canonical["permissions"]
        )
        advisory_steps = [
            step
            for step in canonical["steps"]
            if "advisory" in step.get("name", "").lower()
        ]
        self.assertEqual(4, len(advisory_steps))
        self.assertTrue(
            all(
                step.get("if") == "${{ inputs.advisory_evidence }}"
                for step in advisory_steps
            )
        )
        candidate = yaml.safe_load(
            (ROOT / ".github/workflows/release-candidate.yml").read_text(
                encoding="utf-8"
            )
        )
        for pin in (
            "RELEASE_BUILDX_VERSION",
            "RELEASE_BUILDKIT_IMAGE",
            "SYFT_VERSION",
            "SYFT_LINUX_AMD64_SHA256",
            "GRYPE_VERSION",
            "GRYPE_LINUX_AMD64_SHA256",
            "CRANE_VERSION",
            "CRANE_LINUX_AMD64_SHA256",
            "ORAS_VERSION",
            "ORAS_LINUX_AMD64_SHA256",
        ):
            self.assertEqual(candidate["env"][pin], canonical["env"][pin])
        self.assertRegex(
            canonical["env"]["REHEARSAL_REGISTRY_IMAGE"],
            r"^registry:3\.1\.1@sha256:[0-9a-f]{64}$",
        )
        collection = next(
            step
            for step in canonical["steps"]
            if step.get("name") == "Collect exact advisory review evidence"
        )
        self.assertIn("collect-rehearsal-advisory-evidence.py", collection["run"])
        self.assertIn("${{ github.sha }}", collection["env"]["REHEARSAL_REVISION"])
        self.assertNotIn("github.token", str(canonical))
        self.assertNotIn("ghcr.io", str(canonical))
        binary_job = document["jobs"]["canonical-linux-binaries"]
        self.assertFalse(binary_job["strategy"]["fail-fast"])
        self.assertEqual(
            ["core", "breg", "casework"], binary_job["strategy"]["matrix"]["group"]
        )
        self.assertEqual(
            "${{ github.sha }}", binary_job["steps"][0]["with"]["ref"]
        )
        canonical_cache = next(
            step
            for step in binary_job["steps"]
            if step.get("name") == "Restore reusable Cargo cache"
        )
        prefix = canonical_cache["with"]["restore-keys"].strip()
        self.assertEqual(
            canonical_cache["with"]["key"], prefix + "${{ hashFiles('Cargo.lock') }}"
        )
        self.assertNotIn("Cargo.lock", prefix)
        self.assertIn("${{ matrix.group }}", prefix)
        for recipe_input in (
            "'release/docker/Dockerfile.builder'",
            "'release/requirements/ziglang-0.12.1.txt'",
            "'release/glibc-floor.env'",
            "'release/scripts/zig-glibc-compiler'",
        ):
            self.assertIn(recipe_input, prefix)
        canonical_build = next(
            step["run"]
            for step in binary_job["steps"]
            if step.get("name") == "Build canonical Linux binary shard"
        )
        self.assertIn("release/scripts/build-release-binaries.sh", canonical_build)
        self.assertIn('--group "${{ matrix.group }}"', canonical_build)
        merge = next(
            step["run"]
            for step in canonical["steps"]
            if step.get("name") == "Merge and smoke the canonical Linux payload"
        )
        self.assertIn('--source-sha "${{ github.sha }}"', merge)
        self.assertIn("--core binary-shards/core", merge)
        self.assertIn("--breg binary-shards/breg", merge)
        self.assertIn("breg-v${REHEARSAL_VERSION}-linux-amd64", merge)
        self.assertIn("bregctl-v${REHEARSAL_VERSION}-linux-amd64", merge)
        self.assertNotIn("${{ inputs.", merge)
        for forbidden in (
            "npm publish",
            "gh release",
            "git tag",
            "git push",
        ):
            self.assertNotIn(forbidden, str(canonical))

        clients = document["jobs"]["node-clients"]
        self.assertLessEqual(clients["timeout-minutes"], 40)
        self.assertEqual(
            [
                {
                    "runner": "ubuntu-24.04",
                    "asset": "linux-amd64-glibc",
                    "target": "x86_64-unknown-linux-gnu",
                    "napi_platform": "linux-x64-gnu",
                },
                {
                    "runner": "ubuntu-24.04-arm",
                    "asset": "linux-arm64-glibc",
                    "target": "aarch64-unknown-linux-gnu",
                    "napi_platform": "linux-arm64-gnu",
                },
            ],
            clients["strategy"]["matrix"]["include"],
        )
        self.assertEqual("Checkout prepared branch", clients["steps"][0]["name"])
        self.assertFalse(
            any("upload-artifact@" in str(step) for step in clients["steps"])
        )
        install = next(
            step["run"]
            for step in clients["steps"]
            if step.get("name") == "Install exact Zig toolchain"
        )
        self.assertIn("--require-hashes --only-binary=:all:", install)
        self.assertIn("release/requirements/maturin-1.9.6.txt", install)
        self.assertIn('-m ziglang version)" = 0.12.1', install)

        build = next(
            step["run"]
            for step in clients["steps"]
            if step.get("name") == "Build, package, and smoke Linux Node clients"
        )
        self.assertIn("for client in discovery evidence relay", build)
        helper_call = "release/scripts/build-linux-node-client"
        self.assertIn(helper_call, build)
        for argument in (
            '--client "${client}"',
            '--target "${{ matrix.target }}"',
            '--napi-platform "${{ matrix.napi_platform }}"',
            '--zig-python "${RUNNER_TEMP}/maturin/bin/python"',
        ):
            self.assertIn(argument, build)
        self.assertLess(
            build.index('(cd "${client_dir}" && npm ci)'),
            build.index(helper_call),
        )
        self.assertIn("node-root-${client}", build)
        self.assertIn(
            "LICENSE README.md client.js client.d.ts index.js index.d.ts package.json",
            build,
        )
        self.assertIn("-maxdepth 1 -name '*.node'", build)
        self.assertIn(
            "node_modules/@registrystack/${client}-client-${{ matrix.napi_platform }}/${client}-client.${{ matrix.napi_platform }}.node",
            build,
        )
        host_smoke = 'node "smoke-${client}-client-package.js"'
        docker_smoke = "docker run --rm --network none"
        self.assertLess(build.index(host_smoke), build.index(docker_smoke))
        self.assertIn("node smoke-registry-client-package.js", build)
        self.assertIn("node smoke-registry-client-package.mjs", build)
        self.assertIn('"${NODE_GLIBC_BASELINE_IMAGE}"', build)
        self.assertRegex(
            clients["env"]["NODE_GLIBC_BASELINE_IMAGE"],
            r"^node:22\.12\.0-bullseye-slim@sha256:[0-9a-f]{64}$",
        )
        for forbidden in (
            "--use-napi-cross",
            "upload-artifact@",
            "npm publish",
            "gh release",
            "git tag",
            "git push",
        ):
            self.assertNotIn(forbidden, str(clients))

    def test_script_exercises_future_tag_source_archive_and_dev_base_in_order(
        self,
    ) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        ordered = (
            "git ls-remote --exit-code --tags origin",
            "registry-release prepare",
            "registry-release validate-current",
            "registry-release validate-docsets",
            "check-release-source-model.sh",
            "npm run check:archive-lock",
            "npm run build:archive",
            "npm run archive:snapshot",
            "npm run build:dev",
            "npm run check:production:built",
            "npm run check:archives",
            'final_status="$(git status --short)"',
        )
        positions = [text.index(marker) for marker in ordered]
        self.assertEqual(sorted(positions), positions)
        for forbidden in (
            "git tag -a",
            "git push",
            "gh release",
            "release.yml",
            "crane copy",
        ):
            self.assertNotIn(forbidden, text)

    def test_advisory_artifact_docs_bind_one_image_before_strict_check(self) -> None:
        operations = (ROOT / "release/OPERATIONS.md").read_text(encoding="utf-8")
        preparation = next(
            block
            for block in operations.split("```")
            if 'gh run download "${rehearsal_run}"' in block
        )
        checker = next(
            block
            for block in operations.split("```")
            if 'grype "${artifact_dir}/grype/${name}.grype.json"' in block
        )
        self.assertIn('collection="${artifact_dir}/collection.json"', preparation)
        self.assertIn(".revision", preparation)
        self.assertIn("[.images[] | select(.name == $name)] as $matches", preparation)
        self.assertIn("image must appear exactly once", preparation)
        self.assertIn(".version == $version", preparation)
        self.assertIn('.purpose == "review_only"', preparation)
        self.assertIn('--file="${artifact_dir}/rootfs/${name}.tar"', preparation)
        self.assertIn('--directory="${review_dir}/rootfs"', preparation)
        for schema_binding in (
            '.reference_provenance == "local_reproduction"',
            ".reference_image_digest == $digest",
            ".reference_source_revision == $revision",
        ):
            self.assertIn(schema_binding, checker)
        for argument in (
            '--baseline "${baseline}"',
            '--syft-report "${artifact_dir}/syft/${name}.syft.json"',
            '--rootfs "${review_dir}/rootfs"',
            '--candidate-image-digest "${digest}"',
            '--source-revision "${source_revision}"',
            '--oci-config "${artifact_dir}/oci-config/${name}.json"',
            '--subject "${name}-image"',
        ):
            self.assertIn(argument, checker)
        self.assertNotIn("--reference-provenance", checker)

    def test_docs_ci_replaces_root_build_with_dev_base_build(self) -> None:
        package = json.loads(
            (ROOT / "docs/site/package.json").read_text(encoding="utf-8")
        )
        scripts = package["scripts"]
        self.assertIn("DOCS_BASE=/dev/", scripts["build:dev"])
        self.assertIn("--outDir dist/dev", scripts["build:dev"])
        self.assertIn("DOCS_PUBLIC_BASE=/dev/", scripts["check:production:built"])
        self.assertIn("check:links:current", scripts["check:production:built"])
        self.assertEqual(
            "npm run check:source && npm run build:dev && npm run check:production:built",
            scripts["check:production"],
        )
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        docs_job = ci.split("\n  docs:\n", 1)[1].split("\n  docs-required:\n", 1)[0]
        self.assertIn("run: npm run check:production", docs_job)
        self.assertNotIn("run: npm run check\n", docs_job)


if __name__ == "__main__":
    unittest.main()
