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
        self.assertEqual({"contents": "read"}, document["permissions"])
        self.assertEqual(
            ["validate", "rehearse", "canonical-linux", "node-clients"],
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
        self.assertEqual("${{ inputs.version }}", onboarding["env"]["REHEARSAL_VERSION"])
        self.assertIn("check-image-onboarding", onboarding["run"])
        self.assertIn('--version "${REHEARSAL_VERSION}"', onboarding["run"])
        self.assertNotIn("--allow-missing-baseline", onboarding["run"])
        self.assertNotIn("${{ inputs.", onboarding["run"])
        self.assertEqual(text.count("Require a branch rehearsal"), 1)
        for job_name in ("rehearse", "canonical-linux", "node-clients"):
            self.assertEqual("validate", document["jobs"][job_name]["needs"])
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
        self.assertEqual({"contents": "read"}, canonical["permissions"])
        self.assertFalse(
            any("upload-artifact@" in str(step) for step in canonical["steps"])
        )
        canonical_cache = next(
            step
            for step in canonical["steps"]
            if step.get("name") == "Restore reusable Cargo cache"
        )
        self.assertNotIn("restore-keys", canonical_cache["with"])
        self.assertIn(
            "'release/docker/Dockerfile.builder'",
            canonical_cache["with"]["key"],
        )
        canonical_build = next(
            step["run"]
            for step in canonical["steps"]
            if step.get("name") == "Build and smoke the canonical Linux payload"
        )
        self.assertIn(
            'release/scripts/build-release-binaries.sh "${REHEARSAL_VERSION}"',
            canonical_build,
        )
        self.assertIn("breg-v${REHEARSAL_VERSION}-linux-amd64", canonical_build)
        self.assertIn("bregctl-v${REHEARSAL_VERSION}-linux-amd64", canonical_build)
        self.assertNotIn("${{ inputs.", canonical_build)
        for forbidden in (
            "upload-artifact@",
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
        self.assertIn("-m ziglang version)\" = 0.12.1", install)

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

    def test_script_exercises_future_tag_source_archive_and_dev_base_in_order(self) -> None:
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
