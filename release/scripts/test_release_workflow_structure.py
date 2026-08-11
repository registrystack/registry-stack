#!/usr/bin/env python3
from __future__ import annotations

import json
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
LATEST_RELEASE_HELPER = ROOT / "release/scripts/verify_latest_published_release.py"


def workflow(name: str) -> tuple[str, dict]:
    text = (WORKFLOWS / name).read_text(encoding="utf-8")
    return text, yaml.safe_load(text)


def step_run(document: dict, job: str, name: str) -> str:
    return next(
        step["run"]
        for step in document["jobs"][job]["steps"]
        if step.get("name") == name
    )


def verify_latest_release_fixture(metadata: dict, expected_tag: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary_directory:
        metadata_path = Path(temporary_directory) / "release.json"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        return subprocess.run(
            [
                "python3",
                str(LATEST_RELEASE_HELPER),
                "--metadata",
                str(metadata_path),
                "--expected-tag",
                expected_tag,
            ],
            capture_output=True,
            text=True,
            check=False,
        )


class EvidenceDevelopmentWorkflowStructureTest(unittest.TestCase):
    def test_is_manual_main_only_with_one_narrow_publication_job(self) -> None:
        text, document = workflow("evidence-dev.yml")
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("push:", trigger)
        self.assertNotIn("pull_request:", trigger)
        self.assertNotIn("schedule:", trigger)
        self.assertEqual(
            list(document["jobs"]),
            ["validate", "build", "clients", "assemble", "publish"],
        )
        self.assertEqual(
            document["jobs"]["validate"]["permissions"],
            {"actions": "read", "contents": "read"},
        )
        self.assertEqual(
            document["jobs"]["clients"]["permissions"],
            {"contents": "read"},
        )
        self.assertEqual(
            document["jobs"]["assemble"]["permissions"],
            {"actions": "read", "contents": "read"},
        )
        self.assertEqual(
            document["jobs"]["publish"]["permissions"],
            {"actions": "read", "contents": "write"},
        )
        self.assertEqual(text.count("contents: write"), 1)
        publish_uses = {
            step.get("uses", "") for step in document["jobs"]["publish"]["steps"]
        }
        self.assertFalse(
            any(action.startswith("actions/checkout@") for action in publish_uses)
        )

    def test_binds_a_unique_dev_tag_to_successful_protected_main(self) -> None:
        _, document = workflow("evidence-dev.yml")
        validation = step_run(
            document,
            "validate",
            "Validate manual source and successful CI",
        )
        self.assertIn('"${GITHUB_REF}" != refs/heads/main', validation)
        self.assertIn(
            '"$(git rev-parse refs/remotes/origin/main)" != "${GITHUB_SHA}"',
            validation,
        )
        self.assertIn("actions/workflows/ci.yml/runs?head_sha=${GITHUB_SHA}", validation)
        self.assertIn('.event == "push"', validation)
        self.assertIn(
            'tag="v${version}-dev.${GITHUB_RUN_ID}.${GITHUB_RUN_ATTEMPT}"',
            validation,
        )
        self.assertIn("Cannot prove development tag ${tag} is absent", validation)
        for job_name in ("build", "assemble"):
            checkout = next(
                step
                for step in document["jobs"][job_name]["steps"]
                if step.get("uses", "").startswith("actions/checkout@")
            )
            self.assertEqual(
                checkout["with"]["ref"],
                "${{ needs.validate.outputs.source_sha }}",
            )
            self.assertFalse(checkout["with"]["persist-credentials"])

    def test_builds_and_smokes_the_released_toolset_shape(self) -> None:
        _, document = workflow("evidence-dev.yml")
        matrix = document["jobs"]["build"]["strategy"]["matrix"]["include"]
        self.assertEqual(
            {(entry["target"], entry["asset"]) for entry in matrix},
            {
                ("x86_64-unknown-linux-gnu", "linux-amd64"),
                ("aarch64-unknown-linux-gnu", "linux-arm64"),
                ("aarch64-apple-darwin", "macos-arm64"),
            },
        )
        build = step_run(
            document,
            "build",
            "Build native Evidence development binaries",
        )
        for package in (
            "registry-evidence",
            "registry-evidencectl",
            "registry-mint",
            "registry-evidence-oid4vci",
        ):
            self.assertIn(f"-p {package}", build)
        self.assertIn("cargo build --release --locked", build)
        self.assertIn(
            "for binary in evidence evidencectl mint evidence-oid4vci", build
        )

        assemble = step_run(
            document,
            "assemble",
            "Assemble development assets and checksums",
        )
        smoke = step_run(
            document,
            "assemble",
            "Smoke the development installer before publication",
        )
        self.assertIn('$0 == "default_version=\\\"\\\""', assemble)
        self.assertIn("registry.evidence-development-build/v1", assemble)
        self.assertIn("sha256sum --", assemble)
        self.assertIn("EVIDENCECTL_ASSET_DIR", smoke)
        self.assertIn("bash development-assets/evidencectl-install.sh", smoke)

    def test_development_binaries_report_a_development_version(self) -> None:
        _, document = workflow("evidence-dev.yml")
        build = step_run(
            document,
            "build",
            "Build native Evidence development binaries",
        )
        smoke = step_run(
            document,
            "assemble",
            "Smoke the development installer before publication",
        )
        expected = (
            'test "${observed}" = '
            '"${binary} ${{ needs.validate.outputs.version }}-dev"'
        )
        self.assertIn(expected, build)
        self.assertIn(expected, smoke)
        # These assets are development builds, so the build must stay unmarked:
        # the suffix above is the proof a tester cannot mistake one for the
        # eventual release of the same version.
        self.assertNotIn("REGISTRY_RELEASE_TAG", build)

    def test_builds_and_smokes_the_relying_party_client_packages(self) -> None:
        _, document = workflow("evidence-dev.yml")
        clients = document["jobs"]["clients"]
        matrix = clients["strategy"]["matrix"]["include"]
        self.assertEqual(
            {
                (entry["asset"], entry["wheel_tag"], entry["napi_platform"])
                for entry in matrix
            },
            {
                ("linux-amd64", "cp310-abi3-linux_x86_64", "linux-x64-gnu"),
                ("linux-arm64", "cp310-abi3-linux_aarch64", "linux-arm64-gnu"),
                ("macos-arm64", "cp310-abi3-macosx_11_0_arm64", "darwin-arm64"),
            },
        )
        self.assertEqual(clients["env"]["RUSTUP_TOOLCHAIN"], "1.95.0")

        wheel = step_run(document, "clients", "Build the Python client wheel")
        # The published wheel name has to be predictable from the source, since
        # the roster below names it exactly: hence a stated Linux platform tag
        # instead of maturin's symbol-derived manylinux audit, and exactly one
        # wheel per platform rather than one per interpreter version.
        self.assertIn("--compatibility linux", wheel)
        self.assertIn("expected exactly one wheel", wheel)
        node = step_run(document, "clients", "Build the Node client package")
        self.assertIn(
            "package/evidence-client.${{ matrix.napi_platform }}.node",
            node,
        )

        # Both smokes load a prebuilt native artifact and exercise it offline.
        # Neither may carry a credential, and each addresses a reserved host
        # that cannot resolve, so a request would fail rather than leave.
        for name in ("Smoke the Python client wheel", "Smoke the Node client package"):
            smoke = step_run(document, "clients", name)
            self.assertIn("placeholder-not-a-credential", smoke)
            self.assertIn("https://evidence.invalid", smoke)
            self.assertIn("P-256", smoke)
            self.assertIn("ES256", smoke)
            self.assertNotIn("Ed25519", smoke)
            self.assertNotIn("EdDSA", smoke)

        python_smoke = step_run(document, "clients", "Smoke the Python client wheel")
        self.assertIn('JWKS, [], "placeholder-not-a-credential"', python_smoke)
        self.assertIn('"response_format": "signed-jws"', python_smoke)
        node_smoke = step_run(document, "clients", "Smoke the Node client package")
        self.assertIn("revokedKeyIds: []", node_smoke)
        self.assertIn("responseFormat: 'signed-jws'", node_smoke)

        roster = step_run(
            document,
            "publish",
            "Reverify the closed development asset roster",
        )
        self.assertIn('echo "evidence-client-node-${tag}-${platform}.tgz"', roster)
        self.assertIn(
            'echo "registry_evidence_client-${python_version}-cp310-abi3-${wheel_platform}.whl"',
            roster,
        )
        self.assertIn(
            "for wheel_platform in linux_x86_64 linux_aarch64 macosx_11_0_arm64",
            roster,
        )

    def test_publishes_one_unique_prerelease_and_prints_its_curl_command(self) -> None:
        text, document = workflow("evidence-dev.yml")
        verify = step_run(
            document,
            "publish",
            "Reverify the closed development asset roster",
        )
        publish = step_run(
            document,
            "publish",
            "Publish unique development prerelease",
        )
        self.assertIn("diff -u", verify)
        self.assertIn("sha256sum --check --strict SHA256SUMS", verify)
        self.assertIn("gh release create", publish)
        self.assertIn('--target "${source_sha}"', publish)
        self.assertIn("--prerelease", publish)
        self.assertIn("--latest=false", publish)
        self.assertIn(
            'download_url="https://github.com/${GITHUB_REPOSITORY}/releases/download/${tag}"',
            publish,
        )
        self.assertIn('install_url="${download_url}/evidencectl-install.sh"', publish)
        for forbidden in (
            "gh release upload",
            "gh release delete",
            "--clobber",
            "git push",
            "git update-ref",
        ):
            self.assertNotIn(forbidden, text)


class CandidateWorkflowStructureTest(unittest.TestCase):
    def test_current_release_pipeline_has_no_retired_notary_surface(self) -> None:
        paths = (
            WORKFLOWS / "release-candidate.yml",
            WORKFLOWS / "release.yml",
            WORKFLOWS / "release-canary.yml",
            ROOT / "release/scripts/build-release-binaries.sh",
            ROOT / "release/scripts/build-release-image.sh",
        )
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertNotIn(
                    "registry-notary",
                    path.read_text(encoding="utf-8").lower(),
                )
        self.assertFalse((ROOT / "release/docker/Dockerfile.registry-notary").exists())

        repeatability = (WORKFLOWS / "release-repeatability.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            ".images[] | [.name,.final_ref,.digest] | @tsv",
            repeatability,
        )
        self.assertIn(
            '.images | to_entries[] | select(.key | startswith("registry-"))',
            repeatability,
        )
        self.assertIn("minor == 16 && patch >= 3", repeatability)
        self.assertIn(
            'echo "${TAG} has neither ${release_manifest} nor ${image_lock}"',
            repeatability,
        )
        self.assertNotIn("for name in registry-notary registry-relay", repeatability)

        module_path = ROOT / "release/scripts/release_candidate.py"
        spec = importlib.util.spec_from_file_location("release_candidate", module_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual({"registry-relay"}, module.CURRENT_IMAGE_NAMES)
        self.assertFalse(
            any("registry-notary" in name for name in module.SECURITY_EVIDENCE_REQUIRED_FILES)
        )

    def test_keeps_one_candidate_pipeline_with_narrow_permissions(self) -> None:
        _, document = workflow("release-candidate.yml")
        self.assertEqual(
            list(document["jobs"]),
            [
                "validate",
                "build-canonical",
                "build-platforms",
                "clients",
                "assemble",
                "attest",
            ],
        )
        for job in ("build-canonical", "build-platforms", "clients"):
            permissions = document["jobs"][job]["permissions"]
            self.assertNotEqual(permissions.get("packages"), "write")
            self.assertNotEqual(permissions.get("id-token"), "write")
        self.assertEqual(
            document["jobs"]["assemble"]["permissions"]["packages"], "write"
        )
        self.assertEqual(document["jobs"]["attest"]["permissions"]["id-token"], "write")

    def test_validates_exact_main_source_ci_and_unused_destinations(self) -> None:
        text, document = workflow("release-candidate.yml")
        validation = step_run(
            document,
            "validate",
            "Validate request, source, CI, and destinations",
        )
        self.assertIn('[[ "${REQUEST_SOURCE_SHA}" != "${workflow_revision}" ]]', validation)
        self.assertIn("refs/remotes/origin/main", validation)
        self.assertIn("actions/workflows/ci.yml/runs", validation)
        self.assertIn("git ls-remote --exit-code --tags", validation)
        self.assertIn("require-image-tag-absent", validation)
        self.assertNotIn("select-canary", validation)
        self.assertNotIn("canary", validation.lower())
        self.assertIn(
            '--source-sha "${{ needs.validate.outputs.source_sha }}"',
            text,
        )

    def test_builds_once_scans_exact_images_and_attests_the_candidate(self) -> None:
        text, _ = workflow("release-candidate.yml")
        self.assertIn("Build canonical Linux payload once", text)
        self.assertIn("Build private candidate image layouts once", text)
        self.assertIn("Verify and scan exact candidate images", text)
        self.assertIn("release-candidate-manifest.json", text)
        self.assertIn("Seal compact candidate manifest and bundle", text)
        self.assertIn("Reverify all bytes before requesting OIDC", text)
        self.assertIn("Attest manifest and bundle after re-verification", text)

    def test_current_candidate_excludes_registry_docs(self) -> None:
        text, _ = workflow("release-candidate.yml")
        self.assertNotIn("registry-docs-", text)
        self.assertNotIn("kind=docs", text)
        self.assertNotIn("docs_name", text)
        self.assertNotIn("validate-docsets", text)

    def test_every_published_binary_is_built_as_a_release_build(self) -> None:
        _, document = workflow("release-candidate.yml")
        native = next(
            step
            for step in document["jobs"]["build-platforms"]["steps"]
            if step.get("name") == "Build native platform payload once"
        )
        self.assertEqual(
            native.get("env"),
            {"REGISTRY_RELEASE_TAG": "${{ needs.validate.outputs.tag }}"},
        )
        # The canonical Linux payload carries the same marker through
        # build-release-binaries.sh rather than a step-level environment.
        canonical = step_run(
            document, "build-canonical", "Build canonical Linux payload once"
        )
        self.assertIn("release/scripts/build-release-binaries.sh", canonical)

    def test_release_embeds_evidencectl_tag_and_publishes_latest_alias(self) -> None:
        _, document = workflow("release-candidate.yml")
        assemble = step_run(
            document,
            "assemble",
            "Assemble public payload and validate version-appropriate install inputs",
        )
        self.assertIn('$0 == "default_version=\\\"\\\""', assemble)
        self.assertIn('version="${{ needs.validate.outputs.tag }}"', assemble)
        self.assertIn(
            'cp "candidate/bundle-root/${evidencectl_installer}" \\\n'
            "  candidate/bundle-root/evidencectl-install.sh",
            assemble,
        )
        self.assertIn(
            "chmod 0755 candidate/bundle-root/evidencectl-install.sh",
            assemble,
        )

    def test_next_release_embeds_and_smokes_relay_installer_aliases(self) -> None:
        _, document = workflow("release-candidate.yml")
        assemble = step_run(
            document,
            "assemble",
            "Assemble public payload and validate version-appropriate install inputs",
        )
        self.assertIn(
            'relay_installer="relay-${{ needs.validate.outputs.tag }}-install.sh"',
            assemble,
        )
        self.assertIn("crates/registry-relay-v2/install.sh", assemble)
        self.assertIn(
            'cp "candidate/bundle-root/${relay_installer}" \\\n'
            "    candidate/bundle-root/relay-install.sh",
            assemble,
        )
        self.assertIn(
            'RELAY_ASSET_DIR="${GITHUB_WORKSPACE}/candidate/bundle-root"',
            assemble,
        )
        self.assertIn('RELAY_INSTALL_DIR="${relay_install_dir}"', assemble)
        self.assertIn('"${relay_install_dir}/relay" --version', assemble)
        self.assertIn("relay_patch >= 1", assemble)

    def test_builds_and_smokes_stable_evidence_client_packages(self) -> None:
        text, document = workflow("release-candidate.yml")
        clients = document["jobs"]["clients"]
        matrix = clients["strategy"]["matrix"]["include"]
        self.assertEqual(
            {
                (entry["asset"], entry["wheel_tag"], entry["napi_platform"])
                for entry in matrix
            },
            {
                (
                    "linux-amd64-glibc",
                    "cp310-abi3-linux_x86_64",
                    "linux-x64-gnu",
                ),
                (
                    "linux-arm64-glibc",
                    "cp310-abi3-linux_aarch64",
                    "linux-arm64-gnu",
                ),
                ("macos-arm64", "cp310-abi3-macosx_11_0_arm64", "darwin-arm64"),
            },
        )
        self.assertEqual(
            clients["env"]["CLIENT_VERSION"],
            "${{ needs.validate.outputs.version }}",
        )
        wheel = step_run(document, "clients", "Build the Python client wheel")
        self.assertIn("--compatibility linux", wheel)
        self.assertIn("expected exactly one wheel", wheel)
        self.assertIn("--require-hashes --only-binary=:all:", wheel)
        self.assertIn("release/requirements/maturin-1.9.6.txt", wheel)
        node = step_run(document, "clients", "Build the Node client package")
        self.assertIn(
            "package/evidence-client.${{ matrix.napi_platform }}.node",
            node,
        )
        assemble = step_run(
            document,
            "assemble",
            "Assemble public payload and validate version-appropriate install inputs",
        )
        self.assertIn("candidate-clients-${platform}", assemble)
        self.assertIn('"${client_root}"/* candidate/bundle-root/', assemble)
        self.assertIn("expected-client-assets", assemble)
        self.assertIn("actual-client-assets", assemble)
        self.assertIn("diff -u", assemble)
        self.assertIn("kind=client-package", text)
        for forbidden in ("npm publish", "maturin publish", "twine upload"):
            self.assertNotIn(forbidden, text)

    def test_reuses_cache_with_seven_day_validity_and_storage_margin(self) -> None:
        text, document = workflow("release-candidate.yml")
        cache = next(
            step
            for step in document["jobs"]["build-canonical"]["steps"]
            if step.get("name") == "Restore reusable Cargo cache"
        )
        self.assertEqual(
            cache["with"]["key"],
            "registry-stack-release-${{ runner.os }}-"
            "${{ hashFiles('rust-toolchain.toml', 'Cargo.lock', "
            "'release/scripts/build-release-binaries.sh') }}",
        )
        self.assertIn("registry-stack-release-${{ runner.os }}-", cache["with"]["restore-keys"])
        self.assertIn('created_at} + 7 days', text)
        final_upload = next(
            step
            for step in document["jobs"]["assemble"]["steps"]
            if step.get("name") == "Upload one candidate manifest and bundle"
        )
        self.assertEqual(final_upload["with"]["retention-days"], 8)
        self.assertNotIn("Rehearse forced 1.x release-lock runtime contract", text)

    def test_only_pre_oidc_reverification_accepts_the_current_run(self) -> None:
        text, document = workflow("release-candidate.yml")
        reverify = step_run(
            document,
            "attest",
            "Reverify all bytes before requesting OIDC",
        )
        self.assertEqual(text.count("--allow-current-run-in-progress"), 1)
        self.assertIn("--allow-current-run-in-progress", reverify)


class PublicationWorkflowStructureTest(unittest.TestCase):
    def test_is_a_manual_main_workflow_with_six_recoverable_jobs(self) -> None:
        text, document = workflow("release.yml")
        self.assertIn("workflow_dispatch:", text.split("permissions:", 1)[0])
        self.assertNotIn("push:", text.split("permissions:", 1)[0])
        self.assertIn("${{ inputs.tag }}", text)
        self.assertIn('"${GITHUB_REF}" != refs/heads/main', text)
        self.assertEqual(
            list(document["jobs"]),
            [
                "verify",
                "stage-draft",
                "promote-images",
                "finalize-assets",
                "publish",
                "dispatch-docs",
            ],
        )
        self.assertEqual(
            document["jobs"]["promote-images"]["permissions"],
            {"actions": "read", "contents": "write", "packages": "write"},
        )
        self.assertEqual(
            document["jobs"]["dispatch-docs"]["permissions"],
            {"actions": "write"},
        )

    def test_binds_an_annotated_tag_to_exact_candidate_and_main_revisions(self) -> None:
        text, document = workflow("release.yml")
        identity = next(
            step
            for step in document["jobs"]["verify"]["steps"]
            if step.get("name") == "Resolve exact tag identity"
        )
        self.assertEqual(identity["env"]["RELEASE_TAG"], "${{ inputs.tag }}")
        self.assertNotIn("${{ inputs.tag }}", identity["run"])
        self.assertIn('"${tag%%.*}" != v0', identity["run"])
        self.assertIn('git cat-file -t "refs/tags/${tag}"', text)
        self.assertIn("git merge-base --is-ancestor", text)
        self.assertIn("promotion_revision", text)
        self.assertIn("verify-tag-binding", text)
        self.assertIn("--trusted-run-metadata promotion/trusted-run.json", text)
        self.assertNotIn("select-canary", text)

    def test_checks_out_the_protected_workflow_before_running_repo_scripts(self) -> None:
        _, document = workflow("release.yml")
        for job_name, job in document["jobs"].items():
            script_indexes = [
                index
                for index, step in enumerate(job.get("steps", []))
                if "release/scripts/" in step.get("run", "")
            ]
            if not script_indexes:
                continue
            checkout_indexes = [
                index
                for index, step in enumerate(job["steps"])
                if step.get("uses", "").startswith("actions/checkout@")
            ]
            self.assertTrue(checkout_indexes, job_name)
            self.assertLess(min(checkout_indexes), min(script_indexes), job_name)

    def test_reconciles_only_absent_or_exact_public_image_tags(self) -> None:
        _, document = workflow("release.yml")
        promotion = step_run(
            document,
            "promote-images",
            "Reconcile exact image digests",
        )
        self.assertIn("reconcile-image-tag", promotion)
        self.assertIn('--expected-digest "${digest}"', promotion)
        self.assertIn('if [[ "${state}" == absent ]]', promotion)
        self.assertIn('crane copy "${candidate_ref}" "${final_ref}"', promotion)
        self.assertIn('test "$(crane digest "${final_ref}")" = "${digest}"', promotion)
        self.assertNotIn("require-image-tag-absent", promotion)

    def test_preserves_exact_draft_binding_without_overwriting_assets(self) -> None:
        text, document = workflow("release.yml")
        self.assertIn("Reconcile bound draft and upload exact staged inventory", text)
        self.assertIn("registry-stack-release-candidate-v2 manifest_sha256:", text)
        self.assertIn(".draft == true", text)
        self.assertIn(".prerelease == false", text)
        self.assertNotIn("--prerelease", text)
        self.assertNotIn("--clobber", text)
        tagged_checkout = next(
            step
            for step in document["jobs"]["stage-draft"]["steps"]
            if step.get("name") == "Checkout exact tagged product source"
        )
        self.assertEqual(
            tagged_checkout["with"]["ref"],
            "${{ needs.verify.outputs.source_sha }}",
        )
        stage = step_run(
            document,
            "stage-draft",
            "Reconcile bound draft and upload exact staged inventory",
        )
        self.assertIn(
            'cp "product-source/release/notes/${tag}.md"',
            stage,
        )

    def test_recovers_only_the_closed_final_asset_roster(self) -> None:
        _, document = workflow("release.yml")
        stage = step_run(
            document,
            "stage-draft",
            "Reconcile bound draft and upload exact staged inventory",
        )
        promote = step_run(
            document,
            "promote-images",
            "Reconcile exact staged draft before first public image write",
        )
        finalize = step_run(
            document,
            "finalize-assets",
            "Clean retryable final additions and reverify exact staged assets",
        )
        current_retryable_names = (
            "SHA256SUMS",
            '"registry-stack-${tag}-SHA256SUMS.sigstore.json"',
        )
        retryable_roster = stage[
            stage.index("printf '%s\\n'") : stage.index(
                "> contract/retryable-final-assets"
            )
        ]
        for name in current_retryable_names:
            self.assertIn(name, retryable_roster)
        self.assertIn("if ((major == 0 && minor < 19)); then", retryable_roster)
        self.assertIn(
            'printf \'%s\\n\' "registryctl-${tag}-image-lock.json"',
            retryable_roster,
        )
        for name in (
            *current_retryable_names,
            '"registryctl-${tag}-image-lock.json"',
        ):
            self.assertNotIn(name, finalize)
        self.assertLess(
            stage.index('"${RUNNER_TEMP}/staged-draft.json" >/dev/null'),
            stage.index("> contract/retryable-final-assets"),
        )
        self.assertIn("cat contract/expected-staged-assets", stage)
        self.assertIn("cat contract/retryable-final-assets", stage)
        self.assertIn("contract/allowed-staged-assets", stage)
        self.assertIn("[[ -s contract/unexpected-staged-assets ]]", stage)
        self.assertLess(
            promote.index("contract/draft-release.json >/dev/null"),
            promote.index("comm -23"),
        )
        self.assertIn("contract/observed-assets", promote)
        self.assertIn("contract/retryable-final-assets", promote)
        self.assertIn("diff -u contract/expected-assets contract/actual-assets", promote)
        self.assertLess(
            finalize.index("require_bound_draft\n"),
            finalize.index("cat contract/retryable-final-assets"),
        )
        self.assertLess(
            finalize.index("require_bound_draft\n"),
            finalize.index("gh api --method DELETE"),
        )

    def test_rechecks_candidate_immediately_before_public_image_access(self) -> None:
        text, document = workflow("release.yml")
        expiry = text.index(
            "Recheck candidate expiry immediately before registry login"
        )
        login = text.index("Log in for exact candidate promotion", expiry)
        copy = text.index('crane copy "${candidate_ref}" "${final_ref}"', login)
        self.assertLess(expiry, login)
        self.assertLess(login, copy)
        expiry_run = step_run(
            document,
            "promote-images",
            "Recheck candidate expiry immediately before registry login",
        )
        self.assertIn(".validity.expires_at", expiry_run)
        self.assertNotIn("verify-candidate", expiry_run)

    def test_signs_one_checksum_closure_without_beta_only_ceremony(self) -> None:
        text, _ = workflow("release.yml")
        self.assertIn("SHA256SUMS.sigstore.json", text)
        self.assertIn("cosign sign-blob --yes", text)
        self.assertIn(
            ".github/workflows/release.yml@refs/heads/main",
            text,
        )
        self.assertNotIn("release-provenance", text)
        self.assertNotIn("slsa-framework/slsa-github-generator", text)
        self.assertNotIn("Generate signed 1.x lock", text)
        self.assertNotIn("registry-release-lock.v1.json", text)

    def test_dispatches_docs_only_for_legacy_candidate_retries(self) -> None:
        text, document = workflow("release.yml")
        self.assertIn("Recheck complete signed release and exact public images", text)
        self.assertIn("Publish immutable release", text)
        self.assertIn("-F draft=false", text)
        self.assertIn("-F prerelease=false", text)
        self.assertNotIn("registry-docs-", text)
        verify = step_run(
            document,
            "verify",
            "Verify binding, candidate, and attestations",
        )
        self.assertIn(
            "if ((major == 0 && minor >= 16 && minor < 19)); then",
            verify,
        )
        self.assertIn(".docs.sha256", verify)
        self.assertIn("docs_sha256=${docs_sha256}", verify)
        dispatch = document["jobs"]["dispatch-docs"]
        self.assertEqual(
            dispatch["if"],
            "needs.verify.outputs.docs_sha256 != ''",
        )
        dispatch_run = step_run(
            document,
            "dispatch-docs",
            "Dispatch authenticated legacy docs promotion",
        )
        self.assertIn('released_tag=${{ needs.verify.outputs.tag }}', dispatch_run)
        self.assertIn(
            'docs_sha256=${{ needs.verify.outputs.docs_sha256 }}',
            dispatch_run,
        )


class SupportingWorkflowStructureTest(unittest.TestCase):
    def test_operator_docs_match_the_latest_non_prerelease_contract(self) -> None:
        operations = (ROOT / "release/OPERATIONS.md").read_text(encoding="utf-8")
        verify = (ROOT / "release/VERIFY.md").read_text(encoding="utf-8")
        self.assertIn("public, non-prerelease GitHub Release", operations)
        self.assertNotIn("marked as a prerelease", operations)
        self.assertIn(".isPrerelease == false", verify)
        self.assertNotIn(".isPrerelease == true", verify)

    def test_docs_deploy_rechecks_latest_published_release(self) -> None:
        text, document = workflow("docs-pages.yml")
        latest_endpoint = 'gh api "repos/${GITHUB_REPOSITORY}/releases/latest"'
        helper = "release/scripts/verify_latest_published_release.py"
        self.assertEqual(text.count(latest_endpoint), 2)
        self.assertEqual(text.count(f"python3 {helper}"), 2)
        self.assertIn(".prerelease==false", text)
        self.assertIn(
            ".github/workflows/release.yml@refs/heads/main",
            text,
        )
        deploy_steps = document["jobs"]["deploy"]["steps"]
        recheck = next(
            index
            for index, step in enumerate(deploy_steps)
            if step.get("name")
            == "Recheck latest published release immediately before deployment"
        )
        deployment = next(
            index
            for index, step in enumerate(deploy_steps)
            if step.get("name") == "Deploy to GitHub Pages"
        )
        self.assertEqual(recheck + 1, deployment)
        self.assertEqual(deploy_steps[deployment]["with"]["timeout"], 600_000)

    def test_latest_release_fixture_rejects_stale_or_nonpublished_dispatches(
        self,
    ) -> None:
        release = {
            "tag_name": "v1.4.0",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-07-29T10:00:00Z",
        }
        self.assertEqual(
            verify_latest_release_fixture(release, "v1.4.0").returncode,
            0,
        )
        stale = verify_latest_release_fixture(release, "v1.3.0")
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("is stale", stale.stderr)
        for field in ("draft", "prerelease"):
            with self.subTest(field=field):
                invalid = dict(release)
                invalid[field] = True
                result = verify_latest_release_fixture(invalid, "v1.4.0")
                self.assertNotEqual(result.returncode, 0)

    def test_canary_is_async_and_has_no_public_write_permission(self) -> None:
        text, document = workflow("release-canary.yml")
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("schedule:", trigger)
        self.assertIn("workflow_dispatch:", trigger)
        for job in document["jobs"].values():
            permissions = job.get("permissions", {})
            self.assertNotEqual(permissions.get("contents"), "write")
            self.assertNotEqual(permissions.get("packages"), "write")
        self.assertNotIn("registry-docs-", text)
        self.assertNotIn("docs_sha", text)
        self.assertNotIn("docs-dispatch", text)

    def test_scorecard_is_schedule_or_manual_only(self) -> None:
        text, _ = workflow("scorecard.yml")
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("schedule:", trigger)
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("push:", trigger)
        self.assertNotIn("pull_request:", trigger)


if __name__ == "__main__":
    unittest.main()
