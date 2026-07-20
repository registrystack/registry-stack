#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import subprocess
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "check-gates-inventory.py"


def extract_top_level_block(workflow: str, name: str) -> str:
    lines = workflow.splitlines()
    start = lines.index(f"{name}:")
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index] and not lines[index].startswith(" ")
        ),
        len(lines),
    )
    return "\n".join(lines[start:end]).rstrip()


def extract_classifier_arm(workflow: str, pattern: str) -> list[str]:
    lines = workflow.splitlines()
    start = lines.index(f"                {pattern})") + 1
    end = lines.index("                  ;;", start)
    return [line.strip() for line in lines[start:end]]


def extract_finalization_arm(workflow: str, classification: str) -> list[str]:
    lines = workflow.splitlines()
    start = lines.index(f"              {classification})") + 1
    end = lines.index("                ;;", start)
    return [line.strip() for line in lines[start:end]]


def load_module():
    spec = importlib.util.spec_from_file_location("check_gates_inventory", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GateInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.gitleaks_config = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
        parsed_gitleaks = tomllib.loads(self.gitleaks_config)
        self.gitleaks_paths = {
            path
            for allowlist in parsed_gitleaks["allowlists"]
            for path in allowlist.get("paths", [])
        }

    def test_real_ci_workflow_declares_inventory(self) -> None:
        self.assertEqual([], self.module.missing_gates(self.workflow))

    def test_ci_concurrency_is_pr_scoped_and_only_cancels_pull_requests(self) -> None:
        self.assertEqual(
            "\n".join(
                (
                    "concurrency:",
                    "  group: ci-${{ github.event_name == 'pull_request' && format('pr-{0}', github.event.pull_request.number) || format('run-{0}', github.run_id) }}",
                    "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
                )
            ),
            extract_top_level_block(self.workflow, "concurrency"),
        )

    def test_ci_workflow_change_marks_all_gates(self) -> None:
        self.assertEqual(
            ["mark_all"],
            extract_classifier_arm(self.workflow, ".github/workflows/ci.yml"),
        )

    def test_release_workflow_change_marks_only_release_gates(self) -> None:
        self.assertEqual(
            ["release_tool=true", "release_source_proof=true"],
            extract_classifier_arm(self.workflow, ".github/workflows/release.yml"),
        )

    def test_other_workflow_change_marks_all_gates(self) -> None:
        self.assertEqual(
            ["mark_all"],
            extract_classifier_arm(self.workflow, ".github/workflows/*"),
        )

    def test_dependabot_change_marks_only_release_tool(self) -> None:
        self.assertEqual(
            ["release_tool=true"],
            extract_classifier_arm(self.workflow, ".github/dependabot.yml"),
        )

    def test_eligible_finalization_selects_only_reduced_gates(self) -> None:
        self.assertEqual(
            ["release_tool=true", "release_source_proof=true", "docs=true"],
            extract_finalization_arm(self.workflow, "eligible"),
        )

    def test_full_ci_finalization_fails_closed(self) -> None:
        self.assertEqual(
            ["all=true"],
            extract_finalization_arm(self.workflow, "full-ci"),
        )

    def test_real_repository_has_no_tracked_nested_workflows(self) -> None:
        self.assertEqual(
            [],
            self.module.nested_workflow_paths(self.module.tracked_paths(ROOT)),
        )

    def test_root_workflows_are_allowed(self) -> None:
        self.assertEqual(
            [],
            self.module.nested_workflow_paths(
                [
                    ".github/workflows/ci.yml",
                    ".github/workflows/release.yml",
                ]
            ),
        )

    def test_nested_workflow_is_reported(self) -> None:
        self.assertEqual(
            ["products/example/.github/workflows/ci.yml"],
            self.module.nested_workflow_paths(
                [
                    ".github/workflows/ci.yml",
                    "products/example/.github/workflows/ci.yml",
                ]
            ),
        )

    def test_missing_relay_exposure_gate_is_reported(self) -> None:
        text = self.workflow.replace("name: Relay exposure check", "name: Relay exposure")
        self.assertIn("Relay exposure check", self.module.missing_gates(text))

    def test_missing_pull_request_concurrency_group_is_reported(self) -> None:
        text = self.workflow.replace(
            "format('pr-{0}', github.event.pull_request.number)",
            "format('ref-{0}', github.ref)",
        )
        self.assertIn(
            "Pull request concurrency group", self.module.missing_gates(text)
        )

    def test_missing_pull_request_only_cancellation_is_reported(self) -> None:
        text = self.workflow.replace(
            "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
            "cancel-in-progress: true",
        )
        self.assertIn(
            "Pull request concurrency cancellation", self.module.missing_gates(text)
        )

    def test_missing_release_planning_command_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 -m unittest release/scripts/test_registry_release_plans.py",
            "run: true",
        )
        self.assertIn("Release planning command tests", self.module.missing_gates(text))

    def test_missing_finalization_and_release_policy_wiring_is_reported(self) -> None:
        mutations = (
            (
                "finalization_profile: ${{ steps.filter.outputs.finalization_profile }}",
                "finalization_profile_disabled: true",
                "Finalization profile output",
            ),
            (
                "finalization_promotion_commit: ${{ steps.filter.outputs.finalization_promotion_commit }}",
                "finalization_promotion_commit_disabled: true",
                "Finalization promotion commit output",
            ),
            (
                'git show "${base}:release/scripts/check-finalization-profile.py"',
                'git show "${head}:release/scripts/check-finalization-profile.py"',
                "Trusted base finalization checker",
            ),
            (
                '--base-ref "${base}" \\\n                 --head-ref "${head}"',
                '--base-ref "${head}" \\\n                 --head-ref "${head}"',
                "Exact finalization checker refs",
            ),
            (
                "eligible)\n"
                "                release_tool=true\n"
                "                release_source_proof=true\n"
                "                docs=true\n"
                "                ;;",
                "eligible)\n"
                "                mark_all\n"
                "                ;;",
                "Eligible finalization reduced gates",
            ),
            (
                "full-ci)\n                all=true\n                ;;",
                "full-ci)\n                docs=true\n                ;;",
                "Finalization full-CI fallback",
            ),
            (
                "name: registry-stack-finalization-profile-${{ github.run_id }}",
                "name: omitted-finalization-profile",
                "Finalization profile evidence",
            ),
            (
                ".github/dependabot.yml)\n"
                "                  release_tool=true\n"
                "                  ;;",
                ".github/dependabot.yml)\n"
                "                  docs=true\n"
                "                  ;;",
                "Dependabot release-tool classification",
            ),
            (
                "run: python3 -m unittest release/scripts/test_check_finalization_profile.py",
                "run: true # finalization tests disabled",
                "Release finalization profile tests",
            ),
            (
                "run: python3 release/scripts/check-dependabot-release-window.py",
                "run: true # Dependabot check disabled",
                "Dependabot release window check",
            ),
            (
                "run: python3 -m unittest release/scripts/test_check_dependabot_release_window.py",
                "run: true # Dependabot checker tests disabled",
                "Dependabot release window checker tests",
            ),
            (
                "run: python3 release/scripts/check-release-manual.py",
                "run: true # release manual check disabled",
                "Release manual command check",
            ),
            (
                "run: python3 -m unittest release/scripts/test_check_release_manual.py",
                "run: true # release manual checker tests disabled",
                "Release manual checker tests",
            ),
            (
                "run: python3 -m unittest release/scripts/test_verify_published_release.py",
                "run: true # published release verifier tests disabled",
                "Published release verifier tests",
            ),
            (
                "run: python3 -m unittest release/scripts/test_registry_release_evidence.py",
                "run: true # release evidence bundle tests disabled",
                "Release evidence bundle tests",
            ),
        )
        for old, new, expected in mutations:
            with self.subTest(gate=expected):
                self.assertIn(old, self.workflow)
                text = self.workflow.replace(old, new, 1)
                self.assertIn(expected, self.module.missing_gates(text))

    def test_missing_release_image_oci_checker_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 -m unittest release/scripts/test_check_release_image_oci_labels.py",
            "run: true",
        )
        self.assertIn(
            "Release image OCI label checker tests", self.module.missing_gates(text)
        )

    def test_missing_executable_release_image_oci_smoke_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: release/scripts/smoke-release-image-oci-labels.sh",
            "run: true",
        )
        self.assertIn(
            "Executable release image OCI label smoke", self.module.missing_gates(text)
        )

    def test_missing_release_workflow_classification_is_reported(self) -> None:
        text = self.workflow.replace(
            "                .github/workflows/release.yml)\n"
            "                  release_tool=true\n"
            "                  release_source_proof=true\n"
            "                  ;;",
            "                .github/workflows/release.yml)\n"
            "                  mark_all\n"
            "                  ;;",
        )
        self.assertIn(
            "Release workflow path classification", self.module.missing_gates(text)
        )

    def test_missing_platform_all_features_gate_is_reported(self) -> None:
        text = self.workflow.replace(
            "cargo test --locked -p registry-config-report -p 'registry-platform-*' --all-targets --all-features",
            "cargo test --locked -p registry-config-report -p 'registry-platform-*' --all-targets",
        )
        self.assertIn(
            "Platform all-features tests", self.module.missing_gates(text)
        )

    def test_missing_config_report_platform_path_is_reported(self) -> None:
        text = self.workflow.replace(
            "crates/registry-config-report/*|crates/registry-platform-*",
            "crates/registry-platform-*",
        )
        self.assertIn("Config report platform path", self.module.missing_gates(text))

    def test_missing_config_report_platform_test_is_reported(self) -> None:
        text = self.workflow.replace(
            "cargo test --locked -p registry-config-report -p 'registry-platform-*' --all-targets --all-features",
            "cargo test --locked -p 'registry-platform-*' --all-targets --all-features",
        )
        self.assertIn(
            "Platform all-features tests", self.module.missing_gates(text)
        )

    def test_missing_config_report_platform_build_is_reported(self) -> None:
        text = self.workflow.replace(
            "cargo build --locked -p registry-config-report -p 'registry-platform-*' --all-targets --all-features",
            "cargo build --locked -p 'registry-platform-*' --all-targets --all-features",
        )
        self.assertIn(
            "Platform all-features build", self.module.missing_gates(text)
        )

    def test_missing_config_report_platform_clippy_is_reported(self) -> None:
        text = self.workflow.replace(
            "cargo clippy --locked -p registry-config-report -p 'registry-platform-*' --all-targets --all-features -- -D warnings",
            "cargo clippy --locked -p 'registry-platform-*' --all-targets --all-features -- -D warnings",
        )
        self.assertIn(
            "Platform all-features clippy", self.module.missing_gates(text)
        )

    def test_missing_platform_coverage_threshold_is_reported(self) -> None:
        text = self.workflow.replace("--fail-under-lines 80", "--summary-only")
        self.assertIn("Platform coverage threshold", self.module.missing_gates(text))

    def test_missing_config_report_platform_coverage_is_reported(self) -> None:
        text = self.workflow.replace(
            "cargo llvm-cov --locked\n          -p registry-config-report\n          -p 'registry-platform-*'",
            "cargo llvm-cov --locked\n          -p 'registry-platform-*'",
        )
        self.assertIn(
            "Config report platform coverage", self.module.missing_gates(text)
        )

    def test_missing_secret_scan_redaction_is_reported(self) -> None:
        text = self.workflow.replace("--redact", "--verbose")
        self.assertIn("Gitleaks redaction", self.module.missing_gates(text))

    def test_root_secret_scan_names_all_synthetic_platform_jwt_fixtures(self) -> None:
        for fixture_path in (
            r"^products/platform/fuzz/corpus/oid4vci_request_and_proof/credential_request\.json$",
            r"^products/platform/fuzz/corpus/oid4vci_request_and_proof/valid-proof-jwt$",
            r"^products/platform/fuzz/corpus/sdjwt_holder_proof/holder_proof\.jwt$",
            r"^products/platform/fuzz/corpus/sdjwt_holder_proof/valid-holder-proof-jwt$",
        ):
            with self.subTest(fixture_path=fixture_path):
                self.assertIn(fixture_path, self.gitleaks_paths)

    def test_root_secret_scan_does_not_keep_pre_monorepo_fuzz_paths(self) -> None:
        self.assertFalse(any(path.startswith("^fuzz/") for path in self.gitleaks_paths))

    def test_root_secret_scan_excludes_only_named_generated_ignored_trees(self) -> None:
        generated_trees = (
            (
                r"^docs/site/\.repo-docs-cache/",
                "docs/site/.repo-docs-cache/generated.txt",
            ),
            (
                r"^editors/vscode/\.vscode-test/",
                "editors/vscode/.vscode-test/generated.txt",
            ),
        )
        for allowlist_path, generated_probe in generated_trees:
            with self.subTest(generated_probe=generated_probe):
                self.assertIn(allowlist_path, self.gitleaks_paths)
                ignored = subprocess.run(
                    ["git", "check-ignore", "--quiet", generated_probe],
                    cwd=ROOT,
                    check=False,
                )
                self.assertEqual(0, ignored.returncode)

    def test_missing_platform_fuzz_bound_is_reported(self) -> None:
        text = self.workflow.replace("-max_total_time=60", "-runs=0")
        self.assertIn(
            "Platform fuzz bounded runtime", self.module.missing_gates(text)
        )

    def test_missing_registryctl_tutorial_execution_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: npm run check:tutorial:registryctl",
            "run: npm run execute-registryctl-tutorial",
        )
        self.assertIn(
            "Registryctl tutorial source execution", self.module.missing_gates(text)
        )

    def test_missing_manifest_profile_validation_is_reported(self) -> None:
        text = self.workflow.replace(
            "cargo run --locked -p registry-manifest-cli -- validate-profiles profiles",
            "cargo run --locked -p registry-manifest-cli -- skip-profile-validation",
        )
        self.assertIn("Manifest profile validation", self.module.missing_gates(text))

    def test_missing_release_docset_validation_is_reported(self) -> None:
        text = self.workflow.replace(
            "release/scripts/registry-release validate-docsets",
            "release/scripts/registry-release skip-docsets",
        )
        self.assertIn("Release docset validation", self.module.missing_gates(text))

    def test_missing_openid_conformance_runner_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "python3 -m unittest release/scripts/test_openid_conformance_runner.py",
            "python3 release/scripts/openid-conformance-runner.py list",
        )
        self.assertIn(
            "OpenID conformance runner tests", self.module.missing_gates(text)
        )

    def test_missing_external_integration_runner_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "python3 -m unittest release/scripts/test_integration_e2_runner.py",
            "python3 release/scripts/integration-e2-runner.py dry-run",
        )
        self.assertIn(
            "External integration evidence runner tests",
            self.module.missing_gates(text),
        )

    def test_missing_external_integration_packet_validation_is_reported(self) -> None:
        text = self.workflow.replace(
            "python3 release/scripts/integration-e2-runner.py validate",
            "python3 release/scripts/integration-e2-runner.py plan",
        )
        self.assertIn(
            "External integration evidence packet",
            self.module.missing_gates(text),
        )

    def test_missing_relay_oidc_smoke_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "python3 -m unittest release/scripts/test_relay_oidc_smoke.py",
            "python3 release/scripts/relay-oidc-smoke.py plan",
        )
        self.assertIn("Relay OIDC smoke tests", self.module.missing_gates(text))

    def test_missing_relay_oidc_offline_validation_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 release/scripts/relay-oidc-smoke.py validate",
            "run: python3 release/scripts/relay-oidc-smoke.py skip-validation",
        )
        self.assertIn(
            "Relay OIDC smoke offline validation", self.module.missing_gates(text)
        )

    def test_missing_stable_surface_gate_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 release/scripts/check-stable-surface-compatibility.py",
            "run: python3 release/scripts/skip-stable-surface-compatibility.py",
        )
        self.assertIn("Stable surface compatibility", self.module.missing_gates(text))

    def test_missing_relay_openapi_stability_filter_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 -m unittest release/scripts/test_filter_relay_openapi_stability.py",
            "run: python3 -m unittest release/scripts/skip_filter_relay_openapi_stability.py",
        )
        self.assertIn("Relay OpenAPI stability filter tests", self.module.missing_gates(text))

    def test_missing_openapi_base_reference_is_reported(self) -> None:
        text = self.workflow.replace(
            "OPENAPI_CONTRACT_BASE_REF: ${{ github.event.pull_request.base.sha || github.event.before }}",
            "OPENAPI_CONTRACT_BASE_REF: disabled",
        )
        self.assertIn("OpenAPI base-reference input", self.module.missing_gates(text))

    def test_missing_upgrade_exercise_template_validation_is_reported(self) -> None:
        text = self.workflow.replace(
            "python3 release/scripts/validate-upgrade-exercise.py --template",
            "python3 release/scripts/validate-upgrade-exercise.py --skip-template",
        )
        self.assertIn(
            "Upgrade exercise template validation", self.module.missing_gates(text)
        )

    def test_missing_stable_error_registry_path_filter_is_reported(self) -> None:
        text = self.workflow.replace(
            "docs/site/src/content/docs/reference/errors.mdx)",
            "docs/site/src/content/docs/reference/removed-errors.mdx)",
        )
        self.assertIn("Stable error registry path filter", self.module.missing_gates(text))

    def test_missing_relay_support_roster_path_filter_is_reported(self) -> None:
        text = self.workflow.replace(
            "docs/site/src/data/relay-support.yaml|docs/site/src/data/generated/relay-support.json)",
            "docs/site/src/data/removed-relay-support.yaml)",
        )
        self.assertIn("Relay support roster path filter", self.module.missing_gates(text))

    def test_missing_docs_archive_cache_wiring_is_reported(self) -> None:
        mutations = (
            (
                'pull_request)\n              mode="incremental"\n              ;;',
                'pull_request)\n              mode="full"\n              ;;',
                "Docs pull request incremental archive mode",
            ),
            (
                'push)\n              mode="full"\n              ;;',
                'push)\n              mode="incremental"\n              ;;',
                "Docs main push full archive mode",
            ),
            (
                "name: Compute docs archive cache key\n"
                "        if: github.event_name == 'pull_request' && "
                "steps.docs-archives.outputs.mode == 'incremental'",
                "name: Compute docs archive cache key\n"
                "        if: steps.docs-archives.outputs.mode == 'incremental'",
                "Docs incremental archive cache key condition",
            ),
            (
                "name: Restore docs archive cache\n"
                "        if: github.event_name == 'pull_request' && "
                "steps.docs-archives.outputs.mode == 'incremental'\n"
                "        uses: actions/cache@2c8a9bd7457de244a408f35966fab2fb45fda9c8",
                "name: Restore docs archive cache\n"
                "        if: steps.docs-archives.outputs.mode == 'incremental'\n"
                "        uses: actions/cache@disabled",
                "Docs incremental archive cache restore",
            ),
            (
                'run: node scripts/archive-cache.mjs collection-key >> "${GITHUB_OUTPUT}"',
                "run: echo key=stale >> \"${GITHUB_OUTPUT}\"",
                "Docs archive cache key computation",
            ),
            (
                "path: docs/site/.archive-build-cache",
                "path: docs/site/dist",
                "Docs archive cache path",
            ),
            (
                "key: registry-docs-archives-v1-${{ runner.os }}-node-22.12.0-${{ steps.docs-archive-cache-key.outputs.key }}",
                "key: registry-docs-archives-v1-static",
                "Docs archive cache key",
            ),
            (
                "ARCHIVE_MODE: ${{ steps.docs-archives.outputs.mode }}",
                "ARCHIVE_MODE: full",
                "Docs archive mode input",
            ),
            (
                "name: Check docs build\n"
                "        working-directory: docs/site\n"
                "        env:\n"
                "          ARCHIVE_MODE: ${{ steps.docs-archives.outputs.mode }}\n"
                "        run: npm run check",
                "name: Check docs build\n"
                "        working-directory: docs/site\n"
                "        env:\n"
                "          ARCHIVE_MODE: ${{ steps.docs-archives.outputs.mode }}\n"
                "        run: npm run build",
                "Docs build check",
            ),
        )
        for old, new, expected in mutations:
            with self.subTest(gate=expected):
                self.assertIn(old, self.workflow)
                text = self.workflow.replace(old, new, 1)
                self.assertIn(expected, self.module.missing_gates(text))

    def test_missing_registryctl_tutorial_path_filter_is_reported(self) -> None:
        text = self.workflow.replace(
            "registryctl_tutorial: ${{ steps.filter.outputs.registryctl_tutorial }}",
            "registryctl_tutorial_disabled: ${{ steps.filter.outputs.registryctl_tutorial }}",
        )
        self.assertIn("Registryctl tutorial path filter", self.module.missing_gates(text))


if __name__ == "__main__":
    unittest.main()
