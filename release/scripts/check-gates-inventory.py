#!/usr/bin/env python3
"""Assert that declared RegistryStack gates are wired into root CI."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CI_CLASSIFIER = ROOT / ".github" / "scripts" / "ci_changes.py"

REQUIRED_GATES: tuple[tuple[str, str], ...] = (
    (
        "Pull request concurrency group",
        "group: ci-${{ github.event_name == 'pull_request' && format('pr-{0}', github.event.pull_request.number) || format('run-{0}', github.run_id) }}",
    ),
    (
        "Pull request concurrency cancellation",
        "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
    ),
    ("Merge queue trigger", "merge_group:"),
    (
        "CI classifier invocation",
        "python3 .github/scripts/ci_changes.py",
    ),
    (
        "CI classifier tests",
        "run: python3 .github/scripts/test_ci_changes.py",
    ),
    (
        "CI workflow change classification",
        '".github/workflows/ci.yml",',
    ),
    (
        "Release workflow change classification",
        '".github/workflows/release.yml",',
    ),
    (
        "Release candidate workflow change classification",
        '".github/workflows/release-candidate.yml",',
    ),
    (
        "Release repeatability workflow change classification",
        '".github/workflows/release-repeatability.yml",',
    ),
    (
        "Release candidate cleanup workflow change classification",
        '".github/workflows/release-candidate-cleanup.yml",',
    ),
    ("actionlint version pin", 'ACTIONLINT_VERSION: "1.7.7"'),
    (
        "actionlint archive checksum",
        'ACTIONLINT_LINUX_X64_SHA256: "023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757"',
    ),
    (
        "actionlint workflow lint",
        '"${RUNNER_TEMP}/bin/actionlint"',
    ),
    (
        "Advisory checker byte identity",
        "run: python3 release/scripts/check_advisory_checker_copies.py",
    ),
    (
        "Notary advisory checker tests",
        "python3 -m unittest products/notary/tests/advisory_baseline_check_test.py",
    ),
    (
        "Relay advisory checker tests",
        "python3 -m unittest crates/registry-relay/tests/advisory_baseline_check_test.py",
    ),
    (
        "Advisory checker identity guard tests",
        "run: python3 -m unittest release/scripts/test_check_advisory_checker_copies.py",
    ),
    (
        "Debian 13 image contract",
        "run: python3 release/scripts/check-debian13-images.py",
    ),
    ("Cargo metadata", "cargo metadata --locked --format-version 1"),
    (
        "Manifest profile validation",
        "run: cargo run --locked --profile ci -p registry-manifest-cli -- validate-profiles profiles",
    ),
    ("Format", "run: cargo fmt --check"),
    (
        "Affected package clippy",
        "run: python3 .github/scripts/run_cargo_packages.py clippy",
    ),
    (
        "Affected package tests",
        "run: python3 .github/scripts/run_cargo_packages.py test",
    ),
    (
        "Rust shard matrix",
        "matrix: ${{ fromJSON(needs.changes.outputs.rust_matrix) }}",
    ),
    (
        "Relay all-features shard",
        '"all_features": shard_name == "relay"',
    ),
    ("Disk-bounded Rust cache", "cache-targets: false"),
    ("Rust disk telemetry", "du -sh target 2>/dev/null || true"),
    (
        "Required Rust aggregate",
        "rust-result:\n    name: Rust workspace",
    ),
    (
        "Stable CI aggregate",
        "ci-result:\n    name: CI result",
    ),
    ("Cargo deny", "run: cargo deny check"),
    (
        "Platform path filter",
        "platform: ${{ steps.filter.outputs.platform }}",
    ),
    (
        "Config report platform path",
        '"crates/registry-config-report/*",',
    ),
    (
        "Platform hygiene path filter",
        "platform_hygiene: ${{ steps.filter.outputs.platform_hygiene }}",
    ),
    (
        "Platform all-features clippy",
        "run: cargo clippy --locked -p registry-config-report -p 'registry-platform-*' --all-targets --all-features -- -D warnings",
    ),
    ("Platform coverage job", "platform-coverage:"),
    ("Platform coverage version pin", 'CARGO_LLVM_COV_VERSION: "0.8.7"'),
    ("Platform coverage threshold", "--fail-under-lines 80"),
    (
        "Config report platform coverage",
        "cargo llvm-cov --locked\n          -p registry-config-report\n          -p 'registry-platform-*'",
    ),
    (
        "Platform hygiene alignment",
        "run: products/platform/scripts/check-hygiene-alignment.sh",
    ),
    (
        "Platform config inventory",
        "products/platform/scripts/audit-configs.sh",
    ),
    ("Platform config inventory check", "--check"),
    ("Secret scan job", "secrets:"),
    ("Gitleaks version pin", 'GITLEAKS_VERSION: "8.30.1"'),
    ("Gitleaks archive checksum", "GITLEAKS_LINUX_X64_SHA256:"),
    ("Gitleaks root config", "--config .gitleaks.toml"),
    ("Gitleaks redaction", "--redact"),
    ("oasdiff version pin", 'OASDIFF_VERSION: "1.23.0"'),
    ("oasdiff archive checksum", "OASDIFF_LINUX_X64_SHA256:"),
    (
        "oasdiff pinned install",
        '"https://github.com/oasdiff/oasdiff/releases/download/v${OASDIFF_VERSION}/oasdiff_${OASDIFF_VERSION}_linux_amd64.tar.gz"',
    ),
    ("Platform fuzz job", "platform-fuzz:"),
    ("Platform fuzz version pin", 'CARGO_FUZZ_VERSION: "0.13.2"'),
    ("Platform fuzz bounded runtime", "-max_total_time=60"),
    (
        "Platform fuzz directory",
        "cargo +nightly fuzz run --fuzz-dir fuzz",
    ),
    ("Notary OpenAPI baseline", "run: just openapi-check"),
    ("Notary OpenAPI contract", "name: Notary OpenAPI contract"),
    ("Notary exposure check", "name: Notary exposure check"),
    ("Notary exposure command", "run: just exposure-check"),
    ("Relay OpenAPI contract", "name: Relay OpenAPI contract"),
    ("Relay OpenAPI command", "run: just openapi-contract"),
    ("Relay exposure check", "name: Relay exposure check"),
    (
        "Release helper tests",
        "run: python3 -m unittest release/scripts/test_registry_release.py",
    ),
    (
        "Adopter Compose checker tests",
        "run: python3 -m unittest release/scripts/test_check_adopter_compose_contract.py",
    ),
    (
        "Adopter Compose conformance",
        "run: bash release/scripts/check_adopter_compose_contract.sh",
    ),
    (
        "Release-lock runtime and Compose parity",
        "run: bash release/scripts/check-runtime-contract-parity.sh",
    ),
    (
        "First-country release-form runner tests",
        "run: python3 -m unittest release/scripts/test_first_country_release_form.py",
    ),
    (
        "Release planning command tests",
        "run: python3 -m unittest release/scripts/test_registry_release_plans.py",
    ),
    (
        "Release candidate receipt and promotion verifier tests",
        "run: python3 -m unittest release/scripts/test_release_candidate.py",
    ),
    (
        "Release proof-level selection tests",
        "run: python3 -m unittest release/scripts/test_select_release_proof_level.py",
    ),
    (
        "Release storage preflight tests",
        "run: python3 -m unittest release/scripts/test_check_release_storage.py",
    ),
    (
        "Release candidate cleanup tests",
        "run: python3 -m unittest release/scripts/test_cleanup_release_candidates.py",
    ),
    (
        "Release repeatability workflow tests",
        "run: python3 -m unittest release/scripts/test_release_repeatability_workflow.py",
    ),
    (
        "Release workflow structure tests",
        "run: python3 -m unittest release/scripts/test_release_workflow_structure.py",
    ),
    (
        "Release image OCI label checker tests",
        "run: python3 -m unittest release/scripts/test_check_release_image_oci_labels.py",
    ),
    (
        "Release image layout comparator tests",
        "run: python3 -m unittest release/scripts/test_compare_release_image_layouts.py",
    ),
    (
        "Release Relay feature checker tests",
        "run: python3 -m unittest release/scripts/test_check_release_relay_features.py",
    ),
    (
        "Executable release image OCI label smoke",
        "run: release/scripts/smoke-release-image-oci-labels.sh",
    ),
    (
        "OpenID conformance runner tests",
        "run: python3 -m unittest release/scripts/test_openid_conformance_runner.py",
    ),
    (
        "External integration evidence runner tests",
        "run: python3 -m unittest release/scripts/test_integration_e2_runner.py",
    ),
    (
        "External integration evidence packet",
        "run: python3 release/scripts/integration-e2-runner.py validate",
    ),
    (
        "Relay OIDC smoke tests",
        "run: python3 -m unittest release/scripts/test_relay_oidc_smoke.py",
    ),
    (
        "Relay OIDC smoke offline validation",
        "run: python3 release/scripts/relay-oidc-smoke.py validate",
    ),
    ("Release manifest validation", "release/scripts/registry-release validate"),
    ("Release docset validation", "release/scripts/registry-release validate-docsets"),
    ("Release import audit", "release/scripts/registry-release audit"),
    (
        "Release source model",
        "run: REGISTRY_RELEASE_SOURCE_MODE=monorepo release/scripts/check-release-source-model.sh",
    ),
    (
        "Release source model tests",
        "run: python3 -m unittest release/scripts/test_check_release_source_model.py",
    ),
    (
        "Gate inventory self-check",
        "run: python3 release/scripts/check-gates-inventory.py",
    ),
    (
        "Gate inventory tests",
        "run: python3 -m unittest release/scripts/test_check_gates_inventory.py",
    ),
    (
        "Stable surface compatibility",
        "run: python3 release/scripts/check-stable-surface-compatibility.py",
    ),
    (
        "Stable surface compatibility tests",
        "run: python3 -m unittest release/scripts/test_check_stable_surface_compatibility.py",
    ),
    (
        "Relay OpenAPI stability filter tests",
        "run: python3 -m unittest release/scripts/test_filter_relay_openapi_stability.py",
    ),
    (
        "Upgrade exercise validator tests",
        "run: python3 -m unittest release/scripts/test_validate_upgrade_exercise.py",
    ),
    (
        "Product-input lifecycle validator tests",
        "run: python3 -m unittest release/scripts/test_validate_product_input_lifecycle.py",
    ),
    (
        "Product-input lifecycle record discovery",
        "python3 release/scripts/validate-product-input-lifecycle.py\n"
        "          --discover release/exercises\n"
        "          --candidate-asset-root target/candidate-release-assets",
    ),
    (
        "First-country acceptance validator tests",
        "run: python3 -m unittest release/scripts/test_validate_first_country_acceptance.py",
    ),
    (
        "First-country acceptance source packet",
        "run: python3 release/scripts/validate-first-country-acceptance.py check-packet",
    ),
    (
        "Candidate evidence asset preparation tests",
        "run: python3 -m unittest release/scripts/test_prepare_upgrade_exercise_assets.py",
    ),
    (
        "Candidate evidence asset preparation",
        "python3 release/scripts/prepare-upgrade-exercise-assets.py\n"
        "          --discover release/exercises\n"
        "          --product-input-records "
        "release/exercises/product-input-lifecycle\n"
        "          --asset-root target/candidate-release-assets",
    ),
    (
        "Product-input lifecycle candidate asset preparation",
        "--product-input-records release/exercises/product-input-lifecycle",
    ),
    (
        "Candidate evidence Cosign installation",
        "name: Install cosign for committed candidate evidence\n"
        "        if: steps.candidate-assets.outputs.has_candidates == 'true'",
    ),
    (
        "Candidate evidence SLSA verifier installation",
        "name: Install SLSA verifier for committed candidate evidence\n"
        "        if: steps.candidate-assets.outputs.has_candidates == 'true'",
    ),
    (
        "Upgrade exercise record discovery",
        "python3 release/scripts/validate-upgrade-exercise.py\n"
        "          --discover release/exercises\n"
        "          --candidate-asset-root target/candidate-release-assets",
    ),
    (
        "Base-reference compatibility input",
        "STABLE_SURFACE_BASE_REF: ${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || github.event.before }}",
    ),
    (
        "OpenAPI base-reference input",
        "OPENAPI_CONTRACT_BASE_REF: ${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || github.event.before }}",
    ),
    (
        "Stable error registry path filter",
        '"docs/site/src/content/docs/reference/errors.mdx",',
    ),
    (
        "Relay support roster path filter",
        '"docs/site/src/data/relay-support.yaml",',
    ),
    ("Docs dependency install", "run: npm ci"),
    ("Docs tests", "run: npm test"),
    ("Docs build check", "run: npm run check"),
    (
        "Registryctl tutorial path filter",
        "registryctl_tutorial: ${{ steps.filter.outputs.registryctl_tutorial }}",
    ),
    ("Registryctl tutorial job", "registryctl-tutorials:"),
    (
        "Registryctl tutorial helper tests",
        "run: npm run test:tutorial:registryctl",
    ),
    (
        "Registryctl tutorial command pre-gate",
        "run: npm run check:tutorial:dry-run",
    ),
    (
        "Registryctl tutorial source execution",
        "run: npm run check:tutorial:registryctl",
    ),
)

RELEASE_SECURITY_POLICY_PATHS = (
    ".github/workflows/docs-pages.yml",
    ".github/workflows/release.yml",
    ".github/workflows/release-candidate.yml",
    ".github/workflows/release-canary.yml",
    ".github/workflows/release-repeatability.yml",
    ".github/workflows/release-candidate-cleanup.yml",
    "release/scripts/release_candidate.py",
    "release/scripts/cleanup-release-candidates.py",
    "release/scripts/verify_latest_published_release.py",
)

REQUIRED_RELEASE_SECURITY_GATES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "Candidate-bound annotated tag promotion",
        ".github/workflows/release.yml",
        (
            'push:\n    tags:\n      - "v*"',
            "name: Verify candidate-bound release tag",
            "name: Parse exact annotated-tag candidate binding",
            'for field in ("run_id", "run_attempt", "receipt_sha256"):',
            "name: Validate tag source without rebuilding",
            'test "$(git rev-parse refs/remotes/origin/main)" = \\',
        ),
    ),
    (
        "Tag-target documentation evidence link gate",
        ".github/workflows/release.yml",
        (
            "name: Verify documentation evidence links",
            "npm run check:evidence-links --",
            '--source-ref "${{ steps.release.outputs.tag_target }}"',
        ),
    ),
    (
        "Immutable documentation archive publication",
        ".github/workflows/release.yml",
        (
            "docs-archive:\n    name: Build immutable release docs archive",
            "name: Build and verify the tag-bound docs bundle",
            "npm run build:archive",
            "--verify-lock",
            "name: Download unprivileged docs archive",
            "does not match immutable lock",
            "--require-registry-docs-archive",
        ),
    ),
    (
        "Exact promotion run attempt and receipt binding",
        ".github/workflows/release.yml",
        (
            "EXPECTED_RUN_ID: ${{ needs.verify.outputs.candidate_run }}",
            "EXPECTED_RUN_ATTEMPT: ${{ needs.verify.outputs.candidate_attempt }}",
            'receipt_name="registry-stack-release-candidate-receipt-${EXPECTED_RUN_ID}-${EXPECTED_RUN_ATTEMPT}"',
            'test "$(sha256sum "${receipt}" | awk \'{print $1}\')" = \\',
            '--run-id "${EXPECTED_RUN_ID}"',
            '--run-attempt "${EXPECTED_RUN_ATTEMPT}"',
            "--trusted-run-metadata promotion/control/trusted-run.json",
            "verify-tag-binding",
        ),
    ),
    (
        "Promotion verifier and attestation barrier",
        ".github/workflows/release.yml",
        (
            "name: Download and verify exact candidate attempt",
            "python3 release/scripts/release_candidate.py verify",
            'gh attestation verify "${receipt}"',
            '--signer-workflow "${signer}"',
            "--source-ref refs/heads/main",
            "name: Build fail-closed prewrite promotion state",
            "touch promotion/control/PUBLISH_BARRIER",
            "test -f promotion/control/PUBLISH_BARRIER",
        ),
    ),
    (
        "Promotion requires immutable candidate scan proof",
        "release/scripts/release_candidate.py",
        (
            'scans = require_object(receipt["scans"], "scans", {"policy", "immutable_digests"})',
            'scans != {"policy": "passed", "immutable_digests": True}',
            "candidate scan policy did not pass on immutable digests",
        ),
    ),
    (
        "Exact digest image promotion",
        ".github/workflows/release.yml",
        (
            "name: Promote provenance-bearing candidate indexes without rewriting",
            'staging="${REGISTRY}/${IMAGE_NAMESPACE}/${name}-candidate@${digest}"',
            'crane copy "${staging}" "${public}"',
            'test "$(crane digest "${public}")" = "${digest}"',
            'test "$(crane digest "${REGISTRY}/${IMAGE_NAMESPACE}/${name}@${digest}")" = \\',
        ),
    ),
    (
        "Published candidate receipt and tag-bound evidence",
        ".github/workflows/release.yml",
        (
            "name: Stage exact candidate release files",
            "candidate-receipt.json",
            "name: Render tag-bound image lock and checksums",
            "name: Generate release file SBOMs and release capsule",
            "name: Sign promoted release evidence",
            "name: Create immutable GitHub Release",
            "--verify-tag",
        ),
    ),
    (
        "Final post-provenance reconciliation",
        ".github/workflows/release.yml",
        (
            "release-provenance:\n    name: Generate tag-bound release provenance",
            "reconcile:\n    name: Reconcile exact final release inventory",
            "      - release-provenance",
            "name: Reconcile exact final inventory after SLSA provenance",
            "diff -u expected-assets actual-assets",
            'provenance_sha="$(sha256sum "downloaded/${provenance}"',
            ".workflow.run_attempt==$attempt",
        ),
    ),
    (
        "Final SLSA subject verification",
        ".github/workflows/release.yml",
        (
            "SLSA_VERIFIER_VERSION: v2.7.1",
            "SLSA_VERIFIER_LINUX_AMD64_SHA256:",
            "name: Install pinned final verification tools",
            'echo "${STEP_SLSA_SHA256}  ${slsa}" | sha256sum --check --strict',
            'slsa-verifier verify-artifact "downloaded/${subject_name}"',
            '--provenance-path "downloaded/${provenance}"',
            '--source-uri "github.com/${GITHUB_REPOSITORY}"',
            '--source-tag "${tag}"',
            "python3 release/scripts/release_candidate.py verify-slsa-subjects",
            "--contract reconciliation/pre-provenance.json",
        ),
    ),
    (
        "Promotion reconciliation contract seven-day retention",
        ".github/workflows/release.yml",
        (
            "name: Record exact pre-provenance inventory",
            "name: Upload exact reconciliation contract",
            "retention-days: 7",
        ),
    ),
    (
        "Extended proof dispatch after final reconciliation",
        ".github/workflows/release.yml",
        (
            "extended-proof:\n    name: Schedule extended repeatability proof",
            "      - reconcile",
            "if: ${{ needs.verify-candidate.outputs.proof_level == 'extended' }}",
            "name: Request extended published-tag proof after final reconciliation",
            "-f event_type=release-repeatability",
        ),
    ),
    (
        "Promotion workflow timing and runner telemetry",
        ".github/workflows/release.yml",
        (
            "release-telemetry:\n    name: Record promotion telemetry",
            "      - reconcile",
            "if: ${{ always() }}",
            "name: Record queue, wall-clock, and runner occupancy review triggers",
            'schema_version:"registry-stack.release-promotion-telemetry.v1"',
            "queue_seconds:",
            "wall_clock_to_collector_seconds:",
            "queue_delay_seconds:",
            "runner_occupancy_seconds:",
            "completed_runner_seconds:",
            "wall_clock_budget_seconds:1200",
            "runner_seconds_budget:8000",
            "name: Upload seven-day promotion telemetry",
            "retention-days: 7",
        ),
    ),
    (
        "Protected release candidate trigger",
        ".github/workflows/release-candidate.yml",
        (
            "repository_dispatch:\n    types:\n      - release_candidate",
            "name: Validate exact protected-main request",
            "workflow revision, requested source, and current protected main must be the same exact commit",
        ),
    ),
    (
        "Release candidate proof-level selection",
        ".github/workflows/release-candidate.yml",
        (
            "name: Select standard or extended proof level",
            "python3 release/scripts/select-release-proof-level.py",
            '--requested "${{ steps.request.outputs.requested_proof_level }}"',
        ),
    ),
    (
        "Single canonical candidate build with separate repeatability proof",
        ".github/workflows/release-candidate.yml",
        (
            "build-a:\n    name: Build A cached canonical candidate",
            "name: Restore exact-key Cargo cache",
            "name: Validate canonical binary inventory",
        ),
    ),
    (
        "Candidate cache status and peak storage evidence",
        ".github/workflows/release-candidate.yml",
        (
            "name: Restore exact-key Cargo cache",
            "steps.cargo-cache.outputs.cache-hit",
            "exact_key_hit",
            "name: Start peak-storage sampler",
            "name: Stop peak-storage sampler",
            "storage-measurement-a.json",
            "storage-measurement.json",
        ),
    ),
    (
        "Compact candidate telemetry evidence transfer",
        ".github/workflows/release-candidate.yml",
        (
            "name: Create compact candidate telemetry evidence",
            'schema_version:"registry-stack.release-candidate-telemetry-evidence.v1"',
            '.builds.a.cargo_cache.mode == "exact-key-restore"',
            "(.peak_storage_measurements | length == 4)",
            "name: Upload compact candidate telemetry evidence",
            "registry-stack-candidate-telemetry-evidence-run-${{ github.run_id }}-attempt-${{ github.run_attempt }}",
            "path: dist/candidate-telemetry-evidence/evidence.json",
            "retention-days: 7",
            "Successful candidate has no compact telemetry evidence",
            'cache_state="$(jq -c \'.builds.a.cargo_cache\' "${evidence}")"',
            'storage_evidence="$(jq -c \'.peak_storage_measurements\' "${evidence}")"',
        ),
    ),
    (
        "Candidate workflow timing and resource telemetry",
        ".github/workflows/release-candidate.yml",
        (
            "candidate-telemetry:\n    name: Record candidate workflow telemetry",
            "      - verify-candidate",
            "if: ${{ always() }}",
            "name: Download cache and peak-storage evidence",
            "name: Collect candidate wall clock, queue delay, and runner occupancy",
            "queue_delay_seconds:",
            "wall_clock_seconds:",
            "runner_occupancy_seconds:",
            "completed_runner_occupancy_seconds:",
            "cache_state:",
            "peak_storage_evidence:",
            "name: Upload candidate workflow telemetry",
            "retention-days: 7",
        ),
    ),
    (
        "Candidate registryctl release gates",
        ".github/workflows/release-candidate.yml",
        (
            "verify-registryctl-image-lock-release-version",
            "name: Verify built registryctl binary version",
            "name: Verify native registryctl binary version",
            "verify-registryctl-binary-version",
        ),
    ),
    (
        "Promotion registryctl tag-bound image lock",
        ".github/workflows/release.yml",
        (
            "name: Render tag-bound image lock and checksums",
            "render-registryctl-image-lock",
            '--tag-target "${{ needs.verify.outputs.tag_target }}"',
            "registryctl-${{ needs.verify.outputs.tag }}-image-lock.json",
        ),
    ),
    (
        "Private staging package enforcement",
        ".github/workflows/release-candidate.yml",
        (
            "name: Verify staging packages are private before publication",
            "name: Build and push provenance-bearing staging images",
            "name: Verify staging packages remain private",
            "registry-notary-candidate",
            "registry-relay-candidate",
        ),
    ),
    (
        "Immutable candidate scan and advisory gate",
        ".github/workflows/release-candidate.yml",
        (
            "name: Scan immutable staging digests",
            'digest_ref="$(cat "inputs/build-a/dist/images/${name}.digest")"',
            "scan_sbom() {",
            '(.matches | type == "array")',
            ".descriptor.db.built // .descriptor.db.status.built",
            'test("checksum=sha256%3A[0-9a-fA-F]{64}")',
            "read_db_metadata() {",
            "Grype did not emit a complete scan report",
            "enforcing its complete report through the reviewed advisory policy",
            "name: Enforce advisory policy",
            "--syft-report dist/candidate/dist/sbom/registry-notary.syft.json",
            "--rootfs dist/candidate/dist/rootfs/registry-notary",
            "--syft-report dist/candidate/dist/sbom/registry-relay.syft.json",
            "--rootfs dist/candidate/dist/rootfs/registry-relay",
        ),
    ),
    (
        "Attempt-bound closed candidate receipt",
        ".github/workflows/release-candidate.yml",
        (
            "name: Create closed candidate receipt",
            '--argjson expected_run_id "${GITHUB_RUN_ID}"',
            '--argjson expected_run_attempt "${GITHUB_RUN_ATTEMPT}"',
            '.status == "in_progress" and',
            ".conclusion == null and",
            '--argjson run_id "${GITHUB_RUN_ID}"',
            '--argjson run_attempt "${GITHUB_RUN_ATTEMPT}"',
            '--run-id "${GITHUB_RUN_ID}"',
            '--run-attempt "${GITHUB_RUN_ATTEMPT}"',
            "name: Attest candidate receipt",
            "name: Upload attempt-bound candidate receipt",
        ),
    ),
    (
        "Candidate receipt trusted run and attempt binding",
        "release/scripts/release_candidate.py",
        (
            'WORKFLOW_PATH = ".github/workflows/release-candidate.yml"',
            'run_id = require_positive_integer(workflow["run_id"], "workflow.run_id")',
            "run_attempt = require_positive_integer(",
            "promotion requires independently fetched trusted workflow-run metadata",
            '"run_attempt": run_attempt,',
        ),
    ),
    (
        "Scheduled protected repeatability trigger",
        ".github/workflows/release-repeatability.yml",
        (
            "schedule:",
            "repository_dispatch:\n    types: [release-repeatability]",
            "name: Rebuild published tag",
        ),
    ),
    (
        "Repeatability published-tag proof",
        ".github/workflows/release-repeatability.yml",
        (
            "name: Verify storage runway",
            "name: Build canonical Linux payload from clean state",
            "name: Compare published binary hashes",
            "name: Compare published image config and layers",
            "name: Attest repeatability receipt",
            "name: Refresh durable repeatability evidence",
        ),
    ),
    (
        "Repeatability seven-day evidence retention",
        ".github/workflows/release-repeatability.yml",
        ("name: Upload seven-day repeatability evidence", "retention-days: 7"),
    ),
    (
        "Scheduled protected candidate cleanup trigger",
        ".github/workflows/release-candidate-cleanup.yml",
        (
            "schedule:",
            "repository_dispatch:\n    types: [release-candidate-cleanup]",
            "name: Delete expired candidate versions",
        ),
    ),
    (
        "Candidate cleanup seven-day retention",
        ".github/workflows/release-candidate-cleanup.yml",
        (
            "name: Delete candidate versions older than seven days",
            "python3 release/scripts/cleanup-release-candidates.py",
            "retention-days: 7",
        ),
    ),
    (
        "Candidate cleanup exact package allowlist",
        "release/scripts/cleanup-release-candidates.py",
        (
            'CANDIDATE_PACKAGES = (\n    "registry-notary-candidate",\n'
            '    "registry-relay-candidate",\n)',
            "if package in PUBLIC_PACKAGES:",
            "if package not in CANDIDATE_PACKAGES:",
        ),
    ),
)

ORDERED_RELEASE_SECURITY_GATES: tuple[tuple[str, str, str, str], ...] = (
    (
        "Immutable docs archive before first public image write",
        ".github/workflows/release.yml",
        "name: Build and verify the tag-bound docs bundle",
        "name: Promote provenance-bearing candidate indexes without rewriting",
    ),
    (
        "Promotion binding parsed before candidate verification",
        ".github/workflows/release.yml",
        "name: Parse exact annotated-tag candidate binding",
        "name: Download and verify exact candidate attempt",
    ),
    (
        "Candidate verifier before first public image write",
        ".github/workflows/release.yml",
        "name: Build fail-closed prewrite promotion state",
        "name: Promote provenance-bearing candidate indexes without rewriting",
    ),
    (
        "Candidate verifier before GitHub Release write",
        ".github/workflows/release.yml",
        "name: Build fail-closed prewrite promotion state",
        "name: Create immutable GitHub Release",
    ),
    (
        "Exact image promotion before GitHub Release write",
        ".github/workflows/release.yml",
        "name: Promote provenance-bearing candidate indexes without rewriting",
        "name: Create immutable GitHub Release",
    ),
    (
        "SLSA provenance before final reconciliation",
        ".github/workflows/release.yml",
        "release-provenance:\n    name: Generate tag-bound release provenance",
        "reconcile:\n    name: Reconcile exact final release inventory",
    ),
    (
        "Generated provenance before SLSA subject verification",
        ".github/workflows/release.yml",
        "release-provenance:\n    name: Generate tag-bound release provenance",
        'slsa-verifier verify-artifact "downloaded/${subject_name}"',
    ),
    (
        "Final reconciliation before extended proof dispatch",
        ".github/workflows/release.yml",
        "reconcile:\n    name: Reconcile exact final release inventory",
        "extended-proof:\n    name: Schedule extended repeatability proof",
    ),
    (
        "Candidate proof selection before build",
        ".github/workflows/release-candidate.yml",
        "name: Select standard or extended proof level",
        "build-a:\n    name: Build A cached canonical candidate",
    ),
    (
        "Candidate storage preflight before cache restore",
        ".github/workflows/release-candidate.yml",
        "name: Storage preflight before cache restore",
        "name: Restore exact-key Cargo cache",
    ),
    (
        "Candidate storage preflight before platform build",
        ".github/workflows/release-candidate.yml",
        "name: Storage preflight before platform build",
        "name: Build platform payload once",
    ),
    (
        "Candidate staging privacy verified before push",
        ".github/workflows/release-candidate.yml",
        "name: Verify staging packages are private before publication",
        "name: Build and push provenance-bearing staging images",
    ),
    (
        "Candidate registryctl version gate before staging push",
        ".github/workflows/release-candidate.yml",
        "name: Verify built registryctl binary version",
        "name: Build and push provenance-bearing staging images",
    ),
    (
        "Candidate staging privacy rechecked after push",
        ".github/workflows/release-candidate.yml",
        "name: Build and push provenance-bearing staging images",
        "name: Verify staging packages remain private",
    ),
    (
        "Candidate scan before advisory policy",
        ".github/workflows/release-candidate.yml",
        "name: Scan immutable staging digests",
        "name: Enforce advisory policy",
    ),
    (
        "Candidate advisory policy before receipt",
        ".github/workflows/release-candidate.yml",
        "name: Enforce advisory policy",
        "name: Create closed candidate receipt",
    ),
    (
        "Candidate receipt created before attestation",
        ".github/workflows/release-candidate.yml",
        "name: Create closed candidate receipt",
        "name: Attest candidate receipt",
    ),
    (
        "Repeatability storage preflight before expensive rebuild",
        ".github/workflows/release-repeatability.yml",
        "name: Verify storage runway",
        "name: Build canonical Linux payload from clean state",
    ),
)

FORBIDDEN_RELEASE_SECURITY_GATES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "Promotion cannot rebuild product bytes, write refs, or use branch dispatch",
        ".github/workflows/release.yml",
        (
            "workflow_dispatch:",
            "git push",
            "git tag ",
            "git update-ref",
            "/git/refs",
            "cargo build",
            "docker build",
            "docker push",
            "docker/build-push-action@",
            "buildx build",
            "run: release/scripts/build-release-binaries.sh",
            "run: release/scripts/build-release-image.sh",
        ),
    ),
    (
        "Candidate cannot select branch-controlled workflow code, write refs, or publish",
        ".github/workflows/release-candidate.yml",
        (
            "workflow_dispatch:",
            "contents: write",
            "git push",
            "git update-ref",
            "crane copy",
            "gh release create",
            "gh release upload",
        ),
    ),
    (
        "Repeatability cannot select branch-controlled workflow code or write refs",
        ".github/workflows/release-repeatability.yml",
        ("workflow_dispatch:", "contents: write", "git push", "git update-ref"),
    ),
    (
        "Candidate cleanup cannot select branch-controlled workflow code or write refs",
        ".github/workflows/release-candidate-cleanup.yml",
        ("workflow_dispatch:", "contents: write", "git push", "git update-ref"),
    ),
)

# The compact v2 release contract replaced the receipt, capsule, telemetry, and
# post-publication reconciliation model above. Keep the active inventory close
# to the generic checkers so CI evaluates the current workflow boundary.
REQUIRED_RELEASE_SECURITY_GATES = (
    (
        "Candidate-bound annotated tag promotion",
        ".github/workflows/release.yml",
        (
            'push:\n    tags:\n      - "v*"',
            "name: Resolve exact tag identity",
            'if [[ "$(git cat-file -t "refs/tags/${tag}")" != tag ]]; then',
            "name: Parse compact candidate binding",
            'for field in ("run_id", "run_attempt", "manifest_sha256"):',
        ),
    ),
    (
        "Exact candidate attempt authentication",
        ".github/workflows/release.yml",
        (
            "name: Download exact candidate attempt",
            'artifact_name="registry-stack-release-candidate-${RUN_ID}-${RUN_ATTEMPT}"',
            "expected_archive_digest=",
            "release-candidate-manifest.json",
            "name: Verify binding, candidate, attestations, and recent canary",
            "verify-tag-binding",
            "gh attestation verify",
        ),
    ),
    (
        "Draft-first exact staged publication",
        ".github/workflows/release.yml",
        (
            "stage-draft:\n    name: Create exact resumable draft",
            "name: Reverify and stage exact candidate payloads",
            "gh release create",
            "--draft",
            "name: Upload draft reconciliation contract",
        ),
    ),
    (
        "Tag-bound release provenance",
        ".github/workflows/release.yml",
        (
            "release-provenance:",
            "uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@",
            "upload-assets: true",
        ),
    ),
    (
        "Draft reconciliation and exact image promotion",
        ".github/workflows/release.yml",
        (
            "promote-images:\n    name: Reconcile staged draft, then promote exact image manifests",
            "name: Reconcile exact staged draft before first public image write",
            "diff -u contract/expected-assets contract/actual-assets",
            "name: Reverify candidate expiry immediately before registry login",
            "name: Recheck all destinations before exact digest promotion",
            'crane copy "${candidate_ref}" "${final_ref}"',
            'test "$(crane digest "${final_ref}")" = "${digest}"',
        ),
    ),
    (
        "Final signed runtime release closure",
        ".github/workflows/release.yml",
        (
            "finalize-assets:\n    name: Finalize signed assets and prove the released 1.x runtime",
            "if ((major >= 1)); then",
            "registry_release_lock.py create-payload",
            "registry-release-lock.v1.json",
            "first-country-release-form.py run",
            "first-country-release-form.tar.gz",
            "cosign sign-blob --yes",
            "name: Upload final reconciliation contract",
        ),
    ),
    (
        "Release publication and authenticated docs dispatch",
        ".github/workflows/release.yml",
        (
            "name: Recheck complete signed draft and exact public images",
            "name: Publish immutable release",
            "-F draft=false",
            "-F prerelease=false",
            "name: Dispatch authenticated docs promotion",
            '-f "released_tag=${{ needs.verify.outputs.tag }}"',
            '-f "docs_sha256=${{ needs.verify.outputs.docs_sha256 }}"',
        ),
    ),
    (
        "Latest-only released docs deployment",
        ".github/workflows/docs-pages.yml",
        (
            "name: Authenticate public release and checksum inventory",
            'gh api "repos/${GITHUB_REPOSITORY}/releases/latest"',
            "python3 release/scripts/verify_latest_published_release.py",
            "name: Recheck latest published release immediately before deployment",
            "name: Deploy to GitHub Pages",
        ),
    ),
    (
        "Latest release metadata fails closed",
        "release/scripts/verify_latest_published_release.py",
        (
            'if metadata.get("draft") is not False:',
            'if metadata.get("prerelease") is not False:',
            "if actual_tag != expected_tag:",
            "is stale; latest published",
        ),
    ),
    (
        "Protected candidate request and pure validation",
        ".github/workflows/release-candidate.yml",
        (
            "repository_dispatch:\n    types: [release_candidate]",
            "name: Validate request, source, CI, canary, and destinations",
            "git merge-base --is-ancestor",
            "verify-canary",
            "tag_lookup_status=$?",
            'if [[ "${tag_lookup_status}" -ne 2 ]]; then',
            "cannot prove tag ${tag} is absent",
            "name: Validate manifests, pins, recipes, and scanner policy fixtures",
        ),
    ),
    (
        "Single canonical candidate build",
        ".github/workflows/release-candidate.yml",
        (
            "build-canonical:\n    name: Build Linux payload, private images, and docs once",
            "name: Restore exact-key Cargo cache",
            "name: Build canonical Linux payload once",
            "name: Build private candidate image layouts once",
            "name: Package exact release docs archive",
        ),
    ),
    (
        "Private exact candidate images and advisory gate",
        ".github/workflows/release-candidate.yml",
        (
            "name: Verify local image layouts before package credentials are used",
            "name: Publish exact layouts to private candidate packages",
            "--from-oci-layout",
            "--jq .visibility",
            ")\" = private",
            "name: Verify and scan exact candidate images",
            'scan_image \\\n              "${candidate_ref}"',
            "check_advisory_baselines.py",
        ),
    ),
    (
        "Compact candidate manifest and bundle",
        ".github/workflows/release-candidate.yml",
        (
            "name: Seal compact candidate manifest and bundle",
            "seal-candidate",
            "name: Upload one candidate manifest and bundle",
            "registry-stack-release-candidate-${{ github.run_id }}-${{ github.run_attempt }}",
            "candidate/release-candidate-manifest.json",
            "candidate/registry-stack-${{ needs.validate.outputs.tag }}-candidate.tar.gz",
            "retention-days: 7",
        ),
    ),
    (
        "Candidate verifier and OIDC isolation",
        ".github/workflows/release-candidate.yml",
        (
            "attest:\n    name: Reverify and attest candidate",
            "name: Reverify all bytes before requesting OIDC",
            "verify-candidate",
            "name: Attest manifest and bundle after re-verification",
            "uses: actions/attest-build-provenance@",
        ),
    ),
    (
        "Nightly protected release canary",
        ".github/workflows/release-canary.yml",
        (
            "schedule:",
            "workflow_dispatch:",
            "name: Exercise dispatch, candidate, advisory, draft, and docs contracts",
            "verify-canary",
            "name: Attest canary only after all local checks pass",
            "name: Run platform-specific release-tool contract",
        ),
    ),
    (
        "Scheduled 30-day repeatability boundary",
        ".github/workflows/release-repeatability.yml",
        (
            "schedule:",
            "workflow_dispatch:",
            "name: Resolve exact published tag",
            "name: Build canonical Linux payload from clean state",
            "name: Compare published binary hashes",
            "name: Compare published image config and layers",
            "name: Record successful 30-day proof",
            "silver_claim_valid_through:",
            "name: Upload 30-day repeatability evidence",
            "retention-days: 30",
        ),
    ),
    (
        "Scheduled protected candidate cleanup trigger",
        ".github/workflows/release-candidate-cleanup.yml",
        (
            "schedule:",
            "repository_dispatch:\n    types: [release-candidate-cleanup]",
            "name: Delete candidate versions older than seven days",
        ),
    ),
    (
        "Candidate cleanup exact package allowlist",
        "release/scripts/cleanup-release-candidates.py",
        (
            'CANDIDATE_PACKAGES = (\n    "registry-notary-candidate",\n'
            '    "registry-relay-candidate",\n)',
            "if package in PUBLIC_PACKAGES:",
            "if package not in CANDIDATE_PACKAGES:",
        ),
    ),
)

ORDERED_RELEASE_SECURITY_GATES = (
    (
        "Latest release recheck immediately before docs deployment",
        ".github/workflows/docs-pages.yml",
        "name: Recheck latest published release immediately before deployment",
        "name: Deploy to GitHub Pages",
    ),
    (
        "Promotion binding before candidate verification",
        ".github/workflows/release.yml",
        "name: Parse compact candidate binding",
        "name: Verify binding, candidate, attestations, and recent canary",
    ),
    (
        "Candidate verification before draft creation",
        ".github/workflows/release.yml",
        "name: Reverify and stage exact candidate payloads",
        "name: Recreate resumable draft and upload exact staged inventory",
    ),
    (
        "Draft reconciliation before image promotion",
        ".github/workflows/release.yml",
        "name: Reconcile exact staged draft before first public image write",
        "name: Recheck all destinations before exact digest promotion",
    ),
    (
        "Exact image promotion before final runtime proof",
        ".github/workflows/release.yml",
        "name: Recheck all destinations before exact digest promotion",
        "name: Generate signed 1.x lock and run the clean released runtime",
    ),
    (
        "Final runtime proof before release provenance",
        ".github/workflows/release.yml",
        "name: Generate signed 1.x lock and run the clean released runtime",
        "release-provenance:",
    ),
    (
        "Candidate expiry immediately before registry login",
        ".github/workflows/release.yml",
        "name: Reverify candidate expiry immediately before registry login",
        "name: Log in for exact candidate promotion",
    ),
    (
        "Exact image promotion before release publication",
        ".github/workflows/release.yml",
        "name: Recheck all destinations before exact digest promotion",
        "name: Publish immutable release",
    ),
    (
        "Release publication before docs dispatch",
        ".github/workflows/release.yml",
        "name: Publish immutable release",
        "name: Dispatch authenticated docs promotion",
    ),
    (
        "Candidate validation before build",
        ".github/workflows/release-candidate.yml",
        "name: Validate manifests, pins, recipes, and scanner policy fixtures",
        "build-canonical:\n    name: Build Linux payload, private images, and docs once",
    ),
    (
        "Local layout verification before package credentials",
        ".github/workflows/release-candidate.yml",
        "name: Verify local image layouts before package credentials are used",
        "name: Publish exact layouts to private candidate packages",
    ),
    (
        "Candidate scan before compact seal",
        ".github/workflows/release-candidate.yml",
        "name: Verify and scan exact candidate images",
        "name: Seal compact candidate manifest and bundle",
    ),
    (
        "Compact candidate before attestation",
        ".github/workflows/release-candidate.yml",
        "name: Upload one candidate manifest and bundle",
        "name: Reverify all bytes before requesting OIDC",
    ),
    (
        "Repeatability rebuild before comparison",
        ".github/workflows/release-repeatability.yml",
        "name: Build canonical Linux payload from clean state",
        "name: Compare published binary hashes",
    ),
)

FORBIDDEN_RELEASE_SECURITY_GATES = (
    (
        "Promotion cannot rebuild product bytes, write refs, or use recovery dispatch",
        ".github/workflows/release.yml",
        (
            "workflow_dispatch:",
            "git push",
            "git tag ",
            "git update-ref",
            "/git/refs",
            "cargo build",
            "docker build",
            "docker push",
            "docker/build-push-action@",
            "buildx build",
            "run: release/scripts/build-release-binaries.sh",
            "run: release/scripts/build-release-image.sh",
            "candidate-receipt.json",
            "release-capsule",
            "extended-proof:",
            "release-telemetry:",
        ),
    ),
    (
        "Candidate cannot select branch-controlled workflow code or publish publicly",
        ".github/workflows/release-candidate.yml",
        (
            "workflow_dispatch:",
            "contents: write",
            "git push",
            "git update-ref",
            "crane copy",
            "gh release create",
            "gh release upload",
            "candidate-receipt.json",
            "release-capsule",
        ),
    ),
    (
        "Canary cannot write public state",
        ".github/workflows/release-canary.yml",
        (
            "contents: write",
            "packages: write",
            "git push",
            "gh release create",
            "gh release upload",
            "crane copy",
            "oras cp",
        ),
    ),
    (
        "Repeatability cannot write public state",
        ".github/workflows/release-repeatability.yml",
        (
            "contents: write",
            "packages: write",
            "id-token: write",
            "attestations: write",
            "git push",
            "gh release create",
            "gh release upload",
            "crane copy",
        ),
    ),
    (
        "Candidate cleanup cannot select branch-controlled workflow code or write refs",
        ".github/workflows/release-candidate-cleanup.yml",
        ("workflow_dispatch:", "contents: write", "git push", "git update-ref"),
    ),
)


def missing_gates(workflow_text: str, classifier_text: str | None = None) -> list[str]:
    if classifier_text is None:
        classifier_text = CI_CLASSIFIER.read_text(encoding="utf-8")
    inventory_text = f"{workflow_text}\n{classifier_text}"
    return [name for name, snippet in REQUIRED_GATES if snippet not in inventory_text]


def workflow_policy_violations(
    workflows: dict[str, str],
    *,
    required: tuple[tuple[str, str, tuple[str, ...]], ...] = (),
    ordered: tuple[tuple[str, str, str, str], ...] = (),
    forbidden: tuple[tuple[str, str, tuple[str, ...]], ...] = (),
) -> list[str]:
    """Check security properties scoped to an exact workflow or release script.

    Ordered gates require every occurrence of the first marker to precede every
    occurrence of the second marker. This prevents a later duplicate step from
    silently weakening a publication barrier.
    """

    violations: list[str] = []
    for name, path, snippets in required:
        text = workflows.get(path)
        if text is None or any(snippet not in text for snippet in snippets):
            violations.append(name)
    for name, path, before, after in ordered:
        text = workflows.get(path)
        if (
            text is None
            or before not in text
            or after not in text
            or text.rfind(before) >= text.find(after)
        ):
            violations.append(name)
    for name, path, snippets in forbidden:
        text = workflows.get(path)
        if text is None or any(snippet in text for snippet in snippets):
            violations.append(name)
    return violations


def yaml_job_block(workflow: str, job_id: str) -> str | None:
    lines = workflow.splitlines()
    marker = f"  {job_id}:"
    try:
        start = lines.index(marker)
    except ValueError:
        return None
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("  ")
            and not lines[index].startswith("    ")
            and lines[index].endswith(":")
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


def yaml_step_blocks(workflow: str) -> list[str]:
    lines = workflow.splitlines()
    starts = [
        index for index, line in enumerate(lines) if line.startswith("      - name:")
    ]
    blocks: list[str] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        blocks.append("\n".join(lines[start:end]))
    return blocks


def candidate_build_isolation_violations(workflow: str | None) -> list[str]:
    if workflow is None:
        return ["Candidate build job isolation"]
    build_a = yaml_job_block(workflow, "build-canonical")
    build_b = yaml_job_block(workflow, "build-b")
    if build_a is None or build_b is not None:
        return ["Candidate build job isolation"]
    if (
        "needs: validate" not in build_a
        or "actions/cache@" not in build_a
        or build_a.count("name: Build canonical Linux payload once") != 1
        or build_a.count("name: Build private candidate image layouts once") != 1
        or build_a.count("name: Package exact release docs archive") != 1
        or "actions/download-artifact@" in build_a
    ):
        return ["Candidate build job isolation"]
    return []


def candidate_attestation_isolation_violations(
    workflow: str | None,
) -> list[str]:
    """Require candidate inspection to be read-only and OIDC to be attest-only."""

    gate = "Candidate verification and attestation permission isolation"
    if workflow is None:
        return [gate]
    verify = yaml_job_block(workflow, "assemble")
    attest = yaml_job_block(workflow, "attest")
    if verify is None or attest is None:
        return [gate]
    verify_permissions = (
        "    permissions:\n"
        "      actions: read\n"
        "      contents: read\n"
        "      packages: write"
    )
    attest_permissions = (
        "    permissions:\n"
        "      actions: read\n"
        "      attestations: write\n"
        "      contents: read\n"
        "      id-token: write"
    )
    attestation_action = "uses: actions/attest-build-provenance@"
    if (
        verify_permissions not in verify
        or "id-token: write" in verify
        or "attestations: write" in verify
        or "needs:\n      - validate\n      - assemble" not in attest
        or attest_permissions not in attest
        or "packages: write" in attest
        or "name: Upload one candidate manifest and bundle" not in verify
        or verify.rfind("python3 release/scripts/release_candidate.py verify")
        >= verify.find("name: Upload one candidate manifest and bundle")
        or "name: Download compact candidate" not in attest
        or "name: Reverify all bytes before requesting OIDC" not in attest
        or attest.rfind("python3 release/scripts/release_candidate.py verify")
        >= attest.find(attestation_action)
        or attestation_action not in attest
        or workflow.count("id-token: write") != attest.count("id-token: write")
        or workflow.count("attestations: write") != attest.count("attestations: write")
        or workflow.count(attestation_action) != attest.count(attestation_action)
    ):
        return [gate]
    return []


def promotion_first_write_barrier_violations(
    workflow: str | None,
) -> list[str]:
    """Require a fail-closed last-moment check of every public destination."""

    gate = "Promotion first-write destination barrier"
    if workflow is None:
        return [gate]
    publish = yaml_job_block(workflow, "promote-images")
    if publish is None:
        return [gate]
    barrier_steps = [
        step
        for step in yaml_step_blocks(publish)
        if "name: Recheck all destinations before exact digest promotion" in step
    ]
    if len(barrier_steps) != 1:
        return [gate]
    barrier_step = barrier_steps[0]
    barrier_required = (
        "name: Recheck all destinations before exact digest promotion",
        "while IFS= read -r final_ref; do",
        'crane digest "${final_ref}"',
        "Final image destination ${final_ref} is no longer absent",
        "done < <(jq -r '.images[].final_ref' \"${manifest}\")",
    )
    publish_required = (
        "name: Reconcile exact staged draft before first public image write",
        "name: Reverify candidate expiry immediately before registry login",
        'crane copy "${candidate_ref}" "${final_ref}"',
    )
    barrier = "done < <(jq -r '.images[].final_ref' \"${manifest}\")"
    first_write = 'crane copy "${candidate_ref}" "${final_ref}"'
    if (
        any(marker not in barrier_step for marker in barrier_required)
        or any(marker not in publish for marker in publish_required)
        or publish.rfind(barrier) >= publish.find(first_write)
    ):
        return [gate]
    return []


def artifact_retention_violations(workflow: str | None) -> list[str]:
    if workflow is None:
        return ["Candidate artifact retention"]
    upload_steps = [
        block
        for block in yaml_step_blocks(workflow)
        if "actions/upload-artifact@" in block
    ]
    final_steps = [
        block
        for block in upload_steps
        if "name: Upload one candidate manifest and bundle" in block
    ]
    intermediate_steps = [block for block in upload_steps if block not in final_steps]
    if (
        len(final_steps) != 1
        or "retention-days: 7" not in final_steps[0]
        or not intermediate_steps
        or any("retention-days: 2" not in block for block in intermediate_steps)
    ):
        return ["Candidate artifact retention"]
    return []


def promotion_rebuild_violations(workflow: str | None) -> list[str]:
    if workflow is None:
        return ["Promotion consumes candidate bytes without rebuilding"]
    for line in workflow.splitlines():
        if (
            "release/scripts/build-release-binaries.sh" in line
            or "release/scripts/build-release-image.sh" in line
        ) and "sha256sum" not in line:
            return ["Promotion consumes candidate bytes without rebuilding"]
    return []


def nested_workflow_paths(paths: list[str]) -> list[str]:
    """Return tracked workflows that GitHub cannot run from the repository root."""

    return sorted(
        path
        for path in paths
        if "/.github/workflows/" in f"/{path}"
        and not path.startswith(".github/workflows/")
    )


def release_unit_test_paths(root: Path) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for path in (root / "release" / "scripts").glob("test_*.py")
        if path.is_file()
    )


def unwired_release_unit_tests(workflow_text: str, paths: list[str]) -> list[str]:
    return [
        path for path in paths if f"python3 -m unittest {path}" not in workflow_text
    ]


def policy_file_texts(root: Path, paths: tuple[str, ...]) -> dict[str, str]:
    texts: dict[str, str] = {}
    for path in paths:
        file_path = root / path
        if file_path.is_file():
            texts[path] = file_path.read_text(encoding="utf-8")
    return texts


def tracked_paths(root: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [path.decode("utf-8") for path in completed.stdout.split(b"\0") if path]


def main() -> int:
    workflow_text = CI_WORKFLOW.read_text(encoding="utf-8")
    missing = missing_gates(workflow_text)
    nested = nested_workflow_paths(tracked_paths(ROOT))
    unwired_tests = unwired_release_unit_tests(
        workflow_text,
        release_unit_test_paths(ROOT),
    )
    policy_violations = workflow_policy_violations(
        policy_file_texts(ROOT, RELEASE_SECURITY_POLICY_PATHS),
        required=REQUIRED_RELEASE_SECURITY_GATES,
        ordered=ORDERED_RELEASE_SECURITY_GATES,
        forbidden=FORBIDDEN_RELEASE_SECURITY_GATES,
    )
    policy_texts = policy_file_texts(ROOT, RELEASE_SECURITY_POLICY_PATHS)
    policy_violations.extend(
        candidate_build_isolation_violations(
            policy_texts.get(".github/workflows/release-candidate.yml")
        )
    )
    policy_violations.extend(
        candidate_attestation_isolation_violations(
            policy_texts.get(".github/workflows/release-candidate.yml")
        )
    )
    policy_violations.extend(
        artifact_retention_violations(
            policy_texts.get(".github/workflows/release-candidate.yml")
        )
    )
    policy_violations.extend(
        promotion_rebuild_violations(policy_texts.get(".github/workflows/release.yml"))
    )
    policy_violations.extend(
        promotion_first_write_barrier_violations(
            policy_texts.get(".github/workflows/release.yml")
        )
    )
    if missing or nested or unwired_tests or policy_violations:
        print("gate inventory check failed", file=sys.stderr)
    if missing:
        print("missing root CI wiring:", file=sys.stderr)
        for gate in missing:
            print(f"- {gate}", file=sys.stderr)
    if nested:
        print(
            "nested workflows are inert and must move to root CI or be removed:",
            file=sys.stderr,
        )
        for path in nested:
            print(f"- {path}", file=sys.stderr)
    if unwired_tests:
        print("release unit tests missing from root CI:", file=sys.stderr)
        for path in unwired_tests:
            print(f"- {path}", file=sys.stderr)
    if policy_violations:
        print("release security workflow policy violations:", file=sys.stderr)
        for gate in policy_violations:
            print(f"- {gate}", file=sys.stderr)
    if missing or nested or unwired_tests or policy_violations:
        return 1
    declared_gate_count = (
        len(REQUIRED_GATES)
        + len(REQUIRED_RELEASE_SECURITY_GATES)
        + len(ORDERED_RELEASE_SECURITY_GATES)
        + len(FORBIDDEN_RELEASE_SECURITY_GATES)
        + 5  # Structural isolation, retention, rebuild, and destination gates.
    )
    print(
        f"gate inventory check passed for {declared_gate_count} gates; "
        "no inert nested workflows"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
