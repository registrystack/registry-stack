#!/usr/bin/env python3
"""Assert that declared RegistryStack gates are wired into root CI."""

from __future__ import annotations

import runpy
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
        '".github/workflows/release.yml": frozenset(',
    ),
    (
        "Evidence development workflow change classification",
        '".github/workflows/evidence-dev.yml": frozenset(',
    ),
    (
        "Release candidate workflow change classification",
        '".github/workflows/release-candidate.yml": frozenset(',
    ),
    (
        "Release repeatability workflow change classification",
        '".github/workflows/release-repeatability.yml": frozenset(',
    ),
    (
        "Release candidate cleanup workflow change classification",
        '".github/workflows/release-candidate-cleanup.yml": frozenset(',
    ),
    (
        "Release rehearsal workflow change classification",
        '".github/workflows/release-rehearsal.yml": frozenset(',
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
        "Debian 13 image contract",
        "run: python3 release/scripts/check-debian13-images.py",
    ),
    (
        "Advisory exposure policy tests",
        "run: python3 -m unittest release/scripts/test_check_advisory_baselines.py",
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
        "Platform hygiene path filter",
        "platform_hygiene: ${{ steps.filter.outputs.platform_hygiene }}",
    ),
    ("Platform coverage job", "platform-coverage:"),
    ("Platform coverage version pin", 'CARGO_LLVM_COV_VERSION: "0.8.7"'),
    ("Platform coverage threshold", "--fail-under-lines 80"),
    (
        "Platform hygiene alignment",
        "run: products/platform/scripts/check-hygiene-alignment.sh",
    ),
    ("Secret scan job", "secrets:"),
    ("Gitleaks version pin", 'GITLEAKS_VERSION: "8.30.1"'),
    ("Gitleaks archive checksum", "GITLEAKS_LINUX_X64_SHA256:"),
    ("Gitleaks root config", "--config .gitleaks.toml"),
    ("Gitleaks redaction", "--redact"),
    ("Platform fuzz job", "platform-fuzz:"),
    ("Platform fuzz version pin", 'CARGO_FUZZ_VERSION: "0.13.2"'),
    ("Platform fuzz bounded runtime", "-max_total_time=60"),
    (
        "Platform fuzz directory",
        "cargo +nightly fuzz run --fuzz-dir fuzz",
    ),
    ("Evidence contract gate", "evidence-contracts:"),
    (
        "Evidence contract reproduction",
        "run: products/evidence/scripts/check-contracts.sh",
    ),
    (
        "Evidence source neutrality",
        "run: products/evidence/scripts/check-source-neutrality.sh",
    ),
    (
        "Evidence verifier portability",
        "run: products/evidence/scripts/check-verifier-portability.sh",
    ),
    ("Relay V2 product contract gate", "relay-v2-contracts:"),
    (
        "Relay V2 contract consistency",
        "run: products/relay-v2/scripts/check-contracts.sh",
    ),
    (
        "Relay V2 coequal HTTP journeys",
        "run: products/relay-v2/scripts/test-http.sh",
    ),
    ("Relay client contract gate", "relay-client-contracts:"),
    (
        "Relay client contract consistency",
        "run: products/relay-v2/scripts/check-client-contract.sh",
    ),
    (
        "Relay client source neutrality",
        "run: products/relay-v2/scripts/check-source-neutrality.sh",
    ),
    ("Base Registry Engine product contract gate", "breg-contracts:"),
    (
        "Base Registry Engine contract consistency",
        "run: products/breg/scripts/check-contracts.sh",
    ),
    (
        "BReg client contract consistency",
        "run: products/breg/scripts/check-client-contract.sh",
    ),
    (
        "Base Registry Engine PostgreSQL journeys",
        "run: products/breg/scripts/test-postgres.sh",
    ),
    (
        "Base Registry Engine adopter workflow",
        "run: products/breg/scripts/test-adopter-workflow.sh",
    ),
    (
        "Base Registry Engine PostgreSQL 17 / PostGIS 3.5 image pin",
        "postgis/postgis@sha256:01a6a70e41e6c4467c8f55f6063555ed72db2d6662cd0d571040d42eadaeb6f6",
    ),
    (
        "Release Linux Node client path filter",
        "release_linux_node_clients: ${{ steps.filter.outputs.release_linux_node_clients }}",
    ),
    (
        "Release Linux Node client proof job",
        "release-linux-node-clients:\n    name: Release Linux Node clients",
    ),
    (
        "Release Linux Node client helper invocation",
        "release/scripts/build-linux-node-client \\",
    ),
    (
        # The Evidence tutorial job installs maturin from the same pinned
        # requirements file, so this gate names the step that owns the Linux
        # Node client copy and stays blind to the other one.
        "Release Linux Node client pinned tools",
        "      - name: Install pinned Linux client build tools\n"
        "        shell: bash\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        "          rustup toolchain install 1.95.0 --profile minimal\n"
        '          python3 -m venv "${RUNNER_TEMP}/maturin"\n'
        '          "${RUNNER_TEMP}/maturin/bin/pip" install --quiet \\\n'
        "            --require-hashes --only-binary=:all: \\\n"
        '            --requirement "${GITHUB_WORKSPACE}/release/requirements/maturin-1.9.6.txt"',
    ),
    (
        "Release Linux Node client CI aggregate",
        "      - release-linux-node-clients",
    ),
    (
        "Unified Node client ESM entry point smoke",
        '(cd "${smoke}" && node smoke-registry-client-package.mjs)',
    ),
    (
        "Release helper tests",
        "run: python3 -m unittest release/scripts/test_registry_release.py",
    ),
    (
        "Release planning command tests",
        "run: python3 -m unittest release/scripts/test_registry_release_plans.py",
    ),
    (
        "Release candidate manifest and promotion verifier tests",
        "run: python3 -m unittest release/scripts/test_release_candidate.py",
    ),
    (
        "Public release verifier tests",
        "run: python3 -m unittest release/scripts/test_verify_public_release.py",
    ),
    (
        "Client registry reconciliation tests",
        "run: python3 -m unittest release/scripts/test_client_registry.py",
    ),
    (
        "Unified Python wheel assembly tests",
        "run: python3 -m unittest release/scripts/test_assemble_registry_client_wheel.py",
    ),
    (
        "Local client package assembly tests",
        "run: python3 -m unittest release/scripts/test_assemble_registry_client_packages.py",
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
        "Release rehearsal workflow tests",
        "run: python3 -m unittest release/scripts/test_release_rehearsal.py",
    ),
    (
        "Linux Node client release build helper tests",
        "run: python3 -m unittest release/scripts/test_build_linux_node_client.py",
    ),
    (
        "Zig glibc compiler wrapper tests",
        "run: python3 -m unittest release/scripts/test_zig_glibc_compiler.py",
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
        "Container runtime preflight tests",
        "run: python3 -m unittest docker/test_runtime_preflight.py",
    ),
    (
        "Release image OCI label smoke",
        "run: release/scripts/smoke-release-image-oci-labels.sh",
    ),
    (
        "Release image layout comparator tests",
        "run: python3 -m unittest release/scripts/test_compare_release_image_layouts.py",
    ),
    (
        "Release manifest validation",
        "release/scripts/registry-release validate-current",
    ),
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
        "Stable error registry path filter",
        '"docs/site/src/content/docs/reference/errors.mdx",',
    ),
    (
        "Relay V2 product document path filter",
        '"products/relay-v2/CONCEPT.md",',
    ),
    ("Docs dependency install", "run: npm ci"),
    ("Docs tests", "run: npm test"),
    ("Production-shaped docs build check", "run: npm run check:production"),
    (
        "Base Registry Engine tutorial replay",
        "bash docs/site/scripts/check-breg-tutorial.sh",
    ),
    (
        "Base Registry Engine tutorial command drift",
        "run: npm run check:tutorial:breg:dry-run",
    ),
    (
        "Base Registry Engine tutorial path filter",
        '"docs/site/scripts/check-breg-tutorial.sh",',
    ),
)

RELEASE_SECURITY_POLICY_PATHS = (
    ".github/workflows/codeql.yml",
    ".github/workflows/docs-pages.yml",
    ".github/workflows/evidence-dev.yml",
    ".github/workflows/nightly-rust-coverage.yml",
    ".github/workflows/nightly-security.yml",
    ".github/workflows/release.yml",
    ".github/workflows/release-candidate.yml",
    ".github/workflows/release-canary.yml",
    ".github/workflows/release-repeatability.yml",
    ".github/workflows/release-candidate-cleanup.yml",
    ".github/workflows/release-rehearsal.yml",
    ".github/workflows/scorecard.yml",
    "release/scripts/release_candidate.py",
    "release/scripts/cleanup-release-candidates.py",
    "release/scripts/verify_latest_published_release.py",
    "release/scripts/verify_public_release.py",
)

REQUIRED_SECURITY_WORKFLOW_SELECTIONS: dict[str, frozenset[str]] = {
    ".github/workflows/codeql.yml": frozenset({"release_tool"}),
    ".github/workflows/docs-pages.yml": frozenset(
        {"docs", "release_source_proof", "release_tool"}
    ),
    ".github/workflows/evidence-dev.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/nightly-security.yml": frozenset(
        {"platform", "release_tool"}
    ),
    ".github/workflows/nightly-rust-coverage.yml": frozenset(
        {"platform", "release_tool"}
    ),
    ".github/workflows/release.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/release-candidate.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/release-canary.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/release-repeatability.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/release-candidate-cleanup.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/release-rehearsal.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/scorecard.yml": frozenset({"release_tool"}),
}

REQUIRED_NIGHTLY_FUZZ_TARGETS: dict[str, tuple[str, ...]] = {
    "platform-fuzz": (
        "authcommon_parsers",
        "sdjwt_holder_proof",
        "sdjwt_issuance",
        "sqlite_statement",
    ),
    "manifest-fuzz": (
        "metadata_manifest_yaml",
        "rendered_artifact_json",
    ),
}

# The compact v2 release contract is the active release inventory.
REQUIRED_RELEASE_SECURITY_GATES = (
    (
        "CodeQL security-and-quality analysis",
        ".github/workflows/codeql.yml",
        (
            "pull_request:",
            "security-events: write",
            "github/codeql-action/init@",
            "queries: security-and-quality",
            "github/codeql-action/analyze@",
        ),
    ),
    (
        "Scheduled and manual security assurance sweep",
        ".github/workflows/nightly-security.yml",
        (
            "schedule:",
            "workflow_dispatch:",
            "name: Security assurance manifests",
            "name: Platform fuzz smoke",
            "name: Manifest fuzz smoke",
        ),
    ),
    (
        "Scheduled and manual Rust coverage upload",
        ".github/workflows/nightly-rust-coverage.yml",
        (
            "schedule:",
            "workflow_dispatch:",
            "name: Plan Rust coverage shards",
            "name: Rust coverage (${{ matrix.name }})",
            "id-token: write",
            "uses: codecov/codecov-action@",
            "use_oidc: true",
        ),
    ),
    (
        "Scheduled and manual Scorecard analysis",
        ".github/workflows/scorecard.yml",
        (
            "schedule:",
            "workflow_dispatch:",
            "id-token: write",
            "uses: ossf/scorecard-action@",
            "publish_results: true",
        ),
    ),
    (
        "Protected-main Evidence development prerelease",
        ".github/workflows/evidence-dev.yml",
        (
            "workflow_dispatch:",
            '"${GITHUB_REF}" != refs/heads/main',
            "name: Validate manual source and successful CI",
            "actions/workflows/ci.yml/runs?head_sha=${GITHUB_SHA}&status=success",
            'tag="v${version}-dev.${GITHUB_RUN_ID}.${GITHUB_RUN_ATTEMPT}"',
            "name: Smoke the development installer before publication",
            "name: Reverify the closed development asset roster",
            "name: Publish unique development prerelease",
            '--target "${source_sha}"',
            "--prerelease",
            "--latest=false",
        ),
    ),
    (
        "Protected-main candidate-bound annotated tag promotion",
        ".github/workflows/release.yml",
        (
            "workflow_dispatch:",
            "tag:",
            '"${GITHUB_REF}" != refs/heads/main',
            "name: Resolve exact tag identity",
            'if [[ "$(git cat-file -t "refs/tags/${tag}")" != tag ]]; then',
            "git merge-base --is-ancestor",
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
            "name: Verify binding, candidate, and attestations",
            "verify-tag-binding",
            "gh attestation verify",
        ),
    ),
    (
        "Draft-first exact staged publication",
        ".github/workflows/release.yml",
        (
            "stage-draft:\n    name: Create or reconcile the bound draft",
            "name: Reverify and stage exact candidate payloads",
            "gh release create",
            "--draft",
            "name: Upload draft reconciliation contract",
        ),
    ),
    (
        "Retryable exact image promotion",
        ".github/workflows/release.yml",
        (
            "promote-images:\n    name: Reconcile staged draft, then promote exact image manifests",
            "name: Reconcile exact staged draft before first public image write",
            "diff -u contract/expected-assets contract/actual-assets",
            "name: Reconcile exact image digests",
            "require-package-visibility",
            "--visibility public",
            "reconcile-image-tag",
            '--expected-digest "${digest}"',
            'if [[ "${state}" == absent ]]; then',
            'crane copy "${candidate_ref}" "${final_ref}"',
            'test "$(crane digest "${final_ref}")" = "${digest}"',
        ),
    ),
    (
        "Final signed Beta release closure",
        ".github/workflows/release.yml",
        (
            "finalize-assets:\n    name: Finalize the signed Beta asset closure",
            "name: Clean retryable final additions and reverify exact staged assets",
            "name: Sign and upload the checksum closure",
            "cosign sign-blob --yes",
            "contract/final-upload-release.json",
            "name: Upload final reconciliation contract",
        ),
    ),
    (
        "Exact Beta release publication",
        ".github/workflows/release.yml",
        (
            "name: Classify exact bound draft or published release",
            "name: Recheck complete signed release and exact public images",
            "name: Publish immutable release",
            "-F draft=false",
            "-F prerelease=false",
        ),
    ),
    (
        "Authenticated docs promotion dispatch",
        ".github/workflows/release.yml",
        (
            "dispatch-docs:\n    name: Dispatch authenticated docs promotion",
            "needs.verify.outputs.docs_sha256 != ''",
            "name: Dispatch authenticated docs promotion",
            '-f "released_tag=${{ needs.verify.outputs.tag }}"',
            '-f "docs_sha256=${{ needs.verify.outputs.docs_sha256 }}"',
        ),
    ),
    (
        "Client trusted registry promotion",
        ".github/workflows/release.yml",
        (
            "publish_client_npm:",
            "publish_client_pypi:",
            "matrix: ${{ fromJSON(needs.verify.outputs.client_registry_matrix) }}",
            "matrix: ${{ fromJSON(needs.verify.outputs.client_registry_pypi_matrix) }}",
            "id-token: write",
            "environment: npm",
            '{"client": "evidence", "environment": "pypi-evidence"}',
            '{"client": "relay", "environment": "pypi"}',
            '{"client": "stack", "environment": "pypi"}',
            '"registrystack-client-${version}.tgz"',
            "client_registry.py npm-state",
            "client_registry.py pypi-state",
            "npm publish",
            "pypa/gh-action-pypi-publish@",
        ),
    ),
    (
        "Latest docs-bearing release deployment on main",
        ".github/workflows/docs-pages.yml",
        (
            "name: Authenticate public release and checksum inventory",
            '"repos/${GITHUB_REPOSITORY}/releases?per_page=100"',
            "python3 release/scripts/verify_latest_published_release.py",
            "name: Recheck latest published docs release immediately before deployment",
            "name: Deploy to GitHub Pages",
        ),
    ),
    (
        "Released docset selector gated on the published release",
        ".github/workflows/docs-pages.yml",
        (
            "name: Resolve latest published docs release",
            "name: Gate the released docset selector on the published release",
            "release/scripts/registry-release validate-docsets \\",
            '--published-releases "${PUBLISHED_RELEASES}"',
        ),
    ),
    (
        "Nonpublishing future-tag release rehearsal",
        ".github/workflows/release-rehearsal.yml",
        (
            "workflow_dispatch:",
            "name: Exercise future-tag release paths on Ubuntu",
            "runs-on: ubuntu-24.04",
            "name: Rehearse prepared release without publishing",
            "release/scripts/rehearse-release",
            "--base-ref origin/main",
        ),
    ),
    (
        "Candidate image onboarding bootstrap boundary",
        ".github/workflows/release-candidate.yml",
        (
            "name: Validate manifests, pins, recipes, and scanner policy fixtures",
            "release_candidate.py check-image-onboarding",
            "--allow-missing-baseline",
        ),
    ),
    (
        "Strict rehearsal image onboarding boundary",
        ".github/workflows/release-rehearsal.yml",
        (
            "validate:\n    name: Validate release image onboarding before builds",
            "name: Check complete release image onboarding",
            "release_candidate.py check-image-onboarding",
            "needs: validate",
        ),
    ),
    (
        "Latest docs release metadata fails closed",
        "release/scripts/verify_latest_published_release.py",
        (
            'if value.get("draft") is not False or value.get("prerelease") is not False:',
            "if len(matches) != 1:",
            "if expected_tag is not None and tag != expected_tag:",
            "is stale; latest published ",
        ),
    ),
    (
        "Protected candidate request and pure validation",
        ".github/workflows/release-candidate.yml",
        (
            "repository_dispatch:\n    types: [release_candidate]",
            "run-name: Release candidate ${{ github.event.client_payload.release_id }}",
            "REQUEST_ID: ${{ github.event.client_payload.request_id }}",
            "name: Validate request, source, CI, and destinations",
            "git merge-base --is-ancestor",
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
            "build-canonical:\n    name: Build Linux payload and private images once",
            "name: Restore reusable Cargo cache",
            "restore-keys:",
            "name: Build canonical Linux payload once",
            "name: Build private candidate image layouts once",
        ),
    ),
    (
        "Private exact candidate images and advisory gate",
        ".github/workflows/release-candidate.yml",
        (
            "name: Verify local image layouts before package credentials are used",
            "name: Publish exact layouts to private candidate packages",
            "--from-oci-layout",
            "require-package-visibility",
            "--visibility private",
            "name: Verify and scan exact candidate images",
            'scan_image \\\n              "${candidate_ref}"',
            "SYFT_FILE_METADATA_SELECTION=all",
            'crane config "${candidate_ref}"',
            "candidate/security/oci-config/${name}.json",
            '(.rootfs.diff_ids | type) == "array"',
            '.rootfs.diff_ids | length > 0',
            'crane export "${candidate_ref}" -',
            "check-advisory-baselines.py",
            '--rootfs "candidate/security/rootfs/${name}"',
            '--candidate-image-digest "${digest}"',
            '--source-revision "${{ needs.validate.outputs.source_sha }}"',
            '--oci-config "candidate/security/oci-config/${name}.json"',
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
            "retention-days: 8",
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
        "Scheduled protected candidate cleanup trigger",
        ".github/workflows/release-candidate-cleanup.yml",
        (
            "schedule:",
            "repository_dispatch:\n    types: [release-candidate-cleanup]",
            "name: Delete candidate versions older than eight days",
        ),
    ),
    (
        "Candidate cleanup exact package allowlist",
        "release/scripts/cleanup-release-candidates.py",
        (
            'CANDIDATE_PACKAGES = (\n    # Listing an absent package fails closed, so a candidate name joins this\n    # allowlist with the release that first publishes it.\n    "breg-candidate",\n    "discovery-candidate",\n    "evidence-candidate",\n    "mint-candidate",\n    "relay-candidate",\n)',
            'PUBLIC_PACKAGES = (\n    # Retired public names stay denylisted so cleanup can never delete history.',
            '    "discovery",\n',
            '    "evidence",\n',
            '    "mint",\n',
            '    "breg",\n',
            '    "relay",\n',
            "if package in PUBLIC_PACKAGES:",
            "if package not in CANDIDATE_PACKAGES:",
        ),
    ),
)

ORDERED_RELEASE_SECURITY_GATES = (
    (
        "Evidence development smoke before publication permission",
        ".github/workflows/evidence-dev.yml",
        "name: Smoke the development installer before publication",
        "publish:\n    name: Publish unique Evidence development prerelease",
    ),
    (
        "Latest docs release recheck immediately before docs deployment",
        ".github/workflows/docs-pages.yml",
        "name: Recheck latest published docs release immediately before deployment",
        "name: Deploy to GitHub Pages",
    ),
    (
        "Promotion binding before candidate verification",
        ".github/workflows/release.yml",
        "name: Parse compact candidate binding",
        "name: Verify binding, candidate, and attestations",
    ),
    (
        "Candidate verification before draft creation",
        ".github/workflows/release.yml",
        "name: Reverify and stage exact candidate payloads",
        "name: Reconcile bound draft and upload exact staged inventory",
    ),
    (
        "Draft reconciliation before image promotion",
        ".github/workflows/release.yml",
        "name: Reconcile exact staged draft before first public image write",
        "name: Reconcile exact image digests",
    ),
    (
        "Exact image promotion before checksum signing",
        ".github/workflows/release.yml",
        "name: Reconcile exact image digests",
        "name: Sign and upload the checksum closure",
    ),
    (
        "Exact image promotion before release publication",
        ".github/workflows/release.yml",
        "name: Reconcile exact image digests",
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
        "build-canonical:\n    name: Build Linux payload and private images once",
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
        "CodeQL cannot gain OIDC or repository write permission",
        ".github/workflows/codeql.yml",
        ("id-token: write", "contents: write", "packages: write"),
    ),
    (
        "Nightly security assurance cannot gain publication permission",
        ".github/workflows/nightly-security.yml",
        (
            "id-token: write",
            "contents: write",
            "packages: write",
            "attestations: write",
        ),
    ),
    (
        "Nightly Rust coverage cannot run pull-request code or publish repository state",
        ".github/workflows/nightly-rust-coverage.yml",
        (
            "pull_request:",
            "push:",
            "repository_dispatch:",
            "contents: write",
            "packages: write",
            "attestations: write",
            "security-events: write",
        ),
    ),
    (
        "Scorecard cannot run pull-request code or write repository state",
        ".github/workflows/scorecard.yml",
        ("push:", "pull_request:", "contents: write", "packages: write"),
    ),
    (
        "Evidence development publication cannot mutate an existing release or use branch workflow code",
        ".github/workflows/evidence-dev.yml",
        (
            "push:",
            "pull_request:",
            "schedule:",
            "repository_dispatch:",
            "gh release upload",
            "gh release delete",
            "--clobber",
            "git push",
            "git update-ref",
            "/git/refs",
            "packages: write",
            "id-token: write",
            "attestations: write",
        ),
    ),
    (
        "Promotion cannot rebuild product bytes or write refs",
        ".github/workflows/release.yml",
        (
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
    (
        "Release rehearsal cannot allow a missing advisory baseline",
        ".github/workflows/release-rehearsal.yml",
        ("--allow-missing-baseline",),
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


def security_workflow_classification_violations(
    policy_paths: tuple[str, ...],
    selections: dict[str, frozenset[str]],
) -> list[str]:
    """Keep the policy workflow inventory and CI classifier in exact parity."""

    gate = "Security workflow policy classification inventory"
    policy_workflows = {
        path for path in policy_paths if path.startswith(".github/workflows/")
    }
    if (
        policy_workflows != set(REQUIRED_SECURITY_WORKFLOW_SELECTIONS)
        or selections != REQUIRED_SECURITY_WORKFLOW_SELECTIONS
    ):
        return [gate]
    return []


def classifier_security_workflow_gates() -> dict[str, frozenset[str]]:
    """Load the classifier's declarative table without running its CLI."""

    value = runpy.run_path(str(CI_CLASSIFIER)).get("SECURITY_WORKFLOW_GATES")
    if not isinstance(value, dict):
        return {}
    return value


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


def shell_loop_targets(job: str) -> tuple[str, ...]:
    """Return the ordered target names from the nightly fuzz shell loop."""

    start_marker = "          for target in \\\n"
    end_marker = "\n          do"
    if job.count(start_marker) != 1:
        return ()
    target_block = job.split(start_marker, 1)[1].split(end_marker, 1)
    if len(target_block) != 2:
        return ()
    targets = tuple(
        line.strip().removesuffix("\\").strip()
        for line in target_block[0].splitlines()
    )
    if not targets or any(not target or " " in target for target in targets):
        return ()
    return targets


def nightly_security_sweep_violations(workflow: str | None) -> list[str]:
    """Require every scheduled/manual security sweep to run its full roster."""

    gate = "Nightly security sweep completeness"
    if workflow is None:
        return [gate]

    jobs = {
        job_id: yaml_job_block(workflow, job_id)
        for job_id in ("assurance", *REQUIRED_NIGHTLY_FUZZ_TARGETS)
    }
    path_suppression_markers = (
        "\n  changes:",
        "\n  save-state:",
        "needs.changes.outputs.run",
        ".nightly-security-state",
        "is_relevant_path",
        "last-success-sha",
    )
    if any(job is None for job in jobs.values()) or any(
        marker in workflow for marker in path_suppression_markers
    ):
        return [gate]
    if any(
        "\n    needs:" in job or "\n    if:" in job
        for job in jobs.values()
        if job is not None
    ):
        return [gate]
    if any(
        shell_loop_targets(jobs[job_id] or "") != required_targets
        for job_id, required_targets in REQUIRED_NIGHTLY_FUZZ_TARGETS.items()
    ):
        return [gate]
    return []


def platform_coverage_oidc_isolation_violations(workflow: str | None) -> list[str]:
    """Confine coverage OIDC upload to an exact protected-main push."""

    gate = "Platform coverage OIDC permission isolation"
    if workflow is None:
        return [gate]
    coverage = yaml_job_block(workflow, "platform-coverage")
    upload = yaml_job_block(workflow, "platform-coverage-upload")
    aggregate = yaml_job_block(workflow, "ci-result")
    if coverage is None or upload is None or aggregate is None:
        return [gate]

    upload_permissions = (
        "    permissions:\n"
        "      actions: read\n"
        "      contents: read\n"
        "      id-token: write"
    )
    permission_block = upload.split("    permissions:\n", 1)
    upload_permission_lines = (
        permission_block[1].split("\n    steps:", 1)[0]
        if len(permission_block) == 2
        else ""
    )
    steps_block = upload.split("\n    steps:\n", 1)
    upload_steps_text = steps_block[1] if len(steps_block) == 2 else ""
    upload_steps = yaml_step_blocks(upload)
    coverage_steps = yaml_step_blocks(coverage)
    staging_step = next(
        (
            step
            for step in coverage_steps
            if "name: Stage platform coverage for trusted upload" in step
        ),
        "",
    )
    protected_push = "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    if (
        "id-token: write" in coverage
        or "permissions: write-all" in workflow
        or f"        if: {protected_push}\n" not in staging_step
        or "actions/upload-artifact@" not in staging_step
        or "retention-days: 1" not in staging_step
        or "needs:\n      - changes\n      - platform-coverage" not in upload
        or f"    if: {protected_push} && needs.changes.outputs.platform == 'true'\n"
        not in upload
        or upload_permissions not in upload
        or upload_permission_lines
        != "      actions: read\n      contents: read\n      id-token: write"
        or upload_steps_text.count("\n      - ") != 1
        or not upload_steps_text.startswith("      - ")
        or upload_steps_text.count("        uses:") != 2
        or len(upload_steps) != 2
        or "uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
        not in upload_steps[0]
        or "uses: codecov/codecov-action@fb8b3582c8e4def4969c97caa2f19720cb33a72f"
        not in upload_steps[1]
        or "use_oidc: true" not in upload_steps[1]
        or "actions/checkout@" in upload
        or "        run:" in upload
        or workflow.count("id-token: write") != upload.count("id-token: write")
        or "      - platform-coverage-upload" not in aggregate
    ):
        return [gate]
    return []


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
    """Allow only an absent destination or the already-promoted exact digest."""

    gate = "Promotion first-write destination barrier"
    if workflow is None:
        return [gate]
    publish = yaml_job_block(workflow, "promote-images")
    if publish is None:
        return [gate]
    promotion_steps = [
        step
        for step in yaml_step_blocks(publish)
        if "name: Reconcile exact image digests" in step
    ]
    if len(promotion_steps) != 1:
        return [gate]
    promotion_step = promotion_steps[0]
    promotion_required = (
        "name: Reconcile exact image digests",
        "while IFS=$'\\t' read -r candidate_ref digest final_ref; do",
        'test "$(crane digest "${candidate_ref}")" = "${digest}"',
        "gh api --paginate --slurp",
        "reconcile-image-tag",
        '--expected-digest "${digest}"',
        'if [[ "${state}" == absent ]]; then',
        'test "${state}" = present',
        'crane copy "${candidate_ref}" "${final_ref}"',
        'test "$(crane digest "${final_ref}")" = "${digest}"',
        "[.candidate_ref,.digest,.final_ref] | @tsv",
    )
    publish_required = (
        "name: Reconcile exact staged draft before first public image write",
        "name: Log in for exact candidate promotion",
    )
    source_check = 'test "$(crane digest "${candidate_ref}")" = "${digest}"'
    reconcile = "reconcile-image-tag"
    absent_branch = 'if [[ "${state}" == absent ]]; then'
    first_write = 'crane copy "${candidate_ref}" "${final_ref}"'
    final_check = 'test "$(crane digest "${final_ref}")" = "${digest}"'
    if (
        any(marker not in promotion_step for marker in promotion_required)
        or any(marker not in publish for marker in publish_required)
        or promotion_step.find(source_check)
        >= promotion_step.find(reconcile)
        or promotion_step.find(reconcile)
        >= promotion_step.find(absent_branch)
        or promotion_step.find(absent_branch)
        >= promotion_step.find(first_write)
        or promotion_step.find(first_write)
        >= promotion_step.find(final_check)
    ):
        return [gate]
    return []


def release_draft_mutation_barrier_violations(
    workflow: str | None,
) -> list[str]:
    """Require every final release mutation to target the bound draft."""

    gate = "Final release mutations require the bound draft"
    if workflow is None:
        return [gate]
    finalize = yaml_job_block(workflow, "finalize-assets")
    publish = yaml_job_block(workflow, "publish")
    if finalize is None or publish is None:
        return [gate]

    def step_with(job: str, marker: str) -> str | None:
        matches = [step for step in yaml_step_blocks(job) if marker in step]
        return matches[0] if len(matches) == 1 else None

    cleanup = step_with(
        finalize,
        "name: Clean retryable final additions and reverify exact staged assets",
    )
    final_upload = step_with(
        finalize,
        "name: Sign and upload the checksum closure",
    )
    classification = step_with(
        publish,
        "name: Classify exact bound draft or published release",
    )
    signed_recheck = step_with(
        publish,
        "name: Recheck complete signed release and exact public images",
    )
    publication = step_with(publish, "name: Publish immutable release")
    if any(
        step is None
        for step in (
            cleanup,
            final_upload,
            classification,
            signed_recheck,
            publication,
        )
    ):
        return [gate]
    assert cleanup is not None
    assert final_upload is not None
    assert classification is not None
    assert signed_recheck is not None
    assert publication is not None

    cleanup_loop = cleanup.find("while IFS= read -r name; do")
    cleanup_guard = cleanup.find("require_bound_draft", cleanup_loop)
    cleanup_delete = cleanup.find("gh api --method DELETE", cleanup_guard)
    final_upload_guard = final_upload.find("contract/final-upload-release.json")
    final_upload_write = final_upload.find(
        'gh release upload "${tag}" "${additions[@]}"'
    )
    publication_state = publication.find("publish-state.json")
    publication_draft = publication.find(".draft == true", publication_state)
    publication_draft_branch = publication.find(
        'if [[ "${EXPECTED_RELEASE_STATE}" == draft ]]; then',
        publication_draft,
    )
    publication_patch = publication.find(
        "gh api --method PATCH",
        publication_draft_branch,
    )
    mutations = (
        "gh release upload",
        "gh api --method DELETE",
        'crane copy "${candidate_ref}" "${final_ref}"',
    )
    if (
        cleanup_loop < 0
        or cleanup_guard < cleanup_loop
        or cleanup_delete < cleanup_guard
        or ".draft == true" not in cleanup
        or final_upload_guard < 0
        or final_upload_write < final_upload_guard
        or ".draft == true" not in final_upload[
            final_upload_guard:final_upload_write
        ]
        or "id: release_state" not in classification
        or '["draft", (.id | tostring)]' not in classification
        or '["published", (.id | tostring)]' not in classification
        or ".draft == true" not in classification
        or ".draft == false" not in classification
        or ".published_at == null" not in classification
        or '(.published_at | type == "string"' not in classification
        or any(mutation in classification for mutation in mutations)
        or ".draft == true" not in signed_recheck
        or ".draft == false" not in signed_recheck
        or '$release_state == "draft"' not in signed_recheck
        or '$release_state == "published"' not in signed_recheck
        or '(.draft | type) == "boolean"' in signed_recheck
        or any(mutation in signed_recheck for mutation in mutations)
        or publication_state < 0
        or publication_draft < publication_state
        or publication_draft_branch < publication_draft
        or publication_patch < publication_draft_branch
        or publication.count("gh api --method PATCH") != 1
        or '$release_state == "published"' not in publication
        or any(mutation in publication for mutation in mutations)
        or "is_draft" in publication
        or '(.draft | type) == "boolean"' in publication
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
        or "retention-days: 8" not in final_steps[0]
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
    policy_violations.extend(
        security_workflow_classification_violations(
            RELEASE_SECURITY_POLICY_PATHS,
            classifier_security_workflow_gates(),
        )
    )
    policy_texts = policy_file_texts(ROOT, RELEASE_SECURITY_POLICY_PATHS)
    policy_violations.extend(
        platform_coverage_oidc_isolation_violations(workflow_text)
    )
    policy_violations.extend(
        nightly_security_sweep_violations(
            policy_texts.get(".github/workflows/nightly-security.yml")
        )
    )
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
    policy_violations.extend(
        release_draft_mutation_barrier_violations(
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
        + len(REQUIRED_SECURITY_WORKFLOW_SELECTIONS)
        + 7  # Structural permission, sweep, isolation, retention, rebuild, and destination gates.
    )
    print(
        f"gate inventory check passed for {declared_gate_count} gates; "
        "no inert nested workflows"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
