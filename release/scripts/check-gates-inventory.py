#!/usr/bin/env python3
"""Assert that declared RegistryStack gates are wired into root CI."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

REQUIRED_GATES: tuple[tuple[str, str], ...] = (
    ("Cargo metadata", "run: cargo metadata --locked --format-version 1"),
    (
        "Manifest profile validation",
        "run: cargo run --locked -p registry-manifest-cli -- validate-profiles profiles",
    ),
    ("Format", "run: cargo fmt --check"),
    ("Workspace check", "run: cargo check --locked --workspace --all-targets"),
    ("Clippy", "run: cargo clippy --workspace --all-targets -- -D warnings"),
    ("Workspace tests", "run: cargo test --locked --workspace"),
    (
        "Relay all-features tests",
        "run: cargo test --locked -p registry-relay --all-features",
    ),
    ("Cargo deny", "run: cargo deny check"),
    (
        "Platform path filter",
        "platform: ${{ steps.filter.outputs.platform }}",
    ),
    (
        "Config report platform path",
        "crates/registry-config-report/*|crates/registry-platform-*",
    ),
    (
        "Platform hygiene path filter",
        "platform_hygiene: ${{ steps.filter.outputs.platform_hygiene }}",
    ),
    (
        "Platform all-features build",
        "run: cargo build --locked -p registry-config-report -p 'registry-platform-*' --all-targets --all-features",
    ),
    (
        "Platform all-features clippy",
        "run: cargo clippy --locked -p registry-config-report -p 'registry-platform-*' --all-targets --all-features -- -D warnings",
    ),
    (
        "Platform all-features tests",
        "run: cargo test --locked -p registry-config-report -p 'registry-platform-*' --all-targets --all-features",
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
    ("Release helper tests", "run: python3 -m unittest release/scripts/test_registry_release.py"),
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
    ("Gate inventory self-check", "run: python3 release/scripts/check-gates-inventory.py"),
    ("Gate inventory tests", "run: python3 -m unittest release/scripts/test_check_gates_inventory.py"),
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
        "Upgrade exercise template validation",
        "python3 release/scripts/validate-upgrade-exercise.py --template",
    ),
    (
        "Base-reference compatibility input",
        "STABLE_SURFACE_BASE_REF: ${{ github.event.pull_request.base.sha || github.event.before }}",
    ),
    (
        "OpenAPI base-reference input",
        "OPENAPI_CONTRACT_BASE_REF: ${{ github.event.pull_request.base.sha || github.event.before }}",
    ),
    (
        "Stable error registry path filter",
        "docs/site/src/content/docs/reference/errors.mdx)",
    ),
    (
        "Relay support roster path filter",
        "docs/site/src/data/relay-support.yaml|docs/site/src/data/generated/relay-support.json)",
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


def missing_gates(workflow_text: str) -> list[str]:
    return [name for name, snippet in REQUIRED_GATES if snippet not in workflow_text]


def nested_workflow_paths(paths: list[str]) -> list[str]:
    """Return tracked workflows that GitHub cannot run from the repository root."""

    return sorted(
        path
        for path in paths
        if "/.github/workflows/" in f"/{path}"
        and not path.startswith(".github/workflows/")
    )


def tracked_paths(root: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [
        path.decode("utf-8")
        for path in completed.stdout.split(b"\0")
        if path
    ]


def main() -> int:
    workflow_text = CI_WORKFLOW.read_text(encoding="utf-8")
    missing = missing_gates(workflow_text)
    nested = nested_workflow_paths(tracked_paths(ROOT))
    if missing or nested:
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
    if missing or nested:
        return 1
    print(
        f"gate inventory check passed for {len(REQUIRED_GATES)} gates; "
        "no inert nested workflows"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
