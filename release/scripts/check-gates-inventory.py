#!/usr/bin/env python3
"""Assert that declared RegistryStack gates are wired into root CI."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

REQUIRED_GATES: tuple[tuple[str, str], ...] = (
    ("Cargo metadata", "run: cargo metadata --locked --format-version 1"),
    ("Format", "run: cargo fmt --check"),
    ("Workspace check", "run: cargo check --locked --workspace --all-targets"),
    ("Clippy", "run: cargo clippy --workspace --all-targets -- -D warnings"),
    ("Workspace tests", "run: cargo test --locked --workspace"),
    (
        "Relay all-features tests",
        "run: cargo test --locked -p registry-relay --all-features",
    ),
    ("Cargo deny", "run: cargo deny check"),
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


def main() -> int:
    workflow_text = CI_WORKFLOW.read_text(encoding="utf-8")
    missing = missing_gates(workflow_text)
    if missing:
        print("gate inventory check failed: missing CI wiring", file=sys.stderr)
        for gate in missing:
            print(f"- {gate}", file=sys.stderr)
        return 1
    print(f"gate inventory check passed for {len(REQUIRED_GATES)} gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
