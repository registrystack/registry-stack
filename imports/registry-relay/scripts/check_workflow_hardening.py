#!/usr/bin/env python3
"""Check release and CI workflow hardening rules."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
IMMUTABLE_REF = re.compile(r"^[0-9a-f]{40}$")

# Forbidden ways of installing cargo-nextest in CI. The supply-chain rule is:
# never fetch-and-extract an unverified archive. nextest must come from the
# SHA-pinned taiki-e/install-action with `fallback: none`. These patterns catch
# reintroductions via either a streamed download piped into tar, or a split
# download-to-file followed by tar extraction (no checksum in between).
NEXTEST_FORBIDDEN_PATTERNS: list[tuple[str, str]] = [
    (r"get\.nexte\.st", "unchecked nextest installer"),
    (r"curl\b[^\n|]*\|[^\n]*tar\b", "curl piped to tar"),
    (r"wget\b[^\n|]*\|[^\n]*tar\b", "wget piped to tar"),
    (
        r"(?:curl|wget)\b[^\n]*?\s-(?:o|O|-output|-remote-name)\b[\s\S]{0,400}?\btar\b[^\n]*?\bx",
        "split download piped to tar extraction",
    ),
]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def env_value(text: str, name: str) -> str | None:
    match = re.search(rf"^\s*{re.escape(name)}:\s*(.+?)\s*$", text, re.MULTILINE)
    return match.group(1).strip() if match else None


def require(text: str, needle: str, path: Path, detail: str) -> list[str]:
    if needle in text:
        return []
    return [f"{path.relative_to(ROOT)}: missing {detail}: {needle!r}"]


def forbid(text: str, pattern: str, path: Path, detail: str) -> list[str]:
    if not re.search(pattern, text, re.MULTILINE | re.DOTALL):
        return []
    return [f"{path.relative_to(ROOT)}: forbidden {detail}: /{pattern}/"]


def require_immutable_refs(paths: list[Path]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        text = read(path)
        for name in ("REGISTRY_PLATFORM_REF", "REGISTRY_MANIFEST_REF", "CEL_MAPPING_REF"):
            value = env_value(text, name)
            if value is None:
                failures.append(f"{path.relative_to(ROOT)}: missing {name}")
            elif not IMMUTABLE_REF.fullmatch(value):
                failures.append(
                    f"{path.relative_to(ROOT)}: {name} must be a 40-character commit SHA, got {value!r}"
                )
    return failures


def main() -> int:
    ci_workflows = [
        WORKFLOWS / "ci.yml",
        WORKFLOWS / "dcat-ap-external-validation.yml",
        WORKFLOWS / "perf-smoke.yml",
    ]
    release_workflows = [
        WORKFLOWS / "binary-release.yml",
        WORKFLOWS / "container.yml",
    ]
    all_checked = ci_workflows + release_workflows
    failures: list[str] = []

    failures.extend(require_immutable_refs(all_checked))

    container = WORKFLOWS / "container.yml"
    container_text = read(container)
    failures.extend(
        require(
            container_text,
            "Verify release tag is protected-main reachable",
            container,
            "release image protected-main reachability gate",
        )
    )
    failures.extend(
        require(
            container_text,
            'gh api "repos/${GITHUB_REPOSITORY}/branches/main" --jq \'.protected\'',
            container,
            "main branch protection check before release image publish",
        )
    )
    failures.extend(
        require(
            container_text,
            'git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main',
            container,
            "tag commit reachability check before release image publish",
        )
    )

    for path in all_checked:
        text = read(path)
        failures.extend(
            forbid(
                text,
                r"REGISTRY_(?:PLATFORM|MANIFEST)_REF:\s*(?:main|\$\{\{)",
                path,
                "mutable sibling repository ref",
            )
        )
        failures.extend(
            forbid(
                text,
                r"ref:\s*(?:main|\$\{\{\s*github\.(?:head_ref|ref_name)|\$\{\{\s*env\.REGISTRY_(?:PLATFORM|MANIFEST)_BRANCH)",
                path,
                "mutable sibling checkout ref",
            )
        )

    ci = WORKFLOWS / "ci.yml"
    ci_text = read(ci)
    for pattern, detail in NEXTEST_FORBIDDEN_PATTERNS:
        failures.extend(forbid(ci_text, pattern, ci, detail))
    failures.extend(
        require(
            ci_text,
            "uses: taiki-e/install-action@25435dc8dd3baed7417e0c96d3fe89013a5b2e09 # v2.81.3",
            ci,
            "SHA-pinned cargo-nextest install action",
        )
    )
    failures.extend(require(ci_text, "tool: nextest@0.9.136", ci, "pinned nextest tool version"))
    failures.extend(require(ci_text, "fallback: none", ci, "nextest install fallback disabled"))

    if failures:
        print("Workflow hardening check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("Workflow hardening check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
