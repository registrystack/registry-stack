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

BINARY_RELEASE_PWSH_FORBIDDEN_PATTERNS: list[tuple[str, str]] = [
    (r"\$\{\{\s*github\.ref_name\s*\}\}", "GitHub tag interpolation in PowerShell"),
    (r"\$GITHUB_REF_NAME", "shell tag interpolation in PowerShell"),
    (r"\$version", "tag-derived version interpolation in PowerShell"),
    (r"\$package(?:_dir)?", "tag-derived package path interpolation in PowerShell"),
    (r"target/dist", "archive path literal interpolation in PowerShell"),
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
        for name in ("REGISTRY_PLATFORM_REF", "REGISTRY_MANIFEST_REF", "CROSSWALK_REF"):
            value = env_value(text, name)
            if value is None:
                failures.append(f"{path.relative_to(ROOT)}: missing {name}")
            elif not IMMUTABLE_REF.fullmatch(value):
                failures.append(
                    f"{path.relative_to(ROOT)}: {name} must be a 40-character commit SHA, got {value!r}"
                )
    return failures


def powershell_command_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.search(r"\bpwsh\b", line)
        if match is None:
            index += 1
            continue

        block = [line[match.start() :]]
        here_string_end = None
        if "@'" in line:
            here_string_end = "'@"
        elif '@"' in line:
            here_string_end = '"@'

        if here_string_end is not None:
            index += 1
            while index < len(lines):
                block.append(lines[index])
                if lines[index].strip() == here_string_end:
                    break
                index += 1
        else:
            while block[-1].rstrip().endswith("\\") and index + 1 < len(lines):
                index += 1
                block.append(lines[index])

        blocks.append("\n".join(block))
        index += 1
    return blocks


def require_binary_release_powershell_hardening(text: str, path: Path) -> list[str]:
    failures: list[str] = []
    failures.extend(
        require(
            text,
            '[[ ! "$GITHUB_REF_NAME" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]',
            path,
            "stable semver tag validation before package-name derivation",
        )
    )
    failures.extend(
        require(
            text,
            'PACKAGE_DIR="$package_dir" PACKAGE_ZIP="target/dist/${package}.zip"',
            path,
            "PowerShell archive paths passed through environment variables",
        )
    )
    failures.extend(
        require(
            text,
            r"Compress-Archive -Path (Join-Path \$env:PACKAGE_DIR '*') -DestinationPath \$env:PACKAGE_ZIP -Force",
            path,
            "PowerShell archive command using environment variables",
        )
    )
    for block in powershell_command_blocks(text):
        for pattern, detail in BINARY_RELEASE_PWSH_FORBIDDEN_PATTERNS:
            failures.extend(forbid(block, pattern, path, detail))
    return failures


def require_coverage_contract(text: str, path: Path) -> list[str]:
    failures: list[str] = []
    failures.extend(require(text, 'CARGO_LLVM_COV_VERSION: "0.8.7"', path, "pinned cargo-llvm-cov version"))
    failures.extend(require(text, 'REGISTRY_RELAY_COVERAGE_THRESHOLD: "85"', path, "baseline coverage threshold"))
    failures.extend(require(text, "components: llvm-tools-preview", path, "LLVM tools Rust component"))
    failures.extend(require(text, "tool: cargo-llvm-cov@${{ env.CARGO_LLVM_COV_VERSION }}", path, "pinned cargo-llvm-cov install"))
    failures.extend(require(text, "cargo llvm-cov clean --workspace", path, "clean coverage profile data"))
    failures.extend(require(text, "cargo llvm-cov nextest --no-report --build-jobs 2", path, "default-feature nextest coverage pass"))
    failures.extend(
        require(
            text,
            "cargo llvm-cov nextest --all-features --no-report --build-jobs 2",
            path,
            "all-features nextest coverage pass",
        )
    )
    failures.extend(require(text, "cargo llvm-cov report | tee target/coverage/summary.txt", path, "coverage report before threshold gate"))
    failures.extend(require(text, "Enforce coverage threshold", path, "line coverage threshold gate after artifact upload"))
    failures.extend(require(text, 'dashboard["status"] != "pass"', path, "dashboard status threshold enforcement"))
    failures.extend(
        forbid(
            text,
            r"--fail-under-lines",
            path,
            "direct fail-under coverage gate before artifact upload",
        )
    )
    failures.extend(require(text, "target/coverage/lcov.info", path, "LCOV coverage artifact"))
    failures.extend(require(text, "target/coverage/summary.json", path, "JSON coverage summary artifact"))
    failures.extend(require(text, "target/coverage/summary.txt", path, "text coverage summary artifact"))
    failures.extend(require(text, "target/coverage/dashboard.json", path, "dashboard coverage artifact"))
    failures.extend(
        require(
            text,
            "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2",
            path,
            "SHA-pinned coverage artifact upload action",
        )
    )
    upload_index = text.find("Upload coverage artifacts")
    enforce_index = text.find("Enforce coverage threshold")
    if upload_index == -1 or enforce_index == -1 or enforce_index < upload_index:
        failures.append(
            f"{path.relative_to(ROOT)}: coverage artifacts must upload before threshold enforcement"
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
    binary_release = WORKFLOWS / "binary-release.yml"
    binary_release_text = read(binary_release)
    failures.extend(require_binary_release_powershell_hardening(binary_release_text, binary_release))
    failures.extend(
        require(
            binary_release_text,
            'RUSTFLAGS: ""',
            binary_release,
            "macOS build must neutralize the local-dev ld64.lld override with a set-but-empty RUSTFLAGS",
        )
    )

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
            'main_branch="$(gh api "repos/${GITHUB_REPOSITORY}/branches/main")"',
            container,
            "main branch metadata lookup before release image publish",
        )
    )
    failures.extend(
        require(
            container_text,
            'protected="$(jq -r \'.protected\' <<<"$main_branch")"',
            container,
            "main branch protection check before release image publish",
        )
    )
    failures.extend(
        require(
            container_text,
            'main_sha="$(jq -r \'.commit.sha\' <<<"$main_branch")"',
            container,
            "protected main commit SHA extraction before release image publish",
        )
    )
    failures.extend(
        require(
            container_text,
            'gh api "repos/${GITHUB_REPOSITORY}/compare/${GITHUB_SHA}...${main_sha}"',
            container,
            "tag commit reachability check against protected main commit SHA before release image publish",
        )
    )
    failures.extend(
        forbid(
            container_text,
            r"compare/\$\{GITHUB_SHA\}\.\.\.main",
            container,
            "ambiguous main ref in release tag reachability check",
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
    failures.extend(require_coverage_contract(ci_text, ci))

    if failures:
        print("Workflow hardening check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("Workflow hardening check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
