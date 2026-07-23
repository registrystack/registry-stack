#!/usr/bin/env python3
"""Enforce the Debian 13 boundary for maintained Registry Stack images."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

RUST_BUILDER = (
    "rust:1.95-trixie@sha256:"
    "f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3"
)
DEBIAN_PREPARATION = (
    "debian:trixie-slim@sha256:"
    "020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd"
)
DISTROLESS_RUNTIME = (
    "gcr.io/distroless/cc-debian13:nonroot@sha256:"
    "d97bc0a941b8d4be647dc0ee75b264ddbb772f1ac5ba690a4309c00723b23775"
)
DOCKERFILE_FRONTEND = (
    "docker/dockerfile:1.7@sha256:"
    "a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
)
TUTORIAL_CACHE_STEP = "Cache source-under-test Cargo build"
TUTORIAL_CACHE_KEY = (
    "          key: registryctl-tutorial-${{ runner.os }}-"
    "${{ hashFiles('docs/site/scripts/check-registryctl-tutorials.sh') }}-"
    "${{ hashFiles('Cargo.lock') }}"
)

DOCKERFILES = (
    Path("crates/registry-relay/Dockerfile"),
    Path("crates/registry-relay/Dockerfile.demo"),
    Path("products/notary/Dockerfile"),
    Path("release/docker/Dockerfile.registry-notary"),
    Path("release/docker/Dockerfile.registry-relay"),
)

# These are the maintained image and image-policy surfaces. Historical release
# notes are immutable evidence and intentionally are not rewritten by this gate.
MAINTAINED_TEXT_PATHS = DOCKERFILES + (
    Path(".github/workflows/ci.yml"),
    Path(".github/workflows/release.yml"),
    Path("release/scripts/build-release-binaries.sh"),
    Path("docs/site/scripts/check-registryctl-tutorials.sh"),
    Path("crates/registry-relay/docs/ops.md"),
    Path("crates/registry-relay/docs/security-assurance.md"),
    Path("crates/registry-relay/scripts/check_docker_build_contract.py"),
    Path("crates/registry-relay/scripts/run-live-consultation-journey.sh"),
    Path("products/notary/docs/security-assurance.md"),
)

RUST_BUILDER_DOCKERFILES = DOCKERFILES[:3]
PREPARATION_DOCKERFILES = DOCKERFILES[3:]
RELAY_DOCKERFILES = (
    Path("crates/registry-relay/Dockerfile"),
    Path("crates/registry-relay/Dockerfile.demo"),
    Path("release/docker/Dockerfile.registry-relay"),
)
NOTARY_DOCKERFILES = (
    Path("products/notary/Dockerfile"),
    Path("release/docker/Dockerfile.registry-notary"),
)

FROM_RE = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", re.MULTILINE)
DIGEST_PIN_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
RETIRED_MARKER_RE = re.compile(
    r"\b(?:bookworm|debian[ \t_:-]*12)\b",
    re.IGNORECASE,
)


def read(root: Path, relative: Path, failures: list[str]) -> str:
    path = root / relative
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        failures.append(f"missing maintained image surface: {relative}")
        return ""


def require(
    text: str,
    needle: str,
    relative: Path,
    detail: str,
    failures: list[str],
) -> None:
    if needle not in text:
        failures.append(f"{relative}: missing {detail}: {needle!r}")


def require_exact_line(
    text: str,
    line: str,
    relative: Path,
    detail: str,
    failures: list[str],
) -> None:
    if line not in text.splitlines():
        failures.append(f"{relative}: missing {detail}: exact line {line!r}")


def workflow_step(text: str, name: str) -> str:
    lines = text.splitlines()
    header = f"      - name: {name}"
    matches = [index for index, line in enumerate(lines) if line == header]
    if len(matches) != 1:
        return ""
    start = matches[0]
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("      - name: ")
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


def runtime_stage(text: str) -> str:
    marker = f"FROM {DISTROLESS_RUNTIME} AS runtime"
    offset = text.find(marker)
    return text[offset:] if offset >= 0 else ""


def check_repository(root: Path = ROOT) -> list[str]:
    failures: list[str] = []
    texts = {
        relative: read(root, relative, failures)
        for relative in MAINTAINED_TEXT_PATHS
    }

    for relative, text in texts.items():
        marker = RETIRED_MARKER_RE.search(text)
        if marker:
            failures.append(
                f"{relative}: retired Debian image generation marker remains: "
                f"{marker.group(0).casefold()}"
            )

    for relative in DOCKERFILES:
        text = texts[relative]
        bases = FROM_RE.findall(text)
        if not bases:
            failures.append(f"{relative}: no FROM instruction found")
            continue
        for base in bases:
            if not DIGEST_PIN_RE.search(base):
                failures.append(
                    f"{relative}: upstream base is not pinned by immutable digest: {base}"
                )
        if bases[-1] != DISTROLESS_RUNTIME:
            failures.append(
                f"{relative}: final Dockerfile stage must use pinned "
                f"Distroless Debian 13 runtime: {bases[-1]}"
            )

        require(
            text,
            f"FROM {DISTROLESS_RUNTIME} AS runtime",
            relative,
            "Distroless Debian 13 non-root final runtime",
            failures,
        )
        runtime = runtime_stage(text)
        for forbidden in ("\nRUN ", "apt-get", "/bin/sh", "curl ", "wget "):
            if forbidden in runtime:
                failures.append(
                    f"{relative}: final Distroless runtime contains {forbidden.strip()!r}"
                )
        require(
            runtime,
            "HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3",
            relative,
            "binary healthcheck",
            failures,
        )

    for relative in RUST_BUILDER_DOCKERFILES:
        require(
            texts[relative],
            f"FROM {RUST_BUILDER} AS builder",
            relative,
            "pinned Debian 13 Rust builder",
            failures,
        )

    for relative in PREPARATION_DOCKERFILES:
        text = texts[relative]
        if not text.startswith(f"# syntax={DOCKERFILE_FRONTEND}\n"):
            failures.append(
                f"{relative}: pinned Dockerfile frontend must be the first line"
            )
        require(
            text,
            f"FROM {DEBIAN_PREPARATION} AS runtime-root",
            relative,
            "pinned Debian 13 runtime preparation base",
            failures,
        )
        require(
            text,
            "ARG SOURCE_DATE_EPOCH=0",
            relative,
            "fixed release filesystem timestamp",
            failures,
        )
        require(
            text,
            "RUN --mount=type=bind,source=dist/image-bin,target=/workspace/image-bin",
            relative,
            "ephemeral release input mount",
            failures,
        )
        require(
            text,
            'find /workspace/runtime-root -exec touch -h --date="@${SOURCE_DATE_EPOCH}" {} +',
            relative,
            "normalized release filesystem metadata",
            failures,
        )

    for relative in RELAY_DOCKERFILES:
        text = texts[relative]
        require(
            text,
            "/usr/local/bin/registry-relay-rhai-worker",
            relative,
            "Relay worker binary",
            failures,
        )
        require(
            runtime_stage(text),
            'ENTRYPOINT ["/usr/local/bin/registry-relay"]',
            relative,
            "absolute Relay entrypoint",
            failures,
        )

    product_notary = texts[Path("products/notary/Dockerfile")]
    require(
        product_notary,
        'ARG REGISTRY_NOTARY_FEATURES="registry-notary-cel,pkcs11"',
        Path("products/notary/Dockerfile"),
        "PKCS#11-enabled product build",
        failures,
    )
    for relative in NOTARY_DOCKERFILES:
        text = texts[relative]
        require(
            text,
            "registry-notary-cel-worker",
            relative,
            "Notary CEL worker binary",
            failures,
        )
        require(
            runtime_stage(text),
            'ENTRYPOINT ["/usr/local/bin/registry-notary"]',
            relative,
            "absolute Notary entrypoint",
            failures,
        )
        require(
            text,
            "chown -R 65532:65532",
            relative,
            "numeric nonroot-owned Notary runtime directories",
            failures,
        )
        require(
            runtime_stage(text),
            "WORKDIR /var/lib/registry-notary",
            relative,
            "Notary working directory",
            failures,
        )
        if re.search(
            r"^\s*(?:COPY|ADD)\b[^\n]*(?:\.so\b|pkcs11[^/\s]*module)",
            text,
            re.IGNORECASE | re.MULTILINE,
        ):
            failures.append(
                f"{relative}: vendor PKCS#11 modules must remain external read-only mounts"
            )

    workflow = texts[Path(".github/workflows/release.yml")]
    ci_workflow = texts[Path(".github/workflows/ci.yml")]
    binary_recipe = texts[Path("release/scripts/build-release-binaries.sh")]
    tutorial_check = texts[Path("docs/site/scripts/check-registryctl-tutorials.sh")]
    require_exact_line(
        workflow,
        f"  RELEASE_BUILDER_IMAGE: {RUST_BUILDER}",
        Path(".github/workflows/release.yml"),
        "pinned Debian 13 release builder",
        failures,
    )
    require_exact_line(
        binary_recipe,
        f'default_builder_image="{RUST_BUILDER}"',
        Path("release/scripts/build-release-binaries.sh"),
        "pinned Debian 13 release recipe builder",
        failures,
    )
    require(
        binary_recipe,
        "--features registry-notary/registry-notary-cel,registry-notary/pkcs11",
        Path("release/scripts/build-release-binaries.sh"),
        "PKCS#11-enabled release build",
        failures,
    )
    require_exact_line(
        tutorial_check,
        f'BUILDER_IMAGE="{RUST_BUILDER}"',
        Path("docs/site/scripts/check-registryctl-tutorials.sh"),
        "pinned Debian 13 registryctl tutorial builder",
        failures,
    )

    live_journey = texts[
        Path("crates/registry-relay/scripts/run-live-consultation-journey.sh")
    ]
    require_exact_line(
        live_journey,
        f"    {RUST_BUILDER} \\",
        Path("crates/registry-relay/scripts/run-live-consultation-journey.sh"),
        "pinned Debian 13 live-journey builder",
        failures,
    )

    tutorial_cache = workflow_step(ci_workflow, TUTORIAL_CACHE_STEP)
    if not tutorial_cache:
        failures.append(
            f".github/workflows/ci.yml: missing unique {TUTORIAL_CACHE_STEP!r} step"
        )
    else:
        require_exact_line(
            tutorial_cache,
            TUTORIAL_CACHE_KEY,
            Path(".github/workflows/ci.yml"),
            "registryctl tutorial builder cache key",
            failures,
        )
        if re.search(r"^\s*restore-keys\s*:", tutorial_cache, re.MULTILINE):
            failures.append(
                ".github/workflows/ci.yml: registryctl tutorial builder cache "
                "must not use restore-keys fallback"
            )

    return failures


def main() -> int:
    failures = check_repository()
    if failures:
        print("Debian 13 image contract check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("Debian 13 image contract check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
