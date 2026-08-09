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

# The runtime reference without its digest, used to recognise a Distroless stage
# even when its base is unpinned, so an unpinned base is reported rather than
# quietly dropping the stage out of the scan that follows.
DISTROLESS_REPOSITORY = DISTROLESS_RUNTIME.split("@", 1)[0]

DOCKERFILES = (
    Path("crates/registry-relay/Dockerfile"),
    Path("crates/registry-relay/Dockerfile.demo"),
    Path("release/docker/Dockerfile.registry-relay"),
    Path("release/docker/Dockerfile.relay"),
)

# Adopter and development images. They build from source like the per-product
# Dockerfiles above, but one file produces two binaries as two targets, so there
# is no single stage named `runtime` and no HEALTHCHECK (Distroless has no shell
# and neither binary has a healthcheck subcommand; both serve GET /health for
# HTTP probes instead). The Debian 13 boundary and the digest pins still bind
# them, so they are checked here under their own shape rather than left
# uncovered for not fitting the release one.
ADOPTER_DOCKERFILES = (Path("docker/Dockerfile"),)

# These are the maintained image and image-policy surfaces. Historical release
# notes are immutable evidence and intentionally are not rewritten by this gate.
MAINTAINED_TEXT_PATHS = DOCKERFILES + ADOPTER_DOCKERFILES + (
    Path(".github/workflows/release-candidate.yml"),
    Path(".github/workflows/release.yml"),
    Path("release/scripts/build-release-binaries.sh"),
    Path("crates/registry-relay/docs/ops.md"),
    Path("crates/registry-relay/docs/security-assurance.md"),
    Path("crates/registry-relay/scripts/check_docker_build_contract.py"),
)

RUST_BUILDER_DOCKERFILES = DOCKERFILES[:2]
PREPARATION_DOCKERFILES = DOCKERFILES[2:]
RELAY_DOCKERFILES = (
    Path("crates/registry-relay/Dockerfile"),
    Path("crates/registry-relay/Dockerfile.demo"),
    Path("release/docker/Dockerfile.registry-relay"),
)
RELAY_V2_DOCKERFILES = (Path("release/docker/Dockerfile.relay"),)

FROM_RE = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", re.MULTILINE)
STAGE_NAME_RE = re.compile(r"^FROM\s+\S+\s+AS\s+(\S+)", re.MULTILINE | re.IGNORECASE)
DIGEST_PIN_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
RETIRED_DEBIAN_RE = re.compile(
    r"\b(?:bookworm|debian[\s_:-]*v?[\s_:-]*12)\b",
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


def runtime_stage(text: str) -> str:
    marker = f"FROM {DISTROLESS_RUNTIME} AS runtime"
    offset = text.find(marker)
    return text[offset:] if offset >= 0 else ""


def distroless_stages(text: str) -> list[tuple[str, str]]:
    """Every stage built on the Distroless runtime, as (base, stage text).

    Release images name that stage `runtime`, so `runtime_stage` can find it by
    name. An image that builds more than one binary names one stage per binary,
    so these are found by their base instead. Matching the repository rather
    than the full pinned reference keeps an unpinned base visible here, where it
    is reported, instead of silently dropping the stage from the scan.
    """
    stages = []
    for segment in re.split(r"^FROM ", text, flags=re.MULTILINE)[1:]:
        base = segment.split(maxsplit=1)[0] if segment.split() else ""
        if not base.startswith(DISTROLESS_REPOSITORY):
            continue
        # Comments are scanned out so that a stage may say in prose why it has
        # no shell or curl without the words themselves reading as a violation.
        instructions = "\n".join(
            line for line in segment.splitlines() if not line.lstrip().startswith("#")
        )
        stages.append((base, f"\n{instructions}"))
    return stages


def check_repository(root: Path = ROOT) -> list[str]:
    failures: list[str] = []
    texts = {
        relative: read(root, relative, failures)
        for relative in MAINTAINED_TEXT_PATHS
    }

    for relative, text in texts.items():
        if RETIRED_DEBIAN_RE.search(text):
            failures.append(
                f"{relative}: retired Debian image generation marker remains"
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

    for relative in ADOPTER_DOCKERFILES:
        text = texts[relative]
        if not text.startswith(f"# syntax={DOCKERFILE_FRONTEND}\n"):
            failures.append(
                f"{relative}: pinned Dockerfile frontend must be the first line"
            )
        bases = FROM_RE.findall(text)
        if not bases:
            failures.append(f"{relative}: no FROM instruction found")
        # A multi-target image builds most of its stages on earlier stages of the
        # same file. Only the bases that come from outside the file are upstream
        # images, and only those can carry a digest.
        local_stages = set(STAGE_NAME_RE.findall(text))
        for base in bases:
            if base in local_stages:
                continue
            if not DIGEST_PIN_RE.search(base):
                failures.append(
                    f"{relative}: upstream base is not pinned by immutable digest: {base}"
                )
        require(
            text,
            f"FROM {RUST_BUILDER} AS chef",
            relative,
            "pinned Debian 13 Rust builder",
            failures,
        )
        require(
            text,
            "chown -R 65532:65532",
            relative,
            "numeric nonroot-owned runtime directories",
            failures,
        )
        stages = distroless_stages(text)
        if not stages:
            failures.append(
                f"{relative}: no stage runs on the Distroless Debian 13 non-root runtime"
            )
        for base, stage in stages:
            if base != DISTROLESS_RUNTIME:
                failures.append(
                    f"{relative}: Distroless runtime is not the pinned base: {base}"
                )
            for forbidden in ("\nRUN ", "apt-get", "/bin/sh", "curl ", "wget "):
                if forbidden in stage:
                    failures.append(
                        f"{relative}: Distroless runtime contains {forbidden.strip()!r}"
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

    for relative in RELAY_V2_DOCKERFILES:
        text = texts[relative]
        require(
            text,
            "/usr/local/bin/relay",
            relative,
            "Relay V2 binary",
            failures,
        )
        require(
            runtime_stage(text),
            'ENTRYPOINT ["/usr/local/bin/relay"]',
            relative,
            "absolute Relay V2 entrypoint",
            failures,
        )
        require(
            runtime_stage(text),
            'CMD ["serve", "--runtime", "/etc/relay/runtime.yaml"]',
            relative,
            "absolute Relay V2 runtime configuration binding",
            failures,
        )
    candidate_workflow = texts[Path(".github/workflows/release-candidate.yml")]
    release_workflow = texts[Path(".github/workflows/release.yml")]
    binary_recipe = texts[Path("release/scripts/build-release-binaries.sh")]
    require(
        candidate_workflow,
        f"RELEASE_BUILDER_IMAGE: {RUST_BUILDER}",
        Path(".github/workflows/release-candidate.yml"),
        "pinned Debian 13 release builder",
        failures,
    )
    # The workflow passes the builder in, and the recipe refuses anything but
    # its own default, so both ends have to carry the same pin.
    require(
        binary_recipe,
        f'default_builder_image="{RUST_BUILDER}"',
        Path("release/scripts/build-release-binaries.sh"),
        "pinned Debian 13 release builder",
        failures,
    )
    for forbidden in (
        "RELEASE_BUILDER_IMAGE:",
        "release/scripts/build-release-binaries.sh",
        "release/scripts/build-release-image.sh",
        "cargo build",
        "docker buildx build",
    ):
        if forbidden in release_workflow:
            failures.append(
                ".github/workflows/release.yml: promotion workflow must not "
                f"rebuild candidate artifacts: {forbidden!r}"
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
