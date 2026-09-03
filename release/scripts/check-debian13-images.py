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
RUST_BUILDER_SNAPSHOT = "20250810T000000Z"
RUST_BUILDER_LIBCLANG = "libclang-19-dev=1:19.1.7-3+b1"
RUST_BUILDER_PROTOC = "protobuf-compiler=3.21.12-11"
DEBIAN_PREPARATION = (
    "debian:trixie-slim@sha256:"
    "3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258"
)
# This index carries libssl3t64 3.5.7-1~deb13u2 on both supported Linux
# architectures. Earlier bytes fail the release policy on fixable OpenSSL CVEs.
DISTROLESS_RUNTIME = (
    "gcr.io/distroless/cc-debian13:nonroot@sha256:"
    "c31ff9abcb1910f3ab25c7957bdaf0bfe12a01eb546e8df2282f1c8f682b606c"
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
    Path("release/docker/Dockerfile.discovery"),
    Path("release/docker/Dockerfile.evidence"),
    Path("release/docker/Dockerfile.mint"),
    Path("release/docker/Dockerfile.breg"),
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
RUST_BUILDER_DOCKERFILES = (Path("release/docker/Dockerfile.builder"),)

# These are the maintained image and image-policy surfaces. Historical release
# notes are immutable evidence and intentionally are not rewritten by this gate.
MAINTAINED_TEXT_PATHS = (
    DOCKERFILES
    + ADOPTER_DOCKERFILES
    + RUST_BUILDER_DOCKERFILES
    + (
        Path(".github/workflows/release-candidate.yml"),
        Path(".github/workflows/release.yml"),
        Path("release/scripts/build-release-binaries.sh"),
    )
)

PREPARATION_DOCKERFILES = DOCKERFILES
RELAY_V2_DOCKERFILES = (Path("release/docker/Dockerfile.relay"),)
RELAY_RUNTIME_ROOT_STAGE = f"""\
FROM {DEBIAN_PREPARATION} AS runtime-root
ARG SOURCE_DATE_EPOCH
RUN --mount=type=bind,source=dist/image-bin,target=/workspace/image-bin \\
    --mount=type=bind,source=LICENSE,target=/workspace/LICENSE \\
    mkdir -p \\
        /workspace/runtime-root/licenses/relay \\
        /workspace/runtime-root/usr/local/bin \\
        /workspace/runtime-root/var/lib/relay/audit \\
        /workspace/runtime-root/var/lib/relay/data \\
    && install -d -o 0 -g 0 -m 0755 \\
        /workspace/runtime-root \\
        /workspace/runtime-root/etc \\
        /workspace/runtime-root/etc/relay \\
    && install -m 0755 /workspace/image-bin/relay /workspace/runtime-root/usr/local/bin/relay \\
    && install -m 0644 /workspace/LICENSE /workspace/runtime-root/licenses/relay/LICENSE \\
    && chown -R 65532:65532 /workspace/runtime-root/var/lib/relay \\
    && chmod 0700 /workspace/runtime-root/var/lib/relay/audit \\
    && find /workspace/runtime-root -exec touch -h --date="@${{SOURCE_DATE_EPOCH}}" {{}} +
"""
RELAY_RUNTIME_STAGE = f"""\
FROM {DISTROLESS_RUNTIME} AS runtime
LABEL org.registrystack.runtime.uid="65532" \\
      org.registrystack.runtime.gid="65532"
COPY --from=runtime-root /workspace/runtime-root/ /
WORKDIR /var/lib/relay
EXPOSE 8080
ENV RELAY_HEALTHCHECK_URL=http://127.0.0.1:8080/health
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/relay", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/relay"]
CMD ["serve", "--runtime", "/etc/relay/runtime.yaml"]
"""
# Each entry pins the runtime instructions that bind one HTTP-probed service to
# its configuration. Discovery reads no environment variable, so it declares no
# `environment` and binds its runtime file through the command instead.
HTTP_PROBE_DOCKERFILES = {
    Path("release/docker/Dockerfile.discovery"): {
        "binary": "discovery",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/discovery"]',
        "command": 'CMD ["--runtime", "/etc/registry-discovery/runtime.yaml"]',
    },
    Path("release/docker/Dockerfile.evidence"): {
        "binary": "evidence",
        "environment": "ENV REGISTRY_EVIDENCE_RUNTIME=/etc/registry-evidence/runtime.yaml",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/evidence"]',
        "command": 'CMD ["serve"]',
    },
    Path("release/docker/Dockerfile.mint"): {
        "binary": "mint",
        "environment": "ENV MINT_CONFIG=/etc/registry-mint/config.yaml",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/mint"]',
        "command": 'CMD ["serve"]',
    },
    Path("release/docker/Dockerfile.breg"): {
        "binary": "breg",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/breg"]',
        "command": 'CMD ["--config", "/etc/breg/runtime.yaml"]',
    },
}

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
    """Return each stage built on the Distroless runtime."""
    stages = []
    for segment in re.split(r"^FROM ", text, flags=re.MULTILINE)[1:]:
        base = segment.split(maxsplit=1)[0] if segment.split() else ""
        if not base.startswith(DISTROLESS_REPOSITORY):
            continue
        instructions = "\n".join(
            line for line in segment.splitlines() if not line.lstrip().startswith("#")
        )
        stages.append((base, f"\n{instructions}"))
    return stages


def normalized_instructions(text: str) -> tuple[str, ...]:
    """Return Dockerfile logical instructions with insignificant layout removed."""
    logical_text = re.sub(r"\\\r?\n[ \t]*", " ", text)
    return tuple(
        " ".join(line.split())
        for line in logical_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def named_stage(instructions: tuple[str, ...], name: str) -> tuple[str, ...]:
    """Return one named Dockerfile stage, including its FROM instruction."""
    marker = f" AS {name}".upper()
    starts = tuple(
        index
        for index, instruction in enumerate(instructions)
        if instruction.upper().startswith("FROM ")
        and instruction.upper().endswith(marker)
    )
    if len(starts) != 1:
        return ()
    start = starts[0]
    end = next(
        (
            index
            for index in range(start + 1, len(instructions))
            if instructions[index].upper().startswith("FROM ")
        ),
        len(instructions),
    )
    return instructions[start:end]


def check_relay_image_shape(text: str, relative: Path, failures: list[str]) -> None:
    """Pin the fixed Relay preparation and non-root runtime recipes."""
    instructions = normalized_instructions(text)
    if named_stage(instructions, "runtime-root") != normalized_instructions(
        RELAY_RUNTIME_ROOT_STAGE
    ):
        failures.append(
            f"{relative}: Relay V2 runtime preparation stage must match the "
            "root-owned release recipe"
        )

    final_runtime_stage = named_stage(instructions, "runtime")
    if (
        final_runtime_stage != normalized_instructions(RELAY_RUNTIME_STAGE)
        or instructions[-len(final_runtime_stage) :] != final_runtime_stage
    ):
        failures.append(
            f"{relative}: Relay V2 runtime stage must match the non-root, "
            "metadata-preserving release recipe"
        )


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
        if relative not in HTTP_PROBE_DOCKERFILES:
            require(
                runtime,
                "HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3",
                relative,
                "binary healthcheck",
                failures,
            )

    for relative in RUST_BUILDER_DOCKERFILES:
        text = texts[relative]
        if not text.startswith(f"# syntax={DOCKERFILE_FRONTEND}\n"):
            failures.append(
                f"{relative}: pinned Dockerfile frontend must be the first line"
            )
        bases = FROM_RE.findall(text)
        if not bases:
            failures.append(f"{relative}: no FROM instruction found")
        for base in bases:
            if not DIGEST_PIN_RE.search(base):
                failures.append(
                    f"{relative}: upstream base is not pinned by immutable digest: {base}"
                )
        require(
            text,
            f"FROM {RUST_BUILDER} AS builder",
            relative,
            "pinned Debian 13 Rust builder",
            failures,
        )
        require(
            text,
            f"snapshot.debian.org/archive/debian/{RUST_BUILDER_SNAPSHOT}",
            relative,
            "dated Debian package snapshot",
            failures,
        )
        require(
            text,
            RUST_BUILDER_LIBCLANG,
            relative,
            "exact libclang build package",
            failures,
        )
        require(
            text,
            RUST_BUILDER_PROTOC,
            relative,
            "exact protobuf build package",
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

    for relative in RELAY_V2_DOCKERFILES:
        text = texts[relative]
        check_relay_image_shape(text, relative, failures)
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
        require(
            runtime_stage(text),
            "ENV RELAY_HEALTHCHECK_URL=http://127.0.0.1:8080/health",
            relative,
            "safe configurable Relay V2 healthcheck default",
            failures,
        )
        require(
            runtime_stage(text),
            'HEALTHCHECK --interval=30s --timeout=5s --start-period=10s '
            '--retries=3 CMD ["/usr/local/bin/relay", "healthcheck"]',
            relative,
            "environment-aware Relay V2 healthcheck",
            failures,
        )

    for relative, contract in HTTP_PROBE_DOCKERFILES.items():
        runtime = runtime_stage(texts[relative])
        binary = contract["binary"]
        require(
            texts[relative],
            f"/usr/local/bin/{binary}",
            relative,
            f"{binary} binary",
            failures,
        )
        for key in ("environment", "entrypoint", "command"):
            expected = contract.get(key)
            if expected is None:
                continue
            require(
                runtime,
                expected,
                relative,
                f"fixed {binary} {key}",
                failures,
            )
        if "environment" not in contract and "\nENV " in f"\n{runtime}":
            failures.append(
                f"{relative}: {binary} binds its configuration through the "
                "command, so its runtime must declare no runtime environment"
            )
        if "HEALTHCHECK" in runtime:
            failures.append(
                f"{relative}: HTTP-probed runtime must not carry a binary HEALTHCHECK"
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
