#!/usr/bin/env python3
"""Enforce the Debian 13 boundary for maintained Registry Stack images."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REMOTE_PACKAGE_SOURCE_RE = re.compile(r"\b(?:https?|ftp)://", re.IGNORECASE)

RUST_BUILDER = (
    "rust:1.95-trixie@sha256:"
    "f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3"
)
RUST_BUILDER_SNAPSHOT = "20250810T000000Z"
RUST_BUILDER_CMAKE = "cmake=3.31.6-2"
RUST_BUILDER_GO = "golang-go=2:1.24~2"
RUST_BUILDER_LIBCLANG = "libclang-19-dev=1:19.1.7-3+b1"
RUST_BUILDER_PROTOC = "protobuf-compiler=3.21.12-11"
RUST_BUILDER_PIP = "python3-pip=25.1.1+dfsg-1"
# The builder compiles and links the product binaries with Zig so they bind the
# glibc symbols of the release floor rather than the builder's own newer ones.
# Zig arrives from the Python index, so its file is pinned by hash the way the
# Debian packages above are pinned by version.
RUST_BUILDER_ZIG_REQUIREMENTS = "release/requirements/ziglang-0.12.1.txt"
RUST_BUILDER_HASHED_INSTALL = "--require-hashes"
RUNTIME_PACKAGE_INSTALLER = Path("release/scripts/install-runtime-packages.sh")
# The Debian packages every runtime image overlays on the Distroless base, each
# fixed by version and per-architecture checksum and fetched from a dated
# snapshot.debian.org archive. The installer carries the same list.
RUNTIME_PACKAGES = {
    "libc6": {
        "archive": "debian",
        "snapshot": "20260913T000000Z",
        "pool": "pool/main/g/glibc",
        "version": "2.41-12+deb13u4",
        "sha256": {
            "amd64": "967aa62605721081c3eb2a17650611a792aa802d76a6511d1840242623d204c9",
            "arm64": "8784eda966b189c777a384dac5ce009e8fc9b52d006926c5a013e7fa8aa688cc",
        },
    },
    "libssl3t64": {
        "archive": "debian-security",
        "snapshot": "20260930T060347Z",
        "pool": "pool/updates/main/o/openssl",
        "version": "3.5.7-1~deb13u3",
        "sha256": {
            "amd64": "ff16bc048bcd7d1b256094450b79c77947d8e76fe2a24bd99b91021d591fa074",
            "arm64": "d0681293a160392186c6ef85a165e40603d1628a099936137d24d391bd591f97",
        },
    },
}
RUNTIME_PACKAGE_ADDS = tuple(
    "ADD --checksum=sha256:{checksum} "
    "https://snapshot.debian.org/archive/{archive}/{snapshot}/{pool}/"
    "{name}_{version}_{architecture}.deb "
    "/workspace/runtime-packages/{name}_{version}_{architecture}.deb".format(
        checksum=package["sha256"][architecture],
        archive=package["archive"],
        snapshot=package["snapshot"],
        pool=package["pool"],
        name=name,
        version=package["version"],
        architecture=architecture,
    )
    for name, package in RUNTIME_PACKAGES.items()
    for architecture in ("amd64", "arm64")
)
RUNTIME_PACKAGE_ADD_INSTRUCTIONS = "\n".join(RUNTIME_PACKAGE_ADDS)
RUNTIME_PACKAGE_MOUNT = (
    "--mount=type=bind,source=release/scripts/install-runtime-packages.sh,"
    "target=/workspace/install-runtime-packages.sh,readonly"
)
RUNTIME_PACKAGE_COMMAND = (
    "/workspace/install-runtime-packages.sh "
    "/workspace/runtime-root /workspace/runtime-packages"
)
RUNTIME_ROOT_NORMALIZATION = (
    'find /workspace/runtime-root -exec touch -h '
    '--date="@${SOURCE_DATE_EPOCH}" {} +'
)
DEBIAN_PREPARATION = (
    "debian:trixie-slim@sha256:"
    "a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a"
)
# This index carries libssl3t64 3.5.7-1~deb13u2 on both supported Linux
# architectures. Earlier bytes fail the release policy on fixable OpenSSL CVEs.
# The runtime package overlay above replaces that libssl3t64 with the fixed
# release; once an index carries the fixed release itself, libssl3t64 can
# leave the overlay.
DISTROLESS_RUNTIME = (
    "gcr.io/distroless/cc-debian13:nonroot@sha256:"
    "e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2"
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
    Path("release/docker/Dockerfile.evidence-oid4vci"),
    Path("release/docker/Dockerfile.registry-render"),
    Path("release/docker/Dockerfile.breg"),
    Path("release/docker/Dockerfile.breg-mcp"),
    Path("release/docker/Dockerfile.breg-review"),
    Path("release/docker/Dockerfile.casework"),
    Path("release/docker/Dockerfile.scheduling"),
    Path("release/docker/Dockerfile.messaging"),
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
        RUNTIME_PACKAGE_INSTALLER,
    )
)

PREPARATION_DOCKERFILES = DOCKERFILES
# Each entry pins the runtime instructions that bind one HTTP-probed service to
# its configuration. A service that reads no environment variable declares no
# `environment` and binds its runtime file through the command instead.
# A stateful product image also carries its operator tool, so an operator can
# run it with the image's exact bytes by overriding the entrypoint. The
# runtime stays the entrypoint.
HTTP_PROBE_DOCKERFILES = {
    Path("release/docker/Dockerfile.discovery"): {
        "binary": "discovery",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/discovery"]',
        "command": 'CMD ["--runtime-config", "/etc/registry-discovery/runtime.yaml"]',
    },
    Path("release/docker/Dockerfile.evidence"): {
        "binary": "evidence",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/evidence"]',
        "command": 'CMD ["serve", "--runtime-config", "/etc/registry-evidence/runtime.yaml"]',
    },
    Path("release/docker/Dockerfile.evidence-oid4vci"): {
        "binary": "evidence-oid4vci",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/evidence-oid4vci"]',
        "command": 'CMD ["serve", "--runtime-config", "/etc/registry-evidence-oid4vci/runtime.yaml"]',
    },
    Path("release/docker/Dockerfile.registry-render"): {
        "binary": "registry-render",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/registry-render"]',
        "command": 'CMD ["serve", "--runtime-config", "/etc/registry-render/runtime.yaml"]',
    },
    Path("release/docker/Dockerfile.breg"): {
        "binary": "breg",
        "tool": "bregctl",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/breg"]',
        "command": 'CMD ["--runtime-config", "/etc/breg/runtime.yaml"]',
    },
    Path("release/docker/Dockerfile.breg-mcp"): {
        "binary": "breg-mcp",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/breg-mcp"]',
        "command": 'CMD ["--runtime-config", "/etc/breg-mcp/runtime.yaml", "serve"]',
    },
    Path("release/docker/Dockerfile.breg-review"): {
        "binary": "breg-review",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/breg-review"]',
        "command": 'CMD ["--runtime-config", "/etc/breg-review/runtime.yaml", "serve"]',
    },
    Path("release/docker/Dockerfile.casework"): {
        "binary": "casework",
        "tool": "caseworkctl",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/casework"]',
        "command": 'CMD ["--runtime-config", "/etc/registry-casework/runtime.yaml", "serve"]',
    },
    Path("release/docker/Dockerfile.scheduling"): {
        "binary": "scheduling",
        "tool": "schedulingctl",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/scheduling"]',
        "command": 'CMD ["--runtime-config", "/etc/registry-scheduling/runtime.yaml", "serve"]',
    },
    Path("release/docker/Dockerfile.messaging"): {
        "binary": "messaging",
        "tool": "messagingctl",
        "entrypoint": 'ENTRYPOINT ["/usr/local/bin/messaging"]',
        "command": 'CMD ["--runtime-config", "/etc/registry-messaging/runtime.yaml", "serve"]',
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


def check_repository(root: Path = ROOT) -> list[str]:
    failures: list[str] = []
    expected_release_dockerfiles = set(DOCKERFILES + RUST_BUILDER_DOCKERFILES)
    actual_release_dockerfiles = {
        path.relative_to(root)
        for path in (root / "release/docker").glob("Dockerfile.*")
    }
    missing_release_dockerfiles = sorted(
        expected_release_dockerfiles - actual_release_dockerfiles
    )
    unexpected_release_dockerfiles = sorted(
        actual_release_dockerfiles - expected_release_dockerfiles
    )
    if missing_release_dockerfiles:
        failures.append(
            "release Dockerfile policy is missing maintained files: "
            + ", ".join(map(str, missing_release_dockerfiles))
        )
    if unexpected_release_dockerfiles:
        failures.append(
            "release Dockerfile policy does not cover files: "
            + ", ".join(map(str, unexpected_release_dockerfiles))
        )
    texts = {
        relative: read(root, relative, failures)
        for relative in MAINTAINED_TEXT_PATHS
    }

    for relative, text in texts.items():
        if RETIRED_DEBIAN_RE.search(text):
            failures.append(
                f"{relative}: retired Debian image generation marker remains"
            )

    installer = texts[RUNTIME_PACKAGE_INSTALLER]
    installer_requirements = [
        ("sha256sum --check --strict", "strict runtime package checksum check"),
        ('dpkg-deb --field "$archive" Package', "runtime package identity"),
        ('dpkg-deb --field "$archive" Version', "runtime package version identity"),
        ('dpkg-deb --field "$archive" Architecture', "runtime package architecture identity"),
        ("dpkg-deb --control", "runtime package control extraction"),
        ("dpkg-deb --extract", "runtime package extraction"),
        (
            'dpkg-deb --field "$archive" >"$runtime_root/var/lib/dpkg/status.d/${package}"',
            "runtime package metadata",
        ),
        (
            '"$runtime_root/var/lib/dpkg/status.d/${package}.md5sums"',
            "runtime package file metadata",
        ),
    ]
    for name, package in RUNTIME_PACKAGES.items():
        installer_requirements += [
            (
                f"install_package {name} {package['version']} \\\n",
                f"exact fixed runtime {name} version",
            ),
            (package["sha256"]["amd64"], f"amd64 runtime {name} checksum"),
            (package["sha256"]["arm64"], f"arm64 runtime {name} checksum"),
        ]
    for needle, detail in installer_requirements:
        require(installer, needle, RUNTIME_PACKAGE_INSTALLER, detail, failures)
    if REMOTE_PACKAGE_SOURCE_RE.search(installer):
        failures.append(
            f"{RUNTIME_PACKAGE_INSTALLER}: runtime package installer must not "
            "fetch remote sources"
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
        require(
            text,
            RUNTIME_PACKAGE_MOUNT,
            relative,
            "read-only fixed runtime package installer mount",
            failures,
        )
        require(
            text,
            RUNTIME_PACKAGE_COMMAND,
            relative,
            "fixed runtime package overlay",
            failures,
        )
        for runtime_package_add in RUNTIME_PACKAGE_ADDS:
            if text.count(runtime_package_add) != 1:
                failures.append(
                    f"{relative}: fixed runtime package input must appear exactly once: "
                    f"{runtime_package_add!r}"
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
            RUST_BUILDER_CMAKE,
            relative,
            "exact CMake build package",
            failures,
        )
        require(
            text,
            RUST_BUILDER_GO,
            relative,
            "exact Go build package",
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
            RUST_BUILDER_PIP,
            relative,
            "exact pip build package",
            failures,
        )
        require(
            text,
            RUST_BUILDER_ZIG_REQUIREMENTS,
            relative,
            "hash-pinned Zig requirements file",
            failures,
        )
        require(
            text,
            RUST_BUILDER_HASHED_INSTALL,
            relative,
            "hash-checked Python install",
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
            RUNTIME_ROOT_NORMALIZATION,
            relative,
            "normalized release filesystem metadata",
            failures,
        )
        if (
            RUNTIME_PACKAGE_COMMAND in text
            and RUNTIME_ROOT_NORMALIZATION in text
            and text.index(RUNTIME_PACKAGE_COMMAND)
            > text.index(RUNTIME_ROOT_NORMALIZATION)
        ):
            failures.append(
                f"{relative}: fixed runtime package overlay must precede timestamp "
                "normalization"
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
        if re.search(
            r"chown -R 65532:65532 /workspace/runtime-root(?:\s|$)", text
        ):
            failures.append(
                f"{relative}: adopter runtime must not make the complete libc root nonroot-owned"
            )
        if text.count(RUNTIME_ROOT_NORMALIZATION) != 2:
            failures.append(
                f"{relative}: each adopter runtime must normalize fixed runtime "
                "package metadata"
            )
        if text.count(RUNTIME_PACKAGE_MOUNT) != 2:
            failures.append(
                f"{relative}: each adopter runtime must mount the fixed runtime "
                "package installer"
            )
        if text.count(RUNTIME_PACKAGE_COMMAND) != 2:
            failures.append(
                f"{relative}: each adopter runtime must install the fixed runtime "
                "package overlay"
            )
        for runtime_package_add in RUNTIME_PACKAGE_ADDS:
            if text.count(runtime_package_add) != 2:
                failures.append(
                    f"{relative}: each adopter runtime must use the fixed runtime "
                    f"package input: {runtime_package_add!r}"
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
        if f"\n{runtime}".count("\nENTRYPOINT ") != 1:
            failures.append(
                f"{relative}: {binary} runtime must declare exactly one ENTRYPOINT"
            )
        tool = contract.get("tool")
        if tool is not None:
            install = (
                f"install -m 0755 /workspace/image-bin/{tool} "
                f"/workspace/runtime-root/usr/local/bin/{tool}"
            )
            require(
                texts[relative],
                install,
                relative,
                f"{tool} operator tool",
                failures,
            )
            if (
                install in texts[relative]
                and RUNTIME_ROOT_NORMALIZATION in texts[relative]
                and texts[relative].index(install)
                > texts[relative].index(RUNTIME_ROOT_NORMALIZATION)
            ):
                failures.append(
                    f"{relative}: {tool} operator tool must precede timestamp "
                    "normalization"
                )
            if f"if [ -e /workspace/image-bin/{tool} ]" in texts[relative]:
                failures.append(
                    f"{relative}: {tool} operator tool must be required by every "
                    "release image build"
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
