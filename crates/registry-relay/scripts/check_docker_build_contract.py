#!/usr/bin/env python3
"""Check the container build contract that CI cannot infer from Docker alone."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
_CONTENT_CACHE: dict[Path, str] = {}


def require(path: Path, needle: str, detail: str) -> list[str]:
    if path not in _CONTENT_CACHE:
        _CONTENT_CACHE[path] = path.read_text(encoding="utf-8")
    text = _CONTENT_CACHE[path]
    if needle in text:
        return []
    return [f"{path.relative_to(ROOT)}: missing {detail}: {needle!r}"]


def runtime_stage(path: Path) -> str:
    if path not in _CONTENT_CACHE:
        _CONTENT_CACHE[path] = path.read_text(encoding="utf-8")
    text = _CONTENT_CACHE[path]
    marker = " AS runtime"
    marker_at = text.find(marker)
    if marker_at == -1:
        return ""
    line_start = text.rfind("\n", 0, marker_at) + 1
    return text[line_start:]


def require_runtime(path: Path, needle: str, detail: str) -> list[str]:
    stage = runtime_stage(path)
    if needle in stage:
        return []
    return [f"{path.relative_to(ROOT)} runtime stage: missing {detail}: {needle!r}"]


def forbid_runtime(path: Path, needle: str, detail: str) -> list[str]:
    stage = runtime_stage(path)
    stage_without_comments = "\n".join(
        line for line in stage.splitlines() if not line.strip().startswith("#")
    )
    if needle not in stage_without_comments:
        return []
    return [f"{path.relative_to(ROOT)} runtime stage: forbidden {detail}: {needle!r}"]


def forbid(path: Path, needle: str, detail: str) -> list[str]:
    if path not in _CONTENT_CACHE:
        _CONTENT_CACHE[path] = path.read_text(encoding="utf-8")
    text_without_comments = "\n".join(
        line.split("#", 1)[0] for line in _CONTENT_CACHE[path].splitlines()
    )
    if needle not in text_without_comments:
        return []
    return [f"{path.relative_to(ROOT)}: forbidden {detail}: {needle!r}"]


def forbid_documented_unpinned_build_context(path: Path) -> list[str]:
    if path not in _CONTENT_CACHE:
        _CONTENT_CACHE[path] = path.read_text(encoding="utf-8")
    text = _CONTENT_CACHE[path]
    if "docker buildx build" not in text or "--build-context registry-manifest=../registry-manifest" not in text:
        return []
    return [
        f"{path.relative_to(ROOT)}: forbidden documented unpinned registry-manifest Docker build context"
    ]


def main() -> int:
    dockerfile = ROOT / "Dockerfile"
    build_script = ROOT / "scripts" / "build-image.sh"
    docs = [ROOT / "README.md", ROOT / "docs" / "ops.md"]

    failures: list[str] = []
    failures.extend(
        require(
            dockerfile,
            'ARG REGISTRY_RELAY_FEATURES=""',
            "empty-by-default feature build arg",
        )
    )
    failures.extend(
        require(
            dockerfile,
            'cargo build --release --locked --features "$REGISTRY_RELAY_FEATURES"',
            "feature-enabled cargo build path",
        )
    )
    failures.extend(
        require(
            dockerfile,
            "COPY --from=crosswalk /crates /workspace/crosswalk/crates",
            "crosswalk build context copy",
        )
    )
    failures.extend(
        require(
            dockerfile,
            "cargo build --release --locked",
            "default cargo build path",
        )
    )
    failures.extend(
        require(
            dockerfile,
            "find src benches resources -type f -exec touch {} +",
            "package rebuild guard for cached Docker target dirs",
        )
    )
    failures.extend(
        require(
            build_script,
            'manifest_dir="${REGISTRY_MANIFEST_DIR:-../registry-manifest}"',
            "registry-manifest build context override",
        )
    )
    failures.extend(
        require(
            build_script,
            'manifest_ref="${REGISTRY_MANIFEST_REF:-19cf67ada5eb7325a8fb8b051a2acc266b41bbde}"',
            "registry-manifest immutable default ref",
        )
    )
    failures.extend(
        require(
            build_script,
            'verify_pinned_git_context "REGISTRY_MANIFEST" "$manifest_dir" "$manifest_ref"',
            "registry-manifest local context pin check",
        )
    )
    failures.extend(
        require(
            build_script,
            "REGISTRY_RELAY_ALLOW_UNPINNED_LOCAL_CONTEXTS",
            "explicit local unpinned context bypass",
        )
    )
    failures.extend(
        require(
            build_script,
            "warning: CEL_MAPPING_DIR is deprecated, please use CROSSWALK_DIR instead",
            "deprecated CEL_MAPPING_DIR fallback warning",
        )
    )
    failures.extend(
        require(
            build_script,
            '--build-context "registry-manifest=$manifest_dir"',
            "registry-manifest build context",
        )
    )
    failures.extend(
        require(
            build_script,
            '--build-context "crosswalk=$crosswalk_dir"',
            "crosswalk build context",
        )
    )
    failures.extend(
        require(
            build_script,
            '--build-arg "REGISTRY_RELAY_FEATURES=$REGISTRY_RELAY_FEATURES"',
            "optional feature build arg forwarding",
        )
    )
    failures.extend(
        require_runtime(
            dockerfile,
            "FROM gcr.io/distroless/cc-debian12:nonroot@sha256:",
            "distroless nonroot runtime base",
        )
    )
    failures.extend(
        require_runtime(
            dockerfile,
            'HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/registry-relay", "healthcheck"]',
            "shell-free registry-relay healthcheck",
        )
    )
    failures.extend(
        require_runtime(
            dockerfile,
            'COPY --from=builder --chown=65532:65532 /workspace/runtime-root/ /',
            "numeric nonroot-owned runtime directory skeleton",
        )
    )
    failures.extend(
        require_runtime(
            dockerfile,
            "WORKDIR /var/lib/registry-relay",
            "registry-relay working directory",
        )
    )
    failures.extend(
        require_runtime(
            dockerfile,
            "ENV REGISTRY_RELAY_CONFIG=/etc/registry-relay/config.yaml",
            "default config path",
        )
    )
    for needle, detail in [
        ("debian:bookworm-slim", "Debian slim runtime base"),
        ("apt-get", "package manager in runtime"),
        ("groupadd", "runtime group creation"),
        ("useradd", "runtime user creation"),
        ("/bin/sh", "shell dependency in runtime"),
        ("curl", "curl dependency in runtime"),
        ("wget", "wget dependency in runtime"),
    ]:
        failures.extend(forbid_runtime(dockerfile, needle, detail))
    for path in docs:
        failures.extend(forbid_documented_unpinned_build_context(path))
        failures.extend(
            require(
                path,
                "scripts/build-image.sh",
                "guarded container image build helper",
            )
        )

    if failures:
        print("Docker build contract check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("Docker build contract check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
