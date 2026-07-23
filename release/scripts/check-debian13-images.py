#!/usr/bin/env python3
"""Enforce the Debian 13 boundary for maintained Registry Stack images."""

from __future__ import annotations

import os
import re
import shlex
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
CI_WORKFLOW = Path(".github/workflows/ci.yml")
REGISTRYCTL_TUTORIAL_SCRIPT = Path("docs/site/scripts/check-registryctl-tutorials.sh")

PRODUCT_DOCKERFILES = (
    Path("crates/registry-relay/Dockerfile"),
    Path("crates/registry-relay/Dockerfile.demo"),
    Path("products/notary/Dockerfile"),
    Path("release/docker/Dockerfile.registry-notary"),
    Path("release/docker/Dockerfile.registry-relay"),
)

# Product-specific assertions below require these surfaces. The Debian
# generation and immutable-pin boundary is broader and is discovered from the
# repository instead of relying on this tuple.
REQUIRED_PRODUCT_SURFACES = PRODUCT_DOCKERFILES + (
    CI_WORKFLOW,
    Path(".github/workflows/release.yml"),
    Path("release/scripts/build-release-binaries.sh"),
    Path("crates/registry-relay/docs/ops.md"),
    Path("crates/registry-relay/docs/security-assurance.md"),
    Path("crates/registry-relay/scripts/check_docker_build_contract.py"),
    Path("crates/registry-relay/scripts/run-live-consultation-journey.sh"),
    REGISTRYCTL_TUTORIAL_SCRIPT,
    Path("products/notary/docs/security-assurance.md"),
)

EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".repo-docs-cache",
    ".research",
    ".venv",
    "__pycache__",
    "dist",
    "node_modules",
    "target",
}
# Historical release notes and .research preserve observations, not active policy.
EXCLUDED_PATH_PREFIXES = (Path("release/notes"),)
MARKDOWN_SUFFIXES = {".md", ".mdx"}
SHELL_SUFFIXES = {".bash", ".sh"}
PYTHON_SUFFIXES = {".py"}
JS_TS_SUFFIXES = {".js", ".mjs", ".ts"}
SCRIPT_SUFFIXES = SHELL_SUFFIXES | PYTHON_SUFFIXES | JS_TS_SUFFIXES
YAML_SUFFIXES = {".yaml", ".yml"}

RUST_BUILDER_DOCKERFILES = PRODUCT_DOCKERFILES[:3]
PREPARATION_DOCKERFILES = PRODUCT_DOCKERFILES[3:]
RELAY_DOCKERFILES = (
    Path("crates/registry-relay/Dockerfile"),
    Path("crates/registry-relay/Dockerfile.demo"),
    Path("release/docker/Dockerfile.registry-relay"),
)
NOTARY_DOCKERFILES = (
    Path("products/notary/Dockerfile"),
    Path("release/docker/Dockerfile.registry-notary"),
)

FROM_RE = re.compile(
    r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?",
    re.IGNORECASE | re.MULTILINE,
)
DIGEST_PIN_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
CONTAINER_REFERENCE_RE = re.compile(
    r"(?<![A-Za-z0-9._/@+-])"
    r"(?P<reference>"
    r"(?:[A-Za-z0-9.-]+(?::[0-9]+)?/)*"
    r"[A-Za-z0-9._-]+:[A-Za-z0-9._-]+"
    r"(?:@sha256:[0-9a-f]{64})?"
    r")"
    r"(?![A-Za-z0-9._/@+-])",
    re.IGNORECASE,
)
IMAGE_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:export\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s*(?:=|:)\s*"
    r"(?P<reference>[^#\s]+)",
)
PY_IMAGE_ASSIGNMENT_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*(?P<value>.*)$"
)
JS_TS_IMAGE_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
    r"\s*(?::[^=]+)?=\s*(?P<value>.*)$"
)
STRING_LITERAL_RE = re.compile(
    r"\"(?P<double>(?:\\.|[^\"\\])*)\"|'(?P<single>(?:\\.|[^'\\])*)'"
)
UNTAGGED_IMAGE_REFERENCE_RE = re.compile(
    r"(?:[A-Za-z0-9.-]+(?::[0-9]+)?/)*[A-Za-z0-9._-]+",
)
VERSION_ONLY_TAG_RE = re.compile(r"^[0-9]+(?:[._][0-9]+)*$")
DEBIAN_DEFAULT_IMAGE_NAMES = {
    "buildpack-deps",
    "debian",
    "golang",
    "node",
    "python",
    "rust",
}
CONTAINER_COMMANDS = {"create", "pull", "run"}
CONTAINER_BOOLEAN_OPTIONS = {
    "--detach",
    "--init",
    "--interactive",
    "--no-healthcheck",
    "--oom-kill-disable",
    "--privileged",
    "--publish-all",
    "--quiet",
    "--read-only",
    "--rm",
    "--tty",
    "-d",
    "-i",
    "-it",
    "-P",
    "-q",
    "-t",
}


def is_excluded(relative: Path) -> bool:
    if ".research" in relative.parts:
        return True
    return any(
        relative == prefix or prefix in relative.parents
        for prefix in EXCLUDED_PATH_PREFIXES
    )


def is_dockerfile(relative: Path) -> bool:
    return (
        relative.name == "Dockerfile"
        or relative.name.startswith("Dockerfile.")
        or relative.name.endswith(".Dockerfile")
    )


def is_active_script(relative: Path) -> bool:
    return relative.suffix in {".bash", ".sh"} or (
        "scripts" in relative.parts
        and (relative.suffix in SCRIPT_SUFFIXES or not relative.suffix)
    )


def is_workflow(relative: Path) -> bool:
    return relative.parts[:2] == (".github", "workflows")


def is_maintained_text_surface(relative: Path) -> bool:
    return (
        is_dockerfile(relative)
        or is_active_script(relative)
        or is_workflow(relative)
        or relative.suffix in MARKDOWN_SUFFIXES
        or relative.suffix in YAML_SUFFIXES
    )


def is_image_reference_surface(relative: Path) -> bool:
    return (
        is_dockerfile(relative)
        or is_active_script(relative)
        or relative.suffix in YAML_SUFFIXES
    )


def discover_maintained_surfaces(root: Path) -> tuple[Path, ...]:
    """Discover maintained image policy surfaces without walking build output."""

    discovered: set[Path] = set()
    for directory, directory_names, file_names in os.walk(root):
        directory_path = Path(directory)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in EXCLUDED_DIRECTORY_NAMES
            and not is_excluded((directory_path / name).relative_to(root))
        )
        for name in file_names:
            relative = (directory_path / name).relative_to(root)
            if is_excluded(relative) or not is_maintained_text_surface(relative):
                continue
            discovered.add(relative)
    return tuple(sorted(discovered))


def is_debian_derived(reference: str) -> bool:
    unpinned = reference.split("@", 1)[0]
    repository, tag = unpinned.rsplit(":", 1)
    image_name = repository.rsplit("/", 1)[-1].casefold()
    lowered_tag = tag.casefold()
    generation_tags = ("trixie", "book" + "worm", "bullseye", "buster")
    return (
        image_name == "debian"
        or "debian" in image_name
        or any(marker in lowered_tag for marker in generation_tags)
        or re.search(r"(?:^|[-_.])debian-?1[0-9](?:$|[-_.])", lowered_tag)
        is not None
    )


def retired_generation_marker(reference: str) -> str | None:
    lowered = reference.casefold()
    for marker in ("book" + "worm", "debian" + "12"):
        if marker in lowered:
            return marker
    return None


def is_debian_default_version_only(reference: str) -> bool:
    unpinned = reference.split("@", 1)[0]
    if ":" not in unpinned:
        return False
    repository, tag = unpinned.rsplit(":", 1)
    image_name = repository.rsplit("/", 1)[-1].casefold()
    return (
        image_name in DEBIAN_DEFAULT_IMAGE_NAMES
        and VERSION_ONLY_TAG_RE.fullmatch(tag) is not None
    )


def is_untagged_debian_derived(reference: str) -> bool:
    if UNTAGGED_IMAGE_REFERENCE_RE.fullmatch(reference) is None:
        return False
    if ":" in reference or "@" in reference:
        return False
    image_name = reference.rsplit("/", 1)[-1].casefold()
    return "debian" in image_name or image_name in DEBIAN_DEFAULT_IMAGE_NAMES


def is_image_assignment(name: str) -> bool:
    lowered = name.casefold().replace("$", "")
    return lowered in {"container", "image"} or lowered.endswith("image")


def logical_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    start = 0
    parts: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        if not parts:
            start = line_number
        stripped = raw_line.rstrip()
        continued = stripped.endswith("\\")
        parts.append(stripped[:-1] if continued else stripped)
        if not continued:
            lines.append((start, " ".join(parts)))
            parts = []
    if parts:
        lines.append((start, " ".join(parts)))
    return lines


def command_image_reference(command: str) -> str | None:
    try:
        tokens = shlex.split(command, comments=True, posix=True)
    except ValueError:
        return None
    for container_index, token in enumerate(tokens):
        if token not in {"docker", "podman"}:
            continue
        prefix = tokens[:container_index]
        if any(
            item not in {"-", "command", "env", "sudo"}
            and "=" not in item
            and not item.endswith(":")
            for item in prefix
        ):
            continue
        action_index = container_index + 1
        if action_index >= len(tokens):
            continue
        action = tokens[action_index]
        if action in {"container", "image"} and action_index + 1 < len(tokens):
            action_index += 1
            action = tokens[action_index]
        if action not in CONTAINER_COMMANDS:
            continue
        index = action_index + 1
        while index < len(tokens):
            candidate = tokens[index]
            if candidate == "--":
                index += 1
                break
            if not candidate.startswith("-"):
                break
            if "=" in candidate or candidate in CONTAINER_BOOLEAN_OPTIONS:
                index += 1
            else:
                index += 2
        if index < len(tokens):
            return tokens[index]
    return None


def decode_string_literal(value: str) -> str:
    return value.replace(r"\/", "/").replace(r"\"", '"').replace(r"\'", "'")


def string_literals(line: str) -> list[str]:
    values: list[str] = []
    for match in STRING_LITERAL_RE.finditer(line):
        raw = match.group("double") if match.group("double") is not None else match.group("single")
        values.append(decode_string_literal(raw))
    return values


def reference_candidates(value: str) -> list[str]:
    stripped = value.strip().strip(";").strip(",").strip("\"'")
    candidates = [match.group("reference") for match in CONTAINER_REFERENCE_RE.finditer(value)]
    if stripped and is_untagged_debian_derived(stripped):
        candidates.append(stripped)
    return candidates


def assignment_match(relative: Path, line: str) -> tuple[str, str] | None:
    if relative.suffix in PYTHON_SUFFIXES:
        match = PY_IMAGE_ASSIGNMENT_RE.match(line)
        if match is None:
            return None
        return match.group("name"), match.group("value")
    if relative.suffix in JS_TS_SUFFIXES:
        match = JS_TS_IMAGE_ASSIGNMENT_RE.match(line)
        if match is None:
            return None
        return match.group("name"), match.group("value")
    match = IMAGE_ASSIGNMENT_RE.match(line)
    if match is None:
        return None
    return match.group("name"), match.group("reference")


def assignment_continues(relative: Path, value: str) -> bool:
    stripped = value.strip()
    if relative.suffix not in PYTHON_SUFFIXES | JS_TS_SUFFIXES:
        return False
    if stripped.endswith("\\") or stripped in {"", "(", "["}:
        return True
    if stripped.count("(") > stripped.count(")"):
        return True
    if relative.suffix in JS_TS_SUFFIXES and not stripped.endswith(";"):
        return not string_literals(stripped)
    return False


def image_assignment_references(relative: Path, text: str) -> list[tuple[int, str]]:
    references: set[tuple[int, str]] = set()
    active = False
    for line_number, line in enumerate(text.splitlines(), 1):
        if active:
            for literal in string_literals(line):
                for reference in reference_candidates(literal):
                    references.add((line_number, reference))
            stripped = line.strip()
            if stripped.endswith((")", "];", ";")) or stripped == ")":
                active = False
            continue

        matched = assignment_match(relative, line)
        if matched is None:
            continue
        name, value = matched
        if not is_image_assignment(name):
            continue
        literals = string_literals(value)
        if literals:
            for literal in literals:
                for reference in reference_candidates(literal):
                    references.add((line_number, reference))
        else:
            for reference in reference_candidates(value):
                references.add((line_number, reference))
        active = assignment_continues(relative, value)
    return sorted(references)


def command_image_references(relative: Path, text: str) -> list[tuple[int, str]]:
    if relative.suffix not in SHELL_SUFFIXES | YAML_SUFFIXES and relative.suffix:
        return []
    references: set[tuple[int, str]] = set()
    for line_number, command in logical_lines(text):
        reference = command_image_reference(command)
        if reference is not None:
            references.add((line_number, reference))
    return sorted(references)


def image_references(relative: Path, text: str) -> list[tuple[int, str]]:
    return sorted(
        set(image_assignment_references(relative, text))
        | set(command_image_references(relative, text))
    )


def reference_requires_digest(reference: str) -> bool:
    if DIGEST_PIN_RE.search(reference):
        return False
    if ":" in reference:
        return is_debian_derived(reference) or is_debian_default_version_only(reference)
    return is_untagged_debian_derived(reference)


def read(root: Path, relative: Path, failures: list[str]) -> str:
    path = root / relative
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        failures.append(f"missing maintained image surface: {relative}")
        return ""
    except UnicodeDecodeError:
        failures.append(f"maintained image surface is not UTF-8 text: {relative}")
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


def registryctl_tutorial_cache_step(text: str) -> str:
    start = text.find("- name: Cache source-under-test Cargo build")
    if start < 0:
        return ""
    end = text.find("\n      - name: Execute registryctl tutorials from source", start)
    return text[start:] if end < 0 else text[start:end]


def check_repository(root: Path = ROOT) -> list[str]:
    failures: list[str] = []
    maintained_paths = discover_maintained_surfaces(root)
    all_paths = tuple(sorted(set(maintained_paths) | set(REQUIRED_PRODUCT_SURFACES)))
    texts = {
        relative: read(root, relative, failures)
        for relative in all_paths
    }

    dockerfiles = tuple(
        relative for relative in maintained_paths if is_dockerfile(relative)
    )
    if not dockerfiles:
        failures.append("no maintained Dockerfiles discovered")

    for relative in dockerfiles:
        text = texts[relative]
        bases = FROM_RE.findall(text)
        if not bases:
            failures.append(f"{relative}: no FROM instruction found")
            continue
        stage_names: set[str] = set()
        for base, stage_name in bases:
            internal_stage = base.casefold() in stage_names
            lowered_base = base.casefold()
            for marker in ("book" + "worm", "debian" + "12"):
                if not internal_stage and marker in lowered_base:
                    failures.append(
                        f"{relative}: retired Debian image generation marker remains: {marker}"
                    )
            if (
                base.casefold() != "scratch"
                and not internal_stage
                and not DIGEST_PIN_RE.search(base)
            ):
                failures.append(
                    f"{relative}: upstream base is not pinned by immutable digest: {base}"
                )
            if stage_name:
                stage_names.add(stage_name.casefold())

    for relative in maintained_paths:
        if not is_image_reference_surface(relative):
            continue
        text = texts[relative]
        for line, reference in image_references(relative, text):
            marker = retired_generation_marker(reference)
            if marker is not None:
                failures.append(
                    f"{relative}:{line}: retired Debian image generation marker "
                    f"remains in image reference: {marker}: {reference}"
                )
            if not reference_requires_digest(reference):
                continue
            failures.append(
                f"{relative}:{line}: Debian-derived image reference is not pinned "
                f"by immutable digest: {reference}"
            )

    for relative in PRODUCT_DOCKERFILES:
        text = texts[relative]
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

    ci_workflow = texts[CI_WORKFLOW]
    workflow = texts[Path(".github/workflows/release.yml")]
    binary_recipe = texts[Path("release/scripts/build-release-binaries.sh")]
    require(
        workflow,
        f"RELEASE_BUILDER_IMAGE: {RUST_BUILDER}",
        Path(".github/workflows/release.yml"),
        "pinned Debian 13 release builder",
        failures,
    )
    require(
        binary_recipe,
        "--features registry-notary/registry-notary-cel,registry-notary/pkcs11",
        Path("release/scripts/build-release-binaries.sh"),
        "PKCS#11-enabled release build",
        failures,
    )

    live_journey = texts[
        Path("crates/registry-relay/scripts/run-live-consultation-journey.sh")
    ]
    require(
        live_journey,
        RUST_BUILDER,
        Path("crates/registry-relay/scripts/run-live-consultation-journey.sh"),
        "pinned Debian 13 live-journey builder",
        failures,
    )
    tutorial_checker = texts[REGISTRYCTL_TUTORIAL_SCRIPT]
    tutorial_cache = registryctl_tutorial_cache_step(ci_workflow)
    require(
        tutorial_checker,
        'LINUX_TARGET="$REPO_ROOT/target/registryctl-tutorial-linux-amd64"',
        REGISTRYCTL_TUTORIAL_SCRIPT,
        "registryctl tutorial linux target path matching container target",
        failures,
    )
    require(
        tutorial_checker,
        'CARGO_HOME_DIR="$REPO_ROOT/target/registryctl-tutorial-cargo-home"',
        REGISTRYCTL_TUTORIAL_SCRIPT,
        "registryctl tutorial Cargo home path matching container Cargo home",
        failures,
    )
    require(
        tutorial_cache,
        "hashFiles('docs/site/scripts/check-registryctl-tutorials.sh')",
        CI_WORKFLOW,
        "registryctl tutorial cache key including builder-bearing script",
        failures,
    )
    require(
        tutorial_cache,
        "target/registryctl-tutorial-linux-amd64",
        CI_WORKFLOW,
        "registryctl tutorial linux target cache path",
        failures,
    )
    require(
        tutorial_cache,
        "target/registryctl-tutorial-cargo-home",
        CI_WORKFLOW,
        "registryctl tutorial Cargo home cache path",
        failures,
    )
    if "restore-keys:" in tutorial_cache:
        failures.append(
            f"{CI_WORKFLOW}: registryctl tutorial cache must not restore from "
            "pre-builder-identity keys"
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
