#!/usr/bin/env python3
"""Enforce the Debian 13 boundary for maintained Registry Stack images."""

from __future__ import annotations

import os
import re
import shlex
import sys
from functools import lru_cache
from pathlib import Path

try:
    import yaml
    from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
except ImportError as error:
    yaml = None
    MappingNode = Node = ScalarNode = SequenceNode = None
    YAML_IMPORT_ERROR = error
else:
    YAML_IMPORT_ERROR = None


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
    r"^\s*(?:-\s*)?(?:(?:export|local|readonly)(?:\s+-[A-Za-z]+\s+|\s+))?"
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
COPY_RE = re.compile(r"^\s*COPY\b(?P<args>.*)$", re.IGNORECASE)
SHELL_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
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
DOCKER_GLOBAL_BOOLEAN_OPTIONS = {
    "--debug",
    "--tls",
    "-D",
}
DOCKER_GLOBAL_VALUE_OPTIONS = {
    "--config",
    "--context",
    "--host",
    "--log-level",
    "-H",
}
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
    "--sig-proxy",
    "--tty",
    "-d",
    "-i",
    "-it",
    "-P",
    "-q",
    "-t",
}
SHELL_COMMAND_SEPARATORS = {";", "&&", "||", "&", "|", "|&"}
SHELL_COMMAND_CONTROL_PREFIXES = {
    "do",
    "elif",
    "else",
    "if",
    "then",
    "until",
    "while",
}
SHELL_OPEN_GROUP_PREFIXES = {"(", "{"}
SUPPORTED_SHELL_COMMANDS = {"bash", "dash", "ksh", "sh", "zsh"}
SHELL_COMMAND_SHORT_OPTIONS = set("abcefhklmnptuvxBCEHP")
MAX_SHELL_COMMAND_CHARS = 65_536
MAX_SHELL_COMMAND_TOKENS = 2_048
MAX_SHELL_RECURSION_DEPTH = 4
MAX_YAML_TEXT_CHARS = 2_000_000
MAX_YAML_DOCUMENTS = 128
MAX_YAML_NODES = 100_000
MAX_YAML_DEPTH = 64
KUBERNETES_CONTAINER_COLLECTIONS = {
    "containers", "ephemeralContainers", "initContainers"
}
COMMAND_BOOLEAN_OPTIONS = {"-p"}
ENV_BOOLEAN_OPTIONS = {"--debug", "--ignore-environment", "-i", "-v"}
ENV_VALUE_OPTIONS = {"--chdir", "--unset", "-C", "-u"}
SUDO_BOOLEAN_OPTIONS = {
    "--askpass",
    "--background",
    "--login",
    "--non-interactive",
    "--preserve-env",
    "--preserve-groups",
    "--set-home",
    "--stdin",
    "-A",
    "-E",
    "-H",
    "-P",
    "-S",
    "-b",
    "-i",
    "-k",
    "-n",
}
SUDO_VALUE_OPTIONS = {
    "--chdir",
    "--chroot",
    "--close-from",
    "--command-timeout",
    "--group",
    "--host",
    "--prompt",
    "--role",
    "--type",
    "--user",
    "-C",
    "-D",
    "-g",
    "-h",
    "-p",
    "-r",
    "-R",
    "-t",
    "-T",
    "-u",
}
MARKDOWN_SHELL_FENCE_LANGS = {"bash", "console", "sh", "shell", "terminal", "zsh"}
MARKDOWN_YAML_FENCE_LANGS = {"yaml", "yml"}
MARKDOWN_DOCKERFILE_FENCE_LANGS = {"dockerfile"}


class ImageSurfaceError(RuntimeError):
    """A maintained image surface could not be scanned conclusively."""


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
        or relative.suffix in MARKDOWN_SUFFIXES
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


def normalize_reference(reference: str) -> str:
    stripped = reference.strip().strip(",;").strip("\"'")
    if stripped.startswith("docker://"):
        stripped = stripped.removeprefix("docker://")
    return stripped


def repository_and_tag(reference: str) -> tuple[str, str | None]:
    unpinned = normalize_reference(reference).split("@", 1)[0]
    slash = unpinned.rfind("/")
    colon = unpinned.rfind(":")
    if colon > slash:
        return unpinned[:colon], unpinned[colon + 1:]
    return unpinned, None


def is_debian_derived(reference: str) -> bool:
    repository, tag = repository_and_tag(reference)
    if tag is None:
        return False
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
    repository, tag = repository_and_tag(reference)
    if tag is None:
        return False
    image_name = repository.rsplit("/", 1)[-1].casefold()
    return (
        image_name in DEBIAN_DEFAULT_IMAGE_NAMES
        and VERSION_ONLY_TAG_RE.fullmatch(tag) is not None
    )


def is_untagged_debian_derived(reference: str) -> bool:
    if UNTAGGED_IMAGE_REFERENCE_RE.fullmatch(reference) is None:
        return False
    repository, tag = repository_and_tag(reference)
    if tag is not None or "@" in reference:
        return False
    image_name = repository.rsplit("/", 1)[-1].casefold()
    return "debian" in image_name or image_name in DEBIAN_DEFAULT_IMAGE_NAMES


def is_image_assignment(name: str) -> bool:
    lowered = name.casefold().replace("$", "")
    return lowered in {"container", "image"} or lowered.endswith("image")


def numbered_logical_lines(
    numbered_lines: list[tuple[int, str]],
) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    start = 0
    parts: list[str] = []
    for line_number, raw_line in numbered_lines:
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


def logical_lines(text: str) -> list[tuple[int, str]]:
    return numbered_logical_lines(list(enumerate(text.splitlines(), 1)))


def shell_tokens(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError:
        return []


def shell_command_segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    segment: list[str] = []
    for token in tokens:
        if token in SHELL_COMMAND_SEPARATORS:
            if segment:
                segments.append(segment)
                segment = []
            continue
        segment.append(token)
    if segment:
        segments.append(segment)
    return segments


def skip_explicit_options(
    tokens: list[str],
    index: int,
    *,
    boolean_options: set[str],
    value_options: set[str],
    groupable_short_options: set[str],
    attached_value_options: set[str],
    optional_value_options: set[str] | None = None,
    split_string_options: set[str] | None = None,
) -> tuple[int | None, str | None]:
    optional_value_options = optional_value_options or set()
    split_string_options = split_string_options or set()
    while index < len(tokens):
        candidate = tokens[index]
        if candidate == "--":
            return index + 1, None
        if not candidate.startswith("-") or candidate == "-":
            return index, None
        split_option = candidate.split("=", 1)[0]
        attached_split = (
            "-S"
            if "-S" in split_string_options
            and candidate.startswith("-S")
            and candidate != "-S"
            else None
        )
        if split_option in split_string_options or attached_split is not None:
            if "=" in candidate:
                payload = candidate.split("=", 1)[1]
                suffix = tokens[index + 1 :]
            elif candidate in split_string_options:
                if index + 1 >= len(tokens):
                    return None, None
                payload = tokens[index + 1]
                suffix = tokens[index + 2 :]
            else:
                payload = candidate[len(attached_split) :]
                suffix = tokens[index + 1 :]
            return None, (
                payload if not suffix else f"{payload} {shlex.join(suffix)}"
            )
        if candidate in boolean_options:
            index += 1
            continue
        if candidate in value_options:
            if index + 1 >= len(tokens):
                return None, None
            index += 2
            continue
        if candidate.startswith("--") and "=" in candidate:
            option = candidate.split("=", 1)[0]
            if option in value_options | optional_value_options:
                index += 1
                continue
            return None, None
        if any(
            candidate.startswith(option) and len(candidate) > len(option)
            for option in attached_value_options
        ):
            index += 1
            continue
        if len(candidate) > 2 and all(
            character in groupable_short_options for character in candidate[1:]
        ):
            index += 1
            continue
        return None, None
    return index, None


def skip_time_prefix(tokens: list[str], index: int) -> int:
    index += 1
    if index < len(tokens) and tokens[index] == "-p":
        index += 1
    if index < len(tokens) and tokens[index] == "--":
        index += 1
    return index


def simple_command(tokens: list[str]) -> tuple[int | None, str | None]:
    """Locate a container CLI only through the supported shell prefix grammar."""

    index = 0
    if index < len(tokens) and tokens[index] == "$":
        index += 1

    while index < len(tokens) and tokens[index] in SHELL_OPEN_GROUP_PREFIXES:
        index += 1
    if index < len(tokens) and tokens[index] in SHELL_COMMAND_CONTROL_PREFIXES:
        index += 1
    while index < len(tokens) and tokens[index] in SHELL_OPEN_GROUP_PREFIXES:
        index += 1

    seen_negation = False
    seen_time = False
    while index < len(tokens):
        token = tokens[index]
        if token == "!" and not seen_negation:
            seen_negation = True
            index += 1
        elif token == "time" and not seen_time:
            seen_time = True
            index = skip_time_prefix(tokens, index)
        elif token in SHELL_OPEN_GROUP_PREFIXES:
            index += 1
        else:
            break

    while index < len(tokens):
        while index < len(tokens) and SHELL_ASSIGNMENT_RE.fullmatch(tokens[index]):
            index += 1
        if index >= len(tokens):
            return None, None

        wrapper = tokens[index]
        if wrapper == "time" and not seen_time:
            seen_time = True
            index = skip_time_prefix(tokens, index)
            continue
        if wrapper == "command":
            index, _ = skip_explicit_options(
                tokens,
                index + 1,
                boolean_options=COMMAND_BOOLEAN_OPTIONS,
                value_options=set(),
                groupable_short_options={"p"},
                attached_value_options=set(),
            )
        elif wrapper == "env":
            index, payload = skip_explicit_options(
                tokens,
                index + 1,
                boolean_options=ENV_BOOLEAN_OPTIONS,
                value_options=ENV_VALUE_OPTIONS,
                groupable_short_options={"i", "v"},
                attached_value_options={"-C", "-S", "-u"},
                split_string_options={"-S", "--split-string"},
            )
            if payload is not None:
                return None, payload
        elif wrapper == "sudo":
            index, _ = skip_explicit_options(
                tokens,
                index + 1,
                boolean_options=SUDO_BOOLEAN_OPTIONS,
                value_options=SUDO_VALUE_OPTIONS,
                groupable_short_options={"A", "E", "H", "P", "S", "b", "i", "k", "n"},
                attached_value_options={
                    "-C",
                    "-D",
                    "-g",
                    "-h",
                    "-p",
                    "-r",
                    "-R",
                    "-t",
                    "-T",
                    "-u",
                },
                optional_value_options={"--preserve-env"},
            )
        else:
            return index, None
        if index is None:
            return None, None
    return index, None


def skip_options(
    tokens: list[str],
    index: int,
    *,
    boolean_options: set[str],
    value_options: set[str],
) -> int:
    while index < len(tokens):
        candidate = tokens[index]
        if candidate == "--":
            return index + 1
        if not candidate.startswith("-"):
            return index
        if (
            "=" in candidate
            or candidate in boolean_options
            or any(
                candidate.startswith(f"{option}=")
                for option in value_options
                if option.startswith("--")
            )
        ):
            index += 1
        elif candidate in value_options:
            index += 2
        else:
            index += 2
    return index


def container_command_image_reference(
    tokens: list[str],
    container_index: int,
) -> str | None:
    if (
        container_index >= len(tokens)
        or tokens[container_index] not in {"docker", "podman"}
    ):
        return None
    action_index = skip_options(
        tokens,
        container_index + 1,
        boolean_options=DOCKER_GLOBAL_BOOLEAN_OPTIONS,
        value_options=DOCKER_GLOBAL_VALUE_OPTIONS,
    )
    if action_index >= len(tokens):
        return None
    action = tokens[action_index]
    if action in {"container", "image"} and action_index + 1 < len(tokens):
        action_index += 1
        action = tokens[action_index]
    if action not in CONTAINER_COMMANDS:
        return None
    index = action_index + 1
    index = skip_options(
        tokens,
        index,
        boolean_options=CONTAINER_BOOLEAN_OPTIONS,
        value_options=set(),
    )
    if index < len(tokens):
        return normalize_reference(tokens[index])
    return None


def shell_command_payload(tokens: list[str], command_index: int) -> str | None:
    command = tokens[command_index].rsplit("/", 1)[-1]
    if command not in SUPPORTED_SHELL_COMMANDS:
        return None
    index = command_index + 1
    while index < len(tokens):
        option = tokens[index]
        if option == "-c":
            return tokens[index + 1] if index + 1 < len(tokens) else None
        if (
            option.startswith("-")
            and not option.startswith("--")
            and len(option) > 2
            and all(character in SHELL_COMMAND_SHORT_OPTIONS for character in option[1:])
        ):
            if "c" in option[1:]:
                return tokens[index + 1] if index + 1 < len(tokens) else None
            index += 1
            continue
        if (
            len(option) == 2
            and option.startswith("-")
            and option[1] in SHELL_COMMAND_SHORT_OPTIONS
        ):
            index += 1
            continue
        return None
    return None


def command_segment_image_references(
    tokens: list[str],
    depth: int,
) -> list[str]:
    command_index, split_payload = simple_command(tokens)
    if split_payload is not None:
        return command_image_references_in_command(split_payload, depth=depth + 1)
    if command_index is None or command_index >= len(tokens):
        return []
    reference = container_command_image_reference(tokens, command_index)
    if reference is not None:
        return [reference]
    payload = shell_command_payload(tokens, command_index)
    if payload is not None:
        return command_image_references_in_command(payload, depth=depth + 1)
    return []


def command_image_references_in_command(
    command: str,
    *,
    depth: int = 0,
) -> list[str]:
    if depth > MAX_SHELL_RECURSION_DEPTH:
        raise ImageSurfaceError(
            f"shell command nesting exceeds {MAX_SHELL_RECURSION_DEPTH} levels"
        )
    if len(command) > MAX_SHELL_COMMAND_CHARS:
        raise ImageSurfaceError(
            f"shell command exceeds {MAX_SHELL_COMMAND_CHARS} characters"
        )
    tokens = shell_tokens(command)
    if len(tokens) > MAX_SHELL_COMMAND_TOKENS:
        raise ImageSurfaceError(
            f"shell command exceeds {MAX_SHELL_COMMAND_TOKENS} tokens"
        )
    references: list[str] = []
    for segment in shell_command_segments(tokens):
        references.extend(command_segment_image_references(segment, depth))
    return references


def decode_string_literal(value: str) -> str:
    return value.replace(r"\/", "/").replace(r"\"", '"').replace(r"\'", "'")


def string_literals(line: str) -> list[str]:
    values: list[str] = []
    for match in STRING_LITERAL_RE.finditer(line):
        raw = match.group("double") if match.group("double") is not None else match.group("single")
        values.append(decode_string_literal(raw))
    return values


def reference_candidates(value: str) -> list[str]:
    stripped = normalize_reference(value)
    candidates = [
        normalize_reference(match.group("reference"))
        for match in CONTAINER_REFERENCE_RE.finditer(value)
    ]
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
    if relative.suffix in YAML_SUFFIXES:
        references = set(yaml_declarative_image_references(relative, text))
        for line_number, command in yaml_executable_commands(relative, text):
            matched = assignment_match(relative, command)
            if matched is None:
                continue
            name, value = matched
            if not is_image_assignment(name):
                continue
            for reference in reference_candidates(value):
                references.add((line_number, reference))
        return sorted(references)

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


def require_yaml() -> None:
    if yaml is None:
        detail = f": {YAML_IMPORT_ERROR}" if YAML_IMPORT_ERROR is not None else ""
        raise ImageSurfaceError(
            "PyYAML is required to scan maintained YAML image surfaces" + detail
        )


@lru_cache(maxsize=4)
def compose_yaml_documents(text: str) -> tuple[Node, ...]:
    require_yaml()
    if len(text) > MAX_YAML_TEXT_CHARS:
        raise ImageSurfaceError(
            f"YAML input exceeds {MAX_YAML_TEXT_CHARS} characters"
        )
    try:
        documents: list[Node] = []
        document_count = 0
        for root in yaml.compose_all(text, Loader=yaml.SafeLoader):
            document_count += 1
            if root is not None:
                documents.append(root)
            if document_count > MAX_YAML_DOCUMENTS:
                raise ImageSurfaceError(
                    f"YAML input exceeds {MAX_YAML_DOCUMENTS} documents"
                )
        return tuple(documents)
    except RecursionError as error:
        raise ImageSurfaceError("YAML parser recursion limit exceeded") from error
    except yaml.YAMLError as error:
        detail = str(error).splitlines()[0] if str(error) else type(error).__name__
        raise ImageSurfaceError(f"invalid YAML: {detail}") from error


def yaml_mapping_entries(
    root: Node,
) -> list[tuple[tuple[str | int, ...], Node, Node]]:
    entries: list[tuple[tuple[str | int, ...], Node, Node]] = []
    stack: list[tuple[Node, tuple[str | int, ...], int, tuple[int, ...]]] = [
        (root, (), 0, ())
    ]
    visited_nodes = 0
    while stack:
        node, path, depth, ancestors = stack.pop()
        if depth > MAX_YAML_DEPTH:
            raise ImageSurfaceError(f"YAML nesting exceeds {MAX_YAML_DEPTH} levels")
        if id(node) in ancestors:
            raise ImageSurfaceError("recursive YAML aliases are not supported")
        visited_nodes += 1 + (len(node.value) if isinstance(node, MappingNode) else 0)
        if visited_nodes > MAX_YAML_NODES:
            raise ImageSurfaceError(f"YAML input exceeds {MAX_YAML_NODES} nodes")
        child_ancestors = ancestors + (id(node),)
        if isinstance(node, MappingNode):
            for key_node, value_node in reversed(node.value):
                key = (
                    key_node.value
                    if isinstance(key_node, ScalarNode)
                    and key_node.tag == "tag:yaml.org,2002:str"
                    else "<non-string-key>"
                )
                child_path = path + (key,)
                entries.append((child_path, key_node, value_node))
                stack.append((value_node, child_path, depth + 1, child_ancestors))
        elif isinstance(node, SequenceNode):
            for index, value_node in reversed(list(enumerate(node.value))):
                stack.append(
                    (value_node, path + (index,), depth + 1, child_ancestors)
                )
    return entries


def yaml_document_context(relative: Path, root: Node) -> tuple[bool, bool, bool]:
    fields = (
        {
            key.value: value
            for key, value in root.value
            if isinstance(key, ScalarNode)
            and key.tag == "tag:yaml.org,2002:str"
        }
        if isinstance(root, MappingNode)
        else {}
    )
    name = relative.name.casefold()
    compose = (
        name in {"compose.yaml", "compose.yml"}
        or name.startswith("docker-compose")
        or isinstance(fields.get("services"), MappingNode)
        and not {"registry", "starter", "integrations", "entities"} & set(fields)
    )
    return (
        is_workflow(relative) or isinstance(fields.get("jobs"), MappingNode),
        compose,
        {"apiVersion", "kind"} <= set(fields),
    )


def yaml_field_context(
    path: tuple[str | int, ...],
    context: tuple[bool, bool, bool],
) -> str:
    """Classify only GitHub Actions, Compose, Kubernetes, and image variables."""

    workflow, compose, kubernetes = context
    if (
        workflow
        and len(path) == 5
        and path[:1] == ("jobs",)
        and path[2] == "steps"
        and path[4] in {"run", "uses"}
    ):
        return f"workflow_{path[4]}"
    if workflow and path[:1] == ("jobs",) and (
        len(path) == 3 and path[2] == "container"
        or len(path) == 4 and path[2:] == ("container", "image")
        or len(path) == 5 and path[2] == "services" and path[4] == "image"
    ):
        return "image"
    if compose and len(path) == 3 and path[0] == "services":
        return f"compose_{path[2]}"
    if kubernetes and len(path) >= 4 and (
        path[-3] in KUBERNETES_CONTAINER_COLLECTIONS
        and isinstance(path[-2], int)
        and "spec" in path[:-3]
    ):
        return f"kubernetes_{path[-1]}"
    key = str(path[-1]) if path else ""
    lowered = key.casefold().replace("-", "_")
    return (
        "image"
        if key == "IMAGE"
        or lowered.endswith("_image")
        or key != lowered and lowered.endswith("image")
        else ""
    )


def yaml_scalar_commands(
    node: ScalarNode,
    lines: list[str],
) -> list[tuple[int, str]]:
    if node.tag != "tag:yaml.org,2002:str" or not node.value:
        return []
    if node.style == ">":
        source_line = node.start_mark.line + 1
        return [
            (source_line, command)
            for _, command in logical_lines(node.value)
        ]
    if node.style != "|":
        source_line = node.start_mark.line + 1
        return [
            (source_line + line_number - 1, command)
            for line_number, command in logical_lines(node.value)
        ]

    content = [
        (index + 1, lines[index])
        for index in range(
            node.start_mark.line + 1,
            min(node.end_mark.line, len(lines)),
        )
    ]
    indents = [
        len(line) - len(line.lstrip(" "))
        for _, line in content
        if line.strip()
    ]
    if not indents:
        return []
    content_indent = min(indents)
    return numbered_logical_lines(
        [
            (line_number, line[content_indent:] if line.strip() else "")
            for line_number, line in content
        ]
    )


def yaml_sequence_argv(node: Node) -> list[str] | None:
    if not isinstance(node, SequenceNode):
        return None
    values = [
        item.value
        for item in node.value
        if isinstance(item, ScalarNode)
        and item.tag == "tag:yaml.org,2002:str"
    ]
    return values if len(values) == len(node.value) else None


@lru_cache(maxsize=4)
def yaml_surface_values(
    relative: Path,
    text: str,
) -> tuple[tuple[tuple[int, str], ...], tuple[tuple[int, str], ...]]:
    """Return commands and image references from the finite YAML support matrix."""

    roots = compose_yaml_documents(text)
    lines = text.splitlines()
    commands: list[tuple[int, str]] = []
    references: set[tuple[int, str]] = set()
    for root in roots:
        document_context = yaml_document_context(relative, root)
        kubernetes_argv: dict[
            tuple[str | int, ...], dict[str, tuple[int, list[str]]]
        ] = {}
        for path, key_node, value_node in yaml_mapping_entries(root):
            context = yaml_field_context(path, document_context)
            if context == "workflow_run" and isinstance(value_node, ScalarNode):
                commands.extend(yaml_scalar_commands(value_node, lines))
                continue
            if context in {"compose_command", "compose_entrypoint"}:
                if isinstance(value_node, ScalarNode):
                    commands.extend(yaml_scalar_commands(value_node, lines))
                else:
                    argv = yaml_sequence_argv(value_node)
                    if argv:
                        commands.append((key_node.start_mark.line + 1, shlex.join(argv)))
                continue
            if context in {"kubernetes_command", "kubernetes_args"}:
                argv = yaml_sequence_argv(value_node)
                if argv is not None:
                    kubernetes_argv.setdefault(path[:-1], {})[context] = (
                        key_node.start_mark.line + 1,
                        argv,
                    )
                continue
            if (
                context
                not in {
                    "compose_image",
                    "image",
                    "kubernetes_image",
                    "workflow_uses",
                }
                or not isinstance(key_node, ScalarNode)
                or not isinstance(value_node, ScalarNode)
                or value_node.tag != "tag:yaml.org,2002:str"
            ):
                continue
            value = value_node.value
            if context == "workflow_uses" and not value.casefold().startswith("docker://"):
                continue
            for reference in reference_candidates(normalize_reference(value)):
                references.add((key_node.start_mark.line + 1, reference))
        for fields in kubernetes_argv.values():
            command = fields.get("kubernetes_command")
            args = fields.get("kubernetes_args", (0, []))[1]
            if command is not None and command[1] + args:
                commands.append((command[0], shlex.join(command[1] + args)))
    return tuple(commands), tuple(sorted(references))


def yaml_executable_commands(relative: Path, text: str) -> list[tuple[int, str]]:
    return list(yaml_surface_values(relative, text)[0])


def yaml_declarative_image_references(
    relative: Path,
    text: str,
) -> list[tuple[int, str]]:
    return list(yaml_surface_values(relative, text)[1])


def command_image_references(relative: Path, text: str) -> list[tuple[int, str]]:
    if relative.suffix not in SHELL_SUFFIXES | YAML_SUFFIXES and relative.suffix:
        return []
    references: set[tuple[int, str]] = set()
    commands = (
        yaml_executable_commands(relative, text)
        if relative.suffix in YAML_SUFFIXES
        else logical_lines(text)
    )
    for line_number, command in commands:
        for reference in command_image_references_in_command(command):
            references.add((line_number, reference))
    return sorted(references)


def markdown_code_blocks(text: str) -> list[tuple[int, str, str]]:
    blocks: list[tuple[int, str, str]] = []
    block_lines: list[str] = []
    block_start = 0
    language = ""
    in_block = False
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_block:
                blocks.append((block_start, language, "\n".join(block_lines)))
                block_lines = []
                in_block = False
            else:
                block_start = line_number + 1
                info = stripped.removeprefix("```").strip().split(maxsplit=1)
                language = info[0].casefold() if info else ""
                in_block = True
            continue
        if in_block:
            block_lines.append(line)
    return blocks


def dockerfile_reference_lines(text: str) -> list[tuple[int, str]]:
    references: list[tuple[int, str]] = []
    stage_names: set[str] = set()
    for match in FROM_RE.finditer(text):
        base = normalize_reference(match.group(1))
        line = text.count("\n", 0, match.start()) + 1
        if base.casefold() != "scratch" and base.casefold() not in stage_names:
            references.append((line, base))
        stage_name = match.group(2)
        if stage_name:
            stage_names.add(stage_name.casefold())
    references.extend(copy_from_references(text, stage_names))
    return references


def markdown_image_references(text: str) -> list[tuple[int, str]]:
    references: set[tuple[int, str]] = set()
    for start_line, language, block in markdown_code_blocks(text):
        if language in MARKDOWN_SHELL_FENCE_LANGS:
            block_relative = Path("example.sh")
            block_references = command_image_references(block_relative, block)
        elif language in MARKDOWN_YAML_FENCE_LANGS:
            block_relative = Path("example.yaml")
            block_references = image_references(block_relative, block)
        elif language in MARKDOWN_DOCKERFILE_FENCE_LANGS:
            block_references = dockerfile_reference_lines(block)
        else:
            continue
        for line_number, reference in block_references:
            references.add((start_line + line_number - 1, reference))
    return sorted(references)


def image_references(relative: Path, text: str) -> list[tuple[int, str]]:
    if relative.suffix in MARKDOWN_SUFFIXES:
        return markdown_image_references(text)
    return sorted(
        set(image_assignment_references(relative, text))
        | set(command_image_references(relative, text))
    )


def reference_requires_digest(reference: str) -> bool:
    if DIGEST_PIN_RE.search(reference):
        return False
    _, tag = repository_and_tag(reference)
    if tag is not None:
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


def copy_from_references(text: str, stage_names: set[str]) -> list[tuple[int, str]]:
    references: list[tuple[int, str]] = []
    for line_number, line in logical_lines(text):
        match = COPY_RE.match(line)
        if match is None:
            continue
        try:
            tokens = shlex.split(match.group("args"), comments=True, posix=True)
        except ValueError:
            continue
        index = 0
        while index < len(tokens):
            token = tokens[index]
            source: str | None = None
            if token == "--from" and index + 1 < len(tokens):
                source = tokens[index + 1]
                index += 2
            elif token.startswith("--from="):
                source = token.split("=", 1)[1]
                index += 1
            elif token.startswith("--"):
                index += 1
            else:
                break
            if source is None:
                continue
            normalized = normalize_reference(source)
            if normalized.casefold() in stage_names or normalized.isdigit():
                continue
            references.append((line_number, normalized))
    return references


def append_reference_failures(
    failures: list[str],
    relative: Path,
    line: int,
    reference: str,
) -> None:
    marker = retired_generation_marker(reference)
    if marker is not None:
        failures.append(
            f"{relative}:{line}: retired Debian image generation marker "
            f"remains in image reference: {marker}: {reference}"
        )
    if reference_requires_digest(reference):
        failures.append(
            f"{relative}:{line}: Debian-derived image reference is not pinned "
            f"by immutable digest: {reference}"
        )


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
        for line, reference in copy_from_references(text, stage_names):
            append_reference_failures(failures, relative, line, reference)

    for relative in maintained_paths:
        if not is_image_reference_surface(relative):
            continue
        text = texts[relative]
        try:
            references = image_references(relative, text)
        except ImageSurfaceError as error:
            failures.append(f"{relative}: image scan failed: {error}")
            continue
        for line, reference in references:
            append_reference_failures(failures, relative, line, reference)

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
