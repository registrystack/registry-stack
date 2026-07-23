#!/usr/bin/env python3
"""Enforce the Debian 13 boundary for maintained Registry Stack images."""

from __future__ import annotations

import os
import re
import subprocess
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
TUTORIAL_SCRIPT = Path("docs/site/scripts/check-registryctl-tutorials.sh")
PRODUCT_DOCKERFILES = (
    Path("crates/registry-relay/Dockerfile"),
    Path("crates/registry-relay/Dockerfile.demo"),
    Path("products/notary/Dockerfile"),
    Path("release/docker/Dockerfile.registry-notary"),
    Path("release/docker/Dockerfile.registry-relay"),
)
REQUIRED_PRODUCT_SURFACES = PRODUCT_DOCKERFILES + (
    CI_WORKFLOW,
    Path(".github/workflows/release.yml"),
    Path("release/scripts/build-release-binaries.sh"),
    Path("crates/registry-relay/scripts/run-live-consultation-journey.sh"),
    TUTORIAL_SCRIPT,
)
RELAY_DOCKERFILES = (
    PRODUCT_DOCKERFILES[0],
    PRODUCT_DOCKERFILES[1],
    PRODUCT_DOCKERFILES[4],
)
NOTARY_DOCKERFILES = (PRODUCT_DOCKERFILES[2], PRODUCT_DOCKERFILES[3])

# Scan tracked UTF-8 text, excluding only historical evidence, third-party or
# generated material, build output, and this checker's negative fixtures.
EXCLUDED_DIRS = set(
    ".git .repo-docs-cache .research .venv __pycache__ dist node_modules target".split()
)
EXCLUDED_PREFIXES = ("external/", "release/notes/")
EXCLUDED_EXACT = {
    "release/scripts/check-debian13-images.py",
    "release/scripts/test_check_debian13_images.py",
}
MAX_TRACKED_PATHS = 10_000
MAX_TEXT_FILE_BYTES = 2_000_000
MAX_TOTAL_TEXT_BYTES = 32_000_000
MAX_LINE_CHARS = 131_072

RETIRED_MARKERS = (
    "book" + "worm",
    "bullseye",
    "buster",
    "debian" + "12",
    "debian-12",
    "debian" + "11",
    "debian-11",
    "debian" + "10",
    "debian-10",
)
DEFAULT_DEBIAN_FAMILIES = {"golang", "node", "postgres", "python", "rust"}
OCI_RE = re.compile(
    r"(?<![A-Za-z0-9._/@+-])(?P<ref>(?:docker://)?"
    r"(?:[A-Za-z0-9._-]+(?::[0-9]+)?/)*[A-Za-z0-9._-]+"
    r"(?::[A-Za-z0-9_][A-Za-z0-9._-]*|@sha256:[0-9a-fA-F]{64})"
    r"(?:@sha256:[0-9a-fA-F]{64})?)(?![A-Za-z0-9._/@+-])"
)
BARE_DEFAULT_FAMILY_RE = re.compile(
    rf"(?<![A-Za-z0-9._@+-])(?P<ref>(?:[A-Za-z0-9._-]+(?::[0-9]+)?/)*"
    rf"(?P<name>debian|{'|'.join(sorted(DEFAULT_DEBIAN_FAMILIES))}))"
    r"(?![A-Za-z0-9._/@+:-])"
)
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$", re.IGNORECASE)
FROM_RE = re.compile(
    r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?",
    re.IGNORECASE | re.MULTILINE,
)
ASSIGN_RE = re.compile(
    r"^\s*(?:-\s*)?(?:(?:export|local|readonly|const|let|var)\b[^A-Za-z_]*)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_$-]*)(?:\s*:[^=]+)?"
    r"\s*=\s*(?P<value>.+)$"
)
YAML_KEY_RE = re.compile(
    r"^\s*(?:-\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_$-]*)\s*:\s*(?P<value>.+)$"
)
YAML_FIELD_RE = re.compile(
    r"^(?P<indent>\s*)(?P<item>-\s*)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_$-]*)\s*:\s*(?P<value>.*)$"
)
IMAGE_VAR_RE = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_$-]*(?:_image|Image)|IMAGE)\b",
    re.IGNORECASE,
)
CLI_RE = re.compile(r"(?:^|[\s;&|({])(?:\S*/)?(?:docker|podman)\b(?P<tail>[^\n]*)")
NON_IMAGE_NAMESPACES = set("build buildx compose exec network volume".split())
IMAGE_ALIAS_NAME = r"(?:[A-Za-z_][A-Za-z0-9_]*(?:_IMAGE|Image)|IMAGE)"
DIRECT_IMAGE_ALIAS_RE = re.compile(
    rf"""^["']?\$(?:{IMAGE_ALIAS_NAME}|\{{{IMAGE_ALIAS_NAME}\}})["']?;?$""",
    re.IGNORECASE,
)
IMAGE_FALLBACK_RE = re.compile(
    rf"""^["']?\$\{{{IMAGE_ALIAS_NAME}:-(?:\${IMAGE_ALIAS_NAME}|"""
    rf"""\$\{{{IMAGE_ALIAS_NAME}\}})\}}["']?;?$""",
    re.IGNORECASE,
)
SIMPLE_SHELL_VAR = r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})"
SAFE_TAG_TEMPLATE_RE = re.compile(
    rf"""^["']?(?P<repository>(?:[A-Za-z0-9._-]+(?::[0-9]+)?/)*"""
    rf"""[A-Za-z0-9._-]+):(?:[A-Za-z0-9_.-]|{SIMPLE_SHELL_VAR})+["']?;?$"""
)
COMPUTED_VALUE_RE = re.compile(r"[+%]|`|\$\(|\.format\(|\bf[\"']")
CLI_TOKEN_RE = re.compile(r""""[^"\n]*"|'[^'\n]*'|[^\s,;\[\]]+""")
CONTAINER_VALUE_OPTIONS = {
    "--add-host",
    "--annotation",
    "--attach",
    "--cap-add",
    "--cap-drop",
    "--cgroupns",
    "--cidfile",
    "--cpus",
    "--device",
    "--dns",
    "--dns-search",
    "--entrypoint",
    "--env",
    "--env-file",
    "--expose",
    "--gpus",
    "--group-add",
    "--health-cmd",
    "--health-interval",
    "--health-retries",
    "--health-timeout",
    "--hostname",
    "--ipc",
    "--label",
    "--link",
    "--log-driver",
    "--log-opt",
    "--mac-address",
    "--memory",
    "--mount",
    "--name",
    "--network",
    "--pid",
    "--platform",
    "--publish",
    "--pull",
    "--restart",
    "--runtime",
    "--security-opt",
    "--shm-size",
    "--stop-signal",
    "--stop-timeout",
    "--tmpfs",
    "--ulimit",
    "--user",
    "--volume",
    "--workdir",
    "-a",
    "-e",
    "-h",
    "-l",
    "-m",
    "-p",
    "-u",
    "-v",
    "-w",
}
CONTAINER_FLAG_OPTIONS = {
    "--detach",
    "--init",
    "--interactive",
    "--privileged",
    "--quiet",
    "--read-only",
    "--rm",
    "--tty",
    "-d",
    "-i",
    "-it",
    "-q",
    "-t",
}
PULL_FLAG_OPTIONS = {"--all-tags", "--disable-content-trust", "-a", "-q"}
SHORT_VALUE_OPTIONS = ("-e", "-h", "-l", "-m", "-p", "-u", "-v", "-w")
DOCKER_CONTEXT_RE = re.compile(
    r"docker-image://(?P<ref>(?:[A-Za-z0-9._-]+(?::[0-9]+)?/)*"
    r"[A-Za-z0-9._-]+(?:\:[A-Za-z0-9_][A-Za-z0-9._-]*)?"
    r"(?:@sha256:[0-9a-fA-F]{64})?)(?![A-Za-z0-9._/@+-])"
)
EXEMPTION_RE = re.compile(
    r'<!--\s*debian13-policy:\s*allow-prose\s+reason="[^"]{8,}"\s*-->'
)
MARKDOWN_SUFFIXES = {".md", ".mdx"}
CODE_SUFFIXES = set(".bash .js .mjs .py .sh .ts .yaml .yml".split())
FENCE_LANGS = set(
    "bash console dockerfile javascript js python sh shell terminal "
    "ts typescript yaml yml zsh".split()
)


class ImageSurfaceError(RuntimeError):
    """A maintained text surface exceeded a scanner boundary."""


def is_dockerfile(path: Path) -> bool:
    name = path.name.casefold()
    return (
        name == "dockerfile"
        or name.startswith("dockerfile.")
        or name.endswith(".dockerfile")
    )


def is_excluded(path: Path) -> bool:
    value = path.as_posix()
    return (
        value in EXCLUDED_EXACT
        or any(part in EXCLUDED_DIRS for part in path.parts)
        or any(value.startswith(prefix) for prefix in EXCLUDED_PREFIXES)
        or path.name in {"CHANGELOG.md", "release-notes.md"}
        or value == "docs/site/src/content/docs/changelog.mdx"
        or "/resources/scalar/" in f"/{value}/"
    )


def discover_maintained_surfaces(root: Path) -> tuple[Path, ...]:
    command = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=False,
    )
    if command.returncode == 0:
        paths = [Path(item.decode()) for item in command.stdout.split(b"\0") if item]
    else:
        paths = []
        for directory, names, files in os.walk(root):
            names[:] = [name for name in names if name not in EXCLUDED_DIRS]
            paths.extend((Path(directory) / name).relative_to(root) for name in files)
    if len(paths) > MAX_TRACKED_PATHS:
        raise ImageSurfaceError(
            f"tracked path count exceeds {MAX_TRACKED_PATHS}: {len(paths)}"
        )
    return tuple(
        sorted(
            path
            for path in paths
            if not is_excluded(path)
            and (root / path).is_file()
            and not (root / path).is_symlink()
        )
    )


def read_text(root: Path, path: Path) -> tuple[str | None, int]:
    target = root / path
    try:
        size = target.stat().st_size
    except FileNotFoundError:
        return None, 0
    if size > MAX_TEXT_FILE_BYTES:
        with target.open("rb") as stream:
            sample = stream.read(8192)
        try:
            sample.decode()
        except UnicodeDecodeError:
            return None, 0
        if b"\0" in sample:
            return None, 0
        raise ImageSurfaceError(
            f"{path}: text file exceeds {MAX_TEXT_FILE_BYTES} bytes"
        )
    data = target.read_bytes()
    if b"\0" in data:
        return None, 0
    try:
        return data.decode(), size
    except UnicodeDecodeError:
        return None, 0


def references(text: str) -> list[str]:
    return [
        match.group("ref").removeprefix("docker://").strip("\"',;")
        for match in OCI_RE.finditer(text)
    ]


def exact_reference(value: str) -> str | None:
    candidate = value.strip().removesuffix(";").strip()
    if len(candidate) >= 2 and candidate[0] == candidate[-1] and candidate[0] in "\"'":
        candidate = candidate[1:-1]
    found = references(candidate)
    normalized = candidate.removeprefix("docker://")
    return found[0] if len(found) == 1 and found[0] == normalized else None


def repository_and_tag(reference: str) -> tuple[str, str | None]:
    value = reference.split("@", 1)[0]
    slash, colon = value.rfind("/"), value.rfind(":")
    return (value[:colon], value[colon + 1 :]) if colon > slash else (value, None)


def is_debian_family(reference: str) -> bool:
    repository, tag = repository_and_tag(reference)
    name, tag = repository.rsplit("/", 1)[-1].casefold(), (tag or "").casefold()
    default = name in DEFAULT_DEBIAN_FAMILIES
    excluded = default and ("alpine" in tag or "windows" in tag)
    return not excluded and (
        "debian" in name
        or name == "buildpack-deps"
        or "trixie" in tag
        or re.search(r"debian-?13", tag) is not None
        or default
        and (
            not tag
            or tag in {"latest", "slim"}
            or re.fullmatch(r"[0-9]+(?:[._][0-9]+)*(?:-slim)?", tag) is not None
        )
    )


def assignment(path: Path, line: str) -> tuple[str, str] | None:
    match = (YAML_KEY_RE if path.suffix in {".yaml", ".yml"} else ASSIGN_RE).match(line)
    if match is None:
        return None
    name = match.group("name")
    value = match.group("value").strip()
    if value.rstrip(",") in {"(", "[", "{"} or value.endswith(","):
        return None
    normalized = re.sub("[^A-Za-z0-9]", "", name).casefold()
    return (
        (name, match.group("value"))
        if normalized.endswith("image") or normalized == "container"
        else None
    )


def command_tokens(value: str) -> list[str]:
    command = re.split(r"\s*(?:&&|\|\||[;|])\s*", value, maxsplit=1)[0]
    return [
        token[1:-1]
        if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'"
        else token.strip("\"'()")
        for token in CLI_TOKEN_RE.findall(command)
    ]


def container_image_values(line: str) -> list[str]:
    values = []
    for command in CLI_RE.finditer(line):
        tokens = command_tokens(command.group("tail"))
        action_index = next(
            (
                index
                for index, token in enumerate(tokens)
                if token.casefold() in {"create", "pull", "run"}
            ),
            None,
        )
        if action_index is None:
            continue
        prefix = {token.casefold().lstrip("-") for token in tokens[:action_index]}
        if not prefix & NON_IMAGE_NAMESPACES:
            action = tokens[action_index].casefold()
            value_options = CONTAINER_VALUE_OPTIONS - (
                {"-a", "--attach"} if action == "pull" else set()
            )
            flag_options = CONTAINER_FLAG_OPTIONS | (
                PULL_FLAG_OPTIONS if action == "pull" else set()
            )
            ambiguous, index = False, action_index + 1
            while index < len(tokens):
                token = tokens[index]
                if token == "\\":
                    index += 1
                    continue
                if token == "--":
                    index += 1
                    break
                if not token.startswith("-"):
                    break
                option = token.split("=", 1)[0]
                attached = (
                    option in SHORT_VALUE_OPTIONS
                    and token != option
                    and not token.startswith("--")
                )
                if option in value_options:
                    index += 1 if "=" in token or attached else 2
                elif option in flag_options:
                    index += 1
                else:
                    ambiguous = True
                    index += 1
            if index >= len(tokens):
                values.append("")
            elif ambiguous:
                values.extend(
                    token
                    for token in tokens[index:]
                    if token != "\\" and not token.startswith("-")
                )
            else:
                values.append(tokens[index])
    return values


def is_container_consumer(line: str) -> bool:
    return bool(container_image_values(line))


def policy_image_name(name: str) -> bool:
    value, markers = (
        name.casefold().replace("$", ""),
        {"base", "builder", "debian", "runtime"},
    )
    return (
        re.sub("[^a-z0-9]", "", value) == "image"
        or value.startswith(tuple(markers))
        or bool(set(re.split(r"[_-]+", value)) & markers)
    )


def is_image_alias(value: str) -> bool:
    return (
        DIRECT_IMAGE_ALIAS_RE.fullmatch(value.strip()) is not None
        or IMAGE_FALLBACK_RE.fullmatch(value.strip()) is not None
    )


def has_safe_image_template(value: str) -> bool:
    match = SAFE_TAG_TEMPLATE_RE.fullmatch(value)
    if COMPUTED_VALUE_RE.search(value) or match is None:
        return False
    return not is_debian_family(match.group("repository"))


def build_context_references(text: str) -> list[str]:
    return [match.group("ref") for match in DOCKER_CONTEXT_RE.finditer(text)]


def append_reference_failures(
    path: Path,
    number: int,
    reference: str,
    failures: list[str],
    kind: str = "Debian-derived image reference",
) -> None:
    if not is_debian_family(reference):
        return
    prefix = f"{path}:{number}: {kind}"
    if not DIGEST_RE.search(reference):
        failures.append(f"{prefix} is not pinned by immutable digest: {reference}")
    if (
        "trixie" not in reference.casefold()
        and re.search(r"debian-?13", reference, re.IGNORECASE) is None
    ):
        failures.append(f"{prefix} does not declare Trixie/Debian 13: {reference}")


def append_bare_failures(
    path: Path, number: int, value: str, failures: list[str]
) -> None:
    for bare in BARE_DEFAULT_FAMILY_RE.finditer(value):
        family = bare.group("name")
        label = "Debian" if family == "debian" else f"Debian-default {family}"
        failures.append(
            f"{path}:{number}: bare {label} image reference is not pinned "
            f"and does not declare Trixie/Debian 13: {bare.group('ref')}"
        )


def markdown_code_flags(path: Path, lines: list[str]) -> list[bool]:
    if path.suffix not in MARKDOWN_SUFFIXES:
        return [False] * len(lines)
    active, marker, result = False, "", []
    for line in lines:
        fence = re.match(r"(```+|~~~+)\s*([A-Za-z0-9_-]*)", line.lstrip())
        if fence:
            token, language = fence.groups()
            if marker and token.startswith(marker):
                active, marker = False, ""
            elif not marker:
                active, marker = language.casefold() in FENCE_LANGS, token[:3]
            result.append(False)
        else:
            result.append(active)
    return result


def logical_lines(lines: list[str], flags: list[bool]) -> list[tuple[int, str, bool]]:
    result, parts, start, active = [], [], 1, False
    for number, line in enumerate(lines, 1):
        if not parts:
            start, active = number, flags[number - 1]
        stripped = line.rstrip()
        continued = stripped.endswith("\\")
        parts.append(stripped[:-1] if continued else stripped)
        if not continued:
            result.append((start, " ".join(parts), active))
            parts = []
    if parts:
        result.append((start, " ".join(parts), active))
    return result


def yaml_container_consumers(lines: list[str]) -> dict[int, str]:
    parents: list[tuple[int, int]] = []
    fields: dict[tuple[int, str], tuple[int, str]] = {}
    consumers = {}
    for offset, line in enumerate(lines):
        number = offset + 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        while parents and parents[-1][0] >= indent:
            parents.pop()
        match = YAML_FIELD_RE.match(line)
        if match is None:
            parents.append((indent, number))
            continue
        name = match.group("name").casefold()
        scope = number if match.group("item") else parents[-1][1] if parents else 0
        if name in {"entrypoint", "command"}:
            value = match.group("value").strip()
            if not value:
                parts = []
                for following in lines[offset + 1 :]:
                    if not following.strip() or following.lstrip().startswith("#"):
                        continue
                    following_indent = len(following) - len(following.lstrip())
                    if following_indent <= indent:
                        break
                    item = re.match(r"^\s*-\s*(?P<value>.+)$", following)
                    if item:
                        parts.append(item.group("value"))
                value = " ".join(parts)
            fields[(scope, name)] = (number, value)
        if (scope, "entrypoint") in fields and (scope, "command") in fields:
            command_number, command = fields[(scope, "command")]
            entrypoint = fields[(scope, "entrypoint")][1]
            engine = re.match(
                r"^\s*\[?\s*[\"']?(?P<engine>(?:[^\s,\"'\]]*/)?(?:docker|podman))"
                r"[\"']?(?=$|[\s,\]])",
                entrypoint,
            )
            if engine:
                combined = f"{engine.group('engine')} {command}"
                if is_container_consumer(combined):
                    consumers[command_number] = combined
        parents.append((indent, number))
    return consumers


def scan_surface(path: Path, text: str, executable: bool = False) -> list[str]:
    if len(text.encode()) > MAX_TEXT_FILE_BYTES:
        raise ImageSurfaceError(
            f"{path}: text file exceeds {MAX_TEXT_FILE_BYTES} bytes"
        )
    lines, failures = text.splitlines(), []
    markdown_flags = markdown_code_flags(path, text.splitlines())
    shebang = bool(lines and lines[0].startswith("#!"))
    code_file = (
        is_dockerfile(path) or path.suffix in CODE_SUFFIXES or executable or shebang
    )
    strict_assignments = (
        code_file and not is_dockerfile(path) and path.suffix not in {".yaml", ".yml"}
    )
    yaml_consumers = (
        yaml_container_consumers(lines) if path.suffix in {".yaml", ".yml"} else {}
    )
    records: list[tuple[int, str, str, set[str], bool, bool]] = []
    resolved = set()
    for number, line in enumerate(lines, 1):
        if len(line) > MAX_LINE_CHARS:
            raise ImageSurfaceError(
                f"{path}:{number}: line exceeds {MAX_LINE_CHARS} characters"
            )
        markdown_code = markdown_flags[number - 1]
        comment = line.lstrip().startswith(("#", "//")) and not markdown_code
        exemption = (
            path.suffix in MARKDOWN_SUFFIXES
            and not markdown_code
            and EXEMPTION_RE.search(line) is not None
        )
        if "debian13-policy:" in line and not exemption:
            failures.append(f"{path}:{number}: invalid Debian image prose exemption")
        if exemption:
            continue
        lowered = line.casefold()
        for marker in RETIRED_MARKERS:
            if marker in lowered:
                failures.append(
                    f"{path}:{number}: retired Debian image generation marker remains: {marker}"
                )
        item = assignment(path, line) if code_file else None
        consumer_line = yaml_consumers.get(number, line)
        consumer = (
            is_container_consumer(consumer_line)
            and (code_file or markdown_code)
            and not comment
        )
        reference_context = not comment and (
            is_dockerfile(path)
            or path.suffix in {".yaml", ".yml", ".sh", ".bash"}
            or markdown_code
            or item is not None
            or consumer
        )
        context_references = build_context_references(line)
        if reference_context and not consumer:
            for reference in references(line):
                if reference not in context_references:
                    append_reference_failures(path, number, reference, failures)
        if reference_context:
            for reference in context_references:
                append_reference_failures(
                    path,
                    number,
                    reference,
                    failures,
                    "Docker build context",
                )
        if item:
            name, value = item
            canonical = name.casefold()
            dependencies = {
                found.group("name").casefold() for found in IMAGE_VAR_RE.finditer(value)
            }
            has_literal = exact_reference(value) is not None
            alias = is_image_alias(value)
            has_template = (
                not has_literal and not dependencies and has_safe_image_template(value)
            )
            positional = canonical == "image" and re.fullmatch(
                r"""["']?\$(?:[1-9]|\{[1-9](?::-[^{}]+)?\})["']?;?""",
                value.strip(),
            )
            computed = not positional and (
                (not has_literal and not alias and not has_template)
                or COMPUTED_VALUE_RE.search(value) is not None
            )
            strict = strict_assignments and policy_image_name(name)
            records.append((number, canonical, value, dependencies, computed, strict))
            if ((has_literal or has_template) and not computed) or positional:
                resolved.add(canonical)
        bare_assignment = item is not None and (
            path.suffix in {".yaml", ".yml"}
            and re.sub("[^A-Za-z0-9]", "", item[0]).casefold() in {"image", "container"}
            or strict_assignments
            and policy_image_name(item[0])
        )
        if (
            not comment
            and not consumer
            and BARE_DEFAULT_FAMILY_RE.search(line)
            and (is_dockerfile(path) or bare_assignment)
        ):
            append_bare_failures(path, number, line, failures)
    changed = True
    while changed:
        changed = False
        for _, name, _, dependencies, computed, strict in records:
            if (
                name not in resolved
                and not computed
                and dependencies
                and dependencies <= resolved
            ):
                resolved.add(name)
                changed = True
    for number, name, value, _, computed, strict in records:
        if strict and (computed or name not in resolved):
            failures.append(
                f"{path}:{number}: computed or unresolved image assignment "
                f"is not allowed: {value.strip()}"
            )
    consumer_records = logical_lines(lines, markdown_flags)
    consumer_records.extend(
        (number, line, False) for number, line in yaml_consumers.items()
    )
    for number, line, markdown_code in consumer_records:
        image_values = container_image_values(line)
        if (
            line.lstrip().startswith(("#", "//"))
            or not (code_file or markdown_code)
            or not image_values
        ):
            continue
        image_text = " ".join(image_values)
        for reference in references(image_text):
            append_reference_failures(path, number, reference, failures)
        append_bare_failures(path, number, image_text, failures)
        variables = {
            match.group("name").casefold()
            for match in IMAGE_VAR_RE.finditer(image_text)
        }
        unresolved = sorted(variables - resolved)
        if (
            not any(
                re.search("[A-Za-z]", repository_and_tag(item)[0])
                for item in references(image_text)
            )
            and not BARE_DEFAULT_FAMILY_RE.search(image_text)
            and (not variables or unresolved)
        ):
            detail = (
                f"; unresolved image variables: {', '.join(unresolved)}"
                if unresolved
                else ""
            )
            failures.append(
                f"{path}:{number}: Docker/Podman image consumer must use a "
                f"literal or a statically resolved *_IMAGE assignment{detail}"
            )
    return list(dict.fromkeys(failures))


def require(
    text: str, needle: str, path: Path, detail: str, failures: list[str]
) -> None:
    if needle not in text:
        failures.append(f"{path}: missing {detail}: {needle!r}")


def runtime_stage(text: str) -> str:
    marker = f"FROM {DISTROLESS_RUNTIME} AS runtime"
    offset = text.find(marker)
    return text[offset:] if offset >= 0 else ""


def product_contracts(texts: dict[Path, str], failures: list[str]) -> None:
    for path in PRODUCT_DOCKERFILES:
        text, runtime = texts.get(path, ""), runtime_stage(texts.get(path, ""))
        require(
            text,
            f"FROM {DISTROLESS_RUNTIME} AS runtime",
            path,
            "Distroless Debian 13 non-root final runtime",
            failures,
        )
        require(
            runtime,
            "HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3",
            path,
            "binary healthcheck",
            failures,
        )
        for forbidden in ("\nRUN ", "apt-get", "/bin/sh", "curl ", "wget "):
            if forbidden in runtime:
                failures.append(
                    f"{path}: final Distroless runtime contains {forbidden.strip()!r}"
                )
    for path in PRODUCT_DOCKERFILES[:3]:
        require(
            texts.get(path, ""),
            f"FROM {RUST_BUILDER} AS builder",
            path,
            "pinned Debian 13 Rust builder",
            failures,
        )
    for path in PRODUCT_DOCKERFILES[3:]:
        text = texts.get(path, "")
        if not text.startswith(f"# syntax={DOCKERFILE_FRONTEND}\n"):
            failures.append(
                f"{path}: pinned Dockerfile frontend must be the first line"
            )
        for needle, detail in (
            (f"FROM {DEBIAN_PREPARATION} AS runtime-root", "runtime preparation base"),
            ("ARG SOURCE_DATE_EPOCH=0", "fixed release filesystem timestamp"),
            (
                "RUN --mount=type=bind,source=dist/image-bin,target=/workspace/image-bin",
                "ephemeral release input mount",
            ),
            (
                'find /workspace/runtime-root -exec touch -h --date="@${SOURCE_DATE_EPOCH}" {} +',
                "normalized release filesystem metadata",
            ),
        ):
            require(text, needle, path, detail, failures)
    for path in RELAY_DOCKERFILES:
        text = texts.get(path, "")
        require(
            text,
            "/usr/local/bin/registry-relay-rhai-worker",
            path,
            "Relay worker binary",
            failures,
        )
        require(
            runtime_stage(text),
            'ENTRYPOINT ["/usr/local/bin/registry-relay"]',
            path,
            "absolute Relay entrypoint",
            failures,
        )
    require(
        texts.get(PRODUCT_DOCKERFILES[2], ""),
        'ARG REGISTRY_NOTARY_FEATURES="registry-notary-cel,pkcs11"',
        PRODUCT_DOCKERFILES[2],
        "PKCS#11-enabled product build",
        failures,
    )
    for path in NOTARY_DOCKERFILES:
        text = texts.get(path, "")
        for source, needle, detail in (
            (text, "registry-notary-cel-worker", "Notary CEL worker binary"),
            (
                runtime_stage(text),
                'ENTRYPOINT ["/usr/local/bin/registry-notary"]',
                "absolute Notary entrypoint",
            ),
            (
                text,
                "chown -R 65532:65532",
                "numeric nonroot-owned Notary runtime directories",
            ),
            (
                runtime_stage(text),
                "WORKDIR /var/lib/registry-notary",
                "Notary working directory",
            ),
        ):
            require(source, needle, path, detail, failures)
        if re.search(
            r"^\s*(?:COPY|ADD)\b[^\n]*(?:\.so\b|pkcs11[^/\s]*module)",
            text,
            re.IGNORECASE | re.MULTILINE,
        ):
            failures.append(
                f"{path}: vendor PKCS#11 modules must remain external read-only mounts"
            )
    workflow = texts.get(Path(".github/workflows/release.yml"), "")
    require(
        workflow,
        f"RELEASE_BUILDER_IMAGE: {RUST_BUILDER}",
        Path(".github/workflows/release.yml"),
        "pinned Debian 13 release builder",
        failures,
    )
    require(
        texts.get(Path("release/scripts/build-release-binaries.sh"), ""),
        "--features registry-notary/registry-notary-cel,registry-notary/pkcs11",
        Path("release/scripts/build-release-binaries.sh"),
        "PKCS#11-enabled release build",
        failures,
    )
    require(
        texts.get(
            Path("crates/registry-relay/scripts/run-live-consultation-journey.sh"), ""
        ),
        RUST_BUILDER,
        Path("crates/registry-relay/scripts/run-live-consultation-journey.sh"),
        "pinned Debian 13 live-journey builder",
        failures,
    )
    require(
        texts.get(
            Path("crates/registry-relay/scripts/run-live-consultation-journey.sh"), ""
        ),
        "postgres:16-trixie@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20",
        Path("crates/registry-relay/scripts/run-live-consultation-journey.sh"),
        "pinned Debian 13 live-journey PostgreSQL",
        failures,
    )
    tutorial = texts.get(TUTORIAL_SCRIPT, "")
    ci = texts.get(CI_WORKFLOW, "")
    start = ci.find("- name: Cache source-under-test Cargo build")
    end = ci.find("\n      - name: Execute registryctl tutorials from source", start)
    cache = "" if start < 0 else ci[start:] if end < 0 else ci[start:end]
    for source, needle, path, detail in (
        (
            tutorial,
            'LINUX_TARGET="$REPO_ROOT/target/registryctl-tutorial-linux-amd64"',
            TUTORIAL_SCRIPT,
            "registryctl tutorial linux target path",
        ),
        (
            tutorial,
            'CARGO_HOME_DIR="$REPO_ROOT/target/registryctl-tutorial-cargo-home"',
            TUTORIAL_SCRIPT,
            "registryctl tutorial Cargo home path",
        ),
        (
            cache,
            "hashFiles('docs/site/scripts/check-registryctl-tutorials.sh')",
            CI_WORKFLOW,
            "registryctl tutorial cache builder identity",
        ),
        (
            cache,
            "target/registryctl-tutorial-linux-amd64",
            CI_WORKFLOW,
            "registryctl tutorial linux target cache path",
        ),
        (
            cache,
            "target/registryctl-tutorial-cargo-home",
            CI_WORKFLOW,
            "registryctl tutorial Cargo home cache path",
        ),
    ):
        require(source, needle, path, detail, failures)
    if "restore-keys:" in cache:
        failures.append(
            f"{CI_WORKFLOW}: registryctl tutorial cache must not restore from pre-builder-identity keys"
        )


def check_repository(root: Path = ROOT) -> list[str]:
    failures: list[str] = []
    try:
        discovered = discover_maintained_surfaces(root)
    except ImageSurfaceError as error:
        return [str(error)]
    paths = tuple(sorted(set(discovered) | set(REQUIRED_PRODUCT_SURFACES)))
    texts: dict[Path, str] = {}
    total = 0
    for path in paths:
        try:
            text, size = read_text(root, path)
        except ImageSurfaceError as error:
            failures.append(str(error))
            continue
        if text is None:
            if path in REQUIRED_PRODUCT_SURFACES:
                failures.append(f"missing maintained image surface: {path}")
            continue
        total += size
        if total > MAX_TOTAL_TEXT_BYTES:
            return [f"maintained text exceeds {MAX_TOTAL_TEXT_BYTES} total bytes"]
        texts[path] = text
        try:
            executable = bool((root / path).stat().st_mode & 0o111)
            failures.extend(scan_surface(path, text, executable=executable))
        except ImageSurfaceError as error:
            failures.append(str(error))
    dockerfiles = [path for path in discovered if is_dockerfile(path)]
    if not dockerfiles:
        failures.append("no maintained Dockerfiles discovered")
    for path in dockerfiles:
        bases, stages = FROM_RE.findall(texts.get(path, "")), set()
        if not bases:
            failures.append(f"{path}: no FROM instruction found")
        for base, stage in bases:
            if base.casefold() not in stages | {"scratch"} and not DIGEST_RE.search(
                base
            ):
                failures.append(
                    f"{path}: upstream base is not pinned by immutable digest: {base}"
                )
            if stage:
                stages.add(stage.casefold())
    product_contracts(texts, failures)
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
