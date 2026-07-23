#!/usr/bin/env python3
"""Enforce the Debian 13 boundary for maintained Registry Stack images."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml


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
TUTORIAL_CACHE_VALUE = (
    "registryctl-tutorial-${{ runner.os }}-"
    "${{ hashFiles('docs/site/scripts/check-registryctl-tutorials.sh') }}-"
    "${{ hashFiles('Cargo.lock') }}"
)
TUTORIAL_CACHE_KEYS = tuple(
    f"          {key}: {TUTORIAL_CACHE_VALUE}"
    for key in ("key", "'key'", '"key"')
)
TUTORIAL_CACHE_KEY = TUTORIAL_CACHE_KEYS[0]
RELEASE_BUILDER_HANDOFF = 'release_builder_image="${default_builder_image}"'
RELEASE_BUILDER_CONSUMER = '  "${release_builder_image}" \\'
TUTORIAL_BUILDER_CONSUMER = '\t\t"$BUILDER_IMAGE" \\'
LIVE_JOURNEY_BUILDER = f"    {RUST_BUILDER} \\"
LIVE_JOURNEY_POSTGRES_IMAGE = "postgres:16.13-alpine"
LIVE_JOURNEY_POSTGRES_ASSIGNMENT = (
    f'readonly POSTGRES_IMAGE="{LIVE_JOURNEY_POSTGRES_IMAGE}"'
)
LIVE_JOURNEY_POSTGRES_CONSUMER = '  "$POSTGRES_IMAGE" \\'
RELEASE_BUILDER_PREFIX = (
    "docker run --rm \\",
    "  --platform linux/amd64 \\",
    '  --user "$(id -u):$(id -g)" \\',
    '  --volume "${repo_root}:/workspace" \\',
    '  --volume "${release_cargo_home}:/workspace/.cargo-home" \\',
    '  --volume "${release_target_dir}:/workspace/target" \\',
    "  --workdir /workspace \\",
    "  --env CARGO_HOME=/workspace/.cargo-home \\",
    "  --env CARGO_TARGET_DIR=/workspace/target \\",
    "  --env CARGO_INCREMENTAL=0 \\",
    '  --env CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}" \\',
    "  --env HOME=/workspace \\",
    '  --env RELEASE_TAG="${tag}" \\',
    '  --env RELEASE_RUSTFLAGS="${release_rustflags}" \\',
    RELEASE_BUILDER_CONSUMER,
)
TUTORIAL_BUILDER_PREFIX = (
    "\tdocker run --rm \\",
    "\t\t--platform linux/amd64 \\",
    '\t\t--user "$(id -u):$(id -g)" \\',
    '\t\t--volume "$REPO_ROOT:/workspace" \\',
    "\t\t--workdir /workspace \\",
    "\t\t--env CARGO_HOME=/workspace/target/registryctl-tutorial-cargo-home \\",
    "\t\t--env CARGO_TARGET_DIR=/workspace/target/registryctl-tutorial-linux-amd64 \\",
    "\t\t--env CARGO_TERM_COLOR=always \\",
    "\t\t--env HOME=/tmp/registryctl-tutorial-home \\",
    TUTORIAL_BUILDER_CONSUMER,
)
LIVE_JOURNEY_BUILDER_PREFIX = (
    "  docker run --rm \\",
    "    --add-host host.docker.internal:host-gateway \\",
    '    --network "$network_name" \\',
    "    --network-alias rhai-runner \\",
    '    --env-file "$rhai_test_env_file" \\',
    '    --volume "$repository_root:/workspace" \\',
    '    --volume "$certificate_input:/live-postgres-ca:ro" \\',
    '    --volume "$HOME/.cargo/registry:/usr/local/cargo/registry" \\',
    '    --volume "$HOME/.cargo/git:/usr/local/cargo/git" \\',
    "    --volume registry-relay-linux-target:/target \\",
    "    --workdir /workspace \\",
    LIVE_JOURNEY_BUILDER,
)
LIVE_JOURNEY_POSTGRES_SETUP_PREFIX = (
    "docker run --rm \\",
    "  --user 0:0 \\",
    '  --volume "$certificate_volume:/certificates" \\',
    '  --volume "$certificate_input:/input:ro" \\',
    LIVE_JOURNEY_POSTGRES_CONSUMER,
    "  sh -eu -c \\",
)
LIVE_JOURNEY_POSTGRES_SERVER_PREFIX = (
    "docker run --detach \\",
    '  --name "$container_name" \\',
    '  --env-file "$docker_env_file" \\',
    "  --publish 127.0.0.1::5432 \\",
    '  --volume "$certificate_volume:/certificates:ro" \\',
    LIVE_JOURNEY_POSTGRES_CONSUMER,
    "  -c ssl=on \\",
)
RELEASE_BUILDER_TAIL = "\n".join(
    (
        *RELEASE_BUILDER_PREFIX[-2:],
        "  bash -c 'set -euo pipefail",
    )
)
TUTORIAL_BUILDER_TAIL = "\n".join(
    (
        *TUTORIAL_BUILDER_PREFIX[-2:],
        "\t\tbash -c 'set -euo pipefail",
    )
)
LIVE_JOURNEY_BUILDER_TAIL = "\n".join(
    (
        *LIVE_JOURNEY_BUILDER_PREFIX[-2:],
        "    sh -eu -c \\",
    )
)

DOCKERFILES = (
    Path("crates/registry-relay/Dockerfile"),
    Path("crates/registry-relay/Dockerfile.demo"),
    Path("products/notary/Dockerfile"),
    Path("release/docker/Dockerfile.registry-notary"),
    Path("release/docker/Dockerfile.registry-relay"),
)
NOTARY_POSTGRES_CONFORMANCE_SCRIPT = Path(
    "products/notary/scripts/postgresql-conformance.sh"
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
    NOTARY_POSTGRES_CONFORMANCE_SCRIPT,
)

NOTARY_POSTGRES_WORKFLOW_SOURCE_TARGET_IMAGES = (
    "postgres:16.13-alpine",
    "postgres:16.14-alpine",
    "postgres:17.9-alpine",
    "postgres:17.10-alpine",
    "postgres:18.3-alpine",
    "postgres:18.4-alpine",
)
NOTARY_POSTGRES_WORKFLOW_RESTORE_IMAGES = (
    "postgres:17.10-alpine",
    "postgres:18.4-alpine",
)
NOTARY_POSTGRES_WORKFLOW_IMAGES = tuple(
    dict.fromkeys(
        (
            *NOTARY_POSTGRES_WORKFLOW_SOURCE_TARGET_IMAGES,
            *NOTARY_POSTGRES_WORKFLOW_RESTORE_IMAGES,
        )
    )
)
NOTARY_POSTGRES_WORKFLOW_RATIONALE = (
    "External Alpine PostgreSQL migration conformance, not a "
    "project-owned Debian image."
)
WORKFLOW_IMAGE_ALLOWLIST = {
    (
        Path(".github/workflows/relay-postgres-conformance.yml"),
        "postgres:${{ matrix.postgresql }}-alpine",
    ): (
        "External Alpine PostgreSQL state-plane conformance, not a "
        "project-owned Debian image."
    ),
    **{
        (
            Path(".github/workflows/notary-postgres-conformance.yml"),
            image,
        ): NOTARY_POSTGRES_WORKFLOW_RATIONALE
        for image in NOTARY_POSTGRES_WORKFLOW_IMAGES
    },
}
WORKFLOW_IMAGE_KEYS = frozenset(
    ("image", "source_image", "target_image", "restore_image")
)
NOTARY_POSTGRES_IMAGE_ASSIGNMENTS = (
    ("default_source_image", '"postgres:16.13-alpine"'),
    ("default_target_image", '"postgres:16.14-alpine"'),
    ("default_restore_image", '"postgres:17.10-alpine"'),
    ("default_source_image", '"postgres:17.9-alpine"'),
    ("default_target_image", '"postgres:17.10-alpine"'),
    ("default_restore_image", '"postgres:18.4-alpine"'),
    ("default_source_image", '"postgres:18.3-alpine"'),
    ("default_target_image", '"postgres:18.4-alpine"'),
    ("default_restore_image", '"postgres:18.4-alpine"'),
    ("unsupported_postgres_image", '"postgres:15.18-alpine"'),
)
NOTARY_POSTGRES_LITERAL_LINES = tuple(
    f"{name}={value}" for name, value in NOTARY_POSTGRES_IMAGE_ASSIGNMENTS
)
NOTARY_POSTGRES_FALLBACK_BINDINGS = (
    (
        "source_image",
        '"${NOTARY_POSTGRES_SOURCE_IMAGE:-${default_source_image}}"',
    ),
    (
        "target_image",
        '"${NOTARY_POSTGRES_TARGET_IMAGE:-${default_target_image}}"',
    ),
    (
        "restore_image",
        '"${NOTARY_POSTGRES_RESTORE_IMAGE:-${default_restore_image}}"',
    ),
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
DOCKERFILE_NAMED_CONTEXTS = {
    Path("crates/registry-relay/Dockerfile"): frozenset(
        ("registry-platform", "registry-manifest", "crosswalk")
    ),
    Path("crates/registry-relay/Dockerfile.demo"): frozenset(
        ("registry-platform",)
    ),
    Path("products/notary/Dockerfile"): frozenset(
        ("registry-platform", "crosswalk")
    ),
    Path("release/docker/Dockerfile.registry-notary"): frozenset(),
    Path("release/docker/Dockerfile.registry-relay"): frozenset(),
}
RELAY_FINAL_STAGE_COPY_INSTRUCTIONS = (
    "COPY --from=builder --chown=65532:65532 /workspace/runtime-root/ /",
    (
        "COPY --from=builder /usr/local/bin/registry-relay "
        "/usr/local/bin/registry-relay"
    ),
    (
        "COPY --from=builder /usr/local/bin/registry-relay-rhai-worker "
        "/usr/local/bin/registry-relay-rhai-worker"
    ),
    "COPY LICENSE /licenses/registry-relay/LICENSE",
)
FINAL_STAGE_COPY_INSTRUCTIONS = {
    Path("crates/registry-relay/Dockerfile"): RELAY_FINAL_STAGE_COPY_INSTRUCTIONS,
    Path("crates/registry-relay/Dockerfile.demo"): RELAY_FINAL_STAGE_COPY_INSTRUCTIONS,
    Path("products/notary/Dockerfile"): (
        "COPY --from=builder --chown=65532:65532 /workspace/runtime-root/ /",
        "COPY --from=builder /workspace/out/ /usr/local/bin/",
    ),
    Path("release/docker/Dockerfile.registry-notary"): (
        "COPY --from=runtime-root /workspace/runtime-root/ /",
    ),
    Path("release/docker/Dockerfile.registry-relay"): (
        "COPY --from=runtime-root /workspace/runtime-root/ /",
    ),
}
DOCKERFILE_RUN_INSTRUCTIONS = {
    Path("crates/registry-relay/Dockerfile"): (
        (
            "RUN --mount=type=cache,target=/usr/local/cargo/registry "
            "--mount=type=cache,target=/workspace/registry_relay/target "
            "find src benches resources -type f -exec touch {} + && "
            'if [ -n "$REGISTRY_RELAY_FEATURES" ]; then '
            "cargo build --release --locked --features "
            '"$REGISTRY_RELAY_FEATURES"; '
            "else cargo build --release --locked; fi && "
            "cp /workspace/registry_relay/target/release/registry-relay "
            "/usr/local/bin/registry-relay && "
            "cp /workspace/registry_relay/target/release/"
            "registry-relay-rhai-worker "
            "/usr/local/bin/registry-relay-rhai-worker && "
            "mkdir -p /workspace/runtime-root/etc/registry-relay "
            "/workspace/runtime-root/var/lib/registry-relay/cache "
            "/workspace/runtime-root/var/lib/registry-relay/data "
            "/workspace/runtime-root/var/log/registry-relay && "
            "chown -R 65532:65532 /workspace/runtime-root"
        ),
    ),
    Path("crates/registry-relay/Dockerfile.demo"): (
        (
            "RUN --mount=type=cache,target=/usr/local/cargo/registry "
            "--mount=type=cache,target=/workspace/registry_relay/target "
            "cargo build --release --locked --features "
            "spdci-api-standards,standards-cel-mapping,"
            "attribute-release && "
            "cp /workspace/registry_relay/target/release/registry-relay "
            "/usr/local/bin/registry-relay && "
            "cp /workspace/registry_relay/target/release/"
            "registry-relay-rhai-worker "
            "/usr/local/bin/registry-relay-rhai-worker && "
            "mkdir -p /workspace/runtime-root/etc/registry-relay "
            "/workspace/runtime-root/var/lib/registry-relay/cache "
            "/workspace/runtime-root/var/lib/registry-relay/data "
            "/workspace/runtime-root/var/log/registry-relay && "
            "chown -R 65532:65532 /workspace/runtime-root"
        ),
    ),
    Path("products/notary/Dockerfile"): (
        (
            "RUN --mount=type=cache,target=/usr/local/cargo/registry "
            "--mount=type=cache,target=/workspace/target "
            'if [ -n "$REGISTRY_NOTARY_FEATURES" ]; then '
            "CARGO_TARGET_DIR=/workspace/target cargo build --release "
            "--locked -p registry-notary --features "
            '"$REGISTRY_NOTARY_FEATURES"; '
            "else CARGO_TARGET_DIR=/workspace/target cargo build --release "
            "--locked -p registry-notary; fi && "
            "mkdir -p /workspace/out && "
            "cp /workspace/target/release/registry-notary "
            "/workspace/out/registry-notary && "
            'case ",$REGISTRY_NOTARY_FEATURES," in '
            "*,registry-notary-cel,*) "
            "CARGO_TARGET_DIR=/workspace/target cargo build --release "
            "--locked -p registry-notary-server "
            "--bin registry-notary-cel-worker --features "
            '"$REGISTRY_NOTARY_FEATURES" && '
            "cp /workspace/target/release/registry-notary-cel-worker "
            "/workspace/out/registry-notary-cel-worker ;; "
            "*) true ;; esac && "
            "mkdir -p /workspace/runtime-root/etc/registry-notary "
            "/workspace/runtime-root/var/lib/registry-notary "
            "/workspace/runtime-root/var/log/registry-notary && "
            "chown -R 65532:65532 /workspace/runtime-root"
        ),
    ),
    Path("release/docker/Dockerfile.registry-notary"): (
        (
            "RUN --mount=type=bind,source=dist/image-bin,"
            "target=/workspace/image-bin "
            "mkdir -p /workspace/runtime-root/etc/registry-notary "
            "/workspace/runtime-root/usr/local/bin "
            "/workspace/runtime-root/var/lib/registry-notary "
            "/workspace/runtime-root/var/log/registry-notary && "
            "install -m 0755 /workspace/image-bin/registry-notary "
            "/workspace/runtime-root/usr/local/bin/registry-notary && "
            "install -m 0755 "
            "/workspace/image-bin/registry-notary-cel-worker "
            "/workspace/runtime-root/usr/local/bin/"
            "registry-notary-cel-worker && "
            "chown -R 65532:65532 "
            "/workspace/runtime-root/etc/registry-notary "
            "/workspace/runtime-root/var/lib/registry-notary "
            "/workspace/runtime-root/var/log/registry-notary && "
            'find /workspace/runtime-root -exec touch -h '
            '--date="@${SOURCE_DATE_EPOCH}" {} +'
        ),
    ),
    Path("release/docker/Dockerfile.registry-relay"): (
        (
            "RUN --mount=type=bind,source=dist/image-bin,"
            "target=/workspace/image-bin "
            "--mount=type=bind,source=LICENSE,target=/workspace/LICENSE "
            "mkdir -p /workspace/runtime-root/etc/registry-relay "
            "/workspace/runtime-root/licenses/registry-relay "
            "/workspace/runtime-root/usr/local/bin "
            "/workspace/runtime-root/var/lib/registry-relay/cache "
            "/workspace/runtime-root/var/lib/registry-relay/data "
            "/workspace/runtime-root/var/log/registry-relay && "
            "install -m 0755 /workspace/image-bin/registry-relay "
            "/workspace/runtime-root/usr/local/bin/registry-relay && "
            "install -m 0755 "
            "/workspace/image-bin/registry-relay-rhai-worker "
            "/workspace/runtime-root/usr/local/bin/"
            "registry-relay-rhai-worker && "
            "install -m 0644 /workspace/LICENSE "
            "/workspace/runtime-root/licenses/registry-relay/LICENSE && "
            "chown -R 65532:65532 "
            "/workspace/runtime-root/etc/registry-relay "
            "/workspace/runtime-root/var/lib/registry-relay "
            "/workspace/runtime-root/var/log/registry-relay && "
            'find /workspace/runtime-root -exec touch -h '
            '--date="@${SOURCE_DATE_EPOCH}" {} +'
        ),
    ),
}

RELAY_RUNTIME_DIRECTIVES = (
    (
        "HEALTHCHECK --interval=30s --timeout=5s --start-period=10s "
        '--retries=3 CMD ["/usr/local/bin/registry-relay", "healthcheck"]',
        "binary healthcheck",
    ),
    (
        'ENTRYPOINT ["/usr/local/bin/registry-relay"]',
        "absolute Relay entrypoint",
    ),
    ("WORKDIR /var/lib/registry-relay", "Relay working directory"),
    (
        'CMD ["--config", "/etc/registry-relay/config.yaml"]',
        "Relay default command",
    ),
)
NOTARY_RUNTIME_DIRECTIVES = (
    (
        "HEALTHCHECK --interval=30s --timeout=5s --start-period=10s "
        '--retries=3 CMD ["/usr/local/bin/registry-notary", "healthcheck"]',
        "binary healthcheck",
    ),
    (
        'ENTRYPOINT ["/usr/local/bin/registry-notary"]',
        "absolute Notary entrypoint",
    ),
    ("WORKDIR /var/lib/registry-notary", "Notary working directory"),
    (
        'CMD ["--config", "/etc/registry-notary/config.yaml"]',
        "Notary default command",
    ),
)

FROM_RE = re.compile(
    r"^[ \t]*FROM[ \t]+(?:--platform=(?P<platform>\S+)[ \t]+)?"
    r"(?P<base>[^\s#]+)"
    r"(?:[ \t]+AS[ \t]+(?P<alias>[^\s#]+))?"
    r"[ \t]*(?:#.*)?$",
    re.IGNORECASE | re.MULTILINE,
)
DOCKERFILE_PARSER_DIRECTIVE_RE = re.compile(
    r"^[ \t]*#[ \t]*(?P<key>[A-Za-z]+)[ \t]*="
    r"[ \t]*(?P<value>\S+)[ \t]*$",
    re.IGNORECASE,
)
COPY_INSTRUCTION_RE = re.compile(
    r"^[ \t]*COPY[ \t]+(?P<arguments>.*)$",
    re.IGNORECASE,
)
COPY_OPTION_NAMES = frozenset(("from", "chown"))
COPY_OPTION_RE = re.compile(
    r"--(?P<name>[a-z][a-z0-9-]*)=(?P<value>[^\s\\\"']+)"
)
RUN_INSTRUCTION_RE = re.compile(
    r"^[ \t]*RUN[ \t]+(?P<arguments>.*)$",
    re.IGNORECASE,
)
DIGEST_PIN_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
RETIRED_MARKER_RE = re.compile(
    r"\b(?:bookworm|debian[ \t_:-]*v?[ \t_:-]*12)\b",
    re.IGNORECASE,
)
RUNTIME_DIRECTIVE_RE = re.compile(
    r"^[ \t]*(?P<name>HEALTHCHECK|ENTRYPOINT|WORKDIR|CMD|USER|VOLUME)"
    r"(?:[ \t]+|$)",
    re.IGNORECASE,
)
RELEASE_BUILDER_KEY_RE = re.compile(
    r"^[ \t]*RELEASE_BUILDER_IMAGE[ \t]*:"
)
DEFAULT_BUILDER_ASSIGNMENT_RE = re.compile(
    r"^[ \t]*(?:(?:export|readonly)[ \t]+)?default_builder_image[ \t]*="
)
TUTORIAL_BUILDER_ASSIGNMENT_RE = re.compile(
    r"^[ \t]*(?:(?:export|readonly)[ \t]+)?BUILDER_IMAGE[ \t]*="
)
RELEASE_BUILDER_HANDOFF_RE = re.compile(
    r"^[ \t]*(?:(?:export|readonly)[ \t]+)?release_builder_image[ \t]*="
)
LIVE_JOURNEY_BUILDER_RE = re.compile(
    r"^[ \t]+rust:[^ \t#]+[ \t]+\\[ \t]*$"
)
LIVE_JOURNEY_POSTGRES_ASSIGNMENT_RE = re.compile(
    r"^[ \t]*(?:(?:export|readonly)[ \t]+)?POSTGRES_IMAGE[ \t]*="
)
CACHE_KEY_RE = re.compile(
    r"""^[ \t]*(?:key|'key'|"key")[ \t]*:"""
)
RESTORE_KEYS_RE = re.compile(
    r"""^[ \t]*(?:restore-keys|'restore-keys'|"restore-keys")[ \t]*:""",
    re.MULTILINE,
)
NOTARY_POSTGRES_IMAGE_ASSIGNMENT_RE = re.compile(
    r"^[ \t]*(?P<name>default_source_image|default_target_image|"
    r"default_restore_image|unsupported_postgres_image)[ \t]*="
    r"(?P<value>.*)$"
)
NOTARY_POSTGRES_FALLBACK_RE = re.compile(
    r"^[ \t]*(?P<name>source_image|target_image|restore_image)[ \t]*="
    r"(?P<value>.*)$"
)


def read(root: Path, relative: Path, failures: list[str]) -> str:
    path = root / relative
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        failures.append(f"missing maintained image surface: {relative}")
        return ""


def discover_workflow_paths(root: Path) -> tuple[Path, ...]:
    directory = root / ".github" / "workflows"
    if not directory.is_dir():
        return ()
    return tuple(
        path.relative_to(root)
        for path in sorted(
            (
                path
                for pattern in ("*.yml", "*.yaml")
                for path in directory.glob(pattern)
                if path.is_file()
            ),
            key=lambda path: path.name,
        )
    )


def normalize_dockerfile_instructions(
    text: str,
    relative: Path,
    failures: list[str],
) -> tuple[str, ...]:
    lines = text.splitlines()
    escape_directives = []
    for line in lines:
        if not line.strip():
            break
        match = DOCKERFILE_PARSER_DIRECTIVE_RE.match(line)
        if match is None:
            break
        key = match.group("key").casefold()
        if key not in {"syntax", "escape", "check"}:
            break
        if key == "escape":
            escape_directives.append(match.group("value"))
    if len(escape_directives) > 1 or (
        escape_directives
        and escape_directives[0] != "\\"
    ):
        failures.append(
            f"{relative}: unsupported Dockerfile escape directive prevents "
            "bounded instruction inspection"
        )
        return ()

    instructions = []
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        parts: list[str] = []
        while True:
            continued = line.rstrip().endswith("\\")
            part = line.rstrip()
            if continued:
                part = part[:-1]
            parts.append(part)
            if not continued:
                break

            while index < len(lines):
                line = lines[index]
                index += 1
                if line.strip() and not line.lstrip().startswith("#"):
                    break
            else:
                failures.append(
                    f"{relative}: unterminated Dockerfile line continuation "
                    "prevents bounded instruction inspection"
                )
                return ()

        instructions.append("".join(parts))
    return tuple(instructions)


def collect_dockerfile_copy_sources(
    instructions: tuple[str, ...],
    relative: Path,
    failures: list[str],
) -> list[str]:
    sources = []
    for instruction in instructions:
        instruction_match = COPY_INSTRUCTION_RE.match(instruction)
        if instruction_match is None:
            continue
        tokens = instruction_match.group("arguments").split()
        seen_options = set()
        while tokens and tokens[0].startswith("--"):
            option_match = COPY_OPTION_RE.fullmatch(tokens.pop(0))
            if option_match is None:
                failures.append(
                    f"{relative}: unsupported COPY option syntax prevents "
                    "bounded source inspection"
                )
                return []
            name = option_match.group("name")
            if name not in COPY_OPTION_NAMES or name in seen_options:
                failures.append(
                    f"{relative}: unsupported COPY option syntax prevents "
                    "bounded source inspection"
                )
                return []
            seen_options.add(name)
            if name == "from":
                sources.append(option_match.group("value"))

        if not tokens or tokens[0].startswith(("-", "'", '"', "\\")):
            failures.append(
                f"{relative}: unsupported COPY operand prefix prevents "
                "bounded source inspection"
            )
            return []
    return sources


def collect_workflow_image_references(
    text: str,
    relative: Path,
    failures: list[str],
) -> list[tuple[str, str]]:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        failures.append(
            f"{relative}: workflow YAML parse failed: {type(error).__name__}"
        )
        return []
    if not isinstance(document, dict):
        failures.append(
            f"{relative}: workflow YAML root must be a mapping, "
            f"found {type(document).__name__}"
        )
        return []

    references: list[tuple[str, str]] = []
    active_nodes: set[int] = set()

    def add_image(value: object, location: str) -> None:
        if not isinstance(value, str) or not value.strip():
            failures.append(
                f"{relative}: unsupported workflow image value at {location}: "
                f"expected a non-empty string, found {type(value).__name__}"
            )
            return
        references.append((location, value))

    def visit(value: object, location: str) -> None:
        if not isinstance(value, (dict, list)):
            return
        identity = id(value)
        if identity in active_nodes:
            failures.append(
                f"{relative}: unsupported recursive YAML alias at {location}"
            )
            return
        active_nodes.add(identity)
        if isinstance(value, dict):
            for key, child in value.items():
                child_location = f"{location}.{key}"
                if key == "container":
                    if isinstance(child, str):
                        add_image(child, child_location)
                    elif not isinstance(child, dict) or "image" not in child:
                        failures.append(
                            f"{relative}: unsupported workflow image value at "
                            f"{child_location}: container must be a non-empty "
                            "string or a mapping with an image key"
                        )
                elif key in WORKFLOW_IMAGE_KEYS:
                    add_image(child, child_location)
                elif (
                    key == "uses"
                    and isinstance(child, str)
                    and child.startswith("docker://")
                ):
                    add_image(child.removeprefix("docker://"), child_location)
                visit(child, child_location)
        else:
            for index, child in enumerate(value):
                visit(child, f"{location}[{index}]")
        active_nodes.remove(identity)

    visit(document, "$")
    return references


def require(
    text: str,
    needle: str,
    relative: Path,
    detail: str,
    failures: list[str],
) -> None:
    if needle not in text:
        failures.append(f"{relative}: missing {detail}: {needle!r}")


def require_unique_active_line(
    text: str,
    allowed_lines: tuple[str, ...],
    active_pattern: re.Pattern[str],
    relative: Path,
    detail: str,
    failures: list[str],
) -> None:
    active_lines = [
        candidate
        for candidate in text.splitlines()
        if active_pattern.match(candidate)
    ]
    if len(active_lines) != 1 or active_lines[0] not in allowed_lines:
        failures.append(
            f"{relative}: missing {detail}: expected exactly one active "
            f"line from {allowed_lines!r}; found {active_lines!r}"
        )


def require_unique_text(
    text: str,
    expected: str,
    relative: Path,
    detail: str,
    failures: list[str],
) -> None:
    count = text.count(expected)
    if count != 1:
        failures.append(
            f"{relative}: missing {detail}: expected exactly one exact "
            f"block {expected!r}; found {count}"
        )


def require_exact_command_prefix(
    command: str,
    expected_lines: tuple[str, ...],
    relative: Path,
    detail: str,
    failures: list[str],
    *,
    report_values: bool = True,
) -> None:
    actual_lines = tuple(command.splitlines()[: len(expected_lines)])
    if actual_lines != expected_lines:
        failure = (
            f"{relative}: {detail} does not match the exact expected "
            "header/options/image prefix"
        )
        if report_values:
            failure += f": expected {expected_lines!r}; found {actual_lines!r}"
        failures.append(failure)


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
            if lines[index].startswith("      - ")
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


def shell_continuation_command(
    text: str,
    command: str,
    required_line: str | None = None,
) -> str:
    lines = text.splitlines()
    starts = [
        index
        for index, line in enumerate(lines)
        if line.lstrip() == f"{command} \\"
    ]
    commands = []
    for start in starts:
        end = start + 1
        while end < len(lines) and lines[end - 1].rstrip().endswith("\\"):
            end += 1
        commands.append("\n".join(lines[start:end]))
    if required_line is not None:
        commands = [
            candidate
            for candidate in commands
            if required_line in candidate.splitlines()
        ]
    return commands[0] if len(commands) == 1 else ""


def check_repository(root: Path = ROOT) -> list[str]:
    failures: list[str] = []
    workflow_paths = discover_workflow_paths(root)
    maintained_paths = tuple(
        dict.fromkeys((*MAINTAINED_TEXT_PATHS, *workflow_paths))
    )
    texts = {
        relative: read(root, relative, failures)
        for relative in maintained_paths
    }

    for relative, text in texts.items():
        marker = RETIRED_MARKER_RE.search(text)
        if marker:
            failures.append(
                f"{relative}: retired Debian image generation marker remains: "
                f"{marker.group(0).casefold()}"
            )

    for relative in workflow_paths:
        references = collect_workflow_image_references(
            texts[relative],
            relative,
            failures,
        )
        for location, value in references:
            if (relative, value) not in WORKFLOW_IMAGE_ALLOWLIST:
                failures.append(
                    f"{relative}: workflow image reference is not allowlisted "
                    f"at {location}"
                )

    notary_postgres = texts[NOTARY_POSTGRES_CONFORMANCE_SCRIPT]
    notary_postgres_assignments = tuple(
        (match.group("name"), match.group("value"))
        for line in notary_postgres.splitlines()
        if (match := NOTARY_POSTGRES_IMAGE_ASSIGNMENT_RE.match(line))
    )
    if notary_postgres_assignments != NOTARY_POSTGRES_IMAGE_ASSIGNMENTS:
        failures.append(
            f"{NOTARY_POSTGRES_CONFORMANCE_SCRIPT}: PostgreSQL image "
            "assignments must match the exact ordered reviewed inventory"
        )
    notary_postgres_literal_lines = tuple(
        line.strip()
        for line in notary_postgres.splitlines()
        if not line.lstrip().startswith("#") and "postgres:" in line
    )
    if notary_postgres_literal_lines != NOTARY_POSTGRES_LITERAL_LINES:
        failures.append(
            f"{NOTARY_POSTGRES_CONFORMANCE_SCRIPT}: direct PostgreSQL image "
            "literals must match the exact ordered reviewed assignment lines"
        )
    notary_postgres_fallbacks = tuple(
        (match.group("name"), match.group("value"))
        for line in notary_postgres.splitlines()
        if (match := NOTARY_POSTGRES_FALLBACK_RE.match(line))
    )
    if notary_postgres_fallbacks != NOTARY_POSTGRES_FALLBACK_BINDINGS:
        failures.append(
            f"{NOTARY_POSTGRES_CONFORMANCE_SCRIPT}: PostgreSQL environment "
            "fallbacks must match the exact ordered reviewed bindings"
        )

    for relative in DOCKERFILES:
        text = texts[relative]
        instructions = normalize_dockerfile_instructions(
            text,
            relative,
            failures,
        )
        run_instructions = tuple(
            " ".join(instruction.split())
            for instruction in instructions
            if RUN_INSTRUCTION_RE.match(instruction)
        )
        if run_instructions != DOCKERFILE_RUN_INSTRUCTIONS[relative]:
            failures.append(
                f"{relative}: RUN instructions must match the exact "
                "reviewed inventory"
            )
        stage_matches = list(FROM_RE.finditer(text))
        if not stage_matches:
            failures.append(f"{relative}: no FROM instruction found")
            continue
        stages = tuple(
            (
                match.group("base"),
                match.group("alias"),
                match.group("platform"),
            )
            for match in stage_matches
        )
        expected_stages = (
            (
                (RUST_BUILDER, "builder", None),
                (DISTROLESS_RUNTIME, "runtime", None),
            )
            if relative in RUST_BUILDER_DOCKERFILES
            else (
                (DEBIAN_PREPARATION, "runtime-root", None),
                (DISTROLESS_RUNTIME, "runtime", None),
            )
        )
        if stages != expected_stages:
            failures.append(
                f"{relative}: Dockerfile stage sequence must be exactly "
                f"{expected_stages!r}; found {stages!r}"
            )
        stage_aliases = {
            alias.casefold()
            for _base, alias, _platform in stages
            if alias is not None
        }
        named_contexts = DOCKERFILE_NAMED_CONTEXTS[relative]
        for source in collect_dockerfile_copy_sources(
            instructions,
            relative,
            failures,
        ):
            if (
                source.casefold() not in stage_aliases
                and source not in named_contexts
            ):
                failures.append(
                    f"{relative}: COPY --from source is not a declared stage "
                    "or reviewed named build context"
                )
        final_from_indexes = [
            index
            for index, instruction in enumerate(instructions)
            if FROM_RE.fullmatch(instruction)
        ]
        if final_from_indexes:
            final_copy_instructions = tuple(
                " ".join(instruction.split())
                for instruction in instructions[final_from_indexes[-1] + 1 :]
                if COPY_INSTRUCTION_RE.match(instruction)
            )
            if (
                final_copy_instructions
                != FINAL_STAGE_COPY_INSTRUCTIONS[relative]
            ):
                failures.append(
                    f"{relative}: final-stage COPY instructions must match "
                    "the exact reviewed inventory"
                )
        for base, _alias, _platform in stages:
            if not DIGEST_PIN_RE.search(base):
                failures.append(
                    f"{relative}: upstream base is not pinned by immutable digest: {base}"
                )
        runtime = text[stage_matches[-1].start() :]
        if re.search(r"^[ \t]*RUN(?:[ \t]|$)", runtime, re.IGNORECASE | re.MULTILINE):
            failures.append(
                f"{relative}: final Distroless runtime contains 'RUN'"
            )
        for forbidden in ("apt-get", "/bin/sh", "curl ", "wget "):
            if forbidden in runtime:
                failures.append(
                    f"{relative}: final Distroless runtime contains {forbidden.strip()!r}"
                )
        runtime_directives = (
            RELAY_RUNTIME_DIRECTIVES
            if relative in RELAY_DOCKERFILES
            else NOTARY_RUNTIME_DIRECTIVES
        )
        active_runtime_directives: dict[str, list[str]] = {}
        for line in runtime.splitlines():
            directive_match = RUNTIME_DIRECTIVE_RE.match(line)
            if directive_match:
                name = directive_match.group("name").casefold()
                active_runtime_directives.setdefault(name, []).append(line)
        for directive, detail in runtime_directives:
            name = directive.partition(" ")[0]
            active_lines = active_runtime_directives.get(name.casefold(), [])
            if active_lines != [directive]:
                failures.append(
                    f"{relative}: missing {detail} in final runtime stage: "
                    f"expected exactly one active {name} directive "
                    f"{directive!r}; found {active_lines!r}"
                )
        for name, invariant in (
            ("user", "inherit the nonroot base user"),
            ("volume", "declare no writable VOLUME mount surfaces"),
        ):
            active_lines = active_runtime_directives.get(name, [])
            if active_lines:
                failures.append(
                    f"{relative}: final Distroless runtime must {invariant}; "
                    f"found active {name.upper()} directives {active_lines!r}"
                )

    for relative in PREPARATION_DOCKERFILES:
        text = texts[relative]
        if not text.startswith(f"# syntax={DOCKERFILE_FRONTEND}\n"):
            failures.append(
                f"{relative}: pinned Dockerfile frontend must be the first line"
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
            text,
            "chown -R 65532:65532",
            relative,
            "numeric nonroot-owned Notary runtime directories",
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
    require_unique_active_line(
        workflow,
        (f"  RELEASE_BUILDER_IMAGE: {RUST_BUILDER}",),
        RELEASE_BUILDER_KEY_RE,
        Path(".github/workflows/release.yml"),
        "pinned Debian 13 release builder",
        failures,
    )
    require_unique_active_line(
        binary_recipe,
        tuple(
            f'{prefix}default_builder_image="{RUST_BUILDER}"'
            for prefix in ("", "readonly ", "export ")
        ),
        DEFAULT_BUILDER_ASSIGNMENT_RE,
        Path("release/scripts/build-release-binaries.sh"),
        "pinned Debian 13 release recipe builder",
        failures,
    )
    require_unique_active_line(
        binary_recipe,
        tuple(
            f"{prefix}{RELEASE_BUILDER_HANDOFF}"
            for prefix in ("", "readonly ", "export ")
        ),
        RELEASE_BUILDER_HANDOFF_RE,
        Path("release/scripts/build-release-binaries.sh"),
        "release builder handoff",
        failures,
    )
    release_builder_command = shell_continuation_command(
        binary_recipe,
        "docker run --rm",
    )
    require_unique_text(
        release_builder_command,
        RELEASE_BUILDER_TAIL,
        Path("release/scripts/build-release-binaries.sh"),
        "release Docker builder command tail",
        failures,
    )
    require_exact_command_prefix(
        release_builder_command,
        RELEASE_BUILDER_PREFIX,
        Path("release/scripts/build-release-binaries.sh"),
        "release Docker builder command",
        failures,
    )
    require(
        binary_recipe,
        "--features registry-notary/registry-notary-cel,registry-notary/pkcs11",
        Path("release/scripts/build-release-binaries.sh"),
        "PKCS#11-enabled release build",
        failures,
    )
    require_unique_active_line(
        tutorial_check,
        tuple(
            f'{prefix}BUILDER_IMAGE="{RUST_BUILDER}"'
            for prefix in ("", "readonly ", "export ")
        ),
        TUTORIAL_BUILDER_ASSIGNMENT_RE,
        Path("docs/site/scripts/check-registryctl-tutorials.sh"),
        "pinned Debian 13 registryctl tutorial builder",
        failures,
    )
    tutorial_builder_command = shell_continuation_command(
        tutorial_check,
        "docker run --rm",
    )
    require_unique_text(
        tutorial_builder_command,
        TUTORIAL_BUILDER_TAIL,
        Path("docs/site/scripts/check-registryctl-tutorials.sh"),
        "registryctl tutorial Docker builder command tail",
        failures,
    )
    require_exact_command_prefix(
        tutorial_builder_command,
        TUTORIAL_BUILDER_PREFIX,
        Path("docs/site/scripts/check-registryctl-tutorials.sh"),
        "registryctl tutorial Docker builder command",
        failures,
    )

    live_journey = texts[
        Path("crates/registry-relay/scripts/run-live-consultation-journey.sh")
    ]
    live_journey_path = Path(
        "crates/registry-relay/scripts/run-live-consultation-journey.sh"
    )
    postgres_assignments = [
        line
        for line in live_journey.splitlines()
        if LIVE_JOURNEY_POSTGRES_ASSIGNMENT_RE.match(line)
    ]
    if postgres_assignments != [LIVE_JOURNEY_POSTGRES_ASSIGNMENT]:
        failures.append(
            f"{live_journey_path}: live-journey PostgreSQL image assignment "
            "must remain the single reviewed value"
        )
    postgres_setup_command = shell_continuation_command(
        live_journey,
        "docker run --rm",
        LIVE_JOURNEY_POSTGRES_CONSUMER,
    )
    require_exact_command_prefix(
        postgres_setup_command,
        LIVE_JOURNEY_POSTGRES_SETUP_PREFIX,
        live_journey_path,
        "live-journey PostgreSQL certificate setup command",
        failures,
        report_values=False,
    )
    postgres_server_command = shell_continuation_command(
        live_journey,
        "docker run --detach",
        LIVE_JOURNEY_POSTGRES_CONSUMER,
    )
    require_exact_command_prefix(
        postgres_server_command,
        LIVE_JOURNEY_POSTGRES_SERVER_PREFIX,
        live_journey_path,
        "live-journey PostgreSQL server command",
        failures,
        report_values=False,
    )
    require_unique_active_line(
        live_journey,
        (LIVE_JOURNEY_BUILDER,),
        LIVE_JOURNEY_BUILDER_RE,
        live_journey_path,
        "pinned Debian 13 live-journey builder",
        failures,
    )
    live_builder_command = shell_continuation_command(
        live_journey,
        "docker run --rm",
        LIVE_JOURNEY_BUILDER,
    )
    require_unique_text(
        live_builder_command,
        LIVE_JOURNEY_BUILDER_TAIL,
        live_journey_path,
        "live-journey Docker builder command tail",
        failures,
    )
    require_exact_command_prefix(
        live_builder_command,
        LIVE_JOURNEY_BUILDER_PREFIX,
        live_journey_path,
        "live-journey Docker builder command",
        failures,
    )

    tutorial_cache = workflow_step(ci_workflow, TUTORIAL_CACHE_STEP)
    if not tutorial_cache:
        failures.append(
            f".github/workflows/ci.yml: missing unique {TUTORIAL_CACHE_STEP!r} step"
        )
    else:
        require_unique_active_line(
            tutorial_cache,
            TUTORIAL_CACHE_KEYS,
            CACHE_KEY_RE,
            Path(".github/workflows/ci.yml"),
            "registryctl tutorial builder cache key",
            failures,
        )
        if RESTORE_KEYS_RE.search(tutorial_cache):
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
