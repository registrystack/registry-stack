#!/usr/bin/env python3
"""Run and verify the first-country journey from one closed release payload."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


STABLE_SCHEMA = "registry-stack.first-country-release-form.v3"
TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
RELAY_IMAGE = re.compile(
    r"^ghcr\.io/registrystack/registry-relay@sha256:([0-9a-f]{64})$"
)
NOTARY_IMAGE = re.compile(
    r"^ghcr\.io/registrystack/registry-notary@sha256:([0-9a-f]{64})$"
)
POSTGRESQL_IMAGE = re.compile(
    r"^docker\.io/library/postgres@sha256:([0-9a-f]{64})$"
)
STABLE_COMMAND_ORDER = (
    "install",
    "version",
    "reader_journeys",
    "pull_relay",
    "pull_notary",
    "pull_postgresql",
    "public_source_live",
    "oauth_dev_up",
    "oauth_dev_smoke",
    "oauth_dev_down",
    "doctor",
    "dev_up",
    "dev_status",
    "dev_smoke",
    "dev_logs",
    "inspect",
    "anchor_relay_public",
    "sign_relay_public",
    "verify_relay_public",
    "anchor_relay_consultation",
    "sign_relay_consultation",
    "verify_relay_consultation",
    "anchor_notary",
    "sign_notary",
    "verify_notary",
    "approved_set",
    "deploy_generate",
    "dev_down",
    "deploy_verify",
    "parent_include_config",
    "initialize_config",
    "inspect_secret_stagers",
    "initialize_stage_relay_consultation_action_secrets",
    "initialize_stage_notary_action_secrets",
    "initialize_stage_postgresql_action_secrets",
    "initialize_postgresql",
    "initialize_relay_public_prepare",
    "initialize_relay_consultation_prepare",
    "initialize_notary_prepare",
    "initialize_relay_public",
    "initialize_relay_consultation",
    "initialize_notary",
    "reject_postgresql_data_reinitialization",
    "reject_postgresql_bootstrap_reinitialization",
    "governed_start",
    "governed_restart",
    "governed_stop_for_backup",
    "backup_restore",
    "restored_start",
    "update_build",
    "rotate_relay_consultation",
    "update_sign_relay_consultation",
    "update_verify_relay_consultation",
    "update_sign_notary",
    "update_approved_set",
    "update_generate",
    "update_verify",
    "failed_activation",
    "failed_activation_recovery",
    "update_preview_relay_public",
    "update_preview_relay_consultation",
    "update_preview_notary",
    "update_stop_current",
    "update_accept_relay_consultation",
    "update_accept_notary",
    "update_verify_relay_public_state",
    "update_verify_relay_consultation_state",
    "update_verify_notary_state",
    "update_stage_relay_public_serving_secrets",
    "update_stage_relay_consultation_serving_secrets",
    "update_stage_notary_serving_secrets",
    "update_stage_postgresql_serving_secrets",
    "updated_start",
    "updated_stop",
    "rollback_rejected",
    "final_start",
    "isolated_teardown",
)
STABLE_WORKLOAD_IMAGES = {
    "relay-public": "relay_image",
    "relay-consultation": "relay_image",
    "notary": "notary_image",
    "postgresql": "postgresql_image",
    "synthetic-source": "relay_image",
}
STABLE_LISTENERS = {
    "relay-public": "127.0.0.1:4242",
    "notary": "127.0.0.1:4243",
}
STABLE_READER_EVIDENCE_FILES = {
    "manifest.json",
    "http/init.txt",
    "http/test.txt",
    "http/trace.txt",
    "http/build.txt",
    "http/test.json",
    "http/check.json",
    "http/build.json",
    "opencrvs-init.txt",
    "opencrvs-overlay.txt",
    "opencrvs-check-explain.txt",
    "opencrvs/test.json",
    "opencrvs/check.json",
    "opencrvs/build.json",
    "public-source-init.txt",
    "public-source-overlay.txt",
    "public-source-test.txt",
    "public-source-check.txt",
    "public-source-missing-check.txt",
}
PUBLIC_SOURCE_LIVE_EVIDENCE_FILES = {
    "init.txt",
    "overlay.txt",
    "offline-test.txt",
    "public-demo-check.txt",
    "public-demo-missing-check.txt",
    "public-todo-4.json",
    "public-todo-999999.json",
    "public-demo-start.txt",
    "public-demo-smoke.txt",
    "public-demo-down.txt",
    "public-demo-missing-start.txt",
    "public-demo-missing-smoke.txt",
    "public-demo-missing-down.txt",
}
PUBLIC_MATERIAL_FILENAMES = {
    "request.json",
    "notary-workload-jwks.json",
    "relay-public.public.jwk",
    "relay-consultation.public.jwk",
    "notary.public.jwk",
    "relay-public-tls-certificate",
    "relay-consultation-tls-certificate",
    "notary-tls-certificate",
    "postgresql-tls-certificate",
    "relay-public-tls.crt",
    "relay-consultation-tls.crt",
    "notary-tls.crt",
    "postgres-tls.crt",
}
HTTP_MINIMIZED_CLAIMS = ["person-active", "person-record-exists"]
OPENCRVS_MINIMIZED_CLAIM_IDS = ["birth-event-found", "birth-event-registered"]
GOVERNED_LANES = ("relay-public", "relay-consultation", "notary")
ROLLBACK_AFFECTED_LANES = ("relay-consultation", "notary")
ROLLBACK_SAFE_MESSAGE = (
    "The bundle or override does not satisfy local anti-rollback requirements. "
    "Use a monotonic bundle or an authorized break-glass selection."
)
GOVERNED_DURABLE_VOLUME_SUFFIXES = {
    "registry-postgres": {
        "/var/lib/postgresql/data": "postgresql-data",
    },
    "registry-relay-public": {
        "/var/lib/registry/state": "relay-public-state",
        "/var/lib/registry/audit": "relay-public-audit",
    },
    "registry-relay-consultation": {
        "/var/lib/registry/state": "relay-consultation-state",
        "/var/lib/registry/audit": "relay-consultation-audit",
    },
    "registry-notary": {
        "/var/lib/registry/state": "notary-state",
        "/var/lib/registry/audit": "notary-audit",
    },
}
GOVERNED_OPERATOR_SOURCES = {
    "relay-public-environment": (
        "relay-public-prepare.env",
        "relay-public-initialize.env",
        "relay-public-serve.env",
    ),
    "relay-consultation-environment": (
        "relay-consultation-prepare.env",
        "relay-consultation-initialize.env",
        "relay-consultation-serve.env",
    ),
    "notary-environment": (
        "notary-prepare.env",
        "notary-initialize.env",
        "notary-serve.env",
    ),
    "postgresql-bootstrap-environment": ("postgres-bootstrap.env",),
    "relay-public-tls-certificate": ("relay-public-tls.crt",),
    "relay-public-tls-private-key": ("relay-public-tls.key",),
    "relay-consultation-tls-certificate": ("relay-consultation-tls.crt",),
    "relay-consultation-tls-private-key": ("relay-consultation-tls.key",),
    "notary-tls-certificate": ("notary-tls.crt",),
    "notary-tls-private-key": ("notary-tls.key",),
    "notary-signing-key": ("notary-signing-key.jwk",),
    "notary-relay-workload-credential": ("notary-relay-token",),
    "postgresql-tls-certificate": ("postgres-tls.crt",),
    "postgresql-tls-private-key": ("postgres-tls.key",),
    "postgresql-admin-password": ("postgres-admin-password",),
}
SERVING_SECRET_STAGER_CONTRACT = {
    "registry-relay-public-stage-secrets": {
        "outputs": ("relay-public-serve",),
        "sources": (
            "relay-public-tls-certificate",
            "relay-public-tls-private-key",
        ),
    },
    "registry-relay-consultation-stage-secrets": {
        "outputs": ("relay-consultation-serve",),
        "sources": (
            "postgresql-tls-certificate",
            "relay-consultation-tls-certificate",
            "relay-consultation-tls-private-key",
        ),
    },
    "registry-notary-stage-secrets": {
        "outputs": ("notary-serve",),
        "sources": (
            "notary-relay-workload-credential",
            "notary-signing-key",
            "notary-tls-certificate",
            "notary-tls-private-key",
            "postgresql-tls-certificate",
            "relay-consultation-tls-certificate",
        ),
    },
    "registry-postgresql-stage-secrets": {
        "outputs": ("postgresql-serve",),
        "sources": (
            "postgresql-admin-password",
            "postgresql-tls-certificate",
            "postgresql-tls-private-key",
        ),
    },
}
ACTION_SECRET_STAGER_CONTRACT = {
    "registry-relay-consultation-actions-stage-secrets": {
        "outputs": (
            "relay-consultation-prepare",
            "relay-consultation-initialize",
        ),
        "sources": ("postgresql-tls-certificate",),
    },
    "registry-notary-actions-stage-secrets": {
        "outputs": ("notary-prepare",),
        "sources": ("postgresql-tls-certificate",),
    },
    "registry-postgresql-actions-stage-secrets": {
        "outputs": ("postgresql-bootstrap",),
        "sources": (
            "postgresql-admin-password",
            "postgresql-tls-certificate",
            "postgresql-tls-private-key",
        ),
    },
}
SERVING_SECRET_STAGE_CONSUMERS = {
    "registry-postgres": (
        "registry-postgresql-stage-secrets",
        "postgresql-serve",
    ),
    "registry-relay-public": (
        "registry-relay-public-stage-secrets",
        "relay-public-serve",
    ),
    "registry-relay-consultation": (
        "registry-relay-consultation-stage-secrets",
        "relay-consultation-serve",
    ),
    "registry-notary": (
        "registry-notary-stage-secrets",
        "notary-serve",
    ),
}
ACTION_SECRET_STAGE_CONSUMERS = {
    "registry-postgres-bootstrap": (
        "registry-postgresql-actions-stage-secrets",
        "postgresql-bootstrap",
    ),
    "registry-relay-consultation-prepare-state": (
        "registry-relay-consultation-actions-stage-secrets",
        "relay-consultation-prepare",
    ),
    "registry-relay-consultation-initialize": (
        "registry-relay-consultation-actions-stage-secrets",
        "relay-consultation-initialize",
    ),
    "registry-notary-prepare-state": (
        "registry-notary-actions-stage-secrets",
        "notary-prepare",
    ),
}
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_LOG_BYTES = 1024 * 1024
MAX_AUTHENTICATED_RESPONSE_BYTES = 1024 * 1024
DOCS_ARCHIVE_MAX_BYTES = 256 * 1024 * 1024
DOCS_ARCHIVE_MAX_ENTRY_BYTES = 128 * 1024 * 1024
DOCS_ARCHIVE_MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
DOCS_ARCHIVE_MAX_ENTRIES = 100_000
DOCS_ARCHIVE_MAX_PATH_BYTES = 1024
DOCS_ARCHIVE_MAX_PATH_PARTS = 64
RELEASED_DOCS_REQUIRED_FILES = {
    "configure/oauth-client-credentials.md",
    "examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh",
    "examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh.sha256",
    "examples/registryctl/opencrvs-events-api-overlay-v1.sh",
    "examples/registryctl/opencrvs-events-api-overlay-v1.sh.sha256",
    "operate/approve-initial-baseline.md",
    "tutorials/author-registry-project.md",
    "tutorials/configure-project-script-adapter.md",
    "tutorials/verify-opencrvs-claims.md",
}
RELEASED_DOCS_OVERLAYS = (
    "jsonplaceholder-todo-live-overlay-v1.sh",
    "opencrvs-events-api-overlay-v1.sh",
)
FAILED_ACTIVATION_OUTPUT_CLASSIFICATION = "notary-tls-private-key"
FAILED_ACTIVATION_EXIT_CLASS = "notary_tls_private_key_missing"
RECORDS_URL = "http://127.0.0.1:4242/v1/datasets/projects/entities/projects/records"
RELAY_LISTENER = "127.0.0.1:4242"
NOTARY_LISTENER = "127.0.0.1:4255"
RECORDS_PURPOSE = "public-works-case-management"
MATCH_KEY_ENV = "REGISTRYCTL_LOCAL_RELAY_MATCH_KEY_RAW"
NO_MATCH_KEY_ENV = "REGISTRYCTL_LOCAL_RELAY_NO_MATCH_KEY_RAW"
MATCH_FIELDS = {"project_id", "district_code", "sector", "status"}
ALLOWED_EVIDENCE = [
    {
        "field_names": ["district_code", "project_id", "sector", "status"],
        "http_status": 200,
        "request": "match",
        "row_count": 1,
    },
    {
        "field_names": [],
        "http_status": 200,
        "request": "no-match",
        "row_count": 0,
    },
]
RELAY_SMOKE_OUTCOMES = {
    "allowed public health check": 200,
    "allowed match source is ready": 200,
    "denied anonymous records request": 401,
    "denied wrong local API key": 401,
    "allowed matching principal returns one record": 200,
    "wrong principal safely returns no match": 200,
}
NOTARY_SMOKE_OUTCOMES = {
    "denied anonymous Notary evaluation": 401,
    "denied wrong Notary API key": 401,
    "denied under-scoped Notary caller": 403,
    "matching evaluation returns the accepted predicate": 200,
    "second matching evaluation returns the non-accepted predicate": 200,
    "absent evaluation returns the bounded no-match predicate": 200,
}
SMOKE_EVIDENCE = {
    "relay_only": [
        {"name": name, "http_status": status}
        for name, status in RELAY_SMOKE_OUTCOMES.items()
    ],
    "combined_notary": [
        {"name": name, "http_status": status}
        for name, status in {**RELAY_SMOKE_OUTCOMES, **NOTARY_SMOKE_OUTCOMES}.items()
    ],
}
SECRET_FILES = {
    "local_env": "local.env",
    "relay_env": "relay.env",
    "consultation_relay_env": "relay-consultation.env",
    "relay_bootstrap_env": "relay-bootstrap.env",
    "notary_env": "notary.env",
    "postgres_env": "postgres.env",
    "relay_workload_token": "relay-workload-token",
    "workload_private_jwk": "workload-private.jwk",
}
NON_CREDENTIAL_ENV_NAMES = {
    b"PGDATA",
    b"POSTGRES_USER",
    b"REGISTRYCTL_LOCAL_NOTARY_CALLER_TOKEN_HASH",
    b"REGISTRYCTL_LOCAL_NOTARY_UNDER_SCOPED_TOKEN_HASH",
    b"REGISTRYCTL_LOCAL_POSTGRES_TLS_CERTIFICATE_B64",
    b"REGISTRYCTL_LOCAL_RELAY_MATCH_KEY_HASH",
    b"REGISTRYCTL_LOCAL_RELAY_NO_MATCH_KEY_HASH",
    b"REGISTRYCTL_LOCAL_WORKLOAD_PUBLIC_JWK",
}


class ReleaseFormError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sealed_release_environment(source: dict[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in source.items()
        if not name.startswith(("REGISTRYCTL_", "COMPOSE_"))
    }


def bind_release_form_project_identity(project_file: Path, project_id: str) -> None:
    if re.fullmatch(r"first-country-release-form-[0-9a-f]{16}", project_id) is None:
        raise ReleaseFormError("release-form project identity is invalid")
    require_regular(project_file, max_bytes=4 * 1024 * 1024)
    try:
        source = project_file.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseFormError("release-form project is not valid UTF-8") from error
    registry_id = re.compile(
        r"(?m)^(registry:\n  id: )[A-Za-z0-9][A-Za-z0-9._-]*$"
    )
    if len(registry_id.findall(source)) != 1:
        raise ReleaseFormError(
            "release-form project has no single closed registry identity"
        )
    project_file.write_text(
        registry_id.sub(rf"\g<1>{project_id}", source),
        encoding="utf-8",
    )


def available_governed_loopback_ports() -> tuple[int, int]:
    reservations: list[socket.socket] = []
    try:
        for _ in range(2):
            reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reservation.bind(("127.0.0.1", 0))
            reservations.append(reservation)
        ports = tuple(
            int(reservation.getsockname()[1]) for reservation in reservations
        )
    except OSError as error:
        raise ReleaseFormError(
            "cannot allocate proof-specific governed loopback ports"
        ) from error
    finally:
        for reservation in reservations:
            reservation.close()
    if len(ports) != 2 or ports[0] == ports[1] or any(port == 0 for port in ports):
        raise ReleaseFormError(
            "proof-specific governed loopback ports are unavailable"
        )
    return ports


def require_regular(path: Path, *, max_bytes: int = MAX_FILE_BYTES) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseFormError(f"required file is unavailable: {path.name}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReleaseFormError(
            f"required file must be regular and non-symlink: {path.name}"
        )
    if metadata.st_size <= 0 or metadata.st_size > max_bytes:
        raise ReleaseFormError(f"required file has an invalid size: {path.name}")


def platform_asset(tag: str) -> str:
    system = platform.system()
    machine = platform.machine().lower()
    supported = {
        ("Linux", "x86_64"): "linux-amd64",
        ("Linux", "amd64"): "linux-amd64",
        ("Linux", "aarch64"): "linux-arm64",
        ("Linux", "arm64"): "linux-arm64",
        ("Darwin", "arm64"): "macos-arm64",
        ("Darwin", "aarch64"): "macos-arm64",
    }
    try:
        suffix = supported[(system, machine)]
    except KeyError as error:
        raise ReleaseFormError(
            f"unsupported release-form platform {system}/{machine}; expected Linux amd64, "
            "Linux arm64, or macOS arm64"
        ) from error
    return f"registryctl-{tag}-{suffix}"


def beginner_runtime_asset(tag: str) -> str:
    asset = platform_asset(tag)
    if not asset.endswith("-linux-amd64"):
        raise ReleaseFormError(
            "the complete first-country runtime is supported and release-gated only on Linux amd64; "
            "the Linux arm64 and macOS arm64 Registryctl assets are for CLI authoring"
        )
    return asset


def parse_checksums(path: Path) -> dict[str, str]:
    require_regular(path, max_bytes=4 * 1024 * 1024)
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            raise ReleaseFormError("SHA256SUMS contains an invalid entry")
        name = parts[1].removeprefix("*")
        if Path(name).name != name or name in checksums:
            raise ReleaseFormError(
                "SHA256SUMS contains an unsafe or duplicate asset name"
            )
        checksums[name] = parts[0]
    return checksums


def verify_asset_set(asset_dir: Path, tag: str) -> dict[str, Any]:
    tag_match = TAG.fullmatch(tag)
    if tag_match is None:
        raise ReleaseFormError("release tag must be canonical vMAJOR.MINOR.PATCH")
    if int(tag_match.group(1)) < 1:
        raise ReleaseFormError("release-form proof supports Registry Stack v1 and later")
    installer_name = f"registryctl-{tag}-install.sh"
    binary_name = platform_asset(tag)
    lock_name = f"registryctl-{tag}-image-lock.json"
    release_lock_name = "registry-release-lock.v1.json"
    docs_archive_name = f"registry-docs-{tag}.tar.gz"
    names = [
        installer_name,
        binary_name,
        lock_name,
        release_lock_name,
        docs_archive_name,
    ]
    checksums = parse_checksums(asset_dir / "SHA256SUMS")
    assets: dict[str, str] = {}
    for name in names:
        path = asset_dir / name
        require_regular(
            path,
            max_bytes=(
                DOCS_ARCHIVE_MAX_BYTES
                if name == docs_archive_name
                else MAX_FILE_BYTES
            ),
        )
        expected = checksums.get(name)
        actual = sha256(path)
        if expected is None or expected != actual:
            raise ReleaseFormError(f"release checksum does not bind exact asset {name}")
        assets[name] = actual
    try:
        lock = json.loads((asset_dir / lock_name).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFormError("release image lock is not valid JSON") from error
    expected_lock_keys = {
        "schema_version",
        "release_tag",
        "manifest_source_ref",
        "tag_target",
        "platform",
        "images",
    }
    if (
        not isinstance(lock, dict)
        or set(lock) != expected_lock_keys
        or lock.get("schema_version") != "registryctl.release_image_lock.v2"
        or lock.get("release_tag") != tag
        or lock.get("platform") != "linux/amd64"
    ):
        raise ReleaseFormError(
            "release image lock does not match the current Linux amd64 runtime contract"
        )
    if lock.get("manifest_source_ref") != lock.get("tag_target"):
        raise ReleaseFormError(
            "release image lock must bind one exact candidate and tag revision"
        )
    images = lock.get("images")
    relay_image = images.get("registry-relay") if isinstance(images, dict) else None
    notary_image = images.get("registry-notary") if isinstance(images, dict) else None
    postgresql_image = images.get("postgresql") if isinstance(images, dict) else None
    if not isinstance(images, dict) or set(images) != {
        "registry-relay",
        "registry-notary",
        "postgresql",
    }:
        raise ReleaseFormError("release image lock image set is not closed")
    if not isinstance(relay_image, str) or RELAY_IMAGE.fullmatch(relay_image) is None:
        raise ReleaseFormError(
            "release image lock has no canonical Relay digest reference"
        )
    if (
        not isinstance(notary_image, str)
        or NOTARY_IMAGE.fullmatch(notary_image) is None
    ):
        raise ReleaseFormError(
            "release image lock has no canonical Notary digest reference"
        )
    if (
        not isinstance(postgresql_image, str)
        or POSTGRESQL_IMAGE.fullmatch(postgresql_image) is None
    ):
        raise ReleaseFormError(
            "release image lock has no canonical PostgreSQL digest reference"
        )
    return {
        "installer_name": installer_name,
        "binary_name": binary_name,
        "lock_name": lock_name,
        "release_lock_name": release_lock_name,
        "docs_archive_name": docs_archive_name,
        "assets": assets,
        "lock": lock,
        "relay_image": relay_image,
        "notary_image": notary_image,
        "postgresql_image": postgresql_image,
    }


def released_docs_member_name(raw_name: str) -> str:
    if (
        not raw_name
        or "\0" in raw_name
        or "\\" in raw_name
        or len(raw_name.encode("utf-8")) > DOCS_ARCHIVE_MAX_PATH_BYTES
    ):
        raise ReleaseFormError("released docs archive contains an unsafe path")
    name = raw_name.removesuffix("/")
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or path.as_posix() != name
        or len(path.parts) > DOCS_ARCHIVE_MAX_PATH_PARTS
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.parts[0] not in {"metadata.json", "root", "version"}
        or (path.parts[0] == "metadata.json" and len(path.parts) != 1)
    ):
        raise ReleaseFormError("released docs archive contains an unsafe path")
    return name


def verify_released_docs_overlay(version_root: Path, name: str) -> None:
    overlay = version_root / "examples" / "registryctl" / name
    checksum = overlay.with_name(f"{name}.sha256")
    require_regular(overlay)
    require_regular(checksum, max_bytes=1024)
    try:
        lines = checksum.read_text(encoding="ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ReleaseFormError(
            f"released docs overlay checksum is not ASCII: {name}"
        ) from error
    expected_line = (
        f"{sha256(overlay)}  {name}"
    )
    if lines != [expected_line]:
        raise ReleaseFormError(
            f"released docs overlay checksum does not bind exact asset {name}"
        )


def extract_released_docs_archive(
    archive_path: Path,
    destination: Path,
    *,
    tag: str,
) -> Path:
    """Safely extract and verify the checksum-bound released docs version tree."""

    require_regular(archive_path, max_bytes=DOCS_ARCHIVE_MAX_BYTES)
    if destination.is_symlink() or (
        destination.exists()
        and (not destination.is_dir() or any(destination.iterdir()))
    ):
        raise ReleaseFormError(
            "released docs extraction destination must be absent or an empty real directory"
        )
    destination.mkdir(parents=True, mode=0o700, exist_ok=True)
    seen: set[str] = set()
    total_size = 0
    member_count = 0
    top_level: set[str] = set()
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive:
                member_count += 1
                if member_count > DOCS_ARCHIVE_MAX_ENTRIES:
                    raise ReleaseFormError(
                        "released docs archive has too many entries"
                    )
                name = released_docs_member_name(member.name)
                if name in seen:
                    raise ReleaseFormError(
                        "released docs archive contains a duplicate path"
                    )
                seen.add(name)
                top_level.add(PurePosixPath(name).parts[0])
                if member.isdir():
                    if member.size != 0:
                        raise ReleaseFormError(
                            "released docs archive directory has a nonzero size"
                        )
                    target = destination.joinpath(*PurePosixPath(name).parts)
                    target.mkdir(parents=True, mode=0o700, exist_ok=True)
                    target.chmod(0o700)
                    continue
                if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE}:
                    raise ReleaseFormError(
                        "released docs archive contains a non-regular entry"
                    )
                if member.size < 0 or member.size > DOCS_ARCHIVE_MAX_ENTRY_BYTES:
                    raise ReleaseFormError(
                        "released docs archive entry exceeds its size bound"
                    )
                total_size += member.size
                if total_size > DOCS_ARCHIVE_MAX_EXTRACTED_BYTES:
                    raise ReleaseFormError(
                        "released docs archive exceeds its extracted size bound"
                    )
                source = archive.extractfile(member)
                if source is None:
                    raise ReleaseFormError(
                        "released docs archive member cannot be read"
                    )
                payload = source.read(DOCS_ARCHIVE_MAX_ENTRY_BYTES + 1)
                if len(payload) != member.size:
                    raise ReleaseFormError(
                        "released docs archive contains a truncated member"
                    )
                target = destination.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                with target.open("xb") as handle:
                    handle.write(payload)
                target.chmod(0o700 if member.mode & 0o111 else 0o600)
    except (OSError, tarfile.TarError) as error:
        raise ReleaseFormError(
            f"cannot extract released docs archive: {error}"
        ) from error
    if not seen or top_level != {"metadata.json", "root", "version"}:
        raise ReleaseFormError(
            "released docs archive has an unexpected top-level structure"
        )
    metadata = read_closed_json(
        destination / "metadata.json", "released docs archive metadata"
    )
    expected_metadata_keys = {
        "schema_version",
        "release_tag",
        "root_tree_sha256",
        "version_path",
        "version_tree_sha256",
    }
    if (
        not isinstance(metadata, dict)
        or set(metadata) != expected_metadata_keys
        or metadata.get("schema_version") != "registry-docs.archive-bundle.v3"
        or metadata.get("release_tag") != tag
        or metadata.get("version_path") != f"/v/{tag.removeprefix('v')}/"
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(metadata.get(name))) is None
            for name in ("root_tree_sha256", "version_tree_sha256")
        )
    ):
        raise ReleaseFormError(
            "released docs archive metadata does not match the release tag"
        )
    version_tree = destination / "version"
    for tree in (destination / "root", version_tree):
        tree_metadata = tree.lstat()
        if stat.S_ISLNK(tree_metadata.st_mode) or not stat.S_ISDIR(
            tree_metadata.st_mode
        ):
            raise ReleaseFormError(
                "released docs archive tree must be a real directory"
            )
    observed_version_files = {
        path.relative_to(version_tree).as_posix()
        for path in version_tree.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    missing = RELEASED_DOCS_REQUIRED_FILES - observed_version_files
    if missing:
        raise ReleaseFormError(
            f"released docs archive is missing required public reader input {sorted(missing)[0]}"
        )
    for name in RELEASED_DOCS_OVERLAYS:
        verify_released_docs_overlay(version_tree, name)
    return version_tree


def run_command(
    name: str,
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    logs: Path,
    expected_status: int = 0,
) -> dict[str, Any]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
        check=False,
    )
    output = result.stdout[-MAX_LOG_BYTES:]
    write_private(logs / f"{name}.log", output.encode())
    if result.returncode != expected_status:
        raise ReleaseFormError(
            f"{name} failed with status {result.returncode}; expected {expected_status}"
        )
    return {
        "name": name,
        "status": "passed",
        "exit_code": result.returncode,
        "log_sha256": sha256(logs / f"{name}.log"),
    }


def credential_env_values(path: Path) -> list[bytes]:
    values: list[bytes] = []
    for line in path.read_bytes().splitlines():
        if b"=" not in line or line.startswith(b"#"):
            continue
        name, value = line.split(b"=", 1)
        if name in NON_CREDENTIAL_ENV_NAMES:
            continue
        if value:
            values.append(value)
    return sorted(set(values), key=len, reverse=True)


def available_secret_values(secrets_dir: Path) -> list[bytes]:
    """Collect redaction values without trusting a partial runtime directory."""
    try:
        paths = sorted(secrets_dir.iterdir())
    except OSError:
        return []
    values: list[bytes] = []
    for path in paths:
        try:
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size <= 0
                or metadata.st_size > MAX_FILE_BYTES
            ):
                continue
            if path.suffix == ".env":
                values.extend(credential_env_values(path))
            else:
                data = path.read_bytes()
                values.extend(value for value in (data, data.strip()) if value)
        except OSError:
            continue
    return sorted(set(values), key=len, reverse=True)


def required_local_credentials(path: Path) -> tuple[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ReleaseFormError("canonical local credentials are unavailable") from error
    for line in lines:
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name in {MATCH_KEY_ENV, NO_MATCH_KEY_ENV}:
            if name in values or not value:
                raise ReleaseFormError("canonical local credentials are invalid")
            values[name] = value
    if set(values) != {MATCH_KEY_ENV, NO_MATCH_KEY_ENV}:
        raise ReleaseFormError("canonical local credentials are incomplete")
    if values[MATCH_KEY_ENV] == values[NO_MATCH_KEY_ENV]:
        raise ReleaseFormError(
            "canonical match and no-match credentials must be distinct"
        )
    return values[MATCH_KEY_ENV], values[NO_MATCH_KEY_ENV]


def authenticated_records_request(
    raw_key: str,
    *,
    cwd: Path,
    env: dict[str, str],
) -> tuple[int, str]:
    marker = "\nREGISTRYCTL_HTTP_STATUS:"
    result = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--max-time",
            "30",
            "--max-filesize",
            str(MAX_AUTHENTICATED_RESPONSE_BYTES),
            "--header",
            "@-",
            "--write-out",
            f"{marker}%{{http_code}}",
            RECORDS_URL,
        ],
        cwd=cwd,
        env=env,
        input=(f"Authorization: Bearer {raw_key}\nData-Purpose: {RECORDS_PURPOSE}\n"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=35,
        check=False,
    )
    body, separator, status_text = result.stdout.rpartition(marker)
    if (
        result.returncode != 0
        or not separator
        or not re.fullmatch(r"[0-9]{3}", status_text)
        or len(body.encode("utf-8")) > MAX_AUTHENTICATED_RESPONSE_BYTES
    ):
        raise ReleaseFormError("authenticated records request failed")
    return int(status_text), body


def summarize_records_response(
    name: str,
    status: int,
    body: str,
    *,
    expected_rows: int,
    expected_fields: set[str] | None,
) -> dict[str, Any]:
    if status != 200:
        raise ReleaseFormError(f"authenticated {name} request did not return HTTP 200")
    try:
        document = json.loads(body)
    except json.JSONDecodeError as error:
        raise ReleaseFormError(
            f"authenticated {name} response is not valid JSON"
        ) from error
    if not isinstance(document, dict) or not isinstance(document.get("data"), list):
        raise ReleaseFormError(
            f"authenticated {name} response has an invalid data shape"
        )
    rows = document["data"]
    if any(not isinstance(row, dict) for row in rows):
        raise ReleaseFormError(
            f"authenticated {name} response contains a non-object row"
        )
    if len(rows) != expected_rows:
        raise ReleaseFormError(
            f"authenticated {name} response has an unexpected row count"
        )
    field_names = sorted(rows[0]) if rows else []
    if expected_fields is not None and (
        len(rows) != 1 or set(field_names) != expected_fields
    ):
        raise ReleaseFormError(
            f"authenticated {name} response has unexpected disclosed fields"
        )
    return {
        "request": name,
        "http_status": status,
        "row_count": len(rows),
        "field_names": field_names,
    }


def run_authenticated_records_evidence(
    *,
    project: Path,
    env: dict[str, str],
    logs: Path,
    match_key: str,
    no_match_key: str,
) -> None:
    if match_key == no_match_key:
        raise ReleaseFormError("authenticated evidence credentials must be distinct")
    match_status, match_body = authenticated_records_request(
        match_key, cwd=project, env=env
    )
    no_match_status, no_match_body = authenticated_records_request(
        no_match_key, cwd=project, env=env
    )
    summaries = [
        summarize_records_response(
            "match",
            match_status,
            match_body,
            expected_rows=1,
            expected_fields=MATCH_FIELDS,
        ),
        summarize_records_response(
            "no-match",
            no_match_status,
            no_match_body,
            expected_rows=0,
            expected_fields=None,
        ),
    ]
    (logs / "allowed.log").write_text(
        json.dumps(summaries, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def assert_no_secret_leak(project: Path, secrets: Iterable[bytes]) -> int:
    secrets_root = Path(".registry-stack/runtime/local/secrets")
    scanned = 0
    for path in sorted(project.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(project)
        if secrets_root in relative.parents or "state" in relative.parts:
            continue
        data = path.read_bytes()
        scanned += 1
        if any(secret in data for secret in secrets):
            raise ReleaseFormError(
                f"raw credential leaked into generated file {relative}"
            )
    return scanned


def assert_no_governed_secret_leak(
    package: Path, secrets: Iterable[bytes]
) -> int:
    scanned = 0
    for path in sorted(package.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(package)
        if relative.parts and relative.parts[0] == "operator":
            continue
        try:
            data = path.read_bytes()
        except PermissionError as error:
            if shutil.which("sudo") is None:
                raise ReleaseFormError(
                    "governed generated file cannot be scanned"
                ) from error
            read = subprocess.run(
                ["sudo", "--non-interactive", "cat", "--", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=60,
                check=False,
            )
            if read.returncode != 0 or len(read.stdout) > MAX_FILE_BYTES:
                raise ReleaseFormError(
                    "governed generated file cannot be scanned"
                ) from error
            data = read.stdout
        scanned += 1
        if any(secret in data for secret in secrets):
            raise ReleaseFormError(
                f"raw credential leaked into governed generated file {relative}"
            )
    return scanned


def redact_logs(
    logs: Path,
    secrets: Iterable[bytes],
    private_paths: Iterable[Path] = (),
) -> None:
    candidate_paths = [
        candidate
        for path in private_paths
        if str(path).strip()
        for candidate in (path.absolute(), path.resolve())
    ]
    path_bytes = sorted(
        {os.fsencode(str(path)) for path in candidate_paths},
        key=len,
        reverse=True,
    )
    for path in logs.glob("*.log"):
        data = path.read_bytes()
        for secret in secrets:
            data = data.replace(secret, b"[REDACTED]")
        for private_path in path_bytes:
            data = data.replace(private_path, b"[PRIVATE_PATH]")
        write_private(path, data)


def mode(path: Path) -> str:
    return f"{stat.S_IMODE(path.stat().st_mode):04o}"


def require_private_directory(path: Path) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseFormError(f"required directory must be real: {path.name}")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ReleaseFormError(f"required directory must be owner-only: {path.name}")


def digest_uri(path: Path) -> str:
    require_regular(path)
    return f"sha256:{sha256(path)}"


def read_runtime_inspection(
    project: Path,
    *,
    expected_relay_image: str,
    expected_notary_image: str | None,
    expected_postgresql_image: str | None,
) -> dict[str, str]:
    relay_config = (
        project / ".registry-stack/build/local/private/relay/config/relay.yaml"
    )
    runtime = project / ".registry-stack/runtime/local"
    compose = runtime / "compose.yaml"
    manifest = runtime / "manifest.json"
    require_regular(relay_config)
    require_private_directory(runtime / "secrets")
    require_regular(compose)
    require_regular(manifest)
    try:
        runtime_manifest = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFormError(
            "canonical runtime manifest is not valid JSON"
        ) from error
    expected_topology = (
        "combined_notary" if expected_notary_image is not None else "relay_only"
    )
    # registryctl start and smoke validate the internal runtime contract. Keep
    # this release-form check limited to the identity recorded as evidence.
    required_keys = {
        "schema_version",
        "environment",
        "relay_image",
        "workbook_classification",
        "topology",
    }
    if expected_notary_image is not None:
        required_keys.add("notary")
    if (
        not isinstance(runtime_manifest, dict)
        or not required_keys.issubset(runtime_manifest)
    ):
        raise ReleaseFormError(
            "canonical runtime manifest is missing required evidence fields"
        )
    if (
        runtime_manifest.get("schema_version") != "registryctl.local_runtime.v2"
        or runtime_manifest.get("environment") != "local"
        or runtime_manifest.get("relay_image") != expected_relay_image
        or runtime_manifest.get("workbook_classification")
        != "operator_owned_source_data"
        or runtime_manifest.get("topology") != expected_topology
    ):
        raise ReleaseFormError(
            "canonical runtime release identity, topology, or workbook classification is invalid"
        )
    notary = runtime_manifest.get("notary")
    if expected_notary_image is None:
        if notary is not None or expected_postgresql_image is not None:
            raise ReleaseFormError("Relay-only canonical runtime contains Notary state")
    else:
        if (
            expected_postgresql_image is None
            or not isinstance(notary, dict)
            or notary.get("notary_image") != expected_notary_image
            or notary.get("postgresql_image") != expected_postgresql_image
        ):
            raise ReleaseFormError(
                "combined canonical runtime Notary manifest is incomplete"
            )
    return {
        "relay_config_sha256": sha256(relay_config),
        "runtime_manifest_sha256": sha256(manifest),
        "compose_sha256": sha256(compose),
        "notary_config_sha256": (
            sha256(
                project
                / ".registry-stack/build/local/private/notary/config/notary.yaml"
            )
            if expected_notary_image is not None
            else ""
        ),
        "topology": expected_topology,
        "workbook_classification": "operator_owned_source_data",
    }


def smoke_outcomes(project: Path, topology: str) -> list[dict[str, Any]]:
    report_path = project / ".registry-stack/runtime/local/smoke-results.json"
    require_regular(report_path)
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseFormError("canonical smoke report is not valid JSON") from error
    checks = report.get("checks") if isinstance(report, dict) else None
    expected = (
        RELAY_SMOKE_OUTCOMES
        if topology == "relay_only"
        else {**RELAY_SMOKE_OUTCOMES, **NOTARY_SMOKE_OUTCOMES}
    )
    observed: dict[str, int] = {}
    if isinstance(checks, list):
        for check in checks:
            if (
                not isinstance(check, dict)
                or set(check)
                != {
                    "name",
                    "method",
                    "path",
                    "expected_status",
                    "actual_status",
                    "passed",
                    "error",
                }
                or not isinstance(check.get("name"), str)
                or type(check.get("expected_status")) is not int
                or type(check.get("actual_status")) is not int
                or check.get("passed") is not True
                or check.get("error") is not None
                or check["expected_status"] != check["actual_status"]
                or check["name"] in observed
            ):
                raise ReleaseFormError("canonical smoke report check is invalid")
            observed[check["name"]] = check["actual_status"]
    if (
        not isinstance(report, dict)
        or set(report) != {"schema_version", "base_url", "passed", "checks"}
        or report.get("schema_version") != "registryctl.smoke.v1"
        or report.get("base_url") != "http://127.0.0.1:4242"
        or report.get("passed") is not True
        or observed != expected
    ):
        raise ReleaseFormError(
            f"canonical {topology} smoke did not prove its exact required outcomes"
        )
    return [
        {"name": name, "http_status": status}
        for name, status in observed.items()
    ]


def verify_loopback_listeners(
    project: Path,
    env: dict[str, str],
    logs: Path,
) -> dict[str, str]:
    compose = project / ".registry-stack/runtime/local/compose.yaml"
    expected = {
        "relay": ("registry-relay", "8080", RELAY_LISTENER),
        "notary": ("notary-network", "8081", NOTARY_LISTENER),
    }
    listeners: dict[str, str] = {}
    for name, (service, container_port, expected_listener) in expected.items():
        result = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(compose),
                "port",
                service,
                container_port,
            ],
            cwd=project,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        listener = result.stdout.strip()
        if result.returncode != 0 or listener != expected_listener:
            raise ReleaseFormError(
                f"{name.title()} is not published on the exact IPv4 loopback listener"
            )
        listeners[name] = listener
    (logs / "listeners.log").write_text(
        json.dumps(listeners, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return listeners


def read_closed_json(path: Path, description: str) -> Any:
    require_regular(path, max_bytes=4 * 1024 * 1024)
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ReleaseFormError(f"{description} is not valid closed JSON") from error


def write_json_log(logs: Path, name: str, value: Any) -> None:
    write_private(
        logs / f"{name}.log",
        (json.dumps(value, sort_keys=True) + "\n").encode(),
    )


def stable_reader_summary(
    manifest_path: Path,
    *,
    version: str,
    retained_project: Path,
    retained_oauth_project: Path,
) -> dict[str, Any]:
    manifest = read_closed_json(manifest_path, "reader-journey manifest")
    expected_projects = [
        {
            "id": "http",
            "source": "embedded-http-template",
            "reports": [
                "http/init.txt",
                "http/test.txt",
                "http/trace.txt",
                "http/build.txt",
                "http/test.json",
                "http/check.json",
                "http/build.json",
            ],
        },
        {
            "id": "opencrvs-events-api",
            "source": "public-docs-overlay-v1",
            "covers": [
                "oauth-client-credentials",
                "bounded-http",
                "rhai",
                "opencrvs-shaped-search",
            ],
            "reports": [
                "opencrvs/test.json",
                "opencrvs/check.json",
                "opencrvs/build.json",
            ],
        },
    ]
    expected_keys = {
        "schema_version",
        "status",
        "mode",
        "registryctl_version",
        "projects",
        "release_boundary",
        "retained_project",
        "retained_oauth_project",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != expected_keys
        or manifest.get("schema_version")
        != "registryctl.tutorial_reader_journeys.v1"
        or manifest.get("status") != "passed"
        or manifest.get("mode") != "sealed"
        or manifest.get("registryctl_version") != version
        or manifest.get("projects") != expected_projects
        or manifest.get("retained_project") != str(retained_project)
        or manifest.get("retained_oauth_project") != str(retained_oauth_project)
    ):
        raise ReleaseFormError(
            "reader-journey manifest does not prove the sealed maintained journeys"
        )
    return {
        "schema_version": manifest["schema_version"],
        "status": "passed",
        "mode": "sealed",
        "registryctl_version": version,
        "projects": ["http", "opencrvs-events-api"],
    }


def stable_public_source_live_summary(evidence: Path) -> dict[str, Any]:
    observed = closed_tree_digests(evidence)
    if set(observed) != PUBLIC_SOURCE_LIVE_EVIDENCE_FILES:
        raise ReleaseFormError("public-source live evidence set is not closed")
    for environment in ("public-demo", "public-demo-missing"):
        smoke = evidence / f"{environment}-smoke.txt"
        require_regular(smoke, max_bytes=MAX_LOG_BYTES)
        text = smoke.read_text(encoding="utf-8")
        if (
            "Development smoke: passed." not in text
            or "status=authorized; passed=true" not in text
        ):
            raise ReleaseFormError(
                f"public-source live evidence did not pass {environment}"
            )
    return {
        "schema_version": "registry-stack.public-source-live-proof.v1",
        "status": "passed",
        "environments": ["public-demo", "public-demo-missing"],
        "evidence_sha256": observed,
    }


def stable_doctor_summary(report: Any) -> dict[str, Any]:
    checks = report.get("checks") if isinstance(report, dict) else None
    expected_ids = {
        "authored_environment",
        "installed_release_lock",
        "docker_cli",
        "docker_daemon",
        "docker_compose",
        "locked_images",
    }
    if (
        not isinstance(report, dict)
        or set(report)
        != {"schema_version", "status", "environment", "profile", "checks"}
        or report.get("schema_version") != "registryctl.doctor.v1"
        or report.get("status") != "ready"
        or report.get("environment") != "local"
        or report.get("profile") != "local"
        or not isinstance(checks, list)
        or {check.get("id") for check in checks if isinstance(check, dict)}
        != expected_ids
        or any(
            not isinstance(check, dict)
            or set(check) != {"id", "status", "category", "remediation"}
            or check.get("status") != "ready"
            or check.get("category") != "ready"
            or check.get("remediation") is not None
            for check in checks
        )
    ):
        raise ReleaseFormError("registryctl doctor did not prove the sealed runtime")
    return {
        "schema_version": report["schema_version"],
        "status": "ready",
        "environment": "local",
        "profile": "local",
        "checks": sorted(expected_ids),
    }


def stable_status_summary(report: Any) -> dict[str, Any]:
    workloads = report.get("workloads") if isinstance(report, dict) else None
    binding = report.get("binding") if isinstance(report, dict) else None
    expected = set(STABLE_WORKLOAD_IMAGES)
    if (
        not isinstance(report, dict)
        or set(report)
        != {
            "schema_version",
            "binding",
            "workloads",
            "source_mode",
            "request_command",
        }
        or report.get("schema_version") != "registryctl.dev_status.v1"
        or report.get("source_mode") != "synthetic"
        or not isinstance(binding, dict)
        or set(binding) != {"project", "environment", "project_root_digest"}
        or not isinstance(binding.get("project"), str)
        or not binding["project"]
        or binding.get("environment") != "local"
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(binding.get("project_root_digest"))
        )
        is None
        or not isinstance(report.get("request_command"), str)
        or not report["request_command"]
        or not isinstance(workloads, list)
        or {item.get("workload") for item in workloads if isinstance(item, dict)}
        != expected
        or any(
            not isinstance(item, dict)
            or set(item) != {"workload", "state"}
            or item.get("state") != "running"
            for item in workloads
        )
    ):
        raise ReleaseFormError(
            "registryctl dev status did not prove every bound workload running"
        )
    return {
        "schema_version": "registryctl.dev_status.v1",
        "source_mode": "synthetic",
        "workloads": [
            {"workload": name, "state": "running"} for name in sorted(expected)
        ],
    }


def stable_smoke_summary(
    report: Any,
    *,
    expected_token_delta: int = 0,
    expected_claims: list[str] = HTTP_MINIMIZED_CLAIMS,
) -> dict[str, Any]:
    results = report.get("results") if isinstance(report, dict) else None
    statuses = {
        item.get("status")
        for item in (results if isinstance(results, list) else [])
        if isinstance(item, dict)
    }
    if (
        not isinstance(report, dict)
        or set(report)
        != {
            "schema_version",
            "project",
            "environment",
            "results",
            "passed",
        }
        or report.get("schema_version") != "registryctl.dev_smoke.v1"
        or report.get("environment") != "local"
        or not isinstance(report.get("project"), str)
        or not report["project"]
        or report.get("passed") is not True
        or not isinstance(results, list)
        or len(results) != 2
        or statuses != {"denied", "authorized"}
        or any(
            not isinstance(item, dict)
            or set(item)
            != {
                "scenario_id",
                "status",
                "token_counter_delta",
                "source_counter_delta",
                "minimized_claim_ids",
                "passed",
            }
            or not isinstance(item.get("scenario_id"), str)
            or not item["scenario_id"]
            or item.get("passed") is not True
            or not isinstance(item.get("minimized_claim_ids"), list)
            for item in results
        )
    ):
        raise ReleaseFormError(
            "registryctl dev smoke did not prove denial and authorized scenarios"
        )
    denial = next(item for item in results if item["status"] == "denied")
    authorized = next(item for item in results if item["status"] == "authorized")
    if (
        denial["token_counter_delta"] != 0
        or denial["source_counter_delta"] != 0
        or denial["minimized_claim_ids"] != []
        or authorized["token_counter_delta"] != expected_token_delta
        or authorized["source_counter_delta"] != 1
        or authorized["minimized_claim_ids"] != expected_claims
    ):
        raise ReleaseFormError(
            "registryctl dev smoke counters or minimized claims are invalid"
        )
    return {
        "schema_version": report["schema_version"],
        "project": report["project"],
        "environment": "local",
        "passed": True,
        "results": [
            {
                key: item[key]
                for key in (
                    "scenario_id",
                    "status",
                    "token_counter_delta",
                    "source_counter_delta",
                    "minimized_claim_ids",
                    "passed",
                )
            }
            for item in sorted(results, key=lambda item: item["status"])
        ],
    }


def stable_opencrvs_smoke_summary(report: Any) -> dict[str, Any]:
    return stable_smoke_summary(
        report,
        expected_token_delta=1,
        expected_claims=OPENCRVS_MINIMIZED_CLAIM_IDS,
    )


def stable_logs_summary(report: Any) -> dict[str, Any]:
    products = report.get("products") if isinstance(report, dict) else None
    binding = report.get("binding") if isinstance(report, dict) else None
    expected = {
        "relay-public",
        "relay-consultation",
        "notary",
        "synthetic-source",
    }
    if (
        not isinstance(report, dict)
        or set(report) != {"schema_version", "binding", "products"}
        or report.get("schema_version") != "registryctl.dev_logs.v1"
        or not isinstance(binding, dict)
        or set(binding) != {"project", "environment", "project_root_digest"}
        or not isinstance(binding.get("project"), str)
        or not binding["project"]
        or binding.get("environment") != "local"
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(binding.get("project_root_digest"))
        )
        is None
        or not isinstance(products, list)
        or {item.get("workload") for item in products if isinstance(item, dict)}
        != expected
        or any(
            not isinstance(item, dict)
            or set(item) != {"workload", "available"}
            or item.get("available") is not True
            for item in products
        )
    ):
        raise ReleaseFormError(
            "registryctl dev logs did not prove bounded product log availability"
        )
    return {
        "schema_version": "registryctl.dev_logs.v1",
        "products": [
            {"workload": name, "available": True} for name in sorted(expected)
        ]
    }


def stable_runtime_summary(
    project: Path, *, tag: str, verified: dict[str, Any]
) -> tuple[dict[str, Any], Path]:
    environment_root = project / ".registry-stack/dev/local"
    require_private_directory(environment_root)
    runtime_roots = [
        path
        for path in environment_root.iterdir()
        if path.is_dir() and not path.is_symlink()
    ]
    if len(runtime_roots) != 1:
        raise ReleaseFormError("development runtime binding is missing or ambiguous")
    runtime_root = runtime_roots[0]
    plan_path = runtime_root / "runtime-plan.json"
    plan = read_closed_json(plan_path, "development runtime plan")
    workloads = plan.get("workloads") if isinstance(plan, dict) else None
    observed: dict[str, dict[str, Any]] = {}
    if isinstance(workloads, list):
        for workload in workloads:
            if not isinstance(workload, dict) or not isinstance(
                workload.get("id"), str
            ):
                raise ReleaseFormError("development runtime workload is invalid")
            if workload["id"] in observed:
                raise ReleaseFormError("development runtime workload is duplicated")
            observed[workload["id"]] = workload
    if set(observed) != set(STABLE_WORKLOAD_IMAGES):
        raise ReleaseFormError("development runtime workload set is not closed")
    for name, image_key in STABLE_WORKLOAD_IMAGES.items():
        if observed[name].get("image") != verified[image_key]:
            raise ReleaseFormError(
                "development runtime does not use the exact signed image lock"
            )
    listeners = {
        name: workload.get("host_endpoint")
        for name, workload in observed.items()
        if workload.get("host_endpoint") is not None
    }
    if (
        not isinstance(plan, dict)
        or plan.get("release_tag") != tag
        or plan.get("source_mode") != "synthetic"
        or listeners != STABLE_LISTENERS
        or any(
            not isinstance(plan.get(name), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", plan[name]) is None
            for name in (
                "plan_digest",
                "build_manifest_digest",
                "compose_digest",
                "request_digest",
            )
        )
    ):
        raise ReleaseFormError(
            "development runtime identity or loopback boundary is invalid"
        )
    summary = {
        "release_tag": tag,
        "source_mode": "synthetic",
        "plan_sha256": sha256(plan_path),
        "plan_digest": plan["plan_digest"],
        "build_manifest_digest": plan["build_manifest_digest"],
        "compose_digest": plan["compose_digest"],
        "request_digest": plan["request_digest"],
        "listeners": listeners,
        "workloads": {
            name: observed[name]["image"] for name in sorted(observed)
        },
        "permissions": {
            "runtime_root": mode(runtime_root),
            "credentials": mode(runtime_root / "credentials"),
        },
    }
    if os.name == "posix" and summary["permissions"] != {
        "runtime_root": "0700",
        "credentials": "0700",
    }:
        raise ReleaseFormError(
            "development runtime credential directories are not owner-only"
        )
    return summary, runtime_root


def recursive_secret_values(directory: Path) -> list[bytes]:
    values: list[bytes] = []
    if not directory.exists():
        return values
    for path in sorted(directory.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        require_regular(path)
        if path.name in PUBLIC_MATERIAL_FILENAMES:
            continue
        if path.suffix == ".env":
            values.extend(credential_env_values(path))
        else:
            data = path.read_bytes()
            values.extend(value for value in (data, data.strip()) if value)
    return sorted(set(values), key=len, reverse=True)


def validate_dev_credentials(directory: Path) -> None:
    require_private_directory(directory)
    for path in sorted(directory.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        require_regular(path)
        if os.name == "posix" and mode(path) != "0600":
            raise ReleaseFormError(
                f"development credential is not owner-only: {path.name}"
            )


def redact_text_tree(directory: Path, private_paths: Iterable[Path]) -> None:
    replacements = sorted(
        {
            os.fsencode(str(candidate))
            for path in private_paths
            for candidate in (path.absolute(), path.resolve())
        },
        key=len,
        reverse=True,
    )
    for path in sorted(directory.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        require_regular(path, max_bytes=MAX_LOG_BYTES)
        data = path.read_bytes()
        for private_path in replacements:
            data = data.replace(private_path, b"[PRIVATE_PATH]")
        path.write_bytes(data)


def closed_tree_digests(directory: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        require_regular(path, max_bytes=MAX_LOG_BYTES)
        files[path.relative_to(directory).as_posix()] = sha256(path)
    return files


def write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if os.name == "posix":
        path.chmod(0o600)


def protect_evidence_tree(root: Path) -> None:
    metadata = root.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseFormError("release-form evidence root must be a real directory")
    if os.name == "posix":
        root.chmod(0o700)
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ReleaseFormError(
                f"release-form evidence must not contain symlinks: {path.name}"
            )
        if stat.S_ISDIR(metadata.st_mode):
            if os.name == "posix":
                path.chmod(0o700)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ReleaseFormError(
                f"release-form evidence must contain only regular files: {path.name}"
            )
        if os.name == "posix":
            path.chmod(0o600)


def require_private_evidence_tree(root: Path) -> None:
    require_private_directory(root)
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ReleaseFormError(
                f"release-form evidence must not contain symlinks: {path.name}"
            )
        if stat.S_ISDIR(metadata.st_mode):
            if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ReleaseFormError(
                    f"release-form evidence directory is not owner-only: {path.name}"
                )
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ReleaseFormError(
                f"release-form evidence must contain only regular files: {path.name}"
            )
        if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ReleaseFormError(
                f"release-form evidence file is not owner-only: {path.name}"
            )


def governed_deployment_binding(
    bundle: Path,
    destination: Path,
    *,
    expected_project: str,
    ports: tuple[int, int],
) -> tuple[str, str]:
    if (
        re.fullmatch(
            r"first-country-release-form-[0-9a-f]{16}", expected_project
        )
        is None
        or len(ports) != 2
        or ports[0] == ports[1]
        or any(type(port) is not int or port <= 0 or port > 65535 for port in ports)
    ):
        raise ReleaseFormError("proof-specific governed binding is invalid")
    manifest = read_closed_json(
        bundle / "bundle/manifest.json", "signed Relay public manifest"
    )
    identity = manifest.get("acceptance_identity") if isinstance(manifest, dict) else None
    expected_identity_keys = {
        "trust_domain",
        "project",
        "environment",
        "lane",
        "product",
        "stream",
        "instance",
    }
    if (
        not isinstance(identity, dict)
        or set(identity) != expected_identity_keys
        or identity.get("trust_domain") != "governed"
        or identity.get("lane") != "relay-public"
        or identity.get("product") != "registry-relay"
        or identity.get("project") != expected_project
        or identity.get("environment") != "local"
        or identity.get("stream") != expected_project
        or identity.get("instance") != "relay-public"
    ):
        raise ReleaseFormError("signed deployment identity is not the expected closed value")
    identity_bytes = json.dumps(
        {
            "environment": identity["environment"],
            "project": identity["project"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    package_id = f"registry-{hashlib.sha256(identity_bytes).hexdigest()[:24]}"
    volume_prefix = expected_project
    binding = {
        "schema_id": "io.registrystack.deployment_binding",
        "schema_version": "1.0",
        "package_id": package_id,
        "environment": identity["environment"],
        "loopback_address": "127.0.0.1",
        "ports": {"relay_public": ports[0], "notary": ports[1]},
        "secret_files": {
            name: f"operator/secrets/{name}"
            for name in sorted(GOVERNED_OPERATOR_SOURCES)
        },
        "certificate_files": {},
        "durable_volume_prefix": volume_prefix,
        "restart_policy": "unless-stopped",
        "logging_policy": "local-bounded",
    }
    write_private(
        destination,
        (json.dumps(binding, indent=2, sort_keys=True) + "\n").encode(),
    )
    return package_id, volume_prefix


def assert_governed_resources_absent(
    package_id: str,
    volume_prefix: str,
    *,
    cwd: Path,
    env: dict[str, str],
) -> None:
    queries = {
        "container": [
            "docker",
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={package_id}",
        ],
        "network": [
            "docker",
            "network",
            "ls",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={package_id}",
        ],
        "volume": ["docker", "volume", "ls", "--quiet"],
    }
    observed: dict[str, list[str]] = {}
    for resource, command in queries.items():
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            raise ReleaseFormError(
                f"cannot establish the preexisting governed {resource} boundary"
            )
        observed[resource] = [line for line in result.stdout.splitlines() if line]
    prefixed_volumes = [
        name for name in observed["volume"] if name.startswith(f"{volume_prefix}-")
    ]
    if observed["container"] or observed["network"] or prefixed_volumes:
        raise ReleaseFormError(
            "governed deployment package identity has preexisting Docker resources"
        )


def create_lane_signing_keys(root: Path) -> dict[str, tuple[Path, Path]]:
    if shutil.which("openssl") is None:
        raise ReleaseFormError("governed release proof requires openssl")
    root.mkdir(mode=0o700)
    keys: dict[str, tuple[Path, Path]] = {}
    private_prefix = bytes.fromhex("302e020100300506032b657004220420")
    public_prefix = bytes.fromhex("302a300506032b6570032100")
    for lane in GOVERNED_LANES:
        private_der = root / f"{lane}.private.der"
        public_der = root / f"{lane}.public.der"
        with private_der.open("wb") as output:
            generated = subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-outform", "DER"],
                stdout=output,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        if generated.returncode != 0:
            raise ReleaseFormError("failed to create a synthetic lane signing key")
        with public_der.open("wb") as output:
            derived = subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    str(private_der),
                    "-inform",
                    "DER",
                    "-pubout",
                    "-outform",
                    "DER",
                ],
                stdout=output,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        if derived.returncode != 0:
            raise ReleaseFormError("failed to derive a synthetic lane public key")
        private_bytes = private_der.read_bytes()
        public_bytes = public_der.read_bytes()
        if (
            not private_bytes.startswith(private_prefix)
            or len(private_bytes) != len(private_prefix) + 32
            or not public_bytes.startswith(public_prefix)
            or len(public_bytes) != len(public_prefix) + 32
        ):
            raise ReleaseFormError("openssl emitted an unexpected Ed25519 key encoding")
        def encode(value: bytes) -> str:
            return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

        private_jwk = root / f"{lane}.private.jwk"
        public_jwk = root / f"{lane}.public.jwk"
        write_private(
            private_jwk,
            (
                json.dumps(
                    {
                        "crv": "Ed25519",
                        "d": encode(private_bytes[-32:]),
                        "kty": "OKP",
                        "x": encode(public_bytes[-32:]),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode(),
        )
        write_private(
            public_jwk,
            (
                json.dumps(
                    {
                        "crv": "Ed25519",
                        "kty": "OKP",
                        "x": encode(public_bytes[-32:]),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode(),
        )
        private_der.unlink()
        public_der.unlink()
        keys[lane] = (private_jwk, public_jwk)
    return keys


def copy_governed_operator_inputs(package: Path, credential_root: Path) -> int:
    inventory = read_closed_json(
        package / "generated/operator-files.v1.json", "operator-file inventory"
    )
    files = inventory.get("files") if isinstance(inventory, dict) else None
    if not isinstance(files, list) or len(files) != len(GOVERNED_OPERATOR_SOURCES):
        raise ReleaseFormError("operator-file inventory is not the expected closed set")
    copied = 0
    for entry in files:
        if (
            not isinstance(entry, dict)
            or set(entry)
            != {
                "id",
                "path",
                "consumers",
                "format",
                "mode",
                "allowed_owners",
                "required_keys",
            }
            or entry.get("id") not in GOVERNED_OPERATOR_SOURCES
            or not isinstance(entry.get("path"), str)
            or Path(entry["path"]).is_absolute()
            or ".." in Path(entry["path"]).parts
        ):
            raise ReleaseFormError("operator-file inventory entry is invalid")
        sources = [
            credential_root / name
            for name in GOVERNED_OPERATOR_SOURCES[entry["id"]]
        ]
        for source in sources:
            require_regular(source)
        destination = package / entry["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            for directory in (
                package / "operator",
                package / "operator/secrets",
                destination.parent,
            ):
                if directory.exists():
                    directory.chmod(0o700)
        if entry.get("format") == "dotenv":
            merged: dict[bytes, bytes] = {}
            for source in sources:
                for line in source.read_bytes().splitlines():
                    if not line or line.startswith(b"#"):
                        continue
                    if b"=" not in line:
                        raise ReleaseFormError(
                            "development dotenv input is malformed"
                        )
                    name, value = line.split(b"=", 1)
                    if name in merged and merged[name] != value:
                        raise ReleaseFormError(
                            "development dotenv inputs disagree on a shared key"
                        )
                    merged[name] = value
            data = b"".join(
                name + b"=" + value + b"\n"
                for name, value in sorted(merged.items())
            )
        else:
            if len(sources) != 1:
                raise ReleaseFormError(
                    "non-dotenv operator input has ambiguous sources"
                )
            data = sources[0].read_bytes()
        required_keys = entry.get("required_keys")
        if required_keys:
            if entry.get("format") != "dotenv" or not isinstance(required_keys, list):
                raise ReleaseFormError("operator dotenv requirement is invalid")
            values: dict[str, bytes] = {}
            for line in data.splitlines():
                if b"=" not in line:
                    continue
                name, value = line.split(b"=", 1)
                try:
                    decoded = name.decode("ascii")
                except UnicodeDecodeError:
                    continue
                if decoded in required_keys:
                    values[decoded] = value
            if set(values) != set(required_keys) or any(not value for value in values.values()):
                raise ReleaseFormError(
                    "development credentials do not satisfy the governed operator inventory"
                )
            data = b"".join(name.encode() + b"=" + values[name] + b"\n" for name in required_keys)
        write_private(destination, data)
        copied += 1
    return copied


def protect_governed_operator_inputs(package: Path) -> None:
    operator = package / "operator"
    require_private_directory(operator)
    if os.geteuid() == 0:
        os.chown(operator, 0, 0)
        for path in operator.rglob("*"):
            os.chown(path, 0, 0)
        return
    if shutil.which("sudo") is None:
        raise ReleaseFormError(
            "governed operator inputs require root ownership but sudo is unavailable"
        )
    protected = subprocess.run(
        ["sudo", "--non-interactive", "chown", "-R", "0:0", str(operator)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    if protected.returncode != 0:
        raise ReleaseFormError("cannot establish governed operator-file ownership")


def privileged_registryctl(registryctl: Path, *args: str) -> list[str]:
    if os.geteuid() == 0:
        return [str(registryctl), *args]
    return ["sudo", "--non-interactive", str(registryctl), *args]


def move_privileged(source: Path, destination: Path) -> None:
    if os.geteuid() == 0:
        source.replace(destination)
        return
    moved = subprocess.run(
        [
            "sudo",
            "--non-interactive",
            "mv",
            "--",
            str(source),
            str(destination),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    if moved.returncode != 0:
        raise ReleaseFormError("cannot isolate the failed-activation operator input")


def release_governed_ownership(package: Path) -> None:
    if os.geteuid() == 0 or not package.exists():
        return
    released = subprocess.run(
        [
            "sudo",
            "--non-interactive",
            "chown",
            "-R",
            f"{os.getuid()}:{os.getgid()}",
            str(package),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    if released.returncode != 0:
        raise ReleaseFormError("cannot release the temporary governed package")


def stable_generate_summary(report: Any) -> dict[str, str]:
    if (
        not isinstance(report, dict)
        or report.get("schema_version") != "registryctl.deployment_generate.v1"
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            str(report.get("source_approved_baseline_set_sha256")),
        )
        is None
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            str(report.get("externally_recorded_closure_sha256")),
        )
        is None
    ):
        raise ReleaseFormError("deployment generation report is invalid")
    return {
        "schema_version": report["schema_version"],
        "approved_set_sha256": report["source_approved_baseline_set_sha256"],
        "externally_recorded_closure_sha256": report[
            "externally_recorded_closure_sha256"
        ],
    }


def stable_deploy_verify_summary(report: Any) -> dict[str, Any]:
    if (
        not isinstance(report, dict)
        or set(report)
        != {
            "schema_id",
            "schema_version",
            "verification_scope",
            "ownership",
            "package_freshness",
            "verified_guarantees",
            "operator_owned_guarantees",
            "violations",
            "in_place_regeneration_safe",
        }
        or report.get("schema_id")
        != "io.registrystack.deployment_ownership_report"
        or report.get("schema_version") != "1.0"
        or report.get("ownership") != "managed"
        or report.get("package_freshness") != "current"
        or report.get("verification_scope") != "package"
        or report.get("violations") != []
        or report.get("verified_guarantees")
        != [
            "generator-owned closure matches its manifest",
            (
                "ordinary and initialization effective models match "
                "the generated package"
            ),
        ]
        or report.get("operator_owned_guarantees")
        != [
            (
                "operator files satisfy the signed isolation, mode, owner, "
                "and consumer inventory"
            )
        ]
        or report.get("in_place_regeneration_safe") is not True
    ):
        raise ReleaseFormError("deployment package did not pass managed verification")
    return {
        "ownership": "managed",
        "package_freshness": "current",
        "verification_scope": "package",
        "in_place_regeneration_safe": True,
    }


def stable_update_build_summary(report: Any) -> dict[str, Any]:
    expected_lanes = ["relay-consultation", "notary"]
    if (
        not isinstance(report, dict)
        or report.get("schema_version")
        != "registryctl.reviewed_project_build_report.v1"
        or report.get("affected_lanes") != expected_lanes
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            str(report.get("reviewed_build_record_digest")),
        )
        is None
    ):
        raise ReleaseFormError(
            "purpose-only update did not affect exactly consultation Relay and Notary"
        )
    return {
        "schema_version": report["schema_version"],
        "affected_lanes": expected_lanes,
        "reviewed_build_record_digest": report["reviewed_build_record_digest"],
    }


def validate_governed_summary(summary: Any) -> None:
    phase_keys = {
        "schema_version",
        "approved_set_sha256",
        "externally_recorded_closure_sha256",
        "ownership",
        "package_freshness",
        "verification_scope",
        "in_place_regeneration_safe",
    }
    if (
        not isinstance(summary, dict)
        or set(summary)
        != {
            "schema_version",
            "operator_file_count",
            "initial",
            "parent_include",
            "explicit_initialization",
            "ordinary_restart",
            "backup_restore",
            "anchor_rotation",
            "compatible_update",
            "failed_activation_recovery",
            "rollback_rejection",
            "isolated_teardown",
        }
        or summary.get("schema_version")
        != "registry-stack.governed-deployment-proof.v1"
        or type(summary.get("operator_file_count")) is not int
        or summary["operator_file_count"] != len(GOVERNED_OPERATOR_SOURCES)
        or any(
            summary.get(name) != "passed"
            for name in (
                "parent_include",
                "explicit_initialization",
                "ordinary_restart",
                "backup_restore",
                "anchor_rotation",
                "failed_activation_recovery",
                "rollback_rejection",
                "isolated_teardown",
            )
        )
    ):
        raise ReleaseFormError("governed deployment summary is invalid")
    for phase in ("initial", "compatible_update"):
        value = summary.get(phase)
        if (
            not isinstance(value, dict)
            or set(value) != phase_keys
            or value.get("schema_version") != "registryctl.deployment_generate.v1"
            or re.fullmatch(
                r"sha256:[0-9a-f]{64}", str(value.get("approved_set_sha256"))
            )
            is None
            or re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                str(value.get("externally_recorded_closure_sha256")),
            )
            is None
            or {
                key: value.get(key)
                for key in (
                    "ownership",
                    "package_freshness",
                    "verification_scope",
                    "in_place_regeneration_safe",
                )
            }
            != {
                "ownership": "managed",
                "package_freshness": "current",
                "verification_scope": "package",
                "in_place_regeneration_safe": True,
            }
        ):
            raise ReleaseFormError("governed deployment phase summary is invalid")
    if (
        summary["initial"]["externally_recorded_closure_sha256"]
        == summary["compatible_update"]["externally_recorded_closure_sha256"]
    ):
        raise ReleaseFormError("governed deployment update did not change closure")


def run_expected_failure(
    name: str,
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    logs: Path,
    expected_output_fragment: str | None = None,
    observed_exit_class: str = "nonzero",
) -> dict[str, Any]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
        check=False,
    )
    if result.returncode == 0:
        raise ReleaseFormError(f"{name} unexpectedly succeeded")
    if (
        expected_output_fragment is not None
        and expected_output_fragment not in result.stdout
    ):
        raise ReleaseFormError(f"{name} failed without the expected classification")
    write_json_log(
        logs,
        name,
        {
            "outcome": "rejected",
            "observed_exit_class": observed_exit_class,
        },
    )
    return {
        "name": name,
        "status": "passed",
        "exit_code": 0,
        "log_sha256": sha256(logs / f"{name}.log"),
    }


def run_failed_activation(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    logs: Path,
) -> dict[str, Any]:
    return run_expected_failure(
        "failed_activation",
        command,
        cwd=cwd,
        env=env,
        logs=logs,
        expected_output_fragment=FAILED_ACTIVATION_OUTPUT_CLASSIFICATION,
        observed_exit_class=FAILED_ACTIVATION_EXIT_CLASS,
    )


def require_value_free_rollback_report(output: str, lane: str) -> None:
    expected_components = {
        "relay-consultation": ("registry-relay", None),
        "notary": ("registry-notary", "unknown"),
    }
    if lane not in expected_components:
        raise ReleaseFormError("rollback lane is outside the affected closed set")
    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicate_json_keys)
    report: Any = None
    for match in re.finditer(r"(?m)^[ \t]*\{", output):
        try:
            candidate, _end = decoder.raw_decode(output, match.end() - 1)
        except (json.JSONDecodeError, ValueError):
            continue
        if (
            isinstance(candidate, dict)
            and candidate.get("schema")
            == "registry.platform.config_apply_report.v1"
        ):
            report = candidate
            break
    component, redacted_stream = expected_components[lane]
    expected_keys = {
        "schema",
        "attempt_id",
        "component",
        "stream_id",
        "source",
        "bundle_id",
        "bundle_sequence",
        "previous_config_hash",
        "config_hash",
        "result",
        "restart_required",
        "change_classes",
        "affected_components",
        "warnings",
        "errors",
    }
    if (
        not isinstance(report, dict)
        or set(report) != expected_keys
        or re.fullmatch(
            r"[0-9A-HJKMNP-TV-Z]{26}", str(report.get("attempt_id"))
        )
        is None
        or report.get("component") != component
        or report.get("stream_id") != redacted_stream
        or report.get("source") != "signed_bundle_file"
        or any(
            report.get(name) is not None
            for name in (
                "bundle_id",
                "bundle_sequence",
                "previous_config_hash",
                "config_hash",
            )
        )
        or report.get("result") != "rejected_rollback"
        or report.get("restart_required") is not False
        or any(
            report.get(name) != []
            for name in (
                "change_classes",
                "affected_components",
                "warnings",
            )
        )
        or report.get("errors")
        != [
            {
                "code": "rejected_rollback",
                "message": ROLLBACK_SAFE_MESSAGE,
            }
        ]
    ):
        raise ReleaseFormError(
            f"{lane} did not report a typed, value-free rejected_rollback"
        )


def run_expected_rollbacks(
    name: str,
    lane_commands: list[tuple[str, list[str]]],
    *,
    cwd: Path,
    env: dict[str, str],
    logs: Path,
) -> dict[str, Any]:
    if tuple(lane for lane, _command in lane_commands) != ROLLBACK_AFFECTED_LANES:
        raise ReleaseFormError("rollback proof does not cover every affected lane")
    observed: list[str] = []
    for lane, command in lane_commands:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
            check=False,
        )
        if result.returncode == 0:
            raise ReleaseFormError(
                f"{lane} unexpectedly accepted a rollback"
            )
        require_value_free_rollback_report(result.stdout, lane)
        observed.append(lane)
    write_json_log(
        logs,
        name,
        {
            "outcome": "rejected",
            "classification": "rejected_rollback",
            "lanes": observed,
        },
    )
    return {
        "name": name,
        "status": "passed",
        "exit_code": 0,
        "log_sha256": sha256(logs / f"{name}.log"),
    }


def compose_base(package: Path) -> list[str]:
    return [
        "docker",
        "compose",
        "--env-file",
        str(package / "generated/compose.empty.env"),
        "-f",
        str(package / "generated/compose.yaml"),
    ]


def compose_initialization_base(package: Path) -> list[str]:
    return [
        *compose_base(package),
        "-f",
        str(package / "generated/compose.initialize.yaml"),
    ]


def _compose_secret_stage_commands(
    package: Path,
    contract: dict[str, dict[str, tuple[str, ...]]],
    stagers: Iterable[str],
    *,
    initialization: bool,
) -> list[list[str]]:
    selected = tuple(stagers)
    if len(selected) != len(set(selected)) or any(
        stager not in contract for stager in selected
    ):
        raise ReleaseFormError("secret stager selection is not a closed subset")
    compose = (
        compose_initialization_base(package)
        if initialization
        else compose_base(package)
    )
    return [
        [
            *compose,
            "run",
            "--rm",
            "--no-deps",
            stager,
        ]
        for stager in selected
    ]


def compose_serving_secret_stage_commands(
    package: Path,
    stagers: Iterable[str] = SERVING_SECRET_STAGER_CONTRACT,
) -> list[list[str]]:
    return _compose_secret_stage_commands(
        package,
        SERVING_SECRET_STAGER_CONTRACT,
        stagers,
        initialization=False,
    )


def compose_action_secret_stage_commands(
    package: Path,
    stagers: Iterable[str] = ACTION_SECRET_STAGER_CONTRACT,
) -> list[list[str]]:
    return _compose_secret_stage_commands(
        package,
        ACTION_SECRET_STAGER_CONTRACT,
        stagers,
        initialization=True,
    )


def compose_staged_consumer_commands(
    package: Path,
    consumers: Iterable[list[str]],
    stagers: Iterable[str] = SERVING_SECRET_STAGER_CONTRACT,
) -> list[list[str]]:
    return [
        *compose_serving_secret_stage_commands(package, stagers),
        *list(consumers),
    ]


def expected_secret_staging_summary() -> dict[str, Any]:
    def stagers(
        contract: dict[str, dict[str, tuple[str, ...]]],
    ) -> list[dict[str, Any]]:
        return [
            {
                "service": service,
                "outputs": list(projection["outputs"]),
                "sources": list(projection["sources"]),
            }
            for service, projection in contract.items()
        ]

    def consumers(contract: dict[str, tuple[str, str]]) -> list[dict[str, str]]:
        return [
            {
                "service": service,
                "stager": stager,
                "output": output,
            }
            for service, (stager, output) in contract.items()
        ]

    return {
        "outcome": "passed",
        "serving_stagers": stagers(SERVING_SECRET_STAGER_CONTRACT),
        "action_stagers": stagers(ACTION_SECRET_STAGER_CONTRACT),
        "serving_consumers": consumers(SERVING_SECRET_STAGE_CONSUMERS),
        "action_consumers": consumers(ACTION_SECRET_STAGE_CONSUMERS),
        "networkless_readers": [
            f"registry-{lane}-{action}-state"
            for lane in GOVERNED_LANES
            for action in ("preview", "verify")
        ],
    }


def stable_secret_staging_summary(
    ordinary: Any,
    initialization: Any,
    *,
    volume_prefix: str,
) -> dict[str, Any]:
    if not volume_prefix:
        raise ReleaseFormError("secret staging volume prefix is unavailable")
    services_by_model: dict[str, dict[str, Any]] = {}
    for model_name, model in (
        ("ordinary", ordinary),
        ("initialization", initialization),
    ):
        services = model.get("services") if isinstance(model, dict) else None
        if not isinstance(services, dict):
            raise ReleaseFormError(
                f"{model_name} Compose model has no closed service inventory"
            )
        services_by_model[model_name] = services

    ordinary_services = services_by_model["ordinary"]
    initialization_services = services_by_model["initialization"]
    serving_stagers = set(SERVING_SECRET_STAGER_CONTRACT)
    action_stagers = set(ACTION_SECRET_STAGER_CONTRACT)
    ordinary_stagers = {
        name for name in ordinary_services if name.endswith("-stage-secrets")
    }
    initialization_stagers = {
        name for name in initialization_services if name.endswith("-stage-secrets")
    }
    if ordinary_stagers != serving_stagers:
        raise ReleaseFormError(
            "ordinary Compose model has the wrong serving stager roster"
        )
    if initialization_stagers != serving_stagers | action_stagers:
        raise ReleaseFormError(
            "initialization Compose model has the wrong serving/action stager roster"
        )
    if any(
        ordinary_services[name] != initialization_services[name]
        for name in serving_stagers
    ):
        raise ReleaseFormError("initialization changed a serving secret stager")

    def validate_stager(
        service_name: str,
        service: Any,
        contract: dict[str, tuple[str, ...]],
    ) -> None:
        mounts = service.get("volumes") if isinstance(service, dict) else None
        secrets = service.get("secrets") if isinstance(service, dict) else None
        if (
            service.get("network_mode") != "none"
            or service.get("user") != "0:0"
            or service.get("read_only") is not True
            or service.get("cap_add") != ["CHOWN", "DAC_READ_SEARCH"]
            or service.get("cap_drop") != ["ALL"]
            or service.get("security_opt") != ["no-new-privileges:true"]
            or service.get("tmpfs") != ["/tmp"]
            or service.get("restart") != "no"
            or not isinstance(mounts, list)
            or not isinstance(secrets, list)
        ):
            raise ReleaseFormError(
                f"{service_name} lost its isolated security projection"
            )
        for forbidden in (
            "depends_on",
            "env_file",
            "healthcheck",
            "networks",
            "ports",
        ):
            if forbidden in service:
                raise ReleaseFormError(
                    f"{service_name} gained forbidden {forbidden} authority"
                )
        observed_outputs: dict[str, str] = {}
        for mount in mounts:
            if (
                not isinstance(mount, dict)
                or mount.get("type") != "volume"
                or not isinstance(mount.get("source"), str)
                or not isinstance(mount.get("target"), str)
                or mount.get("read_only") not in (None, False)
                or mount["target"] in observed_outputs
            ):
                raise ReleaseFormError(
                    f"{service_name} has an invalid writable output authority"
                )
            observed_outputs[mount["target"]] = mount["source"]
        expected_outputs = {
            f"/registryctl-stage/output/{stage_id}": (
                f"{volume_prefix}-operator-files-{stage_id}"
            )
            for stage_id in contract["outputs"]
        }
        if observed_outputs != expected_outputs:
            raise ReleaseFormError(
                f"{service_name} has cross-lane or incomplete output authority"
            )
        observed_sources = {
            (
                secret.get("source"),
                secret.get("target"),
            )
            for secret in secrets
            if isinstance(secret, dict)
        }
        expected_sources = {
            (f"registry-{file_id}", f"/run/secrets/{file_id}")
            for file_id in contract["sources"]
        }
        if (
            len(observed_sources) != len(secrets)
            or observed_sources != expected_sources
        ):
            raise ReleaseFormError(
                f"{service_name} has cross-lane or incomplete source authority"
            )

    for service_name, contract in SERVING_SECRET_STAGER_CONTRACT.items():
        validate_stager(service_name, ordinary_services[service_name], contract)
    for service_name, contract in ACTION_SECRET_STAGER_CONTRACT.items():
        validate_stager(service_name, initialization_services[service_name], contract)

    expected_consumers_by_model = {
        "ordinary": SERVING_SECRET_STAGE_CONSUMERS,
        "initialization": {
            **SERVING_SECRET_STAGE_CONSUMERS,
            **ACTION_SECRET_STAGE_CONSUMERS,
        },
    }
    for model_name, expected_consumers in expected_consumers_by_model.items():
        services = services_by_model[model_name]
        missing_consumers = set(expected_consumers).difference(services)
        if missing_consumers:
            raise ReleaseFormError(
                f"{model_name} Compose model is missing staged-secret consumers"
            )
        for service_name, service in services.items():
            if service_name in serving_stagers | action_stagers or not isinstance(
                service, dict
            ):
                continue
            mounts = service.get("volumes", [])
            if not isinstance(mounts, list):
                raise ReleaseFormError(
                    f"{service_name} has an invalid secret consumer mount inventory"
                )
            secret_mounts = [
                mount
                for mount in mounts
                if isinstance(mount, dict) and mount.get("target") == "/run/secrets"
            ]
            dependencies = service.get("depends_on")
            stager_dependencies = {
                name: dependency
                for name, dependency in (
                    dependencies.items() if isinstance(dependencies, dict) else ()
                )
                if name.endswith("-stage-secrets")
            }
            if service_name not in expected_consumers:
                if secret_mounts or stager_dependencies:
                    raise ReleaseFormError(
                        f"{service_name} has unowned staged-secret authority"
                    )
                continue
            stager, stage_id = expected_consumers[service_name]
            if secret_mounts != [
                {
                    "type": "volume",
                    "source": f"{volume_prefix}-operator-files-{stage_id}",
                    "target": "/run/secrets",
                    "read_only": True,
                    "volume": {},
                }
            ]:
                raise ReleaseFormError(
                    f"{service_name} has the wrong staged-secret consumer authority"
                )
            if stager_dependencies != {
                stager: {
                    "condition": "service_completed_successfully",
                    "required": True,
                }
            }:
                raise ReleaseFormError(
                    f"{service_name} does not wait for its exact isolated stager"
                )

    for lane in GOVERNED_LANES:
        for action in ("preview", "verify"):
            service_name = f"registry-{lane}-{action}-state"
            service = initialization_services.get(service_name)
            if not isinstance(service, dict):
                raise ReleaseFormError(
                    f"initialization Compose model is missing {service_name}"
                )
            dependencies = service.get("depends_on", {})
            mounts = service.get("volumes", [])
            if (
                service.get("network_mode") != "none"
                or "networks" in service
                or "env_file" in service
                or not isinstance(dependencies, dict)
                or any(name.endswith("-stage-secrets") for name in dependencies)
                or not isinstance(mounts, list)
                or any(
                    isinstance(mount, dict)
                    and mount.get("target") == "/run/secrets"
                    for mount in mounts
                )
            ):
                raise ReleaseFormError(
                    f"{service_name} is not a dedicated networkless state reader"
                )

        accept_name = f"registry-{lane}-accept-state"
        accept = initialization_services.get(accept_name)
        accept_environments = (
            accept.get("env_file") if isinstance(accept, dict) else None
        )
        if (
            not isinstance(accept, dict)
            or accept.get("network_mode") != "none"
            or "networks" in accept
            or not isinstance(accept_environments, list)
            or len(accept_environments) != 1
            or Path(str(accept_environments[0])).name != f"{lane}-environment"
        ):
            raise ReleaseFormError(
                f"{accept_name} is not bound to its exact lane environment"
            )
    return expected_secret_staging_summary()


def inspect_secret_staging_contract(
    package: Path,
    *,
    volume_prefix: str,
    env: dict[str, str],
    logs: Path,
) -> dict[str, Any]:
    documents: list[Any] = []
    for command in (
        [
            *compose_base(package),
            "config",
            "--no-interpolate",
            "--no-env-resolution",
            "--format",
            "json",
        ],
        [
            *compose_initialization_base(package),
            "config",
            "--no-interpolate",
            "--no-env-resolution",
            "--format",
            "json",
        ],
    ):
        result = subprocess.run(
            command,
            cwd=package.parent,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
        try:
            document = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ReleaseFormError(
                "cannot inspect isolated secret staging models"
            ) from error
        if result.returncode != 0:
            raise ReleaseFormError("isolated secret staging model is unavailable")
        documents.append(document)
    stable_secret_staging_summary(
        documents[0],
        documents[1],
        volume_prefix=volume_prefix,
    )
    write_json_log(logs, "inspect_secret_stagers", {"outcome": "passed"})
    return {
        "name": "inspect_secret_stagers",
        "status": "passed",
        "exit_code": 0,
        "log_sha256": sha256(logs / "inspect_secret_stagers.log"),
    }


def compose_verify_state_commands(package: Path) -> list[list[str]]:
    return [
        [
            *compose_initialization_base(package),
            "run",
            "--rm",
            "--no-deps",
            "registry-relay-public-verify-state",
        ],
        [
            *compose_initialization_base(package),
            "run",
            "--rm",
            "--no-deps",
            "registry-relay-consultation-verify-state",
        ],
        [
            *compose_initialization_base(package),
            "run",
            "--rm",
            "--no-deps",
            "registry-notary-verify-state",
        ],
    ]


def compose_preview_state_commands(package: Path) -> list[list[str]]:
    return [
        [
            *compose_initialization_base(package),
            "run",
            "--rm",
            "--no-deps",
            f"registry-{lane}-preview-state",
        ]
        for lane in GOVERNED_LANES
    ]


def compose_accept_state_commands(
    package: Path, lanes: Iterable[str]
) -> list[list[str]]:
    selected = tuple(lanes)
    if len(selected) != len(set(selected)) or any(
        lane not in GOVERNED_LANES for lane in selected
    ):
        raise ReleaseFormError("state acceptance selection is not a closed lane subset")
    return [
        [
            *compose_initialization_base(package),
            "run",
            "--rm",
            "--no-deps",
            f"registry-{lane}-accept-state",
        ]
        for lane in selected
    ]


def run_compose_group(
    name: str,
    commands: Iterable[list[str]],
    *,
    cwd: Path,
    env: dict[str, str],
    logs: Path,
) -> dict[str, Any]:
    for command in commands:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=300,
            check=False,
        )
        if result.returncode != 0:
            raise ReleaseFormError(f"{name} failed")
    write_json_log(logs, name, {"outcome": "passed"})
    return {
        "name": name,
        "status": "passed",
        "exit_code": 0,
        "log_sha256": sha256(logs / f"{name}.log"),
    }


def backup_and_restore_governed_volumes(
    package: Path,
    *,
    postgresql_image: str,
    volume_prefix: str,
    backup_root: Path,
    env: dict[str, str],
    logs: Path,
) -> dict[str, Any]:
    config = subprocess.run(
        [*compose_base(package), "config", "--format", "json"],
        cwd=package.parent,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    try:
        document = json.loads(config.stdout)
    except json.JSONDecodeError as error:
        raise ReleaseFormError("cannot inspect the governed Compose project") from error
    project_name = document.get("name") if isinstance(document, dict) else None
    if config.returncode != 0 or not isinstance(project_name, str) or not project_name:
        raise ReleaseFormError("governed Compose project identity is unavailable")
    services = document.get("services") if isinstance(document, dict) else None
    declared_volumes = document.get("volumes") if isinstance(document, dict) else None
    if not isinstance(services, dict) or not isinstance(declared_volumes, dict):
        raise ReleaseFormError("governed Compose volume model is invalid")
    selected_sources: set[str] = set()
    for service_name, suffixes_by_target in GOVERNED_DURABLE_VOLUME_SUFFIXES.items():
        service = services.get(service_name)
        mounts = service.get("volumes") if isinstance(service, dict) else None
        if not isinstance(mounts, list):
            raise ReleaseFormError("governed durable volume selection is incomplete")
        observed = [
            (mount.get("source"), mount.get("target"))
            for mount in mounts
            if isinstance(mount, dict)
            and mount.get("type") == "volume"
            and mount.get("target") in suffixes_by_target
        ]
        expected = {
            (f"{volume_prefix}-{suffix}", target)
            for target, suffix in suffixes_by_target.items()
        }
        if len(observed) != len(expected) or set(observed) != expected:
            raise ReleaseFormError(
                "governed durable volume identity is incomplete or unexpected"
            )
        selected_sources.update(source for source, _target in expected)
    if len(selected_sources) != 7:
        raise ReleaseFormError("governed backup must select exactly seven durable volumes")
    observed_stagers = {name for name in services if name.endswith("-stage-secrets")}
    if (
        observed_stagers != set(SERVING_SECRET_STAGER_CONTRACT)
        or "registry-runtime-stage-secrets" in services
    ):
        raise ReleaseFormError("governed staged-secret roster is invalid")
    staged_sources: set[str] = set()
    for stager_name, contract in SERVING_SECRET_STAGER_CONTRACT.items():
        stager = services[stager_name]
        stager_mounts = stager.get("volumes") if isinstance(stager, dict) else None
        if not isinstance(stager_mounts, list):
            raise ReleaseFormError(
                "governed staged-secret volume inventory is unavailable"
            )
        observed_outputs = {
            (mount.get("source"), mount.get("target"))
            for mount in stager_mounts
            if isinstance(mount, dict)
            and mount.get("type") == "volume"
            and isinstance(mount.get("source"), str)
            and isinstance(mount.get("target"), str)
        }
        expected_outputs = {
            (
                f"{volume_prefix}-operator-files-{stage_id}",
                f"/registryctl-stage/output/{stage_id}",
            )
            for stage_id in contract["outputs"]
        }
        if observed_outputs != expected_outputs:
            raise ReleaseFormError(
                f"{stager_name} has the wrong backup-excluded output authority"
            )
        staged_sources.update(source for source, _target in observed_outputs)
    unexpected = set(declared_volumes).difference(selected_sources)
    if selected_sources.intersection(staged_sources) or unexpected != staged_sources:
        raise ReleaseFormError("governed backup found an unexpected durable volume")
    expected_volume_names = {
        source: f"{project_name}_{source}"
        for source in selected_sources | staged_sources
    }
    if any(
        not isinstance(declared_volumes[source], dict)
        or declared_volumes[source].get("name") != expected_volume_names[source]
        for source in expected_volume_names
    ):
        raise ReleaseFormError("governed durable volume identity is unexpected")
    volumes = sorted(
        (source, expected_volume_names[source])
        for source in selected_sources
    )
    listed = subprocess.run(
        [
            "docker",
            "volume",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={project_name}",
            "--format",
            "{{.Name}}",
        ],
        cwd=package.parent,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    observed_volumes = set(filter(None, listed.stdout.splitlines()))
    expected_project_volumes = set(expected_volume_names.values())
    if listed.returncode != 0 or observed_volumes != expected_project_volumes:
        raise ReleaseFormError(
            "governed Docker project volume identity is unavailable or unexpected"
        )
    backup_root.mkdir(mode=0o700)
    for index, (_source, volume) in enumerate(volumes):
        archive = backup_root / f"{index:02}.tar"
        backed_up = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "0:0",
                "--volume",
                f"{volume}:/source:ro",
                "--volume",
                f"{backup_root}:/backup",
                postgresql_image,
                "tar",
                "-C",
                "/source",
                "-cf",
                f"/backup/{archive.name}",
                ".",
            ],
            cwd=package.parent,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
            check=False,
        )
        if backed_up.returncode != 0:
            raise ReleaseFormError("governed consistency-group backup failed")
    for source, volume in volumes:
        removed = subprocess.run(
            ["docker", "volume", "rm", volume],
            cwd=package.parent,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
        created = subprocess.run(
            [
                "docker",
                "volume",
                "create",
                "--label",
                f"com.docker.compose.project={project_name}",
                "--label",
                f"com.docker.compose.volume={source}",
                volume,
            ],
            cwd=package.parent,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
        if removed.returncode != 0 or created.returncode != 0:
            raise ReleaseFormError("governed consistency-group volume restore failed")
    for index, (_source, volume) in enumerate(volumes):
        restored = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "0:0",
                "--volume",
                f"{volume}:/target",
                "--volume",
                f"{backup_root}:/backup:ro",
                postgresql_image,
                "tar",
                "-C",
                "/target",
                "-xf",
                f"/backup/{index:02}.tar",
            ],
            cwd=package.parent,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
            check=False,
        )
        if restored.returncode != 0:
            raise ReleaseFormError("governed consistency-group restore failed")
    write_json_log(
        logs,
        "backup_restore",
        {"outcome": "passed", "consistency_group_volumes": 7},
    )
    return {
        "name": "backup_restore",
        "status": "passed",
        "exit_code": 0,
        "log_sha256": sha256(logs / "backup_restore.log"),
    }


def isolated_governed_teardown(
    package: Path,
    *,
    env: dict[str, str],
    logs: Path,
) -> dict[str, Any]:
    config = subprocess.run(
        [*compose_base(package), "config", "--format", "json"],
        cwd=package.parent,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    try:
        document = json.loads(config.stdout)
    except json.JSONDecodeError as error:
        raise ReleaseFormError("cannot resolve the isolated Compose project") from error
    project_name = document.get("name") if isinstance(document, dict) else None
    if config.returncode != 0 or not isinstance(project_name, str) or not project_name:
        raise ReleaseFormError("isolated Compose project identity is unavailable")
    stopped = subprocess.run(
        [*compose_base(package), "down", "--volumes", "--remove-orphans"],
        cwd=package.parent,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=300,
        check=False,
    )
    if stopped.returncode != 0:
        raise ReleaseFormError("isolated governed teardown failed")
    remaining_containers = subprocess.run(
        [
            "docker",
            "ps",
            "--all",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={project_name}",
        ],
        cwd=package.parent,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    remaining_volumes = subprocess.run(
        [
            "docker",
            "volume",
            "ls",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={project_name}",
        ],
        cwd=package.parent,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    if (
        remaining_containers.returncode != 0
        or remaining_volumes.returncode != 0
        or remaining_containers.stdout.strip()
        or remaining_volumes.stdout.strip()
    ):
        raise ReleaseFormError("isolated governed teardown left project resources")
    write_json_log(logs, "isolated_teardown", {"outcome": "passed"})
    return {
        "name": "isolated_teardown",
        "status": "passed",
        "exit_code": 0,
        "log_sha256": sha256(logs / "isolated_teardown.log"),
    }


def run_stable_release_form(args: argparse.Namespace) -> Path:
    beginner_runtime_asset(args.tag)
    asset_dir = args.asset_dir.resolve()
    evidence_dir = args.evidence_dir.resolve()
    if evidence_dir.exists():
        raise ReleaseFormError("evidence directory must not already exist")
    evidence_dir.mkdir(parents=True, mode=0o700)
    logs = evidence_dir / "logs"
    logs.mkdir(mode=0o700)
    verified = verify_asset_set(asset_dir, args.tag)
    if shutil.which("registry-relay") or shutil.which("registry-notary"):
        raise ReleaseFormError("ambient Registry product binaries must not be on PATH")

    commands: list[dict[str, Any]] = []
    secrets: list[bytes] = []
    reader_summary: dict[str, Any]
    public_source_live_summary: dict[str, Any]
    oauth_runtime_summary: dict[str, Any]
    opencrvs_smoke_summary: dict[str, Any]
    doctor_summary: dict[str, Any]
    status_summary: dict[str, Any]
    smoke_summary: dict[str, Any]
    product_logs_summary: dict[str, Any]
    runtime_summary: dict[str, Any]
    governed_summary: dict[str, Any]
    with tempfile.TemporaryDirectory(
        prefix="registry-first-country-release-form-"
    ) as temporary:
        root = Path(temporary)
        run_nonce = os.urandom(8).hex()
        proof_project_id = f"first-country-release-form-{run_nonce}"
        install_dir = root / "install"
        project = root / "reader-http-project"
        oauth_project = root / "reader-opencrvs-project"
        reader_evidence = evidence_dir / "reader-journeys"
        public_source_evidence = evidence_dir / "public-source-live"
        install_dir.mkdir()
        released_docs_root = extract_released_docs_archive(
            asset_dir / verified["docs_archive_name"],
            root / "released-docs",
            tag=args.tag,
        )
        environment = sealed_release_environment(dict(os.environ))
        environment.update(
            {
                "CI": "1",
                "REGISTRYCTL_NO_UPDATE_CHECK": "1",
                "REGISTRYCTL_ASSET_DIR": str(asset_dir),
                "REGISTRYCTL_INSTALL_DIR": str(install_dir),
                "REGISTRYCTL_VERSION": args.tag,
            }
        )
        registryctl = install_dir / "registryctl"
        installer = asset_dir / verified["installer_name"]
        runtime_root: Path | None = None
        oauth_runtime_root: Path | None = None
        package: Path | None = None
        candidate_package: Path | None = None
        try:
            commands.append(
                run_command(
                    "install",
                    ["bash", str(installer)],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            require_regular(registryctl)
            require_regular(install_dir / "registry-release-lock.v1.json")
            if sha256(registryctl) != verified["assets"][verified["binary_name"]]:
                raise ReleaseFormError(
                    "installed registryctl does not match the verified release asset"
                )
            if (
                sha256(install_dir / "registry-release-lock.v1.json")
                != verified["assets"][verified["release_lock_name"]]
            ):
                raise ReleaseFormError(
                    "installed Registry release lock does not match the verified asset"
                )
            commands.append(
                run_command(
                    "version",
                    [str(registryctl), "--version"],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            version = args.tag.removeprefix("v")
            if (logs / "version.log").read_text(encoding="utf-8").strip() != (
                f"registryctl {version}"
            ):
                raise ReleaseFormError(
                    "installed registryctl version does not match the release tag"
                )
            tutorial_environment = environment.copy()
            tutorial_environment.update(
                {
                    "REGISTRYCTL_BIN": str(registryctl),
                    "REGISTRYCTL_TUTORIAL_EVIDENCE_DIR": str(reader_evidence),
                    "REGISTRYCTL_TUTORIAL_PROJECT_DIR": str(project),
                    "REGISTRYCTL_TUTORIAL_OAUTH_PROJECT_DIR": str(oauth_project),
                    "REGISTRYCTL_RELEASED_DOCS_ROOT": str(released_docs_root),
                }
            )
            commands.append(
                run_command(
                    "reader_journeys",
                    [
                        "bash",
                        str(
                            Path(__file__).resolve().parents[2]
                            / "docs/site/scripts/check-registryctl-tutorials.sh"
                        ),
                    ],
                    cwd=root,
                    env=tutorial_environment,
                    logs=logs,
                )
            )
            reader_summary = stable_reader_summary(
                reader_evidence / "manifest.json",
                version=version,
                retained_project=project,
                retained_oauth_project=oauth_project,
            )
            redact_text_tree(
                reader_evidence, (root, install_dir, project, oauth_project)
            )
            protect_evidence_tree(reader_evidence)
            reader_summary["evidence_sha256"] = closed_tree_digests(reader_evidence)
            bind_release_form_project_identity(
                project / "registry-stack.yaml",
                proof_project_id,
            )
            for name, image in (
                ("pull_relay", verified["relay_image"]),
                ("pull_notary", verified["notary_image"]),
                ("pull_postgresql", verified["postgresql_image"]),
            ):
                commands.append(
                    run_command(
                        name,
                        ["docker", "image", "pull", image],
                        cwd=root,
                        env=environment,
                        logs=logs,
                    )
                )
            public_source_environment = environment.copy()
            public_source_environment.update(
                {
                    "REGISTRYCTL_BIN": str(registryctl),
                    "REGISTRYCTL_PUBLIC_SOURCE_LIVE": "1",
                    "REGISTRYCTL_PUBLIC_SOURCE_EVIDENCE_DIR": str(
                        public_source_evidence
                    ),
                    "REGISTRYCTL_RELEASED_DOCS_ROOT": str(released_docs_root),
                }
            )
            commands.append(
                run_command(
                    "public_source_live",
                    [
                        "sh",
                        str(
                            Path(__file__).resolve().parents[2]
                            / (
                                "docs/site/scripts/"
                                "check-registryctl-public-source-live.sh"
                            )
                        ),
                    ],
                    cwd=root,
                    env=public_source_environment,
                    logs=logs,
                )
            )
            if (
                "PASS public-source live gate; evidence retained at "
                not in (logs / "public_source_live.log").read_text(
                    encoding="utf-8"
                )
            ):
                raise ReleaseFormError("public-source live gate did not execute")
            redact_text_tree(
                public_source_evidence, (root, install_dir, public_source_evidence)
            )
            protect_evidence_tree(public_source_evidence)
            public_source_live_summary = stable_public_source_live_summary(
                public_source_evidence
            )
            write_json_log(
                logs, "public_source_live", public_source_live_summary
            )
            commands.append(
                run_command(
                    "oauth_dev_up",
                    [
                        str(registryctl),
                        "-C",
                        str(oauth_project),
                        "dev",
                        "--detach",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            oauth_runtime_summary, oauth_runtime_root = stable_runtime_summary(
                oauth_project, tag=args.tag, verified=verified
            )
            write_json_log(logs, "oauth_dev_up", oauth_runtime_summary)
            validate_dev_credentials(oauth_runtime_root / "credentials")
            secrets.extend(
                recursive_secret_values(oauth_runtime_root / "credentials")
            )
            commands.append(
                run_command(
                    "oauth_dev_smoke",
                    [
                        str(registryctl),
                        "-C",
                        str(oauth_project),
                        "dev",
                        "smoke",
                        "--format",
                        "json",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            opencrvs_smoke_summary = stable_opencrvs_smoke_summary(
                read_closed_json(
                    logs / "oauth_dev_smoke.log", "OAuth development smoke report"
                )
            )
            write_json_log(logs, "oauth_dev_smoke", opencrvs_smoke_summary)
            commands.append(
                run_command(
                    "oauth_dev_down",
                    [
                        str(registryctl),
                        "-C",
                        str(oauth_project),
                        "dev",
                        "down",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            if oauth_runtime_root.exists():
                raise ReleaseFormError(
                    "OAuth development teardown left disposable runtime state"
                )
            write_json_log(
                logs,
                "oauth_dev_down",
                {"outcome": "passed", "runtime_state": "absent"},
            )
            commands.append(
                run_command(
                    "doctor",
                    [
                        str(registryctl),
                        "-C",
                        str(project),
                        "doctor",
                        "--profile",
                        "local",
                        "--format",
                        "json",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            doctor_summary = stable_doctor_summary(
                read_closed_json(logs / "doctor.log", "doctor report")
            )
            write_json_log(logs, "doctor", doctor_summary)
            commands.append(
                run_command(
                    "dev_up",
                    [
                        str(registryctl),
                        "-C",
                        str(project),
                        "dev",
                        "--detach",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_command(
                    "dev_status",
                    [
                        str(registryctl),
                        "-C",
                        str(project),
                        "dev",
                        "status",
                        "--format",
                        "json",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            status_summary = stable_status_summary(
                read_closed_json(logs / "dev_status.log", "development status report")
            )
            write_json_log(logs, "dev_status", status_summary)
            commands.append(
                run_command(
                    "dev_smoke",
                    [
                        str(registryctl),
                        "-C",
                        str(project),
                        "dev",
                        "smoke",
                        "--format",
                        "json",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            smoke_summary = stable_smoke_summary(
                read_closed_json(logs / "dev_smoke.log", "development smoke report")
            )
            write_json_log(logs, "dev_smoke", smoke_summary)
            commands.append(
                run_command(
                    "dev_logs",
                    [
                        str(registryctl),
                        "-C",
                        str(project),
                        "dev",
                        "logs",
                        "--format",
                        "json",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            product_logs_summary = stable_logs_summary(
                read_closed_json(logs / "dev_logs.log", "development logs report")
            )
            write_json_log(logs, "dev_logs", product_logs_summary)
            runtime_summary, runtime_root = stable_runtime_summary(
                project, tag=args.tag, verified=verified
            )
            write_json_log(logs, "inspect", runtime_summary)
            commands.append(
                {
                    "name": "inspect",
                    "status": "passed",
                    "exit_code": 0,
                    "log_sha256": sha256(logs / "inspect.log"),
                }
            )
            validate_dev_credentials(runtime_root / "credentials")
            secrets.extend(recursive_secret_values(runtime_root / "credentials"))
            governed_private = root / "governed-private"
            governed_private.mkdir(mode=0o700)
            operator_inputs = governed_private / "operator-inputs"
            shutil.copytree(runtime_root / "credentials", operator_inputs)
            secrets.extend(recursive_secret_values(operator_inputs))
            handoff = root / "operator-handoff"
            handoff.mkdir()
            package = root / f"registry-stack-release-form-{os.getpid()}-{run_nonce}"
            candidate_package = root / (
                f"registry-stack-release-form-{os.getpid()}-{run_nonce}-candidate"
            )
            rollback_package = (
                root / f"registry-stack-release-form-{os.getpid()}-{run_nonce}-rollback"
            )
            lane_keys = create_lane_signing_keys(governed_private / "lane-keys")
            signing_inputs = project / ".registry-stack/build/local/signing-inputs"
            anchors: dict[str, Path] = {}
            bundles: dict[str, Path] = {}
            for lane in GOVERNED_LANES:
                private_key, public_key = lane_keys[lane]
                anchor = handoff / f"{lane}-anchor.json"
                bundle = handoff / f"{lane}-bundle"
                anchors[lane] = anchor
                bundles[lane] = bundle
                commands.append(
                    run_command(
                        f"anchor_{lane.replace('-', '_')}",
                        [
                            str(registryctl),
                            "trust",
                            "anchor",
                            "create",
                            "--lane",
                            lane,
                            "--input",
                            str(signing_inputs / lane),
                            "--public-key",
                            str(public_key),
                            "--threshold",
                            "1",
                            "--output-file",
                            str(anchor),
                            "--format",
                            "json",
                        ],
                        cwd=root,
                        env=environment,
                        logs=logs,
                    )
                )
                commands.append(
                    run_command(
                        f"sign_{lane.replace('-', '_')}",
                        [
                            str(registryctl),
                            "trust",
                            "bundle",
                            "sign",
                            "--lane",
                            lane,
                            "--input",
                            str(signing_inputs / lane),
                            "--anchor",
                            str(anchor),
                            "--key",
                            f"file:{private_key}",
                            "--output-dir",
                            str(bundle),
                            "--format",
                            "json",
                        ],
                        cwd=root,
                        env=environment,
                        logs=logs,
                    )
                )
                commands.append(
                    run_command(
                        f"verify_{lane.replace('-', '_')}",
                        [
                            str(registryctl),
                            "trust",
                            "bundle",
                            "verify",
                            "--bundle-dir",
                            str(bundle),
                            "--anchor",
                            str(anchor),
                            "--format",
                            "json",
                        ],
                        cwd=root,
                        env=environment,
                        logs=logs,
                    )
                )
            approved_set = handoff / "approved-set.v1.json"
            commands.append(
                run_command(
                    "approved_set",
                    [
                        str(registryctl),
                        "-C",
                        str(project),
                        "trust",
                        "approved-set",
                        "assemble",
                        "--environment",
                        "local",
                        "--relay-public",
                        str(bundles["relay-public"]),
                        "--relay-consultation",
                        str(bundles["relay-consultation"]),
                        "--notary",
                        str(bundles["notary"]),
                        "--output-file",
                        str(approved_set),
                        "--format",
                        "json",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            binding_file = governed_private / "binding.json"
            governed_ports = available_governed_loopback_ports()
            package_id, volume_prefix = governed_deployment_binding(
                bundles["relay-public"],
                binding_file,
                expected_project=proof_project_id,
                ports=governed_ports,
            )
            assert_governed_resources_absent(
                package_id,
                volume_prefix,
                cwd=root,
                env=environment,
            )
            commands.append(
                run_command(
                    "deploy_generate",
                    [
                        str(registryctl),
                        "deploy",
                        "generate",
                        "--approved-set",
                        str(approved_set),
                        "--output-dir",
                        str(package),
                        "--binding",
                        str(binding_file),
                        "--format",
                        "json",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            initial_generation = stable_generate_summary(
                read_closed_json(logs / "deploy_generate.log", "deployment generation")
            )
            write_json_log(logs, "deploy_generate", initial_generation)
            operator_file_count = copy_governed_operator_inputs(
                package, operator_inputs
            )
            commands.append(
                run_command(
                    "dev_down",
                    [
                        str(registryctl),
                        "-C",
                        str(project),
                        "dev",
                        "down",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            if runtime_root.exists():
                raise ReleaseFormError(
                    "HTTP development teardown left disposable runtime state"
                )
            write_json_log(
                logs,
                "dev_down",
                {"outcome": "passed", "runtime_state": "absent"},
            )
            shutil.copytree(package, rollback_package)
            secrets.extend(recursive_secret_values(governed_private))
            secrets.extend(recursive_secret_values(package / "operator"))
            protect_governed_operator_inputs(package)
            commands.append(
                run_command(
                    "deploy_verify",
                    privileged_registryctl(
                        registryctl,
                        "deploy",
                        "verify",
                        "--package",
                        str(package),
                        "--approved-set",
                        str(approved_set),
                        "--expected-closure-sha256",
                        initial_generation["externally_recorded_closure_sha256"],
                        "--check-operator-files",
                        "--format",
                        "json",
                    ),
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            initial_verification = stable_deploy_verify_summary(
                read_closed_json(logs / "deploy_verify.log", "deployment verification")
            )
            write_json_log(logs, "deploy_verify", initial_verification)
            parent_include = root / "compose.yaml"
            parent_include.write_text(
                f"include:\n  - ./{package.name}/generated/compose.yaml\n",
                encoding="utf-8",
            )
            commands.append(
                run_command(
                    "parent_include_config",
                    [
                        "docker",
                        "compose",
                        "--env-file",
                        str(package / "generated/compose.empty.env"),
                        "-f",
                        str(parent_include),
                        "config",
                        "--no-interpolate",
                        "--no-env-resolution",
                        "--quiet",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_command(
                    "initialize_config",
                    [
                        *compose_initialization_base(package),
                        "config",
                        "--no-interpolate",
                        "--no-env-resolution",
                        "--quiet",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                inspect_secret_staging_contract(
                    package,
                    volume_prefix=volume_prefix,
                    env=environment,
                    logs=logs,
                )
            )
            stage_commands = compose_action_secret_stage_commands(
                package,
                (
                    "registry-relay-consultation-actions-stage-secrets",
                    "registry-notary-actions-stage-secrets",
                    "registry-postgresql-actions-stage-secrets",
                ),
            )
            initialization_steps = [
                (
                    "initialize_stage_relay_consultation_action_secrets",
                    stage_commands[0],
                ),
                (
                    "initialize_stage_notary_action_secrets",
                    stage_commands[1],
                ),
                (
                    "initialize_stage_postgresql_action_secrets",
                    stage_commands[2],
                ),
                (
                    "initialize_postgresql",
                    [
                        *compose_initialization_base(package),
                        "run",
                        "--rm",
                        "registry-postgres-bootstrap",
                    ],
                ),
                (
                    "initialize_relay_public_prepare",
                    [
                        *compose_initialization_base(package),
                        "run",
                        "--rm",
                        "registry-relay-public-prepare-state",
                    ],
                ),
                (
                    "initialize_relay_consultation_prepare",
                    [
                        *compose_initialization_base(package),
                        "run",
                        "--rm",
                        "registry-relay-consultation-prepare-state",
                    ],
                ),
                (
                    "initialize_notary_prepare",
                    [
                        *compose_initialization_base(package),
                        "run",
                        "--rm",
                        "registry-notary-prepare-state",
                    ],
                ),
                (
                    "initialize_relay_public",
                    [
                        *compose_initialization_base(package),
                        "run",
                        "--rm",
                        "registry-relay-public-initialize",
                    ],
                ),
                (
                    "initialize_relay_consultation",
                    [
                        *compose_initialization_base(package),
                        "run",
                        "--rm",
                        "registry-relay-consultation-initialize",
                    ],
                ),
                (
                    "initialize_notary",
                    [
                        *compose_initialization_base(package),
                        "run",
                        "--rm",
                        "registry-notary-initialize",
                    ],
                ),
            ]
            for name, command in initialization_steps:
                commands.append(
                    run_command(
                        name,
                        command,
                        cwd=root,
                        env=environment,
                        logs=logs,
                    )
                )
            commands.append(
                run_expected_failure(
                    "reject_postgresql_data_reinitialization",
                    [
                        *compose_initialization_base(package),
                        "run",
                        "--rm",
                        "--no-deps",
                        "registry-postgres",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                    expected_output_fragment=(
                        "PostgreSQL data directory is not empty; "
                        "refusing explicit initialization"
                    ),
                    observed_exit_class="postgresql_data_not_empty",
                )
            )
            commands.append(
                run_expected_failure(
                    "reject_postgresql_bootstrap_reinitialization",
                    [
                        *compose_initialization_base(package),
                        "run",
                        "--rm",
                        "--no-deps",
                        "registry-postgres-bootstrap",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                    expected_output_fragment="registry_stack_bootstrap_marker",
                    observed_exit_class="postgresql_bootstrap_marker_exists",
                )
            )
            commands.append(
                run_compose_group(
                    "governed_start",
                    compose_staged_consumer_commands(
                        package,
                        [
                        *compose_verify_state_commands(package),
                        [
                            *compose_base(package),
                            "up",
                            "--detach",
                            "--wait",
                            "--wait-timeout",
                            "120",
                        ],
                        [*compose_base(package), "ps"],
                    ],
                    ),
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_compose_group(
                    "governed_restart",
                    compose_staged_consumer_commands(
                        package,
                        [
                        [*compose_base(package), "restart"],
                        [
                            *compose_base(package),
                            "up",
                            "--detach",
                            "--wait",
                            "--wait-timeout",
                            "120",
                        ],
                        *compose_verify_state_commands(package),
                    ],
                    ),
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_command(
                    "governed_stop_for_backup",
                    [*compose_base(package), "down"],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                backup_and_restore_governed_volumes(
                    package,
                    postgresql_image=verified["postgresql_image"],
                    volume_prefix=volume_prefix,
                    backup_root=governed_private / "backup",
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_compose_group(
                    "restored_start",
                    compose_staged_consumer_commands(
                        package,
                        [
                        *compose_verify_state_commands(package),
                        [
                            *compose_base(package),
                            "up",
                            "--detach",
                            "--wait",
                            "--wait-timeout",
                            "120",
                        ],
                    ],
                    ),
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            project_file = project / "registry-stack.yaml"
            project_text = project_file.read_text(encoding="utf-8")
            original_purpose = "purpose: public-service-person-verification"
            updated_purpose = "purpose: public-service-person-verification-updated"
            if project_text.count(original_purpose) != 1:
                raise ReleaseFormError(
                    "maintained HTTP starter does not expose the expected update seam"
                )
            project_file.write_text(
                project_text.replace(original_purpose, updated_purpose),
                encoding="utf-8",
            )
            commands.append(
                run_command(
                    "update_build",
                    [
                        str(registryctl),
                        "-C",
                        str(project),
                        "build",
                        "--environment",
                        "local",
                        "--against",
                        str(approved_set),
                        "--format",
                        "json",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            update_build = stable_update_build_summary(
                read_closed_json(logs / "update_build.log", "updated reviewed build")
            )
            write_json_log(logs, "update_build", update_build)
            rotation_keys = create_lane_signing_keys(
                governed_private / "rotation-keys"
            )
            secrets.extend(
                recursive_secret_values(governed_private / "rotation-keys")
            )
            rotated_trust = handoff / "relay-consultation-rotated-trust"
            commands.append(
                run_command(
                    "rotate_relay_consultation",
                    [
                        str(registryctl),
                        "trust",
                        "anchor",
                        "rotate",
                        "--current-anchor",
                        str(anchors["relay-consultation"]),
                        "--next-public-key",
                        str(rotation_keys["relay-consultation"][1]),
                        "--next-threshold",
                        "1",
                        "--key",
                        f"file:{lane_keys['relay-consultation'][0]}",
                        "--output-dir",
                        str(rotated_trust),
                        "--format",
                        "json",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            updated_bundles: dict[str, Path] = {}
            for lane in update_build["affected_lanes"]:
                private_key, _ = (
                    rotation_keys[lane]
                    if lane == "relay-consultation"
                    else lane_keys[lane]
                )
                updated_anchor = (
                    rotated_trust / "anchor.json"
                    if lane == "relay-consultation"
                    else anchors[lane]
                )
                updated_bundle = handoff / f"{lane}-bundle-v2"
                updated_bundles[lane] = updated_bundle
                commands.append(
                    run_command(
                        f"update_sign_{lane.replace('-', '_')}",
                        [
                            str(registryctl),
                            "trust",
                            "bundle",
                            "sign",
                            "--lane",
                            lane,
                            "--input",
                            str(signing_inputs / lane),
                            "--anchor",
                            str(updated_anchor),
                            "--against",
                            str(approved_set),
                            "--key",
                            f"file:{private_key}",
                            "--output-dir",
                            str(updated_bundle),
                            "--format",
                            "json",
                        ],
                        cwd=root,
                        env=environment,
                        logs=logs,
                    )
                )
                if lane == "relay-consultation":
                    commands.append(
                        run_command(
                            "update_verify_relay_consultation",
                            [
                                str(registryctl),
                                "trust",
                                "bundle",
                                "verify",
                                "--bundle-dir",
                                str(updated_bundle),
                                "--anchor",
                                str(updated_anchor),
                                "--format",
                                "json",
                            ],
                            cwd=root,
                            env=environment,
                            logs=logs,
                        )
                    )
            updated_set = handoff / "approved-set-v2.json"
            commands.append(
                run_command(
                    "update_approved_set",
                    [
                        str(registryctl),
                        "-C",
                        str(project),
                        "trust",
                        "approved-set",
                        "assemble",
                        "--environment",
                        "local",
                        "--from",
                        str(approved_set),
                        "--relay-consultation",
                        str(updated_bundles["relay-consultation"]),
                        "--notary",
                        str(updated_bundles["notary"]),
                        "--output-file",
                        str(updated_set),
                        "--format",
                        "json",
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_command(
                    "update_generate",
                    privileged_registryctl(
                        registryctl,
                        "deploy",
                        "generate",
                        "--approved-set",
                        str(updated_set),
                        "--output-dir",
                        str(candidate_package),
                        "--binding",
                        str(binding_file),
                        "--format",
                        "json",
                    ),
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            updated_generation = stable_generate_summary(
                read_closed_json(logs / "update_generate.log", "updated generation")
            )
            if (
                updated_generation["externally_recorded_closure_sha256"]
                == initial_generation["externally_recorded_closure_sha256"]
            ):
                raise ReleaseFormError("compatible update did not change the governed closure")
            write_json_log(logs, "update_generate", updated_generation)
            candidate_operator_file_count = copy_governed_operator_inputs(
                candidate_package, operator_inputs
            )
            if candidate_operator_file_count != operator_file_count:
                raise ReleaseFormError(
                    "candidate operator-file inventory differs from the current closure"
                )
            secrets.extend(
                recursive_secret_values(candidate_package / "operator")
            )
            protect_governed_operator_inputs(candidate_package)
            commands.append(
                run_command(
                    "update_verify",
                    privileged_registryctl(
                        registryctl,
                        "deploy",
                        "verify",
                        "--package",
                        str(candidate_package),
                        "--approved-set",
                        str(updated_set),
                        "--expected-closure-sha256",
                        updated_generation["externally_recorded_closure_sha256"],
                        "--check-operator-files",
                        "--format",
                        "json",
                    ),
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            updated_verification = stable_deploy_verify_summary(
                read_closed_json(logs / "update_verify.log", "updated verification")
            )
            write_json_log(logs, "update_verify", updated_verification)
            inventory = read_closed_json(
                candidate_package / "generated/operator-files.v1.json",
                "updated operator-file inventory",
            )
            notary_key_entry = next(
                (
                    entry
                    for entry in inventory["files"]
                    if entry.get("id") == "notary-tls-private-key"
                ),
                None,
            )
            if not isinstance(notary_key_entry, dict):
                raise ReleaseFormError("updated package is missing the Notary TLS key binding")
            notary_key = candidate_package / notary_key_entry["path"]
            held_notary_key = governed_private / "held-notary-tls-private-key"
            move_privileged(notary_key, held_notary_key)
            commands.append(
                run_failed_activation(
                    compose_serving_secret_stage_commands(
                        candidate_package,
                        ("registry-notary-stage-secrets",),
                    )[0],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            move_privileged(held_notary_key, notary_key)
            commands.append(
                run_command(
                    "failed_activation_recovery",
                    privileged_registryctl(
                        registryctl,
                        "deploy",
                        "verify",
                        "--package",
                        str(candidate_package),
                        "--approved-set",
                        str(updated_set),
                        "--expected-closure-sha256",
                        updated_generation["externally_recorded_closure_sha256"],
                        "--check-operator-files",
                        "--format",
                        "json",
                    ),
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            recovered_verification = stable_deploy_verify_summary(
                read_closed_json(
                    logs / "failed_activation_recovery.log",
                    "failed-activation recovery verification",
                )
            )
            write_json_log(
                logs, "failed_activation_recovery", recovered_verification
            )
            for name, command in zip(
                (
                    "update_preview_relay_public",
                    "update_preview_relay_consultation",
                    "update_preview_notary",
                ),
                compose_preview_state_commands(candidate_package),
                strict=True,
            ):
                commands.append(
                    run_command(
                        name,
                        command,
                        cwd=root,
                        env=environment,
                        logs=logs,
                    )
                )
            commands.append(
                run_command(
                    "update_stop_current",
                    [*compose_base(package), "down"],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            for name, command in zip(
                (
                    "update_accept_relay_consultation",
                    "update_accept_notary",
                ),
                compose_accept_state_commands(
                    candidate_package, ROLLBACK_AFFECTED_LANES
                ),
                strict=True,
            ):
                commands.append(
                    run_command(
                        name,
                        command,
                        cwd=root,
                        env=environment,
                        logs=logs,
                    )
                )
            for name, command in zip(
                (
                    "update_verify_relay_public_state",
                    "update_verify_relay_consultation_state",
                    "update_verify_notary_state",
                ),
                compose_verify_state_commands(candidate_package),
                strict=True,
            ):
                commands.append(
                    run_command(
                        name,
                        command,
                        cwd=root,
                        env=environment,
                        logs=logs,
                    )
                )
            for name, command in zip(
                (
                    "update_stage_relay_public_serving_secrets",
                    "update_stage_relay_consultation_serving_secrets",
                    "update_stage_notary_serving_secrets",
                    "update_stage_postgresql_serving_secrets",
                ),
                compose_serving_secret_stage_commands(candidate_package),
                strict=True,
            ):
                commands.append(
                    run_command(
                        name,
                        command,
                        cwd=root,
                        env=environment,
                        logs=logs,
                    )
                )
            commands.append(
                run_compose_group(
                    "updated_start",
                    [
                        [
                            *compose_base(candidate_package),
                            "up",
                            "--detach",
                            "--wait",
                            "--wait-timeout",
                            "120",
                        ],
                        [*compose_base(candidate_package), "ps"],
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_command(
                    "updated_stop",
                    [*compose_base(candidate_package), "down"],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_expected_rollbacks(
                    "rollback_rejected",
                    [
                        (
                            "relay-consultation",
                            compose_verify_state_commands(rollback_package)[1],
                        ),
                        (
                            "notary",
                            compose_verify_state_commands(rollback_package)[2],
                        ),
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_compose_group(
                    "final_start",
                    compose_staged_consumer_commands(
                        candidate_package,
                        [
                            *compose_verify_state_commands(candidate_package),
                            [
                                *compose_base(candidate_package),
                                "up",
                                "--detach",
                                "--wait",
                                "--wait-timeout",
                                "120",
                            ],
                        ],
                    ),
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                isolated_governed_teardown(
                    candidate_package,
                    env=environment,
                    logs=logs,
                )
            )
            governed_summary = {
                "schema_version": "registry-stack.governed-deployment-proof.v1",
                "operator_file_count": operator_file_count,
                "initial": {
                    **initial_generation,
                    **initial_verification,
                },
                "parent_include": "passed",
                "explicit_initialization": "passed",
                "ordinary_restart": "passed",
                "backup_restore": "passed",
                "anchor_rotation": "passed",
                "compatible_update": {
                    **updated_generation,
                    **updated_verification,
                },
                "failed_activation_recovery": "passed",
                "rollback_rejection": "passed",
                "isolated_teardown": "passed",
            }
        finally:
            # Capture partially generated development credentials before teardown
            # can remove them, so failure logs retain the same redaction boundary
            # as a completed proof.
            for dev_project in (project, oauth_project):
                dev_root = dev_project / ".registry-stack/dev/local"
                if dev_root.is_dir() and not dev_root.is_symlink():
                    for credential_root in dev_root.glob("*/credentials"):
                        secrets.extend(available_secret_values(credential_root))
            for governed_package in (candidate_package, package):
                if governed_package is not None and governed_package.exists():
                    subprocess.run(
                        [
                            *compose_base(governed_package),
                            "down",
                            "--volumes",
                            "--remove-orphans",
                        ],
                        cwd=root,
                        env=environment,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=300,
                        check=False,
                    )
                    release_governed_ownership(governed_package)
            if oauth_project.exists() and registryctl.exists():
                subprocess.run(
                    [
                        str(registryctl),
                        "-C",
                        str(oauth_project),
                        "dev",
                        "down",
                    ],
                    cwd=root,
                    env=environment,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=180,
                    check=False,
                )
            if project.exists() and registryctl.exists():
                subprocess.run(
                    [
                        str(registryctl),
                        "-C",
                        str(project),
                        "dev",
                        "down",
                    ],
                    cwd=root,
                    env=environment,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=180,
                    check=False,
                )
            for dev_project in (project, oauth_project):
                dev_root = dev_project / ".registry-stack/dev/local"
                if dev_root.is_dir() and not dev_root.is_symlink():
                    for credential_root in dev_root.glob("*/credentials"):
                        secrets.extend(available_secret_values(credential_root))
            for key_root in (
                root / "governed-private/lane-keys",
                root / "governed-private/rotation-keys",
            ):
                if key_root.exists():
                    secrets.extend(recursive_secret_values(key_root))
            for governed_package in (package, candidate_package):
                if (
                    governed_package is not None
                    and (governed_package / "operator").exists()
                ):
                    secrets.extend(
                        recursive_secret_values(governed_package / "operator")
                    )
            secrets = sorted(set(secrets), key=len, reverse=True)
            redact_logs(
                logs,
                secrets,
                private_paths=(
                    root,
                    install_dir,
                    project,
                    oauth_project,
                    asset_dir,
                    evidence_dir,
                ),
            )
            protect_evidence_tree(evidence_dir)
        if tuple(command["name"] for command in commands) != STABLE_COMMAND_ORDER:
            raise ReleaseFormError(
                "stable release-form command sequence did not complete in exact order"
            )
        if runtime_root is not None and runtime_root.exists():
            raise ReleaseFormError("registryctl dev down left disposable runtime state")
        scanned_files = assert_no_secret_leak(project, secrets)
        scanned_files += assert_no_secret_leak(oauth_project, secrets)
        if package is None or candidate_package is None:
            raise ReleaseFormError("governed deployment closures were not created")
        governed_scanned_files = assert_no_governed_secret_leak(package, secrets)
        governed_scanned_files += assert_no_governed_secret_leak(
            candidate_package, secrets
        )
        redact_logs(
            logs,
            secrets,
            private_paths=(
                root,
                install_dir,
                project,
                oauth_project,
                asset_dir,
                evidence_dir,
            ),
        )
        for command in commands:
            command["log_sha256"] = sha256(logs / f"{command['name']}.log")
        report = {
            "schema_version": STABLE_SCHEMA,
            "status": "passed",
            "release_tag": args.tag,
            "manifest_source_ref": verified["lock"]["manifest_source_ref"],
            "tag_target": verified["lock"]["tag_target"],
            "platform_asset": verified["binary_name"],
            "asset_sha256": verified["assets"],
            "release_image_lock_sha256": verified["assets"][verified["lock_name"]],
            "release_lock_sha256": verified["assets"][verified["release_lock_name"]],
            "relay_image": verified["relay_image"],
            "notary_image": verified["notary_image"],
            "postgresql_image": verified["postgresql_image"],
            "commands": commands,
            "reader_journeys": reader_summary,
            "public_source_live": public_source_live_summary,
            "oauth_runtime": oauth_runtime_summary,
            "opencrvs_smoke": opencrvs_smoke_summary,
            "doctor": doctor_summary,
            "runtime": runtime_summary,
            "dev_status": status_summary,
            "smoke": smoke_summary,
            "product_logs": product_logs_summary,
            "governed_deployment": governed_summary,
            "redaction": {
                "status": "passed",
                "generated_files_scanned": scanned_files + governed_scanned_files,
            },
        }
        output = evidence_dir / "first-country-release-form.json"
        write_private(
            output,
            (json.dumps(report, indent=2, sort_keys=True) + "\n").encode(),
        )
        protect_evidence_tree(evidence_dir)
        return output



def run_release_form(args: argparse.Namespace) -> Path:
    match = TAG.fullmatch(args.tag)
    if match is None:
        raise ReleaseFormError("release tag must be canonical vMAJOR.MINOR.PATCH")
    if int(match.group(1)) < 1:
        raise ReleaseFormError("release-form proof supports Registry Stack v1 and later")
    return run_stable_release_form(args)


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON object key")
        result[name] = value
    return result



def verify_stable_evidence(
    report_path: Path, report: dict[str, Any], commands: list[dict[str, Any]]
) -> None:
    require_private_evidence_tree(report_path.parent)
    logs = report_path.parent / "logs"
    entries = list(logs.iterdir())
    expected_logs = {f"{name}.log" for name in STABLE_COMMAND_ORDER}
    if {entry.name for entry in entries} != expected_logs:
        raise ReleaseFormError("stable release-form evidence log set is not closed")
    for command in commands:
        log_path = logs / f"{command['name']}.log"
        require_regular(log_path, max_bytes=MAX_LOG_BYTES)
        if sha256(log_path) != command["log_sha256"]:
            raise ReleaseFormError(
                f"stable release-form evidence log digest does not match: {log_path.name}"
            )
    normalized = {
        "public_source_live": report["public_source_live"],
        "oauth_dev_up": report["oauth_runtime"],
        "oauth_dev_smoke": report["opencrvs_smoke"],
        "doctor": report["doctor"],
        "dev_status": report["dev_status"],
        "dev_smoke": report["smoke"],
        "dev_logs": report["product_logs"],
        "inspect": report["runtime"],
    }
    for name, expected in normalized.items():
        if read_closed_json(logs / f"{name}.log", f"{name} evidence log") != expected:
            raise ReleaseFormError(
                f"{name} evidence log does not bind the normalized report"
            )
    if (
        read_closed_json(
            logs / "inspect_secret_stagers.log",
            "isolated secret staging inspection log",
        )
        != {"outcome": "passed"}
    ):
        raise ReleaseFormError(
            "isolated secret staging evidence does not prove a successful closed-authority inspection"
        )
    if read_closed_json(logs / "dev_down.log", "development teardown log") != {
        "outcome": "passed",
        "runtime_state": "absent",
    }:
        raise ReleaseFormError(
            "development teardown evidence does not prove absent runtime state"
        )
    if read_closed_json(
        logs / "oauth_dev_down.log", "OAuth development teardown log"
    ) != {
        "outcome": "passed",
        "runtime_state": "absent",
    }:
        raise ReleaseFormError(
            "OAuth development teardown evidence does not prove absent runtime state"
        )

    reader_dir = report_path.parent / "reader-journeys"
    require_private_directory(reader_dir)
    observed_reader = closed_tree_digests(reader_dir)
    if (
        set(observed_reader) != STABLE_READER_EVIDENCE_FILES
        or observed_reader != report["reader_journeys"]["evidence_sha256"]
    ):
        raise ReleaseFormError("reader-journey evidence set is not closed")
    manifest = read_closed_json(
        reader_dir / "manifest.json", "reader-journey evidence manifest"
    )
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version")
        != "registryctl.tutorial_reader_journeys.v1"
        or manifest.get("status") != "passed"
        or manifest.get("mode") != "sealed"
        or manifest.get("registryctl_version") != report["release_tag"].removeprefix("v")
        or manifest.get("retained_project") != "[PRIVATE_PATH]"
        or manifest.get("retained_oauth_project") != "[PRIVATE_PATH]"
    ):
        raise ReleaseFormError(
            "reader-journey evidence does not bind the sealed release binary"
        )
    public_source_dir = report_path.parent / "public-source-live"
    require_private_directory(public_source_dir)
    if (
        stable_public_source_live_summary(public_source_dir)
        != report["public_source_live"]
    ):
        raise ReleaseFormError(
            "public-source live evidence does not bind the normalized report"
        )


def verify_stable_report(path: Path, asset_dir: Path, tag: str) -> None:
    report = read_closed_json(path, "stable release-form report")
    expected_keys = {
        "schema_version",
        "status",
        "release_tag",
        "manifest_source_ref",
        "tag_target",
        "platform_asset",
        "asset_sha256",
        "release_image_lock_sha256",
        "release_lock_sha256",
        "relay_image",
        "notary_image",
        "postgresql_image",
        "commands",
        "reader_journeys",
        "public_source_live",
        "oauth_runtime",
        "opencrvs_smoke",
        "doctor",
        "runtime",
        "dev_status",
        "smoke",
        "product_logs",
        "governed_deployment",
        "redaction",
    }
    if not isinstance(report, dict) or set(report) != expected_keys:
        raise ReleaseFormError("stable release-form report fields are not closed")
    verified = verify_asset_set(asset_dir.resolve(), tag)
    commands = report.get("commands")
    command_shape_valid = isinstance(commands, list) and all(
        isinstance(command, dict)
        and set(command) == {"name", "status", "exit_code", "log_sha256"}
        and command.get("status") == "passed"
        and command.get("exit_code") == 0
        and isinstance(command.get("log_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", command["log_sha256"]) is not None
        for command in commands
    )
    reader = report.get("reader_journeys")
    public_source_live = report.get("public_source_live")
    oauth_runtime = report.get("oauth_runtime")
    opencrvs_smoke = report.get("opencrvs_smoke")
    doctor = report.get("doctor")
    runtime = report.get("runtime")
    status = report.get("dev_status")
    smoke = report.get("smoke")
    product_logs = report.get("product_logs")
    governed_deployment = report.get("governed_deployment")
    redaction = report.get("redaction")
    expected_doctor_checks = sorted(
        {
            "authored_environment",
            "installed_release_lock",
            "docker_cli",
            "docker_daemon",
            "docker_compose",
            "locked_images",
        }
    )
    expected_status_workloads = [
        {"workload": name, "state": "running"}
        for name in sorted(STABLE_WORKLOAD_IMAGES)
    ]
    expected_product_logs = [
        {"workload": name, "available": True}
        for name in sorted(
            {
                "relay-public",
                "relay-consultation",
                "notary",
                "synthetic-source",
            }
        )
    ]
    expected_runtime_workloads = {
        name: verified[image_key]
        for name, image_key in sorted(STABLE_WORKLOAD_IMAGES.items())
    }
    if (
        report["schema_version"] != STABLE_SCHEMA
        or report["status"] != "passed"
        or report["release_tag"] != tag
        or report["manifest_source_ref"]
        != verified["lock"].get("manifest_source_ref")
        or report["tag_target"] != verified["lock"].get("tag_target")
        or re.fullmatch(r"[0-9a-f]{40}", str(report["manifest_source_ref"]))
        is None
        or re.fullmatch(r"[0-9a-f]{40}", str(report["tag_target"])) is None
        or report["platform_asset"] != verified["binary_name"]
        or report["asset_sha256"] != verified["assets"]
        or report["release_image_lock_sha256"]
        != verified["assets"][verified["lock_name"]]
        or report["release_lock_sha256"]
        != verified["assets"][verified["release_lock_name"]]
        or report["relay_image"] != verified["relay_image"]
        or report["notary_image"] != verified["notary_image"]
        or report["postgresql_image"] != verified["postgresql_image"]
        or not command_shape_valid
        or tuple(command["name"] for command in commands) != STABLE_COMMAND_ORDER
        or not isinstance(reader, dict)
        or set(reader)
        != {
            "schema_version",
            "status",
            "mode",
            "registryctl_version",
            "projects",
            "evidence_sha256",
        }
        or reader.get("schema_version")
        != "registryctl.tutorial_reader_journeys.v1"
        or reader.get("status") != "passed"
        or reader.get("mode") != "sealed"
        or reader.get("registryctl_version") != tag.removeprefix("v")
        or reader.get("projects") != ["http", "opencrvs-events-api"]
        or not isinstance(reader.get("evidence_sha256"), dict)
        or not all(
            isinstance(name, str)
            and isinstance(digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
            for name, digest in reader.get("evidence_sha256", {}).items()
        )
        or not isinstance(public_source_live, dict)
        or stable_public_source_live_summary(
            path.parent / "public-source-live"
        )
        != public_source_live
        or not isinstance(oauth_runtime, dict)
        or set(oauth_runtime)
        != {
            "release_tag",
            "source_mode",
            "plan_sha256",
            "plan_digest",
            "build_manifest_digest",
            "compose_digest",
            "request_digest",
            "listeners",
            "workloads",
            "permissions",
        }
        or oauth_runtime.get("release_tag") != tag
        or oauth_runtime.get("source_mode") != "synthetic"
        or oauth_runtime.get("listeners") != STABLE_LISTENERS
        or oauth_runtime.get("workloads") != expected_runtime_workloads
        or oauth_runtime.get("permissions")
        != {"runtime_root": "0700", "credentials": "0700"}
        or any(
            not isinstance(oauth_runtime.get(name), str)
            or re.fullmatch(
                r"(?:sha256:)?[0-9a-f]{64}",
                oauth_runtime[name],
            )
            is None
            for name in (
                "plan_sha256",
                "plan_digest",
                "build_manifest_digest",
                "compose_digest",
                "request_digest",
            )
        )
        or stable_opencrvs_smoke_summary(opencrvs_smoke) != opencrvs_smoke
        or doctor
        != {
            "schema_version": "registryctl.doctor.v1",
            "status": "ready",
            "environment": "local",
            "profile": "local",
            "checks": expected_doctor_checks,
        }
        or not isinstance(runtime, dict)
        or set(runtime)
        != {
            "release_tag",
            "source_mode",
            "plan_sha256",
            "plan_digest",
            "build_manifest_digest",
            "compose_digest",
            "request_digest",
            "listeners",
            "workloads",
            "permissions",
        }
        or runtime.get("release_tag") != tag
        or runtime.get("source_mode") != "synthetic"
        or runtime.get("listeners") != STABLE_LISTENERS
        or runtime.get("workloads") != expected_runtime_workloads
        or runtime.get("permissions")
        != {"runtime_root": "0700", "credentials": "0700"}
        or any(
            not isinstance(runtime.get(name), str)
            or re.fullmatch(
                r"(?:sha256:)?[0-9a-f]{64}",
                runtime[name],
            )
            is None
            for name in (
                "plan_sha256",
                "plan_digest",
                "build_manifest_digest",
                "compose_digest",
                "request_digest",
            )
        )
        or status
        != {
            "schema_version": "registryctl.dev_status.v1",
            "source_mode": "synthetic",
            "workloads": expected_status_workloads,
        }
        or stable_smoke_summary(smoke) != smoke
        or product_logs
        != {
            "schema_version": "registryctl.dev_logs.v1",
            "products": expected_product_logs,
        }
        or governed_deployment is None
        or not isinstance(redaction, dict)
        or set(redaction) != {"status", "generated_files_scanned"}
        or redaction.get("status") != "passed"
        or not isinstance(redaction.get("generated_files_scanned"), int)
        or redaction["generated_files_scanned"] <= 0
    ):
        raise ReleaseFormError(
            "stable release-form report does not prove the maintained journey"
        )
    validate_governed_summary(governed_deployment)
    verify_stable_evidence(path, report, commands)


def verify_report(path: Path, asset_dir: Path, tag: str) -> None:
    match = TAG.fullmatch(tag)
    if match is None:
        raise ReleaseFormError("release tag must be canonical vMAJOR.MINOR.PATCH")
    if int(match.group(1)) < 1:
        raise ReleaseFormError("release-form proof supports Registry Stack v1 and later")
    report = read_closed_json(path, "release-form report")
    schema = report.get("schema_version") if isinstance(report, dict) else None
    if schema != STABLE_SCHEMA:
        raise ReleaseFormError(
            "stable release requires the maintained release-form evidence schema"
        )
    verify_stable_report(path, asset_dir, tag)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subcommands = result.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run")
    run.add_argument("--asset-dir", type=Path, required=True)
    run.add_argument("--tag", required=True)
    run.add_argument("--evidence-dir", type=Path, required=True)
    verify = subcommands.add_parser("verify")
    verify.add_argument("--asset-dir", type=Path, required=True)
    verify.add_argument("--tag", required=True)
    verify.add_argument("--report", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "run":
            print(run_release_form(args))
        else:
            verify_report(args.report, args.asset_dir, args.tag)
    except (ReleaseFormError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"first-country release-form check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
