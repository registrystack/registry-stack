#!/usr/bin/env python3
"""Run and verify the first-country journey from one closed release payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "registry-stack.first-country-release-form.v1"
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
STAGING_RELAY_IMAGE = re.compile(
    r"^ghcr\.io/registrystack/registry-relay-candidate@sha256:([0-9a-f]{64})$"
)
STAGING_NOTARY_IMAGE = re.compile(
    r"^ghcr\.io/registrystack/registry-notary-candidate@sha256:([0-9a-f]{64})$"
)
COMMAND_ORDER = (
    "install",
    "version",
    "init",
    "preflight",
    "relay_start",
    "relay_smoke",
    "add_notary",
    "combined_test",
    "combined_restart",
    "combined_smoke",
    "denied",
    "allowed",
    "inspect",
    "listeners",
    "stop",
)
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_LOG_BYTES = 1024 * 1024
MAX_AUTHENTICATED_RESPONSE_BYTES = 1024 * 1024
RECORDS_URL = "http://127.0.0.1:4242/v1/datasets/projects/entities/projects/records"
RELAY_LISTENER = "127.0.0.1:4242"
NOTARY_LISTENER = "127.0.0.1:4255"
RECORDS_PURPOSE = "public-works-case-management"
CANONICAL_WORKBOOK_PROJECT_FILE = "data/public_works_projects.xlsx"
CANONICAL_WORKBOOK_RUNTIME_PATH = "/data/public_works_projects.xlsx"
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
NOTARY_MANIFEST_DIGEST_PATHS = {
    "consultation_relay_config_digest": (
        ".registry-stack/build/local/private/relay/config/relay-consultation.yaml"
    ),
    "runtime_consultation_relay_config_digest": (
        ".registry-stack/runtime/local/private/relay/config/relay-consultation.yaml"
    ),
    "compiled_notary_config_digest": (
        ".registry-stack/build/local/private/notary/config/notary.yaml"
    ),
    "runtime_notary_config_digest": (
        ".registry-stack/runtime/local/private/notary/config/notary.yaml"
    ),
    "postgres_ca_digest": (
        ".registry-stack/runtime/local/private/relay/config/state-plane-ca.pem"
    ),
    "database_init_digest": ".registry-stack/runtime/local/private/db/init.sh",
    "workload_jwks_digest": (
        ".registry-stack/runtime/local/private/workload/jwks.json"
    ),
    "consultation_relay_env_digest": (
        ".registry-stack/runtime/local/secrets/relay-consultation.env"
    ),
    "relay_bootstrap_env_digest": (
        ".registry-stack/runtime/local/secrets/relay-bootstrap.env"
    ),
    "notary_env_digest": ".registry-stack/runtime/local/secrets/notary.env",
    "postgres_env_digest": ".registry-stack/runtime/local/secrets/postgres.env",
    "workload_token_digest": (
        ".registry-stack/runtime/local/secrets/relay-workload-token"
    ),
    "workload_private_jwk_digest": (
        ".registry-stack/runtime/local/secrets/workload-private.jwk"
    ),
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


class ReleaseFormError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    if TAG.fullmatch(tag) is None:
        raise ReleaseFormError("release tag must be canonical vMAJOR.MINOR.PATCH")
    installer_name = f"registryctl-{tag}-install.sh"
    binary_name = platform_asset(tag)
    lock_name = f"registryctl-{tag}-image-lock.json"
    names = (installer_name, binary_name, lock_name)
    checksums = parse_checksums(asset_dir / "SHA256SUMS")
    assets: dict[str, str] = {}
    for name in names:
        path = asset_dir / name
        require_regular(path)
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
        "assets": assets,
        "lock": lock,
        "relay_image": relay_image,
        "notary_image": notary_image,
        "postgresql_image": postgresql_image,
    }


def validate_relay_override(expected: str, override: str | None) -> str | None:
    if override is None:
        return None
    expected_match = RELAY_IMAGE.fullmatch(expected)
    override_match = STAGING_RELAY_IMAGE.fullmatch(override)
    if expected_match is None or override_match is None:
        raise ReleaseFormError(
            "Relay staging transport must use the private candidate repository and an immutable digest"
        )
    if expected_match.group(1) != override_match.group(1):
        raise ReleaseFormError(
            "Relay staging transport does not match the release image digest"
        )
    return override


def validate_notary_override(expected: str, override: str | None) -> str | None:
    if override is None:
        return None
    expected_match = NOTARY_IMAGE.fullmatch(expected)
    override_match = STAGING_NOTARY_IMAGE.fullmatch(override)
    if expected_match is None or override_match is None:
        raise ReleaseFormError(
            "Notary staging transport must use the private candidate repository and an immutable digest"
        )
    if expected_match.group(1) != override_match.group(1):
        raise ReleaseFormError(
            "Notary staging transport does not match the release image digest"
        )
    return override


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
    (logs / f"{name}.log").write_text(output, encoding="utf-8")
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


def local_env_values(path: Path) -> list[bytes]:
    values: list[bytes] = []
    for line in path.read_bytes().splitlines():
        if b"=" not in line or line.startswith(b"#"):
            continue
        value = line.split(b"=", 1)[1]
        if value:
            values.append(value)
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
        path.write_bytes(data)


def mode(path: Path) -> str:
    return f"{stat.S_IMODE(path.stat().st_mode):04o}"


def require_private_directory(path: Path) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseFormError(f"required directory must be real: {path.name}")


def digest_uri(path: Path) -> str:
    require_regular(path)
    return f"sha256:{sha256(path)}"


def require_manifest_digest(
    manifest: dict[str, Any],
    field: str,
    path: Path,
) -> None:
    if manifest.get(field) != digest_uri(path):
        raise ReleaseFormError(
            f"canonical runtime manifest does not bind {field}"
        )


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
    expected_keys = {
        "schema_version",
        "environment",
        "relay_image",
        "compose_digest",
        "artifact_manifest_digest",
        "relay_config_digest",
        "workbook_digest",
        "workbook_classification",
        "workbook_project_file",
        "workbook_runtime_path",
        "topology",
    }
    if expected_notary_image is not None:
        expected_keys.add("notary")
    if not isinstance(runtime_manifest, dict) or set(runtime_manifest) != expected_keys:
        raise ReleaseFormError("canonical runtime manifest fields are not closed")
    if (
        runtime_manifest.get("schema_version") != "registryctl.local_runtime.v1"
        or runtime_manifest.get("environment") != "local"
        or runtime_manifest.get("relay_image") != expected_relay_image
        or runtime_manifest.get("workbook_classification")
        != "operator_owned_source_data"
        or runtime_manifest.get("topology") != expected_topology
    ):
        raise ReleaseFormError(
            "canonical runtime identity, topology, or workbook classification is invalid"
        )
    require_manifest_digest(runtime_manifest, "relay_config_digest", relay_config)
    require_manifest_digest(runtime_manifest, "compose_digest", compose)
    artifact_manifest = project / ".registry-stack/build/local/artifact-manifest.json"
    require_manifest_digest(
        runtime_manifest, "artifact_manifest_digest", artifact_manifest
    )
    workbook_project_file = runtime_manifest.get("workbook_project_file")
    workbook_runtime_path = runtime_manifest.get("workbook_runtime_path")
    if (
        workbook_project_file != CANONICAL_WORKBOOK_PROJECT_FILE
        or workbook_runtime_path != CANONICAL_WORKBOOK_RUNTIME_PATH
    ):
        raise ReleaseFormError(
            "canonical runtime does not bind the maintained spreadsheet starter"
        )
    require_manifest_digest(
        runtime_manifest,
        "workbook_digest",
        project / workbook_project_file,
    )
    notary = runtime_manifest.get("notary")
    if expected_notary_image is None:
        if notary is not None or expected_postgresql_image is not None:
            raise ReleaseFormError("Relay-only canonical runtime contains Notary state")
    else:
        expected_notary_keys = {
            "notary_image",
            "postgresql_image",
            *NOTARY_MANIFEST_DIGEST_PATHS,
        }
        if (
            expected_postgresql_image is None
            or not isinstance(notary, dict)
            or set(notary) != expected_notary_keys
            or notary.get("notary_image") != expected_notary_image
            or notary.get("postgresql_image") != expected_postgresql_image
        ):
            raise ReleaseFormError(
                "combined canonical runtime Notary manifest is incomplete"
            )
        for field, relative in NOTARY_MANIFEST_DIGEST_PATHS.items():
            require_manifest_digest(notary, field, project / relative)
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


def run_release_form(args: argparse.Namespace) -> Path:
    beginner_runtime_asset(args.tag)
    asset_dir = args.asset_dir.resolve()
    evidence_dir = args.evidence_dir.resolve()
    if evidence_dir.exists():
        raise ReleaseFormError("evidence directory must not already exist")
    evidence_dir.mkdir(parents=True)
    logs = evidence_dir / "logs"
    logs.mkdir()
    verified = verify_asset_set(asset_dir, args.tag)
    staging_transport = validate_relay_override(
        verified["relay_image"], args.relay_image_override
    )
    notary_staging_transport = validate_notary_override(
        verified["notary_image"], args.notary_image_override
    )
    if shutil.which("registry-relay") or shutil.which("registry-notary"):
        raise ReleaseFormError("ambient Registry product binaries must not be on PATH")

    with tempfile.TemporaryDirectory(
        prefix="registry-first-country-release-form-"
    ) as temporary:
        root = Path(temporary)
        install_dir = root / "install"
        project = root / "my-first-api"
        install_dir.mkdir()
        environment = os.environ.copy()
        environment.update(
            {
                "CI": "1",
                "REGISTRYCTL_NO_UPDATE_CHECK": "1",
                "REGISTRYCTL_ASSET_DIR": str(asset_dir),
                "REGISTRYCTL_INSTALL_DIR": str(install_dir),
                "REGISTRYCTL_VERSION": args.tag,
                "COMPOSE_PROJECT_NAME": f"registry-first-country-{os.getpid()}",
            }
        )
        if staging_transport is not None:
            environment["REGISTRYCTL_RELAY_STAGING_IMAGE"] = staging_transport
        if notary_staging_transport is not None:
            environment["REGISTRYCTL_NOTARY_STAGING_IMAGE"] = notary_staging_transport
        commands: list[dict[str, Any]] = []
        registryctl = install_dir / "registryctl"
        installer = asset_dir / verified["installer_name"]
        secrets: list[bytes] = []
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
            require_regular(install_dir / verified["lock_name"])
            commands.append(
                run_command(
                    "version",
                    [str(registryctl), "--version"],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            version_text = (logs / "version.log").read_text(encoding="utf-8").strip()
            if version_text != f"registryctl {args.tag.removeprefix('v')}":
                raise ReleaseFormError(
                    "installed registryctl version does not match the release tag"
                )
            commands.append(
                run_command(
                    "init",
                    [
                        str(registryctl),
                        "init",
                        "--from",
                        "spreadsheet",
                        "--project-dir",
                        str(project),
                    ],
                    cwd=root,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_command(
                    "preflight",
                    [str(registryctl), "doctor", "--profile", "local"],
                    cwd=project,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_command(
                    "relay_start",
                    [str(registryctl), "start"],
                    cwd=project,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_command(
                    "relay_smoke",
                    [str(registryctl), "smoke"],
                    cwd=project,
                    env=environment,
                    logs=logs,
                )
            )
            relay_smoke = smoke_outcomes(project, "relay_only")
            read_runtime_inspection(
                project,
                expected_relay_image=staging_transport or verified["relay_image"],
                expected_notary_image=None,
                expected_postgresql_image=None,
            )
            commands.append(
                run_command(
                    "add_notary",
                    [str(registryctl), "add", "notary"],
                    cwd=project,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_command(
                    "combined_test",
                    [str(registryctl), "test", "--environment", "local"],
                    cwd=project,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_command(
                    "combined_restart",
                    [str(registryctl), "restart"],
                    cwd=project,
                    env=environment,
                    logs=logs,
                )
            )
            commands.append(
                run_command(
                    "combined_smoke",
                    [str(registryctl), "smoke"],
                    cwd=project,
                    env=environment,
                    logs=logs,
                )
            )
            combined_smoke = smoke_outcomes(project, "combined_notary")
            denied = subprocess.run(
                [
                    "curl",
                    "-sS",
                    "-o",
                    os.devnull,
                    "-w",
                    "%{http_code}",
                    "-H",
                    "Data-Purpose: public-works-case-management",
                    RECORDS_URL,
                ],
                cwd=project,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
            (logs / "denied.log").write_text(
                denied.stdout[-MAX_LOG_BYTES:], encoding="utf-8"
            )
            if denied.returncode != 0 or denied.stdout.strip() != "401":
                raise ReleaseFormError("anonymous records request did not return 401")
            commands.append(
                {
                    "name": "denied",
                    "status": "passed",
                    "exit_code": 0,
                    "log_sha256": sha256(logs / "denied.log"),
                }
            )
            secrets = sorted(
                set(
                    local_env_values(
                        project / ".registry-stack/runtime/local/secrets/local.env"
                    )
                    + local_env_values(
                        project / ".registry-stack/runtime/local/secrets/relay.env"
                    )
                ),
                key=len,
                reverse=True,
            )
            match_key, no_match_key = required_local_credentials(
                project / ".registry-stack/runtime/local/secrets/local.env"
            )
            run_authenticated_records_evidence(
                project=project,
                env=environment,
                logs=logs,
                match_key=match_key,
                no_match_key=no_match_key,
            )
            commands.append(
                {
                    "name": "allowed",
                    "status": "passed",
                    "exit_code": 0,
                    "log_sha256": sha256(logs / "allowed.log"),
                }
            )
            runtime = read_runtime_inspection(
                project,
                expected_relay_image=staging_transport or verified["relay_image"],
                expected_notary_image=(
                    notary_staging_transport or verified["notary_image"]
                ),
                expected_postgresql_image=verified["postgresql_image"],
            )
            (logs / "inspect.log").write_text(
                "".join(f"{name}={value}\n" for name, value in runtime.items()),
                encoding="utf-8",
            )
            commands.append(
                {
                    "name": "inspect",
                    "status": "passed",
                    "exit_code": 0,
                    "log_sha256": sha256(logs / "inspect.log"),
                }
            )
            listeners = verify_loopback_listeners(project, environment, logs)
            commands.append(
                {
                    "name": "listeners",
                    "status": "passed",
                    "exit_code": 0,
                    "log_sha256": sha256(logs / "listeners.log"),
                }
            )
        finally:
            if project.exists():
                stopped = subprocess.run(
                    [str(registryctl), "stop"] if registryctl.exists() else ["true"],
                    cwd=project,
                    env=environment,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=60,
                    check=False,
                )
                (logs / "stop.log").write_text(
                    stopped.stdout[-MAX_LOG_BYTES:], encoding="utf-8"
                )
                if stopped.returncode == 0:
                    commands.append(
                        {
                            "name": "stop",
                            "status": "passed",
                            "exit_code": 0,
                            "log_sha256": sha256(logs / "stop.log"),
                        }
                    )
        if tuple(command["name"] for command in commands) != COMMAND_ORDER:
            raise ReleaseFormError(
                "release-form command sequence did not complete in exact order"
            )
        secrets_dir = project / ".registry-stack/runtime/local/secrets"
        for secret_path in sorted(secrets_dir.iterdir()):
            require_regular(secret_path)
            if secret_path.suffix == ".env":
                secrets.extend(local_env_values(secret_path))
            else:
                data = secret_path.read_bytes()
                secrets.extend(value for value in (data, data.strip()) if value)
        secrets = sorted(set(secrets), key=len, reverse=True)
        scanned_files = assert_no_secret_leak(project, secrets)
        redact_logs(
            logs,
            secrets,
            private_paths=(root, install_dir, project, asset_dir, evidence_dir),
        )
        for command in commands:
            command["log_sha256"] = sha256(logs / f"{command['name']}.log")
        permissions = {"runtime_secrets_directory": mode(secrets_dir)}
        permissions.update(
            {
                name: mode(secrets_dir / filename)
                for name, filename in SECRET_FILES.items()
            }
        )
        expected_permissions = {
            "runtime_secrets_directory": "0700",
            **{name: "0600" for name in SECRET_FILES},
        }
        if os.name == "posix" and permissions != expected_permissions:
            raise ReleaseFormError(
                "generated credential permissions are not owner-only"
            )
        report = {
            "schema_version": SCHEMA,
            "status": "passed",
            "release_tag": args.tag,
            "manifest_source_ref": verified["lock"].get("manifest_source_ref"),
            "tag_target": verified["lock"].get("tag_target"),
            "platform_asset": verified["binary_name"],
            "asset_sha256": verified["assets"],
            "release_image_lock_sha256": verified["assets"][verified["lock_name"]],
            "relay_image": verified["relay_image"],
            "notary_image": verified["notary_image"],
            "postgresql_image": verified["postgresql_image"],
            "staging_transport": staging_transport,
            "notary_staging_transport": notary_staging_transport,
            "commands": commands,
            "listeners": listeners,
            "permissions": permissions,
            "runtime": runtime,
            "smoke": {
                "relay_only": relay_smoke,
                "combined_notary": combined_smoke,
            },
            "redaction": {
                "status": "passed",
                "generated_files_scanned": scanned_files,
            },
        }
        output = evidence_dir / "first-country-release-form.json"
        output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return output


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON object key")
        result[name] = value
    return result


def verify_evidence_logs(report_path: Path, commands: list[dict[str, Any]]) -> None:
    logs = report_path.parent / "logs"
    try:
        metadata = logs.lstat()
    except OSError as error:
        raise ReleaseFormError("release-form evidence logs are unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseFormError("release-form evidence logs must be a real directory")
    try:
        entries = list(logs.iterdir())
    except OSError as error:
        raise ReleaseFormError("release-form evidence logs are unavailable") from error

    expected_names = {f"{name}.log" for name in COMMAND_ORDER}
    if {entry.name for entry in entries} != expected_names:
        raise ReleaseFormError("release-form evidence log set is not closed")

    contents: dict[str, bytes] = {}
    for command in commands:
        name = command["name"]
        log_path = logs / f"{name}.log"
        require_regular(log_path, max_bytes=MAX_LOG_BYTES)
        try:
            data = log_path.read_bytes()
        except OSError as error:
            raise ReleaseFormError(
                f"release-form evidence log is unreadable: {name}.log"
            ) from error
        digest = hashlib.sha256(data).hexdigest()
        if digest != command["log_sha256"]:
            raise ReleaseFormError(
                f"release-form evidence log digest does not match: {name}.log"
            )
        contents[name] = data

    try:
        allowed = json.loads(
            contents["allowed"].decode("utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ReleaseFormError(
            "allowed evidence log is not valid closed JSON"
        ) from error
    exact_scalar_types = (
        isinstance(allowed, list)
        and len(allowed) == 2
        and all(isinstance(summary, dict) for summary in allowed)
        and all(type(summary.get("http_status")) is int for summary in allowed)
        and all(type(summary.get("row_count")) is int for summary in allowed)
    )
    if not exact_scalar_types or allowed != ALLOWED_EVIDENCE:
        raise ReleaseFormError(
            "allowed evidence log does not prove the exact value-free match and no-match summaries"
        )


def verify_report(path: Path, asset_dir: Path, tag: str) -> None:
    require_regular(path, max_bytes=4 * 1024 * 1024)
    try:
        report = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ReleaseFormError(
            "release-form report is not valid closed JSON"
        ) from error
    expected_keys = {
        "schema_version",
        "status",
        "release_tag",
        "manifest_source_ref",
        "tag_target",
        "platform_asset",
        "asset_sha256",
        "release_image_lock_sha256",
        "relay_image",
        "notary_image",
        "postgresql_image",
        "staging_transport",
        "notary_staging_transport",
        "commands",
        "listeners",
        "permissions",
        "runtime",
        "smoke",
        "redaction",
    }
    if not isinstance(report, dict) or set(report) != expected_keys:
        raise ReleaseFormError("release-form report fields are not closed")
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
    permissions = report.get("permissions")
    runtime = report.get("runtime")
    smoke = report.get("smoke")
    redaction = report.get("redaction")
    if (
        report["schema_version"] != SCHEMA
        or report["status"] != "passed"
        or report["release_tag"] != tag
        or re.fullmatch(r"[0-9a-f]{40}", str(report["manifest_source_ref"])) is None
        or re.fullmatch(r"[0-9a-f]{40}", str(report["tag_target"])) is None
        or report["manifest_source_ref"] != verified["lock"].get("manifest_source_ref")
        or report["tag_target"] != verified["lock"].get("tag_target")
        or report["platform_asset"] != verified["binary_name"]
        or report["asset_sha256"] != verified["assets"]
        or report["release_image_lock_sha256"]
        != verified["assets"][verified["lock_name"]]
        or report["relay_image"] != verified["relay_image"]
        or report["notary_image"] != verified["notary_image"]
        or report["postgresql_image"] != verified["postgresql_image"]
        or report["listeners"]
        != {"relay": RELAY_LISTENER, "notary": NOTARY_LISTENER}
        or not command_shape_valid
        or tuple(command["name"] for command in commands) != COMMAND_ORDER
        or permissions
        != {
            "runtime_secrets_directory": "0700",
            **{name: "0600" for name in SECRET_FILES},
        }
        or not isinstance(runtime, dict)
        or set(runtime)
        != {
            "relay_config_sha256",
            "runtime_manifest_sha256",
            "compose_sha256",
            "notary_config_sha256",
            "topology",
            "workbook_classification",
        }
        or any(
            not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for name, value in runtime.items()
            if name.endswith("_sha256")
        )
        or runtime.get("topology") != "combined_notary"
        or runtime.get("workbook_classification") != "operator_owned_source_data"
        or smoke != SMOKE_EVIDENCE
        or not isinstance(redaction, dict)
        or set(redaction) != {"status", "generated_files_scanned"}
        or redaction.get("status") != "passed"
        or not isinstance(redaction.get("generated_files_scanned"), int)
        or redaction["generated_files_scanned"] <= 0
    ):
        raise ReleaseFormError(
            "release-form report does not prove the required journey"
        )
    validate_relay_override(report["relay_image"], report["staging_transport"])
    validate_notary_override(
        report["notary_image"], report["notary_staging_transport"]
    )
    verify_evidence_logs(path, commands)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subcommands = result.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run")
    run.add_argument("--asset-dir", type=Path, required=True)
    run.add_argument("--tag", required=True)
    run.add_argument("--evidence-dir", type=Path, required=True)
    run.add_argument("--relay-image-override")
    run.add_argument("--notary-image-override")
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
