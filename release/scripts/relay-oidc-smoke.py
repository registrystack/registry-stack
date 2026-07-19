#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the Registry Relay OIDC release smoke against a pinned image digest."""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from string import Template
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "release" / "conformance" / "relay-oidc"
COMPOSE_PATH = CONFIG_DIR / "docker-compose.yml"
TEMPLATE_PATH = CONFIG_DIR / "relay.template.yaml"
FIXTURE_PATH = CONFIG_DIR / "records.csv"
HELPER_PATH = CONFIG_DIR / "zitadel-helper.py"
DEFAULT_WORK_ROOT = REPO_ROOT / "target" / "relay-oidc-smoke"
SCHEMA_VERSION = "registry.release.relay_oidc_smoke.v1"
RELAY_IMAGE_RE = re.compile(
    r"^ghcr\.io/registrystack/registry-relay@sha256:[0-9a-f]{64}$"
)
DIGEST_IMAGE_RE = re.compile(r"^[^\s@]+:[^\s@]+@sha256:[0-9a-f]{64}$")
SOURCE_REF_RE = re.compile(r"^[0-9a-f]{40}$")
RELEASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{12}$")
MAX_HTTP_BODY = 65_536
REQUIRED_CHECKS = (
    "candidate-image-binding",
    "missing-credential",
    "valid-zitadel-role-mapping",
    "tampered-signature",
    "audience-mismatch",
    "token-type-denied",
    "organization-role-scope-denied",
)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep release assertions on the exact loopback origin they target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), NoRedirectHandler()
)


class SmokeError(RuntimeError):
    """A bounded, user-actionable runner failure."""


class CheckFailure(SmokeError):
    """A conformance assertion failed."""


def utc_now() -> str:
    return (
        dt.datetime.now(dt.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def validate_relay_image(value: str) -> str:
    if not RELAY_IMAGE_RE.fullmatch(value):
        raise SmokeError(
            "Relay image must be exactly "
            "ghcr.io/registrystack/registry-relay@sha256:<64 lowercase hex>"
        )
    return value


def validate_source_ref(value: str) -> str:
    if not SOURCE_REF_RE.fullmatch(value):
        raise SmokeError(
            "candidate source ref must be 40 lowercase hexadecimal characters"
        )
    return value


def validate_release_id(value: str) -> str:
    if not RELEASE_ID_RE.fullmatch(value):
        raise SmokeError("release id contains unsupported characters or is too long")
    return value


def compose_image_entries(text: str) -> list[str]:
    return [
        match.group(1).strip()
        for line in text.splitlines()
        if (match := re.match(r"^\s+image:\s+(.+?)\s*$", line))
    ]


def validate_assets() -> dict[str, Any]:
    required = (COMPOSE_PATH, TEMPLATE_PATH, FIXTURE_PATH, HELPER_PATH)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise SmokeError(f"missing Relay OIDC smoke assets: {', '.join(missing)}")

    compose = COMPOSE_PATH.read_text(encoding="utf-8")
    if re.search(r"^\s+build:\s*", compose, re.MULTILINE):
        raise SmokeError("release smoke Compose topology must not build images")
    images = compose_image_entries(compose)
    relay_entries = [
        image
        for image in images
        if image.startswith("${REGISTRY_RELAY_OIDC_SMOKE_RELAY_IMAGE")
    ]
    if relay_entries != [
        "${REGISTRY_RELAY_OIDC_SMOKE_RELAY_IMAGE:"
        "?runner must provide digest-pinned Registry Relay image}"
    ]:
        raise SmokeError(
            "Compose topology must declare one runner-supplied Relay image"
        )
    literal_images = [image for image in images if image not in relay_entries]
    if len(literal_images) < 3:
        raise SmokeError("Compose topology is missing pinned supporting images")
    for image in literal_images:
        if not DIGEST_IMAGE_RE.fullmatch(image):
            raise SmokeError(f"supporting image is not tag-and-digest pinned: {image}")
    if ":latest" in compose or "@sha256:" not in compose:
        raise SmokeError("Compose topology contains a mutable or missing image pin")
    for ownership_env in (
        "REGISTRY_RELAY_OIDC_SMOKE_RUNTIME_UID",
        "REGISTRY_RELAY_OIDC_SMOKE_RUNTIME_GID",
    ):
        if ownership_env not in compose:
            raise SmokeError(
                f"Compose topology does not preserve host ownership: {ownership_env}"
            )

    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    required_template_fragments = (
        "mode: oidc",
        "discovery_url: http://localhost:8080/.well-known/openid-configuration",
        "scope_claim: $scope_claim",
        '"registry-smoke-reader": "smoke_registry:metadata"',
        "$audience",
        "$required_org",
        "$allowed_client",
        "$allowed_token_type",
    )
    for fragment in required_template_fragments:
        if fragment not in template:
            raise SmokeError(f"Relay template is missing required contract: {fragment}")
    fixture = FIXTURE_PATH.read_text(encoding="utf-8")
    if fixture != "person_id,display_name\nperson-001,Registry Smoke Person\n":
        raise SmokeError("synthetic Relay smoke fixture has unexpected content")

    return {
        "compose_sha256": file_sha256(COMPOSE_PATH),
        "fixture_sha256": file_sha256(FIXTURE_PATH),
        "helper_sha256": file_sha256(HELPER_PATH),
        "support_images": sorted(set(literal_images)),
        "template_sha256": file_sha256(TEMPLATE_PATH),
    }


def plan_document(relay_image: str, source_ref: str, release_id: str) -> dict[str, Any]:
    assets = validate_assets()
    return {
        "schema_version": SCHEMA_VERSION,
        "operation": "relay-oidc-smoke",
        "classification": "candidate-neutral-harness-plan",
        "release_id": validate_release_id(release_id),
        "candidate_source_ref": validate_source_ref(source_ref),
        "relay_image": validate_relay_image(relay_image),
        "topology": assets,
        "checks": list(REQUIRED_CHECKS),
        "plan_network_required": False,
        "live_run_requires_docker": True,
        "live_run_network_required": True,
        "live_evidence": False,
        "notes": [
            "This plan validates checked-in inputs only and is not conformance evidence.",
            (
                "A live run remains unreviewed until its digest-bound report is "
                + "reviewed without raw secrets."
            ),
        ],
    }


class SensitiveGuard:
    """Redact and detect values that must not leave ephemeral runtime state."""

    def __init__(self, *values: str):
        self._values: set[str] = set()
        for value in values:
            self.add(value)

    def add(self, value: str | None) -> None:
        if value and len(value) >= 8:
            self._values.add(value)

    def redact(self, text: str) -> str:
        rendered = text
        for value in sorted(self._values, key=len, reverse=True):
            rendered = rendered.replace(value, "<redacted>")
        return rendered

    def assert_clean_bytes(self, value: bytes, context: str) -> None:
        for secret in self._values:
            if secret.encode("utf-8") in value:
                raise SmokeError(f"sensitive-value canary detected in {context}")

    def assert_clean_tree(self, root: Path) -> None:
        for path in root.rglob("*"):
            if path.is_symlink():
                raise SmokeError(f"refusing to scan symlink in output: {path.name}")
            if path.is_file():
                self.assert_clean_bytes(path.read_bytes(), path.name)


def run_checked(
    command: list[str],
    *,
    env: dict[str, str],
    guard: SensitiveGuard,
    timeout: int = 300,
    accepted: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise SmokeError(f"command timed out: {' '.join(command[:4])}") from None
    combined = f"{result.stdout}\n{result.stderr}"
    guard.assert_clean_bytes(combined.encode("utf-8"), "subprocess output")
    if result.returncode not in accepted:
        diagnostic = guard.redact(combined).strip()
        if len(diagnostic) > 2_000:
            diagnostic = diagnostic[:2_000] + "..."
        raise SmokeError(
            f"command failed ({result.returncode}): {' '.join(command[:4])}"
            + (f"\n{diagnostic}" if diagnostic else "")
        )
    return result


def compose_command(project_name: str, *args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "--project-name",
        project_name,
        "-f",
        str(COMPOSE_PATH),
        *args,
    ]


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def read_limited(path: Path, limit: int, *, private: bool = False) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise SmokeError(f"required runtime file is not regular: {path.name}")
    if private and path.stat().st_mode & 0o077:
        raise SmokeError(f"secret runtime file permissions are too broad: {path.name}")
    if path.stat().st_size > limit:
        raise SmokeError(f"runtime file exceeds size limit: {path.name}")
    return path.read_bytes()


def read_json_object(path: Path, *, private: bool = False) -> dict[str, Any]:
    raw = read_limited(path, 65_536, private=private)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise SmokeError(f"runtime file is malformed JSON: {path.name}") from None
    if not isinstance(value, dict):
        raise SmokeError(f"runtime JSON is not an object: {path.name}")
    return value


def require_string(value: dict[str, Any], key: str) -> str:
    candidate = value.get(key)
    if not isinstance(candidate, str) or not candidate:
        raise SmokeError(f"runtime metadata omitted {key}")
    return candidate


def decode_jwt_segment(segment: str, context: str) -> dict[str, Any]:
    if len(segment) > 16_384:
        raise SmokeError(f"JWT {context} segment exceeds size limit")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        parsed = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        raise SmokeError(f"JWT {context} segment is malformed") from None
    if not isinstance(parsed, dict):
        raise SmokeError(f"JWT {context} is not an object")
    return parsed


def inspect_token(token: str, topology: dict[str, Any]) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise SmokeError("Zitadel access token is not a compact JWT")
    header = decode_jwt_segment(parts[0], "header")
    claims = decode_jwt_segment(parts[1], "payload")
    if header.get("alg") != "RS256":
        raise SmokeError("Zitadel access token does not use the pinned RS256 profile")
    token_type = header.get("typ")
    if not isinstance(token_type, str) or token_type.lower() not in {"jwt", "at+jwt"}:
        raise SmokeError("Zitadel access token has an unsupported JOSE typ")
    if not isinstance(header.get("kid"), str) or not header["kid"]:
        raise SmokeError("Zitadel access token has no signing key id")
    if claims.get("iss") != "http://localhost:8080":
        raise SmokeError(
            "Zitadel access token issuer does not match the local topology"
        )

    project_id = require_string(topology, "project_id")
    audiences = claims.get("aud")
    if isinstance(audiences, str):
        audiences = [audiences]
    if not isinstance(audiences, list) or project_id not in audiences:
        raise SmokeError(
            "Zitadel access token is not audience-bound to the smoke project"
        )

    client = claims.get("azp") or claims.get("client_id")
    if not isinstance(client, str) or not client:
        raise SmokeError("Zitadel access token has no authorized client claim")
    configured_client = require_string(topology, "client_id")
    if client != configured_client:
        raise SmokeError(
            "Zitadel access token client differs from the provisioned client"
        )

    role_key = require_string(topology, "role_key")
    org_id = require_string(topology, "service_account_org_id")
    claim_names = (
        f"urn:zitadel:iam:org:project:{project_id}:roles",
        "urn:zitadel:iam:org:project:roles",
    )
    claim_name = next(
        (name for name in claim_names if isinstance(claims.get(name), dict)), None
    )
    if claim_name is None:
        raise SmokeError(
            "Zitadel access token omitted a native project-role object claim"
        )
    roles = claims[claim_name]
    if not isinstance(roles, dict) or not isinstance(roles.get(role_key), dict):
        raise SmokeError(
            "Zitadel access token omitted the provisioned native project role"
        )
    active_org_value = roles[role_key].get(org_id)
    if not isinstance(active_org_value, str) or not active_org_value.strip():
        raise SmokeError(
            "Zitadel role claim is not active for the service account organization"
        )

    return {
        "allowed_client": client,
        "audience": project_id,
        "required_org": org_id,
        "scope_claim": claim_name,
        "token_type": token_type,
    }


def atomic_text(path: Path, value: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            # The temporary was atomically replaced or already removed.
            pass


def render_relay_config(
    token_profile: dict[str, Any],
    *,
    host_port: int,
    audience: str | None = None,
    required_org: str | None = None,
    allowed_token_type: str | None = None,
) -> str:
    params = {
        "base_url": json.dumps(f"http://127.0.0.1:{host_port}"),
        "audience": json.dumps(audience or require_string(token_profile, "audience")),
        "required_org": json.dumps(
            required_org or require_string(token_profile, "required_org")
        ),
        "allowed_client": json.dumps(require_string(token_profile, "allowed_client")),
        "scope_claim": json.dumps(require_string(token_profile, "scope_claim")),
        "allowed_token_type": json.dumps(
            allowed_token_type or require_string(token_profile, "token_type")
        ),
    }
    rendered = Template(TEMPLATE_PATH.read_text(encoding="utf-8")).substitute(params)
    if "$" in rendered:
        raise SmokeError("Relay configuration template left unresolved placeholders")
    return rendered


def tamper_signature(token: str) -> str:
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        raise SmokeError("cannot tamper malformed JWT")
    try:
        signature = bytearray(
            base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        )
    except (ValueError, binascii.Error):
        raise SmokeError("cannot tamper malformed JWT signature") from None
    if not signature:
        raise SmokeError("cannot tamper empty JWT signature")
    signature[-1] ^= 0x01
    encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{parts[0]}.{parts[1]}.{encoded}"


def http_json(
    url: str, token: str | None, guard: SensitiveGuard
) -> tuple[int, dict[str, Any]]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with NO_REDIRECT_OPENER.open(request, timeout=15) as response:
            status = response.status
            body = response.read(MAX_HTTP_BODY + 1)
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            body = exc.read(MAX_HTTP_BODY + 1)
        finally:
            exc.close()
        if 300 <= status < 400:
            raise SmokeError("Relay endpoint returned a redirect") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise SmokeError("Relay request transport failed") from None
    if len(body) > MAX_HTTP_BODY:
        raise SmokeError("Relay response exceeded the 64 KiB smoke limit")
    guard.assert_clean_bytes(body, "Relay response")
    if not body:
        return status, {}
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        raise SmokeError("Relay returned malformed JSON") from None
    if not isinstance(parsed, dict):
        raise SmokeError("Relay response is not a JSON object")
    return status, parsed


def expected_response(
    checks: list[dict[str, Any]],
    check_id: str,
    response: tuple[int, dict[str, Any]],
    *,
    status: int,
    code: str | None = None,
) -> dict[str, Any]:
    actual_status, body = response
    actual_code = body.get("code") if isinstance(body.get("code"), str) else None
    check = {
        "id": check_id,
        "expected_status": status,
        "actual_status": actual_status,
        "expected_code": code,
        "actual_code": actual_code,
        "result": "pass" if actual_status == status and actual_code == code else "fail",
    }
    checks.append(check)
    if check["result"] != "pass":
        raise CheckFailure(
            f"{check_id} expected HTTP {status}/{code or '-'}, "
            f"got {actual_status}/{actual_code or '-'}"
        )
    return body


def wait_for_relay(
    base_url: str, env: dict[str, str], project: str, guard: SensitiveGuard
) -> None:
    deadline = time.monotonic() + 120
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with NO_REDIRECT_OPENER.open(f"{base_url}/healthz", timeout=3) as response:
                if response.status == 200:
                    return
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            last_error = f"HTTP {status}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = (
                str(exc.reason) if isinstance(exc, urllib.error.URLError) else str(exc)
            )
        time.sleep(1)
    logs = run_checked(
        compose_command(project, "logs", "--no-color", "--tail", "100", "relay"),
        env=env,
        guard=guard,
        timeout=30,
        accepted=(0, 1),
    )
    diagnostic = guard.redact(f"{logs.stdout}\n{logs.stderr}").strip()
    if len(diagnostic) > 2_000:
        diagnostic = diagnostic[-2_000:]
    raise SmokeError(f"Relay did not become healthy: {last_error}\n{diagnostic}")


def start_relay(
    config_path: Path,
    rendered: str,
    *,
    base_url: str,
    env: dict[str, str],
    project: str,
    guard: SensitiveGuard,
) -> str:
    atomic_text(config_path, rendered)
    run_checked(
        compose_command(project, "up", "-d", "--force-recreate", "relay"),
        env=env,
        guard=guard,
    )
    wait_for_relay(base_url, env, project, guard)
    return sha256_bytes(rendered.encode("utf-8"))


def relay_container_image(
    env: dict[str, str], project: str, guard: SensitiveGuard
) -> str:
    container = run_checked(
        compose_command(project, "ps", "-q", "relay"), env=env, guard=guard
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{12,64}", container):
        raise SmokeError("could not resolve the running Relay container")
    return run_checked(
        ["docker", "inspect", "--format", "{{.Config.Image}}", container],
        env=env,
        guard=guard,
    ).stdout.strip()


def safe_report(
    report: dict[str, Any], output_dir: Path, guard: SensitiveGuard
) -> Path:
    allowed_keys = {
        "schema_version",
        "classification",
        "review_required",
        "contains_sensitive_material",
        "release_id",
        "candidate_source_ref",
        "relay_image",
        "started_at",
        "completed_at",
        "result",
        "failure_stage",
        "diagnostic",
        "cleanup",
        "topology",
        "configuration_digests",
        "checks",
    }
    unexpected = set(report) - allowed_keys
    if unexpected:
        raise SmokeError(
            f"report contains non-allowlisted fields: {sorted(unexpected)}"
        )
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    guard.assert_clean_bytes(raw, "report")
    path = output_dir / "relay-oidc-smoke-report.json"
    atomic_text(path, raw.decode("utf-8"))
    guard.assert_clean_tree(output_dir)
    return path


def ensure_empty_output(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if resolved == Path(resolved.anchor) or resolved == REPO_ROOT:
        raise SmokeError("output directory is too broad")
    if resolved.exists():
        if not resolved.is_dir() or resolved.is_symlink():
            raise SmokeError("output path must be a regular directory")
        if any(resolved.iterdir()):
            raise SmokeError("output directory must be empty")
    else:
        resolved.mkdir(parents=True, mode=0o755)
    return resolved


def default_output_dir() -> Path:
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_WORK_ROOT / f"run-{stamp}-{secrets.token_hex(3)}"


def execute_live(args: argparse.Namespace) -> Path:
    assets = validate_assets()
    relay_image = validate_relay_image(args.relay_image)
    source_ref = validate_source_ref(args.candidate_source_ref)
    release_id = validate_release_id(args.release_id)
    if not shutil.which("docker"):
        raise SmokeError("Docker with Compose is required for a live smoke")

    output_dir = ensure_empty_output(
        Path(args.output_dir) if args.output_dir else default_output_dir()
    )
    DEFAULT_WORK_ROOT.mkdir(parents=True, exist_ok=True)
    run_id = secrets.token_hex(6)
    if not RUN_ID_RE.fullmatch(run_id):
        raise SmokeError("internal run id generation failed")
    project = f"registry-relay-oidc-{run_id}"
    host_port = args.host_port or free_loopback_port()
    if not 1_024 <= host_port <= 65_535:
        raise SmokeError("host port must be between 1024 and 65535")
    base_url = f"http://127.0.0.1:{host_port}"

    canary = f"RSOIDC_CANARY_{secrets.token_hex(16)}"
    postgres_password = f"{canary}_postgres"
    audit_secret = f"{canary}_audit_{secrets.token_hex(16)}"
    master_key = secrets.token_hex(16)
    guard = SensitiveGuard(canary, postgres_password, audit_secret, master_key)
    runtime_dir = Path(
        tempfile.mkdtemp(prefix=f"runtime-{run_id}-", dir=DEFAULT_WORK_ROOT)
    )
    os.chmod(runtime_dir, 0o700)
    config_path = runtime_dir / "relay.yaml"
    atomic_text(config_path, "# placeholder; Relay is not started before rendering\n")

    env = os.environ.copy()
    env.update(
        {
            "REGISTRY_RELAY_OIDC_SMOKE_AUDIT_HASH_SECRET": audit_secret,
            "REGISTRY_RELAY_OIDC_SMOKE_CONFIG_DIR": str(CONFIG_DIR),
            "REGISTRY_RELAY_OIDC_SMOKE_HOST_PORT": str(host_port),
            "REGISTRY_RELAY_OIDC_SMOKE_POSTGRES_PASSWORD": postgres_password,
            "REGISTRY_RELAY_OIDC_SMOKE_RELAY_CONFIG": str(config_path),
            "REGISTRY_RELAY_OIDC_SMOKE_RELAY_IMAGE": relay_image,
            "REGISTRY_RELAY_OIDC_SMOKE_RUNTIME_GID": str(os.getgid()),
            "REGISTRY_RELAY_OIDC_SMOKE_RUN_ID": run_id,
            "REGISTRY_RELAY_OIDC_SMOKE_RUNTIME_DIR": str(runtime_dir),
            "REGISTRY_RELAY_OIDC_SMOKE_RUNTIME_UID": str(os.getuid()),
            "REGISTRY_RELAY_OIDC_SMOKE_SECRET_CANARY": canary,
            "REGISTRY_RELAY_OIDC_SMOKE_ZITADEL_MASTERKEY": master_key,
        }
    )

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "classification": "unreviewed-live-candidate-output",
        "review_required": True,
        "contains_sensitive_material": False,
        "release_id": release_id,
        "candidate_source_ref": source_ref,
        "relay_image": relay_image,
        "started_at": utc_now(),
        "completed_at": None,
        "result": "error",
        "failure_stage": None,
        "diagnostic": None,
        "cleanup": "pending",
        "topology": assets,
        "configuration_digests": {},
        "checks": [],
    }
    stage = "topology-start"
    primary_error: SmokeError | None = None
    try:
        run_checked(
            compose_command(project, "up", "-d", "zitadel"),
            env=env,
            guard=guard,
            timeout=420,
        )
        stage = "zitadel-provision"
        provision_result = run_checked(
            compose_command(project, "run", "--rm", "--no-deps", "helper", "provision"),
            env=env,
            guard=guard,
            timeout=240,
        )
        topology = read_json_object(runtime_dir / "topology.json")
        secret_topology = read_json_object(
            runtime_dir / "topology-secret.json", private=True
        )
        guard.add(require_string(secret_topology, "client_secret"))
        guard.assert_clean_bytes(
            f"{provision_result.stdout}\n{provision_result.stderr}".encode("utf-8"),
            "provision subprocess output after credential creation",
        )
        if require_string(secret_topology, "canary") != canary:
            raise SmokeError(
                "secret canary did not survive the provider bootstrap boundary"
            )

        stage = "token-mint"
        mint_result = run_checked(
            compose_command(project, "run", "--rm", "--no-deps", "helper", "mint"),
            env=env,
            guard=guard,
            timeout=120,
        )
        token = read_limited(runtime_dir / "access-token", 32_768, private=True).decode(
            "ascii"
        )
        if not token or any(char.isspace() for char in token):
            raise SmokeError("helper produced an empty or malformed access token")
        guard.add(token)
        guard.assert_clean_bytes(
            f"{mint_result.stdout}\n{mint_result.stderr}".encode("utf-8"),
            "mint subprocess output after token creation",
        )
        token_profile = inspect_token(token, topology)

        stage = "positive-relay-start"
        positive = render_relay_config(token_profile, host_port=host_port)
        report["configuration_digests"]["positive"] = start_relay(
            config_path,
            positive,
            base_url=base_url,
            env=env,
            project=project,
            guard=guard,
        )
        running_image = relay_container_image(env, project, guard)
        image_check = {
            "id": "candidate-image-binding",
            "expected_status": None,
            "actual_status": None,
            "expected_code": relay_image,
            "actual_code": running_image,
            "result": "pass" if running_image == relay_image else "fail",
        }
        report["checks"].append(image_check)
        if image_check["result"] != "pass":
            raise CheckFailure(
                "running Relay container is not bound to the requested digest"
            )

        stage = "positive-and-signature-checks"
        endpoint = f"{base_url}/v1/datasets"
        expected_response(
            report["checks"],
            "missing-credential",
            http_json(endpoint, None, guard),
            status=401,
            code="auth.missing_credential",
        )
        valid_body = expected_response(
            report["checks"],
            "valid-zitadel-role-mapping",
            http_json(endpoint, token, guard),
            status=200,
        )
        datasets = valid_body.get("data")
        if not isinstance(datasets, list) or not any(
            isinstance(item, dict) and item.get("dataset_id") == "smoke_registry"
            for item in datasets
        ):
            report["checks"][-1]["result"] = "fail"
            raise CheckFailure(
                "valid token response did not expose the mapped smoke dataset"
            )
        expected_response(
            report["checks"],
            "tampered-signature",
            http_json(endpoint, tamper_signature(token), guard),
            status=401,
            code="auth.token_signature_invalid",
        )

        stage = "audience-mismatch-check"
        wrong_audience = render_relay_config(
            token_profile,
            host_port=host_port,
            audience="registry-relay-smoke-wrong-audience",
        )
        report["configuration_digests"]["wrong_audience"] = start_relay(
            config_path,
            wrong_audience,
            base_url=base_url,
            env=env,
            project=project,
            guard=guard,
        )
        expected_response(
            report["checks"],
            "audience-mismatch",
            http_json(endpoint, token, guard),
            status=401,
            code="auth.audience_mismatch",
        )

        stage = "token-type-check"
        wrong_type = render_relay_config(
            token_profile,
            host_port=host_port,
            allowed_token_type="registry-smoke-invalid+jwt",
        )
        report["configuration_digests"]["wrong_token_type"] = start_relay(
            config_path,
            wrong_type,
            base_url=base_url,
            env=env,
            project=project,
            guard=guard,
        )
        expected_response(
            report["checks"],
            "token-type-denied",
            http_json(endpoint, token, guard),
            status=401,
            code="auth.malformed_credential",
        )

        stage = "organization-role-scope-check"
        wrong_org = render_relay_config(
            token_profile,
            host_port=host_port,
            required_org="registry-smoke-wrong-organization",
        )
        report["configuration_digests"]["wrong_organization"] = start_relay(
            config_path,
            wrong_org,
            base_url=base_url,
            env=env,
            project=project,
            guard=guard,
        )
        expected_response(
            report["checks"],
            "organization-role-scope-denied",
            http_json(endpoint, token, guard),
            status=403,
            code="auth.scope_denied",
        )
        report["result"] = "pass"
    except (SmokeError, UnicodeDecodeError, OSError) as exc:
        if isinstance(exc, SmokeError):
            primary_error = exc
        elif isinstance(exc, UnicodeDecodeError):
            primary_error = SmokeError("token was not ASCII")
        else:
            primary_error = SmokeError(f"local runtime operation failed: {exc}")
        report["result"] = (
            "fail" if isinstance(primary_error, CheckFailure) else "error"
        )
        report["failure_stage"] = stage
        report["diagnostic"] = guard.redact(str(primary_error))[:2_000]
    except KeyboardInterrupt:
        primary_error = SmokeError("run interrupted")
        report["result"] = "error"
        report["failure_stage"] = stage
        report["diagnostic"] = "run interrupted"
    finally:
        cleanup_error: SmokeError | None = None
        try:
            run_checked(
                compose_command(project, "down", "--volumes", "--remove-orphans"),
                env=env,
                guard=guard,
                timeout=180,
            )
            report["cleanup"] = "complete"
        except SmokeError as exc:
            cleanup_error = exc
            report["cleanup"] = "failed"
            if primary_error is None:
                primary_error = exc
                report["result"] = "error"
                report["failure_stage"] = "cleanup"
                report["diagnostic"] = guard.redact(str(exc))[:2_000]
        finally:
            shutil.rmtree(runtime_dir)
        report["completed_at"] = utc_now()
        report_path = safe_report(report, output_dir, guard)
        if cleanup_error and primary_error is not cleanup_error:
            print(
                guard.redact(f"relay-oidc-smoke: cleanup also failed: {cleanup_error}"),
                file=sys.stderr,
            )

    if primary_error:
        raise SmokeError(f"{primary_error}; unreviewed report: {report_path}")
    return report_path


def cmd_validate(args: argparse.Namespace) -> int:
    del args
    print(json.dumps(validate_assets(), indent=2, sort_keys=True))
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    print(
        json.dumps(
            plan_document(args.relay_image, args.candidate_source_ref, args.release_id),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    print(execute_live(args))
    return 0


def add_candidate_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--relay-image", required=True)
    parser.add_argument("--candidate-source-ref", required=True)
    parser.add_argument("--release-id", required=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser(
        "validate", help="validate checked-in topology without Docker or network access"
    )
    validate_parser.set_defaults(func=cmd_validate)

    plan_parser = subparsers.add_parser(
        "plan", help="render a candidate-bound offline execution plan"
    )
    add_candidate_args(plan_parser)
    plan_parser.set_defaults(func=cmd_plan)

    run_parser = subparsers.add_parser("run", help="run the live ephemeral smoke")
    add_candidate_args(run_parser)
    run_parser.add_argument("--host-port", type=int)
    run_parser.add_argument("--output-dir")
    run_parser.set_defaults(func=cmd_run)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        return int(args.func(args))
    except (OSError, SmokeError) as exc:
        print(f"relay-oidc-smoke: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
