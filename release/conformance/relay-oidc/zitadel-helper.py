#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provision and use the ephemeral Zitadel instance for the Relay OIDC smoke.

This helper runs inside the pinned Python container in docker-compose.yml. It
never prints a credential or bearer token. Secret-bearing files are written
atomically with mode 0600 into the runner-owned ephemeral runtime directory.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


BASE_URL = "http://localhost:8080"
MANAGEMENT_URL = f"{BASE_URL}/management/v1"
PAT_PATH = Path("/seed/bootstrap.pat")
PUBLIC_PATH = Path("/runtime/topology.json")
SECRET_PATH = Path("/runtime/topology-secret.json")
TOKEN_PATH = Path("/runtime/access-token")
MAX_RESPONSE_BYTES = 1_048_576
ROLE_KEY = "registry-smoke-reader"


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent credentials from being forwarded to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), NoRedirectHandler()
)


class HelperError(RuntimeError):
    """A bounded diagnostic safe to show without redaction."""


def read_bounded(response: Any) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > MAX_RESPONSE_BYTES:
                raise HelperError("Zitadel response exceeded the one MiB limit")
        except ValueError as exc:
            raise HelperError("Zitadel returned an invalid Content-Length") from exc
    body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise HelperError("Zitadel response exceeded the one MiB limit")
    return body


def request(
    method: str,
    url: str,
    *,
    bearer: str | None = None,
    org_id: str | None = None,
    json_body: dict[str, Any] | None = None,
    form_body: dict[str, str] | None = None,
    basic_auth: tuple[str, str] | None = None,
    accepted_statuses: tuple[int, ...] = (200,),
    parse_json: bool = True,
) -> dict[str, Any]:
    if json_body is not None and form_body is not None:
        raise HelperError("helper request cannot mix JSON and form bodies")
    headers = {"Accept": "application/json"}
    data: bytes | None = None
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if org_id:
        headers["x-zitadel-orgid"] = org_id
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
    elif form_body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form_body).encode("ascii")
    if basic_auth:
        encoded = base64.b64encode(f"{basic_auth[0]}:{basic_auth[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with NO_REDIRECT_OPENER.open(req, timeout=15) as response:
            status = response.status
            body = read_bounded(response)
    except urllib.error.HTTPError as exc:
        # Discard response bodies. Zitadel create responses can contain secrets,
        # and diagnostics do not need their unbounded or provider-controlled text.
        status = exc.code
        try:
            exc.read(MAX_RESPONSE_BYTES + 1)
        finally:
            exc.close()
        if 300 <= status < 400:
            raise HelperError(f"Zitadel API redirect refused for {method}") from None
        if status in accepted_statuses:
            return {}
        raise HelperError(f"Zitadel API returned HTTP {status} for {method}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise HelperError(f"Zitadel API transport failed for {method}") from None

    if status not in accepted_statuses:
        raise HelperError(f"Zitadel API returned unexpected HTTP {status} for {method}")
    if not parse_json or not body:
        return {}
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        raise HelperError("Zitadel API returned malformed JSON") from None
    if not isinstance(parsed, dict):
        raise HelperError("Zitadel API response was not an object")
    return parsed


def wait_ready() -> None:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            request("GET", f"{BASE_URL}/debug/healthz", parse_json=False)
            pat = read_pat()
            request(
                "POST",
                f"{MANAGEMENT_URL}/projects/_search",
                bearer=pat,
                json_body={"queries": []},
            )
            return
        except (HelperError, OSError):
            pass
        time.sleep(2)
    raise HelperError("Zitadel or its bootstrap PAT did not become ready")


def read_pat() -> str:
    try:
        raw = PAT_PATH.read_bytes()
    except OSError:
        raise HelperError("Zitadel bootstrap PAT is unavailable") from None
    if len(raw) > 16_384:
        raise HelperError("Zitadel bootstrap PAT exceeded the size limit")
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise HelperError("Zitadel bootstrap PAT was not ASCII") from None
    if not value or any(char.isspace() for char in value):
        raise HelperError("Zitadel bootstrap PAT was empty or malformed")
    return value


def nested_string(value: dict[str, Any], *path: str) -> str:
    current: Any = value
    for part in path:
        if not isinstance(current, dict):
            raise HelperError(f"Zitadel response omitted {'.'.join(path)}")
        current = current.get(part)
    if not isinstance(current, str) or not current:
        raise HelperError(f"Zitadel response omitted {'.'.join(path)}")
    return current


def runtime_owner() -> tuple[int, int]:
    raw_uid = os.environ.get("REGISTRY_RELAY_OIDC_SMOKE_RUNTIME_UID", "")
    raw_gid = os.environ.get("REGISTRY_RELAY_OIDC_SMOKE_RUNTIME_GID", "")
    if not raw_uid.isdigit() or not raw_gid.isdigit():
        raise HelperError("runner runtime uid and gid must be decimal integers")
    uid = int(raw_uid)
    gid = int(raw_gid)
    if uid > 2**32 - 2 or gid > 2**32 - 2:
        raise HelperError("runner runtime uid or gid is outside the supported range")
    return uid, gid


def atomic_json(path: Path, payload: dict[str, Any], mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, *runtime_owner())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_secret(path: Path, value: str) -> None:
    if not value or "\n" in value or "\r" in value:
        raise HelperError("refusing to write an empty or multiline secret")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.chown(temporary, *runtime_owner())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def provision() -> None:
    wait_ready()
    pat = read_pat()
    run_id = os.environ.get("REGISTRY_RELAY_OIDC_SMOKE_RUN_ID", "")
    canary = os.environ.get("REGISTRY_RELAY_OIDC_SMOKE_SECRET_CANARY", "")
    if not run_id or not canary:
        raise HelperError("runner identity and secret canary are required")
    project_name = f"Registry Relay release smoke {run_id}"
    service_username = f"relay-smoke-{run_id}"

    project = request(
        "POST",
        f"{MANAGEMENT_URL}/projects",
        bearer=pat,
        json_body={"name": project_name, "projectRoleAssertion": True},
    )
    project_id = nested_string(project, "id")
    detail = request("GET", f"{MANAGEMENT_URL}/projects/{project_id}", bearer=pat)
    project_org_id = nested_string(detail, "project", "details", "resourceOwner")

    request(
        "POST",
        f"{MANAGEMENT_URL}/projects/{project_id}/roles",
        bearer=pat,
        org_id=project_org_id,
        json_body={
            "roleKey": ROLE_KEY,
            "displayName": "Registry smoke metadata reader",
            "group": "registry-relay",
        },
    )

    service = request(
        "POST",
        f"{MANAGEMENT_URL}/users/machine",
        bearer=pat,
        org_id=project_org_id,
        json_body={
            "userName": service_username,
            "name": "Registry Relay smoke client",
            "description": "Ephemeral client for release verification",
        },
    )
    service_id = nested_string(service, "userId")
    service_detail = request(
        "GET",
        f"{MANAGEMENT_URL}/users/{service_id}",
        bearer=pat,
        org_id=project_org_id,
    )
    service_org_id = nested_string(service_detail, "user", "details", "resourceOwner")
    request(
        "PUT",
        f"{MANAGEMENT_URL}/users/{service_id}/machine",
        bearer=pat,
        org_id=service_org_id,
        json_body={
            "name": "Registry Relay smoke client",
            "description": "Ephemeral client for release verification",
            "accessTokenType": 1,
        },
    )
    generated_secret = request(
        "PUT",
        f"{MANAGEMENT_URL}/users/{service_id}/secret",
        bearer=pat,
        org_id=service_org_id,
        json_body={},
    )
    client_id = nested_string(generated_secret, "clientId")
    client_secret = nested_string(generated_secret, "clientSecret")

    request(
        "POST",
        f"{MANAGEMENT_URL}/users/{service_id}/grants",
        bearer=pat,
        org_id=project_org_id,
        json_body={"projectId": project_id, "roleKeys": [ROLE_KEY]},
    )

    atomic_json(
        PUBLIC_PATH,
        {
            "client_id": client_id,
            "issuer": BASE_URL,
            "project_id": project_id,
            "project_org_id": project_org_id,
            "role_key": ROLE_KEY,
            "service_account_id": service_id,
            "service_account_org_id": service_org_id,
        },
        0o644,
    )
    atomic_json(
        SECRET_PATH,
        {"client_id": client_id, "client_secret": client_secret, "canary": canary},
        0o600,
    )
    print("zitadel-helper: ephemeral project, role, and service account provisioned")


def load_json(path: Path, *, secret: bool = False) -> dict[str, Any]:
    try:
        if secret and path.stat().st_mode & 0o077:
            raise HelperError("secret runtime file permissions are too broad")
        raw = path.read_bytes()
    except OSError:
        raise HelperError(
            f"required runtime file is unavailable: {path.name}"
        ) from None
    if len(raw) > 65_536:
        raise HelperError(f"runtime file exceeded size limit: {path.name}")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise HelperError(f"runtime file is malformed: {path.name}") from None
    if not isinstance(value, dict):
        raise HelperError(f"runtime file is not an object: {path.name}")
    return value


def mint() -> None:
    public = load_json(PUBLIC_PATH)
    secret = load_json(SECRET_PATH, secret=True)
    project_id = nested_string(public, "project_id")
    role_key = nested_string(public, "role_key")
    client_id = nested_string(secret, "client_id")
    client_secret = nested_string(secret, "client_secret")
    if client_id != nested_string(public, "client_id"):
        raise HelperError("public and secret client identifiers differ")
    scope = " ".join(
        [
            "openid",
            f"urn:zitadel:iam:org:project:id:{project_id}:aud",
            f"urn:zitadel:iam:org:project:role:{role_key}",
        ]
    )
    response = request(
        "POST",
        f"{BASE_URL}/oauth/v2/token",
        form_body={"grant_type": "client_credentials", "scope": scope},
        basic_auth=(client_id, client_secret),
    )
    token = nested_string(response, "access_token")
    if response.get("token_type") != "Bearer":
        raise HelperError("Zitadel token endpoint did not return a Bearer token")
    atomic_secret(TOKEN_PATH, token)
    print("zitadel-helper: bearer token written to the private runtime file")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("provision", "mint"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "provision":
            provision()
        else:
            mint()
        return 0
    except HelperError as exc:
        print(f"zitadel-helper: {exc}", file=os.sys.stderr)
        return 2
    except Exception:
        # The helper deliberately suppresses unexpected exception details: API
        # responses and local variables can hold credentials. The runner still
        # receives a failing status and can inspect provider logs locally.
        print("zitadel-helper: unexpected internal failure", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
