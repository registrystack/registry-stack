#!/usr/bin/env python3
"""Small helpers for the Base Registry Engine local quickstart."""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import socket
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


AUDIENCE = "urn:breg:quickstart"
CLIENT_ID = "generic-quickstart"
READER_CLIENT_ID = "record-reader-quickstart"
DIRECTORY_CLIENT_ID = "directory-reader-quickstart"
SITE_READER_CLIENT_ID = "site-reader-quickstart"
QGIS_CLIENT_ID = "qgis-installation-central"
DATABASE_ID = "generic-registry-local-db"
INSTANCE_ID = "generic_registry_local"
RUNTIME_DATABASE = "registry_quickstart"
TEST_DATABASE = "registry_quickstart_test"
MIGRATION_ROLE = "registry_quickstart_migration"
RUNTIME_ROLE = "registry_quickstart_runtime"
SPATIAL_BBOX_ROLE = "registry_quickstart_runtime__spatial_bbox"
SOURCE_REVISION = "quickstart-source"
OPERATOR_PURPOSE = "registry-operations"
READER_PURPOSE = "registry-reporting"
READER_ROW_BOUNDARY_STATUS = "active"
SPATIAL_OPERATOR_PURPOSE = "service-site-administration"
SPATIAL_MAP_PURPOSE = "service-site-map"
SPATIAL_DIRECTORY_PURPOSE = "service-site-directory"
GENERIC_TOKEN_LIFETIME_SECONDS = 300
SPATIAL_TOKEN_LIFETIME_SECONDS = 60


# The generic project's journeys use one access profile per step, and each
# profile needs its own credential because their scopes and purposes differ.
GENERIC_PROFILE_TOKENS = {
    "operator": "schema-test-token",
    "record-reader": "reader-schema-test-token",
}


class QuickstartError(RuntimeError):
    pass


def _write_new(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)
    path.chmod(mode)


def _write_json(path: Path, value: Any, mode: int = 0o644) -> None:
    _write_new(path, json.dumps(value, sort_keys=True, separators=(",", ":")), mode)


def _read_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise QuickstartError(f"{path.name} must contain one JSON object")
    return value


def _require_root(root: Path) -> Path:
    if root.is_symlink():
        raise QuickstartError("quickstart root must not be a symbolic link")
    resolved = root.resolve()
    if not resolved.is_dir():
        raise QuickstartError("quickstart root must be an existing ordinary directory")
    return resolved


def _require_owner_only_regular(path: Path, name: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise QuickstartError(f"{name} must be an owner-only regular file")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise QuickstartError(f"{name} must be an owner-only regular file")


def reserve_ports() -> tuple[int, int, int]:
    listeners: list[socket.socket] = []
    try:
        for _ in range(3):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listeners.append(listener)
        return tuple(listener.getsockname()[1] for listener in listeners)  # type: ignore[return-value]
    finally:
        for listener in listeners:
            listener.close()


def _render_claims(claims: dict[str, Any]) -> str:
    return "".join(
        f"    {name}: {json.dumps(value, ensure_ascii=True, separators=(',', ':'))}\n"
        for name, value in sorted(claims.items())
    )


def _mint_private_key_client(
    client_id: str,
    public_key: dict[str, Any],
    scopes: list[str],
    claims: dict[str, Any],
) -> str:
    return (
        f"clientId: {client_id}\n"
        f"principal: urn:breg:quickstart:{client_id}\n"
        "authorization:\n"
        f"  scopes: {json.dumps(scopes, separators=(',', ':'))}\n"
        "  claims:\n"
        f"{_render_claims(claims)}"
        f"keys: [{json.dumps(public_key, sort_keys=True, separators=(',', ':'))}]\n"
    )


def _mint_client(public_key: dict[str, Any], spatial: bool) -> str:
    if spatial:
        return _mint_private_key_client(
            CLIENT_ID,
            public_key,
            ["service-sites:seed"],
            {
                "registry_principal": "synthetic-service-site-admin",
                "registry_purpose": SPATIAL_OPERATOR_PURPOSE,
            },
        )
    return _mint_private_key_client(
        CLIENT_ID,
        public_key,
        ["registry:generic:operate"],
        {
            "registry_principal": "generic-registry-operator",
            "registry_purpose": OPERATOR_PURPOSE,
        },
    )


def _generic_reader_client(public_key: dict[str, Any]) -> str:
    return _mint_private_key_client(
        READER_CLIENT_ID,
        public_key,
        ["registry:generic:read"],
        {
            "registry_principal": "generic-registry-reader",
            "registry_purpose": READER_PURPOSE,
            "registry_record_status": READER_ROW_BOUNDARY_STATUS,
        },
    )


def _spatial_reader_clients(public_key: dict[str, Any]) -> dict[str, str]:
    return {
        DIRECTORY_CLIENT_ID: _mint_private_key_client(
            DIRECTORY_CLIENT_ID,
            public_key,
            ["service-sites:directory.read"],
            {
                "registry_principal": "synthetic-directory-reader",
                "registry_purpose": SPATIAL_DIRECTORY_PURPOSE,
            },
        ),
        SITE_READER_CLIENT_ID: _mint_private_key_client(
            SITE_READER_CLIENT_ID,
            public_key,
            ["service-sites:site.read"],
            {
                "registry_principal": "synthetic-site-reader",
                "registry_purpose": SPATIAL_MAP_PURPOSE,
            },
        ),
    }


def _mint_client_secret_client(fingerprint: str) -> str:
    if not fingerprint or any(character.isspace() for character in fingerprint):
        raise QuickstartError("QGIS client secret fingerprint must be one non-empty token")
    return (
        f"clientId: {QGIS_CLIENT_ID}\n"
        f"principal: urn:breg:quickstart:{QGIS_CLIENT_ID}\n"
        "authorization:\n"
        '  scopes: ["service-sites:map.read"]\n'
        "  claims:\n"
        "    registry_principal: synthetic-qgis-installation\n"
        f"    registry_purpose: {SPATIAL_MAP_PURPOSE}\n"
        "    service_zones: central\n"
        "clientAuthentication:\n"
        "  method: client-secret\n"
        f"  secretFingerprints: [{json.dumps(fingerprint)}]\n"
    )


def _template_text(root: Path, revision: str, package_root: Path, runtime_database: bool, spatial: bool) -> str:
    origin = urllib.parse.urlparse((root / "breg-origin").read_text(encoding="ascii").strip())
    mint_origin = (root / "mint-origin").read_text(encoding="ascii").strip()
    if origin.scheme != "http" or origin.hostname != "127.0.0.1" or origin.port is None:
        raise QuickstartError("server origin must be exact loopback HTTP")
    if not revision.startswith("sha256:") or len(revision) != 71:
        raise QuickstartError("package revision must be one SHA-256 identifier")
    runtime_ref = "secret:file/runtime-database-url"
    migration_ref = "secret:file/migration-database-url"
    if not runtime_database:
        runtime_ref = "secret:file/test-runtime-database-url"
        migration_ref = "secret:file/test-migration-database-url"
    allowed_clients = [CLIENT_ID]
    if spatial:
        allowed_clients.extend([QGIS_CLIENT_ID, DIRECTORY_CLIENT_ID, SITE_READER_CLIENT_ID])
    else:
        allowed_clients.append(READER_CLIENT_ID)
    allowed_clients_yaml = ", ".join(allowed_clients)
    return f"""apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:{origin.port}
{f'  publicOrigin: http://127.0.0.1:{origin.port}\n' if spatial else ''}identity:
  environment: local
  instanceId: {INSTANCE_ID}
  databaseId: {DATABASE_ID}
  databaseInitializationEnvironment: local
secretProviders:
  file:
    root: {root / 'secrets'}
database:
  runtimeUrlRef: {runtime_ref}
  migrationUrlRef: {migration_ref}
  pool:
    maxSize: 4
  roles:
    migration: {MIGRATION_ROLE}
    runtime: {RUNTIME_ROLE}
package:
  root: {package_root}
  trustAnchorPath: {root / 'trust-anchor.json'}
  compilerSourceRevision: {SOURCE_REVISION}
  activeRevision: {revision}
  activeSequence: 1
authentication:
  oidc:
    issuer: {mint_origin}
    audience: {AUDIENCE}
    allowedAlgorithm: ES256
    accessTokenType: at+jwt
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [{allowed_clients_yaml}]
    deniedKids: []
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 30000
    jwksSource:
      kind: static
      documentRef: secret:file/mint-jwks
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
eventDestinations: {{}}
"""


def _journey_credentials(root: Path, profile_tokens: dict[str, str]) -> str:
    path = root / "project/tests/journeys.yaml"
    source = path.read_text(encoding="utf-8")
    journey = None
    steps: list[tuple[str, str]] = []
    pending: str | None = None
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("- id: ") and journey is None:
            journey = stripped.removeprefix("- id: ").strip()
        elif stripped.startswith("- id: "):
            pending = stripped.removeprefix("- id: ").strip()
        elif stripped.startswith("accessProfile: ") and pending is not None:
            steps.append((pending, stripped.removeprefix("accessProfile: ").strip()))
            pending = None
    named = {step for step, _ in steps}
    if not journey or not {"create-record", "get-record", "list-records"}.issubset(named):
        raise QuickstartError("bregctl init changed its generic journey shape")
    if pending is not None or len(named) != len(steps):
        raise QuickstartError("bregctl init emitted a journey step without one access profile")
    unbound = sorted({profile for _, profile in steps} - set(profile_tokens))
    if unbound:
        raise QuickstartError(
            f"bregctl init added access profiles the quickstart has no client for: {', '.join(unbound)}"
        )
    bindings = "\n".join(
        f"  - {{journeyId: {journey}, stepId: {step}, credential: {{type: bearer, tokenRef: secret:file/{profile_tokens[profile]}}}}}"
        for step, profile in steps
    )
    return (
        "apiVersion: registry.registrystack.org/breg-schema-test-credentials/v1\n"
        "kind: SchemaTestCredentials\n"
        "bindings:\n"
        f"{bindings}\n"
    )


def _spatial_journey_credentials() -> str:
    bearer_bindings = {
        "create-central-service-site": "schema-test-token",
        "create-null-geometry-service-site": "schema-test-token",
        "create-edge-service-site": "schema-test-token",
        "admin-refuses-coordinate-outside-authored-bounds": "schema-test-token",
        "installation-client-sees-own-central-row": "map-schema-test-token",
        "installation-client-cannot-see-other-installation-row": "map-schema-test-token",
        "hidden-geometry-profile-gets-directory-fields": "directory-schema-test-token",
        "get-only-profile-gets-site": "site-schema-test-token",
    }
    anonymous_bindings = [
        "public-map-reader-lists-public-point-fields",
        "public-map-reader-bbox-finds-central-site",
        "directory-reader-lists-without-geometry",
        "directory-reader-bbox-is-refused",
    ]
    rendered = [
        "apiVersion: registry.registrystack.org/breg-schema-test-credentials/v1",
        "kind: SchemaTestCredentials",
        "bindings:",
    ]
    for step in anonymous_bindings:
        rendered.append(
            "  - {journeyId: service-site-source-profile-smoke, "
            f"stepId: {step}, credential: {{type: anonymous}}}}"
        )
    for step, token in bearer_bindings.items():
        rendered.append(
            "  - {journeyId: service-site-source-profile-smoke, "
            f"stepId: {step}, credential: {{type: bearer, tokenRef: secret:file/{token}}}}}"
        )
    return "\n".join(rendered) + "\n"


def _initialize_sql(database: str, spatial: bool) -> str:
    statements = [
        "CREATE EXTENSION IF NOT EXISTS btree_gist;",
        f"REVOKE ALL ON DATABASE {database} FROM PUBLIC;",
        f"GRANT CONNECT ON DATABASE {database} TO {MIGRATION_ROLE}, {RUNTIME_ROLE};",
        f"CREATE SCHEMA registry_internal AUTHORIZATION {MIGRATION_ROLE};",
        f"CREATE SCHEMA registry_data AUTHORIZATION {MIGRATION_ROLE};",
        f"CREATE SCHEMA registry_source AUTHORIZATION {MIGRATION_ROLE};",
        f"CREATE SCHEMA registry_derived AUTHORIZATION {MIGRATION_ROLE};",
        f"CREATE SCHEMA registry_context AUTHORIZATION {MIGRATION_ROLE};",
        "REVOKE ALL ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context FROM PUBLIC;",
    ]
    if spatial:
        statements[1:1] = [
            "CREATE SCHEMA registry_spatial_ext AUTHORIZATION postgres;",
            "CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA registry_spatial_ext;",
            f"REVOKE CREATE ON DATABASE {database} FROM PUBLIC, {MIGRATION_ROLE}, {RUNTIME_ROLE};",
            "REVOKE ALL ON SCHEMA registry_spatial_ext FROM PUBLIC;",
            f"GRANT USAGE ON SCHEMA registry_spatial_ext TO {MIGRATION_ROLE}, {RUNTIME_ROLE}, {SPATIAL_BBOX_ROLE};",
        ]
    return "\n".join(statements) + "\n"


def prepare(
    root: Path,
    database_port: int,
    mint_port: int,
    breg_port: int,
    spatial: bool = False,
    qgis_client_secret_fingerprint: str | None = None,
) -> None:
    root = _require_root(root)
    project = root / "project"
    if not (project / "registry.yaml").is_file():
        raise QuickstartError("registry project did not create registry.yaml")
    if spatial and not qgis_client_secret_fingerprint:
        raise QuickstartError("spatial quickstart requires a QGIS client secret fingerprint")
    password = (root / "secrets/database-password").read_text(encoding="ascii").strip()
    if not password or any(character not in "0123456789abcdef" for character in password):
        raise QuickstartError("database password must be non-empty lowercase hexadecimal")
    mint_public = _read_json_object(root / "keys/mint-public.jwk.json")
    operator_public = _read_json_object(root / "keys/operator-public.jwk.json")
    kid = mint_public.get("kid")
    if not isinstance(kid, str) or not kid:
        raise QuickstartError("Mint public JWK must carry a key identifier")
    mint_origin = f"http://127.0.0.1:{mint_port}"
    breg_origin = f"http://127.0.0.1:{breg_port}"
    _write_new(root / "mint-origin", mint_origin + "\n")
    _write_new(root / "breg-origin", breg_origin + "\n")
    _write_json(root / "secrets/mint-jwks", {"keys": [mint_public]}, 0o600)
    _write_json(root / f"mint/public-keys/{kid}.jwk.json", mint_public)
    _write_new(root / f"mint/clients/{CLIENT_ID}.yaml", _mint_client(operator_public, spatial))
    if not spatial:
        _write_new(
            root / f"mint/clients/{READER_CLIENT_ID}.yaml",
            _generic_reader_client(operator_public),
        )
    if spatial:
        assert qgis_client_secret_fingerprint is not None
        _write_new(root / f"mint/clients/{QGIS_CLIENT_ID}.yaml", _mint_client_secret_client(qgis_client_secret_fingerprint))
        for client_id, document in _spatial_reader_clients(operator_public).items():
            _write_new(root / f"mint/clients/{client_id}.yaml", document)
    token_lifetime_seconds = SPATIAL_TOKEN_LIFETIME_SECONDS if spatial else GENERIC_TOKEN_LIFETIME_SECONDS
    _write_new(
        root / "mint/mint.yaml",
        f"""version: 1
validationMode: supervised-local-development
issuer: {mint_origin}
listener: {{address: 127.0.0.1, port: {mint_port}}}
signing:
  algorithm: ES256
  activePublicJwkFile: public-keys/{kid}.jwk.json
  publishedPublicJwkFiles: []
  revokedKeyIds: []
signer:
  kind: local-jwk
  privateKeyRef: secret:file/signing-p256-private-jwk
secretProviders:
  file: {{root: {root / 'keys/mint'}}}
audit:
  path: audit/mint.jsonl
  maximumFileBytes: 10485760
  hashKeyRef: secret:file/audit-hmac-key
  hashKeyVersion: 1
accessTokens:
  audiences: [{AUDIENCE}]
  lifetimeSeconds: {token_lifetime_seconds}
clientAssertion:
  audience: {mint_origin}/token
  maximumLifetimeSeconds: 120
  algorithms: [ES256]
clients:
  directory: clients
""",
    )
    encoded_password = urllib.parse.quote(password, safe="")
    base = f"localhost:{database_port}"
    _write_new(
        root / "secrets/test-runtime-database-url",
        f"postgresql://{RUNTIME_ROLE}:{encoded_password}@{base}/{TEST_DATABASE}",
        0o600,
    )
    _write_new(
        root / "secrets/test-migration-database-url",
        f"postgresql://{MIGRATION_ROLE}:{encoded_password}@{base}/{TEST_DATABASE}",
        0o600,
    )
    _write_new(
        root / "secrets/runtime-database-url",
        f"postgresql://{RUNTIME_ROLE}:{encoded_password}@{base}/{RUNTIME_DATABASE}",
        0o600,
    )
    _write_new(
        root / "secrets/migration-database-url",
        f"postgresql://{MIGRATION_ROLE}:{encoded_password}@{base}/{RUNTIME_DATABASE}",
        0o600,
    )
    _write_new(
        root / "database/postgres.env",
        f"POSTGRES_USER=postgres\nPOSTGRES_PASSWORD={password}\nPOSTGRES_DB=postgres\n",
        0o600,
    )
    bootstrap_sql = f"""CREATE ROLE {MIGRATION_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{password}';
CREATE ROLE {RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{password}';
"""
    if spatial:
        bootstrap_sql += f"""CREATE ROLE {SPATIAL_BBOX_ROLE} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
GRANT {SPATIAL_BBOX_ROLE} TO {MIGRATION_ROLE} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;
"""
    _write_new(root / "database/bootstrap.sql", bootstrap_sql, 0o600)
    _write_new(root / "database/initialize.sql", _initialize_sql(TEST_DATABASE, spatial))
    _write_new(root / "database/initialize-runtime.sql", _initialize_sql(RUNTIME_DATABASE, spatial))
    _write_new(root / "trust-anchor.json", "{}")
    (root / "empty-package").mkdir(mode=0o755)
    _write_new(
        root / "runtime-test.yaml",
        _template_text(root, "sha256:" + "1" * 64, root / "empty-package", False, spatial),
    )
    credentials = _spatial_journey_credentials() if spatial else _journey_credentials(root, GENERIC_PROFILE_TOKENS)
    _write_new(root / "schema-test-credentials.yaml", credentials)


def assert_canonical_project(project: Path) -> None:
    if project.is_symlink() or not project.is_dir():
        raise QuickstartError("project must be an ordinary directory")
    path = project / "registry.yaml"
    source = path.read_text(encoding="utf-8")
    if "    purposes: " in source or "        actions: " in source:
        raise QuickstartError(
            "bregctl init emitted legacy access-profile keys; expected requiredPurposes and operations"
        )
    if "    requiredPurposes: [registry-operations]\n" not in source:
        raise QuickstartError("bregctl init output is missing requiredPurposes")
    if "    requiredScopes: [registry:generic:operate]\n" not in source:
        raise QuickstartError("bregctl init output is missing requiredScopes")
    if "        operations: [create, get, list, patch]\n" not in source:
        raise QuickstartError("bregctl init output is missing grant operations")
    if "    requiredScopes: [registry:generic:read]\n" not in source:
        raise QuickstartError("bregctl init output is missing the reader scope")
    if "    requiredPurposes: [registry-reporting]\n" not in source:
        raise QuickstartError("bregctl init output is missing the reader purpose")


def enrich_local_package(project: Path) -> None:
    if project.is_symlink() or not project.is_dir():
        raise QuickstartError("project must be an ordinary directory")
    path = project / "registry.yaml"
    source = path.read_text(encoding="utf-8")
    if "\nmanifestProjection:\n" not in f"\n{source}":
        raise QuickstartError("bregctl init output is missing manifestProjection")
    lines = source.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if line.rstrip("\n") == "package:"]
    if len(starts) != 1:
        raise QuickstartError("bregctl init output has no single package identity block")
    start = starts[0]
    end = start + 1
    while end < len(lines) and lines[end].startswith(" "):
        end += 1
    if not any(line.strip().startswith("sourceRevision:") for line in lines[start:end]):
        raise QuickstartError("bregctl init package identity has no source revision")
    package = (
        "package:\n"
        "  environment: local\n"
        f"  instanceId: {INSTANCE_ID}\n"
        "  sequence: 1\n"
        f"  sourceRevision: {SOURCE_REVISION}\n"
    )
    path.write_text("".join(lines[:start]) + package + "".join(lines[end:]), encoding="utf-8")


def prepare_spatial_project(fixture: Path, project: Path) -> None:
    if fixture.is_symlink() or not fixture.is_dir():
        raise QuickstartError("spatial fixture must be an ordinary directory")
    for child in fixture.rglob("*"):
        if child.is_symlink():
            raise QuickstartError("spatial fixture must not contain symbolic links")
    if project.exists():
        raise QuickstartError("spatial project output must not already exist")
    fixture = fixture.resolve()
    project_parent = project.parent.resolve()
    if project_parent.is_symlink() or not project_parent.is_dir():
        raise QuickstartError("spatial project parent must be an ordinary directory")
    shutil.copytree(fixture, project, symlinks=False)
    path = project / "registry.yaml"
    source = path.read_text(encoding="utf-8")
    start = source.find("\npackage:\n")
    end = source.find("\nmanifestProjection:\n")
    if start < 0 or end < 0 or end <= start:
        raise QuickstartError("spatial fixture must contain package before manifestProjection")
    package = (
        "\npackage:\n"
        "  environment: local\n"
        f"  instanceId: {INSTANCE_ID}\n"
        "  sequence: 1\n"
        f"  sourceRevision: {SOURCE_REVISION}\n"
    )
    path.write_text(source[:start] + package + source[end:], encoding="utf-8")


def render_runtime(root: Path, revision: str, spatial: bool = False) -> None:
    root = _require_root(root)
    _write_new(root / "runtime.yaml", _template_text(root, revision, root / "build/package", True, spatial))


def store_token(path: Path, source: bytes) -> None:
    if len(source) > 64 * 1024:
        raise QuickstartError("Mint returned an oversized token")
    try:
        value = source.decode("ascii").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise QuickstartError("Mint returned a non-ASCII token") from error
    if value.count(".") != 2 or any(character.isspace() for character in value):
        raise QuickstartError("Mint did not return one compact JWT")
    _write_new(path, value, 0o600)


def wait_http(url: str, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    last: int | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                last = response.status
        except urllib.error.HTTPError as error:
            last = error.code
        except Exception:
            last = None
        if last == 200:
            return
        time.sleep(0.25)
    raise QuickstartError(f"{url} did not become ready; last status was {last}")


def json_field(path: Path, field: str) -> None:
    value: Any = _read_json_object(path)
    for part in field.split("."):
        if not isinstance(value, dict):
            raise QuickstartError(f"{field} did not resolve to a scalar")
        value = value[part]
    if not isinstance(value, (str, int, float, bool)):
        raise QuickstartError(f"{field} did not resolve to a scalar")
    print(value)


def _token(root: Path, token_name: str = "operator-token") -> str:
    path = root / f"secrets/{token_name}"
    _require_owner_only_regular(path, token_name)
    value = path.read_text(encoding="ascii").strip()
    if value.count(".") != 2:
        raise QuickstartError(f"{token_name} does not contain one compact JWT")
    return value


def _request(
    root: Path,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    idempotency_key: str | None = None,
    expected: int = 200,
    token_name: str = "operator-token",
    accept: str = "application/json",
) -> dict[str, Any]:
    origin = (root / "breg-origin").read_text(encoding="ascii").strip()
    headers = {"Accept": accept, "Authorization": f"Bearer {_token(root, token_name)}"}
    data = None
    if body is not None:
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    request = urllib.request.Request(origin + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response_bytes = response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        response_bytes = error.read()
        status = error.code
    if status != expected:
        raise QuickstartError(f"{method} {path} returned {status}, expected {expected}")
    document = json.loads(response_bytes) if response_bytes else {}
    if not isinstance(document, dict):
        raise QuickstartError(f"{method} {path} returned a non-object JSON response")
    return document


def request(root: Path, action: str, code: str | None, label: str | None, record_id: str | None) -> None:
    root = _require_root(root)
    if action == "create":
        if not code or not label:
            raise QuickstartError("create requires code and label")
        document = _request(
            root,
            "POST",
            "/v1/records/records?accessProfile=operator",
            {"data": {"code": code, "label": label}},
            f"quickstart-{code}",
            201,
        )
        record = document.get("data")
        identifier = record.get("recordIdentifier") if isinstance(record, dict) else None
        if not isinstance(identifier, str) or not identifier:
            raise QuickstartError("created record has no data.recordIdentifier")
        print(identifier)
    elif action == "get":
        if not record_id:
            raise QuickstartError("get requires a record id")
        document = _request(
            root,
            "GET",
            f"/v1/records/records/{urllib.parse.quote(record_id, safe='')}?accessProfile=operator",
            None,
        )
        print(json.dumps(document, indent=2, sort_keys=True))
    elif action == "list":
        document = _request(root, "GET", "/v1/records/records?accessProfile=operator&$top=10", None)
        print(json.dumps(document, indent=2, sort_keys=True))
    else:
        raise QuickstartError("unknown request action")


def _seed_payloads(seed: Path) -> list[dict[str, Any]]:
    if seed.is_symlink() or not seed.is_file():
        raise QuickstartError("spatial seed input must be an ordinary JSONL file")
    payloads: list[dict[str, Any]] = []
    for line_number, line in enumerate(seed.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict) or value.get("operation") != "create" or not isinstance(value.get("data"), dict):
            raise QuickstartError(f"spatial seed line {line_number} must be a create operation with object data")
        payloads.append(value["data"])
    if len(payloads) < 200:
        raise QuickstartError("spatial seed must contain the multi-page synthetic fixture")
    return payloads


def spatial_smoke(root: Path, seed: Path, operator_token_name: str = "operator-token") -> None:
    root = _require_root(root)
    payloads = _seed_payloads(seed)
    for index, data in enumerate(payloads, start=1):
        _request(
            root,
            "POST",
            "/v1/records/service-sites?accessProfile=service-site-admin",
            {"data": data},
            f"quickstart-spatial-{index:03d}",
            201,
            operator_token_name,
        )
    bbox = urllib.parse.quote("100.45,13.60,100.60,13.80", safe=",")
    list_document = _request(
        root,
        "GET",
        f"/v1/records/service-sites?accessProfile=installation-map-reader&bbox={bbox}&$top=25",
        None,
        token_name="map-token",
    )
    rows = list_document.get("items")
    if not isinstance(rows, list) or not rows:
        raise QuickstartError("spatial bbox record list returned no visible rows")
    geojson = _request(
        root,
        "GET",
        f"/v1/records/service-sites?accessProfile=installation-map-reader&bbox={bbox}&$top=25",
        None,
        token_name="map-token",
        accept="application/geo+json",
    )
    if geojson.get("type") != "FeatureCollection" or not isinstance(geojson.get("features"), list):
        raise QuickstartError("spatial bbox record request did not return a GeoJSON FeatureCollection")
    gis = _request(
        root,
        "GET",
        f"/v1/gis/collections/service-site.installation-map-reader/items?bbox={bbox}&limit=25&f=json",
        None,
        token_name="map-token",
        accept="application/geo+json",
    )
    if gis.get("type") != "FeatureCollection" or not isinstance(gis.get("features"), list):
        raise QuickstartError("QGIS OAPIF items request did not return a GeoJSON FeatureCollection")


def mint_client_secret_token(url: str, client_id: str, secret_path: Path, out: Path) -> None:
    _require_owner_only_regular(secret_path, "QGIS client secret")
    secret = secret_path.read_text(encoding="ascii").strip()
    if not secret or any(character.isspace() for character in secret):
        raise QuickstartError("QGIS client secret must be one non-empty token")
    userpass = f"{urllib.parse.quote(client_id, safe='')}:{urllib.parse.quote(secret, safe='')}"
    headers = {
        "Authorization": "Basic " + base64.b64encode(userpass.encode("ascii")).decode("ascii"),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    body = urllib.parse.urlencode({"grant_type": "client_credentials"}).encode("ascii")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            document = json.loads(response.read())
            status = response.status
    except urllib.error.HTTPError as error:
        document = json.loads(error.read() or b"{}")
        status = error.code
    if status != 200 or not isinstance(document, dict):
        raise QuickstartError(f"Mint client-secret token request returned {status}")
    token = document.get("access_token")
    if not isinstance(token, str):
        raise QuickstartError("Mint client-secret response did not contain an access_token")
    store_token(out, token.encode("ascii"))


def self_test(quickstart_dir: Path) -> None:
    quickstart_dir = quickstart_dir.resolve()
    required = [
        "run.sh",
        "query.sh",
        "self-test.sh",
        ".gitignore",
        "support/quickstart.py",
    ]
    for relative in required:
        if not (quickstart_dir / relative).is_file():
            raise QuickstartError(f"missing quickstart file: {relative}")
    run_source = (quickstart_dir / "run.sh").read_text(encoding="utf-8")
    query_source = (quickstart_dir / "query.sh").read_text(encoding="utf-8")
    readme_source = (quickstart_dir / "README.md").read_text(encoding="utf-8")
    helper_source = (quickstart_dir / "support/quickstart.py").read_text(encoding="utf-8")
    required_needles = [
        ('"$bregctl" --format json init "$run_dir/project"', run_source),
        ('assert-canonical-project --project "$run_dir/project"', run_source),
        ('enrich-local-package --project "$run_dir/project"', run_source),
        ('"$bregctl" --format json check "$run_dir/project"', run_source),
        ('"$mint" token', run_source),
        ('store-token --out "$run_dir/secrets/$operator_token_name"', run_source),
        ("--spatial", run_source),
        ("prepare-spatial-project", run_source),
        ("postgis/postgis@sha256:01a6a70e41e6c4467c8f55f6063555ed72db2d6662cd0d571040d42eadaeb6f6", run_source),
        ("--platform linux/amd64", run_source),
        ("mint-client-secret-token", run_source),
        ("spatial-smoke", run_source),
        ("--operator-token-name", run_source),
        ("operator-token-$(openssl rand -hex 8)", run_source),
        ("databaseInitializationEnvironment: local", helper_source),
        ("apiVersion: registry.registrystack.org/breg-runtime/v1alpha1", helper_source),
        ("kind: BRegRuntimeConfig", helper_source),
        ('INSTANCE_ID = "generic_registry_local"', helper_source),
        ('SOURCE_REVISION = "quickstart-source"', helper_source),
        ("requiredPurposes", helper_source),
        ("operations", helper_source),
        ("clientAuthentication:", helper_source),
        ("secretFingerprints:", helper_source),
        ("registry_spatial_ext", helper_source),
        ('SPATIAL_BBOX_ROLE = "registry_quickstart_runtime__spatial_bbox"', helper_source),
        ("WITH INHERIT FALSE, SET TRUE, ADMIN FALSE", helper_source),
        ("SPATIAL_TOKEN_LIFETIME_SECONDS = 60", helper_source),
        ('QGIS_CLIENT_ID = "qgis-installation-central"', helper_source),
        ("service-site.installation-map-reader", helper_source),
        ('--action get', query_source),
    ]
    for needle, haystack in required_needles:
        if needle not in haystack:
            raise QuickstartError(f"quickstart structure is missing {needle!r}")
    forbidden_needles = [
        ("Authorization: Bearer ${", run_source),
        ("TOKEN=", run_source),
        ("clientSecret=", readme_source),
    ]
    for forbidden, haystack in forbidden_needles:
        if forbidden in haystack:
            raise QuickstartError(f"quickstart leaks token material through {forbidden!r}")
    if (quickstart_dir / ".gitignore").read_text(encoding="utf-8").strip() != ".run/":
        raise QuickstartError("quickstart disposable state must stay ignored")
    removed_references = (
        "canonical" + "ize-project",
        "sample" + "-records.jsonl",
        "runtime" + "-config.template.yaml",
    )
    for removed in removed_references:
        if removed in run_source or removed in query_source or removed in readme_source:
            raise QuickstartError(f"quickstart still references removed artifact or command: {removed}")
    removed_defaults = (
        "jwks" + "Cache:",
        "maxAge" + "Seconds:",
        "operational" + "Timeouts:",
        "wait" + "TimeoutMilliseconds:",
    )
    for removed in removed_defaults:
        if removed in helper_source:
            raise QuickstartError(f"runtime renderer should rely on the default for {removed}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("ports")
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--root", required=True, type=Path)
    prepare_parser.add_argument("--database-port", required=True, type=int)
    prepare_parser.add_argument("--mint-port", required=True, type=int)
    prepare_parser.add_argument("--breg-port", required=True, type=int)
    prepare_parser.add_argument("--spatial", action="store_true")
    prepare_parser.add_argument("--qgis-client-secret-fingerprint")
    canonical_project_parser = commands.add_parser("assert-canonical-project")
    canonical_project_parser.add_argument("--project", required=True, type=Path)
    package_parser = commands.add_parser("enrich-local-package")
    package_parser.add_argument("--project", required=True, type=Path)
    spatial_project_parser = commands.add_parser("prepare-spatial-project")
    spatial_project_parser.add_argument("--fixture", required=True, type=Path)
    spatial_project_parser.add_argument("--project", required=True, type=Path)
    runtime_parser = commands.add_parser("render-runtime")
    runtime_parser.add_argument("--root", required=True, type=Path)
    runtime_parser.add_argument("--revision", required=True)
    runtime_parser.add_argument("--spatial", action="store_true")
    wait_parser = commands.add_parser("wait-http")
    wait_parser.add_argument("--url", required=True)
    wait_parser.add_argument("--timeout", required=True, type=float)
    token_parser = commands.add_parser("store-token")
    token_parser.add_argument("--out", required=True, type=Path)
    secret_token_parser = commands.add_parser("mint-client-secret-token")
    secret_token_parser.add_argument("--url", required=True)
    secret_token_parser.add_argument("--client-id", required=True)
    secret_token_parser.add_argument("--secret", required=True, type=Path)
    secret_token_parser.add_argument("--out", required=True, type=Path)
    field_parser = commands.add_parser("json-field")
    field_parser.add_argument("--path", required=True, type=Path)
    field_parser.add_argument("--field", required=True)
    request_parser = commands.add_parser("request")
    request_parser.add_argument("--root", required=True, type=Path)
    request_parser.add_argument("--action", choices=("create", "get", "list"), required=True)
    request_parser.add_argument("--code")
    request_parser.add_argument("--label")
    request_parser.add_argument("--record-id")
    smoke_parser = commands.add_parser("spatial-smoke")
    smoke_parser.add_argument("--root", required=True, type=Path)
    smoke_parser.add_argument("--seed", required=True, type=Path)
    smoke_parser.add_argument("--operator-token-name", default="operator-token")
    self_test_parser = commands.add_parser("self-test")
    self_test_parser.add_argument("--quickstart-dir", required=True, type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "ports":
            print(" ".join(str(port) for port in reserve_ports()))
        elif args.command == "prepare":
            prepare(
                args.root,
                args.database_port,
                args.mint_port,
                args.breg_port,
                args.spatial,
                args.qgis_client_secret_fingerprint,
            )
        elif args.command == "assert-canonical-project":
            assert_canonical_project(args.project)
        elif args.command == "enrich-local-package":
            enrich_local_package(args.project)
        elif args.command == "prepare-spatial-project":
            prepare_spatial_project(args.fixture, args.project)
        elif args.command == "render-runtime":
            render_runtime(args.root, args.revision, args.spatial)
        elif args.command == "wait-http":
            wait_http(args.url, args.timeout)
        elif args.command == "store-token":
            store_token(args.out, sys.stdin.buffer.read())
        elif args.command == "mint-client-secret-token":
            mint_client_secret_token(args.url, args.client_id, args.secret, args.out)
        elif args.command == "json-field":
            json_field(args.path, args.field)
        elif args.command == "request":
            request(args.root, args.action, args.code, args.label, args.record_id)
        elif args.command == "spatial-smoke":
            spatial_smoke(args.root, args.seed, args.operator_token_name)
        elif args.command == "self-test":
            self_test(args.quickstart_dir)
        else:  # pragma: no cover
            raise AssertionError(args.command)
    except (OSError, KeyError, json.JSONDecodeError, QuickstartError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
