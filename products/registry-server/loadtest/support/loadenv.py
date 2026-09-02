#!/usr/bin/env python3
"""Helpers for the Registry Server load-test environment.

The environment is a self-contained local stack on loopback: pinned
PostgreSQL 17 with TLS and pg_stat_statements, Registry Mint with one
private-key operator client (seeding and schema tests) and one client-secret
driver client (the k6 harness), and Registry Server serving the
business-establishments acceptance fixture with the opt-in metrics listener
enabled. Everything disposable lives under loadtest/.run.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


AUDIENCE = "urn:registry-server:loadtest"
OPERATOR_CLIENT_ID = "loadtest-operator"
NO_PURPOSE_CLIENT_ID = "loadtest-no-purpose"
DRIVER_CLIENT_ID = "loadtest-driver"
DATABASE_ID = "business-establishments-loadtest"
INSTANCE_ID = "business-establishments-loadtest"
SOURCE_REVISION = "business-establishments-loadtest-0.1.0"
RUNTIME_DATABASE = "business_loadtest"
TEST_DATABASE = "business_loadtest_test"
MIGRATION_ROLE = "registry_loadtest_migration"
RUNTIME_ROLE = "registry_loadtest_runtime"
TOKEN_LIFETIME_SECONDS = 900
DEFAULT_POOL_MAX = 32

PROJECT_REPLACEMENTS = {
    "  environment: acceptance": "  environment: local",
    "  instanceId: business-establishments-acceptance": f"  instanceId: {INSTANCE_ID}",
    "  sourceRevision: business-establishments-acceptance-0.1.0": f"  sourceRevision: {SOURCE_REVISION}",
}


class LoadtestError(RuntimeError):
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
        raise LoadtestError(f"{path.name} must contain one JSON object")
    return value


def _require_root(root: Path) -> Path:
    if root.is_symlink():
        raise LoadtestError("load-test run directory must not be a symbolic link")
    resolved = root.resolve()
    if not resolved.is_dir():
        raise LoadtestError("load-test run directory must be an existing ordinary directory")
    return resolved


def _replace_once(source: str, expected: str, replacement: str, message: str) -> str:
    if source.count(expected) != 1:
        raise LoadtestError(message)
    return source.replace(expected, replacement, 1)


def reserve_ports() -> tuple[int, int, int, int]:
    listeners: list[socket.socket] = []
    try:
        for _ in range(4):
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


def _private_key_client(
    client_id: str,
    public_key: dict[str, Any],
    scopes: list[str],
    claims: dict[str, Any],
) -> str:
    return (
        f"clientId: {client_id}\n"
        f"principal: urn:registry-server:loadtest:{client_id}\n"
        "authorization:\n"
        f"  scopes: {json.dumps(scopes, separators=(',', ':'))}\n"
        "  claims:\n"
        f"{_render_claims(claims)}"
        f"keys: [{json.dumps(public_key, sort_keys=True, separators=(',', ':'))}]\n"
    )


def _client_secret_client(fingerprint: str) -> str:
    if not fingerprint or any(character.isspace() for character in fingerprint):
        raise LoadtestError("driver client secret fingerprint must be one non-empty token")
    return (
        f"clientId: {DRIVER_CLIENT_ID}\n"
        f"principal: urn:registry-server:loadtest:{DRIVER_CLIENT_ID}\n"
        "authorization:\n"
        '  scopes: ["registry:business:operate"]\n'
        "  claims:\n"
        "    registry_principal: synthetic-loadtest-driver\n"
        "    registry_purpose: business-administration\n"
        "clientAuthentication:\n"
        "  method: client-secret\n"
        f"  secretFingerprints: [{json.dumps(fingerprint)}]\n"
    )


def operator_clients(public_key: dict[str, Any]) -> dict[str, str]:
    # The fixture journeys pin the synthetic-business-operator principal, so
    # the schema-test clients must carry exactly these claims.
    return {
        OPERATOR_CLIENT_ID: _private_key_client(
            OPERATOR_CLIENT_ID,
            public_key,
            ["registry:business:operate"],
            {
                "registry_principal": "synthetic-business-operator",
                "registry_purpose": "business-administration",
            },
        ),
        NO_PURPOSE_CLIENT_ID: _private_key_client(
            NO_PURPOSE_CLIENT_ID,
            public_key,
            ["registry:business:operate"],
            {"registry_principal": "synthetic-business-operator"},
        ),
    }


def _runtime_template(
    root: Path,
    revision: str,
    package_root: Path,
    database: str,
    pool_max: int,
) -> str:
    origin = urllib.parse.urlparse((root / "server-origin").read_text(encoding="ascii").strip())
    mint_origin = (root / "mint-origin").read_text(encoding="ascii").strip()
    metrics_port = int((root / "metrics-port").read_text(encoding="ascii").strip())
    if origin.scheme != "http" or origin.hostname != "127.0.0.1" or origin.port is None:
        raise LoadtestError("server origin must be exact loopback HTTP")
    if not revision.startswith("sha256:") or len(revision) != 71:
        raise LoadtestError("package revision must be one SHA-256 identifier")
    if not 1 <= pool_max <= 128:
        raise LoadtestError("pool maxSize must be between 1 and 128")
    return f"""apiVersion: registry.registrystack.org/server-runtime/v1alpha1
kind: RegistryServerRuntimeConfig
listener:
  bind: 127.0.0.1:{origin.port}
  trustedProxy: direct
identity:
  environment: local
  instanceId: {INSTANCE_ID}
  databaseId: {DATABASE_ID}
  databaseInitializationEnvironment: local
secretProviders:
  file:
    root: {root / 'secrets'}
database:
  runtimeUrlRef: secret:file/{database}-runtime-database-url
  migrationUrlRef: secret:file/{database}-migration-database-url
  pool:
    maxSize: {pool_max}
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
    allowedClients: [{OPERATOR_CLIENT_ID}, {NO_PURPOSE_CLIENT_ID}, {DRIVER_CLIENT_ID}]
    deniedKids: []
    maxTokenLifetimeSeconds: {TOKEN_LIFETIME_SECONDS}
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
metricsListener:
  bind: 127.0.0.1:{metrics_port}
"""


def _initialize_sql(database: str) -> str:
    statements = [
        "CREATE EXTENSION IF NOT EXISTS btree_gist;",
        "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;",
        f"REVOKE ALL ON DATABASE {database} FROM PUBLIC;",
        f"GRANT CONNECT ON DATABASE {database} TO {MIGRATION_ROLE}, {RUNTIME_ROLE};",
        f"CREATE SCHEMA registry_internal AUTHORIZATION {MIGRATION_ROLE};",
        f"CREATE SCHEMA registry_data AUTHORIZATION {MIGRATION_ROLE};",
        f"CREATE SCHEMA registry_source AUTHORIZATION {MIGRATION_ROLE};",
        f"CREATE SCHEMA registry_derived AUTHORIZATION {MIGRATION_ROLE};",
        f"CREATE SCHEMA registry_context AUTHORIZATION {MIGRATION_ROLE};",
        "REVOKE ALL ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context FROM PUBLIC;",
    ]
    return "\n".join(statements) + "\n"


SCHEMA_TEST_CREDENTIALS = """apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings:
  - {journeyId: business-establishment-lifecycle, stepId: create-north-head-office, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: create-production-branch, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: create-central-head-office, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: create-central-branch, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: create-central-depot, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: create-isolation-head-office, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: create-isolation-regional-office, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: create-isolation-branch, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: create-north-business, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: create-central-business, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: create-isolation-business, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: lookup-north-business, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: read-establishments-from-north-business, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: query-establishment-summary, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: refuse-incomplete-assignment, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: business-establishment-lifecycle, stepId: operator-without-purpose-is-concealed, credential: {type: bearer, tokenRef: secret:file/no-purpose-token}}
"""


def local_project(fixture: Path, project: Path) -> None:
    if fixture.is_symlink() or not fixture.is_dir():
        raise LoadtestError("business-establishments fixture must be an ordinary directory")
    if project.exists():
        raise LoadtestError("load-test project output must not already exist")
    import shutil

    shutil.copytree(fixture, project, symlinks=False)
    path = project / "registry.yaml"
    source = path.read_text(encoding="utf-8")
    for expected, replacement in PROJECT_REPLACEMENTS.items():
        source = _replace_once(
            source,
            expected,
            replacement,
            f"business-establishments fixture no longer has the expected line: {expected.strip()}",
        )
    path.write_text(source, encoding="utf-8")


def prepare(
    root: Path,
    database_port: int,
    mint_port: int,
    server_port: int,
    metrics_port: int,
    driver_secret_fingerprint: str,
    pool_max: int,
) -> None:
    root = _require_root(root)
    if not (root / "project/registry.yaml").is_file():
        raise LoadtestError("local project did not create registry.yaml")
    password = (root / "secrets/database-password").read_text(encoding="ascii").strip()
    if not password or any(character not in "0123456789abcdef" for character in password):
        raise LoadtestError("database password must be non-empty lowercase hexadecimal")
    mint_public = _read_json_object(root / "keys/mint-public.jwk.json")
    operator_public = _read_json_object(root / "keys/operator-public.jwk.json")
    kid = mint_public.get("kid")
    if not isinstance(kid, str) or not kid:
        raise LoadtestError("Mint public JWK must carry a key identifier")
    mint_origin = f"http://127.0.0.1:{mint_port}"
    server_origin = f"http://127.0.0.1:{server_port}"
    _write_new(root / "mint-origin", mint_origin + "\n")
    _write_new(root / "server-origin", server_origin + "\n")
    _write_new(root / "metrics-port", f"{metrics_port}\n")
    _write_json(root / "secrets/mint-jwks", {"keys": [mint_public]}, 0o600)
    _write_json(root / f"mint/public-keys/{kid}.jwk.json", mint_public)
    for client_id, document in operator_clients(operator_public).items():
        _write_new(root / f"mint/clients/{client_id}.yaml", document)
    _write_new(root / f"mint/clients/{DRIVER_CLIENT_ID}.yaml", _client_secret_client(driver_secret_fingerprint))
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
  lifetimeSeconds: {TOKEN_LIFETIME_SECONDS}
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
    for database in (RUNTIME_DATABASE, TEST_DATABASE):
        _write_new(
            root / f"secrets/{database}-runtime-database-url",
            f"postgresql://{RUNTIME_ROLE}:{encoded_password}@{base}/{database}",
            0o600,
        )
        _write_new(
            root / f"secrets/{database}-migration-database-url",
            f"postgresql://{MIGRATION_ROLE}:{encoded_password}@{base}/{database}",
            0o600,
        )
    _write_new(
        root / "database/postgres.env",
        f"POSTGRES_USER=postgres\nPOSTGRES_PASSWORD={password}\nPOSTGRES_DB=postgres\n",
        0o600,
    )
    _write_new(
        root / "database/bootstrap.sql",
        f"""CREATE ROLE {MIGRATION_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{password}';
CREATE ROLE {RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{password}';
""",
        0o600,
    )
    _write_new(root / "database/initialize-runtime.sql", _initialize_sql(RUNTIME_DATABASE))
    _write_new(root / "database/initialize.sql", _initialize_sql(TEST_DATABASE))
    _write_new(root / "trust-anchor.json", "{}")
    _write_new(root / "empty-package/.keep", "")
    _write_new(
        root / "runtime-test.yaml",
        _runtime_template(root, "sha256:" + "1" * 64, root / "empty-package", TEST_DATABASE, pool_max),
    )
    _write_new(root / "schema-test-credentials.yaml", SCHEMA_TEST_CREDENTIALS)


def render_runtime(root: Path, revision: str, pool_max: int) -> None:
    root = _require_root(root)
    _write_new(root / "runtime.yaml", _runtime_template(root, revision, root / "build/package", RUNTIME_DATABASE, pool_max))


def store_token(path: Path, source: bytes) -> None:
    if len(source) > 64 * 1024:
        raise LoadtestError("Mint returned an oversized token")
    try:
        value = source.decode("ascii").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise LoadtestError("Mint returned a non-ASCII token") from error
    if value.count(".") != 2 or any(character.isspace() for character in value):
        raise LoadtestError("Mint did not return one compact JWT")
    _write_new(path, value, 0o600)


def mint_client_secret_token(url: str, client_id: str, secret_path: Path, out: Path) -> None:
    _require_owner_only_regular(secret_path, "driver client secret")
    secret = secret_path.read_text(encoding="ascii").strip()
    body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret}).encode("ascii")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        document = json.loads(response.read().decode("utf-8"))
    token = document.get("access_token")
    if not isinstance(token, str) or token.count(".") != 2:
        raise LoadtestError("Mint did not return one compact access token")
    store_token(out, token.encode("ascii"))


def _require_owner_only_regular(path: Path, name: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise LoadtestError(f"{name} must be an owner-only regular file")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise LoadtestError(f"{name} must be an owner-only regular file")


def wait_http(url: str, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    last: int | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                last = response.status
        except urllib.error.HTTPError as error:
            last = error.code
        except urllib.error.URLError:
            last = None
        if last is not None and 200 <= last < 400:
            return
        time.sleep(0.25)
    raise LoadtestError(f"{url} did not become ready (last status {last})")


def json_field(path: Path, field: str) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    print(value[field])


def scrape(url: str, out: Path) -> None:
    with urllib.request.urlopen(url, timeout=10) as response:
        body = response.read().decode("utf-8")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body, encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Registry Server load-test environment helpers")
    subcommands = result.add_subparsers(dest="command", required=True)

    subcommands.add_parser("ports")

    local = subcommands.add_parser("local-project")
    local.add_argument("--fixture", type=Path, required=True)
    local.add_argument("--project", type=Path, required=True)

    prepare_command = subcommands.add_parser("prepare")
    prepare_command.add_argument("--root", type=Path, required=True)
    prepare_command.add_argument("--database-port", type=int, required=True)
    prepare_command.add_argument("--mint-port", type=int, required=True)
    prepare_command.add_argument("--server-port", type=int, required=True)
    prepare_command.add_argument("--metrics-port", type=int, required=True)
    prepare_command.add_argument("--driver-secret-fingerprint", required=True)
    prepare_command.add_argument("--pool-max", type=int, default=DEFAULT_POOL_MAX)

    render = subcommands.add_parser("render-runtime")
    render.add_argument("--root", type=Path, required=True)
    render.add_argument("--revision", required=True)
    render.add_argument("--pool-max", type=int, default=DEFAULT_POOL_MAX)

    store = subcommands.add_parser("store-token")
    store.add_argument("--out", type=Path, required=True)

    mint = subcommands.add_parser("mint-client-secret-token")
    mint.add_argument("--url", required=True)
    mint.add_argument("--client-id", required=True)
    mint.add_argument("--secret", type=Path, required=True)
    mint.add_argument("--out", type=Path, required=True)

    wait = subcommands.add_parser("wait-http")
    wait.add_argument("--url", required=True)
    wait.add_argument("--timeout", type=float, default=30)

    field = subcommands.add_parser("json-field")
    field.add_argument("--path", type=Path, required=True)
    field.add_argument("--field", required=True)

    scrape_command = subcommands.add_parser("scrape")
    scrape_command.add_argument("--url", required=True)
    scrape_command.add_argument("--out", type=Path, required=True)

    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "ports":
            print(" ".join(str(port) for port in reserve_ports()))
        elif arguments.command == "local-project":
            local_project(arguments.fixture, arguments.project)
        elif arguments.command == "prepare":
            prepare(
                arguments.root,
                arguments.database_port,
                arguments.mint_port,
                arguments.server_port,
                arguments.metrics_port,
                arguments.driver_secret_fingerprint,
                arguments.pool_max,
            )
        elif arguments.command == "render-runtime":
            render_runtime(arguments.root, arguments.revision, arguments.pool_max)
        elif arguments.command == "store-token":
            store_token(arguments.out, sys.stdin.buffer.read())
        elif arguments.command == "mint-client-secret-token":
            mint_client_secret_token(arguments.url, arguments.client_id, arguments.secret, arguments.out)
        elif arguments.command == "wait-http":
            wait_http(arguments.url, arguments.timeout)
        elif arguments.command == "json-field":
            json_field(arguments.path, arguments.field)
        elif arguments.command == "scrape":
            scrape(arguments.url, arguments.out)
    except (LoadtestError, OSError, json.JSONDecodeError, KeyError) as error:
        print(f"load-test environment error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
