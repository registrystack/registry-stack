#!/usr/bin/env python3
"""Small helpers for the generic Registry Server local quickstart."""

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


AUDIENCE = "urn:registry-server:quickstart"
CLIENT_ID = "generic-quickstart"
DATABASE_ID = "generic-registry-local-db"
INSTANCE_ID = "generic_registry_local"
RUNTIME_DATABASE = "registry_quickstart"
TEST_DATABASE = "registry_quickstart_test"
MIGRATION_ROLE = "registry_quickstart_migration"
RUNTIME_ROLE = "registry_quickstart_runtime"
SOURCE_REVISION = "quickstart-source"
OPERATOR_PURPOSE = "registry-operations"


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


def _mint_client(public_key: dict[str, Any]) -> str:
    claims = {
        "registry_principal": "generic-registry-operator",
        "registry_purpose": OPERATOR_PURPOSE,
    }
    rendered_claims = "".join(
        f"    {name}: {json.dumps(value, ensure_ascii=True, separators=(',', ':'))}\n"
        for name, value in sorted(claims.items())
    )
    return (
        f"clientId: {CLIENT_ID}\n"
        f"principal: urn:registry-server:quickstart:{CLIENT_ID}\n"
        "authorization:\n"
        '  scopes: ["registry:generic:operate"]\n'
        "  claims:\n"
        f"{rendered_claims}"
        f"keys: [{json.dumps(public_key, sort_keys=True, separators=(',', ':'))}]\n"
    )


def _template_text(root: Path, revision: str, package_root: Path, runtime_database: bool) -> str:
    origin = urllib.parse.urlparse((root / "server-origin").read_text(encoding="ascii").strip())
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
    allowedClients: [{CLIENT_ID}]
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


def _journey_credentials(root: Path, token_name: str) -> str:
    path = root / "project/tests/journeys.yaml"
    source = path.read_text(encoding="utf-8")
    journey = None
    steps: list[str] = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("- id: ") and journey is None:
            journey = stripped.removeprefix("- id: ").strip()
        elif stripped.startswith("- id: ") and journey is not None:
            steps.append(stripped.removeprefix("- id: ").strip())
    if not journey or not {"create-record", "get-record", "list-records"}.issubset(set(steps)):
        raise QuickstartError("registry-serverctl init changed its generic journey shape")
    bindings = "\n".join(
        f"  - {{journeyId: {journey}, stepId: {step}, credential: {{type: bearer, tokenRef: secret:file/{token_name}}}}}"
        for step in steps
    )
    return (
        "apiVersion: registry.registrystack.org/server-schema-test-credentials/v1\n"
        "kind: SchemaTestCredentials\n"
        "bindings:\n"
        f"{bindings}\n"
    )


def prepare(root: Path, database_port: int, mint_port: int, server_port: int) -> None:
    root = _require_root(root)
    project = root / "project"
    if not (project / "registry.yaml").is_file():
        raise QuickstartError("registry-serverctl init did not create registry.yaml")
    password = (root / "secrets/database-password").read_text(encoding="ascii").strip()
    if not password or any(character not in "0123456789abcdef" for character in password):
        raise QuickstartError("database password must be non-empty lowercase hexadecimal")
    mint_public = _read_json_object(root / "keys/mint-public.jwk.json")
    operator_public = _read_json_object(root / "keys/operator-public.jwk.json")
    kid = mint_public.get("kid")
    if not isinstance(kid, str) or not kid:
        raise QuickstartError("Mint public JWK must carry a key identifier")
    mint_origin = f"http://127.0.0.1:{mint_port}"
    server_origin = f"http://127.0.0.1:{server_port}"
    _write_new(root / "mint-origin", mint_origin + "\n")
    _write_new(root / "server-origin", server_origin + "\n")
    _write_json(root / "secrets/mint-jwks", {"keys": [mint_public]}, 0o600)
    _write_json(root / f"mint/public-keys/{kid}.jwk.json", mint_public)
    _write_new(root / f"mint/clients/{CLIENT_ID}.yaml", _mint_client(operator_public))
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
  lifetimeSeconds: 300
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
    _write_new(
        root / "database/bootstrap.sql",
        f"""CREATE ROLE {MIGRATION_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{password}';
CREATE ROLE {RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{password}';
""",
        0o600,
    )
    _write_new(
        root / "database/initialize.sql",
        f"""CREATE EXTENSION IF NOT EXISTS btree_gist;
REVOKE ALL ON DATABASE {TEST_DATABASE} FROM PUBLIC;
GRANT CONNECT ON DATABASE {TEST_DATABASE} TO {MIGRATION_ROLE}, {RUNTIME_ROLE};
CREATE SCHEMA registry_internal AUTHORIZATION {MIGRATION_ROLE};
CREATE SCHEMA registry_data AUTHORIZATION {MIGRATION_ROLE};
CREATE SCHEMA registry_source AUTHORIZATION {MIGRATION_ROLE};
CREATE SCHEMA registry_derived AUTHORIZATION {MIGRATION_ROLE};
CREATE SCHEMA registry_context AUTHORIZATION {MIGRATION_ROLE};
REVOKE ALL ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context FROM PUBLIC;
""",
    )
    _write_new(
        root / "database/initialize-runtime.sql",
        (root / "database/initialize.sql").read_text(encoding="utf-8").replace(TEST_DATABASE, RUNTIME_DATABASE),
    )
    _write_new(root / "trust-anchor.json", "{}")
    (root / "empty-package").mkdir(mode=0o755)
    _write_new(
        root / "runtime-test.yaml",
        _template_text(root, "sha256:" + "1" * 64, root / "empty-package", False),
    )
    _write_new(root / "schema-test-credentials.yaml", _journey_credentials(root, "schema-test-token"))


def assert_canonical_project(project: Path) -> None:
    if project.is_symlink() or not project.is_dir():
        raise QuickstartError("project must be an ordinary directory")
    path = project / "registry.yaml"
    source = path.read_text(encoding="utf-8")
    if "    purposes: " in source or "        actions: " in source:
        raise QuickstartError(
            "registry-serverctl init emitted legacy access-profile keys; expected requiredPurposes and operations"
        )
    if "    requiredPurposes: [registry-operations]\n" not in source:
        raise QuickstartError("registry-serverctl init output is missing requiredPurposes")
    if "    requiredScopes: [registry:generic:operate]\n" not in source:
        raise QuickstartError("registry-serverctl init output is missing requiredScopes")
    if "        operations: [create, get, list, patch]\n" not in source:
        raise QuickstartError("registry-serverctl init output is missing grant operations")


def enrich_local_package(project: Path) -> None:
    if project.is_symlink() or not project.is_dir():
        raise QuickstartError("project must be an ordinary directory")
    path = project / "registry.yaml"
    source = path.read_text(encoding="utf-8")
    if "\npackage:\n" in f"\n{source}":
        raise QuickstartError("registry-serverctl init output already has package identity")
    if "\nmanifestProjection:\n" in f"\n{source}":
        raise QuickstartError("registry-serverctl init output must not include manifestProjection")
    marker = "kind: RegistryProject\n"
    if source.count(marker) != 1:
        raise QuickstartError("registry-serverctl init output has an unexpected document header")
    package = (
        "package:\n"
        "  environment: local\n"
        f"  instanceId: {INSTANCE_ID}\n"
        "  sequence: 1\n"
        f"  sourceRevision: {SOURCE_REVISION}\n"
    )
    path.write_text(source.replace(marker, marker + package, 1), encoding="utf-8")


def render_runtime(root: Path, revision: str) -> None:
    root = _require_root(root)
    _write_new(root / "runtime.yaml", _template_text(root, revision, root / "build/package", True))


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


def _token(root: Path) -> str:
    path = root / "secrets/operator-token"
    if not path.is_file() or path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise QuickstartError("operator token must be an owner-only regular file")
    value = path.read_text(encoding="ascii").strip()
    if value.count(".") != 2:
        raise QuickstartError("operator token does not contain one compact JWT")
    return value


def _request(
    root: Path,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    idempotency_key: str | None = None,
    expected: int = 200,
) -> dict[str, Any]:
    origin = (root / "server-origin").read_text(encoding="ascii").strip()
    headers = {"Accept": "application/json", "Authorization": f"Bearer {_token(root)}"}
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
        identifier = document.get("id")
        if not isinstance(identifier, str):
            raise QuickstartError("created record has no id")
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
    checks = [
        ('"$registry_serverctl" --format json init "$run_dir/project"', run_source),
        ('assert-canonical-project --project "$run_dir/project"', run_source),
        ('enrich-local-package --project "$run_dir/project"', run_source),
        ('"$registry_serverctl" --format json check "$run_dir/project"', run_source),
        ('"$mint" token', run_source),
        ('store-token --out "$run_dir/secrets/operator-token"', run_source),
        ('Authorization: Bearer ${', run_source),
        ("TOKEN=", run_source),
        ("databaseInitializationEnvironment: local", helper_source),
        ("apiVersion: registry.registrystack.org/server-runtime/v1alpha1", helper_source),
        ("kind: RegistryServerRuntimeConfig", helper_source),
        ('INSTANCE_ID = "generic_registry_local"', helper_source),
        ('SOURCE_REVISION = "quickstart-source"', helper_source),
        ("requiredPurposes", helper_source),
        ("operations", helper_source),
        ('--action get', query_source),
    ]
    for needle, haystack in checks[:6] + checks[8:]:
        if needle not in haystack:
            raise QuickstartError(f"quickstart structure is missing {needle!r}")
    for forbidden, haystack in checks[6:8]:
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
    prepare_parser.add_argument("--server-port", required=True, type=int)
    canonical_project_parser = commands.add_parser("assert-canonical-project")
    canonical_project_parser.add_argument("--project", required=True, type=Path)
    package_parser = commands.add_parser("enrich-local-package")
    package_parser.add_argument("--project", required=True, type=Path)
    runtime_parser = commands.add_parser("render-runtime")
    runtime_parser.add_argument("--root", required=True, type=Path)
    runtime_parser.add_argument("--revision", required=True)
    wait_parser = commands.add_parser("wait-http")
    wait_parser.add_argument("--url", required=True)
    wait_parser.add_argument("--timeout", required=True, type=float)
    token_parser = commands.add_parser("store-token")
    token_parser.add_argument("--out", required=True, type=Path)
    field_parser = commands.add_parser("json-field")
    field_parser.add_argument("--path", required=True, type=Path)
    field_parser.add_argument("--field", required=True)
    request_parser = commands.add_parser("request")
    request_parser.add_argument("--root", required=True, type=Path)
    request_parser.add_argument("--action", choices=("create", "get", "list"), required=True)
    request_parser.add_argument("--code")
    request_parser.add_argument("--label")
    request_parser.add_argument("--record-id")
    self_test_parser = commands.add_parser("self-test")
    self_test_parser.add_argument("--quickstart-dir", required=True, type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "ports":
            print(" ".join(str(port) for port in reserve_ports()))
        elif args.command == "prepare":
            prepare(args.root, args.database_port, args.mint_port, args.server_port)
        elif args.command == "assert-canonical-project":
            assert_canonical_project(args.project)
        elif args.command == "enrich-local-package":
            enrich_local_package(args.project)
        elif args.command == "render-runtime":
            render_runtime(args.root, args.revision)
        elif args.command == "wait-http":
            wait_http(args.url, args.timeout)
        elif args.command == "store-token":
            store_token(args.out, sys.stdin.buffer.read())
        elif args.command == "json-field":
            json_field(args.path, args.field)
        elif args.command == "request":
            request(args.root, args.action, args.code, args.label, args.record_id)
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
