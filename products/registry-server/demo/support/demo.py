#!/usr/bin/env python3
"""Provision and exercise the disposable Registry Server household demo."""

from __future__ import annotations

import argparse
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


DATABASE_ID = "publicschema-household-demo"
INSTANCE_ID = "publicschema-household-local"
SOURCE_REVISION = "publicschema-household-local-0.1.0"
AUDIENCE = "urn:registry-server:household-demo"
OPERATOR_CLIENT = "household-demo"
NO_PURPOSE_CLIENT = "household-demo-no-purpose"
MIGRATION_ROLE = "registry_demo_migration"
RUNTIME_ROLE = "registry_demo_runtime"
TEST_DATABASE = "registry_demo_test"
RUNTIME_DATABASE = "registry_demo"
EXPECTED_PROJECT_REPLACEMENTS = {
    "  environment: acceptance": "  environment: local",
    "  instanceId: publicschema-household-acceptance": f"  instanceId: {INSTANCE_ID}",
    "  sourceRevision: publicschema-household-acceptance-0.1.0": f"  sourceRevision: {SOURCE_REVISION}",
}


class DemoError(RuntimeError):
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
        raise DemoError(f"{path.name} must contain one JSON object")
    return value


def _require_root(root: Path) -> Path:
    if root.is_symlink():
        raise DemoError("demo root must not be a symbolic link")
    root = root.resolve()
    if not root.is_dir():
        raise DemoError("demo root must be an existing ordinary directory")
    return root


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


def _local_project(root: Path, fixture: Path) -> None:
    target = root / "project"
    shutil.copytree(fixture, target, ignore=shutil.ignore_patterns(".DS_Store"))
    project_path = target / "registry.yaml"
    source = project_path.read_text(encoding="utf-8")
    for expected, replacement in EXPECTED_PROJECT_REPLACEMENTS.items():
        if source.count(expected) != 1:
            raise DemoError(f"household fixture no longer has the expected package line: {expected.strip()}")
        source = source.replace(expected, replacement, 1)
    project_path.write_text(source, encoding="utf-8")


def _mint_client(client_id: str, principal: str, public_key: dict[str, Any], purpose: str | None) -> str:
    claims = f"    registry_principal: {principal}\n"
    if purpose is not None:
        claims += f"    registry_purpose: {purpose}\n"
    return (
        f"clientId: {client_id}\n"
        f"principal: urn:registry-server:demo:{client_id}\n"
        "authorization:\n"
        "  scopes: [registry:household:operate]\n"
        "  claims:\n"
        f"{claims}"
        f"keys: [{json.dumps(public_key, sort_keys=True, separators=(',', ':'))}]\n"
    )


def _runtime_config(root: Path, package_root: Path, revision: str, bind: str) -> str:
    secrets = root / "secrets"
    return f"""listener:
  bind: {bind}
  trustedProxy: direct
identity:
  environment: local
  instanceId: {INSTANCE_ID}
  databaseId: {DATABASE_ID}
  databaseInitializationEnvironment: local
secretProviders:
  file:
    root: {secrets}
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 4
    waitTimeoutMilliseconds: 2000
    createTimeoutMilliseconds: 2000
    recycleTimeoutMilliseconds: 2000
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
    issuer: {root.joinpath('mint-origin').read_text(encoding='ascii').strip()}
    audience: {AUDIENCE}
    allowedAlgorithm: ES256
    accessTokenType: at+jwt
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [{OPERATOR_CLIENT}, {NO_PURPOSE_CLIENT}]
    deniedKids: []
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 30000
    jwksCache:
      cacheTtlSeconds: 300
      negativeCacheTtlSeconds: 30
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 2000
      outageToleranceSeconds: 0
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
  maxAgeSeconds: 300
eventDestinations: {{}}
operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 5000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 5000
  migrationStatementMilliseconds: 60000
"""


def prepare(root: Path, fixture: Path, database_port: int, mint_port: int, server_port: int) -> None:
    root = _require_root(root)
    fixture = fixture.resolve()
    if not (fixture / "registry.yaml").is_file():
        raise DemoError("household fixture is missing registry.yaml")
    password_path = root / "secrets/database-password"
    password = password_path.read_text(encoding="ascii").strip()
    if not password or any(character not in "0123456789abcdef" for character in password):
        raise DemoError("database password must be non-empty lowercase hexadecimal")

    _local_project(root, fixture)
    mint_public = _read_json_object(root / "keys/mint-public.jwk.json")
    operator_public = _read_json_object(root / "keys/operator-public.jwk.json")
    no_purpose_public = _read_json_object(root / "keys/no-purpose-public.jwk.json")
    kid = mint_public.get("kid")
    if not isinstance(kid, str) or not kid:
        raise DemoError("Mint public JWK must carry a key identifier")

    mint_origin = f"http://127.0.0.1:{mint_port}"
    server_origin = f"http://127.0.0.1:{server_port}"
    _write_new(root / "mint-origin", mint_origin + "\n")
    _write_new(root / "server-origin", server_origin + "\n")
    _write_json(root / "secrets/mint-jwks", {"keys": [mint_public]}, 0o600)
    _write_json(root / f"mint/public-keys/{kid}.jwk.json", mint_public)
    _write_new(
        root / f"mint/clients/{OPERATOR_CLIENT}.yaml",
        _mint_client(
            OPERATOR_CLIENT,
            "synthetic-household-operator",
            operator_public,
            "household-administration",
        ),
    )
    _write_new(
        root / f"mint/clients/{NO_PURPOSE_CLIENT}.yaml",
        _mint_client(
            NO_PURPOSE_CLIENT,
            "synthetic-household-operator",
            no_purpose_public,
            None,
        ),
    )
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
REVOKE ALL ON SCHEMA registry_internal, registry_data FROM PUBLIC;
""",
    )
    _write_new(
        root / "database/initialize-runtime.sql",
        (root / "database/initialize.sql")
        .read_text(encoding="utf-8")
        .replace(TEST_DATABASE, RUNTIME_DATABASE),
    )
    _write_new(root / "trust-anchor.json", "{}")
    (root / "empty-package").mkdir(mode=0o755)
    dummy_revision = "sha256:" + "1" * 64
    test_runtime = _runtime_config(root, root / "empty-package", dummy_revision, "127.0.0.1:0")
    test_runtime = test_runtime.replace(
        "secret:file/runtime-database-url", "secret:file/test-runtime-database-url"
    ).replace(
        "secret:file/migration-database-url", "secret:file/test-migration-database-url"
    )
    _write_new(root / "runtime-test.yaml", test_runtime)
    _write_new(
        root / "schema-test-credentials.yaml",
        f"""apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings:
  - {{journeyId: household-person-lifecycle, stepId: create-single-headed-head, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: create-under-five-child, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: create-woman-headed-head, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: create-woman-headed-child, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: create-woman-headed-elder, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: create-isolation-head, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: create-isolation-spouse, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: create-isolation-child, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: create-single-headed-household, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: create-woman-headed-household, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: create-isolation-household, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: query-household-demographics, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: refuse-incomplete-membership, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: operator-without-purpose-is-concealed, credential: {{type: bearer, tokenRef: secret:file/no-purpose-token}}}}
""",
    )


def render_runtime(root: Path, revision: str) -> None:
    root = _require_root(root)
    if not revision.startswith("sha256:") or len(revision) != 71:
        raise DemoError("package revision must be one SHA-256 identifier")
    bind = urllib.parse.urlparse((root / "server-origin").read_text(encoding="ascii").strip()).netloc
    _write_new(root / "runtime.yaml", _runtime_config(root, root / "build/package", revision, bind))


def _token(root: Path, name: str) -> str:
    path = root / f"secrets/{name}"
    if not path.is_file() or path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise DemoError(f"{name} must be an owner-only regular file")
    value = path.read_text(encoding="ascii").strip()
    if value.count(".") != 2:
        raise DemoError(f"{name} does not contain one compact JWT")
    return value


def store_token(path: Path, source: bytes) -> None:
    if len(source) > 64 * 1024:
        raise DemoError("Mint returned an oversized token")
    try:
        value = source.decode("ascii").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise DemoError("Mint returned a non-ASCII token") from error
    if value.count(".") != 2 or any(character.isspace() for character in value):
        raise DemoError("Mint did not return one compact JWT")
    _write_new(path, value, 0o600)


def _request(
    root: Path,
    method: str,
    path: str,
    token_name: str,
    body: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
    expected: int = 200,
) -> tuple[dict[str, Any], dict[str, str]]:
    origin = (root / "server-origin").read_text(encoding="ascii").strip()
    headers = {"Accept": "application/json", "Authorization": f"Bearer {_token(root, token_name)}"}
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
            response_headers = {name.lower(): value for name, value in response.headers.items()}
    except urllib.error.HTTPError as error:
        response_bytes = error.read()
        status = error.code
        response_headers = {name.lower(): value for name, value in error.headers.items()}
    if status != expected:
        raise DemoError(f"{method} {path} returned {status}, expected {expected}")
    document = json.loads(response_bytes) if response_bytes else {}
    if not isinstance(document, dict):
        raise DemoError(f"{method} {path} returned a non-object JSON response")
    return document, response_headers


def _create(root: Path, route: str, logical_key: str, data: dict[str, Any]) -> str:
    response, _ = _request(
        root,
        "POST",
        route + "?accessProfile=household-operator",
        "operator-token",
        {"data": data},
        f"demo-{logical_key}",
        201,
    )
    identifier = response.get("id")
    if not isinstance(identifier, str):
        raise DemoError(f"created {logical_key} has no record id")
    return identifier


def seed_spec() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    people = [
        {"person-code": "PERSON-DEMO-001", "legal-name": "Omar Example", "family-name": "Example", "date-of-birth": "1986-02-22", "person-sex": "male", "residency-status": "usual-resident", "preferred-language": "en"},
        {"person-code": "PERSON-DEMO-002", "legal-name": "Lina Example", "family-name": "Example", "date-of-birth": "2023-03-14", "person-sex": "female", "residency-status": "usual-resident", "preferred-language": "en"},
        {"person-code": "PERSON-DEMO-003", "legal-name": "Sofia Sample", "family-name": "Sample", "date-of-birth": "1980-11-02", "person-sex": "female", "residency-status": "usual-resident", "preferred-language": "es"},
        {"person-code": "PERSON-DEMO-004", "legal-name": "Diego Sample", "family-name": "Sample", "date-of-birth": "2016-06-17", "person-sex": "male", "residency-status": "usual-resident", "preferred-language": "es"},
        {"person-code": "PERSON-DEMO-005", "legal-name": "Rosa Sample", "family-name": "Sample", "date-of-birth": "1940-08-20", "person-sex": "female", "residency-status": "usual-resident", "preferred-language": "es"},
        {"person-code": "PERSON-DEMO-006", "legal-name": "Karim Control", "family-name": "Control", "date-of-birth": "1975-01-09", "person-sex": "male", "residency-status": "usual-resident", "preferred-language": "fr"},
        {"person-code": "PERSON-DEMO-007", "legal-name": "Hana Control", "family-name": "Control", "date-of-birth": "1977-09-23", "person-sex": "female", "residency-status": "usual-resident", "preferred-language": "fr"},
        {"person-code": "PERSON-DEMO-008", "legal-name": "Noor Control", "family-name": "Control", "date-of-birth": "2018-05-06", "person-sex": "female", "residency-status": "usual-resident", "preferred-language": "fr"},
    ]
    households = [
        {"household-code": "HOUSEHOLD-DEMO-001", "local-household-number": 1001, "household-name": "Single Headed Under Five Household", "administrative-area": "north-demo", "household-type": "private"},
        {"household-code": "HOUSEHOLD-DEMO-002", "local-household-number": 1002, "household-name": "Woman Headed Child Elderly Household", "administrative-area": "central-demo", "household-type": "private"},
        {"household-code": "HOUSEHOLD-DEMO-003", "local-household-number": 1003, "household-name": "Isolation Control Household", "administrative-area": "south-demo", "household-type": "private"},
    ]
    memberships = [
        {"person-code": "PERSON-DEMO-001", "household-code": "HOUSEHOLD-DEMO-001", "relationship": "head", "valid-from": "2026-01-01"},
        {"person-code": "PERSON-DEMO-002", "household-code": "HOUSEHOLD-DEMO-001", "relationship": "child", "valid-from": "2026-01-01"},
        {"person-code": "PERSON-DEMO-003", "household-code": "HOUSEHOLD-DEMO-002", "relationship": "head", "valid-from": "2026-01-01"},
        {"person-code": "PERSON-DEMO-004", "household-code": "HOUSEHOLD-DEMO-002", "relationship": "child", "valid-from": "2026-01-01"},
        {"person-code": "PERSON-DEMO-005", "household-code": "HOUSEHOLD-DEMO-002", "relationship": "dependent", "valid-from": "2026-01-01"},
        {"person-code": "PERSON-DEMO-006", "household-code": "HOUSEHOLD-DEMO-003", "relationship": "head", "valid-from": "2026-01-01"},
        {"person-code": "PERSON-DEMO-007", "household-code": "HOUSEHOLD-DEMO-003", "relationship": "spouse", "valid-from": "2026-01-01"},
        {"person-code": "PERSON-DEMO-008", "household-code": "HOUSEHOLD-DEMO-003", "relationship": "child", "valid-from": "2026-01-01"},
    ]
    return people, households, memberships


def seed(root: Path) -> None:
    root = _require_root(root)
    people, households, memberships = seed_spec()
    person_ids = {
        person["person-code"]: _create(root, "/v1/records/persons", person["person-code"].lower(), person)
        for person in people
    }
    household_ids = {
        household["household-code"]: _create(
            root, "/v1/records/households", household["household-code"].lower(), household
        )
        for household in households
    }
    for index, membership in enumerate(memberships, start=1):
        _create(
            root,
            "/v1/records/group-memberships",
            f"membership-{index}",
            {
                "person": person_ids[membership["person-code"]],
                "household": household_ids[membership["household-code"]],
                "relationship": membership["relationship"],
                "valid-from": membership["valid-from"],
            },
        )
    _write_json(root / "seed-record-ids.json", {"people": person_ids, "households": household_ids})
    people_response, _ = _request(
        root,
        "GET",
        "/v1/records/persons?accessProfile=household-operator&$top=20",
        "operator-token",
    )
    household_response, _ = _request(
        root,
        "GET",
        "/v1/records/households?accessProfile=household-operator&$top=20",
        "operator-token",
    )
    membership_response, _ = _request(
        root,
        "GET",
        "/v1/records/group-memberships:current?accessProfile=household-operator&$top=20",
        "operator-token",
    )
    if [len(response.get("items", [])) for response in (people_response, household_response, membership_response)] != [8, 3, 8]:
        raise DemoError("seeded list counts did not match the expected 8 people, 3 households, and 8 memberships")
    _request(
        root,
        "GET",
        f"/v1/records/persons/{person_ids['PERSON-DEMO-001']}?accessProfile=household-operator",
        "no-purpose-token",
        expected=404,
    )
    print("Seeded 8 synthetic people, 3 households, and 8 current memberships.")


def query(root: Path) -> None:
    root = _require_root(root)
    seed_ids = _read_json_object(root / "seed-record-ids.json")
    households = seed_ids.get("households")
    if not isinstance(households, dict) or not isinstance(households.get("HOUSEHOLD-DEMO-001"), str):
        raise DemoError("seed record identifiers are missing; run the demo seed first")
    first_household_id = urllib.parse.quote(households["HOUSEHOLD-DEMO-001"], safe="")
    queries = [
        ("People from one household", f"/v1/records/households/{first_household_id}/people?accessProfile=household-operator&$select=person-code,legal-name,person-sex,residency-status&$orderby=person-code&$top=20&$count=true"),
        ("Derived stored and computed filter", "/v1/records/households?accessProfile=household-operator&$select=household-code,administrative-area,local-household-number,child-count&$filter=administrative-area%20eq%20%27north-demo%27%20and%20child-count%20eq%201&$orderby=local-household-number&$top=20&$count=true"),
        ("Single headed with child under five", "/v1/records/households?accessProfile=household-operator&$select=household-code,child-under-5-count,single-headed&$filter=single-headed%20eq%20true%20and%20child-under-5-count%20eq%201&$top=20&$count=true"),
        ("Woman headed with child and elderly", "/v1/records/households?accessProfile=household-operator&$select=household-code,woman-headed,child-count,elderly-count&$filter=woman-headed%20eq%20true%20and%20child-count%20eq%201%20and%20elderly-count%20eq%201&$top=20&$count=true"),
        ("Selector lookup input shape", "/v1/records/households?accessProfile=household-operator&$select=household-code,local-household-number&$filter=household-code%20eq%20%27HOUSEHOLD-DEMO-001%27&$top=1"),
    ]
    for label, path in queries:
        response, _ = _request(root, "GET", path, "operator-token")
        print(f"\n{label}\n{'=' * len(label)}")
        print(json.dumps(response, indent=2, sort_keys=True))


def wait_http(url: str, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_status: int | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                last_status = response.status
                if response.status == 200:
                    return
        except urllib.error.HTTPError as error:
            last_status = error.code
        except OSError:
            pass
        time.sleep(0.1)
    suffix = f" (last HTTP status {last_status})" if last_status is not None else ""
    raise DemoError(f"{url} did not become ready within {timeout_seconds:g} seconds{suffix}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("ports")
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--root", required=True, type=Path)
    prepare_parser.add_argument("--fixture", required=True, type=Path)
    prepare_parser.add_argument("--database-port", required=True, type=int)
    prepare_parser.add_argument("--mint-port", required=True, type=int)
    prepare_parser.add_argument("--server-port", required=True, type=int)
    runtime_parser = commands.add_parser("render-runtime")
    runtime_parser.add_argument("--root", required=True, type=Path)
    runtime_parser.add_argument("--revision", required=True)
    seed_parser = commands.add_parser("seed")
    seed_parser.add_argument("--root", required=True, type=Path)
    query_parser = commands.add_parser("query")
    query_parser.add_argument("--root", required=True, type=Path)
    wait_parser = commands.add_parser("wait-http")
    wait_parser.add_argument("--url", required=True)
    wait_parser.add_argument("--timeout", type=float, default=30.0)
    token_parser = commands.add_parser("store-token")
    token_parser.add_argument("--out", required=True, type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "ports":
            print(*reserve_ports())
        elif args.command == "prepare":
            prepare(args.root, args.fixture, args.database_port, args.mint_port, args.server_port)
        elif args.command == "render-runtime":
            render_runtime(args.root, args.revision)
        elif args.command == "seed":
            seed(args.root)
        elif args.command == "query":
            query(args.root)
        elif args.command == "wait-http":
            wait_http(args.url, args.timeout)
        elif args.command == "store-token":
            store_token(args.out, sys.stdin.buffer.read(64 * 1024 + 1))
        else:  # pragma: no cover
            raise AssertionError(args.command)
    except (DemoError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Registry Server demo failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
