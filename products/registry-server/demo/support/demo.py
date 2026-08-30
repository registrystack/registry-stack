#!/usr/bin/env python3
"""Provision and exercise the disposable Registry Server household demo."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.server
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
import uuid
from datetime import datetime, timezone
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
WEBHOOK_DESTINATION_ID = "household-event-receiver"
WEBHOOK_EVENT_ID = "usual-resident-created-v1"
WEBHOOK_MODULE_ID = "publicschema-household-demographics"
WEBHOOK_MODULE_LOCK = "  - id: publicschema-household-demographics\n    version: 0.1.0\n"
WEBHOOK_MODULE_SOURCE = """    events:
      - id: usual-resident-created-v1
        trigger: created
        projection: [person-code, residency-status]
        when:
          kind: fields
          afterEquals: {residency-status: usual-resident}
        webhook:
          destinationId: household-event-receiver
"""
WEBHOOK_SIGNATURE_DOMAIN = b"registry-server-webhook-signature-v1"
WEBHOOK_RECEIVER_MAX_BODY_BYTES = 1024 * 1024


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


def reserve_ports(count: int = 3) -> tuple[int, ...]:
    if count not in (3, 4):
        raise DemoError("the demo reserves either three or four ports")
    listeners: list[socket.socket] = []
    try:
        for _ in range(count):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listeners.append(listener)
        return tuple(listener.getsockname()[1] for listener in listeners)  # type: ignore[return-value]
    finally:
        for listener in listeners:
            listener.close()


def _local_project(root: Path, fixture: Path, webhook: bool) -> None:
    target = root / "project"
    shutil.copytree(fixture, target, ignore=shutil.ignore_patterns(".DS_Store"))
    project_path = target / "registry.yaml"
    source = project_path.read_text(encoding="utf-8")
    for expected, replacement in EXPECTED_PROJECT_REPLACEMENTS.items():
        if source.count(expected) != 1:
            raise DemoError(f"household fixture no longer has the expected package line: {expected.strip()}")
        source = source.replace(expected, replacement, 1)
    if webhook:
        if source.count(WEBHOOK_MODULE_LOCK) != 1:
            raise DemoError("household fixture no longer has the expected demographics module lock")
        before_lock, after_lock = source.split(WEBHOOK_MODULE_LOCK, 1)
        digest_line, separator, after_digest = after_lock.partition("\n")
        digest = digest_line.removeprefix("    digest: ")
        if (
            not separator
            or not digest.startswith("sha256:")
            or len(digest) != 71
        ):
            raise DemoError(
                "household fixture no longer has the expected demographics module digest"
            )
        source = before_lock + WEBHOOK_MODULE_LOCK + after_digest
        module_path = target / f"modules/{WEBHOOK_MODULE_ID}/module.yaml"
        module_source = module_path.read_text(encoding="utf-8")
        if "    events:\n" in module_source or not module_source.endswith("\n"):
            raise DemoError("household demographics module cannot receive the demo event")
        module_path.write_text(module_source + WEBHOOK_MODULE_SOURCE, encoding="utf-8")
    project_path.write_text(source, encoding="utf-8")


def bind_webhook_module(root: Path, explain_report: Path) -> None:
    root = _require_root(root)
    report = _read_json_object(explain_report)
    closure = report.get("explanation", {}).get("moduleClosure")
    if not isinstance(closure, list):
        raise DemoError("compiled model report has no module closure")
    matching = [
        entry
        for entry in closure
        if isinstance(entry, dict) and entry.get("id") == WEBHOOK_MODULE_ID
    ]
    if len(matching) != 1:
        raise DemoError("compiled model report does not identify the demo webhook module")
    digest = matching[0].get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
        raise DemoError("compiled model report has no canonical demo webhook module digest")
    project_path = root / "project/registry.yaml"
    source = project_path.read_text(encoding="utf-8")
    if source.count(WEBHOOK_MODULE_LOCK) != 1:
        raise DemoError("demo webhook module lock is not ready for its compiled digest")
    source = source.replace(
        WEBHOOK_MODULE_LOCK,
        WEBHOOK_MODULE_LOCK + f"    digest: {digest}\n",
        1,
    )
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


def _runtime_config(
    root: Path,
    package_root: Path,
    revision: str,
    bind: str,
    webhook: bool = False,
) -> str:
    secrets = root / "secrets"
    if webhook:
        receiver_origin = root.joinpath("receiver-origin").read_text(encoding="ascii").strip()
        event_destinations = f"""eventDestinations:
  {WEBHOOK_DESTINATION_ID}:
    origin: {receiver_origin}
    path: /events
    networkProfile: loopbackDevelopmentHttp
    dnsFamily: dualStackStrict
    allowedPrivateCidrs: []
    hmacSha256KeyRef: secret:file/webhook-key
    classificationCeiling: restricted
    deliveryCeilings:
      attemptTimeoutMilliseconds: 1000
      maximumAttempts: 3
eventDelivery:
  payloadRetentionDays: 1
"""
    else:
        event_destinations = "eventDestinations: {}\n"
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
{event_destinations}operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 5000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 5000
  migrationStatementMilliseconds: 60000
"""


def prepare(
    root: Path,
    fixture: Path,
    database_port: int,
    mint_port: int,
    server_port: int,
    webhook: bool = False,
    receiver_port: int | None = None,
) -> None:
    root = _require_root(root)
    fixture = fixture.resolve()
    if not (fixture / "registry.yaml").is_file():
        raise DemoError("household fixture is missing registry.yaml")
    password_path = root / "secrets/database-password"
    password = password_path.read_text(encoding="ascii").strip()
    if not password or any(character not in "0123456789abcdef" for character in password):
        raise DemoError("database password must be non-empty lowercase hexadecimal")

    if webhook and receiver_port is None:
        raise DemoError("the webhook demo requires a receiver port")
    _local_project(root, fixture, webhook)
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
    if webhook:
        _write_new(root / "receiver-origin", f"http://127.0.0.1:{receiver_port}\n")
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
    test_runtime = _runtime_config(
        root,
        root / "empty-package",
        dummy_revision,
        "127.0.0.1:0",
        webhook,
    )
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


def render_runtime(root: Path, revision: str, webhook: bool = False) -> None:
    root = _require_root(root)
    if not revision.startswith("sha256:") or len(revision) != 71:
        raise DemoError("package revision must be one SHA-256 identifier")
    bind = urllib.parse.urlparse((root / "server-origin").read_text(encoding="ascii").strip()).netloc
    _write_new(
        root / "runtime.yaml",
        _runtime_config(root, root / "build/package", revision, bind, webhook),
    )


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


def _write_state(path: Path, state: dict[str, Any]) -> None:
    temporary = path.with_name(path.name + ".next")
    if temporary.exists():
        temporary.unlink()
    _write_json(temporary, state, 0o600)
    os.replace(temporary, path)


def _length_prefixed(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _expected_webhook_signature(key: bytes, headers: dict[str, str], body: bytes) -> str:
    # Keep this receiver-side verifier synchronized with the versioned Registry
    # Server signature contract. It has no access to runtime destination config.
    signed = bytearray(WEBHOOK_SIGNATURE_DOMAIN)
    for value in (
        headers["ce-specversion"].encode("ascii"),
        headers["ce-id"].encode("ascii"),
        headers["ce-source"].encode("ascii"),
        headers["ce-type"].encode("ascii"),
        headers["ce-time"].encode("ascii"),
        headers["ce-dataschema"].encode("ascii"),
        headers["x-registry-event-generation"].encode("ascii"),
        headers["x-registry-delivery-attempt"].encode("ascii"),
        headers["x-registry-delivery-time"].encode("ascii"),
        b"POST",
        b"/events",
        b"application/json",
        headers["idempotency-key"].encode("ascii"),
        body,
    ):
        signed.extend(_length_prefixed(value))
    encoded = base64.urlsafe_b64encode(hmac.new(key, signed, hashlib.sha256).digest()).rstrip(b"=")
    return "v1=" + encoded.decode("ascii")


def _parse_positive_header(headers: dict[str, str], name: str) -> int:
    value = headers.get(name, "")
    if not value.isascii() or not value.isdecimal():
        raise DemoError("the receiver refused webhook metadata")
    parsed = int(value)
    if parsed <= 0:
        raise DemoError("the receiver refused webhook metadata")
    return parsed


def _verify_webhook_request(
    key: bytes,
    path: str,
    headers: dict[str, str],
    body: bytes,
) -> tuple[str, int, int, str]:
    required = {
        "accept",
        "content-type",
        "ce-specversion",
        "ce-id",
        "ce-source",
        "ce-type",
        "ce-time",
        "ce-dataschema",
        "x-registry-event-generation",
        "x-registry-delivery-attempt",
        "x-registry-delivery-time",
        "idempotency-key",
        "x-registry-signature",
    }
    if path != "/events" or not required.issubset(headers):
        raise DemoError("the receiver refused the webhook request shape")
    if (
        headers["accept"] != "application/json"
        or headers["content-type"] != "application/json"
        or headers["ce-specversion"] != "1.0"
    ):
        raise DemoError("the receiver refused the CloudEvents profile")
    event_uuid = str(uuid.UUID(headers["ce-id"]))
    if event_uuid != headers["ce-id"] or headers["ce-type"] != WEBHOOK_EVENT_ID:
        raise DemoError("the receiver refused the CloudEvents identity")
    expected_source = f"urn:registrystack:registry:publicschema-household:instance:{INSTANCE_ID}"
    if headers["ce-source"] != expected_source:
        raise DemoError("the receiver refused the CloudEvents source")
    expected_schema_prefix = (
        "urn:registry-server:event-schema:publicschema-household:person:"
        f"{WEBHOOK_EVENT_ID}:sha256:"
    )
    if not headers["ce-dataschema"].startswith(expected_schema_prefix):
        raise DemoError("the receiver refused the CloudEvents data schema")
    event_time = datetime.fromisoformat(headers["ce-time"].replace("Z", "+00:00"))
    delivery_time = datetime.fromisoformat(
        headers["x-registry-delivery-time"].replace("Z", "+00:00")
    )
    if event_time.tzinfo is None or delivery_time.tzinfo is None:
        raise DemoError("the receiver refused unzoned event time")
    if abs((datetime.now(timezone.utc) - delivery_time).total_seconds()) > 30:
        raise DemoError("the receiver refused stale delivery time")
    generation = _parse_positive_header(headers, "x-registry-event-generation")
    attempt = _parse_positive_header(headers, "x-registry-delivery-attempt")
    idempotency_key = headers["idempotency-key"]
    if not idempotency_key.startswith("sha256:") or len(idempotency_key) != 71:
        raise DemoError("the receiver refused the idempotency key")
    if len(body) == 0 or len(body) > WEBHOOK_RECEIVER_MAX_BODY_BYTES:
        raise DemoError("the receiver refused the webhook body bounds")
    document = json.loads(body)
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if canonical != body or not isinstance(document, dict):
        raise DemoError("the receiver refused a non-canonical webhook body")
    if set(document) != {"entity", "recordId", "revision", "trigger", "packageRevision", "values"}:
        raise DemoError("the receiver refused the webhook body shape")
    if (
        document["entity"] != "person"
        or document["trigger"] != "created"
        or not isinstance(document["revision"], int)
        or document["revision"] < 1
        or not isinstance(document["packageRevision"], str)
        or not document["packageRevision"].startswith("sha256:")
        or str(uuid.UUID(document["recordId"])) != document["recordId"]
        or not isinstance(document["values"], dict)
        or set(document["values"]) != {"person-code", "residency-status"}
    ):
        raise DemoError("the receiver refused the event data contract")
    expected_signature = _expected_webhook_signature(key, headers, body)
    if not hmac.compare_digest(headers["x-registry-signature"], expected_signature):
        raise DemoError("the receiver refused the webhook signature")
    return event_uuid, generation, attempt, idempotency_key


class WebhookReceiver(http.server.BaseHTTPRequestHandler):
    server_version = "RegistryDemoReceiver/1"
    sys_version = ""

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler callback
        self.send_response(200 if self.path == "/ready" else 404)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler callback
        state_path: Path = self.server.state_path  # type: ignore[attr-defined]
        key: bytes = self.server.webhook_key  # type: ignore[attr-defined]
        try:
            raw_length = self.headers.get("Content-Length", "")
            if not raw_length.isdecimal():
                raise DemoError("the receiver refused the webhook length")
            length = int(raw_length)
            if length <= 0 or length > WEBHOOK_RECEIVER_MAX_BODY_BYTES:
                raise DemoError("the receiver refused the webhook length")
            body = self.rfile.read(length)
            headers = {name.lower(): value for name, value in self.headers.items()}
            event_id, generation, attempt, idempotency_key = _verify_webhook_request(
                key, self.path, headers, body
            )
        except (DemoError, KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            state = _read_json_object(state_path)
            state["verificationFailures"] = int(state.get("verificationFailures", 0)) + 1
            _write_state(state_path, state)
            self.send_response(400)
            self.end_headers()
            return

        state = _read_json_object(state_path)
        events = state.setdefault("events", {})
        event = events.get(event_id)
        if event is None:
            event = {"slot": len(events) + 1, "idempotencyKeys": {}, "attempts": []}
            events[event_id] = event
        key_name = str(generation)
        prior_key = event["idempotencyKeys"].get(key_name)
        if prior_key is not None and prior_key != idempotency_key:
            state["verificationFailures"] = int(state.get("verificationFailures", 0)) + 1
            _write_state(state_path, state)
            self.send_response(400)
            self.end_headers()
            return
        event["idempotencyKeys"][key_name] = idempotency_key
        slot = int(event["slot"])
        accepted = (
            slot == 1
            or slot >= 4
            or (slot == 2 and attempt > 1)
            or (slot == 3 and generation > 1)
        )
        event["attempts"].append(
            {"generation": generation, "attempt": attempt, "accepted": accepted}
        )
        _write_state(state_path, state)
        self.send_response(204 if accepted else 503)
        self.end_headers()


def serve_webhook_receiver(root: Path) -> None:
    root = _require_root(root)
    origin = urllib.parse.urlparse((root / "receiver-origin").read_text(encoding="ascii").strip())
    if origin.scheme != "http" or origin.hostname != "127.0.0.1" or origin.port is None:
        raise DemoError("the webhook receiver origin must be exact loopback HTTP")
    key_path = root / "secrets/webhook-key"
    if not key_path.is_file() or key_path.is_symlink() or key_path.stat().st_mode & 0o077:
        raise DemoError("the webhook key must be an owner-only regular file")
    key = key_path.read_bytes()
    if len(key) < 32:
        raise DemoError("the webhook key is too short")
    state_path = root / "webhook-receiver-state.json"
    _write_json(state_path, {"verificationFailures": 0, "events": {}}, 0o600)
    server = http.server.HTTPServer(("127.0.0.1", origin.port), WebhookReceiver)
    server.state_path = state_path  # type: ignore[attr-defined]
    server.webhook_key = key  # type: ignore[attr-defined]
    server.serve_forever(poll_interval=0.1)


def wait_webhook(root: Path, phase: str, timeout_seconds: float) -> None:
    root = _require_root(root)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            state = _read_json_object(root / "webhook-receiver-state.json")
        except (OSError, json.JSONDecodeError, DemoError):
            time.sleep(0.1)
            continue
        events = sorted(state.get("events", {}).values(), key=lambda event: event.get("slot", 0))
        if phase == "dead-letter-ready" and len(events) >= 3:
            second = events[1].get("attempts", [])
            third = events[2].get("attempts", [])
            if any(item.get("accepted") and item.get("attempt", 0) > 1 for item in second) and sum(
                item.get("generation") == 1 and not item.get("accepted") for item in third
            ) >= 3:
                return
        if phase == "replayed" and len(events) >= 3 and any(
            item.get("generation", 0) > 1 and item.get("accepted")
            for item in events[2].get("attempts", [])
        ):
            return
        time.sleep(0.1)
    raise DemoError(f"the webhook receiver did not reach {phase} within {timeout_seconds:g} seconds")


def select_dead_letter(report_path: Path) -> tuple[str, str, int]:
    report = _read_json_object(report_path)
    deliveries = report.get("deliveries")
    if not isinstance(deliveries, list):
        raise DemoError("webhook list returned no delivery inventory")
    matching = [
        delivery
        for delivery in deliveries
        if isinstance(delivery, dict)
        and delivery.get("state") == "dead_lettered"
        and delivery.get("replayEligible") is True
    ]
    if len(matching) != 1:
        raise DemoError("webhook list did not expose exactly one replayable dead letter")
    delivery = matching[0]
    event_id = delivery.get("eventId")
    delivery_id = delivery.get("deliveryId")
    generation = delivery.get("generation")
    if (
        not isinstance(event_id, str)
        or not isinstance(delivery_id, str)
        or not isinstance(generation, int)
    ):
        raise DemoError("webhook list returned invalid replay metadata")
    return event_id, delivery_id, generation


def verify_webhook(root: Path) -> None:
    root = _require_root(root)
    state = _read_json_object(root / "webhook-receiver-state.json")
    events = sorted(state.get("events", {}).values(), key=lambda event: event.get("slot", 0))
    if state.get("verificationFailures") != 0 or len(events) != 4:
        raise DemoError("the webhook receiver did not verify exactly four matching events")
    if not any(item.get("accepted") for item in events[0].get("attempts", [])):
        raise DemoError("the webhook receiver did not prove immediate success")
    if not any(
        item.get("accepted") and item.get("generation") == 1 and item.get("attempt", 0) > 1
        for item in events[1].get("attempts", [])
    ):
        raise DemoError("the webhook receiver did not prove automatic retry")
    if not any(
        item.get("accepted") and item.get("generation", 0) > 1
        for item in events[2].get("attempts", [])
    ):
        raise DemoError("the webhook receiver did not prove replay success")


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
    ports_parser = commands.add_parser("ports")
    ports_parser.add_argument("--count", type=int, choices=(3, 4), default=3)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--root", required=True, type=Path)
    prepare_parser.add_argument("--fixture", required=True, type=Path)
    prepare_parser.add_argument("--database-port", required=True, type=int)
    prepare_parser.add_argument("--mint-port", required=True, type=int)
    prepare_parser.add_argument("--server-port", required=True, type=int)
    prepare_parser.add_argument("--receiver-port", type=int)
    prepare_parser.add_argument("--webhook", action="store_true")
    runtime_parser = commands.add_parser("render-runtime")
    runtime_parser.add_argument("--root", required=True, type=Path)
    runtime_parser.add_argument("--revision", required=True)
    runtime_parser.add_argument("--webhook", action="store_true")
    bind_parser = commands.add_parser("bind-webhook-module")
    bind_parser.add_argument("--root", required=True, type=Path)
    bind_parser.add_argument("--report", required=True, type=Path)
    seed_parser = commands.add_parser("seed")
    seed_parser.add_argument("--root", required=True, type=Path)
    query_parser = commands.add_parser("query")
    query_parser.add_argument("--root", required=True, type=Path)
    wait_parser = commands.add_parser("wait-http")
    wait_parser.add_argument("--url", required=True)
    wait_parser.add_argument("--timeout", type=float, default=30.0)
    token_parser = commands.add_parser("store-token")
    token_parser.add_argument("--out", required=True, type=Path)
    receiver_parser = commands.add_parser("serve-webhook-receiver")
    receiver_parser.add_argument("--root", required=True, type=Path)
    webhook_wait_parser = commands.add_parser("wait-webhook")
    webhook_wait_parser.add_argument("--root", required=True, type=Path)
    webhook_wait_parser.add_argument(
        "--phase", required=True, choices=("dead-letter-ready", "replayed")
    )
    webhook_wait_parser.add_argument("--timeout", type=float, default=30.0)
    dead_letter_parser = commands.add_parser("select-dead-letter")
    dead_letter_parser.add_argument("--report", required=True, type=Path)
    verify_webhook_parser = commands.add_parser("verify-webhook")
    verify_webhook_parser.add_argument("--root", required=True, type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "ports":
            print(*reserve_ports(args.count))
        elif args.command == "prepare":
            prepare(
                args.root,
                args.fixture,
                args.database_port,
                args.mint_port,
                args.server_port,
                args.webhook,
                args.receiver_port,
            )
        elif args.command == "render-runtime":
            render_runtime(args.root, args.revision, args.webhook)
        elif args.command == "bind-webhook-module":
            bind_webhook_module(args.root, args.report)
        elif args.command == "seed":
            seed(args.root)
        elif args.command == "query":
            query(args.root)
        elif args.command == "wait-http":
            wait_http(args.url, args.timeout)
        elif args.command == "store-token":
            store_token(args.out, sys.stdin.buffer.read(64 * 1024 + 1))
        elif args.command == "serve-webhook-receiver":
            serve_webhook_receiver(args.root)
        elif args.command == "wait-webhook":
            wait_webhook(args.root, args.phase, args.timeout)
        elif args.command == "select-dead-letter":
            print(*select_dead_letter(args.report))
        elif args.command == "verify-webhook":
            verify_webhook(args.root)
        else:  # pragma: no cover
            raise AssertionError(args.command)
    except (DemoError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Registry Server demo failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
