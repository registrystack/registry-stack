#!/usr/bin/env python3
"""Provision and exercise disposable Registry Server demos."""

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
VIEWER_CLIENT = "household-demo-viewer"
BUSINESS_DATABASE_ID = "business-establishments-demo"
BUSINESS_INSTANCE_ID = "business-establishments-local"
BUSINESS_SOURCE_REVISION = "business-establishments-local-0.1.0"
BUSINESS_AUDIENCE = "urn:registry-server:business-demo"
BUSINESS_OPERATOR_CLIENT = "business-demo"
BUSINESS_NO_PURPOSE_CLIENT = "business-demo-no-purpose"
BUSINESS_VIEWER_CLIENT = "business-demo-viewer"
ASSET_SITE_DATABASE_ID = "asset-site-placement-demo"
ASSET_SITE_INSTANCE_ID = "asset-site-placement-local"
ASSET_SITE_SOURCE_REVISION = "asset-site-placement-local-0.1.0"
ASSET_SITE_AUDIENCE = "urn:registry-server:asset-site-demo"
ASSET_OPERATOR_CLIENT = "asset-site-demo-operator"
ASSET_PLANNER_CLIENT = "asset-site-demo-planner"
ASSET_PLANNER_NO_PURPOSE_CLIENT = "asset-site-demo-planner-no-purpose"
ASSET_OPERATOR_SCOPE = "registry:asset:operate"
ASSET_PLANNER_SCOPE = "registry:asset:plan"
FACILITY_DATABASE_ID = "facility-demo"
FACILITY_INSTANCE_ID = "facility-local"
FACILITY_SOURCE_REVISION = "facility-local-0.1.0"
FACILITY_AUDIENCE = "urn:registry-server:facility-demo"
FACILITY_OPERATOR_CLIENT = "facility-demo-operator"
FACILITY_SOUTH_OPERATOR_CLIENT = "facility-demo-south-operator"
FACILITY_OPERATOR_SCOPE = "registry:facility:operate"
INSPECTION_DATABASE_ID = "inspection-demo"
INSPECTION_INSTANCE_ID = "inspection-local"
INSPECTION_SOURCE_REVISION = "inspection-local-0.1.0"
INSPECTION_AUDIENCE = "urn:registry-server:inspection-demo"
INSPECTION_INSPECTOR_CLIENT = "inspection-demo-inspector"
INSPECTION_NO_PURPOSE_CLIENT = "inspection-demo-no-purpose"
INSPECTION_INSPECTOR_SCOPE = "registry:inspection:inspect"
DEFAULT_FIXTURE_KIND = "business-establishments"
DEFAULT_TOKEN_LIFETIME_SECONDS = 300
MIN_TOKEN_LIFETIME_SECONDS = 60
MAX_TOKEN_LIFETIME_SECONDS = 900
MIGRATION_ROLE = "registry_demo_migration"
RUNTIME_ROLE = "registry_demo_runtime"
TEST_DATABASE = "registry_demo_test"
RUNTIME_DATABASE = "registry_demo"
EXPECTED_PROJECT_REPLACEMENTS = {
    "  environment: acceptance": "  environment: local",
    "  instanceId: publicschema-household-acceptance": f"  instanceId: {INSTANCE_ID}",
    "  sourceRevision: publicschema-household-acceptance-0.1.0": f"  sourceRevision: {SOURCE_REVISION}",
}
ASSET_SITE_PROJECT_REPLACEMENTS = {
    "  environment: acceptance": "  environment: local",
    "  instanceId: asset-site-placement-acceptance": f"  instanceId: {ASSET_SITE_INSTANCE_ID}",
    "  sourceRevision: asset-site-placement-acceptance-0.1.0": f"  sourceRevision: {ASSET_SITE_SOURCE_REVISION}",
}
FACILITY_PROJECT_REPLACEMENTS = {
    "  environment: acceptance": "  environment: local",
    "  instanceId: facility-acceptance": f"  instanceId: {FACILITY_INSTANCE_ID}",
    "  sourceRevision: facility-acceptance-0.1.0": f"  sourceRevision: {FACILITY_SOURCE_REVISION}",
}
INSPECTION_PROJECT_REPLACEMENTS = {
    "  environment: acceptance": "  environment: local",
    "  instanceId: inspection-acceptance": f"  instanceId: {INSPECTION_INSTANCE_ID}",
    "  sourceRevision: inspection-acceptance-0.1.0": f"  sourceRevision: {INSPECTION_SOURCE_REVISION}",
}
BUSINESS_PROJECT_REPLACEMENTS = {
    "  environment: acceptance": "  environment: local",
    "  instanceId: business-establishments-acceptance": f"  instanceId: {BUSINESS_INSTANCE_ID}",
    "  sourceRevision: business-establishments-acceptance-0.1.0": f"  sourceRevision: {BUSINESS_SOURCE_REVISION}",
}
WEBHOOK_DESTINATION_ID = "household-event-receiver"
WEBHOOK_EVENT_ID = "usual-resident-created-v1"
WEBHOOK_MODULE_ID = "publicschema-household-demographics"
WEBHOOK_MODULE_LOCK = "  - id: publicschema-household-demographics\n    version: 0.1.0\n"
WEBHOOK_ENTITY_INSERTION = "  - entity: household\n"
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


FIXTURE_CONFIGS: dict[str, dict[str, Any]] = {
    "business-establishments": {
        "registry_id": "business-establishments",
        "database_id": BUSINESS_DATABASE_ID,
        "instance_id": BUSINESS_INSTANCE_ID,
        "source_revision": BUSINESS_SOURCE_REVISION,
        "audience": BUSINESS_AUDIENCE,
        "replacements": BUSINESS_PROJECT_REPLACEMENTS,
        "allowed_clients": [
            BUSINESS_OPERATOR_CLIENT,
            BUSINESS_NO_PURPOSE_CLIENT,
            BUSINESS_VIEWER_CLIENT,
        ],
        "personas": [
            {
                "id": "business-operator",
                "label": "Business operator",
                "token_name": "operator-token",
                "access_profile": "business-operator",
            },
            {
                "id": "business-viewer",
                "label": "Business viewer",
                "token_name": "viewer-token",
                "access_profile": "business-viewer",
            },
        ],
        "webhook": {
            "destination_id": "business-event-receiver",
            "event_id": "operating-created-v1",
            "module_id": "business-establishment-summary",
            "module_lock": "  - id: business-establishment-summary\n    version: 0.1.0\n",
            "entity_insertion": "  - entity: business\n",
            "module_source": """    events:
      - id: operating-created-v1
        trigger: created
        projection: [establishment-code, operating-status]
        when:
          kind: fields
          afterEquals:
            operating-status: operating
        webhook:
          destinationId: business-event-receiver
""",
            "entity": "establishment",
            "event_values": {"establishment-code", "operating-status"},
        },
    },
    "household": {
        "registry_id": "publicschema-household",
        "database_id": DATABASE_ID,
        "instance_id": INSTANCE_ID,
        "source_revision": SOURCE_REVISION,
        "audience": AUDIENCE,
        "replacements": EXPECTED_PROJECT_REPLACEMENTS,
        "allowed_clients": [OPERATOR_CLIENT, NO_PURPOSE_CLIENT, VIEWER_CLIENT],
        "personas": [
            {
                "id": "household-operator",
                "label": "Household operator",
                "token_name": "operator-token",
                "access_profile": "household-operator",
            },
            {
                "id": "household-viewer",
                "label": "Household viewer",
                "token_name": "viewer-token",
                "access_profile": "household-viewer",
            },
        ],
        "webhook": {
            "destination_id": WEBHOOK_DESTINATION_ID,
            "event_id": WEBHOOK_EVENT_ID,
            "module_id": WEBHOOK_MODULE_ID,
            "module_lock": WEBHOOK_MODULE_LOCK,
            "entity_insertion": WEBHOOK_ENTITY_INSERTION,
            "module_source": WEBHOOK_MODULE_SOURCE,
            "entity": "person",
            "event_values": {"person-code", "residency-status"},
        },
    },
    "asset-site": {
        "registry_id": "asset-site-placement",
        "database_id": ASSET_SITE_DATABASE_ID,
        "instance_id": ASSET_SITE_INSTANCE_ID,
        "source_revision": ASSET_SITE_SOURCE_REVISION,
        "audience": ASSET_SITE_AUDIENCE,
        "replacements": ASSET_SITE_PROJECT_REPLACEMENTS,
        "allowed_clients": [
            ASSET_OPERATOR_CLIENT,
            ASSET_PLANNER_CLIENT,
            ASSET_PLANNER_NO_PURPOSE_CLIENT,
        ],
        "personas": [
            {
                "id": "asset-operator",
                "label": "Asset operator",
                "token_name": "operator-token",
                "access_profile": "asset-operator",
            },
            {
                "id": "site-planner",
                "label": "Site planner",
                "token_name": "planner-token",
                "access_profile": "site-planner",
            },
        ],
    },
    "facility": {
        "registry_id": "facility",
        "database_id": FACILITY_DATABASE_ID,
        "instance_id": FACILITY_INSTANCE_ID,
        "source_revision": FACILITY_SOURCE_REVISION,
        "audience": FACILITY_AUDIENCE,
        "replacements": FACILITY_PROJECT_REPLACEMENTS,
        "allowed_clients": [
            FACILITY_OPERATOR_CLIENT,
            FACILITY_SOUTH_OPERATOR_CLIENT,
        ],
        "personas": [
            {
                "id": "facility-operator",
                "label": "Facility operator",
                "token_name": "operator-token",
                "access_profile": "facility-operator",
            },
        ],
    },
    "inspection": {
        "registry_id": "inspection",
        "database_id": INSPECTION_DATABASE_ID,
        "instance_id": INSPECTION_INSTANCE_ID,
        "source_revision": INSPECTION_SOURCE_REVISION,
        "audience": INSPECTION_AUDIENCE,
        "replacements": INSPECTION_PROJECT_REPLACEMENTS,
        "allowed_clients": [
            INSPECTION_INSPECTOR_CLIENT,
            INSPECTION_NO_PURPOSE_CLIENT,
        ],
        "personas": [
            {
                "id": "inspection-inspector",
                "label": "Inspection inspector",
                "token_name": "operator-token",
                "access_profile": "inspection-inspector",
            },
        ],
    },
}


def _fixture_config(fixture_kind: str) -> dict[str, Any]:
    try:
        return FIXTURE_CONFIGS[fixture_kind]
    except KeyError as error:
        raise DemoError(
            "fixture must be business-establishments, household, asset-site, facility, or inspection"
        ) from error


def _fixture_kind_for_root(root: Path) -> str:
    marker = root / "fixture-kind"
    if not marker.exists():
        return DEFAULT_FIXTURE_KIND
    return marker.read_text(encoding="ascii").strip()


def _webhook_config(fixture_kind: str) -> dict[str, Any]:
    config = _fixture_config(fixture_kind)
    webhook = config.get("webhook")
    if not isinstance(webhook, dict):
        raise DemoError(f"the webhook demo is not available for the {fixture_kind} fixture")
    return webhook


def _validated_token_lifetime_seconds(value: int) -> int:
    if value < MIN_TOKEN_LIFETIME_SECONDS or value > MAX_TOKEN_LIFETIME_SECONDS:
        raise DemoError("token lifetime seconds must be between 60 and 900")
    return value


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


def _replace_once(source: str, expected: str, replacement: str, description: str) -> str:
    if source.count(expected) != 1:
        raise DemoError(description)
    return source.replace(expected, replacement, 1)


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


def _local_project(
    root: Path,
    fixture: Path,
    webhook: bool,
    fixture_kind: str = DEFAULT_FIXTURE_KIND,
) -> None:
    target = root / "project"
    shutil.copytree(fixture, target, ignore=shutil.ignore_patterns(".DS_Store"))
    project_path = target / "registry.yaml"
    source = project_path.read_text(encoding="utf-8")
    config = _fixture_config(fixture_kind)
    for expected, replacement in config["replacements"].items():
        source = _replace_once(
            source,
            expected,
            replacement,
            f"{fixture_kind} fixture no longer has the expected package line: {expected.strip()}",
        )
    if webhook:
        hook = _webhook_config(fixture_kind)
        module_lock = hook["module_lock"]
        if source.count(module_lock) != 1:
            raise DemoError(f"{fixture_kind} fixture no longer has the expected webhook module lock")
        before_lock, after_lock = source.split(module_lock, 1)
        digest_line, separator, after_digest = after_lock.partition("\n")
        digest = digest_line.removeprefix("    digest: ")
        if (
            not separator
            or not digest.startswith("sha256:")
            or len(digest) != 71
        ):
            raise DemoError(f"{fixture_kind} fixture no longer has the expected webhook module digest")
        source = before_lock + module_lock + after_digest
        module_path = target / f"modules/{hook['module_id']}/module.yaml"
        module_source = module_path.read_text(encoding="utf-8")
        if (
            "    events:\n" in module_source
            or module_source.count(hook["entity_insertion"]) != 1
            or not module_source.endswith("\n")
        ):
            raise DemoError(f"{fixture_kind} webhook module cannot receive the demo event")
        module_path.write_text(
            module_source.replace(
                hook["entity_insertion"],
                hook["module_source"] + hook["entity_insertion"],
                1,
            ),
            encoding="utf-8",
        )
    if fixture_kind == "asset-site":
        source = _replace_once(
            source,
            "  - id: asset-operator\n    default: true\n    principalClaim: registry_principal\n    requiredPurposes:",
            "  - id: asset-operator\n    default: true\n    principalClaim: registry_principal\n"
            f"    requiredScopes: [{ASSET_OPERATOR_SCOPE}]\n    requiredPurposes:",
            "asset-site fixture no longer has the expected asset-operator access profile",
        )
        source = _replace_once(
            source,
            "  - id: site-planner\n    principalClaim: registry_principal\n    requiredPurposes:",
            "  - id: site-planner\n    principalClaim: registry_principal\n"
            f"    requiredScopes: [{ASSET_PLANNER_SCOPE}]\n    requiredPurposes:",
            "asset-site fixture no longer has the expected site-planner access profile",
        )
        journeys_path = target / "tests/journeys.yaml"
        journeys = journeys_path.read_text(encoding="utf-8")
        journeys = _replace_once(
            journeys,
            "        claims: &asset_operator_claims\n"
            "          principal: synthetic-asset-operator\n"
            "          purpose: asset-management\n",
            "        claims: &asset_operator_claims\n"
            "          principal: synthetic-asset-operator\n"
            f"          scopes: [{ASSET_OPERATOR_SCOPE}]\n"
            "          purpose: asset-management\n",
            "asset-site fixture no longer has the expected operator journey claims",
        )
        journeys = _replace_once(
            journeys,
            "        claims: &site_planner_claims\n"
            "          principal: synthetic-site-planner\n"
            "          purpose: site-planning\n",
            "        claims: &site_planner_claims\n"
            "          principal: synthetic-site-planner\n"
            f"          scopes: [{ASSET_PLANNER_SCOPE}]\n"
            "          purpose: site-planning\n",
            "asset-site fixture no longer has the expected planner journey claims",
        )
        no_purpose_claims = (
            "        claims:\n"
            "          principal: synthetic-site-planner\n"
            "        request:\n"
            "          operation: get\n"
            "          recordRef: renamed-asset\n"
        )
        journeys = _replace_once(
            journeys,
            no_purpose_claims,
            "        claims:\n"
            "          principal: synthetic-site-planner\n"
            f"          scopes: [{ASSET_PLANNER_SCOPE}]\n"
            "        request:\n"
            "          operation: get\n"
            "          recordRef: renamed-asset\n",
            "asset-site fixture no longer has the expected no-purpose planner step",
        )
        journeys_path.write_text(journeys, encoding="utf-8")
    elif fixture_kind == "facility":
        source = _replace_once(
            source,
            "  - id: facility-operator\n    principalClaim: registry_principal\n    requiredPurposes:",
            "  - id: facility-operator\n    principalClaim: registry_principal\n"
            f"    requiredScopes: [{FACILITY_OPERATOR_SCOPE}]\n    requiredPurposes:",
            "facility fixture no longer has the expected operator access profile",
        )
        entity_row_boundary = "          claim: administrative_boundaries\n          operator: in"
        grant_row_boundary = "            claim: administrative_boundaries\n            operator: in"
        if source.count(entity_row_boundary) != 1 or source.count(grant_row_boundary) != 4:
            raise DemoError("facility fixture no longer has the expected row-boundary operators")
        source = source.replace(
            entity_row_boundary,
            "          claim: administrative_boundaries\n          operator: equals",
        )
        source = source.replace(
            grant_row_boundary,
            "            claim: administrative_boundaries\n            operator: equals",
        )
        journeys_path = target / "tests/journeys.yaml"
        journeys = journeys_path.read_text(encoding="utf-8")
        journeys = _replace_once(
            journeys,
            "        claims: &north_operator_claims\n"
            "          principal: synthetic-facility-operator\n"
            "          purpose: facility-registry\n",
            "        claims: &north_operator_claims\n"
            "          principal: synthetic-facility-operator\n"
            f"          scopes: [{FACILITY_OPERATOR_SCOPE}]\n"
            "          purpose: facility-registry\n",
            "facility fixture no longer has the expected north operator journey claims",
        )
        journeys = _replace_once(
            journeys,
            "        claims:\n"
            "          principal: synthetic-facility-operator\n"
            "          purpose: facility-registry\n",
            "        claims:\n"
            "          principal: synthetic-facility-operator\n"
            f"          scopes: [{FACILITY_OPERATOR_SCOPE}]\n"
            "          purpose: facility-registry\n",
            "facility fixture no longer has the expected south operator journey claims",
        )
        journeys_path.write_text(journeys, encoding="utf-8")
    elif fixture_kind == "inspection":
        source = _replace_once(
            source,
            "  - id: inspection-inspector\n    principalClaim: registry_principal\n    requiredPurposes:",
            "  - id: inspection-inspector\n    principalClaim: registry_principal\n"
            f"    requiredScopes: [{INSPECTION_INSPECTOR_SCOPE}]\n    requiredPurposes:",
            "inspection fixture no longer has the expected inspector access profile",
        )
        journeys_path = target / "tests/journeys.yaml"
        journeys = journeys_path.read_text(encoding="utf-8")
        journeys = _replace_once(
            journeys,
            "        claims: &inspection_inspector_claims\n"
            "          principal: synthetic-inspection-inspector\n"
            "          purpose: facility-inspection\n",
            "        claims: &inspection_inspector_claims\n"
            "          principal: synthetic-inspection-inspector\n"
            f"          scopes: [{INSPECTION_INSPECTOR_SCOPE}]\n"
            "          purpose: facility-inspection\n",
            "inspection fixture no longer has the expected inspector journey claims",
        )
        journeys = _replace_once(
            journeys,
            "        claims:\n"
            "          principal: synthetic-inspection-inspector\n"
            "        request:\n",
            "        claims:\n"
            "          principal: synthetic-inspection-inspector\n"
            f"          scopes: [{INSPECTION_INSPECTOR_SCOPE}]\n"
            "        request:\n",
            "inspection fixture no longer has the expected no-purpose inspector journey claims",
        )
        journeys_path.write_text(journeys, encoding="utf-8")
    project_path.write_text(source, encoding="utf-8")


def bind_webhook_module(
    root: Path,
    explain_report: Path,
    fixture_kind: str | None = None,
) -> None:
    root = _require_root(root)
    fixture_kind = fixture_kind or _fixture_kind_for_root(root)
    hook = _webhook_config(fixture_kind)
    report = _read_json_object(explain_report)
    closure = report.get("explanation", {}).get("moduleClosure")
    if not isinstance(closure, list):
        raise DemoError("compiled model report has no module closure")
    matching = [
        entry
        for entry in closure
        if isinstance(entry, dict) and entry.get("id") == hook["module_id"]
    ]
    if len(matching) != 1:
        raise DemoError("compiled model report does not identify the demo webhook module")
    digest = matching[0].get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
        raise DemoError("compiled model report has no canonical demo webhook module digest")
    project_path = root / "project/registry.yaml"
    source = project_path.read_text(encoding="utf-8")
    module_lock = hook["module_lock"]
    if source.count(module_lock) != 1:
        raise DemoError("demo webhook module lock is not ready for its compiled digest")
    source = source.replace(
        module_lock,
        module_lock + f"    digest: {digest}\n",
        1,
    )
    project_path.write_text(source, encoding="utf-8")


def _mint_client(
    client_id: str,
    public_key: dict[str, Any],
    scopes: list[str],
    claims: dict[str, Any],
) -> str:
    rendered_scopes = ", ".join(
        json.dumps(scope, ensure_ascii=True, separators=(",", ":")) for scope in scopes
    )
    rendered_claims = "".join(
        f"    {name}: {json.dumps(value, ensure_ascii=True, separators=(',', ':'))}\n"
        for name, value in sorted(claims.items())
    )
    return (
        f"clientId: {client_id}\n"
        f"principal: urn:registry-server:demo:{client_id}\n"
        "authorization:\n"
        f"  scopes: [{rendered_scopes}]\n"
        "  claims:\n"
        f"{rendered_claims}"
        f"keys: [{json.dumps(public_key, sort_keys=True, separators=(',', ':'))}]\n"
    )


def _runtime_config(
    root: Path,
    package_root: Path,
    revision: str,
    bind: str,
    webhook: bool = False,
    fixture_kind: str = DEFAULT_FIXTURE_KIND,
    token_lifetime_seconds: int = DEFAULT_TOKEN_LIFETIME_SECONDS,
) -> str:
    config = _fixture_config(fixture_kind)
    token_lifetime_seconds = _validated_token_lifetime_seconds(token_lifetime_seconds)
    secrets = root / "secrets"
    if webhook:
        hook = _webhook_config(fixture_kind)
        receiver_origin = root.joinpath("receiver-origin").read_text(encoding="ascii").strip()
        event_destinations = f"""eventDestinations:
  {hook["destination_id"]}:
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
    return f"""apiVersion: registry.registrystack.org/server-runtime/v1alpha1
kind: RegistryServerRuntimeConfig
listener:
  bind: {bind}
  trustedProxy: direct
identity:
  environment: local
  instanceId: {config["instance_id"]}
  databaseId: {config["database_id"]}
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
  compilerSourceRevision: {config["source_revision"]}
  activeRevision: {revision}
  activeSequence: 1
authentication:
  oidc:
    issuer: {root.joinpath('mint-origin').read_text(encoding='ascii').strip()}
    audience: {config["audience"]}
    allowedAlgorithm: ES256
    accessTokenType: at+jwt
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [{", ".join(config["allowed_clients"])}]
    deniedKids: []
    maxTokenLifetimeSeconds: {token_lifetime_seconds}
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
    fixture_kind: str = DEFAULT_FIXTURE_KIND,
    token_lifetime_seconds: int = DEFAULT_TOKEN_LIFETIME_SECONDS,
) -> None:
    root = _require_root(root)
    config = _fixture_config(fixture_kind)
    token_lifetime_seconds = _validated_token_lifetime_seconds(token_lifetime_seconds)
    fixture = fixture.resolve()
    if not (fixture / "registry.yaml").is_file():
        raise DemoError(f"{fixture_kind} fixture is missing registry.yaml")
    password_path = root / "secrets/database-password"
    password = password_path.read_text(encoding="ascii").strip()
    if not password or any(character not in "0123456789abcdef" for character in password):
        raise DemoError("database password must be non-empty lowercase hexadecimal")

    if webhook and receiver_port is None:
        raise DemoError("the webhook demo requires a receiver port")
    _local_project(root, fixture, webhook, fixture_kind)
    mint_public = _read_json_object(root / "keys/mint-public.jwk.json")
    operator_public = _read_json_object(root / "keys/operator-public.jwk.json")
    no_purpose_public = (
        _read_json_object(root / "keys/no-purpose-public.jwk.json")
        if fixture_kind in ("business-establishments", "household", "inspection")
        else None
    )
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
    if fixture_kind == "business-establishments":
        if no_purpose_public is None:
            raise DemoError("business no-purpose key material is missing")
        _write_new(
            root / f"mint/clients/{BUSINESS_OPERATOR_CLIENT}.yaml",
            _mint_client(
                BUSINESS_OPERATOR_CLIENT,
                operator_public,
                ["registry:business:operate"],
                {
                    "registry_principal": "synthetic-business-operator",
                    "registry_purpose": "business-administration",
                },
            ),
        )
        _write_new(
            root / f"mint/clients/{BUSINESS_NO_PURPOSE_CLIENT}.yaml",
            _mint_client(
                BUSINESS_NO_PURPOSE_CLIENT,
                no_purpose_public,
                ["registry:business:operate"],
                {"registry_principal": "synthetic-business-operator"},
            ),
        )
    elif fixture_kind == "household":
        if no_purpose_public is None:
            raise DemoError("household no-purpose key material is missing")
        _write_new(
            root / f"mint/clients/{OPERATOR_CLIENT}.yaml",
            _mint_client(
                OPERATOR_CLIENT,
                operator_public,
                ["registry:household:operate"],
                {
                    "registry_principal": "synthetic-household-operator",
                    "registry_purpose": "household-administration",
                },
            ),
        )
        _write_new(
            root / f"mint/clients/{NO_PURPOSE_CLIENT}.yaml",
            _mint_client(
                NO_PURPOSE_CLIENT,
                no_purpose_public,
                ["registry:household:operate"],
                {"registry_principal": "synthetic-household-operator"},
            ),
        )
    elif fixture_kind == "asset-site":
        planner_public = _read_json_object(root / "keys/planner-public.jwk.json")
        planner_no_purpose_public = _read_json_object(
            root / "keys/planner-no-purpose-public.jwk.json"
        )
        _write_new(
            root / f"mint/clients/{ASSET_OPERATOR_CLIENT}.yaml",
            _mint_client(
                ASSET_OPERATOR_CLIENT,
                operator_public,
                [ASSET_OPERATOR_SCOPE],
                {
                    "registry_principal": "synthetic-asset-operator",
                    "registry_purpose": "asset-management",
                },
            ),
        )
        _write_new(
            root / f"mint/clients/{ASSET_PLANNER_CLIENT}.yaml",
            _mint_client(
                ASSET_PLANNER_CLIENT,
                planner_public,
                [ASSET_PLANNER_SCOPE],
                {
                    "registry_principal": "synthetic-site-planner",
                    "registry_purpose": "site-planning",
                },
            ),
        )
        _write_new(
            root / f"mint/clients/{ASSET_PLANNER_NO_PURPOSE_CLIENT}.yaml",
            _mint_client(
                ASSET_PLANNER_NO_PURPOSE_CLIENT,
                planner_no_purpose_public,
                [ASSET_PLANNER_SCOPE],
                {"registry_principal": "synthetic-site-planner"},
            ),
        )
    elif fixture_kind == "facility":
        south_operator_public = _read_json_object(root / "keys/south-operator-public.jwk.json")
        _write_new(
            root / f"mint/clients/{FACILITY_OPERATOR_CLIENT}.yaml",
            _mint_client(
                FACILITY_OPERATOR_CLIENT,
                operator_public,
                [FACILITY_OPERATOR_SCOPE],
                {
                    "administrative_boundaries": "north-district",
                    "registry_principal": "synthetic-facility-operator",
                    "registry_purpose": "facility-registry",
                },
            ),
        )
        _write_new(
            root / f"mint/clients/{FACILITY_SOUTH_OPERATOR_CLIENT}.yaml",
            _mint_client(
                FACILITY_SOUTH_OPERATOR_CLIENT,
                south_operator_public,
                [FACILITY_OPERATOR_SCOPE],
                {
                    "administrative_boundaries": "south-district",
                    "registry_principal": "synthetic-facility-operator",
                    "registry_purpose": "facility-registry",
                },
            ),
        )
    elif fixture_kind == "inspection":
        if no_purpose_public is None:
            raise DemoError("inspection no-purpose key material is missing")
        _write_new(
            root / f"mint/clients/{INSPECTION_INSPECTOR_CLIENT}.yaml",
            _mint_client(
                INSPECTION_INSPECTOR_CLIENT,
                operator_public,
                [INSPECTION_INSPECTOR_SCOPE],
                {
                    "registry_principal": "synthetic-inspection-inspector",
                    "registry_purpose": "facility-inspection",
                },
            ),
        )
        _write_new(
            root / f"mint/clients/{INSPECTION_NO_PURPOSE_CLIENT}.yaml",
            _mint_client(
                INSPECTION_NO_PURPOSE_CLIENT,
                no_purpose_public,
                [INSPECTION_INSPECTOR_SCOPE],
                {"registry_principal": "synthetic-inspection-inspector"},
            ),
        )
    else:
        raise AssertionError(fixture_kind)
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
  audiences: [{config["audience"]}]
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
        fixture_kind,
        token_lifetime_seconds,
    )
    test_runtime = test_runtime.replace(
        "secret:file/runtime-database-url", "secret:file/test-runtime-database-url"
    ).replace(
        "secret:file/migration-database-url", "secret:file/test-migration-database-url"
    )
    _write_new(root / "runtime-test.yaml", test_runtime)
    if fixture_kind == "business-establishments":
        credentials = f"""apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings:
  - {{journeyId: business-establishment-lifecycle, stepId: create-north-head-office, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: create-production-branch, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: create-central-head-office, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: create-central-branch, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: create-central-depot, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: create-isolation-head-office, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: create-isolation-regional-office, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: create-isolation-branch, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: create-north-business, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: create-central-business, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: create-isolation-business, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: lookup-north-business, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: read-establishments-from-north-business, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: query-establishment-summary, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: refuse-incomplete-assignment, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: business-establishment-lifecycle, stepId: operator-without-purpose-is-concealed, credential: {{type: bearer, tokenRef: secret:file/no-purpose-token}}}}
"""
    elif fixture_kind == "household":
        credentials = f"""apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
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
  - {{journeyId: household-person-lifecycle, stepId: lookup-single-headed-household, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: read-people-from-single-headed-household, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: query-household-demographics, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: refuse-incomplete-membership, credential: {{type: bearer, tokenRef: secret:file/operator-token}}}}
  - {{journeyId: household-person-lifecycle, stepId: operator-without-purpose-is-concealed, credential: {{type: bearer, tokenRef: secret:file/no-purpose-token}}}}
"""
    elif fixture_kind == "asset-site":
        credentials = """apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings:
  - {journeyId: asset-and-site-caller-surfaces, stepId: create-asset, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: planner-gets-asset, credential: {type: bearer, tokenRef: secret:file/planner-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: planner-lists-assets, credential: {type: bearer, tokenRef: secret:file/planner-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: operator-renames-asset, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: create-site, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: planner-gets-site, credential: {type: bearer, tokenRef: secret:file/planner-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: planner-lists-sites, credential: {type: bearer, tokenRef: secret:file/planner-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: planner-without-purpose-is-concealed, credential: {type: bearer, tokenRef: secret:file/planner-no-purpose-token}}
"""
    elif fixture_kind == "facility":
        credentials = """apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings:
  - {journeyId: bounded-facility-and-batch-validation, stepId: create-north-district-facility, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: bounded-facility-and-batch-validation, stepId: get-north-district-facility, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: bounded-facility-and-batch-validation, stepId: rename-north-district-facility, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: bounded-facility-and-batch-validation, stepId: list-north-district-facilities, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: bounded-facility-and-batch-validation, stepId: south-district-claim-cannot-see-north-record, credential: {type: bearer, tokenRef: secret:file/south-operator-token}}
  - {journeyId: bounded-facility-and-batch-validation, stepId: batch-refuses-out-of-bounds-installation, credential: {type: bearer, tokenRef: secret:file/operator-token}}
"""
    elif fixture_kind == "inspection":
        credentials = """apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings:
  - {journeyId: inspection-and-schema-validation, stepId: create-inspection, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: inspection-and-schema-validation, stepId: close-inspection, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: inspection-and-schema-validation, stepId: get-closed-inspection, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: inspection-and-schema-validation, stepId: list-inspections, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: inspection-and-schema-validation, stepId: refuse-undeclared-observation-metadata, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: inspection-and-schema-validation, stepId: inspector-without-purpose-is-concealed, credential: {type: bearer, tokenRef: secret:file/no-purpose-token}}
"""
    else:
        raise AssertionError(fixture_kind)
    _write_new(root / "schema-test-credentials.yaml", credentials)


def render_runtime(
    root: Path,
    revision: str,
    webhook: bool = False,
    fixture_kind: str = DEFAULT_FIXTURE_KIND,
    token_lifetime_seconds: int = DEFAULT_TOKEN_LIFETIME_SECONDS,
) -> None:
    root = _require_root(root)
    if not revision.startswith("sha256:") or len(revision) != 71:
        raise DemoError("package revision must be one SHA-256 identifier")
    token_lifetime_seconds = _validated_token_lifetime_seconds(token_lifetime_seconds)
    bind = urllib.parse.urlparse((root / "server-origin").read_text(encoding="ascii").strip()).netloc
    _write_new(
        root / "runtime.yaml",
        _runtime_config(
            root,
            root / "build/package",
            revision,
            bind,
            webhook,
            fixture_kind,
            token_lifetime_seconds,
        ),
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
    fixture_kind: str = DEFAULT_FIXTURE_KIND,
) -> tuple[str, int, int, str]:
    config = _fixture_config(fixture_kind)
    hook = _webhook_config(fixture_kind)
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
    if event_uuid != headers["ce-id"] or headers["ce-type"] != hook["event_id"]:
        raise DemoError("the receiver refused the CloudEvents identity")
    expected_source = (
        f"urn:registrystack:registry:{config['registry_id']}:"
        f"instance:{config['instance_id']}"
    )
    if headers["ce-source"] != expected_source:
        raise DemoError("the receiver refused the CloudEvents source")
    expected_schema_prefix = (
        f"urn:registry-server:event-schema:{config['registry_id']}:{hook['entity']}:"
        f"{hook['event_id']}:sha256:"
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
        document["entity"] != hook["entity"]
        or document["trigger"] != "created"
        or not isinstance(document["revision"], int)
        or document["revision"] < 1
        or not isinstance(document["packageRevision"], str)
        or not document["packageRevision"].startswith("sha256:")
        or str(uuid.UUID(document["recordId"])) != document["recordId"]
        or not isinstance(document["values"], dict)
        or set(document["values"]) != hook["event_values"]
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
            fixture_kind: str = self.server.fixture_kind  # type: ignore[attr-defined]
            event_id, generation, attempt, idempotency_key = _verify_webhook_request(
                key, self.path, headers, body, fixture_kind
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
    fixture_kind = _fixture_kind_for_root(root)
    _webhook_config(fixture_kind)
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
    server.fixture_kind = fixture_kind  # type: ignore[attr-defined]
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
    fixture_kind = _fixture_kind_for_root(root)
    state = _read_json_object(root / "webhook-receiver-state.json")
    events = sorted(state.get("events", {}).values(), key=lambda event: event.get("slot", 0))
    if fixture_kind == "business-establishments":
        establishments, _, _ = business_seed_spec()
        expected_events = sum(
            item.get("operatingStatus") == "operating" for item in establishments
        )
    elif fixture_kind == "household":
        people, _, _ = seed_spec()
        expected_events = sum(
            person.get("residencyStatus") == "usual-resident" for person in people
        )
    else:
        raise DemoError(f"the webhook demo is not available for the {fixture_kind} fixture")
    if state.get("verificationFailures") != 0 or len(events) != expected_events:
        raise DemoError("the webhook receiver did not verify every matching seeded event")
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
    if any(
        not any(
            item.get("accepted")
            and item.get("generation") == 1
            and item.get("attempt") == 1
            for item in event.get("attempts", [])
        )
        for event in events[3:]
    ):
        raise DemoError("the webhook receiver did not accept the remaining seeded events")


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


def _create(
    root: Path,
    route: str,
    logical_key: str,
    data: dict[str, Any],
    access_profile: str = "household-operator",
    token_name: str = "operator-token",
) -> str:
    response, _ = _request(
        root,
        "POST",
        route + f"?accessProfile={urllib.parse.quote(access_profile, safe='')}",
        token_name,
        {"data": data},
        f"demo-{logical_key}",
        201,
    )
    identifier, _, _, _ = _profiled_record(response)
    return identifier


def business_seed_spec() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    establishments = [
        {"establishmentCode": "ESTABLISHMENT-DEMO-001", "siteName": "North Quay Head Office", "locality": "North Quay", "openedOn": "1986-02-22", "establishmentKind": "office", "operatingStatus": "operating", "preferredLanguage": "en"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-002", "siteName": "North Quay Riverside Works", "locality": "North Quay", "openedOn": "2023-03-14", "establishmentKind": "production", "operatingStatus": "operating", "preferredLanguage": "en"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-003", "siteName": "Central Fabrication Works", "locality": "Central District", "openedOn": "1980-11-02", "establishmentKind": "production", "operatingStatus": "operating", "preferredLanguage": "es"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-004", "siteName": "Central Distribution Branch", "locality": "Central District", "openedOn": "2016-06-17", "establishmentKind": "warehouse", "operatingStatus": "operating", "preferredLanguage": "es"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-005", "siteName": "Central Storage Depot", "locality": "Central District", "openedOn": "1940-08-20", "establishmentKind": "warehouse", "operatingStatus": "suspended", "preferredLanguage": "es"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-006", "siteName": "South Harbour Head Office", "locality": "South Harbour", "openedOn": "1975-01-09", "establishmentKind": "office", "operatingStatus": "operating", "preferredLanguage": "fr"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-007", "siteName": "South Harbour Regional Office", "locality": "South Harbour", "openedOn": "1977-09-23", "establishmentKind": "office", "operatingStatus": "operating", "preferredLanguage": "fr"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-008", "siteName": "South Harbour Branch", "locality": "South Harbour", "openedOn": "2018-05-06", "establishmentKind": "warehouse", "operatingStatus": "operating", "preferredLanguage": "fr"},
    ]
    businesses = [
        {"businessCode": "BUSINESS-DEMO-001", "localRegistrationNumber": 1001, "registeredName": "North Quay Engineering Ltd", "administrativeArea": "north-demo", "businessType": "private"},
        {"businessCode": "BUSINESS-DEMO-002", "localRegistrationNumber": 1002, "registeredName": "Central Fabrication Ltd", "administrativeArea": "central-demo", "businessType": "private"},
        {"businessCode": "BUSINESS-DEMO-003", "localRegistrationNumber": 1003, "registeredName": "South Harbour Logistics Ltd", "administrativeArea": "south-demo", "businessType": "private"},
    ]
    assignments = [
        {"establishmentCode": "ESTABLISHMENT-DEMO-001", "businessCode": "BUSINESS-DEMO-001", "relationship": "head-office", "validFrom": "2026-01-01"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-002", "businessCode": "BUSINESS-DEMO-001", "relationship": "branch", "validFrom": "2026-01-01"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-003", "businessCode": "BUSINESS-DEMO-002", "relationship": "head-office", "validFrom": "2026-01-01"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-004", "businessCode": "BUSINESS-DEMO-002", "relationship": "branch", "validFrom": "2026-01-01"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-005", "businessCode": "BUSINESS-DEMO-002", "relationship": "depot", "validFrom": "2026-01-01"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-006", "businessCode": "BUSINESS-DEMO-003", "relationship": "head-office", "validFrom": "2026-01-01"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-007", "businessCode": "BUSINESS-DEMO-003", "relationship": "regional-office", "validFrom": "2026-01-01"},
        {"establishmentCode": "ESTABLISHMENT-DEMO-008", "businessCode": "BUSINESS-DEMO-003", "relationship": "branch", "validFrom": "2026-01-01"},
    ]
    return establishments, businesses, assignments


def seed_business(root: Path) -> None:
    root = _require_root(root)
    establishments, businesses, assignments = business_seed_spec()
    establishment_ids = {
        establishment["establishmentCode"]: _create(
            root,
            "/v1/records/establishments",
            establishment["establishmentCode"].lower(),
            establishment,
            "business-operator",
            "operator-token",
        )
        for establishment in establishments
    }
    business_ids = {
        business["businessCode"]: _create(
            root,
            "/v1/records/businesses",
            business["businessCode"].lower(),
            business,
            "business-operator",
            "operator-token",
        )
        for business in businesses
    }
    for index, assignment in enumerate(assignments, start=1):
        _create(
            root,
            "/v1/records/operator-assignments",
            f"assignment-{index}",
            {
                "establishment": establishment_ids[assignment["establishmentCode"]],
                "business": business_ids[assignment["businessCode"]],
                "relationship": assignment["relationship"],
                "validFrom": assignment["validFrom"],
            },
            "business-operator",
            "operator-token",
        )
    _write_json(
        root / "seed-record-ids.json",
        {"establishments": establishment_ids, "businesses": business_ids},
    )
    establishments_response, _ = _request(
        root,
        "GET",
        "/v1/records/establishments?accessProfile=business-operator&$top=20",
        "operator-token",
    )
    business_response, _ = _request(
        root,
        "GET",
        "/v1/records/businesses?accessProfile=business-operator&$top=20",
        "operator-token",
    )
    assignment_response, _ = _request(
        root,
        "GET",
        "/v1/records/operator-assignments:current?accessProfile=business-operator&$top=20",
        "operator-token",
    )
    if [len(response.get("items", [])) for response in (establishments_response, business_response, assignment_response)] != [8, 3, 8]:
        raise DemoError("seeded list counts did not match the expected 8 establishments, 3 businesses, and 8 assignments")
    _request(
        root,
        "GET",
        f"/v1/records/establishments/{establishment_ids['ESTABLISHMENT-DEMO-001']}?accessProfile=business-operator",
        "no-purpose-token",
        expected=404,
    )
    print("Seeded 8 synthetic establishments, 3 businesses, and 8 current assignments.")


def seed_spec() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    people = [
        {"personCode": "PERSON-DEMO-001", "legalName": "Omar Example", "familyName": "Example", "dateOfBirth": "1986-02-22", "personSex": "male", "residencyStatus": "usual-resident", "preferredLanguage": "en"},
        {"personCode": "PERSON-DEMO-002", "legalName": "Lina Example", "familyName": "Example", "dateOfBirth": "2023-03-14", "personSex": "female", "residencyStatus": "usual-resident", "preferredLanguage": "en"},
        {"personCode": "PERSON-DEMO-003", "legalName": "Sofia Sample", "familyName": "Sample", "dateOfBirth": "1980-11-02", "personSex": "female", "residencyStatus": "usual-resident", "preferredLanguage": "es"},
        {"personCode": "PERSON-DEMO-004", "legalName": "Diego Sample", "familyName": "Sample", "dateOfBirth": "2016-06-17", "personSex": "male", "residencyStatus": "usual-resident", "preferredLanguage": "es"},
        {"personCode": "PERSON-DEMO-005", "legalName": "Rosa Sample", "familyName": "Sample", "dateOfBirth": "1940-08-20", "personSex": "female", "residencyStatus": "usual-resident", "preferredLanguage": "es"},
        {"personCode": "PERSON-DEMO-006", "legalName": "Karim Control", "familyName": "Control", "dateOfBirth": "1975-01-09", "personSex": "male", "residencyStatus": "usual-resident", "preferredLanguage": "fr"},
        {"personCode": "PERSON-DEMO-007", "legalName": "Hana Control", "familyName": "Control", "dateOfBirth": "1977-09-23", "personSex": "female", "residencyStatus": "usual-resident", "preferredLanguage": "fr"},
        {"personCode": "PERSON-DEMO-008", "legalName": "Noor Control", "familyName": "Control", "dateOfBirth": "2018-05-06", "personSex": "female", "residencyStatus": "usual-resident", "preferredLanguage": "fr"},
    ]
    households = [
        {"householdCode": "HOUSEHOLD-DEMO-001", "localHouseholdNumber": 1001, "householdName": "Single Headed Under Five Household", "administrativeArea": "north-demo", "householdType": "private"},
        {"householdCode": "HOUSEHOLD-DEMO-002", "localHouseholdNumber": 1002, "householdName": "Woman Headed Child Elderly Household", "administrativeArea": "central-demo", "householdType": "private"},
        {"householdCode": "HOUSEHOLD-DEMO-003", "localHouseholdNumber": 1003, "householdName": "Isolation Control Household", "administrativeArea": "south-demo", "householdType": "private"},
    ]
    memberships = [
        {"personCode": "PERSON-DEMO-001", "householdCode": "HOUSEHOLD-DEMO-001", "relationship": "head", "validFrom": "2026-01-01"},
        {"personCode": "PERSON-DEMO-002", "householdCode": "HOUSEHOLD-DEMO-001", "relationship": "child", "validFrom": "2026-01-01"},
        {"personCode": "PERSON-DEMO-003", "householdCode": "HOUSEHOLD-DEMO-002", "relationship": "head", "validFrom": "2026-01-01"},
        {"personCode": "PERSON-DEMO-004", "householdCode": "HOUSEHOLD-DEMO-002", "relationship": "child", "validFrom": "2026-01-01"},
        {"personCode": "PERSON-DEMO-005", "householdCode": "HOUSEHOLD-DEMO-002", "relationship": "dependent", "validFrom": "2026-01-01"},
        {"personCode": "PERSON-DEMO-006", "householdCode": "HOUSEHOLD-DEMO-003", "relationship": "head", "validFrom": "2026-01-01"},
        {"personCode": "PERSON-DEMO-007", "householdCode": "HOUSEHOLD-DEMO-003", "relationship": "spouse", "validFrom": "2026-01-01"},
        {"personCode": "PERSON-DEMO-008", "householdCode": "HOUSEHOLD-DEMO-003", "relationship": "child", "validFrom": "2026-01-01"},
    ]
    return people, households, memberships


def seed(root: Path) -> None:
    root = _require_root(root)
    people, households, memberships = seed_spec()
    person_ids = {
        person["personCode"]: _create(root, "/v1/records/persons", person["personCode"].lower(), person)
        for person in people
    }
    household_ids = {
        household["householdCode"]: _create(
            root, "/v1/records/households", household["householdCode"].lower(), household
        )
        for household in households
    }
    for index, membership in enumerate(memberships, start=1):
        _create(
            root,
            "/v1/records/group-memberships",
            f"membership-{index}",
            {
                "person": person_ids[membership["personCode"]],
                "household": household_ids[membership["householdCode"]],
                "relationship": membership["relationship"],
                "validFrom": membership["validFrom"],
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


def seed_asset_site(root: Path) -> None:
    root = _require_root(root)
    asset_id = _create(
        root,
        "/v1/records/assets",
        "asset-synth-001",
        {"assetCode": "ASSET-SYNTH-001", "label": "Synthetic water pump", "assetClass": "equipment"},
        "asset-operator",
        "operator-token",
    )
    site_id = _create(
        root,
        "/v1/records/sites",
        "site-synth-001",
        {"siteCode": "SITE-SYNTH-001", "label": "Synthetic northern depot"},
        "asset-operator",
        "operator-token",
    )
    placement_id = _create(
        root,
        "/v1/records/placements",
        "placement-synth-001",
        {"asset": asset_id, "site": site_id, "validFrom": "2026-01-01"},
        "asset-operator",
        "operator-token",
    )
    inspection_id = _create(
        root,
        "/v1/records/inspections",
        "inspection-synth-001",
        {"asset": asset_id, "observedAt": "2026-01-15T10:00:00Z", "result": "passed"},
        "asset-operator",
        "operator-token",
    )
    _write_json(
        root / "seed-record-ids.json",
        {
            "assets": {"ASSET-SYNTH-001": asset_id},
            "sites": {"SITE-SYNTH-001": site_id},
            "placements": {"PLACEMENT-SYNTH-001": placement_id},
            "inspections": {"INSPECTION-SYNTH-001": inspection_id},
        },
    )
    for route, expected_count in (
        ("/v1/records/assets?accessProfile=asset-operator&$top=20", 1),
        ("/v1/records/sites?accessProfile=asset-operator&$top=20", 1),
        ("/v1/records/placements?accessProfile=asset-operator&$top=20", 1),
        ("/v1/records/inspections?accessProfile=asset-operator&$top=20", 1),
        ("/v1/records/assets?accessProfile=site-planner&$top=20", 1),
        ("/v1/records/sites?accessProfile=site-planner&$top=20", 1),
    ):
        response, _ = _request(root, "GET", route, "planner-token" if "site-planner" in route else "operator-token")
        if len(response.get("items", [])) != expected_count:
            raise DemoError(f"{route} did not return the expected seeded records")
    concealed, _ = _request(
        root,
        "GET",
        f"/v1/records/assets/{urllib.parse.quote(asset_id, safe='')}?accessProfile=site-planner",
        "planner-no-purpose-token",
        expected=404,
    )
    if concealed.get("code") != "resource.not_found":
        raise DemoError("planner without purpose did not receive the concealed resource response")
    print("Seeded 1 synthetic asset, site, placement, and create-only inspection.")


def seed_facility(root: Path) -> None:
    root = _require_root(root)
    north_facility_id = _create(
        root,
        "/v1/records/facilities",
        "facility-north",
        {
            "facilityCode": "FACILITY-SYNTH-001",
            "displayName": "North District Water Treatment Facility",
            "administrativeBoundary": "north-district",
        },
        "facility-operator",
        "operator-token",
    )
    south_facility_id = _create(
        root,
        "/v1/records/facilities",
        "facility-south",
        {
            "facilityCode": "FACILITY-SYNTH-002",
            "displayName": "South District Materials Recovery Facility",
            "administrativeBoundary": "south-district",
        },
        "facility-operator",
        "south-operator-token",
    )
    old_permit_id = _create(
        root,
        "/v1/records/permits",
        "facility-permit-old",
        {
            "permitNumber": "PERMIT-SYNTH-001",
            "facility": north_facility_id,
            "permitType": "air-emissions",
            "validFrom": "2020-01-01",
            "validTo": "2024-01-01",
            "administrativeBoundary": "north-district",
            "importSource": "demo-facility-register",
            "sourceRecordId": "permit-synth-001-old",
        },
        "facility-operator",
        "operator-token",
    )
    current_permit_id = _create(
        root,
        "/v1/records/permits",
        "facility-permit-current",
        {
            "permitNumber": "PERMIT-SYNTH-001",
            "facility": north_facility_id,
            "permitType": "water-discharge",
            "validFrom": "2024-01-01",
            "administrativeBoundary": "north-district",
            "importSource": "demo-facility-register",
            "sourceRecordId": "permit-synth-001-current",
        },
        "facility-operator",
        "operator-token",
    )
    installation_id = _create(
        root,
        "/v1/records/installations",
        "facility-installation-primary",
        {
            "installationCode": "INSTALLATION-SYNTH-001",
            "permit": current_permit_id,
            "administrativeBoundary": "north-district",
            "centroid": {"type": "Point", "coordinates": [30.5, -9.5]},
            "areaValue": "1.2500",
            "areaUnit": "hectare",
            "importSource": "demo-facility-survey",
            "sourceRecordId": "installation-synth-001",
        },
        "facility-operator",
        "operator-token",
    )
    old_report_id = _create(
        root,
        "/v1/records/discharge-reports",
        "facility-discharge-old",
        {
            "installation": installation_id,
            "administrativeBoundary": "north-district",
            "substanceCode": "nitrogen",
            "periodStart": "2024-01-01",
            "periodEnd": "2024-07-01",
            "quantityValue": "12.500",
            "quantityUnit": "kilogram",
        },
        "facility-operator",
        "operator-token",
    )
    current_report_id = _create(
        root,
        "/v1/records/discharge-reports",
        "facility-discharge-current",
        {
            "installation": installation_id,
            "administrativeBoundary": "north-district",
            "substanceCode": "nitrogen",
            "periodStart": "2024-07-01",
            "quantityValue": "8.250",
            "quantityUnit": "kilogram",
        },
        "facility-operator",
        "operator-token",
    )
    _write_json(
        root / "seed-record-ids.json",
        {
            "facilities": {
                "FACILITY-SYNTH-001": north_facility_id,
                "FACILITY-SYNTH-002": south_facility_id,
            },
            "permits": {
                "PERMIT-SYNTH-001-OLD": old_permit_id,
                "PERMIT-SYNTH-001-CURRENT": current_permit_id,
            },
            "installations": {"INSTALLATION-SYNTH-001": installation_id},
            "dischargeReports": {
                "DISCHARGE-SYNTH-001-OLD": old_report_id,
                "DISCHARGE-SYNTH-001-CURRENT": current_report_id,
            },
        },
    )
    for route, expected_count in (
        ("/v1/records/facilities?accessProfile=facility-operator&$top=20", 1),
        ("/v1/records/permits:current?accessProfile=facility-operator&$top=20", 1),
        ("/v1/records/installations?accessProfile=facility-operator&$top=20", 1),
        ("/v1/records/discharge-reports:current?accessProfile=facility-operator&$top=20", 1),
    ):
        response, _ = _request(root, "GET", route, "operator-token")
        if len(response.get("items", [])) != expected_count:
            raise DemoError(f"{route} did not return the expected north-district records")
    concealed, _ = _request(
        root,
        "GET",
        f"/v1/records/facilities/{urllib.parse.quote(south_facility_id, safe='')}?accessProfile=facility-operator",
        "operator-token",
        expected=404,
    )
    if concealed.get("code") != "resource.not_found":
        raise DemoError("north facility operator did not receive the concealed resource response")
    print("Seeded 2 synthetic facilities and north-district permit, installation, and discharge history.")


def seed_inspection(root: Path) -> None:
    root = _require_root(root)
    authority_id = _create(
        root,
        "/v1/records/authorities",
        "inspection-authority",
        {
            "authorityCode": "AUTHORITY-SYNTH-001",
            "name": "Northern Environmental Authority",
            "jurisdiction": "north-district",
        },
        "inspection-inspector",
        "operator-token",
    )
    inspection_id = _create(
        root,
        "/v1/records/inspections",
        "inspection-synth-001",
        {
            "inspectionCode": "INSPECTION-SYNTH-001",
            "facilityCode": "FACILITY-SYNTH-001",
            "openedOn": "2026-01-10",
            "closedOn": "2026-01-20",
            "inspectionAuthority": "synthetic-case-management",
        },
        "inspection-inspector",
        "operator-token",
    )
    observation_id = _create(
        root,
        "/v1/records/inspection-observations",
        "inspection-observation-synth-001",
        {
            "inspection": inspection_id,
            "observedAt": "2026-01-11T09:00:00Z",
            "inspectionDomain": "air",
            "findingGrade": 3,
            "observationSchemaMetadata": {
                "schemaVersion": "1",
                "vocabularyRelease": "2026-01",
                "scoringScale": "zero-to-four",
            },
            "observationNote": "Stack height records matched the submitted operating log.",
        },
        "inspection-inspector",
        "operator-token",
    )
    original_permit_id = _create(
        root,
        "/v1/records/permits",
        "inspection-permit-original",
        {
            "permitCode": "INSPECTION-PERMIT-SYNTH-001",
            "inspection": inspection_id,
            "permitStatus": "active",
            "validFrom": "2026-01-01",
            "validTo": "2026-07-01",
            "issuingAuthority": authority_id,
            "validitySource": "review-board",
        },
        "inspection-inspector",
        "operator-token",
    )
    correction_permit_id = _create(
        root,
        "/v1/records/permits",
        "inspection-permit-correction",
        {
            "permitCode": "INSPECTION-PERMIT-SYNTH-002",
            "inspection": inspection_id,
            "permitStatus": "active",
            "validFrom": "2026-01-01",
            "validTo": "2026-07-01",
            "correctedPermit": original_permit_id,
            "correctionReason": "Reviewed correction after authority reconciliation.",
            "issuingAuthority": authority_id,
            "validitySource": "review-board",
            "provenanceNote": "Signed review packet held by the authority.",
        },
        "inspection-inspector",
        "operator-token",
    )
    _write_json(
        root / "seed-record-ids.json",
        {
            "authorities": {"AUTHORITY-SYNTH-001": authority_id},
            "inspections": {"INSPECTION-SYNTH-001": inspection_id},
            "inspectionObservations": {
                "OBSERVATION-SYNTH-001": observation_id,
            },
            "permits": {
                "INSPECTION-PERMIT-SYNTH-001": original_permit_id,
                "INSPECTION-PERMIT-SYNTH-002": correction_permit_id,
            },
        },
    )
    for route, expected_count in (
        ("/v1/records/authorities?accessProfile=inspection-inspector&$top=20", 1),
        ("/v1/records/inspections?accessProfile=inspection-inspector&$top=20", 1),
        ("/v1/records/inspection-observations?accessProfile=inspection-inspector&$top=20", 1),
        ("/v1/records/permits?accessProfile=inspection-inspector&$top=20", 2),
    ):
        response, _ = _request(root, "GET", route, "operator-token")
        if len(response.get("items", [])) != expected_count:
            raise DemoError(f"{route} did not return the expected seeded records")
    concealed, _ = _request(
        root,
        "GET",
        f"/v1/records/inspections/{urllib.parse.quote(inspection_id, safe='')}?accessProfile=inspection-inspector",
        "no-purpose-token",
        expected=404,
    )
    if concealed.get("code") != "resource.not_found":
        raise DemoError("inspection token without purpose did not receive the concealed resource response")
    print("Seeded 1 inspection authority, inspection, structured observation, and 2 create-only permits.")


def _bound_household(root: Path) -> tuple[str, str]:
    seed_ids = _read_json_object(root / "seed-record-ids.json")
    households = seed_ids.get("households")
    household_code = "HOUSEHOLD-DEMO-001"
    household_id = households.get(household_code) if isinstance(households, dict) else None
    if not isinstance(household_id, str):
        raise DemoError("seed record identifiers are missing; run the demo seed first")
    try:
        parsed = uuid.UUID(household_id)
    except ValueError as error:
        raise DemoError("the bound household identifier is not a UUID") from error
    if str(parsed) != household_id:
        raise DemoError("the bound household identifier is not canonical")
    return household_id, household_code


def _bound_business(root: Path) -> tuple[str, str]:
    seed_ids = _read_json_object(root / "seed-record-ids.json")
    businesses = seed_ids.get("businesses")
    business_code = "BUSINESS-DEMO-001"
    business_id = businesses.get(business_code) if isinstance(businesses, dict) else None
    if not isinstance(business_id, str):
        raise DemoError("seed record identifiers are missing; run the demo seed first")
    try:
        parsed = uuid.UUID(business_id)
    except ValueError as error:
        raise DemoError("the bound business identifier is not a UUID") from error
    if str(parsed) != business_id:
        raise DemoError("the bound business identifier is not canonical")
    return business_id, business_code


def configure_viewer(
    root: Path,
    fixture_kind: str = DEFAULT_FIXTURE_KIND,
) -> None:
    root = _require_root(root)
    viewer_public = _read_json_object(root / "keys/viewer-public.jwk.json")
    if fixture_kind == "business-establishments":
        business_id, business_code = _bound_business(root)
        _write_new(
            root / f"mint/clients/{BUSINESS_VIEWER_CLIENT}.yaml",
            _mint_client(
                BUSINESS_VIEWER_CLIENT,
                viewer_public,
                ["registry:business:view"],
                {
                    "business_code": business_code,
                    "business_id": business_id,
                    "registry_principal": "synthetic-business-viewer",
                    "registry_purpose": "business-view",
                },
            ),
        )
        return
    if fixture_kind != "household":
        raise DemoError(f"the viewer demo is not available for the {fixture_kind} fixture")
    household_id, household_code = _bound_household(root)
    _write_new(
        root / f"mint/clients/{VIEWER_CLIENT}.yaml",
        _mint_client(
            VIEWER_CLIENT,
            viewer_public,
            ["registry:household:view"],
            {
                "household_code": household_code,
                "household_id": household_id,
                "registry_principal": "synthetic-household-viewer",
                "registry_purpose": "household-view",
            },
        ),
    )


def _print_query(label: str, response: dict[str, Any]) -> None:
    print(f"\n{label}\n{'=' * len(label)}")
    print(json.dumps(response, indent=2, sort_keys=True))


def _profiled_record_member(record: object) -> tuple[str, str, dict[str, Any]]:
    if (
        not isinstance(record, dict)
        or not isinstance(record.get("recordIdentifier"), str)
        or not record["recordIdentifier"]
        or not isinstance(record.get("revisionIdentifier"), str)
        or not record["revisionIdentifier"]
        or not isinstance(record.get("domainData"), dict)
    ):
        raise DemoError("response does not contain a valid Registry Record member")
    return record["recordIdentifier"], record["revisionIdentifier"], record["domainData"]


def _profiled_meta(meta: object) -> dict[str, Any]:
    if not isinstance(meta, dict) or any(
        not isinstance(meta.get(member), str) or not meta[member]
        for member in ("registryIdentifier", "datasetIdentifier", "entityTypeIdentifier")
    ):
        raise DemoError("response does not contain valid Registry Record metadata")
    return meta


def _profiled_record(response: dict[str, Any]) -> tuple[str, str, dict[str, Any], dict[str, Any]]:
    record_identifier, revision_identifier, domain_data = _profiled_record_member(
        response.get("data")
    )
    meta = _profiled_meta(response.get("meta"))
    return record_identifier, revision_identifier, domain_data, meta


def _profiled_collection_domain_data(response: dict[str, Any]) -> list[dict[str, Any]]:
    items = response.get("items")
    page_info = response.get("pageInfo")
    _profiled_meta(response.get("meta"))
    if (
        not isinstance(items, list)
        or not isinstance(page_info, dict)
        or set(page_info) != {"nextCursor"}
        or (page_info["nextCursor"] is not None and not isinstance(page_info["nextCursor"], str))
    ):
        raise DemoError("response does not use the Registry Record collection envelope")
    return [_profiled_record_member(item)[2] for item in items]


def _assert_bound_household(response: dict[str, Any], household_id: str, household_code: str) -> None:
    record_identifier, _, domain_data, _ = _profiled_record(response)
    if record_identifier != household_id or domain_data.get("householdCode") != household_code:
        raise DemoError("viewer read did not return its one bound household")


def _assert_bound_business(response: dict[str, Any], business_id: str, business_code: str) -> None:
    record_identifier, _, domain_data, _ = _profiled_record(response)
    if record_identifier != business_id or domain_data.get("businessCode") != business_code:
        raise DemoError("viewer read did not return its one bound business")


def query_business(root: Path, suite: str = "all") -> None:
    root = _require_root(root)
    if suite not in ("all", "operator", "viewer"):
        raise DemoError("query suite must be all, operator, or viewer")
    business_id, business_code = _bound_business(root)
    encoded_business_id = urllib.parse.quote(business_id, safe="")
    if suite in ("all", "operator"):
        queries = [
            ("Establishments from one business", f"/v1/records/businesses/{encoded_business_id}/establishments?accessProfile=business-operator&$select=establishmentCode,siteName,establishmentKind,operatingStatus&$orderby=establishmentCode&$top=20&$count=true"),
            ("Derived stored and computed filter", "/v1/records/businesses?accessProfile=business-operator&$select=businessCode,administrativeArea,localRegistrationNumber,branchCount&$filter=administrativeArea%20eq%20%27north-demo%27%20and%20branchCount%20eq%201&$orderby=localRegistrationNumber&$top=20&$count=true"),
            ("Production sites without a suspended establishment", "/v1/records/businesses?accessProfile=business-operator&$select=businessCode,productionSiteCount,suspendedSiteCount,hasProductionSite&$filter=hasProductionSite%20eq%20true%20and%20suspendedSiteCount%20eq%200&$top=20&$count=true"),
            ("Businesses with a suspended establishment", "/v1/records/businesses?accessProfile=business-operator&$select=businessCode,hasProductionSite,branchCount,suspendedSiteCount&$filter=hasProductionSite%20eq%20true%20and%20branchCount%20eq%201%20and%20suspendedSiteCount%20eq%201&$top=20&$count=true"),
        ]
        expected_rows = [
            [
                {"establishmentCode": "ESTABLISHMENT-DEMO-001", "siteName": "North Quay Head Office", "establishmentKind": "office", "operatingStatus": "operating"},
                {"establishmentCode": "ESTABLISHMENT-DEMO-002", "siteName": "North Quay Riverside Works", "establishmentKind": "production", "operatingStatus": "operating"},
            ],
            [{"businessCode": "BUSINESS-DEMO-001", "administrativeArea": "north-demo", "localRegistrationNumber": 1001, "branchCount": 1}],
            [{"businessCode": "BUSINESS-DEMO-001", "productionSiteCount": 1, "suspendedSiteCount": 0, "hasProductionSite": True}],
            [{"businessCode": "BUSINESS-DEMO-002", "hasProductionSite": True, "branchCount": 1, "suspendedSiteCount": 1}],
        ]
        for (label, path), expected in zip(queries, expected_rows, strict=True):
            response, _ = _request(root, "GET", path, "operator-token")
            rows = _profiled_collection_domain_data(response)
            if (
                rows != expected
                or response.get("count") != len(expected)
            ):
                raise DemoError(f"{label} returned unexpected records, fields, or derived counts")
            _print_query(label, response)
        operator_lookup, _ = _request(
            root,
            "POST",
            "/v1/records/businesses:lookup?accessProfile=business-operator",
            "operator-token",
            {
                "selector": "by-local-reference",
                "values": {
                    "administrativeArea": "north-demo",
                    "localRegistrationNumber": 1001,
                },
            },
        )
        _assert_bound_business(operator_lookup, business_id, business_code)
        _print_query("Exact request-value selector lookup", operator_lookup)

    if suite in ("all", "viewer"):
        viewer_get, _ = _request(
            root,
            "GET",
            f"/v1/records/businesses/{encoded_business_id}?accessProfile=business-viewer",
            "viewer-token",
        )
        _assert_bound_business(viewer_get, business_id, business_code)
        _print_query("Viewer get bound by verified business ID claim", viewer_get)

        viewer_lookup, _ = _request(
            root,
            "POST",
            "/v1/records/businesses:lookup?accessProfile=business-viewer",
            "viewer-token",
            {"selector": "by-business-code"},
        )
        _assert_bound_business(viewer_lookup, business_id, business_code)
        _print_query("Viewer lookup using its verified business code claim", viewer_lookup)

        denied = [
            (
                "Viewer list is concealed",
                "/v1/records/businesses?accessProfile=business-viewer",
            ),
            (
                "Viewer relationship path is concealed",
                f"/v1/records/businesses/{encoded_business_id}/establishments?accessProfile=business-viewer",
            ),
        ]
        for label, path in denied:
            response, _ = _request(root, "GET", path, "viewer-token", expected=404)
            if response.get("code") != "resource.not_found":
                raise DemoError("viewer denial did not use the concealed resource response")
            rendered = json.dumps(response, sort_keys=True)
            if business_id in rendered or business_code in rendered:
                raise DemoError("viewer denial exposed a bound business value")
            _print_query(label, response)


def query(root: Path, suite: str = "all") -> None:
    root = _require_root(root)
    if suite not in ("all", "operator", "viewer"):
        raise DemoError("query suite must be all, operator, or viewer")
    household_id, household_code = _bound_household(root)
    encoded_household_id = urllib.parse.quote(household_id, safe="")
    if suite in ("all", "operator"):
        queries = [
            ("People from one household", f"/v1/records/households/{encoded_household_id}/people?accessProfile=household-operator&$select=personCode,legalName,personSex,residencyStatus&$orderby=personCode&$top=20&$count=true"),
            ("Derived stored and computed filter", "/v1/records/households?accessProfile=household-operator&$select=householdCode,administrativeArea,localHouseholdNumber,childCount&$filter=administrativeArea%20eq%20%27north-demo%27%20and%20childCount%20eq%201&$orderby=localHouseholdNumber&$top=20&$count=true"),
            ("Single headed with child under five", "/v1/records/households?accessProfile=household-operator&$select=householdCode,childUnder5Count,singleHeaded&$filter=singleHeaded%20eq%20true%20and%20childUnder5Count%20eq%201&$top=20&$count=true"),
            ("Woman headed with child and elderly", "/v1/records/households?accessProfile=household-operator&$select=householdCode,womanHeaded,childCount,elderlyCount&$filter=womanHeaded%20eq%20true%20and%20childCount%20eq%201%20and%20elderlyCount%20eq%201&$top=20&$count=true"),
        ]
        for label, path in queries:
            response, _ = _request(root, "GET", path, "operator-token")
            _profiled_collection_domain_data(response)
            _print_query(label, response)
        operator_lookup, _ = _request(
            root,
            "POST",
            "/v1/records/households:lookup?accessProfile=household-operator",
            "operator-token",
            {
                "selector": "by-local-reference",
                "values": {
                    "administrativeArea": "north-demo",
                    "localHouseholdNumber": 1001,
                },
            },
        )
        _assert_bound_household(operator_lookup, household_id, household_code)
        _print_query("Exact request-value selector lookup", operator_lookup)

    if suite in ("all", "viewer"):
        viewer_get, _ = _request(
            root,
            "GET",
            f"/v1/records/households/{encoded_household_id}?accessProfile=household-viewer",
            "viewer-token",
        )
        _assert_bound_household(viewer_get, household_id, household_code)
        _print_query("Viewer get bound by verified household ID claim", viewer_get)

        viewer_lookup, _ = _request(
            root,
            "POST",
            "/v1/records/households:lookup?accessProfile=household-viewer",
            "viewer-token",
            {"selector": "by-household-code"},
        )
        _assert_bound_household(viewer_lookup, household_id, household_code)
        _print_query("Viewer lookup using its verified household code claim", viewer_lookup)

        denied = [
            (
                "Viewer list is concealed",
                "/v1/records/households?accessProfile=household-viewer",
            ),
            (
                "Viewer relationship path is concealed",
                f"/v1/records/households/{encoded_household_id}/people?accessProfile=household-viewer",
            ),
        ]
        for label, path in denied:
            response, _ = _request(root, "GET", path, "viewer-token", expected=404)
            if response.get("code") != "resource.not_found":
                raise DemoError("viewer denial did not use the concealed resource response")
            rendered = json.dumps(response, sort_keys=True)
            if household_id in rendered or household_code in rendered:
                raise DemoError("viewer denial exposed a bound household value")
            _print_query(label, response)


def query_asset_site(root: Path, suite: str = "all") -> None:
    root = _require_root(root)
    if suite not in ("all", "operator", "planner"):
        raise DemoError("query suite must be all, operator, or planner")
    seed_ids = _read_json_object(root / "seed-record-ids.json")
    asset_id = seed_ids.get("assets", {}).get("ASSET-SYNTH-001")
    site_id = seed_ids.get("sites", {}).get("SITE-SYNTH-001")
    if not isinstance(asset_id, str) or not isinstance(site_id, str):
        raise DemoError("asset-site seed record identifiers are missing")
    if suite in ("all", "operator"):
        for label, path in (
            ("Asset operator assets", "/v1/records/assets?accessProfile=asset-operator&$top=20"),
            ("Asset operator sites", "/v1/records/sites?accessProfile=asset-operator&$top=20"),
            ("Asset operator placements", "/v1/records/placements?accessProfile=asset-operator&$top=20"),
            ("Asset operator inspections", "/v1/records/inspections?accessProfile=asset-operator&$top=20"),
        ):
            response, _ = _request(root, "GET", path, "operator-token")
            _print_query(label, response)
    if suite in ("all", "planner"):
        for label, path in (
            ("Site planner assets", "/v1/records/assets?accessProfile=site-planner&$top=20"),
            ("Site planner sites", "/v1/records/sites?accessProfile=site-planner&$top=20"),
            ("Site planner placements", "/v1/records/placements?accessProfile=site-planner&$top=20"),
        ):
            response, _ = _request(root, "GET", path, "planner-token")
            rendered = json.dumps(response, sort_keys=True)
            if "assetClass" in rendered:
                raise DemoError("site planner response exposed the operator-only asset classification")
            _print_query(label, response)
        concealed, _ = _request(
            root,
            "GET",
            f"/v1/records/assets/{urllib.parse.quote(asset_id, safe='')}?accessProfile=site-planner",
            "planner-no-purpose-token",
            expected=404,
        )
        if concealed.get("code") != "resource.not_found":
            raise DemoError("site planner no-purpose denial did not use the concealed resource response")
        _print_query("Site planner without purpose is concealed", concealed)


def query_facility(root: Path, suite: str = "all") -> None:
    root = _require_root(root)
    if suite not in ("all", "operator"):
        raise DemoError("query suite must be all or operator")
    seed_ids = _read_json_object(root / "seed-record-ids.json")
    facility_id = seed_ids.get("facilities", {}).get("FACILITY-SYNTH-001")
    if not isinstance(facility_id, str):
        raise DemoError("facility seed record identifiers are missing")
    for label, path in (
        (
            "North-district facilities",
            "/v1/records/facilities?accessProfile=facility-operator&$top=20",
        ),
        (
            "Current north-district permits",
            "/v1/records/permits:current?accessProfile=facility-operator&$top=20",
        ),
        (
            "North-district installations with point and decimal fields",
            "/v1/records/installations?accessProfile=facility-operator&$top=20",
        ),
        (
            "Current discharge reports",
            "/v1/records/discharge-reports:current?accessProfile=facility-operator&$top=20",
        ),
    ):
        response, _ = _request(root, "GET", path, "operator-token")
        if len(_profiled_collection_domain_data(response)) != 1:
            raise DemoError(f"{label} did not return one seeded north-district record")
        _print_query(label, response)
    response, _ = _request(
        root,
        "GET",
        f"/v1/records/facilities/{urllib.parse.quote(facility_id, safe='')}?accessProfile=facility-operator",
        "operator-token",
    )
    _, _, domain_data, _ = _profiled_record(response)
    if domain_data.get("displayName") != "North District Water Treatment Facility":
        raise DemoError("facility get did not return the seeded north-district facility")
    _print_query("North-district facility by UUID", response)


def query_inspection(root: Path, suite: str = "all") -> None:
    root = _require_root(root)
    if suite not in ("all", "inspector"):
        raise DemoError("query suite must be all or inspector")
    seed_ids = _read_json_object(root / "seed-record-ids.json")
    inspection_id = seed_ids.get("inspections", {}).get("INSPECTION-SYNTH-001")
    if not isinstance(inspection_id, str):
        raise DemoError("inspection seed record identifiers are missing")
    for label, path, expected_count in (
        (
            "Inspection record",
            "/v1/records/inspections?accessProfile=inspection-inspector&$top=20",
            1,
        ),
        (
            "Structured inspection observation",
            "/v1/records/inspection-observations?accessProfile=inspection-inspector&$top=20",
            1,
        ),
        (
            "Create-only permit correction history",
            "/v1/records/permits?accessProfile=inspection-inspector&$top=20",
            2,
        ),
        (
            "Imported public authority",
            "/v1/records/authorities?accessProfile=inspection-inspector&$top=20",
            1,
        ),
    ):
        response, _ = _request(root, "GET", path, "operator-token")
        if len(_profiled_collection_domain_data(response)) != expected_count:
            raise DemoError(f"{label} did not return the expected seeded records")
        _print_query(label, response)
    response, _ = _request(
        root,
        "GET",
        f"/v1/records/inspections/{urllib.parse.quote(inspection_id, safe='')}?accessProfile=inspection-inspector",
        "operator-token",
    )
    _, _, domain_data, _ = _profiled_record(response)
    if domain_data.get("inspectionCode") != "INSPECTION-SYNTH-001":
        raise DemoError("inspection get did not return the seeded inspection")
    _print_query("Inspection by UUID", response)


def _token_expires_at(token: str) -> str:
    parts = token.split(".")
    if len(parts) != 3:
        raise DemoError("token must be one compact JWT")
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except (ValueError, UnicodeError) as error:
        raise DemoError("token payload is not valid JSON") from error
    expires = claims.get("exp")
    if not isinstance(expires, int) or expires <= 0:
        raise DemoError("token payload does not carry an integer exp claim")
    return datetime.fromtimestamp(expires, timezone.utc).isoformat().replace("+00:00", "Z")


def write_handoff(root: Path, fixture_kind: str, out: Path) -> None:
    root = _require_root(root)
    config = _fixture_config(fixture_kind)
    if out.exists() or out.is_symlink():
        raise DemoError("handoff output must name a new regular file")
    server_origin = (root / "server-origin").read_text(encoding="ascii").strip()
    personas = []
    for persona in config["personas"]:
        token_name = persona["token_name"]
        token_file = (root / f"secrets/{token_name}").resolve()
        token = _token(root, token_name)
        personas.append(
            {
                "id": persona["id"],
                "label": persona["label"],
                "tokenFile": str(token_file),
                "accessProfile": persona["access_profile"],
                "expiresAt": _token_expires_at(token),
            }
        )
    _write_json(
        out,
        {
            "schemaVersion": "registry-workspace/demo/v1",
            "registry": {"id": config["registry_id"], "baseUrl": server_origin},
            "personas": personas,
        },
        0o600,
    )


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
    fixture_choices = ("business-establishments", "household", "asset-site", "facility", "inspection")
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
    prepare_parser.add_argument("--fixture-kind", choices=fixture_choices, default=DEFAULT_FIXTURE_KIND)
    prepare_parser.add_argument(
        "--token-lifetime-seconds",
        type=int,
        default=DEFAULT_TOKEN_LIFETIME_SECONDS,
    )
    runtime_parser = commands.add_parser("render-runtime")
    runtime_parser.add_argument("--root", required=True, type=Path)
    runtime_parser.add_argument("--revision", required=True)
    runtime_parser.add_argument("--webhook", action="store_true")
    runtime_parser.add_argument("--fixture-kind", choices=fixture_choices, default=DEFAULT_FIXTURE_KIND)
    runtime_parser.add_argument(
        "--token-lifetime-seconds",
        type=int,
        default=DEFAULT_TOKEN_LIFETIME_SECONDS,
    )
    bind_parser = commands.add_parser("bind-webhook-module")
    bind_parser.add_argument("--root", required=True, type=Path)
    bind_parser.add_argument("--report", required=True, type=Path)
    seed_parser = commands.add_parser("seed")
    seed_parser.add_argument("--root", required=True, type=Path)
    seed_parser.add_argument("--fixture-kind", choices=fixture_choices, default=DEFAULT_FIXTURE_KIND)
    viewer_parser = commands.add_parser("configure-viewer")
    viewer_parser.add_argument("--root", required=True, type=Path)
    viewer_parser.add_argument("--fixture-kind", choices=fixture_choices, default=DEFAULT_FIXTURE_KIND)
    query_parser = commands.add_parser("query")
    query_parser.add_argument("--root", required=True, type=Path)
    query_parser.add_argument("--fixture-kind", choices=fixture_choices, default=DEFAULT_FIXTURE_KIND)
    query_parser.add_argument("--suite", default="all")
    handoff_parser = commands.add_parser("handoff")
    handoff_parser.add_argument("--root", required=True, type=Path)
    handoff_parser.add_argument("--fixture-kind", choices=fixture_choices, default=DEFAULT_FIXTURE_KIND)
    handoff_parser.add_argument("--out", required=True, type=Path)
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
                args.fixture_kind,
                args.token_lifetime_seconds,
            )
        elif args.command == "render-runtime":
            render_runtime(
                args.root,
                args.revision,
                args.webhook,
                args.fixture_kind,
                args.token_lifetime_seconds,
            )
        elif args.command == "bind-webhook-module":
            bind_webhook_module(args.root, args.report)
        elif args.command == "seed":
            if args.fixture_kind == "business-establishments":
                seed_business(args.root)
            elif args.fixture_kind == "household":
                seed(args.root)
            elif args.fixture_kind == "asset-site":
                seed_asset_site(args.root)
            elif args.fixture_kind == "facility":
                seed_facility(args.root)
            elif args.fixture_kind == "inspection":
                seed_inspection(args.root)
            else:
                raise AssertionError(args.fixture_kind)
        elif args.command == "configure-viewer":
            configure_viewer(args.root, args.fixture_kind)
        elif args.command == "query":
            if args.fixture_kind == "business-establishments":
                query_business(args.root, args.suite)
            elif args.fixture_kind == "household":
                query(args.root, args.suite)
            elif args.fixture_kind == "asset-site":
                query_asset_site(args.root, args.suite)
            elif args.fixture_kind == "facility":
                query_facility(args.root, args.suite)
            elif args.fixture_kind == "inspection":
                query_inspection(args.root, args.suite)
            else:
                raise AssertionError(args.fixture_kind)
        elif args.command == "handoff":
            write_handoff(args.root, args.fixture_kind, args.out)
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
