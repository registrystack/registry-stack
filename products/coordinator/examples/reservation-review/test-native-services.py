#!/usr/bin/env python3
"""Native BReg, Casework, Scheduling, Messaging and Coordinator proof.

The agreement outcome is a deterministic fixture. Product state, review,
task-grant authority, capacity, idempotency receipts and source actions use
the compiled public services and their maintained APIs.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server as http_server
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import yaml

REPO = Path(__file__).resolve().parents[4]
SCRIPTS = REPO / "products/coordinator/scripts"
EXAMPLE = REPO / "products/coordinator/examples/reservation-review"
SCHEDULING_PROJECT = EXAMPLE / "scheduling"
REQUIRED_BINARIES = (
    "breg",
    "bregctl",
    "casework",
    "caseworkctl",
    "coordinator",
    "coordinatorctl",
    "messaging",
    "messagingctl",
    "scheduling",
    "schedulingctl",
)

sys.path.insert(0, str(SCRIPTS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


native = load_module(
    "coordinator_real_services_for_reservations", SCRIPTS / "test-real-services.py"
)


class JwksFixture:
    def __init__(self, port: int, key: dict[str, str]):
        body = json.dumps(
            {"keys": [{name: value for name, value in key.items() if name != "d"}]}
        ).encode()

        class Handler(http_server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                if self.path != "/oauth2/jwks":
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http_server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class LostSchedulingResponseProxy:
    """Drop one exact POST reply while forwarding Scheduling DELETE calls."""

    def __init__(self, origin: str, mutation_path: str):
        parts = urllib.parse.urlsplit(origin)
        assert parts.scheme == "http" and parts.hostname == "127.0.0.1"
        assert parts.port is not None and not parts.path and not parts.query
        self.commands = []
        self.lost = False
        proxy = self

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        class Handler(http_server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def do_DELETE(self):
                self.forward()

            def forward(self):
                target = self.requestline.split()[1]
                assert target.startswith("/") and not target.startswith("//")
                assert "#" not in target
                length = int(self.headers.get("Content-Length", "0"))
                assert 0 <= length <= 131_072
                body = self.rfile.read(length) if length else None
                headers = {
                    name: value
                    for name, value in self.headers.items()
                    if name.lower() not in ("host", "connection", "content-length")
                }
                request = urllib.request.Request(
                    origin + target,
                    data=body,
                    headers=headers,
                    method=self.command,
                )
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}), NoRedirect()
                )
                try:
                    response = opener.open(request, timeout=10)
                except urllib.error.HTTPError as error:
                    response = error
                raw = response.read(1_048_577)
                assert len(raw) <= 1_048_576
                mutation = self.command == "POST" and self.path == mutation_path
                if mutation:
                    bearer = self.headers.get("Authorization", "").removeprefix(
                        "Bearer "
                    )
                    encoded = bearer.split(".")[1]
                    claims = json.loads(
                        base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
                    )
                    proxy.commands.append(
                        {
                            "key": self.headers.get("Idempotency-Key"),
                            "bodyHash": hashlib.sha256(body or b"").hexdigest(),
                            "responseStatus": response.status,
                            "issuedAt": claims.get("iat"),
                            "accessTokenExpiresAt": claims.get("exp"),
                            "subject": claims.get("sub"),
                            "issuer": claims.get("iss"),
                            "audience": claims.get("aud"),
                            "clientId": claims.get("client_id"),
                            "scopes": claims.get("scope", "").split(),
                            "signedIdentityObject": isinstance(
                                claims.get("identity"), dict
                            ),
                            "signedIdentityClaims": sorted(claims["identity"])
                            if isinstance(claims.get("identity"), dict)
                            else None,
                            "boundsHash": hashlib.sha256(
                                json.dumps(
                                    claims.get("registry_grant_bounds"),
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ).encode()
                            ).hexdigest(),
                            "grantId": claims.get("registry_grant_id"),
                            "grantExpiresAt": claims.get("registry_grant_exp"),
                        }
                    )
                if mutation and 200 <= response.status < 300 and not proxy.lost:
                    proxy.lost = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                self.send_response(response.status)
                for name, value in response.headers.items():
                    if name.lower() not in (
                        "connection",
                        "transfer-encoding",
                        "content-length",
                        "server",
                        "date",
                    ):
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = http_server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def generate_task_authority_key() -> dict[str, str]:
    generated = subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
        ],
        check=True,
        capture_output=True,
        timeout=30,
    ).stdout
    described = subprocess.run(
        ["openssl", "pkey", "-text", "-noout"],
        input=generated,
        check=True,
        capture_output=True,
        timeout=30,
    ).stdout.decode()
    private_hex = described.split("priv:\n", 1)[1].split("pub:\n", 1)[0]
    public_hex = described.split("pub:\n", 1)[1].split("ASN1 OID:", 1)[0]
    private = bytes.fromhex("".join(private_hex.split()).replace(":", ""))
    public = bytes.fromhex("".join(public_hex.split()).replace(":", ""))
    assert len(private) == 32 and len(public) == 65 and public[0] == 4

    def encoded(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    x, y = encoded(public[1:33]), encoded(public[33:])
    thumbprint = json.dumps(
        {"crv": "P-256", "kty": "EC", "x": x, "y": y},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "kid": encoded(hashlib.sha256(thumbprint).digest()),
        "x": x,
        "y": y,
        "d": encoded(private),
    }


def add_reservation_source_client(project: Path) -> None:
    path = project / "dev-clients.yaml"
    document = json.loads(path.read_text())
    document["clients"].append(
        {
            "id": "reservation-source-agent",
            "accessProfiles": [],
            "scopes": ["reservations:workflow"],
            "claims": {
                "registry_actor_kind": "service",
                "reservation_source": "reservation-source-agent",
            },
        }
    )
    native.private(path, document)


def casework_request(
    url: str,
    token: str,
    body: dict[str, object],
    headers: dict[str, str],
) -> dict[str, object]:
    fields = {
        **headers,
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
    }
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers=fields, method="POST"
    )
    try:
        response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            request, timeout=10
        )
    except urllib.error.HTTPError as error:
        problem = json.loads(error.read(65_537))
        raise AssertionError(
            "Casework refused the synthetic review request: "
            + json.dumps(
                {
                    "status": error.code,
                    "code": problem.get("code"),
                    "detail": problem.get("detail"),
                    "validationPath": error.headers.get(
                        "registry-review-validation-path"
                    ),
                    "validationReason": error.headers.get(
                        "registry-review-validation-reason"
                    ),
                },
                separators=(",", ":"),
            )
        ) from None
    assert response.status in (200, 201)
    return json.load(response)


def bind_review_policy(project: Path, binding: dict[str, object]) -> None:
    assert binding["id"] == "reservation-review" and binding["version"] == "1"
    digest = binding["digest"]
    assert isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    path = project / "functions.rhai"
    source = path.read_text()
    pattern = r'policy:\s*#\{id:\s*"reservation-review",\s*version:\s*"1",\s*digest:\s*"sha256:[0-9a-f]{64}"\}'
    replacement = (
        'policy: #{id: "reservation-review", version: "1", digest: '
        + json.dumps(digest)
        + "}"
    )
    source, changed = re.subn(pattern, lambda _: replacement, source)
    assert changed == 1, "the task-owned project must bind one review policy"
    native.private(path, source)


original_write_messaging = native.write_messaging


def write_reservation_messaging(root: Path) -> Path:
    root = Path(original_write_messaging(root))
    project_path = root / "messaging.yaml"
    project = json.loads(project_path.read_text())
    project["templates"].append({"id": "reservation-confirmed", "version": "1"})
    project["accessProfiles"][0]["templates"].append("reservation-confirmed")
    native.private(project_path, project)
    target = root / "templates/reservation-confirmed/1"
    native.private(
        target / "template.yaml",
        {
            "apiVersion": "id.registrystack.org/formats/messaging/template/v1alpha1",
            "kind": "MessagingTemplate",
            "channel": "email",
            "locales": ["en"],
            "parts": ["subject", "text"],
        },
    )
    native.private(
        target / "schema.json",
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["reservationReference"],
            "properties": {
                "reservationReference": {"type": "string"},
                "appointmentReference": {"type": "string"},
            },
        },
    )
    native.private(
        target / "sample.json",
        {
            "reservationReference": "reservation-one",
            "appointmentReference": "appointment-one",
        },
    )
    native.private(target / "en/subject.j2", "Reservation confirmed\n")
    native.private(
        target / "en/text.j2",
        "Reservation {{ reservationReference }} is confirmed.\n",
    )
    return root


def write_reservation_scheduling(root: Path, _day: str) -> Path:
    root = Path(root)
    root.mkdir(parents=True)
    for name in ("scheduling.yaml", "records.yaml"):
        shutil.copy2(SCHEDULING_PROJECT / name, root / name)
    return root


def write_review_casework(root: Path, urls: dict[str, str], agent_subject: str) -> Path:
    root = Path(native.write_review_casework(root, urls))
    path = root / "casework.yaml"
    project = json.loads(path.read_text())
    policy = project["reviewPolicies"].pop("application-review")
    policy["displaySchema"] = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "reservationId",
            "offering",
            "start",
            "durationMinutes",
            "attendees",
        ],
        "properties": {
            "reservationId": {"type": "string", "format": "uuid"},
            "offering": {"type": "string", "minLength": 1, "maxLength": 120},
            "start": {"type": "string", "format": "date-time"},
            "durationMinutes": {"type": "integer", "minimum": 1, "maximum": 10080},
            "attendees": {"type": "integer", "minimum": 1},
        },
    }
    policy["outcomes"] = {
        "approved": {
            "label": "Approve reservation",
            "settlement": "approved",
            "reasonRequired": False,
            "publicReason": "none",
        },
        "rejected": {
            "label": "Reject reservation",
            "settlement": "rejected",
            "reasonRequired": False,
            "publicReason": "optional",
        },
    }
    project["reviewPolicies"]["reservation-review"] = policy
    project["trustedProducers"]["coordinator"]["reviewPolicies"] = [
        "reservation-review"
    ]
    project["trustedProducers"]["coordinator"]["sourceNamespaces"] = ["reservations"]
    project["trustedProducers"]["coordinator"]["completion"]["recipientBinding"] = (
        "reservation-review-v1"
    )
    project["taskTemplates"] = {
        "reservation-capacity": {
            "version": "1",
            "label": "Manage reviewed reservation capacity",
            "eligibleTeams": ["reviewers"],
            "eligibleProfiles": ["staff"],
            "source": "reservations",
            "reviewPolicies": ["reservation-review"],
            "agent": {"issuer": urls["issuer"], "subject": agent_subject},
            "client": "task-agent",
            "authorizationMode": "deferred",
            "lifetimeSeconds": 900,
            "resource": native.SCHEDULING_RESOURCE,
            "scopes": ["scheduling:read", "scheduling:commit"],
            "purpose": "review",
            "bounds": {
                "type": "scheduling",
                "permissions": [
                    {
                        "service": "room-reservation",
                        "location": "community-hall",
                        "actions": [
                            "appointment.create-for",
                            "appointment.read",
                        ],
                    }
                ],
            },
            "subjects": {"schedulingManager": "reservationId"},
        }
    }
    native.private(path, project)
    return root


class ReservationJourney(native.Journey):
    def drive(self, owner: Path, url: str, run: str):
        deadline = time.monotonic() + 120
        reconciled = []
        requested = set()
        while time.monotonic() < deadline:
            result = self.inspect(owner, url, run)
            native.private(self.root / "native-progress.json", result)
            uncertain = (
                result["run"]["state"] == "uncertain"
                or result["run"]["state"] == "attention"
                and result["run"].get("uncertain")
            )
            if uncertain:
                step = result["run"]["step"]
                if step not in requested:
                    recovery = result["recovery"]
                    route = (
                        "reconcile"
                        if recovery["operation"]["readReceipt"]
                        else "retry-same"
                    )
                    assert recovery["retryAllowed"]
                    self.producer_request(
                        owner,
                        "POST",
                        url + f"/v1/runs/{run}/{route}",
                        {"reason": "Synthetic exact command recovery"},
                    )
                    requested.add(step)
                    reconciled.append(step)
            elif result["run"]["state"] != "running":
                return result, reconciled
            time.sleep(0.15)
        raise AssertionError("coordinator did not settle within fixture deadline")

    def source_service(self, issuer: Path) -> tuple[Path, str, dict[str, object]]:
        source = self.root / "reservation-source"
        shutil.copytree(EXAMPLE / "source-registry", source)
        clients_path = source / "dev-clients.yaml"
        clients = yaml.safe_load(clients_path.read_text())
        clients.pop("issuer", None)
        clients["clients"] = [
            client
            for client in clients["clients"]
            if client["id"] == "reservation-source-agent"
        ]
        native.private(clients_path, clients)
        self.ctl("bregctl", "check", source)
        source_port, database_port = native.free_ports(2)
        self.sessions.append(("bregctl", source))
        report = self.ctl(
            "bregctl",
            "dev",
            "start",
            source,
            "--breg-port",
            source_port,
            "--database-port",
            database_port,
            "--issuer-project",
            issuer,
            "--breg-bin",
            self.bin / "breg",
        )
        return source, f"http://127.0.0.1:{source_port}", report

    def review_casework(
        self,
        owner: Path,
        resource: str,
        port: int,
        completion_url: str,
        completion_token: str,
        agent_subject: str,
    ) -> tuple[Path, str, dict[str, object]]:
        project = write_review_casework(
            self.root / "review-casework", self.urls, agent_subject
        )
        checked = self.ctl("caseworkctl", "check", project)
        binding = next(
            item
            for item in checked["policyBindings"]
            if item["id"] == "reservation-review"
        )
        package = self.root / "review-casework-package"
        self.ctl("caseworkctl", "package", project, "--output", package)
        keys = self.root / "review-casework-secrets"
        native.private(
            keys / "database",
            self.isolated_database(
                "COORDINATOR_TEST_DATABASE_URL", "reservation_casework_"
            ),
        )
        native.private(keys / "audit-key", os.urandom(32))
        native.private(
            keys / "jwks", native.http("GET", self.urls["issuer"] + "/oauth2/jwks")
        )
        native.private(keys / "completion-token", completion_token)
        authority_key = generate_task_authority_key()
        native.private(keys / "task-authority-signing-key", authority_key)
        jwks = JwksFixture(self.ports["jwks"], authority_key)
        self.proxies.append(jwks)
        url = f"http://127.0.0.1:{port}"
        runtime = self.root / "review-casework-runtime.yaml"
        native.private(
            runtime,
            {
                "apiVersion": "id.registrystack.org/formats/casework/runtime/v1alpha1",
                "kind": "CaseworkRuntimeConfig",
                "identity": {"databaseId": "reservation-review-casework"},
                "package": {"root": str(package)},
                "listener": {
                    "bind": f"127.0.0.1:{port}",
                    "tlsTermination": "development-loopback",
                    "networkExposure": "private-address",
                },
                "secretProviders": {"file": {"root": str(keys)}},
                "database": {
                    "runtimeUrlRef": "secret:file/database",
                    "migrationUrlRef": "secret:file/database",
                    "testOnlyPlaintext": True,
                },
                "authentication": {
                    "oidc": {
                        "issuer": self.urls["issuer"],
                        "audience": resource,
                        "allowedClients": [
                            "review-producer",
                            "staff",
                            "administrator",
                            "task-agent",
                            "scheduling-status",
                        ],
                        "scopeClaim": "scope",
                        "jwksSource": {
                            "type": "static",
                            "documentRef": "secret:file/jwks",
                        },
                        "humanIdentity": {
                            "claim": "registry_actor_kind",
                            "value": "human",
                        },
                    }
                },
                "audit": {
                    "path": str(self.root / "audit/review-casework.ndjson"),
                    "hashKeyRef": "secret:file/audit-key",
                },
                "contextProviders": {},
                "taskAuthority": {
                    "issuer": native.AUTHORITY,
                    "exchangeAudience": self.urls["issuer"],
                    "signingKeyRef": "secret:file/task-authority-signing-key",
                    "statusClients": {"scheduling-status": native.SCHEDULING_RESOURCE},
                },
                "reviewCompletionDestinations": {
                    "coordinator": {
                        "url": completion_url,
                        "bearerTokenRef": "secret:file/completion-token",
                        "attemptTimeoutMilliseconds": 5000,
                        "maximumAttempts": 10,
                        "retryDelaySeconds": 1,
                    }
                },
            },
        )
        self.ctl("caseworkctl", "apply", "--runtime-config", runtime)
        child = self.spawn("casework", runtime, "reservation-review-casework")
        self.ready(child, url)
        administrator = self.token("bregctl", owner, "administrator")
        headers = {"Registry-Casework-Profile": "administrator"}
        directory = native.http(
            "GET", url + "/v1/directory", administrator, headers=headers
        )
        native.http(
            "POST",
            url + "/v1/directory/bootstrap",
            administrator,
            {
                "teamId": "reviewers",
                "queueId": "applications",
                "supervisors": [],
                "staff": [
                    {
                        "issuer": self.urls["issuer"],
                        "subject": native.CASEWORK_PRINCIPALS["staff"],
                    }
                ],
            },
            {
                **headers,
                "If-Match": f'"{directory["revision"]}"',
                "Idempotency-Key": str(uuid.uuid4()),
            },
        )
        return project, url, binding

    def coordinator(
        self,
        owner: Path,
        source: Path,
        source_url: str,
        casework_url: str,
        scheduling_url: str,
        messaging_url: str,
        completion_token: str,
        agent_subject: str,
        binding: dict[str, object],
        port: int,
    ):
        keys = self.root / "reservation-coordinator-secrets"
        source_actor = self.export(owner, "reservation-source-agent", keys)
        reviewer = self.export(owner, "review-producer", keys)
        catalogue = self.export(owner, "scheduling-reader", keys)
        booking = self.export(owner, "task-agent", keys)
        sender = self.export(owner, "case-system", keys)
        native.private(keys / "review-completion-token", completion_token)
        task = {
            "baseUrl": casework_url,
            "issuer": native.AUTHORITY,
            "subject": agent_subject,
            "exchangeAudience": self.urls["issuer"],
            "bootstrapResource": reviewer["resource"],
        }
        project = self.root / "bound-reservation-request-only"
        shutil.copytree(EXAMPLE / "request-only", project)
        bind_review_policy(project, binding)
        return self.coordinator_service(
            "reservation-review-request-only",
            keys,
            {
                "reservations": {
                    "type": "breg",
                    "baseUrl": source_url,
                    "profile": "reservation-workflow",
                    "authorization": self.authorization(
                        source_actor,
                        source_actor["resource"],
                        ["reservations:workflow"],
                    ),
                },
                "review": {
                    "type": "casework-review-producer",
                    "baseUrl": casework_url,
                    "profile": "coordinator-producer",
                    "producer": "coordinator",
                    "authorization": self.authorization(
                        reviewer, reviewer["resource"], ["casework:review"]
                    ),
                    "completion": {
                        "recipientBinding": "reservation-review-v1",
                        "bearerTokenRef": "secret:file/review-completion-token",
                    },
                    "resultCheckSeconds": 900,
                },
                "catalogue": {
                    "type": "scheduling",
                    "baseUrl": scheduling_url,
                    "authorization": self.authorization(
                        catalogue,
                        native.SCHEDULING_RESOURCE,
                        ["scheduling:read"],
                    ),
                },
                "bookings": {
                    "type": "scheduling",
                    "baseUrl": scheduling_url,
                    "authorization": self.authorization(
                        booking,
                        native.SCHEDULING_RESOURCE,
                        ["scheduling:read", "scheduling:commit"],
                        taskAuthority=task,
                    ),
                    "observationAuthorization": self.authorization(
                        booking,
                        native.SCHEDULING_RESOURCE,
                        ["scheduling:read"],
                    ),
                },
                "notices": {
                    "type": "messaging",
                    "baseUrl": messaging_url,
                    "authorization": self.authorization(
                        sender, sender["resource"], ["messaging:send"]
                    ),
                },
            },
            port,
            "reservation-coordinator-before-restart",
            primary_project=project,
        )

    def invoke_source(
        self, source_url: str, token: str, action: str, inputs: dict[str, object]
    ) -> dict[str, object]:
        return native.http(
            "POST",
            source_url
            + "/v1/actions/"
            + action
            + "?accessProfile=reservation-workflow",
            token,
            {"input": inputs},
            {"Idempotency-Key": "native-source-" + uuid.uuid4().hex},
            (200, 201),
        )

    def create_reservation(
        self, source_url: str, token: str, label: str, capacity_policy: str, start: str
    ) -> tuple[str, dict[str, object]]:
        response = self.invoke_source(
            source_url,
            token,
            "submit-reservation-request",
            {
                "requestKey": label,
                "requesterReference": "organization-42",
                "notificationDestination": f"{label}@example.invalid",
                "offering": "room-reservation",
                "start": start,
                "durationMinutes": 240,
                "resourceId": "room-a",
                "attendees": 12,
                "agreementRequired": True,
                "capacityPolicy": capacity_policy,
            },
        )
        identifier = response["results"]["reservation"]["recordId"]
        return identifier, self.read_reservation(source_url, token, identifier)

    def read_reservation(self, source_url: str, token: str, identifier: str):
        return native.http(
            "GET",
            source_url
            + "/v1/records/reservation-requests/"
            + identifier
            + "?accessProfile=reservation-workflow",
            token,
        )

    @staticmethod
    def review_request(
        binding: dict[str, object], identifier: str, record: dict[str, object]
    ) -> dict[str, object]:
        domain = record["data"]["domainData"]
        digest = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        return {
            "policy": binding,
            "subject": {
                "source": "reservations",
                "type": "reservation-request",
                "id": identifier,
                "version": str(record["data"]["revisionIdentifier"]),
                "digest": digest,
            },
            "requesterReference": identifier,
            "context": {
                "mode": "submitted",
                "snapshot": {
                    "reservationId": identifier,
                    "offering": domain["offering"],
                    "start": domain["start"],
                    "durationMinutes": domain["durationMinutes"],
                    "attendees": domain["attendees"],
                },
            },
        }

    def capacity_grant(
        self,
        owner: Path,
        casework_url: str,
        binding: dict[str, object],
        identifier: str,
        record: dict[str, object],
    ) -> tuple[dict[str, object], str]:
        producer = self.token("bregctl", owner, "review-producer")
        grant_request = self.review_request(binding, identifier, record)
        grant_request["subject"]["type"] = "reservation-capacity-authorization"
        grant_request["requesterReference"] = "capacity:" + identifier
        request = casework_request(
            casework_url + "/v1/review-requests",
            producer,
            grant_request,
            {
                "Registry-Review-Profile": "coordinator-producer",
                "Idempotency-Key": "native-grant-review-" + identifier,
            },
        )
        staff = self.token("bregctl", owner, "staff")
        headers = {"Registry-Casework-Profile": "staff"}
        deadline = time.monotonic() + 30
        while True:
            page = native.http(
                "GET",
                casework_url + "/v1/review-tasks?queue=applications&limit=100",
                staff,
                headers=headers,
            )
            task = next(
                (
                    item
                    for item in page["items"]
                    if item["requestId"] == request["requestId"]
                ),
                None,
            )
            if task is not None:
                break
            assert time.monotonic() < deadline, "the grant review task was not created"
            time.sleep(0.1)
        url = casework_url + "/v1/review-tasks/" + task["taskId"]
        native.http(
            "POST",
            url + "/claim",
            staff,
            headers={
                **headers,
                "If-Match": f'"{task["revision"]}"',
                "Idempotency-Key": "native-claim-grant-" + identifier,
            },
        )
        current = native.http("GET", url, staff, headers=headers)
        grant = native.http(
            "POST",
            url + "/task-grants",
            staff,
            {"templateId": "reservation-capacity", "templateVersion": "1"},
            {
                **headers,
                "If-Match": f'"{current["revision"]}"',
                "Idempotency-Key": "native-capacity-grant-" + identifier,
            },
        )
        bootstrap = self.token("bregctl", owner, "task-agent")
        assertion = native.http(
            "POST",
            casework_url + f"/v1/task-grants/{grant['id']}/assertion",
            bootstrap,
        )["assertion"]
        encoded = assertion.split(".")[1]
        claims = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        native.private(
            self.root / ("capacity-grant-" + identifier + ".json"),
            {
                key: claims.get(key)
                for key in (
                    "iss",
                    "sub",
                    "aud",
                    "scope",
                    "registry_grant_id",
                    "registry_grant_client",
                    "registry_grant_resource",
                    "registry_grant_bounds",
                    "registry_grant_exp",
                    "identity",
                )
            },
        )
        return grant, request["requestId"]

    def decide_workflow_review(
        self,
        owner: Path,
        casework_url: str,
        identifier: str,
        excluded_request: str,
        decision: str,
    ) -> None:
        staff = self.token("bregctl", owner, "staff")
        headers = {"Registry-Casework-Profile": "staff"}
        deadline = time.monotonic() + 60
        while True:
            page = native.http(
                "GET",
                casework_url + "/v1/review-tasks?queue=applications&limit=100",
                staff,
                headers=headers,
            )
            task = next(
                (
                    item
                    for item in page["items"]
                    if item["requesterReference"] == identifier
                    and item["requestId"] != excluded_request
                    and item["state"] == "open"
                ),
                None,
            )
            if task is not None:
                break
            assert time.monotonic() < deadline, (
                "the workflow review task was not created"
            )
            time.sleep(0.1)
        url = casework_url + "/v1/review-tasks/" + task["taskId"]
        native.http(
            "POST",
            url + "/claim",
            staff,
            headers={
                **headers,
                "If-Match": f'"{task["revision"]}"',
                "Idempotency-Key": "native-claim-workflow-" + identifier,
            },
        )
        current = native.http("GET", url, staff, headers=headers)
        body = (
            {"decision": {"type": "approve", "outcome": "approved"}}
            if decision == "approved"
            else {"decision": {"type": "reject", "outcome": "rejected"}}
        )
        native.http(
            "POST",
            url + "/decisions",
            staff,
            body,
            {
                **headers,
                "If-Match": f'"{current["revision"]}"',
                "Idempotency-Key": "native-decision-" + identifier,
            },
            (204,),
        )

    def run(self) -> None:
        bootstrap = native.write_breg(self.root / "issuer-owner", self.urls)
        add_reservation_source_client(bootstrap)
        self.ctl("bregctl", "check", bootstrap)
        bootstrap_breg, bootstrap_database = native.free_ports(2)
        self.sessions.append(("bregctl", bootstrap))
        bootstrap_report = self.ctl(
            "bregctl",
            "dev",
            "start",
            bootstrap,
            "--breg-port",
            bootstrap_breg,
            "--issuer-port",
            self.ports["issuer"],
            "--database-port",
            bootstrap_database,
            "--breg-bin",
            self.bin / "breg",
        )
        resource = bootstrap_report["resource"]
        agent_subject = native.subject(self.token("bregctl", bootstrap, "task-agent"))
        source, source_url, _ = self.source_service(bootstrap)

        (coordinator_port,) = native.free_ports(1)
        casework_port = self.ports["casework"]
        completion_token = uuid.uuid4().hex + uuid.uuid4().hex
        receiver = f"http://127.0.0.1:{coordinator_port}/v1/review-completions"
        casework_project = write_review_casework(
            self.root / "review-casework-source", self.urls, agent_subject
        )
        checked = self.ctl("caseworkctl", "check", casework_project)
        binding = next(
            item
            for item in checked["policyBindings"]
            if item["id"] == "reservation-review"
        )

        native.write_messaging = write_reservation_messaging
        native.write_scheduling = write_reservation_scheduling
        messaging_url, messaging_runtime = self.messaging_service(bootstrap)
        scheduling_url, scheduling_runtime = self.scheduling_service(
            bootstrap, resource, "2026-11-03"
        )
        scheduling_proxy = LostSchedulingResponseProxy(
            scheduling_url, "/v1/appointments"
        )
        source_proxy = native.LostResponseProxy(
            source_url,
            "/v1/actions/record-direct-confirmed?accessProfile=reservation-workflow",
        )
        self.proxies.extend([scheduling_proxy, source_proxy])

        # Package and start Coordinator before Casework so the latter can bind
        # its authenticated completion destination to the live receiver.
        casework_placeholder = f"http://127.0.0.1:{casework_port}"
        runtime, coordinator_url, worker = self.coordinator(
            bootstrap,
            source,
            source_proxy.url,
            casework_placeholder,
            scheduling_proxy.url,
            messaging_url,
            completion_token,
            agent_subject,
            binding,
            coordinator_port,
        )
        _, casework_url, runtime_binding = self.review_casework(
            bootstrap,
            resource,
            casework_port,
            receiver,
            completion_token,
            agent_subject,
        )
        assert runtime_binding == binding

        source_token = self.token("bregctl", bootstrap, "reservation-source-agent")
        reservations = {}
        for label, policy, start in (
            ("request-only-success", "request-only", "2026-11-03T09:00:00Z"),
            ("request-only-rejected", "request-only", "2026-11-04T09:00:00Z"),
        ):
            identifier, record = self.create_reservation(
                source_url, source_token, label, policy, start
            )
            grant, grant_request = self.capacity_grant(
                bootstrap, casework_url, binding, identifier, record
            )
            request = self.review_request(binding, identifier, record)
            reservations[label] = {
                "id": identifier,
                "record": record,
                "grant": {"id": grant["id"], "expiresAt": grant["expiresAt"]},
                "grantRequest": grant_request,
                "sourceVersion": request["subject"]["version"],
                "sourceDigest": request["subject"]["digest"],
            }

        runs = {}
        agreement_time = native.stamp(1)
        for label, flow, outcome in (
            (
                "request-only-success",
                "reservation-review-request-only",
                "completed",
            ),
            (
                "request-only-rejected",
                "reservation-review-request-only",
                "completed",
            ),
        ):
            reservation = reservations[label]
            runs[label] = self.start(
                bootstrap,
                coordinator_url,
                "native-reservation-" + label,
                {
                    "reservationId": reservation["id"],
                    "sourceVersion": reservation["sourceVersion"],
                    "sourceDigest": reservation["sourceDigest"],
                    "agreementCompleteAt": agreement_time,
                    "agreementCallbackId": "agreement-" + label,
                    "agreementOutcome": outcome,
                    "grant": reservation["grant"],
                },
                flow,
            )

        deadline = time.monotonic() + 60
        for run in runs.values():
            while True:
                status = self.inspect(bootstrap, coordinator_url, run)["run"]
                if status["step"] == "await-review":
                    break
                assert status["state"] == "running", status
                assert time.monotonic() < deadline, "a run never reached review"
                time.sleep(0.1)

        self.stop(worker)
        worker = self.spawn(
            "coordinator", runtime, "reservation-coordinator-after-restart"
        )
        self.ready(worker, coordinator_url)
        request_only = reservations["request-only-success"]
        self.decide_workflow_review(
            bootstrap,
            casework_url,
            request_only["id"],
            request_only["grantRequest"],
            "approved",
        )
        settled = {}
        reconciled = {}
        settled["request-only-success"], reconciled["request-only-success"] = (
            self.drive(bootstrap, coordinator_url, runs["request-only-success"])
        )
        assert scheduling_proxy.lost
        assert "book" in reconciled["request-only-success"]
        assert source_proxy.lost
        assert "record-confirmed" in reconciled["request-only-success"]

        rejected = reservations["request-only-rejected"]
        self.decide_workflow_review(
            bootstrap,
            casework_url,
            rejected["id"],
            rejected["grantRequest"],
            "rejected",
        )
        settled["request-only-rejected"], reconciled["request-only-rejected"] = (
            self.drive(bootstrap, coordinator_url, runs["request-only-rejected"])
        )
        assert settled["request-only-success"]["run"]["outcome"] == (
            "reservation-confirmed"
        )
        assert settled["request-only-rejected"]["run"]["outcome"] == (
            "review-rejected"
        )
        assert len(source_proxy.commands) == 2
        assert source_proxy.commands[0]["key"] == source_proxy.commands[1]["key"]
        assert (
            source_proxy.commands[0]["bodyHash"] == source_proxy.commands[1]["bodyHash"]
        )

        facts = {}
        for label, reservation in reservations.items():
            record = self.read_reservation(source_url, source_token, reservation["id"])[
                "data"
            ]["domainData"]
            facts[label] = {
                key: record.get(key)
                for key in (
                    "requestState",
                    "reviewState",
                    "agreementState",
                    "capacityState",
                    "reservationOutcome",
                    "appointmentId",
                )
            }
        expected_facts = {
            "request-only-success": {
                "requestState": "received",
                "reviewState": "approved",
                "agreementState": "completed",
                "capacityState": "confirmed",
                "reservationOutcome": "confirmed",
            },
            "request-only-rejected": {
                "requestState": "received",
                "reviewState": "rejected",
                "capacityState": "uncommitted",
                "reservationOutcome": "rejected",
            },
        }
        for label, expected in expected_facts.items():
            assert {key: facts[label][key] for key in expected} == expected

        messages = self.ctl(
            "messagingctl",
            "messages",
            "list",
            "--runtime-config",
            messaging_runtime,
        )
        assert len(messages["messages"]) == 1
        native.private(
            self.root / "native-reservation-review-proof.json",
            {
                "proofBoundary": "native-public-services",
                "workerRestartWhileWaiting": True,
                "lostSchedulingResponse": scheduling_proxy.lost,
                "lostSourceResponse": source_proxy.lost,
                "reconciledSteps": reconciled,
                "facts": facts,
                "acceptedMessages": len(messages["messages"]),
                "schedulingRuntime": str(scheduling_runtime.name),
                "binarySha256": self.binary_digests,
            },
        )
        print(
            "Native reservation review passed one confirmation, one rejection, restart and exact recovery.",
            flush=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--build-manifest", type=Path)
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    for variable in (
        "COORDINATOR_TEST_DATABASE_URL",
        "COORDINATOR_MESSAGING_TEST_DATABASE_URL",
    ):
        assert os.environ.get(variable), (
            f"set {variable} to a task-owned local database"
        )
    root = args.work_dir
    if root is None:
        root = Path(tempfile.mkdtemp(prefix="reservation-review-native-"))
    else:
        root = root.resolve()
        root.mkdir(mode=0o700)
    print(f"Private journey state: {root}", flush=True)
    copy2 = native.shutil.copy2

    def link_frozen(source, destination, **_kwargs):
        os.link(source, destination)
        return destination

    native.shutil.copy2 = link_frozen
    try:
        journey = ReservationJourney(
            root,
            args.bin_dir.resolve(),
            1,
            args.build_manifest,
            required_binaries=REQUIRED_BINARIES,
            require_reviewed_notice_starter=False,
        )
    finally:
        native.shutil.copy2 = copy2
    success = False
    try:
        journey.run()
        success = True
    finally:
        journey.cleanup(success)
    print(
        "Native reservation-review journey passed; owned processes stopped.", flush=True
    )


if __name__ == "__main__":
    main()
