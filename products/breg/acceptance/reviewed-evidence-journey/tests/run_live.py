#!/usr/bin/env python3
"""Run reviewed source correction to signed, independently verified Evidence.

All actors and records are synthetic. Runtimes are real; the disposable token
issuer does not prove a production OAuth deployment. No UI or domain rules.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from urllib.parse import urlsplit

import yaml

from proof import check_ask_loop, check_cleanup, check_correlation, check_minimized, check_observations
from support import Harness, INPUTS, ROOT, hashes, port, write, yaml_write


class JourneyHarness(Harness):
    """Observe real Casework traffic and real signed hook delivery without keeping content."""

    def __init__(self, output, binaries):
        super().__init__(output, binaries)
        # The maintained helper carries this across launchers that strip DYLD variables.
        if os.environ.get("REGISTRY_CARGO_RUNTIME_LIBRARY_PATH"):
            self.env["DYLD_FALLBACK_LIBRARY_PATH"] = os.environ["REGISTRY_CARGO_RUNTIME_LIBRARY_PATH"]
        self.observers = []
        self.casework_requests = []
        self.created_request_ids = set()
        self.asked_events = []
        self.observation_lock = threading.Lock()

    def listen(self, handler):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.observers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{server.server_port}"

    def observe_casework(self, origin):
        harness = self

        class Observer(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def exchange(self):
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 <= size <= 1024 * 1024:
                    self.send_error(413)
                    return
                body = self.rfile.read(size)
                connection = HTTPConnection(urlsplit(origin).netloc, timeout=15)
                try:
                    connection.request(self.command, self.path, body, dict(self.headers))
                    response = connection.getresponse()
                    content = response.read(1024 * 1024 + 1)
                    assert len(content) <= 1024 * 1024, "Casework observer response exceeded bound"
                    authorization = self.headers.get("Authorization")
                    actor = next(
                        (
                            role
                            for role, token in harness.tokens.items()
                            if authorization == "Bearer " + token
                        ),
                        "unauthenticated",
                    )
                    actor = "applicant" if actor == "operator" else actor
                    with harness.observation_lock:
                        harness.casework_requests.append(
                            {
                                "actor": actor,
                                "method": self.command,
                                "path": urlsplit(self.path).path,
                                "status": response.status,
                            }
                        )
                        if (
                            self.command == "POST"
                            and urlsplit(self.path).path == "/v1/review-requests"
                            and response.status in (200, 201)
                        ):
                            harness.created_request_ids.add(json.loads(content)["requestId"])
                        write(harness.output / "casework-requests.json", harness.casework_requests)
                    self.send_response(response.status)
                    for name, value in response.getheaders():
                        if name.lower() not in ("connection", "transfer-encoding", "content-length"):
                            self.send_header(name, value)
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                finally:
                    connection.close()

            do_GET = do_POST = do_DELETE = do_PATCH = exchange

        self.casework_origin = self.listen(Observer)
        return self.casework_origin

    def receive_hooks(self):
        harness = self
        key = os.urandom(32).hex().encode()
        (self.secret_root / "ask-hook-key").write_bytes(key)

        class Receiver(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_POST(self):
                size = int(self.headers.get("Content-Length", "0"))
                if self.path != "/events" or not 0 < size <= 8192:
                    self.send_error(400)
                    return
                body = self.rfile.read(size)
                identifier, timestamp = (
                    self.headers.get("webhook-id", ""),
                    self.headers.get("webhook-timestamp", ""),
                )
                expected = (
                    "v1,"
                    + base64.b64encode(
                        hmac.digest(
                            key, identifier.encode() + b"." + timestamp.encode() + b"." + body, "sha256"
                        )
                    ).decode()
                )
                if not hmac.compare_digest(self.headers.get("webhook-signature", ""), expected):
                    self.send_error(403)
                    return
                event = json.loads(body)
                if event["type"] != "proposal.asked" or event["id"] != identifier:
                    self.send_error(400)
                    return
                data = event["data"]
                with harness.observation_lock:
                    harness.asked_events.append(
                        {
                            "id": event["id"],
                            "type": event["type"],
                            "data": {
                                name: data[name] for name in ("proposalId", "submissionVersion", "transition")
                            },
                        }
                    )
                    write(harness.output / "asked-events.json", harness.asked_events)
                self.send_response(204)
                self.end_headers()

        self.hook_origin = self.listen(Receiver)

    def raw(self, origin, path, token, *, body=None, method="GET", headers=None):
        """Bounded file exchange. Bytes remain in memory and never enter proof output."""
        connection = HTTPConnection(urlsplit(origin).netloc, timeout=15)
        try:
            connection.request(method, path, body, {**(headers or {}), "Authorization": "Bearer " + token})
            response = connection.getresponse()
            content = response.read(1024 * 1024 + 1)
            assert len(content) <= 1024 * 1024, "file exchange exceeded bound"
            return response.status, content, {key.lower(): value for key, value in response.getheaders()}
        finally:
            connection.close()

    def cleanup(self):
        try:
            return super().cleanup()
        finally:
            for server in self.observers:
                server.shutdown()
                server.server_close()


def breg_runtime(h, name, package, origin, casework):
    return {
        "apiVersion": "id.registrystack.org/formats/breg/runtime/v1alpha1",
        "kind": "BRegRuntimeConfig",
        "listener": {"bind": origin.removeprefix("http://")},
        "identity": {
            "environment": "acceptance",
            "instanceId": "reviewed-evidence-" + name,
            "databaseId": "reviewed-evidence-" + name,
        },
        "package": {"root": str(package)},
        "secretProviders": {"file": {"root": str(h.secret_root)}},
        "database": h.db_configs[name],
        "authentication": {
            "oidc": {
                "issuers": {
                    "primary": {
                        "issuer": h.issuer_url,
                        "audience": "urn:journey:breg",
                        "allowedAlgorithm": "ES256",
                        "accessTokenType": "at+jwt",
                        "scopeClaim": "scope",
                        "scopeSeparator": " ",
                        "allowedClients": list(h.tokens),
                        "maximumTokenLifetimeSeconds": 3600,
                        "leewayMilliseconds": 60000,
                        "jwksCache": {
                            "cacheTtlSeconds": 600,
                            "negativeCacheTtlSeconds": 60,
                            "refreshCooldownSeconds": 30,
                            "maximumDocumentBytes": 65536,
                            "attemptTimeoutMilliseconds": 5000,
                            "outageToleranceSeconds": 0,
                        },
                        "jwksSource": {"type": "static", "documentRef": "secret:file/oidc-jwks"},
                    },
                },
            },
            "authorityClaims": {"principal": "registry_principal", "purpose": "registry_purpose"},
        },
        "audit": {
            "hashKeyRef": "secret:file/audit-key",
            "path": str(h.output / (name + "-audit/audit.jsonl")),
        },
        "cursor": {"secretRef": "secret:file/cursor-key", "maximumAgeSeconds": 300},
        "destinations": {
            "hooks": {
                "ask-observer": {
                    "origin": h.hook_origin,
                    "path": "/events",
                    "networkProfile": "loopback-development-http",
                    "dnsFamily": "dual-stack-strict",
                    "allowedPrivateCidrs": [],
                    "hmacSha256KeyRef": "secret:file/ask-hook-key",
                    "classificationCeiling": "internal",
                    "deliveryCeilings": {"attemptTimeoutMilliseconds": 1000, "maximumAttempts": 3},
                }
            }
        },
        "reviewAuthorities": {
            "casework": {
                "endpoint": casework,
                "profile": "requester",
                "producerId": "registry",
                "recoveryDays": 7,
                "tokenRef": "secret:file/producer-token",
            }
        },
        "operationalTimeouts": {
            "httpRequestMilliseconds": 10000,
            "shutdownGraceMilliseconds": 1000,
            "recordLockMilliseconds": 5000,
            "migrationLockMilliseconds": 30000,
            "migrationStatementMilliseconds": 60000,
        },
    }


def activate_source(h, origin, casework):
    project = h.output / "registry"
    shutil.copytree(INPUTS / "registry", project)
    empty = h.output / "empty-package"
    empty.mkdir()
    schema_runtime = h.output / "schema-runtime.yaml"
    yaml_write(schema_runtime, breg_runtime(h, "schema", empty, "http://127.0.0.1:0", casework))
    journeys = yaml.safe_load((project / "tests/journeys.yaml").read_text())
    bindings = []
    for journey in journeys["journeys"]:
        for step in journey["steps"]:
            role = "operator" if step["accessProfile"] == "operator" else "source"
            step["claims"]["principal"] = role
            bindings.append(
                {
                    "journeyId": journey["id"],
                    "stepId": step["id"],
                    "credential": {"type": "bearer", "tokenRef": "secret:file/" + role + "-token"},
                }
            )
    yaml_write(project / "tests/journeys.yaml", journeys)
    credentials = h.output / "credentials.json"
    write(
        credentials,
        {
            "apiVersion": "id.registrystack.org/formats/breg/schema-test-credentials/v1",
            "kind": "BRegSchemaTestCredentials",
            "bindings": bindings,
        },
    )
    h.ctl("bregctl", "source-check", "check", project)
    receipt = h.output / "schema-test-receipt.json"
    test = h.ctl(
        "bregctl",
        "source-schema-test",
        "test",
        project,
        "--runtime-config",
        schema_runtime,
        "--credentials",
        credentials,
        "--output",
        receipt,
    )
    h.check("source-schema-journey", test["successfulJourneyIds"] == ["source-lookup-boundary"])
    candidate = h.output / "source-candidate"
    h.ctl(
        "bregctl",
        "source-package",
        "package",
        project,
        "--schema-fingerprint",
        test["schemaFingerprint"],
        "--test-receipt",
        receipt,
        "--output",
        candidate,
    )
    package = candidate / "package"
    compiled = json.loads((package / "inventories/actions.json").read_text())
    h.check(
        "compiled-id-only-review-selection",
        compiled["actions"][0]["execution"]["proposal"]["review"]["policy"] == {"id": "status-review"},
    )
    runtime = h.output / "source-runtime.yaml"
    yaml_write(runtime, breg_runtime(h, "source", package, origin, casework))
    h.ctl("bregctl", "source-apply", "apply", "--runtime-config", runtime, "--package", package, "--initial")
    h.ctl("bregctl", "source-verify", "verify", "--runtime-config", runtime)
    return project, package, runtime


def activate_casework(h, source_package, source, origin):
    project = h.output / "casework"
    shutil.copytree(INPUTS / "casework", project)
    model = yaml.safe_load((project / "casework.yaml").read_text())
    producer = model["trustedProducers"]["registry"]
    producer["issuer"] = producer["trustedInitiatorIssuer"] = h.issuer_url
    yaml_write(project / "casework.yaml", model)
    h.ctl(
        "caseworkctl",
        "context-pair",
        "provider",
        "pair",
        project,
        "--provider-id",
        "registry",
        "--breg-package",
        source_package,
        "--action-id",
        "correct-status",
        "--bregctl-bin",
        h.binaries["bregctl"],
        "--apply",
    )
    checked = h.ctl("caseworkctl", "review-check", "check", project)
    package = h.output / "review-package"
    h.ctl("caseworkctl", "review-package", "package", project, "--output", package)
    config = {
        "apiVersion": "id.registrystack.org/formats/casework/runtime/v1alpha1",
        "kind": "CaseworkRuntimeConfig",
        "identity": {"databaseId": "reviewed-evidence-casework"},
        "package": {"root": str(package)},
        "listener": {
            "bind": origin.removeprefix("http://"),
            "tlsTermination": "development-loopback",
            "networkExposure": "private-address",
        },
        "secretProviders": {"file": {"root": str(h.secret_root)}},
        "database": h.db_configs["casework"],
        "authentication": {
            "oidc": {
                "issuers": {
                    "main": {
                        "issuer": h.issuer_url,
                        "audience": "urn:journey:casework",
                        "allowedClients": list(h.tokens),
                        "jwksSource": {"type": "static", "documentRef": "secret:file/oidc-jwks"},
                    }
                }
            }
        },
        "audit": {"path": str(h.output / "review-audit/audit.ndjson"), "hashKeyRef": "secret:file/audit-key"},
        "contextProviders": {
            "registry": {
                "baseUrl": source,
                "statusProfile": "review-status",
                "tokenEndpoint": h.issuer_url + "/oauth2/token",
                "clientAssertionAudience": h.issuer_url,
                "resource": "urn:journey:breg",
                "scopes": ["registry:review-status"],
                "clientIdRef": "secret:file/context-client-id",
                "clientAssertionKeyRef": "secret:file/client-key",
            }
        },
    }
    runtime = h.output / "review-runtime.yaml"
    yaml_write(runtime, config)
    h.ctl("caseworkctl", "review-apply", "apply", "--runtime-config", runtime)
    h.start("casework", [h.binaries["casework"], "--runtime-config", runtime, "serve"], origin)
    status, _, _ = h.http(
        h.casework_origin,
        "/v1/directory/bootstrap",
        h.tokens["administrator"],
        "administrator",
        {
            "teamId": "reviewers",
            "staff": [{"issuer": h.issuer_url, "subject": "staff"}],
            "supervisors": [],
            "queueId": "reviews",
        },
        "POST",
        {"If-Match": '"0"', "Idempotency-Key": "directory"},
    )
    h.check("review-directory-bootstrap", status == 200)
    return checked["policyBindings"][0]


def registry_connection(origin):
    return {
        "endpoints": {
            "registry": {
                "origin": origin,
                "authentication": {"type": "static-authorization", "tokenRef": "secret:file/source-token"},
            }
        }
    }


def bind_static_fixture(fixture):
    """Match this journey's static source credential, retaining all HTTP/privacy cases."""
    for case in fixture["cases"]:
        acquisition = case.get("acquisition")
        if acquisition:
            acquisition["intercepts"] = [
                item for item in acquisition["intercepts"] if item["type"] != "token-endpoint"
            ]
            acquisition["exchanges"] = [
                item for item in acquisition["exchanges"] if not item["request"].get("tokenRequest")
            ]


def activate_evidence(h, source_project, source, origin):
    exported = h.output / "source-export"
    h.ctl(
        "bregctl",
        "source-export",
        "generate",
        "evidence-source",
        source_project,
        "--access-profile",
        "evidence-source",
        "--record-type",
        "record",
        "--selector",
        "by-code",
        "--selector",
        "by-registration-number",
        "--fields",
        "status",
        "--source-id",
        "registry-status",
        "--connection",
        "registry",
        "--output",
        exported,
    )
    project = h.output / "evidence"
    h.ctl(
        "evidencectl",
        "evidence-init",
        "init",
        project,
        "--starter",
        ROOT / "products/breg/evidence/offline-starter",
        "--profile",
        "local",
    )
    h.ctl("evidencectl", "source-import", "source", "import", exported, "--project", project)
    model = yaml.safe_load((project / "evidence.yaml").read_text())
    fragment = yaml.safe_load((ROOT / "products/breg/evidence/starter/definitions.yaml.fragment").read_text())
    # Import starts from a valid standalone project. Only the imported HTTP
    # Source and its Functions remain in this composition's final model.
    model["sources"].pop("record-status")
    model["selectorProfiles"].pop("record-by-code-v1")
    model["functions"] = {
        id: function
        for id, function in model["functions"].items()
        if id not in ("record-status-extract", "extract-record-active")
    }
    model["functions"]["record-active"] = fragment["functions"]["record-active"]
    model["assertionDefinitions"] = {"record-active": fragment["assertionDefinitions"]["record-active"]}
    yaml_write(project / "evidence.yaml", model)
    for directory, name in [("functions", "record-active.rhai"), ("fixtures", "record-active.yaml")]:
        (project / directory).mkdir(exist_ok=True)
        shutil.copyfile(
            ROOT / "products/breg/evidence/starter" / directory / name, project / directory / name
        )
    fixture_path = project / "fixtures/record-active.yaml"
    fixture = yaml.safe_load(fixture_path.read_text())
    bind_static_fixture(fixture)
    yaml_write(fixture_path, fixture)
    target_dir = h.output / "target"
    h.run(
        "evidence-target",
        [h.binaries["evidencectl"], "target", "new", target_dir, "--local", "--project", project],
    )
    target = yaml.safe_load((target_dir / "target.yaml").read_text())
    target["package"]["root"] = str(h.output / "evidence-installed")
    target["service"].update(
        providerId="urn:example:provider:registry-evidence",
        issuer="urn:example:issuer:registry-evidence",
        publicOrigin=origin,
    )
    target["listener"]["bind"] = origin.removeprefix("http://")
    target["secretProviders"] = {"file": {"root": str(h.secret_root)}}
    target["authentication"]["oidc"].update(
        issuer=h.issuer_url,
        audience="urn:example:audience:local-evidence",
        algorithms=["ES256"],
        maximumTokenLifetimeSeconds=3600,
        jwksSource={"type": "uri", "uri": h.issuer_url + "/.well-known/jwks.json"},
    )
    target["connections"]["registry"] = registry_connection(source)
    # This composition replaced the starter's extract-backed source with HTTP.
    target["extracts"] = {}
    target["signer"].update(
        privateKeyRef="secret:file/signing-p256-private-jwk",
        publicJwkFile="signing-public.jwk.json",
    )
    shutil.copyfile(h.secret_root / "signing-p256-public.jwk.json", target_dir / "signing-public.jwk.json")
    target["subjectBinding"] = {"secretRef": "secret:file/subject-binding-hmac-key", "keyVersion": 1}
    target["audit"].update(
        path=str(h.output / "evidence-audit/audit.jsonl"), hashKeyRef="secret:file/audit-key"
    )
    yaml_write(target_dir / "target.yaml", target)
    authority_path = target_dir / target["authority"]
    authority = yaml.safe_load(authority_path.read_text())
    profile = next(iter(authority["accessProfiles"].values()))
    profile["requesterTags"] = ["consumer"]
    authority["accessProfiles"] = {"consumer": profile}
    yaml_write(authority_path, authority)
    h.ctl("evidencectl", "evidence-check", "check", project, "--target", target_dir)
    fixture = h.ctl("evidencectl", "evidence-fixtures", "test", project, "--target", target_dir)
    h.fixture_cases = len(yaml.safe_load(fixture_path.read_text())["cases"])
    h.check(
        "evidence-fixture-cases",
        fixture["passed"] and fixture["fixtures"][0]["evaluatedCases"] == h.fixture_cases,
    )
    candidate = h.output / "evidence-candidate"
    h.ctl(
        "evidencectl", "evidence-package", "package", project, "--target", target_dir, "--output", candidate
    )
    shutil.copytree(candidate / "bundle", h.output / "evidence-installed")
    runtime = candidate / "runtime.yaml"
    h.run(
        "evidence-authority-activate",
        [
            h.binaries["evidence"],
            "authority",
            "activate",
            "--runtime-config",
            runtime,
            "--document",
            candidate / "compiled-authority.yaml",
        ],
    )
    h.start("evidence", [h.binaries["evidence"], "serve", "--runtime-config", runtime], origin)
    profile_path = h.output / "consumer.json"
    h.run(
        "consumer-profile",
        [
            h.binaries["evidencectl"],
            "client",
            "profile",
            "create",
            "--base-url",
            origin,
            "--client-id",
            "consumer",
            "--private-key-file",
            "secrets/client-key",
            "--local-loopback-discovery",
            "--client-assertion-audience",
            h.issuer_url,
            "--expected-audience",
            "urn:example:audience:local-evidence",
            "--expected-provider",
            "urn:example:provider:registry-evidence",
            "--expected-issuer",
            "urn:example:issuer:registry-evidence",
            "--output",
            profile_path,
        ],
    )
    return project, profile_path


def consume(h, project, profile, label, expected):
    h.run(
        label + "-prepare",
        [
            h.binaries["evidencectl"],
            "request",
            "prepare",
            "--profile",
            profile,
            "--requirement",
            "urn:example:requirement:record-active:v1",
            "--subject",
            "subject:code=SYNTHETIC-LIVE",
            "--name",
            label,
            "--project",
            project,
        ],
    )
    request_dir = project / ".evidence/requests" / label
    # Native preparation fixes trust, subject binding, nonce and output contract
    # before the response exists. curl reads the private config without echoing it.
    response = request_dir / "response.json"
    # The config has a project-relative request path, so run curl in that project.
    completed = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--noproxy",
            "*",
            "--config",
            str(request_dir / "curl.config"),
            "--output",
            str(response),
        ],
        cwd=project,
        env=h.env,
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 0, "prepared Evidence request failed"
    h.run(
        label + "-verify",
        [
            h.binaries["evidencectl"],
            "verify",
            response,
            "--context",
            request_dir / "verification.json",
            "--output",
            request_dir / "verified.json",
        ],
    )
    payload = json.loads((request_dir / "verified.json").read_text())
    check_minimized(payload, expected)
    h.check(label + "-signed-minimized-verified", True)
    return request_dir


def seed_record(h, source):
    status, record, headers = h.http(
        source,
        "/v1/records/records?accessProfile=operator",
        h.tokens["operator"],
        body={
            "data": {
                "code": "SYNTHETIC-LIVE",
                "registrationNumber": "SYNTHETIC-LIVE-REG",
                "status": "retired",
                "label": "PRIVATE-CANARY",
            }
        },
        method="POST",
        headers={"Idempotency-Key": "seed"},
    )
    h.check("source-record-created", status == 201)
    return record["data"]["recordIdentifier"]


def await_served(label, read, ready):
    deadline = time.monotonic() + 90
    while True:
        observation = read()
        if observation[0] == 200 and ready(observation[1]):
            return observation
        if time.monotonic() > deadline:
            raise RuntimeError(label + " did not reach its served state")
        time.sleep(0.25)


def ask_and_answer(h, source, casework, source_call, task_path, claimed, submitted, accepted, correlation):
    observed = {"submitted": submitted, "accepted": accepted, "correlations": [correlation]}
    status, asked, _ = h.http(
        casework,
        task_path + "/asks",
        h.tokens["staff"],
        "staff",
        {"text": "Please provide one supporting document.", "wants": [{"kind": "document"}]},
        "POST",
        {
            "If-Match": '"' + str(claimed["revision"]) + '"',
            "Idempotency-Key": "ask-document",
            "Registry-Source-Profile": "reviewer",
        },
    )
    h.check(
        "task-holder-asks-for-one-document-with-due-date", status == 200 and bool(asked["ask"].get("dueAt"))
    )
    observed["asked"] = asked
    proposal_path = "/v1/proposals/" + submitted["id"]
    ask_id = asked["ask"]["askId"]
    _, party, headers = await_served(
        "mirrored ask",
        lambda: source_call(proposal_path),
        lambda value: (
            value.get("status") == "awaiting-party"
            and any(ask["id"] == ask_id for ask in value.get("asks", []))
        ),
    )
    observed["party"] = party
    h.check("mirrored-ask-returns-the-party-turn", party["turn"] == "party")
    status, page, _ = source_call("/v1/proposals?turn=party&limit=100")
    h.check(
        "party-list-includes-the-asked-proposal",
        status == 200 and any(item["id"] == submitted["id"] for item in page["items"]),
    )
    observed["partyPage"] = page
    deadline = time.monotonic() + 90
    while True:
        with h.observation_lock:
            events = [event for event in h.asked_events if event["data"]["proposalId"] == submitted["id"]]
        if events:
            observed["hook"] = events[0]
            break
        if time.monotonic() > deadline:
            raise RuntimeError("signed asked hook did not arrive")
        time.sleep(0.25)
    h.check("asked-hook-delivered-and-signed", True)
    answer_text, file_bytes = (
        "Synthetic explanation for this correction.",
        b"Synthetic supporting document.\n",
    )
    link = party["additions"]["supporting"]["links"]["add"]
    status, body, _ = h.raw(
        source,
        link["path"] + "?accessProfile=" + link["accessProfile"],
        h.tokens["operator"],
        body=file_bytes,
        method="POST",
        headers={
            "Content-Type": "text/plain",
            "If-Match": link["ifMatch"],
            "Idempotency-Key": "supporting-document",
        },
    )
    h.check("applicant-added-one-file", status == 200)
    added = json.loads(body)
    files = added["additions"]["supporting"]["items"]
    h.check(
        "added-file-metadata-matches-bytes",
        len(files) == 1 and files[0]["sha256"] == hashlib.sha256(file_bytes).hexdigest(),
    )
    file_id = files[0]["id"]
    observed["additionId"] = file_id
    ask = next(item for item in added["asks"] if item["id"] == ask_id)
    link = ask["links"]["answer"]
    status, answered, _ = source_call(
        link["path"],
        body={"text": answer_text, "additions": [file_id]},
        method="POST",
        headers={"If-Match": link["ifMatch"], "Idempotency-Key": "answer-document"},
    )
    h.check("applicant-answered-and-returned-to-review", status == 200 and answered["status"] == "in-review")
    observed["answered"] = answered
    _, task, _ = await_served(
        "delivered answer marker",
        lambda: h.http(
            casework, task_path, h.tokens["staff"], "staff", headers={"Registry-Source-Profile": "reviewer"}
        ),
        lambda value: value.get("marker") == "answered",
    )
    observed["task"] = task
    h.check("casework-received-the-answer-marker", True)
    status, context, _ = h.http(
        casework,
        task_path + "/context",
        h.tokens["staff"],
        "staff",
        headers={"Registry-Source-Profile": "reviewer"},
    )
    h.check("holder-reads-live-answer", status == 200)
    observed["context"] = context
    answer = next(item for item in context["asks"] if item["askId"] == ask_id)["answer"]
    link = answer["documents"][0]["download"]
    separator = "&" if "?" in link["path"] else "?"
    status, downloaded, headers = h.raw(
        source, link["path"] + separator + "accessProfile=" + link["accessProfile"], h.tokens["staff"]
    )
    h.check(
        "holder-downloads-the-cited-file-under-own-token",
        status == 200
        and downloaded == file_bytes
        and headers.get("x-content-type-options") == "nosniff"
        and headers.get("cache-control") == "no-store"
        and headers.get("content-disposition", "").startswith("attachment"),
    )
    observed["download"] = downloaded
    status, correlation, _ = source_call(proposal_path + "/review-status", "context-status", "review-status")
    h.check(
        "answer-keeps-the-accepted-request",
        status == 200 and correlation["requestId"] == accepted["requestId"],
    )
    observed["correlations"].append(correlation)
    return observed, task, answer_text, file_bytes


def reviewed_correction(h, source, casework, policy, record_id):
    def source_call(path, role="operator", profile="operator", body=None, method="GET", headers=None):
        separator = "&" if "?" in path else "?"
        return h.http(
            source,
            path + separator + "accessProfile=" + profile,
            h.tokens[role],
            body=body,
            method=method,
            headers=headers,
        )

    status, _, headers = source_call("/v1/records/records/" + record_id)
    assert status == 200, "source record cannot be read before correction"
    status, refused, _ = source_call(
        "/v1/records/records/" + record_id,
        body=[{"op": "replace", "path": "/data/status", "value": "active"}],
        method="PATCH",
        headers={
            "If-Match": headers["etag"],
            "Idempotency-Key": "no-bypass",
            "Content-Type": "application/json-patch+json",
        },
    )
    h.check("direct-patch-cannot-bypass-review", status == 400 and refused["code"] == "request.invalid")
    status, draft, headers = source_call(
        "/v1/actions/correct-status/proposals",
        body={"input": {"subjectId": record_id, "status": "active"}},
        method="POST",
        headers={"Idempotency-Key": "start"},
    )
    h.check("proposal-draft-started", status == 201)
    proposal_path = "/v1/proposals/" + draft["id"]
    status, submitted, _ = source_call(
        proposal_path + "/submit",
        body={},
        method="POST",
        headers={"If-Match": headers["etag"], "Idempotency-Key": "submit"},
    )
    h.check("frozen-policy-id-selected", status == 200 and submitted["state"] == "submitted")
    write(h.output / "frozen-submission.json", submitted)
    deadline = time.monotonic() + 90
    while True:
        status, page, _ = h.http(
            casework,
            "/v1/review-tasks?queue=reviews&limit=25",
            h.tokens["staff"],
            "staff",
            headers={"Registry-Source-Profile": "reviewer"},
        )
        assert status == 200, "Casework inbox unavailable"
        tasks = [task for task in page["items"] if task["subject"]["id"] == submitted["id"]]
        if tasks:
            task = tasks[0]
            break
        if time.monotonic() > deadline:
            raise RuntimeError("exact source submission did not reach Casework")
        time.sleep(0.25)
    task_path = "/v1/review-tasks/" + task["taskId"]
    status, accepted, _ = h.http(
        casework, "/v1/review-requests/" + task["requestId"], h.tokens["producer"], "requester"
    )
    h.check("provider-concrete-policy-accepted", status == 200 and accepted["policy"] == policy)
    write(h.output / "accepted-review.json", accepted)
    deadline = time.monotonic() + 90
    while True:
        status, correlation, _ = source_call(
            proposal_path + "/review-status", "context-status", "review-status"
        )
        if status == 200 and correlation.get("requestId"):
            break
        if time.monotonic() > deadline:
            raise RuntimeError("source did not retain its accepted review request identity")
        time.sleep(0.25)
    write(h.output / "source-review-correlation.json", correlation)
    # BReg's public subject uses subjectType; the shared Review protocol uses type.
    source_subject = dict(correlation["subject"])
    source_subject["type"] = source_subject.pop("subjectType")
    h.check(
        "source-retains-exact-accepted-request",
        correlation["requestId"] == accepted["requestId"] and source_subject == accepted["subject"],
    )
    apply_body = {
        "submissionVersion": submitted["submissionVersion"],
        "effectDigest": submitted["effectDigest"],
    }
    status, current, etag = source_call(proposal_path, "applier", "applier")
    assert status == 200, "applier cannot inspect submission"
    status, refusal, _ = source_call(
        proposal_path + "/apply",
        "applier",
        "applier",
        apply_body,
        "POST",
        {"If-Match": etag["etag"], "Idempotency-Key": "before-review"},
    )
    h.check("authorized-applier-needs-approval", status == 412 and refusal["code"] == "precondition.failed")
    status, context, _ = h.http(
        casework,
        task_path + "/context",
        h.tokens["staff"],
        "staff",
        headers={"Registry-Source-Profile": "reviewer"},
    )
    h.check(
        "reviewer-current-source-context",
        status == 200
        and context["context"]["projection"]["display"]["currentStatus"] == "retired"
        and context["context"]["projection"]["display"]["proposedStatus"] == "active",
    )
    status, claimed, _ = h.http(
        casework,
        task_path + "/claim",
        h.tokens["staff"],
        "staff",
        None,
        "POST",
        {
            "If-Match": '"' + str(task["revision"]) + '"',
            "Idempotency-Key": "claim",
            "Registry-Source-Profile": "reviewer",
        },
    )
    h.check("independent-human-claimed", status == 200)
    observed, claimed, answer_text, file_bytes = ask_and_answer(
        h, source, casework, source_call, task_path, claimed, submitted, accepted, correlation
    )
    status, _, _ = h.http(
        casework,
        task_path + "/decisions",
        h.tokens["staff"],
        "staff",
        {"decision": {"type": "approve", "outcome": "approved"}},
        "POST",
        {
            "If-Match": '"' + str(claimed["revision"]) + '"',
            "Idempotency-Key": "approve",
            "Registry-Source-Profile": "reviewer",
        },
    )
    h.check("human-decision-recorded", status == 204)
    status, decided, _ = h.http(
        casework, task_path, h.tokens["staff"], "staff", headers={"Registry-Source-Profile": "reviewer"}
    )
    h.check(
        "the-task-that-asked-is-the-task-that-decided", status == 200 and decided["taskId"] == task["taskId"]
    )
    observed["decidedTask"] = decided
    status, correlation, _ = source_call(proposal_path + "/review-status", "context-status", "review-status")
    h.check("decision-keeps-the-accepted-request", status == 200)
    observed["correlations"].append(correlation)
    with h.observation_lock:
        observed["requests"] = list(h.casework_requests)
        observed["createdRequestIds"] = sorted(h.created_request_ids)
    write(h.output / "ask-loop.json", check_ask_loop(observed, answer_text, file_bytes))
    h.check("one-request-one-task-ask-answer-decision-and-no-applicant-token-in-casework", True)
    status, result, _ = h.http(
        casework, "/v1/review-requests/" + task["requestId"] + "/result", h.tokens["producer"], "requester"
    )
    assert status == 200, "review result unavailable"
    check_correlation(submitted, accepted, result)
    write(h.output / "correlated-result.json", result)
    h.check("exact-result-correlated", True)
    deadline = time.monotonic() + 90
    while True:
        status, current, etag = source_call(proposal_path, "applier", "applier")
        if current.get("decision", {}).get("status") == "approved":
            break
        if time.monotonic() > deadline:
            raise RuntimeError("source did not retain correlated review approval")
        time.sleep(0.25)
    status, before, _ = source_call("/v1/records/records/" + record_id)
    h.check(
        "approval-does-not-apply-source",
        status == 200 and before["data"]["domainData"]["status"] == "retired",
    )
    for role in ("staff", "source", "producer"):
        status, _, _ = source_call(
            proposal_path + "/apply",
            role,
            "applier",
            apply_body,
            "POST",
            {"If-Match": etag["etag"], "Idempotency-Key": "denied-" + role},
        )
        h.check(role + "-has-no-source-apply-authority", status in (403, 404))
    status, applied, _ = source_call(
        proposal_path + "/apply",
        "applier",
        "applier",
        apply_body,
        "POST",
        {"If-Match": etag["etag"], "Idempotency-Key": "independent-apply"},
    )
    h.check("independently-authorized-source-apply", status == 200 and applied["state"] == "applied")
    status, after, _ = source_call("/v1/records/records/" + record_id)
    h.check(
        "exact-source-correction-committed",
        status == 200 and after["data"]["domainData"]["status"] == "active",
    )
    write(
        h.output / "applied-submission.json",
        {key: applied[key] for key in ("id", "actionId", "submissionVersion", "revision", "state", "status")},
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument(
        "--output", type=Path, required=True, help="New owner-only output directory on the scratch volume"
    )
    parser.add_argument(
        "--runtime-source-revision",
        help="Operator-recorded source revision of these exact binaries; binary hashes are always recorded",
    )
    args = parser.parse_args()
    if args.runtime_source_revision:
        assert len(args.runtime_source_revision) == 40 and all(
            c in "0123456789abcdef" for c in args.runtime_source_revision
        ), "runtime source revision must be a full lowercase Git commit"
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    binaries = {
        name: (args.bin_dir / name).resolve()
        for name in ("bregctl", "breg", "caseworkctl", "casework", "evidencectl", "evidence")
    }
    assert all(path.is_file() and os.access(path, os.X_OK) for path in binaries.values()), (
        "build all six product binaries first"
    )
    h = JourneyHarness(output, binaries)
    versions = {
        name: h.run("version-" + name, [binary, "--version"]).strip() for name, binary in binaries.items()
    }
    h.check("matching-product-versions", len({value.split(" ", 1)[-1] for value in versions.values()}) == 1)
    write(
        output / "inputs.json",
        {
            "runtimeBinaries": hashes(binaries.values()),
            "runtimeVersions": versions,
            "runtimeSourceRevision": args.runtime_source_revision,
            "harnessCheckoutRevision": subprocess.run(
                ["git", "--no-optional-locks", "-C", str(ROOT), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip(),
            "authoredInputs": hashes(
                path
                for path in INPUTS.rglob("*")
                if path.is_file()
                and not any(
                    part.startswith(".") or part == "__pycache__" for part in path.relative_to(INPUTS).parts
                )
            ),
            "syntheticOnly": True,
        },
    )
    success = False
    try:
        h.database()
        h.identity()
        h.receive_hooks()
        source, casework_origin, evidence = [f"http://127.0.0.1:{port()}" for _ in range(3)]
        casework = h.observe_casework(casework_origin)
        source_project, source_package, source_runtime = activate_source(h, source, casework)
        policy = activate_casework(h, source_package, source, casework_origin)
        h.start("breg", [h.binaries["breg"], "--runtime-config", source_runtime], source)
        evidence_project, client = activate_evidence(h, source_project, source, evidence)
        record_id = seed_record(h, source)
        before = consume(h, evidence_project, client, "before", False)
        reviewed_correction(h, source, casework, policy, record_id)
        after = consume(h, evidence_project, client, "after", True)
        check_observations(
            json.loads((before / "verified.json").read_text()),
            json.loads((after / "verified.json").read_text()),
        )
        h.check("same-subject-contract-observation-pair", True)
        request = json.loads((after / "request.json").read_text())
        status, _, _ = h.http(
            evidence,
            "/v1/evidence",
            h.tokens["ungranted"],
            body=request,
            method="POST",
            headers={"Accept": "application/jose+json"},
        )
        h.check("ungranted-caller-refused", status == 403)
        signed = json.loads((after / "response.json").read_text())
        signed["signature"] = ("A" if signed["signature"][0] != "A" else "B") + signed["signature"][1:]
        write(after / "tampered.json", signed)
        h.run(
            "tampered-signature-refused",
            [
                binaries["evidencectl"],
                "verify",
                after / "tampered.json",
                "--context",
                after / "verification.json",
                "--output",
                after / "must-not-exist.json",
            ],
            refused=True,
        )
        h.check(
            "tampered-signature-releases-no-verified-output", not (after / "must-not-exist.json").exists()
        )
        success = True
    finally:
        cleanup = h.cleanup()
        check_cleanup(cleanup)
        write(
            output / "result.json",
            {
                "passed": success,
                "journeyChecksPassed": len(h.checks),
                "journeyChecksFailed": 0 if success else 1,
                "fixtureCases": getattr(h, "fixture_cases", 0) if "evidence-fixture-cases" in h.checks else 0,
                "skipped": 0,
                "cleanup": cleanup,
            },
        )
    print(
        f"PASS: {len(h.checks)} journey checks; {h.fixture_cases} synthetic fixture cases; cleanup verified. Owner-only evidence: {output}"
    )


if __name__ == "__main__":
    main()
