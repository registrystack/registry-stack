#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native after-commit BReg events enter the same durable Coordinator Run machine.

Uses already-built breg, bregctl, coordinator and coordinatorctl executables.
COORDINATOR_TEST_DATABASE_URL must name an owned disposable loopback database.
All registry, issuer, roles, schemas and containers created here are fixture-owned.
"""
import argparse
import datetime as dt
import http.server
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

SCRIPTS = Path(__file__).resolve().parent
REPO = SCRIPTS.parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


native = module("coordinator_native_event_fixture", SCRIPTS / "test-real-services.py")
receiver = module("breg_existing_signature_fixture", REPO / "products/breg/examples/webhook-receiver/receiver.py")


def request(method, url, body=None, token=None, headers=None, expected=(200,)):
    fields = dict(headers or {})
    if token:
        fields["Authorization"] = "Bearer " + token
    raw = body
    if body is not None and not isinstance(body, bytes):
        raw = json.dumps(body, separators=(",", ":")).encode()
        fields.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=raw, headers=fields, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = response.read(65_537)
        assert len(data) <= 65_536
        assert response.status in expected, f"{method} {urllib.parse.urlsplit(url).path}: HTTP {response.status}"
        return response.status, dict(response.headers.items()), json.loads(data) if data else None


class DeliveryProxy:
    """Forward exact wire bytes; deliberately lose one accepted response."""
    def __init__(self, target):
        self.target = target
        self.deliveries = []
        self.lost = False
        self.lock = threading.Lock()
        proxy = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 65_536:
                    self.send_error(413)
                    return
                body = self.rfile.read(length)
                headers = {name.lower(): value for name, value in self.headers.items()
                           if name.lower() not in {"host", "content-length", "connection"}}
                try:
                    status, result, _ = request("POST", proxy.target + self.path, body=body,
                                                headers=headers, expected=(204, 400, 401, 409, 503))
                except (OSError, urllib.error.URLError):
                    status, result = 503, {}
                run = next((value for name, value in result.items() if name.lower() == "x-coordinator-run-id"), None)
                with proxy.lock:
                    proxy.deliveries.append({"headers": headers, "body": body, "run": run, "status": status, "path": self.path})
                    if status == 204 and not proxy.lost:
                        proxy.lost = True
                        status = 503
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def matching(self, event_type):
        with self.lock:
            return [dict(delivery) for delivery in self.deliveries
                    if delivery["headers"].get("ce-type") == event_type and delivery["status"] == 204]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class EventJourney(native.Journey):
    def runtime(self, keys, connections):
        result = super().runtime(keys, connections)
        result["eventSources"] = self.event_sources
        return result


def write_source(journey, key_root, proxy_url, paths):
    owner = native.write_breg(journey.root / "breg", journey.urls)
    project = json.loads((owner / "registry.yaml").read_text())
    record = project["recordTypes"][0]
    record.pop("mutationPolicy", None)
    record["hooks"] = [{"id": "application-" + trigger + "-v1", "phase": "after", "trigger": trigger,
                        "projection": ["tenant"], "handler": {"type": "url", "destinationId": trigger}}
                       for trigger in ("created", "patched")]
    seed = next(profile for profile in project["accessProfiles"] if profile["id"] == "seeder")
    seed["permissions"]["records"][0]["operations"].append("patch")
    project["actions"].append({
        "id": "update-email", "execution": {"mode": "immediate"},
        "inputs": [{"id": "application", "apiName": "applicationId", "type": "reference", "target": "application",
                    "required": True, "classification": "internal"},
                   {"id": "email", "type": "string", "required": True, "minimumLength": 1, "maximumLength": 254,
                    "classification": "internal"}],
        "plan": {"type": "fixed", "effects": [{"id": "application", "target": {"fromInput": "application"},
                                                   "operation": "patch", "set": {"email": {"fromInput": "email"}}}]},
    })
    seed["permissions"]["actions"].append({"action": "update-email", "operations": ["invoke"],
        "targets": [{"recordType": "application", "rowBoundaries": native.BOUNDARY if hasattr(native, "BOUNDARY")
                     else [{"field": "tenant", "claim": "tenant_claim", "operator": "equals"}]}], "results": ["application"]})
    native.private(owner / "registry.yaml", project)
    clients = json.loads((owner / "dev-clients.yaml").read_text())
    clients["secretProviders"] = {"file": {"root": str(key_root)}}
    clients["eventDestinations"] = {trigger: {"origin": proxy_url, "path": paths[trigger],
        "hmacSha256KeyRef": "secret:file/event-key"} for trigger in ("created", "patched")}
    native.private(owner / "dev-clients.yaml", clients)
    return owner


def write_workflow(journey, owner, sample, data_schemas):
    project = journey.root / "event-follow-up"
    project.mkdir(mode=0o700)
    input_schema = {"type": "object", "additionalProperties": False, "required": ["recordId"],
                    "properties": {"recordId": {"type": "string", "format": "uuid"}}}
    workflow = {
        "apiVersion": "id.registrystack.org/formats/coordinator/project/v1alpha1", "kind": "CoordinatorProject",
        "project": {"id": "event-follow-up", "version": "1"},
        "operations": {"read-current": {"uses": "breg.read-record/v1", "connection": "source"}},
        "workflow": {"input": input_schema, "deadlineSeconds": 3600, "start": "read-current",
            "eventTriggers": {trigger: {"source": "registry", "eventType": item["headers"]["ce-type"],
                "dataSchema": item["headers"]["ce-dataschema"],
                "event": {"type": "object", "required": ["data"], "properties": {"data": data_schemas[trigger]}},
                "input": {"type": "fields", "fields": {"recordId": {"type": "input", "path": "/data/recordId"}}}}
                for trigger, item in sample.items()},
            "steps": {
                "read-current": {"type": "call", "operation": "read-current", "input": {"type": "fields", "fields": {
                    "collection": {"type": "literal", "value": "applications"}, "recordId": {"type": "input", "path": "/recordId"}}}, "next": "observed"},
                "observed": {"type": "finish", "outcome": "current-record-observed", "output": {"type": "fields", "fields": {
                    "recordId": {"type": "step", "step": "read-current", "path": "/data/recordIdentifier"}}}}},
            "outcomes": {"current-record-observed": input_schema}},
    }
    native.private(project / "workflow.yaml", workflow)
    return project


def write_alternate_workflow(journey):
    """A conforming synthetic Scheduling projection, without a Scheduling runtime claim."""
    project = journey.root / "alternate-event-observer"
    project.mkdir(mode=0o700)
    schema = {"type": "object", "additionalProperties": False, "required": ["appointmentId"],
              "properties": {"appointmentId": {"type": "string", "format": "uuid"}}}
    native.private(project / "workflow.yaml", {
        "apiVersion": "id.registrystack.org/formats/coordinator/project/v1alpha1", "kind": "CoordinatorProject",
        "project": {"id": "scheduling-event-observer", "version": "1"},
        "workflow": {"input": schema, "deadlineSeconds": 3600, "start": "observed",
            "eventTriggers": {"confirmed": {"source": "appointments", "eventType": "appointment-confirmed-v1",
                "dataSchema": "urn:example:appointment-confirmed:v1",
                "event": {"type": "object", "required": ["data"], "properties": {"data": {
                    "type": "object", "additionalProperties": False, "required": ["appointmentId", "state"],
                    "properties": {"appointmentId": {"type": "string", "format": "uuid"}, "state": {"const": "confirmed"}}}}},
                "input": {"type": "fields", "fields": {"appointmentId": {"type": "input", "path": "/data/appointmentId"}}}}},
            "steps": {"observed": {"type": "finish", "outcome": "event-observed", "output": {"type": "input"}}},
            "outcomes": {"event-observed": schema}},
    })
    return project


def alternate_delivery(key):
    event_id, appointment_id = str(uuid.uuid4()), str(uuid.uuid4())
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    value = {"id": event_id, "type": "appointment-confirmed-v1", "source": "urn:registrystack:scheduling:synthetic:local",
             "time": now, "subject": {"recordReference": "/v1/appointments/" + appointment_id, "recordRevision": 1},
             "dataschema": "urn:example:appointment-confirmed:v1", "data": {"appointmentId": appointment_id, "state": "confirmed"},
             "causation": {"root": event_id, "hop": 0}}
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    headers = {"ce-specversion": "1.0", "content-type": "application/json", "accept": "application/json",
               "ce-id": event_id, "ce-source": value["source"], "ce-type": value["type"], "ce-time": now,
               "ce-dataschema": value["dataschema"], "x-registry-event-generation": "1", "x-registry-delivery-attempt": "1",
               "x-registry-delivery-time": now, "idempotency-key": "sha256:" + uuid.uuid4().hex + uuid.uuid4().hex}
    path = "/v1/events/scheduling-event-observer/confirmed"
    headers["x-registry-signature"] = receiver._expected_webhook_signature(key, headers, body, path)
    return {"headers": headers, "body": body, "path": path}


def wait_for(action, description, timeout=30):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        result = action()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError(description)


def replay(key, delivery, url, *, invalid_signature=False):
    headers = dict(delivery["headers"])
    headers["x-registry-event-generation"] = "2"
    headers["x-registry-delivery-attempt"] = "1"
    headers["x-registry-delivery-time"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    headers["idempotency-key"] = "sha256:" + uuid.uuid4().hex + uuid.uuid4().hex
    headers["x-registry-signature"] = receiver._expected_webhook_signature(key, headers, delivery["body"], delivery["path"])
    if invalid_signature:
        headers["x-registry-signature"] = "v1=" + "A" * 43
    return request("POST", url + delivery["path"], body=delivery["body"], headers=headers,
                   expected=(401,) if invalid_signature else (204,))


def cleanup_coordinator(journey):
    runtime_path = journey.root / "coordinator-event-follow-up-runtime.yaml"
    if not runtime_path.exists():
        return
    runtime = json.loads(runtime_path.read_text())
    namespace, role = runtime["namespace"], runtime["deployment"]["runtimeRole"]
    assert re.fullmatch(r"coordinator_[0-9a-f]{32}", namespace), "refuse non-fixture schema cleanup"
    assert re.fullmatch(r"coordinator_native_[0-9a-f]{16}", role), "refuse non-fixture role cleanup"
    result = subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1"],
        input=f"DROP SCHEMA IF EXISTS {namespace} CASCADE; DROP ROLE IF EXISTS {role};\n".encode(),
        env=native.database_environment(os.environ["COORDINATOR_TEST_DATABASE_URL"], journey.env),
        capture_output=True, timeout=15)
    native.private(journey.root / "coordinator-cleanup.log", result.stdout + result.stderr)
    assert result.returncode == 0, "owned Coordinator cleanup failed; inspect private cleanup log"


def run(args):
    database = os.environ.get("COORDINATOR_TEST_DATABASE_URL", "")
    parsed = urllib.parse.urlsplit(database)
    if parsed.scheme not in {"postgres", "postgresql"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("COORDINATOR_TEST_DATABASE_URL must name an owned disposable loopback PostgreSQL database")
    root = args.output.resolve()
    root.mkdir(mode=0o700)
    os.umask(0o077)
    journey = EventJourney(root, args.bin_dir.resolve(), 1,
                           build_manifest=args.build_manifest.resolve() if args.build_manifest else None,
                           required_binaries=["breg", "bregctl", "coordinator", "coordinatorctl"],
                           require_reviewed_notice_starter=False)
    succeeded = False
    try:
        coordinator_port = native.free_ports(1)[0]
        coordinator_url = f"http://127.0.0.1:{coordinator_port}"
        proxy = DeliveryProxy(coordinator_url)
        journey.proxies.append(proxy)
        keys = root / "coordinator-secrets"
        keys.mkdir(mode=0o700)
        key = secrets.token_bytes(32)
        native.private(keys / "event-key", key)
        paths = {trigger: f"/v1/events/event-follow-up/{trigger}" for trigger in ("created", "patched")}
        owner = write_source(journey, keys, proxy.url, paths)
        journey.ctl("bregctl", "check", owner)
        sample = {trigger: journey.ctl("bregctl", "webhook", "sample", owner, "--event", "application-" + trigger + "-v1")["request"]
                  for trigger in ("created", "patched")}
        schemas = root / "producer-schemas"
        journey.ctl("bregctl", "generate", "schemas", owner, "--output", schemas)
        data_schemas = {trigger: json.loads((schemas / f"generated/event-schemas/application.application-{trigger}-v1.schema.json").read_text())
                        for trigger in ("created", "patched")}
        journey.sessions.append(("bregctl", owner))
        report = journey.ctl("bregctl", "dev", "start", owner, "--breg-port", journey.ports["breg"],
            "--issuer-port", journey.ports["issuer"], "--database-port", journey.ports["bregdb"], "--breg-bin", journey.bin / "breg")
        state = json.loads(Path(report["stateFile"]).read_text())
        source = f"urn:registrystack:registry:{native.SOURCE}:instance:{state['instanceId']}"
        journey.event_sources = {"registry": {"source": source, "signingKeyRef": "secret:file/event-key"},
            "appointments": {"source": "urn:registrystack:scheduling:synthetic:local", "signingKeyRef": "secret:file/event-key"}}
        project = write_workflow(journey, owner, sample, data_schemas)
        alternate = write_alternate_workflow(journey)
        reader = journey.export(owner, "application-reader", keys)
        runtime, coordinator_url, child = journey.coordinator_service("event-follow-up", keys,
            {"source": {"type": "breg", "baseUrl": journey.urls["breg"], "profile": "follow-up-reader",
                "authorization": journey.authorization(reader, report["resource"], ["records:get"])}},
            coordinator_port, "coordinator-event-intake", primary_project=project,
            additional_projects=(("scheduling-event-observer", alternate),))
        seed = journey.token("bregctl", owner, "seed-client")
        body = {"data": {"tenant": "tenant-a", "applicantName": "Synthetic event applicant", "benefitProgram": "pilot",
                          "requestedAmount": 1, "email": "synthetic@example.invalid", "noticeAllowed": False, "appointmentAllowed": False}}
        _, created_headers, created = request("POST", journey.urls["breg"] + "/v1/records/applications?accessProfile=seeder",
            body, seed, {"Idempotency-Key": str(uuid.uuid4())}, (201,))
        record_id = created["data"]["recordIdentifier"]
        deliveries = wait_for(lambda: proxy.matching("application-created-v1") if len(proxy.matching("application-created-v1")) >= 2 else None,
                              "BReg did not retry the deliberately lost accepted response")
        assert len({delivery["run"] for delivery in deliveries}) == 1
        created_run = deliveries[0]["run"]
        result, _ = journey.drive(owner, coordinator_url, created_run)
        assert result["run"]["outcome"] == "current-record-observed"
        # Rejected source mutation cannot capture an event or start another Run.
        before = len(proxy.deliveries)
        request("POST", journey.urls["breg"] + "/v1/records/applications?accessProfile=seeder",
                {"data": {"tenant": "tenant-a"}}, seed, {"Idempotency-Key": str(uuid.uuid4())}, (400, 422))
        time.sleep(0.3)
        assert len(proxy.deliveries) == before
        # The same event transport receives direct PATCH and Action effects.
        etag = next(value for name, value in created_headers.items() if name.lower() == "etag")
        request("PATCH", journey.urls["breg"] + f"/v1/records/applications/{record_id}?accessProfile=seeder",
                [{"op": "replace", "path": "/data/email", "value": "patched@example.invalid"}], seed,
                {"Idempotency-Key": str(uuid.uuid4()), "If-Match": etag, "Content-Type": "application/json-patch+json"}, (200,))
        patched = wait_for(lambda: proxy.matching("application-patched-v1"), "direct PATCH event was not accepted")
        result, _ = journey.drive(owner, coordinator_url, patched[0]["run"])
        assert result["run"]["outcome"] == "current-record-observed"
        _, _, conditions = request("POST", journey.urls["breg"] + "/v1/actions/update-email/target-conditions?accessProfile=seeder",
                {"input": {"applicationId": record_id}}, seed, expected=(200,))
        request("POST", journey.urls["breg"] + "/v1/actions/update-email?accessProfile=seeder",
                {"input": {"applicationId": record_id, "email": "action@example.invalid"},
                 "preconditions": conditions["preconditions"]}, seed,
                {"Idempotency-Key": str(uuid.uuid4())}, (200,))
        patched = wait_for(lambda: proxy.matching("application-patched-v1") if len(proxy.matching("application-patched-v1")) >= 2 else None,
                           "committed Action effect did not capture the record event")
        action_run = patched[-1]["run"]
        assert action_run != patched[0]["run"]
        result, _ = journey.drive(owner, coordinator_url, action_run)
        assert result["run"]["outcome"] == "current-record-observed"
        journey.stop(child)
        child = journey.spawn("coordinator", runtime, "coordinator-event-restarted")
        journey.ready(child, coordinator_url)
        _, headers, _ = replay(key, deliveries[0], coordinator_url)
        assert next(value for name, value in headers.items() if name.lower() == "x-coordinator-run-id") == created_run
        replay(key, deliveries[0], coordinator_url, invalid_signature=True)
        alternate = alternate_delivery(key)
        _, alternate_headers, _ = request("POST", coordinator_url + alternate["path"], body=alternate["body"],
                                           headers=alternate["headers"], expected=(204,))
        alternate_run = next(value for name, value in alternate_headers.items() if name.lower() == "x-coordinator-run-id")
        result, _ = journey.drive(owner, coordinator_url, alternate_run)
        assert result["run"]["outcome"] == "event-observed"
        _, repeated, _ = replay(key, alternate, coordinator_url)
        assert next(value for name, value in repeated.items() if name.lower() == "x-coordinator-run-id") == alternate_run
        source_events = {delivery["headers"]["ce-id"] for delivery in proxy.deliveries
                         if delivery["status"] == 204 and delivery["headers"]["ce-source"] == source}
        assert len(source_events) == 3, "exactly three committed BReg events were authenticated and accepted"
        previous_ca = journey.env.get("SSL_CERT_FILE")
        try:
            journey.env["SSL_CERT_FILE"] = str(owner / ".breg/dev/tls/ca.pem")
            wait_for(lambda: not journey.ctl("bregctl", "webhook", "list", "--runtime-config", report["runtimeConfig"])["deliveries"],
                     "the producer delivery queue did not drain")
        finally:
            if previous_ca is None:
                journey.env.pop("SSL_CERT_FILE", None)
            else:
                journey.env["SSL_CERT_FILE"] = previous_ca
        runs = journey.producer_request(owner, "GET", coordinator_url + "/v1/runs")
        assert len(runs["runs"]) == 4, "duplicate, replay and refused source/event must not create extra Runs"
        value_free = {"ok": True, "createdRun": created_run, "directPatchRun": patched[0]["run"], "actionPatchRun": action_run,
            "acceptedRuns": 4, "alternateConformingSourceAccepted": True, "lostAcknowledgmentRecovered": True, "restartReplayDeduplicated": True,
            "invalidSignatureRefused": True, "rejectedSourceWriteCapturedNoEvent": True,
            "sourceSchemaOwner": "bregctl generate schemas", "independentEffectAuthority": "BReg follow-up-reader"}
        value_free["binarySha256"] = journey.binary_digests
        value_free["cleanupStatus"] = "pending"
        native.private(root / "result.json", value_free)
        succeeded = True
    finally:
        journey.cleanup(succeeded)
        cleanup_coordinator(journey)
    value_free["cleanupStatus"] = "complete"
    native.private(root / "result.json", value_free)
    print(json.dumps(value_free, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True, help="already-built executable directory")
    parser.add_argument("--output", type=Path, required=True, help="new private disposable evidence directory")
    parser.add_argument("--build-manifest", type=Path, help="matching frozen binary and runtime-library provenance")
    run(parser.parse_args())
