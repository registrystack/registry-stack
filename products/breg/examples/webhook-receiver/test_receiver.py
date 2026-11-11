import http.client
import http.server
import json
import sqlite3
import sys
import tempfile
import threading
import types
import unittest
import urllib.error
import urllib.request
import uuid
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
BINDING_TESTS = HERE.parents[3] / "crates/registry-breg-client-py/tests/python"


# Build the in-tree binding and serve it as `registry_client.breg`, the import
# path an installed registry-stack-client package provides.
sys.path.insert(0, str(BINDING_TESTS))
try:
    from bootstrap import ensure_built
finally:
    sys.path.remove(str(BINDING_TESTS))
ensure_built()
import registry_breg_client  # noqa: E402

REGISTRY_CLIENT = types.ModuleType("registry_client")
REGISTRY_CLIENT.breg = registry_breg_client
sys.modules["registry_client"] = REGISTRY_CLIENT
sys.modules["registry_client.breg"] = registry_breg_client
sys.path.insert(0, str(HERE))
try:
    import receiver as RECEIVER
    import refresh_hints as REFRESH
    import sign_delivery as SIGNER
finally:
    sys.path.remove(str(HERE))


def signed_event(key, contract, values, event_id=None, generation=1, attempt=1, delivery_key=None):
    event_id = event_id or str(uuid.uuid4())
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    source = f"urn:registrystack:registry:{contract['registry_id']}:instance:{contract['instance_id']}"
    schema = (
        f"urn:breg:event-schema:{contract['registry_id']}:{contract['record_type']}:"
        f"{contract['event_id']}:sha256:" + "a" * 64
    )
    document = {
        "id": event_id, "type": contract["event_id"], "source": source,
        "time": now, "dataschema": schema,
        "subject": {"recordReference": "hmac-sha256:" + "d" * 64, "recordRevision": 1},
        "causation": {"root": event_id, "hop": 0},
        "data": {"recordType": contract["record_type"], "recordId": str(uuid.uuid4()),
                 "revision": 1, "trigger": contract.get("trigger", "created"),
                 "packageRevision": "sha256:" + "b" * 64, "values": values},
    }
    body = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    headers = {
        "accept": "application/json", "content-type": "application/json",
        "ce-specversion": "1.0", "ce-id": event_id, "ce-source": source,
        "ce-type": document["type"], "ce-time": now, "ce-dataschema": schema,
        "x-registry-event-generation": str(generation),
        "x-registry-delivery-attempt": str(attempt), "x-registry-delivery-time": now,
        "idempotency-key": delivery_key or "sha256:" + uuid.uuid4().hex * 2,
    }
    headers["x-registry-signature"] = SIGNER.webhook_signature(key, headers, body)
    return headers, body


def post_event(server, headers, body):
    request = urllib.request.Request(
        f"http://127.0.0.1:{server.server_port}/events", body, headers
    )
    try:
        response = urllib.request.urlopen(request, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read()


class WebhookAcceptanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.inbox_path = Path(temporary.name) / "inbox.sqlite3"
        self.key = b"receiver-test-key-material-32-bytes"
        self.contract = {"registry_id": "example-registry", "instance_id": "local",
                         "record_type": "contact", "event_id": "contact-created-v1",
                         "event_values": ["name"]}
        self.start()

    def start(self):
        self.server = RECEIVER.make_server(
            0, self.key, self.contract, RECEIVER.WebhookInbox(self.inbox_path)
        )
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        if self.thread.is_alive():
            self.server.shutdown()
            self.thread.join()
            self.server.server_close()

    def event(self, event_id=None, generation=1, attempt=1, delivery_key=None, name="Contact"):
        return signed_event(
            self.key, self.contract, {"name": name}, event_id, generation, attempt, delivery_key
        )

    def sign(self, headers, body):
        headers["x-registry-signature"] = SIGNER.webhook_signature(self.key, headers, body)

    def post(self, headers, body):
        return post_event(self.server, headers, body)[0]

    def post_pairs(self, headers, body):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.putrequest("POST", "/events")
            connection.putheader("Content-Length", str(len(body)))
            for name, value in headers:
                connection.putheader(name, value)
            connection.endheaders(body)
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def counts(self):
        with sqlite3.connect(self.inbox_path) as connection:
            return tuple(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                         for table in ("accepted_events", "accepted_deliveries"))

    def test_acceptance_survives_restart_and_replay_without_duplicate_work(self):
        headers, body = self.event(name="Jérémie")
        self.assertEqual(self.post(headers, body), 204)
        self.assertEqual(self.counts(), (1, 1))
        self.stop()
        self.start()
        headers["x-registry-delivery-attempt"] = "2"
        self.sign(headers, body)
        self.assertEqual(self.post(headers, body), 204)
        headers["x-registry-event-generation"] = "2"
        headers["idempotency-key"] = "sha256:" + "c" * 64
        self.sign(headers, body)
        self.assertEqual(self.post(headers, body), 204)
        self.assertEqual(self.counts(), (1, 2))

    def test_conflicting_duplicate_and_rebound_delivery_are_refused(self):
        headers, body = self.event()
        self.assertEqual(self.post(headers, body), 204)
        changed = json.loads(body)
        changed["data"]["values"]["name"] = "Changed"
        changed_body = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode()
        self.sign(headers, changed_body)
        self.assertEqual(self.post(headers, changed_body), 409)
        other_headers, other_body = self.event(delivery_key=headers["idempotency-key"])
        self.assertEqual(self.post(other_headers, other_body), 409)
        self.assertEqual(self.counts(), (1, 1))

    def test_authentication_source_and_delivery_time_are_verified_before_acceptance(self):
        for mutation in ("signature", "key", "body", "source", "time"):
            with self.subTest(mutation=mutation):
                headers, body = self.event()
                if mutation == "signature":
                    headers["x-registry-signature"] = "v1=invalid"
                elif mutation == "key":
                    headers["x-registry-signature"] = SIGNER.webhook_signature(
                        b"another-receiver-key-material-32b", headers, body
                    )
                elif mutation == "body":
                    body = body.replace(b'"Contact"', b'"Tampered"')
                elif mutation == "source":
                    headers["ce-source"] = "urn:other"
                    self.sign(headers, body)
                else:
                    headers["x-registry-delivery-time"] = "2000-01-01T00:00:00Z"
                    self.sign(headers, body)
                self.assertEqual(self.post(headers, body), 400)
        self.assertEqual(self.counts(), (0, 0))

    def test_exact_and_cased_duplicate_headers_reach_the_shared_verifier(self):
        for name, value in (
            ("ce-type", "withheld-exact-duplicate"),
            ("CE-TYPE", "withheld-cased-duplicate"),
        ):
            with self.subTest(name=name):
                headers, body = self.event()
                self.assertEqual(
                    self.post_pairs([*headers.items(), (name, value)], body),
                    400,
                )
        self.assertEqual(self.counts(), (0, 0))

    def test_storage_failure_refuses_acknowledgement_then_recovers(self):
        headers, body = self.event()
        with patch.object(self.server.webhook_acceptance, "accept", side_effect=sqlite3.OperationalError):
            self.assertEqual(self.post(headers, body), 503)
        self.assertEqual(self.counts(), (0, 0))
        self.assertEqual(self.post(headers, body), 204)
        self.assertEqual(self.counts(), (1, 1))

    def test_inbox_refuses_non_private_file_and_symlink(self):
        self.inbox_path.chmod(0o644)
        with self.assertRaises(RECEIVER.ReceiverError):
            RECEIVER.WebhookInbox(self.inbox_path)
        link = self.inbox_path.with_name("link.sqlite3")
        link.symlink_to(self.inbox_path)
        with self.assertRaises(RECEIVER.ReceiverError):
            RECEIVER.WebhookInbox(link)


class RefreshHintTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.token_file = Path(temporary.name) / "notifier-token"
        self.token_file.touch(mode=0o600)
        self.token_file.write_text("notifier-token-canary\n", encoding="ascii")
        self.key = b"receiver-test-key-material-32-bytes"
        self.id_key = b"notifier-test-hint-identity-key-material"
        self.attempts = []
        self.accepted = {}
        self.responses = []
        test = self

        class Destination(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                test.attempts.append((self.path, self.headers["Authorization"], request))
                result = test.responses.pop(0) if test.responses else 202
                if result in (202, None):
                    test.accepted.setdefault(request["hintId"], request)
                if result is None:
                    return  # Lose the response after recording admission.
                self.send_response(result)
                self.end_headers()
                self.wfile.write(b"destination-diagnostic-canary")

        self.destination = self.start(http.server.HTTPServer(("127.0.0.1", 0), Destination))

    def start(self, server):
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()

        def stop():
            server.shutdown()
            thread.join()
            server.server_close()

        self.addCleanup(stop)
        return server

    def configure(self, record_type, event_id, fields):
        self.contract = {
            "registry_id": "example-registry", "instance_id": "local", "record_type": record_type,
            "event_id": event_id, "trigger": "patched", "event_values": fields,
            "data_schema": (
                f"urn:breg:event-schema:example-registry:{record_type}:{event_id}:sha256:" + "a" * 64
            ),
        }
        self.sink = REFRESH.RefreshHints(
            origin=f"http://127.0.0.1:{self.destination.server_port}",
            plan="licensing-holders", projection="authority-indexed", scheme="urn:example:authority-key",
            fields=fields, token_file=self.token_file, id_key=self.id_key,
        )
        self.server = self.start(RECEIVER.make_server(0, self.key, self.contract, self.sink))

    def post(self, headers, body):
        return post_event(self.server, headers, body)

    def resign(self, headers, body):
        headers["x-registry-signature"] = SIGNER.webhook_signature(self.key, headers, body)

    def test_person_correction_sends_only_the_approved_selector(self):
        self.configure("person", "person-corrected-v1", ["person-key"])
        selector = "approved-person-selector-canary"
        headers, body = signed_event(self.key, self.contract, {"person-key": selector})
        self.assertEqual(self.post(headers, body), (204, b""))
        path, authorization, hint = self.attempts[0]
        self.assertEqual(path, "/v1/external-refresh-plans/licensing-holders/hints")
        self.assertEqual(authorization, "Bearer notifier-token-canary")
        self.assertRegex(hint["hintId"], r"^[0-9a-f]{64}$")
        self.assertEqual(hint, {
            "hintId": hint["hintId"], "projection": "authority-indexed",
            "selectorScheme": "urn:example:authority-key", "selector": selector,
        })

    def test_invalid_signature_schema_and_unapproved_fields_make_no_request(self):
        self.configure("person", "person-corrected-v1", ["person-key"])
        fields = {"person-key": "approved-person-selector-canary"}
        headers, body = signed_event(self.key, self.contract, fields)
        self.assertEqual(self.post(headers, body.replace(b"approved-person", b"changed-person")), (400, b""))
        changed = json.loads(body)
        changed["dataschema"] = headers["ce-dataschema"] = headers["ce-dataschema"][:-1] + "b"
        body = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode()
        self.resign(headers, body)
        self.assertEqual(self.post(headers, body), (400, b""))
        headers, body = signed_event(
            self.key, self.contract, {**fields, "family-name": "unapproved-family-name-canary"}
        )
        self.assertEqual(self.post(headers, body), (400, b""))
        self.assertEqual(self.attempts, [])

    def test_two_parent_move_retries_partial_admission_and_lost_response(self):
        fields = ["previous-parent", "current-parent"]
        self.configure("holding", "holding-moved-v1", fields)
        previous, current = "previous-parent-canary", "current-parent-canary"
        headers, body = signed_event(self.key, self.contract, dict(zip(fields, [previous, current])))
        self.responses.extend([202, 429, 202, None])
        output = StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            self.assertEqual(self.post(headers, body), (503, b""))
            self.assertEqual(len(self.accepted), 1)
            headers["x-registry-delivery-attempt"] = "2"
            self.resign(headers, body)
            self.assertEqual(self.post(headers, body), (503, b""))
            self.assertEqual(len(self.accepted), 2)
            headers["x-registry-event-generation"] = "2"
            headers["idempotency-key"] = "sha256:" + "c" * 64
            self.resign(headers, body)
            self.assertEqual(self.post(headers, body), (204, b""))
        hints = [attempt[2] for attempt in self.attempts]
        self.assertEqual([hint["selector"] for hint in hints], [previous, current] * 3)
        self.assertEqual(hints, hints[:2] * 3)
        self.assertEqual(len(self.accepted), 2)
        self.assertEqual(output.getvalue(), "")

    def test_all_selectors_must_be_valid_before_any_delivery(self):
        fields = ["previous-parent", "current-parent"]
        self.configure("holding", "holding-moved-v1", fields)
        headers, body = signed_event(
            self.key, self.contract, {"previous-parent": "approved", "current-parent": "bad\nkey"}
        )
        self.assertEqual(self.post(headers, body), (409, b""))
        self.assertEqual(self.attempts, [])

    def test_non_202_success_response_is_retried(self):
        self.configure("person", "person-corrected-v1", ["person-key"])
        headers, body = signed_event(self.key, self.contract, {"person-key": "approved"})
        self.responses.append(200)
        self.assertEqual(self.post(headers, body), (503, b""))
        self.assertEqual(self.accepted, {})
        self.assertEqual(self.post(headers, body), (204, b""))
        self.assertEqual(len(self.accepted), 1)
        self.assertEqual(self.attempts[0], self.attempts[1])


class SignatureContractTests(unittest.TestCase):
    def test_matches_the_shared_rust_wire_signature_vector(self):
        # This vector belongs to registry-platform-crypto/delivery_signature.rs.
        # Its body is arbitrary signed bytes, not a current event schema sample.
        key = b"webhook-delivery-signing-key-0123456789abcdef"
        body = b'{"entity":"case","values":{"label":"value"}}'
        headers = {
            "ce-specversion": "1.0",
            "ce-id": "00000000-0000-4000-8000-000000000001",
            "ce-source": "urn:registrystack:registry:example:instance:primary",
            "ce-type": "case-created-v1", "ce-time": "2026-08-30T00:00:00Z",
            "ce-dataschema": "urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa",
            "x-registry-event-generation": "1", "x-registry-delivery-attempt": "1",
            "x-registry-delivery-time": "2026-08-30T00:00:01Z",
            "idempotency-key": "sha256:" + "a" * 64,
        }
        signature = SIGNER.webhook_signature(key, headers, body, "/hooks/registry")
        self.assertEqual(signature, "v1=OzL5k0ghZJb9nPbb-JOVsroWeanipBlZXbeKDd52RcM")
        header_pairs = [
            *headers.items(),
            ("content-type", "application/json"),
            ("x-registry-signature", signature),
        ]
        verified = RECEIVER.breg.verify_hook_delivery(
            method="POST", path="/hooks/registry", body=body, key=key,
            headers=header_pairs,
        )
        self.assertEqual(verified["body"], body)

        for name, value in (
            ("ce-type", "withheld-exact-duplicate"),
            ("CE-TYPE", "withheld-cased-duplicate"),
        ):
            with self.subTest(name=name):
                with self.assertRaises(RECEIVER.breg.BaseRegistryClientError) as raised:
                    RECEIVER.breg.verify_hook_delivery(
                        method="POST", path="/hooks/registry", body=body, key=key,
                        headers=[*header_pairs, (name, value)],
                    )
                self.assertEqual(raised.exception.kind, "hook-verification")
                self.assertEqual(raised.exception.code, "duplicate-header")
                self.assertNotIn(value, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
