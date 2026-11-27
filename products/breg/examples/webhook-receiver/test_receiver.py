import http.client
import http.server
import json
import sqlite3
import sys
import tempfile
import time
import threading
import types
import unittest
import urllib.error
import urllib.request
import uuid
from contextlib import closing, redirect_stderr, redirect_stdout
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


def signed_event(key, contract, values, event_id=None):
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
        "webhook-id": event_id, "webhook-timestamp": str(int(time.time())),
    }
    sign_headers(key, headers, body)
    return headers, body


def sign_headers(key, headers, body):
    headers["webhook-signature"] = SIGNER.webhook_signature(
        [key], headers["webhook-id"], int(headers["webhook-timestamp"]), body
    )


def post_event(server, headers, body, path="/events"):
    request = urllib.request.Request(
        f"http://127.0.0.1:{server.server_port}{path}", body, headers
    )
    try:
        response = urllib.request.urlopen(request, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read()


class WebhookAcceptanceInterfaceTests(unittest.TestCase):
    def test_incomplete_acceptance_fails_explicitly(self):
        class IncompleteAcceptance(RECEIVER.WebhookAcceptance):
            pass

        with self.assertRaises(NotImplementedError):
            IncompleteAcceptance().accept({}, b"")


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

    def event(self, event_id=None, name="Contact"):
        return signed_event(
            self.key, self.contract, {"name": name}, event_id
        )

    def sign(self, headers, body):
        sign_headers(self.key, headers, body)

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
        with closing(sqlite3.connect(self.inbox_path)) as connection:
            return connection.execute("SELECT count(*) FROM accepted_events").fetchone()[0]

    def test_acceptance_survives_restart_and_replay_without_duplicate_work(self):
        headers, body = self.event(name="Jérémie")
        self.assertEqual(self.post(headers, body), 204)
        self.assertEqual(self.counts(), 1)
        self.stop()
        self.start()
        headers["webhook-timestamp"] = str(int(headers["webhook-timestamp"]) + 1)
        self.sign(headers, body)
        self.assertEqual(self.post(headers, body), 204)
        headers["webhook-timestamp"] = str(int(headers["webhook-timestamp"]) + 1)
        self.sign(headers, body)
        self.assertEqual(self.post(headers, body), 204)
        self.assertEqual(self.counts(), 1)

    def test_conflicting_duplicate_is_refused(self):
        headers, body = self.event()
        self.assertEqual(self.post(headers, body), 204)
        changed = json.loads(body)
        changed["data"]["values"]["name"] = "Changed"
        changed_body = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode()
        self.sign(headers, changed_body)
        self.assertEqual(self.post(headers, changed_body), 409)
        self.assertEqual(self.counts(), 1)

    def test_authentication_and_source_are_verified_before_acceptance(self):
        for mutation in ("signature", "key", "body", "source"):
            with self.subTest(mutation=mutation):
                headers, body = self.event()
                if mutation == "signature":
                    headers["webhook-signature"] = "v1,invalid"
                elif mutation == "key":
                    sign_headers(b"another-receiver-key-material-32b", headers, body)
                elif mutation == "body":
                    body = body.replace(b'"Contact"', b'"Tampered"')
                else:
                    document = json.loads(body)
                    document["source"] = "urn:other"
                    body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
                    self.sign(headers, body)
                self.assertEqual(self.post(headers, body), 400)
        self.assertEqual(self.counts(), 0)

    def test_a_delivery_outside_the_window_is_refused(self):
        headers, body = self.event()
        headers["webhook-timestamp"] = str(int(time.time()) - 305)
        self.sign(headers, body)
        self.assertEqual(self.post(headers, body), 400)
        self.assertEqual(self.counts(), 0)

    def test_a_wrong_route_is_refused(self):
        headers, body = self.event()
        self.assertEqual(post_event(self.server, headers, body, "/other"), (400, b""))
        self.assertEqual(self.counts(), 0)

    def test_exact_and_cased_duplicate_headers_reach_the_shared_verifier(self):
        for name, value in (
            ("webhook-id", "withheld-exact-duplicate"),
            ("WEBHOOK-ID", "withheld-cased-duplicate"),
        ):
            with self.subTest(name=name):
                headers, body = self.event()
                self.assertEqual(
                    self.post_pairs([*headers.items(), (name, value)], body),
                    400,
                )
        self.assertEqual(self.counts(), 0)

    def test_storage_failure_refuses_acknowledgement_then_recovers(self):
        headers, body = self.event()
        with patch.object(self.server.webhook_acceptance, "accept", side_effect=sqlite3.OperationalError):
            self.assertEqual(self.post(headers, body), 503)
        self.assertEqual(self.counts(), 0)
        self.assertEqual(self.post(headers, body), 204)
        self.assertEqual(self.counts(), 1)

    def test_inbox_refuses_non_private_file_and_symlink(self):
        self.inbox_path.chmod(0o644)
        with self.assertRaises(RECEIVER.ReceiverError):
            RECEIVER.WebhookInbox(self.inbox_path)
        link = self.inbox_path.with_name("link.sqlite3")
        link.symlink_to(self.inbox_path)
        with self.assertRaises(RECEIVER.ReceiverError):
            RECEIVER.WebhookInbox(link)


class SourceChangeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.token_file = Path(temporary.name) / "notifier-token"
        self.token_file.touch(mode=0o600)
        self.token_file.write_text("notifier-token-canary\n", encoding="ascii")
        self.key = b"receiver-test-key-material-32-bytes"
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
                    test.accepted.setdefault(request["selector"], request)
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
        self.sink = REFRESH.SourceChanges(
            origin=f"http://127.0.0.1:{self.destination.server_port}",
            plan="licensing-holders", projection="authority-indexed",
            fields=fields, token_file=self.token_file,
        )
        self.server = self.start(RECEIVER.make_server(0, self.key, self.contract, self.sink))

    def post(self, headers, body):
        return post_event(self.server, headers, body)

    def resign(self, headers, body):
        sign_headers(self.key, headers, body)

    def test_person_correction_sends_only_the_approved_selector(self):
        self.configure("person", "person-corrected-v1", ["person-key"])
        selector = "approved-person-selector-canary"
        headers, body = signed_event(self.key, self.contract, {"person-key": selector})
        self.assertEqual(self.post(headers, body), (204, b""))
        path, authorization, change = self.attempts[0]
        self.assertEqual(path, "/v1/external-refresh-plans/licensing-holders/source-changes")
        self.assertEqual(authorization, "Bearer notifier-token-canary")
        self.assertEqual(change, {"projection": "authority-indexed", "selector": selector})

    def test_invalid_signature_schema_and_unapproved_fields_make_no_request(self):
        self.configure("person", "person-corrected-v1", ["person-key"])
        fields = {"person-key": "approved-person-selector-canary"}
        headers, body = signed_event(self.key, self.contract, fields)
        self.assertEqual(self.post(headers, body.replace(b"approved-person", b"changed-person")), (400, b""))
        changed = json.loads(body)
        changed["dataschema"] = changed["dataschema"][:-1] + "b"
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
            headers["webhook-timestamp"] = str(int(headers["webhook-timestamp"]) + 1)
            self.resign(headers, body)
            self.assertEqual(self.post(headers, body), (503, b""))
            self.assertEqual(len(self.accepted), 2)
            headers["webhook-timestamp"] = str(int(headers["webhook-timestamp"]) + 1)
            self.resign(headers, body)
            self.assertEqual(self.post(headers, body), (204, b""))
        changes = [attempt[2] for attempt in self.attempts]
        self.assertEqual([change["selector"] for change in changes], [previous, current] * 3)
        self.assertEqual(changes, changes[:2] * 3)
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
    def test_signer_reproduces_the_committed_vectors(self):
        fixture = HERE.parents[3] / "crates/registry-platform-crypto/tests/fixtures/standard-webhooks.json"
        for vector in json.loads(fixture.read_bytes()):
            if vector["expected"] != "accepted":
                continue
            keys = [bytes.fromhex(vector["keyHex"])]
            if vector["previousKeyHex"] is not None:
                keys.append(bytes.fromhex(vector["previousKeyHex"]))
            arguments = (keys, vector["id"], int(vector["timestamp"]), vector["body"].encode())
            with self.subTest(vector=vector["name"]):
                if vector["keyPolicy"] == "below-minimum":
                    with self.assertRaises(ValueError):
                        SIGNER.webhook_signature(*arguments)
                else:
                    self.assertEqual(SIGNER.webhook_signature(*arguments), vector["signature"])

    def test_signer_refuses_empty_and_oversized_keys(self):
        for keys in ([], [b"x" * 65]):
            with self.subTest(count=len(keys)):
                with self.assertRaises(ValueError):
                    SIGNER.webhook_signature(keys, str(uuid.uuid4()), 1, b"{}")


if __name__ == "__main__":
    unittest.main()
