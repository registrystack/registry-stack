import importlib.util
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
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
BINDING_TESTS = HERE.parents[3] / "crates/registry-breg-client-py/tests/python"


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


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
RECEIVER = load("receiver")
SIGNER = load("sign_delivery")


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
        event_id = event_id or str(uuid.uuid4())
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        source = "urn:registrystack:registry:example-registry:instance:local"
        schema = "urn:breg:event-schema:example-registry:contact:contact-created-v1:sha256:" + "a" * 64
        document = {
            "id": event_id, "type": "contact-created-v1", "source": source,
            "time": now, "dataschema": schema,
            "subject": {"recordReference": "hmac-sha256:" + "d" * 64, "recordRevision": 1},
            "causation": {"root": event_id, "hop": 0},
            "data": {"recordType": "contact", "recordId": str(uuid.uuid4()), "revision": 1,
                     "trigger": "created", "packageRevision": "sha256:" + "b" * 64,
                     "values": {"name": name}},
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
        self.sign(headers, body)
        return headers, body

    def sign(self, headers, body):
        headers["x-registry-signature"] = SIGNER.webhook_signature(self.key, headers, body)

    def post(self, headers, body):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.server.server_port}/events", body, headers
        )
        try:
            response = urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status

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

    def test_storage_failure_refuses_acknowledgement_then_recovers(self):
        headers, body = self.event()
        with patch.object(self.server.webhook_inbox, "accept", side_effect=sqlite3.OperationalError):
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
        verified = RECEIVER.breg.verify_webhook_delivery(
            method="POST", path="/hooks/registry", body=body, key=key,
            headers={**headers, "content-type": "application/json",
                     "x-registry-signature": signature},
        )
        self.assertEqual(verified["body"], body)


if __name__ == "__main__":
    unittest.main()
