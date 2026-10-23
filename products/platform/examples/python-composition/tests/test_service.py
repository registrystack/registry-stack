from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import threading
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from registry_client import breg
from service import (
    Composition,
    CompositionError,
    Inbox,
    TokenSource,
    WakeRefused,
    receiver,
)

# The fixed vector is owned by registry-breg-client/tests/webhook.rs and the
# shared registry-platform-crypto delivery signing contract, not this service.
CANARY_KEY = b"webhook-delivery-signing-key-0123456789abcdef"
BODY = b'{"entity":"case","values":{"label":"value"}}'
SOURCE = "urn:registrystack:registry:example:instance:primary"
SCHEMA = "urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa"
NOW = datetime(2026, 8, 30, 0, 0, 1, tzinfo=timezone.utc)


def headers():
    return {
        "ce-specversion": "1.0",
        "ce-id": "00000000-0000-4000-8000-000000000001",
        "ce-source": SOURCE,
        "ce-type": "case-created-v1",
        "ce-time": "2026-08-30T00:00:00Z",
        "ce-dataschema": SCHEMA,
        "x-registry-event-generation": "1",
        "x-registry-delivery-attempt": "1",
        "x-registry-delivery-time": "2026-08-30T00:00:01Z",
        "idempotency-key": "sha256:" + "a" * 64,
        "content-type": "application/json",
        "x-registry-signature": "v1=OzL5k0ghZJb9nPbb-JOVsroWeanipBlZXbeKDd52RcM",
    }


def accept(inbox, body=BODY, **overrides):
    options = dict(
        method="POST",
        path="/hooks/registry",
        headers=headers(),
        body=body,
        key=CANARY_KEY,
        source=SOURCE,
        event_type="case-created-v1",
        schema=SCHEMA,
        now=NOW,
    )
    options.update(overrides)
    return inbox.accept(**options)


class WakeReceiverTests(unittest.TestCase):
    def test_native_signature_acceptance_is_durable_and_event_replay_is_deduplicated(
        self,
    ):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "inbox.sqlite"
            inbox = Inbox(path)
            self.assertTrue(accept(inbox))
            self.assertFalse(accept(inbox))
            self.assertEqual(Inbox(path).pending(), 1)
            verified = breg.verify_webhook_delivery(
                method="POST",
                path="/hooks/registry",
                headers=headers(),
                body=BODY,
                key=CANARY_KEY,
            )
            # A trusted verification result isolates the persisted event/body
            # conflict check without implementing a second signing function.
            with patch.object(
                breg,
                "verify_webhook_delivery",
                return_value={**verified, "body": b"different"},
            ):
                with self.assertRaises(WakeRefused):
                    accept(inbox)

    def test_signature_target_identity_schema_and_freshness_refusals_precede_acceptance(
        self,
    ):
        with tempfile.TemporaryDirectory() as root:
            inbox = Inbox(Path(root) / "inbox.sqlite")
            for overrides in [
                {"body": b"tampered"},
                {"path": "/hooks/other"},
                {"key": b"x" * 32},
                {"source": "urn:other"},
                {"event_type": "proposal.applied"},
                {"schema": "urn:other"},
                {"now": datetime(2026, 10, 23, tzinfo=timezone.utc)},
            ]:
                with self.subTest(overrides=tuple(overrides)):
                    with self.assertRaises(WakeRefused):
                        accept(inbox, **overrides)
            self.assertEqual(inbox.pending(), 0)


class PublishedClientTests(unittest.TestCase):
    def config(self, root):
        file = Path(root) / "canary.headers"
        file.write_text("Authorization: Bearer canary-token\n")
        return {
            "bregUrl": "https://registry.example.org/",
            "bregProfile": "applier",
            "caseworkUrl": "https://casework.example.org/",
            "caseworkProfile": "staff",
            "messagingUrl": "https://messaging.example.org/",
            "tokens": {
                name: {
                    "headerFile": str(file),
                    "resource": "urn:example:" + name,
                    "scopes": [name + ":call"],
                }
                for name in ("breg", "casework", "messaging")
            },
        }

    def test_pinned_043_native_constructors_are_called_with_released_spellings(self):
        with tempfile.TemporaryDirectory() as root:
            app = Composition(self.config(root), Inbox(Path(root) / "inbox.sqlite"))
            self.assertIsNotNone(app.registry)
            self.assertIsNotNone(app.reviews)
            self.assertIsNotNone(app.messages)

    def test_closed_resource_bound_provider_configuration(self):
        for config in [
            {},
            {"headerFile": "file"},
            {"privateKeyJwt": {}, "headerFile": "file"},
            {"headerFile": "file", "resource": "urn:test", "scopes": []},
            {"privateKeyJwt": {"resource": "urn:test", "scopes": []}},
        ]:
            with self.assertRaises(CompositionError):
                TokenSource(config)

    def test_context_read_uses_its_own_authority_and_source_profile(self):
        app = Composition.__new__(Composition)
        app.config = {
            "caseworkProfile": "staff",
            "caseworkSourceProfile": "proposal-reviewer",
        }
        app.tokens = {
            "casework": SimpleNamespace(bearer_token=lambda: "canary-casework-token")
        }
        calls = []
        app.reviews = SimpleNamespace(
            review_task_context=lambda *args, **kwargs: calls.append((args, kwargs))
        )
        app.review_context("task-id")
        self.assertEqual(
            calls,
            [
                (
                    ("canary-casework-token", "staff", "task-id"),
                    {"source_profile": "proposal-reviewer"},
                )
            ],
        )


class ReceiptRecoveryTests(unittest.TestCase):
    def app(self, root):
        app = Composition.__new__(Composition)
        app.config = {"bregProfile": "applier"}
        app.inbox = Inbox(Path(root) / "inbox.sqlite")
        app.inbox.register(
            "proposal-one",
            1,
            "sha256:" + "a" * 64,
            {
                "senderProfile": "notices",
                "content": {"text": "Approved"},
                "to": {"email": "person@example.org"},
            },
        )
        app.tokens = {
            "messaging": SimpleNamespace(bearer_token=lambda: "canary-messaging-token")
        }
        app.registry = SimpleNamespace(
            registry_contract=lambda _: SimpleNamespace(
                select_proposal_get=lambda _: None
            ),
            get_proposal=lambda *_: SimpleNamespace(
                document={
                    "state": "applied",
                    "submissionVersion": 1,
                    "effectDigest": "sha256:" + "a" * 64,
                }
            ),
        )
        return app

    def test_lost_notice_response_reads_original_receipt_without_resubmitting(self):
        with tempfile.TemporaryDirectory() as root:
            app = self.app(root)
            submits = []
            receipts = []

            def lost(*args):
                submits.append(args)
                raise RuntimeError("synthetic lost response")

            app.messages = SimpleNamespace(
                submit=lost,
                message_receipt=lambda *args: (
                    receipts.append(args)
                    or {"kind": "complete", "value": {"id": "message-one"}}
                ),
            )
            with self.assertRaises(RuntimeError):
                app.reconcile()
            self.assertEqual(app.inbox.jobs()[0][2], "notice-uncertain")
            self.assertEqual(app.reconcile(), 1)
            self.assertEqual(len(submits), 1)
            self.assertEqual(len(receipts), 1)
            self.assertEqual(submits[0], receipts[0])
            self.assertEqual(app.inbox.jobs(), [])

    def test_unresolved_or_expired_receipt_does_not_mean_no_effect(self):
        for code in ("receipt.unresolved", "idempotency.expired"):
            with tempfile.TemporaryDirectory() as root:
                app = self.app(root)
                with app.inbox.connect() as db:
                    db.execute("UPDATE jobs SET state='notice-uncertain'")

                def refused(*_):
                    error = RuntimeError(code)
                    error.code = code
                    raise error

                app.messages = SimpleNamespace(
                    submit=lambda *_: self.fail("must not resubmit"),
                    message_receipt=refused,
                )
                with self.assertRaises(RuntimeError):
                    app.reconcile()
                self.assertEqual(app.inbox.jobs()[0][2], "notice-uncertain")


class ReceiverHttpTests(unittest.TestCase):
    def test_acknowledgment_follows_persistence_and_replay_is_safe(self):
        with tempfile.TemporaryDirectory() as root:
            inbox = Inbox(Path(root) / "inbox.sqlite")
            verified = breg.verify_webhook_delivery(
                method="POST",
                path="/hooks/registry",
                headers=headers(),
                body=BODY,
                key=CANARY_KEY,
            )
            verified["delivery_time"] = datetime.now(timezone.utc).isoformat()
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                receiver(
                    inbox,
                    key=CANARY_KEY,
                    source=SOURCE,
                    event_type="case-created-v1",
                    schema=SCHEMA,
                ),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                # Native cryptography and target checks are covered above.
                # This trusted result isolates HTTP framing and commit order.
                with patch.object(
                    breg, "verify_webhook_delivery", return_value=verified
                ):
                    for _ in range(2):
                        connection = HTTPConnection(*server.server_address, timeout=5)
                        connection.request(
                            "POST", "/hooks/breg", body=BODY, headers=headers()
                        )
                        response = connection.getresponse()
                        self.assertEqual(response.status, 204)
                        self.assertEqual(response.read(), b"")
                        self.assertEqual(Inbox(inbox.path).pending(), 1)
                        connection.close()
                connection = HTTPConnection(*server.server_address, timeout=5)
                connection.request("POST", "/hooks/other", body=BODY, headers=headers())
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                problem = json.loads(response.read())
                self.assertEqual(problem["code"], "receiver.hook-refused")
                self.assertEqual(
                    response.getheader("traceparent").split("-")[1], problem["traceId"]
                )
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
