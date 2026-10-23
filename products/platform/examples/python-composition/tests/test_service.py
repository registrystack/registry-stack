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
from registry_client import breg, messaging
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


PROPOSAL_ID = "00000000-0000-4000-8000-000000000002"
PROPOSAL_SCHEMA = "https://id.registrystack.org/contracts/breg/proposal-event/v1"


def proposal_envelope():
    return {
        "id": headers()["ce-id"],
        "type": "proposal.applied",
        "source": SOURCE,
        "time": "2026-08-30T00:00:00Z",
        "dataschema": PROPOSAL_SCHEMA,
        "subject": {
            "recordReference": "/v1/proposals/" + PROPOSAL_ID,
            "recordRevision": 2,
        },
        "causation": {"root": headers()["ce-id"], "hop": 0},
        "data": {
            "proposalId": PROPOSAL_ID,
            "submissionVersion": 1,
            "revision": 2,
            "actionId": "issue-licence",
            "actionRevision": "sha256:" + "b" * 64,
            "fromState": "submitted",
            "state": "applied",
            "transition": "applied",
            "effectDigest": "sha256:" + "a" * 64,
            "authorityKind": "caller",
            "systemApplyGrantRevision": None,
            "turn": "nobody",
        },
    }


def verified_proposal(envelope=None):
    envelope = proposal_envelope() if envelope is None else envelope
    verified = breg.verify_webhook_delivery(
        method="POST",
        path="/hooks/registry",
        headers=headers(),
        body=BODY,
        key=CANARY_KEY,
    )
    verified.update(
        {
            name: envelope[name]
            for name in ("id", "type", "source", "time", "dataschema")
        }
    )
    verified["body"] = json.dumps(envelope).encode()
    return verified


def accept_proposal(inbox, envelope=None):
    verified = verified_proposal(envelope)
    with patch.object(breg, "verify_webhook_delivery", return_value=verified):
        return inbox.accept(
            "POST",
            "/hooks/breg",
            {},
            verified["body"],
            key=CANARY_KEY,
            source=SOURCE,
            event_type="proposal.applied",
            schema=PROPOSAL_SCHEMA,
            now=NOW,
        )


class WakeReceiverTests(unittest.TestCase):
    def test_authenticated_record_payload_is_not_an_accepted_proposal_hint(self):
        with tempfile.TemporaryDirectory() as root:
            inbox = Inbox(Path(root) / "inbox.sqlite")
            with self.assertRaises(WakeRefused):
                accept(inbox)
            self.assertEqual(inbox.pending(), 0)

    def test_native_signature_acceptance_is_durable_and_event_replay_is_deduplicated(
        self,
    ):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "inbox.sqlite"
            inbox = Inbox(path)
            self.assertTrue(accept_proposal(inbox))
            self.assertFalse(accept_proposal(inbox))
            self.assertEqual(Inbox(path).pending(), 1)
            conflict = proposal_envelope()
            conflict["data"]["actionId"] = "another-action"
            with self.assertRaises(WakeRefused):
                accept_proposal(inbox, conflict)

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

        def record(*args, **kwargs):
            calls.append((args, kwargs))

        app.reviews = SimpleNamespace(
            review_task_context=record,
            review_tasks=record,
            claim_review_task=record,
            decide_review_task=record,
        )
        app.review_context("task-id")
        app.review_tasks()
        app.claim("task-id", 1, "claim-key")
        app.decide(
            "task-id",
            1,
            "key",
            {"decision": {"type": "approve", "outcome": "approved"}},
        )
        self.assertEqual(len(calls), 4)
        self.assertTrue(
            all(
                kwargs == {"source_profile": "proposal-reviewer"} for _, kwargs in calls
            )
        )
        self.assertEqual(
            calls[:1],
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
            verified = verified_proposal()
            verified["delivery_time"] = datetime.now(timezone.utc).isoformat()
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                receiver(
                    inbox,
                    key=CANARY_KEY,
                    source=SOURCE,
                    event_type="proposal.applied",
                    schema=PROPOSAL_SCHEMA,
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


class NativeFailureRecoveryTests(unittest.TestCase):
    app = ReceiptRecoveryTests.app

    def test_native_known_pre_send_failure_restores_prepared_state(self):
        with tempfile.TemporaryDirectory() as root:
            app = self.app(root)
            # This fixture notice is deliberately outside the native wire schema.
            # The actual released SDK rejects it before opening a connection.
            app.messages = messaging.MessagingClient(
                "http://127.0.0.1:1", max_mutation_retries=0
            )
            with self.assertRaises(messaging.MessagingClientError) as raised:
                app.reconcile()
            self.assertIs(raised.exception.outcome_unknown, False)
            self.assertEqual(app.inbox.jobs()[0][2], "prepared")

    def test_receipt_recovery_still_runs_at_the_attempt_budget(self):
        with tempfile.TemporaryDirectory() as root:
            app = self.app(root)
            with app.inbox.connect() as db:
                db.execute("UPDATE jobs SET state='notice-uncertain',attempts=12")
            app.messages = SimpleNamespace(
                submit=lambda *_: self.fail("must not resubmit"),
                message_receipt=lambda *_: {
                    "kind": "complete",
                    "value": {"id": "message-one"},
                },
            )
            self.assertEqual(app.reconcile(), 1)
            self.assertEqual(app.inbox.jobs(), [])


class IntakeCopyTests(unittest.TestCase):
    def app(self, application="application-one"):
        calls = []
        app = Composition.__new__(Composition)
        app.config = {"bregProfile": "officer"}
        intake = SimpleNamespace(
            document={
                "actionId": "submit-application",
                "state": "applied",
                "submissionVersion": 1,
                "effectDigest": "sha256:" + "a" * 64,
                "application": {
                    "submissionVersion": 1,
                    "effectDigest": "sha256:" + "a" * 64,
                    "resultLinks": [
                        {
                            "recordType": "application",
                            "recordId": application,
                            "revision": 1,
                        }
                    ],
                },
            }
        )
        app.registry = SimpleNamespace(
            registry_contract=lambda _: SimpleNamespace(
                select_proposal_get=lambda _: "get", select_action=lambda *_: "action"
            ),
            get_proposal=lambda *_: intake,
            download_proposal_attachment=lambda *_: {
                "media_type": "application/pdf",
                "body": b"synthetic PDF",
            },
            start_proposal=lambda *_: calls.append("start") or "draft",
            upload_proposal_attachment=lambda *args: (
                calls.append(("copy", args)) or "draft-with-document"
            ),
            prepare_proposal=lambda *args: calls.append(("submit", args)) or "prepared",
            execute_proposal=lambda _: "submitted",
        )
        return app, calls

    def test_native_intake_slot_copy_precedes_submit_with_its_updated_draft(self):
        app, calls = self.app()
        self.assertEqual(
            app.prepare(
                "issue-licence",
                {"application": "application-one"},
                "key",
                intake_proposal_id="intake",
            ),
            "submitted",
        )
        self.assertEqual(
            calls,
            [
                "start",
                (
                    "copy",
                    (
                        "draft",
                        "supporting-document",
                        "application/pdf",
                        b"synthetic PDF",
                        "key:document",
                    ),
                ),
                ("submit", ("draft-with-document", "submit", {}, "key:submit")),
            ],
        )

    def test_cross_application_intake_refuses_before_creating_an_issuance_draft(self):
        app, calls = self.app("another-application")
        with self.assertRaises(CompositionError):
            app.prepare(
                "issue-licence",
                {"application": "application-one"},
                "key",
                intake_proposal_id="intake",
            )
        self.assertEqual(calls, [])


class ProposalHintTests(unittest.TestCase):
    def test_exact_native_subject_is_prioritized_then_consumed_after_source_reread(
        self,
    ):
        with tempfile.TemporaryDirectory() as root:
            app = ReceiptRecoveryTests().app(root)
            notice = json.loads(app.inbox.jobs()[0][1])["notice"]
            app.inbox.register(PROPOSAL_ID, 1, "sha256:" + "a" * 64, notice)
            self.assertTrue(accept_proposal(app.inbox))
            self.assertEqual(app.inbox.jobs()[0][0], PROPOSAL_ID)
            reads = []
            get = app.registry.get_proposal
            app.registry.get_proposal = lambda *args: (
                reads.append(args[-1]) or get(*args)
            )
            app.messages = SimpleNamespace(submit=lambda *_: {"kind": "complete"})
            self.assertEqual(app.reconcile(), 2)
            self.assertEqual(reads[0], PROPOSAL_ID)
            self.assertEqual(app.inbox.pending(), 0)
            self.assertEqual(app.inbox.jobs(), [])

    def test_subject_version_and_payload_schema_are_checked_before_durable_acceptance(
        self,
    ):
        for change in ("subject", "version", "unknown-field", "header"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as root:
                inbox = Inbox(Path(root) / "inbox.sqlite")
                envelope = proposal_envelope()
                if change == "subject":
                    envelope["subject"]["recordReference"] = "/v1/proposals/another"
                elif change == "version":
                    envelope["data"]["submissionVersion"] = True
                elif change == "unknown-field":
                    envelope["data"]["privateValue"] = "must-not-persist"
                else:
                    envelope["type"] = "proposal.submitted"
                with self.assertRaises(WakeRefused):
                    accept_proposal(inbox, envelope)
                self.assertEqual(inbox.pending(), 0)


class OwningSchemaTests(unittest.TestCase):
    def test_bundled_proposal_schema_matches_the_owning_generated_contract(self):
        root = Path(__file__).resolve().parents[5]
        self.assertEqual(
            json.loads(
                (
                    Path(__file__).resolve().parents[1] / "proposal-event.schema.json"
                ).read_text()
            ),
            json.loads(
                (
                    root
                    / "products/breg/generated/event-schemas/proposal-lifecycle.schema.json"
                ).read_text()
            ),
        )
