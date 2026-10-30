import json
import sqlite3
import tempfile
import threading
import unittest
from datetime import UTC, datetime
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from registry_client import breg, messaging

from service import (
    MAXIMUM_ATTEMPTS,
    PROPOSAL_PAYLOAD,
    PROPOSAL_SCHEMA_PATH,
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
NOW = datetime(2026, 8, 30, 0, 0, 1, tzinfo=UTC)


def headers():
    return [
        ("ce-specversion", "1.0"),
        ("ce-id", "00000000-0000-4000-8000-000000000001"),
        ("ce-source", SOURCE),
        ("ce-type", "case-created-v1"),
        ("ce-time", "2026-08-30T00:00:00Z"),
        ("ce-dataschema", SCHEMA),
        ("x-registry-event-generation", "1"),
        ("x-registry-delivery-attempt", "1"),
        ("x-registry-delivery-time", "2026-08-30T00:00:01Z"),
        ("idempotency-key", "sha256:" + "a" * 64),
        ("content-type", "application/json"),
        ("x-registry-signature", "v1=OzL5k0ghZJb9nPbb-JOVsroWeanipBlZXbeKDd52RcM"),
    ]


def header(name):
    return next(value for candidate, value in headers() if candidate == name)


def accept(inbox, body=BODY, **overrides):
    options = {
        "method": "POST",
        "path": "/hooks/registry",
        "headers": headers(),
        "body": body,
        "key": CANARY_KEY,
        "source": SOURCE,
        "event_type": "case-created-v1",
        "schema": SCHEMA,
        "now": NOW,
    }
    options.update(overrides)
    return inbox.accept(**options)


PROPOSAL_ID = "00000000-0000-4000-8000-000000000002"
PROPOSAL_SCHEMA = "https://id.registrystack.org/contracts/breg/proposal-event/v1"


def proposal_envelope():
    return {
        "id": header("ce-id"),
        "type": "proposal.applied",
        "source": SOURCE,
        "time": "2026-08-30T00:00:00Z",
        "dataschema": PROPOSAL_SCHEMA,
        "subject": {
            "proposalReference": "/v1/proposals/" + PROPOSAL_ID,
            "proposalRevision": 2,
        },
        "causation": {"root": header("ce-id"), "hop": 0},
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
    verified = breg.verify_hook_delivery(
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
    with patch.object(breg, "verify_hook_delivery", return_value=verified):
        return inbox.accept(
            "POST",
            "/hooks/breg",
            [],
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
                {"now": datetime(2026, 10, 23, tzinfo=UTC)},
            ]:
                with (
                    self.subTest(overrides=tuple(overrides)),
                    self.assertRaises(WakeRefused),
                ):
                    accept(inbox, **overrides)
            self.assertEqual(inbox.pending(), 0)


class ClientConstructionTests(unittest.TestCase):
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

    def test_native_constructors_are_called_with_current_spellings(self):
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

    def test_token_failure_keeps_prepared_job_and_recovers_with_one_original_submit(
        self,
    ):
        cases = (
            ("credential-file", CompositionError("canary credential unavailable"), 0),
            (
                "token-endpoint",
                RuntimeError("canary token endpoint unavailable"),
                MAXIMUM_ATTEMPTS - 1,
            ),
        )
        for fault, error, attempts in cases:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as root:
                app = self.app(root)
                with app.inbox.connect() as db:
                    db.execute("UPDATE jobs SET attempts=?", (attempts,))
                    original = db.execute(
                        "SELECT body,state,attempts FROM jobs"
                    ).fetchone()
                submits = []
                app.messages = SimpleNamespace(
                    submit=lambda *args: submits.append(args),
                    message_receipt=lambda *_: self.fail(
                        "an unsent notice has no receipt"
                    ),
                )
                with (
                    patch.object(
                        app.tokens["messaging"],
                        "bearer_token",
                        side_effect=[error, "canary-messaging-token"],
                    ) as tokens,
                    patch("service.LOG.error") as diagnostic,
                ):
                    with self.assertRaises(type(error)):
                        app.reconcile()
                    with app.inbox.connect() as db:
                        body, state, count = db.execute(
                            "SELECT body,state,attempts FROM jobs"
                        ).fetchone()
                        self.assertEqual((state, count), original[1:])
                        self.assertEqual(body, original[0])
                    self.assertEqual(submits, [])
                    diagnostic.assert_not_called()
                    self.assertEqual(app.reconcile(), 1)
                    self.assertEqual(app.reconcile(), 0)
                    self.assertEqual(tokens.call_count, 2)
                self.assertEqual(
                    submits,
                    [
                        (
                            "canary-messaging-token",
                            "proposal-one:1:notice",
                            json.loads(original[0])["notice"],
                        )
                    ],
                )
                with app.inbox.connect() as db:
                    self.assertEqual(
                        db.execute("SELECT body,state,attempts FROM jobs").fetchone(),
                        (original[0], "notified", attempts + 1),
                    )

    def test_lost_notice_response_reads_original_receipt_without_resubmitting(self):
        with tempfile.TemporaryDirectory() as root:
            app = self.app(root)
            submits = []
            receipts = []
            dispatch_states = []

            def lost(*args):
                with app.inbox.connect() as db:
                    dispatch_states.append(
                        db.execute("SELECT state,attempts FROM jobs").fetchone()
                    )
                submits.append(args)
                raise RuntimeError("synthetic lost response")

            app.messages = SimpleNamespace(
                submit=lost,
                message_receipt=lambda *args: (
                    receipts.append(args)
                    or {"kind": "complete", "value": {"id": "message-one"}}
                ),
            )
            with self.assertLogs("python-composition", level="ERROR"):
                self.assertEqual(app.reconcile(), 0)
            self.assertEqual(app.inbox.jobs()[0][2], "notice-uncertain")
            self.assertEqual(app.reconcile(), 1)
            self.assertEqual(dispatch_states, [("notice-uncertain", 1)])
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

                def refused(*_, code=code):
                    error = RuntimeError(code)
                    error.code = code
                    raise error

                app.messages = SimpleNamespace(
                    submit=lambda *_: self.fail("must not resubmit"),
                    message_receipt=refused,
                )
                with self.assertLogs("python-composition", level="ERROR"):
                    self.assertEqual(app.reconcile(), 0)
                self.assertEqual(app.inbox.jobs()[0][2], "notice-uncertain")


class ReceiverHttpTests(unittest.TestCase):
    def test_acknowledgment_follows_persistence_and_replay_is_safe(self):
        with tempfile.TemporaryDirectory() as root:
            inbox = Inbox(Path(root) / "inbox.sqlite")
            verified = verified_proposal()
            verified["delivery_time"] = datetime.now(UTC).isoformat()
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
                    breg, "verify_hook_delivery", return_value=verified
                ):
                    for _ in range(2):
                        connection = HTTPConnection(*server.server_address, timeout=5)
                        connection.request(
                            "POST", "/hooks/breg", body=BODY, headers=dict(headers())
                        )
                        response = connection.getresponse()
                        self.assertEqual(response.status, 204)
                        self.assertEqual(response.read(), b"")
                        self.assertEqual(Inbox(inbox.path).pending(), 1)
                        connection.close()
                connection = HTTPConnection(*server.server_address, timeout=5)
                connection.request(
                    "POST", "/hooks/other", body=BODY, headers=dict(headers())
                )
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

    def test_repeated_header_reaches_the_native_verifier_without_collapsing(self):
        with tempfile.TemporaryDirectory() as root:
            inbox = Inbox(Path(root) / "inbox.sqlite")
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
            captured = []

            def refuse_duplicate(**delivery):
                captured.extend(delivery["headers"])
                raise ValueError("the native verifier refused a repeated header")

            try:
                with patch.object(
                    breg, "verify_hook_delivery", side_effect=refuse_duplicate
                ):
                    connection = HTTPConnection(*server.server_address, timeout=5)
                    connection.putrequest("POST", "/hooks/breg")
                    connection.putheader("Content-Length", str(len(BODY)))
                    for name, value in [*headers(), ("CE-TYPE", "proposal.applied")]:
                        connection.putheader(name, value)
                    connection.endheaders(BODY)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 403)
                    self.assertEqual(
                        json.loads(response.read())["code"], "receiver.hook-refused"
                    )
                    connection.close()
                self.assertEqual(
                    [
                        (name.lower(), value)
                        for name, value in captured
                        if name.lower() == "ce-type"
                    ],
                    [("ce-type", "case-created-v1"), ("ce-type", "proposal.applied")],
                )
                self.assertEqual(inbox.pending(), 0)
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
            # The native SDK rejects it before opening a connection.
            native = messaging.MessagingClient(
                "http://127.0.0.1:1", maximum_mutation_retries=0
            )
            failures = []

            def submit(*args):
                try:
                    return native.submit(*args)
                except messaging.MessagingClientError as error:
                    failures.append(error)
                    raise

            app.messages = SimpleNamespace(submit=submit)
            with self.assertLogs("python-composition", level="ERROR"):
                self.assertEqual(app.reconcile(), 0)
            self.assertEqual(len(failures), 1)
            self.assertIs(failures[0].outcome_unknown, False)
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
        for change in (
            "subject-path",
            "subject-revision",
            "record-subject",
            "mixed-subject",
            "unknown-subject-member",
            "version",
            "unknown-field",
            "header",
        ):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as root:
                inbox = Inbox(Path(root) / "inbox.sqlite")
                envelope = proposal_envelope()
                if change == "subject-path":
                    envelope["subject"]["proposalReference"] = "/v1/proposals/another"
                elif change == "subject-revision":
                    envelope["subject"]["proposalRevision"] = 3
                elif change == "record-subject":
                    envelope["subject"] = {
                        "recordReference": "/v1/proposals/" + PROPOSAL_ID,
                        "recordRevision": 2,
                    }
                elif change == "mixed-subject":
                    envelope["subject"]["recordReference"] = "must-not-appear"
                elif change == "unknown-subject-member":
                    envelope["subject"]["privateValue"] = "must-not-appear"
                elif change == "version":
                    envelope["data"]["submissionVersion"] = True
                elif change == "unknown-field":
                    envelope["data"]["privateValue"] = "must-not-persist"
                else:
                    envelope["type"] = "proposal.submitted"
                with self.assertRaises(WakeRefused) as refused:
                    accept_proposal(inbox, envelope)
                self.assertEqual(
                    str(refused.exception),
                    "hook signature or expected envelope was refused"
                    if change == "header"
                    else "the authenticated native Proposal envelope was refused",
                )
                self.assertEqual(inbox.pending(), 0)


class OwningSchemaTests(unittest.TestCase):
    def test_proposal_validator_uses_the_owning_contract_from_the_source_archive(self):
        root = Path(__file__).resolve().parents[5]
        self.assertEqual(
            PROPOSAL_SCHEMA_PATH,
            root
            / "products/breg/generated/event-schemas/proposal-lifecycle.schema.json",
        )
        self.assertEqual(
            PROPOSAL_PAYLOAD.schema,
            json.loads(PROPOSAL_SCHEMA_PATH.read_text()),
        )
        self.assertEqual(PROPOSAL_PAYLOAD.schema["$id"], PROPOSAL_SCHEMA)


class FairPollingTests(unittest.TestCase):
    def test_later_approved_work_is_polled_past_a_full_batch_awaiting_review(self):
        with tempfile.TemporaryDirectory() as root:
            app = ReceiptRecoveryTests().app(root)
            notice = json.loads(app.inbox.jobs()[0][1])["notice"]
            with app.inbox.connect() as db:
                db.execute("DELETE FROM jobs")
            for index in range(101):
                app.inbox.register(
                    f"proposal-{index:03}", 1, "sha256:" + "a" * 64, notice
                )
            reads = []

            def current(_binding, identifier):
                reads.append(identifier)
                return SimpleNamespace(
                    document={
                        "state": "applied"
                        if identifier == "proposal-100"
                        else "submitted",
                        "submissionVersion": 1,
                        "effectDigest": "sha256:" + "a" * 64,
                    }
                )

            def awaiting(*_):
                error = RuntimeError("source does not promote Apply")
                error.kind = "invalid-request"
                raise error

            app.registry.get_proposal = current
            app.registry.prepare_proposal = awaiting
            submits = []
            app.messages = SimpleNamespace(submit=lambda *args: submits.append(args))
            self.assertEqual(app.reconcile(), 0)
            self.assertEqual(app.reconcile(), 1)
            self.assertIn("proposal-100", reads)
            self.assertEqual(len(submits), 1)
            with app.inbox.connect() as db:
                self.assertEqual(
                    db.execute(
                        "SELECT COUNT(*) FROM jobs WHERE state='prepared' AND attempts!=0"
                    ).fetchone()[0],
                    0,
                )


class ReconcileIsolationTests(unittest.TestCase):
    def test_stale_first_job_does_not_starve_a_healthy_job_in_the_same_batch(self):
        with tempfile.TemporaryDirectory() as root:
            app = ReceiptRecoveryTests().app(root)
            with app.inbox.connect() as db:
                original = db.execute(
                    "SELECT body FROM jobs WHERE id='proposal-one'"
                ).fetchone()[0]
            app.inbox.register(
                "proposal-two", 1, "sha256:" + "a" * 64, json.loads(original)["notice"]
            )
            reads, submits = [], []

            def current(_binding, identifier):
                reads.append(identifier)
                return SimpleNamespace(
                    document={
                        "state": "applied",
                        "submissionVersion": 2 if identifier == "proposal-one" else 1,
                        "effectDigest": "sha256:" + "a" * 64,
                    }
                )

            app.registry.get_proposal = current
            app.messages = SimpleNamespace(submit=lambda *args: submits.append(args))
            with self.assertLogs("python-composition", level="ERROR") as diagnostic:
                completed = [app.reconcile() for _ in range(2)]
            self.assertEqual(completed, [1, 0])
            self.assertEqual(reads, ["proposal-one", "proposal-two", "proposal-one"])
            self.assertEqual(len(submits), 1)
            self.assertEqual(submits[0][1], "proposal-two:1:notice")
            with app.inbox.connect() as db:
                self.assertEqual(
                    db.execute(
                        "SELECT body,state,attempts FROM jobs WHERE id='proposal-one'"
                    ).fetchone(),
                    (original, "prepared", 2),
                )
                self.assertEqual(
                    db.execute(
                        "SELECT state FROM jobs WHERE id='proposal-two'"
                    ).fetchone(),
                    ("notified",),
                )
            self.assertEqual(len(diagnostic.output), 2)
            self.assertEqual(diagnostic.output[0], diagnostic.output[1])
            self.assertRegex(diagnostic.output[0], r"job=[0-9a-f]{16};")
            self.assertTrue(all("stage=binding" in line for line in diagnostic.output))
            self.assertTrue(all(len(line) < 256 for line in diagnostic.output))
            self.assertNotIn("proposal-one", "\n".join(diagnostic.output))
            self.assertNotIn("canary-messaging-token", "\n".join(diagnostic.output))
            self.assertNotIn("person@example.org", "\n".join(diagnostic.output))

    def test_related_job_failures_do_not_abort_the_remaining_batch(self):
        cases = (
            ("read", "read"),
            ("effect", "binding"),
            ("prepare", "prepare"),
            ("execute", "apply"),
            ("readback-error", "confirm"),
            ("readback-pending", "confirm"),
            ("receipt-error", "receipt"),
            ("receipt-unresolved", "receipt"),
            ("submit", "submit"),
        )
        for fault, stage in cases:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as root:
                app = ReceiptRecoveryTests().app(root)
                with app.inbox.connect() as db:
                    original = db.execute(
                        "SELECT body FROM jobs WHERE id='proposal-one'"
                    ).fetchone()[0]
                    if fault.startswith("receipt-"):
                        db.execute(
                            "UPDATE jobs SET state='notice-uncertain',attempts=?",
                            (MAXIMUM_ATTEMPTS,),
                        )
                notice = json.loads(original)["notice"]
                app.inbox.register("proposal-two", 1, "sha256:" + "a" * 64, notice)
                reads, preparations, executions, submits, receipts = [], [], [], [], []
                applies = fault in {
                    "prepare",
                    "execute",
                    "readback-error",
                    "readback-pending",
                }

                def current(_binding, identifier):
                    reads.append(identifier)
                    if identifier == "proposal-one" and (
                        fault == "read"
                        or fault == "readback-error"
                        and reads.count(identifier) == 2
                    ):
                        raise RuntimeError("canary private remote failure")
                    return SimpleNamespace(
                        identifier=identifier,
                        document={
                            "state": "submitted"
                            if applies and identifier == "proposal-one"
                            else "applied",
                            "submissionVersion": 1,
                            "effectDigest": "sha256:"
                            + (
                                "b"
                                if fault == "effect" and identifier == "proposal-one"
                                else "a"
                            )
                            * 64,
                        },
                    )

                def prepare(current, transition, authority, key):
                    preparations.append((transition, authority, key))
                    if fault == "prepare":
                        raise RuntimeError("canary private remote failure")
                    return current.identifier

                def execute(prepared):
                    executions.append(prepared)
                    if fault == "execute":
                        raise RuntimeError("canary private remote failure")

                def submit(*args):
                    submits.append(args)
                    if fault == "submit" and args[1] == "proposal-one:1:notice":
                        raise RuntimeError("canary private remote failure")
                    return {"kind": "complete"}

                def receipt(*args):
                    receipts.append(args)
                    if fault == "receipt-error":
                        raise RuntimeError("canary private remote failure")
                    return {"kind": "pending"}

                app.registry.get_proposal = current
                app.registry.prepare_proposal = prepare
                app.registry.execute_proposal = execute
                app.messages = SimpleNamespace(submit=submit, message_receipt=receipt)
                with self.assertLogs("python-composition", level="ERROR") as diagnostic:
                    self.assertEqual(app.reconcile(), 1)
                self.assertEqual(len(diagnostic.output), 1)
                self.assertIn("stage=" + stage, diagnostic.output[0])
                self.assertLess(len(diagnostic.output[0]), 256)
                for hidden in (
                    "canary private remote failure",
                    "canary-messaging-token",
                    "person@example.org",
                    "Approved",
                    "proposal-one",
                ):
                    self.assertNotIn(hidden, diagnostic.output[0])
                with app.inbox.connect() as db:
                    self.assertEqual(
                        db.execute(
                            "SELECT body,state,attempts FROM jobs WHERE id='proposal-one'"
                        ).fetchone(),
                        (
                            original,
                            "notice-uncertain"
                            if fault.startswith("receipt-") or fault == "submit"
                            else "prepared",
                            MAXIMUM_ATTEMPTS if fault.startswith("receipt-") else 1,
                        ),
                    )
                    self.assertEqual(
                        db.execute(
                            "SELECT state FROM jobs WHERE id='proposal-two'"
                        ).fetchone(),
                        ("notified",),
                    )
                self.assertIn("proposal-two", reads)
                self.assertEqual(submits[-1][1], "proposal-two:1:notice")
                if applies:
                    self.assertEqual(
                        preparations,
                        [
                            (
                                "apply",
                                {
                                    "submissionVersion": 1,
                                    "effectDigest": "sha256:" + "a" * 64,
                                },
                                "proposal-one:1:apply",
                            )
                        ],
                    )
                    self.assertEqual(
                        executions, [] if fault == "prepare" else ["proposal-one"]
                    )
                if fault.startswith("receipt-"):
                    self.assertEqual(
                        receipts,
                        [("canary-messaging-token", "proposal-one:1:notice", notice)],
                    )
                    self.assertEqual(len(submits), 1)

    def test_failed_checks_exhaust_only_the_original_job_budget(self):
        with tempfile.TemporaryDirectory() as root:
            app = ReceiptRecoveryTests().app(root)
            with app.inbox.connect() as db:
                original = db.execute("SELECT body FROM jobs").fetchone()[0]
                db.execute("UPDATE jobs SET attempts=?", (MAXIMUM_ATTEMPTS - 1,))
            app.inbox.register(
                "proposal-two", 1, "sha256:" + "a" * 64, json.loads(original)["notice"]
            )
            reads = []

            def stale(_binding, identifier):
                reads.append(identifier)
                return SimpleNamespace(
                    document={
                        "state": "applied",
                        "submissionVersion": 2 if identifier == "proposal-one" else 1,
                        "effectDigest": "sha256:" + "a" * 64,
                    }
                )

            app.registry.get_proposal = stale
            app.messages = SimpleNamespace(submit=lambda *_: {"kind": "complete"})
            with self.assertLogs("python-composition", level="ERROR") as diagnostic:
                self.assertEqual([app.reconcile(), app.reconcile()], [1, 0])
            self.assertEqual(reads, ["proposal-one", "proposal-two"])
            self.assertIn("stage=binding", diagnostic.output[0])
            self.assertIn("stage=budget", diagnostic.output[1])
            with app.inbox.connect() as db:
                self.assertEqual(
                    db.execute(
                        "SELECT body,state,attempts FROM jobs WHERE id='proposal-one'"
                    ).fetchone(),
                    (original, "prepared", MAXIMUM_ATTEMPTS),
                )

    def test_global_contract_configuration_and_persistence_failures_still_escape(self):
        for fault in ("contract", "credential", "persistence", "stored-body"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as root:
                app = ReceiptRecoveryTests().app(root)
                app.messages = SimpleNamespace(submit=lambda *_: {"kind": "complete"})
                if fault == "contract":
                    target, member, error = (
                        app.registry,
                        "registry_contract",
                        RuntimeError("canary startup refusal"),
                    )
                elif fault == "credential":
                    target, member, error = (
                        app.tokens["messaging"],
                        "bearer_token",
                        CompositionError("credential could not be read"),
                    )
                elif fault == "persistence":
                    target, member, error = (
                        app.inbox,
                        "consume",
                        sqlite3.OperationalError("canary persistence refusal"),
                    )
                else:
                    with app.inbox.connect() as db:
                        db.execute("UPDATE jobs SET body='{'")
                    with (
                        patch("service.LOG.error") as diagnostic,
                        self.assertRaises(json.JSONDecodeError),
                    ):
                        app.reconcile()
                    diagnostic.assert_not_called()
                    continue
                with (
                    patch.object(target, member, side_effect=error),
                    patch("service.LOG.error") as diagnostic,
                    self.assertRaises(type(error)),
                ):
                    app.reconcile()
                diagnostic.assert_not_called()

    def test_confirmed_apply_uses_the_last_attempt_without_submitting_a_notice(self):
        with tempfile.TemporaryDirectory() as root:
            app = ReceiptRecoveryTests().app(root)
            with app.inbox.connect() as db:
                db.execute("UPDATE jobs SET attempts=?", (MAXIMUM_ATTEMPTS - 1,))
            reads, executions, submits = [], [], []

            def current(*_):
                reads.append(True)
                return SimpleNamespace(
                    document={
                        "state": "submitted" if len(reads) == 1 else "applied",
                        "submissionVersion": 1,
                        "effectDigest": "sha256:" + "a" * 64,
                    }
                )

            app.registry.get_proposal = current
            app.registry.prepare_proposal = lambda *_: "prepared-apply"
            app.registry.execute_proposal = lambda prepared: executions.append(prepared)
            app.messages = SimpleNamespace(submit=lambda *args: submits.append(args))
            with patch("service.LOG.error") as diagnostic:
                completed = app.reconcile()
            with app.inbox.connect() as db:
                self.assertEqual(
                    db.execute("SELECT state,attempts FROM jobs").fetchone(),
                    ("prepared", MAXIMUM_ATTEMPTS),
                )
            self.assertEqual(completed, 0)
            self.assertEqual(executions, ["prepared-apply"])
            self.assertEqual(submits, [])
            diagnostic.assert_called_once()
            self.assertIn(
                "stage=budget",
                diagnostic.call_args.args[0] % diagnostic.call_args.args[1:],
            )

    def test_native_uncertain_or_conflicting_notices_keep_original_receipt_recovery(
        self,
    ):
        cases = (
            (False, "idempotency.expired"),
            (False, "idempotency.key-reused"),
            (True, "transport.failed"),
        )
        for unknown, code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as root:
                app = ReceiptRecoveryTests().app(root)
                error = messaging.MessagingClientError("canary private notice failure")
                error.outcome_unknown, error.code = unknown, code
                submits, receipts = [], []

                def submit(*args):
                    submits.append(args)
                    raise error

                def receipt(*args):
                    receipts.append(args)
                    return {"kind": "complete", "value": {"id": "message-one"}}

                app.messages = SimpleNamespace(submit=submit, message_receipt=receipt)
                with self.assertLogs("python-composition", level="ERROR") as diagnostic:
                    self.assertEqual(app.reconcile(), 0)
                self.assertIn("stage=submit", diagnostic.output[0])
                self.assertNotIn("canary private notice failure", diagnostic.output[0])
                with app.inbox.connect() as db:
                    self.assertEqual(
                        db.execute("SELECT state,attempts FROM jobs").fetchone(),
                        ("notice-uncertain", 1),
                    )
                    db.execute("UPDATE jobs SET attempts=?", (MAXIMUM_ATTEMPTS,))
                self.assertEqual(app.reconcile(), 1)
                self.assertEqual(len(submits), 1)
                self.assertEqual(receipts, submits)
                self.assertEqual(app.inbox.jobs(), [])

    def test_failed_attempt_persistence_is_not_downgraded_to_a_job_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            app = ReceiptRecoveryTests().app(root)
            app.messages = SimpleNamespace(submit=lambda *_: {"kind": "complete"})
            with app.inbox.connect() as db:
                db.execute(
                    "CREATE TRIGGER refuse_attempt BEFORE UPDATE OF attempts ON jobs "
                    "BEGIN SELECT RAISE(ABORT, 'canary durable write failure'); END"
                )
            with (
                patch.object(
                    app.registry,
                    "get_proposal",
                    side_effect=RuntimeError("canary private remote failure"),
                ),
                patch("service.LOG.error") as diagnostic,
                self.assertRaises(sqlite3.IntegrityError),
            ):
                app.reconcile()
            diagnostic.assert_not_called()
            with app.inbox.connect() as db:
                self.assertEqual(
                    db.execute("SELECT state,attempts FROM jobs").fetchone(),
                    ("prepared", 0),
                )
