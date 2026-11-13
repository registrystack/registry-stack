from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import os
import stat
import sys
import tempfile
import threading
import unittest


EXAMPLE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE))

from effect import (  # noqa: E402
    CommandConflict,
    MessageEffect,
    MessageEffectStore,
    MessagingTargets,
)


@dataclass(frozen=True)
class Context:
    subject: str
    issuer: str = "https://issuer.example.invalid/"
    resource: str = "urn:registry:python:test"
    client_id: str = "coordinator-client"
    profile: str = "coordinator-invoker"
    persona: str = "service"


@dataclass(frozen=True)
class Authority:
    fingerprint: str
    product: str = "messaging"


class SyntheticProcessStop(BaseException):
    pass


class FakeMessagingError(Exception):
    def __init__(
        self,
        code: str,
        *,
        status: int | None,
        outcome_unknown: bool,
        kind: str = "problem",
    ) -> None:
        super().__init__("synthetic Messaging error")
        self.code = code
        self.status = status
        self.outcome_unknown = outcome_unknown
        self.kind = kind


class FakeMessaging:
    def __init__(self, effects=None) -> None:
        self.effects = {} if effects is None else effects
        self.submit_calls = []
        self.receipt_calls = []
        self.submit_error: BaseException | None = None
        self.receipt_error: Exception | None = None
        self.stop_after_accept = False
        self.entered = threading.Event()
        self.release = threading.Event()
        self.block = False

    def submit(self, key, message):
        self.submit_calls.append((key, message))
        receipt = {
            "kind": "complete",
            "value": {
                "id": f"message-{len(self.effects) + 1}",
                "status": "queued",
                "links": {"self": "/message", "cancel": "/cancel"},
            },
            "trace_id": "trace-canary",
        }
        self.effects[key] = (message, receipt)
        self.entered.set()
        if self.block:
            self.release.wait(timeout=5)
        if self.stop_after_accept:
            raise SyntheticProcessStop()
        if self.submit_error is not None:
            raise self.submit_error
        return receipt

    def message_receipt(self, key, message):
        self.receipt_calls.append((key, message))
        if self.receipt_error is not None:
            raise self.receipt_error
        original, receipt = self.effects[key]
        if original != message:
            raise AssertionError("recovery request changed")
        return receipt


class FakeStack:
    def __init__(
        self, default, named=None, *, authority=None, authorities=None
    ) -> None:
        self.messaging = default
        self.named = {} if named is None else named
        self.default_authority = authority or Authority("a" * 64)
        self.authorities = {} if authorities is None else authorities
        self.selections = []

    def authority(self, product):
        if product != "messaging":
            raise AssertionError("unexpected product")
        return self.default_authority

    def using(self, name):
        self.selections.append(name)
        return type(
            "Bound",
            (),
            {
                "messaging": self.named[name],
                "authority": self.authorities.get(name, self.default_authority),
            },
        )()


def authority_fingerprint(
    *,
    subject: str = "notice-service",
    client_id: str = "notice-client",
    profile: str = "service-sender",
    claims: dict[str, object] | None = None,
) -> str:
    identity = {
        "claims": claims or {"registry_actor_kind": "service"},
        "clientId": client_id,
        "issuer": "https://issuer.example.invalid/",
        "product": "messaging",
        "profile": profile,
        "resource": "urn:registry:messaging:test",
        "scopes": ["messaging:send"],
        "subject": subject,
    }
    encoded = json.dumps(
        identity, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(
        b"registry-stack-workload-authority/v1\0" + encoded
    ).hexdigest()


def message(recipient: str, *, version: str = "1") -> dict[str, object]:
    return {
        "senderProfile": "service-notices",
        "to": {"email": recipient},
        "template": {"id": "renewal", "version": version},
        "locale": "en",
        "data": {"name": "Synthetic Person"},
    }


class MessageEffectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "effects.sqlite3"
        self.store = MessageEffectStore(self.database)
        self.store.migrate()
        self.context = Context("caller-a")
        self.messaging = FakeMessaging()
        self.targets = MessagingTargets(FakeStack(self.messaging), {"a" * 64: None})
        self.audit = []
        self.effect = MessageEffect(
            self.store,
            self.targets,
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"A" * 32,
            audit_sink=self.audit.append,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def seed(
        self,
        notice_id: str,
        payload: dict[str, object],
        *,
        context: Context | None = None,
        authority: str = "a" * 64,
    ) -> None:
        self.store.put_notice(
            context or self.context,
            notice_id,
            authority,
            payload,
            service_namespace="urn:example:service:renewal-notices",
        )

    def test_submit_uses_only_the_protected_request_and_derived_key(self) -> None:
        payload = message("person@example.invalid")
        self.seed("notice-1", payload)

        result = self.effect.execute(self.context, "command-1", "notice-1")

        self.assertEqual(result.status, 200)
        self.assertEqual(result.body["state"], "accepted")
        self.assertEqual(len(self.messaging.submit_calls), 1)
        downstream_key, sent = self.messaging.submit_calls[0]
        self.assertEqual(len(downstream_key), 64)
        self.assertEqual(sent, payload)
        self.assertNotIn("token", repr(self.messaging.submit_calls))

    def test_audit_correlates_caller_authority_recovery_and_outcome_without_values(
        self,
    ) -> None:
        self.seed("notice-1", message("recipient-canary@example.invalid"))

        accepted = self.effect.execute(self.context, "command-1", "notice-1")
        repeated = self.effect.execute(self.context, "command-1", "notice-1")

        self.assertEqual(accepted, repeated)
        self.assertEqual(len(self.audit), 2)
        self.assertEqual(self.audit[0], self.audit[1])
        self.assertEqual(
            set(self.audit[0]),
            {"operation", "caller", "authority", "recovery", "outcome"},
        )
        self.assertEqual(self.audit[0]["operation"], "registry-messaging.submit/v1")
        self.assertEqual(self.audit[0]["authority"], "a" * 64)
        self.assertEqual(self.audit[0]["recovery"], accepted.body["recovery"])
        self.assertEqual(self.audit[0]["outcome"], "accepted")
        self.assertRegex(self.audit[0]["caller"], r"\Ahmac-sha256:[0-9a-f]{64}\Z")
        encoded = json.dumps(self.audit)
        for canary in (
            "recipient-canary",
            "Synthetic Person",
            "caller-a",
            "command-1",
            "renewal",
        ):
            self.assertNotIn(canary, encoded)

        rotated = []
        MessageEffect(
            self.store,
            self.targets,
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"B" * 32,
            audit_sink=rotated.append,
        ).execute(self.context, "command-1", "notice-1")
        self.assertNotEqual(self.audit[0]["caller"], rotated[0]["caller"])
        self.assertEqual(self.audit[0]["recovery"], rotated[0]["recovery"])

    def test_audit_covers_conflict_refusal_unknown_recovery_and_busy(self) -> None:
        self.seed("notice-1", message("one@example.invalid"))
        self.seed("notice-2", message("two@example.invalid"))
        self.effect.execute(self.context, "command-1", "notice-1")
        with self.assertRaises(CommandConflict):
            self.effect.execute(self.context, "command-1", "notice-2")
        self.messaging.submit_error = FakeMessagingError(
            "template.not-found", status=422, outcome_unknown=False
        )
        self.effect.execute(self.context, "command-2", "notice-2")
        self.messaging.submit_error = FakeMessagingError(
            "exception-message-canary", status=503, outcome_unknown=True
        )
        self.effect.execute(self.context, "command-3", "notice-2")
        self.messaging.submit_error = None
        self.effect.execute(self.context, "command-3", "notice-2")

        self.assertEqual(
            [event["outcome"] for event in self.audit],
            ["accepted", "conflict", "refused", "uncertain", "accepted"],
        )
        self.assertNotIn("exception-message-canary", json.dumps(self.audit))

    def test_default_audit_logger_outputs_only_correlation_fields(self) -> None:
        self.seed("notice-1", message("recipient-canary@example.invalid"))
        effect = MessageEffect(
            self.store,
            self.targets,
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"A" * 32,
        )

        with self.assertLogs("registry.message_effect", level="INFO") as captured:
            effect.execute(self.context, "command-1", "notice-1")

        event = json.loads(captured.records[0].getMessage())
        self.assertEqual(event["outcome"], "accepted")
        self.assertEqual(event["authority"], "a" * 64)
        self.assertNotIn("recipient-canary", captured.output[0])

    def test_audit_sink_failure_is_visible_and_recovery_does_not_resubmit(self) -> None:
        self.seed("notice-1", message("person@example.invalid"))

        def unavailable_audit(_event):
            raise RuntimeError("audit sink unavailable")

        failing = MessageEffect(
            self.store,
            self.targets,
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"A" * 32,
            audit_sink=unavailable_audit,
        )
        with self.assertRaisesRegex(RuntimeError, "audit sink unavailable"):
            failing.execute(self.context, "command-1", "notice-1")

        recovered = self.effect.execute(self.context, "command-1", "notice-1")
        self.assertEqual(recovered.body["state"], "accepted")
        self.assertEqual(len(self.messaging.submit_calls), 1)
        self.assertEqual(self.audit[0]["outcome"], "accepted")

    def test_store_is_owner_only_and_protected_notices_are_immutable(self) -> None:
        self.assertEqual(stat.S_IMODE(self.database.stat().st_mode), 0o600)
        self.seed("notice-1", message("one@example.invalid"))
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.seed("notice-1", message("two@example.invalid"))

        os.chmod(self.database, 0o640)
        with self.assertRaisesRegex(PermissionError, "owner-only"):
            MessageEffectStore(self.database).migrate()

    def test_same_caller_key_with_changed_work_conflicts_without_an_effect(
        self,
    ) -> None:
        self.seed("notice-1", message("one@example.invalid"))
        self.seed("notice-2", message("two@example.invalid"))
        self.effect.execute(self.context, "command-1", "notice-1")

        with self.assertRaises(CommandConflict):
            self.effect.execute(self.context, "command-1", "notice-2")

        self.assertEqual(len(self.messaging.submit_calls), 1)
        self.assertEqual(len(self.messaging.receipt_calls), 0)

    def test_two_callers_using_the_same_input_key_have_separate_effects(self) -> None:
        other = Context("caller-b")
        self.seed("notice-1", message("one@example.invalid"))
        self.seed(
            "notice-1",
            message("two@example.invalid"),
            context=other,
        )

        first = self.effect.execute(self.context, "same-key", "notice-1")
        second = self.effect.execute(other, "same-key", "notice-1")

        self.assertEqual(first.status, 200)
        self.assertEqual(second.status, 200)
        keys = [call[0] for call in self.messaging.submit_calls]
        self.assertEqual(len(set(keys)), 2)

    def test_issuer_and_resource_changes_separate_protected_effects(self) -> None:
        other = Context(
            "caller-a",
            issuer="https://other-issuer.example.invalid/",
            resource="urn:registry:python:other",
        )
        self.seed("notice-1", message("one@example.invalid"))
        self.seed("notice-1", message("two@example.invalid"), context=other)

        first = self.effect.execute(self.context, "same-key", "notice-1")
        second = self.effect.execute(other, "same-key", "notice-1")

        self.assertEqual(first.status, 200)
        self.assertEqual(second.status, 200)
        self.assertEqual(len({call[0] for call in self.messaging.submit_calls}), 2)

    def test_process_stop_after_acceptance_recovers_without_resubmission(self) -> None:
        payload = message("person@example.invalid")
        original = json.loads(json.dumps(payload))
        self.seed("notice-1", payload)
        self.messaging.stop_after_accept = True

        with self.assertRaises(SyntheticProcessStop):
            self.effect.execute(self.context, "command-1", "notice-1")

        payload["to"] = {"email": "changed@example.invalid"}
        payload["template"] = {"id": "renewal", "version": "2"}
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.seed("notice-1", payload)

        recovered_client = FakeMessaging(self.messaging.effects)
        restarted = MessageEffect(
            MessageEffectStore(self.database),
            MessagingTargets(FakeStack(recovered_client), {"a" * 64: None}),
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"A" * 32,
        )
        result = restarted.execute(self.context, "command-1", "notice-1")

        self.assertEqual(result.status, 200)
        self.assertEqual(result.body["state"], "accepted")
        self.assertEqual(recovered_client.submit_calls, [])
        self.assertEqual(len(recovered_client.receipt_calls), 1)
        self.assertEqual(recovered_client.receipt_calls[0][1], original)

    def test_unknown_reply_uses_receipt_recovery_and_never_submit_again(self) -> None:
        self.seed("notice-1", message("person@example.invalid"))
        self.messaging.submit_error = FakeMessagingError(
            "service.unavailable", status=503, outcome_unknown=True
        )

        unknown = self.effect.execute(self.context, "command-1", "notice-1")
        self.messaging.submit_error = None
        recovered = self.effect.execute(self.context, "command-1", "notice-1")

        self.assertEqual(unknown.status, 202)
        self.assertEqual(unknown.body["state"], "uncertain")
        self.assertEqual(recovered.status, 200)
        self.assertEqual(len(self.messaging.submit_calls), 1)
        self.assertEqual(len(self.messaging.receipt_calls), 1)

    def test_later_denial_or_expired_receipt_keeps_the_outcome_uncertain(self) -> None:
        self.seed("notice-1", message("person@example.invalid"))
        self.messaging.submit_error = FakeMessagingError(
            "service.unavailable", status=503, outcome_unknown=True
        )
        self.effect.execute(self.context, "command-1", "notice-1")
        self.messaging.submit_error = None

        for code, status in [
            ("operation.not-authorized", 403),
            ("receipt.unresolved", 409),
        ]:
            with self.subTest(code=code):
                self.messaging.receipt_error = FakeMessagingError(
                    code, status=status, outcome_unknown=False
                )
                result = self.effect.execute(self.context, "command-1", "notice-1")
                self.assertEqual(result.status, 202)
                self.assertEqual(result.body["state"], "uncertain")

        self.assertEqual(len(self.messaging.submit_calls), 1)

    def test_declared_no_effect_problem_is_terminal_and_not_retried(self) -> None:
        self.seed("notice-1", message("person@example.invalid"))
        self.messaging.submit_error = FakeMessagingError(
            "template.not-found", status=422, outcome_unknown=False
        )

        refused = self.effect.execute(self.context, "command-1", "notice-1")
        repeated = self.effect.execute(self.context, "command-1", "notice-1")

        self.assertEqual(refused.status, 422)
        self.assertEqual(
            refused.body, {"state": "refused", "code": "template.not-found"}
        )
        self.assertEqual(repeated, refused)
        self.assertEqual(len(self.messaging.submit_calls), 1)
        self.assertEqual(self.messaging.receipt_calls, [])

    def test_missing_authority_binding_is_uncertain_until_exact_binding_returns(
        self,
    ) -> None:
        self.seed("notice-1", message("person@example.invalid"), authority="b" * 64)

        result = self.effect.execute(self.context, "command-1", "notice-1")

        self.assertEqual(result.status, 202)
        self.assertEqual(result.body["state"], "uncertain")
        self.assertRegex(result.body["recovery"], r"\A[0-9a-f]{64}\Z")
        self.assertEqual(self.messaging.submit_calls, [])
        self.assertEqual(self.messaging.receipt_calls, [])

        restored_client = FakeMessaging()
        restored = MessageEffect(
            MessageEffectStore(self.database),
            MessagingTargets(
                FakeStack(restored_client, authority=Authority("b" * 64)),
                {"b" * 64: None},
            ),
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"A" * 32,
        ).execute(self.context, "command-1", "notice-1")

        self.assertEqual(restored.status, 200)
        self.assertEqual(restored.body["recovery"], result.body["recovery"])
        self.assertEqual(len(restored_client.submit_calls), 1)

    def test_product_403_is_terminal_without_identity_fallback(self) -> None:
        primary = FakeMessaging()
        secondary = FakeMessaging()
        primary.submit_error = FakeMessagingError(
            "operation.not-authorized", status=403, outcome_unknown=False
        )
        stack = FakeStack(
            primary,
            {"secondary": secondary},
            authority=Authority("a" * 64),
            authorities={"secondary": Authority("b" * 64)},
        )
        effect = MessageEffect(
            self.store,
            MessagingTargets(
                stack,
                {"a" * 64: None, "b" * 64: "secondary"},
            ),
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"A" * 32,
        )
        self.seed("notice-1", message("person@example.invalid"))

        refused = effect.execute(self.context, "command-1", "notice-1")
        repeated = effect.execute(self.context, "command-1", "notice-1")

        self.assertEqual(refused.status, 422)
        self.assertEqual(
            refused.body,
            {"state": "refused", "code": "operation.not-authorized"},
        )
        self.assertEqual(repeated, refused)
        self.assertEqual(len(primary.submit_calls), 1)
        self.assertEqual(primary.receipt_calls, [])
        self.assertEqual(secondary.submit_calls, [])
        self.assertEqual(secondary.receipt_calls, [])
        self.assertEqual(stack.selections, ["secondary"])

    def test_alias_can_change_for_same_authority_but_authority_cannot_change(
        self,
    ) -> None:
        self.seed("notice-1", message("person@example.invalid"))
        self.messaging.submit_error = FakeMessagingError(
            "service.unavailable", status=503, outcome_unknown=True
        )
        self.effect.execute(self.context, "command-1", "notice-1")
        self.seed("notice-2", message("other@example.invalid"))
        second_unknown = self.effect.execute(self.context, "command-2", "notice-2")
        self.assertEqual(second_unknown.status, 202)

        renamed_client = FakeMessaging(self.messaging.effects)
        renamed_stack = FakeStack(FakeMessaging(), {"renamed": renamed_client})
        renamed = MessageEffect(
            MessageEffectStore(self.database),
            MessagingTargets(renamed_stack, {"a" * 64: "renamed"}),
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"A" * 32,
        )
        recovered = renamed.execute(self.context, "command-1", "notice-1")
        self.assertEqual(recovered.status, 200)
        self.assertEqual(renamed_stack.selections, ["renamed", "renamed"])
        self.assertEqual(renamed_client.submit_calls, [])

        unavailable_client = FakeMessaging()
        changed = Authority("b" * 64)
        unavailable = MessageEffect(
            MessageEffectStore(self.database),
            MessagingTargets(
                FakeStack(
                    unavailable_client,
                    {"renamed": unavailable_client},
                    authorities={"renamed": changed},
                ),
                {"b" * 64: "renamed"},
            ),
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"A" * 32,
        )
        no_authority = unavailable.execute(self.context, "command-2", "notice-2")
        self.assertEqual(no_authority.status, 202)
        self.assertEqual(no_authority.body["state"], "uncertain")
        self.assertEqual(unavailable_client.submit_calls, [])

        with self.assertRaisesRegex(ValueError, "fingerprint"):
            MessagingTargets(
                FakeStack(
                    unavailable_client,
                    {"renamed": unavailable_client},
                    authorities={"renamed": changed},
                ),
                {"a" * 64: "renamed"},
            )
        self.assertEqual(unavailable_client.submit_calls, [])

    def test_subject_client_profile_or_claim_change_cannot_recover_old_unknown_command(
        self,
    ) -> None:
        original = authority_fingerprint()
        payload = message("person@example.invalid")
        self.seed("notice-authority", payload, authority=original)
        original_client = FakeMessaging()
        original_client.submit_error = FakeMessagingError(
            "service.unavailable", status=503, outcome_unknown=True
        )
        original_effect = MessageEffect(
            MessageEffectStore(self.database),
            MessagingTargets(
                FakeStack(original_client, authority=Authority(original)),
                {original: None},
            ),
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"A" * 32,
        )
        unknown = original_effect.execute(
            self.context, "command-authority", "notice-authority"
        )
        self.assertEqual(unknown.status, 202)

        changes = {
            "subject": authority_fingerprint(subject="other-service"),
            "client": authority_fingerprint(client_id="other-client"),
            "profile": authority_fingerprint(profile="other-sender"),
            "claims": authority_fingerprint(claims={"registry_actor_kind": "human"}),
        }
        for field, changed in changes.items():
            with self.subTest(field=field):
                changed_client = FakeMessaging(original_client.effects)
                changed_effect = MessageEffect(
                    MessageEffectStore(self.database),
                    MessagingTargets(
                        FakeStack(changed_client, authority=Authority(changed)),
                        {changed: None},
                    ),
                    service_namespace="urn:example:service:renewal-notices",
                    audit_key=b"A" * 32,
                )
                unresolved = changed_effect.execute(
                    self.context, "command-authority", "notice-authority"
                )
                self.assertEqual(unresolved.status, 202)
                self.assertEqual(unresolved.body["state"], "uncertain")
                self.assertEqual(changed_client.submit_calls, [])

    def test_concurrent_duplicate_has_one_submit(self) -> None:
        self.seed("notice-1", message("person@example.invalid"))
        self.messaging.block = True

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(
                self.effect.execute, self.context, "command-1", "notice-1"
            )
            self.assertTrue(self.messaging.entered.wait(timeout=2))
            second = pool.submit(
                self.effect.execute, self.context, "command-1", "notice-1"
            )
            self.messaging.release.set()
            results = [first.result(timeout=2), second.result(timeout=2)]

        self.assertEqual(len(self.messaging.submit_calls), 1)
        self.assertEqual({result.status for result in results}, {200})

    def test_429_is_only_returned_before_a_new_effect_starts(self) -> None:
        second_client = FakeMessaging()
        second_client.block = True
        audit = []
        effect = MessageEffect(
            self.store,
            MessagingTargets(FakeStack(second_client), {"a" * 64: None}),
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"A" * 32,
            maximum_inflight_submissions=1,
            audit_sink=audit.append,
        )
        self.seed("notice-1", message("one@example.invalid"))
        self.seed("notice-2", message("two@example.invalid"))

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(effect.execute, self.context, "command-1", "notice-1")
            self.assertTrue(second_client.entered.wait(timeout=2))
            busy = effect.execute(self.context, "command-2", "notice-2")
            second_client.release.set()
            accepted = first.result(timeout=2)

        self.assertEqual(busy.status, 429)
        self.assertEqual(busy.body, {"state": "not-processed", "code": "busy"})
        self.assertEqual(accepted.status, 200)
        self.assertEqual(len(second_client.submit_calls), 1)
        self.assertEqual(
            sorted(event["outcome"] for event in audit),
            ["accepted", "not-processed"],
        )


if __name__ == "__main__":
    unittest.main()
