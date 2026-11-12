from __future__ import annotations

from contextlib import redirect_stderr
import importlib
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


EXAMPLE = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
CLIENT_SOURCE = (
    Path(__file__).resolve().parents[5]
    / "crates/registry-stack-client-py/python/registry_client"
)
sys.path.insert(0, str(EXAMPLE))
sys.path.insert(0, str(TESTS))

from effect import MessageEffectStore  # noqa: E402
from service import create_app, create_app_from_environment  # noqa: E402

from test_effect import Authority, FakeMessaging, FakeMessagingError, message  # noqa: E402


def load_client_module(name: str):
    package_name = "_python_machine_service_client_test"
    package = sys.modules.get(package_name)
    if package is None:
        package = types.ModuleType(package_name)
        package.__path__ = [str(CLIENT_SOURCE)]
        sys.modules[package_name] = package
    return importlib.import_module(f"{package_name}.{name}")


machine = load_client_module("machine")
flask_adapter = load_client_module("flask_adapter")


class Stack:
    def __init__(self) -> None:
        self.primary = FakeMessaging()
        self.secondary = FakeMessaging()
        self.messaging = self.primary
        self.admission_calls = []
        self.selections = []
        self.primary_authority = Authority("a" * 64)
        self.secondary_authority = Authority("b" * 64)

    def admit(self, values):
        self.admission_calls.append(values)
        headers = values.get("authorization")
        if headers == ["Bearer caller-a"]:
            return machine.MachineContext(
                "caller-a",
                "coordinator-client",
                "coordinator-invoker",
                "https://issuer.example.invalid/",
                "urn:registry:python:test",
            )
        if headers == ["Bearer caller-b"]:
            return machine.MachineContext(
                "caller-b",
                "coordinator-client",
                "coordinator-invoker",
                "https://issuer.example.invalid/",
                "urn:registry:python:test",
            )
        raise machine.AdmissionError()

    def using(self, name):
        self.selections.append(name)
        if name != "secondary":
            raise AssertionError("unexpected binding")
        return type(
            "Bound",
            (),
            {"messaging": self.secondary, "authority": self.secondary_authority},
        )()

    def authority(self, product):
        if product != "messaging":
            raise AssertionError("unexpected product")
        return self.primary_authority


class MachineServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "effects.sqlite3"
        self.stack = Stack()
        self.connect_calls = 0

        registry_client = types.ModuleType("registry_client")

        def connect():
            self.connect_calls += 1
            return self.stack

        registry_client.connect = connect
        registry_client.flask_adapter = flask_adapter
        self.prior_registry_client = sys.modules.get("registry_client")
        sys.modules["registry_client"] = registry_client

        self.audit = []
        self.app = create_app(
            database_path=self.database,
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"A" * 32,
            audit_sink=self.audit.append,
            targets={
                "a" * 64: None,
                "b" * 64: "secondary",
            },
        )
        self.app.testing = True
        self.client = self.app.test_client()
        self.store: MessageEffectStore = self.app.extensions[
            "registry_message_effect_store"
        ]
        self.context = machine.MachineContext(
            "caller-a",
            "coordinator-client",
            "coordinator-invoker",
            "https://issuer.example.invalid/",
            "urn:registry:python:test",
        )

    def test_factory_rejects_short_audit_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "audit_key must be 32 bytes"):
            create_app(
                database_path=self.database,
                service_namespace="urn:example:service:renewal-notices",
                audit_key=b"short",
                audit_sink=self.audit.append,
                targets={"a" * 64: None},
                stack=self.stack,
            )

    def test_environment_factory_requires_a_bounded_audit_key(self) -> None:
        settings = {
            "MESSAGE_EFFECT_DATABASE": str(self.database),
            "MESSAGE_EFFECT_SERVICE_NAMESPACE": "urn:example:service:renewal-notices",
            "MESSAGE_EFFECT_TARGETS": json.dumps({"a" * 64: None}),
        }
        with patch.dict(os.environ, settings, clear=True):
            with self.assertRaisesRegex(RuntimeError, "AUDIT_KEY_HEX.*required"):
                create_app_from_environment()
            os.environ["MESSAGE_EFFECT_AUDIT_KEY_HEX"] = "invalid-key-canary"
            with self.assertRaisesRegex(RuntimeError, "64 hexadecimal") as caught:
                create_app_from_environment()
            self.assertNotIn("invalid-key-canary", str(caught.exception))
            os.environ["MESSAGE_EFFECT_AUDIT_KEY_HEX"] = "a" * 64
            app = create_app_from_environment()
        self.assertIn("registry_message_effect_store", app.extensions)

    def test_environment_factory_writes_bounded_audit_to_stderr(self) -> None:
        settings = {
            "MESSAGE_EFFECT_DATABASE": str(self.database),
            "MESSAGE_EFFECT_SERVICE_NAMESPACE": "urn:example:service:renewal-notices",
            "MESSAGE_EFFECT_TARGETS": json.dumps({"a" * 64: None}),
            "MESSAGE_EFFECT_AUDIT_KEY_HEX": "a" * 64,
        }
        self.seed("notice-1", message("recipient-canary@example.invalid"))
        with patch.dict(os.environ, settings, clear=True):
            app = create_app_from_environment()
        app.testing = True
        with redirect_stderr(StringIO()) as captured:
            response = app.test_client().post(
                "/v1/message-effects",
                json={"key": "command-1", "noticeId": "notice-1"},
                headers={"Authorization": "Bearer caller-a"},
            )
        self.assertEqual(response.status_code, 200)
        event = json.loads(captured.getvalue())
        self.assertEqual(event["outcome"], "accepted")
        self.assertEqual(event["authority"], "a" * 64)
        self.assertRegex(event["caller"], r"\Ahmac-sha256:[0-9a-f]{64}\Z")
        self.assertNotIn("recipient-canary", captured.getvalue())

    def test_http_audit_failure_is_visible_and_same_command_recovers(self) -> None:
        self.seed("notice-1", message("person@example.invalid"))

        def unavailable_audit(_event):
            raise RuntimeError("audit sink unavailable")

        failing = create_app(
            database_path=self.database,
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"A" * 32,
            audit_sink=unavailable_audit,
            targets={"a" * 64: None},
            stack=self.stack,
        )
        failing.testing = True
        with self.assertRaisesRegex(RuntimeError, "audit sink unavailable"):
            failing.test_client().post(
                "/v1/message-effects",
                json={"key": "command-1", "noticeId": "notice-1"},
                headers={"Authorization": "Bearer caller-a"},
            )

        recovered = self.post({"key": "command-1", "noticeId": "notice-1"})
        self.assertEqual(recovered.status_code, 200)
        self.assertEqual(len(self.stack.primary.submit_calls), 1)
        self.assertEqual(self.audit[0]["outcome"], "accepted")

    def tearDown(self) -> None:
        if self.prior_registry_client is None:
            sys.modules.pop("registry_client", None)
        else:
            sys.modules["registry_client"] = self.prior_registry_client
        self.temporary.cleanup()

    def seed(self, notice_id, payload, authority="a" * 64):
        self.store.put_notice(
            self.context,
            notice_id,
            authority,
            payload,
            service_namespace="urn:example:service:renewal-notices",
        )

    def post(self, body, *, bearer="caller-a"):
        return self.client.post(
            "/v1/message-effects",
            json=body,
            headers={"Authorization": f"Bearer {bearer}"},
        )

    def test_factory_uses_connect_and_flask_machine_admission(self) -> None:
        self.seed("notice-1", message("person@example.invalid"))

        response = self.post({"key": "command-1", "noticeId": "notice-1"})

        self.assertEqual(self.connect_calls, 1)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["state"], "accepted")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(
            self.stack.admission_calls[-1],
            {"authorization": ["Bearer caller-a"]},
        )

    def test_cookie_or_missing_bearer_cannot_reach_the_effect(self) -> None:
        self.seed("notice-1", message("person@example.invalid"))

        missing = self.client.post(
            "/v1/message-effects",
            json={"key": "command-1", "noticeId": "notice-1"},
        )
        cookie = self.client.post(
            "/v1/message-effects",
            json={"key": "command-1", "noticeId": "notice-1"},
            headers={"Cookie": "session=canary"},
        )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(cookie.status_code, 401)
        self.assertEqual(self.stack.primary.submit_calls, [])

    def test_request_cannot_select_binding_url_scope_recipient_or_token(self) -> None:
        self.seed("notice-1", message("protected@example.invalid"))
        base = {"key": "command-1", "noticeId": "notice-1"}

        for field, value in [
            ("binding", "secondary"),
            ("url", "https://other.example.invalid"),
            ("scope", "admin"),
            ("recipient", "substitute@example.invalid"),
            ("token", "secret-canary"),
        ]:
            with self.subTest(field=field):
                response = self.post({**base, field: value})
                self.assertEqual(response.status_code, 422)

        self.assertEqual(self.stack.primary.submit_calls, [])
        self.assertEqual(self.stack.secondary.submit_calls, [])

    def test_duplicate_or_oversized_json_is_refused_before_the_effect(self) -> None:
        self.seed("notice-1", message("protected@example.invalid"))
        headers = {"Authorization": "Bearer caller-a"}
        duplicate = self.client.post(
            "/v1/message-effects",
            data='{"key":"first","key":"second","noticeId":"notice-1"}',
            content_type="application/json",
            headers=headers,
        )
        oversized = self.client.post(
            "/v1/message-effects",
            data=json.dumps(
                {
                    "key": "command-1",
                    "noticeId": "notice-1",
                    "padding": "x" * 5000,
                }
            ),
            content_type="application/json",
            headers=headers,
        )

        self.assertEqual(duplicate.status_code, 422)
        self.assertEqual(oversized.status_code, 422)
        self.assertEqual(self.stack.primary.submit_calls, [])

    def test_protected_state_selects_default_and_named_bindings(self) -> None:
        self.seed("primary", message("one@example.invalid"))
        self.seed(
            "secondary",
            message("two@example.invalid"),
            "b" * 64,
        )

        first = self.post({"key": "command-1", "noticeId": "primary"})
        second = self.post({"key": "command-2", "noticeId": "secondary"})

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(len(self.stack.primary.submit_calls), 1)
        self.assertEqual(len(self.stack.secondary.submit_calls), 1)
        self.assertEqual(self.stack.selections, ["secondary", "secondary"])

    def test_changed_command_is_uncertain_for_coordinator_not_declared_refused(
        self,
    ) -> None:
        self.seed("notice-1", message("one@example.invalid"))
        self.seed("notice-2", message("two@example.invalid"))
        self.post({"key": "same-key", "noticeId": "notice-1"})

        conflict = self.post({"key": "same-key", "noticeId": "notice-2"})

        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json["state"], "uncertain")
        self.assertEqual(len(self.stack.primary.submit_calls), 1)

    def test_http_contract_distinguishes_declared_refusal_and_uncertainty(self) -> None:
        self.seed("refused", message("one@example.invalid"))
        self.stack.primary.submit_error = FakeMessagingError(
            "template.not-found", status=422, outcome_unknown=False
        )
        refused = self.post({"key": "command-1", "noticeId": "refused"})

        self.seed("unknown", message("two@example.invalid"))
        self.stack.primary.submit_error = FakeMessagingError(
            "service.unavailable", status=503, outcome_unknown=True
        )
        uncertain = self.post({"key": "command-2", "noticeId": "unknown"})

        self.assertEqual(refused.status_code, 422)
        self.assertEqual(
            refused.json,
            {"state": "refused", "code": "template.not-found"},
        )
        self.assertEqual(uncertain.status_code, 202)
        self.assertEqual(uncertain.json["state"], "uncertain")
        self.assertIn("recovery", uncertain.json)

    def test_response_encoding_failure_recovers_committed_acceptance(self) -> None:
        self.seed("notice-1", message("person@example.invalid"))
        original_dumps = self.app.json.dumps

        def fail_accepted(value, **kwargs):
            if isinstance(value, dict) and value.get("state") == "accepted":
                raise UnicodeError("synthetic response encoding failure")
            return original_dumps(value, **kwargs)

        self.app.json.dumps = fail_accepted
        with self.assertRaisesRegex(UnicodeError, "response encoding failure"):
            self.client.post(
                "/v1/message-effects",
                data=json.dumps({"key": "command-1", "noticeId": "notice-1"}),
                content_type="application/json",
                headers={"Authorization": "Bearer caller-a"},
            )

        self.app.json.dumps = original_dumps
        recovered = self.post({"key": "command-1", "noticeId": "notice-1"})
        self.assertEqual(recovered.status_code, 200)
        self.assertEqual(recovered.json["state"], "accepted")
        self.assertEqual(len(self.stack.primary.submit_calls), 1)


if __name__ == "__main__":
    unittest.main()
