from __future__ import annotations

import asyncio
from contextlib import redirect_stderr
import importlib
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import tomllib
import types
import unittest
from unittest.mock import patch

import httpx


EXAMPLE = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
CLIENT_SOURCE = (
    Path(__file__).resolve().parents[5]
    / "crates/registry-stack-client-py/python/registry_client"
)
sys.path.insert(0, str(EXAMPLE))
sys.path.insert(0, str(TESTS))

from effect import MessageEffectStore  # noqa: E402
from service import (  # noqa: E402
    create_app,
    create_app_from_environment,
    create_fastapi_app,
    create_fastapi_app_from_environment,
)

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
fastapi_adapter = load_client_module("fastapi_adapter")
flask_adapter = load_client_module("flask_adapter")
web = load_client_module("web")
workload = load_client_module("workload")


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


class PackagingTests(unittest.TestCase):
    def test_framework_servers_are_separate_extras_and_dev_installs_both(self) -> None:
        with (EXAMPLE / "pyproject.toml").open("rb") as source:
            project = tomllib.load(source)

        metadata = project["project"]
        self.assertEqual(metadata.get("dependencies", []), [])
        extras = metadata["optional-dependencies"]
        self.assertEqual(set(extras), {"fastapi", "flask"})
        self.assertEqual(
            set(extras["flask"]),
            {"flask==3.1.2", "gunicorn>=23,<24"},
        )
        self.assertEqual(
            set(extras["fastapi"]),
            {"fastapi>=0.115,<1", "uvicorn>=0.34,<1"},
        )
        dev = set(project["dependency-groups"]["dev"])
        self.assertTrue(set(extras["flask"]).issubset(dev))
        self.assertTrue(set(extras["fastapi"]).issubset(dev))
        self.assertIn("httpx>=0.28,<1", dev)
        self.assertIn("ruff==0.14.3", dev)


class RealConnectionFactoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.prior_modules = {
            name: module
            for name, module in sys.modules.items()
            if name == "registry_client" or name.startswith("registry_client.")
        }
        for name in self.prior_modules:
            sys.modules.pop(name, None)

        package = types.ModuleType("registry_client")
        package.__path__ = [str(CLIENT_SOURCE)]
        sys.modules["registry_client"] = package

        yaml_module = types.ModuleType("registry_client.yaml")

        class ConfigReadError(ValueError):
            def __init__(self, message, *, diagnostics=None):
                super().__init__(message)
                self.diagnostics = diagnostics or ()

        def read_document(contents, *, file, api_version, kind):
            del file

            def unique_members(pairs):
                value = {}
                for name, member in pairs:
                    if name in value:
                        raise ConfigReadError("duplicate mapping key")
                    value[name] = member
                return value

            try:
                value = json.loads(contents, object_pairs_hook=unique_members)
            except (UnicodeError, json.JSONDecodeError):
                raise ConfigReadError("invalid connection document") from None
            if value.get("apiVersion") != api_version or value.get("kind") != kind:
                raise ConfigReadError("wrong connection envelope")
            return value

        yaml_module.ConfigReadError = ConfigReadError
        yaml_module.read_document = read_document
        sys.modules["registry_client.yaml"] = yaml_module

        oidc_module = types.ModuleType("registry_client.oidc")

        class VerificationFailure(ValueError):
            kind = "verification"

        class AccessTokenVerifier:
            instances = []
            results = {}

            def __init__(self, *args, **options):
                self.args = args
                self.options = options
                self.__class__.instances.append(self)

            def verify(self, token):
                result = self.__class__.results.get(token)
                if result is None:
                    raise VerificationFailure("synthetic token refused")
                return result

        oidc_module.AccessTokenVerifier = AccessTokenVerifier
        sys.modules["registry_client.oidc"] = oidc_module

        self.connection = importlib.import_module("registry_client.connection")
        package.connect = self.connection.connect
        package.flask_adapter = importlib.import_module("registry_client.flask_adapter")
        self.AccessTokenVerifier = AccessTokenVerifier
        self.addCleanup(self.restore_modules)

    def restore_modules(self) -> None:
        for name in tuple(sys.modules):
            if name == "registry_client" or name.startswith("registry_client."):
                sys.modules.pop(name, None)
        sys.modules.update(self.prior_modules)

    def documented_connection(self) -> dict[str, object]:
        readme = (EXAMPLE / "README.md").read_text(encoding="utf-8")
        section = readme.split("<!-- machine-service-connection-example:start -->", 1)[
            1
        ].split("<!-- machine-service-connection-example:end -->", 1)[0]
        source = section.split("```json", 1)[1].split("```", 1)[0]
        return json.loads(source)

    def verified(self, admission, *, scopes=None, claims=None):
        return types.SimpleNamespace(
            kind="access",
            issuer=admission["issuer"],
            audiences=(admission["resource"],),
            subject="synthetic-coordinator-run",
            client_id=admission["clientId"],
            scopes=tuple(scopes or admission["requiredScopes"]),
            claims=dict(claims or admission["requiredClaims"]),
        )

    def test_documented_connection_reaches_real_machine_admission(self) -> None:
        document = self.documented_connection()
        secrets = self.root / "secrets"
        secrets.mkdir(mode=0o700)
        document["secretProviders"]["file"]["root"] = str(secrets)
        connection_path = self.root / "connection.json"

        outbound_only = json.loads(json.dumps(document))
        outbound_only.pop("admission")
        connection_path.write_text(json.dumps(outbound_only), encoding="utf-8")
        script_stack = self.connection.connect(path=connection_path)
        self.assertEqual(script_stack.authority("messaging").product, "messaging")
        with self.assertRaisesRegex(
            self.connection.ConnectionError,
            "machine admission is not configured",
        ):
            script_stack.admit({"authorization": ["Bearer admitted"]})

        connection_path.write_text(json.dumps(document), encoding="utf-8")

        admission = document["admission"]
        self.AccessTokenVerifier.results = {
            "admitted": self.verified(admission),
            "wrong-scope": self.verified(admission, scopes=("other:invoke",)),
            "wrong-claim": self.verified(
                admission,
                claims={"registry_actor_kind": "person"},
            ),
        }
        stack = self.connection.connect(path=connection_path)
        fingerprint = stack.authority("messaging").fingerprint
        context = stack.admit({"authorization": ["Bearer admitted"]})
        self.assertEqual(context.client_id, admission["clientId"])
        self.assertEqual(context.profile, admission["profile"])
        self.assertEqual(context.issuer, admission["issuer"])
        self.assertEqual(context.resource, admission["resource"])
        settings = {
            "REGISTRY_STACK_CONNECTION": str(connection_path),
            "MESSAGE_EFFECT_DATABASE": str(self.root / "effects.sqlite3"),
            "MESSAGE_EFFECT_SERVICE_NAMESPACE": "urn:example:service:renewal-notices",
            "MESSAGE_EFFECT_TARGETS": json.dumps({fingerprint: None}),
            "MESSAGE_EFFECT_AUDIT_KEY_HEX": "a" * 64,
        }

        with patch.dict(os.environ, settings, clear=True):
            app = create_app_from_environment()
        app.testing = True
        client = app.test_client()
        refused = client.post(
            "/v1/message-effects",
            json={"key": "command-1", "noticeId": "notice-1"},
            headers={"Authorization": "Bearer wrong-scope"},
        )
        wrong_claim = client.post(
            "/v1/message-effects",
            json={"key": "command-1", "noticeId": "notice-1"},
            headers={"Authorization": "Bearer wrong-claim"},
        )
        admitted = client.post(
            "/v1/message-effects",
            json={"key": "command-1", "noticeId": "notice-1"},
            headers={"Authorization": "Bearer admitted"},
        )

        self.assertEqual(refused.status_code, 401)
        self.assertEqual(refused.json, {"code": "authentication.refused"})
        self.assertEqual(wrong_claim.status_code, 401)
        self.assertEqual(wrong_claim.json, {"code": "authentication.refused"})
        self.assertEqual(admitted.status_code, 422)
        self.assertEqual(
            admitted.json,
            {"state": "refused", "code": "notice-not-found"},
        )

        with patch.dict(os.environ, settings, clear=True):
            fastapi_app = create_fastapi_app_from_environment()

        async def exercise_fastapi():
            transport = httpx.ASGITransport(app=fastapi_app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as fastapi_client:
                command = {"key": "command-1", "noticeId": "notice-1"}
                denied_scope = await fastapi_client.post(
                    "/v1/message-effects",
                    json=command,
                    headers={"Authorization": "Bearer wrong-scope"},
                )
                denied_claim = await fastapi_client.post(
                    "/v1/message-effects",
                    json=command,
                    headers={"Authorization": "Bearer wrong-claim"},
                )
                allowed = await fastapi_client.post(
                    "/v1/message-effects",
                    json=command,
                    headers={"Authorization": "Bearer admitted"},
                )
            return denied_scope, denied_claim, allowed

        denied_scope, denied_claim, allowed = asyncio.run(exercise_fastapi())
        self.assertEqual(denied_scope.status_code, 401)
        self.assertEqual(denied_scope.json(), {"code": "authentication.refused"})
        self.assertEqual(denied_claim.status_code, 401)
        self.assertEqual(denied_claim.json(), {"code": "authentication.refused"})
        self.assertEqual(allowed.status_code, 422)
        self.assertEqual(
            allowed.json(),
            {"state": "refused", "code": "notice-not-found"},
        )
        self.assertEqual(len(self.AccessTokenVerifier.instances), 3)
        for verifier in self.AccessTokenVerifier.instances:
            self.assertEqual(
                verifier.args,
                (
                    admission["issuer"],
                    admission["resource"],
                    admission["clientId"],
                ),
            )
            self.assertEqual(verifier.options["algorithm"], admission["algorithm"])
            self.assertEqual(
                verifier.options["access_token_type"], admission["accessTokenType"]
            )
            self.assertEqual(
                verifier.options["maximum_access_token_lifetime_seconds"],
                admission["maximumAccessTokenLifetimeSeconds"],
            )
            self.assertEqual(
                verifier.options["claim_names"],
                tuple(admission["requiredClaims"]),
            )
            self.assertEqual(verifier.options["jwks_uri"], admission["jwksUri"])
            self.assertEqual(
                verifier.options["clock_skew_seconds"], admission["clockSkewSeconds"]
            )


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


class FastAPIMachineServiceTests(unittest.TestCase):
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
        registry_client.fastapi_adapter = fastapi_adapter
        registry_client.web = web
        self.prior_registry_client = sys.modules.get("registry_client")
        sys.modules["registry_client"] = registry_client

        self.audit = []
        self.app = create_fastapi_app(
            database_path=self.database,
            service_namespace="urn:example:service:renewal-notices",
            audit_key=b"A" * 32,
            audit_sink=self.audit.append,
            targets={
                "a" * 64: None,
                "b" * 64: "secondary",
            },
        )
        self.store: MessageEffectStore = self.app.state.registry_message_effect_store
        self.context = machine.MachineContext(
            "caller-a",
            "coordinator-client",
            "coordinator-invoker",
            "https://issuer.example.invalid/",
            "urn:registry:python:test",
        )

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

    async def request(self, method, path, **kwargs):
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.request(method, path, **kwargs)

    def post(self, body, *, bearer="caller-a"):
        return asyncio.run(
            self.request(
                "POST",
                "/v1/message-effects",
                json=body,
                headers={"Authorization": f"Bearer {bearer}"},
            )
        )

    def test_factory_uses_connect_and_sync_handler_for_native_effect(self) -> None:
        self.seed("notice-1", message("person@example.invalid"))
        effect_thread = []
        request_deadline = []
        running_loop = []
        original_submit = self.stack.primary.submit

        def observe_submit(key, payload):
            effect_thread.append(threading.get_ident())
            request_deadline.append(workload._deadline.get())
            workload._require_sync()
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                running_loop.append(False)
            else:
                running_loop.append(True)
            return original_submit(key, payload)

        self.stack.primary.submit = observe_submit

        async def exercise():
            loop_thread = threading.get_ident()
            response = await self.request(
                "POST",
                "/v1/message-effects",
                json={"key": "command-1", "noticeId": "notice-1"},
                headers={"Authorization": "Bearer caller-a"},
            )
            return response, loop_thread

        response, loop_thread = asyncio.run(exercise())

        self.assertEqual(self.connect_calls, 1)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "accepted")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(running_loop, [False])
        self.assertIsInstance(request_deadline[0], float)
        self.assertNotEqual(effect_thread, [loop_thread])
        self.assertEqual(
            self.stack.admission_calls[-1],
            {"authorization": ["Bearer caller-a"]},
        )

    def test_missing_or_invalid_bearer_is_refused_before_effect(self) -> None:
        self.seed("notice-1", message("person@example.invalid"))
        command = {"key": "command-1", "noticeId": "notice-1"}

        missing = asyncio.run(self.request("POST", "/v1/message-effects", json=command))
        cookie = asyncio.run(
            self.request(
                "POST",
                "/v1/message-effects",
                json=command,
                headers={"Cookie": "session=canary"},
            )
        )
        invalid = asyncio.run(
            self.request(
                "POST",
                "/v1/message-effects",
                json=command,
                headers={"Authorization": "Bearer invalid-canary"},
            )
        )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(cookie.status_code, 401)
        self.assertEqual(invalid.status_code, 401)
        self.assertEqual(
            invalid.json(),
            {"code": "authentication.refused"},
        )
        self.assertEqual(invalid.headers["Cache-Control"], "no-store")
        self.assertEqual(self.stack.primary.submit_calls, [])

    def test_public_liveness_exception_is_explicit(self) -> None:
        response = asyncio.run(self.request("GET", "/healthz"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(self.stack.admission_calls, [])

    def test_duplicate_oversized_or_lookalike_command_is_refused(self) -> None:
        self.seed("notice-1", message("protected@example.invalid"))
        headers = {
            "Authorization": "Bearer caller-a",
            "Content-Type": "application/json",
        }
        duplicate = asyncio.run(
            self.request(
                "POST",
                "/v1/message-effects",
                content=b'{"key":"first","key":"second","noticeId":"notice-1"}',
                headers=headers,
            )
        )
        valid = b'{"key":"command-1","noticeId":"notice-1"}'
        duplicate_length = asyncio.run(
            self.request(
                "POST",
                "/v1/message-effects",
                content=valid,
                headers=[
                    ("Authorization", "Bearer caller-a"),
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(valid))),
                    ("Content-Length", str(len(valid))),
                ],
            )
        )
        oversized = asyncio.run(
            self.request(
                "POST",
                "/v1/message-effects",
                content=json.dumps(
                    {
                        "key": "command-1",
                        "noticeId": "notice-1",
                        "padding": "x" * 5000,
                    }
                ),
                headers=headers,
            )
        )
        lookalike = self.post(
            {
                "key": "command-1",
                "noticeId": "notice-1",
                "token": "secret-canary",
            }
        )

        self.assertEqual(duplicate.status_code, 422)
        self.assertEqual(duplicate_length.status_code, 422)
        self.assertEqual(oversized.status_code, 422)
        self.assertEqual(lookalike.status_code, 422)
        self.assertEqual(self.stack.primary.submit_calls, [])

    def test_streamed_body_stops_when_declared_length_is_exceeded(self) -> None:
        self.seed("notice-1", message("protected@example.invalid"))
        declared = b'{"key":"command-1","noticeId":"notice-1"}'
        chunks_requested = []

        async def body():
            chunks_requested.append(1)
            yield declared
            chunks_requested.append(2)
            yield b"x"
            raise AssertionError("bounded reader requested another body chunk")

        response = asyncio.run(
            self.request(
                "POST",
                "/v1/message-effects",
                content=body(),
                headers={
                    "Authorization": "Bearer caller-a",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(declared)),
                },
            )
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(chunks_requested, [1, 2])
        self.assertEqual(self.stack.primary.submit_calls, [])

    def test_response_contract_preserves_refusal_and_uncertainty(self) -> None:
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
            refused.json(),
            {"state": "refused", "code": "template.not-found"},
        )
        self.assertEqual(uncertain.status_code, 202)
        self.assertEqual(uncertain.json()["state"], "uncertain")
        self.assertIn("recovery", uncertain.json())

    def test_environment_factory_constructs_fastapi_worker(self) -> None:
        settings = {
            "MESSAGE_EFFECT_DATABASE": str(self.database),
            "MESSAGE_EFFECT_SERVICE_NAMESPACE": "urn:example:service:renewal-notices",
            "MESSAGE_EFFECT_TARGETS": json.dumps({"a" * 64: None}),
            "MESSAGE_EFFECT_AUDIT_KEY_HEX": "a" * 64,
        }

        with patch.dict(os.environ, settings, clear=True):
            app = create_fastapi_app_from_environment()

        self.assertIsInstance(
            app.state.registry_message_effect_store, MessageEffectStore
        )


if __name__ == "__main__":
    unittest.main()
