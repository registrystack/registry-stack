"""Connection validation keeps workload authority explicit and bounded."""

from contextlib import redirect_stderr
import importlib
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch


class ConnectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class NativeClient:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs

            def submit(self, *args):
                return args

            def message_receipt(self, *args):
                return args

            def health(self):
                return "healthy"

            def bearer_token(self):
                return "test-bearer"

            def registry_metadata(self, access_profile=None):
                return self.kwargs["authorization"]

        cls.NativeClient = NativeClient

        modules = {}
        for product in (
            "breg",
            "casework",
            "discovery",
            "evidence",
            "messaging",
            "scheduling",
            "coordinator",
            "render",
        ):
            module = types.ModuleType(f"registry_client.{product}")
            module.PrivateKeyJwt = NativeClient
            module.BaseRegistryClient = NativeClient
            module.MessagingClient = NativeClient
            modules[module.__name__] = module
        yaml_module = types.ModuleType("registry_client.yaml")

        class ConfigReadError(ValueError):
            def __init__(self, message, *, diagnostics=None):
                super().__init__(message)
                self.diagnostics = diagnostics or ({"code": "configuration.refused"},)

        def read_document(contents, *, file, api_version, kind):
            def unique_pairs(pairs):
                result = {}
                for name, value in pairs:
                    if name in result:
                        raise ConfigReadError("duplicate mapping key")
                    result[name] = value
                return result

            try:
                value = json.loads(contents, object_pairs_hook=unique_pairs)
            except (UnicodeError, json.JSONDecodeError):
                raise ConfigReadError("invalid document") from None
            if not isinstance(value, dict):
                raise ConfigReadError("wrong envelope")
            if value.get("kind") != kind:
                raise ConfigReadError(
                    "wrong kind", diagnostics=({"code": "config.wrong-kind"},)
                )
            if value.get("apiVersion") != api_version:
                raise ConfigReadError(
                    "wrong version",
                    diagnostics=({"code": "config.unsupported-api-version"},),
                )
            return value

        yaml_module.ConfigReadError = ConfigReadError
        yaml_module.read_document = read_document
        modules[yaml_module.__name__] = yaml_module
        cls.module_patch = patch.dict(sys.modules, modules)
        cls.module_patch.start()
        cls.path_patch = patch.object(
            sys,
            "path",
            [str(Path(__file__).resolve().parents[1] / "python"), *sys.path],
        )
        cls.path_patch.start()
        cls.client = importlib.import_module("registry_client.connection")

    @classmethod
    def tearDownClass(cls):
        for name in (
            "registry_client.connection",
            "registry_client.auth",
            "registry_client",
        ):
            sys.modules.pop(name, None)
        cls.path_patch.stop()
        cls.module_patch.stop()

    def setUp(self):
        self.ConnectionError = self.client.ConnectionError
        self.connect = self.client.connect
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "key").write_text('{"kty":"EC"}', encoding="utf-8")
        (self.root / "key").chmod(0o600)

    def connection(self, bindings):
        path = self.root / "connection.json"
        path.write_text(
            json.dumps(
                {
                    "apiVersion": "id.registrystack.org/formats/platform/python-connection/v1alpha1",
                    "kind": "PlatformPythonConnection",
                    "service": "test-service",
                    "audience": "service",
                    "secretProviders": {"file": {"root": str(self.root)}},
                    "bindings": bindings,
                }
            ),
            encoding="utf-8",
        )
        return path

    def binding(self, name="registry", product="breg", default=True):
        return {
            "name": name,
            "product": product,
            "url": "https://example.invalid/",
            "default": default,
            "credential": {
                "type": "private-key-jwt",
                "issuer": "https://issuer.example.invalid/",
                "subject": "test-workload",
                "tokenEndpoint": "https://issuer.example.invalid/token",
                "clientId": "test-client",
                "profile": "test-profile",
                "clientKeyRef": "secret:file/key",
                "resource": "https://example.invalid/",
                "scopes": ["registry.read"],
                "claims": {
                    "application_reference": "application-001",
                    "registry_actor_kind": "service",
                },
            },
        }

    def test_authority_fingerprint_tracks_identity_not_alias_or_secret(self):
        primary = self.binding(product="messaging")
        alias = self.binding(name="renamed", product="messaging", default=False)
        alias["url"] = "https://moved.example.invalid/"
        alias["credential"]["tokenEndpoint"] = (
            "https://issuer.example.invalid/other-token-endpoint"
        )
        alias["credential"]["clientKeyRef"] = "secret:file/other-key"
        alias["credential"]["claims"] = {
            "registry_actor_kind": "service",
            "application_reference": "application-001",
        }
        (self.root / "other-key").write_text('{"kty":"EC"}', encoding="utf-8")
        (self.root / "other-key").chmod(0o600)

        stack = self.connect(path=self.connection([primary, alias]))
        default = stack.authority("messaging")
        renamed = stack.using("renamed").authority

        self.assertEqual(default, renamed)
        self.assertEqual(default.product, "messaging")
        self.assertEqual(default.issuer, "https://issuer.example.invalid/")
        self.assertEqual(default.subject, "test-workload")
        self.assertEqual(default.client_id, "test-client")
        self.assertEqual(default.profile, "test-profile")
        self.assertEqual(default.resource, "https://example.invalid/")
        self.assertEqual(default.scopes, ("registry.read",))
        self.assertEqual(
            default.claims,
            {
                "application_reference": "application-001",
                "registry_actor_kind": "service",
            },
        )
        self.assertRegex(default.fingerprint, r"\A[0-9a-f]{64}\Z")
        self.assertNotIn("other-key", repr(default))
        self.assertNotIn("application-001", repr(default))
        self.assertNotIn("test-workload", repr(default))
        with self.assertRaises(TypeError):
            default.claims["registry_actor_kind"] = "human"

        for field, value in (
            ("issuer", "https://other-issuer.example.invalid/"),
            ("subject", "other-workload"),
            ("clientId", "other-client"),
            ("profile", "other-profile"),
            ("resource", "urn:registry:messaging:other"),
            ("scopes", ["registry.read", "registry.write"]),
            (
                "claims",
                {
                    "application_reference": "application-002",
                    "registry_actor_kind": "service",
                },
            ),
        ):
            with self.subTest(field=field):
                changed = self.binding(
                    name="changed", product="messaging", default=False
                )
                changed["credential"][field] = value
                changed_stack = self.connect(path=self.connection([primary, changed]))
                self.assertNotEqual(
                    default.fingerprint,
                    changed_stack.using("changed").authority.fingerprint,
                )

        reordered = self.binding(
            name="reordered", product="messaging", default=False
        )
        primary["credential"]["scopes"] = ["registry.write", "registry.read"]
        reordered["credential"]["scopes"] = ["registry.read", "registry.write"]
        reordered_stack = self.connect(path=self.connection([primary, reordered]))
        self.assertEqual(
            reordered_stack.authority("messaging").fingerprint,
            reordered_stack.using("reordered").authority.fingerprint,
        )

    def test_private_key_authority_requires_complete_identity_metadata(self):
        for field in ("issuer", "subject", "profile", "claims"):
            with self.subTest(field=field):
                binding = self.binding()
                del binding["credential"][field]
                with self.assertRaisesRegex(self.ConnectionError, f"{field}.*required"):
                    self.connect(path=self.connection([binding]))

    def test_environment_secret_reference_uses_declared_environment_provider(self):
        binding = self.binding()
        binding["credential"]["clientKeyRef"] = "secret:env/TEST_WORKLOAD_KEY"
        path = self.connection([binding])
        document = json.loads(path.read_text(encoding="utf-8"))
        document["secretProviders"] = {"environment": {}}
        path.write_text(json.dumps(document), encoding="utf-8")

        stack = self.connect(path=path)

        self.assertEqual(stack.authority("breg").subject, "test-workload")

        document["secretProviders"] = {"file": {"root": str(self.root)}}
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            self.ConnectionError, "declared environment secret provider"
        ):
            self.connect(path=path)

    def test_declared_claims_cannot_replace_protocol_identity(self):
        binding = self.binding()
        binding["credential"]["claims"]["sub"] = "other-workload"
        with self.assertRaisesRegex(self.ConnectionError, "claim name"):
            self.connect(path=self.connection([binding]))

    def test_missing_default_refuses_without_selecting_another_binding(self):
        path = self.connection([self.binding(default=False)])
        with self.assertRaisesRegex(self.ConnectionError, "default.*breg"):
            self.connect(path=path)

    def test_connect_is_the_public_core_entry_point(self):
        from registry_client import WorkloadAuthority, connect

        self.assertIs(connect, self.connect)
        self.assertIs(WorkloadAuthority, self.client.WorkloadAuthority)

    def test_duplicate_default_refuses(self):
        path = self.connection([self.binding(), self.binding(name="other")])
        with self.assertRaisesRegex(self.ConnectionError, "default.*breg"):
            self.connect(path=path)

    def test_connection_kind_is_required_and_exact(self):
        path = self.connection([self.binding()])
        document = json.loads(path.read_text(encoding="utf-8"))
        document["kind"] = "PlatformOtherConnection"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(self.ConnectionError) as caught:
            self.connect(path=path)
        self.assertEqual(caught.exception.diagnostics[0]["code"], "config.wrong-kind")

    def test_duplicate_mapping_key_is_refused_with_bounded_diagnostics(self):
        path = self.connection([self.binding()])
        raw = path.read_text(encoding="utf-8")
        path.write_text(raw.replace('"service": "test-service",',
                                    '"service": "test-service", "service": "other",'),
                        encoding="utf-8")
        with self.assertRaises(self.ConnectionError) as caught:
            self.connect(path=path)
        self.assertEqual(caught.exception.diagnostics[0]["code"], "configuration.refused")

    def test_unknown_binding_and_product_refuse_with_named_errors(self):
        path = self.connection([self.binding()])
        stack = self.connect(path=path)
        with self.assertRaisesRegex(self.ConnectionError, "unknown.*binding"):
            stack.using("missing")
        with self.assertRaisesRegex(self.ConnectionError, "messaging"):
            _ = stack.messaging

    def test_inline_credential_and_malformed_reference_refuse_without_leak(self):
        binding = self.binding()
        binding["credential"]["token"] = "secret-canary"
        path = self.connection([binding])
        with self.assertRaises(self.ConnectionError) as caught:
            self.connect(path=path)
        self.assertNotIn("secret-canary", str(caught.exception))
        del binding["credential"]["token"]
        binding["credential"]["clientKeyRef"] = "secret:file/../key"
        path = self.connection([binding])
        with self.assertRaisesRegex(self.ConnectionError, "clientKeyRef"):
            self.connect(path=path)

    def test_unsupported_audience_refuses(self):
        path = self.connection([self.binding()])
        document = json.loads(path.read_text(encoding="utf-8"))
        document["audience"] = "all"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(self.ConnectionError, "audience"):
            self.connect(path=path)

    def test_breg_uses_native_provider_and_named_binding_is_immutable(self):
        from registry_client.workload_breg import BRegWorkload

        path = self.connection(
            [self.binding(), self.binding(name="other", default=False)]
        )
        stack = self.connect(path=path)
        default = stack.breg
        named = stack.using("other").breg
        self.assertIsInstance(default, BRegWorkload)
        self.assertIs(default, stack.breg)
        self.assertIsNot(default, named)
        self.assertIn("private_key_jwt", default._client.kwargs["authorization"])
        self.assertEqual(
            stack.breg._client.kwargs["authorization"]["private_key_jwt"]["client_id"],
            "test-client",
        )

    def test_messaging_supplies_token_for_every_protected_call(self):
        path = self.connection([self.binding(product="messaging")])
        stack = self.connect(path=path)
        self.assertEqual(stack.messaging.health(), "healthy")
        self.assertEqual(
            stack.messaging.submit("key", {"message": "test"}),
            ("test-bearer", "key", {"message": "test"}),
        )
        self.assertEqual(
            stack.messaging.message_receipt("key", {"message": "test"}),
            ("test-bearer", "key", {"message": "test"}),
        )
        with self.assertRaisesRegex(
            AttributeError, "client.operation-not-supported.*messaging.*bearer_token"
        ):
            _ = stack.messaging.bearer_token

    def test_urn_resource_and_local_runner_http_are_valid(self):
        binding = self.binding()
        binding["url"] = "http://127.0.0.1:8123/registry"
        binding["credential"]["tokenEndpoint"] = "http://localhost:8124/oauth/token"
        binding["credential"]["resource"] = "urn:registry:breg:test"
        stack = self.connect(path=self.connection([binding]))
        self.assertEqual(stack.breg._client.args[0], binding["url"])

    def test_nonloopback_http_is_refused(self):
        binding = self.binding()
        binding["url"] = "http://registry.example.invalid/"
        with self.assertRaisesRegex(self.ConnectionError, "url"):
            self.connect(path=self.connection([binding]))

    def test_concurrent_selection_constructs_one_native_client(self):
        path = self.connection([self.binding()])
        stack = self.connect(path=path)
        constructed = []
        original = self.NativeClient.__init__

        def initialize(instance, *args, **kwargs):
            time.sleep(0.01)
            constructed.append(instance)
            original(instance, *args, **kwargs)

        results = []
        with patch.object(self.NativeClient, "__init__", initialize):
            threads = [
                threading.Thread(target=lambda: results.append(stack.breg))
                for _ in range(8)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(len(constructed), 1)
        self.assertTrue(all(result is results[0] for result in results))

    def test_file_secret_must_be_private_and_owned(self):
        stack = self.connect(path=self.connection([self.binding()]))
        (self.root / "key").chmod(0o644)
        with self.assertRaisesRegex(self.ConnectionError, "private regular file"):
            _ = stack.breg

    def test_file_secret_rejects_a_shared_root_and_symlink(self):
        path = self.connection([self.binding()])
        self.root.chmod(0o755)
        with self.assertRaisesRegex(self.ConnectionError, "private directory"):
            _ = self.connect(path=path).breg
        self.root.chmod(0o700)
        (self.root / "key").rename(self.root / "original")
        (self.root / "key").symlink_to(self.root / "original")
        with self.assertRaisesRegex(self.ConnectionError, "private regular file"):
            _ = self.connect(path=path).breg

    def test_offline_checker_reads_secret_refs_without_native_construction(self):
        from registry_client.check_connection import check_file

        path = self.connection([self.binding()])
        with patch.object(self.NativeClient, "__init__", side_effect=AssertionError("native")):
            check_file(path)
        (self.root / "key").write_text("not-json", encoding="utf-8")
        with self.assertRaisesRegex(self.ConnectionError, "client key"):
            check_file(path)

    def test_offline_checker_cli_prints_bounded_structured_diagnostics(self):
        checker = importlib.import_module("registry_client.check_connection")
        diagnostics = tuple(
            {
                "code": "config.unknown-key",
                "path": f"/bindings/{index}/unexpected",
                "message": "value-canary must not be printed",
                "source": {
                    "file": "connection.json",
                    "line": index + 1,
                    "column": 7,
                },
            }
            for index in range(12)
        )
        failure = self.ConnectionError("the read-back document was refused", diagnostics=diagnostics)
        stderr = StringIO()
        with (
            patch.object(checker, "check_file", side_effect=failure),
            patch.object(sys, "argv", ["registry-client-check", "connection.json"]),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as caught,
        ):
            checker.main()
        self.assertEqual(caught.exception.code, 2)
        output = stderr.getvalue()
        self.assertIn("config.unknown-key at /bindings/0/unexpected", output)
        self.assertIn("connection.json:1:7", output)
        self.assertIn("2 additional diagnostics omitted", output)
        self.assertNotIn("/bindings/10/unexpected", output)
        self.assertNotIn("value-canary", output)

    def test_expired_budget_refuses_new_native_work(self):
        from registry_client.workload import RequestBudgetExceeded, request_budget

        stack = self.connect(path=self.connection([self.binding()]))
        native = stack.breg._client
        with patch.object(native, "health", wraps=native.health) as health:
            with request_budget(0.001):
                time.sleep(0.005)
                with self.assertRaises(RequestBudgetExceeded):
                    stack.breg.health()
            health.assert_not_called()

    def test_nested_budget_cannot_extend_the_outer_limit(self):
        from registry_client.workload import RequestBudgetExceeded, request_budget

        stack = self.connect(path=self.connection([self.binding()]))
        with request_budget(0.001):
            with request_budget(60):
                time.sleep(0.005)
                with self.assertRaises(RequestBudgetExceeded):
                    stack.breg.health()

    def runner_binding(self, product="breg"):
        binding = self.binding(product=product)
        binding["credential"] = {
            "type": "runner-token",
            "tokenRef": "secret:file/workload-registry.json",
            "runId": "run-one",
            "binding": "registry",
            "issuer": "https://issuer.example.invalid/",
            "subject": "test-workload",
            "clientId": "test-client",
            "profile": "test-profile",
            "resource": "urn:registry:breg:test",
            "scopes": ["registry.read"],
            "claims": {"registry_actor_kind": "service"},
            "runExpiresAt": int(time.time()) + 900,
        }
        return binding

    def write_runner_state(self, binding, generation, *, token=None, issuer=None):
        credential = binding["credential"]
        now = int(time.time())
        state = {
            "apiVersion": "id.registrystack.org/formats/platform/dev-workload-token/v1alpha1",
            "kind": "PlatformDevWorkloadToken",
            "runId": credential["runId"],
            "binding": binding["name"],
            "product": binding["product"],
            "issuer": issuer or credential["issuer"],
            "subject": credential["subject"],
            "clientId": credential["clientId"],
            "profile": credential["profile"],
            "resource": credential["resource"],
            "scopes": credential["scopes"],
            "claims": credential["claims"],
            "generation": generation,
            "issuedAt": now,
            "expiresAt": now + 300,
            "runExpiresAt": credential["runExpiresAt"],
            "token": token or f"synthetic-token-{generation}",
        }
        temporary = self.root / "next-token.json"
        temporary.write_text(json.dumps(state), encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, self.root / "workload-registry.json")

    def test_runner_token_rotation_updates_breg_without_changing_handle(self):
        binding = self.runner_binding()
        self.write_runner_state(binding, 1)
        stack = self.connect(path=self.connection([binding]))
        handle = stack.breg
        self.assertEqual(handle.registry_metadata(), {"static": "synthetic-token-1"})
        self.write_runner_state(binding, 2)
        self.assertIs(stack.breg, handle)
        self.assertEqual(handle.registry_metadata(), {"static": "synthetic-token-2"})

    def test_runner_token_kind_cannot_cross_format_boundary(self):
        binding = self.runner_binding()
        self.write_runner_state(binding, 1)
        state_path = self.root / "workload-registry.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["kind"] = "PlatformPythonConnection"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        state_path.chmod(0o600)
        stack = self.connect(path=self.connection([binding]))
        with self.assertRaisesRegex(self.ConnectionError, "runner token"):
            stack.breg.registry_metadata()

    def test_offline_checker_validates_standalone_runner_state(self):
        from registry_client.check_connection import check_file

        binding = self.runner_binding()
        self.write_runner_state(binding, 1)
        state_path = self.root / "workload-registry.json"
        check_file(state_path)
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["expiresAt"] = 0
        state_path.write_text(json.dumps(state), encoding="utf-8")
        state_path.chmod(0o600)
        with self.assertRaisesRegex(self.ConnectionError, "lifetime"):
            check_file(state_path)

    def test_offline_checker_accepts_stopped_envelope_but_consumer_refuses(self):
        from registry_client.check_connection import check_file

        binding = self.runner_binding()
        self.write_runner_state(binding, 1)
        state_path = self.root / "workload-registry.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["status"] = "stopped"
        state["expiresAt"] = state["issuedAt"]
        del state["token"]
        state_path.write_text(json.dumps(state), encoding="utf-8")
        state_path.chmod(0o600)
        check_file(state_path)
        stack = self.connect(path=self.connection([binding]))
        with self.assertRaisesRegex(self.ConnectionError, "runner token state"):
            stack.breg.registry_metadata()

    def test_runner_token_rejects_identity_change_and_generation_rollback(self):
        binding = self.runner_binding()
        self.write_runner_state(binding, 2)
        stack = self.connect(path=self.connection([binding]))
        self.assertEqual(stack.breg.registry_metadata(), {"static": "synthetic-token-2"})
        self.write_runner_state(binding, 3, issuer="https://other.example.invalid/")
        with self.assertRaisesRegex(self.ConnectionError, "runner"):
            stack.breg.registry_metadata()
        self.write_runner_state(binding, 3)
        state_path = self.root / "workload-registry.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["claims"]["registry_actor_kind"] = "human"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        state_path.chmod(0o600)
        with self.assertRaisesRegex(self.ConnectionError, "authority"):
            stack.breg.registry_metadata()
        self.write_runner_state(binding, 1)
        with self.assertRaisesRegex(self.ConnectionError, "generation"):
            stack.breg.registry_metadata()

    def test_runner_token_stop_refuses_without_using_cached_bearer(self):
        binding = self.runner_binding(product="messaging")
        self.write_runner_state(binding, 1)
        stack = self.connect(path=self.connection([binding]))
        self.assertEqual(stack.messaging.submit("key", {}), ("synthetic-token-1", "key", {}))
        (self.root / "workload-registry.json").unlink()
        with self.assertRaises(self.ConnectionError):
            stack.messaging.submit("key", {})

    def admission_config(self):
        return {
            "issuer": "https://issuer.example.invalid/",
            "resource": "urn:registry:python:test",
            "clientId": "coordinator-client",
            "profile": "coordinator-invoker",
            "requiredScopes": ["python.invoke"],
            "requiredClaims": {"registry_actor_kind": "machine"},
            "algorithm": "RS256",
            "accessTokenType": "at+jwt",
            "maximumAccessTokenLifetimeSeconds": 300,
        }

    def test_connection_admits_only_its_exact_service_invoker(self):
        path = self.connection([self.binding()])
        document = json.loads(path.read_text(encoding="utf-8"))
        document["admission"] = self.admission_config()
        path.write_text(json.dumps(document), encoding="utf-8")

        class Verifier:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.options = kwargs

            def verify(self, token):
                return types.SimpleNamespace(
                    kind="access",
                    issuer="https://issuer.example.invalid/",
                    audiences=("urn:registry:python:test",),
                    subject="coordinator",
                    client_id="coordinator-client",
                    scopes=("python.invoke",),
                    claims={"registry_actor_kind": "machine"},
                )

        native = types.ModuleType("registry_client.oidc")
        native.AccessTokenVerifier = Verifier
        with patch.dict(sys.modules, {"registry_client.oidc": native}):
            stack = self.connect(path=path)
            context = stack.admit({"authorization": ["Bearer synthetic"]})
        self.assertEqual(context.client_id, "coordinator-client")
        self.assertEqual(context.profile, "coordinator-invoker")

    def test_admission_configuration_is_service_only(self):
        path = self.connection([self.binding()])
        document = json.loads(path.read_text(encoding="utf-8"))
        document["admission"] = self.admission_config()
        document["audience"] = "holder"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(self.ConnectionError, "admission"):
            self.connect(path=path)

    def test_malformed_machine_scope_is_a_named_configuration_error(self):
        path = self.connection([self.binding()])
        document = json.loads(path.read_text(encoding="utf-8"))
        document["admission"] = self.admission_config()
        document["admission"]["requiredScopes"] = [{"invalid": "scope"}]
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(self.ConnectionError, "requiredScopes"):
            self.connect(path=path)


if __name__ == "__main__":
    unittest.main()
