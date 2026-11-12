import asyncio
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

from flask import g
import httpx


ROOT = Path(__file__).resolve().parents[1]
RECORD_ID = "11111111-1111-4111-8111-111111111111"
REQUEST_ID = "22222222-2222-4222-8222-222222222222"
TASK_ID = "33333333-3333-4333-8333-333333333333"
PROPOSAL_ID = "44444444-4444-4444-8444-444444444444"


class GrantPolicy:
    def __init__(
        self, name, resource, scopes, profile, required_claims, forward_resource=None
    ):
        self.name = name
        self.resource = resource
        self.scopes = scopes
        self.profile = profile
        self.required_claims = required_claims
        self.forward_resource = forward_resource


class Recorder:
    calls = []

    @classmethod
    def reset(cls):
        cls.calls = []


class NativeGrantVerifier(Recorder):
    @classmethod
    def from_native(cls, **kwargs):
        cls.calls.append(kwargs)
        return ("native-verifier", kwargs)


class AuthlibOIDCClient(Recorder):
    def __init__(self, **kwargs):
        self.configuration = kwargs
        self.calls.append(kwargs)


class PortalConfig(Recorder):
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.calls.append(kwargs)


class PortalSessions(Recorder):
    def __init__(self, config, oidc, store):
        self.config = config
        self.oidc = oidc
        self.store = store
        self.calls.append((config, oidc, store))


class PortalEncryptionKeys:
    def __init__(self, *, primary_key_id, keys):
        self.primary_key_id = primary_key_id
        self.keys = keys


class PostgresSessionStore:
    def __init__(self, connect, keys):
        self.connect = connect
        self.keys = keys
        self.actions = []

    def migrate(self):
        self.actions.append("migrate")

    def check_ready(self):
        self.actions.append("check_ready")

    def rotate_encryption(self):
        self.actions.append("rotate_encryption")
        return 3


class Proposal:
    def __init__(self, identifier, document):
        self.identifier = identifier
        self.document = document


class Metadata:
    def __init__(self):
        self.select_action = mock.Mock(return_value="submit-application-binding")
        self.select_proposal_review_context = mock.Mock(
            return_value="review-context-binding"
        )


class Person:
    def __init__(self, persona="holder"):
        self.persona = persona
        self.subject = f"{persona}-subject"
        self.principal = f"{persona}-principal"
        self.csrf_token = f"{persona}-csrf"
        self.metadata = Metadata()
        self.draft = Proposal("proposal-1", {"id": "proposal-1", "state": "draft"})
        self.prepared = object()
        self.submitted = Proposal(
            "proposal-1",
            {
                "id": "proposal-1",
                "state": "review",
                "requestId": REQUEST_ID,
            },
        )
        self.breg = types.SimpleNamespace(
            list_records=mock.Mock(
                return_value={
                    "kind": "complete",
                    "value": [{"data": {"reference": "application-001"}}],
                }
            ),
            get_record=mock.Mock(
                return_value={
                    "kind": "complete",
                    "value": {
                        "data": {
                            "recordIdentifier": RECORD_ID,
                            "revisionIdentifier": "1",
                            "domainData": {
                                "reference": "application-001",
                                "profession": "Surveyor",
                                "status": "submitted",
                            },
                        },
                        "meta": {
                            "registryIdentifier": "licensing",
                            "datasetIdentifier": "licensing",
                            "recordTypeIdentifier": "application",
                        },
                    },
                }
            ),
            registry_contract=mock.Mock(return_value=self.metadata),
            read_proposal_review_by_id=mock.Mock(
                return_value={
                    "kind": "complete",
                    "value": {
                        "id": PROPOSAL_ID,
                        "actionId": "submit-application",
                        "effectDigest": "sha256:" + "a" * 64,
                        "context": {"reference": "application-001"},
                    },
                }
            ),
            start_proposal=mock.Mock(return_value=self.draft),
            prepare_proposal=mock.Mock(return_value=self.prepared),
            execute_proposal=mock.Mock(return_value=self.submitted),
        )
        self.casework = types.SimpleNamespace(
            review_policies=mock.Mock(
                return_value={
                    "kind": "complete",
                    "value": [{"id": "licensing-approval"}],
                }
            ),
            review_tasks=mock.Mock(
                return_value={
                    "kind": "complete",
                    "value": {"items": [{"taskId": "task-1"}]},
                }
            ),
            review_history=mock.Mock(
                return_value={
                    "kind": "complete",
                    "value": {"items": [{"status": "approved"}]},
                }
            ),
            review_task=mock.Mock(
                return_value={
                    "kind": "complete",
                    "value": {
                        "taskId": TASK_ID,
                        "requestId": REQUEST_ID,
                        "revision": 4,
                        "subject": {
                            "source": "licensing",
                            "type": "proposal",
                            "id": PROPOSAL_ID,
                            "version": "1",
                            "digest": "sha256:" + "a" * 64,
                        },
                    },
                }
            ),
            review_task_context=mock.Mock(
                return_value={
                    "kind": "complete",
                    "value": {"context": {"reference": "application-001"}},
                }
            ),
            claim_review_task=mock.Mock(
                return_value={
                    "kind": "complete",
                    "value": {"taskId": TASK_ID, "revision": 5},
                }
            ),
            release_review_task=mock.Mock(
                return_value={
                    "kind": "complete",
                    "value": {"taskId": TASK_ID, "revision": 6},
                }
            ),
            decide_review_task=mock.Mock(
                return_value={"kind": "complete", "value": None}
            ),
            own_review_decisions=mock.Mock(
                return_value={
                    "kind": "complete",
                    "value": {"items": [{"requestId": REQUEST_ID}]},
                }
            ),
        )


def install_modules():
    package = types.ModuleType("registry_client")
    package.__path__ = []
    portal = types.ModuleType("registry_client.portal")
    portal.GrantPolicy = GrantPolicy
    portal.PortalConfig = PortalConfig
    portal.AuthlibOIDCClient = AuthlibOIDCClient
    portal.PortalSessions = PortalSessions
    portal_flask = types.ModuleType("registry_client.portal_flask")
    portal_fastapi = types.ModuleType("registry_client.portal_fastapi")
    portal_postgres = types.ModuleType("registry_client.portal_postgres")
    portal_postgres.PortalEncryptionKeys = PortalEncryptionKeys
    portal_postgres.PostgresSessionStore = PostgresSessionStore
    portal_products = types.ModuleType("registry_client.portal_products")
    portal_products.bind_person = mock.Mock(return_value="bound-person")
    portal_verifier = types.ModuleType("registry_client.portal_verifier")
    portal_verifier.NativeGrantVerifier = NativeGrantVerifier
    package.portal_flask = portal_flask
    package.portal_fastapi = portal_fastapi
    modules = {
        "registry_client": package,
        "registry_client.portal": portal,
        "registry_client.portal_flask": portal_flask,
        "registry_client.portal_fastapi": portal_fastapi,
        "registry_client.portal_postgres": portal_postgres,
        "registry_client.portal_products": portal_products,
        "registry_client.portal_verifier": portal_verifier,
    }
    sys.modules.update(modules)
    return portal_flask, portal_fastapi, portal_products


def load_example():
    portal_flask, portal_fastapi, portal_products = install_modules()
    spec = importlib.util.spec_from_file_location(
        "registry_python_portal_example", ROOT / "portal_example.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module, portal_flask, portal_fastapi, portal_products


def load_service(example):
    previous = sys.modules.get("portal_example")
    sys.modules["portal_example"] = example
    spec = importlib.util.spec_from_file_location(
        "registry_python_portal_service", ROOT / "service.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            del sys.modules["portal_example"]
        else:
            sys.modules["portal_example"] = previous
    return module


def document():
    grant_claims = {"registry_actor_kind": "human"}
    return {
        "issuer": {
            "url": "https://identity.example.test",
            "authorizationEndpoint": "https://identity.example.test/authorize",
            "tokenEndpoint": "https://identity.example.test/token",
            "endSessionEndpoint": "https://identity.example.test/logout",
            "jwksUri": "https://identity.example.test/jwks.json",
            "algorithm": "ES256",
            "accessTokenType": "at+jwt",
            "maximumAccessTokenLifetimeSeconds": 300,
            "maximumIdTokenLifetimeSeconds": 3600,
        },
        "products": {
            "recordsUrl": "https://records.example.test",
            "reviewsUrl": "https://reviews.example.test",
            "recordRoute": "applications",
            "recordFields": ["reference", "profession", "status"],
            "reviewQueue": "applications",
            "reviewActionId": "submit-application",
            "reviewRecordInput": "application",
            "reviewSubjectSource": "licensing",
            "reviewSubjectType": "application",
        },
        "sessionStore": {
            "databaseUrlEnv": "PORTAL_DATABASE_URL",
            "primaryKeyId": "current",
            "encryptionKeyEnvs": {"current": "PORTAL_SESSION_KEY_CURRENT"},
        },
        "services": {
            "holder": {
                "clientId": "applicant-portal",
                "clientSecretEnv": "PORTAL_HOLDER_CLIENT_SECRET",
                "origin": "https://holder.example.test",
                "redirectUri": "https://holder.example.test/auth/callback",
                "switchRedirectUri": "https://holder.example.test/auth/login",
                "bregProfile": "applicant",
                "caseworkProfile": "applicant",
                "sessionSeconds": 900,
                "pendingSeconds": 300,
                "requestSeconds": 10,
                "sameSite": "Lax",
                "grants": {
                    "breg": {
                        "resource": "urn:example:licensing:registry",
                        "scopes": ["licensing:apply"],
                        "profile": "applicant",
                        "requiredClaims": grant_claims,
                    },
                    "casework": {
                        "resource": "urn:example:licensing:review",
                        "scopes": ["casework:history"],
                        "profile": "applicant",
                        "requiredClaims": grant_claims,
                    },
                },
            },
            "staff": {
                "clientId": "licensing-auditor",
                "clientSecretEnv": "PORTAL_STAFF_CLIENT_SECRET",
                "origin": "https://staff.example.test",
                "redirectUri": "https://staff.example.test/auth/callback",
                "switchRedirectUri": "https://staff.example.test/auth/login",
                "bregProfile": "auditor",
                "caseworkProfile": "reviewer",
                "sessionSeconds": 900,
                "pendingSeconds": 300,
                "requestSeconds": 10,
                "sameSite": "Lax",
                "grants": {
                    "breg": {
                        "resource": "urn:example:licensing:registry",
                        "scopes": ["licensing:audit"],
                        "profile": "auditor",
                        "requiredClaims": grant_claims,
                    },
                    "casework": {
                        "resource": "urn:example:licensing:review",
                        "forwardResource": "urn:example:licensing:registry",
                        "scopes": ["casework:review", "licensing:audit"],
                        "profile": "reviewer",
                        "requiredClaims": grant_claims,
                    },
                },
            },
        },
    }


class PortalExampleTests(unittest.TestCase):
    def setUp(self):
        for recorder in (
            NativeGrantVerifier,
            AuthlibOIDCClient,
            PortalConfig,
            PortalSessions,
        ):
            recorder.reset()

    def test_config_requires_distinct_holder_and_staff_registrations(self):
        module, _, _, _ = load_example()
        config = module.load_config(ROOT / "config.example.toml")

        self.assertEqual(set(config.services), {"holder", "staff"})
        self.assertNotEqual(
            config.services["holder"].client_id,
            config.services["staff"].client_id,
        )
        self.assertEqual(
            config.services["holder"].grants[1].resource,
            "urn:example:licensing:review",
        )
        self.assertEqual(config.services["holder"].casework_profile, "applicant")

        invalid = document()
        invalid["services"]["staff"]["clientId"] = invalid["services"]["holder"][
            "clientId"
        ]
        with self.assertRaises(ValueError):
            module._parse_config(invalid)

    def test_staff_current_source_bridge_cannot_be_omitted(self):
        module, _, _, _ = load_example()
        invalid = document()
        del invalid["services"]["staff"]["grants"]["casework"]["forwardResource"]
        with self.assertRaisesRegex(ValueError, "forwarded Casework grant"):
            module._parse_config(invalid)

    def test_operator_example_matches_the_licensing_resource_contract(self):
        module, _, _, _ = load_example()
        config = module.load_config(ROOT / "config.example.toml")

        self.assertEqual(config.services["holder"].client_id, "applicant-portal")
        self.assertEqual(config.services["staff"].client_id, "licensing-auditor")
        for service in config.services.values():
            self.assertEqual(
                [grant.resource for grant in service.grants],
                ["urn:example:licensing:registry", "urn:example:licensing:review"],
            )
        self.assertEqual(config.services["holder"].casework_profile, "applicant")
        invalid = document()
        invalid["services"]["holder"]["grants"]["breg"]["resource"] = "/records"
        with self.assertRaises(ValueError):
            module._parse_config(invalid)

    def test_runtime_binds_exact_native_grants_and_request_local_person_clients(self):
        module, _, _, portal_products = load_example()
        config = module.load_config(ROOT / "config.example.toml")
        store = object()
        environment = {"PORTAL_HOLDER_CLIENT_SECRET": "client-secret-canary"}

        with mock.patch.dict(os.environ, environment, clear=False):
            runtime = module.build_runtime(config, "holder", store=store)

        verifier = NativeGrantVerifier.calls[0]
        self.assertEqual(verifier["persona"], "holder")
        self.assertEqual(verifier["client_id"], "applicant-portal")
        self.assertEqual(
            [grant.name for grant in verifier["grants"]], ["breg", "casework"]
        )
        self.assertEqual(
            [grant.resource for grant in verifier["grants"]],
            [
                "urn:example:licensing:registry",
                "urn:example:licensing:review",
            ],
        )
        self.assertEqual(
            AuthlibOIDCClient.calls[0]["client_secret"], "client-secret-canary"
        )
        self.assertEqual(
            AuthlibOIDCClient.calls[0]["switch_redirect_uri"],
            "https://holder.example.test/auth/login",
        )

        with mock.patch.dict(
            os.environ,
            {"PORTAL_STAFF_CLIENT_SECRET": "client-secret-canary"},
            clear=False,
        ):
            module.build_runtime(config, "staff", store=store)
        staff = NativeGrantVerifier.calls[-1]["grants"]
        self.assertEqual(staff[1].forward_resource, staff[0].resource)
        self.assertTrue(set(staff[0].scopes).issubset(staff[1].scopes))
        self.assertEqual(PortalSessions.calls[0][2], store)

        context = object()
        self.assertEqual(runtime.person_factory(context), "bound-person")
        portal_products.bind_person.assert_called_once_with(
            context,
            persona="holder",
            breg_url="https://records.licensing.example.test",
            casework_url="https://reviews.licensing.example.test",
            casework_profile="applicant",
        )

    def test_postgres_store_resolves_key_and_database_references_without_logging_values(
        self,
    ):
        module, _, _, _ = load_example()
        config = module.load_config(ROOT / "config.example.toml")
        connections = []
        psycopg = types.ModuleType("psycopg")
        psycopg.connect = lambda value: connections.append(value) or "connection"
        key = base64.b64encode(b"k" * 32).decode("ascii")
        environment = {
            "PORTAL_DATABASE_URL": "postgresql://portal-secret-canary",
            "PORTAL_SESSION_KEY_CURRENT": key,
        }

        with mock.patch.dict(sys.modules, {"psycopg": psycopg}):
            with mock.patch.dict(os.environ, environment, clear=False):
                store = module.build_store(config)

        self.assertEqual(store.keys.primary_key_id, "current")
        self.assertEqual(store.keys.keys, {"current": b"k" * 32})
        self.assertEqual(store.connect(), "connection")
        self.assertEqual(connections, ["postgresql://portal-secret-canary"])

    def test_holder_reads_own_record_submits_review_and_reads_history(self):
        module, _, _, _ = load_example()
        config = module.load_config(ROOT / "config.example.toml")
        holder = Person("holder")

        submitted = module.holder_submit_review(
            holder,
            config,
            RECORD_ID,
            {"application": RECORD_ID, "status": "submitted"},
            "holder-review-001",
        )
        history = module.holder_review_history(holder, config, REQUEST_ID)

        holder.breg.get_record.assert_called_once_with(
            "applications",
            RECORD_ID,
            select=["reference", "profession", "status"],
            access_profile="applicant",
        )
        holder.breg.registry_contract.assert_called_once_with("applicant")
        holder.metadata.select_action.assert_called_once_with(
            "submit-application", "applicant"
        )
        holder.breg.start_proposal.assert_called_once_with(
            "submit-application-binding",
            {"application": RECORD_ID, "status": "submitted"},
            "holder-review-001:draft",
        )
        holder.breg.prepare_proposal.assert_called_once_with(
            holder.draft, "submit", {}, "holder-review-001:submit"
        )
        holder.breg.execute_proposal.assert_called_once_with(holder.prepared)
        holder.casework.review_history.assert_called_once_with(REQUEST_ID)
        self.assertEqual(submitted["proposal"]["requestId"], REQUEST_ID)
        self.assertEqual(history["items"][0]["status"], "approved")

    def test_staff_uses_exact_task_context_mutation_and_outcome_methods(self):
        module, _, _, _ = load_example()
        config = module.load_config(ROOT / "config.example.toml")
        staff = Person("staff")

        staff_dashboard = module.dashboard(staff, config)
        detail = module.staff_review_task(staff, config, TASK_ID)
        claimed = module.staff_claim_task(staff, config, TASK_ID, 4, "staff-claim-001")
        released = module.staff_release_task(
            staff, config, TASK_ID, 5, "staff-release-001"
        )
        decided = module.staff_decide_task(
            staff,
            config,
            TASK_ID,
            5,
            "staff-decision-001",
            {"decision": {"type": "approve", "outcome": "approved"}},
        )
        decisions = module.staff_own_decisions(staff, config, {"limit": 10})
        history = module.staff_review_history(staff, config, REQUEST_ID)

        staff.breg.list_records.assert_not_called()
        staff.casework.review_tasks.assert_called_once_with(
            {"queue": "applications"}, source_profile="auditor"
        )
        staff.casework.review_task.assert_called_once_with(
            TASK_ID, source_profile="auditor"
        )
        staff.casework.review_task_context.assert_called_once_with(
            TASK_ID, source_profile="auditor"
        )
        staff.metadata.select_proposal_review_context.assert_called_once_with(
            "auditor", "submit-application"
        )
        staff.breg.read_proposal_review_by_id.assert_called_once_with(
            "review-context-binding", PROPOSAL_ID
        )
        staff.breg.get_record.assert_not_called()
        staff.casework.claim_review_task.assert_called_once_with(
            TASK_ID, 4, "staff-claim-001", source_profile="auditor"
        )
        staff.casework.release_review_task.assert_called_once_with(
            TASK_ID, 5, "staff-release-001"
        )
        staff.casework.decide_review_task.assert_called_once_with(
            TASK_ID,
            5,
            "staff-decision-001",
            {"decision": {"type": "approve", "outcome": "approved"}},
            source_profile="auditor",
        )
        staff.casework.own_review_decisions.assert_called_once_with(
            {"limit": 10}, source_profile="auditor"
        )
        staff.casework.review_history.assert_called_once_with(
            REQUEST_ID, source_profile="auditor"
        )
        self.assertEqual(staff_dashboard["applications"], [])
        self.assertEqual(detail["task"]["taskId"], TASK_ID)
        self.assertEqual(detail["source"]["id"], PROPOSAL_ID)
        self.assertEqual(claimed["revision"], 5)
        self.assertEqual(released["revision"], 6)
        self.assertEqual(decided, {"status": "accepted"})
        self.assertEqual(decisions["items"][0]["requestId"], REQUEST_ID)
        self.assertEqual(history["items"][0]["status"], "approved")

    def test_mutations_refuse_changed_binding_or_revision_before_product_calls(self):
        module, _, _, _ = load_example()
        config = module.load_config(ROOT / "config.example.toml")
        holder = Person("holder")
        staff = Person("staff")

        with self.assertRaises(ValueError):
            module.holder_submit_review(
                holder,
                config,
                RECORD_ID,
                {"application": TASK_ID, "status": "submitted"},
                "holder-review-002",
            )
        holder.breg.get_record.assert_not_called()
        holder.breg.start_proposal.assert_not_called()

        with self.assertRaises(ValueError):
            module.staff_claim_task(staff, config, TASK_ID, -1, "staff-claim-refused")
        staff.casework.claim_review_task.assert_not_called()

        with self.assertRaises(PermissionError):
            module.staff_decide_task(
                holder,
                config,
                TASK_ID,
                4,
                "wrong-persona-decision",
                {"decision": {"type": "approve", "outcome": "approved"}},
            )
        holder.casework.decide_review_task.assert_not_called()

    def test_flask_html_and_fastapi_frontend_share_the_business_functions(self):
        module, portal_flask, portal_fastapi, _ = load_example()
        config = module.load_config(ROOT / "config.example.toml")

        holder = Person("holder")

        def install_flask(app, sessions, **kwargs):
            @app.before_request
            def person():
                g.registry_person = holder

        portal_flask.install = mock.Mock(side_effect=install_flask)
        holder_runtime = module.Runtime(
            config.services["holder"], object(), object(), lambda _: holder
        )
        flask_app = module.create_flask_app(config, holder_runtime)
        client = flask_app.test_client()
        page = client.get("/", base_url="https://holder.example.test")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"holder-subject", page.data)
        self.assertIn(b"holder-csrf", page.data)
        self.assertIn(b'action="/auth/logout"', page.data)
        self.assertIn(b'action="/auth/switch"', page.data)
        self.assertEqual(page.data.count(b'name="csrf_token"'), 2)
        self.assertEqual(page.headers["Cache-Control"], "no-store")
        submitted = client.post(
            f"/api/applications/{RECORD_ID}/reviews",
            base_url="https://holder.example.test",
            headers={
                "Origin": "https://holder.example.test",
                "X-CSRF-Token": "holder-csrf",
            },
            json={
                "idempotencyKey": "holder-review-route-001",
                "inputs": {"application": RECORD_ID, "status": "submitted"},
            },
        )
        self.assertEqual(submitted.status_code, 200)
        self.assertEqual(submitted.json["proposal"]["requestId"], REQUEST_ID)
        refused = client.post(
            f"/api/applications/{RECORD_ID}/reviews",
            base_url="https://holder.example.test",
            headers={
                "Origin": "https://holder.example.test",
                "X-CSRF-Token": "holder-csrf",
            },
            json={
                "idempotencyKey": "holder-review-route-refused",
                "inputs": {"application": TASK_ID, "status": "submitted"},
            },
        )
        self.assertEqual(refused.status_code, 400)
        self.assertEqual(refused.json, {"code": "request.invalid"})
        history = client.get(
            f"/api/review-requests/{REQUEST_ID}/history",
            base_url="https://holder.example.test",
        )
        self.assertEqual(history.status_code, 200)
        self.assertEqual(history.json["items"][0]["status"], "approved")

        staff = Person("staff")

        def install_fastapi(app, sessions, **kwargs):
            @app.middleware("http")
            async def person(request, call_next):
                request.state.registry_person = staff
                return await call_next(request)

        portal_fastapi.install = mock.Mock(side_effect=install_fastapi)
        staff_runtime = module.Runtime(
            config.services["staff"], object(), object(), lambda _: staff
        )
        fastapi_app = module.create_fastapi_app(config, staff_runtime)

        async def check_fastapi():
            transport = httpx.ASGITransport(app=fastapi_app)
            async with httpx.AsyncClient(
                transport=transport, base_url="https://staff.example.test"
            ) as client:
                page = await client.get("/")
                self.assertEqual(page.status_code, 200)
                self.assertIn("staff-csrf", page.text)
                self.assertIn('action="/auth/logout"', page.text)
                self.assertIn('action="/auth/switch"', page.text)
                self.assertEqual(page.text.count('name="csrf_token"'), 2)
                dashboard = await client.get("/api/dashboard")
                self.assertEqual(dashboard.status_code, 200)
                self.assertEqual(dashboard.json()["persona"], "staff")
                task = await client.get(f"/api/tasks/{TASK_ID}")
                self.assertEqual(task.json()["task"]["taskId"], TASK_ID)
                claim = await client.post(
                    f"/api/tasks/{TASK_ID}/claim",
                    headers={
                        "Origin": "https://staff.example.test",
                        "X-CSRF-Token": "staff-csrf",
                    },
                    json={"revision": 4, "idempotencyKey": "claim1"},
                )
                self.assertEqual(claim.json()["revision"], 5)
                release = await client.post(
                    f"/api/tasks/{TASK_ID}/release",
                    headers={
                        "Origin": "https://staff.example.test",
                        "X-CSRF-Token": "staff-csrf",
                    },
                    json={"revision": 5, "idempotencyKey": "release1"},
                )
                self.assertEqual(release.json()["revision"], 6)
                decision = await client.post(
                    f"/api/tasks/{TASK_ID}/decisions",
                    headers={
                        "Origin": "https://staff.example.test",
                        "X-CSRF-Token": "staff-csrf",
                    },
                    json={
                        "revision": 5,
                        "idempotencyKey": "decision1",
                        "decision": {"type": "approve", "outcome": "approved"},
                    },
                )
                self.assertEqual(decision.json(), {"status": "accepted"})
                decisions = await client.get("/api/decisions?limit=10")
                self.assertEqual(decisions.json()["items"][0]["requestId"], REQUEST_ID)
                history = await client.get(f"/api/review-requests/{REQUEST_ID}/history")
                self.assertEqual(history.json()["items"][0]["status"], "approved")
                refused = await client.post(
                    f"/api/applications/{RECORD_ID}/reviews",
                    headers={
                        "Origin": "https://staff.example.test",
                        "X-CSRF-Token": "staff-csrf",
                    },
                    json={
                        "idempotencyKey": "staff-holder-route-refused",
                        "inputs": {
                            "application": RECORD_ID,
                            "status": "submitted",
                        },
                    },
                )
                self.assertEqual(refused.status_code, 403)
                self.assertEqual(
                    refused.json(), {"code": "authorization.persona-refused"}
                )

        asyncio.run(check_fastapi())

    def test_store_lifecycle_cli_reports_only_bounded_results(self):
        example, _, _, _ = load_example()
        service = load_service(example)
        store = PostgresSessionStore(
            lambda: None,
            PortalEncryptionKeys(primary_key_id="current", keys={"current": b"k" * 32}),
        )
        service.load_config = mock.Mock(return_value="configuration")
        service.build_store = mock.Mock(return_value=store)

        for action, expected in (
            ("migrate", {"action": "migrate", "status": "complete"}),
            ("check-store", {"action": "check-store", "status": "ready"}),
            (
                "rotate-encryption",
                {"action": "rotate-encryption", "status": "complete", "rewritten": 3},
            ),
        ):
            output = io.StringIO()
            with self.subTest(action=action), contextlib.redirect_stdout(output):
                service.main([action, "--config", "operator.toml"])
            self.assertEqual(json.loads(output.getvalue()), expected)
        self.assertEqual(store.actions, ["migrate", "check_ready", "rotate_encryption"])


if __name__ == "__main__":
    unittest.main()
