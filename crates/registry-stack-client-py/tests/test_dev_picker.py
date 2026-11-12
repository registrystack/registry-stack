"""The local picker accepts only one live runner's complete development authority."""

from __future__ import annotations

import asyncio
import base64
import fcntl
import importlib
import json
from pathlib import Path
import re
import sys
import tempfile
import time
import types
import unittest

from fastapi import FastAPI, Request
from flask import Flask, g, jsonify
import httpx


SOURCE = Path(__file__).resolve().parents[1] / "python" / "registry_client"
PACKAGE = "_registry_client_dev_picker_test"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(SOURCE)]
sys.modules[PACKAGE] = package
yaml_module = types.ModuleType(f"{PACKAGE}.yaml")


class ConfigReadError(ValueError):
    def __init__(self, message, *, diagnostics=()):
        super().__init__(message)
        self.diagnostics = diagnostics


def read_document(contents, *, file, api_version, kind):
    try:
        value = json.loads(contents)
    except (UnicodeError, json.JSONDecodeError):
        raise ConfigReadError("invalid document") from None
    if value.get("apiVersion") != api_version or value.get("kind") != kind:
        raise ConfigReadError("wrong envelope")
    return value


yaml_module.ConfigReadError = ConfigReadError
yaml_module.read_document = read_document
sys.modules[yaml_module.__name__] = yaml_module
portal = importlib.import_module(f"{PACKAGE}.portal")
dev_picker = importlib.import_module(f"{PACKAGE}.dev_picker")


RUN_ID = "0123456789abcdef0123456789abcdef"


def _segment(value):
    return base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


def _token(*, product, persona, generation, issued, expires, **changes):
    audience = f"urn:test:{product}"
    claims = {
        "iss": "https://issuer.example.test",
        "aud": audience,
        "sub": "person-one",
        "client_id": "portal-client",
        "scope": f"{product}:read",
        "registry_principal": "person-one",
        "registry_dev_persona": persona,
        "iat": issued,
        "exp": expires,
        "jti": f"generation-{generation}-{product}",
    }
    claims.update(changes)
    return f"{_segment({'typ': 'at+jwt'})}.{_segment(claims)}.signature"


class LivePicker:
    def __init__(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.root = Path(self.scratch.name) / RUN_ID
        self.root.mkdir(mode=0o700)
        self.lock_path = self.root / "worker.lock"
        self.lock_path.write_bytes(b"")
        self.lock_path.chmod(0o600)
        self.lock = self.lock_path.open("rb")
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.now = int(time.time())
        self.expires = self.now + 600
        self.origin = "http://127.0.0.1:43891"
        self.persona = "holder"
        self.namespace = "run-namespace-canary"
        self.picker_root = self.root / "python-picker" / self.persona
        self.picker_root.mkdir(parents=True, mode=0o700)
        self.picker_root.parent.chmod(0o700)
        self.workload_root = self.root / "python-workload"
        self.workload_root.mkdir(mode=0o700)
        self.descriptor_path = self.picker_root / "picker.json"
        self.selector = "opaque-selector-canary"
        self._write_report("ready")
        self._write_connection()
        self.write_generation(1)
        self.write_token("breg", 1)
        self.write_token("casework", 1)
        self.write_descriptor()

    def close(self):
        self.lock.close()
        self.scratch.cleanup()

    def _write_json(self, path, value):
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(0o600)

    def _write_report(self, status):
        self._write_json(
            self.root / "report.json",
            {
                "schema_version": "registry.rstack.dev.v1",
                "run_id": RUN_ID,
                "status": status,
                "expires_at": self.expires,
            },
        )

    def _write_connection(
        self,
        *,
        endpoint="http://127.0.0.1:49201",
        credential_type="runner-token",
        run_id=RUN_ID,
    ):
        credential = {
            "type": credential_type,
            "tokenRef": "secret:file/workload-notices.json",
            "runId": run_id,
            "binding": "notices",
            "issuer": "https://issuer.example.test",
            "subject": "notice-service",
            "clientId": "notice-client",
            "profile": "service-sender",
            "resource": "urn:test:messaging",
            "scopes": ["messaging:send"],
            "claims": {"registry_actor_kind": "service"},
            "runExpiresAt": self.expires,
        }
        if credential_type != "runner-token":
            credential = {
                "type": "private-key-jwt",
                "issuer": "https://production.example.test/",
                "subject": "production-service",
                "tokenEndpoint": "https://production.example.test/token",
                "clientId": "production",
                "profile": "service-sender",
                "clientKeyRef": "secret:env/PRODUCTION_KEY",
                "resource": "urn:test:messaging",
                "scopes": ["messaging:send"],
                "claims": {"registry_actor_kind": "service"},
            }
        self._write_json(
            self.workload_root / "python-connection.json",
            {
                "apiVersion": "id.registrystack.org/formats/platform/python-connection/v1alpha1",
                "kind": "PlatformPythonConnection",
                "service": f"rstack-dev-{RUN_ID}",
                "audience": "service",
                "secretProviders": {"file": {"root": str(self.workload_root.resolve())}},
                "bindings": [{
                    "name": "notices",
                    "product": "messaging",
                    "url": endpoint,
                    "default": True,
                    "credential": credential,
                }],
            },
        )

    def write_descriptor(self, **changes):
        descriptor = {
            "apiVersion": "id.registrystack.org/formats/platform/dev-person-picker/v1alpha1",
            "kind": "PlatformDevPersonPicker",
            "runId": RUN_ID,
            "persona": self.persona,
            "origin": self.origin,
            "sessionNamespace": self.namespace,
            "issuedAt": self.now,
            "expiresAt": self.expires,
            "generationRef": "generation.json",
            "products": {
                "breg": {"url": "http://127.0.0.1:49199", "resource": "urn:test:breg"},
                "casework": {"url": "http://127.0.0.1:49200", "resource": "urn:test:casework"},
                "messaging": {"url": "http://127.0.0.1:49201", "resource": "urn:test:messaging"},
            },
            "people": [{
                "selector": self.selector,
                "label": "Applicant One",
                "subject": "person-one",
                "principal": "person-one",
                "clientId": "portal-client",
                "credentials": {
                    product: {
                        "tokenRef": f"person-one-{product}.json",
                        "profile": "applicant" if product == "breg" else "requester",
                        "resource": f"urn:test:{product}",
                        "audiences": [f"urn:test:{product}"],
                        "scopes": [f"{product}:read"],
                        "principalClaim": "registry_principal",
                    }
                    for product in ("breg", "casework")
                },
            }],
            "workloadConnectionRef": "../../python-workload/python-connection.json",
            "workloads": [{
                "name": "notices",
                "product": "messaging",
                "default": True,
                "url": "http://127.0.0.1:49201",
                "issuer": "https://issuer.example.test",
                "subject": "notice-service",
                "clientId": "notice-client",
                "profile": "service-sender",
                "resource": "urn:test:messaging",
                "scopes": ["messaging:send"],
                "claims": {"registry_actor_kind": "service"},
            }],
        }
        descriptor.update(changes)
        self._write_json(self.descriptor_path, descriptor)

    def write_generation(self, generation, *, status="ready", run_id=RUN_ID):
        self._write_json(
            self.picker_root / "generation.json",
            {
                "apiVersion": "id.registrystack.org/formats/platform/dev-person-generation/v1alpha1",
                "kind": "PlatformDevPersonGeneration",
                "status": status,
                "runId": run_id,
                "picker": self.persona,
                "generation": generation,
                "runExpiresAt": self.expires,
            },
        )

    def write_token(self, product, generation, **changes):
        state = {
            "apiVersion": "id.registrystack.org/formats/platform/dev-person-token/v1alpha1",
            "kind": "PlatformDevPersonToken",
            "runId": RUN_ID,
            "picker": self.persona,
            "persona": self.persona,
            "selector": self.selector,
            "product": product,
            "issuer": "https://issuer.example.test",
            "subject": "person-one",
            "principal": "person-one",
            "clientId": "portal-client",
            "profile": "applicant" if product == "breg" else "requester",
            "resource": f"urn:test:{product}",
            "audiences": [f"urn:test:{product}"],
            "scopes": [f"{product}:read"],
            "principalClaim": "registry_principal",
            "generation": generation,
            "issuedAt": self.now,
            "expiresAt": min(self.now + 300, self.expires),
            "runExpiresAt": self.expires,
            "token": _token(
                product=product,
                persona=self.persona,
                generation=generation,
                issued=self.now,
                expires=min(self.now + 300, self.expires),
            ),
        }
        state.update(changes)
        self._write_json(self.picker_root / f"person-one-{product}.json", state)


class DevelopmentPickerTests(unittest.TestCase):
    def setUp(self):
        self.live = LivePicker()

    def tearDown(self):
        self.live.close()

    def picker(self):
        return dev_picker.DevelopmentPicker.from_descriptor(self.live.descriptor_path)

    def select(self, picker=None):
        picker = picker or self.picker()
        form = picker.begin()
        session = picker.select(
            form.pending_id,
            selector=self.live.selector,
            origin=self.live.origin,
            host="127.0.0.1:43891",
            csrf_token=form.csrf_token,
        )
        return picker, session

    def test_only_a_private_live_runner_descriptor_mounts(self):
        picker = self.picker()
        self.assertEqual(picker.origin, self.live.origin)
        self.assertEqual(picker.persona, "holder")
        self.assertIn(self.live.namespace, picker.session_cookie)
        self.assertEqual(
            [(choice.label, choice.selector) for choice in picker.choices()],
            [("Applicant One", self.live.selector)],
        )
        self.assertNotIn("person-one", repr(picker))
        self.live.lock.close()
        with self.assertRaisesRegex(dev_picker.PickerUnavailable, "live development run"):
            dev_picker.DevelopmentPicker.from_descriptor(self.live.descriptor_path)

    def test_nonloopback_wrong_run_stopped_expired_and_copied_descriptors_are_refused(self):
        cases = (
            {"origin": "https://portal.example.test"},
            {"runId": "f" * 32},
            {"expiresAt": self.live.now - 1},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.live.write_descriptor(**changes)
                with self.assertRaises(dev_picker.PickerUnavailable):
                    dev_picker.DevelopmentPicker.from_descriptor(self.live.descriptor_path)
        self.live.write_descriptor()
        self.live._write_report("stopping")
        with self.assertRaises(dev_picker.PickerUnavailable):
            dev_picker.DevelopmentPicker.from_descriptor(self.live.descriptor_path)
        self.live._write_report("ready")
        copied = self.live.root / "copied.json"
        copied.write_bytes(self.live.descriptor_path.read_bytes())
        copied.chmod(0o600)
        with self.assertRaises(dev_picker.PickerUnavailable):
            dev_picker.DevelopmentPicker.from_descriptor(copied)

    def test_selection_is_opaque_csrf_bound_and_all_or_nothing(self):
        picker = self.picker()
        form = picker.begin()
        for selector, origin, host, csrf in (
            ("person-one", self.live.origin, "127.0.0.1:43891", form.csrf_token),
            (self.live.selector, "http://127.0.0.1:1", "127.0.0.1:43891", form.csrf_token),
            (self.live.selector, self.live.origin, "127.0.0.1:1", form.csrf_token),
            (self.live.selector, self.live.origin, "127.0.0.1:43891", "wrong"),
        ):
            with self.subTest(selector=selector, origin=origin, host=host, csrf=csrf):
                with self.assertRaises(dev_picker.PickerAdmissionError):
                    picker.select(
                        form.pending_id,
                        selector=selector,
                        origin=origin,
                        host=host,
                        csrf_token=csrf,
                    )
        self.assertEqual(picker.session_count(), 0)
        self.live.write_token("casework", 1, persona="staff")
        with self.assertRaises(dev_picker.PickerAdmissionError):
            picker.select(
                form.pending_id,
                selector=self.live.selector,
                origin=self.live.origin,
                host="127.0.0.1:43891",
                csrf_token=form.csrf_token,
            )
        self.assertEqual(picker.session_count(), 0)

    def test_complete_session_tracks_rotation_and_refuses_mismatch_stop_or_old_run(self):
        picker, session = self.select()
        context = picker.context(session.session_id)
        self.assertEqual(context.subject, "person-one")
        self.assertEqual(context.persona, "holder")
        self.assertNotIn("canary", repr(context))

        self.live.write_token("breg", 2)
        with self.assertRaises(dev_picker.PickerUnavailable):
            picker.context(session.session_id)
        self.live.write_token("casework", 2)
        self.live.write_generation(2)
        rotated = picker.context(session.session_id)
        self.assertEqual(rotated.session_id, session.session_id)

        self.live.write_generation(3, status="stopped")
        with self.assertRaises(portal.ReauthenticationRequired):
            picker.context(session.session_id)
        self.assertEqual(picker.session_count(), 0)

    def test_person_clients_are_bound_to_descriptor_endpoints(self):
        class NativeBReg:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs

        class NativeCasework:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs

        breg_module = types.ModuleType(f"{PACKAGE}.breg")
        breg_module.BaseRegistryClient = NativeBReg
        casework_module = types.ModuleType(f"{PACKAGE}.casework")
        casework_module.CaseworkClient = NativeCasework
        sys.modules[breg_module.__name__] = breg_module
        sys.modules[casework_module.__name__] = casework_module
        setattr(package, "breg", breg_module)
        setattr(package, "casework", casework_module)

        picker, session = self.select()
        person = picker.context(session.session_id)
        self.assertEqual(person.breg._client.args[0], "http://127.0.0.1:49199")
        self.assertEqual(
            person.breg._client.kwargs["authorization"]["static"],
            person._context._token_for("breg"),
        )
        casework = person.casework
        self.assertEqual(
            casework._CaseworkWorkload__client.args[0], "http://127.0.0.1:49200"
        )
        self.assertEqual(casework._CaseworkWorkload__profile, "requester")
        self.assertNotIn("http", repr(person))

    def test_tampered_identity_audience_client_or_missing_product_opens_no_session(self):
        mutations = (
            ("breg", {"subject": "other"}),
            ("breg", {"clientId": "other-client"}),
            ("breg", {"audiences": ["urn:other"]}),
            ("casework", {"resource": "urn:other"}),
        )
        for product, changes in mutations:
            with self.subTest(product=product, changes=changes):
                self.live.write_token(product, 1, **changes)
                picker = self.picker()
                form = picker.begin()
                with self.assertRaises(dev_picker.PickerAdmissionError):
                    picker.select(
                        form.pending_id,
                        selector=self.live.selector,
                        origin=self.live.origin,
                        host="127.0.0.1:43891",
                        csrf_token=form.csrf_token,
                    )
                self.assertEqual(picker.session_count(), 0)
                self.live.write_token(product, 1)
        (self.live.picker_root / "person-one-casework.json").unlink()
        with self.assertRaises(dev_picker.PickerUnavailable):
            self.picker()

    def test_workload_connection_is_same_run_runner_only_and_endpoint_bound(self):
        picker = self.picker()
        connection = picker.workloads
        self.assertEqual(connection.using("notices")._binding.product, "messaging")

        self.live._write_connection(endpoint="http://127.0.0.1:49999")
        with self.assertRaisesRegex(dev_picker.PickerUnavailable, "workload"):
            self.picker().workloads
        self.live._write_connection(credential_type="private-key-jwt")
        with self.assertRaisesRegex(dev_picker.PickerUnavailable, "workload"):
            self.picker().workloads
        self.live._write_connection(run_id="f" * 32)
        with self.assertRaisesRegex(dev_picker.PickerUnavailable, "workload"):
            self.picker().workloads
        self.live._write_connection()
        connection_path = self.live.workload_root / "python-connection.json"
        connection = json.loads(connection_path.read_text(encoding="utf-8"))
        connection["bindings"][0]["credential"]["claims"] = {
            "registry_actor_kind": "human"
        }
        self.live._write_json(connection_path, connection)
        with self.assertRaisesRegex(dev_picker.PickerUnavailable, "workload"):
            self.picker().workloads


class FrameworkPickerTests(unittest.TestCase):
    def setUp(self):
        self.live = LivePicker()

    def tearDown(self):
        self.live.close()

    @staticmethod
    def _form(body):
        values = {}
        for name in ("pending_id", "selector", "csrf_token"):
            pattern = (
                rb'<select name="selector"><option value="([^"]+)"'
                if name == "selector"
                else rf'name="{name}" value="([^"]+)"'.encode()
            )
            match = re.search(pattern, body)
            assert match is not None
            values[name] = match.group(1).decode()
        return values

    def test_flask_starter_has_origin_csrf_cookie_and_secret_separation(self):
        picker = dev_picker.DevelopmentPicker.from_descriptor(self.live.descriptor_path)
        app = Flask(__name__)

        @app.get("/")
        def home():
            return jsonify({"subject": g.registry_person.subject})

        dev_picker.install_flask(
            app, picker, person_factory=lambda context: context, request_seconds=1
        )
        client = app.test_client()
        base = self.live.origin
        login = client.get("/auth/dev", base_url=base)
        self.assertEqual(login.status_code, 200)
        self.assertNotIn(b"person-one", login.data)
        self.assertNotIn(b"Bearer", login.data)
        form = self._form(login.data)
        refused = client.post(
            "/auth/dev", base_url=base, data=form, headers={"Origin": "http://127.0.0.1:1"}
        )
        self.assertEqual(refused.status_code, 403)
        form = self._form(client.get("/auth/dev", base_url=base).data)
        selected = client.post(
            "/auth/dev", base_url=base, data=form, headers={"Origin": base}
        )
        self.assertEqual(selected.status_code, 302)
        self.assertIn(picker.session_cookie, selected.headers["Set-Cookie"])
        self.assertNotIn(picker.pending_cookie, selected.headers["Set-Cookie"])
        self.assertEqual(client.get("/", base_url=base).json, {"subject": "person-one"})
        self.assertEqual(client.get("/", base_url="http://127.0.0.1:1").status_code, 400)

    def test_fastapi_starter_routes_the_same_picker_contract(self):
        async def exercise():
            picker = dev_picker.DevelopmentPicker.from_descriptor(self.live.descriptor_path)
            app = FastAPI()

            @app.get("/")
            async def home(request: Request):
                return {"subject": request.state.registry_person.subject}

            dev_picker.install_fastapi(
                app, picker, person_factory=lambda context: context, request_seconds=1
            )
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url=self.live.origin) as client:
                login = await client.get("/auth/dev")
                self.assertEqual(login.status_code, 200)
                form = self._form(login.content)
                selected = await client.post(
                    "/auth/dev", data=form, headers={"Origin": self.live.origin}
                )
                self.assertEqual(selected.status_code, 302)
                response = await client.get("/")
                self.assertEqual(response.json(), {"subject": "person-one"})

        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
