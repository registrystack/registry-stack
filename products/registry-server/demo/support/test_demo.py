#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("demo.py")
SPEC = importlib.util.spec_from_file_location("registry_server_demo", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
DEMO = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DEMO
SPEC.loader.exec_module(DEMO)


def public_jwk(kid: str) -> dict[str, str]:
    return {
        "alg": "ES256",
        "crv": "P-256",
        "kid": kid,
        "kty": "EC",
        "x": "A" * 43,
        "y": "B" * 43,
    }


class DemoProvisioningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "run"
        self.root.mkdir(mode=0o700)
        (self.root / "secrets").mkdir(mode=0o700)
        password = self.root / "secrets/database-password"
        password.write_text("a" * 48, encoding="ascii")
        password.chmod(0o600)
        (self.root / "keys").mkdir()
        for name in ("mint", "operator", "no-purpose"):
            (self.root / f"keys/{name}-public.jwk.json").write_text(
                json.dumps(public_jwk(f"{name}-key")), encoding="utf-8"
            )
        self.fixture = MODULE_PATH.parents[2] / "acceptance/publicschema-household"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_prepare_binds_mint_authority_static_jwks_and_secret_database_urls(self) -> None:
        DEMO.prepare(self.root, self.fixture, 15432, 18081, 18080)

        project = (self.root / "project/registry.yaml").read_text(encoding="utf-8")
        self.assertIn("environment: local", project)
        self.assertIn(f"instanceId: {DEMO.INSTANCE_ID}", project)
        self.assertNotIn("publicschema-household-acceptance", project)
        self.assertFalse(any((self.root / "project").rglob(".DS_Store")))

        mint = (self.root / "mint/mint.yaml").read_text(encoding="utf-8")
        self.assertIn("validationMode: supervised-local-development", mint)
        self.assertIn("audiences: [urn:registry-server:household-demo]", mint)
        self.assertIn("algorithms: [ES256]", mint)
        self.assertNotIn("database-password", mint)
        operator = (self.root / "mint/clients/household-demo.yaml").read_text(encoding="utf-8")
        self.assertIn("registry_principal: synthetic-household-operator", operator)
        self.assertIn("registry_purpose: household-administration", operator)
        no_purpose = (self.root / "mint/clients/household-demo-no-purpose.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("registry_principal: synthetic-household-operator", no_purpose)
        self.assertNotIn("registry_purpose", no_purpose)

        runtime = (self.root / "runtime-test.yaml").read_text(encoding="utf-8")
        self.assertIn("accessTokenType: at+jwt", runtime)
        self.assertIn("kind: static", runtime)
        self.assertIn("documentRef: secret:file/mint-jwks", runtime)
        self.assertIn("principal: registry_principal", runtime)
        self.assertIn("purpose: registry_purpose", runtime)
        self.assertNotIn("a" * 48, runtime)
        self.assertEqual(
            json.loads((self.root / "secrets/mint-jwks").read_text(encoding="utf-8"))["keys"][0]["kid"],
            "mint-key",
        )
        for name in (
            "test-runtime-database-url",
            "test-migration-database-url",
            "runtime-database-url",
            "migration-database-url",
            "mint-jwks",
        ):
            self.assertEqual(os.stat(self.root / f"secrets/{name}").st_mode & 0o077, 0)

    def test_render_runtime_selects_exact_package_and_listener(self) -> None:
        DEMO.prepare(self.root, self.fixture, 15432, 18081, 18080)
        revision = "sha256:" + "2" * 64
        DEMO.render_runtime(self.root, revision)
        runtime = (self.root / "runtime.yaml").read_text(encoding="utf-8")
        self.assertIn(f"activeRevision: {revision}", runtime)
        self.assertIn(f"root: {self.root.resolve() / 'build/package'}", runtime)
        self.assertIn("bind: 127.0.0.1:18080", runtime)

    def test_webhook_mode_extends_only_the_disposable_module_and_binds_its_compiled_digest(
        self,
    ) -> None:
        webhook_key = self.root / "secrets/webhook-key"
        webhook_key.write_bytes(b"k" * 32)
        webhook_key.chmod(0o600)
        fixture_module = self.fixture / "modules/publicschema-household-demographics/module.yaml"
        original_fixture_module = fixture_module.read_bytes()

        DEMO.prepare(self.root, self.fixture, 15432, 18081, 18080, True, 18082)

        project_path = self.root / "project/registry.yaml"
        project = project_path.read_text(encoding="utf-8")
        module = (
            self.root / "project/modules/publicschema-household-demographics/module.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn(DEMO.WEBHOOK_MODULE_LOCK, project)
        self.assertNotIn(DEMO.WEBHOOK_MODULE_LOCK + "    digest:", project)
        self.assertIn("id: usual-resident-created-v1", module)
        self.assertIn("afterEquals: {residency-status: usual-resident}", module)
        self.assertEqual(fixture_module.read_bytes(), original_fixture_module)

        digest = "sha256:" + "3" * 64
        report = self.root / "explain.json"
        report.write_text(
            json.dumps(
                {
                    "explanation": {
                        "moduleClosure": [
                            {
                                "id": DEMO.WEBHOOK_MODULE_ID,
                                "version": "0.1.0",
                                "digest": digest,
                            }
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )
        DEMO.bind_webhook_module(self.root, report)
        self.assertIn(f"    digest: {digest}", project_path.read_text(encoding="utf-8"))

        runtime = (self.root / "runtime-test.yaml").read_text(encoding="utf-8")
        self.assertIn("origin: http://127.0.0.1:18082", runtime)
        self.assertIn("networkProfile: loopbackDevelopmentHttp", runtime)
        self.assertIn("dnsFamily: dualStackStrict", runtime)
        self.assertIn("hmacSha256KeyRef: secret:file/webhook-key", runtime)
        self.assertNotIn("k" * 32, runtime)

    def test_receiver_verifies_the_exact_cloudevents_and_signature_contract(self) -> None:
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        event_id = str(uuid.UUID("00000000-0000-4000-8000-000000000001"))
        body = json.dumps(
            {
                "entity": "person",
                "packageRevision": "sha256:" + "4" * 64,
                "recordId": "00000000-0000-4000-8000-000000000002",
                "revision": 1,
                "trigger": "created",
                "values": {
                    "person-code": "PERSON-DEMO-001",
                    "residency-status": "usual-resident",
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "ce-specversion": "1.0",
            "ce-id": event_id,
            "ce-source": (
                "urn:registrystack:registry:publicschema-household:"
                f"instance:{DEMO.INSTANCE_ID}"
            ),
            "ce-type": DEMO.WEBHOOK_EVENT_ID,
            "ce-time": "2026-01-01T00:00:00Z",
            "ce-dataschema": (
                "urn:registry-server:event-schema:publicschema-household:person:"
                f"{DEMO.WEBHOOK_EVENT_ID}:sha256:" + "5" * 64
            ),
            "x-registry-event-generation": "1",
            "x-registry-delivery-attempt": "1",
            "x-registry-delivery-time": now,
            "idempotency-key": "sha256:" + "6" * 64,
        }
        key = b"receiver-test-key" * 4
        headers["x-registry-signature"] = DEMO._expected_webhook_signature(key, headers, body)

        self.assertEqual(
            DEMO._verify_webhook_request(key, "/events", headers, body),
            (event_id, 1, 1, "sha256:" + "6" * 64),
        )
        tampered = dict(headers)
        tampered["idempotency-key"] = "sha256:" + "7" * 64
        with self.assertRaises(DEMO.DemoError):
            DEMO._verify_webhook_request(key, "/events", tampered, body)

    def test_dead_letter_selection_returns_only_replay_eligible_value_free_metadata(self) -> None:
        report = self.root / "list.json"
        event_id = "00000000-0000-4000-8000-000000000001"
        report.write_text(
            json.dumps(
                {
                    "deliveries": [
                        {
                            "eventId": event_id,
                            "deliveryId": "person.usual-resident-created-v1.webhook",
                            "generation": 1,
                            "state": "dead_lettered",
                            "replayEligible": True,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        self.assertEqual(
            DEMO.select_dead_letter(report),
            (event_id, "person.usual-resident-created-v1.webhook", 1),
        )

    def test_seed_is_referentially_closed_and_stable(self) -> None:
        people, households, memberships = DEMO.seed_spec()
        person_codes = {person["person-code"] for person in people}
        household_codes = {household["household-code"] for household in households}
        self.assertEqual((len(people), len(households), len(memberships)), (5, 2, 5))
        self.assertEqual(len(person_codes), len(people))
        self.assertEqual(len(household_codes), len(households))
        self.assertTrue(all(row["person-code"] in person_codes for row in memberships))
        self.assertTrue(all(row["household-code"] in household_codes for row in memberships))
        self.assertEqual(
            sum(person["residency-status"] == "usual-resident" for person in people),
            4,
        )

    def test_prepare_refuses_a_fixture_without_the_expected_localization_boundary(self) -> None:
        bad_fixture = Path(self.temporary.name) / "bad-fixture"
        bad_fixture.mkdir()
        (bad_fixture / "registry.yaml").write_text("apiVersion: wrong\n", encoding="utf-8")
        with self.assertRaisesRegex(DEMO.DemoError, "expected package line"):
            DEMO.prepare(self.root, bad_fixture, 15432, 18081, 18080)

    def test_demo_root_must_not_be_a_symbolic_link(self) -> None:
        linked_root = Path(self.temporary.name) / "linked-run"
        linked_root.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(DEMO.DemoError, "must not be a symbolic link"):
            DEMO.prepare(linked_root, self.fixture, 15432, 18081, 18080)

    def test_token_capture_removes_transport_newline_and_uses_owner_only_mode(self) -> None:
        output = self.root / "secrets/token"
        DEMO.store_token(output, b"aaa.bbb.ccc\n")

        self.assertEqual("aaa.bbb.ccc", output.read_text(encoding="ascii"))
        self.assertEqual(0, output.stat().st_mode & 0o077)
        with self.assertRaises(FileExistsError):
            DEMO.store_token(output, b"ddd.eee.fff\n")

    def test_token_capture_refuses_non_compact_output(self) -> None:
        for value in (b"not a token\n", b" aaa.bbb.ccc\n"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(DEMO.DemoError, "compact JWT"):
                    DEMO.store_token(self.root / "secrets/token", value)


if __name__ == "__main__":
    unittest.main()
