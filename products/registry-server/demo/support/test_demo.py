#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import base64
import json
import os
import re
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


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


def compact_jwt(expires: int) -> str:
    def encode(value: dict[str, object]) -> str:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{encode({'alg': 'ES256', 'typ': 'JWT'})}.{encode({'exp': expires})}.signature"


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
        for name in ("mint", "operator", "no-purpose", "viewer"):
            (self.root / f"keys/{name}-public.jwk.json").write_text(
                json.dumps(public_jwk(f"{name}-key")), encoding="utf-8"
            )
        self.fixture = MODULE_PATH.parents[2] / "acceptance/business-establishments"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_prepare_binds_mint_authority_static_jwks_and_secret_database_urls(self) -> None:
        DEMO.prepare(self.root, self.fixture, 15432, 18081, 18080)

        project = (self.root / "project/registry.yaml").read_text(encoding="utf-8")
        self.assertIn("environment: local", project)
        self.assertIn(f"instanceId: {DEMO.BUSINESS_INSTANCE_ID}", project)
        self.assertNotIn("business-establishments-acceptance", project)
        self.assertFalse(any((self.root / "project").rglob(".DS_Store")))

        mint = (self.root / "mint/mint.yaml").read_text(encoding="utf-8")
        self.assertIn("validationMode: supervised-local-development", mint)
        self.assertIn("audiences: [urn:registry-server:business-demo]", mint)
        self.assertIn("lifetimeSeconds: 300", mint)
        self.assertIn("algorithms: [ES256]", mint)
        self.assertNotIn("database-password", mint)
        operator = (self.root / "mint/clients/business-demo.yaml").read_text(encoding="utf-8")
        self.assertIn('registry_principal: "synthetic-business-operator"', operator)
        self.assertIn('registry_purpose: "business-administration"', operator)
        no_purpose = (self.root / "mint/clients/business-demo-no-purpose.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn('registry_principal: "synthetic-business-operator"', no_purpose)
        self.assertNotIn("registry_purpose", no_purpose)

        runtime = (self.root / "runtime-test.yaml").read_text(encoding="utf-8")
        self.assertIn("apiVersion: registry.registrystack.org/server-runtime/v1alpha1", runtime)
        self.assertIn("kind: RegistryServerRuntimeConfig", runtime)
        self.assertIn("accessTokenType: at+jwt", runtime)
        self.assertIn("maxTokenLifetimeSeconds: 300", runtime)
        self.assertIn("kind: static", runtime)
        self.assertIn("documentRef: secret:file/mint-jwks", runtime)
        self.assertIn("principal: registry_principal", runtime)
        self.assertIn("purpose: registry_purpose", runtime)
        self.assertIn("business-demo-viewer", runtime)
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
        database_setup = (self.root / "database/initialize.sql").read_text(
            encoding="utf-8"
        )
        for schema in (
            "registry_internal",
            "registry_data",
            "registry_source",
            "registry_derived",
            "registry_context",
        ):
            self.assertIn(f"CREATE SCHEMA {schema}", database_setup)

    def test_render_runtime_selects_exact_package_and_listener(self) -> None:
        DEMO.prepare(self.root, self.fixture, 15432, 18081, 18080)
        revision = "sha256:" + "2" * 64
        DEMO.render_runtime(self.root, revision)
        runtime = (self.root / "runtime.yaml").read_text(encoding="utf-8")
        self.assertIn(f"activeRevision: {revision}", runtime)
        self.assertIn(f"root: {self.root.resolve() / 'build/package'}", runtime)
        self.assertIn("bind: 127.0.0.1:18080", runtime)

    def test_token_lifetime_override_binds_mint_and_server_consistently(self) -> None:
        DEMO.prepare(
            self.root,
            self.fixture,
            15432,
            18081,
            18080,
            token_lifetime_seconds=900,
        )
        mint = (self.root / "mint/mint.yaml").read_text(encoding="utf-8")
        runtime_test = (self.root / "runtime-test.yaml").read_text(encoding="utf-8")
        self.assertIn("lifetimeSeconds: 900", mint)
        self.assertIn("maxTokenLifetimeSeconds: 900", runtime_test)

        revision = "sha256:" + "2" * 64
        DEMO.render_runtime(self.root, revision, token_lifetime_seconds=900)
        runtime = (self.root / "runtime.yaml").read_text(encoding="utf-8")
        self.assertIn("maxTokenLifetimeSeconds: 900", runtime)

    def test_token_lifetime_override_is_bounded(self) -> None:
        with self.assertRaisesRegex(DEMO.DemoError, "between 60 and 900"):
            DEMO.prepare(
                self.root,
                self.fixture,
                15432,
                18081,
                18080,
                token_lifetime_seconds=59,
            )
        with self.assertRaisesRegex(DEMO.DemoError, "between 60 and 900"):
            DEMO.render_runtime(
                self.root,
                "sha256:" + "2" * 64,
                token_lifetime_seconds=901,
            )

    def test_webhook_mode_extends_only_the_disposable_module_and_binds_its_compiled_digest(
        self,
    ) -> None:
        webhook_key = self.root / "secrets/webhook-key"
        webhook_key.write_bytes(b"k" * 32)
        webhook_key.chmod(0o600)
        fixture_module = self.fixture / "modules/business-establishment-summary/module.yaml"
        original_fixture_module = fixture_module.read_bytes()

        DEMO.prepare(self.root, self.fixture, 15432, 18081, 18080, True, 18082)

        project_path = self.root / "project/registry.yaml"
        project = project_path.read_text(encoding="utf-8")
        module = (
            self.root / "project/modules/business-establishment-summary/module.yaml"
        ).read_text(encoding="utf-8")
        hook = DEMO.FIXTURE_CONFIGS["business-establishments"]["webhook"]
        self.assertIn(hook["module_lock"], project)
        self.assertNotIn(hook["module_lock"] + "    digest:", project)
        self.assertIn("id: operating-created-v1", module)
        self.assertIn("afterEquals:\n            operating-status: operating", module)
        self.assertLess(
            module.index("id: operating-created-v1"),
            module.index(hook["entity_insertion"]),
        )
        self.assertEqual(fixture_module.read_bytes(), original_fixture_module)

        digest = "sha256:" + "3" * 64
        report = self.root / "explain.json"
        report.write_text(
            json.dumps(
                {
                    "explanation": {
                        "moduleClosure": [
                            {
                                "id": hook["module_id"],
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
                "entity": "establishment",
                "packageRevision": "sha256:" + "4" * 64,
                "recordId": "00000000-0000-4000-8000-000000000002",
                "revision": 1,
                "trigger": "created",
                "values": {
                    "establishment-code": "ESTABLISHMENT-DEMO-001",
                    "operating-status": "operating",
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
                "urn:registrystack:registry:business-establishments:"
                f"instance:{DEMO.BUSINESS_INSTANCE_ID}"
            ),
            "ce-type": "operating-created-v1",
            "ce-time": "2026-01-01T00:00:00Z",
            "ce-dataschema": (
                "urn:registry-server:event-schema:business-establishments:establishment:"
                "operating-created-v1:sha256:" + "5" * 64
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
                            "deliveryId": "establishment.operating-created-v1.webhook",
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
            (event_id, "establishment.operating-created-v1.webhook", 1),
        )

    def test_webhook_verification_covers_every_matching_seeded_establishment(self) -> None:
        (self.root / "fixture-kind").write_text("business-establishments\n", encoding="ascii")
        establishments, _, _ = DEMO.business_seed_spec()
        events = {}
        slot = 0
        for establishment in establishments:
            if establishment["operatingStatus"] != "operating":
                continue
            slot += 1
            attempts = [{"generation": 1, "attempt": 1, "accepted": True}]
            if slot == 2:
                attempts = [
                    {"generation": 1, "attempt": 1, "accepted": False},
                    {"generation": 1, "attempt": 2, "accepted": True},
                ]
            elif slot == 3:
                attempts = [
                    {"generation": 1, "attempt": 1, "accepted": False},
                    {"generation": 2, "attempt": 1, "accepted": True},
                ]
            events[f"event-{slot}"] = {"slot": slot, "attempts": attempts}
        (self.root / "webhook-receiver-state.json").write_text(
            json.dumps({"verificationFailures": 0, "events": events}),
            encoding="utf-8",
        )

        DEMO.verify_webhook(self.root)

        events.pop(next(reversed(events)))
        (self.root / "webhook-receiver-state.json").write_text(
            json.dumps({"verificationFailures": 0, "events": events}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(DEMO.DemoError, "every matching seeded event"):
            DEMO.verify_webhook(self.root)

    def test_schema_test_credentials_cover_every_packaged_journey_step(self) -> None:
        DEMO.prepare(self.root, self.fixture, 15432, 18081, 18080)
        journey_source = (self.root / "project/tests/journeys.yaml").read_text(
            encoding="utf-8"
        )
        credential_source = (self.root / "schema-test-credentials.yaml").read_text(
            encoding="utf-8"
        )
        journey_id = next(
            line.removeprefix("  - id: ").strip()
            for line in journey_source.splitlines()
            if line.startswith("  - id: ")
        )
        expected = {
            (journey_id, line.removeprefix("      - id: ").strip())
            for line in journey_source.splitlines()
            if line.startswith("      - id: ")
        }
        actual = set(
            re.findall(
                r"journeyId: ([a-z0-9-]+), stepId: ([a-z0-9-]+)",
                credential_source,
            )
        )
        self.assertEqual(actual, expected)

    def test_business_seed_is_referentially_closed_and_stable(self) -> None:
        establishments, businesses, assignments = DEMO.business_seed_spec()
        establishment_codes = {item["establishmentCode"] for item in establishments}
        business_codes = {business["businessCode"] for business in businesses}
        self.assertEqual((len(establishments), len(businesses), len(assignments)), (8, 3, 8))
        self.assertEqual(len(establishment_codes), len(establishments))
        self.assertEqual(len(business_codes), len(businesses))
        self.assertTrue(
            all(
                "-" not in key
                for rows in (establishments, businesses, assignments)
                for row in rows
                for key in row
            ),
            "seed data must use compiled public API field names",
        )
        self.assertEqual(
            [business["localRegistrationNumber"] for business in businesses],
            [1001, 1002, 1003],
        )
        self.assertTrue(all(row["establishmentCode"] in establishment_codes for row in assignments))
        self.assertTrue(all(row["businessCode"] in business_codes for row in assignments))
        self.assertEqual(
            {item["operatingStatus"] for item in establishments},
            {"operating", "suspended"},
        )
        self.assertEqual(
            sum(item["operatingStatus"] == "operating" for item in establishments),
            7,
        )

    def test_viewer_registration_is_created_only_after_a_business_id_is_known(self) -> None:
        DEMO.prepare(self.root, self.fixture, 15432, 18081, 18080)
        business_id = "0198f0f5-0877-7ae2-a853-09f2d47b6840"
        (self.root / "seed-record-ids.json").write_text(
            json.dumps(
                {
                    "establishments": {},
                    "businesses": {"BUSINESS-DEMO-001": business_id},
                }
            ),
            encoding="utf-8",
        )

        DEMO.configure_viewer(self.root)

        viewer = (self.root / "mint/clients/business-demo-viewer.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn('scopes: ["registry:business:view"]', viewer)
        self.assertIn(f'business_id: "{business_id}"', viewer)
        self.assertIn('business_code: "BUSINESS-DEMO-001"', viewer)
        self.assertIn('registry_purpose: "business-view"', viewer)
        self.assertIn("viewer-key", viewer)
        self.assertNotIn("signing-p256-private-jwk", viewer)

    def test_viewer_registration_refuses_a_non_uuid_bound_record(self) -> None:
        DEMO.prepare(self.root, self.fixture, 15432, 18081, 18080)
        (self.root / "seed-record-ids.json").write_text(
            json.dumps({"businesses": {"BUSINESS-DEMO-001": "not-a-record-id"}}),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(DEMO.DemoError, "not a UUID"):
            DEMO.configure_viewer(self.root)

    def test_viewer_queries_prove_bound_get_claim_lookup_and_concealed_denials(self) -> None:
        business_id = "0198f0f5-0877-7ae2-a853-09f2d47b6840"
        (self.root / "seed-record-ids.json").write_text(
            json.dumps({"businesses": {"BUSINESS-DEMO-001": business_id}}),
            encoding="utf-8",
        )
        calls: list[tuple[str, str, str, object, object]] = []

        def request(
            root: Path,
            method: str,
            path: str,
            token_name: str,
            body: dict[str, object] | None = None,
            idempotency_key: str | None = None,
            expected: int = 200,
        ) -> tuple[dict[str, object], dict[str, str]]:
            self.assertEqual(root, self.root.resolve())
            calls.append((method, path, token_name, body, expected))
            if expected == 404:
                return {"code": "resource.not_found"}, {}
            return {
                "id": business_id,
                "revision": 1,
                "data": {"businessCode": "BUSINESS-DEMO-001"},
            }, {}

        with mock.patch.object(DEMO, "_request", side_effect=request), mock.patch.object(
            DEMO, "_print_query"
        ):
            DEMO.query_business(self.root, "viewer")

        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[0][0:3], ("GET", f"/v1/records/businesses/{business_id}?accessProfile=business-viewer", "viewer-token"))
        self.assertEqual(calls[1][0:3], ("POST", "/v1/records/businesses:lookup?accessProfile=business-viewer", "viewer-token"))
        self.assertEqual(calls[1][3], {"selector": "by-business-code"})
        self.assertTrue(all(call[2] == "viewer-token" for call in calls))
        self.assertEqual([call[4] for call in calls], [200, 200, 404, 404])

    def test_operator_selector_query_uses_the_exact_values_property(self) -> None:
        business_id = "0198f0f5-0877-7ae2-a853-09f2d47b6840"
        (self.root / "seed-record-ids.json").write_text(
            json.dumps({"businesses": {"BUSINESS-DEMO-001": business_id}}),
            encoding="utf-8",
        )
        calls: list[tuple[str, str, object]] = []
        expected_get_rows = [
            [
                {"establishmentCode": "ESTABLISHMENT-DEMO-001", "siteName": "North Quay Head Office", "establishmentKind": "office", "operatingStatus": "operating"},
                {"establishmentCode": "ESTABLISHMENT-DEMO-002", "siteName": "North Quay Riverside Works", "establishmentKind": "production", "operatingStatus": "operating"},
            ],
            [{"businessCode": "BUSINESS-DEMO-001", "administrativeArea": "north-demo", "localRegistrationNumber": 1001, "branchCount": 1}],
            [{"businessCode": "BUSINESS-DEMO-001", "productionSiteCount": 1, "suspendedSiteCount": 0, "hasProductionSite": True}],
            [{"businessCode": "BUSINESS-DEMO-002", "hasProductionSite": True, "branchCount": 1, "suspendedSiteCount": 1}],
        ]

        def request(
            root: Path,
            method: str,
            path: str,
            token_name: str,
            body: dict[str, object] | None = None,
            idempotency_key: str | None = None,
            expected: int = 200,
        ) -> tuple[dict[str, object], dict[str, str]]:
            calls.append((method, path, body))
            if method == "POST":
                return {
                    "id": business_id,
                    "revision": 1,
                    "data": {"businessCode": "BUSINESS-DEMO-001"},
                }, {}
            rows = expected_get_rows[len([call for call in calls if call[0] == "GET"]) - 1]
            return {
                "items": [{"id": str(uuid.uuid4()), "data": row} for row in rows],
                "count": len(rows),
            }, {}

        with mock.patch.object(DEMO, "_request", side_effect=request), mock.patch.object(
            DEMO, "_print_query"
        ):
            DEMO.query_business(self.root, "operator")

        query_paths = [call[1] for call in calls[:-1]]
        self.assertIn("$select=establishmentCode,siteName,establishmentKind,operatingStatus", query_paths[0])
        self.assertIn("$orderby=establishmentCode", query_paths[0])
        self.assertIn("$filter=administrativeArea%20eq", query_paths[1])
        self.assertIn("$orderby=localRegistrationNumber", query_paths[1])
        self.assertIn("$filter=hasProductionSite%20eq", query_paths[2])
        self.assertIn("suspendedSiteCount%20eq", query_paths[2])
        self.assertIn("$filter=hasProductionSite%20eq", query_paths[3])
        self.assertTrue(
            all(
                internal_name not in path
                for path in query_paths
                for internal_name in (
                    "establishment-code",
                    "administrative-area",
                    "local-registration-number",
                    "production-site-count",
                    "suspended-site-count",
                )
            )
        )
        self.assertEqual(calls[-1][0:2], ("POST", "/v1/records/businesses:lookup?accessProfile=business-operator"))
        self.assertEqual(
            calls[-1][2],
            {
                "selector": "by-local-reference",
                "values": {
                    "administrativeArea": "north-demo",
                    "localRegistrationNumber": 1001,
                },
            },
        )

    def test_prepare_refuses_a_fixture_without_the_expected_localization_boundary(self) -> None:
        bad_fixture = Path(self.temporary.name) / "bad-fixture"
        bad_fixture.mkdir()
        (bad_fixture / "registry.yaml").write_text("apiVersion: wrong\n", encoding="utf-8")
        with self.assertRaisesRegex(DEMO.DemoError, "expected package line"):
            DEMO.prepare(self.root, bad_fixture, 15432, 18081, 18080)

    def test_prepare_household_remains_explicit_legacy_demo_fixture(self) -> None:
        household_fixture = MODULE_PATH.parents[2] / "acceptance/publicschema-household"

        DEMO.prepare(
            self.root,
            household_fixture,
            15432,
            18081,
            18080,
            fixture_kind="household",
        )

        project = (self.root / "project/registry.yaml").read_text(encoding="utf-8")
        runtime = (self.root / "runtime-test.yaml").read_text(encoding="utf-8")
        self.assertIn(f"instanceId: {DEMO.INSTANCE_ID}", project)
        self.assertNotIn("publicschema-household-acceptance", project)
        self.assertIn("audience: urn:registry-server:household-demo", runtime)
        self.assertIn("allowedClients: [household-demo, household-demo-no-purpose, household-demo-viewer]", runtime)
        self.assertTrue((self.root / "mint/clients/household-demo.yaml").is_file())
        self.assertTrue((self.root / "mint/clients/household-demo-no-purpose.yaml").is_file())

    def test_prepare_asset_site_writes_distinct_clients_credentials_and_local_project(self) -> None:
        for name in ("planner", "planner-no-purpose"):
            (self.root / f"keys/{name}-public.jwk.json").write_text(
                json.dumps(public_jwk(f"{name}-key")), encoding="utf-8"
            )
        asset_fixture = MODULE_PATH.parents[2] / "acceptance/asset-site-placement"

        DEMO.prepare(self.root, asset_fixture, 15432, 18081, 18080, fixture_kind="asset-site")

        project = (self.root / "project/registry.yaml").read_text(encoding="utf-8")
        self.assertIn("environment: local", project)
        self.assertIn(f"instanceId: {DEMO.ASSET_SITE_INSTANCE_ID}", project)
        self.assertIn(f"sourceRevision: {DEMO.ASSET_SITE_SOURCE_REVISION}", project)
        self.assertNotIn("asset-site-placement-acceptance", project)
        self.assertIn("requiredScopes: [registry:asset:operate]", project)
        self.assertIn("requiredScopes: [registry:asset:plan]", project)
        journeys = (self.root / "project/tests/journeys.yaml").read_text(encoding="utf-8")
        self.assertIn("scopes: [registry:asset:operate]", journeys)
        self.assertIn("scopes: [registry:asset:plan]", journeys)

        runtime = (self.root / "runtime-test.yaml").read_text(encoding="utf-8")
        self.assertIn(f"audience: {DEMO.ASSET_SITE_AUDIENCE}", runtime)
        self.assertIn("allowedClients: [asset-site-demo-operator, asset-site-demo-planner, asset-site-demo-planner-no-purpose]", runtime)
        self.assertIn(f"instanceId: {DEMO.ASSET_SITE_INSTANCE_ID}", runtime)

        operator = (self.root / "mint/clients/asset-site-demo-operator.yaml").read_text(encoding="utf-8")
        planner = (self.root / "mint/clients/asset-site-demo-planner.yaml").read_text(encoding="utf-8")
        no_purpose = (self.root / "mint/clients/asset-site-demo-planner-no-purpose.yaml").read_text(encoding="utf-8")
        self.assertIn('registry_principal: "synthetic-asset-operator"', operator)
        self.assertIn('scopes: ["registry:asset:operate"]', operator)
        self.assertIn('registry_purpose: "asset-management"', operator)
        self.assertIn('registry_principal: "synthetic-site-planner"', planner)
        self.assertIn('scopes: ["registry:asset:plan"]', planner)
        self.assertIn('registry_purpose: "site-planning"', planner)
        self.assertIn('registry_principal: "synthetic-site-planner"', no_purpose)
        self.assertIn('scopes: ["registry:asset:plan"]', no_purpose)
        self.assertNotIn("registry_purpose", no_purpose)

        credentials = (self.root / "schema-test-credentials.yaml").read_text(encoding="utf-8")
        self.assertIn("stepId: planner-without-purpose-is-concealed", credentials)
        self.assertIn("tokenRef: secret:file/planner-no-purpose-token", credentials)

    def test_seed_asset_site_uses_normal_api_routes_and_validates_planner_projection(self) -> None:
        created_ids = {
            "/v1/records/assets": str(uuid.uuid4()),
            "/v1/records/sites": str(uuid.uuid4()),
            "/v1/records/placements": str(uuid.uuid4()),
            "/v1/records/inspections": str(uuid.uuid4()),
        }
        calls: list[tuple[str, str, str, dict[str, object] | None]] = []

        def request(
            root: Path,
            method: str,
            path: str,
            token_name: str,
            body: dict[str, object] | None = None,
            idempotency_key: str | None = None,
            expected: int = 200,
        ) -> tuple[dict[str, object], dict[str, str]]:
            calls.append((method, path, token_name, body))
            route = path.split("?", 1)[0]
            if method == "POST":
                return {"id": created_ids[route], "data": body.get("data", {}) if body else {}}, {}
            if token_name == "planner-no-purpose-token":
                return {"code": "resource.not_found"}, {}
            return {"items": [{"id": "one", "data": {"assetCode": "ASSET-SYNTH-001", "label": "Synthetic water pump"}}]}, {}

        with mock.patch.object(DEMO, "_request", side_effect=request), mock.patch("builtins.print"):
            DEMO.seed_asset_site(self.root)

        post_paths = [call[1] for call in calls if call[0] == "POST"]
        self.assertEqual(
            post_paths,
            [
                "/v1/records/assets?accessProfile=asset-operator",
                "/v1/records/sites?accessProfile=asset-operator",
                "/v1/records/placements?accessProfile=asset-operator",
                "/v1/records/inspections?accessProfile=asset-operator",
            ],
        )
        self.assertTrue((self.root / "seed-record-ids.json").is_file())
        rendered = json.dumps([call[3] for call in calls if call[0] == "POST"], sort_keys=True)
        self.assertIn("observedAt", rendered)
        self.assertIn("validFrom", rendered)

    def test_handoff_contains_only_frozen_persona_metadata_and_owner_only_token_paths(self) -> None:
        (self.root / "server-origin").write_text("http://127.0.0.1:18080\n", encoding="ascii")
        expires = 1798761600
        for name in ("operator-token", "viewer-token"):
            path = self.root / f"secrets/{name}"
            path.write_text(compact_jwt(expires), encoding="ascii")
            path.chmod(0o600)

        handoff = self.root / "handoff.json"
        DEMO.write_handoff(self.root, "business-establishments", handoff)

        self.assertEqual(handoff.stat().st_mode & 0o077, 0)
        value = json.loads(handoff.read_text(encoding="utf-8"))
        self.assertEqual(value["schemaVersion"], "registry-workspace/demo/v1")
        self.assertEqual(value["registry"], {"id": "business-establishments", "baseUrl": "http://127.0.0.1:18080"})
        self.assertEqual(
            value["personas"],
            [
                {
                    "id": "business-operator",
                    "label": "Business operator",
                    "tokenFile": str((self.root / "secrets/operator-token").resolve()),
                    "accessProfile": "business-operator",
                    "expiresAt": "2027-01-01T00:00:00Z",
                },
                {
                    "id": "business-viewer",
                    "label": "Business viewer",
                    "tokenFile": str((self.root / "secrets/viewer-token").resolve()),
                    "accessProfile": "business-viewer",
                    "expiresAt": "2027-01-01T00:00:00Z",
                },
            ],
        )
        rendered = json.dumps(value, sort_keys=True)
        self.assertNotIn(compact_jwt(expires), rendered)

    def test_handoff_refuses_group_readable_token_files(self) -> None:
        (self.root / "server-origin").write_text("http://127.0.0.1:18080\n", encoding="ascii")
        for name in ("operator-token", "viewer-token"):
            path = self.root / f"secrets/{name}"
            path.write_text(compact_jwt(1798752000), encoding="ascii")
            path.chmod(0o600)
        (self.root / "secrets/viewer-token").chmod(0o640)

        with self.assertRaisesRegex(DEMO.DemoError, "owner-only"):
            DEMO.write_handoff(self.root, "business-establishments", self.root / "handoff.json")

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
