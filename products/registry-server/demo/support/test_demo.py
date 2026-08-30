#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
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
        self.assertIn('registry_principal: "synthetic-household-operator"', operator)
        self.assertIn('registry_purpose: "household-administration"', operator)
        no_purpose = (self.root / "mint/clients/household-demo-no-purpose.yaml").read_text(encoding="utf-8")
        self.assertIn('registry_principal: "synthetic-household-operator"', no_purpose)
        self.assertNotIn("registry_purpose", no_purpose)

        runtime = (self.root / "runtime-test.yaml").read_text(encoding="utf-8")
        self.assertIn("accessTokenType: at+jwt", runtime)
        self.assertIn("kind: static", runtime)
        self.assertIn("documentRef: secret:file/mint-jwks", runtime)
        self.assertIn("principal: registry_principal", runtime)
        self.assertIn("purpose: registry_purpose", runtime)
        self.assertIn("household-demo-viewer", runtime)
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

    def test_seed_is_referentially_closed_and_stable(self) -> None:
        people, households, memberships = DEMO.seed_spec()
        person_codes = {person["person-code"] for person in people}
        household_codes = {household["household-code"] for household in households}
        self.assertEqual((len(people), len(households), len(memberships)), (8, 3, 8))
        self.assertEqual(len(person_codes), len(people))
        self.assertEqual(len(household_codes), len(households))
        self.assertEqual(
            [household["local-household-number"] for household in households],
            [1001, 1002, 1003],
        )
        self.assertTrue(all(row["person-code"] in person_codes for row in memberships))
        self.assertTrue(all(row["household-code"] in household_codes for row in memberships))
        self.assertEqual(
            {person["person-sex"] for person in people},
            {"female", "male"},
        )
        self.assertEqual(
            sum(person["residency-status"] == "usual-resident" for person in people),
            8,
        )

    def test_viewer_registration_is_created_only_after_a_household_id_is_known(self) -> None:
        DEMO.prepare(self.root, self.fixture, 15432, 18081, 18080)
        household_id = "0198f0f5-0877-7ae2-a853-09f2d47b6840"
        (self.root / "seed-record-ids.json").write_text(
            json.dumps(
                {
                    "people": {},
                    "households": {"HOUSEHOLD-DEMO-001": household_id},
                }
            ),
            encoding="utf-8",
        )

        DEMO.configure_viewer(self.root)

        viewer = (self.root / "mint/clients/household-demo-viewer.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn('scopes: ["registry:household:view"]', viewer)
        self.assertIn(f'household_id: "{household_id}"', viewer)
        self.assertIn('household_code: "HOUSEHOLD-DEMO-001"', viewer)
        self.assertIn('registry_purpose: "household-view"', viewer)
        self.assertIn("viewer-key", viewer)
        self.assertNotIn("signing-p256-private-jwk", viewer)

    def test_viewer_registration_refuses_a_non_uuid_bound_record(self) -> None:
        DEMO.prepare(self.root, self.fixture, 15432, 18081, 18080)
        (self.root / "seed-record-ids.json").write_text(
            json.dumps({"households": {"HOUSEHOLD-DEMO-001": "not-a-record-id"}}),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(DEMO.DemoError, "not a UUID"):
            DEMO.configure_viewer(self.root)

    def test_viewer_queries_prove_bound_get_claim_lookup_and_concealed_denials(self) -> None:
        household_id = "0198f0f5-0877-7ae2-a853-09f2d47b6840"
        (self.root / "seed-record-ids.json").write_text(
            json.dumps({"households": {"HOUSEHOLD-DEMO-001": household_id}}),
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
                "id": household_id,
                "revision": 1,
                "data": {"household-code": "HOUSEHOLD-DEMO-001"},
            }, {}

        with mock.patch.object(DEMO, "_request", side_effect=request), mock.patch.object(
            DEMO, "_print_query"
        ):
            DEMO.query(self.root, "viewer")

        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[0][0:3], ("GET", f"/v1/records/households/{household_id}?accessProfile=household-viewer", "viewer-token"))
        self.assertEqual(calls[1][0:3], ("POST", "/v1/records/households:lookup?accessProfile=household-viewer", "viewer-token"))
        self.assertEqual(calls[1][3], {"selector": "by-household-code"})
        self.assertTrue(all(call[2] == "viewer-token" for call in calls))
        self.assertEqual([call[4] for call in calls], [200, 200, 404, 404])

    def test_operator_selector_query_uses_the_exact_values_property(self) -> None:
        household_id = "0198f0f5-0877-7ae2-a853-09f2d47b6840"
        (self.root / "seed-record-ids.json").write_text(
            json.dumps({"households": {"HOUSEHOLD-DEMO-001": household_id}}),
            encoding="utf-8",
        )
        calls: list[tuple[str, str, object]] = []

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
                    "id": household_id,
                    "revision": 1,
                    "data": {"household-code": "HOUSEHOLD-DEMO-001"},
                }, {}
            return {"items": []}, {}

        with mock.patch.object(DEMO, "_request", side_effect=request), mock.patch.object(
            DEMO, "_print_query"
        ):
            DEMO.query(self.root, "operator")

        self.assertEqual(calls[-1][0:2], ("POST", "/v1/records/households:lookup?accessProfile=household-operator"))
        self.assertEqual(
            calls[-1][2],
            {
                "selector": "by-local-reference",
                "values": {
                    "administrative-area": "north-demo",
                    "local-household-number": 1001,
                },
            },
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
