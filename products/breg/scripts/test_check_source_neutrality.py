#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
SCRIPT_PATH = Path(__file__).with_name("check_source_neutrality.py")
SPEC = importlib.util.spec_from_file_location("breg_source_neutrality", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class SourceNeutralityTests(unittest.TestCase):
    def test_fixture_identifier_in_breg_client_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "crates/registry-breg-client/src/client.rs"
            source.parent.mkdir(parents=True)
            source.write_text(
                'const ROUTE: &str = "/v1/records/legal-entities";\n',
                encoding="utf-8",
            )
            violations = CHECKER.find_violations(root)
        self.assertTrue(violations, violations)
        self.assertIn("/v1/records/legal-entities", violations[0])

    def test_fixture_identifier_in_production_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "crates/registry-breg/src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text(
                'const ROUTE: &str = "/v1/records/assets";\n',
                encoding="utf-8",
            )
            violations = CHECKER.find_violations(root)
        self.assertTrue(violations, violations)
        self.assertIn("/v1/records/assets", violations[0])

    def test_every_domain_fixture_family_has_a_rejected_route_canary(self) -> None:
        for route in (
            "/v1/records/assets",
            "/v1/records/persons",
            "/v1/records/assessment-episodes",
            "/v1/records/farmers",
            "/v1/records/facilities",
            "/v1/records/businesses",
            "/v1/records/establishments",
            "business-establishment-summary",
            "/v1/records/authorities",
            "/v1/records/legal-entities",
        ):
            with self.subTest(route=route), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "crates/registry-breg/src/lib.rs"
                source.parent.mkdir(parents=True)
                source.write_text(
                    f'const FIXTURE_ROUTE: &str = "{route}";\n',
                    encoding="utf-8",
                )
                violations = CHECKER.find_violations(root)
            self.assertTrue(violations, violations)
            self.assertTrue(
                any(route in violation for violation in violations),
                violations,
            )

    def test_generic_source_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "crates/registry-breg/src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text("pub struct CompiledRegistry;\n", encoding="utf-8")
            self.assertEqual([], CHECKER.find_violations(root))

    def test_generic_module_asset_vocabulary_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "crates/registry-breg/src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text(
                'pub struct ModuleAssetSource;\nconst ERROR: &str = "module.asset.refused";\n',
                encoding="utf-8",
            )
            self.assertEqual([], CHECKER.find_violations(root))

    def test_fixture_identifier_in_test_code_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "crates/registry-breg/src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text("pub struct CompiledRegistry;\n", encoding="utf-8")
            fixture_test = root / "crates/registry-breg/tests/asset_fixture.rs"
            fixture_test.parent.mkdir(parents=True)
            fixture_test.write_text('const FIXTURE: &str = "asset-site-placement";\n', encoding="utf-8")
            self.assertEqual([], CHECKER.find_violations(root))

    def test_fixture_identifier_in_inline_rust_test_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "crates/registry-breg/src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pub struct CompiledRegistry;\n"
                "#[cfg(test)]\n"
                "mod tests {\n"
                '    const FIXTURE: &str = "asset-site-placement";\n'
                "}\n",
                encoding="utf-8",
            )
            self.assertEqual([], CHECKER.find_violations(root))

    def test_bare_domain_rust_type_identifier_is_rejected(self) -> None:
        for identifier in ("Person", "Household", "Farmer", "LegalEntity"):
            with self.subTest(identifier=identifier), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "crates/registry-breg/src/lib.rs"
                source.parent.mkdir(parents=True)
                source.write_text(f"pub struct {identifier};\n", encoding="utf-8")
                violations = CHECKER.find_violations(root)
            self.assertTrue(
                any("Rust type identifier" in violation for violation in violations),
                violations,
            )

    def test_domain_cargo_feature_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "crates/registry-breg/Cargo.toml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                "[package]\nname = \"neutral\"\nversion = \"0.1.0\"\n"
                "[features]\nfarmer-pilot = []\n",
                encoding="utf-8",
            )
            violations = CHECKER.find_violations(root)
        self.assertTrue(any("Cargo feature farmer-pilot" in item for item in violations), violations)

    def test_domain_migration_and_resource_inputs_are_rejected(self) -> None:
        cases = (
            ("migrations/001.sql", "CREATE TABLE farmer (id uuid);\n"),
            ("resources/metrics.yaml", "name: registry.person.requests\n"),
        )
        for relative, contents in cases:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "crates/registry-breg" / relative
                source.parent.mkdir(parents=True)
                source.write_text(contents, encoding="utf-8")
                violations = CHECKER.find_violations(root)
            self.assertTrue(
                any("production identifier" in violation for violation in violations),
                violations,
            )

    def test_domain_metric_and_error_identifiers_are_rejected(self) -> None:
        for value in ("registry.farmer.requests", "person.not_found"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "crates/registry-breg/src/lib.rs"
                source.parent.mkdir(parents=True)
                source.write_text(f'const IDENTIFIER: &str = "{value}";\n', encoding="utf-8")
                violations = CHECKER.find_violations(root)
            self.assertTrue(
                any("metric/error identifier" in violation for violation in violations),
                violations,
            )

    def test_rust_string_scanner_stays_synchronized_after_escaped_quotes_and_raw_literals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "crates/registry-breg/src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text(
                'const ORDINARY_CANARY: &str = "quoted \\"value\\" at /v1/records/assets";\n'
                'const RAW_CANARY: &str = r#"registry.person.requests"#;\n'
                "impl PostgresFixtureTestRunner {\n"
                "    fn capture<'a>(observations: &'a BTreeMap<String, Observation>) {}\n"
                "}\n",
                encoding="utf-8",
            )
            violations = CHECKER.find_violations(root)

        self.assertTrue(any("/v1/records/assets" in item for item in violations), violations)
        self.assertTrue(any("person" in item for item in violations), violations)
        self.assertFalse(any("observation" in item.lower() for item in violations), violations)

    def test_public_kernel_contract_canary_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "products/breg/contracts/package-layout.yaml"
            contract.parent.mkdir(parents=True)
            contract.write_text("canary: /v1/records/farmers\n", encoding="utf-8")
            violations = CHECKER.find_violations(root)
        self.assertTrue(violations, violations)

    def test_fixture_directories_and_ordinary_docs_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "crates/registry-breg/src/fixtures/domain.rs"
            fixture.parent.mkdir(parents=True)
            fixture.write_text("pub struct Farmer;\n", encoding="utf-8")
            docs = root / "crates/registry-breg/README.md"
            docs.write_text(
                "A person can operate a household or farmer registry.\n",
                encoding="utf-8",
            )
            self.assertEqual([], CHECKER.find_violations(root))

    def test_fixture_identifier_in_build_script_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_script = root / "crates/registry-breg/build.rs"
            build_script.parent.mkdir(parents=True)
            build_script.write_text(
                'const ROUTE: &str = "/v1/records/assets";\n',
                encoding="utf-8",
            )
            violations = CHECKER.find_violations(root)
        self.assertTrue(violations, violations)
        self.assertIn("build.rs", violations[0])


if __name__ == "__main__":
    unittest.main()
