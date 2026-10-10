#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
SCRIPT_DIR = Path(__file__).parent
COMPARATOR_PATH = SCRIPT_DIR / "compare-generated-tree.py"
SPEC = importlib.util.spec_from_file_location("breg_generated_tree", COMPARATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
COMPARATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COMPARATOR
SPEC.loader.exec_module(COMPARATOR)


class GeneratedGateTests(unittest.TestCase):
    def test_comparator_rejects_a_missing_committed_artifact(self) -> None:
        baseline = SCRIPT_DIR.parent / "generated/asset-site-placement"
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            shutil.copytree(baseline, candidate)
            (candidate / COMPARATOR.EXPECTED_PATHS[-1]).unlink()
            errors = COMPARATOR.compare(baseline, candidate)
        self.assertTrue(any("candidate is missing expected artifacts" in error for error in errors), errors)

    def test_attachment_baseline_requires_request_metadata_schema(self) -> None:
        baseline = SCRIPT_DIR.parent / "generated/request-attachments"
        self.assertEqual([], COMPARATOR.compare(baseline, baseline))
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            shutil.copytree(baseline, candidate)
            (candidate / "generated/schemas/correction-request.schema.json").unlink()
            errors = COMPARATOR.compare(baseline, candidate)
        self.assertTrue(any("candidate is missing expected artifacts" in error for error in errors), errors)

    def test_comparator_requires_action_inventory_and_target_condition_schemas(self) -> None:
        baselines = SCRIPT_DIR.parent / "generated"
        self.assertEqual([], COMPARATOR.compare(
            baselines / "asset-registration-actions",
            baselines / "asset-registration-actions",
        ))
        self.assertEqual([], COMPARATOR.compare(
            baselines / "household-contact-actions",
            baselines / "household-contact-actions",
        ))
        self.assertEqual([], COMPARATOR.compare(
            baselines / "person-registration-rhai",
            baselines / "person-registration-rhai",
        ))

        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            shutil.copytree(baselines / "household-contact-actions", candidate)
            (candidate / "compiled/actions.json").unlink()
            (
                candidate
                / "generated/action-schemas/register-household-contact.target-conditions.response.schema.json"
            ).unlink()
            errors = COMPARATOR.compare(baselines / "household-contact-actions", candidate)

        self.assertTrue(any("compiled/actions.json" in error for error in errors), errors)
        self.assertTrue(any("target-conditions.response.schema.json" in error for error in errors), errors)

    def test_generated_gate_script_keeps_a_bounded_database_free_cli_journey(self) -> None:
        generated_gate = (SCRIPT_DIR / "check-generated.sh").read_text(encoding="utf-8")
        self.assertIn("mktemp -d", generated_gate)
        self.assertIn("business-establishments", generated_gate)
        self.assertIn("asset-site-placement-change-requests", generated_gate)
        self.assertIn("publicschema-household-change-requests", generated_gate)
        self.assertIn("acceptance/person-registration-rhai", generated_gate)
        self.assertIn("acceptance/request-attachments", generated_gate)
        self.assertIn('export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"', generated_gate)
        self.assertIn("authoring_baseline", generated_gate)
        self.assertIn("--features schema --example authoring-schema", generated_gate)
        self.assertIn("products/breg/generated/authoring", generated_gate)
        self.assertIn("runtime_baseline", generated_gate)
        self.assertIn("--features runtime,schema --example runtime-schema", generated_gate)
        self.assertIn("products/breg/generated/runtime", generated_gate)
        for selector in ("openapi", "schemas", "manifest", "metadata", "sql"):
            self.assertIn(selector, generated_gate)
        self.assertNotIn(" apply ", generated_gate)
        self.assertNotIn(" serve ", generated_gate)
        self.assertNotIn("BREG_TEST_DATABASE_URL", generated_gate)
        self.assertIn("compare-generated-tree.py", generated_gate)

    def test_change_request_examples_script_uses_protected_runtime_files(self) -> None:
        script = (SCRIPT_DIR / "test-change-request-examples.sh").read_text(encoding="utf-8")
        self.assertIn("mktemp -d", script)
        self.assertIn("BREG_TEST_DATABASE_URL", script)
        self.assertIn("BREG_TEST_TLS_CA_PEM_PATH", script)
        self.assertIn("schema-test-credentials", script)
        self.assertIn("--asset-project", script)
        self.assertIn("--household-project", script)
        self.assertIn("--rhai-project", script)
        self.assertIn("normalize_project asset", script)
        self.assertIn("normalize_project household", script)
        self.assertIn("normalize_project rhai", script)
        self.assertIn("secret:file/", script)
        self.assertIn("write_jwt", script)
        self.assertIn("import yaml", script)
        self.assertIn("json.dumps", script)
        self.assertIn("bregctl", script)
        self.assertIn("--format json test", script)
        self.assertIn("asset-site-placement-change-requests", script)
        self.assertIn("publicschema-household-change-requests", script)
        self.assertIn("person-name-change-rhai", script)
        self.assertNotIn("test-postgres.sh", script)
        self.assertNotIn("BREG_TEST_DATABASE_URL=", script)
        self.assertNotIn("Authorization: Bearer", script)

    def test_example_workflows_publish_unsigned_packages(self) -> None:
        product = SCRIPT_DIR.parent
        workflows = [
            SCRIPT_DIR / "test-historical-workflow.sh",
            SCRIPT_DIR / "test-change-request-examples.sh",
            SCRIPT_DIR / "test-promotion.sh",
            product / "acceptance/person-registration-rhai/tests/live_registration.py",
            product / "acceptance/farmer-landholding-evidence/tests/live_registration.py",
            product / "acceptance/farmer-landholding-evidence/tests/run-live.py",
        ]
        for workflow in workflows:
            source = workflow.read_text(encoding="utf-8")
            for retired in (
                "--signatures",
                "--signature-threshold",
                "--signature-key-id",
                "--database-id",
                "--baseline-runtime-config",
                "signing-input.json",
                "trustAnchorPath",
                "activeRevision",
                "activeSequence",
                "compilerSourceRevision",
            ):
                with self.subTest(workflow=workflow.name, retired=retired):
                    self.assertNotIn(retired, source)

    def test_promotion_workflow_moves_one_package_through_two_environments(self) -> None:
        promotion = SCRIPT_DIR / "test-promotion.sh"
        self.assertTrue(os.access(promotion, os.X_OK))
        source = promotion.read_text(encoding="utf-8")
        for marker in (
            "BREG_TEST_TLS_CA_PEM_PATH",
            'if [[ "${BREG_SKIP_BUILD:-0}" != "1" ]]',
            "registry_prepare_cargo_runtime",
            "plan --runtime-config",
            "--initial",
            "status --runtime-config",
            "--baseline-package",
            "--reviewed-migrations",
            "--backup",
            "generate evidence-source",
            "registryRevision",
            "apply.backup_evidence.refused",
            "apply.package.refused",
            "apply.database.identity_mismatch",
            "has not activated the package at package.root",
            "catalog_digest",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        workflow = (SCRIPT_DIR.parents[2] / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("run: products/breg/scripts/test-promotion.sh", workflow)

    def test_backup_restore_workflow_proves_the_documented_recovery(self) -> None:
        proof = SCRIPT_DIR / "test-backup-restore.sh"
        self.assertTrue(os.access(proof, os.X_OK))
        source = proof.read_text(encoding="utf-8")
        for marker in (
            "BREG_TEST_TLS_CA_PEM_PATH",
            'if [[ "${BREG_SKIP_BUILD:-0}" != "1" ]]',
            "registry_prepare_cargo_runtime",
            "pg_dump",
            "pg_restore --exit-on-error",
            "startup.instance_claim.mismatch",
            "instance_claim.acknowledgement.required",
            "--acknowledge-original-retired",
            "startup.instance_id.pending_deliveries",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        self.assertNotIn("--signing-key", source)
        workflow = (SCRIPT_DIR.parents[2] / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("run: products/breg/scripts/test-backup-restore.sh", workflow)

    def test_adopter_workflow_uses_public_binaries_database_and_recovery(self) -> None:
        adopter_gate = (SCRIPT_DIR / "test-adopter-workflow.sh").read_text(encoding="utf-8")
        self.assertIn("mktemp -d", adopter_gate)
        self.assertIn('export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"', adopter_gate)
        self.assertIn('bregctl=${BREGCTL_BIN:-"$repository_root/target/debug/bregctl"}', adopter_gate)
        self.assertIn('breg=${BREG_BIN:-"$repository_root/target/debug/breg"}', adopter_gate)
        self.assertIn("registry_cargo_build", adopter_gate)
        self.assertIn("-p registry-bregctl", adopter_gate)
        self.assertIn("-p registry-breg", adopter_gate)
        self.assertIn("server_hash_before", adopter_gate)
        self.assertIn("server_hash_after", adopter_gate)
        self.assertIn('BREG_SKIP_BUILD=1 "$script_dir/test-historical-workflow.sh"', adopter_gate)
        self.assertNotIn("cargo run", adopter_gate)
        self.assertNotIn("--signing-key", adopter_gate)

        for marker in (
            "BREG_TEST_DATABASE_URL",
            "CREATE ROLE",
            "CREATE DATABASE",
            "CREATE SCHEMA registry_source",
            "CREATE SCHEMA registry_derived",
            "CREATE SCHEMA registry_context",
            "REVOKE ALL ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context FROM PUBLIC",
            "adopter_schema_test_v1_database",
            "adopter_schema_test_v2_database",
            "adopter_production_database",
            "derive_admin_database_url",
            "secret:file/schema-test-v1-runtime-url",
            "secret:file/schema-test-v1-migration-url",
            "secret:file/schema-test-v2-runtime-url",
            "secret:file/schema-test-v2-migration-url",
            "secret:file/production-runtime-url",
            "secret:file/production-migration-url",
            "BREG_TEST_TLS_CA_PEM_PATH",
            'export SSL_CERT_FILE="$adopter_tls_ca_pem_path"',
            "umask 077",
            "apiVersion: id.registrystack.org/formats/breg/runtime/v1alpha1",
            "kind: BRegRuntimeConfig",
            "maximumTokenLifetimeSeconds: 3600",
            '"exp": now + 3600',
            "jwksSource:",
            "type: static",
            "documentRef: secret:file/oidc-jwks",
            "write_jwt",
            "--production",
            "compare-generated-tree.py",
            "schemaFingerprint",
            "missing-migration-url",
            "apply.database_configuration.refused",
            "author refusal changed the production database state",
            "apply --runtime-config",
            '"$breg" --runtime-config',
            "data validate",
            "data import",
            '"assetCode":"ASSET-PUBLIC-001"',
            '"assetClass":"equipment"',
            "entity_list_path",
            "http_get_json",
            "authorized public data read",
            "field-added-optional",
            "compatible-additive",
            "LOCK TABLE",
            "pg_terminate_backend",
            "apply.migration.failed",
            "plan --runtime-config",
            "status --runtime-config",
            "assert_plan",
            "assert_ledger",
            "resumes",
            "maintenanceTargetPackageDigest",
            "--baseline-package",
            "--reviewed-migrations",
            "restricted successor field was disclosed",
        ):
            self.assertIn(marker, adopter_gate)
        self.assertNotIn("--from-release", adopter_gate)
        self.assertNotIn("--signature", adopter_gate)
        self.assertNotIn('"psql", admin, "-d", database', adopter_gate)
        self.assertNotIn('"scope": "registry:records"', adopter_gate)

        historical_gate = (SCRIPT_DIR / "test-historical-workflow.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('if [[ "${BREG_SKIP_BUILD:-0}" != "1" ]]', historical_gate)
        self.assertIn("registry_prepare_cargo_runtime", historical_gate)

    def test_postgres_tls_script_hands_off_public_ca_material_without_retaining_keys(self) -> None:
        tls_gate = (SCRIPT_DIR / "test-postgres-tls.sh").read_text(encoding="utf-8")
        self.assertIn("validate_caller_output_path", tls_gate)
        self.assertIn("BREG_TEST_TLS_CA_DER_PATH", tls_gate)
        self.assertIn("BREG_TEST_TLS_CA_PEM_PATH", tls_gate)
        self.assertIn("trusted-ca.der", tls_gate)
        self.assertIn("trusted-ca.pem", tls_gate)
        self.assertIn("wrong-ca.der", tls_gate)
        self.assertIn('mktemp "$(dirname -- "$caller_ca_pem_path")/.breg-postgres-ca-pem.XXXXXX"', tls_gate)
        self.assertIn('pg_isready -q -d "$database_url"', tls_gate)
        self.assertIn('pg_ctl -D "$postgres_data_directory" reload', tls_gate)
        self.assertIn('rm -rf -- "$tls_dir"', tls_gate)
        self.assertIn('chmod 600 "$tls_dir"/*.key', tls_gate)
        self.assertNotIn("trusted-ca.key\" \"$caller", tls_gate)

    def test_postgres_tls_setup_only_mode_stops_before_the_proof(self) -> None:
        tls_gate = (SCRIPT_DIR / "test-postgres-tls.sh").read_text(encoding="utf-8")
        setup_only = tls_gate.index('BREG_TEST_TLS_SETUP_ONLY:-0}" == "1"')
        self.assertLess(tls_gate.index('pg_isready -q -d "$database_url"'), setup_only)
        self.assertLess(setup_only, tls_gate.index("cargo test --locked -p registry-breg"))

    def test_local_postgres_tls_helper_prepares_the_ci_shape(self) -> None:
        helper = SCRIPT_DIR / "local-postgres-tls.sh"
        self.assertTrue(os.access(helper, os.X_OK))
        text = helper.read_text(encoding="utf-8")
        workflow = (SCRIPT_DIR.parents[2] / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        image = re.search(r"image='(postgis/postgis@sha256:[0-9a-f]{64})'", text)
        self.assertIsNotNone(image)
        self.assertIn(f"image: {image.group(1)}", workflow)
        self.assertIn("BREG_TEST_TLS_SETUP_ONLY=1", text)
        self.assertIn("docker inspect -f '{{.Id}}'", text)
        self.assertIn("-p 127.0.0.1::5432", text)
        self.assertIn('tls_dir="$repo_root/target/breg-postgres-tls"', text)
        for name in (
            "BREG_TEST_DATABASE_URL",
            "BREG_TEST_TLS_DATABASE_URL",
            "BREG_TEST_TLS_HOSTNAME_MISMATCH_DATABASE_URL",
            "BREG_TEST_TLS_DATABASE_HOST",
            "BREG_TEST_TLS_POSTGRES_CONTAINER_ID",
            "BREG_TEST_TLS_CA_PEM_PATH",
        ):
            self.assertIn(f"printf 'export {name}=%q\\n'", text)

    def test_comparator_rejects_a_symbolic_link_without_reading_its_target(self) -> None:
        if os.name == "nt":
            self.skipTest("symbolic-link setup is not portable on Windows")
        baseline = SCRIPT_DIR.parent / "generated/asset-site-placement"
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            shutil.copytree(baseline, candidate)
            target = candidate / COMPARATOR.EXPECTED_PATHS[0]
            target.unlink()
            target.symlink_to("/not/a-generated-artifact")
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                COMPARATOR.compare(baseline, candidate)


if __name__ == "__main__":
    unittest.main()
